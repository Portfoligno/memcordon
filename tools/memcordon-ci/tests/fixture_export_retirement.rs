#![cfg(any(target_os = "linux", target_os = "macos"))]
#![deny(unsafe_code, dead_code)]
use memcordon_ci::{CiError, Result};
#[path = "../src/release/fixture_export_retirement.rs"]
mod retirement;
use sha2::{Digest, Sha256};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::time::{Duration, Instant};

impl retirement::Owner {
    fn fail_next_progress(&self) {
        self.fail_progress.set(true);
    }
}

fn fixture() -> (tempfile::TempDir, std::path::PathBuf, Vec<u8>) {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary
        .path()
        .canonicalize()
        .unwrap()
        .join("private-export-ab12");
    std::fs::create_dir_all(root.join("work/nested")).unwrap();
    for path in [&root, &root.join("work"), &root.join("work/nested")] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut files = Vec::new();
    for (path, bytes) in [
        ("work/result.bin", b"result".as_slice()),
        ("work/nested/empty", b"".as_slice()),
    ] {
        std::fs::write(root.join(path), bytes).unwrap();
        std::fs::set_permissions(root.join(path), std::fs::Permissions::from_mode(0o400)).unwrap();
        files.push(serde_json::json!({"path":path,"length":bytes.len(),"sha256":hex::encode(Sha256::digest(bytes))}));
    }
    let receipt = serde_json::to_vec(&serde_json::json!({
        "format":"memcordon.private-export","revision":1,"attempt_id":"ab12",
        "root_layout":"original","identity":"original","files":files,
    }))
    .unwrap();
    std::fs::write(root.join("export-receipt.json"), &receipt).unwrap();
    std::fs::set_permissions(
        root.join("export-receipt.json"),
        std::fs::Permissions::from_mode(0o400),
    )
    .unwrap();
    (temporary, root, receipt)
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

#[test]
fn preserves_every_product_before_finite_authenticated_retirement() {
    let (_temporary, root, receipt) = fixture();
    let uid = std::fs::metadata(&root).unwrap().uid();
    let held = std::fs::File::open(&root).unwrap();
    let mut products = Vec::new();
    let mut owner = retirement::prepare(
        &root,
        &receipt,
        uid,
        deadline(),
        &root.parent().unwrap().join("journal"),
        |name, bytes| {
            assert!(root.join("export-receipt.json").is_file());
            assert!(root.join("work/result.bin").is_file());
            products.push((name.to_owned(), bytes.to_vec()));
            Ok(())
        },
    )
    .unwrap();
    assert!(!owner.settled());
    let proof = owner.retire().unwrap();
    assert!(owner.settled());
    assert_eq!(products.len(), 2);
    assert_eq!(proof["captured_files"], 2);
    assert_eq!(proof["named_absent"], true);
    assert!(!root.exists());
    assert_eq!(proof["held_link_count"], held.metadata().unwrap().nlink());
}

#[test]
fn refuses_foreign_changed_aliased_or_uncaptured_exports_without_deletion() {
    for mutation in 0..10 {
        let (_temporary, root, mut receipt) = fixture();
        let uid = std::fs::metadata(&root).unwrap().uid();
        let mut cutoff = deadline();
        match mutation {
            0 => {
                std::fs::write(root.join("unknown-user-output"), b"preserve").unwrap();
            }
            1 => {
                std::fs::set_permissions(
                    root.join("work/result.bin"),
                    std::fs::Permissions::from_mode(0o600),
                )
                .unwrap();
                std::fs::write(root.join("work/result.bin"), b"changed").unwrap();
            }
            2 => {
                std::fs::remove_file(root.join("work/result.bin")).unwrap();
                std::os::unix::fs::symlink("nested/empty", root.join("work/result.bin")).unwrap();
            }
            3 => {
                std::fs::hard_link(root.join("work/result.bin"), root.join("alias")).unwrap();
            }
            4 => {
                let mut value: serde_json::Value = serde_json::from_slice(&receipt).unwrap();
                value["attempt_id"] = "cd34".into();
                receipt = serde_json::to_vec(&value).unwrap();
            }
            5 => {
                cutoff = Instant::now();
            }
            6 => {
                std::fs::set_permissions(root.join("work"), std::fs::Permissions::from_mode(0o777))
                    .unwrap();
            }
            7 => {
                std::fs::create_dir(root.join("unknown-directory")).unwrap();
            }
            8 | 9 => {}
            _ => unreachable!(),
        }
        let result = retirement::prepare(
            &root,
            &receipt,
            uid,
            cutoff,
            &root.parent().unwrap().join("journal"),
            |_, _| {
                if mutation == 8 {
                    return Err(CiError::Message("durable capture failed".into()));
                }
                if mutation == 9 {
                    std::fs::write(root.join("late-user-output"), b"preserve")?;
                }
                Ok(())
            },
        );
        assert!(result.is_err(), "mutation {mutation}");
        assert!(
            root.join("export-receipt.json").exists(),
            "mutation {mutation}"
        );
        assert!(
            root.join("work/nested/empty").exists(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn partial_unlink_retains_original_owner_for_bounded_retry() {
    let (_temporary, root, receipt) = fixture();
    let uid = std::fs::metadata(&root).unwrap().uid();
    let journal = root.parent().unwrap().join("journal");
    let mut captured = Vec::new();
    let mut owner =
        retirement::prepare(&root, &receipt, uid, deadline(), &journal, |name, bytes| {
            captured.push((name.to_owned(), bytes.to_vec()));
            Ok(())
        })
        .unwrap();
    owner.fail_next_progress();
    assert!(
        owner
            .retire()
            .unwrap_err()
            .to_string()
            .contains("progress persistence")
    );
    assert!(!owner.settled());
    assert!(!root.join("work/nested/empty").exists());
    assert!(root.join("work/result.bin").exists());
    assert!(root.join("export-receipt.json").exists());
    assert_eq!(captured.len(), 2);
    owner.retire().unwrap();
    assert!(owner.settled());
    assert!(!root.exists());
    let progress = std::fs::read_to_string(journal).unwrap();
    assert!(progress.lines().next().unwrap().contains("intent"));
    assert!(progress.lines().last().unwrap().contains("settled"));
}

#[test]
fn partial_retry_rejects_new_foreign_members_without_adopting_them() {
    let (_temporary, root, receipt) = fixture();
    let uid = std::fs::metadata(&root).unwrap().uid();
    let mut owner = retirement::prepare(
        &root,
        &receipt,
        uid,
        deadline(),
        &root.parent().unwrap().join("journal"),
        |_, _| Ok(()),
    )
    .unwrap();
    owner.fail_next_progress();
    assert!(owner.retire().is_err());
    std::fs::write(root.join("unknown-user-output"), b"preserve").unwrap();
    assert!(
        owner
            .retire()
            .unwrap_err()
            .to_string()
            .contains("inventory changed")
    );
    assert!(!owner.settled());
    assert_eq!(
        std::fs::read(root.join("unknown-user-output")).unwrap(),
        b"preserve"
    );
    assert!(root.join("work/result.bin").exists());
    assert!(root.join("export-receipt.json").exists());
}
