use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};

fn cell(records: Vec<Artifact>) -> CellEvidence {
    CellEvidence {
        format: "memcordon.consumer-readiness.cell".into(),
        revision: 1,
        identity: crate::consumer_readiness_ledger::SourceIdentity {
            run_id: "1".into(),
            source_commit: "a".repeat(40),
            source_tree_sha256: "b".repeat(64),
            version: "0.5.8-dev".into(),
        },
        key: memcordon_readiness_verifier::ProductKey {
            target: "x86_64-unknown-linux-gnu".into(),
            channel: "candidate-native".into(),
        },
        product: None,
        component_build: None,
        records: vec![],
        artifacts: records,
        cleanup_failures: vec!["original namespace preparation failed".into()],
        cache_quiescent: false,
    }
}
fn record(path: &str, bytes: &[u8]) -> Artifact {
    Artifact {
        path: path.into(),
        length: bytes.len() as u64,
        sha256: crate::release::artifacts::checksum(bytes),
    }
}
fn cutoff() -> Instant {
    Instant::now() + std::time::Duration::from_secs(5)
}

#[test]
fn selected_projection_preserves_private_originals_and_failed_verdict() {
    let owned = tempfile::tempdir().unwrap();
    let path = owned.path().canonicalize().unwrap();
    std::fs::create_dir(path.join("private")).unwrap();
    std::fs::set_permissions(path.join("private"), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(path.join("private/selected.bin"), b"approved").unwrap();
    std::fs::set_permissions(
        path.join("private/selected.bin"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    std::fs::write(
        path.join("private/unselected-secret.bin"),
        b"not catalogued",
    )
    .unwrap();
    let selected = cell(vec![record("private/selected.bin", b"approved")]);
    publish(&path, &selected, cutoff()).unwrap();
    publish(&path, &selected, cutoff()).unwrap();
    assert_eq!(
        std::fs::read(path.join("producer/private/selected.bin")).unwrap(),
        b"approved"
    );
    assert!(!path.join("producer/private/unselected-secret.bin").exists());
    assert_eq!(
        std::fs::metadata(path.join("private")).unwrap().mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(path.join("private/selected.bin"))
            .unwrap()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(path.join("producer/private"))
            .unwrap()
            .mode()
            & 0o777,
        0o755
    );
    assert_eq!(
        std::fs::metadata(path.join("producer/private/selected.bin"))
            .unwrap()
            .mode()
            & 0o777,
        0o644
    );
    let projected: CellEvidence =
        serde_json::from_slice(&std::fs::read(path.join("producer/cell.json")).unwrap()).unwrap();
    assert_eq!(
        serde_json::to_value(&projected).unwrap(),
        serde_json::to_value(&selected).unwrap()
    );
    std::fs::write(path.join("private/selected.bin"), b"replaced").unwrap();
    assert!(publish(&path, &selected, cutoff()).is_err());
    let failed: CellEvidence =
        serde_json::from_slice(&std::fs::read(path.join("producer/cell.json")).unwrap()).unwrap();
    assert!(!failed.cache_quiescent);
    assert_eq!(
        failed.cleanup_failures.first(),
        selected.cleanup_failures.first()
    );
    assert!(failed.cleanup_failures.len() > selected.cleanup_failures.len());
    assert_eq!(
        std::fs::read(path.join("producer/private/selected.bin")).unwrap(),
        b"approved"
    );

    std::fs::write(path.join("private/selected.bin"), b"approved").unwrap();
    let mut successful = selected.clone();
    successful.cache_quiescent = true;
    successful.cleanup_failures.clear();
    publish(&path, &successful, cutoff()).unwrap();
    let before: CellEvidence =
        serde_json::from_slice(&std::fs::read(path.join("producer/cell.json")).unwrap()).unwrap();
    assert!(before.cache_quiescent);
    assert!(before.cleanup_failures.is_empty());
    std::fs::write(path.join("private/selected.bin"), b"replaced").unwrap();
    assert!(publish(&path, &successful, cutoff()).is_err());
    let interrupted: CellEvidence =
        serde_json::from_slice(&std::fs::read(path.join("producer/cell.json")).unwrap()).unwrap();
    assert!(!interrupted.cache_quiescent);
    assert!(!interrupted.cleanup_failures.is_empty());
    assert_eq!(
        serde_json::to_value(&interrupted.identity).unwrap(),
        serde_json::to_value(&successful.identity).unwrap()
    );
    assert_eq!(
        std::fs::read(path.join("producer/private/selected.bin")).unwrap(),
        b"approved"
    );
}

#[test]
fn source_and_destination_aliases_escape_and_false_digests_are_refused() {
    for mutation in [
        "source-link",
        "source-parent-link",
        "external-hardlink",
        "destination-link",
        "digest",
        "escape",
        "duplicate",
    ] {
        let owned = tempfile::tempdir().unwrap();
        let path = owned.path().canonicalize().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir(path.join("private")).unwrap();
        std::fs::write(path.join("private/selected.bin"), b"approved").unwrap();
        std::fs::write(outside.path().join("selected.bin"), b"approved").unwrap();
        let mut records = vec![record("private/selected.bin", b"approved")];
        match mutation {
            "source-link" => {
                std::fs::remove_file(path.join("private/selected.bin")).unwrap();
                symlink(
                    outside.path().join("selected.bin"),
                    path.join("private/selected.bin"),
                )
                .unwrap();
            }
            "source-parent-link" => {
                std::fs::rename(path.join("private"), path.join("original")).unwrap();
                symlink(outside.path(), path.join("private")).unwrap();
            }
            "external-hardlink" => {
                std::fs::hard_link(path.join("private/selected.bin"), path.join("alias.bin"))
                    .unwrap()
            }
            "destination-link" => {
                std::fs::create_dir(path.join("producer")).unwrap();
                symlink(outside.path(), path.join("producer/private")).unwrap();
            }
            "digest" => records[0].sha256 = "0".repeat(64),
            "escape" => records[0].path = "../selected.bin".into(),
            "duplicate" => records.push(records[0].clone()),
            _ => unreachable!(),
        }
        assert!(
            publish(&path, &cell(records), cutoff()).is_err(),
            "{mutation}"
        );
        assert_eq!(
            std::fs::read(outside.path().join("selected.bin")).unwrap(),
            b"approved"
        );
        assert!(!outside.path().join("cell.json").exists());
    }
}

#[test]
fn overall_byte_plan_and_original_cutoff_are_enforced_before_payload_copy() {
    let owned = tempfile::tempdir().unwrap();
    let path = owned.path().canonicalize().unwrap();
    let records: Vec<_> = (0..9)
        .map(|index| {
            let mut artifact = record(&format!("absent-{index}.bin"), b"");
            artifact.length = MAX_FILE;
            artifact
        })
        .collect();
    assert!(records.iter().all(|record| record.length <= MAX_FILE));
    assert!(records.iter().map(|record| record.length).sum::<u64>() > MAX_PRODUCER_BYTES);
    assert!(publish(&path, &cell(records), cutoff()).is_err());
    assert!(!path.join("producer/absent-0.bin").exists());
    assert!(publish(&path, &cell(vec![]), Instant::now()).is_err());
}
