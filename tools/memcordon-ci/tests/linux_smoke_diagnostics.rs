#![cfg(unix)]
use diagnostic_projection::{Limit, MAX_ENTRIES, MAX_FILE_BYTES, Projection};
use memcordon_ci::{CiError, Result, diagnostic_projection};
#[path = "../src/release/linux_smoke_diagnostics.rs"]
mod diagnostics;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    time::{Duration, Instant},
};

#[test]
fn copies_actual_private_bytes_without_changing_authority_modes_and_keeps_error() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let source = root.join("authority");
    fs::create_dir(&source).unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(source.join("receipt.json"), b"actual protected observation").unwrap();
    fs::set_permissions(
        source.join("receipt.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let output = root.join("diagnostics");
    let failure: Result<()> = Err(CiError::Message("original primary failure".into()));
    assert_eq!(
        diagnostics::export(
            &source,
            &output,
            Instant::now() + Duration::from_secs(3),
            "primary",
            &failure,
        )
        .unwrap(),
        Projection::Complete
    );
    assert_eq!(
        fs::read(output.join("observations/receipt.json")).unwrap(),
        b"actual protected observation"
    );
    assert_eq!(
        fs::metadata(&source).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(source.join("receipt.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(output.join("observations/receipt.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    let summary: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("diagnostic-export.json")).unwrap()).unwrap();
    assert_eq!(summary["certification_authority"], false);
    assert_eq!(summary["incomplete"], false);
    assert_eq!(summary["completeness"]["status"], "complete");
    assert!(
        summary["operation_error"]
            .as_str()
            .unwrap()
            .contains("original primary failure")
    );
    assert_eq!(
        summary["records"][0]["mode"].as_u64().unwrap() & 0o777,
        0o600
    );
    assert!(
        diagnostics::export(
            &source,
            &output,
            Instant::now() + Duration::from_secs(3),
            "again",
            &Ok(())
        )
        .is_err()
    );
}

#[test]
fn refuses_unsafe_custody_and_expiry_but_records_oversized_projection_loss() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let source = root.join("authority");
    fs::create_dir(&source).unwrap();
    symlink("/", source.join("redirect.json")).unwrap();
    assert!(
        diagnostics::export(
            &source,
            &root.join("out"),
            Instant::now() + Duration::from_secs(3),
            "cleanup",
            &Ok(())
        )
        .is_err()
    );
    assert!(!root.join("out/observations/redirect.json").exists());
    symlink(&source, root.join("alias")).unwrap();
    assert!(
        diagnostics::export(
            &root.join("alias"),
            &root.join("out2"),
            Instant::now() + Duration::from_secs(3),
            "cleanup",
            &Ok(())
        )
        .is_err()
    );
    assert!(
        diagnostics::export(
            &source,
            &root.join("out3"),
            Instant::now(),
            "cleanup",
            &Ok(())
        )
        .is_err()
    );
    fs::remove_file(source.join("redirect.json")).unwrap();
    fs::File::create(source.join("large.json"))
        .unwrap()
        .set_len(MAX_FILE_BYTES + 1)
        .unwrap();
    assert_eq!(
        diagnostics::export(
            &source,
            &root.join("out4"),
            Instant::now() + Duration::from_secs(3),
            "cleanup",
            &Ok(())
        )
        .unwrap(),
        Projection::Incomplete {
            limits: vec![Limit::FileBytes],
            remaining_entries: None
        }
    );
    assert!(!root.join("out4/observations/large.json").exists());
    let summary: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("out4/diagnostic-export.json")).unwrap())
            .unwrap();
    assert_eq!(summary["incomplete"], true);
    assert_eq!(
        summary["completeness"],
        serde_json::to_value(Projection::Incomplete {
            limits: vec![Limit::FileBytes],
            remaining_entries: None
        })
        .unwrap()
    );
    assert!(summary["copy_error"].is_null());
    assert!(summary["operation_error"].is_null());
    assert_eq!(summary["certification_authority"], false);
    assert_eq!(summary["limits"]["file_bytes"], MAX_FILE_BYTES);
    assert_eq!(summary["records"][0]["reason"], "per-file-byte-bound");
}

#[test]
fn hardlink_custody_is_fatal_while_entry_overflow_is_explicit_projection_loss() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let source = root.join("authority");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("original.json"), b"bytes").unwrap();
    fs::hard_link(source.join("original.json"), source.join("alias.json")).unwrap();
    fs::write(source.join("receipt.json"), b"actual retained receipt").unwrap();
    let failure = Err(CiError::Message("recovery failed originally".into()));
    assert!(
        diagnostics::export(
            &source,
            &root.join("out"),
            Instant::now() + Duration::from_secs(3),
            "cleanup",
            &failure
        )
        .is_err()
    );
    let summary: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("out/diagnostic-export.json")).unwrap())
            .unwrap();
    assert!(
        summary["operation_error"]
            .as_str()
            .unwrap()
            .contains("recovery failed originally")
    );
    assert!(summary["copy_error"].as_str().unwrap().contains("custody"));
    assert!(!root.join("out/observations/original.json").exists());
    assert!(!root.join("out/observations/alias.json").exists());
    assert!(summary["incomplete"].as_bool().unwrap());
    assert!(summary["completeness"].is_null());
    fs::remove_file(source.join("alias.json")).unwrap();
    for index in 0..MAX_ENTRIES {
        fs::write(source.join(format!("entry-{index}")), b"").unwrap();
    }
    assert_eq!(
        diagnostics::export(
            &source,
            &root.join("overflow"),
            Instant::now() + Duration::from_secs(3),
            "cleanup",
            &Ok(())
        )
        .unwrap(),
        Projection::Incomplete {
            limits: vec![Limit::Entries],
            remaining_entries: None
        }
    );
    let summary: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("overflow/diagnostic-export.json")).unwrap())
            .unwrap();
    assert_eq!(summary["incomplete"], true);
    assert_eq!(
        summary["completeness"],
        serde_json::to_value(Projection::Incomplete {
            limits: vec![Limit::Entries],
            remaining_entries: None
        })
        .unwrap()
    );
    assert_eq!(summary["visited_entries"], MAX_ENTRIES);
    assert_eq!(summary["records"].as_array().unwrap().len(), MAX_ENTRIES);
    assert_eq!(summary["limits"]["entries"], MAX_ENTRIES);
    assert!(summary["copy_error"].is_null());
    assert!(summary["operation_error"].is_null());
    assert_eq!(summary["certification_authority"], false);
}

#[test]
fn controller_payloads_are_metadata_only_without_using_observation_byte_budget() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let source = root.join("authority");
    fs::create_dir(&source).unwrap();
    // Sparse files exercise the real two-controller size boundary without allocating payloads.
    for name in ["current-linux-owner", "current-linux-owner-again"] {
        fs::File::create(source.join(name))
            .unwrap()
            .set_len(43 * 1024 * 1024)
            .unwrap();
    }
    fs::write(source.join("receipt.json"), b"receipt bytes").unwrap();
    fs::write(source.join("public-deadline.stdout.bin"), b"actual stdout").unwrap();
    assert_eq!(
        diagnostics::export(
            &source,
            &root.join("out"),
            Instant::now() + Duration::from_secs(3),
            "primary",
            &Ok(()),
        )
        .unwrap(),
        Projection::Complete
    );
    let summary: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("out/diagnostic-export.json")).unwrap())
            .unwrap();
    assert_eq!(summary["incomplete"], false);
    assert_eq!(summary["completeness"]["status"], "complete");
    assert_eq!(
        fs::read(root.join("out/observations/receipt.json")).unwrap(),
        b"receipt bytes"
    );
    assert_eq!(
        fs::read(root.join("out/observations/public-deadline.stdout.bin")).unwrap(),
        b"actual stdout"
    );
    for name in ["current-linux-owner", "current-linux-owner-again"] {
        assert!(!root.join("out/observations").join(name).exists());
        let record = summary["records"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["path"] == name)
            .unwrap();
        assert_eq!(record["copied"], false);
        assert_eq!(record["reason"], "outside-observation-projection");
        assert_eq!(record["length"], 43 * 1024 * 1024);
    }
}
