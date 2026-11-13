#[path = "../src/bin/consumer_readiness_windows/peer_stdout.rs"]
mod stdout;

use std::{fs, io::Write};

#[test]
fn original_held_file_and_typed_stdio_duplicate_produce_empty_product() {
    let root = tempfile::tempdir().unwrap();
    let owner = stdout::Owned::create(root.path(), None).unwrap();
    let stdio = owner.stdio().unwrap();
    drop(stdio);
    owner.finish().unwrap();
    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(root.path().join(stdout::RECORD)).unwrap()).unwrap();
    assert_eq!(record["state"], "empty");
    assert_eq!(record["peer_retired"], true);
    assert_eq!(record["observed_bytes"], 0);
    assert_eq!(record["content_complete"], true);
    assert_eq!(
        record["observed_sha256"],
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(record["identity_from_path_reopen"], false);
    assert_eq!(fs::read(root.path().join(stdout::OUTPUT)).unwrap(), b"");
}

#[test]
fn nonempty_output_fails_and_retains_only_bounded_evidence() {
    let root = tempfile::tempdir().unwrap();
    let owner = stdout::Owned::create(root.path(), None).unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(root.path().join(stdout::OUTPUT))
        .unwrap()
        .write_all(&vec![255; 65537])
        .unwrap();
    let error = owner.finish().unwrap_err();
    assert!(error.to_string().contains("stdout is nonempty"));
    let bytes = fs::read(root.path().join(stdout::RECORD)).unwrap();
    assert!(bytes.len() < 8192);
    let record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(record["observed_bytes"], 65537);
    assert_eq!(record["observed_prefix"].as_array().unwrap().len(), 256);
    assert_eq!(record["content_complete"], false);
    assert!(record["observed_sha256"].is_null());
    assert_eq!(record["state"], "unexpected-output");
}

#[test]
fn collisions_aliases_and_expired_original_cutoff_never_become_empty_success() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join(stdout::OUTPUT), b"existing").unwrap();
    assert!(stdout::Owned::create(root.path(), None).is_err());
    assert_eq!(
        fs::read(root.path().join(stdout::OUTPUT)).unwrap(),
        b"existing"
    );
    let absent = tempfile::tempdir().unwrap();
    assert!(stdout::Owned::create(absent.path(), Some(std::time::Instant::now())).is_err());
    assert!(!absent.path().join(stdout::OUTPUT).exists());

    #[cfg(unix)]
    {
        let aliased = tempfile::tempdir().unwrap();
        let owner = stdout::Owned::create(aliased.path(), None).unwrap();
        fs::hard_link(
            aliased.path().join(stdout::OUTPUT),
            aliased.path().join("alias"),
        )
        .unwrap();
        assert!(
            owner
                .finish()
                .unwrap_err()
                .to_string()
                .contains("single-link ordinary")
        );
        let record: serde_json::Value =
            serde_json::from_slice(&fs::read(aliased.path().join(stdout::RECORD)).unwrap())
                .unwrap();
        assert_eq!(record["state"], "held-readback-error");
        assert!(record["observed_bytes"].is_null());
        let linked = tempfile::tempdir().unwrap();
        let target = linked.path().join("target");
        fs::write(&target, b"preserve").unwrap();
        std::os::unix::fs::symlink(&target, linked.path().join(stdout::OUTPUT)).unwrap();
        assert!(stdout::Owned::create(linked.path(), None).is_err());
        assert_eq!(fs::read(target).unwrap(), b"preserve");
    }
}

#[test]
fn actual_child_output_uses_the_held_stdio_object_and_nonempty_is_rejected() {
    let root = tempfile::tempdir().unwrap();
    let cutoff = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let owner = stdout::Owned::create(root.path(), Some(cutoff)).unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--list")
        .stdout(owner.stdio().unwrap())
        .spawn()
        .unwrap();
    let status = loop {
        if std::time::Instant::now() >= cutoff {
            std::mem::forget(child);
            std::mem::forget(owner);
            panic!("stdout test child retirement unproved at original test cutoff");
        }
        match child.try_wait() {
            Ok(Some(status)) if std::time::Instant::now() < cutoff => break status,
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(1)),
            result => {
                std::mem::forget(child);
                std::mem::forget(owner);
                panic!("stdout test child retirement unavailable: {result:?}");
            }
        }
    };
    assert!(status.success());
    assert!(
        owner
            .finish()
            .unwrap_err()
            .to_string()
            .contains("stdout is nonempty")
    );
    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(root.path().join(stdout::RECORD)).unwrap()).unwrap();
    assert!(record["observed_bytes"].as_u64().unwrap() > 0);
    assert_eq!(record["peer_retired"], true);
}

#[test]
fn unresolved_retirement_never_reads_content_or_claims_empty() {
    let root = tempfile::tempdir().unwrap();
    let owner = stdout::Owned::create(root.path(), None).unwrap();
    owner.unresolved().unwrap();
    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(root.path().join(stdout::RECORD)).unwrap()).unwrap();
    assert_eq!(record["peer_retired"], false);
    assert!(record["observed_bytes"].is_null());
    assert!(record["observed_sha256"].is_null());
    assert_eq!(record["content_complete"], false);
    // The caller retains this actual owner; publication is not settlement.
    drop(owner.stdio().unwrap());
    drop(owner);
}
