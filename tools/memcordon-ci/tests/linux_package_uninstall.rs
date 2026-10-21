#[path = "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/package_uninstall.rs"]
mod uninstall;

use std::{cell::RefCell, fs};

#[test]
fn cleanup_refusal_restores_package_files_and_preserves_unknown_output() {
    let root = tempfile::tempdir().unwrap();
    let binary = root.path().join("provider");
    let backup = root.path().join("provider-backup");
    let runtime = root.path().join("runtime");
    fs::write(&binary, b"original installed provider").unwrap();
    fs::create_dir(&runtime).unwrap();
    fs::write(runtime.join("unconsumed-output"), b"user bytes").unwrap();
    fs::rename(&binary, &backup).unwrap();
    let events = RefCell::new(Vec::new());
    let error = uninstall::finish(
        backup,
        || {
            events.borrow_mut().push("cleanup");
            fs::remove_dir(&runtime).map_err(|error| error.to_string())
        },
        |_| panic!("refused cleanup must not commit package removal"),
        |backup| {
            events.borrow_mut().push("rollback");
            fs::rename(backup, &binary).map_err(|error| error.to_string())
        },
        || {
            events.borrow_mut().push("reload");
            Ok(())
        },
    )
    .unwrap_err();
    assert!(!error.is_empty());
    assert_eq!(fs::read(&binary).unwrap(), b"original installed provider");
    assert_eq!(
        fs::read(runtime.join("unconsumed-output")).unwrap(),
        b"user bytes"
    );
    assert_eq!(*events.borrow(), ["cleanup", "rollback", "reload"]);
}

#[test]
fn successful_cleanup_commits_only_after_runtime_absence() {
    let root = tempfile::tempdir().unwrap();
    let backup = root.path().join("provider-backup");
    let runtime = root.path().join("runtime");
    fs::write(&backup, b"original installed provider").unwrap();
    fs::create_dir(&runtime).unwrap();
    uninstall::finish(
        backup.clone(),
        || fs::remove_dir(&runtime).map_err(|error| error.to_string()),
        |backup| {
            assert!(!runtime.exists());
            fs::remove_file(backup).map_err(|error| error.to_string())
        },
        |_| panic!("successful cleanup must not roll back"),
        || panic!("successful cleanup must not reload restored units"),
    )
    .unwrap();
    assert!(!backup.exists());
}

#[test]
fn cleanup_primary_survives_failed_compensation_and_reload() {
    let error = uninstall::finish(
        (),
        || Err("original cleanup refusal".into()),
        |_| panic!("failed cleanup cannot commit"),
        |_| Err("original backup restore failed".into()),
        || Err("unit reload failed".into()),
    )
    .unwrap_err();
    assert!(error.starts_with("original cleanup refusal"));
    assert!(error.contains("original backup restore failed"));
    assert!(error.contains("unit reload failed"));
}
