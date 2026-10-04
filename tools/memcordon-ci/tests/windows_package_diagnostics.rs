use std::{path::Path, time::Duration};

use memcordon_ci::{
    command::CommandSpec, config, windows_installed_cases::retain_package_operation,
};
use memcordon_testkit::{ProcessTestError, TimeoutObservation};

fn directory() -> tempfile::TempDir {
    if cfg!(unix) {
        tempfile::tempdir_in("/tmp").unwrap()
    } else {
        tempfile::tempdir().unwrap()
    }
}

#[test]
fn actual_failed_install_and_cleanup_preserve_distinct_raw_streams_and_statuses() {
    // This real child exercises diagnostic custody, not Windows installation.
    let owner = directory();
    let binary = owner
        .path()
        .join(if cfg!(windows) { "child.exe" } else { "child" });
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let compiler = CommandSpec::toolchain_program(
        "rustup",
        owner.path(),
        &config::toolchains(root).unwrap().stable,
        "rustc",
        Duration::from_secs(30),
    )
    .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/package_operation_child.rs"))
    .args(["--edition", "2024", "-o"])
    .arg(&binary)
    .output_quiet()
    .unwrap();
    assert!(compiler.status.success(), "{compiler:?}");

    for (operation, expected_stdout, expected_stderr) in [
        (
            "install",
            b"install stdout\xff\n".as_slice(),
            b"install: protected image rejected\xfe\n".as_slice(),
        ),
        (
            "uninstall",
            b"uninstall stdout\xfd\n".as_slice(),
            b"uninstall: native service stop failed\xfc\n".as_slice(),
        ),
    ] {
        let mut command = CommandSpec::new(&binary, owner.path(), Duration::from_secs(5))
            .args(["package", operation])
            .materialize()
            .unwrap();
        let output = memcordon_testkit::run_with_deadline_output_limit(
            &mut command,
            Duration::from_secs(5),
            memcordon_ci::windows_causal_acceptance::MAX_STREAM_BYTES,
        );
        let failure = retain_package_operation(owner.path(), operation, output).unwrap_err();
        assert!(failure.contains("Some(125)"), "{failure}");
        assert!(
            failure.contains(&String::from_utf8_lossy(expected_stderr).into_owned()),
            "{failure}"
        );
        let prefix = owner.path().join(match operation {
            "install" => "package-install",
            "uninstall" => "package-uninstall",
            _ => unreachable!(),
        });
        assert_eq!(
            std::fs::read(prefix.with_extension("stdout.bin")).unwrap(),
            expected_stdout
        );
        assert_eq!(
            std::fs::read(prefix.with_extension("stderr.bin")).unwrap(),
            expected_stderr
        );
        let capture: serde_json::Value =
            serde_json::from_slice(&std::fs::read(prefix.with_extension("capture.json")).unwrap())
                .unwrap();
        assert_eq!(capture["operation"], operation);
        assert_eq!(capture["observed_exit_code"], 125);
        assert_eq!(capture["operation_complete"], true);
        assert_eq!(capture["streams_available"], true);
    }
    // Cleanup cannot overwrite the preceding failed install evidence.
    assert_eq!(
        std::fs::read(owner.path().join("package-install.stderr.bin")).unwrap(),
        b"install: protected image rejected\xfe\n"
    );
    let before = std::fs::read(owner.path().join("package-install.capture.json")).unwrap();
    let duplicate = retain_package_operation(
        owner.path(),
        "install",
        Err(ProcessTestError::Spawn(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "later missing agent",
        ))),
    )
    .unwrap_err();
    assert!(duplicate.contains("retaining package diagnostic"));
    assert_eq!(
        std::fs::read(owner.path().join("package-install.capture.json")).unwrap(),
        before
    );
    let blocked = owner.path().join("blocked-recording");
    std::fs::create_dir(&blocked).unwrap();
    let existing = blocked.join("package-install.stderr.bin");
    std::fs::write(&existing, b"earlier diagnostic must survive").unwrap();
    let mut command = CommandSpec::new(&binary, owner.path(), Duration::from_secs(5))
        .args(["package", "install"])
        .materialize()
        .unwrap();
    let output = memcordon_testkit::run_with_deadline_output_limit(
        &mut command,
        Duration::from_secs(5),
        memcordon_ci::windows_causal_acceptance::MAX_STREAM_BYTES,
    );
    let failure = retain_package_operation(&blocked, "install", output).unwrap_err();
    assert!(failure.contains("Some(125)"), "{failure}");
    assert!(failure.contains("protected image rejected"), "{failure}");
    assert!(
        failure.contains("retaining package diagnostic"),
        "{failure}"
    );
    assert_eq!(
        std::fs::read(existing).unwrap(),
        b"earlier diagnostic must survive"
    );
}

#[test]
fn timeout_snapshots_remain_incomplete_without_fabricated_native_exit() {
    let owner = directory();
    // Valid partial observation fixture: no child status was observed and both
    // readers are pending. This tests recording, not native timeout execution.
    let output = Err(ProcessTestError::Timeout {
        deadline: Duration::from_secs(120),
        stdout: b"partial stdout\xff".to_vec(),
        stderr: b"partial package error\xfe".to_vec(),
        cleanup: Err("native cleanup remains unconfirmed".to_owned()),
        observation: Box::new(TimeoutObservation {
            child_id: 42,
            observed_status: None,
            callback_completed: false,
            spawn_returned: Duration::from_millis(1),
            boundary_admitted: Duration::from_millis(2),
            timeout_observed: Duration::from_secs(120),
            stdout_reader_finished: false,
            stderr_reader_finished: false,
        }),
    });
    let failure = retain_package_operation(owner.path(), "upgrade", output).unwrap_err();
    assert!(failure.contains("capture incomplete"));
    assert!(failure.contains("native cleanup remains unconfirmed"));
    assert!(failure.contains("partial package error"));
    assert_eq!(
        std::fs::read(owner.path().join("package-upgrade.stdout.bin")).unwrap(),
        b"partial stdout\xff"
    );
    assert_eq!(
        std::fs::read(owner.path().join("package-upgrade.stderr.bin")).unwrap(),
        b"partial package error\xfe"
    );
    let capture: serde_json::Value = serde_json::from_slice(
        &std::fs::read(owner.path().join("package-upgrade.capture.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(capture["operation_complete"], false);
    assert_eq!(capture["streams_available"], true);
    assert_eq!(capture["stdout_reader_finished"], false);
    assert_eq!(capture["stderr_reader_finished"], false);
    assert!(capture["observed_exit_code"].is_null());
}

#[test]
fn unavailable_output_records_failure_without_inventing_empty_streams() {
    let owner = directory();
    let output = Err(ProcessTestError::Output(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "bounded output reader failed",
    )));
    let failure = retain_package_operation(owner.path(), "install", output).unwrap_err();
    assert!(failure.contains("bounded output reader failed"));
    assert!(failure.contains("output unavailable"));
    assert!(!owner.path().join("package-install.stdout.bin").exists());
    assert!(!owner.path().join("package-install.stderr.bin").exists());
    let capture: serde_json::Value = serde_json::from_slice(
        &std::fs::read(owner.path().join("package-install.capture.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(capture["operation_complete"], false);
    assert_eq!(capture["streams_available"], false);
    assert!(capture["stdout_reader_finished"].is_null());
    assert!(capture["observed_exit_code"].is_null());
    assert!(
        retain_package_operation(
            owner.path(),
            "unknown",
            Err(ProcessTestError::Spawn(std::io::Error::other(
                "unknown operation"
            )))
        )
        .is_err()
    );
}
