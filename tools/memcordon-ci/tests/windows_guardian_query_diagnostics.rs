use std::{path::Path, time::Duration};

use memcordon_ci::{
    command::CommandSpec, config, windows_installed_cases::retain_guardian_query_capture,
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
fn actual_failed_observation_keeps_native_streams_before_assessment_and_refuses_overwrite() {
    // This real failed child tests diagnostic custody, not an installed RPC.
    let owner = directory();
    let child = owner
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
    .arg(&child)
    .output_quiet()
    .unwrap();
    assert!(compiler.status.success(), "{compiler:?}");
    let mut command = CommandSpec::new(&child, owner.path(), Duration::from_secs(5))
        .args(["package", "install"])
        .materialize()
        .unwrap();
    let output = memcordon_testkit::run_with_deadline_output_limit(
        &mut command,
        Duration::from_secs(5),
        16 * 1024,
    );
    retain_guardian_query_capture(owner.path(), &output).unwrap();
    assert_eq!(output.as_ref().unwrap().status.code(), Some(125));
    assert_eq!(
        std::fs::read(owner.path().join("guardian-query.stdout.bin")).unwrap(),
        b"install stdout\xff\n"
    );
    assert_eq!(
        std::fs::read(owner.path().join("guardian-query.stderr.bin")).unwrap(),
        b"install: protected image rejected\xfe\n"
    );
    let before = std::fs::read(owner.path().join("guardian-query.capture.json")).unwrap();
    let capture: serde_json::Value = serde_json::from_slice(&before).unwrap();
    assert_eq!(capture["operation_complete"], true);
    assert_eq!(capture["observed_exit_code"], 125);
    assert!(
        capture["failure"]
            .as_str()
            .unwrap()
            .contains("protected image rejected")
    );
    let duplicate = retain_guardian_query_capture(owner.path(), &output).unwrap_err();
    assert!(duplicate.contains("Some(125)"), "{duplicate}");
    assert!(
        duplicate.contains("protected image rejected"),
        "{duplicate}"
    );
    assert_eq!(
        std::fs::read(owner.path().join("guardian-query.capture.json")).unwrap(),
        before
    );
}

#[test]
fn partial_timeout_and_unavailable_observation_remain_distinct() {
    let owner = directory();
    // Descriptive partial capture: no native status or reader completion was observed.
    let output = Err(ProcessTestError::Timeout {
        deadline: Duration::from_secs(30),
        stdout: b"partial observation\xff".to_vec(),
        stderr: b"partial native error\xfe".to_vec(),
        cleanup: Err("cleanup unconfirmed".into()),
        observation: Box::new(TimeoutObservation {
            child_id: 42,
            observed_status: None,
            callback_completed: false,
            spawn_returned: Duration::from_millis(1),
            boundary_admitted: Duration::from_millis(2),
            timeout_observed: Duration::from_secs(30),
            stdout_reader_finished: false,
            stderr_reader_finished: false,
        }),
    });
    retain_guardian_query_capture(owner.path(), &output).unwrap();
    let capture: serde_json::Value = serde_json::from_slice(
        &std::fs::read(owner.path().join("guardian-query.capture.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(capture["operation_complete"], false);
    assert_eq!(capture["streams_available"], true);
    assert_eq!(capture["stdout_reader_finished"], false);
    assert!(capture["observed_exit_code"].is_null());
    assert!(
        capture["failure"]
            .as_str()
            .unwrap()
            .contains("capture incomplete")
    );
    assert_eq!(
        std::fs::read(owner.path().join("guardian-query.stdout.bin")).unwrap(),
        b"partial observation\xff"
    );

    let absent = directory();
    let output = Err(ProcessTestError::Spawn(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "actual observer unavailable",
    )));
    retain_guardian_query_capture(absent.path(), &output).unwrap();
    let capture: serde_json::Value = serde_json::from_slice(
        &std::fs::read(absent.path().join("guardian-query.capture.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(capture["streams_available"], false);
    assert_eq!(capture["operation_complete"], false);
    assert!(!absent.path().join("guardian-query.stdout.bin").exists());
    assert!(!absent.path().join("guardian-query.stderr.bin").exists());
}
