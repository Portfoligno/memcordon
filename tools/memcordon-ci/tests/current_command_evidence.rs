use memcordon_ci::current_command_evidence::{
    into_ci_error, require_frontend_pending, retain_failure,
};
use memcordon_testkit::ProcessTestError;
use std::{fs, io, process::ExitStatus};

fn exited(code: i32) -> ExitStatus {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        ExitStatus::from_raw(code << 8)
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::ExitStatusExt;
        ExitStatus::from_raw(code as u32)
    }
}
fn callback() -> ProcessTestError {
    ProcessTestError::Callback {
        error: io::Error::new(
            io::ErrorKind::BrokenPipe,
            "original frontend exited before preparation",
        ),
        stdout: vec![0, 255, 10],
        stderr: b"fixture usage rejection".to_vec(),
        capture_complete: false,
        observed_status: Some(exited(2)),
        termination: Some(exited(137)),
        cleanup: Err("owned retirement remains uncertain".into()),
    }
}
#[test]
fn callback_keeps_binary_streams_statuses_capture_and_cleanup_before_returning_failure() {
    let directory = tempfile::tempdir().unwrap();
    let error = callback();
    retain_failure(directory.path(), &error, 1024).unwrap();
    assert_eq!(
        fs::read(directory.path().join("stdout.bin")).unwrap(),
        [0, 255, 10]
    );
    assert_eq!(
        fs::read(directory.path().join("stderr.bin")).unwrap(),
        b"fixture usage rejection"
    );
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(directory.path().join("command-failure.json")).unwrap())
            .unwrap();
    let observation = &value["observation"];
    assert_eq!(observation["kind"], "callback");
    assert_eq!(observation["error_kind"], "BrokenPipe");
    assert_eq!(observation["observed_status"]["code"], 2);
    assert_eq!(observation["termination"]["code"], 137);
    assert_eq!(observation["capture_complete"], false);
    assert_eq!(
        observation["cleanup"]["Err"],
        "owned retirement remains uncertain"
    );
    assert!(retain_failure(directory.path(), &error, 1024).is_err());
    assert_eq!(
        fs::read(directory.path().join("stdout.bin")).unwrap(),
        [0, 255, 10]
    );
}
#[test]
fn original_cutoff_early_exit_unexpected_wait_and_native_wait_error_are_distinct() {
    assert_eq!(
        require_frontend_pending("association", true, || panic!(
            "expired cutoff must not perform another wait"
        ))
        .unwrap_err()
        .kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(
        require_frontend_pending("association", false, || Ok(0))
            .unwrap_err()
            .kind(),
        io::ErrorKind::BrokenPipe
    );
    require_frontend_pending("association", false, || Ok(258)).unwrap();
    assert_eq!(
        require_frontend_pending("association", false, || Ok(128))
            .unwrap_err()
            .kind(),
        io::ErrorKind::Other
    );
    assert_eq!(
        require_frontend_pending("association", false, || Err(io::Error::from_raw_os_error(
            5
        )))
        .unwrap_err()
        .raw_os_error(),
        Some(5)
    );
}
#[test]
fn absent_capture_and_bounds_do_not_fabricate_empty_streams_or_success() {
    let directory = tempfile::tempdir().unwrap();
    let error = ProcessTestError::Spawn(io::Error::from(io::ErrorKind::NotFound));
    retain_failure(directory.path(), &error, 1024).unwrap();
    assert!(!directory.path().join("stdout.bin").exists());
    assert!(!directory.path().join("stderr.bin").exists());
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(directory.path().join("command-failure.json")).unwrap())
            .unwrap();
    assert_eq!(value["streams_available"], false);
    assert_eq!(value["observation"]["kind"], "spawn");
    let bounded = tempfile::tempdir().unwrap();
    assert!(retain_failure(bounded.path(), &callback(), 1).is_err());
    assert_eq!(fs::read_dir(bounded.path()).unwrap().count(), 0);
}
#[test]
fn custody_failure_preserves_the_original_operational_error() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("stdout.bin"), b"existing").unwrap();
    let failure = into_ci_error(directory.path(), callback(), 1024).to_string();
    assert!(failure.contains("original frontend exited before preparation"));
    assert!(failure.contains("command failure evidence custody failed"));
    assert_eq!(
        fs::read(directory.path().join("stdout.bin")).unwrap(),
        b"existing"
    );
}
#[test]
fn returned_output_is_retained_without_claiming_observer_success() {
    let directory = tempfile::tempdir().unwrap();
    let output = memcordon_testkit::ObservedOutput {
        status: exited(2),
        stdout: vec![255, 0],
        stderr: b"original error".to_vec(),
        elapsed: std::time::Duration::from_millis(4),
    };
    memcordon_ci::current_command_evidence::retain_output(directory.path(), &output, 1024).unwrap();
    assert_eq!(
        fs::read(directory.path().join("stdout.bin")).unwrap(),
        [255, 0]
    );
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(directory.path().join("command-output.json")).unwrap())
            .unwrap();
    assert_eq!(value["status"]["code"], 2);
    assert_eq!(value["status"]["success"], false);
    assert_eq!(
        fs::read(directory.path().join("stderr.bin")).unwrap(),
        b"original error"
    );
}
