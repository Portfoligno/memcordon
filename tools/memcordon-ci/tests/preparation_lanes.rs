use memcordon_ci::{
    CiError,
    command::CommandSpec,
    performance_plan::Layout,
    preparation::{complete_lanes, observed, remaining},
};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[test]
fn both_owners_finish_after_failure_or_panic_in_fixed_result_order() {
    for layout in [Layout::Serial, Layout::Parallel] {
        let observed = Arc::new(Mutex::new(Vec::new()));
        let first = Arc::clone(&observed);
        let second = Arc::clone(&observed);
        let error = complete_lanes(
            layout,
            move || {
                first.lock().unwrap().push("first");
                Err(CiError::Message("first failure".into()))
            },
            move || {
                second.lock().unwrap().push("second");
                Err(CiError::Message("second failure".into()))
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.find("first failure").unwrap() < error.find("second failure").unwrap());
        let mut completed = observed.lock().unwrap().clone();
        completed.sort();
        assert_eq!(completed, ["first", "second"]);
        let done = Arc::new(Mutex::new(false));
        let second = Arc::clone(&done);
        assert!(
            complete_lanes(
                layout,
                || panic!("actual injected owner failure"),
                move || {
                    *second.lock().unwrap() = true;
                    Ok(())
                }
            )
            .is_err()
        );
        assert!(*done.lock().unwrap());
    }
}

#[test]
fn original_group_deadline_caps_each_command_without_renewal() {
    let end = Instant::now() + Duration::from_secs(2);
    assert!(remaining(end, Duration::from_secs(30)).unwrap() <= Duration::from_secs(2));
    assert!(remaining(Instant::now(), Duration::from_secs(30)).is_err());
}

#[test]
fn failed_operation_exposes_child_diagnostics_even_when_collection_fails() {
    #[cfg(unix)]
    let root = tempfile::Builder::new()
        .prefix("memcordon-operation-fixture-")
        .tempdir_in("/tmp")
        .unwrap();
    #[cfg(not(unix))]
    let root = tempfile::Builder::new()
        .prefix("memcordon-operation-fixture-")
        .tempdir()
        .unwrap();
    let executable = std::env::current_exe().unwrap();
    for directory in [root.path().to_path_buf(), root.path().join("absent")] {
        let command = CommandSpec::new(&executable, root.path(), Duration::from_secs(20)).args([
            "--ignored",
            "--exact",
            "failing_operation_child",
            "--nocapture",
        ]);
        let error = observed(command, &directory, "diagnostic-fixture")
            .unwrap_err()
            .to_string();
        assert!(error.contains("operation diagnostic-fixture failed"));
        assert!(error.contains("captured stdout diagnostic"));
        assert!(error.contains("captured stderr diagnostic"));
        if directory == root.path() {
            let stdout =
                std::fs::read_to_string(directory.join("diagnostic-fixture.stdout.bin")).unwrap();
            let stderr =
                std::fs::read_to_string(directory.join("diagnostic-fixture.stderr.bin")).unwrap();
            assert!(stdout.contains("captured stdout diagnostic"));
            assert!(stderr.contains("captured stderr diagnostic"));
        } else {
            assert!(error.contains("stdout collection=Err"));
            assert!(error.contains("stderr collection=Err"));
        }
    }
}

#[test]
#[ignore = "explicit subprocess fixture for failure diagnostics"]
fn failing_operation_child() {
    println!("captured stdout diagnostic");
    eprintln!("captured stderr diagnostic");
    panic!("deliberate child failure");
}
