#![cfg(target_os = "linux")]

use memcordon_ci::command::CommandSpec;
use std::time::{Duration, Instant};

#[test]
fn fast_original_program_remains_live_until_image_observation_finishes() {
    let directory = tempfile::tempdir().unwrap();
    let execution_budget = Duration::from_secs(5);
    // CommandSpec reserves ten seconds outside execution for owned cleanup.
    // The original cutoff must include both allowances before phase admission.
    let deadline = Instant::now() + execution_budget + Duration::from_secs(10);
    let mut observed_pid = None;
    let output = CommandSpec::new("/bin/echo", directory.path(), execution_budget)
        .args(["original-exec-observed"])
        .bounded_until(deadline)
        .output_quiet_with_exec_observation(|child| {
            observed_pid = Some(child.id());
            let image = std::path::PathBuf::from(format!("/proc/{}/exe", child.id()));
            let before = std::fs::read(&image)?;
            std::thread::sleep(Duration::from_millis(30));
            assert_eq!(std::fs::read(&image)?, before);
            Ok(())
        })
        .unwrap();
    assert!(observed_pid.is_some());
    assert!(output.status.success());
    assert_eq!(output.stdout, b"original-exec-observed\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn refused_exec_observation_settles_child_without_running_program() {
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("must-not-exist");
    let mut pid = None;
    let error = CommandSpec::new("/usr/bin/touch", directory.path(), Duration::from_secs(5))
        .args([marker.as_os_str()])
        .output_quiet_with_exec_observation(|child| {
            pid = Some(child.id());
            Err(memcordon_ci::CiError::Message(
                "original image observation refused".into(),
            ))
        })
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("original image observation refused")
    );
    assert!(!marker.exists());
    assert!(!std::path::PathBuf::from(format!("/proc/{}", pid.unwrap())).exists());
}
