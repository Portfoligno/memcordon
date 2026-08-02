use std::process::Command;

#[test]
fn probe_json_is_machine_readable() {
    let output = Command::new(env!("CARGO_BIN_EXE_memcordon"))
        .args(["probe", "--json"])
        .output()
        .expect("probe should run");
    assert!(output.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("probe must emit JSON");
    assert!(value.get("available").is_some());
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
#[test]
fn command_not_found_maps_to_127() {
    // Linux must establish a delegated cgroup before releasing its launcher, so ordinary hosted
    // runners correctly fail closed before command lookup. macOS and Windows can exercise the
    // wrapper-level spawn classification through their supported native backends.
    let missing_command = std::env::temp_dir().join(format!(
        "memcordon-command-that-does-not-exist-{}{}",
        std::process::id(),
        std::env::consts::EXE_SUFFIX
    ));
    assert!(
        !missing_command.exists(),
        "missing-command fixture unexpectedly exists"
    );
    let output = Command::new(env!("CARGO_BIN_EXE_memcordon"))
        .args(["run", "--enforcement", "auto", "--memory", "1GiB", "--"])
        .arg(missing_command)
        .output()
        .expect("wrapper should run");
    assert_eq!(output.status.code(), Some(127));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("MCSPAWN-NOT-FOUND"),
        "wrapper must report a classified spawn failure"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn hard_mode_fails_before_target_launch_on_macos() {
    let marker = std::env::temp_dir().join(format!("memcordon-marker-{}", std::process::id()));
    let output = Command::new(env!("CARGO_BIN_EXE_memcordon"))
        .args([
            "run",
            "--enforcement",
            "hard",
            "--memory",
            "1GiB",
            "--",
            "/usr/bin/touch",
        ])
        .arg(&marker)
        .output()
        .expect("wrapper should run");
    assert_eq!(output.status.code(), Some(125));
    assert!(!marker.exists(), "hard-mode failure released the target");
}

#[cfg(target_os = "macos")]
#[test]
fn json_report_is_versioned_and_atomic_destination_is_complete() {
    let report = std::env::temp_dir().join(format!("memcordon-report-{}.json", std::process::id()));
    let output = Command::new(env!("CARGO_BIN_EXE_memcordon"))
        .args([
            "run",
            "--enforcement",
            "watchdog",
            "--memory",
            "1GiB",
            "--report",
            "json",
            "--report-file",
        ])
        .arg(&report)
        .args(["--", "/usr/bin/true"])
        .output()
        .expect("wrapper should run");
    assert_eq!(output.status.code(), Some(0));
    let bytes = std::fs::read(&report).expect("report should exist");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("report should be JSON");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["result"]["wrapper_exit_code"], 0);
    assert_eq!(value["cleanup"]["direct_child_reaped"], true);
    std::fs::remove_file(report).expect("test report should be removable");
}
