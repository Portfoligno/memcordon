#![cfg(feature = "test-fixtures")]

use std::fs;
#[cfg(target_os = "linux")]
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use memcordon_platform::test_support::ProcessIdentity;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use memcordon_testkit::run_with_deadline_after;
use memcordon_testkit::{assert_stdout_empty, run_with_deadline};

static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

fn fixture() -> &'static str {
    env!("CARGO_BIN_EXE_memcordon-test-fixture")
}

fn expected_backend() -> &'static str {
    if cfg!(target_os = "linux") {
        "linux-cgroup-v2"
    } else if cfg!(target_os = "windows") {
        "windows-job-object"
    } else {
        panic!("hard-backend contract runs only on Linux or Windows")
    }
}

fn require_backend() {
    let output = Command::new(env!("CARGO_BIN_EXE_memcordon"))
        .args(["probe", "--json"])
        .output()
        .expect("probe should run");
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("probe output should be JSON");
    assert_eq!(value["selected"]["name"], expected_backend());
    assert_eq!(value["selected"]["hard_limit"], true);
}

fn wrapped(arguments: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_memcordon"));
    command.args([
        "run",
        "--enforcement",
        "hard",
        "--memory",
        "8GiB",
        "--",
        fixture(),
    ]);
    command.args(arguments);
    command
}

fn temporary_pid_file() -> PathBuf {
    let number = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "memcordon-certified-{}-{number}.pid",
        std::process::id()
    ))
}

fn read_identity(path: &Path) -> ProcessIdentity {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Ok(value) = fs::read_to_string(path) {
            let mut fields = value.split_whitespace();
            let pid = fields
                .next()
                .and_then(|field| field.parse().ok())
                .expect("PID file should contain a process id");
            let birth = fields
                .next()
                .and_then(|field| field.parse().ok())
                .expect("PID file should contain a birth identity");
            return ProcessIdentity { pid, birth };
        }
        assert!(Instant::now() < deadline, "PID file was not produced");
        thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(target_os = "linux")]
fn read_identities(path: &Path) -> io::Result<Vec<ProcessIdentity>> {
    let contents = fs::read_to_string(path)?;
    contents
        .lines()
        .map(|line| {
            let mut fields = line.split_whitespace();
            let pid = fields
                .next()
                .ok_or_else(|| io::Error::other("identity lacks a process id"))?
                .parse()
                .map_err(io::Error::other)?;
            let birth = fields
                .next()
                .ok_or_else(|| io::Error::other("identity lacks a birth value"))?
                .parse()
                .map_err(io::Error::other)?;
            Ok(ProcessIdentity { pid, birth })
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn wait_for_identities(path: &Path, minimum: usize) -> io::Result<Vec<ProcessIdentity>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(identities) = read_identities(path) {
            if identities.len() >= minimum {
                return Ok(identities);
            }
        }
        if Instant::now() >= deadline {
            return Err(io::Error::other(format!(
                "continual forking fixture did not record {minimum} children"
            )));
        }
        thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn reported_run(
    memory: &str,
    arguments: &[&str],
) -> (memcordon_testkit::ObservedOutput, serde_json::Value) {
    let report_file = temporary_pid_file().with_extension("json");
    let mut command = Command::new(env!("CARGO_BIN_EXE_memcordon"));
    command.args([
        "run",
        "--enforcement",
        "hard",
        "--memory",
        memory,
        "--report",
        "json",
        "--report-file",
    ]);
    command.arg(&report_file).arg("--").arg(fixture());
    command.args(arguments);
    let output = run_with_deadline(&mut command, Duration::from_secs(15))
        .unwrap_or_else(|error| panic!("reported backend run failed: {error}"));
    let report = serde_json::from_slice(
        &fs::read(&report_file).expect("backend JSON report should be written"),
    )
    .expect("backend report should be valid JSON");
    fs::remove_file(report_file).expect("backend report should be removable");
    (output, report)
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn native_containment_case() {
    require_backend();
    let output = run_with_deadline(
        &mut wrapped(&["assert-native-containment", "--memory", "8GiB"]),
        Duration::from_secs(5),
    )
    .unwrap_or_else(|error| panic!("native containment assertion failed: {error}"));
    assert_eq!(output.status.code(), Some(0));
    assert_stdout_empty(&output);
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn wrapper_crash_cleanup_case() {
    require_backend();
    let pid_file = temporary_pid_file();
    let callback_pid_file = pid_file.clone();
    let mut command = wrapped(&["hold", "--duration", "30s"]);
    command.arg("--pid-file").arg(&pid_file);
    let output =
        run_with_deadline_after(&mut command, Duration::from_secs(8), move |wrapper_pid| {
            let child = read_identity(&callback_pid_file);
            memcordon_platform::test_support::force_terminate(wrapper_pid)?;
            let deadline = Instant::now() + Duration::from_secs(5);
            while child.still_exists()? && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            if child.still_exists()? {
                Err(std::io::Error::other(
                    "native containment left workload alive after wrapper crash",
                ))
            } else {
                Ok(())
            }
        })
        .unwrap_or_else(|error| panic!("wrapper crash scenario failed: {error}"));
    assert!(output.status.code().is_none() || cfg!(windows));
    fs::remove_file(pid_file).expect("PID file should be removable");
}

#[test]
#[ignore = "requires the protected certified backend runner"]
fn certified_backend_preserves_ordinary_status_and_reaps() {
    require_backend();
    let output = run_with_deadline(
        &mut wrapped(&["exit", "--code", "37"]),
        Duration::from_secs(5),
    )
    .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        output.status.code(),
        Some(37),
        "stdout={:?}; stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_stdout_empty(&output);
}

#[test]
#[ignore = "requires the protected certified backend runner"]
fn certified_backend_reports_limit_and_removes_workload() {
    require_backend();
    let mut command = Command::new(env!("CARGO_BIN_EXE_memcordon"));
    command.args([
        "run",
        "--enforcement",
        "hard",
        "--memory",
        "128MiB",
        "--",
        fixture(),
        "allocate",
        "--bytes",
        "256MiB",
        "--hold",
        "30s",
    ]);
    let output = run_with_deadline(&mut command, Duration::from_secs(10))
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        output.status.code(),
        Some(124),
        "stdout={:?}; stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_stdout_empty(&output);
}

#[test]
#[ignore = "requires the protected certified backend runner"]
fn certified_backend_cleans_background_descendant_by_birth_identity() {
    require_backend();
    let pid_file = temporary_pid_file();
    let mut command = wrapped(&["spawn-background", "--child-duration", "30s"]);
    command.arg("--pid-file").arg(&pid_file);
    let output = run_with_deadline(&mut command, Duration::from_secs(5))
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(output.status.code(), Some(0));
    let identity = read_identity(&pid_file);
    assert!(
        !identity
            .still_exists()
            .expect("process identity query should succeed"),
        "certified backend left descendant {identity:?} alive"
    );
    fs::remove_file(pid_file).expect("PID file should be removable");
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn aggregate_tree_limit_case() {
    require_backend();
    let mut command = Command::new(env!("CARGO_BIN_EXE_memcordon"));
    command.args([
        "run",
        "--enforcement",
        "hard",
        "--memory",
        "96MiB",
        "--",
        fixture(),
    ]);
    command.args([
        "spawn-tree",
        "--depth",
        "1",
        "--breadth",
        "4",
        "--leaf-mode",
        "allocate",
    ]);
    let output = run_with_deadline(&mut command, Duration::from_secs(15))
        .unwrap_or_else(|error| panic!("aggregate workload limit failed: {error}"));
    assert_eq!(output.status.code(), Some(124));
    assert_stdout_empty(&output);
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn rapid_process_churn_case() {
    require_backend();
    for iteration in 0..64 {
        let code = [0, 1, 37][iteration % 3];
        let output = run_with_deadline(
            &mut wrapped(&["exit", "--code", &code.to_string()]),
            Duration::from_secs(3),
        )
        .unwrap_or_else(|error| panic!("rapid process {iteration} failed: {error}"));
        assert_eq!(output.status.code(), Some(code));
        assert_stdout_empty(&output);
    }
}

#[test]
#[ignore = "requires the protected certified backend runner"]
fn certified_backend_allows_bounded_transient_burst() {
    require_backend();
    let mut command = Command::new(env!("CARGO_BIN_EXE_memcordon"));
    command.args([
        "run",
        "--enforcement",
        "hard",
        "--memory",
        "256MiB",
        "--",
        fixture(),
        "burst",
        "--bytes",
        "32MiB",
        "--hold",
        "10ms",
    ]);
    let output = run_with_deadline(&mut command, Duration::from_secs(5))
        .unwrap_or_else(|error| panic!("bounded burst failed: {error}"));
    assert_eq!(output.status.code(), Some(0));
    assert_stdout_empty(&output);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires protected Linux cgroup v2 runner"]
fn linux_cgroup_v2_contains_aggregate_tree() {
    aggregate_tree_limit_case();
}

#[cfg(target_os = "windows")]
#[test]
#[ignore = "requires protected Windows Job Object runner"]
fn windows_job_object_contains_aggregate_tree() {
    aggregate_tree_limit_case();
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires protected Linux cgroup v2 runner"]
fn linux_cgroup_v2_handles_rapid_process_churn() {
    rapid_process_churn_case();
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires protected Linux cgroup v2 runner"]
fn linux_cgroup_controls_are_applied_before_target_observation() {
    native_containment_case();
    let (output, report) = reported_run("256MiB", &["exit", "--code", "0"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(report["policy"]["memory_limit_bytes"], 268_435_456_u64);
    assert_eq!(report["backend"]["name"], "linux-cgroup-v2");
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires protected Linux cgroup v2 runner"]
fn linux_memory_events_produce_limit_evidence() {
    let (output, report) = reported_run(
        "128MiB",
        &["allocate", "--bytes", "256MiB", "--hold", "30s"],
    );
    assert_eq!(output.status.code(), Some(124));
    assert_eq!(report["result"]["outcome"], "limit-exceeded");
    assert_eq!(
        report["result"]["limit_evidence"]["backend"],
        "linux-cgroup-v2"
    );
    assert!(
        report["result"]["limit_evidence"]["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("memory.events"))
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires protected Linux cgroup v2 runner"]
fn linux_cleanup_evidence_confirms_empty_reaped_cgroup() {
    let (output, report) = reported_run("8GiB", &["exit", "--code", "0"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(report["cleanup"]["direct_child_reaped"], true);
    assert_eq!(report["cleanup"]["workload_empty"], true);
    assert_eq!(report["cleanup"]["errors"], serde_json::json!([]));
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires protected Linux cgroup v2 runner"]
fn linux_cgroup_identity_is_verified_before_exec() {
    native_containment_case();
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires protected Linux cgroup v2 runner"]
fn linux_guardian_cleans_cgroup_after_wrapper_crash() {
    wrapper_crash_cleanup_case();
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires protected Linux cgroup v2 runner"]
fn linux_cgroup_kill_reaps_continually_forking_workload() {
    require_backend();
    let pid_file = temporary_pid_file();
    let report_file = pid_file.with_extension("json");
    let callback_pid_file = pid_file.clone();
    let mut command = Command::new(env!("CARGO_BIN_EXE_memcordon"));
    command.args([
        "run",
        "--enforcement",
        "hard",
        "--memory",
        "8GiB",
        "--report",
        "json",
        "--report-file",
    ]);
    command
        .arg(&report_file)
        .arg("--")
        .arg(fixture())
        .args(["fork-continually", "--pid-file"])
        .arg(&pid_file);
    let output =
        run_with_deadline_after(&mut command, Duration::from_secs(15), move |wrapper_pid| {
            let identities = wait_for_identities(&callback_pid_file, 8)?;
            let membership = fs::read_to_string(format!("/proc/{}/cgroup", identities[0].pid))?;
            let relative = membership
                .lines()
                .find_map(|line| line.strip_prefix("0::"))
                .ok_or_else(|| io::Error::other("continual child lacks unified cgroup"))?;
            let kill_file = Path::new("/sys/fs/cgroup")
                .join(relative.trim_start_matches('/'))
                .join("cgroup.kill");
            if !kill_file.is_file() {
                return Err(io::Error::other(
                    "continually-forking workload cgroup lacks cgroup.kill",
                ));
            }
            memcordon_platform::test_support::request_interrupt(wrapper_pid)
        })
        .unwrap_or_else(|error| panic!("continual-fork cgroup.kill scenario failed: {error}"));
    assert_eq!(output.status.code(), Some(143));
    let report: serde_json::Value = serde_json::from_slice(
        &fs::read(&report_file).expect("interrupted run should write a report"),
    )
    .expect("interrupted report should be JSON");
    assert_eq!(report["result"]["outcome"], "interrupted");
    assert_eq!(report["cleanup"]["force_attempted"], true);
    assert_eq!(report["cleanup"]["workload_empty"], true);
    assert_eq!(report["cleanup"]["errors"], serde_json::json!([]));
    let identities = read_identities(&pid_file).expect("child identities should remain readable");
    assert!(identities.len() >= 8);
    for identity in identities {
        assert!(
            !identity
                .still_exists()
                .expect("child identity query should succeed"),
            "cgroup.kill left continual-fork child {identity:?} alive"
        );
    }
    fs::remove_file(pid_file).expect("PID list should be removable");
    fs::remove_file(report_file).expect("report should be removable");
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires protected Linux cgroup v2 runner"]
fn linux_supervisor_monitor_error_fails_closed_end_to_end() {
    let pid_file = temporary_pid_file();
    let pid_text = pid_file.to_string_lossy().into_owned();
    let (output, report) = reported_run(
        "8GiB",
        &[
            "monitor-failure",
            "--pid-file",
            &pid_text,
            "--duration",
            "30s",
        ],
    );
    assert_eq!(output.status.code(), Some(125));
    assert_eq!(report["result"]["outcome"], "monitor-failed");
    assert_eq!(report["cleanup"]["force_attempted"], true);
    assert_eq!(report["cleanup"]["workload_empty"], true);
    assert_eq!(report["cleanup"]["errors"], serde_json::json!([]));
    let identity = read_identity(&pid_file);
    assert!(
        !identity
            .still_exists()
            .expect("failed-monitor child identity query should succeed"),
        "monitor failure left target {identity:?} alive"
    );
    fs::remove_file(pid_file).expect("PID file should be removable");
}

#[cfg(target_os = "windows")]
#[test]
#[ignore = "requires protected Windows Job Object runner"]
fn windows_target_is_suspended_until_job_assignment() {
    native_containment_case();
}

#[cfg(target_os = "windows")]
#[test]
#[ignore = "requires protected Windows Job Object runner"]
fn windows_descendants_remain_in_job_and_are_cleaned() {
    certified_backend_cleans_background_descendant_by_birth_identity();
}

#[cfg(target_os = "windows")]
#[test]
#[ignore = "requires protected Windows Job Object runner"]
fn windows_breakaway_descendant_is_not_left_alive() {
    require_backend();
    let output = run_with_deadline(
        &mut wrapped(&["attempt-job-breakaway"]),
        Duration::from_secs(5),
    )
    .unwrap_or_else(|error| panic!("breakaway denial scenario failed: {error}"));
    assert_eq!(output.status.code(), Some(0));
    assert_stdout_empty(&output);
}

#[cfg(target_os = "windows")]
#[test]
#[ignore = "requires protected Windows Job Object runner"]
fn windows_job_notification_produces_limit_evidence() {
    let (output, report) = reported_run(
        "128MiB",
        &["allocate", "--bytes", "256MiB", "--hold", "30s"],
    );
    assert_eq!(output.status.code(), Some(124));
    assert_eq!(
        report["result"]["limit_evidence"]["backend"],
        "windows-job-object"
    );
}

#[cfg(target_os = "windows")]
#[test]
#[ignore = "requires protected Windows Job Object runner"]
fn windows_kill_on_close_cleans_workload() {
    wrapper_crash_cleanup_case();
}

#[cfg(target_os = "windows")]
#[test]
#[ignore = "requires protected Windows Job Object runner"]
fn windows_wrapper_crash_closes_job_and_reaps_descendants() {
    wrapper_crash_cleanup_case();
}

#[cfg(target_os = "windows")]
#[test]
#[ignore = "requires protected Windows Job Object runner"]
fn windows_job_object_handles_rapid_process_churn() {
    rapid_process_churn_case();
}
