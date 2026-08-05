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

#[cfg(target_os = "linux")]
fn embedding_fixture(memory: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_memcordon-embedding-fixture"));
    command
        .arg("--memcordon")
        .arg(env!("CARGO_BIN_EXE_memcordon"))
        .arg(memory);
    command
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
        .args(["doctor", "--json"])
        .output()
        .expect("probe should run");
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("probe output should be JSON");
    assert_eq!(value["selected"]["name"], expected_backend());
    assert_eq!(value["selected"]["memory"]["supported"], true);
    assert_eq!(value["selected"]["memory"]["class"], "hard");
}

fn wrapped(arguments: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_memcordon"));
    command.args(["--enforcement", "hard", "+8GiB", "--", fixture()]);
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
    command
        .args(["--enforcement", "hard", "--report"])
        .arg(&report_file)
        .arg(memory)
        .arg("--")
        .arg(fixture());
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
        &mut wrapped(&["assert-native-containment", "--limit", "8GiB"]),
        Duration::from_secs(5),
    )
    .unwrap_or_else(|error| panic!("native containment assertion failed: {error}"));
    assert_eq!(output.status.code(), Some(0));
    assert_stdout_empty(&output);
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
#[test]
#[ignore = "requires a qualified platform backend"]
fn canonical_boundaries_preserve_exact_fixture_argv() {
    require_backend();
    let concise_path = temporary_pid_file().with_extension("concise.json");
    let explicit_path = temporary_pid_file().with_extension("explicit.json");
    for (explicit, path) in [(false, &concise_path), (true, &explicit_path)] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_memcordon"));
        command.args(["--enforcement", "hard", "+8GiB"]);
        if explicit {
            command.arg("--");
        }
        command.arg(fixture()).arg("record-argv").arg(path).args([
            "two words",
            "",
            "--leading",
            "+child",
            "--",
        ]);
        let output = run_with_deadline(&mut command, Duration::from_secs(5))
            .unwrap_or_else(|error| panic!("argv recording failed: {error}"));
        assert_eq!(output.status.code(), Some(0));
    }
    let concise: serde_json::Value =
        serde_json::from_slice(&fs::read(&concise_path).expect("concise argv record should exist"))
            .expect("concise argv record should be JSON");
    let explicit: serde_json::Value = serde_json::from_slice(
        &fs::read(&explicit_path).expect("explicit argv record should exist"),
    )
    .expect("explicit argv record should be JSON");
    assert_eq!(concise, explicit);
    assert_eq!(concise[0]["display"], "two words");
    assert_eq!(concise[1]["display"], "");
    assert_eq!(concise[2]["display"], "--leading");
    assert_eq!(concise[3]["display"], "+child");
    assert_eq!(concise[4]["display"], "--");
    fs::remove_file(concise_path).expect("concise argv record should remove");
    fs::remove_file(explicit_path).expect("explicit argv record should remove");
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
        "--enforcement",
        "hard",
        "+128MiB",
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
    command.args(["--enforcement", "hard", "+96MiB", "--", fixture()]);
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
        "--enforcement",
        "hard",
        "+256MiB",
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
    let (output, report) = reported_run("+256MiB", &["exit", "--code", "0"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        report["policy"]["requested"]["memory"]["limit_bytes"],
        268_435_456_u64
    );
    assert_eq!(report["backend"]["name"], "linux-cgroup-v2");
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires protected Linux cgroup v2 runner"]
fn linux_embedding_limiter_blocks_target_until_containment_is_verified() {
    require_backend();
    let output = run_with_deadline(
        embedding_fixture("+8GiB").arg(fixture()).args([
            "assert-native-containment",
            "--limit",
            "8GiB",
        ]),
        Duration::from_secs(5),
    )
    .unwrap_or_else(|error| panic!("embedded limiter containment assertion failed: {error}"));
    assert_eq!(output.status.code(), Some(0));
    assert_stdout_empty(&output);

    let output = run_with_deadline(
        embedding_fixture("+8GiB")
            .arg(fixture())
            .arg("assert-no-memcordon-environment"),
        Duration::from_secs(5),
    )
    .unwrap_or_else(|error| panic!("embedded environment assertion failed: {error}"));
    assert_eq!(output.status.code(), Some(0));
    assert_stdout_empty(&output);

    let output = run_with_deadline(
        embedding_fixture("+128MiB").args([
            fixture(),
            "allocate",
            "--bytes",
            "256MiB",
            "--hold",
            "30s",
        ]),
        Duration::from_secs(10),
    )
    .unwrap_or_else(|error| panic!("embedded limit cleanup failed: {error}"));
    assert_eq!(output.status.code(), Some(124));

    let crash_pid_file = temporary_pid_file().with_extension("embedding-crash.pid");
    let callback_pid_file = crash_pid_file.clone();
    let mut crash = embedding_fixture("+8GiB");
    crash
        .arg(fixture())
        .args(["hold", "--duration", "30s", "--pid-file"])
        .arg(&crash_pid_file);
    let output = run_with_deadline_after(&mut crash, Duration::from_secs(8), move |wrapper_pid| {
        let child = read_identity(&callback_pid_file);
        memcordon_platform::test_support::force_terminate(wrapper_pid)?;
        let deadline = Instant::now() + Duration::from_secs(5);
        while child.still_exists()? && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        if child.still_exists()? {
            Err(io::Error::other(
                "embedded guardian left workload alive after host death",
            ))
        } else {
            Ok(())
        }
    })
    .unwrap_or_else(|error| panic!("embedded guardian cleanup failed: {error}"));
    assert!(output.status.code().is_none());
    fs::remove_file(crash_pid_file).expect("embedding crash PID file should remove");

    let interrupt_pid_file = temporary_pid_file().with_extension("embedding-interrupt.pid");
    let callback_pid_file = interrupt_pid_file.clone();
    let mut interrupted = embedding_fixture("+8GiB");
    interrupted
        .arg(fixture())
        .args(["hold", "--duration", "30s", "--pid-file"])
        .arg(&interrupt_pid_file);
    let output = run_with_deadline_after(
        &mut interrupted,
        Duration::from_secs(8),
        move |wrapper_pid| {
            let child = read_identity(&callback_pid_file);
            // Deliver the interrupt while the backend monitor is in its bounded poll. This
            // regresses the wait-to-next-cycle handoff where the observed signal was consumed.
            thread::sleep(Duration::from_millis(50));
            memcordon_platform::test_support::request_interrupt(wrapper_pid)?;
            let deadline = Instant::now() + Duration::from_secs(5);
            while child.still_exists()? && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            if child.still_exists()? {
                Err(io::Error::other("embedded interrupt left target alive"))
            } else {
                Ok(())
            }
        },
    )
    .unwrap_or_else(|error| panic!("embedded interrupt cleanup failed: {error}"));
    assert_eq!(output.status.code(), Some(143));
    fs::remove_file(interrupt_pid_file).expect("embedding interrupt PID file should remove");
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires protected Linux cgroup v2 runner"]
fn linux_embedding_limiter_preserves_non_utf8_target_argv() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    require_backend();
    let record = temporary_pid_file().with_extension("argv.json");
    let native = OsString::from_vec(vec![b'a', 0xff, b'z']);
    let mut command = embedding_fixture("+8GiB");
    command
        .arg(fixture())
        .arg("record-argv")
        .arg(&record)
        .arg(&native);
    let output = run_with_deadline(&mut command, Duration::from_secs(5))
        .unwrap_or_else(|error| panic!("embedded non-UTF-8 argv run failed: {error}"));
    assert_eq!(output.status.code(), Some(0));
    let recorded: serde_json::Value =
        serde_json::from_slice(&fs::read(&record).expect("native argv record should be written"))
            .expect("native argv record should be JSON");
    assert_eq!(recorded[0]["raw"]["encoding"], "unix-bytes-base64");
    assert_eq!(recorded[0]["raw"]["data"], "Yf96");
    fs::remove_file(record).expect("native argv record should remove");
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires protected Linux cgroup v2 runner"]
fn linux_target_spawn_failures_preserve_native_provenance() {
    use std::os::unix::fs::PermissionsExt;

    require_backend();
    let missing = temporary_pid_file().with_extension("missing-target");
    let report_file = temporary_pid_file().with_extension("missing.json");
    let mut command = Command::new(env!("CARGO_BIN_EXE_memcordon"));
    command
        .args(["--enforcement", "hard", "--report"])
        .arg(&report_file)
        .args(["+8GiB", "--"])
        .arg(&missing);
    let output = run_with_deadline(&mut command, Duration::from_secs(5))
        .unwrap_or_else(|error| panic!("missing-target run failed: {error}"));
    assert_eq!(output.status.code(), Some(127));
    let report: serde_json::Value = serde_json::from_slice(
        &fs::read(&report_file).expect("missing-target report should exist"),
    )
    .expect("missing-target report should be JSON");
    assert_eq!(report["attempts"][0]["phase"], "failed");
    assert!(report["attempts"][0]["target_pid"].as_u64().is_some());
    assert_eq!(report["attempts"][0]["error"]["os_code"], libc::ENOENT);
    assert_eq!(
        report["attempts"][0]["launch"]["containment_verified_before_authorization"],
        true
    );
    assert_eq!(
        report["attempts"][0]["launch"]["guardian_started_before_authorization"],
        false
    );
    fs::remove_file(&report_file).expect("missing-target report should remove");

    let non_executable = temporary_pid_file().with_extension("not-executable");
    fs::write(&non_executable, b"not an executable\n").expect("fixture should write");
    fs::set_permissions(&non_executable, fs::Permissions::from_mode(0o644))
        .expect("fixture permissions should set");
    let report_file = temporary_pid_file().with_extension("not-executable.json");
    let mut command = Command::new(env!("CARGO_BIN_EXE_memcordon"));
    command
        .args(["--enforcement", "hard", "--report"])
        .arg(&report_file)
        .args(["+8GiB", "--"])
        .arg(&non_executable);
    let output = run_with_deadline(&mut command, Duration::from_secs(5))
        .unwrap_or_else(|error| panic!("non-executable target run failed: {error}"));
    assert_eq!(output.status.code(), Some(126));
    let report: serde_json::Value = serde_json::from_slice(
        &fs::read(&report_file).expect("non-executable report should exist"),
    )
    .expect("non-executable report should be JSON");
    assert_eq!(report["attempts"][0]["phase"], "failed");
    assert_eq!(report["attempts"][0]["error"]["os_code"], libc::EACCES);
    fs::remove_file(report_file).expect("non-executable report should remove");
    let mut embedded = embedding_fixture("+8GiB");
    embedded.arg(&non_executable);
    let output = run_with_deadline(&mut embedded, Duration::from_secs(5))
        .unwrap_or_else(|error| panic!("embedded non-executable run failed: {error}"));
    assert_eq!(output.status.code(), Some(126));
    fs::remove_file(non_executable).expect("non-executable fixture should remove");

    let mut embedded_missing = embedding_fixture("+8GiB");
    embedded_missing.arg(&missing);
    let output = run_with_deadline(&mut embedded_missing, Duration::from_secs(5))
        .unwrap_or_else(|error| panic!("embedded missing-target run failed: {error}"));
    assert_eq!(output.status.code(), Some(127));

    let (output, report) = reported_run("+8GiB", &["exit", "--code", "127"]);
    assert_eq!(output.status.code(), Some(127));
    assert_eq!(report["attempts"][0]["phase"], "completed");
    assert_eq!(
        report["attempts"][0]["outcome"]["child"]["kind"],
        "exit-code"
    );
    assert_eq!(report["attempts"][0]["outcome"]["child"]["code"], 127);
    let (output, report) = reported_run("+8GiB", &["exit", "--code", "126"]);
    assert_eq!(output.status.code(), Some(126));
    assert_eq!(report["attempts"][0]["phase"], "completed");
    assert_eq!(report["attempts"][0]["outcome"]["child"]["code"], 126);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires protected Linux cgroup v2 runner"]
fn linux_memory_events_produce_limit_evidence() {
    let (output, report) = reported_run(
        "+128MiB",
        &["allocate", "--bytes", "256MiB", "--hold", "30s"],
    );
    assert_eq!(output.status.code(), Some(124));
    assert_eq!(
        report["attempts"][0]["outcome"]["outcome"],
        "limit-exceeded"
    );
    assert_eq!(
        report["attempts"][0]["outcome"]["evidence"]["backend"],
        "linux-cgroup-v2"
    );
    assert!(
        report["attempts"][0]["outcome"]["evidence"]["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("memory.events"))
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires protected Linux cgroup v2 runner"]
fn linux_cleanup_evidence_confirms_empty_reaped_cgroup() {
    let (output, report) = reported_run("+8GiB", &["exit", "--code", "0"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        report["attempts"][0]["outcome"]["cleanup"]["direct_child_reaped"],
        true
    );
    assert_eq!(
        report["attempts"][0]["outcome"]["cleanup"]["workload_empty"],
        true
    );
    assert_eq!(
        report["attempts"][0]["outcome"]["cleanup"]["errors"],
        serde_json::json!([])
    );
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
fn linux_report_pid_is_the_actual_target_pid() {
    let pid_file = temporary_pid_file();
    let pid_text = pid_file.to_string_lossy().into_owned();
    let (output, report) = reported_run("+8GiB", &["exit", "--code", "0", "--pid-file", &pid_text]);
    assert_eq!(output.status.code(), Some(0));
    let identity = read_identity(&pid_file);
    assert_eq!(report["attempts"][0]["target_pid"], u64::from(identity.pid));
    fs::remove_file(pid_file).expect("PID file should remove");
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires protected Linux cgroup v2 runner"]
fn linux_gate_failures_kill_the_blocked_target_before_fixture_code() {
    use std::os::unix::fs::PermissionsExt;

    use memcordon::{ByteSize, CommandSpec, Limiter, MemcordonExecutable, Policy};

    require_backend();
    let non_executable = temporary_pid_file().with_extension("helper-not-executable");
    fs::write(&non_executable, b"not executable\n").expect("helper fixture should write");
    fs::set_permissions(&non_executable, fs::Permissions::from_mode(0o644))
        .expect("helper fixture permissions should set");
    let missing = temporary_pid_file().with_extension("helper-missing");
    for (case, helper) in [
        ("missing-helper", missing),
        ("non-executable-helper", non_executable.clone()),
        ("wrong-helper-protocol", PathBuf::from(fixture())),
    ] {
        let marker = temporary_pid_file().with_extension(case);
        let helper_display = helper.display().to_string();
        let command = CommandSpec::new(fixture()).args([
            std::ffi::OsString::from("gate-failure"),
            std::ffi::OsString::from("--phase"),
            std::ffi::OsString::from(case),
            std::ffi::OsString::from("--marker"),
            marker.as_os_str().to_owned(),
        ]);
        let error = Limiter::new(Policy::new(ByteSize::gib(8)))
            .memcordon_executable(
                MemcordonExecutable::new(helper).expect("helper test path must be absolute"),
            )
            .command(command)
            .run()
            .expect_err("invalid helper must fail before target execution");
        assert!(error.code.starts_with("MCSETUP-"));
        assert!(
            error.message.contains(&helper_display),
            "helper error must name configured executable: {}",
            error.message
        );
        assert!(!marker.exists(), "{case} released target code");
    }
    fs::remove_file(non_executable).expect("helper fixture should remove");
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires protected Linux cgroup v2 runner"]
fn linux_guardian_kills_process_group_after_wrapper_crash() {
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
    command
        .args(["--enforcement", "hard", "--report"])
        .arg(&report_file)
        .args(["+8GiB", "--"])
        .arg(fixture())
        .args(["fork-continually", "--pid-file"])
        .arg(&pid_file);
    let output =
        run_with_deadline_after(&mut command, Duration::from_secs(15), move |wrapper_pid| {
            let identities = wait_for_identities(&callback_pid_file, 8)?;
            let membership = fs::read_to_string(
                Path::new("/proc")
                    .join(identities[0].pid.to_string())
                    .join("cgroup"),
            )?;
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
    assert_eq!(report["attempts"][0]["outcome"]["outcome"], "interrupted");
    assert_eq!(
        report["attempts"][0]["outcome"]["cleanup"]["force_attempted"],
        true
    );
    assert_eq!(
        report["attempts"][0]["outcome"]["cleanup"]["workload_empty"],
        true
    );
    assert_eq!(
        report["attempts"][0]["outcome"]["cleanup"]["errors"],
        serde_json::json!([])
    );
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
        "+8GiB",
        &[
            "monitor-failure",
            "--pid-file",
            &pid_text,
            "--duration",
            "30s",
        ],
    );
    assert_eq!(output.status.code(), Some(125));
    assert_eq!(
        report["attempts"][0]["outcome"]["outcome"],
        "monitor-failed"
    );
    assert_eq!(
        report["attempts"][0]["outcome"]["cleanup"]["force_attempted"],
        true
    );
    assert_eq!(
        report["attempts"][0]["outcome"]["cleanup"]["workload_empty"],
        true
    );
    assert_eq!(
        report["attempts"][0]["outcome"]["cleanup"]["errors"],
        serde_json::json!([])
    );
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
        "+128MiB",
        &["allocate", "--bytes", "256MiB", "--hold", "30s"],
    );
    assert_eq!(output.status.code(), Some(124));
    assert_eq!(
        report["attempts"][0]["outcome"]["evidence"]["backend"],
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
