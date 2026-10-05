#![cfg(feature = "test-fixtures")]

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use memcordon_platform::test_support::ProcessIdentity;
#[cfg(unix)]
use memcordon_testkit::run_with_deadline_after;
use memcordon_testkit::{ObservedOutput, assert_stdout_empty, run_with_deadline};

static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CaseRun {
    Executed,
    Unavailable,
}

#[derive(Clone, Copy)]
enum CaseSelection {
    Optional,
    Required,
}

fn select_case(selection: CaseSelection, case: impl FnOnce() -> CaseRun) -> CaseRun {
    let disposition = case();
    if matches!(selection, CaseSelection::Required) {
        assert_eq!(
            disposition,
            CaseRun::Executed,
            "required native scenario backend unavailable"
        );
    }
    disposition
}

#[test]
fn optional_unavailable_is_explicit_and_required_unavailable_fails() {
    assert_eq!(
        select_case(CaseSelection::Optional, || CaseRun::Unavailable),
        CaseRun::Unavailable
    );
    assert!(
        std::panic::catch_unwind(|| select_case(CaseSelection::Required, || CaseRun::Unavailable))
            .is_err()
    );
}

#[test]
fn immediate_success_failure_and_status_are_reaped_and_preserved() {
    select_case(
        CaseSelection::Optional,
        run_immediate_success_failure_and_status_are_reaped_and_preserved,
    );
}

#[test]
#[ignore = "requires available native backend"]
fn required_immediate_success_failure_and_status_are_reaped_and_preserved() {
    select_case(
        CaseSelection::Required,
        run_immediate_success_failure_and_status_are_reaped_and_preserved,
    );
}

#[test]
fn confirmed_limit_has_dedicated_status() {
    select_case(
        CaseSelection::Optional,
        run_confirmed_limit_has_dedicated_status,
    );
}

#[test]
#[ignore = "requires available native backend"]
fn required_confirmed_limit_has_dedicated_status() {
    select_case(
        CaseSelection::Required,
        run_confirmed_limit_has_dedicated_status,
    );
}

#[test]
fn default_command_lifetime_kills_background_descendant_before_return() {
    select_case(
        CaseSelection::Optional,
        run_default_command_lifetime_kills_background_descendant_before_return,
    );
}

#[test]
#[ignore = "requires available native backend"]
fn required_default_command_lifetime_kills_background_descendant_before_return() {
    select_case(
        CaseSelection::Required,
        run_default_command_lifetime_kills_background_descendant_before_return,
    );
}

#[test]
fn command_exit_grace_allows_remaining_workload_to_drain_naturally() {
    select_case(
        CaseSelection::Optional,
        run_command_exit_grace_allows_remaining_workload_to_drain_naturally,
    );
}

#[test]
#[ignore = "requires available native backend"]
fn required_command_exit_grace_allows_remaining_workload_to_drain_naturally() {
    select_case(
        CaseSelection::Required,
        run_command_exit_grace_allows_remaining_workload_to_drain_naturally,
    );
}

#[test]
fn command_exit_grace_force_cleans_survivors_after_expiry() {
    select_case(
        CaseSelection::Optional,
        run_command_exit_grace_force_cleans_survivors_after_expiry,
    );
}

#[test]
#[ignore = "requires available native backend"]
fn required_command_exit_grace_force_cleans_survivors_after_expiry() {
    select_case(
        CaseSelection::Required,
        run_command_exit_grace_force_cleans_survivors_after_expiry,
    );
}

#[test]
fn deadline_remains_authoritative_during_command_exit_grace() {
    select_case(
        CaseSelection::Optional,
        run_deadline_remains_authoritative_during_command_exit_grace,
    );
}

#[test]
#[ignore = "requires available native backend"]
fn required_deadline_remains_authoritative_during_command_exit_grace() {
    select_case(
        CaseSelection::Required,
        run_deadline_remains_authoritative_during_command_exit_grace,
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn workload_lifetime_deadline_cleans_background_descendant() {
    select_case(
        CaseSelection::Optional,
        run_workload_lifetime_deadline_cleans_background_descendant,
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
#[ignore = "requires available native backend"]
fn required_workload_lifetime_deadline_cleans_background_descendant() {
    select_case(
        CaseSelection::Required,
        run_workload_lifetime_deadline_cleans_background_descendant,
    );
}

#[cfg(unix)]
#[test]
fn wrapper_interrupt_is_forwarded_cleaned_and_mapped() {
    select_case(
        CaseSelection::Optional,
        run_wrapper_interrupt_is_forwarded_cleaned_and_mapped,
    );
}

#[cfg(unix)]
#[test]
#[ignore = "requires available native backend"]
fn required_wrapper_interrupt_is_forwarded_cleaned_and_mapped() {
    select_case(
        CaseSelection::Required,
        run_wrapper_interrupt_is_forwarded_cleaned_and_mapped,
    );
}

#[cfg(unix)]
#[test]
fn guardian_kills_workload_after_wrapper_crash() {
    select_case(
        CaseSelection::Optional,
        run_guardian_kills_workload_after_wrapper_crash,
    );
}

#[cfg(unix)]
#[test]
#[ignore = "requires available native backend"]
fn required_guardian_kills_workload_after_wrapper_crash() {
    select_case(
        CaseSelection::Required,
        run_guardian_kills_workload_after_wrapper_crash,
    );
}

fn fixture() -> &'static str {
    env!("CARGO_BIN_EXE_memcordon-test-fixture")
}

fn temporary_pid_file() -> PathBuf {
    let number = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "memcordon-lifecycle-{}-{number}.pid",
        std::process::id()
    ))
}

fn backend_available() -> bool {
    let output = Command::new(env!("CARGO_BIN_EXE_memcordon"))
        .args(["doctor", "--json"])
        .output()
        .expect("probe should run");
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("probe output should be JSON");
    value
        .get("selected")
        .is_some_and(|selected| !selected.is_null())
}

fn configured_iterations(name: &str) -> u32 {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ci/policy.toml");
    let policy: toml::Value =
        toml::from_str(&fs::read_to_string(path).expect("CI policy should be readable"))
            .expect("CI policy should be valid TOML");
    policy["test"][name]
        .as_integer()
        .and_then(|value| value.try_into().ok())
        .filter(|value: &u32| *value > 0)
        .expect("configured iteration count should be positive")
}

fn wrapped(command: impl AsRef<OsStr>, args: &[&str]) -> Command {
    wrapped_with_options(&[], command, args)
}

fn wrapped_with_options(options: &[&str], command: impl AsRef<OsStr>, args: &[&str]) -> Command {
    let mut invocation = Command::new(env!("CARGO_BIN_EXE_memcordon"));
    invocation.args([
        "--enforcement",
        if cfg!(target_os = "macos") {
            "watchdog"
        } else {
            "hard"
        },
    ]);
    invocation.args(options);
    invocation.args(["+8GiB", "--"]);
    invocation.arg(command);
    invocation.args(args);
    invocation
}

fn completed(command: &mut Command, deadline: Duration) -> ObservedOutput {
    run_with_deadline(command, deadline).unwrap_or_else(|error| panic!("{error}"))
}

fn read_identity(path: &Path) -> ProcessIdentity {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        match fs::read_to_string(path) {
            Ok(value) => {
                let mut fields = value.split_whitespace();
                let pid = fields
                    .next()
                    .and_then(|field| field.parse::<u32>().ok())
                    .expect("PID file should contain a process id");
                let birth = fields
                    .next()
                    .and_then(|field| field.parse::<u128>().ok())
                    .expect("PID file should contain a birth identity");
                assert!(
                    fields.next().is_none(),
                    "PID file should contain one identity"
                );
                return ProcessIdentity { pid, birth };
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("PID file was not readable: {error}"),
        }
    }
}

fn assert_process_gone(identity: ProcessIdentity) {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        if !identity
            .still_exists()
            .expect("process identity query should succeed")
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "process identity {identity:?} survived cleanup"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn hard_unavailability_refuses_before_target_execution() {
    select_case(
        CaseSelection::Optional,
        run_hard_unavailability_refuses_before_target_execution,
    );
}

#[test]
#[ignore = "requires unavailable hard backend"]
fn required_hard_unavailability_refuses_before_target_execution() {
    select_case(
        CaseSelection::Required,
        run_hard_unavailability_refuses_before_target_execution,
    );
}

fn run_hard_unavailability_refuses_before_target_execution() -> CaseRun {
    // macOS's available watchdog is distinct from the unavailable hard backend.
    if !cfg!(target_os = "macos") && backend_available() {
        return CaseRun::Unavailable;
    }
    let marker = temporary_pid_file();
    let mut invocation = Command::new(env!("CARGO_BIN_EXE_memcordon"));
    invocation.args([
        "--enforcement",
        "hard",
        "+1GiB",
        "--",
        fixture(),
        "exit",
        "--code",
        "0",
        "--pid-file",
    ]);
    invocation.arg(&marker);
    let output = completed(&mut invocation, Duration::from_secs(2));
    assert_eq!(output.status.code(), Some(125));
    assert!(!marker.exists(), "unavailable hard backend released target");
    CaseRun::Executed
}

fn run_immediate_success_failure_and_status_are_reaped_and_preserved() -> CaseRun {
    if !backend_available() {
        return CaseRun::Unavailable;
    }
    let iterations = configured_iterations("fast_short_child_iterations");
    for iteration in 0..iterations {
        let code = [0, 1, 37][iteration as usize % 3];
        let report_path = temporary_pid_file().with_extension("json");
        let target = wrapped(fixture(), &["exit", "--code", &code.to_string()]);
        let mut command = Command::new(target.get_program());
        command
            .arg("--report")
            .arg(&report_path)
            .args(target.get_args());
        let timeout = if cfg!(target_os = "macos") {
            // Native retirement and result delivery retain a bounded four-second
            // window after the terminal status is observed.
            Duration::from_secs(5)
        } else {
            Duration::from_secs(2)
        };
        let result = run_with_deadline(&mut command, timeout);
        let report = fs::read_to_string(&report_path);
        let output = result
            .unwrap_or_else(|error| panic!("iteration {iteration}: {error}; report={report:?}"));
        assert_eq!(
            output.status.code(),
            Some(code),
            "iteration {iteration}: {}; report={report:?}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_stdout_empty(&output);
        let _: memcordon_core::MemcordonReport = serde_json::from_str(
            &report.expect("successful iteration must retain its execution report"),
        )
        .expect("lifecycle report must remain valid");
        fs::remove_file(report_path).expect("successful lifecycle report should be removable");
    }
    CaseRun::Executed
}

#[cfg(target_os = "macos")]
#[test]
fn macos_system_success_and_failure_smoke_tests_are_bounded() {
    let success = completed(&mut wrapped("/usr/bin/true", &[]), Duration::from_secs(2));
    assert_eq!(success.status.code(), Some(0));
    assert_stdout_empty(&success);
    let failure = completed(&mut wrapped("/usr/bin/false", &[]), Duration::from_secs(2));
    assert_eq!(failure.status.code(), Some(1));
    assert_stdout_empty(&failure);
    let report_file = temporary_pid_file().with_extension("json");
    let mut command = Command::new(env!("CARGO_BIN_EXE_memcordon"));
    command
        .args(["--enforcement", "watchdog", "--report"])
        .arg(&report_file)
        .args(["+8GiB", "--", "/usr/bin/true"]);
    let output = completed(&mut command, Duration::from_secs(5));
    assert_eq!(output.status.code(), Some(0));
    let report: memcordon_core::MemcordonReport =
        serde_json::from_slice(&fs::read(&report_file).unwrap()).unwrap();
    assert_eq!(report.attempts.len(), 1);
    assert!(
        report.attempts[0]
            .launch
            .guardian_started_before_authorization
    );
    fs::remove_file(report_file).unwrap();
}

fn run_confirmed_limit_has_dedicated_status() -> CaseRun {
    if !backend_available() {
        return CaseRun::Unavailable;
    }
    let mut invocation = Command::new(env!("CARGO_BIN_EXE_memcordon"));
    invocation.args([
        "--enforcement",
        if cfg!(target_os = "macos") {
            "watchdog"
        } else {
            "hard"
        },
        if cfg!(target_os = "macos") {
            "+1B"
        } else {
            "+32MiB"
        },
        "--",
        fixture(),
        "allocate",
        "--bytes",
        "64MiB",
        "--hold",
        "30s",
    ]);
    let output = completed(&mut invocation, Duration::from_secs(5));
    assert_eq!(output.status.code(), Some(124));
    assert_stdout_empty(&output);
    CaseRun::Executed
}

fn run_default_command_lifetime_kills_background_descendant_before_return() -> CaseRun {
    if !backend_available() {
        return CaseRun::Unavailable;
    }
    let pid_file = temporary_pid_file();
    let report_file = pid_file.with_extension("json");
    let completion_marker = pid_file.with_extension("completed");
    let mut invocation = Command::new(env!("CARGO_BIN_EXE_memcordon"));
    invocation.args([
        "--enforcement",
        if cfg!(target_os = "macos") {
            "watchdog"
        } else {
            "hard"
        },
        "--report",
    ]);
    invocation.arg(&report_file).args([
        "+8GiB",
        "--",
        fixture(),
        "spawn-background",
        "--child-duration",
        "30s",
    ]);
    invocation
        .arg("--pid-file")
        .arg(&pid_file)
        .arg("--completion-marker")
        .arg(&completion_marker);
    // The outer guard covers native startup, prompt root-exit observation,
    // fixed retirement, report delivery, and harness margin. It must not
    // preempt legitimate cleanup or allow the descendant's 30 s natural exit.
    let harness_budget = memcordon_testkit::harness_budget::natural_root_guard(
        Duration::from_secs(5),
        Duration::from_secs(2),
        Duration::from_secs(3),
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_secs(30),
    )
    .expect("independent root-exit guard must precede natural descendant completion");
    let output = completed(&mut invocation, harness_budget);
    assert_eq!(output.status.code(), Some(0));
    assert_stdout_empty(&output);
    let typed_report: memcordon_core::MemcordonReport = serde_json::from_str(
        &fs::read_to_string(&report_file).expect("lifetime execution report must be readable"),
    )
    .expect("lifetime execution report must be valid");
    let report = serde_json::to_value(&typed_report).unwrap();
    assert_eq!(typed_report.attempts.len(), 1, "{report:#}");
    assert!(
        pid_file.exists(),
        "descendant identity must be published; {report:#}"
    );
    assert!(
        !completion_marker.exists(),
        "descendant must be terminated before natural completion; {report:#}"
    );
    let identity = read_identity(&pid_file);
    assert_process_gone(identity);
    let outcome = &report["attempts"][0]["outcome"];
    assert_eq!(outcome["outcome"], "exited", "{report:#}");
    let cleanup = &outcome["cleanup"];
    assert_eq!(cleanup["direct_child_reaped"], true, "{report:#}");
    assert_eq!(cleanup["workload_empty"], true, "{report:#}");
    assert_eq!(cleanup["force_attempted"], true, "{report:#}");
    assert_eq!(cleanup["errors"], serde_json::json!([]), "{report:#}");
    #[cfg(target_os = "macos")]
    {
        let runtime = typed_report.attempts[0]
            .runtime
            .as_ref()
            .expect("native runtime receipts are required");
        assert!(runtime.is_consistent(), "{runtime:#?}");
        assert!(
            runtime.work_expires.is_none(),
            "default lifetime has no work deadline; {runtime:#?}"
        );
        assert_eq!(
            runtime.startup_expires.checked_sub(runtime.attempt_origin),
            Some(5_000_000_000),
            "{runtime:#?}"
        );
        assert!(
            matches!(
                runtime.release,
                memcordon_core::ReleaseEvidence::Issued {
                    exec_confirmed: true,
                    ..
                }
            ),
            "{runtime:#?}"
        );
        let terminal = runtime
            .terminal_observed
            .expect("root completion observation is required");
        assert!(
            terminal < runtime.startup_expires + 2_000_000_000,
            "{runtime:#?}"
        );
        let force = runtime
            .force_expires
            .expect("original force boundary is required");
        assert!(
            force >= terminal && force < runtime.startup_expires + 2_000_000_000,
            "{runtime:#?}"
        );
        assert_eq!(
            runtime.retirement_expires,
            Some(force + 3_000_000_000),
            "{runtime:#?}"
        );
        assert_eq!(
            runtime.delivery_expires,
            Some(force + 4_000_000_000),
            "{runtime:#?}"
        );
        assert!(runtime.retirement.is_complete(), "{runtime:#?}");
    }
    fs::remove_file(pid_file).expect("temporary PID file should be removable");
    fs::remove_file(report_file).expect("temporary report should be removable");
    CaseRun::Executed
}

fn run_command_exit_grace_allows_remaining_workload_to_drain_naturally() -> CaseRun {
    if !backend_available() {
        return CaseRun::Unavailable;
    }
    let pid_file = temporary_pid_file();
    let completion_marker = pid_file.with_extension("completed");
    let report_file = pid_file.with_extension("json");
    let mut invocation = Command::new(env!("CARGO_BIN_EXE_memcordon"));
    invocation.args([
        "--enforcement",
        if cfg!(target_os = "macos") {
            "watchdog"
        } else {
            "hard"
        },
        "--command-exit-grace",
        "2s",
        "--report",
    ]);
    invocation.arg(&report_file);
    invocation.args([
        "+8GiB",
        "--",
        fixture(),
        "spawn-background",
        "--child-duration",
        "100ms",
        "--exit-code",
        "37",
        "--pid-file",
    ]);
    invocation
        .arg(&pid_file)
        .arg("--completion-marker")
        .arg(&completion_marker);

    let output = completed(&mut invocation, Duration::from_secs(4));
    assert_eq!(
        output.status.code(),
        Some(37),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_stdout_empty(&output);
    assert!(
        completion_marker.exists(),
        "command-exit grace returned before natural completion"
    );
    let identity = read_identity(&pid_file);
    assert_process_gone(identity);
    let report: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&report_file).expect("execution report should be readable"),
    )
    .expect("execution report should be valid JSON");
    assert_eq!(
        report["policy"]["requested"]["command_exit_grace_ms"],
        2_000
    );
    assert_eq!(
        report["policy"]["effective"]["command_exit_grace_ms"],
        2_000
    );
    let cleanup = &report["attempts"][0]["outcome"]["cleanup"];
    assert_eq!(cleanup["direct_child_reaped"], true);
    assert_eq!(cleanup["workload_empty"], true);
    assert_eq!(cleanup["graceful_attempted"], false);
    assert_eq!(cleanup["force_attempted"], false);
    assert_eq!(cleanup["errors"], serde_json::json!([]));
    fs::remove_file(pid_file).expect("temporary PID file should be removable");
    fs::remove_file(completion_marker).expect("completion marker should be removable");
    fs::remove_file(report_file).expect("temporary report should be removable");
    CaseRun::Executed
}

fn run_command_exit_grace_force_cleans_survivors_after_expiry() -> CaseRun {
    if !backend_available() {
        return CaseRun::Unavailable;
    }
    let pid_file = temporary_pid_file();
    let completion_marker = pid_file.with_extension("completed");
    let report_file = pid_file.with_extension("json");
    let mut invocation = Command::new(env!("CARGO_BIN_EXE_memcordon"));
    invocation.args([
        "--enforcement",
        if cfg!(target_os = "macos") {
            "watchdog"
        } else {
            "hard"
        },
        "--command-exit-grace",
        "100ms",
        "--report",
    ]);
    invocation.arg(&report_file);
    invocation.args([
        "+8GiB",
        "--",
        fixture(),
        "spawn-background",
        "--child-duration",
        "30s",
        "--exit-code",
        "37",
        "--pid-file",
    ]);
    invocation
        .arg(&pid_file)
        .arg("--completion-marker")
        .arg(&completion_marker);

    let output = completed(&mut invocation, Duration::from_secs(4));
    assert_eq!(output.status.code(), Some(37));
    assert_stdout_empty(&output);
    assert!(!completion_marker.exists(), "survivor completed naturally");
    let identity = read_identity(&pid_file);
    assert_process_gone(identity);
    let report: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&report_file).expect("execution report should be readable"),
    )
    .expect("execution report should be valid JSON");
    let cleanup = &report["attempts"][0]["outcome"]["cleanup"];
    assert_eq!(cleanup["direct_child_reaped"], true);
    assert_eq!(cleanup["workload_empty"], true);
    assert_eq!(cleanup["graceful_attempted"], false);
    assert_eq!(cleanup["force_attempted"], true);
    assert_eq!(cleanup["errors"], serde_json::json!([]));
    fs::remove_file(pid_file).expect("temporary PID file should be removable");
    fs::remove_file(report_file).expect("temporary report should be removable");
    CaseRun::Executed
}

fn run_deadline_remains_authoritative_during_command_exit_grace() -> CaseRun {
    if !backend_available() {
        return CaseRun::Unavailable;
    }
    let pid_file = temporary_pid_file();
    let completion_marker = pid_file.with_extension("completed");
    let report_file = pid_file.with_extension("json");
    let mut invocation = Command::new(env!("CARGO_BIN_EXE_memcordon"));
    invocation.args([
        "--enforcement",
        if cfg!(target_os = "macos") {
            "watchdog"
        } else {
            "hard"
        },
        "--command-exit-grace",
        "20s",
        "--report",
    ]);
    invocation.arg(&report_file);
    invocation.args([
        "+8GiB",
        "+8s",
        "--",
        fixture(),
        "spawn-background",
        "--child-duration",
        "30s",
        "--pid-file",
    ]);
    invocation
        .arg(&pid_file)
        .arg("--completion-marker")
        .arg(&completion_marker);

    // Startup itself can consume five seconds. This fixture must actually reach
    // root exit with a live descendant to exercise command-exit grace, while
    // retaining one startup-inclusive work cutoff shorter than that grace.
    let output = completed(&mut invocation, Duration::from_secs(15));
    let report_text = fs::read_to_string(&report_file);
    assert_eq!(
        output.status.code(),
        Some(123),
        "{}; execution report: {report_text:?}",
        String::from_utf8_lossy(&output.stderr),
    );
    assert_stdout_empty(&output);
    assert!(
        !completion_marker.exists(),
        "descendant completed naturally"
    );
    let typed_report: memcordon_core::MemcordonReport =
        serde_json::from_str(&report_text.expect("execution report should be readable"))
            .expect("execution report should be valid JSON");
    let report = serde_json::to_value(&typed_report).unwrap();
    assert_eq!(typed_report.attempts.len(), 1, "{report:#}");
    assert!(
        pid_file.exists(),
        "descendant identity was not published; {report:#}; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let identity = read_identity(&pid_file);
    assert_process_gone(identity);
    assert_eq!(report["supervision"]["terminal"]["kind"], "attempt-outcome");
    assert_eq!(
        report["attempts"][0]["outcome"]["outcome"],
        "deadline-exceeded"
    );
    assert_eq!(
        report["policy"]["requested"]["command_exit_grace_ms"],
        20_000
    );
    let outcome = &report["attempts"][0]["outcome"];
    assert_eq!(outcome["deadline"]["duration_ms"], 8_000, "{report:#}");
    #[cfg(windows)]
    let natural_root_exit = memcordon_core::ChildTermination::WindowsStatus { status: 0 };
    #[cfg(not(windows))]
    let natural_root_exit = memcordon_core::ChildTermination::ExitCode { code: 0 };
    assert_eq!(
        outcome["child_after_termination"],
        serde_json::to_value(natural_root_exit).unwrap(),
        "root must exit naturally before deadline cleanup; {report:#}"
    );
    let cleanup = &outcome["cleanup"];
    assert_eq!(cleanup["direct_child_reaped"], true, "{report:#}");
    assert_eq!(cleanup["workload_empty"], true, "{report:#}");
    assert_eq!(cleanup["force_attempted"], true, "{report:#}");
    assert_eq!(cleanup["errors"], serde_json::json!([]), "{report:#}");
    #[cfg(target_os = "macos")]
    {
        let runtime = typed_report.attempts[0]
            .runtime
            .as_ref()
            .expect("native runtime receipts are required");
        assert!(runtime.is_consistent(), "{runtime:#?}");
        let work = runtime
            .work_expires
            .expect("original work cutoff is required");
        assert_eq!(
            work.checked_sub(runtime.run_origin),
            Some(8_000_000_000),
            "{runtime:#?}"
        );
        assert!(
            matches!(
                runtime.release,
                memcordon_core::ReleaseEvidence::Issued { .. }
            ),
            "{runtime:#?}"
        );
        let terminal = runtime
            .terminal_observed
            .expect("terminal receipt is required");
        assert!(
            terminal >= work && terminal < work + 2_000_000_000,
            "{runtime:#?}"
        );
        assert_eq!(runtime.force_expires, Some(work), "{runtime:#?}");
        assert_eq!(
            runtime.retirement_expires,
            Some(work + 3_000_000_000),
            "{runtime:#?}"
        );
        assert_eq!(
            runtime.delivery_expires,
            Some(work + 4_000_000_000),
            "{runtime:#?}"
        );
        assert!(runtime.retirement.is_complete(), "{runtime:#?}");
    }
    fs::remove_file(pid_file).expect("temporary PID file should be removable");
    fs::remove_file(report_file).expect("temporary report should be removable");
    CaseRun::Executed
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn workload_lifetime_waits_for_background_descendant_to_finish_naturally() {
    select_case(CaseSelection::Optional, || {
        assert_natural_workload_completion(
            "100ms",
            natural_workload_harness_guard(Duration::from_millis(100)),
        )
    });
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn natural_workload_completion_starts_retirement_reserve_at_completion() {
    select_case(CaseSelection::Optional, || {
        assert_natural_workload_completion(
            "3500ms",
            natural_workload_harness_guard(Duration::from_millis(3500)),
        )
    });
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
#[ignore = "requires available native backend"]
fn required_workload_lifetime_waits_for_background_descendant_to_finish_naturally() {
    select_case(CaseSelection::Required, || {
        assert_natural_workload_completion(
            "100ms",
            natural_workload_harness_guard(Duration::from_millis(100)),
        )
    });
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
#[ignore = "requires available native backend"]
fn required_natural_workload_completion_starts_retirement_reserve_at_completion() {
    select_case(CaseSelection::Required, || {
        assert_natural_workload_completion(
            "3500ms",
            natural_workload_harness_guard(Duration::from_millis(3500)),
        )
    });
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn natural_workload_harness_guard(child_duration: Duration) -> Duration {
    memcordon_testkit::harness_budget::sum(&[
        Duration::from_secs(5),
        child_duration,
        Duration::from_secs(3),
        Duration::from_secs(1),
        Duration::from_secs(1),
    ])
    .expect("natural workload guard must cover startup, workload, retirement and delivery")
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn assert_natural_workload_completion(child_duration: &str, outer_deadline: Duration) -> CaseRun {
    if !backend_available() {
        return CaseRun::Unavailable;
    }
    let pid_file = temporary_pid_file();
    let completion_marker = pid_file.with_extension("completed");
    let report_file = pid_file.with_extension("json");
    let mut invocation = Command::new(env!("CARGO_BIN_EXE_memcordon"));
    invocation.args([
        "--enforcement",
        if cfg!(target_os = "macos") {
            "watchdog"
        } else {
            "hard"
        },
        "--wait-for",
        "workload",
        "--report",
    ]);
    invocation.arg(&report_file);
    invocation.args(["+8GiB", "--"]);
    invocation.arg(fixture());
    invocation.args([
        "spawn-background",
        "--child-duration",
        child_duration,
        "--exit-code",
        "37",
    ]);
    invocation
        .arg("--pid-file")
        .arg(&pid_file)
        .arg("--completion-marker")
        .arg(&completion_marker);

    let output = completed(&mut invocation, outer_deadline);
    let report = fs::read_to_string(&report_file);
    assert_eq!(
        output.status.code(),
        Some(37),
        "stderr={}; natural_completion_marker={}; report={report:?}",
        String::from_utf8_lossy(&output.stderr),
        completion_marker.exists(),
    );
    let _: serde_json::Value =
        serde_json::from_str(&report.expect("natural completion report should be readable"))
            .expect("natural completion report should be valid JSON");
    assert_stdout_empty(&output);
    assert!(
        completion_marker.exists(),
        "workload completion returned before the descendant's natural completion marker"
    );
    let identity = read_identity(&pid_file);
    assert_process_gone(identity);
    fs::remove_file(pid_file).expect("temporary PID file should be removable");
    fs::remove_file(completion_marker).expect("completion marker should be removable");
    fs::remove_file(report_file).expect("temporary report should be removable");
    CaseRun::Executed
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_workload_lifetime_deadline_cleans_background_descendant() -> CaseRun {
    if !backend_available() {
        return CaseRun::Unavailable;
    }
    let pid_file = temporary_pid_file();
    let report_file = pid_file.with_extension("json");
    let mut invocation = Command::new(env!("CARGO_BIN_EXE_memcordon"));
    invocation.args([
        "--enforcement",
        if cfg!(target_os = "macos") {
            "watchdog"
        } else {
            "hard"
        },
        "--wait-for",
        "workload",
        "--report",
    ]);
    invocation.arg(&report_file);
    invocation.args([
        "+8GiB",
        "+2s",
        "--",
        fixture(),
        "spawn-background",
        "--child-duration",
        "30s",
        "--pid-file",
    ]);
    invocation.arg(&pid_file);

    let output = completed(&mut invocation, Duration::from_secs(5));
    assert_eq!(output.status.code(), Some(123));
    assert_stdout_empty(&output);
    let identity = read_identity(&pid_file);
    assert_process_gone(identity);
    let report: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&report_file).expect("execution report should be readable"),
    )
    .expect("execution report should be valid JSON");
    let cleanup = &report["attempts"][0]["outcome"]["cleanup"];
    assert_eq!(cleanup["direct_child_reaped"], true, "{report:#}");
    assert_eq!(cleanup["workload_empty"], true, "{report:#}");
    assert_eq!(cleanup["errors"], serde_json::json!([]), "{report:#}");
    fs::remove_file(pid_file).expect("temporary PID file should be removable");
    fs::remove_file(report_file).expect("temporary report should be removable");
    CaseRun::Executed
}

#[cfg(unix)]
fn run_wrapper_interrupt_is_forwarded_cleaned_and_mapped() -> CaseRun {
    if !backend_available() {
        return CaseRun::Unavailable;
    }
    let mut invocation = wrapped(fixture(), &["hold", "--duration", "30s"]);
    let output = run_with_deadline_after(&mut invocation, Duration::from_secs(3), |wrapper_pid| {
        thread::sleep(Duration::from_millis(100));
        let wrapper_pid = i32::try_from(wrapper_pid).map_err(io::Error::other)?;
        // SAFETY: this process id belongs to the wrapper just spawned by the test boundary.
        if unsafe { libc::kill(wrapper_pid, libc::SIGINT) } == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    })
    .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(output.status.code(), Some(130));
    assert_stdout_empty(&output);
    CaseRun::Executed
}

#[cfg(target_os = "macos")]
#[test]
fn virtual_metric_is_explicitly_supported() {
    let mut invocation = Command::new(env!("CARGO_BIN_EXE_memcordon"));
    invocation.args([
        "--enforcement",
        "watchdog",
        "--metric",
        "virtual",
        "+1TiB",
        "--",
        "/usr/bin/true",
    ]);
    let output = completed(&mut invocation, Duration::from_secs(2));
    assert_eq!(output.status.code(), Some(0));
    assert_stdout_empty(&output);
}

#[cfg(unix)]
fn run_guardian_kills_workload_after_wrapper_crash() -> CaseRun {
    if !backend_available() {
        return CaseRun::Unavailable;
    }
    let pid_file = temporary_pid_file();
    let callback_pid_file = pid_file.clone();
    let mut invocation = wrapped(fixture(), &["hold", "--duration", "30s"]);
    invocation.arg("--pid-file").arg(&pid_file);
    let output = run_with_deadline_after(
        &mut invocation,
        Duration::from_secs(3),
        move |wrapper_pid| {
            let child_identity = read_identity(&callback_pid_file);
            let wrapper_pid = i32::try_from(wrapper_pid).map_err(io::Error::other)?;
            // SAFETY: this process id belongs to the wrapper just spawned by the test boundary.
            if unsafe { libc::kill(wrapper_pid, libc::SIGKILL) } == -1 {
                return Err(io::Error::last_os_error());
            }
            assert_process_gone(child_identity);
            Ok(())
        },
    )
    .unwrap_or_else(|error| panic!("{error}"));
    assert!(output.status.code().is_none());
    fs::remove_file(pid_file).expect("temporary PID file should be removable");
    CaseRun::Executed
}
