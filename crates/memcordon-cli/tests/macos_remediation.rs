#![cfg(all(target_os = "macos", feature = "test-fixtures"))]

use std::ffi::OsString;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use memcordon_core::{CommandSpec, NativeStartupCleanupStateV1, Policy};
use memcordon_platform::test_support::{
    MacosLaunchFault, macos_disarm_timeout, macos_rejects_protocol, macos_startup_fault,
};
use memcordon_testkit::run_with_deadline;

fn image() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_memcordon"))
}
fn fixture() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_memcordon-test-fixture"))
}

fn native_runtime() -> std::sync::MutexGuard<'static, ()> {
    static RUNTIME: std::sync::Mutex<()> = std::sync::Mutex::new(());
    RUNTIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[test]
fn repeated_stop_events_preserve_first_grace_and_retirement_deadline() {
    let _runtime = native_runtime();
    let directory = tempfile::tempdir().unwrap();
    memcordon_platform::test_support::macos_repeated_stop(
        image(),
        fixture(),
        &directory.path().join("signal-ready"),
    )
    .unwrap();
}

#[test]
fn running_guardian_loss_is_prompt_and_never_clean_retirement() {
    let _runtime = native_runtime();
    memcordon_platform::test_support::macos_running_guardian_loss(image(), fixture()).unwrap();
}

#[test]
fn submillisecond_remaining_admission_never_renews_budget() {
    let _runtime = native_runtime();
    memcordon_platform::test_support::macos_submillisecond_deadline(image()).unwrap();
}

#[test]
fn mutation_disabled_guardian_timer_is_detected() {
    let _runtime = native_runtime();
    memcordon_platform::test_support::macos_timer_mutation_detected(image(), fixture()).unwrap();
}

#[test]
fn continuous_clock_jump_expires_original_guardian_deadline() {
    let _runtime = native_runtime();
    memcordon_platform::test_support::macos_clock_jump(image(), fixture()).unwrap();
}

#[test]
fn valid_control_flood_cannot_starve_guardian_deadline() {
    let _runtime = native_runtime();
    memcordon_platform::test_support::macos_control_flood(image(), fixture()).unwrap();
}

#[test]
fn mutation_release_after_cancel_is_detected() {
    let _runtime = native_runtime();
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("forbidden target marker");
    let command = CommandSpec::new(fixture())
        .args([OsString::from("gate-marker"), marker.as_os_str().to_owned()]);
    let _ = macos_startup_fault(
        &command,
        image(),
        MacosLaunchFault::NativeSpawnHeldReleaseAfterCancel,
    )
    .unwrap();
    assert!(
        marker.exists(),
        "release-after-cancel mutation must trip the target marker oracle"
    );
}

#[test]
fn held_native_spawn_publication_is_cancelled_after_startup_expiry() {
    let _runtime = native_runtime();
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("late target marker");
    let command = CommandSpec::new(fixture())
        .args([OsString::from("gate-marker"), marker.as_os_str().to_owned()]);
    let started = Instant::now();
    let diagnostic =
        macos_startup_fault(&command, image(), MacosLaunchFault::NativeSpawnHeld).unwrap();
    assert!(
        diagnostic.launcher_pid.is_some(),
        "native creation phase must be reached"
    );
    assert!(
        started.elapsed() >= Duration::from_secs(1),
        "publication must cross the original startup boundary"
    );
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "late publication must retain bounded cleanup"
    );
    assert!(
        !marker.exists(),
        "expired creation must never execute target code"
    );
    assert!(!diagnostic.release_sent);
    assert!(!diagnostic.exec_confirmed);
    assert_eq!(
        diagnostic.cleanup.state,
        NativeStartupCleanupStateV1::Complete,
        "{diagnostic:?}"
    );
    assert!(diagnostic.is_consistent());
}

#[test]
fn guardian_and_launcher_loss_never_execute_target_marker() {
    let _runtime = native_runtime();
    for fault in [
        MacosLaunchFault::GuardianBeforeArm,
        MacosLaunchFault::GuardianAfterArm,
        MacosLaunchFault::LauncherBeforeExec,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("target marker");
        let command = CommandSpec::new(fixture())
            .args([OsString::from("gate-marker"), marker.as_os_str().to_owned()]);
        let diagnostic = macos_startup_fault(&command, image(), fault).unwrap();
        assert!(!marker.exists());
        assert!(!diagnostic.exec_confirmed);
        assert!(diagnostic.is_consistent());
    }
}

#[test]
fn missing_helper_and_unacknowledged_readiness_have_bounded_typed_failures() {
    let _runtime = native_runtime();
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("target");
    let command = CommandSpec::new(fixture())
        .args([OsString::from("gate-marker"), marker.as_os_str().to_owned()]);
    let missing = directory.path().join("missing helper");
    let failure = memcordon_platform::run(Policy::unbounded(), &command, &missing).unwrap_err();
    let diagnostic = failure.native_startup.unwrap();
    assert_eq!(diagnostic.native_errno, Some(libc::ENOENT));
    assert_eq!(
        diagnostic.cleanup.state,
        NativeStartupCleanupStateV1::Complete
    );
    assert!(!diagnostic.release_sent);
    let started = Instant::now();
    let failure = memcordon_platform::run(Policy::unbounded(), &command, fixture()).unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(9));
    assert!(!failure.native_startup.unwrap().release_sent);
    assert!(!marker.exists());
}

#[test]
fn disarm_timeout_has_nonblocking_drop_and_eventual_owned_reap() {
    let _runtime = native_runtime();
    macos_disarm_timeout(image()).unwrap();
}

#[test]
fn private_protocol_rejects_truncation_duplicates_and_wrong_binding() {
    let _runtime = native_runtime();
    let body = br#"{"version":2,"run":7,"sequence":0,"message":{"kind":"Ready"}}"#;
    let mut valid = (body.len() as u16).to_be_bytes().to_vec();
    valid.extend_from_slice(body);
    assert!(!macos_rejects_protocol(&valid));
    for body in [
        br#"{"version":1,"run":7,"sequence":0,"message":{"kind":"Ready"}}"#.as_slice(),
        br#"{"version":2,"run":8,"sequence":0,"message":{"kind":"Ready"}}"#.as_slice(),
        br#"{"version":2,"run":7,"run":7,"sequence":0,"message":{"kind":"Ready"}}"#.as_slice(),
        br#"{"version":2,"run":7,"sequence":0,"message":{"kind":"Armed","group":9}}"#.as_slice(),
        br#"{"version":2,"run":7,"sequence":1,"message":{"kind":"Ready"}}"#.as_slice(),
    ] {
        let mut frame = (body.len() as u16).to_be_bytes().to_vec();
        frame.extend_from_slice(body);
        assert!(macos_rejects_protocol(&frame));
        assert!(macos_rejects_protocol(&frame[..frame.len() - 1]));
    }
    assert!(macos_rejects_protocol(&u16::MAX.to_be_bytes()));
}

#[test]
fn installed_layout_probe_works_with_spaces_minimal_path_and_closed_stdio() {
    let _runtime = native_runtime();
    let directory = tempfile::tempdir().unwrap();
    let installed = directory.path().join("installed native image with spaces");
    std::fs::copy(image(), &installed).unwrap();
    let mut probe = Command::new(&installed);
    probe
        .args(["doctor", "--probe-execution", "--json"])
        .env("PATH", "/usr/bin:/bin");
    let output = run_with_deadline(&mut probe, Duration::from_secs(10)).unwrap();
    assert_eq!(output.status.code(), Some(0));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["kind"], "doctor-execution-probe");
    assert_eq!(value["doctor"]["schema_version"], 6);
    assert_eq!(value["execution"]["helper_ready"], true);
    assert_eq!(value["execution"]["target_exec_confirmed"], true);
    assert_eq!(value["execution"]["cleanup_complete"], true);
    let marker = directory.path().join("closed-stdio-marker");
    let mut closed = Command::new(fixture());
    closed
        .arg("macos-closed-stdio")
        .arg(&installed)
        .args(["+2s", "--"])
        .arg(fixture())
        .arg("gate-marker")
        .arg(&marker);
    let output = run_with_deadline(&mut closed, Duration::from_secs(10)).unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(std::fs::read(&marker).unwrap(), b"target-executed\n");
}

#[test]
fn isolated_accounting_reports_memory_limits_and_complete_retirement() {
    let _runtime = native_runtime();
    for metric in ["rss", "physical-footprint"] {
        let directory = tempfile::tempdir().unwrap();
        let report = directory.path().join("memory.json");
        let mut command = Command::new(image());
        command
            .args([
                "+16MiB",
                "+5s",
                "--limit-grace",
                "0ms",
                "--metric",
                metric,
                "--report",
            ])
            .arg(&report)
            .arg("--")
            .arg(fixture())
            .args(["allocate", "--bytes", "64MiB", "--hold", "20s"]);
        let output = run_with_deadline(&mut command, Duration::from_secs(9)).unwrap();
        assert_eq!(
            output.status.code(),
            Some(124),
            "{metric}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let bytes = std::fs::read(report).unwrap();
        let report: memcordon_core::MemcordonReport = serde_json::from_slice(&bytes).unwrap();
        assert!(
            matches!(
                report.attempts[0].runtime.as_ref().unwrap().retirement,
                memcordon_core::RetirementEvidence::Complete { .. }
            ),
            "{:?}",
            report.attempts[0]
        );
        let runtime = report.attempts[0].runtime.as_ref().unwrap();
        let force = runtime
            .force_requested
            .expect("guardian's actual force request receipt");
        assert!(force >= runtime.terminal_observed.unwrap());
        assert!(force <= runtime.retirement_expires.unwrap());
    }
}

#[test]
fn native_accounting_backend_preserves_consistent_retirement() {
    let _runtime = native_runtime();
    let mut command = Command::new(fixture());
    command
        .arg("macos-accounting-backend")
        .arg(image())
        .arg(fixture());
    let output = run_with_deadline(&mut command, Duration::from_secs(10)).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn large_poll_interval_cannot_postpone_a_short_deadline() {
    let _runtime = native_runtime();
    let mut command = Command::new(image());
    command
        .args(["+1GiB", "+100ms", "--poll-interval", "30s", "--"])
        .arg(fixture())
        .args(["hold", "--duration", "30s"]);
    let started = Instant::now();
    let output = run_with_deadline(&mut command, Duration::from_secs(3)).unwrap();
    assert_eq!(output.status.code(), Some(123));
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn caller_envelope_owns_descriptor_and_cwd_snapshots_and_rejects_bad_manifests() {
    let _runtime = native_runtime();
    let directory = tempfile::tempdir().unwrap();
    let mut command = Command::new(fixture());
    command.arg("macos-envelope-transfer").arg(directory.path());
    let output = run_with_deadline(&mut command, Duration::from_secs(5)).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn caller_envelope_preserves_native_bytes_signals_limits_umask_and_exact_descriptors() {
    let _runtime = native_runtime();
    let directory = tempfile::tempdir().unwrap();
    let mut command = Command::new(fixture());
    command
        .arg("macos-envelope-parent")
        .arg(image())
        .arg(fixture())
        .arg(directory.path());
    let output = run_with_deadline(&mut command, Duration::from_secs(10)).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(directory.path().join("created")).unwrap(),
        b"caller envelope preserved\n"
    );
}

#[test]
fn caller_envelope_preserves_additional_inherited_caller_descriptor() {
    let _runtime = native_runtime();
    let directory = tempfile::tempdir().unwrap();
    let mut command = Command::new(fixture());
    command
        .arg("macos-envelope-caller")
        .arg(image())
        .arg(fixture())
        .arg(directory.path());
    let output = run_with_deadline(&mut command, Duration::from_secs(10)).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(directory.path().join("created")).unwrap(),
        b"caller envelope preserved\n"
    );
}

#[test]
fn target_exec_failure_is_distinct_from_reserved_child_exit() {
    let _runtime = native_runtime();
    let directory = tempfile::tempdir().unwrap();
    let report_path = directory.path().join("failed-exec.json");
    let missing = directory.path().join("missing target");
    let mut command = Command::new(image());
    command
        .arg("+2s")
        .arg("--report")
        .arg(&report_path)
        .arg("--")
        .arg(&missing);
    let output = run_with_deadline(&mut command, Duration::from_secs(6)).unwrap();
    assert_eq!(output.status.code(), Some(127));
    let bytes = std::fs::read(&report_path).unwrap();
    let _: memcordon_core::MemcordonReport = serde_json::from_slice(&bytes).unwrap();
    let report: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let diagnostic = &report["supervision"]["terminal"]["error"]["native_startup"];
    assert_eq!(diagnostic["phase"], "target-exec");
    assert_eq!(diagnostic["release_sent"], true);
    assert_eq!(diagnostic["exec_confirmed"], false);
    let denied = directory.path().join("nonexecutable target");
    std::fs::write(&denied, b"native nonexecutable fixture\n").unwrap();
    let mut command = Command::new(image());
    command
        .arg("+2s")
        .arg("--report")
        .arg(&report_path)
        .arg("--")
        .arg(&denied);
    let output = run_with_deadline(&mut command, Duration::from_secs(6)).unwrap();
    assert_eq!(output.status.code(), Some(126));
    let _: memcordon_core::MemcordonReport =
        serde_json::from_slice(&std::fs::read(&report_path).unwrap()).unwrap();
    for code in ["126", "127"] {
        let mut command = Command::new(image());
        command
            .args(["+2s", "--"])
            .arg(fixture())
            .args(["exit", "--code", code]);
        let output = run_with_deadline(&mut command, Duration::from_secs(6)).unwrap();
        assert_eq!(output.status.code(), Some(code.parse().unwrap()));
    }
}

#[test]
fn requested_deadline_expires_during_unacknowledged_startup() {
    let _runtime = native_runtime();
    let policy = Policy::unbounded()
        .with_deadline(Duration::from_millis(100))
        .unwrap();
    let command = CommandSpec::new(fixture()).args(["exit", "--code", "0"]);
    let started = Instant::now();
    let execution = memcordon_platform::run(policy, &command, fixture()).unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(matches!(
        execution.outcome,
        memcordon_core::RunOutcome::DeadlineExceeded { .. }
    ));
    assert!(execution.outcome.cleanup().direct_child_reaped);
    assert_eq!(execution.outcome.cleanup().workload_empty, Some(true));
    assert!(!execution.launch.target_released);
}

#[test]
fn stalled_inspector_is_bounded_and_guardian_retirement_progresses() {
    let _runtime = native_runtime();
    memcordon_platform::test_support::macos_inspector_stall(image()).unwrap();
}

fn read_identity(path: &Path) -> memcordon_platform::test_support::ProcessIdentity {
    let bytes = std::fs::read_to_string(path).unwrap();
    let mut fields = bytes.split_whitespace();
    memcordon_platform::test_support::ProcessIdentity {
        pid: fields.next().unwrap().parse().unwrap(),
        birth: fields.next().unwrap().parse().unwrap(),
    }
}

#[test]
fn stopped_guardian_cleans_observed_descendant_after_root_and_frontend_exit() {
    let _runtime = native_runtime();
    let directory = tempfile::tempdir().unwrap();
    let descendant_marker = directory.path().join("descendant");
    let guardian_marker = directory.path().join("guardian");
    let mut wrapper = Command::new(fixture())
        .arg("macos-custody-wrapper")
        .arg(image())
        .arg(fixture())
        .arg(&descendant_marker)
        .arg(&guardian_marker)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !guardian_marker.exists() && Instant::now() < deadline {
        assert!(
            wrapper.try_wait().unwrap().is_none(),
            "custody fixture exited before readiness"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    if !guardian_marker.exists() {
        let _ = wrapper.kill();
        let _ = wrapper.wait();
        panic!("guardian snapshot readiness timed out");
    }
    let guardian = read_identity(&guardian_marker);
    let descendant = read_identity(&descendant_marker);
    wrapper.kill().unwrap();
    wrapper.wait().unwrap();
    if guardian.still_exists().unwrap() {
        // SAFETY: revalidated fixture identity; orphaned stopped groups may
        // already have received the kernel's automatic SIGHUP/SIGCONT pair.
        assert_eq!(unsafe { libc::kill(guardian.pid as i32, libc::SIGCONT) }, 0);
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    while (descendant.still_exists().unwrap() || guardian.still_exists().unwrap())
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    let descendant_gone = !descendant.still_exists().unwrap();
    let guardian_gone = !guardian.still_exists().unwrap();
    if !descendant_gone {
        memcordon_platform::test_support::force_terminate(descendant.pid).unwrap();
    }
    if !guardian_gone {
        memcordon_platform::test_support::force_terminate(guardian.pid).unwrap();
    }
    assert!(
        descendant_gone && guardian_gone,
        "retained native member identity did not survive loss of root and frontend"
    );
}

#[test]
#[allow(
    clippy::zombie_processes,
    reason = "the complementary lose_frontend branches both kill and reap the wrapper; readiness timeout also reaps"
)]
fn guardian_inspector_stalls_preserve_custody_after_frontend_death() {
    let _runtime = native_runtime();
    for (lanes, lose_frontend) in [("normal", true), ("both", true), ("normal", false)] {
        let directory = tempfile::tempdir().unwrap();
        let mut wrapper = Command::new(fixture())
            .args(["macos-guardian-inspector-wrapper"])
            .arg(image())
            .arg(fixture())
            .arg(directory.path())
            .arg(lanes)
            .spawn()
            .unwrap();
        let ready = directory.path().join("guardian");
        let ready_by = Instant::now() + Duration::from_secs(5);
        while !ready.exists() && Instant::now() < ready_by {
            assert!(
                wrapper.try_wait().unwrap().is_none(),
                "guardian fault fixture exited before readiness"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        if !ready.exists() {
            let _ = wrapper.kill();
            let _ = wrapper.wait();
            panic!("guardian inspector fault barrier not reached");
        }
        let guardian = read_identity(&ready);
        let target = read_identity(&directory.path().join("target"));
        let normal = read_identity(&directory.path().join("normal"));
        let emergency = read_identity(&directory.path().join("emergency"));
        if lose_frontend {
            wrapper.kill().unwrap();
            wrapper.wait().unwrap();
        }
        let stopped_by = Instant::now() + Duration::from_secs(2);
        while target.still_exists().unwrap() && Instant::now() < stopped_by {
            std::thread::sleep(Duration::from_millis(5));
        }
        let target_stopped = !target.still_exists().unwrap();
        let custody_retained = guardian.still_exists().unwrap();
        if !lose_frontend {
            assert!(
                wrapper.try_wait().unwrap().is_none(),
                "frontend exited before guardian deadline observation"
            );
            wrapper.kill().unwrap();
            wrapper.wait().unwrap();
        }
        for helper in [normal, emergency] {
            if helper.still_exists().unwrap() {
                // SAFETY: the exact fixture-owned birth identity is still present.
                assert_eq!(unsafe { libc::kill(helper.pid as i32, libc::SIGCONT) }, 0);
            }
        }
        let retired_by = Instant::now() + Duration::from_secs(3);
        while [guardian, normal, emergency]
            .iter()
            .any(|identity| identity.still_exists().unwrap())
            && Instant::now() < retired_by
        {
            std::thread::sleep(Duration::from_millis(5));
        }
        let retired = [guardian, normal, emergency]
            .iter()
            .all(|identity| !identity.still_exists().unwrap());
        for identity in [target, guardian, normal, emergency] {
            if identity.still_exists().unwrap() {
                let _ = memcordon_platform::test_support::force_terminate(identity.pid);
            }
        }
        assert!(
            target_stopped,
            "guardian timer failed with {lanes} inspectors stopped"
        );
        assert!(
            custody_retained,
            "guardian abandoned a stopped inspector obligation"
        );
        assert!(retired, "resumed inspector obligations did not retire");
    }
}

#[test]
fn bounded_child_slots_and_descriptors_recover_after_repeated_launches() {
    let _runtime = native_runtime();
    memcordon_platform::test_support::macos_resource_recovery(image()).unwrap();
}
