#![cfg(all(target_os = "macos", feature = "test-fixtures"))]

use std::ffi::OsString;
use std::io::Read;
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

fn require_native_backend() {
    let mut probe = Command::new(image());
    probe.args(["doctor", "--json"]);
    let output = run_with_deadline(&mut probe, Duration::from_secs(30))
        .expect("required native backend probe must complete before scenario work begins");
    assert!(
        output.status.success(),
        "native backend probe failed: {output:?}"
    );
    let probe: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("native backend probe must produce its actual JSON observation");
    assert_eq!(
        probe["selected"]["name"], "macos-watchdog",
        "required native scenario backend unavailable: {probe:#}"
    );
    assert_eq!(
        probe["selected"]["containment"]["supported"], true,
        "required native containment unavailable: {probe:#}"
    );
    assert_eq!(
        probe["selected"]["deadline"]["supported"], true,
        "required native deadline unavailable: {probe:#}"
    );
}

struct ReadinessFailureEvidence<'a>(
    &'a memcordon_platform::test_support::StartupDeadlineObservations,
);

impl Drop for ReadinessFailureEvidence<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            // Existing native observations are bounded to two frames/eight slots.
            // Do not resample processes or infer absent birth/final-settlement evidence.
            eprintln!(
                "retained actual native readiness observations: {:#?}",
                self.0
            );
        }
    }
}

fn native_runtime() -> std::sync::MutexGuard<'static, ()> {
    static RUNTIME: std::sync::Mutex<()> = std::sync::Mutex::new(());
    RUNTIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn public_signal_policy(signal: &str, number: i32) {
    use std::os::unix::process::ExitStatusExt;

    let _runtime = native_runtime();
    for policy in ["ignored", "default", "caught", "blocked-default"] {
        for route in ["direct", "supervised"] {
            let directory = tempfile::tempdir().unwrap();
            let marker = directory.path().join("signal-marker");
            let mut command = Command::new(fixture());
            command.args(["macos-signal-parent", signal, policy, route]);
            command.arg(image()).arg(fixture()).arg(&marker);
            let output = run_with_deadline(&mut command, Duration::from_secs(7)).unwrap();
            assert_eq!(
                std::fs::read(&marker).unwrap_or_default(),
                b"signal policy verified\n",
                "{signal}/{policy}/{route}: {}",
                String::from_utf8_lossy(&output.stderr),
            );
            let survives = matches!(policy, "ignored" | "blocked-default");
            assert_eq!(marker.with_extension("completed").exists(), survives);
            if survives {
                assert!(output.status.success(), "{signal}/{policy}/{route}");
            } else if route == "direct" {
                assert_eq!(output.status.signal(), Some(number));
            } else {
                assert_eq!(output.status.code(), Some(128 + number));
            }
            if route == "supervised" {
                let bytes = std::fs::read(marker.with_extension("json")).unwrap();
                let _: memcordon_core::MemcordonReport = serde_json::from_slice(&bytes).unwrap();
                let report: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(report["supervision"]["targets_authorized"], 1);
                assert_eq!(report["attempts"][0]["outcome"]["outcome"], "exited");
            }
        }
    }
}

#[test]
fn public_frontend_preserves_sigint_exec_policy() {
    public_signal_policy("interrupt", libc::SIGINT);
}

#[test]
fn public_frontend_preserves_sigterm_exec_policy() {
    public_signal_policy("terminate", libc::SIGTERM);
}

#[test]
fn public_frontend_preserves_sighup_exec_policy() {
    public_signal_policy("hangup", libc::SIGHUP);
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
    require_native_backend();
    let directory = tempfile::Builder::new()
        .prefix("memcordon-short-deadline-")
        .tempdir_in("/tmp")
        .unwrap();
    let report_path = directory.path().join("deadline.json");
    let mut command = Command::new(image());
    command
        .arg("--report")
        .arg(&report_path)
        .args(["+1GiB", "+100ms", "--poll-interval", "30s", "--"])
        .arg(fixture())
        .args(["hold", "--duration", "30s"]);
    let started = Instant::now();
    // Work expiry is independent of the subsequent native retirement and report
    // delivery reserves. The harness must allow those reserves to finish.
    let harness_budget = Duration::from_millis(100)
        + Duration::from_secs(2)
        + Duration::from_secs(3)
        + Duration::from_secs(1)
        + Duration::from_secs(1);
    let output = run_with_deadline(&mut command, harness_budget).unwrap_or_else(|error| {
        // Retain actual bounded bytes before TempDir cleanup; absent evidence stays absent.
        let evidence = std::fs::File::open(&report_path).and_then(|file| {
            let mut bytes = Vec::new();
            file.take(16 * 1024 + 1).read_to_end(&mut bytes)?;
            let truncated = bytes.len() > 16 * 1024;
            bytes.truncate(16 * 1024);
            Ok((bytes, truncated))
        });
        panic!("short-deadline harness failed; intended phase unconfirmed; {error}; actual report prefix/truncated or read error={evidence:?}");
    });
    let elapsed = started.elapsed();
    let diagnostic = format!(
        "status={:?}; elapsed={elapsed:?}; stdout({} bytes)={:?}; stderr({} bytes)={:?}",
        output.status,
        output.stdout.len(),
        String::from_utf8_lossy(&output.stdout[..output.stdout.len().min(16 * 1024)]),
        output.stderr.len(),
        String::from_utf8_lossy(&output.stderr[..output.stderr.len().min(16 * 1024)]),
    );
    assert_eq!(output.status.code(), Some(123), "{diagnostic}");
    let bytes = std::fs::read(&report_path).expect(&diagnostic);
    let report: memcordon_core::MemcordonReport =
        serde_json::from_slice(&bytes).expect(&diagnostic);
    assert_eq!(report.attempts.len(), 1, "{diagnostic}");
    let runtime = report.attempts[0].runtime.as_ref().expect(&diagnostic);
    assert!(
        short_deadline_runtime_is_valid(runtime),
        "{diagnostic}; {runtime:#?}"
    );
    let report = serde_json::to_value(report).unwrap();
    assert_eq!(
        report["attempts"].as_array().unwrap().len(),
        1,
        "{diagnostic}"
    );
    let outcome = &report["attempts"][0]["outcome"];
    assert_eq!(outcome["outcome"], "deadline-exceeded", "{diagnostic}");
    assert_eq!(outcome["deadline"]["duration_ms"], 100, "{diagnostic}");
    assert_eq!(
        outcome["cleanup"]["direct_child_reaped"], true,
        "{diagnostic}"
    );
    assert_eq!(outcome["cleanup"]["workload_empty"], true, "{diagnostic}");
    assert!(
        outcome["cleanup"]["errors"].as_array().unwrap().is_empty(),
        "{diagnostic}"
    );
}

fn short_deadline_runtime_is_valid(runtime: &memcordon_core::RuntimeEvidenceV1) -> bool {
    use memcordon_core::{ClockDomain, ReleaseEvidence, RetirementEvidence};

    let ClockDomain::DarwinContinuousTicksV1 {
        ticks_per_second, ..
    } = &runtime.clock;
    let ticks = |duration: Duration| u64::try_from(duration.as_nanos()).unwrap();
    let Some(work) = runtime.work_expires else {
        return false;
    };
    let Some(terminal) = runtime.terminal_observed else {
        return false;
    };
    let Some(force) = runtime.force_expires else {
        return false;
    };
    let Some(retire) = runtime.retirement_expires else {
        return false;
    };
    let Some(deliver) = runtime.delivery_expires else {
        return false;
    };
    let RetirementEvidence::Complete { at, .. } = runtime.retirement else {
        return false;
    };
    *ticks_per_second == ticks(Duration::from_secs(1))
        && runtime.is_consistent()
        && work.checked_sub(runtime.run_origin) == Some(ticks(Duration::from_millis(100)))
        && runtime.startup_expires <= work
        && !matches!(runtime.release, ReleaseEvidence::Unknown)
        && match runtime.release {
            ReleaseEvidence::Issued { .. } => runtime.target_pid.is_some(),
            ReleaseEvidence::NotIssued => true,
            ReleaseEvidence::Unknown => false,
        }
        && terminal >= work
        // Preserve the original responsiveness bound at the work observation,
        // rather than incorrectly applying it to cleanup and report delivery.
        && terminal.checked_sub(work).is_some_and(|delay| delay < ticks(Duration::from_secs(2)))
        && force == work
        && retire.checked_sub(force) == Some(ticks(Duration::from_secs(3)))
        && deliver.checked_sub(retire) == Some(ticks(Duration::from_secs(1)))
        && runtime.retirement.is_complete()
        && at <= retire
        && runtime.force_requested.is_none_or(|at| terminal <= at && at <= retire)
}

#[test]
fn short_deadline_runtime_oracle_rejects_late_or_unsettled_evidence() {
    use memcordon_core::{
        ClockDomain, DeliveryEvidence, ReleaseEvidence, RetirementEvidence, RuntimeEvidenceV1,
    };
    let valid = RuntimeEvidenceV1 {
        schema_version: 1,
        clock: ClockDomain::DarwinContinuousTicksV1 {
            boot_identity: "oracle-fixture".into(),
            ticks_per_second: 1_000_000_000,
        },
        run_origin: 1_000_000_000,
        attempt_origin: 1_010_000_000,
        work_expires: Some(1_100_000_000),
        startup_expires: 1_100_000_000,
        release: ReleaseEvidence::NotIssued,
        target_pid: None,
        terminal_observed: Some(1_100_000_000),
        force_requested: None,
        force_expires: Some(1_100_000_000),
        retirement_expires: Some(4_100_000_000),
        delivery_expires: Some(5_100_000_000),
        retirement: RetirementEvidence::Complete {
            at: 4_000_000_000,
            target_reaped_or_absent: true,
            group_reconciled: true,
            detached_identities_discharged: true,
            native_obligations_settled: true,
            policy_retired: true,
        },
        delivery: DeliveryEvidence::Prepared,
    };
    assert!(short_deadline_runtime_is_valid(&valid));
    let mut released = valid.clone();
    released.release = ReleaseEvidence::Issued {
        at: 1_050_000_000,
        exec_confirmed: true,
    };
    released.target_pid = std::num::NonZeroU32::new(42);
    assert!(short_deadline_runtime_is_valid(&released));
    released.release = ReleaseEvidence::Issued {
        at: 1_050_000_000,
        exec_confirmed: false,
    };
    assert!(short_deadline_runtime_is_valid(&released));
    let mut bad = valid.clone();
    bad.terminal_observed = Some(3_100_000_000);
    assert!(bad.is_consistent());
    assert!(!short_deadline_runtime_is_valid(&bad));
    let mut bad = valid.clone();
    bad.work_expires = None;
    assert!(!short_deadline_runtime_is_valid(&bad));
    let mut bad = valid.clone();
    bad.retirement_expires = Some(5_100_000_000);
    bad.delivery_expires = Some(6_100_000_000);
    assert!(!short_deadline_runtime_is_valid(&bad));
    let mut bad = valid.clone();
    bad.delivery_expires = Some(6_100_000_000);
    assert!(!short_deadline_runtime_is_valid(&bad));
    let mut bad = valid.clone();
    bad.release = ReleaseEvidence::Unknown;
    assert!(!short_deadline_runtime_is_valid(&bad));
    let mut bad = valid.clone();
    if let RetirementEvidence::Complete {
        native_obligations_settled,
        ..
    } = &mut bad.retirement
    {
        *native_obligations_settled = false;
    }
    assert!(!short_deadline_runtime_is_valid(&bad));
    let mut bad = valid.clone();
    bad.work_expires = Some(31_000_000_000);
    assert!(!short_deadline_runtime_is_valid(&bad));
    let mut bad = valid.clone();
    bad.terminal_observed = Some(31_000_000_000);
    assert!(!short_deadline_runtime_is_valid(&bad));
    let mut bad = valid.clone();
    bad.release = ReleaseEvidence::Issued {
        at: 1_100_000_000,
        exec_confirmed: true,
    };
    bad.target_pid = std::num::NonZeroU32::new(42);
    assert!(!short_deadline_runtime_is_valid(&bad));
    let mut bad = valid.clone();
    bad.retirement = RetirementEvidence::Unconfirmed { last_owner: None };
    assert!(!short_deadline_runtime_is_valid(&bad));
    let mut bad = valid;
    if let RetirementEvidence::Complete { at, .. } = &mut bad.retirement {
        *at = 4_100_000_001;
    }
    assert!(!short_deadline_runtime_is_valid(&bad));
}

#[test]
fn naturally_exited_inspector_drop_retires_without_suppressing_group_errors() {
    let _runtime = native_runtime();
    memcordon_platform::test_support::macos_inspector_eof_retirement(image()).unwrap();
}

#[test]
fn guardian_readiness_expiry_reports_timeout_after_verified_cleanup() {
    let _runtime = native_runtime();
    require_native_backend();
    for fault in [
        MacosLaunchFault::GuardianReadyExpired,
        MacosLaunchFault::GuardianInspectorsExpired,
    ] {
        let directory = tempfile::Builder::new()
            .prefix("memcordon-startup-deadline-")
            .tempdir_in("/tmp")
            .unwrap();
        let marker = directory.path().join("target marker");
        let command = CommandSpec::new(fixture())
            .args([OsString::from("gate-marker"), marker.as_os_str().to_owned()]);
        let started = Instant::now();
        let observation =
            memcordon_platform::test_support::macos_startup_deadline_fault_observations(
                &command,
                image(),
                fault,
            )
            .unwrap();
        let kind = observation.kind;
        let _failure_evidence = ReadinessFailureEvidence(&observation);
        assert!(
            observation.configuration_written,
            "fixture configuration was not delivered; {fault:?}: {observation:#?}"
        );
        assert!(
            observation.fault_phase_reached,
            "fixture did not reach its acknowledged readiness fault phase; {fault:?}: {observation:#?}"
        );
        let diagnostic = &observation.diagnostic;
        let release = &observation.release;
        assert_eq!(
            kind,
            std::io::ErrorKind::TimedOut,
            "{fault:?}: {observation:#?}"
        );
        assert_eq!(
            diagnostic.native_errno,
            Some(libc::ETIMEDOUT),
            "{fault:?}: {diagnostic:#?}"
        );
        assert!(
            diagnostic.guardian_pid.is_some(),
            "{fault:?}: {diagnostic:#?}"
        );
        assert_eq!(
            diagnostic.phase,
            memcordon_core::NativeStartupPhaseV1::GuardianReadiness
        );
        assert_eq!(*release, memcordon_core::ReleaseEvidence::NotIssued);
        assert!(!marker.exists(), "{fault:?}: {diagnostic:#?}");
        assert!(!diagnostic.guardian_ready, "{fault:?}: {diagnostic:#?}");
        assert!(
            diagnostic.launcher_pid.is_none(),
            "{fault:?}: {diagnostic:#?}"
        );
        assert!(!diagnostic.release_sent, "{fault:?}: {diagnostic:#?}");
        assert!(!diagnostic.exec_confirmed, "{fault:?}: {diagnostic:#?}");
        assert!(
            !observation.cleanup_observations.is_empty(),
            "readiness cleanup must retain its actual native handoff snapshot; {fault:?}: {observation:#?}"
        );
        assert!(
            observation.cleanup_observations.len() <= 2,
            "{observation:#?}"
        );
        let handoff = &observation.cleanup_observations[0];
        assert_eq!(handoff["settlement_finished"], false, "{observation:#?}");
        assert_eq!(
            handoff["normal_inspector_created"],
            fault == MacosLaunchFault::GuardianInspectorsExpired,
            "the configured fault must reach its intended native ownership phase; {observation:#?}"
        );
        for snapshot in &observation.cleanup_observations {
            let sampled = snapshot["observed_at"]
                .as_u64()
                .expect("native cleanup snapshot must retain its sampling time");
            assert!(sampled >= observation.work_expires, "{observation:#?}");
            assert!(sampled <= observation.published_at, "{observation:#?}");
            let slots = snapshot["slots"]
                .as_array()
                .expect("native slot snapshot must be structured");
            assert!(slots.len() <= 8, "{observation:#?}");
        }
        assert_eq!(
            diagnostic.cleanup.state,
            NativeStartupCleanupStateV1::Complete,
            "{fault:?}: {observation:#?}"
        );
        assert!(
            diagnostic.cleanup.errors.is_empty(),
            "{fault:?}: {diagnostic:#?}"
        );
        assert!(diagnostic.is_consistent(), "{fault:?}: {diagnostic:#?}");
        let terminal = observation
            .terminal_observed
            .expect("readiness expiry must retain its original timeout observation");
        let retired = observation
            .retirement_observed
            .expect("complete readiness cleanup must retain its actual native receipt");
        assert!(
            terminal >= observation.work_expires,
            "{fault:?}: {diagnostic:#?}"
        );
        assert!(terminal <= retired, "{fault:?}: {diagnostic:#?}");
        assert!(
            retired <= observation.work_expires + 3_000_000_000,
            "{fault:?}: {diagnostic:#?}"
        );
        assert!(
            retired <= observation.published_at,
            "{fault:?}: {diagnostic:#?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{fault:?}: {diagnostic:#?}"
        );
    }
}

#[test]
fn startup_deadline_observation_precedes_delayed_retirement_and_publication() {
    let _runtime = native_runtime();
    let directory = tempfile::Builder::new()
        .prefix("memcordon-startup-receipts-")
        .tempdir_in("/tmp")
        .unwrap();
    let marker = directory.path().join("target marker");
    let command = CommandSpec::new(fixture())
        .args([OsString::from("gate-marker"), marker.as_os_str().to_owned()]);
    let observation =
        memcordon_platform::test_support::macos_startup_deadline_observations(&command, image())
            .unwrap();
    let diagnostic = &observation.diagnostic;
    assert_eq!(
        observation.kind,
        std::io::ErrorKind::TimedOut,
        "{diagnostic:#?}"
    );
    assert_eq!(
        diagnostic.native_errno,
        Some(libc::ETIMEDOUT),
        "{diagnostic:#?}"
    );
    assert!(diagnostic.guardian_pid.is_some(), "{diagnostic:#?}");
    assert_eq!(
        diagnostic.phase,
        memcordon_core::NativeStartupPhaseV1::GuardianReadiness
    );
    assert_eq!(
        observation.release,
        memcordon_core::ReleaseEvidence::NotIssued
    );
    assert!(!marker.exists());
    assert_eq!(
        diagnostic.cleanup.state,
        NativeStartupCleanupStateV1::Complete
    );
    assert!(diagnostic.cleanup.errors.is_empty(), "{diagnostic:#?}");
    let terminal = observation
        .terminal_observed
        .expect("original timeout observation");
    let retired = observation
        .retirement_observed
        .expect("actual successful native retirement receipt");
    let cutoff = observation.work_expires;
    assert!(
        terminal >= cutoff,
        "timeout must observe original work expiry"
    );
    assert!(
        terminal - cutoff < 2_000_000_000,
        "observation must precede cleanup reserve exhaustion"
    );
    assert!(
        terminal < retired,
        "timeout observation must precede actual native retirement"
    );
    assert!(
        retired >= cutoff + 500_000_000,
        "the configured guardian retirement delay must be exercised"
    );
    assert!(
        retired <= cutoff + 3_000_000_000,
        "retirement must settle within the original reserve"
    );
    assert!(
        observation.published_at >= retired + 400_000_000,
        "publication delay must not rewrite either native receipt"
    );
}

#[test]
fn guardian_loss_is_not_reported_as_clean_startup_deadline() {
    let _runtime = native_runtime();
    let directory = tempfile::Builder::new()
        .prefix("memcordon-startup-loss-")
        .tempdir_in("/tmp")
        .unwrap();
    let marker = directory.path().join("target marker");
    let command = CommandSpec::new(fixture())
        .args([OsString::from("gate-marker"), marker.as_os_str().to_owned()]);
    let (kind, diagnostic, release) =
        memcordon_platform::test_support::macos_startup_deadline_fault(
            &command,
            image(),
            MacosLaunchFault::GuardianBeforeArm,
        )
        .unwrap();
    assert_ne!(kind, std::io::ErrorKind::TimedOut, "{diagnostic:#?}");
    assert_ne!(
        diagnostic.native_errno,
        Some(libc::ETIMEDOUT),
        "{diagnostic:#?}"
    );
    assert_eq!(release, memcordon_core::ReleaseEvidence::NotIssued);
    assert!(!marker.exists(), "{diagnostic:#?}");
    assert!(!diagnostic.release_sent, "{diagnostic:#?}");
    assert!(!diagnostic.exec_confirmed, "{diagnostic:#?}");
    assert_ne!(
        diagnostic.cleanup.state,
        NativeStartupCleanupStateV1::Complete
    );
    assert!(diagnostic.is_consistent(), "{diagnostic:#?}");
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
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(1),
        "elapsed={elapsed:?}; execution={execution:#?}"
    );
    assert!(
        matches!(
            execution.outcome,
            memcordon_core::RunOutcome::DeadlineExceeded { .. }
        ),
        "elapsed={elapsed:?}; execution={execution:#?}"
    );
    assert!(
        execution.outcome.cleanup().direct_child_reaped,
        "elapsed={elapsed:?}; execution={execution:#?}"
    );
    assert_eq!(
        execution.outcome.cleanup().workload_empty,
        Some(true),
        "elapsed={elapsed:?}; execution={execution:#?}"
    );
    assert!(
        !execution.launch.target_released,
        "elapsed={elapsed:?}; execution={execution:#?}"
    );
}

#[test]
fn stalled_inspector_startup_error_retains_native_cause_and_phase() {
    let _runtime = native_runtime();
    let directory = tempfile::tempdir().unwrap();
    let missing_image = directory.path().join("missing-inspector-image");
    let native_error = std::fs::metadata(&missing_image).unwrap_err();
    assert_eq!(native_error.raw_os_error(), Some(libc::ENOENT));
    let error =
        memcordon_platform::test_support::macos_inspector_stall(&missing_image).unwrap_err();
    assert!(
        error.starts_with("stalled inspector normal lane startup: "),
        "{error}"
    );
    assert!(error.contains(&native_error.to_string()), "{error}");
}

#[test]
fn stalled_inspector_is_bounded_and_guardian_retirement_progresses() {
    let _runtime = native_runtime();
    memcordon_platform::test_support::macos_inspector_stall(image()).unwrap();
}

#[test]
fn inspector_natural_exit_cancellation_preserves_actual_owned_reap() {
    let _runtime = native_runtime();
    memcordon_platform::test_support::macos_inspector_cancel_after_exit(image()).unwrap();
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
