#![cfg(target_os = "linux")]

mod support;

#[path = "support/retained_streams.rs"]
mod retained_streams;

#[path = "support/concurrency.rs"]
mod concurrency;

#[cfg(feature = "test-support")]
#[path = "support/sealed_faults.rs"]
mod sealed_faults;

use memcordon_sealed_agent::linux::launch::{ExecFailureClass, TargetExecStatus};
use memcordon_sealed_agent::request::Lifetime;
#[cfg(feature = "test-support")]
use memcordon_sealed_agent::{
    linux::launch::{
        FaultExecutionOutcome, FaultPlan, FaultPoint, GuardianTrigger, RetirementOwner,
    },
    rejection::{RejectionCleanupV1, RejectionPhaseV1, RejectionV1},
};

#[cfg(feature = "test-support")]
#[test]
fn staged_frontend_hold_is_ready_live_and_sigkill_reaped() {
    sealed_faults::assert_frontend_hold_lifecycle(std::path::Path::new(support::fixture()));
}

#[cfg(feature = "test-support")]
#[test]
fn staged_frontend_hold_rejects_exit_before_readiness() {
    sealed_faults::assert_frontend_hold_rejects_early_exit(
        std::path::Path::new(support::fixture()),
    );
}

fn run(mode: &str, lifetime: Lifetime) {
    let facts = support::execute(mode, lifetime).expect("native sealed launch must complete");
    assert_eq!(
        facts.child_status, 0,
        "fixture mode {mode} did not complete successfully"
    );
    support::assert_retired(&facts);
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_direct_exit_retires_fresh_boundary() {
    run("exit", Lifetime::Command);
}

#[test]
fn sealed_fixture_deadline_is_future_monotonic_time() {
    let before = memcordon_sealed_agent::linux::clock::monotonic_millis().unwrap();
    let request = support::request("exit", Lifetime::Command).unwrap();
    let after = memcordon_sealed_agent::linux::clock::monotonic_millis().unwrap();
    let deadline = request.policy.absolute_deadline_millis.unwrap();
    assert!(deadline >= before.saturating_add(30_000));
    assert!(deadline <= after.saturating_add(30_000));
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_future_deadline_authorizes_and_retires() {
    let facts = support::execute("exit", Lifetime::Command).unwrap();
    assert_eq!(facts.child_status, 0);
    assert!(!facts.deadline_exceeded);
    assert!(facts.authorization_offset_millis < 30_000);
    support::assert_retired(&facts);
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_expired_deadline_never_authorizes_and_retires() {
    let marker = std::path::Path::new("/tmp/memcordon-sealed-preauthorization-marker");
    let _ = std::fs::remove_file(marker);
    let now = memcordon_sealed_agent::linux::clock::monotonic_millis().unwrap();
    let fixture = support::StagedFixture::new().unwrap();
    let fixture_directory = fixture.directory().to_owned();
    let request = fixture.request_with_deadline("mark", Lifetime::Command, now.saturating_sub(1));
    // SAFETY: getpid has no pointer or ownership requirements and identifies this live frontend.
    let frontend_pid = unsafe { libc::getpid() };
    let (descriptors, attempt) = support::resources(frontend_pid).unwrap();
    let identity = attempt
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let record_path =
        std::path::Path::new(memcordon_sealed_agent::linux::STATE_ROOT).join(&identity);
    let transaction_path = record_path.with_extension("new");
    let cgroup_path =
        std::path::Path::new(memcordon_sealed_agent::linux::CGROUP_ROOT).join(&identity);
    let error = memcordon_sealed_agent::linux::launch::execute(
        request,
        descriptors,
        attempt,
        frontend_pid,
        65_534,
        65_534,
        Vec::new(),
    )
    .expect_err("an expired deadline must fail before gate release");
    assert_eq!(
        error,
        "MCSEALED-AUTHORIZATION: deadline expired before authorization; target was not authorized"
    );
    assert!(
        !marker.exists(),
        "expired target passed its authorization gate"
    );
    assert!(
        !record_path.exists(),
        "failed attempt record was not retired"
    );
    assert!(
        !transaction_path.exists(),
        "failed attempt record transaction was not retired"
    );
    assert!(
        !cgroup_path.exists(),
        "failed attempt cgroup was not retired"
    );
    let ambiguity = memcordon_sealed_agent::linux::recovery::recover().unwrap();
    assert!(
        ambiguity.is_empty(),
        "expired attempt poisoned subsequent recovery: {ambiguity:?}"
    );
    drop(fixture);
    assert!(
        !fixture_directory.exists(),
        "expired attempt leaked its isolated fixture"
    );
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_staged_fixture_is_isolated_and_removed_after_retirement() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let fixture = support::StagedFixture::new().unwrap();
    let second_fixture = support::StagedFixture::new().unwrap();
    let fixture_directory = fixture.directory().to_owned();
    let second_directory = second_fixture.directory().to_owned();
    assert_ne!(fixture_directory, second_directory);
    let directory_metadata = std::fs::symlink_metadata(&fixture_directory).unwrap();
    let program_metadata = std::fs::symlink_metadata(fixture.program()).unwrap();
    assert_eq!(directory_metadata.uid(), 0);
    assert_eq!(directory_metadata.permissions().mode() & 0o777, 0o755);
    assert!(program_metadata.file_type().is_file());
    assert_eq!(program_metadata.uid(), 0);
    assert_eq!(program_metadata.permissions().mode() & 0o777, 0o555);
    let facts = support::execute_request(fixture.request("exit", Lifetime::Command).unwrap())
        .expect("isolated staged fixture must execute as the reduced target identity");
    assert_eq!(facts.child_status, 0);
    support::assert_retired(&facts);
    drop(fixture);
    drop(second_fixture);
    assert!(
        !fixture_directory.exists(),
        "retired attempt leaked its isolated fixture"
    );
    assert!(
        !second_directory.exists(),
        "unused isolated fixture leaked its unique directory"
    );
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_child_outlives_direct_target_until_cleanup() {
    run("child", Lifetime::Command);
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_double_fork_remains_in_pid_namespace_and_cgroup() {
    run("double-fork", Lifetime::Command);
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_setsid_daemon_remains_contained() {
    run("setsid", Lifetime::Command);
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_retained_streams_do_not_finish_before_retirement() {
    let fixture = support::StagedFixture::new().unwrap();
    let fixture_directory = fixture.directory().to_owned();
    let request = fixture
        .request("retained-stream", Lifetime::Workload)
        .unwrap();
    let captured = retained_streams::execute(request)
        .expect("retained-stream workload must complete before its attempt deadline");
    assert!(
        captured.execution_millis >= 400,
        "provider returned before the descendant retained its streams"
    );
    assert!(
        captured.execution_millis < 10_000,
        "bounded retained-stream workload approached its attempt deadline"
    );
    assert_eq!(
        captured.stdout,
        b"retained-stdout-open\nretained-stdout-release\n"
    );
    assert_eq!(
        captured.stderr,
        b"retained-stderr-open\nretained-stderr-release\n"
    );
    assert_eq!(captured.facts.child_status, 0);
    assert_eq!(captured.facts.exec_status, TargetExecStatus::Succeeded);
    assert!(captured.facts.spawn_error_reported);
    assert!(!captured.facts.deadline_exceeded);
    assert!(!captured.facts.memory_limit_exceeded);
    support::assert_retired(&captured.facts);
    drop(fixture);
    assert!(
        !fixture_directory.exists(),
        "retained-stream attempt leaked its isolated fixture"
    );
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_fork_storm_is_empty_before_result() {
    run("fork-storm", Lifetime::Command);
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_fork_during_cleanup_cannot_survive() {
    run("fork-storm", Lifetime::Command);
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_target_cannot_move_to_parent_or_sibling_cgroup() {
    run("deny-cgroup", Lifetime::Command);
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_target_cannot_setns_into_host_namespace() {
    run("deny-setns", Lifetime::Command);
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_target_cannot_mount_writable_cgroup_view() {
    run("deny-cgroup-mount", Lifetime::Command);
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_target_inherits_only_verified_descriptors() {
    run("identity", Lifetime::Command);
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_target_cannot_disable_namespace_init() {
    run("child", Lifetime::Command);
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
#[cfg(feature = "test-support")]
fn sealed_frontend_loss_before_authorization_never_runs_target() {
    let captured = sealed_faults::execute_loss(FaultPoint::FrontendLossBeforeAuthorization, false)
        .expect_err("frontend loss must abort authorization");
    sealed_faults::assert_loss_outcome(
        "sealed_frontend_loss_before_authorization_never_runs_target",
        &captured,
        "MCSEALED-FRONTEND-LOSS-BEFORE-AUTHORIZATION",
        RejectionPhaseV1::Authorization,
        false,
        RetirementOwner::Guardian,
    );
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
#[cfg(feature = "test-support")]
fn sealed_frontend_loss_after_authorization_triggers_guardian() {
    let captured = sealed_faults::execute_loss(FaultPoint::FrontendLossAfterAuthorization, true)
        .expect_err("frontend loss cannot report success");
    sealed_faults::assert_loss_outcome(
        "sealed_frontend_loss_after_authorization_triggers_guardian",
        &captured,
        "MCSEALED-FRONTEND-LOSS-AFTER-AUTHORIZATION",
        RejectionPhaseV1::Monitoring,
        true,
        RetirementOwner::Guardian,
    );
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
#[cfg(feature = "test-support")]
fn sealed_provider_worker_loss_triggers_guardian() {
    assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) }, 0);
    let fixture = support::StagedFixture::new().unwrap();
    let (marker, request) = sealed_faults::prepare_fault_target(&fixture);
    let claim_path = fixture.directory().join("provider-loss-claim");
    let attempt = [0x44; 16];
    let worker = unsafe { libc::fork() };
    assert!(worker >= 0);
    if worker == 0 {
        sealed_faults::exit_as_provider_worker(request, claim_path, attempt);
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(worker, &raw mut status, 0) }, worker);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 86);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let claim_bytes = loop {
        match std::fs::read(&claim_path) {
            Ok(bytes) => break bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("provider-loss claim read failed: {error}"),
        }
        assert!(
            std::time::Instant::now() < deadline,
            "guardian omitted provider-loss terminal claim"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    let claim =
        memcordon_sealed_agent::linux::launch::decode_guardian_terminal_for_test(&claim_bytes)
            .unwrap();
    assert_eq!(claim.trigger, GuardianTrigger::ProviderLoss);
    assert_eq!(claim.attempt_id, attempt);
    assert!(claim.cgroup_kill_invoked);
    assert!(claim.populated_zero_observed);
    assert!(claim.containment_removed);
    assert!(claim.record_retired);
    let mut helpers_reaped = 0_u32;
    loop {
        let reaped = unsafe { libc::waitpid(-1, &raw mut status, libc::WNOHANG) };
        if reaped > 0 {
            helpers_reaped += 1;
            continue;
        }
        if reaped == -1 {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ECHILD)
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "provider-loss helpers were not reaped"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(
        helpers_reaped >= 2,
        "namespace init and guardian were not both reaped"
    );
    assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 0) }, 0);
    assert!(std::fs::read(&marker).is_ok_and(|contents| contents.is_empty()));
    support::assert_attempt_retired(attempt);
    let rejection = RejectionV1::from_launch_facts(
        "MCSEALED-PROVIDER-WORKER-LOSS",
        RejectionPhaseV1::GuardianStartup,
        "MCSEALED-PROVIDER-WORKER-LOSS: authenticated guardian retirement",
        false,
        false,
        RejectionCleanupV1 {
            attempted: true,
            direct_child_reaped: true,
            workload_empty: Some(true),
            helpers_reaped: true,
            containment_removed: true,
            sealed_boundary_retired: true,
            errors: Vec::new(),
        },
    )
    .unwrap();
    sealed_faults::emit_fault_evidence(
        "sealed_provider_worker_loss_triggers_guardian",
        &sealed_faults::CapturedFaultOutcome {
            outcome: memcordon_sealed_agent::linux::launch::FaultExecutionOutcome {
                attempt_id: attempt,
                rejection,
                retirement_owner: RetirementOwner::Guardian,
            },
            marker_observed: false,
            guardian_reaped: true,
            final_record_absent: true,
            final_cgroup_absent: true,
        },
    );
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
#[cfg(feature = "test-support")]
fn sealed_guardian_loss_before_authorization_fails_closed() {
    let captured = sealed_faults::execute_loss(FaultPoint::GuardianLossBeforeAuthorization, false)
        .expect_err("guardian loss must abort authorization");
    sealed_faults::assert_loss_outcome(
        "sealed_guardian_loss_before_authorization_fails_closed",
        &captured,
        "MCSEALED-GUARDIAN-LOSS-BEFORE-AUTHORIZATION",
        RejectionPhaseV1::Authorization,
        false,
        RetirementOwner::Provider,
    );
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
#[cfg(feature = "test-support")]
fn sealed_guardian_loss_after_authorization_cannot_report_success() {
    let captured = sealed_faults::execute_loss(FaultPoint::GuardianLossAfterAuthorization, true)
        .expect_err("guardian loss cannot report success");
    sealed_faults::assert_loss_outcome(
        "sealed_guardian_loss_after_authorization_cannot_report_success",
        &captured,
        "MCSEALED-GUARDIAN-LOSS-AFTER-AUTHORIZATION",
        RejectionPhaseV1::Monitoring,
        true,
        RetirementOwner::Provider,
    );
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
#[cfg(feature = "test-support")]
fn sealed_cgroup_kill_failure_never_reports_retirement() {
    let captured =
        sealed_faults::execute_loss(FaultPoint::CgroupKillFailureAfterAuthorization, true)
            .expect_err("injected cgroup.kill failure cannot report success");
    sealed_faults::assert_loss_outcome(
        "sealed_cgroup_kill_failure_never_reports_retirement",
        &captured,
        "MCSEALED-CGROUP-KILL-FAILURE",
        RejectionPhaseV1::Retirement,
        true,
        RetirementOwner::Provider,
    );
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
#[cfg(feature = "test-support")]
fn sealed_persistent_populated_state_blocks_restart() {
    let captured =
        sealed_faults::execute_loss(FaultPoint::PersistentPopulatedAfterAuthorization, true)
            .expect_err("persistent populated state cannot report success");
    sealed_faults::assert_loss_outcome(
        "sealed_persistent_populated_state_blocks_restart",
        &captured,
        "MCSEALED-CGROUP-NOT-EMPTY",
        RejectionPhaseV1::Retirement,
        true,
        RetirementOwner::Provider,
    );
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
#[cfg(feature = "test-support")]
fn sealed_namespace_init_reap_delay_blocks_result() {
    let captured =
        sealed_faults::execute_loss(FaultPoint::NamespaceInitReapDelayAfterAuthorization, true)
            .expect_err("live namespace init cannot report terminal success");
    sealed_faults::assert_loss_outcome(
        "sealed_namespace_init_reap_delay_blocks_result",
        &captured,
        "MCSEALED-NAMESPACE-INIT-REAP-DELAY",
        RejectionPhaseV1::Retirement,
        true,
        RetirementOwner::Provider,
    );
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
#[cfg(feature = "test-support")]
fn sealed_guardian_reap_failure_blocks_result() {
    let captured =
        sealed_faults::execute_loss(FaultPoint::GuardianReapFailureAfterAuthorization, true)
            .expect_err("live guardian cannot report terminal success");
    sealed_faults::assert_loss_outcome(
        "sealed_guardian_reap_failure_blocks_result",
        &captured,
        "MCSEALED-GUARDIAN-REAP-FAILURE",
        RejectionPhaseV1::Retirement,
        true,
        RetirementOwner::Provider,
    );
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
#[cfg(feature = "test-support")]
fn sealed_faults_before_authorization_never_create_marker() {
    let fixture = support::StagedFixture::new().unwrap();
    let (marker, request) = sealed_faults::prepare_fault_target(&fixture);
    let attempt = [0xb1; 16];
    let error = memcordon_sealed_agent::linux::launch::execute(
        request,
        Vec::new(),
        attempt,
        unsafe { libc::getpid() },
        65_534,
        65_534,
        Vec::new(),
    )
    .expect_err("descriptor fault must fail before authorization");
    assert_eq!(
        error,
        "MCSEALED-LAUNCH-DESCRIPTOR-SET: exact descriptor inventory required"
    );
    let rejection = RejectionV1::from_launch_error(&error, attempt);
    assert_eq!(rejection.code, "MCSEALED-LAUNCH-DESCRIPTOR-SET");
    assert_eq!(rejection.phase, RejectionPhaseV1::RequestValidation);
    assert!(!rejection.target_created);
    assert!(!rejection.target_released);
    assert!(!rejection.cleanup.attempted);
    rejection.validate().unwrap();
    assert!(std::fs::read(&marker).is_ok_and(|contents| contents.is_empty()));
    support::assert_attempt_retired(attempt);
    sealed_faults::emit_fault_evidence(
        "sealed_faults_before_authorization_never_create_marker",
        &sealed_faults::CapturedFaultOutcome {
            outcome: FaultExecutionOutcome {
                attempt_id: attempt,
                rejection,
                retirement_owner: RetirementOwner::Provider,
            },
            marker_observed: false,
            guardian_reaped: false,
            final_record_absent: true,
            final_cgroup_absent: true,
        },
    );
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
#[cfg(feature = "test-support")]
fn sealed_namespace_init_failure_is_typed_prompt_and_retired() {
    let fixture = support::StagedFixture::new().unwrap();
    let (marker, request) = sealed_faults::prepare_fault_target(&fixture);
    let frontend = unsafe { libc::getpid() };
    let (descriptors, attempt) = support::resources(frontend).unwrap();
    let started = std::time::Instant::now();
    let outcome = memcordon_sealed_agent::linux::launch::execute_with_fault_typed(
        request,
        descriptors,
        attempt,
        frontend,
        65_534,
        65_534,
        Vec::new(),
        FaultPlan {
            point: FaultPoint::NamespaceInitFailureBeforeTarget,
            postauthorization_ready: None,
            provider_loss_claim_path: None,
        },
    )
    .expect_err("namespace-init fault must fail before target creation");
    let rejection = &outcome.rejection;
    assert_eq!(rejection.code, "MCSEALED-NAMESPACE-INIT-TARGET-FORK");
    assert_eq!(rejection.phase, RejectionPhaseV1::TargetCreation);
    assert!(!rejection.target_created);
    assert!(!rejection.target_released);
    assert!(rejection.cleanup.attempted);
    assert!(rejection.cleanup.direct_child_reaped);
    assert_eq!(rejection.cleanup.workload_empty, Some(true));
    assert!(rejection.cleanup.helpers_reaped);
    assert!(rejection.cleanup.containment_removed);
    assert!(rejection.cleanup.sealed_boundary_retired);
    assert!(rejection.cleanup.errors.is_empty());
    rejection.validate().unwrap();
    assert!(started.elapsed() < std::time::Duration::from_secs(4));
    assert!(std::fs::read(&marker).is_ok_and(|contents| contents.is_empty()));
    support::assert_attempt_retired(attempt);
    assert_eq!(outcome.retirement_owner, RetirementOwner::Provider);
    sealed_faults::emit_fault_evidence(
        "sealed_namespace_init_failure_is_typed_prompt_and_retired",
        &sealed_faults::CapturedFaultOutcome {
            outcome,
            marker_observed: false,
            guardian_reaped: true,
            final_record_absent: true,
            final_cgroup_absent: true,
        },
    );
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_native_nonzero_exit_preserves_provenance() {
    let captured = support::execute_captured("exit-17", Lifetime::Command).unwrap();
    assert_eq!(captured.facts.child_status, 17);
    assert_eq!(captured.facts.exec_status, TargetExecStatus::Succeeded);
    assert!(captured.facts.spawn_error_reported);
    support::assert_retired(&captured.facts);
    support::assert_attempt_retired(captured.attempt);
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_native_exit_126_and_127_are_not_exec_failures() {
    for (mode, expected) in [("exit-126", 126), ("exit-127", 127)] {
        let captured = support::execute_captured(mode, Lifetime::Command).unwrap();
        assert_eq!(captured.facts.child_status, expected);
        assert_eq!(captured.facts.exec_status, TargetExecStatus::Succeeded);
        assert!(captured.facts.spawn_error_reported);
        support::assert_retired(&captured.facts);
        support::assert_attempt_retired(captured.attempt);
    }
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_missing_target_preserves_enoent_exec_provenance() {
    let fixture = support::StagedFixture::new().unwrap();
    let request = fixture.request("exit", Lifetime::Command).unwrap();
    drop(fixture);
    let captured = support::execute_request_captured(request).unwrap();
    assert_eq!(captured.facts.child_status, 127);
    assert_eq!(
        captured.facts.exec_status,
        TargetExecStatus::Failed {
            class: ExecFailureClass::NotFound,
            os_code: libc::ENOENT,
        }
    );
    assert!(captured.facts.spawn_error_reported);
    support::assert_retired(&captured.facts);
    support::assert_attempt_retired(captured.attempt);
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_non_executable_target_preserves_eacces_exec_provenance() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = support::StagedFixture::new().unwrap();
    std::fs::set_permissions(fixture.program(), std::fs::Permissions::from_mode(0o444)).unwrap();
    let request = fixture.request("exit", Lifetime::Command).unwrap();
    let captured = support::execute_request_captured(request).unwrap();
    assert_eq!(captured.facts.child_status, 126);
    assert_eq!(
        captured.facts.exec_status,
        TargetExecStatus::Failed {
            class: ExecFailureClass::NotExecutable,
            os_code: libc::EACCES,
        }
    );
    assert!(captured.facts.spawn_error_reported);
    support::assert_retired(&captured.facts);
    support::assert_attempt_retired(captured.attempt);
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_restart_uses_fresh_retired_boundary() {
    let first = support::execute_captured("exit", Lifetime::Command).unwrap();
    let second = support::execute_captured("exit", Lifetime::Command).unwrap();
    assert_eq!(first.facts.child_status, 0);
    assert_eq!(second.facts.child_status, 0);
    assert_ne!(first.facts.target_pid, second.facts.target_pid);
    assert_ne!(first.attempt, second.attempt);
    assert_ne!(first.identity(), second.identity());
    support::assert_retired(&first.facts);
    support::assert_retired(&second.facts);
    support::assert_attempt_retired(first.attempt);
    support::assert_attempt_retired(second.attempt);
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_simultaneous_attempts_have_disjoint_boundaries() {
    concurrency::run();
}

#[test]
fn sealed_concurrency_evidence_starts_on_an_independent_line() {
    let output = format!(
        "running 1 test\ntest sealed_simultaneous_attempts_have_disjoint_boundaries ... {}ok\n",
        concurrency::frame_evidence("{}")
    );
    let payloads = output
        .lines()
        .filter_map(|line| line.strip_prefix("MCSEALED-CONCURRENCY-EVIDENCE:"))
        .collect::<Vec<_>>();
    assert_eq!(payloads, ["{}"]);
}
