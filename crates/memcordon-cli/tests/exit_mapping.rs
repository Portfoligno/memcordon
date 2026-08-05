use memcordon::exit_mapping::{error_exit_code, outcome_exit_code};
use memcordon_core::{
    ByteSize, ChildTermination, CleanupErrorRecord, CleanupSummary, Error, ErrorCategory,
    LimitEvidence, RunOutcome,
};

#[test]
fn confirmed_limit_wins_over_successful_child_cleanup_status() {
    let outcome = RunOutcome::LimitExceeded {
        limit: ByteSize::from_bytes(1),
        observed: Some(ByteSize::from_bytes(2)),
        peak: Some(ByteSize::from_bytes(2)),
        evidence: LimitEvidence {
            backend: "test".to_owned(),
            metric: "test".to_owned(),
            detail: "limit".to_owned(),
        },
        child_after_termination: Some(ChildTermination::ExitCode { code: 0 }),
        cleanup: CleanupSummary {
            direct_child_reaped: true,
            workload_empty: Some(true),
            ..CleanupSummary::default()
        },
    };
    assert_eq!(outcome_exit_code(&outcome), 124);
}

#[test]
fn incomplete_cleanup_turns_normal_exit_into_wrapper_failure() {
    let outcome = RunOutcome::Exited {
        child: ChildTermination::ExitCode { code: 0 },
        peak: None,
        cleanup: CleanupSummary {
            direct_child_reaped: true,
            workload_empty: Some(false),
            ..CleanupSummary::default()
        },
    };
    assert_eq!(outcome_exit_code(&outcome), 125);
}

#[test]
fn incomplete_cleanup_overrides_spawn_and_interrupt_mappings() {
    let mut not_found = Error::new(ErrorCategory::Spawn, "MCSPAWN-NOT-FOUND", "missing");
    not_found.cleanup.errors.push(CleanupErrorRecord {
        operation: "cleanup".to_owned(),
        message: "failed".to_owned(),
    });
    assert_eq!(error_exit_code(&not_found), 125);

    let mut not_executable = Error::new(ErrorCategory::Spawn, "MCSPAWN-NOT-EXECUTABLE", "denied");
    not_executable.cleanup.workload_empty = Some(false);
    assert_eq!(error_exit_code(&not_executable), 125);

    let mut interrupted = Error::new(
        ErrorCategory::Termination,
        "MCINTERRUPT-SPAWN-GATE",
        "interrupted",
    );
    interrupted.os_code = Some(15);
    interrupted.workload_may_be_alive = true;
    assert_eq!(error_exit_code(&interrupted), 125);
}
