use memcordon_core::{ChildTermination, Error, ErrorCategory, RunOutcome};

pub fn outcome_exit_code(outcome: &RunOutcome) -> i32 {
    match outcome {
        RunOutcome::LimitExceeded { .. } => 124,
        RunOutcome::MonitorFailed { .. } => 125,
        RunOutcome::Interrupted {
            signal, cleanup, ..
        } => {
            if !cleanup.errors.is_empty() || cleanup.workload_empty == Some(false) {
                125
            } else {
                128 + signal.signal
            }
        }
        RunOutcome::Exited { child, cleanup, .. } => {
            if !cleanup.errors.is_empty() || cleanup.workload_empty == Some(false) {
                return 125;
            }
            child_exit_code(child)
        }
    }
}

fn child_exit_code(child: &ChildTermination) -> i32 {
    match child {
        ChildTermination::ExitCode { code } => *code,
        ChildTermination::UnixSignal { signal } => 128 + signal,
        ChildTermination::WindowsStatus { status } => i32::try_from(*status).unwrap_or(125),
        ChildTermination::Unavailable => 125,
    }
}

pub fn error_exit_code(error: &Error) -> i32 {
    if error.code == "MCSPAWN-NOT-FOUND" {
        127
    } else if error.code == "MCSPAWN-NOT-EXECUTABLE" {
        126
    } else if error.category == ErrorCategory::Usage {
        2
    } else {
        125
    }
}

#[cfg(test)]
mod tests {
    use memcordon_core::{ByteSize, ChildTermination, CleanupSummary, LimitEvidence, RunOutcome};

    use super::outcome_exit_code;

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
}
