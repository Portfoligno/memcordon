use memcordon_core::{ChildTermination, Error, ErrorCategory, RunOutcome};

pub fn outcome_exit_code(outcome: &RunOutcome) -> i32 {
    match outcome {
        RunOutcome::LimitExceeded { .. } => 124,
        RunOutcome::DeadlineExceeded { .. } => 123,
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
    if !error.cleanup.errors.is_empty()
        || error.cleanup.workload_empty == Some(false)
        || error.workload_may_be_alive
    {
        125
    } else if error.code == "MCINTERRUPT-SPAWN-GATE" {
        error.os_code.map_or(125, |signal| 128 + signal)
    } else if error.code == "MCSPAWN-NOT-FOUND" {
        127
    } else if error.code == "MCSPAWN-NOT-EXECUTABLE" {
        126
    } else if error.category == ErrorCategory::Usage {
        2
    } else {
        125
    }
}
