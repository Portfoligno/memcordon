//! Native child termination semantics for ordinary cross-platform consumers.
use memcordon_core::{ChildTermination, RunOutcome};

/// Preserve the reported native variant; only the exact zero value succeeds.
pub fn exited_zero(outcome: Option<&RunOutcome>) -> bool {
    matches!(
        outcome,
        Some(RunOutcome::Exited {
            child: ChildTermination::ExitCode { code: 0 }
                | ChildTermination::WindowsStatus { status: 0 },
            ..
        })
    )
}
