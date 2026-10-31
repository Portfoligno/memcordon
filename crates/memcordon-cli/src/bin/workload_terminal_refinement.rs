//! Refine only the independently observed closure of original control handles.
use memcordon_core::{
    BoundedVec,
    result_v3::{CleanupObligationV3, CleanupResourceV3, LinuxWorkloadTerminalV1},
};

pub(crate) fn settle_control_handles(
    terminal: &LinuxWorkloadTerminalV1,
) -> Result<Option<LinuxWorkloadTerminalV1>, String> {
    terminal.validate()?;
    let mut seen = std::collections::BTreeSet::new();
    let mut obligations = BoundedVec::default();
    let mut changed = false;
    for obligation in terminal.cleanup.obligations.as_slice() {
        if !seen.insert(obligation.resource) {
            return Err("duplicate workload terminal cleanup obligation".into());
        }
        let mut obligation = obligation.clone();
        if obligation.resource == CleanupResourceV3::ControlHandles && !obligation.settled {
            obligation.settled = true;
            changed = true;
        }
        obligations
            .try_push(obligation)
            .map_err(|_| "cleanup obligation ceiling")?;
    }
    if !seen.contains(&CleanupResourceV3::ControlHandles) {
        obligations
            .try_push(CleanupObligationV3 {
                resource: CleanupResourceV3::ControlHandles,
                settled: true,
            })
            .map_err(|_| "cleanup obligation ceiling")?;
        changed = true;
    }
    let mut refined = terminal.clone();
    refined.cleanup.obligations = obligations;
    refined.validate()?;
    Ok(changed.then_some(refined))
}
