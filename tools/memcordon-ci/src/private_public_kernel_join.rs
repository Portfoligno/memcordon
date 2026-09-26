//! Joins protected provider target identities to independently captured BPF events.
//! A target is never selected by taking the first exec in a capture.

use crate::private_kernel_observer::{
    KernelEventV1, KernelTaskIdentityV1, VerifiedKernelIntervalV1,
};
use crate::private_process_clock::VerifiedProcClockCalibrationV1;
use crate::{CiError, Result};
use memcordon_core::DiagnosticSha256;
use std::collections::BTreeSet;

#[derive(Clone, Debug)]
pub(crate) struct ProtectedPublicTargetExpectationV1 {
    pub(crate) attempt_id: String,
    pub(crate) pid: u32,
    pub(crate) start_ticks: u64,
    pub(crate) network_namespace_inode: u64,
    pub(crate) entrypoint_sha256: DiagnosticSha256,
    pub(crate) entrypoint_device: u64,
    pub(crate) entrypoint_inode: u64,
    pub(crate) entrypoint_path: String,
}

#[derive(Clone, Debug)]
pub(crate) struct VerifiedPublicCaseKernelJoinV1 {
    capture_sha256: DiagnosticSha256,
    targets: Vec<(String, KernelTaskIdentityV1)>,
}

impl VerifiedPublicCaseKernelJoinV1 {
    pub(crate) fn capture_sha256(&self) -> &DiagnosticSha256 {
        &self.capture_sha256
    }

    pub(crate) fn target_count(&self) -> usize {
        self.targets.len()
    }
}

fn fail(message: &'static str) -> CiError {
    CiError::Message(message.into())
}

/// `targets` must come from independently read, hash-joined provider
/// `target-identity.json` leaves. The caller must separately join each
/// protected approved entrypoint digest/path to the authenticated registry,
/// and attempt ids and count to
/// the signed public case plan and terminal provider report.
pub(crate) fn join_public_case_kernel_targets(
    interval: &VerifiedKernelIntervalV1,
    clock: &VerifiedProcClockCalibrationV1,
    result_key: &DiagnosticSha256,
    targets: &[ProtectedPublicTargetExpectationV1],
) -> Result<VerifiedPublicCaseKernelJoinV1> {
    interval.capture_bytes()?;
    if interval.result_key() != result_key {
        return Err(fail("public kernel interval or installed image differs"));
    }
    if targets.is_empty() {
        interval.verify_no_allocation(result_key)?;
        if interval.events().iter().any(|event| {
            matches!(event, KernelEventV1::Exec { task, .. }
                if task.cgroup_inode == interval.cgroup_inode())
        }) {
            return Err(fail("rejected public plan executed in the service cgroup"));
        }
        return Ok(VerifiedPublicCaseKernelJoinV1 {
            capture_sha256: interval.trace_sha256().clone(),
            targets: Vec::new(),
        });
    }
    interval.verify_allocation(result_key)?;
    let mut seen_attempts = BTreeSet::new();
    let mut seen_pids = BTreeSet::new();
    let mut joined = Vec::with_capacity(targets.len());
    for target in targets {
        if target.attempt_id.is_empty()
            || target.pid == 0
            || target.start_ticks == 0
            || target.network_namespace_inode == 0
            || target.entrypoint_device == 0
            || target.entrypoint_inode == 0
            || target.entrypoint_path.is_empty()
            || target.entrypoint_sha256 == DiagnosticSha256::from_bytes([0; 32])
            || !seen_attempts.insert(target.attempt_id.as_str())
            || !seen_pids.insert(target.pid)
        {
            return Err(fail(
                "public protected target identity duplicated or incomplete",
            ));
        }
        let mut selected = None;
        for event in interval.events() {
            if let KernelEventV1::Exec {
                task,
                image_dev,
                image_inode,
                ..
            } = event
            {
                if task.pid == target.pid && clock.matches(*task, target.start_ticks) {
                    if selected.replace(*task).is_some()
                        || *image_dev != target.entrypoint_device
                        || *image_inode != target.entrypoint_inode
                    {
                        return Err(fail("public target exec/image is ambiguous or differs"));
                    }
                }
            }
        }
        let task = selected.ok_or_else(|| fail("protected public target absent from BPF exec"))?;
        if !interval.retired_task(task) {
            return Err(fail("public target exit/reap absent"));
        }
        let fork_seen = interval.events().iter().any(|event| {
            matches!(event, KernelEventV1::ForkObserved { child_pid, .. }
                if *child_pid == target.pid)
                || matches!(event, KernelEventV1::Fork { child, .. }
                    if *child == task)
        });
        if !fork_seen {
            return Err(fail("public target fork lineage absent"));
        }
        // The owner of the namespace fd is the coordinator/guardian, not the
        // target. Require one exact close in the same verified interval.
        let reap_index = interval.events().iter().position(|event| {
            matches!(event, KernelEventV1::Reap { task: observed } if *observed == task)
        }).ok_or_else(|| fail("public target reap event absent"))?;
        let close_seen_after_reap = interval.events()[reap_index + 1..].iter().any(|event| {
            matches!(event, KernelEventV1::NamespaceFdClosed { namespace_inode, .. }
                if *namespace_inode == target.network_namespace_inode)
        });
        if !close_seen_after_reap {
            return Err(fail("public target namespace fd closure absent"));
        }
        joined.push((target.attempt_id.clone(), task));
    }
    let observed_target_execs = interval
        .events()
        .iter()
        .filter(|event| {
            matches!(event, KernelEventV1::Exec { task, .. }
                if joined.iter().any(|(_, selected)| selected == task))
        })
        .count();
    if observed_target_execs != targets.len() {
        return Err(fail("public target exec inventory differs"));
    }
    Ok(VerifiedPublicCaseKernelJoinV1 {
        capture_sha256: interval.trace_sha256().clone(),
        targets: joined,
    })
}
