//! Five separately armed, loss-free policy intervals. Exit status is never
//! policy authority; every branch needs protected readback and kernel facts.

use std::collections::BTreeSet;

use memcordon_core::private_release_branch_v1::PolicyOperationBranchV1;

use crate::private_kernel_observer::{
    ExpectedKernelAdapterV1, VerifiedKernelIntervalV1, VerifiedKnownActionControlsV1,
    VerifiedNoAllocationIntervalV1, run_probe_case_interval,
};
use crate::private_probe_bundle::VerifiedProbeBundleV1;
use crate::{CiError, Result};

pub(crate) struct VerifiedPolicyIntervalsV1 {
    intervals: [VerifiedKernelIntervalV1; 5],
    all_no_allocation: [VerifiedNoAllocationIntervalV1; 5],
}

impl VerifiedPolicyIntervalsV1 {
    pub(crate) fn positive(&self) -> &VerifiedKernelIntervalV1 {
        &self.intervals[0]
    }
    pub(crate) fn rejected(&self) -> &[VerifiedKernelIntervalV1; 4] {
        self.intervals[1..]
            .try_into()
            .expect("fixed policy interval count")
    }
    pub(crate) fn all_no_allocation(&self) -> &[VerifiedNoAllocationIntervalV1; 5] {
        &self.all_no_allocation
    }
}

/// The five expected keys and host identities must come from protected CI
/// intent. Each operation runs only after its probe is armed and must make
/// its own authenticated request plus protected raw readback.
pub(crate) fn run_policy_intervals(
    bundle: &VerifiedProbeBundleV1,
    controls: &VerifiedKnownActionControlsV1,
    expected: [ExpectedKernelAdapterV1; 5],
    mut operation: impl FnMut(PolicyOperationBranchV1) -> Result<()>,
) -> Result<VerifiedPolicyIntervalsV1> {
    let mut keys = BTreeSet::new();
    for item in &expected {
        if !keys.insert(String::from(item.result_key.clone())) {
            return Err(CiError::Message(
                "policy interval result key duplicated".into(),
            ));
        }
    }
    let branches = PolicyOperationBranchV1::ALL;
    let mut intervals = Vec::with_capacity(5);
    for (branch, expected) in branches.into_iter().zip(expected) {
        intervals.push(run_probe_case_interval(bundle, expected, controls, || {
            operation(branch)
        })?);
    }
    let mut captures = BTreeSet::new();
    for interval in &intervals {
        interval.capture_bytes()?;
        if !captures.insert(String::from(interval.trace_sha256().clone())) {
            return Err(CiError::Message(
                "policy interval capture duplicated".into(),
            ));
        }
    }
    let intervals: [VerifiedKernelIntervalV1; 5] = intervals
        .try_into()
        .map_err(|_| CiError::Message("policy interval branch count differs".into()))?;
    let all_no_allocation = [
        intervals[0].verify_no_allocation(intervals[0].result_key())?,
        intervals[1].verify_no_allocation(intervals[1].result_key())?,
        intervals[2].verify_no_allocation(intervals[2].result_key())?,
        intervals[3].verify_no_allocation(intervals[3].result_key())?,
        intervals[4].verify_no_allocation(intervals[4].result_key())?,
    ];
    Ok(VerifiedPolicyIntervalsV1 {
        intervals,
        all_no_allocation,
    })
}
