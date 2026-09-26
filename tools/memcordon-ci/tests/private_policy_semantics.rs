pub use memcordon_ci::{CiError, Result};

#[path = "../src/private_kernel_observer.rs"]
mod private_kernel_observer;
#[path = "../src/private_kernel_replay.rs"]
mod private_kernel_replay;
#[path = "../src/private_policy_semantics.rs"]
mod private_policy_semantics;
#[path = "../src/private_probe_bundle.rs"]
mod private_probe_bundle;
#[path = "../src/private_process_clock.rs"]
mod private_process_clock;

use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_branch_v1::{
    PolicyBranchOutcomeV1, PolicyBranchV1, PolicyFourBranchTranscriptV1, RejectedPolicyBranchV1,
};
use memcordon_core::workload_registry_v2::AdmissionCodeV2;
use private_kernel_observer::{
    AllocationBoundaryKindV1, KernelEventV1, KernelTaskIdentityV1, VerifiedKernelIntervalV1,
    VerifiedNoAllocationIntervalV1,
};
use private_policy_semantics::join_policy_kernel_intervals;

fn digest(byte: u8) -> DiagnosticSha256 {
    DiagnosticSha256::from_bytes([byte; 32])
}

fn interval(
    key: DiagnosticSha256,
    capture: DiagnosticSha256,
    allocate: bool,
) -> VerifiedKernelIntervalV1 {
    let task = KernelTaskIdentityV1 {
        pid: 1,
        start_time: 1,
        cgroup_inode: 77,
        time_ns_inode: 88,
    };
    let mut events = vec![KernelEventV1::AllocationBoundary {
        task,
        request_key: key.clone(),
        kind: AllocationBoundaryKindV1::Enter,
    }];
    if allocate {
        events.push(KernelEventV1::AllocationBoundary {
            task,
            request_key: key.clone(),
            kind: AllocationBoundaryKindV1::Allocate,
        });
    }
    events.push(KernelEventV1::AllocationBoundary {
        task,
        request_key: key.clone(),
        kind: AllocationBoundaryKindV1::Exit,
    });
    VerifiedKernelIntervalV1::from_events_with_ids_for_test(events, 77, key, capture)
}

fn transcript() -> PolicyFourBranchTranscriptV1 {
    let names = [
        PolicyBranchV1::WrongGrant,
        PolicyBranchV1::WrongProfile,
        PolicyBranchV1::UnapprovedChangedPortPlan,
        PolicyBranchV1::CommittedPortTamper,
    ];
    let rejected = std::array::from_fn(|index| RejectedPolicyBranchV1 {
        branch: names[index],
        exact_request_sha256: digest(30 + index as u8),
        exact_registry_sha256: digest(21),
        authenticated_caller_sha256: digest(22),
        outcome: match index {
            0 => PolicyBranchOutcomeV1::Admission(AdmissionCodeV2::ProfileNotAuthorized),
            2 => PolicyBranchOutcomeV1::Admission(AdmissionCodeV2::PlanNotApproved),
            1 => PolicyBranchOutcomeV1::Admission(AdmissionCodeV2::ProfileDigestMismatch),
            _ => PolicyBranchOutcomeV1::FrozenBindingMismatch,
        },
        independent_interval_sha256: digest(40 + index as u8),
    });
    PolicyFourBranchTranscriptV1 {
        schema_version: 1,
        challenge_sha256: digest(23),
        accepted_control_request_sha256: digest(20),
        accepted_control_registry_sha256: digest(21),
        authenticated_caller_sha256: digest(22),
        rejected,
    }
}

#[test]
fn five_policy_decisions_need_distinct_lossless_no_allocation_intervals() {
    let positive = interval(digest(5), digest(6), false)
        .verify_no_allocation(&digest(5))
        .unwrap();
    let negatives: [VerifiedNoAllocationIntervalV1; 4] = std::array::from_fn(|index| {
        interval(digest(50 + index as u8), digest(40 + index as u8), false)
            .verify_no_allocation(&digest(50 + index as u8))
            .unwrap()
    });
    let keys = std::array::from_fn(|index| digest(50 + index as u8));
    let joined = join_policy_kernel_intervals(
        &transcript(),
        &digest(23),
        &digest(20),
        &digest(21),
        &digest(22),
        &digest(5),
        &keys,
        &positive,
        [&negatives[0], &negatives[1], &negatives[2], &negatives[3]],
    )
    .unwrap();
    assert_eq!(joined.negative_capture_sha256()[3], digest(43));
    let duplicate = interval(digest(53), digest(42), false)
        .verify_no_allocation(&digest(53))
        .unwrap();
    assert!(
        join_policy_kernel_intervals(
            &transcript(),
            &digest(23),
            &digest(20),
            &digest(21),
            &digest(22),
            &digest(5),
            &keys,
            &positive,
            [&negatives[0], &negatives[1], &negatives[2], &duplicate]
        )
        .is_err()
    );
}
