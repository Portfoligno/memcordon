pub use memcordon_ci::{CiError, Result};

#[path = "../src/private_kernel_observer.rs"]
mod private_kernel_observer;
#[path = "../src/private_kernel_replay.rs"]
mod private_kernel_replay;
#[path = "../src/private_probe_bundle.rs"]
mod private_probe_bundle;
#[path = "../src/private_process_clock.rs"]
mod private_process_clock;
#[path = "../src/private_public_kernel_join.rs"]
mod private_public_kernel_join;

use memcordon_core::DiagnosticSha256;
use private_kernel_observer::{
    AllocationBoundaryKindV1, KernelEventV1, KernelTaskIdentityV1, VerifiedKernelIntervalV1,
};
use private_process_clock::VerifiedProcClockCalibrationV1;
use private_public_kernel_join::{
    ProtectedPublicTargetExpectationV1, join_public_case_kernel_targets,
};

fn task(pid: u32) -> KernelTaskIdentityV1 {
    KernelTaskIdentityV1 {
        pid,
        start_time: u64::from(pid) * 100_000_000,
        cgroup_inode: 77,
        time_ns_inode: 88,
    }
}

#[test]
fn joins_only_exact_protected_target_with_retirement_and_fd_close() {
    let key = DiagnosticSha256::from_bytes([5; 32]);
    let parent = task(10);
    let target = task(20);
    let events = vec![
        KernelEventV1::AllocationBoundary {
            task: parent,
            request_key: key.clone(),
            kind: AllocationBoundaryKindV1::Enter,
        },
        KernelEventV1::AllocationBoundary {
            task: parent,
            request_key: key.clone(),
            kind: AllocationBoundaryKindV1::Allocate,
        },
        KernelEventV1::ForkObserved {
            parent,
            child_pid: target.pid,
        },
        KernelEventV1::Exec {
            task: target,
            image_dev: 9,
            image_inode: 99,
            abi: 0,
        },
        KernelEventV1::Exit {
            task: target,
            signal: 0,
        },
        KernelEventV1::Reap { task: target },
        KernelEventV1::NamespaceFdClosed {
            task: parent,
            namespace_inode: 123,
        },
        KernelEventV1::AllocationBoundary {
            task: parent,
            request_key: key.clone(),
            kind: AllocationBoundaryKindV1::Exit,
        },
    ];
    let interval = VerifiedKernelIntervalV1::from_events_for_test(events.clone(), 77);
    let clock = VerifiedProcClockCalibrationV1::from_parts_for_test(99, 990, 88, 0);
    let protected = ProtectedPublicTargetExpectationV1 {
        attempt_id: "attempt-1".into(),
        pid: 20,
        start_ticks: 200,
        network_namespace_inode: 123,
        entrypoint_sha256: DiagnosticSha256::from_bytes([7; 32]),
        entrypoint_device: 9,
        entrypoint_inode: 99,
        entrypoint_path: "/approved/target".into(),
    };
    let joined = join_public_case_kernel_targets(&interval, &clock, &key, &[protected.clone()])
        .expect("exact protected target and complete retirement must join");
    assert_eq!(joined.target_count(), 1);
    assert_eq!(joined.capture_sha256(), interval.trace_sha256());

    let mut wrong = protected.clone();
    wrong.start_ticks += 1;
    assert!(join_public_case_kernel_targets(&interval, &clock, &key, &[wrong]).is_err());
    let mut wrong_image = protected.clone();
    wrong_image.entrypoint_inode = 100;
    assert!(join_public_case_kernel_targets(&interval, &clock, &key, &[wrong_image]).is_err());
    let missing_close = VerifiedKernelIntervalV1::from_events_for_test(
        events
            .into_iter()
            .filter(|event| !matches!(event, KernelEventV1::NamespaceFdClosed { .. }))
            .collect(),
        77,
    );
    assert!(join_public_case_kernel_targets(&missing_close, &clock, &key, &[protected]).is_err());
}

#[test]
fn rejected_plan_requires_no_target_exec_and_no_allocation() {
    let key = DiagnosticSha256::from_bytes([5; 32]);
    let parent = task(10);
    let events = [
        AllocationBoundaryKindV1::Enter,
        AllocationBoundaryKindV1::Exit,
    ]
    .into_iter()
    .map(|kind| KernelEventV1::AllocationBoundary {
        task: parent,
        request_key: key.clone(),
        kind,
    })
    .collect();
    let interval = VerifiedKernelIntervalV1::from_events_for_test(events, 77);
    let clock = VerifiedProcClockCalibrationV1::from_parts_for_test(99, 990, 88, 0);
    assert_eq!(
        join_public_case_kernel_targets(&interval, &clock, &key, &[])
            .unwrap()
            .target_count(),
        0
    );
}
