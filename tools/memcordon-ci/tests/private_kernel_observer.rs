pub use memcordon_ci::{CiError, Result};

#[path = "../src/private_kernel_observer.rs"]
mod private_kernel_observer;
#[path = "../src/private_probe_bundle.rs"]
mod private_probe_bundle;
#[path = "../src/private_process_clock.rs"]
mod private_process_clock;

use memcordon_core::DiagnosticSha256;
use private_kernel_observer::{
    AllocationBoundaryKindV1, ExpectedKernelAdapterV1, KernelEventV1, KernelTaskIdentityV1,
    VerifiedKernelIntervalV1, parse_probe_capture_for_test,
};

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn event(sequence: u64, kind: u32) -> [u8; 128] {
    let mut raw = [0_u8; 128];
    put_u64(&mut raw, 0, sequence);
    put_u64(&mut raw, 8, sequence * 1000);
    put_u64(&mut raw, 16, 77);
    put_u64(&mut raw, 24, 123);
    put_u32(&mut raw, 64, 1234);
    put_u32(&mut raw, 80, kind);
    put_u64(&mut raw, 120, 88);
    raw[84..116].copy_from_slice(&[1; 32]);
    raw
}

fn capture() -> Vec<u8> {
    let mut bytes = vec![0_u8; 24];
    put_u32(&mut bytes, 0, 0x4d434b31);
    put_u32(&mut bytes, 4, 1);
    put_u64(&mut bytes, 8, 3);
    bytes.extend_from_slice(&event(1, 1));
    let mut decision = event(2, 4);
    put_u32(&mut decision, 72, 0xc000003e);
    put_u32(&mut decision, 76, 0x00050000);
    bytes.extend_from_slice(&decision);
    bytes.extend_from_slice(&event(3, 2));
    bytes
}

fn packed(events: Vec<[u8; 128]>) -> Vec<u8> {
    let mut bytes = vec![0_u8; 24];
    put_u32(&mut bytes, 0, 0x4d434b31);
    put_u32(&mut bytes, 4, 1);
    put_u64(&mut bytes, 8, events.len() as u64);
    for (index, mut event) in events.into_iter().enumerate() {
        put_u64(&mut event, 0, index as u64 + 1);
        put_u64(&mut event, 8, (index as u64 + 1) * 1000);
        bytes.extend_from_slice(&event);
    }
    bytes
}

fn worker_event(sequence: u64, kind: u32, pid: u32, start: u64) -> [u8; 128] {
    let mut raw = event(sequence, kind);
    put_u32(&mut raw, 64, pid);
    put_u64(&mut raw, 24, start);
    raw
}

fn service_fork(sequence: u64, child_pid: u32) -> [u8; 128] {
    let mut raw = event(sequence, 7);
    put_u32(&mut raw, 68, child_pid);
    raw
}

fn expected() -> ExpectedKernelAdapterV1 {
    ExpectedKernelAdapterV1 {
        boot_id: "test-boot".into(),
        kernel_release: "test-kernel".into(),
        btf_sha256: DiagnosticSha256::from_bytes([2; 32]),
        probe_map_sha256: DiagnosticSha256::from_bytes([3; 32]),
        result_key: DiagnosticSha256::from_bytes([1; 32]),
        coordinator_pid: 1234,
        coordinator_start_time: 123,
        coordinator_start_ticks: 0,
        cgroup_inode: 77,
        broker_pid: 2345,
        broker_start_ticks: 0,
        broker_cgroup_inode: 78,
    }
}

#[test]
fn binary_probe_capture_requires_contiguous_lossless_bounded_interval() {
    let bytes = capture();
    let events = parse_probe_capture_for_test(&bytes, &expected()).unwrap();
    assert_eq!(events.len(), 3);
    let mut lost = bytes.clone();
    put_u64(&mut lost, 16, 1);
    assert!(parse_probe_capture_for_test(&lost, &expected()).is_err());
    let mut duplicate = bytes.clone();
    put_u64(&mut duplicate, 24 + 128, 1);
    assert!(parse_probe_capture_for_test(&duplicate, &expected()).is_err());
    let mut wrong_key = bytes;
    wrong_key[24 + 84] = 9;
    assert!(parse_probe_capture_for_test(&wrong_key, &expected()).is_err());
    let mut wrong_coordinator = expected();
    wrong_coordinator.coordinator_start_time += 1;
    assert!(parse_probe_capture_for_test(&capture(), &wrong_coordinator).is_err());
    let mut reordered = capture();
    put_u64(&mut reordered, 24 + 128, 3);
    put_u64(&mut reordered, 24 + 2 * 128, 2);
    assert!(parse_probe_capture_for_test(&reordered, &expected()).is_err());
}

#[test]
fn binary_probe_accepts_two_ordered_service_worker_requests() {
    let mut allocation = event(6, 3);
    put_u32(&mut allocation, 64, 2345);
    put_u64(&mut allocation, 24, 345);
    put_u64(&mut allocation, 16, 78);
    let events = vec![
        service_fork(1, 2001),
        worker_event(2, 1, 2001, 201),
        worker_event(3, 2, 2001, 201),
        service_fork(4, 2002),
        worker_event(5, 1, 2002, 202),
        allocation,
        worker_event(7, 2, 2002, 202),
    ];
    assert_eq!(
        parse_probe_capture_for_test(&packed(events.clone()), &expected())
            .expect("Plan then Launch are bounded service-worker requests")
            .len(),
        7
    );

    let mut escaped = events.clone();
    let escaped_allocation = escaped.remove(5);
    escaped.insert(3, escaped_allocation);
    assert!(parse_probe_capture_for_test(&packed(escaped), &expected()).is_err());

    let mut nested = events.clone();
    nested[2] = worker_event(3, 1, 2001, 201);
    assert!(parse_probe_capture_for_test(&packed(nested), &expected()).is_err());

    let mut mismatched_exit = events.clone();
    mismatched_exit[6] = worker_event(7, 2, 2001, 201);
    assert!(parse_probe_capture_for_test(&packed(mismatched_exit), &expected()).is_err());

    let mut repeated_worker = events.clone();
    repeated_worker[4] = worker_event(5, 1, 2001, 201);
    repeated_worker[6] = worker_event(7, 2, 2001, 201);
    assert!(parse_probe_capture_for_test(&packed(repeated_worker), &expected()).is_err());

    let mut no_worker_fork = events.clone();
    no_worker_fork.remove(3);
    assert!(parse_probe_capture_for_test(&packed(no_worker_fork), &expected()).is_err());

    let mut third = events;
    third.push(service_fork(8, 2003));
    third.push(worker_event(9, 1, 2003, 203));
    third.push(worker_event(10, 2, 2003, 203));
    assert!(parse_probe_capture_for_test(&packed(third), &expected()).is_err());
}

#[test]
fn reap_requires_exact_prior_exit_and_nsfd_close_requires_inode() {
    let mut bytes = vec![0_u8; 24];
    put_u32(&mut bytes, 0, 0x4d434b31);
    put_u32(&mut bytes, 4, 1);
    put_u64(&mut bytes, 8, 5);
    bytes.extend_from_slice(&event(1, 1));
    let mut exit = event(2, 8);
    put_u32(&mut exit, 64, 99);
    put_u64(&mut exit, 24, 123_000);
    bytes.extend_from_slice(&exit);
    let mut reap = event(3, 9);
    put_u32(&mut reap, 68, 99);
    put_u64(&mut reap, 56, 123_000);
    bytes.extend_from_slice(&reap);
    let mut close = event(4, 10);
    put_u64(&mut close, 40, 55);
    bytes.extend_from_slice(&close);
    bytes.extend_from_slice(&event(5, 2));
    let parsed = parse_probe_capture_for_test(&bytes, &expected()).unwrap();
    assert!(
        matches!(&parsed[2], KernelEventV1::Reap { task } if task.pid == 99 && task.start_time == 123_000)
    );
    assert!(matches!(
        &parsed[3],
        KernelEventV1::NamespaceFdClosed {
            namespace_inode: 55,
            ..
        }
    ));
    let mut wrong = bytes;
    put_u64(&mut wrong, 24 + 2 * 128 + 56, 123_001);
    assert!(parse_probe_capture_for_test(&wrong, &expected()).is_err());
}

#[test]
fn moved_child_requires_a_fork_in_the_armed_interval() {
    let mut bytes = vec![0_u8; 24];
    put_u32(&mut bytes, 0, 0x4d434b31);
    put_u32(&mut bytes, 4, 1);
    put_u64(&mut bytes, 8, 5);
    bytes.extend_from_slice(&event(1, 1));
    let mut fork = event(2, 7);
    put_u32(&mut fork, 68, 99);
    bytes.extend_from_slice(&fork);
    let mut child = event(3, 6);
    put_u32(&mut child, 64, 99);
    put_u64(&mut child, 24, 123_000);
    put_u64(&mut child, 16, 88);
    bytes.extend_from_slice(&child);
    let mut exit = event(4, 8);
    put_u32(&mut exit, 64, 99);
    put_u64(&mut exit, 24, 123_000);
    put_u64(&mut exit, 16, 88);
    bytes.extend_from_slice(&exit);
    bytes.extend_from_slice(&event(5, 2));
    assert_eq!(
        parse_probe_capture_for_test(&bytes, &expected())
            .unwrap()
            .len(),
        5
    );
    let mut no_fork = bytes;
    put_u32(&mut no_fork, 24 + 128 + 80, 5);
    assert!(parse_probe_capture_for_test(&no_fork, &expected()).is_err());
}

#[test]
fn negative_branch_token_requires_exact_key_and_no_allocation() {
    let task = KernelTaskIdentityV1 {
        pid: 1234,
        start_time: 123,
        cgroup_inode: 77,
        time_ns_inode: 88,
    };
    let key = DiagnosticSha256::from_bytes([5; 32]);
    let boundary = |kind| KernelEventV1::AllocationBoundary {
        task,
        request_key: key.clone(),
        kind,
    };
    let interval = VerifiedKernelIntervalV1::from_events_for_test(
        vec![
            boundary(AllocationBoundaryKindV1::Enter),
            boundary(AllocationBoundaryKindV1::Exit),
        ],
        77,
    );
    assert_eq!(
        interval.verify_no_allocation(&key).unwrap().result_key(),
        &key
    );
    assert!(
        interval
            .verify_no_allocation(&DiagnosticSha256::from_bytes([9; 32]))
            .is_err()
    );
    let allocated = VerifiedKernelIntervalV1::from_events_for_test(
        vec![
            boundary(AllocationBoundaryKindV1::Enter),
            boundary(AllocationBoundaryKindV1::Allocate),
            boundary(AllocationBoundaryKindV1::Exit),
        ],
        77,
    );
    assert!(allocated.verify_no_allocation(&key).is_err());
}
