pub use memcordon_ci::{CiError, Result};

#[path = "../src/private_abi_composite.rs"]
mod private_abi_composite;
#[path = "../src/private_kernel_observer.rs"]
mod private_kernel_observer;
#[path = "../src/private_kernel_replay.rs"]
mod private_kernel_replay;
#[path = "../src/private_probe_bundle.rs"]
mod private_probe_bundle;
#[path = "../src/private_process_clock.rs"]
mod private_process_clock;

use private_abi_composite::{
    AbiBranchTaskV1, AbiCompositeIntentV1, X32ControlResultV1, join_abi_kernel_events,
};
use private_kernel_observer::{
    KernelEventV1, KernelTaskIdentityV1, SeccompActionV1, VerifiedKernelIntervalV1,
};
use private_process_clock::VerifiedProcClockCalibrationV1;

fn branch(pid: u32) -> AbiBranchTaskV1 {
    AbiBranchTaskV1 {
        producer_pid: pid,
        producer_start_ticks: u64::from(pid) * 10,
        kernel: KernelTaskIdentityV1 {
            pid,
            start_time: u64::from(pid) * 100_000_000,
            cgroup_inode: 77,
            time_ns_inode: 88,
        },
    }
}

fn decision(
    branch: AbiBranchTaskV1,
    arch: u32,
    syscall: i64,
    action: SeccompActionV1,
) -> KernelEventV1 {
    KernelEventV1::SeccompDecision {
        task: branch.kernel,
        arch,
        syscall,
        action,
        errno: 0,
    }
}

fn returned(branch: AbiBranchTaskV1, arch: u32, syscall: i64, value: i64) -> KernelEventV1 {
    KernelEventV1::SyscallReturn {
        task: branch.kernel,
        arch,
        syscall,
        value,
    }
}

fn terminal(events: &mut Vec<KernelEventV1>, branch: AbiBranchTaskV1, signal: i32) {
    events.push(KernelEventV1::Exit {
        task: branch.kernel,
        signal,
    });
    events.push(KernelEventV1::Reap {
        task: branch.kernel,
    });
}

#[test]
fn x86_composite_requires_both_compat_denials_and_live_controls() {
    let calibration = VerifiedProcClockCalibrationV1::from_parts_for_test(99, 990, 88, 0);
    let [
        native,
        x32_control,
        x32_filtered,
        i386_control,
        i386_filtered,
    ] = [10, 11, 12, 13, 14].map(branch);
    let mut events = vec![
        decision(native, 0xc000_003e, 39, SeccompActionV1::Allow),
        returned(native, 0xc000_003e, 39, 10),
        decision(
            x32_control,
            0xc000_003e,
            0x4000_0027,
            SeccompActionV1::Allow,
        ),
        returned(x32_control, 0xc000_003e, 0x4000_0027, -38),
        decision(
            x32_filtered,
            0xc000_003e,
            0x4000_0027,
            SeccompActionV1::KillProcess,
        ),
        decision(i386_control, 0x4000_0003, 20, SeccompActionV1::Allow),
        returned(i386_control, 0x4000_0003, 20, 13),
        decision(i386_filtered, 0x4000_0003, 20, SeccompActionV1::KillProcess),
    ];
    for branch in [native, x32_control, i386_control] {
        terminal(&mut events, branch, 0);
    }
    for branch in [x32_filtered, i386_filtered] {
        terminal(&mut events, branch, 31);
    }
    let intent = AbiCompositeIntentV1::X86 {
        native,
        x32_control,
        x32_result: X32ControlResultV1::Enosys,
        x32_filtered,
        i386_control,
        i386_filtered,
    };
    let interval = VerifiedKernelIntervalV1::from_events_for_test(events.clone(), 77);
    assert_eq!(
        join_abi_kernel_events(&interval, &calibration, (99, 990), intent)
            .unwrap()
            .branch_count(),
        5
    );
    let wrong_clock = VerifiedProcClockCalibrationV1::from_parts_for_test(99, 990, 88, 10_000_000);
    assert!(join_abi_kernel_events(&interval, &wrong_clock, (99, 990), intent).is_err());
    // A different time namespace needs its own independently calibrated
    // reader. Reusing this reader's offset must be rejected.
    let distinct_reader_namespace =
        VerifiedProcClockCalibrationV1::from_parts_for_test(99, 990, 89, 0);
    assert!(
        join_abi_kernel_events(&interval, &distinct_reader_namespace, (99, 990), intent).is_err()
    );
    let interval = VerifiedKernelIntervalV1::from_events_for_test(events[..7].to_vec(), 77);
    assert!(join_abi_kernel_events(&interval, &calibration, (99, 990), intent).is_err());
}

#[test]
fn arm32_composite_requires_exact_helper_exec_for_both_children() {
    let calibration = VerifiedProcClockCalibrationV1::from_parts_for_test(99, 990, 88, 0);
    let [native, control, filtered] = [20, 21, 22].map(branch);
    let mut events = vec![
        decision(native, 0xc000_00b7, 172, SeccompActionV1::Allow),
        returned(native, 0xc000_00b7, 172, 20),
        KernelEventV1::Exec {
            task: control.kernel,
            image_dev: 9,
            image_inode: 99,
            abi: 0,
        },
        KernelEventV1::Exec {
            task: filtered.kernel,
            image_dev: 9,
            image_inode: 99,
            abi: 0,
        },
        decision(control, 0x4000_0028, 20, SeccompActionV1::Allow),
        returned(control, 0x4000_0028, 20, 21),
        decision(filtered, 0x4000_0028, 20, SeccompActionV1::KillProcess),
    ];
    for branch in [native, control] {
        terminal(&mut events, branch, 0);
    }
    terminal(&mut events, filtered, 31);
    let intent = AbiCompositeIntentV1::Arm64 {
        native,
        arm32_control: control,
        arm32_filtered: filtered,
        helper_dev: 9,
        helper_inode: 99,
    };
    let interval = VerifiedKernelIntervalV1::from_events_for_test(events.clone(), 77);
    assert_eq!(
        join_abi_kernel_events(&interval, &calibration, (99, 990), intent)
            .unwrap()
            .branch_count(),
        3
    );
    events[3] = KernelEventV1::Exec {
        task: filtered.kernel,
        image_dev: 9,
        image_inode: 100,
        abi: 0,
    };
    let interval = VerifiedKernelIntervalV1::from_events_for_test(events, 77);
    assert!(join_abi_kernel_events(&interval, &calibration, (99, 990), intent).is_err());
}
