//! Independent ABI event-chain join. It remains partial until protected raw
//! custody and all host/retirement joins are attached to this kernel interval.

use crate::private_kernel_observer::{
    KernelEventV1, KernelTaskIdentityV1, SeccompActionV1, VerifiedKernelIntervalV1,
};
use crate::private_process_clock::VerifiedProcClockCalibrationV1;
use crate::{CiError, Result};
use memcordon_core::DiagnosticSha256;

const X86_64: u32 = 0xc000_003e;
const I386: u32 = 0x4000_0003;
const AARCH64: u32 = 0xc000_00b7;
const ARM32: u32 = 0x4000_0028;
const X32_GETPID: i64 = 0x4000_0027;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AbiBranchTaskV1 {
    pub(crate) producer_pid: u32,
    pub(crate) producer_start_ticks: u64,
    pub(crate) kernel: KernelTaskIdentityV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum X32ControlResultV1 {
    Pid,
    Enosys,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AbiCompositeIntentV1 {
    X86 {
        native: AbiBranchTaskV1,
        x32_control: AbiBranchTaskV1,
        x32_result: X32ControlResultV1,
        x32_filtered: AbiBranchTaskV1,
        i386_control: AbiBranchTaskV1,
        i386_filtered: AbiBranchTaskV1,
    },
    Arm64 {
        native: AbiBranchTaskV1,
        arm32_control: AbiBranchTaskV1,
        arm32_filtered: AbiBranchTaskV1,
        helper_dev: u64,
        helper_inode: u64,
    },
}

pub(crate) struct PartialAbiKernelJoinV1 {
    capture_sha256: DiagnosticSha256,
    branch_count: usize,
}

impl PartialAbiKernelJoinV1 {
    pub(crate) fn capture_sha256(&self) -> &DiagnosticSha256 {
        &self.capture_sha256
    }
    pub(crate) fn branch_count(&self) -> usize {
        self.branch_count
    }
}

fn fail(message: &'static str) -> CiError {
    CiError::Message(message.into())
}

fn task_join(
    interval: &VerifiedKernelIntervalV1,
    calibration: &VerifiedProcClockCalibrationV1,
    branch: AbiBranchTaskV1,
) -> Result<()> {
    if branch.producer_pid == 0
        || branch.producer_start_ticks == 0
        || branch.kernel.pid != branch.producer_pid
        || branch.kernel.start_time == 0
        || branch.kernel.cgroup_inode == 0
        || !calibration.matches(branch.kernel, branch.producer_start_ticks)
    {
        return Err(fail("ABI branch task identity differs"));
    }
    // PID reuse within this interval is ambiguous even when the producer
    // recorded a distinct `/proc` tick value.
    for event in interval.events() {
        let task = match event {
            KernelEventV1::Fork { child, .. } => child,
            KernelEventV1::ForkObserved { parent, .. } => parent,
            KernelEventV1::Exec { task, .. }
            | KernelEventV1::Exit { task, .. }
            | KernelEventV1::Reap { task }
            | KernelEventV1::NamespaceFdClosed { task, .. }
            | KernelEventV1::SeccompDecision { task, .. }
            | KernelEventV1::SyscallReturn { task, .. }
            | KernelEventV1::AllocationBoundary { task, .. } => task,
        };
        if task.pid == branch.producer_pid && *task != branch.kernel {
            return Err(fail("ABI branch PID reused in kernel interval"));
        }
    }
    Ok(())
}

fn decision(
    interval: &VerifiedKernelIntervalV1,
    calibration: &VerifiedProcClockCalibrationV1,
    branch: AbiBranchTaskV1,
    arch: u32,
    syscall: i64,
    action: SeccompActionV1,
) -> Result<()> {
    task_join(interval, calibration, branch)?;
    if !interval.seccomp_decision(branch.kernel, arch, syscall, action) {
        return Err(fail("ABI branch seccomp tuple absent"));
    }
    Ok(())
}

fn returned(
    interval: &VerifiedKernelIntervalV1,
    branch: AbiBranchTaskV1,
    arch: u32,
    syscall: i64,
    value: i64,
) -> bool {
    interval.events().iter().any(|event| {
        matches!(event,
        KernelEventV1::SyscallReturn { task, arch: observed_arch, syscall: nr, value: actual }
        if *task == branch.kernel && *observed_arch == arch && *nr == syscall && *actual == value)
    })
}

fn terminal(
    interval: &VerifiedKernelIntervalV1,
    branch: AbiBranchTaskV1,
    expected_signal: i32,
) -> Result<()> {
    let mut exit_at = None;
    let mut reap_at = None;
    for (index, event) in interval.events().iter().enumerate() {
        match event {
            KernelEventV1::Exit { task, signal } if *task == branch.kernel => {
                let status_matches = if expected_signal == 0 {
                    *signal == 0
                } else {
                    (0..=255).contains(signal) && (*signal & 0x7f) == expected_signal
                };
                if exit_at.replace(index).is_some() || !status_matches {
                    return Err(fail("ABI branch exit status differs"));
                }
            }
            KernelEventV1::Reap { task } if *task == branch.kernel => {
                if reap_at.replace(index).is_some() {
                    return Err(fail("ABI branch reap aliases"));
                }
            }
            _ => {}
        }
    }
    if !matches!((exit_at, reap_at), (Some(exit), Some(reap)) if exit < reap) {
        return Err(fail("ABI branch exit/reap chain absent"));
    }
    Ok(())
}

fn unique(branches: &[AbiBranchTaskV1]) -> Result<()> {
    for (index, branch) in branches.iter().enumerate() {
        if branches[..index]
            .iter()
            .any(|prior| prior.producer_pid == branch.producer_pid || prior.kernel == branch.kernel)
        {
            return Err(fail("ABI sibling branches alias one task"));
        }
    }
    Ok(())
}

pub(crate) fn join_abi_kernel_events(
    interval: &VerifiedKernelIntervalV1,
    calibration: &VerifiedProcClockCalibrationV1,
    producer_reader: (u32, u64),
    intent: AbiCompositeIntentV1,
) -> Result<PartialAbiKernelJoinV1> {
    interval.capture_bytes()?;
    if calibration.reader_identity() != producer_reader {
        return Err(fail("ABI producer reader clock identity differs"));
    }
    let branch_count = match intent {
        AbiCompositeIntentV1::X86 {
            native,
            x32_control,
            x32_result,
            x32_filtered,
            i386_control,
            i386_filtered,
        } => {
            unique(&[
                native,
                x32_control,
                x32_filtered,
                i386_control,
                i386_filtered,
            ])?;
            decision(
                interval,
                calibration,
                native,
                X86_64,
                39,
                SeccompActionV1::Allow,
            )?;
            if !returned(interval, native, X86_64, 39, i64::from(native.producer_pid)) {
                return Err(fail("native x86 positive return absent"));
            }
            decision(
                interval,
                calibration,
                x32_control,
                X86_64,
                X32_GETPID,
                SeccompActionV1::Allow,
            )?;
            let expected = match x32_result {
                X32ControlResultV1::Pid => i64::from(x32_control.producer_pid),
                X32ControlResultV1::Enosys => -38, // Linux UAPI ENOSYS.
            };
            if !returned(interval, x32_control, X86_64, X32_GETPID, expected) {
                return Err(fail("x32 outer-control return absent"));
            }
            decision(
                interval,
                calibration,
                x32_filtered,
                X86_64,
                X32_GETPID,
                SeccompActionV1::KillProcess,
            )?;
            decision(
                interval,
                calibration,
                i386_control,
                I386,
                20,
                SeccompActionV1::Allow,
            )?;
            if !returned(
                interval,
                i386_control,
                I386,
                20,
                i64::from(i386_control.producer_pid),
            ) {
                return Err(fail("i386 outer-control return absent"));
            }
            decision(
                interval,
                calibration,
                i386_filtered,
                I386,
                20,
                SeccompActionV1::KillProcess,
            )?;
            for branch in [native, x32_control, i386_control] {
                terminal(interval, branch, 0)?;
            }
            for branch in [x32_filtered, i386_filtered] {
                terminal(interval, branch, 31)?;
            }
            5
        }
        AbiCompositeIntentV1::Arm64 {
            native,
            arm32_control,
            arm32_filtered,
            helper_dev,
            helper_inode,
        } => {
            unique(&[native, arm32_control, arm32_filtered])?;
            if helper_dev == 0 || helper_inode == 0 {
                return Err(fail("ARM32 helper image identity absent"));
            }
            decision(
                interval,
                calibration,
                native,
                AARCH64,
                172,
                SeccompActionV1::Allow,
            )?;
            if !returned(
                interval,
                native,
                AARCH64,
                172,
                i64::from(native.producer_pid),
            ) {
                return Err(fail("native ARM64 positive return absent"));
            }
            for branch in [arm32_control, arm32_filtered] {
                if !interval.events().iter().any(|event| {
                    matches!(event,
                    KernelEventV1::Exec { task, image_dev, image_inode, .. }
                    if *task == branch.kernel && *image_dev == helper_dev
                        && *image_inode == helper_inode)
                }) {
                    return Err(fail("ARM32 helper exec image absent"));
                }
            }
            decision(
                interval,
                calibration,
                arm32_control,
                ARM32,
                20,
                SeccompActionV1::Allow,
            )?;
            if !returned(
                interval,
                arm32_control,
                ARM32,
                20,
                i64::from(arm32_control.producer_pid),
            ) {
                return Err(fail("ARM32 outer-control return absent"));
            }
            decision(
                interval,
                calibration,
                arm32_filtered,
                ARM32,
                20,
                SeccompActionV1::KillProcess,
            )?;
            for branch in [native, arm32_control] {
                terminal(interval, branch, 0)?;
            }
            terminal(interval, arm32_filtered, 31)?;
            3
        }
    };
    Ok(PartialAbiKernelJoinV1 {
        capture_sha256: interval.trace_sha256().clone(),
        branch_count,
    })
}
