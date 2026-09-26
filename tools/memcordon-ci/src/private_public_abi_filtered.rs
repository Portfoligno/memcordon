//! Protected installed-public ABI target claims and independent kernel join.
//! The service captures target stdout, but only a loss-free kernel interval
//! can establish that the child entered the alternate ABI under the filter.

use std::collections::HashSet;

use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_codec::hash_bytes;
use memcordon_core::workload_evidence_v2::{PrivateTcpCheckpointV2, QualifiedNativeAbiV2};
use serde::{Deserialize, Serialize};

use crate::{CiError, Result};

const SELECTOR: &str = "private_tcp::abi_alternate_entry_denied";
const X86_64: &str = "x86_64-unknown-linux-gnu";
const ARM64: &str = "aarch64-unknown-linux-gnu";
const LINUX_SIGSYS: i32 = 31;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FilteredChildV1 {
    branch: String,
    pid: u32,
    start_time_ticks: u64,
    audit_arch: u32,
    syscall_number: u32,
    terminal_signal: i32,
    helper_device: Option<u64>,
    helper_inode: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FilteredTargetReportV1 {
    schema_version: u8,
    evidence_scope: String,
    challenge: DiagnosticSha256,
    target_pid: u32,
    target_start_time_ticks: u64,
    target_uid: u32,
    target_gid: u32,
    no_new_privs: bool,
    seccomp_mode: u32,
    seccomp_filters: u32,
    native_getpid: u32,
    children: Vec<FilteredChildV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProtectedFilteredAbiV1 {
    schema_version: u8,
    selector: String,
    evidence_scope: String,
    result_key: DiagnosticSha256,
    challenge: DiagnosticSha256,
    boot_id: String,
    installation_epoch: DiagnosticSha256,
    active_h1_receipt_sha256: DiagnosticSha256,
    attempt_id: String,
    target_pid: u32,
    target_start_time_ticks: u64,
    checkpoint_sha256: DiagnosticSha256,
    filter_sha256: DiagnosticSha256,
    target_report_sha256: DiagnosticSha256,
    helper_device: Option<u64>,
    helper_inode: Option<u64>,
}

pub struct ExpectedPublicAbiFilteredV1<'a> {
    pub target: &'a str,
    pub challenge: &'a [u8; 32],
    pub result_key: &'a DiagnosticSha256,
    pub boot_id: &'a str,
    pub installation_epoch: &'a DiagnosticSha256,
    pub active_h1_receipt_sha256: &'a DiagnosticSha256,
    pub attempt_id: &'a str,
    pub target_pid: u32,
    pub target_start_ticks: u64,
    pub target_uid: u32,
    pub target_gid: u32,
    pub checkpoint_sha256: &'a DiagnosticSha256,
    pub filter_sha256: &'a DiagnosticSha256,
    pub network_namespace_inode: u64,
    pub helper_device: Option<u64>,
    pub helper_inode: Option<u64>,
}

/// Exact-byte custody only; this does not assert an independent ABI decision.
pub struct StructuralPublicAbiFilteredV1 {
    pub report_sha256: DiagnosticSha256,
    pub protected_sha256: DiagnosticSha256,
    pub checkpoint_file_sha256: DiagnosticSha256,
    pub result_key: DiagnosticSha256,
    pub target_pid: u32,
    pub target_start_ticks: u64,
    children: Vec<FilteredChildV1>,
}

pub(crate) struct VerifiedPublicAbiFilteredKernelV1 {
    capture_sha256: DiagnosticSha256,
    child_count: usize,
}

impl VerifiedPublicAbiFilteredKernelV1 {
    pub(crate) fn capture_sha256(&self) -> &DiagnosticSha256 {
        &self.capture_sha256
    }
    pub(crate) fn child_count(&self) -> usize {
        self.child_count
    }
}

fn fail(message: &'static str) -> CiError {
    CiError::Message(message.into())
}

fn canonical<T: for<'de> Deserialize<'de> + Serialize>(bytes: &[u8], bound: usize) -> Result<T> {
    if bytes.is_empty() || bytes.len() > bound {
        return Err(fail("public filtered ABI raw byte bound differs"));
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)
        .map_err(CiError::Message)?;
    let value: T = serde_json::from_slice(bytes)?;
    if serde_json::to_vec(&value)? != bytes {
        return Err(fail("public filtered ABI raw encoding differs"));
    }
    Ok(value)
}

pub fn readback_public_abi_filtered_v1(
    target_report_bytes: &[u8],
    protected_bytes: &[u8],
    checkpoint_bytes: &[u8],
    expected: &ExpectedPublicAbiFilteredV1<'_>,
) -> Result<StructuralPublicAbiFilteredV1> {
    let report: FilteredTargetReportV1 = canonical(target_report_bytes, 4096)?;
    let protected: ProtectedFilteredAbiV1 = canonical(protected_bytes, 4096)?;
    let checkpoint: PrivateTcpCheckpointV2 = canonical(checkpoint_bytes, 4096)?;
    let branches: &[(&str, u32, u32)] = match expected.target {
        X86_64 => &[("x32", 0xc000_003e, 0x4000_0027), ("i386", 0x4000_0003, 20)],
        ARM64 => &[("arm32", 0x4000_0028, 20)],
        _ => return Err(fail("public filtered ABI target differs")),
    };
    let zero = DiagnosticSha256::from_bytes([0; 32]);
    if expected.challenge == &[0; 32]
        || expected.result_key == &zero
        || expected.checkpoint_sha256 == &zero
        || expected.filter_sha256 == &zero
        || expected.target_pid == 0
        || expected.target_start_ticks == 0
        || expected.target_uid == 0
        || expected.target_gid == 0
        || expected.network_namespace_inode == 0
        || expected.boot_id.is_empty()
        || expected.attempt_id.is_empty()
        || report.schema_version != 1
        || report.evidence_scope != "filtered-public-target-claims-require-kernel-join"
        || report.challenge.bytes() != expected.challenge
        || report.target_pid != expected.target_pid
        || report.target_start_time_ticks != expected.target_start_ticks
        || report.target_uid != expected.target_uid
        || report.target_gid != expected.target_gid
        || !report.no_new_privs
        || report.seccomp_mode != 2
        || report.seccomp_filters < 2
        || report.native_getpid != expected.target_pid
        || report.children.len() != branches.len()
        || protected.schema_version != 1
        || protected.selector != SELECTOR
        || protected.evidence_scope != "service-captured-filtered-target-stdout"
        || protected.result_key != *expected.result_key
        || protected.challenge.bytes() != expected.challenge
        || protected.boot_id != expected.boot_id
        || protected.installation_epoch != *expected.installation_epoch
        || protected.active_h1_receipt_sha256 != *expected.active_h1_receipt_sha256
        || protected.attempt_id != expected.attempt_id
        || protected.target_pid != expected.target_pid
        || protected.target_start_time_ticks != expected.target_start_ticks
        || protected.checkpoint_sha256 != *expected.checkpoint_sha256
        || protected.filter_sha256 != *expected.filter_sha256
        || checkpoint.canonical_digest().map_err(CiError::Message)? != protected.checkpoint_sha256
        || checkpoint.filter_digest != *expected.filter_sha256
        || checkpoint
            .target_network_namespace
            .target_network_inode
            .get()
            != expected.network_namespace_inode
        || checkpoint.native_abi
            != match expected.target {
                X86_64 => QualifiedNativeAbiV2::X86_64LinuxGnu,
                ARM64 => QualifiedNativeAbiV2::Aarch64LinuxGnu,
                _ => unreachable!("target inventory checked above"),
            }
        || protected.target_report_sha256 != hash_bytes(target_report_bytes)
        || protected.helper_device != expected.helper_device
        || protected.helper_inode != expected.helper_inode
    {
        return Err(fail("public filtered ABI protected target binding differs"));
    }
    if matches!(expected.target, X86_64)
        && (expected.helper_device.is_some() || expected.helper_inode.is_some())
        || matches!(expected.target, ARM64)
            && (!expected.helper_device.is_some_and(|value| value != 0)
                || !expected.helper_inode.is_some_and(|value| value != 0))
    {
        return Err(fail("public filtered ABI helper inventory differs"));
    }
    let mut identities = HashSet::new();
    for (child, (name, arch, syscall)) in report.children.iter().zip(branches) {
        if child.branch != *name
            || child.pid == 0
            || child.pid == expected.target_pid
            || child.start_time_ticks == 0
            || !identities.insert((child.pid, child.start_time_ticks))
            || child.audit_arch != *arch
            || child.syscall_number != *syscall
            || child.terminal_signal != LINUX_SIGSYS
            || child.helper_device != expected.helper_device
            || child.helper_inode != expected.helper_inode
        {
            return Err(fail("public filtered ABI child claim differs"));
        }
    }
    Ok(StructuralPublicAbiFilteredV1 {
        report_sha256: hash_bytes(target_report_bytes),
        protected_sha256: hash_bytes(protected_bytes),
        checkpoint_file_sha256: hash_bytes(checkpoint_bytes),
        result_key: expected.result_key.clone(),
        target_pid: expected.target_pid,
        target_start_ticks: expected.target_start_ticks,
        children: report.children,
    })
}

/// Returns only after each claimed filtered child has an exact fork, actual
/// alternate-ABI KILL decision, SIGSYS exit and reap in one loss-free capture.
#[cfg(target_os = "linux")]
pub(crate) fn join_public_abi_filtered_kernel_v1(
    structural: &StructuralPublicAbiFilteredV1,
    interval: &crate::private_kernel_observer::VerifiedKernelIntervalV1,
    clock: &crate::private_process_clock::VerifiedProcClockCalibrationV1,
    approved_image_device: u64,
    approved_image_inode: u64,
) -> Result<VerifiedPublicAbiFilteredKernelV1> {
    use crate::private_kernel_observer::{KernelEventV1, SeccompActionV1};
    if interval.result_key() != &structural.result_key
        || interval.capture_bytes()?.is_empty()
        || approved_image_device == 0
        || approved_image_inode == 0
    {
        return Err(fail("public filtered ABI kernel interval differs"));
    }
    let target = interval
        .events()
        .iter()
        .find_map(|event| match event {
            KernelEventV1::Exec {
                task,
                image_dev,
                image_inode,
                ..
            } if task.pid == structural.target_pid
                && clock.matches(*task, structural.target_start_ticks)
                && *image_dev == approved_image_device
                && *image_inode == approved_image_inode =>
            {
                Some(*task)
            }
            _ => None,
        })
        .ok_or_else(|| fail("public filtered ABI approved target exec absent"))?;
    let mut seen = HashSet::new();
    for child in &structural.children {
        let task = interval
            .events()
            .iter()
            .find_map(|event| match event {
                KernelEventV1::Fork {
                    parent,
                    child: task,
                } if *parent == target
                    && task.pid == child.pid
                    && clock.matches(*task, child.start_time_ticks) =>
                {
                    Some(*task)
                }
                _ => None,
            })
            .ok_or_else(|| fail("public filtered ABI child fork absent"))?;
        if !seen.insert((
            task.pid,
            task.start_time,
            task.cgroup_inode,
            task.time_ns_inode,
        )) || !interval.seccomp_decision(
            task,
            child.audit_arch,
            i64::from(child.syscall_number),
            SeccompActionV1::KillProcess,
        ) {
            return Err(fail("public filtered ABI seccomp KILL absent"));
        }
        if child.branch == "arm32"
            && !interval.events().iter().any(|event| {
                matches!(event,
                    KernelEventV1::Exec { task: actual, image_dev, image_inode, .. }
                    if *actual == task
                        && Some(*image_dev) == child.helper_device
                        && Some(*image_inode) == child.helper_inode)
            })
        {
            return Err(fail("public filtered ARM32 helper exec absent"));
        }
        let mut decision = None;
        let mut exit = None;
        let mut reap = None;
        for (index, event) in interval.events().iter().enumerate() {
            match event {
                KernelEventV1::SeccompDecision {
                    task: actual,
                    arch,
                    syscall,
                    action: SeccompActionV1::KillProcess,
                    ..
                } if *actual == task
                    && *arch == child.audit_arch
                    && *syscall == i64::from(child.syscall_number) =>
                {
                    if decision.replace(index).is_some() {
                        return Err(fail("public filtered ABI duplicate KILL decision"));
                    }
                }
                KernelEventV1::Exit {
                    task: actual,
                    signal,
                } if *actual == task => {
                    let status = *signal;
                    if exit.replace(index).is_some()
                        || status != libc::SIGSYS
                            && !(libc::WIFSIGNALED(status)
                                && libc::WTERMSIG(status) == libc::SIGSYS)
                    {
                        return Err(fail("public filtered ABI child exit differs"));
                    }
                }
                KernelEventV1::Reap { task: actual } if *actual == task => {
                    if reap.replace(index).is_some() {
                        return Err(fail("public filtered ABI child reap aliases"));
                    }
                }
                KernelEventV1::SyscallReturn {
                    task: actual,
                    arch,
                    syscall,
                    ..
                } if *actual == task
                    && *arch == child.audit_arch
                    && *syscall == i64::from(child.syscall_number) =>
                {
                    return Err(fail("public filtered ABI denied syscall returned"));
                }
                _ => {}
            }
        }
        if !matches!((decision, exit, reap), (Some(d), Some(e), Some(r)) if d < e && e < r)
            || !interval.retired_task(task)
        {
            return Err(fail("public filtered ABI KILL/exit/reap order differs"));
        }
    }
    if seen.len() != structural.children.len() {
        return Err(fail("public filtered ABI child kernel inventory differs"));
    }
    Ok(VerifiedPublicAbiFilteredKernelV1 {
        capture_sha256: interval.trace_sha256().clone(),
        child_count: seen.len(),
    })
}
