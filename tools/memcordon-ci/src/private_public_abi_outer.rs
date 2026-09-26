//! Structural custody for the installed service's outer-only ABI controls.
//! These children are never the filtered public CLI target. A public P join
//! must additionally verify their independent kernel events and the actual
//! public target's filtered denial in separate, loss-free intervals.

use std::collections::BTreeSet;

use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::{PrivateReleaseStageV1, private_release_case_key_v1};
use memcordon_core::workload_codec::hash_bytes;
use serde::{Deserialize, Serialize};

use crate::{CiError, Result};

const SELECTOR: &str = "private_tcp::abi_alternate_entry_denied";
const DOMAIN: &[u8] = b"memcordon-public-abi-outer-v1\0";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RequestV1 {
    schema: u32,
    selector: String,
    challenge: DiagnosticSha256,
    dispatch_key: DiagnosticSha256,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IdentityV1 {
    pid: u32,
    start_time: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OuterV1 {
    service: IdentityV1,
    service_worker: IdentityV1,
    cgroup: String,
    cgroup_inode: u64,
    seccomp_mode: u32,
    seccomp_filters: u32,
    no_new_privs: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BranchV1 {
    branch: String,
    child: IdentityV1,
    audit_arch: u32,
    syscall_nr: u32,
    return_value: Option<i64>,
    errno: Option<i32>,
    return_marker: Option<u8>,
    exec_device: Option<u64>,
    exec_inode: Option<u64>,
    exit_code: i32,
    reaped: bool,
    inherited_outer_filters: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawV1 {
    schema: u32,
    selector: String,
    auxiliary_only: bool,
    challenge_sha256: DiagnosticSha256,
    dispatch_key: DiagnosticSha256,
    auxiliary_key: DiagnosticSha256,
    h1_sha256: DiagnosticSha256,
    installation_epoch: DiagnosticSha256,
    outer: OuterV1,
    branches: Vec<BranchV1>,
}

/// Exact independently held helper-image metadata. Parsing this diagnostic
/// carrier does not confer origin, installation, or ABI authority.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicAbiHelperImageV1 {
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub nlink: u64,
    pub size: u64,
    pub sha256: DiagnosticSha256,
}

/// Validate original held bytes against an independently approved H1 image
/// pin. The result is an object identity, not a semantic capability.
pub fn validate_public_abi_helper_image_v1(
    bytes: &[u8],
    metadata: &[u8],
    expected: &DiagnosticSha256,
) -> Result<(u64, u64)> {
    let image: PublicAbiHelperImageV1 =
        crate::private_observer_session::strict_json(metadata, 4096)?;
    if bytes.is_empty()
        || bytes.len() > 8 * 1024 * 1024
        || image.device == 0
        || image.inode == 0
        || image.uid != 0
        || image.gid != 0
        || image.mode & u32::from(libc::S_IFMT) != u32::from(libc::S_IFREG)
        || image.mode & 0o022 != 0
        || image.mode & 0o111 == 0
        || image.nlink != 1
        || image.size != bytes.len() as u64
        || image.sha256 != *expected
        || hash_bytes(bytes) != *expected
    {
        return Err(CiError::Message(
            "public ABI original held helper image or object protection differs".into(),
        ));
    }
    Ok((image.device, image.inode))
}

pub struct ExpectedPublicAbiOuterV1<'a> {
    pub target: &'a str,
    pub challenge: &'a [u8; 32],
    pub h1_sha256: &'a DiagnosticSha256,
    pub installation_epoch: &'a DiagnosticSha256,
    pub service_pid: u32,
    pub service_start_ticks: u64,
    pub service_cgroup_inode: u64,
}

/// A typed *structural* readback, deliberately not a public semantic token.
pub struct StructuralPublicAbiOuterV1 {
    pub dispatch_key: DiagnosticSha256,
    pub auxiliary_key: DiagnosticSha256,
    pub request_sha256: DiagnosticSha256,
    pub raw_sha256: DiagnosticSha256,
    pub service_worker_pid: u32,
    pub service_worker_start_ticks: u64,
    pub children: Vec<(u32, u64)>,
    branches: Vec<BranchV1>,
    service_pid: u32,
    service_start_ticks: u64,
    service_cgroup_inode: u64,
}

pub(crate) struct VerifiedPublicAbiOuterKernelV1 {
    capture_sha256: DiagnosticSha256,
}

impl VerifiedPublicAbiOuterKernelV1 {
    pub(crate) fn capture_sha256(&self) -> &DiagnosticSha256 {
        &self.capture_sha256
    }
}

fn canonical<T: for<'de> Deserialize<'de> + Serialize>(bytes: &[u8], bound: usize) -> Result<T> {
    if bytes.is_empty() || bytes.len() > bound {
        return Err(CiError::Message(
            "public ABI outer raw byte bound differs".into(),
        ));
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)
        .map_err(CiError::Message)?;
    let value: T = serde_json::from_slice(bytes)?;
    if serde_json::to_vec(&value)? != bytes {
        return Err(CiError::Message(
            "public ABI outer raw is not canonical".into(),
        ));
    }
    Ok(value)
}

pub fn readback_public_abi_outer_v1(
    request_bytes: &[u8],
    raw_bytes: &[u8],
    expected: &ExpectedPublicAbiOuterV1<'_>,
) -> Result<StructuralPublicAbiOuterV1> {
    let request: RequestV1 = canonical(request_bytes, 1024)?;
    let raw: RawV1 = canonical(raw_bytes, 16 * 1024)?;
    let dispatch_key = private_release_case_key_v1(
        PrivateReleaseStageV1::FinalPublic,
        SELECTOR,
        expected.challenge,
    )
    .map_err(CiError::Message)?;
    let mut auxiliary_key_bytes = DOMAIN.to_vec();
    for digest in [
        expected.h1_sha256,
        expected.installation_epoch,
        &dispatch_key,
        &DiagnosticSha256::from_bytes(*expected.challenge),
    ] {
        auxiliary_key_bytes.extend_from_slice(digest.bytes());
    }
    let auxiliary_key = hash_bytes(&auxiliary_key_bytes);
    if request.schema != 1
        || request.selector != SELECTOR
        || request.challenge.bytes() != expected.challenge
        || request.dispatch_key != dispatch_key
        || raw.schema != 1
        || raw.selector != SELECTOR
        || !raw.auxiliary_only
        || raw.challenge_sha256 != hash_bytes(expected.challenge)
        || raw.dispatch_key != dispatch_key
        || raw.auxiliary_key != auxiliary_key
        || raw.h1_sha256 != *expected.h1_sha256
        || raw.installation_epoch != *expected.installation_epoch
        || raw.outer.service.pid != expected.service_pid
        || raw.outer.service.start_time != expected.service_start_ticks
        || raw.outer.cgroup_inode != expected.service_cgroup_inode
        || raw.outer.service_worker.pid == 0
        || raw.outer.service_worker.start_time == 0
        || raw.outer.service_worker == raw.outer.service
        || raw.outer.cgroup.is_empty()
        || raw.outer.seccomp_mode != 2
        || raw.outer.seccomp_filters == 0
        || raw.outer.no_new_privs != 1
    {
        return Err(CiError::Message(
            "public ABI outer identity or provenance differs".into(),
        ));
    }
    let branches: &[(&str, u32, u32)] = match expected.target {
        "x86_64-unknown-linux-gnu" => &[
            ("native", 0xc000_003e, 39),
            ("x32", 0xc000_003e, 0x4000_0027),
            ("i386", 0x4000_0003, 20),
        ],
        "aarch64-unknown-linux-gnu" => &[("native", 0xc000_00b7, 172), ("arm32", 0x4000_0028, 20)],
        _ => return Err(CiError::Message("public ABI outer target differs".into())),
    };
    if raw.branches.len() != branches.len() {
        return Err(CiError::Message(
            "public ABI outer branch inventory differs".into(),
        ));
    }
    let mut children = BTreeSet::new();
    for (branch, (name, arch, nr)) in raw.branches.iter().zip(branches) {
        let valid_result = if *name == "x32" {
            branch.return_marker.is_none()
                && branch.exec_device.is_none()
                && branch.exec_inode.is_none()
                && (branch.return_value == Some(i64::from(branch.child.pid))
                    && branch.errno.is_none()
                    || branch.return_value == Some(-1) && branch.errno == Some(38))
        } else if *name == "arm32" {
            branch.return_value.is_none()
                && branch.errno.is_none()
                && branch.return_marker == Some(b'A')
                && branch.exec_device.is_some_and(|value| value != 0)
                && branch.exec_inode.is_some_and(|value| value != 0)
        } else {
            branch.return_value == Some(i64::from(branch.child.pid))
                && branch.errno.is_none()
                && branch.return_marker.is_none()
                && branch.exec_device.is_none()
                && branch.exec_inode.is_none()
        };
        if branch.branch != *name
            || branch.audit_arch != *arch
            || branch.syscall_nr != *nr
            || branch.child.pid == 0
            || branch.child.start_time == 0
            || branch.child == raw.outer.service
            || branch.child == raw.outer.service_worker
            || !children.insert((branch.child.pid, branch.child.start_time))
            || branch.exit_code != 0
            || !branch.reaped
            || branch.inherited_outer_filters != raw.outer.seccomp_filters
            || !valid_result
        {
            return Err(CiError::Message("public ABI outer branch differs".into()));
        }
    }
    Ok(StructuralPublicAbiOuterV1 {
        dispatch_key,
        auxiliary_key,
        request_sha256: hash_bytes(request_bytes),
        raw_sha256: hash_bytes(raw_bytes),
        service_worker_pid: raw.outer.service_worker.pid,
        service_worker_start_ticks: raw.outer.service_worker.start_time,
        children: children.into_iter().collect(),
        branches: raw.branches,
        service_pid: raw.outer.service.pid,
        service_start_ticks: raw.outer.service.start_time,
        service_cgroup_inode: raw.outer.cgroup_inode,
    })
}

/// Independently joins the outer-only children to the loss-free kernel event
/// stream. This is still only the *auxiliary* half of a public ABI composite.
pub(crate) fn join_public_abi_outer_kernel_v1(
    structural: &StructuralPublicAbiOuterV1,
    interval: &crate::private_kernel_observer::VerifiedKernelIntervalV1,
    clock: &crate::private_process_clock::VerifiedProcClockCalibrationV1,
) -> Result<VerifiedPublicAbiOuterKernelV1> {
    use crate::private_kernel_observer::{KernelEventV1, SeccompActionV1};
    if interval.result_key() != &structural.auxiliary_key
        || interval.capture_bytes()?.is_empty()
        || !interval.has_allocation_boundary()
        || !interval.no_allocation()
        || interval.cgroup_inode() != structural.service_cgroup_inode
    {
        return Err(CiError::Message(
            "public ABI outer interval identity differs".into(),
        ));
    }
    let worker = interval
        .events()
        .iter()
        .find_map(|event| match event {
            KernelEventV1::Fork { parent, child }
                if parent.pid == structural.service_pid
                    && child.pid == structural.service_worker_pid
                    && parent.cgroup_inode == structural.service_cgroup_inode
                    && child.cgroup_inode == structural.service_cgroup_inode
                    && clock.matches(*parent, structural.service_start_ticks)
                    && clock.matches(*child, structural.service_worker_start_ticks) =>
            {
                Some(*child)
            }
            _ => None,
        })
        .ok_or_else(|| CiError::Message("public ABI outer service worker fork absent".into()))?;
    let mut observed = BTreeSet::new();
    for branch in &structural.branches {
        let task = interval
            .events()
            .iter()
            .find_map(|event| match event {
                KernelEventV1::Fork { parent, child }
                    if *parent == worker
                        && child.pid == branch.child.pid
                        && child.cgroup_inode == structural.service_cgroup_inode
                        && clock.matches(*child, branch.child.start_time) =>
                {
                    Some(*child)
                }
                _ => None,
            })
            .ok_or_else(|| CiError::Message("public ABI outer child fork absent".into()))?;
        if !observed.insert((task.pid, task.start_time))
            || !interval.seccomp_decision(
                task,
                branch.audit_arch,
                i64::from(branch.syscall_nr),
                SeccompActionV1::Allow,
            )
            || !interval.events().iter().any(|event| {
                matches!(event,
                    KernelEventV1::SyscallReturn { task: observed_task, arch, syscall, value }
                        if *observed_task == task && *arch == branch.audit_arch
                            && *syscall == i64::from(branch.syscall_nr)
                            && *value == branch.return_value.unwrap_or(i64::from(task.pid))
                )
            })
            || !interval.retired_task(task)
            || branch.branch == "arm32"
                && !interval.exec_identity(
                    task,
                    branch.exec_device.expect("structural ARM helper device"),
                    branch.exec_inode.expect("structural ARM helper inode"),
                    0,
                )
        {
            return Err(CiError::Message(
                "public ABI outer kernel branch differs".into(),
            ));
        }
    }
    if observed.len() != structural.branches.len() {
        return Err(CiError::Message(
            "public ABI outer kernel inventory differs".into(),
        ));
    }
    if !interval.retired_task(worker) {
        return Err(CiError::Message(
            "public ABI actual outer worker exit/reap absent".into(),
        ));
    }
    Ok(VerifiedPublicAbiOuterKernelV1 {
        capture_sha256: interval.trace_sha256().clone(),
    })
}
