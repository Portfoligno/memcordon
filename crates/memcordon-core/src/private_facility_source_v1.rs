//! Closed sacrificial-helper source protocol. These records alone are not
//! authority: replay also requires enrolled kernel install/operation/lifecycle
//! capture, the original reader clock and independently reviewed case recipe.
use crate::{DiagnosticSha256, workload_codec::hash_bytes};
use serde::{Deserialize, Serialize};

pub fn facility_source_revision_sha256() -> DiagnosticSha256 {
    hash_bytes(b"memcordon/owned-facility-controls/v1\0root-owned-disposable-helper;native-noop-retallow-install;real-valid-outer-success;exact-private-installed-filter;same-held-context-private-errno;typed-operands;all-exceptions-closed;source-helper-exit-reap;no-ordinary-target-exceptions\0")
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FacilityOperationV1 {
    Socket,
    Socketpair,
    IoUringSetup,
    PidfdGetfd,
    Setns,
    Unshare,
    Sendmsg,
}
pub fn facility_operations_v1(
    selector: &str,
) -> Result<&'static [FacilityOperationV1], &'static str> {
    use FacilityOperationV1::*;
    match selector {
        "private_tcp::af_unix_abstract_and_pathname_denied" => Ok(&[Socket]),
        "private_tcp::af_unix_socketpair_denied" => Ok(&[Socket, Socketpair]),
        "private_tcp::io_uring_and_pidfd_import_denied" => Ok(&[IoUringSetup, PidfdGetfd]),
        "private_tcp::namespace_reentry_denied" => Ok(&[Setns, Unshare]),
        "private_tcp::scm_rights_and_precreated_socket_denied" => Ok(&[Sendmsg]),
        _ => Err("facility selector is outside the closed controls catalogue"),
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FacilityPhaseV1 {
    Outer,
    Private,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FacilityProcessV1 {
    pub pid: u32,
    pub start_time_ticks: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FacilityObjectV1 {
    pub role: String,
    pub fd: i32,
    pub device: u64,
    pub inode: u64,
    /// Original fdinfo bytes, including actual pidfd/source context.
    pub fdinfo: Vec<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum FacilityOperandV1 {
    Scalars,
    Socketpair {
        output_address: u64,
        slots_before: [i32; 2],
        slots_after: [i32; 2],
    },
    IoUring {
        parameter_address: u64,
        parameters_before: [u64; 15],
        parameters_after: [u64; 15],
    },
    Descriptor {
        object: FacilityObjectV1,
        source: Option<FacilityObjectV1>,
        source_process: Option<FacilityProcessV1>,
    },
    ScmRights {
        socket: FacilityObjectV1,
        source: FacilityObjectV1,
        message_address: u64,
        iov_address: u64,
        payload_address: u64,
        control_address: u64,
        payload: Vec<u8>,
        control_bytes: Vec<u8>,
        transferred_device: Option<u64>,
        transferred_inode: Option<u64>,
    },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FacilityCallV1 {
    pub operation: FacilityOperationV1,
    pub phase: FacilityPhaseV1,
    pub audit_arch: u32,
    pub syscall_nr: i64,
    pub args: [u64; 6],
    pub before_monotonic_ns: u64,
    pub after_monotonic_ns: u64,
    pub result: i64,
    pub errno: u32,
    pub namespace_before: u64,
    pub namespace_after: u64,
    pub operand: FacilityOperandV1,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FacilityCloseV1 {
    pub object: FacilityObjectV1,
    pub before_monotonic_ns: u64,
    pub after_monotonic_ns: u64,
    pub result: i32,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FacilitySourceReportV1 {
    pub schema_version: u8,
    pub source_revision_sha256: DiagnosticSha256,
    pub selector: String,
    pub parent_result_key: DiagnosticSha256,
    pub helper: FacilityProcessV1,
    pub source_process: Option<FacilityProcessV1>,
    pub private_filter_sha256: DiagnosticSha256,
    pub outer_filter_sha256: DiagnosticSha256,
    pub status_after_outer_install: Vec<u8>,
    pub status_after_private_install: Vec<u8>,
    pub calls: Vec<FacilityCallV1>,
    pub closes: Vec<FacilityCloseV1>,
    pub source_wait_status: Option<i32>,
    pub helper_wait_status: i32,
}

pub fn outer_allow_program_v1() -> [u8; 8] {
    // Native cBPF sock_filter { RET|K, jt=0, jf=0, SECCOMP_RET_ALLOW }.
    let mut bytes = [0; 8];
    bytes[..2].copy_from_slice(&6u16.to_le_bytes());
    bytes[4..].copy_from_slice(&0x7fff0000u32.to_le_bytes());
    bytes
}

/// Structural diagnostic only. Genuine enforcement additionally needs exact
/// original kernel events, installed programs, held source and lifecycle joins.
pub fn validate_facility_source_shape(report: &FacilitySourceReportV1) -> Result<(), &'static str> {
    use FacilityOperationV1::*;
    let operations = facility_operations_v1(&report.selector)?;
    if report.schema_version != 1
        || report.source_revision_sha256 != facility_source_revision_sha256()
        || report.helper.pid == 0
        || report.helper.start_time_ticks == 0
        || report.helper_wait_status != 0
        || report.outer_filter_sha256 != hash_bytes(&outer_allow_program_v1())
        || report.calls.len() != operations.len() * 2
        || report.status_after_outer_install.len() > 8192
        || report.status_after_private_install.len() > 8192
        || operations.contains(&PidfdGetfd)
            != (report.source_process.is_some() && report.source_wait_status == Some(0))
        || !operations.contains(&PidfdGetfd)
            && (report.source_process.is_some() || report.source_wait_status.is_some())
    {
        return Err("facility source header/lifecycle shape differs");
    }
    for (index, operation) in operations.iter().enumerate() {
        let outer = &report.calls[index];
        let private = &report.calls[index + operations.len()];
        if outer.operation != *operation
            || private.operation != *operation
            || outer.phase != FacilityPhaseV1::Outer
            || private.phase != FacilityPhaseV1::Private
            || outer.audit_arch != private.audit_arch
            || outer.syscall_nr != private.syscall_nr
            || outer.args != private.args
            || outer.before_monotonic_ns == 0
            || outer.after_monotonic_ns <= outer.before_monotonic_ns
            || private.after_monotonic_ns <= private.before_monotonic_ns
            || outer.after_monotonic_ns >= private.before_monotonic_ns
            || outer.errno != 0
            || outer.result < 0
            || private.result != -1
            || private.errno != if *operation == Socket { 97 } else { 1 }
            || outer.namespace_before == 0
            || outer.namespace_after == 0
            || private.namespace_before == 0
            || private.namespace_before != private.namespace_after
        {
            return Err("facility actual outer/private paired shape differs");
        }
        let native_nr = match (outer.audit_arch, operation) {
            (0xc000003e, Socket) => 41,
            (0xc000003e, Socketpair) => 53,
            (0xc000003e, IoUringSetup) => 425,
            (0xc000003e, PidfdGetfd) => 438,
            (0xc000003e, Setns) => 308,
            (0xc000003e, Unshare) => 272,
            (0xc000003e, Sendmsg) => 46,
            (0xc00000b7, Socket) => 198,
            (0xc00000b7, Socketpair) => 199,
            (0xc00000b7, IoUringSetup) => 425,
            (0xc00000b7, PidfdGetfd) => 438,
            (0xc00000b7, Setns) => 268,
            (0xc00000b7, Unshare) => 97,
            (0xc00000b7, Sendmsg) => 211,
            _ => return Err("facility native ABI differs"),
        };
        if outer.syscall_nr != native_nr {
            return Err("facility native syscall differs");
        }
        let valid_object = |object: &FacilityObjectV1| {
            object.fd >= 0 && object.inode != 0 && object.fdinfo.len() <= 8192
        };
        let same_object = |a: &FacilityObjectV1, b: &FacilityObjectV1| {
            a.fd == b.fd && a.device == b.device && a.inode == b.inode && a.role == b.role
        };
        match (&outer.operand, &private.operand, operation) {
            (FacilityOperandV1::Scalars, FacilityOperandV1::Scalars, Socket)
                if outer.args[0] == 1
                    && outer.args[1] == 0x80001
                    && outer.args[2..] == [0; 4]
                    && outer.result <= i32::MAX as i64 => {}
            (FacilityOperandV1::Scalars, FacilityOperandV1::Scalars, Unshare)
                if outer.args == [0x40000000, 0, 0, 0, 0, 0]
                    && outer.result == 0
                    && outer.namespace_after != outer.namespace_before => {}
            (
                FacilityOperandV1::Socketpair {
                    output_address: a,
                    slots_before: b,
                    slots_after: c,
                },
                FacilityOperandV1::Socketpair {
                    output_address: d,
                    slots_before: e,
                    slots_after: f,
                },
                Socketpair,
            ) if a == d
                && *a != 0
                && *b == [-1; 2]
                && c.iter().all(|fd| *fd >= 0)
                && c[0] != c[1]
                && *e == [-1; 2]
                && *f == [-1; 2]
                && outer.result == 0
                && outer.args == [1, 0x80001, 0, *a, 0, 0] => {}
            (
                FacilityOperandV1::IoUring {
                    parameter_address: a,
                    parameters_before: b,
                    ..
                },
                FacilityOperandV1::IoUring {
                    parameter_address: c,
                    parameters_before: d,
                    parameters_after: e,
                },
                IoUringSetup,
            ) if a == c
                && *a != 0
                && *b == [0; 15]
                && *d == [0; 15]
                && *e == [0; 15]
                && outer.args == [1, *a, 0, 0, 0, 0]
                && outer.result <= i32::MAX as i64 => {}
            (
                FacilityOperandV1::Descriptor {
                    object: a,
                    source: Some(b),
                    source_process: Some(c),
                },
                FacilityOperandV1::Descriptor {
                    object: d,
                    source: Some(e),
                    source_process: Some(f),
                },
                PidfdGetfd,
            ) if valid_object(a)
                && valid_object(b)
                && same_object(a, d)
                && same_object(b, e)
                && c == f
                && Some(c) == report.source_process.as_ref()
                && c.pid != 0
                && c.start_time_ticks != 0
                && a.role == "pidfd"
                && b.role == "source"
                && outer.args == [a.fd as u64, b.fd as u64, 0, 0, 0, 0]
                && outer.result <= i32::MAX as i64 => {}
            (
                FacilityOperandV1::Descriptor {
                    object: a,
                    source: None,
                    source_process: None,
                },
                FacilityOperandV1::Descriptor {
                    object: b,
                    source: None,
                    source_process: None,
                },
                Setns,
            ) if valid_object(a)
                && same_object(a, b)
                && a.role == "namespace"
                && a.inode == outer.namespace_before
                && outer.namespace_after == outer.namespace_before
                && outer.result == 0
                && outer.args == [a.fd as u64, 0x40000000, 0, 0, 0, 0] => {}
            (
                FacilityOperandV1::ScmRights {
                    socket: a,
                    source: b,
                    message_address: c,
                    iov_address: d,
                    payload_address: e,
                    control_address: f,
                    payload: g,
                    control_bytes: h,
                    transferred_device: Some(i),
                    transferred_inode: Some(j),
                },
                FacilityOperandV1::ScmRights {
                    socket: k,
                    source: l,
                    message_address: m,
                    iov_address: n,
                    payload_address: o,
                    control_address: p,
                    payload: q,
                    control_bytes: r,
                    transferred_device: None,
                    transferred_inode: None,
                },
                Sendmsg,
            ) if valid_object(a)
                && valid_object(b)
                && same_object(a, k)
                && same_object(b, l)
                && a.role == "scm-send"
                && b.role == "source"
                && c == m
                && d == n
                && e == o
                && f == p
                && [*c, *d, *e, *f].iter().all(|v| *v != 0)
                && g == q
                && *g == [0x51]
                && h == r
                && h.len() == 24
                && h[..8] == 20u64.to_le_bytes()
                && h[8..12] == 1u32.to_le_bytes()
                && h[12..16] == 1u32.to_le_bytes()
                && h[16..20] == b.fd.to_le_bytes()
                && h[20..] == [0; 4]
                && *i == b.device
                && *j == b.inode
                && outer.result == 1
                && outer.args == [a.fd as u64, *c, 0x4000, 0, 0, 0] => {}
            _ => return Err("facility tightly bound valid operands differ"),
        }
    }
    if report.closes.is_empty()
        || report.closes.iter().any(|close| {
            close.object.fd < 0
                || close.object.inode == 0
                || close.result != 0
                || close.before_monotonic_ns == 0
                || close.after_monotonic_ns < close.before_monotonic_ns
                || close.before_monotonic_ns
                    <= report
                        .calls
                        .last()
                        .expect("closed nonempty facility operations")
                        .after_monotonic_ns
        })
    {
        return Err("facility actual exception closes absent or early");
    }
    Ok(())
}
