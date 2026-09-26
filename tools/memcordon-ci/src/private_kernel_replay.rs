//! Portable decoding only. Parsed captures never authenticate observer origin.
use crate::{CiError, Result};
use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};
#[path = "private_kernel_filter_replay.rs"]
mod filter_sources;
#[path = "private_kernel_host_replay.rs"]
mod host_sources;
#[path = "private_kernel_reuse_replay.rs"]
mod reuse_sources;
pub(crate) use filter_sources::{
    InstalledKernelFilterV1, installed_kernel_filters, is_filter_install,
};
pub(crate) use host_sources::validate_host_records;
pub(crate) use reuse_sources::validate_reuse_records;

pub(crate) const CAPTURE_HEADER_BYTES_V2: usize = 40;
pub(crate) const CAPTURE_RECORD_BYTES_V2: usize = 192;
pub(crate) const MAX_CAPTURE_BYTES_V2: usize = 8 * 1024 * 1024;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CaptureStageV2 {
    Candidate,
    FinalPublic,
}
impl CaptureStageV2 {
    pub(crate) fn max_capture_bytes(self) -> usize {
        match self {
            Self::Candidate => MAX_CAPTURE_BYTES_V2,
            Self::FinalPublic => CAPTURE_HEADER_BYTES_V2 + 100_000 * CAPTURE_RECORD_BYTES_V2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IntervalPurposeV1 {
    KnownControls,
    Ordinary,
    AbiOuter,
    AbiFiltered,
    Historical,
    CallerSpoof,
    Policy,
    ReuseFirst,
    ReuseBlocked,
    Recovery,
    DualContinuous,
    FacilityControls,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IntervalIdV1 {
    pub(crate) session_nonce: [u8; 32],
    pub(crate) generation: u32,
    pub(crate) logical_case_key: DiagnosticSha256,
    pub(crate) purpose: IntervalPurposeV1,
    pub(crate) ordinal: u32,
}

impl IntervalIdV1 {
    pub(crate) fn storage_sha256(&self) -> DiagnosticSha256 {
        let mut bytes = b"memcordon-physical-interval-v1\0".to_vec();
        bytes.extend_from_slice(&self.session_nonce);
        bytes.extend_from_slice(&self.generation.to_le_bytes());
        bytes.extend_from_slice(self.logical_case_key.bytes());
        bytes.push(self.purpose as u8);
        bytes.extend_from_slice(&self.ordinal.to_le_bytes());
        hash_bytes(&bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KernelTaskIdentityV2 {
    pub(crate) tid: u32,
    pub(crate) tgid: u32,
    pub(crate) start_boottime_ns: u64,
    pub(crate) cgroup_inode: u64,
    pub(crate) time_ns_inode: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KernelEventRecordV2 {
    pub(crate) sequence: u64,
    pub(crate) monotonic_ns: u64,
    pub(crate) task: KernelTaskIdentityV2,
    pub(crate) request_key: DiagnosticSha256,
    pub(crate) kind: u32,
    pub(crate) other_tid: u32,
    pub(crate) image_dev: u64,
    pub(crate) image_inode: u64,
    pub(crate) syscall_arch: u32,
    pub(crate) syscall_nr: i64,
    pub(crate) syscall_result: i64,
    pub(crate) seccomp_action: u32,
    pub(crate) syscall_occurrence: u64,
    pub(crate) args: [u64; 6],
    /// Explicit featurebit8 only: union fields for native bind/connect entry.
    /// Legacy captures cannot prove a concrete network address from a pointer.
    pub(crate) network_address: Option<KernelNetworkAddressV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KernelNetworkAddressV1 {
    pub(crate) family: u16,
    pub(crate) length: u16,
    pub(crate) address: [u8; 4],
    pub(crate) port: u16,
}

pub(crate) struct ParsedKernelCaptureV2 {
    events: Vec<KernelEventRecordV2>,
    digest: DiagnosticSha256,
}
impl ParsedKernelCaptureV2 {
    pub(crate) fn events(&self) -> &[KernelEventRecordV2] {
        &self.events
    }
    pub(crate) fn digest(&self) -> &DiagnosticSha256 {
        &self.digest
    }
}

fn fail(message: &'static str) -> CiError {
    CiError::Message(message.into())
}
fn word<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    bytes
        .get(
            offset
                ..offset
                    .checked_add(N)
                    .ok_or_else(|| fail("capture offset overflow"))?,
        )
        .ok_or_else(|| fail("capture truncated"))?
        .try_into()
        .map_err(|_| fail("capture truncated"))
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(word(bytes, offset)?))
}
fn u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(word(bytes, offset)?))
}
fn i64_at(bytes: &[u8], offset: usize) -> Result<i64> {
    Ok(i64::from_le_bytes(word(bytes, offset)?))
}

/// Lifecycle flags attest loader protocol shape only. Authenticated custody
/// and a supported native detach adapter are separate verifier prerequisites.
pub(crate) fn parse_capture_v2(
    bytes: &[u8],
    expected_key: &DiagnosticSha256,
) -> Result<ParsedKernelCaptureV2> {
    parse_capture_v2_with_budget(bytes, expected_key, CaptureStageV2::Candidate)
}

pub(crate) fn parse_capture_v2_with_budget(
    bytes: &[u8],
    expected_key: &DiagnosticSha256,
    stage: CaptureStageV2,
) -> Result<ParsedKernelCaptureV2> {
    if bytes.len() < CAPTURE_HEADER_BYTES_V2
        || bytes.len() > stage.max_capture_bytes()
        || u32_at(bytes, 0)? != 0x4d434b31
        || u32_at(bytes, 4)? != 2
        || u64_at(bytes, 16)? != 0
        || u32_at(bytes, 24)? != CAPTURE_RECORD_BYTES_V2 as u32
        || !matches!(
            (u32_at(bytes, 28)?, u32_at(bytes, 32)?),
            (3, 11)
                | (7, 12)
                | (15, 12)
                | (31, 12)
                | (47, 16)
                | (63, 16)
                | (79, 14)
                | (95, 14)
                | (111, 18)
                | (127, 18)
        )
        || u32_at(bytes, 36)? != 0x01020304
    {
        return Err(fail("V2 capture header/loss/lifecycle differs"));
    }
    let unfiltered_lifecycle = u32_at(bytes, 28)? & 4 != 0;
    let network_operands = u32_at(bytes, 28)? & 8 != 0;
    let filter_evidence = u32_at(bytes, 28)? & 16 != 0;
    let host_evidence = u32_at(bytes, 28)? & 32 != 0;
    let reuse_evidence = u32_at(bytes, 28)? & 64 != 0;
    let count = usize::try_from(u64_at(bytes, 8)?).map_err(|_| fail("capture count overflow"))?;
    let length = count
        .checked_mul(CAPTURE_RECORD_BYTES_V2)
        .and_then(|n| n.checked_add(CAPTURE_HEADER_BYTES_V2))
        .ok_or_else(|| fail("capture size overflow"))?;
    if count == 0 || length != bytes.len() {
        return Err(fail("V2 capture length differs"));
    }
    let mut events = Vec::with_capacity(count);
    let mut pending = std::collections::BTreeMap::<(u32, u64), (u64, u32, i64, [u64; 6])>::new();
    let mut occurrences = std::collections::BTreeSet::new();
    for (index, raw) in bytes[CAPTURE_HEADER_BYTES_V2..]
        .chunks_exact(CAPTURE_RECORD_BYTES_V2)
        .enumerate()
    {
        let task = KernelTaskIdentityV2 {
            tid: u32_at(raw, 64)?,
            tgid: u32_at(raw, 184)?,
            start_boottime_ns: u64_at(raw, 24)?,
            cgroup_inode: u64_at(raw, 16)?,
            time_ns_inode: u64_at(raw, 120)?,
        };
        let kind = u32_at(raw, 80)?;
        let args = [
            u64_at(raw, 136)?,
            u64_at(raw, 144)?,
            u64_at(raw, 152)?,
            u64_at(raw, 160)?,
            u64_at(raw, 168)?,
            u64_at(raw, 176)?,
        ];
        let network_address = if network_operands
            && kind == 4
            && matches!(
                (u32_at(raw, 72)?, i64_at(raw, 48)?),
                (0xc000003e, 49 | 42) | (0xc00000b7, 200 | 203)
            ) {
            let tag = u64_at(raw, 32)?;
            let value = u64_at(raw, 40)?;
            if tag != (2u64 << 32 | 16) || args[1] == 0 || args[2] != 16 || value & 0xffff0000 != 0
            {
                return Err(fail(
                    "V2 checked native socket operand family/length/reserved differs",
                ));
            }
            Some(KernelNetworkAddressV1 {
                family: 2,
                length: 16,
                address: ((value >> 32) as u32).to_le_bytes(),
                port: value as u16,
            })
        } else {
            None
        };
        let record = KernelEventRecordV2 {
            sequence: u64_at(raw, 0)?,
            monotonic_ns: u64_at(raw, 8)?,
            task,
            request_key: expected_key.clone(),
            kind,
            other_tid: u32_at(raw, 68)?,
            image_dev: u64_at(raw, 32)?,
            image_inode: u64_at(raw, 40)?,
            syscall_arch: u32_at(raw, 72)?,
            syscall_nr: i64_at(raw, 48)?,
            syscall_result: i64_at(raw, 56)?,
            seccomp_action: u32_at(raw, 76)?,
            syscall_occurrence: u64_at(raw, 128)?,
            args,
            network_address,
        };
        if record.sequence != index as u64 + 1
            || record.monotonic_ns == 0
            || task.tid == 0
            || task.tgid == 0
            || task.start_boottime_ns == 0
            || task.cgroup_inode == 0
            || task.time_ns_inode == 0
            || !(1..=if reuse_evidence {
                19
            } else if host_evidence {
                16
            } else if filter_evidence {
                14
            } else if unfiltered_lifecycle {
                11
            } else {
                10
            })
                .contains(&kind)
            || raw[84..116] != *expected_key.bytes()
            || u32_at(raw, 188)? != 0
        {
            return Err(fail("V2 capture event identity/order differs"));
        }
        let identity = (task.tid, task.start_boottime_ns);
        if kind == 17 {
            if !reuse_evidence
                || record.seccomp_action != 0
                || record.syscall_result != 0
                || record.syscall_occurrence == 0
                || !occurrences.insert(record.syscall_occurrence)
                || pending
                    .insert(
                        identity,
                        (
                            record.syscall_occurrence,
                            record.syscall_arch,
                            record.syscall_nr,
                            args,
                        ),
                    )
                    .is_some()
            {
                return Err(fail("reuse native entry/occurrence differs"));
            }
        } else if kind == 11 {
            if !unfiltered_lifecycle
                || record.seccomp_action != 0
                || record.syscall_result != 0
                || record.syscall_occurrence == 0
                || !occurrences.insert(record.syscall_occurrence)
                || !(reviewed_unfiltered_syscall(record.syscall_arch, record.syscall_nr)
                    || filter_evidence
                        && is_filter_install(record.syscall_arch, record.syscall_nr, &args))
                || pending
                    .insert(
                        identity,
                        (
                            record.syscall_occurrence,
                            record.syscall_arch,
                            record.syscall_nr,
                            args,
                        ),
                    )
                    .is_some()
            {
                return Err(fail("V2 unfiltered lifecycle entry differs"));
            }
        } else if kind == 4 {
            if record.syscall_occurrence == 0
                || !occurrences.insert(record.syscall_occurrence)
                || !matches!(record.seccomp_action, 0x7fff0000 | 0x00050000 | 0x80000000)
                || !(0..=65535).contains(&record.syscall_result)
            {
                return Err(fail("V2 syscall decision differs"));
            }
            // KILL_PROCESS has no syscall return; the lifecycle verifier must
            // join exact SIGSYS exit and reap for this occurrence's task.
            if record.seccomp_action != 0x80000000
                && pending
                    .insert(
                        identity,
                        (
                            record.syscall_occurrence,
                            record.syscall_arch,
                            record.syscall_nr,
                            args,
                        ),
                    )
                    .is_some()
            {
                return Err(fail("V2 syscall occurrence overlapped"));
            }
        } else if kind == 5 {
            if pending.remove(&identity)
                != Some((
                    record.syscall_occurrence,
                    record.syscall_arch,
                    record.syscall_nr,
                    args,
                ))
            {
                return Err(fail("V2 syscall return lacks exact entry/decision"));
            }
        } else if matches!(kind, 12..=14) {
            if !filter_evidence {
                return Err(fail("filter metadata lacks explicit source feature"));
            }
            // Feature16 metadata does not create a second syscall entry. Its
            // exact source occurrence and role are checked against the full
            // capture by installed_kernel_filters below.
        } else if matches!(kind, 15..=16) {
            if !host_evidence {
                return Err(fail("host metadata lacks explicit source feature"));
            }
        } else if matches!(kind, 18 | 19) {
            if !reuse_evidence {
                return Err(fail("reuse metadata lacks explicit source feature"));
            }
        } else if record.syscall_occurrence != 0 || args != [0; 6] {
            return Err(fail("V2 non-syscall carries operands"));
        }
        events.push(record);
    }
    // A final exit may interrupt an allowed exit syscall. Other outstanding
    // calls indicate a cut capture and cannot establish complete observation.
    for ((tid, start), _) in pending {
        if !events.iter().any(|event| {
            event.kind == 8 && event.task.tid == tid && event.task.start_boottime_ns == start
        }) {
            return Err(fail("V2 capture ends inside syscall"));
        }
    }
    if filter_evidence {
        installed_kernel_filters(&events)?;
    }
    if host_evidence {
        validate_host_records(&events)?;
    }
    if reuse_evidence {
        validate_reuse_records(&events)?;
    }
    Ok(ParsedKernelCaptureV2 {
        events,
        digest: hash_bytes(bytes),
    })
}

pub(crate) fn reviewed_unfiltered_syscall(arch: u32, nr: i64) -> bool {
    match arch {
        0xc000003e => matches!(nr, 0 | 1 | 3 | 44 | 46 | 47 | 48 | 62 | 74 | 75 | 234 | 424),
        0xc00000b7 => matches!(
            nr,
            57 | 63 | 64 | 82 | 83 | 129 | 131 | 206 | 210 | 211 | 212 | 424
        ),
        _ => false,
    }
}

/// Diagnostic compatibility projection. Keep V2 bytes/records for semantic
/// replay: this projection alone cannot prove operands or occurrence joins.
pub(crate) fn diagnostic_v1_projection(bytes: &[u8], key: &DiagnosticSha256) -> Result<Vec<u8>> {
    diagnostic_v1_projection_with_stage(bytes, key, CaptureStageV2::Candidate)
}

pub(crate) fn diagnostic_v1_projection_with_stage(
    bytes: &[u8],
    key: &DiagnosticSha256,
    stage: CaptureStageV2,
) -> Result<Vec<u8>> {
    let parsed = parse_capture_v2_with_budget(bytes, key, stage)?;
    let mut output = Vec::new();
    output.extend_from_slice(&0x4d434b31u32.to_le_bytes());
    output.extend_from_slice(&1u32.to_le_bytes());
    let unfiltered = parsed
        .events
        .iter()
        .filter(|event| matches!(event.kind, 11 | 17))
        .map(|event| event.syscall_occurrence)
        .collect::<std::collections::BTreeSet<_>>();
    let selected = parsed
        .events
        .iter()
        .filter(|event| {
            event.kind <= 10 && !(event.kind == 5 && unfiltered.contains(&event.syscall_occurrence))
        })
        .collect::<Vec<_>>();
    output.extend_from_slice(&(selected.len() as u64).to_le_bytes());
    output.extend_from_slice(&0u64.to_le_bytes());
    for (index, event) in selected.iter().enumerate() {
        let offset =
            CAPTURE_HEADER_BYTES_V2 + (event.sequence as usize - 1) * CAPTURE_RECORD_BYTES_V2;
        let raw = &bytes[offset..offset + 128];
        // This named diagnostic projection has its own order-preserving rank;
        // original raw sequence remains immutable for every causal proof.
        output.extend_from_slice(&(index as u64 + 1).to_le_bytes());
        output.extend_from_slice(&raw[8..]);
    }
    Ok(output)
}
