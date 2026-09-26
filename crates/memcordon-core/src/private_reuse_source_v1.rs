//! Versioned candidate-only recovery source. None of these records grants
//! qualification: origin replay must join actual kernel operands and the
//! original physical retirement in three distinct enrolled intervals.
use crate::{DiagnosticSha256, workload_codec::hash_bytes};
use serde::{Deserialize, Serialize};
pub const REUSE_SELECTOR_V1: &str = "private_tcp::retirement_failure_blocks_reuse";
pub fn reuse_source_revision_sha256() -> DiagnosticSha256 {
    hash_bytes(b"memcordon/candidate-owned-retirement-recovery/v1\0original-physical-retirement;canonical-retiring-journal;exact-owned-exclusive-marker;actual-same-key-openat-eexist;independent-held-directory-marker-record;checked-unlinkat-owned-marker;normal-fsync-renameat2-fsync-retired-readback;three-distinct-enrolled-intervals;no-allocation-or-new-release\0")
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReuseSourcePhaseV1 {
    Blocked,
    Recover,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReuseSourceProcessV1 {
    pub pid: u32,
    pub start_time_ticks: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReuseSourceObjectV1 {
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
    pub mode: u32,
    pub nlink: u64,
    pub size: u64,
    pub bytes_sha256: DiagnosticSha256,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReuseSourceGateV1 {
    pub schema_version: u8,
    pub source_revision_sha256: DiagnosticSha256,
    pub phase: ReuseSourcePhaseV1,
    pub selector: String,
    pub parent_result_key: DiagnosticSha256,
    pub challenge: [u8; 32],
    pub admission_sha256: DiagnosticSha256,
    pub helper: ReuseSourceProcessV1,
    pub directory_device: u64,
    pub directory_inode: u64,
    pub marker: ReuseSourceObjectV1,
    pub record: ReuseSourceObjectV1,
    pub observed_monotonic_ns: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReuseSourceAckV1 {
    pub schema_version: u8,
    pub source_revision_sha256: DiagnosticSha256,
    pub phase: ReuseSourcePhaseV1,
    pub parent_result_key: DiagnosticSha256,
    pub gate_sha256: DiagnosticSha256,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReuseSourceAdmissionV1 {
    pub schema_version: u8,
    pub protocol: String,
    pub source_revision_sha256: DiagnosticSha256,
    pub phase: ReuseSourcePhaseV1,
    pub selector: String,
    pub parent_result_key: DiagnosticSha256,
    pub challenge: [u8; 32],
    pub original_request_sha256: DiagnosticSha256,
    pub installation_epoch: DiagnosticSha256,
    pub candidate_manifest_sha256: DiagnosticSha256,
    pub installed_inspection_sha256: DiagnosticSha256,
    pub service_generation_sha256: DiagnosticSha256,
    pub helper: ReuseSourceProcessV1,
    pub admission_monotonic_ns: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReuseSourceReportV1 {
    pub schema_version: u8,
    pub source_revision_sha256: DiagnosticSha256,
    pub phase: ReuseSourcePhaseV1,
    pub parent_result_key: DiagnosticSha256,
    pub helper: ReuseSourceProcessV1,
    pub admission_sha256: DiagnosticSha256,
    pub gate_sha256: DiagnosticSha256,
    pub before_bytes: Vec<u8>,
    pub marker_bytes: Vec<u8>,
    pub original_observer_bytes: Vec<u8>,
    pub retry_begin_monotonic_ns: u64,
    pub retry_end_monotonic_ns: u64,
    pub actual_reuse_error: String,
    pub removed_monotonic_ns: Option<u64>,
    pub recovered_monotonic_ns: Option<u64>,
    pub after_bytes: Option<Vec<u8>>,
}
pub fn validate_reuse_source_shape_v1(
    gate: &ReuseSourceGateV1,
    report: &ReuseSourceReportV1,
) -> Result<(), &'static str> {
    if gate.schema_version != 1
        || report.schema_version != 1
        || gate.source_revision_sha256 != reuse_source_revision_sha256()
        || report.source_revision_sha256 != gate.source_revision_sha256
        || gate.selector != REUSE_SELECTOR_V1
        || gate.phase != report.phase
        || gate.parent_result_key != report.parent_result_key
        || gate.helper != report.helper
        || gate.helper.pid == 0
        || gate.helper.start_time_ticks == 0
        || gate.challenge == [0; 32]
        || gate.directory_device == 0
        || gate.directory_inode == 0
        || gate.marker.device == 0
        || gate.marker.inode == 0
        || gate.record.device == 0
        || gate.record.inode == 0
        || (gate.marker.device, gate.marker.inode) == (gate.record.device, gate.record.inode)
        || [&gate.marker, &gate.record]
            .iter()
            .any(|object| object.uid != 0 || object.mode & 0o777 != 0o600 || object.nlink != 1)
        || gate.marker.size != report.marker_bytes.len() as u64
        || gate.record.size != report.before_bytes.len() as u64
        || gate.marker.bytes_sha256 != hash_bytes(&report.marker_bytes)
        || gate.record.bytes_sha256 != hash_bytes(&report.before_bytes)
        || gate.admission_sha256 != report.admission_sha256
        || hash_bytes(
            &serde_json::to_vec(gate).map_err(|_| "reuse canonical gate serialization failed")?,
        ) != report.gate_sha256
        || gate.observed_monotonic_ns == 0
        || report.retry_begin_monotonic_ns <= gate.observed_monotonic_ns
        || report.retry_end_monotonic_ns <= report.retry_begin_monotonic_ns
        || report.actual_reuse_error.is_empty()
        || report.original_observer_bytes.is_empty()
        || report.before_bytes.is_empty()
        || report.marker_bytes.is_empty()
    {
        return Err("reuse original held source shape differs");
    }
    match report.phase {
        ReuseSourcePhaseV1::Blocked => {
            if report.removed_monotonic_ns.is_some()
                || report.recovered_monotonic_ns.is_some()
                || report.after_bytes.is_some()
            {
                return Err("blocked reuse source claims recovery");
            }
        }
        ReuseSourcePhaseV1::Recover => {
            let (Some(removed), Some(recovered), Some(after)) = (
                report.removed_monotonic_ns,
                report.recovered_monotonic_ns,
                report.after_bytes.as_ref(),
            ) else {
                return Err("actual recovery source absent");
            };
            if removed <= report.retry_end_monotonic_ns
                || recovered <= removed
                || after.is_empty()
                || after == &report.before_bytes
            {
                return Err("actual recovery source order or journal unchanged");
            }
        }
    }
    Ok(())
}
