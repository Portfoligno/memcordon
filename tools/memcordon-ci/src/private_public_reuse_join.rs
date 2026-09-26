//! Exact final-public retirement-failure/reuse join. The current provider V2
//! transcript does not produce the protected obstruction/failure leaves; this
//! verifier deliberately cannot issue a P token without them.

use memcordon_core::DiagnosticSha256;
use memcordon_core::provider_rejection_wire::RejectionWireV1;
use memcordon_core::workload_codec::hash_bytes;
use serde::Deserialize;

use crate::{CiError, Result};

/// Diagnostic validation of original held namespace descriptor bytes.
/// This does not construct a retirement or qualification capability.
pub use crate::private_public_reuse_live::validate_holder_fd_source;

fn fail(message: &'static str) -> CiError {
    CiError::Message(message.into())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedReuseTranscriptV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    boot_id: String,
    installation_epoch: DiagnosticSha256,
    active_h1_receipt_sha256: DiagnosticSha256,
    first_attempt_id: String,
    second_attempt_id: String,
    cleanup_failure_sha256: DiagnosticSha256,
    durable_incomplete_state_sha256: DiagnosticSha256,
    namespace_inode: u64,
    holder_pid: u32,
    holder_start_time: u64,
    held_fd: u32,
    failure_boot_nanos: u64,
    blocked_request_sha256: DiagnosticSha256,
    blocked_rejection_sha256: DiagnosticSha256,
    blocked_boot_nanos: u64,
    namespace_fd_closed_boot_nanos: u64,
    recovered_cleanup_sha256: DiagnosticSha256,
    recovery_boot_nanos: u64,
    durable_attempt_record_absent_after_recovery: bool,
}

/// Exact detached bytes and independently fixed H1/attempt expectations. The
/// protected transcript must come from service-side journal and fd custody,
/// not from the final CLI report or an uploaded P artifact.
pub struct ExpectedPublicReuseV1<'a> {
    pub result_key: &'a DiagnosticSha256,
    pub boot_id: &'a str,
    pub installation_epoch: &'a DiagnosticSha256,
    pub active_h1_receipt_sha256: &'a DiagnosticSha256,
    pub first_attempt_id: &'a str,
    pub second_attempt_id: &'a str,
    pub cleanup_failure_bytes: &'a [u8],
    pub blocked_request_bytes: &'a [u8],
    pub blocked_rejection_bytes: &'a [u8],
    pub recovered_cleanup_bytes: &'a [u8],
    pub expected_failure_code: &'a str,
    pub expected_blocked_code: &'a str,
}

#[derive(Clone, Debug)]
pub struct StructuralPublicReuseV1 {
    pub transcript_sha256: DiagnosticSha256,
    pub cleanup_failure_sha256: DiagnosticSha256,
    pub blocked_rejection_sha256: DiagnosticSha256,
    pub recovered_cleanup_sha256: DiagnosticSha256,
    pub namespace_inode: u64,
    pub holder_pid: u32,
    pub holder_start_time: u64,
}

pub fn validate_protected_public_reuse_v1(
    record_bytes: &[u8],
    expected: &ExpectedPublicReuseV1<'_>,
) -> Result<StructuralPublicReuseV1> {
    if record_bytes.is_empty() || record_bytes.len() > 16 * 1024 {
        return Err(fail("public reuse protected transcript bound differs"));
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(record_bytes)
        .map_err(CiError::Message)?;
    let record: ProtectedReuseTranscriptV1 = serde_json::from_slice(record_bytes)?;
    let failure =
        RejectionWireV1::parse(expected.cleanup_failure_bytes).map_err(CiError::Message)?;
    let blocked =
        RejectionWireV1::parse(expected.blocked_rejection_bytes).map_err(CiError::Message)?;
    let zero = DiagnosticSha256::from_bytes([0; 32]);
    if record.schema_version != 1
        || record.selector != "private_tcp::retirement_failure_blocks_reuse"
        || record.result_key != *expected.result_key
        || record.boot_id != expected.boot_id
        || record.boot_id.trim().is_empty()
        || record.installation_epoch != *expected.installation_epoch
        || record.active_h1_receipt_sha256 != *expected.active_h1_receipt_sha256
        || record.first_attempt_id != expected.first_attempt_id
        || record.second_attempt_id != expected.second_attempt_id
        || record.first_attempt_id.is_empty()
        || record.second_attempt_id.is_empty()
        || record.first_attempt_id == record.second_attempt_id
        || record.cleanup_failure_sha256 != hash_bytes(expected.cleanup_failure_bytes)
        || record.durable_incomplete_state_sha256 == zero
        || record.namespace_inode == 0
        || record.holder_pid == 0
        || record.holder_start_time == 0
        || record.held_fd <= 2
        || record.failure_boot_nanos == 0
        || record.blocked_boot_nanos <= record.failure_boot_nanos
        || record.namespace_fd_closed_boot_nanos <= record.blocked_boot_nanos
        || record.recovery_boot_nanos < record.namespace_fd_closed_boot_nanos
        || record.blocked_request_sha256 != hash_bytes(expected.blocked_request_bytes)
        || record.blocked_rejection_sha256 != hash_bytes(expected.blocked_rejection_bytes)
        || record.recovered_cleanup_sha256 != hash_bytes(expected.recovered_cleanup_bytes)
        || !record.durable_attempt_record_absent_after_recovery
        || expected.expected_failure_code != "MCSEALED-PRIVATE-REUSE-CLEANUP-INCOMPLETE"
        || expected.expected_blocked_code != "MCSEALED-PRIVATE-REUSE-BLOCKED"
        || failure.code != expected.expected_failure_code
        || failure.phase != memcordon_core::provider_rejection_wire::RejectionPhaseV1::Retirement
        || !failure.target_created
        || !failure.target_released
        || !failure.cleanup.attempted
        || failure.cleanup.sealed_boundary_retired
        || failure.cleanup.errors.is_empty()
        || blocked.code != expected.expected_blocked_code
        || blocked.phase
            != memcordon_core::provider_rejection_wire::RejectionPhaseV1::RequestValidation
        || blocked.target_created
        || blocked.target_released
        || blocked.cleanup.attempted
    {
        return Err(fail(
            "public reuse obstruction, blocked request or recovery differs",
        ));
    }
    Ok(StructuralPublicReuseV1 {
        transcript_sha256: hash_bytes(record_bytes),
        cleanup_failure_sha256: record.cleanup_failure_sha256,
        blocked_rejection_sha256: record.blocked_rejection_sha256,
        recovered_cleanup_sha256: record.recovered_cleanup_sha256,
        namespace_inode: record.namespace_inode,
        holder_pid: record.holder_pid,
        holder_start_time: record.holder_start_time,
    })
}

pub struct ExpectedPublicReuseLiveV1<'a> {
    pub protected_record_bytes: &'a [u8],
    pub detached_stdout: &'a [u8],
    pub detached: ExpectedPublicReuseV1<'a>,
    pub provider: &'a crate::private_public_dispatch::StructuralProviderFrameReadbackV2,
    pub first_clock: &'a crate::private_process_clock::VerifiedProcClockCalibrationV1,
    pub holder_clock: &'a crate::private_process_clock::VerifiedProcClockCalibrationV1,
    pub first_interval: &'a crate::private_kernel_observer::VerifiedKernelIntervalV1,
    pub blocked_interval: &'a crate::private_kernel_observer::VerifiedKernelIntervalV1,
    pub recovery_interval: &'a crate::private_kernel_observer::VerifiedKernelIntervalV1,
}

pub(crate) struct VerifiedPublicReuseV1 {
    transcript_sha256: DiagnosticSha256,
    observer_sha256: DiagnosticSha256,
    cleanup_failure_sha256: DiagnosticSha256,
    blocked_rejection_sha256: DiagnosticSha256,
    recovered_cleanup_sha256: DiagnosticSha256,
}

impl VerifiedPublicReuseV1 {
    pub(crate) fn transcript_sha256(&self) -> &DiagnosticSha256 {
        &self.transcript_sha256
    }
    pub(crate) fn observer_sha256(&self) -> &DiagnosticSha256 {
        &self.observer_sha256
    }
    pub(crate) fn cleanup_failure_sha256(&self) -> &DiagnosticSha256 {
        &self.cleanup_failure_sha256
    }
    pub(crate) fn blocked_rejection_sha256(&self) -> &DiagnosticSha256 {
        &self.blocked_rejection_sha256
    }
    pub(crate) fn recovered_cleanup_sha256(&self) -> &DiagnosticSha256 {
        &self.recovered_cleanup_sha256
    }
}

pub(crate) fn join_public_reuse_v1(
    input: &ExpectedPublicReuseLiveV1<'_>,
) -> Result<VerifiedPublicReuseV1> {
    use crate::private_kernel_observer::KernelEventV1;
    let structural =
        validate_protected_public_reuse_v1(input.protected_record_bytes, &input.detached)?;
    if input.detached_stdout.strip_suffix(b"\n") != Some(input.protected_record_bytes) {
        return Err(fail("public reuse detached installed readback differs"));
    }
    if input.holder_clock.reader_identity() != (structural.holder_pid, structural.holder_start_time)
    {
        return Err(fail("public reuse holder clock identity differs"));
    }
    let provider = input.provider;
    if provider.result_key != *input.detached.result_key
        || input.first_interval.boot_id() != input.detached.boot_id
        || input.blocked_interval.boot_id() != input.detached.boot_id
        || input.recovery_interval.boot_id() != input.detached.boot_id
        || input.first_interval.kernel_release() != input.blocked_interval.kernel_release()
        || input.first_interval.kernel_release() != input.recovery_interval.kernel_release()
        || input.first_interval.btf_sha256() != input.blocked_interval.btf_sha256()
        || input.first_interval.btf_sha256() != input.recovery_interval.btf_sha256()
        || input.first_interval.probe_map_sha256() != input.blocked_interval.probe_map_sha256()
        || input.first_interval.probe_map_sha256() != input.recovery_interval.probe_map_sha256()
        || provider.phase != "launch-exchanges-complete"
        || provider.attempts.len() != 2
        || provider.attempts[0].attempt_id != input.detached.first_attempt_id
        || provider.attempts[1].attempt_id != input.detached.second_attempt_id
        || provider.attempts[0].response_bytes != input.detached.cleanup_failure_bytes
        || provider.attempts[0].terminal_bytes.is_some()
        || provider.attempts[0].cleanup_bytes.as_deref()
            != Some(input.detached.recovered_cleanup_bytes)
        || provider.attempts[1].request_bytes != input.detached.blocked_request_bytes
        || provider.attempts[1].response_bytes != input.detached.blocked_rejection_bytes
        || provider.attempts[1].target_identity_bytes.is_some()
        || provider.attempts[1].cleanup_bytes.is_some()
        || provider.attempts[0].target_identity_bytes.is_none()
    {
        return Err(fail("public reuse provider V2 ordered attempts differ"));
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(&provider.record_bytes)
        .map_err(CiError::Message)?;
    let raw: serde_json::Value = serde_json::from_slice(&provider.record_bytes)?;
    let phases = raw
        .get("attempts")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| fail("public reuse protected provider attempts absent"))?;
    if raw.get("selector").and_then(serde_json::Value::as_str)
        != Some("private_tcp::retirement_failure_blocks_reuse")
        || raw.get("installation_epoch")
            != Some(&serde_json::to_value(input.detached.installation_epoch)?)
        || raw.get("active_h1_receipt_sha256")
            != Some(&serde_json::to_value(
                input.detached.active_h1_receipt_sha256,
            )?)
        || phases.len() != 2
        || phases[0].get("phase").and_then(serde_json::Value::as_str)
            != Some("recovered-after-incomplete")
        || phases[1].get("phase").and_then(serde_json::Value::as_str)
            != Some("reuse-blocked-observed")
    {
        return Err(fail("public reuse provider recovery phases/H1 differ"));
    }
    input
        .first_interval
        .verify_allocation(input.detached.result_key)?;
    // The ordinary public kernel join requires namespace-fd closure before
    // returning. That would contradict this selector's *intentional* held fd,
    // so join target exec/retirement here and defer namespace closure to the
    // independent recovery interval below.
    let target = provider.attempts[0]
        .target_identity_bytes
        .as_ref()
        .expect("checked");
    memcordon_core::workload_contract::reject_duplicate_json_keys(target)
        .map_err(CiError::Message)?;
    let target: serde_json::Value = serde_json::from_slice(target)?;
    let pid = target
        .pointer("/target/pid")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| fail("reuse target PID absent"))?;
    let start_ticks = target
        .pointer("/target/start_time")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| fail("reuse target start ticks absent"))?;
    let image_dev = target
        .get("entrypoint_device")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| fail("reuse approved image device absent"))?;
    let image_inode = target
        .get("entrypoint_inode")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| fail("reuse approved image inode absent"))?;
    let namespace_inode = target
        .get("network_namespace_inode")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| fail("reuse namespace inode absent"))?;
    if pid == 0
        || pid > u32::MAX as u64
        || start_ticks == 0
        || image_dev == 0
        || image_inode == 0
        || namespace_inode != structural.namespace_inode
    {
        return Err(fail("reuse protected first target identity differs"));
    }
    let execs = input
        .first_interval
        .events()
        .iter()
        .filter_map(|event| match event {
            KernelEventV1::Exec {
                task,
                image_dev: observed_dev,
                image_inode: observed_inode,
                ..
            } if task.pid == pid as u32 && input.first_clock.matches(*task, start_ticks) => {
                Some((*task, *observed_dev, *observed_inode))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if execs.len() != 1
        || execs[0].1 != image_dev
        || execs[0].2 != image_inode
        || !input.first_interval.retired_task(execs[0].0)
        || !input.first_interval.events().iter().any(|event| {
            matches!(event,
            KernelEventV1::ForkObserved { child_pid, .. } if *child_pid == pid as u32)
                || matches!(event, KernelEventV1::Fork { child, .. } if *child == execs[0].0)
        })
    {
        return Err(fail(
            "reuse first target exec/retirement kernel join differs",
        ));
    }
    input
        .blocked_interval
        .verify_no_allocation(input.detached.result_key)?;
    input.recovery_interval.capture_bytes()?;
    if input.recovery_interval.result_key() != input.detached.result_key
        || !input.recovery_interval.no_allocation()
        || !input.recovery_interval.events().iter().any(|event| {
            matches!(event,
            KernelEventV1::NamespaceFdClosed { task, namespace_inode }
                if *namespace_inode == structural.namespace_inode
                    && task.pid == structural.holder_pid
                    && input.holder_clock.matches(*task, structural.holder_start_time))
        })
    {
        return Err(fail(
            "public reuse actual observer namespace fd closure is absent",
        ));
    }
    let joined = serde_json::to_vec(&(
        "memcordon/public-reuse-join/v1",
        &structural.transcript_sha256,
        input.first_interval.trace_sha256(),
        input.blocked_interval.trace_sha256(),
        input.recovery_interval.trace_sha256(),
        &structural.cleanup_failure_sha256,
        &structural.blocked_rejection_sha256,
        &structural.recovered_cleanup_sha256,
    ))?;
    Ok(VerifiedPublicReuseV1 {
        transcript_sha256: hash_bytes(&joined),
        observer_sha256: input.blocked_interval.trace_sha256().clone(),
        cleanup_failure_sha256: structural.cleanup_failure_sha256,
        blocked_rejection_sha256: structural.blocked_rejection_sha256,
        recovered_cleanup_sha256: structural.recovered_cleanup_sha256,
    })
}
