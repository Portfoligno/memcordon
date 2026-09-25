//! Protected raw candidate attachments. These are diagnostic physical-run
//! inputs, not a completed 25-case result or a qualification token.

use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd};
use std::os::unix::fs::MetadataExt;

use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::{
    MAX_PRIVATE_RELEASE_ATTACHMENT_BYTES_V1, PrivateReleaseAttachmentRoleV1,
    PrivateReleaseAttachmentV1,
};
use memcordon_core::workload_codec::hash_bytes;
use serde::{Deserialize, Serialize};

use super::private_attempt::ProcessIdentityV4;
use super::private_release_attempt::ReadbackRetiredCandidateAttemptV1;
use super::private_release_child_execution::ChildCandidateNativeObservationV1;
use super::private_release_child_owner::LiveDescendantWitnessV1;
use super::private_release_execution::BlockedCandidateNativeObservationV1;
use super::private_release_execution::CandidateNativeObservationV1;
use super::private_release_execution::UncertainCandidateNativeObservationV1;
use super::private_release_frontend_loss::FrontendLossCandidateNativeObservationV1;
use super::private_release_gate::CheckpointGateNativeObservationV1;
use super::private_release_guardian_loss::GuardianLossCandidateNativeObservationV1;

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct NativeCandidateReportV1<'a> {
    schema_version: u8,
    selector: &'a str,
    result_key: &'a DiagnosticSha256,
    attempt_id: &'a str,
    checkpoint_sha256: &'a DiagnosticSha256,
    terminal_record_digest: &'a DiagnosticSha256,
    challenge_sha256: &'a DiagnosticSha256,
    response_sha256: &'a DiagnosticSha256,
    candidate_exit_code: i32,
    installed_inspection_json: &'a str,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeCandidateCleanupV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    candidate_exit_code: i32,
    kernel_trace_sha256: DiagnosticSha256,
    coordinator: ProcessIdentityV4,
    worker: ProcessIdentityV4,
    worker_pidfd_exited: bool,
    service_generation_sha256: DiagnosticSha256,
    settlement_source: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeUncertainCandidateCleanupV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    release_knowledge: String,
    transport_errno: i32,
    kernel_trace_sha256: DiagnosticSha256,
    coordinator: ProcessIdentityV4,
    worker: ProcessIdentityV4,
    worker_pidfd_exited: bool,
    service_generation_sha256: DiagnosticSha256,
    settlement_source: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeBlockedRetirementCleanupV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    fault_marker_sha256: DiagnosticSha256,
    reuse_rejection_sha256: DiagnosticSha256,
    kernel_trace_sha256: DiagnosticSha256,
    coordinator: ProcessIdentityV4,
    worker: ProcessIdentityV4,
    worker_pidfd_exited: bool,
    service_generation_sha256: DiagnosticSha256,
    settlement_source: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeGuardianLossCleanupV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    guardian_signal: i32,
    kernel_trace_sha256: DiagnosticSha256,
    coordinator: ProcessIdentityV4,
    worker: ProcessIdentityV4,
    worker_pidfd_exited: bool,
    service_generation_sha256: DiagnosticSha256,
    settlement_source: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeCandidateKernelObservationV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    settlement: super::private_lifecycle::ReleaseCandidateSettlementFactsV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    host_network_preservation: Option<super::private_release_host_state::HostNetworkPreservationV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent_path_preservation: Option<super::private_release_ancestor::AgentPathPreservationV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unix_absence: Option<super::private_release_unix_intent::UnixIntentSupervisorAbsenceV1>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeUncertainCandidateReportV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    release_knowledge: String,
    transport_errno: i32,
    authorization_failure_phase: u8,
    authorization_failure_detail: String,
    candidate_exit_code: Option<i32>,
    installed_inspection_json: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeUncertainKernelObservationV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    authorization_failure_phase: u8,
    authorization_failure_detail: String,
    settlement: super::private_release_attempt::UncertainCandidateSettlementFactsV1,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeBlockedRetirementReportV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    response_sha256: DiagnosticSha256,
    fault_marker_sha256: DiagnosticSha256,
    transition_error: String,
    reuse_error: String,
    installed_inspection_json: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeBlockedRetirementObserverV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    fault_marker_sha256: DiagnosticSha256,
    settlement: super::private_lifecycle::ReleaseCandidateSettlementFactsV1,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeGuardianLossReportV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    armed_response_sha256: DiagnosticSha256,
    network_namespace_inode: u64,
    candidate_exit_code: Option<i32>,
    installed_inspection_json: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeGuardianLossObserverV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    settlement: super::private_release_attempt::GuardianLossCandidateSettlementFactsV1,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeFrontendLossReportV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    armed_response_sha256: DiagnosticSha256,
    network_namespace_inode: u64,
    frontend_proxy: ProcessIdentityV4,
    candidate_exit_code: Option<i32>,
    installed_inspection_json: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeFrontendLossObserverV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    settlement: super::private_release_attempt::FrontendLossCandidateSettlementFactsV1,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeFrontendLossCleanupV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    frontend_proxy: ProcessIdentityV4,
    frontend_signal: i32,
    guardian_terminal: [u8; 20],
    kernel_trace_sha256: DiagnosticSha256,
    coordinator: ProcessIdentityV4,
    worker: ProcessIdentityV4,
    worker_pidfd_exited: bool,
    service_generation_sha256: DiagnosticSha256,
    settlement_source: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeCheckpointGateReportV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    response_sha256: DiagnosticSha256,
    checkpoint_gate_sha256: DiagnosticSha256,
    candidate_exit_code: i32,
    installed_inspection_json: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeCheckpointGateObserverV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    checkpoint_gate_sha256: DiagnosticSha256,
    settlement: super::private_lifecycle::ReleaseCandidateSettlementFactsV1,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeCheckpointGateCleanupV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    checkpoint_gate_sha256: DiagnosticSha256,
    kernel_trace_sha256: DiagnosticSha256,
    coordinator: ProcessIdentityV4,
    worker: ProcessIdentityV4,
    worker_pidfd_exited: bool,
    service_generation_sha256: DiagnosticSha256,
    settlement_source: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeChildReportV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    response_sha256: DiagnosticSha256,
    child: ProcessIdentityV4,
    thread_tid: u32,
    thread_start_time: u64,
    target_namespace_pid: u32,
    child_namespace_pid: u32,
    thread_namespace_tid: u32,
    target_pid_chain: Vec<u32>,
    child_pid_chain: Vec<u32>,
    thread_tid_chain: Vec<u32>,
    candidate_exit_code: i32,
    installed_inspection_json: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeChildObserverV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    live: LiveDescendantWitnessV1,
    settlement: super::private_lifecycle::ReleaseCandidateSettlementFactsV1,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeChildCleanupV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    child: ProcessIdentityV4,
    thread_tid: u32,
    target_namespace_pid: u32,
    child_namespace_pid: u32,
    thread_namespace_tid: u32,
    target_pid_chain: Vec<u32>,
    child_pid_chain: Vec<u32>,
    thread_tid_chain: Vec<u32>,
    kernel_trace_sha256: DiagnosticSha256,
    coordinator: ProcessIdentityV4,
    worker: ProcessIdentityV4,
    worker_pidfd_exited: bool,
    service_generation_sha256: DiagnosticSha256,
    settlement_source: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadbackNativeCandidateReportV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    response_sha256: DiagnosticSha256,
    candidate_exit_code: i32,
    installed_inspection_json: String,
}

#[derive(Clone, Copy)]
pub(crate) struct CandidateRawContextV1<'a> {
    pub(crate) directory: &'a File,
    pub(crate) selector: &'a str,
    pub(crate) result_key: &'a DiagnosticSha256,
    pub(crate) challenge: &'a [u8; 32],
    pub(crate) expected_response: &'a [u8],
    pub(crate) installed_inspection_bytes: &'a [u8],
    pub(crate) agent_path_snapshot:
        Option<&'a super::private_release_ancestor::ProtectedAgentPathV1>,
}

/// Worker-authored diagnostics for one deliberately lost release transport.
/// They are not a result or independent OS proof; the coordinator and
/// detached reader must still join exact worker exit and cgroup retirement.
#[allow(dead_code)] // Enabled with the fixed uncertainty selector route.
pub(crate) fn persist_uncertain_candidate_worker_raw(
    context: CandidateRawContextV1<'_>,
    observed: &UncertainCandidateNativeObservationV1,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    if unsafe { libc::geteuid() } != 0
        || context.selector != super::private_release_case::AUTHORIZATION_UNCERTAIN_SELECTOR
        || !context.expected_response.is_empty()
        || context.agent_path_snapshot.is_some()
        || observed.challenge_sha256 != hash_bytes(context.challenge)
        || observed.settlement.transport_errno != libc::EPIPE
        || observed.authorization_failure_phase != 4
        || observed.authorization_failure_detail != "authorization packet invalid"
        || observed.settlement.candidate_exit_code == Some(0)
    {
        return Err("MCSEALED-PRIVATE-RELEASE: uncertain raw producer differs".into());
    }
    protected_directory(context.directory, 0)?;
    let request = read_fixed(context.directory, "request.json", 0)?;
    if read_fixed(context.directory, "attempt.json", 0)? != observed.terminal_bytes {
        return Err("MCSEALED-PRIVATE-RELEASE: uncertain terminal changed".into());
    }
    let inspection = std::str::from_utf8(context.installed_inspection_bytes)
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE: uncertain inspection is not UTF-8")?;
    let report = serde_json::to_vec(&NativeUncertainCandidateReportV1 {
        schema_version: 1,
        selector: context.selector.to_owned(),
        result_key: context.result_key.clone(),
        attempt_id: observed.attempt_id.clone(),
        checkpoint_sha256: observed.checkpoint_digest.clone(),
        terminal_record_digest: observed.terminal_record_digest.clone(),
        challenge_sha256: observed.challenge_sha256.clone(),
        release_knowledge: "possibly-released".into(),
        transport_errno: observed.settlement.transport_errno,
        authorization_failure_phase: observed.authorization_failure_phase,
        authorization_failure_detail: observed.authorization_failure_detail.clone(),
        candidate_exit_code: observed.settlement.candidate_exit_code,
        installed_inspection_json: inspection.to_owned(),
    })
    .map_err(|error| error.to_string())?;
    let observer = serde_json::to_vec(&NativeUncertainKernelObservationV1 {
        schema_version: 1,
        attempt_id: observed.attempt_id.clone(),
        checkpoint_sha256: observed.checkpoint_digest.clone(),
        terminal_record_digest: observed.terminal_record_digest.clone(),
        authorization_failure_phase: observed.authorization_failure_phase,
        authorization_failure_detail: observed.authorization_failure_detail.clone(),
        settlement: observed.settlement.clone(),
    })
    .map_err(|error| error.to_string())?;
    let stdio = context.challenge.to_vec();
    let raw = [request, report, stdio, observer];
    let mut inventory = Vec::with_capacity(raw.len());
    for (role, bytes) in PrivateReleaseAttachmentRoleV1::ALL
        .into_iter()
        .take(raw.len())
        .zip(raw)
    {
        if bytes.len() as u64 > MAX_PRIVATE_RELEASE_ATTACHMENT_BYTES_V1 {
            return Err("MCSEALED-PRIVATE-RELEASE: uncertain raw byte bound differs".into());
        }
        persist_fixed(context.directory, role.leaf(), &bytes, 0)?;
        inventory.push(PrivateReleaseAttachmentV1 {
            role,
            size: bytes.len() as u64,
            sha256: hash_bytes(&bytes),
        });
    }
    if readback_uncertain_candidate_worker_raw(
        context,
        &ReadbackRetiredCandidateAttemptV1 {
            attempt_id: observed.attempt_id.clone(),
            checkpoint_digest: observed.checkpoint_digest.clone(),
            terminal_record_digest: observed.terminal_record_digest.clone(),
            terminal_bytes: observed.terminal_bytes.clone(),
        },
    )? != inventory
    {
        return Err("MCSEALED-PRIVATE-RELEASE: uncertain raw readback differs".into());
    }
    Ok(inventory)
}

#[allow(dead_code)] // The detached uncertainty reader is not connected yet.
pub(crate) fn readback_uncertain_candidate_worker_raw(
    context: CandidateRawContextV1<'_>,
    journal: &ReadbackRetiredCandidateAttemptV1,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    readback_uncertain_candidate_worker_raw_with_owner(context, journal, 0)
}

#[allow(dead_code)] // Enabled with the detached retirement-fault reader.
pub(crate) fn persist_blocked_retirement_worker_raw(
    context: CandidateRawContextV1<'_>,
    observed: &BlockedCandidateNativeObservationV1,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    if unsafe { libc::geteuid() } != 0
        || context.selector != super::private_release_case::RETIREMENT_FAULT_SELECTOR
        || context.agent_path_snapshot.is_some()
        || observed.challenge_sha256 != hash_bytes(context.challenge)
        || observed.response_bytes != context.expected_response
        || observed.response_sha256 != hash_bytes(context.expected_response)
        || observed.settlement.candidate_exit_code != Some(0)
        || observed.transition_error.is_empty()
        || observed.transition_error.len() > 512
        || observed.reuse_error.is_empty()
        || observed.reuse_error.len() > 512
    {
        return Err("MCSEALED-PRIVATE-RELEASE: blocked raw producer differs".into());
    }
    protected_directory(context.directory, 0)?;
    let request = read_fixed(context.directory, "request.json", 0)?;
    if read_fixed(context.directory, "attempt.json", 0)? != observed.terminal_bytes
        || read_fixed(context.directory, "attempt.json.new", 0)? != observed.fault_marker_bytes
    {
        return Err("MCSEALED-PRIVATE-RELEASE: blocked raw journal changed".into());
    }
    let inspection = std::str::from_utf8(context.installed_inspection_bytes)
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE: blocked inspection is not UTF-8")?;
    let marker_sha256 = hash_bytes(&observed.fault_marker_bytes);
    let report = serde_json::to_vec(&NativeBlockedRetirementReportV1 {
        schema_version: 1,
        selector: context.selector.to_owned(),
        result_key: context.result_key.clone(),
        attempt_id: observed.attempt_id.clone(),
        checkpoint_sha256: observed.checkpoint_digest.clone(),
        terminal_record_digest: observed.terminal_record_digest.clone(),
        challenge_sha256: observed.challenge_sha256.clone(),
        response_sha256: observed.response_sha256.clone(),
        fault_marker_sha256: marker_sha256.clone(),
        transition_error: observed.transition_error.clone(),
        reuse_error: observed.reuse_error.clone(),
        installed_inspection_json: inspection.to_owned(),
    })
    .map_err(|error| error.to_string())?;
    let observer = serde_json::to_vec(&NativeBlockedRetirementObserverV1 {
        schema_version: 1,
        attempt_id: observed.attempt_id.clone(),
        checkpoint_sha256: observed.checkpoint_digest.clone(),
        terminal_record_digest: observed.terminal_record_digest.clone(),
        fault_marker_sha256: marker_sha256,
        settlement: observed.settlement.clone(),
    })
    .map_err(|error| error.to_string())?;
    let mut stdio = Vec::with_capacity(context.challenge.len() + observed.response_bytes.len());
    stdio.extend_from_slice(context.challenge);
    stdio.extend_from_slice(&observed.response_bytes);
    let raw = [request, report, stdio, observer];
    let mut inventory = Vec::with_capacity(raw.len());
    for (role, bytes) in PrivateReleaseAttachmentRoleV1::ALL
        .into_iter()
        .take(raw.len())
        .zip(raw)
    {
        if bytes.len() as u64 > MAX_PRIVATE_RELEASE_ATTACHMENT_BYTES_V1 {
            return Err("MCSEALED-PRIVATE-RELEASE: blocked raw byte bound differs".into());
        }
        persist_fixed(context.directory, role.leaf(), &bytes, 0)?;
        inventory.push(PrivateReleaseAttachmentV1 {
            role,
            size: bytes.len() as u64,
            sha256: hash_bytes(&bytes),
        });
    }
    let readback = readback_blocked_retirement_worker_raw(
        context,
        &super::private_release_attempt::ReadbackBlockedCandidateAttemptV1 {
            journal: ReadbackRetiredCandidateAttemptV1 {
                attempt_id: observed.attempt_id.clone(),
                checkpoint_digest: observed.checkpoint_digest.clone(),
                terminal_record_digest: observed.terminal_record_digest.clone(),
                terminal_bytes: observed.terminal_bytes.clone(),
            },
            fault_marker_bytes: observed.fault_marker_bytes.clone(),
            detached_reuse_error: observed.reuse_error.clone(),
        },
    )?;
    if readback != inventory {
        return Err("MCSEALED-PRIVATE-RELEASE: blocked raw readback differs".into());
    }
    Ok(inventory)
}

#[allow(dead_code)] // Called by the detached retirement-fault reader.
pub(crate) fn readback_blocked_retirement_worker_raw(
    context: CandidateRawContextV1<'_>,
    blocked: &super::private_release_attempt::ReadbackBlockedCandidateAttemptV1,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    readback_blocked_retirement_worker_raw_with_owner(context, blocked, 0)
}

fn readback_blocked_retirement_worker_raw_with_owner(
    context: CandidateRawContextV1<'_>,
    blocked: &super::private_release_attempt::ReadbackBlockedCandidateAttemptV1,
    owner_uid: u32,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    if context.selector != super::private_release_case::RETIREMENT_FAULT_SELECTOR
        || context.agent_path_snapshot.is_some()
    {
        return Err("MCSEALED-PRIVATE-RELEASE: blocked raw selector differs".into());
    }
    protected_directory(context.directory, owner_uid)?;
    let request = read_fixed(context.directory, "request.bin", owner_uid)?;
    if request != read_fixed(context.directory, "request.json", owner_uid)?
        || blocked.journal.terminal_bytes
            != read_fixed(context.directory, "attempt.json", owner_uid)?
        || blocked.fault_marker_bytes
            != read_fixed(context.directory, "attempt.json.new", owner_uid)?
    {
        return Err("MCSEALED-PRIVATE-RELEASE: blocked raw custody differs".into());
    }
    let report_bytes = read_fixed(context.directory, "report.bin", owner_uid)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&report_bytes)?;
    let report: NativeBlockedRetirementReportV1 =
        serde_json::from_slice(&report_bytes).map_err(|error| error.to_string())?;
    let inspection = std::str::from_utf8(context.installed_inspection_bytes)
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE: blocked inspection is not UTF-8")?;
    if report.schema_version != 1
        || report.selector != context.selector
        || &report.result_key != context.result_key
        || report.attempt_id != blocked.journal.attempt_id
        || report.checkpoint_sha256 != blocked.journal.checkpoint_digest
        || report.terminal_record_digest != blocked.journal.terminal_record_digest
        || report.challenge_sha256 != hash_bytes(context.challenge)
        || report.response_sha256 != hash_bytes(context.expected_response)
        || report.fault_marker_sha256 != hash_bytes(&blocked.fault_marker_bytes)
        || report.transition_error.is_empty()
        || report.transition_error.len() > 512
        || report.reuse_error.is_empty()
        || report.reuse_error.len() > 512
        || report.reuse_error != blocked.detached_reuse_error
        || report.installed_inspection_json != inspection
    {
        return Err("MCSEALED-PRIVATE-RELEASE: blocked raw report differs".into());
    }
    let stdio = read_fixed(context.directory, "stdio.bin", owner_uid)?;
    if stdio.len() != context.challenge.len() + context.expected_response.len()
        || stdio[..context.challenge.len()] != *context.challenge
        || stdio[context.challenge.len()..] != *context.expected_response
    {
        return Err("MCSEALED-PRIVATE-RELEASE: blocked target I/O differs".into());
    }
    let observer = read_fixed(context.directory, "observer.bin", owner_uid)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&observer)?;
    let trace: NativeBlockedRetirementObserverV1 =
        serde_json::from_slice(&observer).map_err(|error| error.to_string())?;
    let settlement = &trace.settlement;
    let guardian = super::private_guardian::GuardianTerminalV4::decode(
        settlement.guardian_terminal,
        super::private_release_attempt::candidate_attempt_bytes(context.result_key),
    )?;
    if trace.schema_version != 1
        || trace.attempt_id != report.attempt_id
        || trace.checkpoint_sha256 != report.checkpoint_sha256
        || trace.terminal_record_digest != report.terminal_record_digest
        || trace.fault_marker_sha256 != report.fault_marker_sha256
        || settlement.schema_version != 1
        || settlement.monitor_outcome != super::private_lifecycle::PrivateMonitorOutcome::Completed
        || !settlement.cgroup_empty_before_cleanup
        || !settlement.containment_removed
        || !settlement.target_pidfd_exited
        || !settlement.namespace_init_reaped
        || settlement.candidate_exit_code != Some(0)
        || guardian.trigger != super::private_guardian::GuardianTriggerV4::Stopped
        || guardian.boundary_retired
    {
        return Err("MCSEALED-PRIVATE-RELEASE: blocked kernel observation differs".into());
    }
    let raw = [request, report_bytes, stdio, observer];
    Ok(PrivateReleaseAttachmentRoleV1::ALL
        .into_iter()
        .take(raw.len())
        .zip(raw)
        .map(|(role, bytes)| PrivateReleaseAttachmentV1 {
            role,
            size: bytes.len() as u64,
            sha256: hash_bytes(&bytes),
        })
        .collect())
}

#[cfg(feature = "test-support")]
pub(crate) fn readback_blocked_retirement_worker_raw_for_test(
    context: CandidateRawContextV1<'_>,
    blocked: &super::private_release_attempt::ReadbackBlockedCandidateAttemptV1,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    readback_blocked_retirement_worker_raw_with_owner(context, blocked, unsafe { libc::geteuid() })
}

#[allow(dead_code)] // Guardian-loss worker dispatch remains closed until detached joins.
pub(crate) fn persist_guardian_loss_worker_raw(
    context: CandidateRawContextV1<'_>,
    observed: &GuardianLossCandidateNativeObservationV1,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    if unsafe { libc::geteuid() } != 0
        || context.selector != super::private_release_guardian_loss::SELECTOR
        || context.agent_path_snapshot.is_some()
        || context.expected_response
            != super::private_release_guardian_loss::armed_response(context.challenge)
        || observed.challenge_sha256 != hash_bytes(context.challenge)
        || observed.armed_response_sha256 != hash_bytes(context.expected_response)
        || observed.network_namespace_inode == 0
        || observed.settlement.schema_version != 1
        || observed.settlement.guardian_signal != libc::SIGKILL
        || observed.settlement.candidate_exit_code == Some(0)
        || !observed.settlement.containment_removed
        || !observed.settlement.target_pidfd_exited
        || !observed.settlement.namespace_init_reaped
    {
        return Err("MCSEALED-PRIVATE-RELEASE: guardian-loss raw producer differs".into());
    }
    protected_directory(context.directory, 0)?;
    let request = read_fixed(context.directory, "request.json", 0)?;
    if read_fixed(context.directory, "attempt.json", 0)? != observed.terminal_bytes {
        return Err("MCSEALED-PRIVATE-RELEASE: guardian-loss journal changed".into());
    }
    let inspection = std::str::from_utf8(context.installed_inspection_bytes)
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE: guardian-loss inspection is not UTF-8")?;
    let report = serde_json::to_vec(&NativeGuardianLossReportV1 {
        schema_version: 1,
        selector: context.selector.to_owned(),
        result_key: context.result_key.clone(),
        attempt_id: observed.attempt_id.clone(),
        checkpoint_sha256: observed.checkpoint_digest.clone(),
        terminal_record_digest: observed.terminal_record_digest.clone(),
        challenge_sha256: observed.challenge_sha256.clone(),
        armed_response_sha256: observed.armed_response_sha256.clone(),
        network_namespace_inode: observed.network_namespace_inode,
        candidate_exit_code: observed.settlement.candidate_exit_code,
        installed_inspection_json: inspection.to_owned(),
    })
    .map_err(|error| error.to_string())?;
    let observer = serde_json::to_vec(&NativeGuardianLossObserverV1 {
        schema_version: 1,
        attempt_id: observed.attempt_id.clone(),
        checkpoint_sha256: observed.checkpoint_digest.clone(),
        terminal_record_digest: observed.terminal_record_digest.clone(),
        settlement: observed.settlement.clone(),
    })
    .map_err(|error| error.to_string())?;
    let mut stdio = Vec::with_capacity(context.challenge.len() + context.expected_response.len());
    stdio.extend_from_slice(context.challenge);
    stdio.extend_from_slice(context.expected_response);
    let raw = [request, report, stdio, observer];
    let mut inventory = Vec::with_capacity(raw.len());
    for (role, bytes) in PrivateReleaseAttachmentRoleV1::ALL
        .into_iter()
        .take(raw.len())
        .zip(raw)
    {
        if bytes.len() as u64 > MAX_PRIVATE_RELEASE_ATTACHMENT_BYTES_V1 {
            return Err("MCSEALED-PRIVATE-RELEASE: guardian-loss raw bound differs".into());
        }
        persist_fixed(context.directory, role.leaf(), &bytes, 0)?;
        inventory.push(PrivateReleaseAttachmentV1 {
            role,
            size: bytes.len() as u64,
            sha256: hash_bytes(&bytes),
        });
    }
    let journal = ReadbackRetiredCandidateAttemptV1 {
        attempt_id: observed.attempt_id.clone(),
        checkpoint_digest: observed.checkpoint_digest.clone(),
        terminal_record_digest: observed.terminal_record_digest.clone(),
        terminal_bytes: observed.terminal_bytes.clone(),
    };
    if readback_guardian_loss_worker_raw(context, &journal)? != inventory {
        return Err("MCSEALED-PRIVATE-RELEASE: guardian-loss raw readback differs".into());
    }
    Ok(inventory)
}

#[allow(dead_code)] // Detached guardian-loss reader is not connected yet.
pub(crate) fn readback_guardian_loss_worker_raw(
    context: CandidateRawContextV1<'_>,
    journal: &ReadbackRetiredCandidateAttemptV1,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    readback_guardian_loss_worker_raw_with_owner(context, journal, 0)
}

fn readback_guardian_loss_worker_raw_with_owner(
    context: CandidateRawContextV1<'_>,
    journal: &ReadbackRetiredCandidateAttemptV1,
    owner_uid: u32,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    if context.selector != super::private_release_guardian_loss::SELECTOR
        || context.agent_path_snapshot.is_some()
        || context.expected_response
            != super::private_release_guardian_loss::armed_response(context.challenge)
    {
        return Err("MCSEALED-PRIVATE-RELEASE: guardian-loss raw selector differs".into());
    }
    protected_directory(context.directory, owner_uid)?;
    let request = read_fixed(context.directory, "request.bin", owner_uid)?;
    if request != read_fixed(context.directory, "request.json", owner_uid)?
        || journal.terminal_bytes != read_fixed(context.directory, "attempt.json", owner_uid)?
    {
        return Err("MCSEALED-PRIVATE-RELEASE: guardian-loss raw custody differs".into());
    }
    let report_bytes = read_fixed(context.directory, "report.bin", owner_uid)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&report_bytes)?;
    let report: NativeGuardianLossReportV1 =
        serde_json::from_slice(&report_bytes).map_err(|error| error.to_string())?;
    let native = journal.native_identities()?;
    let inspection = std::str::from_utf8(context.installed_inspection_bytes)
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE: guardian-loss inspection is not UTF-8")?;
    if report.schema_version != 1
        || report.selector != context.selector
        || &report.result_key != context.result_key
        || report.attempt_id != journal.attempt_id
        || report.checkpoint_sha256 != journal.checkpoint_digest
        || report.terminal_record_digest != journal.terminal_record_digest
        || report.challenge_sha256 != hash_bytes(context.challenge)
        || report.armed_response_sha256 != hash_bytes(context.expected_response)
        || report.network_namespace_inode != native.network_namespace_inode
        || report.candidate_exit_code == Some(0)
        || report.candidate_exit_code != native.candidate_exit_code
        || report.installed_inspection_json != inspection
    {
        return Err("MCSEALED-PRIVATE-RELEASE: guardian-loss raw report differs".into());
    }
    let stdio = read_fixed(context.directory, "stdio.bin", owner_uid)?;
    if stdio.len() != context.challenge.len() + context.expected_response.len()
        || stdio[..context.challenge.len()] != *context.challenge
        || stdio[context.challenge.len()..] != *context.expected_response
    {
        return Err("MCSEALED-PRIVATE-RELEASE: guardian-loss target I/O differs".into());
    }
    let observer = read_fixed(context.directory, "observer.bin", owner_uid)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&observer)?;
    let trace: NativeGuardianLossObserverV1 =
        serde_json::from_slice(&observer).map_err(|error| error.to_string())?;
    if trace.schema_version != 1
        || trace.attempt_id != report.attempt_id
        || trace.checkpoint_sha256 != report.checkpoint_sha256
        || trace.terminal_record_digest != report.terminal_record_digest
        || trace.settlement.schema_version != 1
        || trace.settlement.guardian != native.guardian
        || trace.settlement.guardian_signal != libc::SIGKILL
        || !trace.settlement.containment_removed
        || !trace.settlement.target_pidfd_exited
        || !trace.settlement.namespace_init_reaped
        || trace.settlement.candidate_exit_code != report.candidate_exit_code
    {
        return Err("MCSEALED-PRIVATE-RELEASE: guardian-loss observer differs".into());
    }
    let raw = [request, report_bytes, stdio, observer];
    Ok(PrivateReleaseAttachmentRoleV1::ALL
        .into_iter()
        .take(raw.len())
        .zip(raw)
        .map(|(role, bytes)| PrivateReleaseAttachmentV1 {
            role,
            size: bytes.len() as u64,
            sha256: hash_bytes(&bytes),
        })
        .collect())
}

pub(crate) fn persist_frontend_loss_worker_raw(
    context: CandidateRawContextV1<'_>,
    observed: &FrontendLossCandidateNativeObservationV1,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    if unsafe { libc::geteuid() } != 0
        || context.selector != super::private_release_frontend_loss::SELECTOR
        || context.agent_path_snapshot.is_some()
        || context.expected_response
            != super::private_release_frontend_loss::armed_response(context.challenge)
        || observed.challenge_sha256 != hash_bytes(context.challenge)
        || observed.armed_response_sha256 != hash_bytes(context.expected_response)
        || observed.network_namespace_inode == 0
        || observed.settlement.schema_version != 1
        || observed.settlement.frontend_signal != libc::SIGKILL
        || observed.settlement.candidate_exit_code == Some(0)
        || !observed.settlement.containment_removed
        || !observed.settlement.target_pidfd_exited
        || !observed.settlement.namespace_init_reaped
    {
        return Err("MCSEALED-PRIVATE-RELEASE: frontend-loss raw producer differs".into());
    }
    protected_directory(context.directory, 0)?;
    let request = read_fixed(context.directory, "request.json", 0)?;
    if read_fixed(context.directory, "attempt.json", 0)? != observed.terminal_bytes {
        return Err("MCSEALED-PRIVATE-RELEASE: frontend-loss journal changed".into());
    }
    let inspection = std::str::from_utf8(context.installed_inspection_bytes)
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE: frontend-loss inspection is not UTF-8")?;
    let report = serde_json::to_vec(&NativeFrontendLossReportV1 {
        schema_version: 1,
        selector: context.selector.to_owned(),
        result_key: context.result_key.clone(),
        attempt_id: observed.attempt_id.clone(),
        checkpoint_sha256: observed.checkpoint_digest.clone(),
        terminal_record_digest: observed.terminal_record_digest.clone(),
        challenge_sha256: observed.challenge_sha256.clone(),
        armed_response_sha256: observed.armed_response_sha256.clone(),
        network_namespace_inode: observed.network_namespace_inode,
        frontend_proxy: observed.settlement.frontend.clone(),
        candidate_exit_code: observed.settlement.candidate_exit_code,
        installed_inspection_json: inspection.to_owned(),
    })
    .map_err(|error| error.to_string())?;
    let observer = serde_json::to_vec(&NativeFrontendLossObserverV1 {
        schema_version: 1,
        attempt_id: observed.attempt_id.clone(),
        checkpoint_sha256: observed.checkpoint_digest.clone(),
        terminal_record_digest: observed.terminal_record_digest.clone(),
        settlement: observed.settlement.clone(),
    })
    .map_err(|error| error.to_string())?;
    let mut stdio = Vec::with_capacity(context.challenge.len() + context.expected_response.len());
    stdio.extend_from_slice(context.challenge);
    stdio.extend_from_slice(context.expected_response);
    let raw = [request, report, stdio, observer];
    let mut inventory = Vec::with_capacity(raw.len());
    for (role, bytes) in PrivateReleaseAttachmentRoleV1::ALL
        .into_iter()
        .take(raw.len())
        .zip(raw)
    {
        if bytes.len() as u64 > MAX_PRIVATE_RELEASE_ATTACHMENT_BYTES_V1 {
            return Err("MCSEALED-PRIVATE-RELEASE: frontend-loss raw bound differs".into());
        }
        persist_fixed(context.directory, role.leaf(), &bytes, 0)?;
        inventory.push(PrivateReleaseAttachmentV1 {
            role,
            size: bytes.len() as u64,
            sha256: hash_bytes(&bytes),
        });
    }
    let journal = ReadbackRetiredCandidateAttemptV1 {
        attempt_id: observed.attempt_id.clone(),
        checkpoint_digest: observed.checkpoint_digest.clone(),
        terminal_record_digest: observed.terminal_record_digest.clone(),
        terminal_bytes: observed.terminal_bytes.clone(),
    };
    if readback_frontend_loss_worker_raw(context, &journal)? != inventory {
        return Err("MCSEALED-PRIVATE-RELEASE: frontend-loss raw readback differs".into());
    }
    Ok(inventory)
}

pub(crate) fn readback_frontend_loss_worker_raw(
    context: CandidateRawContextV1<'_>,
    journal: &ReadbackRetiredCandidateAttemptV1,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    readback_frontend_loss_worker_raw_with_owner(context, journal, 0)
}

fn readback_frontend_loss_worker_raw_with_owner(
    context: CandidateRawContextV1<'_>,
    journal: &ReadbackRetiredCandidateAttemptV1,
    owner_uid: u32,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    if context.selector != super::private_release_frontend_loss::SELECTOR
        || context.agent_path_snapshot.is_some()
        || context.expected_response
            != super::private_release_frontend_loss::armed_response(context.challenge)
    {
        return Err("MCSEALED-PRIVATE-RELEASE: frontend-loss raw selector differs".into());
    }
    protected_directory(context.directory, owner_uid)?;
    let request = read_fixed(context.directory, "request.bin", owner_uid)?;
    if request != read_fixed(context.directory, "request.json", owner_uid)?
        || journal.terminal_bytes != read_fixed(context.directory, "attempt.json", owner_uid)?
    {
        return Err("MCSEALED-PRIVATE-RELEASE: frontend-loss raw custody differs".into());
    }
    let report_bytes = read_fixed(context.directory, "report.bin", owner_uid)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&report_bytes)?;
    let report: NativeFrontendLossReportV1 =
        serde_json::from_slice(&report_bytes).map_err(|error| error.to_string())?;
    let native = journal.native_identities()?;
    let inspection = std::str::from_utf8(context.installed_inspection_bytes)
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE: frontend-loss inspection is not UTF-8")?;
    if report.schema_version != 1
        || report.selector != context.selector
        || &report.result_key != context.result_key
        || report.attempt_id != journal.attempt_id
        || report.checkpoint_sha256 != journal.checkpoint_digest
        || report.terminal_record_digest != journal.terminal_record_digest
        || report.challenge_sha256 != hash_bytes(context.challenge)
        || report.armed_response_sha256 != hash_bytes(context.expected_response)
        || report.network_namespace_inode != native.network_namespace_inode
        || native.frontend_proxy.as_ref() != Some(&report.frontend_proxy)
        || report.candidate_exit_code == Some(0)
        || report.candidate_exit_code != native.candidate_exit_code
        || report.installed_inspection_json != inspection
    {
        return Err("MCSEALED-PRIVATE-RELEASE: frontend-loss raw report differs".into());
    }
    let stdio = read_fixed(context.directory, "stdio.bin", owner_uid)?;
    if stdio.len() != context.challenge.len() + context.expected_response.len()
        || stdio[..context.challenge.len()] != *context.challenge
        || stdio[context.challenge.len()..] != *context.expected_response
    {
        return Err("MCSEALED-PRIVATE-RELEASE: frontend-loss target I/O differs".into());
    }
    let observer = read_fixed(context.directory, "observer.bin", owner_uid)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&observer)?;
    let trace: NativeFrontendLossObserverV1 =
        serde_json::from_slice(&observer).map_err(|error| error.to_string())?;
    let terminal = super::private_guardian::GuardianTerminalV4::decode(
        trace.settlement.guardian_terminal,
        super::private_release_attempt::candidate_attempt_bytes(context.result_key),
    )?;
    if trace.schema_version != 1
        || trace.attempt_id != report.attempt_id
        || trace.checkpoint_sha256 != report.checkpoint_sha256
        || trace.terminal_record_digest != report.terminal_record_digest
        || trace.settlement.schema_version != 1
        || trace.settlement.frontend != report.frontend_proxy
        || trace.settlement.frontend_signal != libc::SIGKILL
        || terminal.trigger != super::private_guardian::GuardianTriggerV4::FrontendLost
        || !terminal.boundary_retired
        || !trace.settlement.containment_removed
        || !trace.settlement.target_pidfd_exited
        || !trace.settlement.namespace_init_reaped
        || trace.settlement.candidate_exit_code != report.candidate_exit_code
    {
        return Err("MCSEALED-PRIVATE-RELEASE: frontend-loss observer differs".into());
    }
    let raw = [request, report_bytes, stdio, observer];
    Ok(PrivateReleaseAttachmentRoleV1::ALL
        .into_iter()
        .take(raw.len())
        .zip(raw)
        .map(|(role, bytes)| PrivateReleaseAttachmentV1 {
            role,
            size: bytes.len() as u64,
            sha256: hash_bytes(&bytes),
        })
        .collect())
}

#[cfg(feature = "test-support")]
pub(crate) fn readback_frontend_loss_worker_raw_for_test(
    context: CandidateRawContextV1<'_>,
    journal: &ReadbackRetiredCandidateAttemptV1,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    readback_frontend_loss_worker_raw_with_owner(context, journal, unsafe { libc::geteuid() })
}

#[cfg(feature = "test-support")]
pub(crate) fn readback_guardian_loss_worker_raw_for_test(
    context: CandidateRawContextV1<'_>,
    journal: &ReadbackRetiredCandidateAttemptV1,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    readback_guardian_loss_worker_raw_with_owner(context, journal, unsafe { libc::geteuid() })
}

fn readback_uncertain_candidate_worker_raw_with_owner(
    context: CandidateRawContextV1<'_>,
    journal: &ReadbackRetiredCandidateAttemptV1,
    owner_uid: u32,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    if context.selector != super::private_release_case::AUTHORIZATION_UNCERTAIN_SELECTOR
        || !context.expected_response.is_empty()
        || context.agent_path_snapshot.is_some()
    {
        return Err("MCSEALED-PRIVATE-RELEASE: uncertain raw selector differs".into());
    }
    protected_directory(context.directory, owner_uid)?;
    let request = read_fixed(context.directory, "request.bin", owner_uid)?;
    if request != read_fixed(context.directory, "request.json", owner_uid)?
        || journal.terminal_bytes != read_fixed(context.directory, "attempt.json", owner_uid)?
    {
        return Err("MCSEALED-PRIVATE-RELEASE: uncertain raw custody differs".into());
    }
    let report_bytes = read_fixed(context.directory, "report.bin", owner_uid)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&report_bytes)?;
    let report: NativeUncertainCandidateReportV1 =
        serde_json::from_slice(&report_bytes).map_err(|error| error.to_string())?;
    let inspection = std::str::from_utf8(context.installed_inspection_bytes)
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE: uncertain inspection is not UTF-8")?;
    if report.schema_version != 1
        || report.selector != context.selector
        || &report.result_key != context.result_key
        || report.attempt_id != journal.attempt_id
        || report.checkpoint_sha256 != journal.checkpoint_digest
        || report.terminal_record_digest != journal.terminal_record_digest
        || report.challenge_sha256 != hash_bytes(context.challenge)
        || report.release_knowledge != "possibly-released"
        || report.transport_errno != libc::EPIPE
        || report.authorization_failure_phase != 4
        || report.authorization_failure_detail != "authorization packet invalid"
        || report.candidate_exit_code == Some(0)
        || report.installed_inspection_json != inspection
    {
        return Err("MCSEALED-PRIVATE-RELEASE: uncertain raw report differs".into());
    }
    let stdio = read_fixed(context.directory, "stdio.bin", owner_uid)?;
    if stdio != context.challenge {
        return Err("MCSEALED-PRIVATE-RELEASE: uncertain target I/O differs".into());
    }
    let observer = read_fixed(context.directory, "observer.bin", owner_uid)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&observer)?;
    let trace: NativeUncertainKernelObservationV1 =
        serde_json::from_slice(&observer).map_err(|error| error.to_string())?;
    let guardian = super::private_guardian::GuardianTerminalV4::decode(
        trace.settlement.guardian_terminal,
        super::private_release_attempt::candidate_attempt_bytes(context.result_key),
    )?;
    if trace.schema_version != 1
        || trace.attempt_id != report.attempt_id
        || trace.checkpoint_sha256 != report.checkpoint_sha256
        || trace.terminal_record_digest != report.terminal_record_digest
        || trace.settlement.schema_version != 1
        || trace.settlement.transport_errno != libc::EPIPE
        || trace.authorization_failure_phase != report.authorization_failure_phase
        || trace.authorization_failure_detail != report.authorization_failure_detail
        || trace.settlement.candidate_exit_code != report.candidate_exit_code
        || !trace.settlement.containment_removed
        || !trace.settlement.target_pidfd_exited
        || !trace.settlement.namespace_init_reaped
        || guardian.trigger != super::private_guardian::GuardianTriggerV4::Stopped
        || guardian.boundary_retired
    {
        return Err("MCSEALED-PRIVATE-RELEASE: uncertain kernel trace differs".into());
    }
    let raw = [request, report_bytes, stdio, observer];
    Ok(PrivateReleaseAttachmentRoleV1::ALL
        .into_iter()
        .take(raw.len())
        .zip(raw)
        .map(|(role, bytes)| PrivateReleaseAttachmentV1 {
            role,
            size: bytes.len() as u64,
            sha256: hash_bytes(&bytes),
        })
        .collect())
}

#[cfg(feature = "test-support")]
pub(crate) fn readback_uncertain_candidate_worker_raw_for_test(
    context: CandidateRawContextV1<'_>,
    journal: &ReadbackRetiredCandidateAttemptV1,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    readback_uncertain_candidate_worker_raw_with_owner(context, journal, unsafe { libc::geteuid() })
}

#[allow(dead_code)]
pub(crate) fn persist_candidate_raw(
    context: CandidateRawContextV1<'_>,
    observed: &CandidateNativeObservationV1,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    if !super::private_release_case::candidate_fixture_supported(context.selector) {
        return Err("MCSEALED-PRIVATE-RELEASE: raw producer selector unavailable".into());
    }
    persist_candidate_raw_with_exact_selector(context, observed)
}

/// Protected raw for the AF_UNIX socket-stage case. Its exact selector stays
/// outside the generic TCP fixture path and requires the held-target witness.
pub(crate) fn persist_closed_unix_intent_raw(
    context: CandidateRawContextV1<'_>,
    observed: &CandidateNativeObservationV1,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    if context.selector != super::private_release_unix_intent::SELECTOR
        || context.expected_response
            != super::private_release_unix_intent::expected_observation_bytes(context.challenge)?
        || observed.unix_absence.as_ref().is_none_or(|witness| {
            witness
                .verify_binding(
                    context.challenge,
                    &witness.target,
                    observed.network_namespace_inode,
                )
                .is_err()
        })
    {
        return Err("MCSEALED-PRIVATE-RELEASE: Unix intent raw selector or shape differs".into());
    }
    persist_candidate_raw_with_exact_selector(context, observed)
}

fn persist_candidate_raw_with_exact_selector(
    context: CandidateRawContextV1<'_>,
    observed: &CandidateNativeObservationV1,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    if unsafe { libc::geteuid() } != 0
        || observed.attempt_id.is_empty()
        || observed.candidate_exit_code != 0
        || observed.challenge_sha256 != hash_bytes(context.challenge)
        || observed.response_bytes != context.expected_response
        || observed.response_sha256 != hash_bytes(context.expected_response)
        || (context.selector == super::private_release_unix_intent::SELECTOR)
            != observed.unix_absence.is_some()
    {
        return Err("MCSEALED-PRIVATE-RELEASE: raw producer authority differs".into());
    }
    protected_directory(context.directory, 0)?;
    let request = read_fixed(context.directory, "request.json", 0)?;
    let terminal = read_fixed(context.directory, "attempt.json", 0)?;
    if terminal != observed.terminal_bytes {
        return Err("MCSEALED-PRIVATE-RELEASE: terminal journal changed".into());
    }
    let inspection = std::str::from_utf8(context.installed_inspection_bytes)
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE: installed inspection is not UTF-8")?;
    let report = serde_json::to_vec(&NativeCandidateReportV1 {
        schema_version: 1,
        selector: context.selector,
        result_key: context.result_key,
        attempt_id: &observed.attempt_id,
        checkpoint_sha256: &observed.checkpoint_digest,
        terminal_record_digest: &observed.terminal_record_digest,
        challenge_sha256: &observed.challenge_sha256,
        response_sha256: &observed.response_sha256,
        candidate_exit_code: observed.candidate_exit_code,
        installed_inspection_json: inspection,
    })
    .map_err(|error| error.to_string())?;
    let kernel_trace = serde_json::to_vec(&NativeCandidateKernelObservationV1 {
        schema_version: 1,
        attempt_id: observed.attempt_id.clone(),
        checkpoint_sha256: observed.checkpoint_digest.clone(),
        terminal_record_digest: observed.terminal_record_digest.clone(),
        settlement: observed.settlement.clone(),
        host_network_preservation: observed.host_network_preservation.clone(),
        agent_path_preservation: observed.agent_path_preservation.clone(),
        unix_absence: observed.unix_absence.clone(),
    })
    .map_err(|error| error.to_string())?;
    let mut stdio = Vec::with_capacity(context.challenge.len() + observed.response_bytes.len());
    stdio.extend_from_slice(context.challenge);
    stdio.extend_from_slice(&observed.response_bytes);
    let bytes = [request, report, stdio, kernel_trace];
    let mut inventory = Vec::with_capacity(bytes.len());
    for (role, raw) in PrivateReleaseAttachmentRoleV1::ALL
        .into_iter()
        .take(bytes.len())
        .zip(bytes)
    {
        if raw.len() as u64 > MAX_PRIVATE_RELEASE_ATTACHMENT_BYTES_V1 {
            return Err("MCSEALED-PRIVATE-RELEASE: raw attachment exceeds byte bound".into());
        }
        persist_fixed(context.directory, role.leaf(), &raw, 0)?;
        inventory.push(PrivateReleaseAttachmentV1 {
            role,
            size: raw.len() as u64,
            sha256: hash_bytes(&raw),
        });
    }
    let readback = readback_candidate_worker_raw(
        context,
        &ReadbackRetiredCandidateAttemptV1 {
            attempt_id: observed.attempt_id.clone(),
            checkpoint_digest: observed.checkpoint_digest.clone(),
            terminal_record_digest: observed.terminal_record_digest.clone(),
            terminal_bytes: observed.terminal_bytes.clone(),
        },
    )?;
    if readback != inventory {
        return Err("MCSEALED-PRIVATE-RELEASE: raw attachment inventory changed".into());
    }
    Ok(inventory)
}

/// The worker records a distinct gate digest in both its report and kernel
/// observation. The detached service reader validates the gate leaf against
/// the protected pre-release journal before accepting these bytes.
#[allow(dead_code)]
pub(crate) fn persist_checkpoint_gate_worker_raw(
    context: CandidateRawContextV1<'_>,
    observed: &CheckpointGateNativeObservationV1,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    let candidate = &observed.candidate;
    if unsafe { libc::geteuid() } != 0
        || context.selector != super::private_release_case::CHECKPOINT_GATE_SELECTOR
        || context.agent_path_snapshot.is_some()
        || candidate.attempt_id.is_empty()
        || candidate.candidate_exit_code != 0
        || candidate.challenge_sha256 != hash_bytes(context.challenge)
        || candidate.response_bytes != context.expected_response
        || candidate.response_sha256 != hash_bytes(context.expected_response)
        || observed.gate_sha256 != hash_bytes(&read_checkpoint_gate_leaf(context.directory)?)
    {
        return Err("MCSEALED-PRIVATE-RELEASE: checkpoint-gate raw authority differs".into());
    }
    protected_directory(context.directory, 0)?;
    let request = read_fixed(context.directory, "request.json", 0)?;
    if read_fixed(context.directory, "attempt.json", 0)? != candidate.terminal_bytes {
        return Err("MCSEALED-PRIVATE-RELEASE: checkpoint-gate journal changed".into());
    }
    let inspection = std::str::from_utf8(context.installed_inspection_bytes)
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE: checkpoint-gate inspection is not UTF-8")?;
    let report = serde_json::to_vec(&NativeCheckpointGateReportV1 {
        schema_version: 1,
        selector: context.selector.to_owned(),
        result_key: context.result_key.clone(),
        attempt_id: candidate.attempt_id.clone(),
        checkpoint_sha256: candidate.checkpoint_digest.clone(),
        terminal_record_digest: candidate.terminal_record_digest.clone(),
        challenge_sha256: candidate.challenge_sha256.clone(),
        response_sha256: candidate.response_sha256.clone(),
        checkpoint_gate_sha256: observed.gate_sha256.clone(),
        candidate_exit_code: candidate.candidate_exit_code,
        installed_inspection_json: inspection.to_owned(),
    })
    .map_err(|error| error.to_string())?;
    let observer = serde_json::to_vec(&NativeCheckpointGateObserverV1 {
        schema_version: 1,
        attempt_id: candidate.attempt_id.clone(),
        checkpoint_sha256: candidate.checkpoint_digest.clone(),
        terminal_record_digest: candidate.terminal_record_digest.clone(),
        checkpoint_gate_sha256: observed.gate_sha256.clone(),
        settlement: candidate.settlement.clone(),
    })
    .map_err(|error| error.to_string())?;
    let mut stdio = Vec::with_capacity(context.challenge.len() + candidate.response_bytes.len());
    stdio.extend_from_slice(context.challenge);
    stdio.extend_from_slice(&candidate.response_bytes);
    let raw = [request, report, stdio, observer];
    let mut inventory = Vec::with_capacity(raw.len());
    for (role, bytes) in PrivateReleaseAttachmentRoleV1::ALL
        .into_iter()
        .take(raw.len())
        .zip(raw)
    {
        if bytes.len() as u64 > MAX_PRIVATE_RELEASE_ATTACHMENT_BYTES_V1 {
            return Err("MCSEALED-PRIVATE-RELEASE: checkpoint-gate raw bound differs".into());
        }
        persist_fixed(context.directory, role.leaf(), &bytes, 0)?;
        inventory.push(PrivateReleaseAttachmentV1 {
            role,
            size: bytes.len() as u64,
            sha256: hash_bytes(&bytes),
        });
    }
    let journal = ReadbackRetiredCandidateAttemptV1 {
        attempt_id: candidate.attempt_id.clone(),
        checkpoint_digest: candidate.checkpoint_digest.clone(),
        terminal_record_digest: candidate.terminal_record_digest.clone(),
        terminal_bytes: candidate.terminal_bytes.clone(),
    };
    if readback_checkpoint_gate_worker_raw(context, &journal)? != inventory {
        return Err("MCSEALED-PRIVATE-RELEASE: checkpoint-gate raw readback differs".into());
    }
    Ok(inventory)
}

#[allow(dead_code)]
pub(crate) fn readback_checkpoint_gate_worker_raw(
    context: CandidateRawContextV1<'_>,
    journal: &ReadbackRetiredCandidateAttemptV1,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    if context.selector != super::private_release_case::CHECKPOINT_GATE_SELECTOR
        || context.agent_path_snapshot.is_some()
    {
        return Err("MCSEALED-PRIVATE-RELEASE: checkpoint-gate selector differs".into());
    }
    protected_directory(context.directory, 0)?;
    let request = read_fixed(context.directory, "request.bin", 0)?;
    if request != read_fixed(context.directory, "request.json", 0)?
        || journal.terminal_bytes != read_fixed(context.directory, "attempt.json", 0)?
    {
        return Err("MCSEALED-PRIVATE-RELEASE: checkpoint-gate custody differs".into());
    }
    let gate_sha256 = hash_bytes(&read_checkpoint_gate_leaf(context.directory)?);
    let report_bytes = read_fixed(context.directory, "report.bin", 0)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&report_bytes)?;
    let report: NativeCheckpointGateReportV1 =
        serde_json::from_slice(&report_bytes).map_err(|error| error.to_string())?;
    let inspection = std::str::from_utf8(context.installed_inspection_bytes)
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE: checkpoint-gate inspection is not UTF-8")?;
    let native = journal.native_identities()?;
    if report.schema_version != 1
        || report.selector != context.selector
        || &report.result_key != context.result_key
        || report.attempt_id != journal.attempt_id
        || report.checkpoint_sha256 != journal.checkpoint_digest
        || report.terminal_record_digest != journal.terminal_record_digest
        || report.challenge_sha256 != hash_bytes(context.challenge)
        || report.response_sha256 != hash_bytes(context.expected_response)
        || report.checkpoint_gate_sha256 != gate_sha256
        || report.candidate_exit_code != 0
        || native.candidate_exit_code != Some(0)
        || report.installed_inspection_json != inspection
    {
        return Err("MCSEALED-PRIVATE-RELEASE: checkpoint-gate report differs".into());
    }
    let stdio = read_fixed(context.directory, "stdio.bin", 0)?;
    if stdio.len() != context.challenge.len() + context.expected_response.len()
        || stdio[..context.challenge.len()] != *context.challenge
        || stdio[context.challenge.len()..] != *context.expected_response
    {
        return Err("MCSEALED-PRIVATE-RELEASE: checkpoint-gate target I/O differs".into());
    }
    let observer = read_fixed(context.directory, "observer.bin", 0)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&observer)?;
    let trace: NativeCheckpointGateObserverV1 =
        serde_json::from_slice(&observer).map_err(|error| error.to_string())?;
    let settlement = &trace.settlement;
    let guardian = super::private_guardian::GuardianTerminalV4::decode(
        settlement.guardian_terminal,
        super::private_release_attempt::candidate_attempt_bytes(context.result_key),
    )?;
    if trace.schema_version != 1
        || trace.attempt_id != journal.attempt_id
        || trace.checkpoint_sha256 != journal.checkpoint_digest
        || trace.terminal_record_digest != journal.terminal_record_digest
        || trace.checkpoint_gate_sha256 != gate_sha256
        || settlement.schema_version != 1
        || settlement.monitor_outcome != super::private_lifecycle::PrivateMonitorOutcome::Completed
        || !settlement.cgroup_empty_before_cleanup
        || !settlement.containment_removed
        || !settlement.target_pidfd_exited
        || !settlement.namespace_init_reaped
        || settlement.candidate_exit_code != Some(0)
        || guardian.trigger != super::private_guardian::GuardianTriggerV4::Stopped
        || guardian.boundary_retired
    {
        return Err("MCSEALED-PRIVATE-RELEASE: checkpoint-gate observer differs".into());
    }
    let raw = [request, report_bytes, stdio, observer];
    Ok(PrivateReleaseAttachmentRoleV1::ALL
        .into_iter()
        .take(raw.len())
        .zip(raw)
        .map(|(role, bytes)| PrivateReleaseAttachmentV1 {
            role,
            size: bytes.len() as u64,
            sha256: hash_bytes(&bytes),
        })
        .collect())
}

fn expected_child_response(challenge: &[u8; 32], live: &LiveDescendantWitnessV1) -> Vec<u8> {
    let final_response = super::private_release_case::candidate_fixture_response(
        super::private_release_children::SELECTOR,
        challenge,
    );
    let mut response = Vec::with_capacity(live.live_frame().len() + final_response.len());
    response.extend_from_slice(&live.live_frame());
    response.extend_from_slice(&final_response);
    response
}

#[allow(dead_code)] // Child selector remains closed until detached joins land.
pub(crate) fn persist_child_worker_raw(
    context: CandidateRawContextV1<'_>,
    observed: &ChildCandidateNativeObservationV1,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    let candidate = &observed.candidate;
    let live = &observed.live;
    if unsafe { libc::geteuid() } != 0
        || context.selector != super::private_release_children::SELECTOR
        || !context.expected_response.is_empty()
        || context.agent_path_snapshot.is_some()
        || live.schema_version != 1
        || live.challenge_sha256 != hash_bytes(context.challenge)
        || live.target.pid == 0
        || live.child.pid == 0
        || live.child.pid == live.target.pid
        || live.thread_tid == 0
        || live.thread_tid == live.target.pid
        || live.thread_tid == live.child.pid
        || live.thread_start_time == 0
        || candidate.candidate_exit_code != 0
        || candidate.challenge_sha256 != hash_bytes(context.challenge)
        || candidate.response_bytes != expected_child_response(context.challenge, live)
        || candidate.response_sha256 != hash_bytes(&candidate.response_bytes)
    {
        return Err("MCSEALED-PRIVATE-RELEASE: child raw authority differs".into());
    }
    protected_directory(context.directory, 0)?;
    let request = read_fixed(context.directory, "request.json", 0)?;
    if read_fixed(context.directory, "attempt.json", 0)? != candidate.terminal_bytes {
        return Err("MCSEALED-PRIVATE-RELEASE: child journal changed".into());
    }
    let inspection = std::str::from_utf8(context.installed_inspection_bytes)
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE: child inspection is not UTF-8")?;
    let report = serde_json::to_vec(&NativeChildReportV1 {
        schema_version: 1,
        selector: context.selector.to_owned(),
        result_key: context.result_key.clone(),
        attempt_id: candidate.attempt_id.clone(),
        checkpoint_sha256: candidate.checkpoint_digest.clone(),
        terminal_record_digest: candidate.terminal_record_digest.clone(),
        challenge_sha256: candidate.challenge_sha256.clone(),
        response_sha256: candidate.response_sha256.clone(),
        child: live.child.clone(),
        thread_tid: live.thread_tid,
        thread_start_time: live.thread_start_time,
        target_namespace_pid: live.target_namespace_pid,
        child_namespace_pid: live.child_namespace_pid,
        thread_namespace_tid: live.thread_namespace_tid,
        target_pid_chain: live.target_pid_chain.clone(),
        child_pid_chain: live.child_pid_chain.clone(),
        thread_tid_chain: live.thread_tid_chain.clone(),
        candidate_exit_code: candidate.candidate_exit_code,
        installed_inspection_json: inspection.to_owned(),
    })
    .map_err(|error| error.to_string())?;
    let observer = serde_json::to_vec(&NativeChildObserverV1 {
        schema_version: 1,
        attempt_id: candidate.attempt_id.clone(),
        checkpoint_sha256: candidate.checkpoint_digest.clone(),
        terminal_record_digest: candidate.terminal_record_digest.clone(),
        live: live.clone(),
        settlement: candidate.settlement.clone(),
    })
    .map_err(|error| error.to_string())?;
    let mut stdio = Vec::with_capacity(context.challenge.len() + candidate.response_bytes.len());
    stdio.extend_from_slice(context.challenge);
    stdio.extend_from_slice(&candidate.response_bytes);
    let raw = [request, report, stdio, observer];
    let mut inventory = Vec::with_capacity(raw.len());
    for (role, bytes) in PrivateReleaseAttachmentRoleV1::ALL
        .into_iter()
        .take(raw.len())
        .zip(raw)
    {
        if bytes.len() as u64 > MAX_PRIVATE_RELEASE_ATTACHMENT_BYTES_V1 {
            return Err("MCSEALED-PRIVATE-RELEASE: child raw bound differs".into());
        }
        persist_fixed(context.directory, role.leaf(), &bytes, 0)?;
        inventory.push(PrivateReleaseAttachmentV1 {
            role,
            size: bytes.len() as u64,
            sha256: hash_bytes(&bytes),
        });
    }
    let journal = ReadbackRetiredCandidateAttemptV1 {
        attempt_id: candidate.attempt_id.clone(),
        checkpoint_digest: candidate.checkpoint_digest.clone(),
        terminal_record_digest: candidate.terminal_record_digest.clone(),
        terminal_bytes: candidate.terminal_bytes.clone(),
    };
    if readback_child_worker_raw(context, &journal)? != inventory {
        return Err("MCSEALED-PRIVATE-RELEASE: child raw readback differs".into());
    }
    Ok(inventory)
}

#[allow(dead_code)] // Child selector remains closed until detached joins land.
pub(crate) fn readback_child_worker_raw(
    context: CandidateRawContextV1<'_>,
    journal: &ReadbackRetiredCandidateAttemptV1,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    if context.selector != super::private_release_children::SELECTOR
        || !context.expected_response.is_empty()
        || context.agent_path_snapshot.is_some()
    {
        return Err("MCSEALED-PRIVATE-RELEASE: child raw selector differs".into());
    }
    protected_directory(context.directory, 0)?;
    let request = read_fixed(context.directory, "request.bin", 0)?;
    if request != read_fixed(context.directory, "request.json", 0)?
        || journal.terminal_bytes != read_fixed(context.directory, "attempt.json", 0)?
    {
        return Err("MCSEALED-PRIVATE-RELEASE: child raw custody differs".into());
    }
    let report_bytes = read_fixed(context.directory, "report.bin", 0)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&report_bytes)?;
    let report: NativeChildReportV1 =
        serde_json::from_slice(&report_bytes).map_err(|error| error.to_string())?;
    let inspection = std::str::from_utf8(context.installed_inspection_bytes)
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE: child inspection is not UTF-8")?;
    if report.schema_version != 1
        || report.selector != context.selector
        || &report.result_key != context.result_key
        || report.attempt_id != journal.attempt_id
        || report.checkpoint_sha256 != journal.checkpoint_digest
        || report.terminal_record_digest != journal.terminal_record_digest
        || report.challenge_sha256 != hash_bytes(context.challenge)
        || report.candidate_exit_code != 0
        || report.installed_inspection_json != inspection
    {
        return Err("MCSEALED-PRIVATE-RELEASE: child report differs".into());
    }
    let observer = read_fixed(context.directory, "observer.bin", 0)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&observer)?;
    let trace: NativeChildObserverV1 =
        serde_json::from_slice(&observer).map_err(|error| error.to_string())?;
    let native = journal.native_identities()?;
    let live = &trace.live;
    let guardian = super::private_guardian::GuardianTerminalV4::decode(
        trace.settlement.guardian_terminal,
        super::private_release_attempt::candidate_attempt_bytes(context.result_key),
    )?;
    if trace.schema_version != 1
        || trace.attempt_id != journal.attempt_id
        || trace.checkpoint_sha256 != journal.checkpoint_digest
        || trace.terminal_record_digest != journal.terminal_record_digest
        || live.schema_version != 1
        || live.target != native.target
        || live.child != report.child
        || live.child.pid == live.target.pid
        || live.thread_tid != report.thread_tid
        || live.thread_tid == live.target.pid
        || live.thread_tid == live.child.pid
        || live.thread_start_time != report.thread_start_time
        || live.thread_start_time == 0
        || live.target_namespace_pid != report.target_namespace_pid
        || live.child_namespace_pid != report.child_namespace_pid
        || live.thread_namespace_tid != report.thread_namespace_tid
        || live.target_pid_chain != report.target_pid_chain
        || live.child_pid_chain != report.child_pid_chain
        || live.thread_tid_chain != report.thread_tid_chain
        || live.target_namespace_pid == 0
        || live.child_namespace_pid == 0
        || live.thread_namespace_tid == 0
        || live.target_namespace_pid == live.child_namespace_pid
        || live.target_namespace_pid == live.thread_namespace_tid
        || live.child_namespace_pid == live.thread_namespace_tid
        || live.challenge_sha256 != report.challenge_sha256
        || trace.settlement.schema_version != 1
        || trace.settlement.monitor_outcome
            != super::private_lifecycle::PrivateMonitorOutcome::Completed
        || !trace.settlement.cgroup_empty_before_cleanup
        || !trace.settlement.containment_removed
        || !trace.settlement.target_pidfd_exited
        || !trace.settlement.namespace_init_reaped
        || trace.settlement.candidate_exit_code != Some(0)
        || guardian.trigger != super::private_guardian::GuardianTriggerV4::Stopped
        || guardian.boundary_retired
    {
        return Err("MCSEALED-PRIVATE-RELEASE: child observer differs".into());
    }
    let response = expected_child_response(context.challenge, live);
    let stdio = read_fixed(context.directory, "stdio.bin", 0)?;
    if report.response_sha256 != hash_bytes(&response)
        || stdio.len() != context.challenge.len() + response.len()
        || stdio[..context.challenge.len()] != *context.challenge
        || stdio[context.challenge.len()..] != response
    {
        return Err("MCSEALED-PRIVATE-RELEASE: child target I/O differs".into());
    }
    super::private_release_child_gate::readback_gate_and_ack(
        context.directory,
        context.result_key,
        context.challenge,
        live,
    )?;
    super::private_release_child_owner::verify_retired_witness(live, &journal.attempt_id)?;
    let raw = [request, report_bytes, stdio, observer];
    Ok(PrivateReleaseAttachmentRoleV1::ALL
        .into_iter()
        .take(raw.len())
        .zip(raw)
        .map(|(role, bytes)| PrivateReleaseAttachmentV1 {
            role,
            size: bytes.len() as u64,
            sha256: hash_bytes(&bytes),
        })
        .collect())
}

pub(crate) fn readback_candidate_worker_raw(
    context: CandidateRawContextV1<'_>,
    journal: &ReadbackRetiredCandidateAttemptV1,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    readback_candidate_worker_raw_with_owner(context, journal, 0)
}

pub(crate) struct CandidateCoordinatorCleanupContextV1<'a> {
    pub(crate) raw: CandidateRawContextV1<'a>,
    pub(crate) journal: &'a ReadbackRetiredCandidateAttemptV1,
    pub(crate) coordinator: &'a ProcessIdentityV4,
    pub(crate) worker: &'a ProcessIdentityV4,
    pub(crate) worker_pidfd: BorrowedFd<'a>,
    pub(crate) service_generation_sha256: &'a DiagnosticSha256,
}

/// Only the control coordinator calls this after the authenticated worker's
/// retained pidfd becomes readable. The worker cannot publish cleanup itself.
pub(crate) fn persist_coordinator_cleanup(
    context: CandidateCoordinatorCleanupContextV1<'_>,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    if unsafe { libc::geteuid() } != 0
        || context.worker == context.coordinator
        || context.worker.pid == 0
        || context.worker.start_time == 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE: coordinator cleanup authority differs".into());
    }
    let mut pollfd = libc::pollfd {
        fd: context.worker_pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll reads the exact worker pidfd authenticated before dispatch.
    if unsafe { libc::poll(&raw mut pollfd, 1, 0) } != 1
        || pollfd.revents & libc::POLLIN == 0
        || pollfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE: worker exit not observed".into());
    }
    let worker_inventory = readback_candidate_worker_raw(context.raw, context.journal)?;
    if worker_inventory.len() != PrivateReleaseAttachmentRoleV1::ALL.len() - 1 {
        return Err("MCSEALED-PRIVATE-RELEASE: worker raw inventory differs".into());
    }
    let observer = read_fixed(context.raw.directory, "observer.bin", 0)?;
    let cleanup = serde_json::to_vec(&NativeCandidateCleanupV1 {
        schema_version: 1,
        attempt_id: context.journal.attempt_id.clone(),
        checkpoint_sha256: context.journal.checkpoint_digest.clone(),
        terminal_record_digest: context.journal.terminal_record_digest.clone(),
        candidate_exit_code: 0,
        kernel_trace_sha256: hash_bytes(&observer),
        coordinator: context.coordinator.clone(),
        worker: context.worker.clone(),
        worker_pidfd_exited: true,
        service_generation_sha256: context.service_generation_sha256.clone(),
        settlement_source: "control-coordinator-pidfd".into(),
    })
    .map_err(|error| error.to_string())?;
    persist_fixed(context.raw.directory, "cleanup.bin", &cleanup, 0)?;
    readback_candidate_raw(
        context.raw,
        context.journal,
        context.coordinator,
        context.service_generation_sha256,
    )
}

#[allow(dead_code)]
pub(crate) fn persist_checkpoint_gate_coordinator_cleanup(
    context: CandidateCoordinatorCleanupContextV1<'_>,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    if unsafe { libc::geteuid() } != 0
        || context.raw.selector != super::private_release_case::CHECKPOINT_GATE_SELECTOR
        || context.worker == context.coordinator
        || context.worker.pid == 0
        || context.worker.start_time == 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE: checkpoint-gate cleanup authority differs".into());
    }
    let mut pollfd = libc::pollfd {
        fd: context.worker_pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: the coordinator retains the authenticated worker's exact pidfd.
    if unsafe { libc::poll(&raw mut pollfd, 1, 0) } != 1
        || pollfd.revents & libc::POLLIN == 0
        || pollfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE: checkpoint-gate worker exit absent".into());
    }
    let inventory = readback_checkpoint_gate_worker_raw(context.raw, context.journal)?;
    if inventory.len() != PrivateReleaseAttachmentRoleV1::ALL.len() - 1 {
        return Err("MCSEALED-PRIVATE-RELEASE: checkpoint-gate worker inventory differs".into());
    }
    let gate_sha256 = hash_bytes(&read_checkpoint_gate_leaf(context.raw.directory)?);
    let observer = read_fixed(context.raw.directory, "observer.bin", 0)?;
    let cleanup = serde_json::to_vec(&NativeCheckpointGateCleanupV1 {
        schema_version: 1,
        attempt_id: context.journal.attempt_id.clone(),
        checkpoint_sha256: context.journal.checkpoint_digest.clone(),
        terminal_record_digest: context.journal.terminal_record_digest.clone(),
        checkpoint_gate_sha256: gate_sha256,
        kernel_trace_sha256: hash_bytes(&observer),
        coordinator: context.coordinator.clone(),
        worker: context.worker.clone(),
        worker_pidfd_exited: true,
        service_generation_sha256: context.service_generation_sha256.clone(),
        settlement_source: "control-coordinator-pidfd".into(),
    })
    .map_err(|error| error.to_string())?;
    persist_fixed(context.raw.directory, "cleanup.bin", &cleanup, 0)?;
    readback_checkpoint_gate_raw(
        context.raw,
        context.journal,
        context.coordinator,
        context.service_generation_sha256,
    )
}

#[allow(dead_code)]
pub(crate) fn readback_checkpoint_gate_raw(
    context: CandidateRawContextV1<'_>,
    journal: &ReadbackRetiredCandidateAttemptV1,
    coordinator: &ProcessIdentityV4,
    service_generation_sha256: &DiagnosticSha256,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    let mut inventory = readback_checkpoint_gate_worker_raw(context, journal)?;
    let observer = read_fixed(context.directory, "observer.bin", 0)?;
    let cleanup_bytes = read_fixed(context.directory, "cleanup.bin", 0)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&cleanup_bytes)?;
    let cleanup: NativeCheckpointGateCleanupV1 =
        serde_json::from_slice(&cleanup_bytes).map_err(|error| error.to_string())?;
    if cleanup.schema_version != 1
        || cleanup.attempt_id != journal.attempt_id
        || cleanup.checkpoint_sha256 != journal.checkpoint_digest
        || cleanup.terminal_record_digest != journal.terminal_record_digest
        || cleanup.checkpoint_gate_sha256
            != hash_bytes(&read_checkpoint_gate_leaf(context.directory)?)
        || cleanup.kernel_trace_sha256 != hash_bytes(&observer)
        || &cleanup.coordinator != coordinator
        || cleanup.worker == *coordinator
        || cleanup.worker.pid == 0
        || cleanup.worker.start_time == 0
        || !cleanup.worker_pidfd_exited
        || &cleanup.service_generation_sha256 != service_generation_sha256
        || cleanup.settlement_source != "control-coordinator-pidfd"
    {
        return Err("MCSEALED-PRIVATE-RELEASE: checkpoint-gate cleanup differs".into());
    }
    super::private_release_run::require_recorded_process_exited(&cleanup.worker)?;
    inventory.push(PrivateReleaseAttachmentV1 {
        role: PrivateReleaseAttachmentRoleV1::Cleanup,
        size: cleanup_bytes.len() as u64,
        sha256: hash_bytes(&cleanup_bytes),
    });
    Ok(inventory)
}

#[allow(dead_code)] // Child selector remains closed until detached joins land.
pub(crate) fn persist_child_coordinator_cleanup(
    context: CandidateCoordinatorCleanupContextV1<'_>,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    if unsafe { libc::geteuid() } != 0
        || context.raw.selector != super::private_release_children::SELECTOR
        || context.worker == context.coordinator
        || context.worker.pid == 0
        || context.worker.start_time == 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE: child cleanup authority differs".into());
    }
    let mut pollfd = libc::pollfd {
        fd: context.worker_pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: the coordinator retains the authenticated worker's exact pidfd.
    if unsafe { libc::poll(&raw mut pollfd, 1, 0) } != 1
        || pollfd.revents & libc::POLLIN == 0
        || pollfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE: child worker exit absent".into());
    }
    let inventory = readback_child_worker_raw(context.raw, context.journal)?;
    if inventory.len() != PrivateReleaseAttachmentRoleV1::ALL.len() - 1 {
        return Err("MCSEALED-PRIVATE-RELEASE: child worker inventory differs".into());
    }
    let observer = read_fixed(context.raw.directory, "observer.bin", 0)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&observer)?;
    let trace: NativeChildObserverV1 =
        serde_json::from_slice(&observer).map_err(|error| error.to_string())?;
    let cleanup = serde_json::to_vec(&NativeChildCleanupV1 {
        schema_version: 1,
        attempt_id: context.journal.attempt_id.clone(),
        checkpoint_sha256: context.journal.checkpoint_digest.clone(),
        terminal_record_digest: context.journal.terminal_record_digest.clone(),
        child: trace.live.child,
        thread_tid: trace.live.thread_tid,
        target_namespace_pid: trace.live.target_namespace_pid,
        child_namespace_pid: trace.live.child_namespace_pid,
        thread_namespace_tid: trace.live.thread_namespace_tid,
        target_pid_chain: trace.live.target_pid_chain.clone(),
        child_pid_chain: trace.live.child_pid_chain.clone(),
        thread_tid_chain: trace.live.thread_tid_chain.clone(),
        kernel_trace_sha256: hash_bytes(&observer),
        coordinator: context.coordinator.clone(),
        worker: context.worker.clone(),
        worker_pidfd_exited: true,
        service_generation_sha256: context.service_generation_sha256.clone(),
        settlement_source: "control-coordinator-pidfd".into(),
    })
    .map_err(|error| error.to_string())?;
    persist_fixed(context.raw.directory, "cleanup.bin", &cleanup, 0)?;
    readback_child_raw(
        context.raw,
        context.journal,
        context.coordinator,
        context.service_generation_sha256,
    )
}

#[allow(dead_code)] // Child selector remains closed until detached joins land.
pub(crate) fn readback_child_raw(
    context: CandidateRawContextV1<'_>,
    journal: &ReadbackRetiredCandidateAttemptV1,
    coordinator: &ProcessIdentityV4,
    service_generation_sha256: &DiagnosticSha256,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    let mut inventory = readback_child_worker_raw(context, journal)?;
    let observer = read_fixed(context.directory, "observer.bin", 0)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&observer)?;
    let trace: NativeChildObserverV1 =
        serde_json::from_slice(&observer).map_err(|error| error.to_string())?;
    let cleanup_bytes = read_fixed(context.directory, "cleanup.bin", 0)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&cleanup_bytes)?;
    let cleanup: NativeChildCleanupV1 =
        serde_json::from_slice(&cleanup_bytes).map_err(|error| error.to_string())?;
    if cleanup.schema_version != 1
        || cleanup.attempt_id != journal.attempt_id
        || cleanup.checkpoint_sha256 != journal.checkpoint_digest
        || cleanup.terminal_record_digest != journal.terminal_record_digest
        || cleanup.child != trace.live.child
        || cleanup.thread_tid != trace.live.thread_tid
        || cleanup.target_namespace_pid != trace.live.target_namespace_pid
        || cleanup.child_namespace_pid != trace.live.child_namespace_pid
        || cleanup.thread_namespace_tid != trace.live.thread_namespace_tid
        || cleanup.target_pid_chain != trace.live.target_pid_chain
        || cleanup.child_pid_chain != trace.live.child_pid_chain
        || cleanup.thread_tid_chain != trace.live.thread_tid_chain
        || cleanup.kernel_trace_sha256 != hash_bytes(&observer)
        || &cleanup.coordinator != coordinator
        || cleanup.worker == *coordinator
        || cleanup.worker.pid == 0
        || cleanup.worker.start_time == 0
        || !cleanup.worker_pidfd_exited
        || &cleanup.service_generation_sha256 != service_generation_sha256
        || cleanup.settlement_source != "control-coordinator-pidfd"
    {
        return Err("MCSEALED-PRIVATE-RELEASE: child cleanup differs".into());
    }
    super::private_release_run::require_recorded_process_exited(&cleanup.worker)?;
    super::private_release_child_owner::verify_retired_witness(&trace.live, &journal.attempt_id)?;
    inventory.push(PrivateReleaseAttachmentV1 {
        role: PrivateReleaseAttachmentRoleV1::Cleanup,
        size: cleanup_bytes.len() as u64,
        sha256: hash_bytes(&cleanup_bytes),
    });
    Ok(inventory)
}

/// The coordinator, never the worker, writes the uncertainty cleanup after
/// observing the exact worker pidfd exit and rereading its protected bytes.
#[allow(dead_code)] // Routed with detached uncertainty verification.
pub(crate) fn persist_uncertain_coordinator_cleanup(
    context: CandidateCoordinatorCleanupContextV1<'_>,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    if unsafe { libc::geteuid() } != 0
        || context.raw.selector != super::private_release_case::AUTHORIZATION_UNCERTAIN_SELECTOR
        || context.worker == context.coordinator
        || context.worker.pid == 0
        || context.worker.start_time == 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE: uncertain cleanup authority differs".into());
    }
    let mut pollfd = libc::pollfd {
        fd: context.worker_pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: this reads the exact worker pidfd retained by the coordinator.
    if unsafe { libc::poll(&raw mut pollfd, 1, 0) } != 1
        || pollfd.revents & libc::POLLIN == 0
        || pollfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE: uncertain worker exit not observed".into());
    }
    let worker_inventory = readback_uncertain_candidate_worker_raw(context.raw, context.journal)?;
    if worker_inventory.len() != PrivateReleaseAttachmentRoleV1::ALL.len() - 1 {
        return Err("MCSEALED-PRIVATE-RELEASE: uncertain worker inventory differs".into());
    }
    let observer = read_fixed(context.raw.directory, "observer.bin", 0)?;
    let cleanup = serde_json::to_vec(&NativeUncertainCandidateCleanupV1 {
        schema_version: 1,
        attempt_id: context.journal.attempt_id.clone(),
        checkpoint_sha256: context.journal.checkpoint_digest.clone(),
        terminal_record_digest: context.journal.terminal_record_digest.clone(),
        release_knowledge: "possibly-released".into(),
        transport_errno: libc::EPIPE,
        kernel_trace_sha256: hash_bytes(&observer),
        coordinator: context.coordinator.clone(),
        worker: context.worker.clone(),
        worker_pidfd_exited: true,
        service_generation_sha256: context.service_generation_sha256.clone(),
        settlement_source: "control-coordinator-pidfd".into(),
    })
    .map_err(|error| error.to_string())?;
    persist_fixed(context.raw.directory, "cleanup.bin", &cleanup, 0)?;
    readback_uncertain_candidate_raw(
        context.raw,
        context.journal,
        context.coordinator,
        context.service_generation_sha256,
    )
}

#[allow(dead_code)] // Called by the detached uncertainty reader once routed.
pub(crate) fn readback_uncertain_candidate_raw(
    context: CandidateRawContextV1<'_>,
    journal: &ReadbackRetiredCandidateAttemptV1,
    coordinator: &ProcessIdentityV4,
    service_generation_sha256: &DiagnosticSha256,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    let mut inventory = readback_uncertain_candidate_worker_raw(context, journal)?;
    let observer = read_fixed(context.directory, "observer.bin", 0)?;
    let cleanup_bytes = read_fixed(context.directory, "cleanup.bin", 0)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&cleanup_bytes)?;
    let cleanup: NativeUncertainCandidateCleanupV1 =
        serde_json::from_slice(&cleanup_bytes).map_err(|error| error.to_string())?;
    if cleanup.schema_version != 1
        || cleanup.attempt_id != journal.attempt_id
        || cleanup.checkpoint_sha256 != journal.checkpoint_digest
        || cleanup.terminal_record_digest != journal.terminal_record_digest
        || cleanup.release_knowledge != "possibly-released"
        || cleanup.transport_errno != libc::EPIPE
        || cleanup.kernel_trace_sha256 != hash_bytes(&observer)
        || &cleanup.coordinator != coordinator
        || cleanup.worker == *coordinator
        || cleanup.worker.pid == 0
        || cleanup.worker.start_time == 0
        || !cleanup.worker_pidfd_exited
        || &cleanup.service_generation_sha256 != service_generation_sha256
        || cleanup.settlement_source != "control-coordinator-pidfd"
    {
        return Err("MCSEALED-PRIVATE-RELEASE: uncertain coordinator cleanup differs".into());
    }
    super::private_release_run::require_recorded_process_exited(&cleanup.worker)?;
    inventory.push(PrivateReleaseAttachmentV1 {
        role: PrivateReleaseAttachmentRoleV1::Cleanup,
        size: cleanup_bytes.len() as u64,
        sha256: hash_bytes(&cleanup_bytes),
    });
    Ok(inventory)
}

#[allow(dead_code)] // Coordinator fault route is not connected yet.
pub(crate) fn persist_blocked_retirement_coordinator_cleanup(
    context: CandidateCoordinatorCleanupContextV1<'_>,
    blocked: &super::private_release_attempt::ReadbackBlockedCandidateAttemptV1,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    if unsafe { libc::geteuid() } != 0
        || context.raw.selector != super::private_release_case::RETIREMENT_FAULT_SELECTOR
        || context.journal.terminal_bytes != blocked.journal.terminal_bytes
        || context.worker == context.coordinator
        || context.worker.pid == 0
        || context.worker.start_time == 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE: blocked cleanup authority differs".into());
    }
    let mut pollfd = libc::pollfd {
        fd: context.worker_pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: this observes the authenticated worker's retained exact pidfd.
    if unsafe { libc::poll(&raw mut pollfd, 1, 0) } != 1
        || pollfd.revents & libc::POLLIN == 0
        || pollfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE: blocked worker exit absent".into());
    }
    let worker_inventory = readback_blocked_retirement_worker_raw(context.raw, blocked)?;
    if worker_inventory.len() != PrivateReleaseAttachmentRoleV1::ALL.len() - 1 {
        return Err("MCSEALED-PRIVATE-RELEASE: blocked worker inventory differs".into());
    }
    let observer = read_fixed(context.raw.directory, "observer.bin", 0)?;
    let cleanup = serde_json::to_vec(&NativeBlockedRetirementCleanupV1 {
        schema_version: 1,
        attempt_id: blocked.journal.attempt_id.clone(),
        checkpoint_sha256: blocked.journal.checkpoint_digest.clone(),
        terminal_record_digest: blocked.journal.terminal_record_digest.clone(),
        fault_marker_sha256: hash_bytes(&blocked.fault_marker_bytes),
        reuse_rejection_sha256: hash_bytes(blocked.detached_reuse_error.as_bytes()),
        kernel_trace_sha256: hash_bytes(&observer),
        coordinator: context.coordinator.clone(),
        worker: context.worker.clone(),
        worker_pidfd_exited: true,
        service_generation_sha256: context.service_generation_sha256.clone(),
        settlement_source: "control-coordinator-pidfd".into(),
    })
    .map_err(|error| error.to_string())?;
    persist_fixed(context.raw.directory, "cleanup.bin", &cleanup, 0)?;
    readback_blocked_retirement_raw(
        context.raw,
        blocked,
        context.coordinator,
        context.service_generation_sha256,
    )
}

#[allow(dead_code)] // Detached fault reader invokes this after coordinator exit.
pub(crate) fn readback_blocked_retirement_raw(
    context: CandidateRawContextV1<'_>,
    blocked: &super::private_release_attempt::ReadbackBlockedCandidateAttemptV1,
    coordinator: &ProcessIdentityV4,
    service_generation_sha256: &DiagnosticSha256,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    let mut inventory = readback_blocked_retirement_worker_raw(context, blocked)?;
    let observer = read_fixed(context.directory, "observer.bin", 0)?;
    let cleanup_bytes = read_fixed(context.directory, "cleanup.bin", 0)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&cleanup_bytes)?;
    let cleanup: NativeBlockedRetirementCleanupV1 =
        serde_json::from_slice(&cleanup_bytes).map_err(|error| error.to_string())?;
    if cleanup.schema_version != 1
        || cleanup.attempt_id != blocked.journal.attempt_id
        || cleanup.checkpoint_sha256 != blocked.journal.checkpoint_digest
        || cleanup.terminal_record_digest != blocked.journal.terminal_record_digest
        || cleanup.fault_marker_sha256 != hash_bytes(&blocked.fault_marker_bytes)
        || cleanup.reuse_rejection_sha256 != hash_bytes(blocked.detached_reuse_error.as_bytes())
        || cleanup.kernel_trace_sha256 != hash_bytes(&observer)
        || &cleanup.coordinator != coordinator
        || cleanup.worker == *coordinator
        || cleanup.worker.pid == 0
        || cleanup.worker.start_time == 0
        || !cleanup.worker_pidfd_exited
        || &cleanup.service_generation_sha256 != service_generation_sha256
        || cleanup.settlement_source != "control-coordinator-pidfd"
    {
        return Err("MCSEALED-PRIVATE-RELEASE: blocked coordinator cleanup differs".into());
    }
    super::private_release_run::require_recorded_process_exited(&cleanup.worker)?;
    inventory.push(PrivateReleaseAttachmentV1 {
        role: PrivateReleaseAttachmentRoleV1::Cleanup,
        size: cleanup_bytes.len() as u64,
        sha256: hash_bytes(&cleanup_bytes),
    });
    Ok(inventory)
}

#[allow(dead_code)] // Fixed guardian-loss coordinator route remains closed.
pub(crate) fn persist_guardian_loss_coordinator_cleanup(
    context: CandidateCoordinatorCleanupContextV1<'_>,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    if unsafe { libc::geteuid() } != 0
        || context.raw.selector != super::private_release_guardian_loss::SELECTOR
        || context.worker == context.coordinator
        || context.worker.pid == 0
        || context.worker.start_time == 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE: guardian-loss cleanup authority differs".into());
    }
    let mut pollfd = libc::pollfd {
        fd: context.worker_pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: this observes the authenticated worker's retained exact pidfd.
    if unsafe { libc::poll(&raw mut pollfd, 1, 0) } != 1
        || pollfd.revents & libc::POLLIN == 0
        || pollfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE: guardian-loss worker exit absent".into());
    }
    let worker_inventory = readback_guardian_loss_worker_raw(context.raw, context.journal)?;
    if worker_inventory.len() != PrivateReleaseAttachmentRoleV1::ALL.len() - 1 {
        return Err("MCSEALED-PRIVATE-RELEASE: guardian-loss worker inventory differs".into());
    }
    let observer = read_fixed(context.raw.directory, "observer.bin", 0)?;
    let cleanup = serde_json::to_vec(&NativeGuardianLossCleanupV1 {
        schema_version: 1,
        attempt_id: context.journal.attempt_id.clone(),
        checkpoint_sha256: context.journal.checkpoint_digest.clone(),
        terminal_record_digest: context.journal.terminal_record_digest.clone(),
        guardian_signal: libc::SIGKILL,
        kernel_trace_sha256: hash_bytes(&observer),
        coordinator: context.coordinator.clone(),
        worker: context.worker.clone(),
        worker_pidfd_exited: true,
        service_generation_sha256: context.service_generation_sha256.clone(),
        settlement_source: "control-coordinator-pidfd".into(),
    })
    .map_err(|error| error.to_string())?;
    persist_fixed(context.raw.directory, "cleanup.bin", &cleanup, 0)?;
    readback_guardian_loss_raw(
        context.raw,
        context.journal,
        context.coordinator,
        context.service_generation_sha256,
    )
}

#[allow(dead_code)] // Detached guardian-loss reader invokes this after coordinator exit.
pub(crate) fn readback_guardian_loss_raw(
    context: CandidateRawContextV1<'_>,
    journal: &ReadbackRetiredCandidateAttemptV1,
    coordinator: &ProcessIdentityV4,
    service_generation_sha256: &DiagnosticSha256,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    let mut inventory = readback_guardian_loss_worker_raw(context, journal)?;
    let observer = read_fixed(context.directory, "observer.bin", 0)?;
    let cleanup_bytes = read_fixed(context.directory, "cleanup.bin", 0)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&cleanup_bytes)?;
    let cleanup: NativeGuardianLossCleanupV1 =
        serde_json::from_slice(&cleanup_bytes).map_err(|error| error.to_string())?;
    if cleanup.schema_version != 1
        || cleanup.attempt_id != journal.attempt_id
        || cleanup.checkpoint_sha256 != journal.checkpoint_digest
        || cleanup.terminal_record_digest != journal.terminal_record_digest
        || cleanup.guardian_signal != libc::SIGKILL
        || cleanup.kernel_trace_sha256 != hash_bytes(&observer)
        || &cleanup.coordinator != coordinator
        || cleanup.worker == *coordinator
        || cleanup.worker.pid == 0
        || cleanup.worker.start_time == 0
        || !cleanup.worker_pidfd_exited
        || &cleanup.service_generation_sha256 != service_generation_sha256
        || cleanup.settlement_source != "control-coordinator-pidfd"
    {
        return Err("MCSEALED-PRIVATE-RELEASE: guardian-loss cleanup differs".into());
    }
    super::private_release_run::require_recorded_process_exited(&cleanup.worker)?;
    inventory.push(PrivateReleaseAttachmentV1 {
        role: PrivateReleaseAttachmentRoleV1::Cleanup,
        size: cleanup_bytes.len() as u64,
        sha256: hash_bytes(&cleanup_bytes),
    });
    Ok(inventory)
}

pub(crate) fn persist_frontend_loss_coordinator_cleanup(
    context: CandidateCoordinatorCleanupContextV1<'_>,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    if unsafe { libc::geteuid() } != 0
        || context.raw.selector != super::private_release_frontend_loss::SELECTOR
        || context.worker == context.coordinator
        || context.worker.pid == 0
        || context.worker.start_time == 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE: frontend-loss cleanup authority differs".into());
    }
    let mut pollfd = libc::pollfd {
        fd: context.worker_pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: the retained exact pidfd belongs to the broker worker, not the
    // sacrificial relay-owning frontend proxy.
    if unsafe { libc::poll(&raw mut pollfd, 1, 0) } != 1
        || pollfd.revents & libc::POLLIN == 0
        || pollfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE: frontend-loss worker exit absent".into());
    }
    let worker_inventory = readback_frontend_loss_worker_raw(context.raw, context.journal)?;
    if worker_inventory.len() != PrivateReleaseAttachmentRoleV1::ALL.len() - 1 {
        return Err("MCSEALED-PRIVATE-RELEASE: frontend-loss worker inventory differs".into());
    }
    let native = context.journal.native_identities()?;
    let frontend_proxy = native
        .frontend_proxy
        .ok_or("MCSEALED-PRIVATE-RELEASE: frontend-loss proxy absent")?;
    let observer = read_fixed(context.raw.directory, "observer.bin", 0)?;
    let trace: NativeFrontendLossObserverV1 =
        serde_json::from_slice(&observer).map_err(|error| error.to_string())?;
    let cleanup = serde_json::to_vec(&NativeFrontendLossCleanupV1 {
        schema_version: 1,
        attempt_id: context.journal.attempt_id.clone(),
        checkpoint_sha256: context.journal.checkpoint_digest.clone(),
        terminal_record_digest: context.journal.terminal_record_digest.clone(),
        frontend_proxy,
        frontend_signal: libc::SIGKILL,
        guardian_terminal: trace.settlement.guardian_terminal,
        kernel_trace_sha256: hash_bytes(&observer),
        coordinator: context.coordinator.clone(),
        worker: context.worker.clone(),
        worker_pidfd_exited: true,
        service_generation_sha256: context.service_generation_sha256.clone(),
        settlement_source: "control-coordinator-pidfd".into(),
    })
    .map_err(|error| error.to_string())?;
    persist_fixed(context.raw.directory, "cleanup.bin", &cleanup, 0)?;
    readback_frontend_loss_raw(
        context.raw,
        context.journal,
        context.coordinator,
        context.service_generation_sha256,
    )
}

pub(crate) fn readback_frontend_loss_raw(
    context: CandidateRawContextV1<'_>,
    journal: &ReadbackRetiredCandidateAttemptV1,
    coordinator: &ProcessIdentityV4,
    service_generation_sha256: &DiagnosticSha256,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    let mut inventory = readback_frontend_loss_worker_raw(context, journal)?;
    let native = journal.native_identities()?;
    let frontend_proxy = native
        .frontend_proxy
        .ok_or("MCSEALED-PRIVATE-RELEASE: frontend-loss proxy absent")?;
    let observer = read_fixed(context.directory, "observer.bin", 0)?;
    let trace: NativeFrontendLossObserverV1 =
        serde_json::from_slice(&observer).map_err(|error| error.to_string())?;
    let cleanup_bytes = read_fixed(context.directory, "cleanup.bin", 0)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&cleanup_bytes)?;
    let cleanup: NativeFrontendLossCleanupV1 =
        serde_json::from_slice(&cleanup_bytes).map_err(|error| error.to_string())?;
    if cleanup.schema_version != 1
        || cleanup.attempt_id != journal.attempt_id
        || cleanup.checkpoint_sha256 != journal.checkpoint_digest
        || cleanup.terminal_record_digest != journal.terminal_record_digest
        || cleanup.frontend_proxy != frontend_proxy
        || cleanup.frontend_signal != libc::SIGKILL
        || cleanup.guardian_terminal != trace.settlement.guardian_terminal
        || cleanup.kernel_trace_sha256 != hash_bytes(&observer)
        || &cleanup.coordinator != coordinator
        || cleanup.worker == *coordinator
        || cleanup.worker == frontend_proxy
        || cleanup.worker.pid == 0
        || cleanup.worker.start_time == 0
        || !cleanup.worker_pidfd_exited
        || &cleanup.service_generation_sha256 != service_generation_sha256
        || cleanup.settlement_source != "control-coordinator-pidfd"
    {
        return Err("MCSEALED-PRIVATE-RELEASE: frontend-loss cleanup differs".into());
    }
    super::private_release_run::require_recorded_process_exited(&cleanup.worker)?;
    inventory.push(PrivateReleaseAttachmentV1 {
        role: PrivateReleaseAttachmentRoleV1::Cleanup,
        size: cleanup_bytes.len() as u64,
        sha256: hash_bytes(&cleanup_bytes),
    });
    Ok(inventory)
}

pub(crate) fn readback_candidate_raw(
    context: CandidateRawContextV1<'_>,
    journal: &ReadbackRetiredCandidateAttemptV1,
    coordinator: &ProcessIdentityV4,
    service_generation_sha256: &DiagnosticSha256,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    let mut inventory = readback_candidate_worker_raw(context, journal)?;
    let observer = read_fixed(context.directory, "observer.bin", 0)?;
    let cleanup_bytes = read_fixed(context.directory, "cleanup.bin", 0)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&cleanup_bytes)?;
    let cleanup: NativeCandidateCleanupV1 =
        serde_json::from_slice(&cleanup_bytes).map_err(|error| error.to_string())?;
    if cleanup.schema_version != 1
        || cleanup.attempt_id != journal.attempt_id
        || cleanup.checkpoint_sha256 != journal.checkpoint_digest
        || cleanup.terminal_record_digest != journal.terminal_record_digest
        || cleanup.candidate_exit_code != 0
        || cleanup.kernel_trace_sha256 != hash_bytes(&observer)
        || &cleanup.coordinator != coordinator
        || cleanup.worker == *coordinator
        || cleanup.worker.pid == 0
        || cleanup.worker.start_time == 0
        || !cleanup.worker_pidfd_exited
        || &cleanup.service_generation_sha256 != service_generation_sha256
        || cleanup.settlement_source != "control-coordinator-pidfd"
    {
        return Err("MCSEALED-PRIVATE-RELEASE: coordinator cleanup differs".into());
    }
    super::private_release_run::require_recorded_process_exited(&cleanup.worker)?;
    inventory.push(PrivateReleaseAttachmentV1 {
        role: PrivateReleaseAttachmentRoleV1::Cleanup,
        size: cleanup_bytes.len() as u64,
        sha256: hash_bytes(&cleanup_bytes),
    });
    Ok(inventory)
}

fn readback_candidate_worker_raw_with_owner(
    context: CandidateRawContextV1<'_>,
    journal: &ReadbackRetiredCandidateAttemptV1,
    owner_uid: u32,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    protected_directory(context.directory, owner_uid)?;
    let request = read_fixed(context.directory, "request.bin", owner_uid)?;
    if request != read_fixed(context.directory, "request.json", owner_uid)? {
        return Err("MCSEALED-PRIVATE-RELEASE: protected request copy differs".into());
    }
    let report_bytes = read_fixed(context.directory, "report.bin", owner_uid)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&report_bytes)?;
    let report: ReadbackNativeCandidateReportV1 =
        serde_json::from_slice(&report_bytes).map_err(|error| error.to_string())?;
    let inspection = std::str::from_utf8(context.installed_inspection_bytes)
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE: installed inspection is not UTF-8")?;
    if report.schema_version != 1
        || report.selector != context.selector
        || &report.result_key != context.result_key
        || report.attempt_id != journal.attempt_id
        || report.checkpoint_sha256 != journal.checkpoint_digest
        || report.terminal_record_digest != journal.terminal_record_digest
        || report.challenge_sha256 != hash_bytes(context.challenge)
        || report.response_sha256 != hash_bytes(context.expected_response)
        || report.candidate_exit_code != 0
        || report.installed_inspection_json != inspection
    {
        return Err("MCSEALED-PRIVATE-RELEASE: protected native report differs".into());
    }
    let stdio = read_fixed(context.directory, "stdio.bin", owner_uid)?;
    if stdio.len() != context.challenge.len() + context.expected_response.len()
        || stdio[..context.challenge.len()] != *context.challenge
        || stdio[context.challenge.len()..] != *context.expected_response
    {
        return Err("MCSEALED-PRIVATE-RELEASE: protected target I/O differs".into());
    }
    let observer = read_fixed(context.directory, "observer.bin", owner_uid)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&observer)?;
    let kernel_trace: NativeCandidateKernelObservationV1 =
        serde_json::from_slice(&observer).map_err(|error| error.to_string())?;
    let settlement = &kernel_trace.settlement;
    let host_preservation_valid = match (
        context.selector == super::private_release_host_state::SELECTOR,
        kernel_trace.host_network_preservation.as_ref(),
    ) {
        (true, Some(proof)) => proof.verify_current().is_ok(),
        (false, None) => true,
        _ => false,
    };
    let agent_path_valid = match (
        context.selector == super::private_release_ancestor::SELECTOR,
        kernel_trace.agent_path_preservation.as_ref(),
        context.agent_path_snapshot,
    ) {
        (true, Some(proof), Some(current)) => proof.verify_current(current).is_ok(),
        (false, None, None) => true,
        _ => false,
    };
    let unix_absence_valid = match (
        context.selector == super::private_release_unix_intent::SELECTOR,
        kernel_trace.unix_absence.as_ref(),
    ) {
        (true, Some(witness)) => journal
            .native_identities()
            .and_then(|native| {
                witness.verify_binding(
                    context.challenge,
                    &native.target,
                    native.network_namespace_inode,
                )?;
                super::private_release_unix_gate::readback_gate_and_ack(
                    context.directory,
                    context.result_key,
                    context.challenge,
                    witness,
                )
            })
            .is_ok(),
        (false, None) => true,
        _ => false,
    };
    let guardian = super::private_guardian::GuardianTerminalV4::decode(
        settlement.guardian_terminal,
        super::private_release_attempt::candidate_attempt_bytes(context.result_key),
    )?;
    if kernel_trace.schema_version != 1
        || kernel_trace.attempt_id != journal.attempt_id
        || kernel_trace.checkpoint_sha256 != journal.checkpoint_digest
        || kernel_trace.terminal_record_digest != journal.terminal_record_digest
        || settlement.schema_version != 1
        || settlement.monitor_outcome != super::private_lifecycle::PrivateMonitorOutcome::Completed
        || !settlement.cgroup_empty_before_cleanup
        || !settlement.containment_removed
        || !settlement.target_pidfd_exited
        || !settlement.namespace_init_reaped
        || settlement.candidate_exit_code != Some(0)
        || !host_preservation_valid
        || !agent_path_valid
        || !unix_absence_valid
        || guardian.trigger != super::private_guardian::GuardianTriggerV4::Stopped
        || guardian.boundary_retired
    {
        return Err("MCSEALED-PRIVATE-RELEASE: protected kernel trace differs".into());
    }
    let raw = [request, report_bytes, stdio, observer];
    Ok(PrivateReleaseAttachmentRoleV1::ALL
        .into_iter()
        .take(raw.len())
        .zip(raw)
        .map(|(role, bytes)| PrivateReleaseAttachmentV1 {
            role,
            size: bytes.len() as u64,
            sha256: hash_bytes(&bytes),
        })
        .collect())
}

#[cfg(feature = "test-support")]
pub(crate) fn readback_candidate_worker_raw_for_test(
    context: CandidateRawContextV1<'_>,
    journal: &ReadbackRetiredCandidateAttemptV1,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    readback_candidate_worker_raw_with_owner(context, journal, unsafe { libc::geteuid() })
}

pub(crate) fn protected_directory(directory: &File, owner_uid: u32) -> Result<(), String> {
    let metadata = directory.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_dir() || metadata.uid() != owner_uid || metadata.mode() & 0o777 != 0o700 {
        return Err("MCSEALED-PRIVATE-RELEASE: raw directory protection differs".into());
    }
    Ok(())
}

pub(crate) fn read_fixed(directory: &File, leaf: &str, owner_uid: u32) -> Result<Vec<u8>, String> {
    let name = CString::new(leaf).map_err(|_| "MCSEALED-PRIVATE-RELEASE: raw leaf NUL")?;
    // SAFETY: openat resolves one fixed leaf below the retained directory.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: raw source open: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful openat transferred one owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > MAX_PRIVATE_RELEASE_ATTACHMENT_BYTES_V1
    {
        return Err("MCSEALED-PRIVATE-RELEASE: raw source protection differs".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_PRIVATE_RELEASE_ATTACHMENT_BYTES_V1 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_PRIVATE_RELEASE_ATTACHMENT_BYTES_V1 {
        return Err("MCSEALED-PRIVATE-RELEASE: raw source byte bound differs".into());
    }
    Ok(bytes)
}

pub(crate) fn persist_fixed(
    directory: &File,
    leaf: &str,
    bytes: &[u8],
    owner_uid: u32,
) -> Result<(), String> {
    protected_directory(directory, owner_uid)?;
    let name = CString::new(leaf).map_err(|_| "MCSEALED-PRIVATE-RELEASE: raw leaf NUL")?;
    // SAFETY: O_EXCL and O_NOFOLLOW prevent replacing prior evidence.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: raw attachment already exists: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful openat transferred one owned descriptor.
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string())?;
    directory.sync_all().map_err(|error| error.to_string())?;
    if read_fixed(directory, leaf, owner_uid)? != bytes {
        return Err("MCSEALED-PRIVATE-RELEASE: raw attachment readback differs".into());
    }
    Ok(())
}

pub(crate) fn persist_checkpoint_gate_leaf(directory: &File, bytes: &[u8]) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("MCSEALED-PRIVATE-RELEASE: checkpoint gate requires root".into());
    }
    persist_fixed(directory, "checkpoint-gate.json", bytes, 0)
}

pub(crate) fn read_checkpoint_gate_leaf(directory: &File) -> Result<Vec<u8>, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("MCSEALED-PRIVATE-RELEASE: checkpoint gate requires root".into());
    }
    read_fixed(directory, "checkpoint-gate.json", 0)
}

#[cfg(feature = "test-support")]
pub(crate) fn persist_checkpoint_gate_leaf_for_test(
    directory: &File,
    bytes: &[u8],
) -> Result<(), String> {
    persist_fixed(directory, "checkpoint-gate.json", bytes, unsafe {
        libc::geteuid()
    })
}

#[cfg(feature = "test-support")]
pub(crate) fn read_checkpoint_gate_leaf_for_test(directory: &File) -> Result<Vec<u8>, String> {
    read_fixed(directory, "checkpoint-gate.json", unsafe {
        libc::geteuid()
    })
}

#[cfg(feature = "test-support")]
pub(crate) fn persist_attachment_for_test(
    directory: &File,
    role: PrivateReleaseAttachmentRoleV1,
    bytes: &[u8],
) -> Result<(), String> {
    persist_fixed(directory, role.leaf(), bytes, unsafe { libc::geteuid() })
}

#[cfg(feature = "test-support")]
pub(crate) fn read_attachment_for_test(
    directory: &File,
    role: PrivateReleaseAttachmentRoleV1,
) -> Result<Vec<u8>, String> {
    read_fixed(directory, role.leaf(), unsafe { libc::geteuid() })
}
