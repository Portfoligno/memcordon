//! Protected post-release midpoint diagnostics. The early live frame is
//! joined to a durable ExecObserved snapshot and later native settlement;
//! the worker cannot author coordinator cleanup or a completed result.

use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::{
    MAX_PRIVATE_RELEASE_ATTACHMENT_BYTES_V1, PrivateReleaseAttachmentRoleV1,
    PrivateReleaseAttachmentV1,
};
use memcordon_core::workload_codec::hash_bytes;
use serde::{Deserialize, Serialize};

use super::private_attempt::ProcessIdentityV4;
use super::private_release_attempt::ReadbackRetiredCandidateAttemptV1;
use super::private_release_raw::{
    CandidateCoordinatorCleanupContextV1, CandidateRawContextV1, persist_fixed,
    protected_directory, read_fixed,
};
use super::private_release_terminal_execution::TerminalJoinNativeObservationV1;
use super::private_release_terminal_join::{LIVE_BYTES, SELECTOR, TerminalJoinLiveFrameV1};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TerminalJoinReportV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    response_sha256: DiagnosticSha256,
    midflight_record_digest: DiagnosticSha256,
    terminal_join_gate_sha256: DiagnosticSha256,
    target_namespace_pid: u32,
    target_pid_chain: Vec<u32>,
    candidate_exit_code: i32,
    installed_inspection_json: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TerminalJoinObserverV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    live_frame: Vec<u8>,
    settlement: super::private_lifecycle::ReleaseCandidateSettlementFactsV1,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TerminalJoinCleanupV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    terminal_join_gate_sha256: DiagnosticSha256,
    kernel_trace_sha256: DiagnosticSha256,
    coordinator: ProcessIdentityV4,
    worker: ProcessIdentityV4,
    worker_pidfd_exited: bool,
    service_generation_sha256: DiagnosticSha256,
    settlement_source: String,
}

fn expected_response(challenge: &[u8; 32], live_frame: &[u8; LIVE_BYTES]) -> Vec<u8> {
    let final_response =
        super::private_release_case::candidate_fixture_response(SELECTOR, challenge);
    let mut response = Vec::with_capacity(live_frame.len() + final_response.len());
    response.extend_from_slice(live_frame);
    response.extend_from_slice(&final_response);
    response
}

pub(crate) fn persist_worker_raw(
    context: CandidateRawContextV1<'_>,
    observed: &TerminalJoinNativeObservationV1,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    let candidate = &observed.candidate;
    let live = TerminalJoinLiveFrameV1::decode(&observed.live_frame, context.challenge)?;
    if unsafe { libc::geteuid() } != 0
        || context.selector != SELECTOR
        || !context.expected_response.is_empty()
        || context.agent_path_snapshot.is_some()
        || candidate.candidate_exit_code != 0
        || candidate.challenge_sha256 != hash_bytes(context.challenge)
        || candidate.response_bytes != expected_response(context.challenge, &observed.live_frame)
        || candidate.response_sha256 != hash_bytes(&candidate.response_bytes)
        || observed.target_namespace_pid != live.target_pid
        || observed.target_pid_chain.is_empty()
        || observed.midflight_record_digest == DiagnosticSha256::from_bytes([0; 32])
    {
        return Err("MCSEALED-PRIVATE-RELEASE: terminal-join raw authority differs".into());
    }
    protected_directory(context.directory, 0)?;
    let request = read_fixed(context.directory, "request.json", 0)?;
    if read_fixed(context.directory, "attempt.json", 0)? != candidate.terminal_bytes {
        return Err("MCSEALED-PRIVATE-RELEASE: terminal-join journal changed".into());
    }
    let inspection = std::str::from_utf8(context.installed_inspection_bytes)
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE: terminal-join inspection is not UTF-8")?;
    let report = serde_json::to_vec(&TerminalJoinReportV1 {
        schema_version: 1,
        selector: SELECTOR.into(),
        result_key: context.result_key.clone(),
        attempt_id: candidate.attempt_id.clone(),
        checkpoint_sha256: candidate.checkpoint_digest.clone(),
        terminal_record_digest: candidate.terminal_record_digest.clone(),
        challenge_sha256: candidate.challenge_sha256.clone(),
        response_sha256: candidate.response_sha256.clone(),
        midflight_record_digest: observed.midflight_record_digest.clone(),
        terminal_join_gate_sha256: observed.terminal_join_gate_sha256.clone(),
        target_namespace_pid: observed.target_namespace_pid,
        target_pid_chain: observed.target_pid_chain.clone(),
        candidate_exit_code: 0,
        installed_inspection_json: inspection.into(),
    })
    .map_err(|error| error.to_string())?;
    let observer = serde_json::to_vec(&TerminalJoinObserverV1 {
        schema_version: 1,
        attempt_id: candidate.attempt_id.clone(),
        checkpoint_sha256: candidate.checkpoint_digest.clone(),
        terminal_record_digest: candidate.terminal_record_digest.clone(),
        live_frame: observed.live_frame.to_vec(),
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
            return Err("MCSEALED-PRIVATE-RELEASE: terminal-join raw bound differs".into());
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
    if readback_worker_raw(context, &journal)? != inventory {
        return Err("MCSEALED-PRIVATE-RELEASE: terminal-join raw readback differs".into());
    }
    Ok(inventory)
}

pub(crate) fn readback_worker_raw(
    context: CandidateRawContextV1<'_>,
    journal: &ReadbackRetiredCandidateAttemptV1,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    if context.selector != SELECTOR
        || !context.expected_response.is_empty()
        || context.agent_path_snapshot.is_some()
    {
        return Err("MCSEALED-PRIVATE-RELEASE: terminal-join raw selector differs".into());
    }
    protected_directory(context.directory, 0)?;
    let request = read_fixed(context.directory, "request.bin", 0)?;
    if request != read_fixed(context.directory, "request.json", 0)?
        || journal.terminal_bytes != read_fixed(context.directory, "attempt.json", 0)?
    {
        return Err("MCSEALED-PRIVATE-RELEASE: terminal-join custody differs".into());
    }
    let report_bytes = read_fixed(context.directory, "report.bin", 0)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&report_bytes)?;
    let report: TerminalJoinReportV1 =
        serde_json::from_slice(&report_bytes).map_err(|error| error.to_string())?;
    let inspection = std::str::from_utf8(context.installed_inspection_bytes)
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE: terminal-join inspection is not UTF-8")?;
    if report.schema_version != 1
        || report.selector != SELECTOR
        || &report.result_key != context.result_key
        || report.attempt_id != journal.attempt_id
        || report.checkpoint_sha256 != journal.checkpoint_digest
        || report.terminal_record_digest != journal.terminal_record_digest
        || report.challenge_sha256 != hash_bytes(context.challenge)
        || report.candidate_exit_code != 0
        || report.installed_inspection_json != inspection
        || serde_json::to_vec(&report).map_err(|error| error.to_string())? != report_bytes
    {
        return Err("MCSEALED-PRIVATE-RELEASE: terminal-join report differs".into());
    }
    let observer = read_fixed(context.directory, "observer.bin", 0)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&observer)?;
    let trace: TerminalJoinObserverV1 =
        serde_json::from_slice(&observer).map_err(|error| error.to_string())?;
    let native = journal.native_identities()?;
    let live = TerminalJoinLiveFrameV1::decode(&trace.live_frame, context.challenge)?;
    let guardian = super::private_guardian::GuardianTerminalV4::decode(
        trace.settlement.guardian_terminal,
        super::private_release_attempt::candidate_attempt_bytes(context.result_key),
    )?;
    if trace.schema_version != 1
        || trace.attempt_id != journal.attempt_id
        || trace.checkpoint_sha256 != journal.checkpoint_digest
        || trace.terminal_record_digest != journal.terminal_record_digest
        || live.target_pid != report.target_namespace_pid
        || !super::private_release_child_owner::chain_matches(
            &report.target_pid_chain,
            native.target.pid,
            live.target_pid,
        )
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
        || serde_json::to_vec(&trace).map_err(|error| error.to_string())? != observer
    {
        return Err("MCSEALED-PRIVATE-RELEASE: terminal-join observer differs".into());
    }
    let live_frame: [u8; LIVE_BYTES] = trace
        .live_frame
        .as_slice()
        .try_into()
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE: terminal-join frame width differs")?;
    let response = expected_response(context.challenge, &live_frame);
    let stdio = read_fixed(context.directory, "stdio.bin", 0)?;
    if report.response_sha256 != hash_bytes(&response)
        || stdio.len() != context.challenge.len() + response.len()
        || stdio[..context.challenge.len()] != *context.challenge
        || stdio[context.challenge.len()..] != response
    {
        return Err("MCSEALED-PRIVATE-RELEASE: terminal-join target I/O differs".into());
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

pub(crate) fn persist_coordinator_cleanup(
    context: CandidateCoordinatorCleanupContextV1<'_>,
    gate_sha256: &DiagnosticSha256,
    midflight_record_digest: &DiagnosticSha256,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    if unsafe { libc::geteuid() } != 0
        || context.raw.selector != SELECTOR
        || context.worker == context.coordinator
        || context.worker.pid == 0
        || context.worker.start_time == 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE: terminal-join coordinator differs".into());
    }
    let mut pollfd = libc::pollfd {
        fd: std::os::fd::AsRawFd::as_raw_fd(&context.worker_pidfd),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll examines only the authenticated worker pidfd.
    if unsafe { libc::poll(&raw mut pollfd, 1, 0) } != 1
        || pollfd.revents & libc::POLLIN == 0
        || pollfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE: terminal-join worker exit absent".into());
    }
    if readback_worker_raw(context.raw, context.journal)?.len()
        != PrivateReleaseAttachmentRoleV1::ALL.len() - 1
    {
        return Err("MCSEALED-PRIVATE-RELEASE: terminal-join worker inventory differs".into());
    }
    let observer = read_fixed(context.raw.directory, "observer.bin", 0)?;
    let cleanup = serde_json::to_vec(&TerminalJoinCleanupV1 {
        schema_version: 1,
        attempt_id: context.journal.attempt_id.clone(),
        checkpoint_sha256: context.journal.checkpoint_digest.clone(),
        terminal_record_digest: context.journal.terminal_record_digest.clone(),
        terminal_join_gate_sha256: gate_sha256.clone(),
        kernel_trace_sha256: hash_bytes(&observer),
        coordinator: context.coordinator.clone(),
        worker: context.worker.clone(),
        worker_pidfd_exited: true,
        service_generation_sha256: context.service_generation_sha256.clone(),
        settlement_source: "control-coordinator-pidfd".into(),
    })
    .map_err(|error| error.to_string())?;
    persist_fixed(context.raw.directory, "cleanup.bin", &cleanup, 0)?;
    readback_raw(
        context.raw,
        context.journal,
        context.coordinator,
        context.service_generation_sha256,
        gate_sha256,
        midflight_record_digest,
    )
}

pub(crate) fn readback_raw(
    context: CandidateRawContextV1<'_>,
    journal: &ReadbackRetiredCandidateAttemptV1,
    coordinator: &ProcessIdentityV4,
    service_generation_sha256: &DiagnosticSha256,
    gate_sha256: &DiagnosticSha256,
    midflight_record_digest: &DiagnosticSha256,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    let mut inventory = readback_worker_raw(context, journal)?;
    let report_bytes = read_fixed(context.directory, "report.bin", 0)?;
    let report: TerminalJoinReportV1 =
        serde_json::from_slice(&report_bytes).map_err(|error| error.to_string())?;
    let observer = read_fixed(context.directory, "observer.bin", 0)?;
    let bytes = read_fixed(context.directory, "cleanup.bin", 0)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)?;
    let cleanup: TerminalJoinCleanupV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if cleanup.schema_version != 1
        || cleanup.attempt_id != journal.attempt_id
        || cleanup.checkpoint_sha256 != journal.checkpoint_digest
        || cleanup.terminal_record_digest != journal.terminal_record_digest
        || &cleanup.terminal_join_gate_sha256 != gate_sha256
        || &report.terminal_join_gate_sha256 != gate_sha256
        || &report.midflight_record_digest != midflight_record_digest
        || cleanup.kernel_trace_sha256 != hash_bytes(&observer)
        || &cleanup.coordinator != coordinator
        || cleanup.worker == *coordinator
        || cleanup.worker.pid == 0
        || cleanup.worker.start_time == 0
        || !cleanup.worker_pidfd_exited
        || &cleanup.service_generation_sha256 != service_generation_sha256
        || cleanup.settlement_source != "control-coordinator-pidfd"
        || serde_json::to_vec(&cleanup).map_err(|error| error.to_string())? != bytes
    {
        return Err("MCSEALED-PRIVATE-RELEASE: terminal-join cleanup differs".into());
    }
    super::private_release_run::require_recorded_process_exited(&cleanup.worker)?;
    inventory.push(PrivateReleaseAttachmentV1 {
        role: PrivateReleaseAttachmentRoleV1::Cleanup,
        size: bytes.len() as u64,
        sha256: hash_bytes(&bytes),
    });
    Ok(inventory)
}
