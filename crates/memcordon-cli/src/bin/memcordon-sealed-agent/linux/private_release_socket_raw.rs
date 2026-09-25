//! Worker-owned socket laundering diagnostics. The coordinator and detached
//! reader must still join worker exit and protected retirement before a result.

use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::{
    MAX_PRIVATE_RELEASE_ATTACHMENT_BYTES_V1, PrivateReleaseAttachmentRoleV1,
    PrivateReleaseAttachmentV1,
};
use memcordon_core::workload_codec::hash_bytes;
use serde::{Deserialize, Serialize};

use super::private_release_attempt::ReadbackRetiredCandidateAttemptV1;
use super::private_release_raw::{
    CandidateCoordinatorCleanupContextV1, CandidateRawContextV1, persist_fixed,
    protected_directory, read_fixed,
};
use super::private_release_socket_execution::SocketLaunderNativeObservationV1;
use super::private_release_socket_launder::{PrecreatedSocketGatedWitnessV1, SELECTOR};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SocketReportV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    response_sha256: DiagnosticSha256,
    socket_gate_sha256: DiagnosticSha256,
    candidate_exit_code: i32,
    installed_inspection_json: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SocketObserverV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    gated_witness: PrecreatedSocketGatedWitnessV1,
    settlement: super::private_lifecycle::ReleaseCandidateSettlementFactsV1,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SocketCleanupV1 {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    socket_gate_sha256: DiagnosticSha256,
    kernel_trace_sha256: DiagnosticSha256,
    coordinator: super::private_attempt::ProcessIdentityV4,
    worker: super::private_attempt::ProcessIdentityV4,
    worker_pidfd_exited: bool,
    service_generation_sha256: DiagnosticSha256,
    settlement_source: String,
}

#[allow(dead_code)] // This selector remains closed until coordinator and detached joins land.
pub(crate) fn persist_worker_raw(
    context: CandidateRawContextV1<'_>,
    observed: &SocketLaunderNativeObservationV1,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    let candidate = &observed.candidate;
    if unsafe { libc::geteuid() } != 0
        || context.selector != SELECTOR
        || context.agent_path_snapshot.is_some()
        || candidate.candidate_exit_code != 0
        || candidate.challenge_sha256 != hash_bytes(context.challenge)
        || candidate.response_bytes != context.expected_response
        || candidate.response_sha256 != hash_bytes(context.expected_response)
        || observed.gated_witness.schema_version != 1
        || observed.gated_witness.sendmsg_errno != libc::EPERM
        || observed.gated_witness.network_namespace_inode != candidate.network_namespace_inode
    {
        return Err("MCSEALED-PRIVATE-RELEASE: socket raw authority differs".into());
    }
    protected_directory(context.directory, 0)?;
    let request = read_fixed(context.directory, "request.json", 0)?;
    if read_fixed(context.directory, "attempt.json", 0)? != candidate.terminal_bytes {
        return Err("MCSEALED-PRIVATE-RELEASE: socket journal changed".into());
    }
    let inspection = std::str::from_utf8(context.installed_inspection_bytes)
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE: socket inspection is not UTF-8")?;
    let report = serde_json::to_vec(&SocketReportV1 {
        schema_version: 1,
        selector: SELECTOR.into(),
        result_key: context.result_key.clone(),
        attempt_id: candidate.attempt_id.clone(),
        checkpoint_sha256: candidate.checkpoint_digest.clone(),
        terminal_record_digest: candidate.terminal_record_digest.clone(),
        challenge_sha256: candidate.challenge_sha256.clone(),
        response_sha256: candidate.response_sha256.clone(),
        socket_gate_sha256: observed.socket_gate_sha256.clone(),
        candidate_exit_code: 0,
        installed_inspection_json: inspection.into(),
    })
    .map_err(|error| error.to_string())?;
    let observer = serde_json::to_vec(&SocketObserverV1 {
        schema_version: 1,
        attempt_id: candidate.attempt_id.clone(),
        checkpoint_sha256: candidate.checkpoint_digest.clone(),
        terminal_record_digest: candidate.terminal_record_digest.clone(),
        gated_witness: observed.gated_witness.clone(),
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
            return Err("MCSEALED-PRIVATE-RELEASE: socket raw bound differs".into());
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
    if readback_worker_raw(context, &journal)?.0 != inventory {
        return Err("MCSEALED-PRIVATE-RELEASE: socket raw readback differs".into());
    }
    Ok(inventory)
}

pub(crate) fn readback_worker_raw(
    context: CandidateRawContextV1<'_>,
    journal: &ReadbackRetiredCandidateAttemptV1,
) -> Result<
    (
        Vec<PrivateReleaseAttachmentV1>,
        PrecreatedSocketGatedWitnessV1,
    ),
    String,
> {
    if context.selector != SELECTOR || context.agent_path_snapshot.is_some() {
        return Err("MCSEALED-PRIVATE-RELEASE: socket raw selector differs".into());
    }
    protected_directory(context.directory, 0)?;
    let request = read_fixed(context.directory, "request.bin", 0)?;
    if request != read_fixed(context.directory, "request.json", 0)?
        || journal.terminal_bytes != read_fixed(context.directory, "attempt.json", 0)?
    {
        return Err("MCSEALED-PRIVATE-RELEASE: socket raw custody differs".into());
    }
    let report_bytes = read_fixed(context.directory, "report.bin", 0)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&report_bytes)?;
    let report: SocketReportV1 =
        serde_json::from_slice(&report_bytes).map_err(|error| error.to_string())?;
    let inspection = std::str::from_utf8(context.installed_inspection_bytes)
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE: socket inspection is not UTF-8")?;
    if report.schema_version != 1
        || report.selector != SELECTOR
        || &report.result_key != context.result_key
        || report.attempt_id != journal.attempt_id
        || report.checkpoint_sha256 != journal.checkpoint_digest
        || report.terminal_record_digest != journal.terminal_record_digest
        || report.challenge_sha256 != hash_bytes(context.challenge)
        || report.response_sha256 != hash_bytes(context.expected_response)
        || report.candidate_exit_code != 0
        || report.installed_inspection_json != inspection
        || serde_json::to_vec(&report).map_err(|error| error.to_string())? != report_bytes
    {
        return Err("MCSEALED-PRIVATE-RELEASE: socket report differs".into());
    }
    let observer = read_fixed(context.directory, "observer.bin", 0)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&observer)?;
    let trace: SocketObserverV1 =
        serde_json::from_slice(&observer).map_err(|error| error.to_string())?;
    let native = journal.native_identities()?;
    let witness = &trace.gated_witness;
    let guardian = super::private_guardian::GuardianTerminalV4::decode(
        trace.settlement.guardian_terminal,
        super::private_release_attempt::candidate_attempt_bytes(context.result_key),
    )?;
    if trace.schema_version != 1
        || trace.attempt_id != journal.attempt_id
        || trace.checkpoint_sha256 != journal.checkpoint_digest
        || trace.terminal_record_digest != journal.terminal_record_digest
        || witness.schema_version != 1
        || witness.target != native.target
        || witness.network_namespace_inode == 0
        || witness.network_namespace_inode != native.network_namespace_inode
        || witness.first_socket_inode == 0
        || witness.second_socket_inode == 0
        || (witness.first_socket_device, witness.first_socket_inode)
            == (witness.second_socket_device, witness.second_socket_inode)
        || witness.filter_sha256 != journal.filter_digest()?
        || witness.sendmsg_errno != libc::EPERM
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
        return Err("MCSEALED-PRIVATE-RELEASE: socket observer differs".into());
    }
    let stdio = read_fixed(context.directory, "stdio.bin", 0)?;
    if stdio.len() != context.challenge.len() + context.expected_response.len()
        || stdio[..context.challenge.len()] != *context.challenge
        || stdio[context.challenge.len()..] != *context.expected_response
    {
        return Err("MCSEALED-PRIVATE-RELEASE: socket target I/O differs".into());
    }
    if super::private_release_socket_gate::readback_gate_and_ack(
        context.directory,
        context.result_key,
        context.challenge,
        &journal.attempt_id,
        witness,
    )? != report.socket_gate_sha256
    {
        return Err("MCSEALED-PRIVATE-RELEASE: socket gate digest differs".into());
    }
    let raw = [request, report_bytes, stdio, observer];
    let inventory = PrivateReleaseAttachmentRoleV1::ALL
        .into_iter()
        .take(raw.len())
        .zip(raw)
        .map(|(role, bytes)| PrivateReleaseAttachmentV1 {
            role,
            size: bytes.len() as u64,
            sha256: hash_bytes(&bytes),
        })
        .collect();
    Ok((inventory, witness.clone()))
}

/// The control coordinator alone publishes cleanup after its retained worker
/// pidfd becomes readable. Neither the target nor worker can create this fact.
pub(crate) fn persist_coordinator_cleanup(
    context: CandidateCoordinatorCleanupContextV1<'_>,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    if unsafe { libc::geteuid() } != 0
        || context.raw.selector != SELECTOR
        || context.worker == context.coordinator
        || context.worker.pid == 0
        || context.worker.start_time == 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE: socket cleanup authority differs".into());
    }
    let mut pollfd = libc::pollfd {
        fd: std::os::fd::AsRawFd::as_raw_fd(&context.worker_pidfd),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll examines the exact worker pidfd retained by the coordinator.
    if unsafe { libc::poll(&raw mut pollfd, 1, 0) } != 1
        || pollfd.revents & libc::POLLIN == 0
        || pollfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE: socket worker exit absent".into());
    }
    let (inventory, witness) = readback_worker_raw(context.raw, context.journal)?;
    if inventory.len() != PrivateReleaseAttachmentRoleV1::ALL.len() - 1 {
        return Err("MCSEALED-PRIVATE-RELEASE: socket worker inventory differs".into());
    }
    let gate_sha256 = super::private_release_socket_gate::readback_gate_and_ack(
        context.raw.directory,
        context.raw.result_key,
        context.raw.challenge,
        &context.journal.attempt_id,
        &witness,
    )?;
    let observer = read_fixed(context.raw.directory, "observer.bin", 0)?;
    let cleanup = serde_json::to_vec(&SocketCleanupV1 {
        schema_version: 1,
        attempt_id: context.journal.attempt_id.clone(),
        checkpoint_sha256: context.journal.checkpoint_digest.clone(),
        terminal_record_digest: context.journal.terminal_record_digest.clone(),
        socket_gate_sha256: gate_sha256,
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
    )
}

pub(crate) fn readback_raw(
    context: CandidateRawContextV1<'_>,
    journal: &ReadbackRetiredCandidateAttemptV1,
    coordinator: &super::private_attempt::ProcessIdentityV4,
    service_generation_sha256: &DiagnosticSha256,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    let (mut inventory, witness) = readback_worker_raw(context, journal)?;
    let gate_sha256 = super::private_release_socket_gate::readback_gate_and_ack(
        context.directory,
        context.result_key,
        context.challenge,
        &journal.attempt_id,
        &witness,
    )?;
    let observer = read_fixed(context.directory, "observer.bin", 0)?;
    let bytes = read_fixed(context.directory, "cleanup.bin", 0)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)?;
    let cleanup: SocketCleanupV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if cleanup.schema_version != 1
        || cleanup.attempt_id != journal.attempt_id
        || cleanup.checkpoint_sha256 != journal.checkpoint_digest
        || cleanup.terminal_record_digest != journal.terminal_record_digest
        || cleanup.socket_gate_sha256 != gate_sha256
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
        return Err("MCSEALED-PRIVATE-RELEASE: socket cleanup differs".into());
    }
    super::private_release_run::require_recorded_process_exited(&cleanup.worker)?;
    inventory.push(PrivateReleaseAttachmentV1 {
        role: PrivateReleaseAttachmentRoleV1::Cleanup,
        size: bytes.len() as u64,
        sha256: hash_bytes(&bytes),
    });
    Ok(inventory)
}
