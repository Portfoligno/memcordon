//! Two-sided native diagnostic attachments. Only the protected worker writes
//! the first four roles; the control coordinator later owns cleanup.bin.

use std::fs::File;
use std::os::fd::{AsRawFd, BorrowedFd};

use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::{
    PrivateReleaseAttachmentRoleV1, PrivateReleaseAttachmentV1,
};
use memcordon_core::workload_codec::hash_bytes;
use serde::{Deserialize, Serialize};

use super::private_attempt::ProcessIdentityV4;
use super::private_lifecycle::ReleaseCandidateSettlementFactsV1;
use super::private_release_attempt::ReadbackRetiredCandidateAttemptV1;
use super::private_release_dual_attempt::{self, DualAttemptRoleV1, SELECTOR};
use super::private_release_dual_execution::DualCandidateNativeObservationV1;
use super::private_release_dual_gate::DualLiveGateReadbackV1;
use super::private_release_raw::{persist_fixed, protected_directory, read_fixed};

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DualRawBranchV1 {
    pub(crate) subattempt_key: DiagnosticSha256,
    pub(crate) attempt_id: String,
    pub(crate) checkpoint_sha256: DiagnosticSha256,
    pub(crate) terminal_record_digest: DiagnosticSha256,
    pub(crate) terminal_sha256: DiagnosticSha256,
    pub(crate) settlement_sha256: DiagnosticSha256,
    pub(crate) network_namespace_inode: u64,
    pub(crate) listener_socket_inode: u64,
    pub(crate) candidate_exit_code: i32,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DualRawReportV1 {
    pub(crate) schema_version: u8,
    pub(crate) selector: String,
    pub(crate) result_key: DiagnosticSha256,
    pub(crate) challenge_sha256: DiagnosticSha256,
    pub(crate) gate_sha256: DiagnosticSha256,
    pub(crate) port: u16,
    pub(crate) first: DualRawBranchV1,
    pub(crate) second: DualRawBranchV1,
    pub(crate) installed_inspection_json: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DualRawObserverV1 {
    pub(crate) schema_version: u8,
    pub(crate) gate_sha256: DiagnosticSha256,
    pub(crate) first: ReleaseCandidateSettlementFactsV1,
    pub(crate) second: ReleaseCandidateSettlementFactsV1,
}

#[derive(Clone, Copy)]
pub(crate) struct DualRawContextV1<'a> {
    pub(crate) directory: &'a File,
    pub(crate) result_key: &'a DiagnosticSha256,
    pub(crate) challenge: &'a [u8; 32],
    pub(crate) installed_inspection_bytes: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DualCoordinatorCleanupV1 {
    pub(crate) schema_version: u8,
    pub(crate) selector: String,
    pub(crate) result_key: DiagnosticSha256,
    pub(crate) gate_sha256: DiagnosticSha256,
    pub(crate) first_attempt_id: String,
    pub(crate) second_attempt_id: String,
    pub(crate) first_terminal_sha256: DiagnosticSha256,
    pub(crate) second_terminal_sha256: DiagnosticSha256,
    pub(crate) observer_sha256: DiagnosticSha256,
    pub(crate) coordinator: ProcessIdentityV4,
    pub(crate) worker: ProcessIdentityV4,
    pub(crate) worker_pidfd_exited: bool,
    pub(crate) service_generation_sha256: DiagnosticSha256,
    pub(crate) settlement_source: String,
}

pub(crate) struct DualCoordinatorCleanupContextV1<'a> {
    pub(crate) raw: DualRawContextV1<'a>,
    pub(crate) gate: &'a DualLiveGateReadbackV1,
    pub(crate) first_journal: &'a ReadbackRetiredCandidateAttemptV1,
    pub(crate) second_journal: &'a ReadbackRetiredCandidateAttemptV1,
    pub(crate) coordinator: &'a ProcessIdentityV4,
    pub(crate) worker: &'a ProcessIdentityV4,
    pub(crate) worker_pidfd: BorrowedFd<'a>,
    pub(crate) service_generation_sha256: &'a DiagnosticSha256,
}

pub(crate) fn persist_dual_worker_raw(
    context: DualRawContextV1<'_>,
    observed: &DualCandidateNativeObservationV1,
    gate: &DualLiveGateReadbackV1,
    first_journal: &ReadbackRetiredCandidateAttemptV1,
    second_journal: &ReadbackRetiredCandidateAttemptV1,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("MCSEALED-PRIVATE-RELEASE: dual raw requires root".into());
    }
    protected_directory(context.directory, 0)?;
    let report = expected_report(&context, observed, gate, first_journal, second_journal)?;
    let observer = DualRawObserverV1 {
        schema_version: 1,
        gate_sha256: gate.gate_sha256.clone(),
        first: observed.first.settlement.clone(),
        second: observed.second.settlement.clone(),
    };
    let request = read_fixed(context.directory, "request.json", 0)?;
    let report_bytes = serde_json::to_vec(&report).map_err(|error| error.to_string())?;
    let mut stdio = Vec::with_capacity(
        context.challenge.len() + observed.first_frame.len() + observed.second_frame.len(),
    );
    stdio.extend_from_slice(context.challenge);
    stdio.extend_from_slice(&observed.first_frame);
    stdio.extend_from_slice(&observed.second_frame);
    let observer_bytes = serde_json::to_vec(&observer).map_err(|error| error.to_string())?;
    let payloads = [request, report_bytes, stdio, observer_bytes];
    let mut inventory = Vec::with_capacity(payloads.len());
    for (role, bytes) in PrivateReleaseAttachmentRoleV1::ALL
        .into_iter()
        .take(payloads.len())
        .zip(payloads)
    {
        persist_fixed(context.directory, role.leaf(), &bytes, 0)?;
        inventory.push(PrivateReleaseAttachmentV1 {
            role,
            size: bytes.len() as u64,
            sha256: hash_bytes(&bytes),
        });
    }
    if readback_dual_worker_raw(context, observed, gate, first_journal, second_journal)?
        != inventory
    {
        return Err("MCSEALED-PRIVATE-RELEASE: dual raw readback differs".into());
    }
    Ok(inventory)
}

pub(crate) fn readback_dual_worker_raw(
    context: DualRawContextV1<'_>,
    observed: &DualCandidateNativeObservationV1,
    gate: &DualLiveGateReadbackV1,
    first_journal: &ReadbackRetiredCandidateAttemptV1,
    second_journal: &ReadbackRetiredCandidateAttemptV1,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    let expected = expected_report(&context, observed, gate, first_journal, second_journal)?;
    let observer = DualRawObserverV1 {
        schema_version: 1,
        gate_sha256: gate.gate_sha256.clone(),
        first: observed.first.settlement.clone(),
        second: observed.second.settlement.clone(),
    };
    let report = serde_json::to_vec(&expected).map_err(|error| error.to_string())?;
    let observer = serde_json::to_vec(&observer).map_err(|error| error.to_string())?;
    let mut stdio = Vec::with_capacity(
        context.challenge.len() + observed.first_frame.len() + observed.second_frame.len(),
    );
    stdio.extend_from_slice(context.challenge);
    stdio.extend_from_slice(&observed.first_frame);
    stdio.extend_from_slice(&observed.second_frame);
    let request = read_fixed(context.directory, "request.json", 0)?;
    let expected_bytes = [request, report, stdio, observer];
    let mut inventory = Vec::with_capacity(expected_bytes.len());
    for (role, expected_bytes) in PrivateReleaseAttachmentRoleV1::ALL
        .into_iter()
        .take(expected_bytes.len())
        .zip(expected_bytes)
    {
        let readback = read_fixed(context.directory, role.leaf(), 0)?;
        if readback != expected_bytes {
            return Err("MCSEALED-PRIVATE-RELEASE: dual raw bytes differ".into());
        }
        inventory.push(PrivateReleaseAttachmentV1 {
            role,
            size: readback.len() as u64,
            sha256: hash_bytes(&readback),
        });
    }
    Ok(inventory)
}

/// Reconstruct the four worker roles from protected bytes, without accepting
/// a worker-supplied in-memory observation after the worker has exited.
pub(crate) fn readback_dual_worker_raw_from_disk(
    context: DualRawContextV1<'_>,
    gate: &DualLiveGateReadbackV1,
    first_journal: &ReadbackRetiredCandidateAttemptV1,
    second_journal: &ReadbackRetiredCandidateAttemptV1,
) -> Result<(DualRawReportV1, Vec<PrivateReleaseAttachmentV1>), String> {
    protected_directory(context.directory, 0)?;
    let request = read_fixed(context.directory, "request.json", 0)?;
    let request_attachment = read_fixed(context.directory, "request.bin", 0)?;
    let report_bytes = read_fixed(context.directory, "report.bin", 0)?;
    let stdio = read_fixed(context.directory, "stdio.bin", 0)?;
    let observer_bytes = read_fixed(context.directory, "observer.bin", 0)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&report_bytes)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&observer_bytes)?;
    let report: DualRawReportV1 =
        serde_json::from_slice(&report_bytes).map_err(|error| error.to_string())?;
    let observer: DualRawObserverV1 =
        serde_json::from_slice(&observer_bytes).map_err(|error| error.to_string())?;
    if request_attachment != request
        || serde_json::to_vec(&report).map_err(|error| error.to_string())? != report_bytes
        || serde_json::to_vec(&observer).map_err(|error| error.to_string())? != observer_bytes
        || report.schema_version != 1
        || report.selector != SELECTOR
        || report.result_key != *context.result_key
        || report.challenge_sha256 != hash_bytes(context.challenge)
        || report.gate_sha256 != gate.gate_sha256
        || report.port != gate.gate.port
        || gate.gate.result_key != *context.result_key
        || gate.gate.selector != SELECTOR
        || gate.gate.challenge_sha256 != report.challenge_sha256
        || observer.schema_version != 1
        || observer.gate_sha256 != gate.gate_sha256
        || report.installed_inspection_json.as_bytes() != context.installed_inspection_bytes
    {
        return Err("MCSEALED-PRIVATE-RELEASE: dual disk raw header differs".into());
    }
    validate_disk_branch(
        &report.first,
        &observer.first,
        &gate.gate.first,
        first_journal,
        context.result_key,
        DualAttemptRoleV1::First,
    )?;
    validate_disk_branch(
        &report.second,
        &observer.second,
        &gate.gate.second,
        second_journal,
        context.result_key,
        DualAttemptRoleV1::Second,
    )?;
    if report.first.attempt_id == report.second.attempt_id
        || report.first.network_namespace_inode == report.second.network_namespace_inode
        || report.first.listener_socket_inode == report.second.listener_socket_inode
        || gate.first_midflight.execution_record_digest != gate.gate.first.execution_record_digest
        || gate.second_midflight.execution_record_digest != gate.gate.second.execution_record_digest
    {
        return Err("MCSEALED-PRIVATE-RELEASE: dual disk branch separation differs".into());
    }
    let mut expected_stdio = Vec::with_capacity(context.challenge.len() + 84);
    expected_stdio.extend_from_slice(context.challenge);
    expected_stdio.extend_from_slice(&private_release_dual_attempt::ready_frame(
        context.challenge,
        report.port,
        report.first.network_namespace_inode,
    ));
    expected_stdio.extend_from_slice(&private_release_dual_attempt::ready_frame(
        context.challenge,
        report.port,
        report.second.network_namespace_inode,
    ));
    if stdio != expected_stdio {
        return Err("MCSEALED-PRIVATE-RELEASE: dual disk stdio differs".into());
    }
    let inventory = [request_attachment, report_bytes, stdio, observer_bytes]
        .into_iter()
        .zip(PrivateReleaseAttachmentRoleV1::ALL)
        .map(|(bytes, role)| PrivateReleaseAttachmentV1 {
            role,
            size: bytes.len() as u64,
            sha256: hash_bytes(&bytes),
        })
        .collect();
    Ok((report, inventory))
}

fn validate_disk_branch(
    branch: &DualRawBranchV1,
    settlement: &ReleaseCandidateSettlementFactsV1,
    gate: &super::private_release_dual_gate::DualLiveBranchV1,
    journal: &ReadbackRetiredCandidateAttemptV1,
    result_key: &DiagnosticSha256,
    role: DualAttemptRoleV1,
) -> Result<(), String> {
    let key = private_release_dual_attempt::subattempt_key(result_key, role);
    let native = journal.native_identities()?;
    let settlement_bytes = serde_json::to_vec(settlement).map_err(|error| error.to_string())?;
    let guardian = super::private_guardian::GuardianTerminalV4::decode(
        settlement.guardian_terminal,
        super::private_release_attempt::candidate_attempt_bytes(&key),
    )?;
    if branch.subattempt_key != key
        || gate.subattempt_key != key
        || branch.attempt_id != super::private_release_attempt::candidate_attempt_id(&key)
        || branch.attempt_id != journal.attempt_id
        || gate.attempt_id != branch.attempt_id
        || branch.checkpoint_sha256 != journal.checkpoint_digest
        || gate.checkpoint_sha256 != branch.checkpoint_sha256
        || branch.terminal_record_digest != journal.terminal_record_digest
        || branch.terminal_sha256 != hash_bytes(&journal.terminal_bytes)
        || branch.settlement_sha256 != hash_bytes(&settlement_bytes)
        || branch.network_namespace_inode == 0
        || branch.network_namespace_inode != gate.network_namespace_inode
        || branch.network_namespace_inode != native.network_namespace_inode
        || branch.listener_socket_inode == 0
        || branch.listener_socket_inode != gate.listener_socket_inode
        || gate.target != native.target
        || gate.filter_sha256 != journal.filter_digest()?
        || branch.candidate_exit_code != 0
        || native.candidate_exit_code != Some(0)
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
        return Err("MCSEALED-PRIVATE-RELEASE: dual disk branch differs".into());
    }
    Ok(())
}

/// The coordinator may write only cleanup.bin, and only after its retained
/// authenticated worker pidfd has become readable.
pub(crate) fn persist_dual_coordinator_cleanup(
    context: DualCoordinatorCleanupContextV1<'_>,
) -> Result<Vec<PrivateReleaseAttachmentV1>, String> {
    if unsafe { libc::geteuid() } != 0
        || context.worker == context.coordinator
        || context.worker.pid == 0
        || context.worker.start_time == 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE: dual cleanup authority differs".into());
    }
    let mut pollfd = libc::pollfd {
        fd: context.worker_pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll observes only the coordinator-retained authenticated pidfd.
    if unsafe { libc::poll(&raw mut pollfd, 1, 0) } != 1
        || pollfd.revents & libc::POLLIN == 0
        || pollfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE: dual worker exit not observed".into());
    }
    let (report, mut inventory) = readback_dual_worker_raw_from_disk(
        context.raw,
        context.gate,
        context.first_journal,
        context.second_journal,
    )?;
    if inventory.len() != PrivateReleaseAttachmentRoleV1::ALL.len() - 1 {
        return Err("MCSEALED-PRIVATE-RELEASE: dual worker inventory differs".into());
    }
    let observer = read_fixed(context.raw.directory, "observer.bin", 0)?;
    let cleanup = DualCoordinatorCleanupV1 {
        schema_version: 1,
        selector: SELECTOR.into(),
        result_key: context.raw.result_key.clone(),
        gate_sha256: context.gate.gate_sha256.clone(),
        first_attempt_id: report.first.attempt_id,
        second_attempt_id: report.second.attempt_id,
        first_terminal_sha256: report.first.terminal_sha256,
        second_terminal_sha256: report.second.terminal_sha256,
        observer_sha256: hash_bytes(&observer),
        coordinator: context.coordinator.clone(),
        worker: context.worker.clone(),
        worker_pidfd_exited: true,
        service_generation_sha256: context.service_generation_sha256.clone(),
        settlement_source: "control-coordinator-pidfd".into(),
    };
    let bytes = serde_json::to_vec(&cleanup).map_err(|error| error.to_string())?;
    persist_fixed(context.raw.directory, "cleanup.bin", &bytes, 0)?;
    if read_fixed(context.raw.directory, "cleanup.bin", 0)? != bytes {
        return Err("MCSEALED-PRIVATE-RELEASE: dual cleanup readback differs".into());
    }
    inventory.push(PrivateReleaseAttachmentV1 {
        role: PrivateReleaseAttachmentRoleV1::Cleanup,
        size: bytes.len() as u64,
        sha256: hash_bytes(&bytes),
    });
    Ok(inventory)
}

/// Detached service readback of the complete protected five-role inventory.
/// The worker and coordinator identities are checked against independent
/// process-exit observations by the caller, not trusted from these bytes.
pub(crate) fn readback_dual_raw(
    context: DualRawContextV1<'_>,
    gate: &DualLiveGateReadbackV1,
    first_journal: &ReadbackRetiredCandidateAttemptV1,
    second_journal: &ReadbackRetiredCandidateAttemptV1,
    coordinator: &ProcessIdentityV4,
    service_generation_sha256: &DiagnosticSha256,
) -> Result<
    (
        DualRawReportV1,
        DualCoordinatorCleanupV1,
        Vec<PrivateReleaseAttachmentV1>,
    ),
    String,
> {
    let (report, mut inventory) =
        readback_dual_worker_raw_from_disk(context, gate, first_journal, second_journal)?;
    let cleanup_bytes = read_fixed(context.directory, "cleanup.bin", 0)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&cleanup_bytes)?;
    let cleanup: DualCoordinatorCleanupV1 =
        serde_json::from_slice(&cleanup_bytes).map_err(|error| error.to_string())?;
    let observer = read_fixed(context.directory, "observer.bin", 0)?;
    if serde_json::to_vec(&cleanup).map_err(|error| error.to_string())? != cleanup_bytes
        || cleanup.schema_version != 1
        || cleanup.selector != SELECTOR
        || cleanup.result_key != *context.result_key
        || cleanup.gate_sha256 != gate.gate_sha256
        || cleanup.first_attempt_id != report.first.attempt_id
        || cleanup.second_attempt_id != report.second.attempt_id
        || cleanup.first_terminal_sha256 != report.first.terminal_sha256
        || cleanup.second_terminal_sha256 != report.second.terminal_sha256
        || cleanup.observer_sha256 != hash_bytes(&observer)
        || cleanup.coordinator != *coordinator
        || cleanup.worker == *coordinator
        || cleanup.worker.pid == 0
        || cleanup.worker.start_time == 0
        || !cleanup.worker_pidfd_exited
        || cleanup.service_generation_sha256 != *service_generation_sha256
        || cleanup.settlement_source != "control-coordinator-pidfd"
    {
        return Err("MCSEALED-PRIVATE-RELEASE: dual cleanup readback differs".into());
    }
    inventory.push(PrivateReleaseAttachmentV1 {
        role: PrivateReleaseAttachmentRoleV1::Cleanup,
        size: cleanup_bytes.len() as u64,
        sha256: hash_bytes(&cleanup_bytes),
    });
    Ok((report, cleanup, inventory))
}

fn expected_report(
    context: &DualRawContextV1<'_>,
    observed: &DualCandidateNativeObservationV1,
    gate: &DualLiveGateReadbackV1,
    first_journal: &ReadbackRetiredCandidateAttemptV1,
    second_journal: &ReadbackRetiredCandidateAttemptV1,
) -> Result<DualRawReportV1, String> {
    let first_key =
        private_release_dual_attempt::subattempt_key(context.result_key, DualAttemptRoleV1::First);
    let second_key =
        private_release_dual_attempt::subattempt_key(context.result_key, DualAttemptRoleV1::Second);
    let first = branch(
        first_key,
        &observed.first,
        first_journal,
        observed.first_namespace_inode,
        observed.first_listener_inode,
    )?;
    let second = branch(
        second_key,
        &observed.second,
        second_journal,
        observed.second_namespace_inode,
        observed.second_listener_inode,
    )?;
    let first_native = first_journal.native_identities()?;
    let second_native = second_journal.native_identities()?;
    if gate.gate.result_key != *context.result_key
        || gate.gate.selector != SELECTOR
        || gate.gate.challenge_sha256 != hash_bytes(context.challenge)
        || gate.gate.port != observed.port
        || gate.gate_sha256 != observed.gate_sha256
        || gate.gate.first.subattempt_key != first.subattempt_key
        || gate.gate.second.subattempt_key != second.subattempt_key
        || gate.gate.first.attempt_id != first.attempt_id
        || gate.gate.second.attempt_id != second.attempt_id
        || gate.gate.first.checkpoint_sha256 != first.checkpoint_sha256
        || gate.gate.second.checkpoint_sha256 != second.checkpoint_sha256
        || gate.gate.first.network_namespace_inode != first.network_namespace_inode
        || gate.gate.second.network_namespace_inode != second.network_namespace_inode
        || gate.gate.first.listener_socket_inode != first.listener_socket_inode
        || gate.gate.second.listener_socket_inode != second.listener_socket_inode
        || gate.gate.first.target != first_native.target
        || gate.gate.second.target != second_native.target
        || gate.gate.first.network_namespace_inode != first_native.network_namespace_inode
        || gate.gate.second.network_namespace_inode != second_native.network_namespace_inode
        || gate.gate.first.filter_sha256 != first_journal.filter_digest()?
        || gate.gate.second.filter_sha256 != second_journal.filter_digest()?
        || gate.first_midflight.execution_record_digest != gate.gate.first.execution_record_digest
        || gate.second_midflight.execution_record_digest != gate.gate.second.execution_record_digest
        || observed.first_frame
            != private_release_dual_attempt::ready_frame(
                context.challenge,
                observed.port,
                first.network_namespace_inode,
            )
        || observed.second_frame
            != private_release_dual_attempt::ready_frame(
                context.challenge,
                observed.port,
                second.network_namespace_inode,
            )
    {
        return Err("MCSEALED-PRIVATE-RELEASE: dual raw gate or frame differs".into());
    }
    let inspection = std::str::from_utf8(context.installed_inspection_bytes)
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE: dual installed inspection encoding differs")?;
    Ok(DualRawReportV1 {
        schema_version: 1,
        selector: SELECTOR.into(),
        result_key: context.result_key.clone(),
        challenge_sha256: hash_bytes(context.challenge),
        gate_sha256: gate.gate_sha256.clone(),
        port: observed.port,
        first,
        second,
        installed_inspection_json: inspection.into(),
    })
}

fn branch(
    subattempt_key: DiagnosticSha256,
    observed: &super::private_release_attempt::ReleaseCandidateRetirementObservationV1,
    journal: &ReadbackRetiredCandidateAttemptV1,
    network_namespace_inode: u64,
    listener_socket_inode: u64,
) -> Result<DualRawBranchV1, String> {
    if observed.attempt_id != journal.attempt_id
        || observed.attempt_id
            != super::private_release_attempt::candidate_attempt_id(&subattempt_key)
        || observed.checkpoint_digest.as_ref() != Some(&journal.checkpoint_digest)
        || observed.terminal_record_digest != journal.terminal_record_digest
        || observed.terminal_bytes != journal.terminal_bytes
        || observed.candidate_exit_code != Some(0)
        || observed.settlement.schema_version != 1
        || observed.settlement.monitor_outcome
            != super::private_lifecycle::PrivateMonitorOutcome::Completed
        || !observed.settlement.cgroup_empty_before_cleanup
        || !observed.settlement.containment_removed
        || !observed.settlement.target_pidfd_exited
        || !observed.settlement.namespace_init_reaped
        || observed.settlement.candidate_exit_code != Some(0)
        || network_namespace_inode == 0
        || listener_socket_inode == 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE: dual raw retirement differs".into());
    }
    let settlement = serde_json::to_vec(&observed.settlement).map_err(|error| error.to_string())?;
    Ok(DualRawBranchV1 {
        subattempt_key,
        attempt_id: observed.attempt_id.clone(),
        checkpoint_sha256: journal.checkpoint_digest.clone(),
        terminal_record_digest: journal.terminal_record_digest.clone(),
        terminal_sha256: hash_bytes(&journal.terminal_bytes),
        settlement_sha256: hash_bytes(&settlement),
        network_namespace_inode,
        listener_socket_inode,
        candidate_exit_code: 0,
    })
}
