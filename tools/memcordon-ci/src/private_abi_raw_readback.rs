//! Detached parsing of the protected ABI subwitness leaves. These records are
//! claimant observations, not kernel evidence or a completed case result.

use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::{
    PrivateReleaseAllocatedOutcomeV1, PrivateReleaseExecV1, PrivateReleaseKnowledgeV1,
    PrivateReleaseObservationV1,
};
use memcordon_core::private_release_case_v1::{PrivateReleaseStageV1, private_release_case_key_v1};
use memcordon_core::workload_codec::hash_bytes;
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::private_abi_composite::{AbiBranchTaskV1, X32ControlResultV1};
use crate::private_kernel_observer::{
    AllocationBoundaryKindV1, KernelEventV1, KernelTaskIdentityV1, LiveKernelSubjectV1,
    VerifiedKernelIntervalV1,
};
use crate::private_process_clock::VerifiedProcClockCalibrationV1;
use crate::private_protected_readback::{
    ProtectedCandidateAttemptV1, ProtectedCandidateReleaseRequestV1,
    parse_protected_candidate_attempt,
};
use crate::{CiError, Result};

const SELECTOR: &str = "private_tcp::abi_alternate_entry_denied";
const X32_MAX: usize = 4096;
const I386_MAX: usize = 16 * 1024;
const ARM_MAX: usize = 4096;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AbiProcessIdentityV1 {
    pub(crate) pid: u32,
    pub(crate) start_time: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum X32Outcome {
    Getpid,
    Enosys,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct X32Witness {
    challenge_sha256: DiagnosticSha256,
    filter_sha256: DiagnosticSha256,
    native: AbiProcessIdentityV1,
    native_response_sha256: DiagnosticSha256,
    outer_control: AbiProcessIdentityV1,
    outer_control_outcome: X32Outcome,
    outer_control_response_sha256: DiagnosticSha256,
    alternate: AbiProcessIdentityV1,
    alternate_signal: i32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct I386Witness {
    challenge_sha256: DiagnosticSha256,
    filter_sha256: DiagnosticSha256,
    outer_control: AbiProcessIdentityV1,
    outer_control_response_sha256: DiagnosticSha256,
    filtered: AbiProcessIdentityV1,
    filtered_signal: i32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ArmWitness {
    challenge_sha256: DiagnosticSha256,
    helper_sha256: DiagnosticSha256,
    filter_sha256: DiagnosticSha256,
    native: AbiProcessIdentityV1,
    native_response_sha256: DiagnosticSha256,
    outer_control: AbiProcessIdentityV1,
    filtered: AbiProcessIdentityV1,
    control_exec_observed: bool,
    filtered_exec_observed: bool,
    control_returned: bool,
    filtered_signal: i32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RawRecord<W> {
    schema: u32,
    selector: String,
    result_key: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    installed_inspection_sha256: DiagnosticSha256,
    filter_sha256: DiagnosticSha256,
    worker: AbiProcessIdentityV1,
    witness: W,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ArmRawRecord {
    schema: u32,
    selector: String,
    result_key: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    installed_inspection_sha256: DiagnosticSha256,
    filter_sha256: DiagnosticSha256,
    helper_sha256: DiagnosticSha256,
    worker: AbiProcessIdentityV1,
    witness: ArmWitness,
}

pub(crate) enum VerifiedAbiRawV1 {
    X86 {
        worker: AbiProcessIdentityV1,
        native: AbiProcessIdentityV1,
        x32_control: AbiProcessIdentityV1,
        x32_result: X32ControlResultV1,
        x32_filtered: AbiProcessIdentityV1,
        i386_control: AbiProcessIdentityV1,
        i386_filtered: AbiProcessIdentityV1,
        x32_sha256: DiagnosticSha256,
        i386_sha256: DiagnosticSha256,
    },
    Arm64 {
        worker: AbiProcessIdentityV1,
        native: AbiProcessIdentityV1,
        arm32_control: AbiProcessIdentityV1,
        arm32_filtered: AbiProcessIdentityV1,
        arm32_sha256: DiagnosticSha256,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PositiveReport {
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

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PositiveSettlement {
    schema_version: u8,
    monitor_outcome: String,
    cgroup_empty_before_cleanup: bool,
    containment_removed: bool,
    target_pidfd_exited: bool,
    namespace_init_reaped: bool,
    guardian_terminal: [u8; 20],
    candidate_exit_code: Option<i32>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PositiveObserver {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    settlement: PositiveSettlement,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    host_network_preservation: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent_path_preservation: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unix_absence: Option<serde_json::Value>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PositiveCleanup {
    schema_version: u8,
    attempt_id: String,
    checkpoint_sha256: DiagnosticSha256,
    terminal_record_digest: DiagnosticSha256,
    candidate_exit_code: i32,
    kernel_trace_sha256: DiagnosticSha256,
    coordinator: AbiProcessIdentityV1,
    worker: AbiProcessIdentityV1,
    worker_pidfd_exited: bool,
    service_generation_sha256: DiagnosticSha256,
    settlement_source: String,
}

pub(crate) struct VerifiedAbiPositiveRawV1 {
    pub(crate) worker: AbiProcessIdentityV1,
    pub(crate) guardian: AbiProcessIdentityV1,
    pub(crate) namespace_init: AbiProcessIdentityV1,
    pub(crate) target: AbiProcessIdentityV1,
    pub(crate) network_namespace_inode: u64,
    pub(crate) attempt_id: String,
    pub(crate) checkpoint_sha256: DiagnosticSha256,
    pub(crate) terminal_sha256: DiagnosticSha256,
    pub(crate) retirement_sha256: DiagnosticSha256,
    pub(crate) observer_sha256: DiagnosticSha256,
}

fn checked_json<T: for<'de> Deserialize<'de> + Serialize>(
    bytes: &[u8],
    maximum: usize,
) -> Result<T> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(fail("ABI positive raw size differs"));
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)
        .map_err(CiError::Message)?;
    let parsed: T = serde_json::from_slice(bytes)?;
    if serde_json::to_vec(&parsed)? != bytes {
        return Err(fail("ABI positive raw is not canonical"));
    }
    Ok(parsed)
}

/// Parse the standard positive target's protected request/report/I/O/kernel
/// observer/cleanup/attempt without inventing a main result. The transient
/// observation below is only a consistency expectation for the existing
/// strict attempt parser; it is never serialized or published as authority.
pub(crate) fn readback_abi_positive_raw(
    request: &ProtectedCandidateReleaseRequestV1,
    challenge: &[u8; 32],
    installed_inspection_sha256: &DiagnosticSha256,
    filter_sha256: &DiagnosticSha256,
    attachments: [&[u8]; 5],
    attempt_bytes: &[u8],
) -> Result<VerifiedAbiPositiveRawV1> {
    request_binding(request, challenge)?;
    let [
        request_bytes,
        report_bytes,
        stdio,
        observer_bytes,
        cleanup_bytes,
    ] = attachments;
    let recorded_request: ProtectedCandidateReleaseRequestV1 =
        checked_json(request_bytes, 16 * 1024)?;
    if recorded_request != *request || serde_json::to_vec(&recorded_request)? != request_bytes {
        return Err(fail("ABI positive request custody differs"));
    }
    let report: PositiveReport = checked_json(report_bytes, 16 * 1024)?;
    let observer: PositiveObserver = checked_json(observer_bytes, 16 * 1024)?;
    let cleanup: PositiveCleanup = checked_json(cleanup_bytes, 16 * 1024)?;
    let _: ProtectedCandidateAttemptV1 = checked_json(attempt_bytes, 16 * 1024)?;
    let mut response = b"memcordon-private-release-candidate-fixture-v1\0".to_vec();
    response.extend_from_slice(SELECTOR.as_bytes());
    response.push(0);
    response.extend_from_slice(challenge);
    let expected_response = hash_bytes(&response);
    let mut expected_stdio = challenge.to_vec();
    expected_stdio.extend_from_slice(expected_response.bytes());
    let expected_guardian =
        hex::decode(&report.attempt_id).map_err(|_| fail("ABI positive attempt id is not hex"))?;
    if report.schema_version != 1
        || report.selector != SELECTOR
        || report.result_key != request.result_key
        || report.challenge_sha256 != hash_bytes(challenge)
        || report.response_sha256 != hash_bytes(expected_response.bytes())
        || report.candidate_exit_code != 0
        || hash_bytes(report.installed_inspection_json.as_bytes()) != *installed_inspection_sha256
        || stdio != expected_stdio
        || observer.schema_version != 1
        || observer.attempt_id != report.attempt_id
        || observer.checkpoint_sha256 != report.checkpoint_sha256
        || observer.terminal_record_digest != report.terminal_record_digest
        || observer.host_network_preservation.is_some()
        || observer.agent_path_preservation.is_some()
        || observer.unix_absence.is_some()
        || observer.settlement.schema_version != 1
        || observer.settlement.monitor_outcome != "Completed"
        || !observer.settlement.cgroup_empty_before_cleanup
        || !observer.settlement.containment_removed
        || !observer.settlement.target_pidfd_exited
        || !observer.settlement.namespace_init_reaped
        || observer.settlement.candidate_exit_code != Some(0)
        || expected_guardian.len() != 16
        || observer.settlement.guardian_terminal[0] != 4
        || observer.settlement.guardian_terminal[1..17] != expected_guardian
        || observer.settlement.guardian_terminal[17..] != [1, 0, 0]
        || cleanup.schema_version != 1
        || cleanup.attempt_id != report.attempt_id
        || cleanup.checkpoint_sha256 != report.checkpoint_sha256
        || cleanup.terminal_record_digest != report.terminal_record_digest
        || cleanup.candidate_exit_code != 0
        || cleanup.kernel_trace_sha256 != hash_bytes(observer_bytes)
        || cleanup.coordinator.pid != request.coordinator.pid
        || cleanup.coordinator.start_time != request.coordinator.start_time
        || !valid_identity(&cleanup.worker)
        || cleanup.worker == cleanup.coordinator
        || !cleanup.worker_pidfd_exited
        || cleanup.service_generation_sha256 != request.service_generation_sha256
        || cleanup.settlement_source != "control-coordinator-pidfd"
    {
        return Err(fail("ABI positive protected raw differs"));
    }
    let transient = PrivateReleaseObservationV1::AllocatedRetired {
        outcome: PrivateReleaseAllocatedOutcomeV1::TargetCompleted,
        attempt_id: report.attempt_id.clone(),
        checkpoint_sha256: report.checkpoint_sha256.clone(),
        terminal_sha256: hash_bytes(attempt_bytes),
        retirement_sha256: hash_bytes(cleanup_bytes),
        release_knowledge: PrivateReleaseKnowledgeV1::ExecObserved,
        exec: PrivateReleaseExecV1::Succeeded,
        native_observer_sha256: hash_bytes(observer_bytes),
    };
    let attempt =
        parse_protected_candidate_attempt(attempt_bytes, request, &transient, *challenge)?;
    let [guardian, namespace_init, target] = attempt
        .terminal_processes()
        .ok_or_else(|| fail("ABI positive terminal identities absent"))?;
    let network_namespace_inode = attempt
        .checkpoint_network_namespace_inode()
        .filter(|inode| *inode != 0)
        .ok_or_else(|| fail("ABI positive namespace inode absent"))?;
    if attempt.terminal_record_digest() != &report.terminal_record_digest
        || attempt.checkpoint_filter_sha256() != Some(filter_sha256)
    {
        return Err(fail("ABI positive attempt journal differs"));
    }
    Ok(VerifiedAbiPositiveRawV1 {
        worker: cleanup.worker,
        guardian: AbiProcessIdentityV1 {
            pid: guardian.pid,
            start_time: guardian.start_time,
        },
        namespace_init: AbiProcessIdentityV1 {
            pid: namespace_init.pid,
            start_time: namespace_init.start_time,
        },
        target: AbiProcessIdentityV1 {
            pid: target.pid,
            start_time: target.start_time,
        },
        network_namespace_inode,
        attempt_id: report.attempt_id,
        checkpoint_sha256: report.checkpoint_sha256,
        terminal_sha256: hash_bytes(attempt_bytes),
        retirement_sha256: hash_bytes(cleanup_bytes),
        observer_sha256: hash_bytes(observer_bytes),
    })
}

/// Map one producer-held pidfd identity to one independently recorded kernel
/// task. The parent fork must precede the first child event, and any PID reuse
/// or differing start/cgroup/time-namespace identity rejects the interval.
pub(crate) fn join_abi_branch_task(
    interval: &VerifiedKernelIntervalV1,
    calibration: &VerifiedProcClockCalibrationV1,
    identity: &AbiProcessIdentityV1,
    parent: &AbiProcessIdentityV1,
) -> Result<AbiBranchTaskV1> {
    if !valid_identity(identity) || !valid_identity(parent) || identity == parent {
        return Err(fail("ABI branch/parent identity absent"));
    }
    let mut fork_at = None;
    let mut child_task: Option<KernelTaskIdentityV1> = None;
    let mut first_child_at = None;
    for (index, event) in interval.events().iter().enumerate() {
        match event {
            KernelEventV1::ForkObserved {
                parent: observed,
                child_pid,
            } if *child_pid == identity.pid => {
                if observed.pid != parent.pid
                    || !calibration.matches(*observed, parent.start_time)
                    || fork_at.replace(index).is_some()
                {
                    return Err(fail("ABI fork parent identity differs"));
                }
            }
            KernelEventV1::Fork {
                parent: observed,
                child,
            } if child.pid == identity.pid => {
                if observed.pid != parent.pid
                    || !calibration.matches(*observed, parent.start_time)
                    || fork_at.replace(index).is_some()
                {
                    return Err(fail("ABI fork parent identity differs"));
                }
                child_task = Some(*child);
                first_child_at = Some(index);
            }
            _ => {}
        }
        let task = match event {
            KernelEventV1::ForkObserved { parent: task, .. } => Some(task),
            KernelEventV1::Exec { task, .. }
            | KernelEventV1::Exit { task, .. }
            | KernelEventV1::Reap { task }
            | KernelEventV1::NamespaceFdClosed { task, .. }
            | KernelEventV1::SeccompDecision { task, .. }
            | KernelEventV1::SyscallReturn { task, .. }
            | KernelEventV1::AllocationBoundary { task, .. } => Some(task),
            KernelEventV1::Fork { child, .. } => Some(child),
        };
        if let Some(task) = task.filter(|task| task.pid == identity.pid) {
            if child_task.is_some_and(|prior| prior != *task) {
                return Err(fail("ABI branch PID reused in kernel capture"));
            }
            child_task = Some(*task);
            first_child_at.get_or_insert(index);
        }
    }
    let task = child_task.ok_or_else(|| fail("ABI branch kernel task absent"))?;
    if !calibration.matches(task, identity.start_time)
        || !matches!((fork_at, first_child_at), (Some(fork), Some(first)) if fork <= first)
    {
        return Err(fail("ABI branch clock/fork ordering differs"));
    }
    Ok(AbiBranchTaskV1 {
        producer_pid: identity.pid,
        producer_start_ticks: identity.start_time,
        kernel: task,
    })
}

/// Bind the protected ABI request to the independently observed sealed
/// service generation, coordinator fork, and ordered request-entry/exit pair.
pub(crate) fn join_abi_request_origin(
    root: &Path,
    request: &ProtectedCandidateReleaseRequestV1,
    challenge: &[u8; 32],
    expected_manifest: &DiagnosticSha256,
    expected_epoch: &DiagnosticSha256,
    interval: &VerifiedKernelIntervalV1,
    calibration: &VerifiedProcClockCalibrationV1,
    service: &LiveKernelSubjectV1,
) -> Result<()> {
    request_binding(request, challenge)?;
    interval.capture_bytes()?;
    let generation =
        crate::private_policy_request_join::verify_sealed_service_generation(root, service)?;
    if &request.candidate_manifest_sha256 != expected_manifest
        || &request.installation_epoch != expected_epoch
        || request.service_generation_sha256 != generation
        || interval.result_key() != &request.result_key
        || interval.cgroup_inode() != service.cgroup_inode
    {
        return Err(fail("ABI protected request service origin differs"));
    }
    let mut fork_at = None;
    let mut enter_at = None;
    let mut exit_at = None;
    let mut coordinator = None;
    for (index, event) in interval.events().iter().enumerate() {
        match event {
            KernelEventV1::ForkObserved { parent, child_pid }
                if *child_pid == request.coordinator.pid =>
            {
                if parent.pid != service.pid
                    || parent.cgroup_inode != service.cgroup_inode
                    || !calibration.matches(*parent, service.start_ticks)
                    || fork_at.replace(index).is_some()
                {
                    return Err(fail("ABI coordinator fork origin differs"));
                }
            }
            KernelEventV1::AllocationBoundary {
                task,
                request_key,
                kind,
            } if request_key == &request.result_key && task.pid == request.coordinator.pid => {
                if task.cgroup_inode != service.cgroup_inode
                    || !calibration.matches(*task, request.coordinator.start_time)
                    || coordinator.is_some_and(|prior| prior != *task)
                {
                    return Err(fail("ABI coordinator request task differs"));
                }
                coordinator = Some(*task);
                match kind {
                    AllocationBoundaryKindV1::Enter if enter_at.replace(index).is_none() => {}
                    AllocationBoundaryKindV1::Exit if exit_at.replace(index).is_none() => {}
                    _ => return Err(fail("ABI coordinator request boundary differs")),
                }
            }
            _ => {}
        }
    }
    if !matches!((fork_at, enter_at, exit_at), (Some(fork), Some(enter), Some(exit)) if fork < enter && enter < exit)
        || coordinator.is_none()
    {
        return Err(fail("ABI coordinator request interval absent"));
    }
    Ok(())
}

fn fail(message: &'static str) -> CiError {
    CiError::Message(message.into())
}

fn parse_canonical<W: for<'de> Deserialize<'de> + Serialize>(
    bytes: &[u8],
    limit: usize,
) -> Result<RawRecord<W>> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err(fail("ABI raw size differs"));
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)
        .map_err(CiError::Message)?;
    let record: RawRecord<W> = serde_json::from_slice(bytes)?;
    if serde_json::to_vec(&record)? != bytes {
        return Err(fail("ABI raw is not canonical"));
    }
    Ok(record)
}

fn valid_identity(identity: &AbiProcessIdentityV1) -> bool {
    identity.pid != 0 && identity.start_time != 0
}

fn response_digest(
    domain: &[u8],
    challenge: &[u8; 32],
    filter: &DiagnosticSha256,
    pid: u32,
) -> Result<DiagnosticSha256> {
    let pid = i32::try_from(pid).map_err(|_| fail("ABI raw PID overflows"))?;
    let mut bytes = domain.to_vec();
    bytes.extend_from_slice(challenge);
    bytes.extend_from_slice(filter.bytes());
    bytes.extend_from_slice(&pid.to_be_bytes());
    bytes.extend_from_slice(&(i64::from(pid)).to_be_bytes());
    Ok(hash_bytes(&bytes))
}

fn common<W>(
    record: &RawRecord<W>,
    request: &ProtectedCandidateReleaseRequestV1,
    challenge: &[u8; 32],
    inspection: &DiagnosticSha256,
    filter: &DiagnosticSha256,
) -> Result<()> {
    if record.schema != 1
        || record.selector != SELECTOR
        || record.result_key != request.result_key
        || record.challenge_sha256 != hash_bytes(challenge)
        || record.installed_inspection_sha256 != *inspection
        || record.filter_sha256 != *filter
        || !valid_identity(&record.worker)
        || record.worker.pid == request.coordinator.pid
    {
        return Err(fail("ABI raw protected binding differs"));
    }
    Ok(())
}

fn request_binding(
    request: &ProtectedCandidateReleaseRequestV1,
    challenge: &[u8; 32],
) -> Result<()> {
    if request.schema_version != 1
        || request.stage != "candidate-capability"
        || request.selector != SELECTOR
        || request.challenge != hex::encode(challenge)
        || request.result_key
            != private_release_case_key_v1(
                PrivateReleaseStageV1::CandidateCapability,
                SELECTOR,
                challenge,
            )
            .map_err(CiError::Message)?
        || request.coordinator.pid == 0
        || request.coordinator.start_time == 0
    {
        return Err(fail("ABI protected request differs"));
    }
    Ok(())
}

pub(crate) fn readback_x86_abi_raw(
    request: &ProtectedCandidateReleaseRequestV1,
    challenge: &[u8; 32],
    installed_inspection_sha256: &DiagnosticSha256,
    filter_sha256: &DiagnosticSha256,
    x32_bytes: &[u8],
    i386_bytes: &[u8],
) -> Result<VerifiedAbiRawV1> {
    request_binding(request, challenge)?;
    let x32: RawRecord<X32Witness> = parse_canonical(x32_bytes, X32_MAX)?;
    let i386: RawRecord<I386Witness> = parse_canonical(i386_bytes, I386_MAX)?;
    common(
        &x32,
        request,
        challenge,
        installed_inspection_sha256,
        filter_sha256,
    )?;
    common(
        &i386,
        request,
        challenge,
        installed_inspection_sha256,
        filter_sha256,
    )?;
    if x32.worker != i386.worker
        || x32.witness.challenge_sha256 != hash_bytes(challenge)
        || x32.witness.filter_sha256 != *filter_sha256
        || i386.witness.challenge_sha256 != hash_bytes(challenge)
        || i386.witness.filter_sha256 != *filter_sha256
        || x32.witness.alternate_signal != libc::SIGSYS
        || i386.witness.filtered_signal != libc::SIGSYS
        || x32.witness.native_response_sha256
            != response_digest(
                b"memcordon-private-release-native-getpid-v1\0",
                challenge,
                filter_sha256,
                x32.witness.native.pid,
            )?
        || i386.witness.outer_control_response_sha256
            != response_digest(
                b"memcordon-private-release-i386-getpid-v1\0",
                challenge,
                filter_sha256,
                i386.witness.outer_control.pid,
            )?
    {
        return Err(fail("x86 ABI subwitness differs"));
    }
    let x32_result = match x32.witness.outer_control_outcome {
        X32Outcome::Getpid => X32ControlResultV1::Pid,
        X32Outcome::Enosys => X32ControlResultV1::Enosys,
    };
    let mut x32_response = b"memcordon-private-release-x32-outer-control-v1\0".to_vec();
    x32_response.extend_from_slice(challenge);
    x32_response.extend_from_slice(filter_sha256.bytes());
    x32_response.extend_from_slice(
        &(i32::try_from(x32.witness.outer_control.pid)
            .map_err(|_| fail("x32 control PID overflows"))?)
        .to_be_bytes(),
    );
    x32_response.push(match x32_result {
        X32ControlResultV1::Pid => 1,
        X32ControlResultV1::Enosys => 2,
    });
    if x32.witness.outer_control_response_sha256 != hash_bytes(&x32_response) {
        return Err(fail("x32 outer-control response differs"));
    }
    let identities = [
        &x32.worker,
        &x32.witness.native,
        &x32.witness.outer_control,
        &x32.witness.alternate,
        &i386.witness.outer_control,
        &i386.witness.filtered,
    ];
    for (index, identity) in identities.iter().enumerate() {
        if !valid_identity(identity)
            || identities[..index].contains(identity)
            || identity.pid == request.coordinator.pid
        {
            return Err(fail("x86 ABI branch identity aliases"));
        }
    }
    Ok(VerifiedAbiRawV1::X86 {
        worker: x32.worker,
        native: x32.witness.native,
        x32_control: x32.witness.outer_control,
        x32_result,
        x32_filtered: x32.witness.alternate,
        i386_control: i386.witness.outer_control,
        i386_filtered: i386.witness.filtered,
        x32_sha256: hash_bytes(x32_bytes),
        i386_sha256: hash_bytes(i386_bytes),
    })
}

pub(crate) fn readback_arm64_abi_raw(
    request: &ProtectedCandidateReleaseRequestV1,
    challenge: &[u8; 32],
    installed_inspection_sha256: &DiagnosticSha256,
    filter_sha256: &DiagnosticSha256,
    expected_helper_sha256: &DiagnosticSha256,
    arm_bytes: &[u8],
) -> Result<VerifiedAbiRawV1> {
    request_binding(request, challenge)?;
    if arm_bytes.is_empty() || arm_bytes.len() > ARM_MAX {
        return Err(fail("ARM ABI raw size differs"));
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(arm_bytes)
        .map_err(CiError::Message)?;
    let arm: ArmRawRecord = serde_json::from_slice(arm_bytes)?;
    if serde_json::to_vec(&arm)? != arm_bytes {
        return Err(fail("ARM ABI raw is not canonical"));
    }
    if arm.schema != 1
        || arm.selector != SELECTOR
        || arm.result_key != request.result_key
        || arm.challenge_sha256 != hash_bytes(challenge)
        || arm.installed_inspection_sha256 != *installed_inspection_sha256
        || arm.filter_sha256 != *filter_sha256
        || arm.helper_sha256 != *expected_helper_sha256
        || arm.witness.challenge_sha256 != hash_bytes(challenge)
        || arm.witness.helper_sha256 != *expected_helper_sha256
        || arm.witness.filter_sha256 != *filter_sha256
        || arm.witness.native_response_sha256
            != response_digest(
                b"memcordon-private-release-native-getpid-v1\0",
                challenge,
                filter_sha256,
                arm.witness.native.pid,
            )?
        || !arm.witness.control_exec_observed
        || !arm.witness.filtered_exec_observed
        || !arm.witness.control_returned
        || arm.witness.filtered_signal != libc::SIGSYS
    {
        return Err(fail("ARM ABI subwitness differs"));
    }
    let identities = [
        &arm.worker,
        &arm.witness.native,
        &arm.witness.outer_control,
        &arm.witness.filtered,
    ];
    for (index, identity) in identities.iter().enumerate() {
        if !valid_identity(identity)
            || identities[..index].contains(identity)
            || identity.pid == request.coordinator.pid
        {
            return Err(fail("ARM ABI branch identity aliases"));
        }
    }
    Ok(VerifiedAbiRawV1::Arm64 {
        worker: arm.worker,
        native: arm.witness.native,
        arm32_control: arm.witness.outer_control,
        arm32_filtered: arm.witness.filtered,
        arm32_sha256: hash_bytes(arm_bytes),
    })
}
