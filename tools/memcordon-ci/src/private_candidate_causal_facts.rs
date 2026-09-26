//! Causal facts reconstructed from exact native durable wires and independently
//! held task measurements. No owner verdict or selector label is a proof.
use crate::private_candidate_replay::{CaseFactV1, ReplayTaskV1};
use crate::private_kernel_replay::KernelEventRecordV2;
use crate::private_process_clock::{ParsedProcClockCalibrationV1, ProcClockInputsV1};
use crate::private_protected_readback::{self as native, StructuralProtectedNativeCaseV1};
use crate::private_public_live::HeldPublicTargetSamplesV1;
use crate::{CiError, Result};
use memcordon_core::private_release_case_v1::{
    PrivateReleaseCaseResultV1, PrivateReleaseInstalledBindingV1,
};
use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub(crate) struct CandidateCausalPathsV1 {
    pub(crate) raw_leaves: BTreeMap<String, Vec<u8>>,
    pub(crate) result_path: String,
    pub(crate) request_path: String,
    pub(crate) attempt_path: Option<String>,
    pub(crate) checkpoint_path: Option<String>,
    pub(crate) checkpoint_metadata_path: Option<String>,
    pub(crate) midpoint_path: Option<String>,
    pub(crate) observer_path: String,
    pub(crate) cleanup_path: String,
    pub(crate) stdout_path: String,
    pub(crate) stderr_path: String,
    pub(crate) clock_path: String,
    pub(crate) dual: Option<NativeDualPathsV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeDualPathsV1 {
    pub(crate) result_path: String,
    pub(crate) request_path: String,
    pub(crate) first_midpoint_path: String,
    pub(crate) second_midpoint_path: String,
    pub(crate) first_terminal_path: String,
    pub(crate) second_terminal_path: String,
    pub(crate) post_retirement_path: String,
    pub(crate) first_sample_path: String,
    pub(crate) second_sample_path: String,
    pub(crate) post_sample_path: String,
    pub(crate) clock_path: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeCausalJoinV1 {
    pub result_path: String,
    pub request_path: String,
    pub attempt_path: String,
    pub attachments: [String; 5],
    pub checkpoint_gate_path: Option<String>,
    pub reopen_metadata_path: Option<String>,
    #[serde(default)]
    pub terminal_sources: Option<NativeTerminalSourceJoinV1>,
    #[serde(default)]
    pub streams_metadata_path: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeTerminalSourceJoinV1 {
    pub midpoint_path: String,
    pub gate_path: String,
    pub held_sample_path: String,
}

pub(crate) fn replay_native_causal_join<'a>(
    paths: &NativeCausalJoinV1,
    leaf: impl Fn(&str) -> Result<&'a [u8]>,
) -> Result<StructuralProtectedNativeCaseV1> {
    let result =
        PrivateReleaseCaseResultV1::parse(leaf(&paths.result_path)?).map_err(CiError::Message)?;
    let challenge = result.challenge_bytes().map_err(CiError::Message)?;
    let request = native::parse_protected_candidate_request(
        leaf(&paths.request_path)?,
        &result.selector,
        challenge,
        &result.result_key().map_err(CiError::Message)?,
    )?;
    let attempt_bytes = leaf(&paths.attempt_path)?.to_vec();
    let attempt = native::parse_protected_candidate_attempt(
        &attempt_bytes,
        &request,
        &result.observation,
        challenge,
    )?;
    let attachments = paths
        .attachments
        .iter()
        .map(|path| leaf(path).map(ToOwned::to_owned))
        .collect::<Result<Vec<_>>>()?;
    for (expected, bytes) in result.attachments.iter().zip(&attachments) {
        if expected.size != bytes.len() as u64 || expected.sha256 != hash_bytes(bytes) {
            return fail("native causal original attachment hash/size differs");
        }
    }
    let raw = StructuralProtectedNativeCaseV1 {
        result,
        candidate_request: request,
        candidate_request_bytes: leaf(&paths.request_path)?.to_vec(),
        attempt_record: Some(attempt),
        attempt_record_bytes: Some(attempt_bytes),
        fault_marker_bytes: None,
        checkpoint_gate_bytes: paths
            .checkpoint_gate_path
            .as_ref()
            .map(|path| leaf(path).map(ToOwned::to_owned))
            .transpose()?,
        attachments,
    };
    let inspection = match &raw.result.installed {
        PrivateReleaseInstalledBindingV1::CandidateCapability {
            installed_inspection_sha256,
            ..
        } => installed_inspection_sha256,
        _ => return fail("native causal source used outside candidate stage"),
    };
    match raw.result.selector.as_str() {
        "private_tcp::checkpoint_persisted_before_release" => {
            native::validate_candidate_checkpoint_gate_raw_attachments(&raw, challenge, inspection)?
        }
        "private_tcp::authorization_uncertainty_retired" => {
            native::validate_candidate_uncertain_raw_attachments(&raw, challenge, inspection)?
        }
        "private_tcp::frontend_loss_retired" => {
            native::validate_candidate_frontend_loss_raw_attachments(&raw, challenge, inspection)?
        }
        "private_tcp::guardian_loss_retired" => {
            native::validate_candidate_guardian_loss_raw_attachments(&raw, challenge, inspection)?
        }
        "private_tcp::child_runtime_and_threads_retired" => {
            native::validate_candidate_child_raw_attachments(&raw, challenge, inspection)?
        }
        "private_tcp::release_checkpoint_terminal_joined" => {
            let sources = paths.terminal_sources.as_ref().ok_or_else(|| {
                CiError::Message(
                    "native terminal original midpoint/gate/sample paths absent".into(),
                )
            })?;
            let midpoint = native::parse_protected_terminal_midflight(
                leaf(&sources.midpoint_path)?,
                &raw.candidate_request,
                challenge,
            )?;
            let sample = crate::private_source_carrier::decode_held_source(
                leaf(&sources.held_sample_path)?,
                |path| Ok(leaf(path)?.to_vec()),
            )?;
            let key = std::path::Path::new("tasks")
                .join(midpoint.target.pid.to_string())
                .join("status.raw");
            let status = sample
                .leaves
                .get(key.to_string_lossy().as_ref())
                .ok_or_else(|| {
                    CiError::Message("terminal independently sampled target status absent".into())
                })?;
            let text = std::str::from_utf8(status)
                .map_err(|_| CiError::Message("terminal NSpid source not text".into()))?;
            let values = text
                .lines()
                .filter_map(|line| line.strip_prefix("NSpid:"))
                .collect::<Vec<_>>();
            let [value] = values.as_slice() else {
                return fail("terminal NSpid absent or duplicated");
            };
            let chain = value
                .split_whitespace()
                .map(|part| {
                    part.parse::<u32>()
                        .map_err(|_| CiError::Message("terminal NSpid scalar differs".into()))
                })
                .collect::<Result<Vec<_>>>()?;
            if sample.pid != midpoint.target.pid
                || sample.start_time_ticks != midpoint.target.start_time
            {
                return fail("terminal sampled PID/start differs");
            }
            native::validate_candidate_terminal_raw_attachments(
                &raw,
                challenge,
                inspection,
                &midpoint,
                &hash_bytes(leaf(&sources.gate_path)?),
                &chain,
            )?;
        }
        _ => return fail("native causal original wire family is not admitted"),
    }
    Ok(raw)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointReopenRawV1 {
    schema_version: u8,
    file_dev: u64,
    file_inode: u64,
    directory_dev: u64,
    directory_inode: u64,
    observed_monotonic_ns: u64,
    bytes_sha256: DiagnosticSha256,
}

fn fail<T>(message: &str) -> Result<T> {
    Err(CiError::Message(message.into()))
}
fn json(bytes: &[u8]) -> Result<serde_json::Value> {
    crate::private_observer_session::strict_json(bytes, 1024 * 1024)
}
fn source<'a>(paths: &'a CandidateCausalPathsV1, path: &str) -> Result<&'a [u8]> {
    if path.is_empty()
        || std::path::Path::new(path).is_absolute()
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return fail("causal source path is not a closed relative leaf");
    }
    paths
        .raw_leaves
        .get(path)
        .map(Vec::as_slice)
        .ok_or_else(|| CiError::Message("exact causal source leaf absent".into()))
}
fn required<'a>(value: &'a Option<String>, role: &str) -> Result<&'a str> {
    value
        .as_deref()
        .ok_or_else(|| CiError::Message(format!("actual causal {role} source absent")))
}
fn task(raw: crate::private_kernel_replay::KernelTaskIdentityV2) -> ReplayTaskV1 {
    ReplayTaskV1 {
        tid: raw.tid,
        tgid: raw.tgid,
        start_boottime_ns: raw.start_boottime_ns,
        cgroup_inode: raw.cgroup_inode,
        time_ns_inode: raw.time_ns_inode,
    }
}
fn matches(task: &ReplayTaskV1, event: &KernelEventRecordV2) -> bool {
    task == &self::task(event.task)
}
fn kernel_task(
    events: &[KernelEventRecordV2],
    clock: &ParsedProcClockCalibrationV1,
    pid: u32,
    ticks: u64,
) -> Result<ReplayTaskV1> {
    let mut identities = events
        .iter()
        .filter(|event| {
            event.task.tid == pid
                && clock.matches(
                    crate::private_kernel_observer::KernelTaskIdentityV1 {
                        pid,
                        start_time: event.task.start_boottime_ns,
                        cgroup_inode: event.task.cgroup_inode,
                        time_ns_inode: event.task.time_ns_inode,
                    },
                    ticks,
                )
        })
        .map(|event| task(event.task))
        .collect::<Vec<_>>();
    identities.sort_by_key(|task| {
        (
            task.start_boottime_ns,
            task.cgroup_inode,
            task.tgid,
            task.time_ns_inode,
        )
    });
    identities.dedup();
    match identities.as_slice() {
        [task] => Ok(task.clone()),
        _ => fail("actual native task lacks unique original clock/kernel identity"),
    }
}
fn paired<'a>(
    events: &'a [KernelEventRecordV2],
    ret: &KernelEventRecordV2,
    kind: u32,
) -> Result<&'a KernelEventRecordV2> {
    let entries = events
        .iter()
        .filter(|entry| {
            entry.kind == kind
                && entry.syscall_occurrence == ret.syscall_occurrence
                && entry.task == ret.task
                && entry.syscall_arch == ret.syscall_arch
                && entry.syscall_nr == ret.syscall_nr
                && entry.args == ret.args
                && entry.sequence < ret.sequence
        })
        .collect::<Vec<_>>();
    match entries.as_slice() {
        [entry] => Ok(*entry),
        _ => fail("causal syscall lacks unique typed entry/return occurrence"),
    }
}
fn latest_held<'a>(
    held: &[(&str, &'a HeldPublicTargetSamplesV1)],
    task: &ReplayTaskV1,
    clock: &ParsedProcClockCalibrationV1,
) -> Result<&'a HeldPublicTargetSamplesV1> {
    let mut candidates = held
        .iter()
        .filter_map(|(_, sample)| {
            (sample.pid == task.tid
                && clock.matches(
                    crate::private_kernel_observer::KernelTaskIdentityV1 {
                        pid: task.tid,
                        start_time: task.start_boottime_ns,
                        cgroup_inode: task.cgroup_inode,
                        time_ns_inode: task.time_ns_inode,
                    },
                    sample.start_time_ticks,
                ))
            .then_some(*sample)
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|sample| sample.end_monotonic_ns);
    candidates
        .last()
        .copied()
        .ok_or_else(|| CiError::Message("independent held causal task sample absent".into()))
}

pub(crate) fn verify_native_terminal_v1(
    result_bytes: &[u8],
    request_bytes: &[u8],
    midpoint_bytes: &[u8],
    terminal_bytes: &[u8],
    clock: &ProcClockInputsV1,
    target: &ReplayTaskV1,
    key: &DiagnosticSha256,
    challenge: &[u8],
    attempt_id: &str,
) -> Result<()> {
    let challenge: [u8; 32] = challenge
        .try_into()
        .map_err(|_| CiError::Message("native terminal challenge size differs".into()))?;
    let result = PrivateReleaseCaseResultV1::parse(result_bytes).map_err(CiError::Message)?;
    const SELECTOR: &str = "private_tcp::release_checkpoint_terminal_joined";
    if result.selector != SELECTOR
        || result.result_key().map_err(CiError::Message)? != *key
        || result.challenge_bytes().map_err(CiError::Message)? != challenge
    {
        return fail("native terminal result differs from protected scenario");
    }
    let request =
        native::parse_protected_candidate_request(request_bytes, SELECTOR, challenge, key)?;
    let terminal = native::parse_protected_candidate_attempt(
        terminal_bytes,
        &request,
        &result.observation,
        challenge,
    )?;
    let midpoint = native::parse_protected_terminal_midflight(midpoint_bytes, &request, challenge)?;
    let clock = ParsedProcClockCalibrationV1::parse(clock)?;
    let identity = terminal
        .target_identity()
        .ok_or_else(|| CiError::Message("native terminal target absent".into()))?;
    if terminal.attempt_id() != attempt_id
        || midpoint.attempt_id != attempt_id
        || terminal.phase() != native::ProtectedAttemptPhaseV1::Retired
        || terminal.release_knowledge() != native::ProtectedReleaseKnowledgeV1::ExecObserved
        || identity != &midpoint.target
        || terminal.checkpoint_digest() != Some(&midpoint.checkpoint_sha256)
        || terminal.checkpoint_filter_sha256() != Some(&midpoint.filter_sha256)
        || terminal.checkpoint_network_namespace_inode() != Some(midpoint.network_namespace_inode)
        || !clock.matches(
            crate::private_kernel_observer::KernelTaskIdentityV1 {
                pid: target.tid,
                start_time: target.start_boottime_ns,
                cgroup_inode: target.cgroup_inode,
                time_ns_inode: target.time_ns_inode,
            },
            identity.start_time,
        )
        || identity.pid != target.tid
    {
        return fail("actual native checkpoint/midpoint/terminal identity or knowledge differs");
    }
    Ok(())
}

pub(crate) fn record_candidate_causal_facts(
    raw: &StructuralProtectedNativeCaseV1,
    events: &[KernelEventRecordV2],
    clock: &ProcClockInputsV1,
    target: &ReplayTaskV1,
    held: &[(&str, &HeldPublicTargetSamplesV1)],
    paths: &CandidateCausalPathsV1,
) -> Result<Vec<CaseFactV1>> {
    let mut facts = record_measurements(raw, events, clock, target, held, paths)?;
    if matches!(
        raw.result.selector.as_str(),
        "private_tcp::frontend_loss_retired"
            | "private_tcp::guardian_loss_retired"
            | "private_tcp::release_checkpoint_terminal_joined"
    ) {
        facts.push(record_checkpoint_measurement(raw, events, target, paths)?);
    }
    if !matches!(
        raw.result.selector.as_str(),
        "private_tcp::checkpoint_persisted_before_release"
            | "private_tcp::authorization_uncertainty_retired"
            | "private_tcp::frontend_loss_retired"
            | "private_tcp::guardian_loss_retired"
            | "private_tcp::child_runtime_and_threads_retired"
            | "private_tcp::release_checkpoint_terminal_joined"
    ) {
        return Ok(facts);
    }
    let prefix = std::path::Path::new(&paths.observer_path)
        .parent()
        .ok_or_else(|| CiError::Message("causal raw attachment parent absent".into()))?;
    let join = NativeCausalJoinV1 {
        result_path: paths.result_path.clone(),
        request_path: paths.request_path.clone(),
        attempt_path: required(&paths.attempt_path, "terminal")?.into(),
        attachments: [
            "request.bin",
            "report.bin",
            "stdio.bin",
            "observer.bin",
            "cleanup.bin",
        ]
        .map(|name| prefix.join(name).to_string_lossy().into_owned()),
        checkpoint_gate_path: raw.checkpoint_gate_bytes.as_ref().map(|_| {
            prefix
                .join("checkpoint-gate.json")
                .to_string_lossy()
                .into_owned()
        }),
        reopen_metadata_path: paths.checkpoint_metadata_path.clone(),
        streams_metadata_path: if raw.result.selector
            == "private_tcp::authorization_uncertainty_retired"
        {
            Some(
                std::path::Path::new(&paths.stdout_path)
                    .with_file_name("uncertain-streams-v1.json")
                    .to_string_lossy()
                    .into_owned(),
            )
        } else {
            None
        },
        terminal_sources: if raw.result.selector
            == "private_tcp::release_checkpoint_terminal_joined"
        {
            let midpoint = required(&paths.midpoint_path, "terminal midpoint")?;
            let sample = latest_held(held, target, &ParsedProcClockCalibrationV1::parse(clock)?)?;
            let (sample_path, _) = held
                .iter()
                .find(|(_, candidate)| std::ptr::eq(*candidate, sample))
                .ok_or_else(|| {
                    CiError::Message("terminal independent sample source path absent".into())
                })?;
            Some(NativeTerminalSourceJoinV1 {
                midpoint_path: midpoint.into(),
                gate_path: std::path::Path::new(midpoint)
                    .with_file_name("terminal-join-gate.json")
                    .to_string_lossy()
                    .into_owned(),
                held_sample_path: (*sample_path).into(),
            })
        } else {
            None
        },
    };
    replay_native_causal_join(&join, |path| source(paths, path))?;
    for measurement in &facts {
        verify_reopened_causal_source(&join, measurement, events, clock, |path| {
            source(paths, path)
        })?;
    }
    let mut wrapped = facts
        .into_iter()
        .map(|measurement| {
            if matches!(measurement, CaseFactV1::NativeTerminalV1 { .. }) {
                measurement
            } else {
                CaseFactV1::NativeCausalV1 {
                    family: measurement.kind(),
                    sources: join.clone(),
                    measurement: Box::new(measurement),
                }
            }
        })
        .collect::<Vec<_>>();
    if raw.result.selector == "private_tcp::authorization_uncertainty_retired" {
        let measurement = wrapped
            .iter()
            .find_map(|fact| match fact {
                CaseFactV1::NativeCausalV1 {
                    family: crate::private_case_semantics::CaseFactKindV1::AuthorizationLoss,
                    measurement,
                    ..
                } => Some(measurement.clone()),
                _ => None,
            })
            .ok_or_else(|| CiError::Message("actual authorization loss source absent".into()))?;
        verify_uncertain_checkpoint_source(&join, &measurement, events, |path| {
            source(paths, path)
        })?;
        wrapped.push(CaseFactV1::NativeUncertainCheckpointV1 {
            sources: join,
            measurement,
        });
    }
    Ok(wrapped)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UncertainCheckpointOperandsV1 {
    pub target: ReplayTaskV1,
    pub file_sync_sequence: u64,
    pub transport_loss_sequence: u64,
    pub gate_failure_sequence: u64,
    pub file_dev: u64,
    pub file_inode: u64,
    pub directory_dev: u64,
    pub directory_inode: u64,
    pub reopened_monotonic_ns: u64,
}

/// Diagnostic causal predicate only. Authority additionally requires exact
/// native durable phases, enrolled subject, original source bytes and custody.
pub(crate) fn validate_uncertain_checkpoint_operations(
    events: &[KernelEventRecordV2],
    operands: &UncertainCheckpointOperandsV1,
) -> Result<()> {
    let at = |sequence| {
        events
            .iter()
            .find(|event| event.sequence == sequence)
            .ok_or_else(|| CiError::Message("uncertain checkpoint occurrence absent".into()))
    };
    let sync = at(operands.file_sync_sequence)?;
    let lost = at(operands.transport_loss_sequence)?;
    let gate = at(operands.gate_failure_sequence)?;
    let entry = paired(events, sync, 11)?;
    if sync.kind != 5
        || !matches!(sync.syscall_nr, 74 | 82)
        || sync.syscall_result != 0
        || entry.image_dev != operands.file_dev
        || entry.image_inode != operands.file_inode
        || sync.monotonic_ns >= operands.reopened_monotonic_ns
        || operands.reopened_monotonic_ns >= lost.monotonic_ns
        || lost.kind != 5
        || !matches!(lost.syscall_nr, 44 | 206)
        || lost.args[2] != 1
        || lost.args[3] != 0x4000 // Linux UAPI MSG_NOSIGNAL, not collector libc.
        || lost.syscall_result != -32
        || lost.task != sync.task
        || lost.sequence >= gate.sequence
        || gate.kind != 5
        || !matches(&operands.target, gate)
        || !matches!(gate.syscall_nr, 45 | 207)
        || gate.args[0] != 3
        || gate.args[2] != 2
        || gate.args[3] != 0
        || gate.syscall_result != 0
        || [
            operands.file_dev,
            operands.file_inode,
            operands.directory_dev,
            operands.directory_inode,
            operands.reopened_monotonic_ns,
        ]
        .contains(&0)
    {
        return fail("uncertain checkpoint real fsync/fstat/EPIPE/gate order differs");
    }
    paired(events, lost, 11)?;
    paired(events, gate, 4)?;
    let directories = events
        .iter()
        .filter(|event| {
            event.kind == 5
                && event.task == sync.task
                && event.syscall_nr == sync.syscall_nr
                && event.syscall_result == 0
                && event.sequence > sync.sequence
                && event.monotonic_ns < operands.reopened_monotonic_ns
                && paired(events, event, 11).is_ok_and(|entry| {
                    entry.image_dev == operands.directory_dev
                        && entry.image_inode == operands.directory_inode
                })
        })
        .collect::<Vec<_>>();
    if directories.len() != 1 {
        return fail("uncertain checkpoint actual parent directory fsync absent/ambiguous");
    }
    if events.iter().any(|event| {
        event.kind == 6 && matches(&operands.target, event)
            || event.kind == 5
                && event.task == lost.task
                && matches!(event.syscall_nr, 1 | 64)
                && event.args[0] == lost.args[0]
                && event.args[2] == 1
                && event.syscall_result == 1
                && event.sequence > sync.sequence
    }) {
        return fail("uncertain checkpoint observed successful GO or target exec");
    }
    Ok(())
}

pub fn validate_uncertain_checkpoint_capture(
    bytes: &[u8],
    key: &DiagnosticSha256,
    operands: &UncertainCheckpointOperandsV1,
) -> Result<()> {
    let capture = crate::private_kernel_replay::parse_capture_v2(bytes, key)?;
    validate_uncertain_checkpoint_operations(capture.events(), operands)
}

pub(crate) fn verify_uncertain_checkpoint_source<'a>(
    sources: &NativeCausalJoinV1,
    measurement: &CaseFactV1,
    events: &[KernelEventRecordV2],
    leaf: impl Fn(&str) -> Result<&'a [u8]>,
) -> Result<()> {
    let CaseFactV1::AuthorizationLoss {
        task,
        checkpoint_path,
        release_intent_sequence,
        transport_loss_sequence,
        gate_failure_sequence,
        ..
    } = measurement
    else {
        return fail("uncertain checkpoint does not carry actual authorization loss source");
    };
    let raw = replay_native_causal_join(sources, &leaf)?;
    if raw.result.selector != "private_tcp::authorization_uncertainty_retired" {
        return fail("uncertain checkpoint native result branch differs");
    }
    let terminal = raw
        .attempt_record
        .as_ref()
        .ok_or_else(|| CiError::Message("uncertain checkpoint native terminal absent".into()))?;
    if terminal.phase() != native::ProtectedAttemptPhaseV1::Retired
        || terminal.release_knowledge() != native::ProtectedReleaseKnowledgeV1::PossiblyReleased
    {
        return fail("uncertain checkpoint actual durable knowledge/terminal phase differs");
    }
    terminal.validate_prior_release_intent(leaf(checkpoint_path)?)?;
    let metadata = sources
        .reopen_metadata_path
        .as_ref()
        .ok_or_else(|| CiError::Message("uncertain checkpoint reopened fstat absent".into()))?;
    let reopened: CheckpointReopenRawV1 =
        crate::private_observer_session::strict_json(leaf(metadata)?, 4096)?;
    if reopened.schema_version != 1 || reopened.bytes_sha256 != hash_bytes(leaf(checkpoint_path)?) {
        return fail("uncertain checkpoint reopened durable bytes differ");
    }
    validate_uncertain_checkpoint_operations(
        events,
        &UncertainCheckpointOperandsV1 {
            target: task.clone(),
            file_sync_sequence: *release_intent_sequence,
            transport_loss_sequence: *transport_loss_sequence,
            gate_failure_sequence: *gate_failure_sequence,
            file_dev: reopened.file_dev,
            file_inode: reopened.file_inode,
            directory_dev: reopened.directory_dev,
            directory_inode: reopened.directory_inode,
            reopened_monotonic_ns: reopened.observed_monotonic_ns,
        },
    )
}

fn record_measurements(
    raw: &StructuralProtectedNativeCaseV1,
    events: &[KernelEventRecordV2],
    clock: &ProcClockInputsV1,
    target: &ReplayTaskV1,
    held: &[(&str, &HeldPublicTargetSamplesV1)],
    paths: &CandidateCausalPathsV1,
) -> Result<Vec<CaseFactV1>> {
    let parsed_clock = ParsedProcClockCalibrationV1::parse(clock)?;
    let challenge = raw.result.challenge_bytes().map_err(CiError::Message)?;
    let result = PrivateReleaseCaseResultV1::parse(source(paths, &paths.result_path)?)
        .map_err(CiError::Message)?;
    if serde_json::to_vec(&result)? != serde_json::to_vec(&raw.result)?
        || source(paths, &paths.request_path)? != raw.candidate_request_bytes
        || events.is_empty()
        || events
            .iter()
            .any(|event| event.request_key != raw.candidate_request.result_key)
    {
        return fail("causal source result/request/capture differs");
    }
    let inspection = match &raw.result.installed {
        PrivateReleaseInstalledBindingV1::CandidateCapability {
            installed_inspection_sha256,
            ..
        } => installed_inspection_sha256,
        _ => return fail("native causal branch is not candidate stage"),
    };
    let selector = raw.result.selector.as_str();
    match selector {
        "private_tcp::release_checkpoint_terminal_joined" => {
            let midpoint = required(&paths.midpoint_path, "midpoint")?;
            let terminal = required(&paths.attempt_path, "terminal")?;
            let attempt = raw
                .attempt_record
                .as_ref()
                .ok_or_else(|| CiError::Message("native terminal attempt absent".into()))?;
            verify_native_terminal_v1(
                source(paths, &paths.result_path)?,
                source(paths, &paths.request_path)?,
                source(paths, midpoint)?,
                source(paths, terminal)?,
                clock,
                target,
                &raw.result.result_key().map_err(CiError::Message)?,
                &challenge,
                attempt.attempt_id(),
            )?;
            Ok(vec![CaseFactV1::NativeTerminalV1 {
                result_path: paths.result_path.clone(),
                request_path: paths.request_path.clone(),
                midpoint_path: midpoint.into(),
                terminal_path: terminal.into(),
                clock_path: paths.clock_path.clone(),
                attempt_id: attempt.attempt_id().into(),
            }])
        }
        "private_tcp::child_runtime_and_threads_retired" => {
            native::validate_candidate_child_raw_attachments(raw, challenge, inspection)?;
            let value = json(source(paths, &paths.observer_path)?)?;
            let live = value.get("live").ok_or_else(|| {
                CiError::Message("actual native descendant witness absent".into())
            })?;
            let child: native::ProtectedCoordinatorIdentityV1 = serde_json::from_value(
                live.get("child")
                    .cloned()
                    .ok_or_else(|| CiError::Message("native child absent".into()))?,
            )?;
            let thread_tid = u32::try_from(
                live.get("thread_tid")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or_else(|| CiError::Message("native thread absent".into()))?,
            )
            .map_err(|_| CiError::Message("native thread overflow".into()))?;
            let thread_ticks = live
                .get("thread_start_time")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| CiError::Message("native thread start absent".into()))?;
            let child = kernel_task(events, &parsed_clock, child.pid, child.start_time)?;
            let thread = kernel_task(events, &parsed_clock, thread_tid, thread_ticks)?;
            let parent_sample = latest_held(held, target, &parsed_clock)?;
            let child_sample = latest_held(held, &child, &parsed_clock)?;
            if !parent_sample.tasks.iter().any(|sample| {
                sample.tid == thread.tid
                    && sample.start_time_ticks == thread_ticks
                    && sample.tgid == target.tgid
            }) {
                return fail("actual held thread source absent");
            }
            let overlap = parent_sample
                .end_monotonic_ns
                .max(child_sample.end_monotonic_ns);
            for descendant in [&child, &thread] {
                if !events.iter().any(|event| {
                    event.kind == 7
                        && matches(target, event)
                        && event.other_tid == descendant.tid
                        && event.monotonic_ns < overlap
                }) || events.iter().any(|event| {
                    event.kind == 8 && matches(descendant, event) && event.monotonic_ns <= overlap
                }) {
                    return fail("independent simultaneous descendant lifecycle absent");
                }
            }
            Ok(vec![CaseFactV1::Descendants {
                parent: target.clone(),
                child,
                thread,
                simultaneously_live_monotonic_ns: overlap,
            }])
        }
        "private_tcp::frontend_loss_retired" | "private_tcp::guardian_loss_retired" => {
            let frontend = selector == "private_tcp::frontend_loss_retired";
            if frontend {
                native::validate_candidate_frontend_loss_raw_attachments(
                    raw, challenge, inspection,
                )?;
            } else {
                native::validate_candidate_guardian_loss_raw_attachments(
                    raw, challenge, inspection,
                )?;
            }
            let attempt = raw
                .attempt_record
                .as_ref()
                .ok_or_else(|| CiError::Message("native fault attempt absent".into()))?;
            let victim = if frontend {
                attempt.frontend_identity()
            } else {
                attempt.guardian_identity()
            }
            .ok_or_else(|| CiError::Message("native fault victim absent".into()))?;
            let victim = kernel_task(events, &parsed_clock, victim.pid, victim.start_time)?;
            let sample = latest_held(held, target, &parsed_clock)?;
            let exits = events
                .iter()
                .filter(|event| {
                    event.kind == 8
                        && matches(&victim, event)
                        && event.syscall_result & 127 == 9
                        && event.monotonic_ns > sample.end_monotonic_ns
                })
                .collect::<Vec<_>>();
            let [exit] = exits.as_slice() else {
                return fail("exact fault victim SIGKILL exit absent or ambiguous");
            };
            let signals = events
                .iter()
                .filter(|event| {
                    event.kind == 5
                        && event.syscall_nr == 424
                        && event.args[1] == 9
                        && event.syscall_result == 0
                        && event.monotonic_ns > sample.end_monotonic_ns
                        && event.sequence < exit.sequence
                })
                .collect::<Vec<_>>();
            let [signal] = signals.as_slice() else {
                return fail("exact successful pidfd fault signal occurrence absent or ambiguous");
            };
            paired(events, signal, 11)?;
            let recovery = required(&paths.attempt_path, "fault retired recovery")?;
            if source(paths, recovery)?
                != raw
                    .attempt_record_bytes
                    .as_deref()
                    .ok_or_else(|| CiError::Message("fault terminal bytes absent".into()))?
            {
                return fail("fault recovery leaf substitutes original terminal");
            }
            let fact = if frontend {
                CaseFactV1::FrontendLoss {
                    target: target.clone(),
                    victim,
                    target_live_monotonic_ns: sample.end_monotonic_ns,
                    signal_monotonic_ns: signal.monotonic_ns,
                    victim_exit_sequence: exit.sequence,
                    recovery_path: recovery.into(),
                }
            } else {
                CaseFactV1::GuardianLoss {
                    target: target.clone(),
                    victim,
                    target_live_monotonic_ns: sample.end_monotonic_ns,
                    signal_monotonic_ns: signal.monotonic_ns,
                    victim_exit_sequence: exit.sequence,
                    recovery_path: recovery.into(),
                }
            };
            Ok(vec![fact])
        }
        "private_tcp::authorization_uncertainty_retired" => {
            native::validate_candidate_uncertain_raw_attachments(raw, challenge, inspection)?;
            if events
                .iter()
                .any(|event| event.kind == 6 && matches(target, event))
            {
                return fail("pre-exec authorization branch observed target exec");
            }
            let lost = events
                .iter()
                .filter(|event| {
                    event.kind == 5
                        && event.syscall_result == -32
                        && matches!(event.syscall_nr, 44 | 206)
                        && event.args[2] == 1
                        && event.args[3] == 0x4000 // Reviewed Linux UAPI.
                })
                .collect::<Vec<_>>();
            let [lost] = lost.as_slice() else {
                return fail("actual owner EPIPE authorization occurrence absent or ambiguous");
            };
            paired(events, lost, 11)?;
            let owner = task(lost.task);
            let reopen: CheckpointReopenRawV1 = crate::private_observer_session::strict_json(
                source(
                    paths,
                    required(
                        &paths.checkpoint_metadata_path,
                        "authorization reopened fstat",
                    )?,
                )?,
                4096,
            )?;
            let intent = events
                .iter()
                .filter(|event| {
                    event.kind == 5
                        && matches(&owner, event)
                        && matches!(event.syscall_nr, 74 | 82)
                        && event.syscall_result == 0
                        && event.sequence < lost.sequence
                        && event.monotonic_ns < reopen.observed_monotonic_ns
                })
                .filter(|event| {
                    paired(events, event, 11).is_ok_and(|entry| {
                        entry.image_dev == reopen.file_dev && entry.image_inode == reopen.file_inode
                    })
                })
                .max_by_key(|event| event.sequence)
                .ok_or_else(|| {
                    CiError::Message(
                        "actual reopened durable release-intent file sync absent".into(),
                    )
                })?;
            let gate = events
                .iter()
                .filter(|event| {
                    event.kind == 5
                        && matches(target, event)
                        && matches!(event.syscall_nr, 45 | 207)
                        && event.args[0] == 3
                        && event.args[2] == 2
                        && event.args[3] == 0
                        && event.syscall_result == 0
                        && event.sequence > lost.sequence
                })
                .min_by_key(|event| event.sequence)
                .ok_or_else(|| {
                    CiError::Message("actual closed authorization gate read absent".into())
                })?;
            paired(events, gate, 4)?;
            let checkpoint = required(&paths.checkpoint_path, "prior release intent")?;
            raw.attempt_record
                .as_ref()
                .ok_or_else(|| CiError::Message("authorization terminal absent".into()))?
                .validate_prior_release_intent(source(paths, checkpoint)?)?;
            let value = json(source(paths, checkpoint)?)?;
            if value.get("phase").and_then(serde_json::Value::as_str) != Some("release-intent")
                || value
                    .get("release_knowledge")
                    .and_then(serde_json::Value::as_str)
                    != Some("possibly-released")
            {
                return fail("prior durable authorization state differs");
            }
            if source(paths, &paths.stdout_path)? != 0_u64.to_be_bytes()
                || source(paths, &paths.stderr_path)? != 0_u64.to_be_bytes()
            {
                return fail("pre-exec authorization branch has target output");
            }
            Ok(vec![CaseFactV1::AuthorizationLoss {
                task: target.clone(),
                checkpoint_path: checkpoint.into(),
                release_intent_sequence: intent.sequence,
                transport_loss_sequence: lost.sequence,
                gate_failure_sequence: gate.sequence,
                transport_errno: 32,
                phase: 4,
                stdout_path: paths.stdout_path.clone(),
                stderr_path: paths.stderr_path.clone(),
            }])
        }
        "private_tcp::checkpoint_persisted_before_release" => {
            native::validate_candidate_checkpoint_gate_raw_attachments(raw, challenge, inspection)?;
            Ok(vec![record_checkpoint_measurement(
                raw, events, target, paths,
            )?])
        }
        "private_tcp::dual_attempt_namespace_isolation" => {
            record_native_dual(raw, events, clock, paths)
        }
        _ => Ok(Vec::new()), // This helper owns only the seven causal families.
    }
}

fn record_checkpoint_measurement(
    raw: &StructuralProtectedNativeCaseV1,
    events: &[KernelEventRecordV2],
    target: &ReplayTaskV1,
    paths: &CandidateCausalPathsV1,
) -> Result<CaseFactV1> {
    let checkpoint = required(&paths.checkpoint_path, "reopened release intent")?;
    let metadata = required(&paths.checkpoint_metadata_path, "checkpoint reopened fstat")?;
    raw.attempt_record
        .as_ref()
        .ok_or_else(|| CiError::Message("checkpoint terminal absent".into()))?
        .validate_prior_release_intent(source(paths, checkpoint)?)?;
    let reopened: CheckpointReopenRawV1 =
        crate::private_observer_session::strict_json(source(paths, metadata)?, 4096)?;
    if reopened.schema_version != 1
        || reopened.bytes_sha256 != hash_bytes(source(paths, checkpoint)?)
        || [
            reopened.file_dev,
            reopened.file_inode,
            reopened.directory_dev,
            reopened.directory_inode,
            reopened.observed_monotonic_ns,
        ]
        .contains(&0)
    {
        return fail("actual reopened checkpoint measurement differs");
    }
    let syncs = events
        .iter()
        .filter(|ret| {
            ret.kind == 5
                && matches!(ret.syscall_nr, 74 | 82)
                && ret.syscall_result == 0
                && ret.monotonic_ns < reopened.observed_monotonic_ns
        })
        .filter(|ret| {
            paired(events, ret, 11).is_ok_and(|entry| {
                entry.image_dev == reopened.file_dev && entry.image_inode == reopened.file_inode
            })
        })
        .collect::<Vec<_>>();
    let [file_sync] = syncs.as_slice() else {
        return fail("reopened checkpoint exact file fsync occurrence absent or ambiguous");
    };
    let owner = task(file_sync.task);
    let directory_sync = events
        .iter()
        .filter(|ret| {
            ret.kind == 5
                && matches(&owner, ret)
                && matches!(ret.syscall_nr, 74 | 82)
                && ret.syscall_result == 0
                && ret.sequence > file_sync.sequence
                && ret.monotonic_ns < reopened.observed_monotonic_ns
        })
        .find(|ret| {
            paired(events, ret, 11).is_ok_and(|entry| {
                entry.image_dev == reopened.directory_dev
                    && entry.image_inode == reopened.directory_inode
            })
        })
        .ok_or_else(|| {
            CiError::Message("actual checkpoint parent directory fsync absent".into())
        })?;
    let exec = events
        .iter()
        .find(|event| event.kind == 6 && matches(target, event))
        .ok_or_else(|| CiError::Message("checkpoint target exec absent".into()))?;
    let releases = events
        .iter()
        .filter(|ret| {
            ret.kind == 5
                && matches(&owner, ret)
                && matches!(ret.syscall_nr, 1 | 64)
                && ret.args[2] == 1
                && ret.syscall_result == 1
                && ret.monotonic_ns > reopened.observed_monotonic_ns
                && ret.sequence < exec.sequence
        })
        .collect::<Vec<_>>();
    let [release] = releases.as_slice() else {
        return fail("actual post-reopen one-byte GO write absent or ambiguous");
    };
    paired(events, release, 11)?;
    Ok(CaseFactV1::Checkpoint {
        checkpoint_path: checkpoint.into(),
        file_dev: reopened.file_dev,
        file_inode: reopened.file_inode,
        owner,
        fd: u32::try_from(file_sync.args[0])
            .map_err(|_| CiError::Message("checkpoint fd overflow".into()))?,
        directory_fd: u32::try_from(directory_sync.args[0])
            .map_err(|_| CiError::Message("checkpoint dirfd overflow".into()))?,
        file_sync_sequence: file_sync.sequence,
        directory_sync_sequence: directory_sync.sequence,
        release_sequence: release.sequence,
    })
}

fn record_native_dual(
    raw: &StructuralProtectedNativeCaseV1,
    events: &[KernelEventRecordV2],
    clock: &ProcClockInputsV1,
    paths: &CandidateCausalPathsV1,
) -> Result<Vec<CaseFactV1>> {
    let dual = paths
        .dual
        .as_ref()
        .ok_or_else(|| CiError::Message("native dual exact source paths absent".into()))?;
    verify_native_dual_sources(raw, events, clock, dual, |path| source(paths, path))?;
    Ok(vec![CaseFactV1::NativeDualV1 {
        sources: dual.clone(),
    }])
}

pub(crate) fn verify_reopened_causal_source<'a>(
    paths: &NativeCausalJoinV1,
    measurement: &CaseFactV1,
    events: &[KernelEventRecordV2],
    clock: &ProcClockInputsV1,
    leaf: impl Fn(&str) -> Result<&'a [u8]>,
) -> Result<()> {
    let (checkpoint, file_sync, release, expected_object) = match measurement {
        CaseFactV1::Checkpoint {
            checkpoint_path,
            file_sync_sequence,
            release_sequence,
            file_dev,
            file_inode,
            ..
        } => (
            checkpoint_path,
            *file_sync_sequence,
            *release_sequence,
            Some((*file_dev, *file_inode)),
        ),
        CaseFactV1::AuthorizationLoss {
            checkpoint_path,
            release_intent_sequence,
            transport_loss_sequence,
            ..
        } => (
            checkpoint_path,
            *release_intent_sequence,
            *transport_loss_sequence,
            None,
        ),
        _ => return Ok(()),
    };
    let metadata = paths
        .reopen_metadata_path
        .as_ref()
        .ok_or_else(|| CiError::Message("original causal reopened metadata absent".into()))?;
    let reopened: CheckpointReopenRawV1 =
        crate::private_observer_session::strict_json(leaf(metadata)?, 4096)?;
    if let CaseFactV1::Checkpoint {
        directory_sync_sequence,
        ..
    } = measurement
    {
        let directory = events
            .iter()
            .find(|event| event.sequence == *directory_sync_sequence)
            .ok_or_else(|| {
                CiError::Message("actual reopened directory fsync return absent".into())
            })?;
        let entry = paired(events, directory, 11)?;
        if entry.image_dev != reopened.directory_dev
            || entry.image_inode != reopened.directory_inode
            || directory.monotonic_ns >= reopened.observed_monotonic_ns
        {
            return fail("actual reopened parent directory fsync object/timing differs");
        }
    }
    let sync = events
        .iter()
        .find(|event| event.sequence == file_sync)
        .ok_or_else(|| CiError::Message("causal reopened fsync return absent".into()))?;
    let entry = paired(events, sync, 11)?;
    let release = events
        .iter()
        .find(|event| event.sequence == release)
        .ok_or_else(|| CiError::Message("causal reopened release return absent".into()))?;
    if reopened.schema_version != 1
        || [
            reopened.file_dev,
            reopened.file_inode,
            reopened.directory_dev,
            reopened.directory_inode,
            reopened.observed_monotonic_ns,
        ]
        .contains(&0)
        || reopened.bytes_sha256 != hash_bytes(leaf(checkpoint)?)
        || expected_object.is_some_and(|object| object != (reopened.file_dev, reopened.file_inode))
        || entry.image_dev != reopened.file_dev
        || entry.image_inode != reopened.file_inode
        || sync.monotonic_ns >= reopened.observed_monotonic_ns
        || reopened.observed_monotonic_ns >= release.monotonic_ns
    {
        return fail("original causal opened object/bytes/timing differ");
    }
    if let CaseFactV1::AuthorizationLoss {
        task,
        stdout_path,
        stderr_path,
        ..
    } = measurement
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Streams {
            schema_version: u8,
            reader: native::ProtectedCoordinatorIdentityV1,
            stdout_fd: i32,
            stderr_fd: i32,
            stdout_inode: u64,
            stderr_inode: u64,
            stdout_dev: u64,
            stderr_dev: u64,
            stdout_sha256: DiagnosticSha256,
            stderr_sha256: DiagnosticSha256,
            begin_monotonic_ns: u64,
            end_monotonic_ns: u64,
        }
        let metadata = paths.streams_metadata_path.as_ref().ok_or_else(|| {
            CiError::Message("actual uncertainty stream drain source absent".into())
        })?;
        let streams: Streams = crate::private_observer_session::strict_json(leaf(metadata)?, 4096)?;
        let reader = kernel_task(
            events,
            &ParsedProcClockCalibrationV1::parse(clock)?,
            streams.reader.pid,
            streams.reader.start_time,
        )?;
        if streams.schema_version != 1
            || streams.stdout_fd < 0
            || streams.stderr_fd < 0
            || streams.stdout_fd == streams.stderr_fd
            || [
                streams.stdout_inode,
                streams.stderr_inode,
                streams.stdout_dev,
                streams.stderr_dev,
                streams.begin_monotonic_ns,
            ]
            .contains(&0)
            || streams.stdout_inode == streams.stderr_inode
            || streams.end_monotonic_ns < streams.begin_monotonic_ns
            || streams.stdout_sha256 != hash_bytes(leaf(stdout_path)?)
            || streams.stderr_sha256 != hash_bytes(leaf(stderr_path)?)
        {
            return fail("actual uncertainty stream object/hash/time differs");
        }
        for fd in [streams.stdout_fd, streams.stderr_fd] {
            let reads = events
                .iter()
                .filter(|event| {
                    event.kind == 5
                        && matches(&reader, event)
                        && matches!(event.syscall_nr, 0 | 63)
                        && event.args[0] == fd as u64
                        && event.syscall_result == 0
                        && event.monotonic_ns >= streams.begin_monotonic_ns
                        && event.monotonic_ns <= streams.end_monotonic_ns
                })
                .collect::<Vec<_>>();
            let [returned] = reads.as_slice() else {
                return fail("uncertainty exact reader EOF occurrence absent or ambiguous");
            };
            paired(events, returned, 11)?;
        }
        if events.iter().any(|event| {
            event.kind == 5
                && matches(task, event)
                && matches!(event.syscall_nr, 1 | 20 | 64 | 66)
                && matches!(event.args[0], 1 | 2)
                && event.syscall_result > 0
        }) {
            return fail("authorization-lost target wrote stdout/stderr before exec");
        }
    }
    Ok(())
}

pub(crate) fn verify_native_dual_sources<'a>(
    raw: &StructuralProtectedNativeCaseV1,
    events: &[KernelEventRecordV2],
    clock: &ProcClockInputsV1,
    paths: &NativeDualPathsV1,
    leaf: impl Fn(&str) -> Result<&'a [u8]>,
) -> Result<()> {
    use memcordon_core::private_release_case_v1::PrivateReleaseObservationV1;
    use sha2::{Digest, Sha256};
    let challenge = raw.result.challenge_bytes().map_err(CiError::Message)?;
    let PrivateReleaseObservationV1::DualAttemptsRetired {
        first,
        second,
        native_observer_sha256,
        ..
    } = &raw.result.observation
    else {
        return fail("actual native dual result branch differs");
    };
    let parent_key = raw.result.result_key().map_err(CiError::Message)?;
    let child_key = |tag| {
        let mut digest = Sha256::new();
        digest.update(b"memcordon-private-release-dual-subattempt-v1\0");
        digest.update(parent_key.bytes());
        digest.update([tag]);
        DiagnosticSha256::from_bytes(digest.finalize().into())
    };
    let first_key = child_key(1);
    let second_key = child_key(2);
    let first_terminal = native::parse_protected_dual_retired_attempt(
        leaf(&paths.first_terminal_path)?,
        &raw.candidate_request,
        first,
        &first_key,
        challenge,
        native_observer_sha256,
    )?;
    let second_terminal = native::parse_protected_dual_retired_attempt(
        leaf(&paths.second_terminal_path)?,
        &raw.candidate_request,
        second,
        &second_key,
        challenge,
        native_observer_sha256,
    )?;
    let first_mid = native::parse_protected_dual_midflight(
        leaf(&paths.first_midpoint_path)?,
        &raw.candidate_request,
        challenge,
        &first_key,
    )?;
    let second_mid = native::parse_protected_dual_midflight(
        leaf(&paths.second_midpoint_path)?,
        &raw.candidate_request,
        challenge,
        &second_key,
    )?;
    let clock = ParsedProcClockCalibrationV1::parse(clock)?;
    let first_task = kernel_task(
        events,
        &clock,
        first_mid.target.pid,
        first_mid.target.start_time,
    )?;
    let second_task = kernel_task(
        events,
        &clock,
        second_mid.target.pid,
        second_mid.target.start_time,
    )?;
    let first_sample = crate::private_source_carrier::decode_held_source(
        leaf(&paths.first_sample_path)?,
        |path| Ok(leaf(path)?.to_vec()),
    )?;
    let second_sample = crate::private_source_carrier::decode_held_source(
        leaf(&paths.second_sample_path)?,
        |path| Ok(leaf(path)?.to_vec()),
    )?;
    let post_sample = crate::private_source_carrier::decode_held_source(
        leaf(&paths.post_sample_path)?,
        |path| Ok(leaf(path)?.to_vec()),
    )?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Post {
        schema_version: u8,
        protocol: String,
        first_attempt_id: String,
        first_terminal_sha256: DiagnosticSha256,
        first_retirement_monotonic_ns: u64,
        second_response_monotonic_ns: u64,
        second_target: native::ProtectedCoordinatorIdentityV1,
        frame: Vec<u8>,
    }
    let post: Post =
        crate::private_observer_session::strict_json(leaf(&paths.post_retirement_path)?, 4096)?;
    if post.schema_version != 1
        || post.protocol != "candidate-dual-second-exchange-v1"
        || post.first_attempt_id != first_terminal.attempt_id()
        || post.first_terminal_sha256 != hash_bytes(leaf(&paths.first_terminal_path)?)
        || post.second_target != second_mid.target
        || first_terminal.target_identity() != Some(&first_mid.target)
        || second_terminal.target_identity() != Some(&second_mid.target)
        || first_terminal.checkpoint_digest() != Some(&first_mid.checkpoint_sha256)
        || second_terminal.checkpoint_digest() != Some(&second_mid.checkpoint_sha256)
        || first_task.tgid == second_task.tgid
        || first_task.cgroup_inode == second_task.cgroup_inode
        || first_mid.network_namespace_inode == second_mid.network_namespace_inode
    {
        return fail("native dual exact durable identities differ");
    }
    for (sample, task, identity) in [
        (&first_sample, &first_task, &first_mid.target),
        (&second_sample, &second_task, &second_mid.target),
        (&post_sample, &second_task, &second_mid.target),
    ] {
        if sample.pid != identity.pid
            || sample.start_time_ticks != identity.start_time
            || sample.begin_monotonic_ns == 0
            || sample.end_monotonic_ns < sample.begin_monotonic_ns
            || !clock.matches(
                crate::private_kernel_observer::KernelTaskIdentityV1 {
                    pid: task.tid,
                    start_time: task.start_boottime_ns,
                    cgroup_inode: task.cgroup_inode,
                    time_ns_inode: task.time_ns_inode,
                },
                sample.start_time_ticks,
            )
        {
            return fail("native dual independently held task differs");
        }
    }
    let overlap = first_sample
        .end_monotonic_ns
        .max(second_sample.end_monotonic_ns);
    if overlap >= post.first_retirement_monotonic_ns
        || post.first_retirement_monotonic_ns >= post.second_response_monotonic_ns
        || post.second_response_monotonic_ns > post_sample.begin_monotonic_ns
        || !events.iter().any(|event| {
            event.kind == 9
                && event.other_tid == first_task.tid
                && event.syscall_result as u64 == first_task.start_boottime_ns
                && event.monotonic_ns <= post.first_retirement_monotonic_ns
        })
        || !events.iter().any(|event| {
            event.kind == 8
                && matches(&first_task, event)
                && event.monotonic_ns > overlap
                && event.monotonic_ns <= post.first_retirement_monotonic_ns
        })
        || events.iter().any(|event| {
            event.kind == 8
                && matches(&second_task, event)
                && event.monotonic_ns <= post_sample.end_monotonic_ns
        })
    {
        return fail("native dual first retired / second still live ordering differs");
    }
    let port = memcordon_core::private_release_case_v1::candidate_fixture_port_v1(&challenge);
    let endpoints = crate::private_candidate_network_facts::validate_held_tcp_endpoints;
    let (first_listener, _) =
        endpoints(&first_sample, &first_task, events, &raw.result.target, port)?;
    let (second_listener, second_connector) = endpoints(
        &second_sample,
        &second_task,
        events,
        &raw.result.target,
        port,
    )?;
    let (post_listener, post_connector) =
        endpoints(&post_sample, &second_task, events, &raw.result.target, port)?;
    if first_listener.netns_inode != first_mid.network_namespace_inode
        || second_listener.netns_inode != second_mid.network_namespace_inode
        || second_listener != post_listener
        || second_connector != post_connector
        || first_listener.socket_inode == second_listener.socket_inode
    {
        return fail("dual held TCP namespace/object continuity differs after R1");
    }
    crate::private_candidate_network_facts::validate_held_tcp_exchange_after(
        &post_sample,
        &second_task,
        events,
        &raw.result.target,
        second_connector.socket_inode,
        post.first_retirement_monotonic_ns,
        post.second_response_monotonic_ns,
    )?;
    let mut echo = Sha256::new();
    echo.update(b"memcordon/private-dual-second-exchange/v1\0");
    echo.update(challenge);
    let echo = echo.finalize();
    let frame = &post.frame;
    if frame.len() != 82
        || &frame[..8] != b"MCDR\x01\0\0\0"
        || frame[8..40] != challenge
        || frame[40..72] != echo[..]
        || frame[72..74] != port.to_le_bytes()
        || frame[74..] != second_mid.network_namespace_inode.to_le_bytes()
    {
        return fail("native dual genuine post-retirement TCP response differs");
    }
    Ok(())
}
