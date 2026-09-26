//! Versioned caller/history conjunction. All four auxiliary physical captures
//! and both positive controls are replayed from immutable custody; a rejection
//! label or an ordinary allocating capture never establishes non-allocation.
use crate::private_candidate_replay::{CaseFactV1, CaseReplayFactsV1, ExpectedCaseSubjectV1};
use crate::private_observer_session::{
    ObserverEvidenceV1, ObserverIntervalRecordV1, ObserverStageV1,
};
use crate::{CiError, Result};
use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_codec::hash_bytes;
use serde::{Deserialize, Serialize};
use std::path::Path;

const CALLER: &str = "private_tcp::caller_identity_and_epoch_bound";
const CONTROL: &str = "private_tcp::native_tcp_bind_listen_connect";
const INTENT: &str = "candidate-c-v3/observer/static-intent.v1.json";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeCallerEpochSourcesV1 {
    pub(crate) static_intent_path: String,
    pub(crate) current_request_path: String,
    pub(crate) e0_capture_path: String,
    pub(crate) replay_capture_path: String,
    pub(crate) e1_capture_path: String,
    pub(crate) spoof_capture_path: String,
}
fn fail<T>(message: &str) -> Result<T> {
    Err(CiError::Message(message.into()))
}
fn sibling(path: &str, leaf: &str) -> Result<String> {
    Ok(Path::new(path)
        .parent()
        .ok_or_else(|| CiError::Message("caller physical source parent absent".into()))?
        .join(leaf)
        .to_string_lossy()
        .into_owned())
}
fn record<'a>(
    session: &'a impl ObserverEvidenceV1,
    path: &str,
    purpose: &str,
    generation: u32,
    ordinal: u32,
) -> Result<&'a ObserverIntervalRecordV1> {
    let records = session
        .descriptor()
        .intervals
        .iter()
        .filter(|record| record.capture_path == path)
        .collect::<Vec<_>>();
    let [record] = records.as_slice() else {
        return fail("caller auxiliary physical interval absent/ambiguous");
    };
    if record.purpose != purpose || record.generation != generation || record.ordinal != ordinal {
        return fail("caller auxiliary physical purpose/generation/ordinal differs");
    }
    Ok(record)
}
pub(crate) fn record_candidate_caller_fact(
    descriptor: &crate::private_observer_session::ObserverSessionDescriptorV1,
    current_request_path: String,
) -> Result<CaseFactV1> {
    let find = |purpose: &str| -> Result<String> {
        let records = descriptor
            .intervals
            .iter()
            .filter(|record| record.purpose == purpose)
            .collect::<Vec<_>>();
        let [record] = records.as_slice() else {
            return fail("caller auxiliary source record missing/duplicated");
        };
        Ok(record.capture_path.clone())
    };
    Ok(CaseFactV1::NativeCallerEpochV1 {
        sources: NativeCallerEpochSourcesV1 {
            static_intent_path: INTENT.into(),
            current_request_path,
            e0_capture_path: find("historical-e0")?,
            replay_capture_path: find("historical-replay")?,
            e1_capture_path: find("historical-e1")?,
            spoof_capture_path: find("caller-spoof")?,
        },
    })
}
fn credentials(
    sample: &crate::private_public_live::HeldPublicTargetSamplesV1,
    uid: u32,
    gid: u32,
    group: u32,
) -> Result<()> {
    let status = std::str::from_utf8(
        sample
            .leaves
            .get("status.raw")
            .ok_or_else(|| CiError::Message("caller held raw status absent".into()))?,
    )
    .map_err(|_| CiError::Message("caller held raw status not text".into()))?;
    for (field, expected) in [
        ("Uid:", vec![uid; 4]),
        ("Gid:", vec![gid; 4]),
        ("Groups:", vec![group]),
    ] {
        let matching = status
            .lines()
            .filter_map(|line| line.strip_prefix(field))
            .collect::<Vec<_>>();
        let [value] = matching.as_slice() else {
            return fail("caller exact held credential field absent/duplicated");
        };
        let actual = value
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| CiError::Message("caller actual held credential invalid".into()))?;
        if actual != expected {
            return fail("caller independently held credentials differ");
        }
    }
    Ok(())
}
fn positive(
    session: &impl ObserverEvidenceV1,
    plan: &crate::private_candidate_producer::StaticCandidateProducerIntentV1,
    capture: &str,
    generation: u32,
    ordinal: u32,
    filter: &DiagnosticSha256,
) -> Result<memcordon_core::private_release_case_v1::PrivateReleaseCaseResultV1> {
    let recipe = crate::private_candidate_producer::prepared_candidate_case_recipe_v1(
        plan,
        &session.descriptor().session_nonce,
        generation,
        CONTROL,
        crate::private_kernel_replay::IntervalPurposeV1::Historical,
        ordinal,
    )?;
    let source = sibling(capture, "facts.json")?;
    let facts: CaseReplayFactsV1 =
        crate::private_observer_session::strict_json(session.leaf(&source)?, 8 * 1024 * 1024)?;
    let [held_path] = facts.held_sample_paths.as_slice() else {
        return fail("historical positive exact held baseline absent");
    };
    let sample =
        crate::private_source_carrier::decode_held_source(session.leaf(held_path)?, |path| {
            session.leaf(path).map(ToOwned::to_owned)
        })?;
    let net = sample
        .tasks
        .iter()
        .find(|task| task.tid == sample.pid)
        .and_then(|task| task.namespace_inodes.get("net").copied())
        .ok_or_else(|| CiError::Message("historical positive held netns absent".into()))?;
    let response = memcordon_core::private_release_case_v1::candidate_fixture_expected_response_v1(
        &plan.subject.target,
        CONTROL,
        &recipe.challenge,
        Some(net),
        Some((sample.executable_device, sample.executable_inode)),
    )
    .map_err(|error| CiError::Message(error.into()))?;
    let expected = ExpectedCaseSubjectV1 {
        selector: CONTROL,
        result_key: &recipe.key,
        fixture_sha256: &recipe.recipe.fixture_sha256,
        filter_sha256: filter,
        fixture_argv: &recipe.argv,
        uid: recipe.recipe.uid,
        gid: recipe.recipe.gid,
        groups: &recipe.recipe.groups,
        port: recipe.port,
        challenge: &recipe.challenge,
        auxiliary_semantics_sha256: recipe.recipe.auxiliary_semantics_sha256.as_ref(),
        filter_install_source_sha256: recipe.recipe.filter_install_source_sha256.as_ref(),
        facility_source_sha256: recipe.recipe.facility_source_sha256.as_ref(),
        host_preservation_source_sha256: recipe.recipe.host_preservation_source_sha256.as_ref(),
        reuse_source_sha256: recipe.recipe.reuse_source_sha256.as_ref(),
        exact_response: &response,
    };
    let bytes = session.leaf(&sibling(capture, "result.json")?)?;
    crate::private_candidate_replay::verify_origin_bound_case(
        session, &expected, &source, bytes, capture,
    )?;
    let result = memcordon_core::private_release_case_v1::PrivateReleaseCaseResultV1::parse(bytes)
        .map_err(CiError::Message)?;
    crate::private_candidate_replay::verify_candidate_native_binding(
        session, &facts, &expected, &result,
    )?;
    Ok(result)
}

pub(crate) fn verify_native_caller_epoch(
    session: &impl ObserverEvidenceV1,
    expected: &ExpectedCaseSubjectV1<'_>,
    facts: &CaseReplayFactsV1,
    sources: &NativeCallerEpochSourcesV1,
) -> Result<()> {
    use crate::private_candidate_caller_frames::{
        IndependentCallerAdmissionV2, IndependentCallerReadyV1,
    };
    use crate::private_process_clock::{ParsedProcClockCalibrationV1, ProcClockInputsV1};
    if session.descriptor().subject.stage != ObserverStageV1::Candidate
        || expected.selector != CALLER
        || facts.generation != 1
        || sources.static_intent_path != INTENT
    {
        return fail("native caller history stage/configuration differs");
    }
    let plan: crate::private_candidate_producer::StaticCandidateProducerIntentV1 =
        crate::private_observer_session::strict_json(session.leaf(INTENT)?, 128 * 1024)?;
    plan.validate()?;
    if plan.identity_sha256()? != session.descriptor().subject.intent_sha256
        || plan.subject != session.descriptor().subject
    {
        return fail("caller configuration witness not independently enrolled");
    }
    let e0 = record(session, &sources.e0_capture_path, "historical-e0", 0, 0)?;
    let replay = record(
        session,
        &sources.replay_capture_path,
        "historical-replay",
        1,
        1,
    )?;
    let e1 = record(session, &sources.e1_capture_path, "historical-e1", 1, 2)?;
    let spoof = record(session, &sources.spoof_capture_path, "caller-spoof", 1, 0)?;
    let current = session
        .descriptor()
        .intervals
        .iter()
        .filter(|record| record.interval_id == facts.interval_id)
        .collect::<Vec<_>>();
    let [current] = current.as_slice() else {
        return fail("caller current physical interval absent/ambiguous");
    };
    if current.purpose != "ordinary"
        || current.generation != 1
        || current.logical_case_key != *expected.result_key
        || !current.sample_paths.contains(&facts.clock_path)
        || sources.current_request_path != sibling(&facts.clock_path, "request.json")?
        || spoof.end_monotonic_ns >= current.begin_monotonic_ns
    {
        return fail("caller auxiliary source not before exact current positive interval");
    }
    if e0.end_monotonic_ns >= replay.begin_monotonic_ns
        || replay.end_monotonic_ns >= e1.begin_monotonic_ns
        || e1.end_monotonic_ns >= spoof.begin_monotonic_ns
    {
        return fail("actual caller/history physical ordering differs");
    }
    let timeline = &session.descriptor().generations;
    let [old, new] = timeline.as_slice() else {
        return fail("caller exact observed E0/E1 generations absent");
    };
    if old.generation != 0
        || new.generation != 1
        || old.installation_epoch == new.installation_epoch
        || old.installed_manifest_sha256 != new.installed_manifest_sha256
    {
        return fail("caller same-B actual epoch advance differs");
    }
    let e0_result = positive(
        session,
        &plan,
        &sources.e0_capture_path,
        0,
        0,
        expected.filter_sha256,
    )?;
    positive(
        session,
        &plan,
        &sources.e1_capture_path,
        1,
        2,
        expected.filter_sha256,
    )?;
    let original = session.leaf(&sibling(&sources.e0_capture_path, "request.json")?)?;
    if original != session.leaf(&sibling(&sources.replay_capture_path, "request.json")?)?
        || replay.logical_case_key != e0_result.result_key().map_err(CiError::Message)?
    {
        return fail("stale replay did not preserve exact original E0 request/key");
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Stale {
        schema_version: u8,
        selector: String,
        result_key: DiagnosticSha256,
        original_request_sha256: DiagnosticSha256,
        e0_installation_epoch_sha256: DiagnosticSha256,
        e1_installation_epoch_sha256: DiagnosticSha256,
        mismatch: String,
    }
    let stale: Stale = crate::private_observer_session::strict_json(
        session.leaf(&sibling(
            &sources.replay_capture_path,
            "replay-rejection.json",
        )?)?,
        16 * 1024,
    )?;
    if stale.schema_version != 1
        || stale.selector != CONTROL
        || stale.result_key != replay.logical_case_key
        || stale.original_request_sha256 != hash_bytes(original)
        || stale.e0_installation_epoch_sha256 != old.installation_epoch
        || stale.e1_installation_epoch_sha256 != new.installation_epoch
        || stale.mismatch != "installation-epoch"
    {
        return fail("actual native stale admission result differs");
    }
    crate::private_candidate_replay::verify_no_allocation(
        &crate::private_candidate_replay::replay_observer_interval(
            session,
            &sources.replay_capture_path,
        )?,
    )?;
    let interval = crate::private_candidate_replay::replay_observer_interval(
        session,
        &sources.spoof_capture_path,
    )?;
    crate::private_candidate_replay::verify_no_allocation(&interval)?;
    let admission_bytes = session.leaf(&sibling(&sources.spoof_capture_path, "request.json")?)?;
    let admission: IndependentCallerAdmissionV2 =
        crate::private_observer_session::strict_json(admission_bytes, 16 * 1024)?;
    let ready_bytes = session.leaf(&sibling(
        &sources.spoof_capture_path,
        "caller-ready-v1.json",
    )?)?;
    let ready: IndependentCallerReadyV1 =
        crate::private_observer_session::strict_json(ready_bytes, 16 * 1024)?;
    let challenge: [u8; 32] = expected
        .challenge
        .try_into()
        .map_err(|_| CiError::Message("caller parent challenge length differs".into()))?;
    let derived = crate::private_candidate_caller_frames::caller_spoof_challenge_v1(&challenge);
    let spoof_key = memcordon_core::private_release_case_v1::private_release_case_key_v1(
        memcordon_core::private_release_case_v1::PrivateReleaseStageV1::CandidateCapability,
        CALLER,
        &derived,
    )
    .map_err(CiError::Message)?;
    let current = crate::private_protected_readback::parse_protected_candidate_request(
        session.leaf(&sources.current_request_path)?,
        CALLER,
        challenge,
        expected.result_key,
    )?;
    if admission.schema_version != 2
        || admission.protocol != "candidate-independent-caller-probe-v2"
        || admission.parent_result_key != *expected.result_key
        || admission.challenge != challenge
        || admission.spoof_challenge != derived
        || admission.spoof_result_key != spoof_key
        || spoof.logical_case_key != spoof_key
        || admission.installation_epoch != new.installation_epoch
        || admission.candidate_manifest_sha256 != new.installed_manifest_sha256
        || admission.installed_inspection_sha256 != new.installed_receipt_sha256
        || admission.service_generation_sha256 != current.service_generation_sha256
        || current.installation_epoch != new.installation_epoch
        || current.candidate_manifest_sha256 != new.installed_manifest_sha256
        || admission.caller_uid != expected.uid
        || admission.caller_gid != expected.gid
        || ready.schema_version != 1
        || ready.protocol != "candidate-independent-caller-ready-v1"
        || ready.parent_result_key != *expected.result_key
        || ready.admission_sha256 != hash_bytes(admission_bytes)
        || ready.caller_uid != expected.uid
        || ready.caller_gid != expected.gid
        || ready.control_group_gid == 0
    {
        return fail("caller original admission/ready/installed authority differs");
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Ack {
        schema_version: u8,
        gate_sha256: DiagnosticSha256,
    }
    let ack: Ack = crate::private_observer_session::strict_json(
        session.leaf(&sibling(
            &sources.spoof_capture_path,
            "caller-ready-v1.ack",
        )?)?,
        1024,
    )?;
    if ack.schema_version != 1 || ack.gate_sha256 != hash_bytes(ready_bytes) {
        return fail("caller actual SHAACK differs");
    }
    let witness = crate::private_candidate_caller_frames::parse_candidate_caller_frames_v1(
        session.leaf(&sibling(
            &sources.spoof_capture_path,
            "caller-rejection-v1.json",
        )?)?,
        &challenge,
        expected.uid,
        expected.gid,
    )?;
    if witness.caller != ready.caller
        || witness.control_group_gid != ready.control_group_gid
        || hash_bytes(&witness.request_frame_bytes) != ready.request_frame_sha256
    {
        return fail("actual held caller original frames differ");
    }
    let sample = crate::private_source_carrier::decode_held_source(
        session.leaf(&sibling(&sources.spoof_capture_path, "caller-held.v1.bin")?)?,
        |path| session.leaf(path).map(ToOwned::to_owned),
    )?;
    if sample.pid != ready.caller.pid
        || sample.start_time_ticks != ready.caller.start_time
        || sample.executable_sha256 != plan.observer.agent_sha256
        || admission.admission_monotonic_ns < spoof.begin_monotonic_ns
        || ready.ready_monotonic_ns < admission.admission_monotonic_ns
        || sample.begin_monotonic_ns < ready.ready_monotonic_ns
        || sample.end_monotonic_ns < sample.begin_monotonic_ns
        || sample.end_monotonic_ns > spoof.end_monotonic_ns
    {
        return fail("caller actual held image/process/timing differs");
    }
    credentials(&sample, expected.uid, expected.gid, ready.control_group_gid)?;
    let clock: ProcClockInputsV1 = crate::private_observer_session::strict_json(
        session.leaf(&sibling(&sources.spoof_capture_path, "clock.json")?)?,
        128 * 1024,
    )?;
    let calibration = ParsedProcClockCalibrationV1::parse(&clock)?;
    let matches =
        |event: &crate::private_kernel_replay::KernelEventRecordV2, pid: u32, ticks: u64| {
            event.task.tid == pid
                && event.task.tgid == pid
                && calibration.matches(
                    crate::private_kernel_observer::KernelTaskIdentityV1 {
                        pid: event.task.tid,
                        start_time: event.task.start_boottime_ns,
                        cgroup_inode: event.task.cgroup_inode,
                        time_ns_inode: event.task.time_ns_inode,
                    },
                    ticks,
                )
        };
    let events = interval.events();
    let enter = events
        .iter()
        .find(|event| event.kind == 1)
        .ok_or_else(|| CiError::Message("caller actual request entry absent".into()))?;
    let exit = events
        .iter()
        .find(|event| event.kind == 2)
        .ok_or_else(|| CiError::Message("caller actual request exit absent".into()))?;
    if !matches(
        enter,
        admission.coordinator.pid,
        admission.coordinator.start_time,
    ) || enter.monotonic_ns < sample.end_monotonic_ns
        || exit.monotonic_ns > spoof.end_monotonic_ns
    {
        return fail("caller actual decision bracket actor/timing differs");
    }
    let forks = events
        .iter()
        .filter(|event| event.kind == 7 && event.other_tid == ready.caller.pid)
        .collect::<Vec<_>>();
    let [fork] = forks.as_slice() else {
        return fail("caller actual auxiliary fork absent/ambiguous");
    };
    if !matches(
        fork,
        admission.coordinator.pid,
        admission.coordinator.start_time,
    ) || fork.monotonic_ns >= ready.ready_monotonic_ns
    {
        return fail("caller actual fork parent/timing differs");
    }
    let caller_events = events
        .iter()
        .filter(|event| event.task.tid == ready.caller.pid)
        .collect::<Vec<_>>();
    if caller_events.is_empty()
        || caller_events.iter().any(|event| {
            !matches(event, ready.caller.pid, ready.caller.start_time)
                || event.sequence <= fork.sequence
        })
    {
        return fail("caller raw task identity aliases or precedes fork");
    }
    let exits = caller_events
        .iter()
        .filter(|event| event.kind == 8)
        .collect::<Vec<_>>();
    let [caller_exit] = exits.as_slice() else {
        return fail("caller actual helper exit absent/ambiguous");
    };
    let reaps = events
        .iter()
        .filter(|event| {
            event.kind == 9
                && event.other_tid == ready.caller.pid
                && u64::try_from(event.syscall_result).ok()
                    == Some(caller_exit.task.start_boottime_ns)
        })
        .collect::<Vec<_>>();
    let [reap] = reaps.as_slice() else {
        return fail("caller actual helper reap absent/ambiguous");
    };
    if caller_exit.syscall_result != 0
        || caller_exit.sequence <= enter.sequence
        || reap.sequence <= caller_exit.sequence
        || reap.sequence >= exit.sequence
    {
        return fail("caller actual decision/exit/reap chain differs");
    }
    Ok(())
}
