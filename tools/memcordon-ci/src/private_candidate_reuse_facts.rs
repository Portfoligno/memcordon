//! Genuine owned-journal recovery sources. Structural recording returns
//! claims only; capability construction replays all three authenticated
//! physical intervals and their independently retained exact operands.
use crate::private_candidate_replay::{CaseFactV1, ExpectedCaseSubjectV1};
use crate::private_kernel_replay::{CaptureStageV2, KernelEventRecordV2};
use crate::private_observer_session::{
    ObserverEvidenceV1, ObserverSessionDescriptorV1, ObserverStageV1, strict_json,
};
use crate::private_process_clock::{ParsedProcClockCalibrationV1, ProcClockInputsV1};
use crate::private_protected_readback as native;
use crate::{CiError, Result};
use memcordon_core::private_release_case_v1::{
    PrivateReleaseCaseResultV1, PrivateReleaseInstalledBindingV1,
};
use memcordon_core::private_reuse_source_v1::*;
use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReuseHeldObjectsV1 {
    pub schema_version: u8,
    pub directory_device: u64,
    pub directory_inode: u64,
    pub marker: ReuseSourceObjectV1,
    pub record: ReuseSourceObjectV1,
    pub marker_bytes: Vec<u8>,
    pub record_bytes: Vec<u8>,
    pub begin_monotonic_ns: u64,
    pub end_monotonic_ns: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReuseAfterObjectsV1 {
    pub schema_version: u8,
    pub directory_device: u64,
    pub directory_inode: u64,
    pub old_marker_nlink: u64,
    pub old_record_nlink: u64,
    pub current_record: ReuseSourceObjectV1,
    pub current_bytes: Vec<u8>,
    pub observed_monotonic_ns: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReusePhaseSourcesV1 {
    pub capture_path: String,
    pub clock_path: String,
    pub admission_path: String,
    pub gate_path: String,
    pub ack_path: String,
    pub helper_path: String,
    pub objects_path: String,
    pub report_path: String,
    pub after_path: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeReuseSourcesV1 {
    pub result_path: String,
    pub request_path: String,
    pub attempt_path: String,
    pub marker_path: String,
    pub attachments: [String; 5],
    pub first_capture_path: String,
    pub blocked: ReusePhaseSourcesV1,
    pub recovery: ReusePhaseSourcesV1,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperImageV1 {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    nlink: u64,
    size: u64,
    sha256: DiagnosticSha256,
}
fn fail<T>(message: &str) -> Result<T> {
    Err(CiError::Message(message.into()))
}
fn same_call(left: &KernelEventRecordV2, right: &KernelEventRecordV2) -> bool {
    left.task == right.task
        && left.syscall_occurrence == right.syscall_occurrence
        && left.syscall_arch == right.syscall_arch
        && left.syscall_nr == right.syscall_nr
}
fn returned<'a>(
    events: &'a [KernelEventRecordV2],
    entry: &KernelEventRecordV2,
) -> Result<&'a KernelEventRecordV2> {
    let matches = events
        .iter()
        .filter(|event| event.kind == 5 && same_call(entry, event))
        .collect::<Vec<_>>();
    let [event] = matches.as_slice() else {
        return fail("Reuse syscall return absent or duplicated");
    };
    if event.sequence <= entry.sequence
        || event.args != entry.args
        || event.monotonic_ns < entry.monotonic_ns
    {
        return fail("Reuse syscall return precedes or substitutes entry");
    }
    Ok(event)
}
fn objects<'a>(
    events: &'a [KernelEventRecordV2],
    entry: &KernelEventRecordV2,
) -> Result<&'a KernelEventRecordV2> {
    let matches = events
        .iter()
        .filter(|event| event.kind == 19 && same_call(entry, event))
        .collect::<Vec<_>>();
    let [event] = matches.as_slice() else {
        return fail("Reuse successful VFS identity absent or duplicated");
    };
    Ok(event)
}
fn valid_object(object: &ReuseSourceObjectV1, bytes: &[u8]) -> bool {
    object.device != 0
        && object.inode != 0
        && object.uid == 0
        && object.mode & 0o777 == 0o600
        && object.nlink == 1
        && object.size == bytes.len() as u64
        && object.bytes_sha256 == hash_bytes(bytes)
}

/// Diagnostic predicate over original measured operands; this function does
/// not mint an origin or completion token.
pub(crate) fn validate_reuse_kernel_operands_v1(
    events: &[KernelEventRecordV2],
    gate: &ReuseSourceGateV1,
    report: &ReuseSourceReportV1,
    held: &ReuseHeldObjectsV1,
    after: &ReuseAfterObjectsV1,
) -> Result<()> {
    validate_reuse_source_shape_v1(gate, report)
        .map_err(|message| CiError::Message(message.into()))?;
    if held.schema_version != 1
        || after.schema_version != 1
        || (held.directory_device, held.directory_inode)
            != (gate.directory_device, gate.directory_inode)
        || (after.directory_device, after.directory_inode)
            != (gate.directory_device, gate.directory_inode)
        || held.marker != gate.marker
        || held.record != gate.record
        || held.marker_bytes != report.marker_bytes
        || held.record_bytes != report.before_bytes
        || !valid_object(&held.marker, &held.marker_bytes)
        || !valid_object(&held.record, &held.record_bytes)
        || held.begin_monotonic_ns < gate.observed_monotonic_ns
        || held.end_monotonic_ns < held.begin_monotonic_ns
        || held.end_monotonic_ns >= report.retry_begin_monotonic_ns
        || after.observed_monotonic_ns <= report.retry_end_monotonic_ns
    {
        return fail("Reuse independent held objects or chronology differ");
    }
    let helper = gate.helper.pid;
    let begins = events
        .iter()
        .filter(|event| event.kind == 1 && event.task.tid == helper)
        .collect::<Vec<_>>();
    let ends = events
        .iter()
        .filter(|event| event.kind == 2 && event.task.tid == helper)
        .collect::<Vec<_>>();
    let ([begin], [end]) = (begins.as_slice(), ends.as_slice()) else {
        return fail("Reuse actual helper request bracket absent or duplicated");
    };
    if begin.sequence >= end.sequence
        || begin.task != end.task
        || begin.monotonic_ns < held.end_monotonic_ns
        || begin.monotonic_ns > report.retry_begin_monotonic_ns
        || end.monotonic_ns < report.retry_end_monotonic_ns
        || events.iter().any(|event| event.kind == 3)
    {
        return fail("Reuse source allocates or differs from actual helper bracket");
    }
    let entries = events
        .iter()
        .filter(|event| {
            event.kind == 17
                && event.task == begin.task
                && event.sequence > begin.sequence
                && event.sequence < end.sequence
        })
        .collect::<Vec<_>>();
    let conflicts = entries
        .iter()
        .filter(|entry| {
            entry.other_tid == 1
                && entry.monotonic_ns >= report.retry_begin_monotonic_ns
                && entry.monotonic_ns <= report.retry_end_monotonic_ns
                && entry.args[2] & 0xc0 == 0xc0
                && entry.args[3] == 0o600
                && (entry.image_dev, entry.image_inode)
                    == (gate.directory_device, gate.directory_inode)
                && returned(events, entry).is_ok_and(|event| {
                    event.syscall_result == -17
                        && event.monotonic_ns <= report.retry_end_monotonic_ns
                })
        })
        .count();
    if conflicts == 0 {
        return fail("Reuse has no actual same owned-marker O_EXCL EEXIST retry");
    }
    match gate.phase {
        ReuseSourcePhaseV1::Blocked => {
            if entries.iter().any(|entry| matches!(entry.other_tid, 2 | 3))
                || after.old_marker_nlink != 1
                || after.old_record_nlink != 1
                || after.current_record != held.record
                || after.current_bytes != held.record_bytes
            {
                return fail("blocked Reuse changes original owned journal objects");
            }
        }
        ReuseSourcePhaseV1::Recover => {
            let unlinks = entries
                .iter()
                .filter(|entry| entry.other_tid == 2)
                .copied()
                .collect::<Vec<_>>();
            let renames = entries
                .iter()
                .filter(|entry| entry.other_tid == 3)
                .copied()
                .collect::<Vec<_>>();
            let ([unlink], [rename]) = (unlinks.as_slice(), renames.as_slice()) else {
                return fail("Reuse requires exact owned unlink and normal rename");
            };
            let removed = report
                .removed_monotonic_ns
                .ok_or_else(|| CiError::Message("actual marker removal time absent".into()))?;
            let recovered = report
                .recovered_monotonic_ns
                .ok_or_else(|| CiError::Message("actual recovery time absent".into()))?;
            let unlink_return = returned(events, unlink)?;
            let rename_return = returned(events, rename)?;
            let unlink_object = objects(events, unlink)?;
            let rename_object = objects(events, rename)?;
            if unlink.args[2] != 0
                || rename.args[4] != 0
                || unlink_return.syscall_result != 0
                || rename_return.syscall_result != 0
                || (unlink.image_dev, unlink.image_inode)
                    != (gate.directory_device, gate.directory_inode)
                || (rename.image_dev, rename.image_inode)
                    != (gate.directory_device, gate.directory_inode)
                || (unlink_object.args[0], unlink_object.args[1])
                    != (held.marker.device, held.marker.inode)
                || (rename_object.args[2], rename_object.args[3])
                    != (held.record.device, held.record.inode)
                || (rename_object.args[4], rename_object.args[5])
                    != (gate.directory_device, gate.directory_inode)
                || unlink_return.sequence >= rename.sequence
                || unlink_return.monotonic_ns > removed
                || rename_return.monotonic_ns > recovered
                || recovered > end.monotonic_ns
                || after.observed_monotonic_ns < recovered
                || after.old_marker_nlink != 0
                || after.old_record_nlink != 0
                || !valid_object(&after.current_record, &after.current_bytes)
                || (after.current_record.device, after.current_record.inode)
                    != (rename_object.args[0], rename_object.args[1])
                || (after.current_record.device, after.current_record.inode)
                    == (held.marker.device, held.marker.inode)
                || report.after_bytes.as_deref() != Some(after.current_bytes.as_slice())
            {
                return fail(
                    "Reuse deletion/replacement substitutes or reorders actual owned objects",
                );
            }
            let successful_sync = |dev, ino, after_seq, before_seq, before_ns| {
                events
                    .iter()
                    .filter(|entry| {
                        entry.kind == 11
                            && entry.task == begin.task
                            && matches!(
                                (entry.syscall_arch, entry.syscall_nr),
                                (0xc000003e, 74)
                                    | (0xc000003e, 75)
                                    | (0xc00000b7, 82)
                                    | (0xc00000b7, 83)
                            )
                            && (entry.image_dev, entry.image_inode) == (dev, ino)
                            && entry.sequence > after_seq
                            && entry.sequence < before_seq
                    })
                    .any(|entry| {
                        returned(events, entry).is_ok_and(|ret| {
                            ret.syscall_result == 0
                                && ret.sequence < before_seq
                                && ret.monotonic_ns <= before_ns
                        })
                    })
            };
            if !successful_sync(
                gate.directory_device,
                gate.directory_inode,
                unlink_return.sequence,
                rename.sequence,
                removed,
            ) || !successful_sync(
                rename_object.args[0],
                rename_object.args[1],
                unlink_return.sequence,
                rename.sequence,
                rename.monotonic_ns,
            ) || !successful_sync(
                gate.directory_device,
                gate.directory_inode,
                rename_return.sequence,
                end.sequence,
                recovered,
            ) {
                return fail(
                    "Reuse lacks actual removed-marker/file/replacement directory durability order",
                );
            }
        }
    }
    Ok(())
}

/// Portable bounded diagnostic replay, not an authenticated semantic token.
pub fn validate_reuse_capture_operands_v1(
    bytes: &[u8],
    key: &DiagnosticSha256,
    gate: &ReuseSourceGateV1,
    report: &ReuseSourceReportV1,
    held: &ReuseHeldObjectsV1,
    after: &ReuseAfterObjectsV1,
) -> Result<()> {
    let parsed = crate::private_kernel_replay::parse_capture_v2_with_budget(
        bytes,
        key,
        CaptureStageV2::Candidate,
    )?;
    validate_reuse_kernel_operands_v1(parsed.events(), gate, report, held, after)
}

pub(crate) fn verify_native_reuse_source(
    session: &impl ObserverEvidenceV1,
    expected: &ExpectedCaseSubjectV1<'_>,
    generation: u32,
    sources: &NativeReuseSourcesV1,
) -> Result<()> {
    for capture in [
        &sources.first_capture_path,
        &sources.blocked.capture_path,
        &sources.recovery.capture_path,
    ] {
        crate::private_candidate_replay::replay_observer_interval(session, capture)?;
    }
    validate_native_reuse_sources(
        session.descriptor(),
        expected,
        generation,
        sources,
        |path| Ok(session.leaf(path)?.to_vec()),
    )
}

pub(crate) fn record_reuse_source_facts(
    descriptor: &ObserverSessionDescriptorV1,
    expected: &ExpectedCaseSubjectV1<'_>,
    generation: u32,
    sources: NativeReuseSourcesV1,
    leaf: impl Fn(&str) -> Result<Vec<u8>>,
) -> Result<Vec<CaseFactV1>> {
    validate_native_reuse_sources(descriptor, expected, generation, &sources, leaf)?;
    Ok(vec![CaseFactV1::NativeReuseV1 { sources }])
}

fn validate_native_reuse_sources(
    descriptor: &ObserverSessionDescriptorV1,
    expected: &ExpectedCaseSubjectV1<'_>,
    generation: u32,
    sources: &NativeReuseSourcesV1,
    leaf: impl Fn(&str) -> Result<Vec<u8>>,
) -> Result<()> {
    if descriptor.subject.stage != ObserverStageV1::Candidate
        || expected.selector != REUSE_SELECTOR_V1
        || expected.reuse_source_sha256 != Some(&reuse_source_revision_sha256())
    {
        return fail("Reuse source not approved for this exact candidate recipe");
    }
    let result = PrivateReleaseCaseResultV1::parse(&leaf(&sources.result_path)?)
        .map_err(CiError::Message)?;
    let challenge = result.challenge_bytes().map_err(CiError::Message)?;
    if expected.challenge != challenge
        || result.selector != expected.selector
        || result.result_key().map_err(CiError::Message)? != *expected.result_key
    {
        return fail("Reuse original result differs from enrolled parent recipe");
    }
    let request_bytes = leaf(&sources.request_path)?;
    let request = native::parse_protected_candidate_request(
        &request_bytes,
        expected.selector,
        challenge,
        expected.result_key,
    )?;
    let attempt_bytes = leaf(&sources.attempt_path)?;
    let attempt = native::parse_protected_candidate_attempt(
        &attempt_bytes,
        &request,
        &result.observation,
        challenge,
    )?;
    if attempt.checkpoint_fixture_sha256() != Some(expected.fixture_sha256)
        || attempt.checkpoint_filter_sha256() != Some(expected.filter_sha256)
    {
        return fail("Reuse original checkpoint image/filter differs from protected recipe");
    }
    let attachments = sources
        .attachments
        .iter()
        .map(|path| leaf(path))
        .collect::<Result<Vec<_>>>()?;
    if result.attachments.len() != attachments.len()
        || result
            .attachments
            .iter()
            .zip(&attachments)
            .any(|(expected, bytes)| {
                expected.size != bytes.len() as u64 || expected.sha256 != hash_bytes(bytes)
            })
    {
        return fail("Reuse original raw attachment inventory differs");
    }
    let marker = leaf(&sources.marker_path)?;
    let PrivateReleaseInstalledBindingV1::CandidateCapability {
        installed_inspection_sha256,
        ..
    } = &result.installed
    else {
        return fail("Reuse original candidate install binding absent");
    };
    let original = native::StructuralProtectedNativeCaseV1 {
        result: result.clone(),
        candidate_request: request.clone(),
        candidate_request_bytes: request_bytes.clone(),
        attempt_record: Some(attempt.clone()),
        attempt_record_bytes: Some(attempt_bytes.clone()),
        fault_marker_bytes: Some(marker.clone()),
        checkpoint_gate_bytes: None,
        attachments,
    };
    native::validate_candidate_blocked_retirement_raw_attachments(
        &original,
        challenge,
        installed_inspection_sha256,
    )?;
    let original_report: serde_json::Value = strict_json(&original.attachments[1], 128 * 1024)?;
    let original_reuse_error = original_report
        .get("reuse_error")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| CiError::Message("original typed reuse rejection absent".into()))?;
    let generation_record = descriptor
        .generations
        .iter()
        .find(|entry| entry.generation == generation)
        .ok_or_else(|| CiError::Message("Reuse actual generation absent".into()))?;
    if generation_record.installation_epoch != request.installation_epoch
        || generation_record.installed_manifest_sha256 != request.candidate_manifest_sha256
        || generation_record.installed_receipt_sha256 != *installed_inspection_sha256
    {
        return fail("Reuse original install differs from independently observed generation");
    }
    let record = |capture: &str, purpose: &str| {
        let records = descriptor
            .intervals
            .iter()
            .filter(|entry| entry.capture_path == capture)
            .collect::<Vec<_>>();
        let [entry] = records.as_slice() else {
            return fail("Reuse physical source interval absent or ambiguous");
        };
        if entry.generation != generation
            || entry.purpose != purpose
            || entry.logical_case_key != *expected.result_key
        {
            return fail("Reuse source physical purpose/generation/key differs");
        }
        Ok(*entry)
    };
    let first = record(&sources.first_capture_path, "reuse-first")?;
    let blocked = record(&sources.blocked.capture_path, "reuse-blocked")?;
    let recovery = record(&sources.recovery.capture_path, "recovery")?;
    let source_prefix = |entry: &crate::private_observer_session::ObserverIntervalRecordV1| {
        std::path::Path::new("candidate-c-v3/observer/intervals")
            .join(String::from(entry.interval_id.clone()))
    };
    let first_prefix = source_prefix(first);
    let at =
        |prefix: &std::path::Path, name: &str| prefix.join(name).to_string_lossy().into_owned();
    if sources.result_path != at(&first_prefix, "result.json")
        || sources.request_path != at(&first_prefix, "request.json")
        || sources.attempt_path != at(&first_prefix, "attempt.json")
        || sources.marker_path != at(&first_prefix, "attempt.json.new")
        || sources.attachments
            != memcordon_core::private_release_case_v1::PrivateReleaseAttachmentRoleV1::ALL
                .map(|role| at(&first_prefix, role.leaf()))
    {
        return fail("Reuse original source inventory is remapped");
    }
    if first.detach_monotonic_ns >= blocked.arm_monotonic_ns
        || blocked.detach_monotonic_ns >= recovery.arm_monotonic_ns
        || first.interval_id == blocked.interval_id
        || blocked.interval_id == recovery.interval_id
        || ![
            &sources.result_path,
            &sources.request_path,
            &sources.attempt_path,
            &sources.marker_path,
        ]
        .iter()
        .all(|path| first.sample_paths.contains(path))
        || !sources
            .attachments
            .iter()
            .all(|path| first.sample_paths.contains(path))
    {
        return fail("Reuse three distinct original source intervals differ");
    }
    let mut prior_objects = None;
    for (phase, paths, enrolled) in [
        (ReuseSourcePhaseV1::Blocked, &sources.blocked, blocked),
        (ReuseSourcePhaseV1::Recover, &sources.recovery, recovery),
    ] {
        let prefix = source_prefix(enrolled);
        if paths.capture_path != at(&prefix, "capture.bin")
            || paths.clock_path != at(&prefix, "clock.json")
            || paths.admission_path != at(&prefix, "admission.json")
            || paths.gate_path != at(&prefix, "gate.json")
            || paths.ack_path != at(&prefix, "ack.json")
            || paths.helper_path != at(&prefix, "helper-held.v1.bin")
            || paths.objects_path != at(&prefix, "objects.json")
            || paths.report_path != at(&prefix, "report.json")
            || paths.after_path != at(&prefix, "after.json")
        {
            return fail("Reuse exact physical source inventory is remapped");
        }
        for path in [
            &paths.clock_path,
            &paths.admission_path,
            &paths.gate_path,
            &paths.ack_path,
            &paths.helper_path,
            &paths.objects_path,
            &paths.report_path,
            &paths.after_path,
        ] {
            if !enrolled.sample_paths.contains(path) {
                return fail("Reuse raw operand not enrolled in its physical interval");
            }
        }
        let admission_bytes = leaf(&paths.admission_path)?;
        let admission: ReuseSourceAdmissionV1 = strict_json(&admission_bytes, 128 * 1024)?;
        let gate: ReuseSourceGateV1 = strict_json(&leaf(&paths.gate_path)?, 128 * 1024)?;
        let ack: ReuseSourceAckV1 = strict_json(&leaf(&paths.ack_path)?, 128 * 1024)?;
        let report: ReuseSourceReportV1 = strict_json(&leaf(&paths.report_path)?, 128 * 1024)?;
        let held: ReuseHeldObjectsV1 = strict_json(&leaf(&paths.objects_path)?, 128 * 1024)?;
        let after: ReuseAfterObjectsV1 = strict_json(&leaf(&paths.after_path)?, 128 * 1024)?;
        if admission.schema_version != 1
            || admission.protocol != "candidate-owned-retirement-recovery-v1"
            || admission.source_revision_sha256 != reuse_source_revision_sha256()
            || admission.phase != phase
            || admission.selector != expected.selector
            || admission.parent_result_key != *expected.result_key
            || admission.challenge != challenge
            || admission.original_request_sha256 != hash_bytes(&request_bytes)
            || admission.installation_epoch != request.installation_epoch
            || admission.candidate_manifest_sha256 != request.candidate_manifest_sha256
            || admission.installed_inspection_sha256 != *installed_inspection_sha256
            || admission.service_generation_sha256 != request.service_generation_sha256
            || admission.helper != gate.helper
            || admission.admission_monotonic_ns < enrolled.begin_monotonic_ns
            || admission.admission_monotonic_ns > gate.observed_monotonic_ns
            || gate.admission_sha256 != hash_bytes(&admission_bytes)
            || gate.phase != phase
            || gate.challenge != challenge
            || gate.parent_result_key != *expected.result_key
            || report.before_bytes != attempt_bytes
            || report.marker_bytes != marker
            || report.original_observer_bytes != original.attachments[3]
            || report.actual_reuse_error != original_reuse_error
            || ack.schema_version != 1
            || ack.phase != phase
            || ack.source_revision_sha256 != reuse_source_revision_sha256()
            || ack.parent_result_key != *expected.result_key
            || ack.gate_sha256 != report.gate_sha256
            || after.observed_monotonic_ns > enrolled.end_monotonic_ns
        {
            return fail("Reuse exact original admission/gate/ACK/physical result join differs");
        }
        let pin = (
            held.directory_device,
            held.directory_inode,
            held.marker.clone(),
            held.record.clone(),
        );
        if prior_objects.as_ref().is_some_and(|prior| prior != &pin) {
            return fail("Reuse substitutes original pinned objects between intervals");
        }
        prior_objects = Some(pin);
        let clock: ProcClockInputsV1 = strict_json(&leaf(&paths.clock_path)?, 128 * 1024)?;
        let calibration = ParsedProcClockCalibrationV1::parse(&clock)?;
        let helper = crate::private_source_carrier::decode_held_source(
            &leaf(&paths.helper_path)?,
            |path| leaf(path),
        )?;
        let parsed = crate::private_kernel_replay::parse_capture_v2_with_budget(
            &leaf(&paths.capture_path)?,
            expected.result_key,
            CaptureStageV2::Candidate,
        )?;
        let events = parsed.events();
        let image_bytes = helper
            .leaves
            .get("image.raw")
            .ok_or_else(|| CiError::Message("Reuse actual held helper ELF absent".into()))?;
        let image: HelperImageV1 = strict_json(
            helper.leaves.get("image-metadata.json").ok_or_else(|| {
                CiError::Message("Reuse original held image metadata absent".into())
            })?,
            128 * 1024,
        )?;
        if hash_bytes(image_bytes) != *expected.fixture_sha256
            || image.sha256 != *expected.fixture_sha256
            || (image.device, image.inode) != (helper.executable_device, helper.executable_inode)
            || image.uid != 0
            || image.gid != 0
            || image.mode & 0o170000 != 0o100000
            || image.mode & 0o022 != 0
            || image.nlink != 1
            || image.size != image_bytes.len() as u64
        {
            return fail("Reuse kernel helper image differs from held protected ELF");
        }
        for name in ["stat-before.raw", "stat-after.raw"] {
            let stat = std::str::from_utf8(
                helper
                    .leaves
                    .get(name)
                    .ok_or_else(|| CiError::Message("Reuse helper original stat absent".into()))?,
            )
            .map_err(|_| CiError::Message("Reuse original proc stat not text".into()))?;
            if crate::private_supervisor::parse_linux_child_stat(stat, helper.pid)?.start_time_ticks
                != helper.start_time_ticks
            {
                return fail("Reuse helper raw start identity changed");
            }
        }
        if helper.pid != gate.helper.pid
            || helper.start_time_ticks != gate.helper.start_time_ticks
            || helper.executable_sha256 != *expected.fixture_sha256
            || helper.begin_monotonic_ns < gate.observed_monotonic_ns
            || helper.end_monotonic_ns > report.retry_begin_monotonic_ns
        {
            return fail("Reuse independent actual root helper identity differs");
        }
        let status = std::str::from_utf8(
            helper
                .leaves
                .get("status.raw")
                .ok_or_else(|| CiError::Message("Reuse helper actual status absent".into()))?,
        )
        .map_err(|_| CiError::Message("Reuse helper status not text".into()))?;
        for prefix in ["Uid:", "Gid:"] {
            let rows = status
                .lines()
                .filter_map(|line| line.strip_prefix(prefix))
                .collect::<Vec<_>>();
            let [row] = rows.as_slice() else {
                return fail("Reuse actual root helper credential field differs");
            };
            if row.split_whitespace().collect::<Vec<_>>() != ["0"; 4] {
                return fail("Reuse helper not actual root");
            }
        }
        let actual_argv = helper
            .leaves
            .get("cmdline.raw")
            .ok_or_else(|| CiError::Message("Reuse helper original argv absent".into()))?
            .split(|byte| *byte == 0)
            .filter(|part| !part.is_empty())
            .map(|part| {
                std::str::from_utf8(part)
                    .map(str::to_owned)
                    .map_err(|_| CiError::Message("Reuse helper argv not text".into()))
            })
            .collect::<Result<Vec<_>>>()?;
        let expected_argv = vec![
            expected
                .fixture_argv
                .first()
                .ok_or_else(|| CiError::Message("Reuse fixture executable path absent".into()))?
                .clone(),
            "release-case-reuse-source".into(),
            "candidate-capability".into(),
            expected.selector.into(),
            hex::encode(challenge),
            "--source-revision".into(),
            String::from(reuse_source_revision_sha256()),
            "--phase".into(),
            match phase {
                ReuseSourcePhaseV1::Blocked => "blocked",
                ReuseSourcePhaseV1::Recover => "recover",
            }
            .into(),
        ];
        if actual_argv != expected_argv {
            return fail("Reuse actual helper argv differs from exact enrolled source protocol");
        }
        let execs = events
            .iter()
            .filter(|event| {
                event.kind == 6
                    && event.task.tid == helper.pid
                    && event.image_dev == helper.executable_device
                    && event.image_inode == helper.executable_inode
                    && event.monotonic_ns <= helper.begin_monotonic_ns
                    && calibration.matches(
                        crate::private_kernel_observer::KernelTaskIdentityV1 {
                            pid: event.task.tid,
                            start_time: event.task.start_boottime_ns,
                            cgroup_inode: event.task.cgroup_inode,
                            time_ns_inode: event.task.time_ns_inode,
                        },
                        helper.start_time_ticks,
                    )
            })
            .collect::<Vec<_>>();
        let [exec] = execs.as_slice() else {
            return fail("Reuse actual root helper exec absent or ambiguous");
        };
        if events
            .iter()
            .any(|event| event.kind == 7 && event.task == exec.task)
        {
            return fail("Reuse source creates an unreviewed helper descendant");
        }
        if !events.iter().any(|fork| {
            fork.kind == 7 && fork.other_tid == helper.pid && fork.sequence < exec.sequence
        }) || !events.iter().any(|exit| {
            exit.kind == 8
                && exit.task == exec.task
                && exit.syscall_result == 0
                && exit.monotonic_ns > report.retry_end_monotonic_ns
                && events.iter().any(|reap| {
                    reap.kind == 9
                        && reap.other_tid == helper.pid
                        && reap.syscall_result as u64 == exec.task.start_boottime_ns
                        && reap.sequence > exit.sequence
                })
        }) {
            return fail("Reuse source helper lacks actual fork/clean exit/reap");
        }
        validate_reuse_kernel_operands_v1(events, &gate, &report, &held, &after)?;
        if phase == ReuseSourcePhaseV1::Recover {
            attempt.validate_owned_retirement_recovery(&after.current_bytes)?;
        }
    }
    Ok(())
}
