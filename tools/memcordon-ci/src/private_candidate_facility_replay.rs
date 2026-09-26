//! Original, versioned sacrificial-helper Facility conjunction. Neither the
//! native report nor a submitted operation buffer is an observer capability.
use crate::private_candidate_replay::{ExpectedCaseSubjectV1, ReplayTaskV1};
use crate::private_kernel_replay::{
    KernelEventRecordV2, KernelTaskIdentityV2, installed_kernel_filters,
};
use crate::private_observer_session::{ObserverEvidenceV1, ObserverStageV1, strict_json};
use crate::private_process_clock::{ParsedProcClockCalibrationV1, ProcClockInputsV1};
use crate::private_public_live::HeldPublicTargetSamplesV1;
use crate::{CiError, Result};
use memcordon_core::private_facility_source_v1::*;
use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeFacilitySourcesV1 {
    pub schema_version: u8,
    pub capture_path: String,
    pub clock_path: String,
    pub admission_path: String,
    pub report_path: String,
    pub outer_gate_path: String,
    pub outer_ack_path: String,
    pub outer_held_path: String,
    pub private_gate_path: String,
    pub private_ack_path: String,
    pub private_held_path: String,
    pub source_outer_held_path: Option<String>,
    pub source_private_held_path: Option<String>,
    /// Candidate cross-interval original product request, never a leaf claimed
    /// to have been observed in the earlier disposable-helper interval.
    pub product_request_path: Option<String>,
}
impl NativeFacilitySourcesV1 {
    fn sample_paths(&self) -> Vec<&str> {
        let mut paths = vec![
            self.clock_path.as_str(),
            self.admission_path.as_str(),
            self.report_path.as_str(),
            self.outer_gate_path.as_str(),
            self.outer_ack_path.as_str(),
            self.outer_held_path.as_str(),
            self.private_gate_path.as_str(),
            self.private_ack_path.as_str(),
            self.private_held_path.as_str(),
        ];
        paths.extend(self.source_outer_held_path.as_deref());
        paths.extend(self.source_private_held_path.as_deref());
        paths
    }
}
fn fail<T>(message: &str) -> Result<T> {
    Err(CiError::Message(message.into()))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Coordinator {
    pid: u32,
    start_time: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateAdmission {
    schema_version: u8,
    protocol: String,
    source_revision_sha256: DiagnosticSha256,
    parent_result_key: DiagnosticSha256,
    selector: String,
    challenge: [u8; 32],
    installation_epoch: DiagnosticSha256,
    candidate_manifest_sha256: DiagnosticSha256,
    filter_sha256: DiagnosticSha256,
    installed_inspection_sha256: DiagnosticSha256,
    service_generation_sha256: DiagnosticSha256,
    coordinator: Coordinator,
    admission_monotonic_ns: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateGate {
    schema_version: u8,
    phase: FacilityPhaseV1,
    parent_result_key: DiagnosticSha256,
    source_revision_sha256: DiagnosticSha256,
    admission_sha256: DiagnosticSha256,
    helper: FacilityProcessV1,
    objects: Vec<FacilityObjectV1>,
    status: Vec<u8>,
    observed_monotonic_ns: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicGate {
    schema_version: u8,
    selector: String,
    phase: FacilityPhaseV1,
    parent_result_key: DiagnosticSha256,
    source_revision_sha256: DiagnosticSha256,
    prepared_admission_sha256: DiagnosticSha256,
    installation_epoch: DiagnosticSha256,
    active_h1_receipt_sha256: DiagnosticSha256,
    manifest_sha256: DiagnosticSha256,
    qualification_sha256: DiagnosticSha256,
    helper: FacilityProcessV1,
    objects: Vec<FacilityObjectV1>,
    status: Vec<u8>,
    observed_monotonic_ns: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateAck {
    schema_version: u8,
    phase: FacilityPhaseV1,
    parent_result_key: DiagnosticSha256,
    source_revision_sha256: DiagnosticSha256,
    gate_sha256: DiagnosticSha256,
}
struct Gate {
    phase: FacilityPhaseV1,
    helper: FacilityProcessV1,
    objects: Vec<FacilityObjectV1>,
    status: Vec<u8>,
    observed: u64,
}
fn gate(
    stage: ObserverStageV1,
    bytes: &[u8],
    ack: &[u8],
    admission: &[u8],
    key: &DiagnosticSha256,
    selector: &str,
    generation: &crate::private_observer_session::ObservedGenerationV1,
) -> Result<Gate> {
    let revision = facility_source_revision_sha256();
    match stage {
        ObserverStageV1::Candidate => {
            let parsed: CandidateGate = strict_json(bytes, 128 * 1024)?;
            let receipt: CandidateAck = strict_json(ack, 4096)?;
            if parsed.schema_version != 1
                || parsed.parent_result_key != *key
                || parsed.source_revision_sha256 != revision
                || parsed.admission_sha256 != hash_bytes(admission)
                || receipt.schema_version != 1
                || receipt.phase != parsed.phase
                || receipt.parent_result_key != *key
                || receipt.source_revision_sha256 != revision
                || receipt.gate_sha256 != hash_bytes(bytes)
            {
                return fail("candidate Facility gate/ACK exact admission differs");
            }
            Ok(Gate {
                phase: parsed.phase,
                helper: parsed.helper,
                objects: parsed.objects,
                status: parsed.status,
                observed: parsed.observed_monotonic_ns,
            })
        }
        ObserverStageV1::Public => {
            let parsed: PublicGate = strict_json(bytes, 128 * 1024)?;
            if parsed.schema_version != 1
                || parsed.parent_result_key != *key
                || parsed.selector != selector
                || parsed.source_revision_sha256 != revision
                || parsed.prepared_admission_sha256 != hash_bytes(admission)
                || parsed.installation_epoch != generation.installation_epoch
                || parsed.manifest_sha256 != generation.installed_manifest_sha256
                || parsed.active_h1_receipt_sha256 != generation.installed_receipt_sha256
                || parsed.qualification_sha256.bytes().iter().all(|v| *v == 0)
                || ack != hash_bytes(bytes).bytes()
            {
                return fail("public Facility gate/ACK exact approved generation differs");
            }
            Ok(Gate {
                phase: parsed.phase,
                helper: parsed.helper,
                objects: parsed.objects,
                status: parsed.status,
                observed: parsed.observed_monotonic_ns,
            })
        }
    }
}

/// Capability boundary: all sources belong to the same enrolled immutable
/// interval. Candidate controls are physically separate; public helper calls
/// are an explicit pre-target conjunction in the ordinary public interval.
pub(crate) fn verify_facility_source(
    session: &impl ObserverEvidenceV1,
    expected: &ExpectedCaseSubjectV1<'_>,
    product_target: &ReplayTaskV1,
    product_capture_path: &str,
    generation: u32,
    sources: &NativeFacilitySourcesV1,
) -> Result<()> {
    if session.descriptor().subject.stage == ObserverStageV1::Candidate {
        let request = sources.product_request_path.as_ref().ok_or_else(|| {
            CiError::Message("candidate Facility original product request absent".into())
        })?;
        let records = session
            .descriptor()
            .intervals
            .iter()
            .filter(|record| record.capture_path == product_capture_path)
            .collect::<Vec<_>>();
        let [record] = records.as_slice() else {
            return fail("candidate Facility product physical interval absent or duplicated");
        };
        let auxiliary = session
            .descriptor()
            .intervals
            .iter()
            .filter(|entry| entry.capture_path == sources.capture_path)
            .collect::<Vec<_>>();
        let [auxiliary] = auxiliary.as_slice() else {
            return fail("candidate Facility auxiliary interval absent or duplicated");
        };
        if record.generation != generation
            || record.logical_case_key != *expected.result_key
            || !record.sample_paths.contains(request)
            || auxiliary.detach_monotonic_ns > record.arm_monotonic_ns
            || auxiliary.capture_path == record.capture_path
        {
            return fail(
                "candidate Facility product request is not independently enrolled after closed auxiliary lifetime",
            );
        }
    }
    let interval =
        crate::private_candidate_replay::replay_observer_interval(session, &sources.capture_path)?;
    validate_sources(
        session.descriptor(),
        expected,
        product_target,
        product_capture_path,
        generation,
        sources,
        interval.events(),
        &|path| Ok(session.leaf(path)?.to_vec()),
    )
}

/// Claimed facts only, not a capability. Immutable replay later independently
/// re-authenticates capture, calibration controls, generation and every leaf.
pub(crate) fn record_facility_source_facts(
    descriptor: &crate::private_observer_session::ObserverSessionDescriptorV1,
    expected: &ExpectedCaseSubjectV1<'_>,
    product_target: &ReplayTaskV1,
    product_capture_path: &str,
    generation: u32,
    sources: NativeFacilitySourcesV1,
    events: &[KernelEventRecordV2],
    leaf: impl Fn(&str) -> Result<Vec<u8>>,
) -> Result<Vec<crate::private_candidate_replay::CaseFactV1>> {
    validate_sources(
        descriptor,
        expected,
        product_target,
        product_capture_path,
        generation,
        &sources,
        events,
        &leaf,
    )?;
    use crate::private_candidate_replay::CaseFactV1;
    Ok(vec![match descriptor.subject.stage {
        ObserverStageV1::Candidate => CaseFactV1::NativeFacilityV1 { sources },
        ObserverStageV1::Public => CaseFactV1::PublicFacilityV1 { sources },
    }])
}

fn validate_sources(
    descriptor: &crate::private_observer_session::ObserverSessionDescriptorV1,
    expected: &ExpectedCaseSubjectV1<'_>,
    product_target: &ReplayTaskV1,
    product_capture_path: &str,
    generation: u32,
    sources: &NativeFacilitySourcesV1,
    events: &[KernelEventRecordV2],
    leaf: &impl Fn(&str) -> Result<Vec<u8>>,
) -> Result<()> {
    if sources.schema_version != 1
        || expected.facility_source_sha256 != Some(&facility_source_revision_sha256())
    {
        return fail("Facility source version or independently protected opt-in differs");
    }
    let paths = sources.sample_paths();
    if paths.iter().copied().collect::<BTreeSet<_>>().len() != paths.len()
        || paths.contains(&sources.capture_path.as_str())
    {
        return fail("Facility original leaf paths alias");
    }
    let records = descriptor
        .intervals
        .iter()
        .filter(|record| record.capture_path == sources.capture_path)
        .collect::<Vec<_>>();
    let [record] = records.as_slice() else {
        return fail("Facility enrolled physical interval absent or ambiguous");
    };
    let stage = descriptor.subject.stage;
    if record.generation != generation
        || record.logical_case_key != *expected.result_key
        || paths
            .iter()
            .any(|path| !record.sample_paths.iter().any(|value| value == path))
        || stage == ObserverStageV1::Candidate && record.purpose != "facility-controls"
        || stage == ObserverStageV1::Public
            && (record.purpose != "ordinary" || sources.capture_path != product_capture_path)
    {
        return fail("Facility source stage/purpose/generation/original inventory differs");
    }
    let clock: ProcClockInputsV1 = strict_json(&leaf(&sources.clock_path)?, 128 * 1024)?;
    let report: FacilitySourceReportV1 = strict_json(&leaf(&sources.report_path)?, 128 * 1024)?;
    let admission = leaf(&sources.admission_path)?;
    let enrolled = descriptor
        .generations
        .iter()
        .find(|entry| entry.generation == generation)
        .ok_or_else(|| CiError::Message("Facility generation absent".into()))?;
    let coordinator = match stage {
        ObserverStageV1::Candidate => {
            let parsed: CandidateAdmission = strict_json(&admission, 128 * 1024)?;
            if parsed.schema_version != 1
                || parsed.protocol != "candidate-independent-facility-source-v1"
                || parsed.source_revision_sha256 != facility_source_revision_sha256()
                || parsed.parent_result_key != *expected.result_key
                || parsed.selector != expected.selector
                || parsed.challenge.as_slice() != expected.challenge
                || parsed.installation_epoch != enrolled.installation_epoch
                || parsed.candidate_manifest_sha256 != enrolled.installed_manifest_sha256
                || parsed.filter_sha256 != *expected.filter_sha256
                || parsed.installed_inspection_sha256 != enrolled.installed_receipt_sha256
                || parsed
                    .service_generation_sha256
                    .bytes()
                    .iter()
                    .all(|v| *v == 0)
                || parsed.admission_monotonic_ns < record.begin_monotonic_ns
                || parsed.admission_monotonic_ns > record.end_monotonic_ns
            {
                return fail("candidate Facility protected current admission differs");
            }
            let path = sources.product_request_path.as_ref().ok_or_else(|| {
                CiError::Message("candidate Facility original product request absent".into())
            })?;
            if paths.contains(&path.as_str()) || path == &sources.capture_path {
                return fail("candidate Facility product request aliases auxiliary sources");
            }
            let product: crate::private_protected_readback::ProtectedCandidateReleaseRequestV1 =
                strict_json(&leaf(path)?, 128 * 1024)?;
            if product.schema_version != 1
                || product.stage != "candidate-capability"
                || product.selector != expected.selector
                || product.result_key != *expected.result_key
                || product.challenge != hex::encode(expected.challenge)
                || product.installation_epoch != parsed.installation_epoch
                || product.candidate_manifest_sha256 != parsed.candidate_manifest_sha256
                || product.service_generation_sha256 != parsed.service_generation_sha256
            {
                return fail(
                    "candidate Facility original product request/current native generation differs",
                );
            }
            Some(parsed.coordinator)
        }
        ObserverStageV1::Public => {
            if sources.product_request_path.is_some() {
                return fail("public Facility cannot accept a candidate product request carrier");
            }
            use memcordon_core::private_public_preparation_v2::{
                PreparedPublicDispatchRecordV2, PublicPreparedRoleV2,
            };
            let parsed: PreparedPublicDispatchRecordV2 = strict_json(&admission, 2 * 1024 * 1024)?;
            let nonce = hex::decode(&descriptor.session_nonce)
                .map_err(|_| CiError::Message("Facility origin nonce invalid".into()))?;
            if parsed.schema_version != 2
                || parsed.static_suite_sha256 != descriptor.subject.intent_sha256
                || parsed.session_nonce.as_slice() != nonce
                || parsed.generation != generation
                || parsed.role != PublicPreparedRoleV2::Ordinary
                || parsed.selector != expected.selector
                || parsed.challenge.as_slice() != expected.challenge
                || parsed.result_key != *expected.result_key
                || parsed.installation_epoch != enrolled.installation_epoch
                || parsed.active_h1_receipt_sha256 != enrolled.installed_receipt_sha256
            {
                return fail("public Facility immutable preparation/current origin differs");
            }
            None
        }
    };
    let outer = gate(
        stage,
        &leaf(&sources.outer_gate_path)?,
        &leaf(&sources.outer_ack_path)?,
        &admission,
        expected.result_key,
        expected.selector,
        enrolled,
    )?;
    let private = gate(
        stage,
        &leaf(&sources.private_gate_path)?,
        &leaf(&sources.private_ack_path)?,
        &admission,
        expected.result_key,
        expected.selector,
        enrolled,
    )?;
    let decode = |path: &str| {
        crate::private_source_carrier::decode_held_source(&leaf(path)?, |image| leaf(image))
    };
    let outer_held = decode(&sources.outer_held_path)?;
    let private_held = decode(&sources.private_held_path)?;
    let source_outer = sources
        .source_outer_held_path
        .as_deref()
        .map(decode)
        .transpose()?;
    let source_private = sources
        .source_private_held_path
        .as_deref()
        .map(decode)
        .transpose()?;
    for sample in [&outer_held, &private_held]
        .into_iter()
        .chain(source_outer.iter())
        .chain(source_private.iter())
    {
        if sample.begin_monotonic_ns < record.begin_monotonic_ns
            || sample.end_monotonic_ns > record.end_monotonic_ns
        {
            return fail("Facility held source outside actual operation interval");
        }
    }
    let end = validate_facility_conjunction(
        events,
        &clock,
        &report,
        &outer,
        &private,
        &outer_held,
        &private_held,
        source_outer.as_ref(),
        source_private.as_ref(),
        expected,
        stage,
        coordinator.as_ref(),
    )?;
    if stage == ObserverStageV1::Public {
        let execs = events
            .iter()
            .filter(|event| event.kind == 6 && task_matches(product_target, &event.task))
            .collect::<Vec<_>>();
        let [exec] = execs.as_slice() else {
            return fail("public Facility ordinary target Exec absent or duplicated");
        };
        if end >= exec.monotonic_ns || report.helper.pid == product_target.tid {
            return fail("public Facility exception lifecycle overlaps product clean entry");
        }
    } else if events.iter().any(|event| event.kind == 3) {
        return fail("candidate independent Facility interval allocated a product attempt");
    }
    Ok(())
}

/// Portable diagnostics only. This never authenticates an observer origin or
/// creates a qualification capability; immutable replay performs those checks.
pub fn validate_capture_facility_source(
    descriptor: &crate::private_observer_session::ObserverSessionDescriptorV1,
    expected: &ExpectedCaseSubjectV1<'_>,
    product_target: &ReplayTaskV1,
    product_capture_path: &str,
    generation: u32,
    sources: &NativeFacilitySourcesV1,
    leaves: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    let leaf = |path: &str| {
        leaves
            .get(path)
            .cloned()
            .ok_or_else(|| CiError::Message(format!("Facility diagnostic leaf absent: {path}")))
    };
    let stage = match descriptor.subject.stage {
        ObserverStageV1::Candidate => crate::private_kernel_replay::CaptureStageV2::Candidate,
        ObserverStageV1::Public => crate::private_kernel_replay::CaptureStageV2::FinalPublic,
    };
    let capture = crate::private_kernel_replay::parse_capture_v2_with_budget(
        &leaf(&sources.capture_path)?,
        expected.result_key,
        stage,
    )?;
    validate_sources(
        descriptor,
        expected,
        product_target,
        product_capture_path,
        generation,
        sources,
        capture.events(),
        &leaf,
    )
}

fn task_matches(target: &ReplayTaskV1, task: &KernelTaskIdentityV2) -> bool {
    target.tid == task.tid
        && target.tgid == task.tgid
        && target.start_boottime_ns == task.start_boottime_ns
        && target.cgroup_inode == task.cgroup_inode
        && target.time_ns_inode == task.time_ns_inode
}
fn scalar(raw: &[u8], name: &str) -> Result<Vec<u64>> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| CiError::Message("Facility raw scalar is not text".into()))?;
    let rows = text
        .lines()
        .filter_map(|line| line.strip_prefix(name))
        .collect::<Vec<_>>();
    let [row] = rows.as_slice() else {
        return fail("Facility raw scalar absent or duplicated");
    };
    row.split_whitespace()
        .map(|value| {
            value
                .parse()
                .map_err(|_| CiError::Message("Facility raw scalar invalid".into()))
        })
        .collect()
}

/// Live proc counters are intentionally not compared as whole status bytes.
/// Both original sources remain retained; only closed identity/filter scalars
/// are joined here, without minting an observer or operation capability.
pub fn validate_facility_status_join(gate_status: &[u8], held_status: &[u8]) -> Result<()> {
    if gate_status.len() > 128 * 1024 || held_status.len() > 128 * 1024 {
        return fail("Facility status source exceeds bound");
    }
    for (name, count) in [
        ("Pid:", 1),
        ("Tgid:", 1),
        ("Uid:", 4),
        ("Gid:", 4),
        ("NoNewPrivs:", 1),
        ("Seccomp:", 1),
        ("Seccomp_filters:", 1),
    ] {
        let gate = scalar(gate_status, name)?;
        let held = scalar(held_status, name)?;
        if gate.len() != count || held.len() != count || gate != held {
            return fail("Facility original status identity/filter scalars differ");
        }
    }
    if scalar(held_status, "Uid:")? != [0; 4]
        || scalar(held_status, "Gid:")? != [0; 4]
        || scalar(held_status, "NoNewPrivs:")? != [1]
        || scalar(held_status, "Seccomp:")? != [2]
        || scalar(held_status, "Seccomp_filters:")?[0] == 0
    {
        return fail("Facility root helper installed status differs");
    }
    Ok(())
}
fn sample_leaf<'a>(sample: &'a HeldPublicTargetSamplesV1, path: &str) -> Result<&'a [u8]> {
    sample
        .leaves
        .get(path)
        .map(Vec::as_slice)
        .ok_or_else(|| CiError::Message(format!("Facility actual held leaf absent: {path}")))
}
fn sampled_object(sample: &HeldPublicTargetSamplesV1, object: &FacilityObjectV1) -> Result<()> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Identity {
        fd: i32,
        link: String,
        device: u64,
        inode: u64,
        mode: u32,
    }
    let prefix = std::path::Path::new("tasks")
        .join(sample.pid.to_string())
        .join("fds")
        .join(object.fd.to_string());
    let identity: Identity = strict_json(
        sample_leaf(
            sample,
            prefix
                .join("identity.json")
                .to_str()
                .expect("numeric fd path"),
        )?,
        8192,
    )?;
    let info = sample_leaf(
        sample,
        prefix.join("fdinfo.raw").to_str().expect("numeric fd path"),
    )?;
    if identity.fd != object.fd
        || identity.device != object.device
        || identity.inode != object.inode
        || identity.inode == 0
        || identity.mode & 0o170000 == 0
        || identity.link.is_empty()
        || info != object.fdinfo
    {
        return fail("Facility independently held descriptor object differs");
    }
    Ok(())
}
fn held_identity(
    sample: &HeldPublicTargetSamplesV1,
    process: &FacilityProcessV1,
    task: &KernelTaskIdentityV2,
    clock: &ProcClockInputsV1,
    expected: &ExpectedCaseSubjectV1<'_>,
    stage: ObserverStageV1,
    count: Option<u32>,
) -> Result<()> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Image {
        device: u64,
        inode: u64,
        uid: u32,
        gid: u32,
        mode: u32,
        nlink: u64,
        size: u64,
        sha256: DiagnosticSha256,
    }
    let image: Image = strict_json(sample_leaf(sample, "image-metadata.json")?, 8192)?;
    let calibration = ParsedProcClockCalibrationV1::parse(clock)?;
    if sample.schema_version != 1
        || sample.pid != process.pid
        || sample.start_time_ticks != process.start_time_ticks
        || sample.tasks.len() != 1
        || sample.tasks[0].tid != process.pid
        || sample.tasks[0].tgid != process.pid
        || sample.tasks[0].start_time_ticks != process.start_time_ticks
        || task.tid != process.pid
        || task.tgid != process.pid
        || sample.begin_monotonic_ns == 0
        || sample.end_monotonic_ns < sample.begin_monotonic_ns
        || !calibration.matches(
            crate::private_kernel_observer::KernelTaskIdentityV1 {
                pid: process.pid,
                start_time: task.start_boottime_ns,
                cgroup_inode: task.cgroup_inode,
                time_ns_inode: task.time_ns_inode,
            },
            process.start_time_ticks,
        )
        || sample.executable_sha256 != *expected.fixture_sha256
        || hash_bytes(sample_leaf(sample, "image.raw")?) != *expected.fixture_sha256
        || sample.executable_inode == 0
        || sample.executable_device == 0
    {
        return fail("Facility independent root helper image/task/original clock differs");
    }
    if image.device != sample.executable_device
        || image.inode != sample.executable_inode
        || image.uid != 0
        || image.gid != 0
        || image.mode & 0o170000 != 0o100000
        || image.mode & 0o022 != 0
        || image.nlink != 1
        || image.size != sample_leaf(sample, "image.raw")?.len() as u64
        || image.sha256 != *expected.fixture_sha256
    {
        return fail("Facility independently held installed image protection differs");
    }
    let raw = sample_leaf(sample, "status.raw")?;
    if scalar(raw, "Uid:")? != [0; 4]
        || scalar(raw, "Gid:")? != [0; 4]
        || scalar(raw, "Pid:")? != [u64::from(process.pid)]
        || scalar(raw, "Tgid:")? != [u64::from(process.pid)]
    {
        return fail("Facility actual helper root identity differs");
    }
    if let Some(count) = count {
        let target = ReplayTaskV1 {
            tid: task.tid,
            tgid: task.tgid,
            start_boottime_ns: task.start_boottime_ns,
            cgroup_inode: task.cgroup_inode,
            time_ns_inode: task.time_ns_inode,
        };
        super::private_candidate_filter_facility_facts::check_sample(
            sample, &target, clock, count,
        )?;
    }
    let cmdline = sample_leaf(sample, "cmdline.raw")?;
    if !cmdline.ends_with(&[0]) {
        return fail("Facility original argv is not terminated");
    }
    let argv = cmdline[..cmdline.len() - 1]
        .split(|byte| *byte == 0)
        .collect::<Vec<_>>();
    let image = expected.fixture_argv.first().ok_or_else(|| {
        CiError::Message("Facility independently reviewed image path absent".into())
    })?;
    let stage = match stage {
        ObserverStageV1::Candidate => "candidate-capability",
        ObserverStageV1::Public => "final-public",
    };
    let challenge = hex::encode(expected.challenge);
    let revision = String::from(facility_source_revision_sha256());
    let expected_argv = [
        image.as_str(),
        "release-facility-controls",
        stage,
        expected.selector,
        challenge.as_str(),
        "--source-revision",
        revision.as_str(),
    ];
    if argv != expected_argv.map(str::as_bytes) {
        return fail("Facility independently reviewed fixed root argv differs");
    }
    Ok(())
}
fn actual_return<'a>(
    events: &'a [KernelEventRecordV2],
    entry: &KernelEventRecordV2,
) -> Result<&'a KernelEventRecordV2> {
    let matches = events
        .iter()
        .filter(|event| {
            event.kind == 5
                && event.task == entry.task
                && event.syscall_occurrence == entry.syscall_occurrence
                && event.syscall_arch == entry.syscall_arch
                && event.syscall_nr == entry.syscall_nr
                && event.args == entry.args
                && event.sequence > entry.sequence
        })
        .collect::<Vec<_>>();
    let [result] = matches.as_slice() else {
        return fail("Facility exact actual return absent or duplicated");
    };
    Ok(result)
}
fn lifetime(
    events: &[KernelEventRecordV2],
    process: &FacilityProcessV1,
    task: &KernelTaskIdentityV2,
    parent: &KernelTaskIdentityV2,
    after: u64,
) -> Result<u64> {
    let exits = events
        .iter()
        .filter(|event| event.kind == 8 && event.task == *task)
        .collect::<Vec<_>>();
    let [exit] = exits.as_slice() else {
        return fail("Facility owned process Exit absent or duplicated");
    };
    let reaps = events
        .iter()
        .filter(|event| {
            event.kind == 9
                && event.task == *parent
                && event.other_tid == process.pid
                && u64::try_from(event.syscall_result).ok() == Some(task.start_boottime_ns)
        })
        .collect::<Vec<_>>();
    let [reap] = reaps.as_slice() else {
        return fail("Facility owned process Reap absent or duplicated");
    };
    if exit.monotonic_ns <= after
        || exit.syscall_result != 0
        || reap.sequence <= exit.sequence
        || reap.monotonic_ns < exit.monotonic_ns
    {
        return fail("Facility actual success wait/lifecycle ordering differs");
    }
    Ok(reap.monotonic_ns)
}

fn validate_facility_conjunction(
    events: &[KernelEventRecordV2],
    clock: &ProcClockInputsV1,
    report: &FacilitySourceReportV1,
    outer: &Gate,
    private: &Gate,
    outer_held: &HeldPublicTargetSamplesV1,
    private_held: &HeldPublicTargetSamplesV1,
    source_outer: Option<&HeldPublicTargetSamplesV1>,
    source_private: Option<&HeldPublicTargetSamplesV1>,
    expected: &ExpectedCaseSubjectV1<'_>,
    stage: ObserverStageV1,
    coordinator: Option<&Coordinator>,
) -> Result<u64> {
    validate_facility_source_shape(report).map_err(|message| CiError::Message(message.into()))?;
    if report.parent_result_key != *expected.result_key
        || report.selector != expected.selector
        || report.private_filter_sha256 != *expected.filter_sha256
        || outer.phase != FacilityPhaseV1::Outer
        || private.phase != FacilityPhaseV1::Private
        || outer.helper != report.helper
        || private.helper != report.helper
        || outer.status != report.status_after_outer_install
        || private.status != report.status_after_private_install
        || outer.observed == 0
        || outer.observed > outer_held.begin_monotonic_ns
        || private.observed > private_held.begin_monotonic_ns
        || outer_held.end_monotonic_ns >= report.calls[0].before_monotonic_ns
        || private_held.end_monotonic_ns >= report.calls[report.calls.len() / 2].before_monotonic_ns
    {
        return fail("Facility independently held phase/report/subject ordering differs");
    }
    let all = installed_kernel_filters(events)?;
    let installs = all
        .iter()
        .filter(|filter| filter.task.tid == report.helper.pid)
        .collect::<Vec<_>>();
    let [first, second] = installs.as_slice() else {
        return fail("Facility helper needs two actual installed programs");
    };
    if first.task != second.task
        || first.instructions != outer_allow_program_v1()
        || first.instructions_sha256 != report.outer_filter_sha256
        || second.instructions_sha256 != *expected.filter_sha256
        || first.filter_identity != second.previous_filter_identity
        || first.count_before.checked_add(1) != Some(first.count_after)
        || first.count_after != second.count_before
        || second.count_before.checked_add(1) != Some(second.count_after)
        || first.installed_sequence >= second.install_sequence
    {
        return fail("Facility actual noop/private kernel install/count/identity chain differs");
    }
    let task = &first.task;
    let installed_time = |sequence| {
        events
            .iter()
            .find(|event| event.sequence == sequence)
            .map(|event| event.monotonic_ns)
            .ok_or_else(|| CiError::Message("Facility actual install endpoint absent".into()))
    };
    let operations = facility_operations_v1(expected.selector)
        .map_err(|message| CiError::Message(message.into()))?;
    if installed_time(first.installed_sequence)? > outer.observed
        || installed_time(second.install_sequence)?
            <= report.calls[operations.len() - 1].after_monotonic_ns
        || installed_time(second.installed_sequence)? > private.observed
    {
        return fail("Facility actual install/held/operation phase ordering differs");
    }
    for (gate, count) in [(outer, first.count_after), (private, second.count_after)] {
        if scalar(&gate.status, "NoNewPrivs:")? != [1]
            || scalar(&gate.status, "Seccomp:")? != [2]
            || scalar(&gate.status, "Seccomp_filters:")? != [u64::from(count)]
        {
            return fail("Facility native held status differs from installed kernel program count");
        }
    }
    held_identity(
        outer_held,
        &report.helper,
        task,
        clock,
        expected,
        stage,
        Some(first.count_after),
    )?;
    validate_facility_status_join(&outer.status, sample_leaf(outer_held, "status.raw")?)?;
    validate_facility_status_join(&private.status, sample_leaf(private_held, "status.raw")?)?;
    if (outer_held.executable_device, outer_held.executable_inode)
        != (
            private_held.executable_device,
            private_held.executable_inode,
        )
    {
        return fail("Facility helper executable object changed between phases");
    }
    held_identity(
        private_held,
        &report.helper,
        task,
        clock,
        expected,
        stage,
        Some(second.count_after),
    )?;
    let parent_forks = events
        .iter()
        .filter(|event| {
            event.kind == 7
                && event.other_tid == task.tid
                && u64::try_from(event.syscall_result).ok() == Some(task.start_boottime_ns)
                && event.sequence < first.install_sequence
        })
        .collect::<Vec<_>>();
    let [fork] = parent_forks.as_slice() else {
        return fail("Facility actual owned helper fork absent or duplicated");
    };
    if events.iter().any(|event| {
        event.task == *task
            && event.kind == 7
            && Some(event.other_tid) != report.source_process.as_ref().map(|source| source.pid)
    }) {
        return fail("Facility helper created an unreviewed descendant");
    }
    if let Some(coordinator) = coordinator {
        if fork.task.tid != coordinator.pid
            || !ParsedProcClockCalibrationV1::parse(clock)?.matches(
                crate::private_kernel_observer::KernelTaskIdentityV1 {
                    pid: fork.task.tid,
                    start_time: fork.task.start_boottime_ns,
                    cgroup_inode: fork.task.cgroup_inode,
                    time_ns_inode: fork.task.time_ns_inode,
                },
                coordinator.start_time,
            )
        {
            return fail("Facility actual native coordinator admission/fork differs");
        }
    }
    let outer_objects = outer
        .objects
        .iter()
        .map(|object| (object.fd, object))
        .collect::<BTreeMap<_, _>>();
    let private_objects = private
        .objects
        .iter()
        .map(|object| (object.fd, object))
        .collect::<BTreeMap<_, _>>();
    if outer_objects.len() != outer.objects.len() || private_objects.len() != private.objects.len()
    {
        return fail("Facility held descriptor roles alias");
    }
    for object in &outer.objects {
        sampled_object(outer_held, object)?;
        let next = private_objects.get(&object.fd).ok_or_else(|| {
            CiError::Message("Facility valid context disappeared before private phase".into())
        })?;
        if object != *next {
            return fail("Facility held valid context changed between phases");
        }
    }
    for object in &private.objects {
        sampled_object(private_held, object)?;
    }
    let outer_netns = outer_held.tasks[0]
        .namespace_inodes
        .get("net")
        .copied()
        .ok_or_else(|| CiError::Message("Facility outer netns source absent".into()))?;
    let private_netns = private_held.tasks[0]
        .namespace_inodes
        .get("net")
        .copied()
        .ok_or_else(|| CiError::Message("Facility private netns source absent".into()))?;
    if report.calls[0].namespace_before != outer_netns
        || report.calls[operations.len() - 1].namespace_after != private_netns
        || report.calls[..operations.len()]
            .windows(2)
            .any(|calls| calls[0].namespace_after != calls[1].namespace_before)
        || report.calls[operations.len()..].iter().any(|call| {
            call.namespace_before != private_netns || call.namespace_after != private_netns
        })
        || report.calls.iter().any(|call| {
            call.operation != FacilityOperationV1::Unshare
                && call.namespace_before != call.namespace_after
        })
    {
        return fail("Facility independently held actual namespace/context continuity differs");
    }
    let mut result_lifetimes = BTreeMap::new();
    for (index, call) in report.calls.iter().enumerate() {
        let filter = if index < operations.len() {
            *first
        } else {
            *second
        };
        let entries = events
            .iter()
            .filter(|event| {
                event.kind == 4
                    && event.task == *task
                    && event.syscall_arch == call.audit_arch
                    && event.syscall_nr == call.syscall_nr
                    && event.args == call.args
                    && event.monotonic_ns >= call.before_monotonic_ns
                    && event.monotonic_ns <= call.after_monotonic_ns
            })
            .collect::<Vec<_>>();
        let [entry] = entries.as_slice() else {
            return fail("Facility actual decision/call operands absent or duplicated");
        };
        let returned = actual_return(events, entry)?;
        let outer_call = call.phase == FacilityPhaseV1::Outer;
        if entry.sequence <= filter.installed_sequence
            || returned.monotonic_ns > call.after_monotonic_ns
            || returned.syscall_result
                != if outer_call {
                    call.result
                } else {
                    -i64::from(call.errno)
                }
            || entry.seccomp_action != if outer_call { 0x7fff0000 } else { 0x50000 }
            || !outer_call && entry.syscall_result != i64::from(call.errno)
            || !events.iter().any(|identity| {
                identity.kind == 13
                    && identity.seccomp_action == 2
                    && identity.task == *task
                    && identity.syscall_occurrence == entry.syscall_occurrence
                    && identity.image_dev == filter.filter_identity
                    && identity.image_inode == filter.previous_filter_identity
                    && identity.sequence < entry.sequence
            })
            || outer_call && returned.sequence >= second.install_sequence
        {
            return fail("Facility actual installed action/return/filter identity differs");
        }
        if outer_call {
            let successful_fds = match &call.operand {
                FacilityOperandV1::Socketpair { slots_after, .. } => slots_after.to_vec(),
                _ if matches!(
                    call.operation,
                    FacilityOperationV1::Socket
                        | FacilityOperationV1::IoUringSetup
                        | FacilityOperationV1::PidfdGetfd
                ) =>
                {
                    vec![i32::try_from(call.result).map_err(|_| {
                        CiError::Message("Facility result FD exceeds native range".into())
                    })?]
                }
                _ => Vec::new(),
            };
            for fd in successful_fds {
                if outer_objects.contains_key(&fd) || !private_objects.contains_key(&fd) {
                    return fail("Facility successful result object not independently held");
                }
                if result_lifetimes.insert(fd, returned.sequence).is_some() {
                    return fail("Facility operation result descriptor was reused");
                }
            }
        }
        match &call.operand {
            FacilityOperandV1::Descriptor { object, source, .. } => {
                if outer_objects.get(&object.fd) != Some(&object) {
                    return fail("Facility operation descriptor outside exact held context");
                }
                if let Some(source) = source {
                    if outer_objects.get(&source.fd) != Some(&source) {
                        return fail("Facility source descriptor outside exact held context");
                    }
                }
            }
            FacilityOperandV1::ScmRights {
                socket,
                source,
                transferred_device,
                transferred_inode,
                ..
            } => {
                if outer_objects.get(&socket.fd) != Some(&socket)
                    || outer_objects.get(&source.fd) != Some(&source)
                {
                    return fail("Facility SCM descriptor outside exact held context");
                }
                if outer_call
                    && private
                        .objects
                        .iter()
                        .filter(|object| {
                            object.role == "transferred-source"
                                && Some(object.device) == *transferred_device
                                && Some(object.inode) == *transferred_inode
                        })
                        .count()
                        != 1
                {
                    return fail("Facility actual transferred SCM object not independently held");
                }
                if outer_call {
                    let receiver = outer
                        .objects
                        .iter()
                        .find(|object| object.role == "scm-receive")
                        .ok_or_else(|| {
                            CiError::Message("Facility live SCM receiver absent".into())
                        })?;
                    let nr = if call.audit_arch == 0xc000003e {
                        47
                    } else {
                        212
                    };
                    let received = events
                        .iter()
                        .filter(|event| {
                            event.kind == 4
                                && event.task == *task
                                && event.syscall_arch == call.audit_arch
                                && event.syscall_nr == nr
                                && event.args[0] == receiver.fd as u64
                                && event.args[1] != 0
                                && event.args[2] == 0x40000040
                                && event.sequence > returned.sequence
                                && event.sequence < second.install_sequence
                        })
                        .collect::<Vec<_>>();
                    let [receive] = received.as_slice() else {
                        return fail(
                            "Facility actual valid-context SCM receive absent or duplicated",
                        );
                    };
                    if receive.seccomp_action != 0x7fff0000
                        || actual_return(events, receive)?.syscall_result != 1
                    {
                        return fail("Facility actual outer SCM transfer did not complete");
                    }
                }
            }
            _ => {}
        }
    }
    let last_call = report
        .calls
        .last()
        .expect("closed Facility operations")
        .after_monotonic_ns;
    let closes = report
        .closes
        .iter()
        .map(|close| (close.object.fd, close))
        .collect::<BTreeMap<_, _>>();
    if closes.len() != report.closes.len() || closes.len() != private_objects.len() {
        return fail("Facility every held exception needs exactly one close");
    }
    for (fd, object) in &private_objects {
        let close = closes
            .get(fd)
            .ok_or_else(|| CiError::Message("Facility held exception was not closed".into()))?;
        if close.object.fd != object.fd
            || close.object.role != object.role
            || close.object.device != object.device
            || close.object.inode != object.inode
        {
            return fail("Facility close object differs from held exception");
        }
        let nr = if report.calls[0].audit_arch == 0xc000003e {
            3
        } else {
            57
        };
        let entries = events
            .iter()
            .filter(|event| {
                matches!(event.kind, 4 | 11)
                    && event.task == *task
                    && event.syscall_nr == nr
                    && event.syscall_arch == report.calls[0].audit_arch
                    && event.args[0] == *fd as u64
                    && event.monotonic_ns >= close.before_monotonic_ns
                    && event.monotonic_ns <= close.after_monotonic_ns
            })
            .collect::<Vec<_>>();
        let [entry] = entries.as_slice() else {
            return fail("Facility exact exception close syscall absent or duplicated");
        };
        let returned = actual_return(events, entry)?;
        if returned.syscall_result != 0 || returned.monotonic_ns > close.after_monotonic_ns {
            return fail("Facility actual exception close did not succeed");
        }
        if events.iter().any(|event| {
            event.task == *task
                && matches!(event.kind, 4 | 11)
                && event.sequence
                    > result_lifetimes
                        .get(fd)
                        .copied()
                        .unwrap_or(first.installed_sequence)
                && event.monotonic_ns < close.before_monotonic_ns
                && event.syscall_nr == nr
                && event.args[0] == *fd as u64
        }) {
            return fail("Facility held descriptor closed/reused before acknowledged cleanup");
        }
    }
    let mut end = report
        .closes
        .iter()
        .map(|close| close.after_monotonic_ns)
        .max()
        .expect("nonempty Facility closes");
    if let Some(process) = &report.source_process {
        let (Some(before), Some(after)) = (source_outer, source_private) else {
            return fail("Facility pidfd source lacks independent held samples");
        };
        let forks = events
            .iter()
            .filter(|event| {
                event.kind == 7
                    && event.task == *task
                    && event.other_tid == process.pid
                    && event.sequence < first.install_sequence
            })
            .collect::<Vec<_>>();
        let [source_fork] = forks.as_slice() else {
            return fail("Facility pidfd source actual owned fork absent or duplicated");
        };
        let source_task = events
            .iter()
            .find(|event| event.task.tid == process.pid)
            .map(|event| &event.task)
            .ok_or_else(|| CiError::Message("Facility source kernel task absent".into()))?;
        if events
            .iter()
            .any(|event| event.task.tid == process.pid && event.task != *source_task)
            || u64::try_from(source_fork.syscall_result).ok() != Some(source_task.start_boottime_ns)
        {
            return fail("Facility source fork/start identity differs");
        }
        held_identity(before, process, source_task, clock, expected, stage, None)?;
        held_identity(after, process, source_task, clock, expected, stage, None)?;
        if before.end_monotonic_ns >= report.calls[0].before_monotonic_ns
            || after.end_monotonic_ns >= report.calls[operations.len()].before_monotonic_ns
        {
            return fail("Facility actual source samples were not held before calls");
        }
        let source = outer
            .objects
            .iter()
            .find(|object| object.role == "source")
            .ok_or_else(|| CiError::Message("Facility pidfd source descriptor absent".into()))?;
        sampled_object(before, source)?;
        sampled_object(after, source)?;
        let pidfd = outer
            .objects
            .iter()
            .find(|object| object.role == "pidfd")
            .ok_or_else(|| CiError::Message("Facility pidfd object absent".into()))?;
        if scalar(&pidfd.fdinfo, "Pid:")? != [u64::from(process.pid)] {
            return fail("Facility pidfd is not bound to actual held source");
        }
        let import = report
            .calls
            .iter()
            .find(|call| {
                call.phase == FacilityPhaseV1::Outer
                    && call.operation == FacilityOperationV1::PidfdGetfd
            })
            .expect("closed pidfd operations");
        let imported = private_objects
            .get(
                &i32::try_from(import.result)
                    .map_err(|_| CiError::Message("Facility imported fd invalid".into()))?,
            )
            .ok_or_else(|| CiError::Message("Facility imported source not held".into()))?;
        if imported.device != source.device || imported.inode != source.inode {
            return fail("Facility actual imported descriptor differs from source object");
        }
        end = end.max(lifetime(events, process, source_task, task, last_call)?);
    } else if source_outer.is_some() || source_private.is_some() {
        return fail("Facility unrelated source samples present");
    }
    if events
        .iter()
        .any(|event| event.task == *task && (event.kind == 3 || event.kind == 6))
    {
        return fail("Facility sacrificial helper allocated or changed executable");
    }
    end = end.max(lifetime(events, &report.helper, task, &fork.task, end)?);
    Ok(end)
}
