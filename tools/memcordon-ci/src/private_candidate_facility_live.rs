//! Actual candidate auxiliary gate sampling. These sources are not capabilities.
use crate::private_candidate_producer::PreparedCandidateCaseV1;
use crate::private_observer_session::{ObservedGenerationV1, strict_json};
use crate::private_public_live::HeldPublicTargetSamplesV1;
use crate::{CiError, Result};
use memcordon_core::private_facility_source_v1::*;
use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Default)]
pub(crate) struct CandidateFacilityLiveSourcesV1 {
    pub(crate) originals: BTreeMap<String, Vec<u8>>,
    pub(crate) held: BTreeMap<String, HeldPublicTargetSamplesV1>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Coordinator {
    pid: u32,
    start_time: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Admission {
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
struct Gate {
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
fn fail<T>(message: &str) -> Result<T> {
    Err(CiError::Message(message.into()))
}
fn field(bytes: &[u8], prefix: &str) -> Result<Vec<u64>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| CiError::Message("facility status is not text".into()))?;
    let rows = text
        .lines()
        .filter_map(|line| line.strip_prefix(prefix))
        .collect::<Vec<_>>();
    let [row] = rows.as_slice() else {
        return fail("facility stable status field absent or duplicated");
    };
    row.split_whitespace()
        .map(|word| {
            word.parse::<u64>()
                .map_err(|_| CiError::Message("facility status scalar differs".into()))
        })
        .collect()
}
#[cfg(target_os = "linux")]
pub(crate) fn sample_candidate_facility_if_ready(
    directory: &Path,
    case: &PreparedCandidateCaseV1,
    generation: &ObservedGenerationV1,
    image: &DiagnosticSha256,
    state: &mut CandidateFacilityLiveSourcesV1,
) -> Result<bool> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let (phase, gate_name, ack_name, held_name, source_name) =
        if !state.held.contains_key("outer-held.v1.bin") {
            (
                FacilityPhaseV1::Outer,
                "facility-helper-outer-v1.json",
                "facility-helper-outer-v1.ack",
                "outer-held.v1.bin",
                "source-outer-held.v1.bin",
            )
        } else if !state.held.contains_key("private-held.v1.bin") {
            (
                FacilityPhaseV1::Private,
                "facility-helper-private-v1.json",
                "facility-helper-private-v1.ack",
                "private-held.v1.bin",
                "source-private-held.v1.bin",
            )
        } else {
            return Ok(true);
        };
    let gate_path = directory.join(gate_name);
    if matches!(std::fs::symlink_metadata(&gate_path),Err(error)if error.kind()==std::io::ErrorKind::NotFound)
    {
        return Ok(false);
    }
    let read = |name: &str| {
        crate::private_protected_readback::read_protected_raw_case_file(&directory.join(name))
    };
    let bytes = read(gate_name)?;
    let admission_bytes = read("request.json")?;
    let gate: Gate = strict_json(&bytes, 128 * 1024)?;
    let admission: Admission = strict_json(&admission_bytes, 128 * 1024)?;
    if case.recipe.facility_source_sha256.as_ref() != Some(&facility_source_revision_sha256())
        || admission.schema_version != 1
        || admission.protocol != "candidate-independent-facility-source-v1"
        || admission.source_revision_sha256 != facility_source_revision_sha256()
        || admission.parent_result_key != case.key
        || admission.selector != case.selector
        || admission.challenge != case.challenge
        || admission.installation_epoch != generation.installation_epoch
        || admission.candidate_manifest_sha256 != generation.installed_manifest_sha256
        || admission.installed_inspection_sha256 != generation.installed_receipt_sha256
        || admission.service_generation_sha256.bytes() == &[0; 32]
        || admission.filter_sha256.bytes() == &[0; 32]
        || admission.coordinator.pid == 0
        || admission.coordinator.start_time == 0
        || admission.admission_monotonic_ns == 0
        || gate.schema_version != 1
        || gate.phase != phase
        || gate.parent_result_key != case.key
        || gate.source_revision_sha256 != facility_source_revision_sha256()
        || gate.admission_sha256 != hash_bytes(&admission_bytes)
        || gate.observed_monotonic_ns < admission.admission_monotonic_ns
        || gate.objects.is_empty()
    {
        return fail("candidate Facility actual held admission/generation differs");
    }
    crate::private_process_clock::require_live_start_ticks(
        admission.coordinator.pid,
        admission.coordinator.start_time,
    )?;
    let sample = crate::private_public_live::sample_held_target_raw(
        gate.helper.pid,
        gate.helper.start_time_ticks,
        image,
    )?;
    let actual = sample
        .leaves
        .get("status.raw")
        .ok_or_else(|| CiError::Message("facility sampled status absent".into()))?;
    for prefix in [
        "Pid:",
        "Tgid:",
        "Uid:",
        "Gid:",
        "NoNewPrivs:",
        "Seccomp:",
        "Seccomp_filters:",
    ] {
        if field(actual, prefix)? != field(&gate.status, prefix)? {
            return fail("facility independently held stable status differs");
        }
    }
    if field(actual, "Uid:")? != [0; 4]
        || field(actual, "Gid:")? != [0; 4]
        || sample.begin_monotonic_ns < gate.observed_monotonic_ns
    {
        return fail("facility actual root helper identity or sample clock differs");
    }
    let source = if case.selector == "private_tcp::io_uring_and_pidfd_import_denied" {
        let objects = gate
            .objects
            .iter()
            .filter(|object| object.role == "pidfd")
            .collect::<Vec<_>>();
        let [object] = objects.as_slice() else {
            return fail("facility actual source pidfd is absent or duplicated");
        };
        let path = Path::new("tasks")
            .join(sample.pid.to_string())
            .join("fds")
            .join(object.fd.to_string())
            .join("fdinfo.raw");
        let raw = sample
            .leaves
            .get(path.to_string_lossy().as_ref())
            .ok_or_else(|| CiError::Message("facility independent pidfd fdinfo absent".into()))?;
        let pids = field(raw, "Pid:")?;
        let [pid] = pids.as_slice() else {
            return fail("facility independent pidfd source PID differs");
        };
        let pid = u32::try_from(*pid)
            .map_err(|_| CiError::Message("facility source PID overflow".into()))?;
        let stat = std::fs::read_to_string(Path::new("/proc").join(pid.to_string()).join("stat"))?;
        let identity = crate::private_supervisor::parse_linux_child_stat(&stat, pid)?;
        Some(crate::private_public_live::sample_held_target_raw(
            pid,
            identity.start_time_ticks,
            image,
        )?)
    } else {
        None
    };
    if read(gate_name)? != bytes || read("request.json")? != admission_bytes {
        return fail("facility held gate or admission changed before ACK");
    }
    let ack = serde_json::to_vec(
        &serde_json::json!({"schema_version":1,"phase":phase,"parent_result_key":case.key,"source_revision_sha256":facility_source_revision_sha256(),"gate_sha256":hash_bytes(&bytes)}),
    )?;
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join(ack_name))?;
    file.write_all(&ack)?;
    file.sync_all()?;
    std::fs::File::open(directory)?.sync_all()?;
    state
        .originals
        .insert("request.json".into(), admission_bytes);
    state.originals.insert(gate_name.into(), bytes);
    state.originals.insert(ack_name.into(), ack);
    state.held.insert(held_name.into(), sample);
    if let Some(source) = source {
        state.held.insert(source_name.into(), source);
    }
    Ok(phase == FacilityPhaseV1::Private)
}
#[cfg(not(target_os = "linux"))]
pub(crate) fn sample_candidate_facility_if_ready(
    _directory: &Path,
    _case: &PreparedCandidateCaseV1,
    _generation: &ObservedGenerationV1,
    _image: &DiagnosticSha256,
    _state: &mut CandidateFacilityLiveSourcesV1,
) -> Result<bool> {
    fail("candidate Facility sampling requires actual native Linux")
}
