//! Completed Actions producer custody, distinct from native semantics.
//!
//! Only the fixed Actions transport may create this token in production. The
//! downloaded ZIP still needs independent physical-case verification before Q
//! or P can be issued.

use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_build_v2::PrivateCandidateRecordV2;
use memcordon_core::workload_codec::hash_bytes;
use serde::Deserialize;
use std::path::Path;

use crate::certification_context::ExpectedCertificationOrigin;
use crate::private_candidate_c_v3::{
    CandidateEvidenceIndexV3, ParsedCandidateC3V1, parse_candidate_c_v3_full,
};
use crate::private_native::{
    CandidateInstalledBindingV2, ExpectedNativeRunV2, NativeRunStageV2, PRODUCERS,
    StructuralNativeArtifactV2, validate_native_artifact_zip,
};
use crate::private_probe_bundle::{ExpectedProbeBundleV1, verify_probe_bundle};
use crate::{CiError, Result};

pub(crate) struct AuthenticatedCompletedProducerV2 {
    pub(crate) artifact: StructuralNativeArtifactV2,
    pub(crate) repository_id: u64,
    pub(crate) run_id: u64,
    pub(crate) run_attempt: u32,
    pub(crate) producer_job_id: u64,
    pub(crate) artifact_id: u64,
    pub(crate) archive_sha256: DiagnosticSha256,
    pub(crate) provenance_sha256: DiagnosticSha256,
}

/// Administrator-protected expected release identity on the downstream
/// verifier host. This is not supplied by C or by the candidate runner.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedCandidateCollectorIntentV1 {
    schema_version: u8,
    repository_id: u64,
    origin: ExpectedCertificationOrigin,
    release_version: String,
    target: String,
    native_machine: String,
    workflow_attempt: u32,
    challenge: String,
    invocation_argv: Vec<String>,
    build_sha256: DiagnosticSha256,
    build_context_sha256: DiagnosticSha256,
    runner_sha256: DiagnosticSha256,
    host_prerequisites_sha256: DiagnosticSha256,
    release_catalogue_sha256: DiagnosticSha256,
    policy_intent_sha256: DiagnosticSha256,
    candidate_installed: CandidateInstalledBindingV2,
    probe_bundle: ExpectedProbeBundleV1,
}

fn read_protected_candidate_intent(
    path: &Path,
) -> Result<(ProtectedCandidateCollectorIntentV1, DiagnosticSha256)> {
    let bytes = crate::private_protected_readback::read_protected_raw_case_file(path)?;
    if bytes.len() > 64 * 1024 {
        return Err(CiError::Message(
            "protected collector intent exceeds bound".into(),
        ));
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)
        .map_err(CiError::Message)?;
    let intent: ProtectedCandidateCollectorIntentV1 = serde_json::from_slice(&bytes)?;
    if intent.schema_version != 1
        || intent.repository_id == 0
        || intent.workflow_attempt == 0
        || intent.target != "x86_64-unknown-linux-gnu"
            && intent.target != "aarch64-unknown-linux-gnu"
        || intent.native_machine
            != if intent.target == "x86_64-unknown-linux-gnu" {
                "x86_64"
            } else {
                "aarch64"
            }
        || intent.origin.repository != "Portfoligno/memcordon"
        || !intent
            .origin
            .workflow_ref
            .contains("/.github/workflows/release.yml@")
        || intent.origin.workflow_commit != intent.origin.source_commit
        || intent.challenge.len() != 64
        || !intent
            .challenge
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || intent.invocation_argv.is_empty()
        || intent.release_catalogue_sha256
            != hash_bytes(include_bytes!("../../../ci/private-native-v2.toml"))
        || intent.policy_intent_sha256 == DiagnosticSha256::from_bytes([0; 32])
    {
        return Err(CiError::Message(
            "protected collector release intent differs".into(),
        ));
    }
    Ok((intent, hash_bytes(&bytes)))
}

/// Retrieves a completed predecessor and exact C ZIP. It cannot issue Q:
/// detached protected supervisor evidence and loss-free independent kernel
/// intervals must be joined before the private semantic token is constructed.
pub(crate) fn collect_completed_candidate_from_intent(
    intent_path: &Path,
    build_bytes: &[u8],
    token: &str,
) -> Result<AuthenticatedCompletedProducerV2> {
    let (intent, _) = read_protected_candidate_intent(intent_path)?;
    let probe_bundle = verify_probe_bundle(intent.probe_bundle.clone())?;
    let build = PrivateCandidateRecordV2::parse(build_bytes).map_err(CiError::Message)?;
    if build.target != intent.target
        || build.source_commit != intent.origin.source_commit
        || build.version != intent.release_version
        || hash_bytes(build_bytes) != intent.build_sha256
        || intent.origin.run_id.get() == 0
    {
        return Err(CiError::Message(
            "completed candidate differs from protected B".into(),
        ));
    }
    let expected = ExpectedNativeRunV2 {
        stage: NativeRunStageV2::CandidateCapability,
        version: &intent.release_version,
        source_commit: &intent.origin.source_commit,
        target: &intent.target,
        native_machine: &intent.native_machine,
        workflow_run_id: &intent.origin.run_id.to_string(),
        workflow_job: "linux-private-candidate",
        workflow_attempt: intent.workflow_attempt,
        challenge: &intent.challenge,
        invocation_argv: &intent.invocation_argv,
        build_context_sha256: &intent.build_context_sha256,
        runner_sha256: &intent.runner_sha256,
        host_prerequisites_sha256: &intent.host_prerequisites_sha256,
        release_catalogue_sha256: &intent.release_catalogue_sha256,
        component_sha256: &build.component_sha256,
        unit_sha256: &build.unit_sha256,
        filter_sha256: &build.filter_sha256,
        candidate_installed: Some(&intent.candidate_installed),
        final_installed: None,
    };
    let producer = read_completed_producer(&intent.origin, intent.repository_id, &expected, token)?;
    probe_bundle.revalidate()?;
    Ok(producer)
}

pub(crate) struct AuthenticatedCandidateC3 {
    pub(crate) index: CandidateEvidenceIndexV3,
    pub(crate) parsed: ParsedCandidateC3V1,
    pub(crate) raw_index_sha256: DiagnosticSha256,
    pub(crate) repository_id: u64,
    pub(crate) run_id: u64,
    pub(crate) run_attempt: u32,
    pub(crate) producer_job_id: u64,
    pub(crate) artifact_id: u64,
    pub(crate) archive_sha256: DiagnosticSha256,
    pub(crate) provenance_sha256: DiagnosticSha256,
}

fn collect_completed_candidate_c3(
    intent: &ProtectedCandidateCollectorIntentV1,
    intent_sha256: &DiagnosticSha256,
    token: &str,
) -> Result<AuthenticatedCandidateC3> {
    use serde_json::Value;
    let spec = PRODUCERS
        .into_iter()
        .find(|spec| {
            spec.stage == NativeRunStageV2::CandidateCapability && spec.target == intent.target
        })
        .ok_or_else(|| CiError::Message("candidate C producer target differs".into()))?;
    let attempt = std::num::NonZeroU32::new(intent.workflow_attempt)
        .ok_or_else(|| CiError::Message("candidate C workflow attempt is zero".into()))?;
    let fetched = crate::private_actions_readback::read_actions_native_artifact(
        &intent.origin,
        spec,
        attempt,
        token,
    )?;
    let parsed = parse_candidate_c_v3_full(&fetched.archive_bytes)?;
    let index = parsed.index.clone();
    let run = &fetched.run;
    let jobs = &fetched.jobs;
    let artifact = &fetched.artifact;
    let repository_id = run
        .pointer("/repository/id")
        .and_then(Value::as_u64)
        .filter(|value| *value != 0)
        .ok_or_else(|| CiError::Message("candidate C repository id absent".into()))?;
    let expected_ref = intent
        .origin
        .workflow_ref
        .split_once("/.github/workflows/")
        .and_then(|(_, tail)| tail.split_once('@'))
        .filter(|(path, _)| *path == "release.yml")
        .map(|(_, reference)| reference)
        .ok_or_else(|| CiError::Message("candidate C workflow reference differs".into()))?;
    let run_path = run
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| CiError::Message("candidate C workflow path absent".into()))?;
    let (workflow_path, observed_ref) = run_path
        .split_once('@')
        .ok_or_else(|| CiError::Message("candidate C workflow path differs".into()))?;
    let short_ref = expected_ref
        .strip_prefix("refs/heads/")
        .or_else(|| expected_ref.strip_prefix("refs/tags/"));
    let matching_jobs: Vec<_> = jobs
        .get("jobs")
        .and_then(Value::as_array)
        .ok_or_else(|| CiError::Message("candidate C jobs absent".into()))?
        .iter()
        .filter(|job| job.get("name").and_then(Value::as_str) == Some(spec.job_name))
        .collect();
    let [job] = matching_jobs.as_slice() else {
        return Err(CiError::Message(
            "candidate C completed job ambiguous".into(),
        ));
    };
    let producer_job_id = job
        .get("id")
        .and_then(Value::as_u64)
        .filter(|value| *value != 0)
        .ok_or_else(|| CiError::Message("candidate C producer job id absent".into()))?;
    let artifact_id = artifact
        .get("id")
        .and_then(Value::as_u64)
        .filter(|value| *value != 0)
        .ok_or_else(|| CiError::Message("candidate C artifact id absent".into()))?;
    let archive_sha256 = hash_bytes(&fetched.archive_bytes);
    let archive_digest = format!("sha256:{}", String::from(archive_sha256.clone()));
    if repository_id != intent.repository_id
        || index.target != intent.target
        || index.source_commit != intent.origin.source_commit
        || index.release_version != intent.release_version
        || index.collector_intent_sha256 != *intent_sha256
        || workflow_path != ".github/workflows/release.yml"
        || (observed_ref != expected_ref && short_ref != Some(observed_ref))
        || !matches!(
            run.get("event").and_then(Value::as_str),
            Some("push" | "workflow_dispatch")
        )
        || !(run.get("status").and_then(Value::as_str) == Some("in_progress")
            && run.get("conclusion").is_some_and(Value::is_null)
            || run.get("status").and_then(Value::as_str) == Some("completed")
                && run.get("conclusion").and_then(Value::as_str) == Some("success"))
        || job.get("run_id").and_then(Value::as_u64) != Some(intent.origin.run_id.get())
        || job.get("run_attempt").and_then(Value::as_u64)
            != Some(u64::from(intent.workflow_attempt))
        || job.get("head_sha").and_then(Value::as_str) != Some(intent.origin.source_commit.as_str())
        || job.get("status").and_then(Value::as_str) != Some("completed")
        || job.get("conclusion").and_then(Value::as_str) != Some("success")
        || job
            .get("runner_id")
            .and_then(Value::as_u64)
            .is_none_or(|id| id == 0)
        || !job
            .get("labels")
            .and_then(Value::as_array)
            .is_some_and(|labels| {
                labels
                    .iter()
                    .any(|label| label.as_str() == Some(spec.runner_label))
            })
        || artifact.get("name").and_then(Value::as_str) != Some(spec.artifact_name)
        || artifact.get("expired").and_then(Value::as_bool) != Some(false)
        || artifact.get("size_in_bytes").and_then(Value::as_u64)
            != Some(fetched.archive_bytes.len() as u64)
        || artifact.get("digest").and_then(Value::as_str) != Some(archive_digest.as_str())
        || artifact.pointer("/workflow_run/id").and_then(Value::as_u64)
            != Some(intent.origin.run_id.get())
        || artifact
            .pointer("/workflow_run/repository_id")
            .and_then(Value::as_u64)
            != Some(repository_id)
        || artifact
            .pointer("/workflow_run/head_repository_id")
            .and_then(Value::as_u64)
            != Some(repository_id)
        || artifact
            .pointer("/workflow_run/head_sha")
            .and_then(Value::as_str)
            != Some(intent.origin.source_commit.as_str())
    {
        return Err(CiError::Message(
            "candidate C completed Actions provenance differs".into(),
        ));
    }
    let mut provenance = b"memcordon/completed-private-c3-producer/v1\0".to_vec();
    provenance.extend_from_slice(&repository_id.to_be_bytes());
    append_text(&mut provenance, &intent.origin.repository)?;
    append_text(&mut provenance, &intent.origin.workflow_ref)?;
    append_text(&mut provenance, &intent.origin.source_commit)?;
    provenance.extend_from_slice(&intent.origin.run_id.get().to_be_bytes());
    provenance.extend_from_slice(&intent.workflow_attempt.to_be_bytes());
    provenance.extend_from_slice(&producer_job_id.to_be_bytes());
    provenance.extend_from_slice(&artifact_id.to_be_bytes());
    append_text(&mut provenance, spec.artifact_name)?;
    append_text(&mut provenance, &intent.target)?;
    provenance.extend_from_slice(&(fetched.archive_bytes.len() as u64).to_be_bytes());
    provenance.extend_from_slice(archive_sha256.bytes());
    provenance.extend_from_slice(parsed.index_sha256.bytes());
    let raw_index_sha256 = parsed.index_sha256.clone();
    Ok(AuthenticatedCandidateC3 {
        index,
        parsed,
        raw_index_sha256,
        repository_id,
        run_id: intent.origin.run_id.get(),
        run_attempt: intent.workflow_attempt,
        producer_job_id,
        artifact_id,
        archive_sha256,
        provenance_sha256: hash_bytes(&provenance),
    })
}

/// Diagnostic collector entry point. It authenticates the completed Actions
/// producer and its exact B/probe inputs, but never turns structural C into
/// CQ. The missing native interval and protected raw case reader is surfaced
/// as a hard failure on the actual completed producer path.
pub fn inspect_completed_candidate_for_qualification(
    intent_path: &Path,
    build_path: &Path,
) -> Result<()> {
    let metadata = std::fs::symlink_metadata(build_path)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 64 * 1024 {
        return Err(CiError::Message(
            "candidate B file type or bound differs".into(),
        ));
    }
    let build_bytes = std::fs::read(build_path)?;
    if build_bytes.len() as u64 != metadata.len() {
        return Err(CiError::Message(
            "candidate B file changed during readback".into(),
        ));
    }
    let token = std::env::var("GITHUB_TOKEN")
        .map_err(|_| CiError::Message("candidate Actions readback token absent".into()))?;
    let (intent, intent_sha256) = read_protected_candidate_intent(intent_path)?;
    let build = PrivateCandidateRecordV2::parse(&build_bytes).map_err(CiError::Message)?;
    if hash_bytes(&build_bytes) != intent.build_sha256
        || build.target != intent.target
        || build.source_commit != intent.origin.source_commit
        || build.version != intent.release_version
    {
        return Err(CiError::Message("candidate C protected B differs".into()));
    }
    let bundle = verify_probe_bundle(intent.probe_bundle.clone())?;
    let producer = collect_completed_candidate_c3(&intent, &intent_sha256, &token)?;
    if producer.index.cases.len()
        != memcordon_core::private_release_case_v1::REQUIRED_PRIVATE_RELEASE_SELECTORS_V1.len()
    {
        return Err(CiError::Message(
            "completed C lacks the exact 25-case inventory".into(),
        ));
    }
    bundle.revalidate()?;
    Err(CiError::Message(
        "completed C V3 is structurally authenticated, but downstream independent replay of protected V1 raw results and kernel intervals is absent; CQ was not issued".into(),
    ))
}

/// CQ materialization is invoked only after the exact completed candidate
/// producer is read back. The output path is reserved but never created when
/// the independent protected-raw/kernel semantic token cannot be constructed.
pub fn collect_private_q_after_completed_producer(
    intent_path: &Path,
    build_path: &Path,
    output_path: &Path,
) -> Result<()> {
    if !output_path.is_absolute()
        || output_path.parent().is_none()
        || std::fs::symlink_metadata(output_path).is_ok()
    {
        return Err(CiError::Message(
            "CQ output must be a fresh absolute file".into(),
        ));
    }
    inspect_completed_candidate_for_qualification(intent_path, build_path)
}

fn append_text(out: &mut Vec<u8>, text: &str) -> Result<()> {
    let bytes = text.as_bytes();
    let length = u32::try_from(bytes.len())
        .map_err(|_| CiError::Message("completed producer identity exceeds bound".into()))?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// The expected identity comes from protected release intent and B, never the
/// artifact. A downstream job may run before the whole workflow completes;
/// the exact predecessor producer job must already have succeeded.
pub(crate) fn read_completed_producer(
    origin: &ExpectedCertificationOrigin,
    expected_repository_id: u64,
    expected: &ExpectedNativeRunV2<'_>,
    token: &str,
) -> Result<AuthenticatedCompletedProducerV2> {
    let spec = PRODUCERS
        .into_iter()
        .find(|spec| spec.stage == expected.stage && spec.target == expected.target)
        .ok_or_else(|| CiError::Message("completed producer target differs".into()))?;
    let attempt = std::num::NonZeroU32::new(expected.workflow_attempt)
        .ok_or_else(|| CiError::Message("completed producer attempt is zero".into()))?;
    let fetched = crate::private_actions_readback::read_actions_native_artifact(
        origin, spec, attempt, token,
    )?;
    let artifact = validate_native_artifact_zip(
        &fetched.archive_bytes,
        expected,
        origin,
        &fetched.run,
        &fetched.jobs,
        &fetched.artifact,
    )?;
    let job = fetched
        .jobs
        .get("jobs")
        .and_then(serde_json::Value::as_array)
        .and_then(|jobs| {
            let matching: Vec<_> = jobs
                .iter()
                .filter(|job| {
                    job.get("name").and_then(serde_json::Value::as_str) == Some(spec.job_name)
                })
                .collect();
            matching
                .as_slice()
                .first()
                .copied()
                .filter(|_| matching.len() == 1)
        })
        .ok_or_else(|| CiError::Message("completed producer job is ambiguous".into()))?;
    let repository_id = fetched
        .run
        .pointer("/repository/id")
        .and_then(serde_json::Value::as_u64)
        .filter(|value| *value != 0)
        .ok_or_else(|| CiError::Message("completed repository id absent".into()))?;
    if expected_repository_id == 0 || repository_id != expected_repository_id {
        return Err(CiError::Message(
            "completed producer repository numeric identity differs".into(),
        ));
    }
    let producer_job_id = job
        .get("id")
        .and_then(serde_json::Value::as_u64)
        .filter(|value| *value != 0)
        .ok_or_else(|| CiError::Message("completed producer job id absent".into()))?;
    let artifact_id = fetched
        .artifact
        .get("id")
        .and_then(serde_json::Value::as_u64)
        .filter(|value| *value != 0)
        .ok_or_else(|| CiError::Message("completed artifact id absent".into()))?;
    let archive_sha256 = hash_bytes(&fetched.archive_bytes);
    let mut provenance = b"memcordon/completed-private-producer/v1\0".to_vec();
    provenance.extend_from_slice(&repository_id.to_be_bytes());
    append_text(&mut provenance, &origin.repository)?;
    append_text(&mut provenance, &origin.workflow_ref)?;
    append_text(&mut provenance, &origin.source_commit)?;
    provenance.extend_from_slice(&origin.run_id.get().to_be_bytes());
    provenance.extend_from_slice(&expected.workflow_attempt.to_be_bytes());
    provenance.extend_from_slice(&producer_job_id.to_be_bytes());
    provenance.extend_from_slice(&artifact_id.to_be_bytes());
    append_text(&mut provenance, spec.artifact_name)?;
    append_text(&mut provenance, expected.target)?;
    provenance.push(match expected.stage {
        NativeRunStageV2::CandidateCapability => 1,
        NativeRunStageV2::FinalPublic => 2,
    });
    provenance.extend_from_slice(&(fetched.archive_bytes.len() as u64).to_be_bytes());
    provenance.extend_from_slice(archive_sha256.bytes());
    Ok(AuthenticatedCompletedProducerV2 {
        artifact,
        repository_id,
        run_id: origin.run_id.get(),
        run_attempt: expected.workflow_attempt,
        producer_job_id,
        artifact_id,
        archive_sha256,
        provenance_sha256: hash_bytes(&provenance),
    })
}
