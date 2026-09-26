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
    #[serde(default)]
    challenge: String,
    #[serde(default)]
    invocation_argv: Vec<String>,
    build_sha256: DiagnosticSha256,
    build_context_sha256: DiagnosticSha256,
    runner_sha256: DiagnosticSha256,
    host_prerequisites_sha256: DiagnosticSha256,
    release_catalogue_sha256: DiagnosticSha256,
    policy_intent_sha256: DiagnosticSha256,
    #[serde(default)]
    candidate_installed: Option<CandidateInstalledBindingV2>,
    #[serde(default)]
    probe_bundle: Option<ExpectedProbeBundleV1>,
    #[serde(default)]
    replay: Option<ProtectedCandidateReplayIntentV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedCandidateReplayIntentV1 {
    observer_subject: crate::private_observer_session::ObserverSubjectV1,
    custody_policy: std::path::PathBuf,
    runner_name: String,
    #[serde(default)]
    cases: Vec<ProtectedCandidateCaseRecipeV1>,
    #[serde(default)]
    static_producer: Option<crate::private_candidate_producer::StaticCandidateProducerIntentV1>,
}

/// Administrator-reviewed fixture recipe, not facts copied from the upload.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedCandidateCaseRecipeV1 {
    selector: String,
    fixture_sha256: DiagnosticSha256,
    fixture_argv: Vec<String>,
    uid: u32,
    gid: u32,
    groups: Vec<u32>,
    port: u16,
    challenge_hex: String,
    exact_response_hex: String,
    auxiliary_semantics_sha256: Option<DiagnosticSha256>,
    #[serde(default)]
    filter_install_source_sha256: Option<DiagnosticSha256>,
    #[serde(default)]
    facility_source_sha256: Option<DiagnosticSha256>,
    #[serde(default)]
    host_preservation_source_sha256: Option<DiagnosticSha256>,
    reuse_source_sha256: Option<DiagnosticSha256>,
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
    if !matches!(intent.schema_version, 1 | 2 | 3)
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
        || intent.schema_version != 3
            && (intent.challenge.len() != 64
                || !intent
                    .challenge
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                || intent.invocation_argv.is_empty()
                || intent.candidate_installed.is_none()
                || intent.probe_bundle.is_none())
        || intent.release_catalogue_sha256
            != hash_bytes(include_bytes!("../../../ci/private-native-v2.toml"))
        || intent.policy_intent_sha256 == DiagnosticSha256::from_bytes([0; 32])
    {
        return Err(CiError::Message(
            "protected collector release intent differs".into(),
        ));
    }
    if matches!(intent.schema_version, 2 | 3) {
        let replay = intent
            .replay
            .as_ref()
            .ok_or_else(|| CiError::Message("protected replay intent absent".into()))?;
        replay.observer_subject.validate()?;
        let subject = &replay.observer_subject;
        if subject.stage != crate::private_observer_session::ObserverStageV1::Candidate
            || subject.repository_id != intent.repository_id
            || subject.run_id != intent.origin.run_id.get()
            || subject.run_attempt != intent.workflow_attempt
            || subject.source_commit != intent.origin.source_commit
            || subject.release_version != intent.release_version
            || subject.target != intent.target
            || subject.build_sha256 != intent.build_sha256
            || subject.catalogue_sha256 != intent.release_catalogue_sha256
            || !replay.custody_policy.is_absolute()
            || replay.runner_name.is_empty()
            || intent.schema_version == 2
                && (replay.static_producer.is_some()
                    || replay.cases.len() != crate::private_suite::REQUIRED_CASES.len()
                    || replay
                        .cases
                        .iter()
                        .zip(crate::private_suite::REQUIRED_CASES)
                        .any(|(recipe, selector)| {
                            recipe.selector != selector
                                || recipe.fixture_sha256.bytes() == &[0; 32]
                                || recipe.fixture_argv.is_empty()
                                || recipe.uid == 0
                                || recipe.port == 0
                                || hex::decode(&recipe.challenge_hex).is_err()
                                || hex::decode(&recipe.exact_response_hex).is_err()
                                || recipe.challenge_hex.is_empty()
                                || recipe.exact_response_hex.is_empty()
                        }))
        {
            return Err(CiError::Message(
                "protected replay exact subject/fixture recipe differs".into(),
            ));
        }
        if intent.schema_version == 3 {
            let plan = replay
                .static_producer
                .as_ref()
                .ok_or_else(|| CiError::Message("static candidate replay plan absent".into()))?;
            plan.validate()?;
            if plan.subject != *subject
                || plan.custody_policy != replay.custody_policy
                || !replay.cases.is_empty()
                || !intent.challenge.is_empty()
                || !intent.invocation_argv.is_empty()
                || intent.candidate_installed.is_some()
                || intent.probe_bundle.is_some()
            {
                return Err(CiError::Message(
                    "static candidate collector contains predicted dynamic authority".into(),
                ));
            }
        }
    } else if intent.replay.is_some() {
        return Err(CiError::Message(
            "legacy intent cannot carry replay authority".into(),
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
    let probe_bundle = verify_probe_bundle(
        intent
            .probe_bundle
            .clone()
            .ok_or_else(|| CiError::Message("legacy collector probe bundle absent".into()))?,
    )?;
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
        candidate_installed: intent.candidate_installed.as_ref(),
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
    pub(crate) observer_origin:
        Option<crate::private_observer_session::AuthenticatedObserverSessionV1>,
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
        || intent.replay.as_ref().is_some_and(|replay| {
            producer_job_id != replay.observer_subject.job_id
                || job.get("runner_id").and_then(Value::as_u64)
                    != Some(replay.observer_subject.runner_id)
                || job.get("runner_name").and_then(Value::as_str)
                    != Some(replay.runner_name.as_str())
        })
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
    let observer_origin = if let Some(replay) = &intent.replay {
        if !matches!(index.schema_version, 4 | 5 | 6) {
            return Err(CiError::Message(
                "replay requires candidate transport schema four".into(),
            ));
        }
        let mut transport =
            crate::private_observer_session::AuthenticatedCustodianTransportV1::connect(
                &replay.custody_policy,
            )?;
        let upload = crate::private_observer_session::CompletedObserverArtifactV1 {
            artifact_id,
            archive_sha256: archive_sha256.clone(),
            archive_size: fetched.archive_bytes.len() as u64,
            uploaded_job_id: producer_job_id,
            uploaded_run_attempt: intent.workflow_attempt,
        };
        let origin = transport.authenticate_completed_session(
            &replay.observer_subject,
            &upload,
            parsed.payload_members(),
            parsed.origin_member(crate::private_observer_session::PAYLOAD_INDEX_LEAF)?,
            parsed.origin_member(crate::private_observer_session::ORIGIN_COMMITMENT_LEAF)?,
            parsed.origin_member(crate::private_observer_session::ORIGIN_RECEIPT_LEAF)?,
        )?;
        provenance.extend_from_slice(origin.payload_index_sha256().bytes());
        provenance.extend_from_slice(origin.origin_commitment_sha256().bytes());
        provenance.extend_from_slice(origin.receipt_sha256().bytes());
        provenance.extend_from_slice(origin.generation_timeline_sha256().bytes());
        Some(origin)
    } else {
        None
    };
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
        observer_origin,
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
    let producer = collect_completed_candidate_c3(&intent, &intent_sha256, &token)?;
    if producer.index.cases.len()
        != memcordon_core::private_release_case_v1::REQUIRED_PRIVATE_RELEASE_SELECTORS_V1.len()
    {
        return Err(CiError::Message(
            "completed C lacks the exact 25-case inventory".into(),
        ));
    }
    replay_completed_candidate(&intent, &producer, &build)?;
    Ok(())
}

/// Portable replay uses only immutable exact upload bytes and the protected
/// reviewed recipe. It never probes the collector's /proc, service or kernel.
fn replay_completed_candidate(
    intent: &ProtectedCandidateCollectorIntentV1,
    producer: &AuthenticatedCandidateC3,
    build: &PrivateCandidateRecordV2,
) -> Result<crate::private_native_verify::VerifiedCandidateSemanticsV2> {
    use crate::private_candidate_replay::{
        ExpectedCaseSubjectV1, ReplayLeafRoleV1, replay_role_path, verify_origin_bound_case,
    };
    let replay = intent.replay.as_ref().ok_or_else(|| {
        CiError::Message(
            "candidate replay requires protected schema-two custody/recipe intent".into(),
        )
    })?;
    let origin = producer.observer_origin.as_ref().ok_or_else(|| {
        CiError::Message("completed candidate has no authenticated immutable origin".into())
    })?;
    let mut results = Vec::with_capacity(producer.index.cases.len());
    let mut proofs = Vec::with_capacity(producer.index.cases.len());
    for (ordinal, case) in producer.index.cases.iter().enumerate() {
        let bundle = case
            .family_raw
            .iter()
            .find(|leaf| leaf.path.ends_with("/replay-bundle.v1.bin"))
            .ok_or_else(|| CiError::Message("completed candidate replay bundle absent".into()))?;
        let facts_path = replay_role_path(&bundle.path, ReplayLeafRoleV1::Facts, 0)?;
        let facts: crate::private_candidate_replay::CaseReplayFactsV1 =
            crate::private_observer_session::strict_json(
                origin.leaf(&facts_path)?,
                8 * 1024 * 1024,
            )?;
        let static_recipe;
        let recipe = if let Some(plan) = &replay.static_producer {
            use crate::private_kernel_replay::IntervalPurposeV1;
            let selector = *crate::private_suite::REQUIRED_CASES
                .get(ordinal)
                .ok_or_else(|| {
                    CiError::Message("completed candidate ordinal exceeds closed catalogue".into())
                })?;
            let (purpose, physical_ordinal) = match selector {
                "private_tcp::wrong_grant_profile_and_port_rejected" => {
                    (IntervalPurposeV1::Policy, 0)
                }
                "private_tcp::dual_attempt_namespace_isolation" => {
                    (IntervalPurposeV1::DualContinuous, ordinal as u32)
                }
                "private_tcp::retirement_failure_blocks_reuse" => {
                    (IntervalPurposeV1::ReuseFirst, ordinal as u32)
                }
                _ => (IntervalPurposeV1::Ordinary, ordinal as u32),
            };
            let prepared = crate::private_candidate_producer::prepared_candidate_case_recipe_v1(
                plan,
                &origin.descriptor().session_nonce,
                1,
                selector,
                purpose,
                physical_ordinal,
            )?;
            let physical_id = if selector == "private_tcp::wrong_grant_profile_and_port_rejected" {
                crate::private_candidate_replay::candidate_policy_interval_identity_v1(
                    &origin.descriptor().session_nonce,1,&prepared.challenge,
                    memcordon_core::private_release_branch_v1::PolicyOperationBranchV1::AcceptedControl,
                )?.1
            } else {
                prepared.interval_id.storage_sha256()
            };
            if facts.generation != 1
                || facts.interval_id != physical_id
                || facts.result_key != prepared.key
                || case.result_key != prepared.key
            {
                return Err(CiError::Message(
                    "completed candidate physical identity differs from prepared static recipe"
                        .into(),
                ));
            }
            let interval_key = &origin
                .descriptor()
                .intervals
                .iter()
                .find(|interval| {
                    interval.interval_id == facts.interval_id
                        && interval.capture_path == case.kernel_capture.path
                })
                .ok_or_else(|| {
                    CiError::Message("completed candidate exact physical interval absent".into())
                })?
                .logical_case_key;
            let parsed = crate::private_kernel_replay::parse_capture_v2(
                origin.leaf(&case.kernel_capture.path)?,
                interval_key,
            )?;
            let image = parsed
                .events()
                .iter()
                .find(|event| {
                    event.kind == 6
                        && event.task.tid == facts.target.tid
                        && event.task.start_boottime_ns == facts.target.start_boottime_ns
                })
                .map(|event| (event.image_dev, event.image_inode));
            let netns = facts.held_sample_paths.iter().find_map(|path| {
                let sample = crate::private_source_carrier::decode_held_source(
                    origin.leaf(path).ok()?,
                    |image_path| origin.leaf(image_path).map(ToOwned::to_owned),
                )
                .ok()?;
                if sample.pid != facts.target.tgid
                    || sample.executable_sha256 != prepared.recipe.fixture_sha256
                {
                    return None;
                }
                sample
                    .tasks
                    .iter()
                    .find(|task| task.tid == facts.target.tid)
                    .and_then(|task| task.namespace_inodes.get("net").copied())
            });
            let response = if matches!(
                selector,
                "private_tcp::authorization_uncertainty_retired"
                    | "private_tcp::wrong_grant_profile_and_port_rejected"
            ) {
                Vec::new()
            } else {
                memcordon_core::private_release_case_v1::candidate_fixture_expected_response_v1(
                    &plan.subject.target,
                    selector,
                    &prepared.challenge,
                    netns,
                    image,
                )
                .map_err(|error| CiError::Message(error.into()))?
            };
            static_recipe = ProtectedCandidateCaseRecipeV1 {
                selector: selector.into(),
                fixture_sha256: prepared.recipe.fixture_sha256,
                fixture_argv: prepared.argv,
                uid: prepared.recipe.uid,
                gid: prepared.recipe.gid,
                groups: prepared.recipe.groups,
                port: prepared.port,
                challenge_hex: hex::encode(prepared.challenge),
                exact_response_hex: hex::encode(response),
                auxiliary_semantics_sha256: prepared.recipe.auxiliary_semantics_sha256,
                filter_install_source_sha256: prepared.recipe.filter_install_source_sha256,
                facility_source_sha256: prepared.recipe.facility_source_sha256,
                host_preservation_source_sha256: prepared.recipe.host_preservation_source_sha256,
                reuse_source_sha256: prepared.recipe.reuse_source_sha256,
            };
            &static_recipe
        } else {
            replay
                .cases
                .get(ordinal)
                .ok_or_else(|| CiError::Message("legacy candidate replay recipe absent".into()))?
        };
        let bytes = producer
            .parsed
            .member(&case.result.path)
            .ok_or_else(|| CiError::Message("completed candidate result absent".into()))?;
        origin.require_exact_leaf(&case.result.path, bytes)?;
        let result =
            memcordon_core::private_release_case_v1::PrivateReleaseCaseResultV1::parse(bytes)
                .map_err(CiError::Message)?;
        let challenge = hex::decode(&recipe.challenge_hex)
            .map_err(|_| CiError::Message("protected challenge encoding differs".into()))?;
        let response = hex::decode(&recipe.exact_response_hex)
            .map_err(|_| CiError::Message("protected response encoding differs".into()))?;
        if result
            .challenge_bytes()
            .map_err(CiError::Message)?
            .as_slice()
            != challenge.as_slice()
        {
            return Err(CiError::Message(
                "completed case challenge differs from protected fresh recipe".into(),
            ));
        }
        crate::private_protected_readback::validate_fixed_case_observation(
            NativeRunStageV2::CandidateCapability,
            &recipe.selector,
            &result.observation,
        )?;
        let expected = ExpectedCaseSubjectV1 {
            selector: &recipe.selector,
            result_key: &case.result_key,
            fixture_sha256: &recipe.fixture_sha256,
            filter_sha256: &build.filter_sha256,
            fixture_argv: &recipe.fixture_argv,
            uid: recipe.uid,
            gid: recipe.gid,
            groups: &recipe.groups,
            port: recipe.port,
            challenge: &challenge,
            exact_response: &response,
            auxiliary_semantics_sha256: recipe.auxiliary_semantics_sha256.as_ref(),
            filter_install_source_sha256: recipe.filter_install_source_sha256.as_ref(),
            facility_source_sha256: recipe.facility_source_sha256.as_ref(),
            host_preservation_source_sha256: recipe.host_preservation_source_sha256.as_ref(),
            reuse_source_sha256: recipe.reuse_source_sha256.as_ref(),
        };
        proofs.push(verify_origin_bound_case(
            origin,
            &expected,
            &facts_path,
            bytes,
            &case.kernel_capture.path,
        )?);
        results.push((bytes.to_vec(), result));
    }
    crate::private_native_verify::verify_candidate_semantics(origin, &results, &proofs)
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
    let (intent, intent_sha256) = read_protected_candidate_intent(intent_path)?;
    let build_bytes = crate::private_observer_session::read_bounded_file(build_path, 64 * 1024)?;
    let build = PrivateCandidateRecordV2::parse(&build_bytes).map_err(CiError::Message)?;
    if hash_bytes(&build_bytes) != intent.build_sha256
        || build.target != intent.target
        || build.source_commit != intent.origin.source_commit
        || build.version != intent.release_version
    {
        return Err(CiError::Message("candidate Q protected B differs".into()));
    }
    let token = std::env::var("GITHUB_TOKEN")
        .map_err(|_| CiError::Message("candidate Actions token absent".into()))?;
    let producer = collect_completed_candidate_c3(&intent, &intent_sha256, &token)?;
    let semantics = replay_completed_candidate(&intent, &producer, &build)?;
    let identity = crate::private_release_gate::IndependentBuildIdentityV2 {
        version: &build.version,
        source_commit: &build.source_commit,
        target: &build.target,
        component_sha256: &build.component_sha256,
        unit_sha256: &build.unit_sha256,
        filter_sha256: &build.filter_sha256,
        host_prerequisites_sha256: &intent.host_prerequisites_sha256,
    };
    let qualification = crate::private_release_gate::produce_private_qualification_c3(
        &semantics, &producer, &identity,
    )?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)?;
    use std::io::Write;
    file.write_all(&qualification.bytes)?;
    file.sync_all()?;
    let readback = crate::private_observer_session::read_bounded_file(output_path, 64 * 1024)?;
    if readback != qualification.bytes {
        return Err(CiError::Message(
            "Q exclusive output readback differs".into(),
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedNativeSigningIntentV1 {
    schema_version: u8,
    root_key_id: String,
    root_public_key_hex: String,
    signed_policy: memcordon_core::release_trust::SignedReleaseTrustPolicyV1,
    high_water_policy_version: u64,
    high_water_release_sequence: u64,
    high_water_wall_unix: u64,
    key_id: String,
    release_sequence: u64,
    repository: String,
    workflow_path: String,
    workflow_revision: String,
    verifier_sha256: String,
    verifier_source_commit: String,
    issued_at_unix: u64,
    expires_at_unix: u64,
}

/// Shared inherited-descriptor boundary for the existing release signing
/// roles. Role/delegation checks stay in the NativeQ/PublicP issuers.
#[cfg(target_os = "linux")]
pub(crate) fn read_release_signing_credential(
    credential_fd: u32,
) -> Result<ed25519_dalek::SigningKey> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    if credential_fd < 3 {
        return Err(CiError::Message(
            "release credential descriptor differs".into(),
        ));
    }
    let mut credential =
        std::fs::File::open(Path::new("/proc/self/fd").join(credential_fd.to_string()))?;
    let metadata = credential.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
        || metadata.len() != 32
    {
        return Err(CiError::Message(
            "release inherited credential protection/size differs".into(),
        ));
    }
    let mut secret = [0_u8; 32];
    credential.read_exact(&mut secret)?;
    let key = ed25519_dalek::SigningKey::from_bytes(&secret);
    secret.fill(0);
    Ok(key)
}

/// The explicit completed-C -> replay -> Q -> NativeQ certificate operation.
/// All authority comes from protected policy and an inherited key descriptor;
/// the producer cannot submit a digest or JSON blob to be signed.
pub fn collect_signed_private_q_after_completed_producer(
    intent_path: &Path,
    build_path: &Path,
    signing_intent_path: &Path,
    credential_fd: u32,
    output_dir: &Path,
) -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            intent_path,
            build_path,
            signing_intent_path,
            credential_fd,
            output_dir,
        );
        Err(CiError::Message(
            "protected NativeQ credential operation requires Linux".into(),
        ))
    }
    #[cfg(target_os = "linux")]
    {
        use std::io::Write;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        if credential_fd < 3
            || !output_dir.is_absolute()
            || std::fs::symlink_metadata(output_dir).is_ok()
        {
            return Err(CiError::Message(
                "NativeQ output/credential descriptor differs".into(),
            ));
        }
        let (intent, intent_sha256) = read_protected_candidate_intent(intent_path)?;
        let signing: ProtectedNativeSigningIntentV1 = crate::private_observer_session::strict_json(
            &crate::private_protected_readback::read_protected_raw_case_file(signing_intent_path)?,
            128 * 1024,
        )?;
        if signing.schema_version != 1 {
            return Err(CiError::Message(
                "NativeQ signing intent revision differs".into(),
            ));
        }
        let build_bytes =
            crate::private_observer_session::read_bounded_file(build_path, 16 * 1024)?;
        let build = PrivateCandidateRecordV2::parse(&build_bytes).map_err(CiError::Message)?;
        if hash_bytes(&build_bytes) != intent.build_sha256
            || build.target != intent.target
            || build.source_commit != intent.origin.source_commit
            || build.version != intent.release_version
        {
            return Err(CiError::Message(
                "NativeQ protected build subject differs".into(),
            ));
        }
        let token = std::env::var("GITHUB_TOKEN")
            .map_err(|_| CiError::Message("candidate Actions readback token absent".into()))?;
        let producer = collect_completed_candidate_c3(&intent, &intent_sha256, &token)?;
        let semantics = replay_completed_candidate(&intent, &producer, &build)?;
        let identity = crate::private_release_gate::IndependentBuildIdentityV2 {
            version: &build.version,
            source_commit: &build.source_commit,
            target: &build.target,
            component_sha256: &build.component_sha256,
            unit_sha256: &build.unit_sha256,
            filter_sha256: &build.filter_sha256,
            host_prerequisites_sha256: &intent.host_prerequisites_sha256,
        };
        let qualification = crate::private_release_gate::produce_private_qualification_c3(
            &semantics, &producer, &identity,
        )?;
        // Obtain signing material only after completed custody and all native
        // predicates passed. A path in the submitted artifact is never used.
        let key = read_release_signing_credential(credential_fd)?;
        let anchor = memcordon_core::release_trust::ReleaseTrustAnchorV1 {
            root_key_id: signing.root_key_id,
            public_key_hex: signing.root_public_key_hex,
        };
        let high_water = memcordon_core::release_trust::TrustHighWaterV1 {
            policy_version: signing.high_water_policy_version,
            release_sequence: signing.high_water_release_sequence,
            last_accepted_wall_unix: signing.high_water_wall_unix,
        };
        let authority = crate::private_release_gate::NativeCertificateSigningIntentV1 {
            trust_anchor: &anchor,
            signed_policy: &signing.signed_policy,
            high_water: &high_water,
            signing_key: &key,
            key_id: &signing.key_id,
            release_sequence: signing.release_sequence,
            repository: &signing.repository,
            workflow_path: &signing.workflow_path,
            workflow_revision: &signing.workflow_revision,
            verifier_sha256: &signing.verifier_sha256,
            verifier_source_commit: &signing.verifier_source_commit,
            build_context_sha256: &intent.build_context_sha256,
            collector_intent_sha256: &intent_sha256,
            release_catalogue_sha256: &intent.release_catalogue_sha256,
            issued_at_unix: signing.issued_at_unix,
            expires_at_unix: signing.expires_at_unix,
        };
        let certificate = crate::private_release_gate::sign_native_qualification_certificate_c3(
            &semantics,
            &producer,
            &identity,
            &build_bytes,
            &qualification,
            &authority,
        )?;
        std::fs::create_dir(output_dir)?;
        std::fs::set_permissions(output_dir, std::fs::Permissions::from_mode(0o700))?;
        for (name, bytes) in [
            ("qualification.json", qualification.bytes.as_slice()),
            ("qualification.certificate.json", certificate.as_slice()),
        ] {
            let path = output_dir.join(name);
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            if crate::private_observer_session::read_bounded_file(&path, 128 * 1024)? != bytes {
                return Err(CiError::Message(
                    "NativeQ exclusive output readback differs".into(),
                ));
            }
        }
        std::fs::File::open(output_dir)?.sync_all()?;
        std::fs::File::open(
            output_dir
                .parent()
                .ok_or_else(|| CiError::Message("NativeQ output parent absent".into()))?,
        )?
        .sync_all()?;
        Ok(())
    }
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
