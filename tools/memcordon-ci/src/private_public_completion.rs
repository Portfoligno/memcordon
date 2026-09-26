//! Completed public collection and canonical P. The producer cannot obtain
//! these capabilities while its job is running. No artifact JSON revives one.

/// Protected expectations are administered independently of the downloaded P/CP.
/// Exact payload equality also pins all case/catalogue and expiry commitments.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedPublicCompletionIntentV1 {
    schema_version: u8,
    root_key_id: String,
    root_public_key_hex: String,
    signed_policy: memcordon_core::release_trust::SignedReleaseTrustPolicyV1,
    high_water_policy_version: u64,
    high_water_release_sequence: u64,
    high_water_wall_unix: u64,
    expected: memcordon_core::public_release_trust::PublicQualificationCertificateV2,
}

/// Validates the signed completed P/CP against independent protected authority.
pub fn verify_private_completion(
    intent_path: &std::path::Path,
    qualification: &std::path::Path,
) -> Result<()> {
    if !qualification.is_absolute() {
        return fail("private completion protected path differs");
    }
    let intent = crate::private_protected_readback::read_protected_raw_case_file(intent_path)?;
    let p = crate::private_observer_session::read_bounded_file(
        &qualification.join("public-evidence.json"),
        4 * 1024 * 1024,
    )?;
    let cp = crate::private_observer_session::read_bounded_file(
        &qualification.join("public-evidence.certificate.json"),
        128 * 1024,
    )?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| CiError::Message("private completion wall clock precedes epoch".into()))?
        .as_secs();
    validate_private_completion_bytes(&intent, &p, &cp, now)
}

/// Pure validation only: success does not create authority or a signing capability.
/// The filesystem entrypoint alone supplies independently protected expectations.
pub fn validate_private_completion_bytes(
    intent_bytes: &[u8],
    p: &[u8],
    cp_bytes: &[u8],
    now: u64,
) -> Result<()> {
    use memcordon_core::public_release_trust::{
        ExpectedPublicQualificationV1, ExpectedPublicQualificationV2,
        SignedPublicQualificationCertificateV2,
    };
    use memcordon_core::release_trust::{ReleaseTrustAnchorV1, TrustHighWaterV1};
    let intent: ProtectedPublicCompletionIntentV1 =
        crate::private_observer_session::strict_json(intent_bytes, 256 * 1024)?;
    if intent.schema_version != 1 {
        return fail("private completion protected schema differs");
    }
    let index = PublicEvidenceIndexV3::parse(p)?;
    let subject = &intent.expected.subject;
    if index.target != subject.target
        || index.native_machine != subject.native_machine
        || index.source_commit != subject.source_commit
        || index.release_version != subject.release_version
        || [
            (&index.build_sha256, &subject.build_sha256),
            (&index.archive_sha256, &subject.archive_sha256),
            (&index.manifest_sha256, &subject.manifest_sha256),
            (&index.qualification_sha256, &subject.qualification_sha256),
            (
                &index.qualification_certificate_payload_sha256,
                &subject.qualification_certificate_sha256,
            ),
            (&index.host_receipt_sha256, &subject.host_receipt_sha256),
            (&index.raw_index_sha256, &subject.raw_index_sha256),
            (
                &index.completed_provenance_sha256,
                &subject.completed_provenance_sha256,
            ),
            (&index.catalogue_sha256, &subject.catalogue_sha256),
            (
                &index.payload_index_sha256,
                &intent.expected.payload_index_sha256,
            ),
            (
                &index.origin_commitment_sha256,
                &intent.expected.origin_commitment_sha256,
            ),
            (
                &index.custody_receipt_sha256,
                &intent.expected.custody_receipt_sha256,
            ),
            (
                &index.generation_timeline_sha256,
                &intent.expected.generation_timeline_sha256,
            ),
            (
                &index.qualification_certificate_file_sha256,
                &intent.expected.qualification_certificate_file_sha256,
            ),
            (&index.semantics_sha256, &intent.expected.semantics_sha256),
        ]
        .iter()
        .any(|(actual, expected)| String::from((*actual).clone()) != **expected)
    {
        return fail("private completion P subject differs from independent expectation");
    }
    let cp = SignedPublicQualificationCertificateV2::parse(cp_bytes).map_err(CiError::Message)?;
    if cp.payload != intent.expected {
        return fail("private completion independently approved subject differs");
    }
    let high_water = TrustHighWaterV1 {
        policy_version: intent.high_water_policy_version,
        release_sequence: intent.high_water_release_sequence,
        last_accepted_wall_unix: intent.high_water_wall_unix,
    };
    let policy = intent
        .signed_policy
        .verify(
            &ReleaseTrustAnchorV1 {
                root_key_id: intent.root_key_id,
                public_key_hex: intent.root_public_key_hex,
            },
            &high_water,
            now,
        )
        .map_err(CiError::Message)?;
    let s = &intent.expected.subject;
    cp.verify(
        &policy,
        &ExpectedPublicQualificationV2 {
            subject: ExpectedPublicQualificationV1 {
                release_sequence: s.release_sequence,
                repository_id: s.repository_id,
                repository: &s.repository,
                workflow_path: &s.workflow_path,
                workflow_revision: &s.workflow_revision,
                run_id: s.run_id,
                run_attempt: s.run_attempt,
                producer_job_id: s.producer_job_id,
                artifact_id: s.artifact_id,
                target: &s.target,
                native_machine: &s.native_machine,
                source_commit: &s.source_commit,
                release_version: &s.release_version,
                verifier_sha256: &s.verifier_sha256,
                verifier_source_commit: &s.verifier_source_commit,
                build_sha256: &s.build_sha256,
                qualification_sha256: &s.qualification_sha256,
                qualification_certificate_sha256: &s.qualification_certificate_sha256,
                archive_sha256: &s.archive_sha256,
                manifest_sha256: &s.manifest_sha256,
                host_receipt_sha256: &s.host_receipt_sha256,
                raw_index_sha256: &s.raw_index_sha256,
                completed_provenance_sha256: &s.completed_provenance_sha256,
                accepted_case_set_sha256: &s.accepted_case_set_sha256,
                public_evidence_bytes: &p,
            },
            payload_index_sha256: &intent.expected.payload_index_sha256,
            origin_commitment_sha256: &intent.expected.origin_commitment_sha256,
            custody_receipt_sha256: &intent.expected.custody_receipt_sha256,
            generation_timeline_sha256: &intent.expected.generation_timeline_sha256,
            qualification_certificate_file_sha256: &intent
                .expected
                .qualification_certificate_file_sha256,
            semantics_sha256: &intent.expected.semantics_sha256,
        },
        &high_water,
        now,
    )
    .map_err(CiError::Message)?;
    Ok(())
}

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, SeekFrom, Write};
use std::time::Duration;

use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::REQUIRED_PRIVATE_RELEASE_SELECTORS_V1;
use memcordon_core::workload_codec::hash_bytes;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::private_candidate_replay::{
    ExpectedCaseSubjectV1, VerifiedNativeCaseV1, verify_origin_bound_case,
};
use crate::private_observer_session::{
    AuthenticatedCustodianTransportV1, AuthenticatedObserverSessionV1, CompletedObserverArtifactV1,
    ObserverStageV1,
};
use crate::private_public_plan::{
    StaticPublicSuiteIntentV1, VerifiedInstalledPublicTimelineV1, verify_installed_public_timeline,
};
use crate::private_public_raw::{
    ORIGIN_COMMITMENT, ORIGIN_RECEIPT, PAYLOAD_INDEX, PublicRawBudgetV1, RawPublicEvidenceIndexV1,
    canonical_json, visit_public_archive,
};
use crate::{CiError, Result};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedPublicCollectorIntentV1 {
    pub schema_version: u8,
    pub suite: StaticPublicSuiteIntentV1,
    pub repository: String,
    pub workflow_path: String,
    pub workflow_revision: String,
    pub event: String,
    pub producer_job_name: String,
    pub artifact_name: String,
    pub artifact_id: u64,
    pub runner_name: String,
    pub runner_labels: Vec<String>,
    pub custody_policy: std::path::PathBuf,
}

impl ProtectedPublicCollectorIntentV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let intent: Self = crate::private_observer_session::strict_json(bytes, 256 * 1024)?;
        intent.validate()?;
        Ok(intent)
    }
    pub fn validate(&self) -> Result<()> {
        self.suite.validate()?;
        let parts = self.repository.split('/').collect::<Vec<_>>();
        if self.schema_version != 2
            || parts.len() != 2
            || parts.iter().any(|part| {
                part.is_empty()
                    || !part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
            })
            || self.workflow_path != ".github/workflows/release.yml"
            || self.workflow_revision.len() != 40
            || !self
                .workflow_revision
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !matches!(self.event.as_str(), "push" | "workflow_dispatch")
            || self.artifact_id == 0
            || !self.custody_policy.is_absolute()
            || self.runner_name.is_empty()
            || self.runner_labels.is_empty()
            || self.runner_labels.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return fail("protected public collector workflow/runner identity differs");
        }
        let spec = crate::private_native::PUBLIC_RAW_PRODUCERS
            .iter()
            .find(|spec| {
                spec.stage == crate::private_native::NativeRunStageV2::FinalPublic
                    && spec.target == self.suite.observer_subject.target
            })
            .ok_or_else(|| {
                CiError::Message("public producer target has no reviewed contract".into())
            })?;
        if self.producer_job_name != spec.job_name || self.artifact_name != spec.artifact_name {
            return fail("public producer job/artifact is not the closed target contract");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CompletedPublicProvenanceV1 {
    pub repository_id: u64,
    pub repository: String,
    pub workflow_path: String,
    pub workflow_revision: String,
    pub run_id: u64,
    pub run_attempt: u32,
    pub producer_job_id: u64,
    pub artifact_id: u64,
    pub runner_id: u64,
    pub archive_sha256: DiagnosticSha256,
    pub archive_size: u64,
    pub metadata_sha256: DiagnosticSha256,
}

pub(crate) struct AuthenticatedCompletedPublicEvidenceV2 {
    origin: AuthenticatedObserverSessionV1,
    transport: RawPublicEvidenceIndexV1,
    raw_index_sha256: DiagnosticSha256,
    provenance: CompletedPublicProvenanceV1,
    provenance_sha256: DiagnosticSha256,
    origin_carriers: BTreeMap<String, Vec<u8>>,
    source_archive: std::fs::File,
}

impl AuthenticatedCompletedPublicEvidenceV2 {
    pub(crate) fn export_raw<W: Write + Seek>(&self, mut writer: W) -> Result<W> {
        let mut source = self.source_archive.try_clone()?;
        source.seek(SeekFrom::Start(0))?;
        if std::io::copy(&mut source, &mut writer)? != self.provenance.archive_size {
            return fail("completed raw export size differs from held downloaded archive");
        }
        Ok(writer)
    }
    pub(crate) fn transport_index(&self) -> &RawPublicEvidenceIndexV1 {
        &self.transport
    }
    pub(crate) fn origin(&self) -> &AuthenticatedObserverSessionV1 {
        &self.origin
    }
    pub(crate) fn raw_index_sha256(&self) -> &DiagnosticSha256 {
        &self.raw_index_sha256
    }
    pub(crate) fn provenance(&self) -> &CompletedPublicProvenanceV1 {
        &self.provenance
    }
    pub(crate) fn provenance_sha256(&self) -> &DiagnosticSha256 {
        &self.provenance_sha256
    }
}

fn fail<T>(message: &str) -> Result<T> {
    Err(CiError::Message(message.into()))
}

/// Diagnostic validator only. Its successful return is not a completed token.
pub fn validate_completed_public_metadata(
    intent: &ProtectedPublicCollectorIntentV1,
    run: &Value,
    jobs: &Value,
    artifacts: &Value,
) -> Result<()> {
    intent.validate()?;
    let subject = &intent.suite.observer_subject;
    if run.get("id").and_then(Value::as_u64) != Some(subject.run_id)
        || run.get("run_attempt").and_then(Value::as_u64) != Some(u64::from(subject.run_attempt))
        || run.get("head_sha").and_then(Value::as_str) != Some(subject.source_commit.as_str())
        || run.get("event").and_then(Value::as_str) != Some(intent.event.as_str())
        || run.get("path").and_then(Value::as_str) != Some(intent.workflow_path.as_str())
        || run.pointer("/repository/id").and_then(Value::as_u64) != Some(subject.repository_id)
        || run.pointer("/repository/full_name").and_then(Value::as_str)
            != Some(intent.repository.as_str())
    {
        return fail("completed public Actions run differs from protected release subject");
    }
    let jobs = complete_inventory(jobs, "jobs")?;
    let matching = jobs
        .iter()
        .filter(|job| {
            job.get("name").and_then(Value::as_str) == Some(intent.producer_job_name.as_str())
        })
        .collect::<Vec<_>>();
    let [job] = matching.as_slice() else {
        return fail("completed public producer absent/duplicated");
    };
    let mut labels = job
        .get("labels")
        .and_then(Value::as_array)
        .ok_or_else(|| CiError::Message("public runner labels absent".into()))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| CiError::Message("public runner label is not text".into()))
        })
        .collect::<Result<Vec<_>>>()?;
    labels.sort();
    if job.get("id").and_then(Value::as_u64) != Some(subject.job_id)
        || job.get("run_id").and_then(Value::as_u64) != Some(subject.run_id)
        || job.get("run_attempt").and_then(Value::as_u64) != Some(u64::from(subject.run_attempt))
        || job.get("head_sha").and_then(Value::as_str) != Some(subject.source_commit.as_str())
        || job.get("status").and_then(Value::as_str) != Some("completed")
        || job.get("conclusion").and_then(Value::as_str) != Some("success")
        || job.get("runner_id").and_then(Value::as_u64) != Some(subject.runner_id)
        || job.get("runner_name").and_then(Value::as_str) != Some(intent.runner_name.as_str())
        || labels
            != intent
                .runner_labels
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
    {
        return fail("public producer completion/attempt/runner differs");
    }
    let artifacts = complete_inventory(artifacts, "artifacts")?;
    let matching = artifacts
        .iter()
        .filter(|artifact| {
            artifact.get("name").and_then(Value::as_str) == Some(intent.artifact_name.as_str())
        })
        .collect::<Vec<_>>();
    let [artifact] = matching.as_slice() else {
        return fail("public completed artifact absent/ambiguous");
    };
    if artifact.get("id").and_then(Value::as_u64) != Some(intent.artifact_id)
        || artifact.get("expired").and_then(Value::as_bool) != Some(false)
        || artifact.pointer("/workflow_run/id").and_then(Value::as_u64) != Some(subject.run_id)
        || artifact
            .pointer("/workflow_run/head_sha")
            .and_then(Value::as_str)
            != Some(subject.source_commit.as_str())
        || artifact
            .get("size_in_bytes")
            .and_then(Value::as_u64)
            .is_none_or(|size| size == 0 || size > PublicRawBudgetV1::REVIEWED.archive_bytes)
    {
        return fail("public artifact identity/ownership/size differs");
    }
    // Attempt-level ownership is additionally pinned by the custodian's exact
    // immutable upload handoff; run-level artifact names never suffice.
    Ok(())
}

fn complete_inventory<'a>(value: &'a Value, key: &str) -> Result<&'a [Value]> {
    let items = value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| CiError::Message("Actions inventory absent".into()))?;
    let total = value
        .get("total_count")
        .and_then(Value::as_u64)
        .ok_or_else(|| CiError::Message("Actions inventory count absent".into()))?;
    let mut ids = BTreeSet::new();
    if total != items.len() as u64
        || items.len() > 10_000
        || items.iter().any(|item| {
            item.get("id")
                .and_then(Value::as_u64)
                .is_none_or(|id| id == 0 || !ids.insert(id))
        })
    {
        return fail("Actions pagination incomplete or identifiers duplicated");
    }
    Ok(items)
}

/// Only fixed authenticated Actions transport plus independently enrolled
/// custody readback constructs completed public authority.
pub(crate) fn collect_completed_public(
    intent: &ProtectedPublicCollectorIntentV1,
    actions_token: &str,
    custody: &mut AuthenticatedCustodianTransportV1,
) -> Result<AuthenticatedCompletedPublicEvidenceV2> {
    intent.validate()?;
    let subject = &intent.suite.observer_subject;
    let run_url = format!(
        "https://api.github.com/repos/{}/actions/runs/{}/attempts/{}",
        intent.repository, subject.run_id, subject.run_attempt
    );
    let jobs_url = format!("{run_url}/jobs?per_page=100");
    let artifacts_url = format!(
        "https://api.github.com/repos/{}/actions/runs/{}/artifacts?per_page=100",
        intent.repository, subject.run_id
    );
    let mut read = |url: &str, limit: usize, accept: &str| {
        crate::private_actions_readback::fetch_actions_url(actions_token, url, limit, accept)
    };
    let run_bytes = read(&run_url, 1024 * 1024, "application/vnd.github+json")?;
    let run: Value = crate::private_observer_session::strict_json(&run_bytes, 1024 * 1024)?;
    let jobs =
        crate::private_actions_readback::read_complete_inventory(&jobs_url, "jobs", &mut read)?;
    let artifacts = crate::private_actions_readback::read_complete_inventory(
        &artifacts_url,
        "artifacts",
        &mut read,
    )?;
    validate_completed_public_metadata(intent, &run, &jobs, &artifacts)?;
    let artifact = complete_inventory(&artifacts, "artifacts")?
        .iter()
        .find(|artifact| artifact.get("id").and_then(Value::as_u64) == Some(intent.artifact_id))
        .expect("validated artifact identity");
    // Independently retrieve exact reviewed workflow bytes. A producer's own
    // JSON revision field is never a workflow pin.
    let workflow_url = format!(
        "https://api.github.com/repos/{}/contents/{}?ref={}",
        intent.repository, intent.workflow_path, intent.workflow_revision
    );
    let expected_workflow = read(
        &workflow_url,
        1024 * 1024,
        "application/vnd.github.raw+json",
    )?;
    let producer_workflow_url = format!(
        "https://api.github.com/repos/{}/contents/{}?ref={}",
        intent.repository, intent.workflow_path, subject.source_commit
    );
    if read(
        &producer_workflow_url,
        1024 * 1024,
        "application/vnd.github.raw+json",
    )? != expected_workflow
    {
        return fail("producer workflow bytes differ from independently reviewed revision");
    }
    let archive_url = format!(
        "https://api.github.com/repos/{}/actions/artifacts/{}/zip",
        intent.repository, intent.artifact_id
    );
    let (mut file, archive_sha256, archive_size) =
        download_public_archive(actions_token, &archive_url)?;
    let expected_digest = artifact
        .get("digest")
        .and_then(Value::as_str)
        .and_then(|value| value.strip_prefix("sha256:"))
        .ok_or_else(|| {
            CiError::Message("public artifact immutable platform digest absent".into())
        })?;
    if expected_digest != String::from(archive_sha256.clone())
        || artifact.get("size_in_bytes").and_then(Value::as_u64) != Some(archive_size)
    {
        return fail("downloaded public archive exact platform bytes differ");
    }
    file.seek(SeekFrom::Start(0))?;
    let source_archive = file.try_clone()?;
    let mut payload = BTreeMap::new();
    let mut i = None;
    let mut k = None;
    let mut r = None;
    let (transport, raw_index_sha256) =
        visit_public_archive(file, PublicRawBudgetV1::REVIEWED, |leaf, bytes| {
            match leaf.path.as_str() {
                PAYLOAD_INDEX => i = Some(bytes.to_vec()),
                ORIGIN_COMMITMENT => k = Some(bytes.to_vec()),
                ORIGIN_RECEIPT => r = Some(bytes.to_vec()),
                _ => {
                    payload.insert(leaf.path.clone(), bytes.to_vec());
                }
            }
            Ok(())
        })?;
    let upload = CompletedObserverArtifactV1 {
        artifact_id: intent.artifact_id,
        archive_sha256: archive_sha256.clone(),
        archive_size,
        uploaded_job_id: subject.job_id,
        uploaded_run_attempt: subject.run_attempt,
    };
    let origin_carriers = BTreeMap::from([
        (
            PAYLOAD_INDEX.into(),
            i.ok_or_else(|| CiError::Message("public I missing".into()))?,
        ),
        (
            ORIGIN_COMMITMENT.into(),
            k.ok_or_else(|| CiError::Message("public K missing".into()))?,
        ),
        (
            ORIGIN_RECEIPT.into(),
            r.ok_or_else(|| CiError::Message("public R missing".into()))?,
        ),
    ]);
    let origin = custody.authenticate_completed_session(
        subject,
        &upload,
        payload,
        &origin_carriers[PAYLOAD_INDEX],
        &origin_carriers[ORIGIN_COMMITMENT],
        &origin_carriers[ORIGIN_RECEIPT],
    )?;
    let metadata_sha256 = hash_bytes(&canonical_json(&(run, jobs, artifacts))?);
    let provenance = CompletedPublicProvenanceV1 {
        repository_id: subject.repository_id,
        repository: intent.repository.clone(),
        workflow_path: intent.workflow_path.clone(),
        workflow_revision: intent.workflow_revision.clone(),
        run_id: subject.run_id,
        run_attempt: subject.run_attempt,
        producer_job_id: subject.job_id,
        artifact_id: intent.artifact_id,
        runner_id: subject.runner_id,
        archive_sha256,
        archive_size,
        metadata_sha256,
    };
    let provenance_sha256 = hash_bytes(&canonical_json(&(
        &provenance,
        origin.origin_commitment_sha256(),
        origin.receipt_sha256(),
    ))?);
    Ok(AuthenticatedCompletedPublicEvidenceV2 {
        origin,
        transport,
        raw_index_sha256,
        provenance,
        provenance_sha256,
        origin_carriers,
        source_archive,
    })
}

fn download_public_archive(
    token: &str,
    url: &str,
) -> Result<(std::fs::File, DiagnosticSha256, u64)> {
    if token.is_empty() || !url.starts_with("https://api.github.com/repos/") {
        return fail("public downloader origin/token differs");
    }
    let agent = ureq::Agent::config_builder()
        .http_status_as_error(true)
        .timeout_connect(Some(Duration::from_secs(15)))
        .timeout_recv_response(Some(Duration::from_secs(60)))
        .timeout_recv_body(Some(Duration::from_secs(60)))
        .build()
        .new_agent();
    let mut response = agent
        .get(url)
        .header("Accept", "application/zip")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "memcordon-ci")
        .header("Authorization", format!("Bearer {token}"))
        .call()
        .map_err(|error| CiError::Http(Box::new(error)))?;
    let mut reader = response.body_mut().as_reader();
    let mut file = tempfile::tempfile()?;
    let mut hash = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        size = size
            .checked_add(count as u64)
            .filter(|size| *size <= PublicRawBudgetV1::REVIEWED.archive_bytes)
            .ok_or_else(|| {
                CiError::Message("public download exceeded reviewed stage bound".into())
            })?;
        hash.update(&buffer[..count]);
        file.write_all(&buffer[..count])?;
    }
    if size == 0 {
        return fail("public archive is empty");
    }
    file.sync_all()?;
    Ok((
        file,
        DiagnosticSha256::from_bytes(hash.finalize().into()),
        size,
    ))
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PublicCaseEvidenceFormatV3 {
    SingleCaseV3,
    PolicyCompositeV1,
    AbiCompositeV1,
    ReuseCompositeV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicCaseDigestV3 {
    pub selector: String,
    pub evidence_format: PublicCaseEvidenceFormatV3,
    pub case_sha256: DiagnosticSha256,
    pub result_key: DiagnosticSha256,
    pub generation_ref: u32,
    pub raw_case_commitment_sha256: DiagnosticSha256,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicEvidenceIndexV3 {
    pub schema_version: u8,
    pub target: String,
    pub native_machine: String,
    pub source_commit: String,
    pub release_version: String,
    pub build_sha256: DiagnosticSha256,
    pub archive_sha256: DiagnosticSha256,
    pub archive_size: u64,
    pub manifest_sha256: DiagnosticSha256,
    pub qualification_sha256: DiagnosticSha256,
    pub qualification_certificate_file_sha256: DiagnosticSha256,
    pub qualification_certificate_payload_sha256: DiagnosticSha256,
    pub host_receipt_sha256: DiagnosticSha256,
    pub installation_epoch: DiagnosticSha256,
    pub boot_identity: String,
    pub generation_timeline_sha256: DiagnosticSha256,
    pub origin_commitment_sha256: DiagnosticSha256,
    pub custody_receipt_sha256: DiagnosticSha256,
    pub payload_index_sha256: DiagnosticSha256,
    pub raw_index_sha256: DiagnosticSha256,
    pub completed_provenance_sha256: DiagnosticSha256,
    pub catalogue_sha256: DiagnosticSha256,
    pub semantics_sha256: DiagnosticSha256,
    pub historical_transition_sha256: DiagnosticSha256,
    pub cases: Vec<PublicCaseDigestV3>,
}

impl PublicEvidenceIndexV3 {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let index: Self = crate::private_observer_session::strict_json(
            bytes,
            PublicRawBudgetV1::REVIEWED.semantic_index_bytes as usize,
        )?;
        if index.schema_version != 3
            || !matches!(
                (index.target.as_str(), index.native_machine.as_str()),
                ("x86_64-unknown-linux-gnu", "x86_64") | ("aarch64-unknown-linux-gnu", "aarch64")
            )
            || index.source_commit.len() != 40
            || !index
                .source_commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || index.release_version.is_empty()
            || index.release_version.len() > 128
            || index.boot_identity.is_empty()
            || index.archive_size == 0
            || index.archive_size > PublicRawBudgetV1::REVIEWED.archive_bytes
            || [
                &index.build_sha256,
                &index.archive_sha256,
                &index.manifest_sha256,
                &index.qualification_sha256,
                &index.qualification_certificate_file_sha256,
                &index.qualification_certificate_payload_sha256,
                &index.host_receipt_sha256,
                &index.installation_epoch,
                &index.generation_timeline_sha256,
                &index.origin_commitment_sha256,
                &index.custody_receipt_sha256,
                &index.payload_index_sha256,
                &index.raw_index_sha256,
                &index.completed_provenance_sha256,
                &index.catalogue_sha256,
                &index.semantics_sha256,
                &index.historical_transition_sha256,
            ]
            .iter()
            .any(|hash| hash.bytes() == &[0; 32])
            || index.cases.len() != REQUIRED_PRIVATE_RELEASE_SELECTORS_V1.len()
            || index
                .cases
                .iter()
                .zip(REQUIRED_PRIVATE_RELEASE_SELECTORS_V1)
                .any(|(case, selector)| {
                    case.selector != selector
                        || case.evidence_format
                            != match selector {
                                "private_tcp::abi_alternate_entry_denied" => {
                                    PublicCaseEvidenceFormatV3::AbiCompositeV1
                                }
                                "private_tcp::retirement_failure_blocks_reuse" => {
                                    PublicCaseEvidenceFormatV3::ReuseCompositeV1
                                }
                                "private_tcp::wrong_grant_profile_and_port_rejected" => {
                                    PublicCaseEvidenceFormatV3::PolicyCompositeV1
                                }
                                _ => PublicCaseEvidenceFormatV3::SingleCaseV3,
                            }
                        || case.result_key.bytes() == &[0; 32]
                        || case.case_sha256.bytes() == &[0; 32]
                        || case.raw_case_commitment_sha256.bytes() == &[0; 32]
                })
            || canonical_json(&index)? != bytes
        {
            return fail("public P V3 exact catalogue/canonical bytes differ");
        }
        Ok(index)
    }
}

pub(crate) struct VerifiedPublicSemanticsV3 {
    index: PublicEvidenceIndexV3,
}
impl VerifiedPublicSemanticsV3 {
    pub(crate) fn index(&self) -> &PublicEvidenceIndexV3 {
        &self.index
    }
    pub(crate) fn public_index_bytes(&self) -> Result<Vec<u8>> {
        produce_public_evidence_index_v3(self)
    }
}

pub(crate) fn verify_public_case_v3(
    completed: &AuthenticatedCompletedPublicEvidenceV2,
    expected: &ExpectedCaseSubjectV1<'_>,
    result_path: &str,
    facts_path: &str,
    capture_path: &str,
) -> Result<VerifiedNativeCaseV1> {
    if completed.origin.descriptor().subject.stage != ObserverStageV1::Public {
        return fail("candidate origin cannot authorize public case");
    }
    let result = completed.origin.leaf(result_path)?;
    verify_origin_bound_case(
        &completed.origin,
        expected,
        facts_path,
        result,
        capture_path,
    )
}

/// Rebuild the 22 ordinary public family proofs from completed custody. The
/// three composite protocols are reconstructed by their specialist adapters.
pub(crate) fn replay_completed_public_ordinary(
    intent: &StaticPublicSuiteIntentV1,
    completed: &AuthenticatedCompletedPublicEvidenceV2,
) -> Result<Vec<VerifiedNativeCaseV1>> {
    replay_public_ordinary_origin(intent, completed.origin())
}

pub(crate) fn replay_public_ordinary_origin(
    intent: &StaticPublicSuiteIntentV1,
    origin: &impl crate::private_observer_session::ObserverEvidenceV1,
) -> Result<Vec<VerifiedNativeCaseV1>> {
    if origin.descriptor().subject.stage != ObserverStageV1::Public {
        return fail("nonpublic origin cannot authorize public replay");
    }
    let mut verified = Vec::with_capacity(22);
    for (ordinal, scenario) in intent
        .scenarios
        .iter()
        .enumerate()
        .filter(|(ordinal, _)| ![0, 20, 24].contains(ordinal))
    {
        let root = std::path::Path::new("cases").join(ordinal.to_string());
        let path = |name: &str| root.join(name).to_string_lossy().into_owned();
        let facts_path = path("facts.json");
        let facts: crate::private_candidate_replay::CaseReplayFactsV1 =
            crate::private_observer_session::strict_json(origin.leaf(&facts_path)?, 1024 * 1024)?;
        let interval = origin
            .descriptor()
            .intervals
            .iter()
            .find(|interval| interval.interval_id == facts.interval_id)
            .ok_or_else(|| {
                CiError::Message("public replay exact physical interval absent".into())
            })?;
        let (challenge, prepared_argv) =
            crate::private_public_plan::prepared_public_case_recipe_v1(
                intent,
                &origin.descriptor().session_nonce,
                interval.generation,
                &scenario.selector,
            )?;
        let key = memcordon_core::private_release_case_v1::private_release_case_key_v1(
            memcordon_core::private_release_case_v1::PrivateReleaseStageV1::FinalPublic,
            &scenario.selector,
            &challenge,
        )
        .map_err(CiError::Message)?;
        let (observed_challenge, observed_argv) =
            crate::private_public_plan::public_first_observed_fixture_recipe_v1(
                &scenario.selector,
                challenge,
                &prepared_argv,
            )?;
        let expected_response =
            memcordon_core::private_release_case_v1::public_fixture_expected_response_v1(
                &scenario.selector,
                &observed_challenge,
                scenario.recipe.port,
            )
            .map_err(|error| CiError::Message(error.into()))?;
        let recipe = &scenario.recipe;
        let expected = ExpectedCaseSubjectV1 {
            selector: &scenario.selector,
            result_key: &key,
            fixture_sha256: &scenario.fixture_sha256,
            filter_sha256: &recipe.filter_sha256,
            filter_install_source_sha256: recipe.filter_install_source_sha256.as_ref(),
            facility_source_sha256: recipe.facility_source_sha256.as_ref(),
            host_preservation_source_sha256: recipe.host_preservation_source_sha256.as_ref(),
            reuse_source_sha256: None,
            fixture_argv: &observed_argv,
            uid: recipe.target_uid,
            gid: recipe.target_gid,
            groups: &recipe.supplementary_groups,
            port: recipe.port,
            challenge: &challenge,
            auxiliary_semantics_sha256: Some(&intent.semantics_policy.approved_semantics_sha256),
            exact_response: &expected_response,
        };
        if facts.result_key != key
            || facts.selector != scenario.selector
            || interval.logical_case_key != key
            || facts.generation != interval.generation
        {
            return fail("public replay recipe/physical interval differs");
        }
        if matches!(
            scenario.selector.as_str(),
            "private_tcp::authorization_uncertainty_retired"
                | "private_tcp::dual_attempt_namespace_isolation"
                | "private_tcp::frontend_loss_retired"
                | "private_tcp::guardian_loss_retired"
        ) {
            crate::private_public_fault_dual_replay::replay_public_fault_dual_origin(
                intent, origin, ordinal,
            )?;
        }
        crate::private_public_ordinary_replay::verify_public_case_inputs(
            intent, origin, ordinal, interval, &challenge, &key,
        )?;
        verified.push(verify_origin_bound_case(
            origin,
            &expected,
            &facts_path,
            origin.leaf(&path("result.json"))?,
            &interval.capture_path,
        )?);
    }
    Ok(verified)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProtectedPublicSigningIntentV1 {
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
    archive_path: std::path::PathBuf,
    native_build_context_sha256: String,
    native_raw_index_sha256: String,
    native_completed_provenance_sha256: String,
    native_accepted_case_set_sha256: String,
}

pub(crate) fn verify_installed_native_certificate(
    intent: &ProtectedPublicCollectorIntentV1,
    completed: &AuthenticatedCompletedPublicEvidenceV2,
    signing: &ProtectedPublicSigningIntentV1,
) -> Result<memcordon_core::release_trust::VerifiedNativeQualificationV1> {
    use memcordon_core::release_trust::{
        ExpectedNativeQualificationV1, ReleaseTrustAnchorV1,
        SignedNativeQualificationCertificateV1, TrustHighWaterV1,
    };
    if signing.schema_version != 1
        || signing.repository != intent.repository
        || signing.workflow_path != intent.workflow_path
        || signing.workflow_revision != intent.workflow_revision
        || !signing.archive_path.is_absolute()
    {
        return fail(
            "public signing policy subject/archive route differs from protected collector",
        );
    }
    let anchor = ReleaseTrustAnchorV1 {
        root_key_id: signing.root_key_id.clone(),
        public_key_hex: signing.root_public_key_hex.clone(),
    };
    let high_water = TrustHighWaterV1 {
        policy_version: signing.high_water_policy_version,
        release_sequence: signing.high_water_release_sequence,
        last_accepted_wall_unix: signing.high_water_wall_unix,
    };
    let policy = signing
        .signed_policy
        .verify(&anchor, &high_water, signing.issued_at_unix)
        .map_err(CiError::Message)?;
    let certificate = SignedNativeQualificationCertificateV1::parse(
        completed.origin.leaf("installed/native-certificate.json")?,
    )
    .map_err(CiError::Message)?;
    let build_hash = String::from(intent.suite.observer_subject.build_sha256.clone());
    let expected = ExpectedNativeQualificationV1 {
        repository_id: intent.suite.observer_subject.repository_id,
        repository: &intent.repository,
        workflow_path: &intent.workflow_path,
        workflow_revision: &intent.workflow_revision,
        target: &intent.suite.observer_subject.target,
        native_machine: if intent.suite.observer_subject.target == "x86_64-unknown-linux-gnu" {
            "x86_64"
        } else {
            "aarch64"
        },
        verifier_sha256: &signing.verifier_sha256,
        source_commit: &intent.suite.observer_subject.source_commit,
        release_version: &intent.suite.observer_subject.release_version,
        build_sha256: &build_hash,
        build_context_sha256: &signing.native_build_context_sha256,
        qualification_bytes: completed.origin.leaf("installed/qualification.json")?,
        raw_index_sha256: &signing.native_raw_index_sha256,
        completed_provenance_sha256: &signing.native_completed_provenance_sha256,
        accepted_case_set_sha256: &signing.native_accepted_case_set_sha256,
    };
    let verified = certificate
        .verify(&policy, &expected, &high_water, signing.issued_at_unix)
        .map_err(CiError::Message)?;
    if verified.release_sequence() != signing.release_sequence
        || verified.certificate_sha256()
            != String::from(
                intent
                    .suite
                    .qualification_certificate_payload_sha256
                    .clone(),
            )
    {
        return fail("public installed CQ canonical subject/sequence differs");
    }
    Ok(verified)
}

/// Completed Actions readback, custodian origin, ordinary and specialist
/// semantics must all succeed before the delegated PublicP credential is read.
pub fn collect_signed_private_p_after_completed_producer(
    intent_path: &std::path::Path,
    build_path: &std::path::Path,
    signing_path: &std::path::Path,
    credential_fd: u32,
    output_dir: &std::path::Path,
) -> Result<()> {
    #[cfg(unix)]
    {
        collect_signed_private_p_with_replay(
            intent_path,
            build_path,
            signing_path,
            credential_fd,
            output_dir,
            crate::private_public_specialist_replay::replay_completed_public_specialists,
        )
    }
    #[cfg(not(unix))]
    {
        let _ = (
            intent_path,
            build_path,
            signing_path,
            credential_fd,
            output_dir,
        );
        fail("protected completed PublicP signing requires Linux")
    }
}

pub(crate) fn collect_signed_private_p_with_replay(
    intent_path: &std::path::Path,
    build_path: &std::path::Path,
    signing_path: &std::path::Path,
    credential_fd: u32,
    output_dir: &std::path::Path,
    replay_specialists: fn(
        &StaticPublicSuiteIntentV1,
        &AuthenticatedCompletedPublicEvidenceV2,
    ) -> Result<crate::private_public_verify::PublicSpecialistProofsV1>,
) -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            intent_path,
            build_path,
            signing_path,
            credential_fd,
            output_dir,
            replay_specialists,
        );
        fail("protected completed PublicP signing requires Linux")
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        if credential_fd < 3
            || !output_dir.is_absolute()
            || std::fs::symlink_metadata(output_dir).is_ok()
        {
            return fail("PublicP exclusive output/credential descriptor differs");
        }
        let intent = ProtectedPublicCollectorIntentV1::parse(
            &crate::private_protected_readback::read_protected_raw_case_file(intent_path)?,
        )?;
        let signing: ProtectedPublicSigningIntentV1 = crate::private_observer_session::strict_json(
            &crate::private_protected_readback::read_protected_raw_case_file(signing_path)?,
            128 * 1024,
        )?;
        let build_bytes =
            crate::private_observer_session::read_bounded_file(build_path, 16 * 1024)?;
        if hash_bytes(&build_bytes) != intent.suite.observer_subject.build_sha256 {
            return fail("PublicP actual B differs from protected static intent");
        }
        let mut custody = AuthenticatedCustodianTransportV1::connect(&intent.custody_policy)?;
        let token = std::env::var("GITHUB_TOKEN")
            .map_err(|_| CiError::Message("public Actions readback token absent".into()))?;
        let completed = collect_completed_public(&intent, &token, &mut custody)?;
        let q = verify_installed_native_certificate(&intent, &completed, &signing)?;
        let ordinary = replay_completed_public_ordinary(&intent.suite, &completed)?;
        let specialists = replay_specialists(&intent.suite, &completed)?;
        let semantics =
            assemble_public_semantics_v3(&intent.suite, &completed, ordinary, &specialists)?;
        let _completed_run =
            crate::private_release_gate::complete_final_public_run(&completed, &semantics)?;
        let p = produce_public_evidence_index_v3(&semantics)?;
        let archive = crate::private_observer_session::read_bounded_file(
            &signing.archive_path,
            intent.suite.archive_size,
        )?;
        if archive.len() as u64 != intent.suite.archive_size
            || hash_bytes(&archive) != intent.suite.archive_sha256
        {
            return fail("PublicP independently protected A bytes differ");
        }
        let final_generation = completed
            .origin
            .descriptor()
            .generations
            .last()
            .ok_or_else(|| CiError::Message("PublicP final H1 absent".into()))?;
        let h1_path = std::path::Path::new("installed")
            .join("generations")
            .join(final_generation.generation.to_string())
            .join("h1.json");
        let h1_path = h1_path
            .to_str()
            .ok_or_else(|| CiError::Message("PublicP H1 path encoding differs".into()))?;
        let anchor = memcordon_core::release_trust::ReleaseTrustAnchorV1 {
            root_key_id: signing.root_key_id.clone(),
            public_key_hex: signing.root_public_key_hex.clone(),
        };
        let high_water = memcordon_core::release_trust::TrustHighWaterV1 {
            policy_version: signing.high_water_policy_version,
            release_sequence: signing.high_water_release_sequence,
            last_accepted_wall_unix: signing.high_water_wall_unix,
        };
        let key = crate::private_completed_run::read_release_signing_credential(credential_fd)?;
        let authority = crate::private_public_verify::PublicCertificateSigningIntentV1 {
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
            build_bytes: &build_bytes,
            qualification_bytes: completed.origin.leaf("installed/qualification.json")?,
            qualification_certificate_bytes: completed
                .origin
                .leaf("installed/native-certificate.json")?,
            archive_bytes: &archive,
            manifest_bytes: completed.origin.leaf("installed/manifest.json")?,
            host_receipt_bytes: completed.origin.leaf(h1_path)?,
            issued_at_unix: signing.issued_at_unix,
            expires_at_unix: signing.expires_at_unix,
        };
        let cp = sign_public_qualification_certificate_v2(&semantics, &completed, &q, &authority)?;
        std::fs::create_dir(output_dir)?;
        std::fs::set_permissions(output_dir, std::fs::Permissions::from_mode(0o700))?;
        let open = |name: &str| -> Result<std::fs::File> {
            Ok(std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(output_dir.join(name))?)
        };
        for (name, bytes) in [
            ("public-evidence.json", p.as_slice()),
            ("public-evidence.certificate.json", cp.as_slice()),
            (
                "completed-provenance.json",
                canonical_json(&completed.provenance)?.as_slice(),
            ),
        ] {
            let mut file = open(name)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            if crate::private_observer_session::read_bounded_file(
                &output_dir.join(name),
                128 * 1024,
            )? != bytes
            {
                return fail("PublicP exclusive output readback differs");
            }
        }
        completed.export_raw(open("raw-public.zip")?)?.sync_all()?;
        std::fs::File::open(output_dir)?.sync_all()?;
        std::fs::File::open(
            output_dir
                .parent()
                .ok_or_else(|| CiError::Message("PublicP output parent absent".into()))?,
        )?
        .sync_all()?;
        Ok(())
    }
}

pub(crate) fn assemble_public_semantics_v3(
    intent: &StaticPublicSuiteIntentV1,
    completed: &AuthenticatedCompletedPublicEvidenceV2,
    cases: Vec<VerifiedNativeCaseV1>,
    specialists: &crate::private_public_verify::PublicSpecialistProofsV1,
) -> Result<VerifiedPublicSemanticsV3> {
    let timeline = verify_installed_public_timeline(intent, &completed.origin)?;
    verify_public_case_set(intent, &completed.origin, &timeline, &cases)?;
    specialists.verify_completed_links(intent, &completed.origin, &cases)?;
    let historical = hash_bytes(completed.origin.leaf("historical/epoch-transition.json")?);
    let mut rows: Vec<_> = cases
        .iter()
        .map(|case| PublicCaseDigestV3 {
            selector: case.selector().into(),
            evidence_format: PublicCaseEvidenceFormatV3::SingleCaseV3,
            case_sha256: case.result_hash().clone(),
            result_key: case.result_key().clone(),
            generation_ref: case.generation(),
            raw_case_commitment_sha256: case.raw_commitment().clone(),
        })
        .collect();
    rows.extend(specialists.rows(completed)?);
    rows.sort_by_key(|row| {
        REQUIRED_PRIVATE_RELEASE_SELECTORS_V1
            .iter()
            .position(|selector| *selector == row.selector)
            .expect("verified selector is in closed catalogue")
    });
    let generation = timeline.final_generation();
    let index = PublicEvidenceIndexV3 {
        schema_version: 3,
        target: intent.observer_subject.target.clone(),
        native_machine: if intent.observer_subject.target == "x86_64-unknown-linux-gnu" {
            "x86_64".into()
        } else {
            "aarch64".into()
        },
        source_commit: intent.observer_subject.source_commit.clone(),
        release_version: intent.observer_subject.release_version.clone(),
        build_sha256: intent.observer_subject.build_sha256.clone(),
        archive_sha256: intent.archive_sha256.clone(),
        archive_size: intent.archive_size,
        manifest_sha256: intent.manifest_sha256.clone(),
        qualification_sha256: intent.qualification_sha256.clone(),
        qualification_certificate_file_sha256: intent.qualification_certificate_file_sha256.clone(),
        qualification_certificate_payload_sha256: intent
            .qualification_certificate_payload_sha256
            .clone(),
        host_receipt_sha256: generation.installed_receipt_sha256.clone(),
        installation_epoch: generation.installation_epoch.clone(),
        boot_identity: timeline.boot_id().into(),
        generation_timeline_sha256: timeline.digest().clone(),
        origin_commitment_sha256: completed.origin.origin_commitment_sha256().clone(),
        custody_receipt_sha256: completed.origin.receipt_sha256().clone(),
        payload_index_sha256: completed.origin.payload_index_sha256().clone(),
        raw_index_sha256: completed.raw_index_sha256.clone(),
        completed_provenance_sha256: completed.provenance_sha256.clone(),
        catalogue_sha256: intent.observer_subject.catalogue_sha256.clone(),
        semantics_sha256: intent.semantics_policy.approved_semantics_sha256.clone(),
        historical_transition_sha256: historical,
        cases: rows,
    };
    PublicEvidenceIndexV3::parse(&canonical_json(&index)?)?;
    Ok(VerifiedPublicSemanticsV3 { index })
}

fn verify_public_case_set(
    intent: &StaticPublicSuiteIntentV1,
    origin: &impl crate::private_observer_session::ObserverEvidenceV1,
    timeline: &VerifiedInstalledPublicTimelineV1,
    cases: &[VerifiedNativeCaseV1],
) -> Result<()> {
    if cases.len() != 22 || origin.descriptor().subject != intent.observer_subject {
        return fail("public ordinary22 origin/count differs");
    }
    let mut keys = BTreeSet::new();
    for (case, scenario) in cases.iter().zip(
        intent
            .scenarios
            .iter()
            .enumerate()
            .filter(|(ordinal, _)| ![0, 20, 24].contains(ordinal))
            .map(|(_, scenario)| scenario),
    ) {
        let (challenge, _) = crate::private_public_plan::prepared_public_case_recipe_v1(
            intent,
            &origin.descriptor().session_nonce,
            case.generation(),
            &scenario.selector,
        )?;
        let expected_key = memcordon_core::private_release_case_v1::private_release_case_key_v1(
            memcordon_core::private_release_case_v1::PrivateReleaseStageV1::FinalPublic,
            &scenario.selector,
            &challenge,
        )
        .map_err(CiError::Message)?;
        let spec = crate::private_case_semantics::closed_case_spec(
            &scenario.selector,
            &intent.observer_subject.target,
        )?;
        if case.selector() != scenario.selector
            || case.stage() != ObserverStageV1::Public
            || case.result_key() != &expected_key
            || !keys.insert(*case.result_key().bytes())
            || !timeline
                .generations()
                .iter()
                .any(|generation| generation.generation == case.generation())
            || case.origin_commitment_sha256 != *origin.origin_commitment_sha256()
            || case
                .branch_set()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                != spec.branches
        {
            return fail("public selector/stage/generation/branch/raw origin differs");
        }
    }
    Ok(())
}

/// Live custody may prove export completeness, never completed Actions or P
/// signing authority. The completed collector replays the same sources again.
pub(crate) fn verify_public_live_all25(
    intent: &StaticPublicSuiteIntentV1,
    origin: &impl crate::private_observer_session::ObserverEvidenceV1,
) -> Result<()> {
    if origin.completed() {
        return fail("live exporter requires its sealed live capability");
    }
    let timeline = crate::private_public_plan::verify_public_timeline_origin(intent, origin)?;
    let cases = replay_public_ordinary_origin(intent, origin)?;
    verify_public_case_set(intent, origin, &timeline, &cases)?;
    let specialists = crate::private_public_verify::PublicSpecialistProofsV1 {
        abi: crate::private_public_specialist_replay::replay_public_abi_origin(intent, origin)?,
        reuse: crate::private_public_specialist_replay::replay_public_reuse_origin(intent, origin)?,
        policy: crate::private_public_policy_replay::replay_public_policy_origin(intent, origin)?,
        historical: crate::private_public_specialist_replay::replay_public_history_origin(
            intent, origin,
        )?,
    };
    specialists.verify_completed_links(intent, origin, &cases)
}

pub(crate) fn produce_public_evidence_index_v3(
    verified: &VerifiedPublicSemanticsV3,
) -> Result<Vec<u8>> {
    let bytes = canonical_json(&verified.index)?;
    PublicEvidenceIndexV3::parse(&bytes)?;
    Ok(bytes)
}

/// Existing PublicP authority signs a regenerated completed decision. No
/// supplied hash or serialized capability can request this operation.
pub(crate) fn sign_public_qualification_certificate_v2(
    verified: &VerifiedPublicSemanticsV3,
    completed: &AuthenticatedCompletedPublicEvidenceV2,
    q: &memcordon_core::release_trust::VerifiedNativeQualificationV1,
    intent: &crate::private_public_verify::PublicCertificateSigningIntentV1<'_>,
) -> Result<Vec<u8>> {
    use ed25519_dalek::Signer;
    use memcordon_core::public_release_trust::{
        ExpectedPublicQualificationV1, ExpectedPublicQualificationV2,
        PublicQualificationCertificateV1, PublicQualificationCertificateV2,
        SignedPublicQualificationCertificateV2,
    };
    let p = &verified.index;
    let p_bytes = produce_public_evidence_index_v3(verified)?;
    let policy = intent
        .signed_policy
        .verify(
            intent.trust_anchor,
            intent.high_water,
            intent.issued_at_unix,
        )
        .map_err(CiError::Message)?;
    let key = policy
        .policy()
        .delegated_keys
        .iter()
        .find(|key| key.key_id == intent.key_id)
        .ok_or_else(|| CiError::Message("public signing key is not delegated".into()))?;
    let provenance = &completed.provenance;
    let signed_q = memcordon_core::release_trust::SignedNativeQualificationCertificateV1::parse(
        intent.qualification_certificate_bytes,
    )
    .map_err(CiError::Message)?;
    let build = memcordon_core::private_release_build_v2::PrivateCandidateRecordV2::parse(
        intent.build_bytes,
    )
    .map_err(CiError::Message)?;
    if p.raw_index_sha256 != completed.raw_index_sha256
        || p.completed_provenance_sha256 != completed.provenance_sha256
        || p.payload_index_sha256 != *completed.origin.payload_index_sha256()
        || p.origin_commitment_sha256 != *completed.origin.origin_commitment_sha256()
        || p.custody_receipt_sha256 != *completed.origin.receipt_sha256()
        || p.generation_timeline_sha256 != *completed.origin.generation_timeline_sha256()
        || hash_bytes(intent.build_bytes) != p.build_sha256
        || hash_bytes(intent.archive_bytes) != p.archive_sha256
        || intent.archive_bytes.len() as u64 != p.archive_size
        || hash_bytes(intent.manifest_bytes) != p.manifest_sha256
        || hash_bytes(intent.qualification_bytes) != p.qualification_sha256
        || hash_bytes(intent.host_receipt_bytes) != p.host_receipt_sha256
        || hash_bytes(intent.qualification_certificate_bytes)
            != p.qualification_certificate_file_sha256
        || hash_bytes(
            &signed_q
                .payload
                .canonical_bytes()
                .map_err(CiError::Message)?,
        ) != p.qualification_certificate_payload_sha256
        || q.certificate_sha256()
            != String::from(p.qualification_certificate_payload_sha256.clone())
        || q.release_sequence() != intent.release_sequence
        || signed_q.payload.build_sha256 != String::from(p.build_sha256.clone())
        || signed_q.payload.qualification_sha256 != String::from(p.qualification_sha256.clone())
        || signed_q.payload.target != p.target
        || signed_q.payload.source_commit != p.source_commit
        || signed_q.payload.release_version != p.release_version
        || build.target != p.target
        || build.source_commit != p.source_commit
        || build.version != p.release_version
        || !key
            .roles
            .contains(&memcordon_core::release_trust::ReleaseSigningRoleV1::PublicP)
        || key.public_key_hex != hex::encode(intent.signing_key.verifying_key().as_bytes())
    {
        return fail("public V2 signing completed provenance/release/key subject differs");
    }
    let mut accepted = b"memcordon/public-accepted-case-set/v3\0".to_vec();
    for case in &p.cases {
        let row = canonical_json(case)?;
        accepted.extend_from_slice(&(row.len() as u64).to_be_bytes());
        accepted.extend_from_slice(&row);
    }
    let accepted_hash = String::from(hash_bytes(&accepted));
    let subject = PublicQualificationCertificateV1 {
        schema_version: 1,
        policy_version: policy.policy().policy_version,
        key_id: intent.key_id.into(),
        release_sequence: intent.release_sequence,
        build_sha256: String::from(p.build_sha256.clone()),
        qualification_sha256: String::from(p.qualification_sha256.clone()),
        qualification_certificate_sha256: String::from(
            p.qualification_certificate_payload_sha256.clone(),
        ),
        archive_sha256: String::from(p.archive_sha256.clone()),
        manifest_sha256: String::from(p.manifest_sha256.clone()),
        host_receipt_sha256: String::from(p.host_receipt_sha256.clone()),
        public_evidence_sha256: String::from(hash_bytes(&p_bytes)),
        public_evidence_size: p_bytes.len() as u64,
        raw_index_sha256: String::from(p.raw_index_sha256.clone()),
        completed_provenance_sha256: String::from(p.completed_provenance_sha256.clone()),
        target: p.target.clone(),
        native_machine: p.native_machine.clone(),
        source_commit: p.source_commit.clone(),
        release_version: p.release_version.clone(),
        repository_id: provenance.repository_id,
        repository: provenance.repository.clone(),
        workflow_path: provenance.workflow_path.clone(),
        workflow_revision: provenance.workflow_revision.clone(),
        run_id: provenance.run_id,
        run_attempt: provenance.run_attempt,
        producer_job_id: provenance.producer_job_id,
        artifact_id: provenance.artifact_id,
        verifier_sha256: intent.verifier_sha256.into(),
        verifier_source_commit: intent.verifier_source_commit.into(),
        verifier_policy_sha256: policy.policy().verifier_policy_sha256.clone(),
        catalogue_sha256: String::from(p.catalogue_sha256.clone()),
        accepted_case_set_sha256: accepted_hash.clone(),
        issued_at_unix: intent.issued_at_unix,
        expires_at_unix: intent.expires_at_unix,
        decision: "Complete".into(),
    };
    let payload = PublicQualificationCertificateV2 {
        schema_version: 2,
        subject,
        payload_index_sha256: String::from(p.payload_index_sha256.clone()),
        origin_commitment_sha256: String::from(p.origin_commitment_sha256.clone()),
        custody_receipt_sha256: String::from(p.custody_receipt_sha256.clone()),
        generation_timeline_sha256: String::from(p.generation_timeline_sha256.clone()),
        qualification_certificate_file_sha256: String::from(
            p.qualification_certificate_file_sha256.clone(),
        ),
        semantics_sha256: String::from(p.semantics_sha256.clone()),
    };
    let signed = SignedPublicQualificationCertificateV2 {
        signature_hex: hex::encode(
            intent
                .signing_key
                .sign(&payload.canonical_bytes().map_err(CiError::Message)?)
                .to_bytes(),
        ),
        payload,
    };
    let s = &signed.payload.subject;
    signed
        .verify(
            &policy,
            &ExpectedPublicQualificationV2 {
                subject: ExpectedPublicQualificationV1 {
                    release_sequence: intent.release_sequence,
                    repository_id: provenance.repository_id,
                    repository: intent.repository,
                    workflow_path: intent.workflow_path,
                    workflow_revision: intent.workflow_revision,
                    run_id: provenance.run_id,
                    run_attempt: provenance.run_attempt,
                    producer_job_id: provenance.producer_job_id,
                    artifact_id: provenance.artifact_id,
                    target: &p.target,
                    native_machine: &p.native_machine,
                    source_commit: &p.source_commit,
                    release_version: &p.release_version,
                    verifier_sha256: intent.verifier_sha256,
                    verifier_source_commit: intent.verifier_source_commit,
                    build_sha256: &s.build_sha256,
                    qualification_sha256: &s.qualification_sha256,
                    qualification_certificate_sha256: q.certificate_sha256(),
                    archive_sha256: &s.archive_sha256,
                    manifest_sha256: &s.manifest_sha256,
                    host_receipt_sha256: &s.host_receipt_sha256,
                    public_evidence_bytes: &p_bytes,
                    raw_index_sha256: &s.raw_index_sha256,
                    completed_provenance_sha256: &s.completed_provenance_sha256,
                    accepted_case_set_sha256: &accepted_hash,
                },
                payload_index_sha256: &signed.payload.payload_index_sha256,
                origin_commitment_sha256: &signed.payload.origin_commitment_sha256,
                custody_receipt_sha256: &signed.payload.custody_receipt_sha256,
                generation_timeline_sha256: &signed.payload.generation_timeline_sha256,
                qualification_certificate_file_sha256: &signed
                    .payload
                    .qualification_certificate_file_sha256,
                semantics_sha256: &signed.payload.semantics_sha256,
            },
            intent.high_water,
            intent.issued_at_unix,
        )
        .map_err(CiError::Message)?;
    canonical_json(&signed)
}
