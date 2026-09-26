//! Independent, bounded GitHub Actions readback for a private native artifact.
//!
//! This authenticates where metadata and ZIP bytes were fetched from. It does
//! not authenticate native observations or construct a release qualification.

use std::io::Read;
use std::num::NonZeroU32;
use std::time::Duration;

use serde_json::Value;

use crate::certification_context::{CertificationContext, ExpectedCertificationOrigin};
use crate::private_native::{
    ExpectedNativeRunV2, NativeRunStageV2, PRODUCERS, PrivateNativeProducerSpec,
    StructuralNativeArtifactV2, validate_native_artifact_zip,
};
use crate::{CiError, Result};

const API_ROOT: &str = "https://api.github.com";
const MAX_METADATA_BYTES: usize = 1024 * 1024;
const MAX_ARCHIVE_BYTES: usize = 128 * 1024 * 1024;
const MAX_INVENTORY: usize = 1000;
const PAGE_SIZE: usize = 100;

pub struct StructuralActionsNativeArtifactV2 {
    pub run: Value,
    pub jobs: Value,
    pub artifact: Value,
    pub archive_bytes: Vec<u8>,
}

fn fail(message: &str) -> CiError {
    CiError::Message(message.to_owned())
}

fn valid_repository(repository: &str) -> bool {
    let mut pieces = repository.split('/');
    let valid_piece = |piece: &str| {
        !piece.is_empty()
            && piece.len() <= 100
            && piece
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    };
    matches!((pieces.next(), pieces.next(), pieces.next()), (Some(owner), Some(name), None) if valid_piece(owner) && valid_piece(name))
}

fn complete_inventory<'a>(value: &'a Value, field: &str) -> Result<&'a [Value]> {
    let total = value
        .get("total_count")
        .and_then(Value::as_u64)
        .ok_or_else(|| fail("GitHub Actions inventory count absent"))?;
    let members = value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| fail("GitHub Actions inventory array absent"))?;
    if total > MAX_INVENTORY as u64 || members.len() as u64 != total {
        return Err(fail("GitHub Actions inventory is incomplete or unbounded"));
    }
    Ok(members)
}

fn read_complete_inventory(
    url: &str,
    field: &str,
    mut read: impl FnMut(&str, usize, &str) -> Result<Vec<u8>>,
) -> Result<Value> {
    let mut members = Vec::new();
    let mut expected_total = None;
    let mut ids = std::collections::BTreeSet::new();
    for page in 1..=MAX_INVENTORY / PAGE_SIZE {
        let page_url = if page == 1 {
            url.to_owned()
        } else {
            format!("{url}&page={page}")
        };
        let bytes = read(&page_url, MAX_METADATA_BYTES, "application/vnd.github+json")?;
        if bytes.is_empty() || bytes.len() > MAX_METADATA_BYTES {
            return Err(fail("GitHub Actions inventory page size differs"));
        }
        memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)
            .map_err(CiError::Message)?;
        let value: Value = serde_json::from_slice(&bytes)?;
        let total = value
            .get("total_count")
            .and_then(Value::as_u64)
            .ok_or_else(|| fail("GitHub Actions inventory count absent"))?;
        if total > MAX_INVENTORY as u64 || expected_total.is_some_and(|old| old != total) {
            return Err(fail(
                "GitHub Actions inventory count changed or exceeds bound",
            ));
        }
        expected_total = Some(total);
        let page_members = value
            .get(field)
            .and_then(Value::as_array)
            .ok_or_else(|| fail("GitHub Actions inventory page absent"))?;
        if page_members.len() > PAGE_SIZE || members.len() + page_members.len() > MAX_INVENTORY {
            return Err(fail("GitHub Actions inventory page exceeds bound"));
        }
        for member in page_members {
            let id = member
                .get("id")
                .and_then(Value::as_u64)
                .filter(|id| *id != 0)
                .ok_or_else(|| fail("GitHub Actions inventory member id absent"))?;
            if !ids.insert(id) {
                return Err(fail("GitHub Actions inventory has a duplicated id"));
            }
            members.push(member.clone());
        }
        if members.len() == total as usize {
            let mut combined = serde_json::Map::new();
            combined.insert("total_count".into(), Value::from(total));
            combined.insert(field.to_owned(), Value::Array(members));
            return Ok(Value::Object(combined));
        }
        if page_members.len() != PAGE_SIZE {
            return Err(fail("GitHub Actions inventory pagination is incomplete"));
        }
    }
    Err(fail("GitHub Actions inventory exceeds page bound"))
}

/// Authenticated GitHub metadata for the still-running candidate job. This
/// confirms Actions run/job custody only, not any native case outcome or Q.
pub fn validate_running_candidate_actions_with(
    context: &CertificationContext,
    spec: PrivateNativeProducerSpec,
    mut read: impl FnMut(&str, usize, &str) -> Result<Vec<u8>>,
) -> Result<u64> {
    context.validate("backend-linux-private-v4")?;
    let provenance = context
        .provenance
        .as_ref()
        .ok_or_else(|| fail("running candidate has no hosted provenance"))?;
    let expected_arch = match spec.native_machine {
        "x86_64" => "X64",
        "aarch64" => "ARM64",
        _ => return Err(fail("running candidate native machine differs")),
    };
    if spec.stage != NativeRunStageV2::CandidateCapability
        || provenance.job != spec.job_id
        || provenance.workflow_commit != context.source_commit
        || provenance.runner_os != "Linux"
        || provenance.runner_arch != expected_arch
        || provenance.runner_environment != "github-hosted"
        || !valid_repository(&provenance.repository)
    {
        return Err(fail("running candidate Actions origin differs"));
    }
    let workflow_prefix = format!("{}/.github/workflows/release.yml@", provenance.repository);
    let expected_ref = provenance
        .workflow_ref
        .strip_prefix(&workflow_prefix)
        .ok_or_else(|| fail("running candidate workflow ref differs"))?;
    let run_url = format!(
        "{API_ROOT}/repos/{}/actions/runs/{}/attempts/{}",
        provenance.repository, provenance.run_id, provenance.run_attempt
    );
    let jobs_url = format!("{run_url}/jobs?per_page={PAGE_SIZE}");
    let bounded_json = |bytes: Vec<u8>| -> Result<Value> {
        if bytes.is_empty() || bytes.len() > MAX_METADATA_BYTES {
            return Err(fail("running candidate Actions metadata size differs"));
        }
        memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)
            .map_err(CiError::Message)?;
        Ok(serde_json::from_slice(&bytes)?)
    };
    let run = bounded_json(read(
        &run_url,
        MAX_METADATA_BYTES,
        "application/vnd.github+json",
    )?)?;
    let run_path = run
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| fail("running candidate workflow path absent"))?;
    let (workflow_path, run_ref) = run_path
        .split_once('@')
        .ok_or_else(|| fail("running candidate workflow path differs"))?;
    let short_ref = expected_ref
        .strip_prefix("refs/heads/")
        .or_else(|| expected_ref.strip_prefix("refs/tags/"));
    if run.get("id").and_then(Value::as_u64) != Some(provenance.run_id.get())
        || run.get("run_attempt").and_then(Value::as_u64)
            != Some(u64::from(provenance.run_attempt.get()))
        || run.get("head_sha").and_then(Value::as_str) != Some(context.source_commit.as_str())
        || run.pointer("/repository/full_name").and_then(Value::as_str)
            != Some(provenance.repository.as_str())
        || run.get("event").and_then(Value::as_str) != Some("workflow_dispatch")
        || run.get("status").and_then(Value::as_str) != Some("in_progress")
        || !run.get("conclusion").is_some_and(Value::is_null)
        || workflow_path != ".github/workflows/release.yml"
        || (run_ref != expected_ref && short_ref != Some(run_ref))
    {
        return Err(fail("running candidate Actions run identity differs"));
    }
    let jobs = bounded_json(read(
        &jobs_url,
        MAX_METADATA_BYTES,
        "application/vnd.github+json",
    )?)?;
    let matching: Vec<_> = complete_inventory(&jobs, "jobs")?
        .iter()
        .filter(|job| job.get("name").and_then(Value::as_str) == Some(spec.job_name))
        .collect();
    let [job] = matching.as_slice() else {
        return Err(fail("running candidate Actions job absent or ambiguous"));
    };
    let job_id = job
        .get("id")
        .and_then(Value::as_u64)
        .filter(|id| *id != 0)
        .ok_or_else(|| fail("running candidate Actions job id absent"))?;
    if job.get("run_id").and_then(Value::as_u64) != Some(provenance.run_id.get())
        || job.get("run_attempt").and_then(Value::as_u64)
            != Some(u64::from(provenance.run_attempt.get()))
        || job.get("head_sha").and_then(Value::as_str) != Some(context.source_commit.as_str())
        || job.get("status").and_then(Value::as_str) != Some("in_progress")
        || !job.get("conclusion").is_some_and(Value::is_null)
        || job.get("workflow_name").and_then(Value::as_str) != Some("Release")
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
    {
        return Err(fail("running candidate Actions job identity differs"));
    }
    Ok(job_id)
}

fn fetch_actions_url(token: &str, url: &str, limit: usize, accept: &str) -> Result<Vec<u8>> {
    if token.is_empty() || !url.starts_with(&format!("{API_ROOT}/")) {
        return Err(fail("GitHub Actions request origin or token differs"));
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
        .header("Accept", accept)
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "memcordon-ci")
        .header("Authorization", format!("Bearer {token}"))
        .call()
        .map_err(|error| CiError::Http(Box::new(error)))?;
    let mut bytes = Vec::new();
    response
        .body_mut()
        .as_reader()
        .take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(fail("GitHub Actions response exceeds fixed bound"));
    }
    Ok(bytes)
}

pub fn validate_running_candidate_actions(
    context: &CertificationContext,
    spec: PrivateNativeProducerSpec,
    token: &str,
) -> Result<u64> {
    validate_running_candidate_actions_with(context, spec, |url, limit, accept| {
        fetch_actions_url(token, url, limit, accept)
    })
}

/// All URLs are derived from the independently expected repository/run and
/// fixed Actions endpoints. `read` must fetch each URL from GitHub itself;
/// a test transport can verify the request sequence without network access.
pub fn read_actions_native_artifact_with(
    origin: &ExpectedCertificationOrigin,
    spec: PrivateNativeProducerSpec,
    run_attempt: NonZeroU32,
    mut read: impl FnMut(&str, usize, &str) -> Result<Vec<u8>>,
) -> Result<StructuralActionsNativeArtifactV2> {
    if !valid_repository(&origin.repository) || origin.workflow_commit != origin.source_commit {
        return Err(fail(
            "private Actions origin is not an exact repository/commit",
        ));
    }
    let run_url = format!(
        "{API_ROOT}/repos/{}/actions/runs/{}/attempts/{}",
        origin.repository, origin.run_id, run_attempt
    );
    let jobs_url = format!("{run_url}/jobs?per_page={PAGE_SIZE}");
    let artifacts_url = format!(
        "{API_ROOT}/repos/{}/actions/runs/{}/artifacts?per_page={PAGE_SIZE}",
        origin.repository, origin.run_id
    );
    let read_json = |bytes: Vec<u8>| -> Result<Value> {
        if bytes.is_empty() || bytes.len() > MAX_METADATA_BYTES {
            return Err(fail("GitHub Actions metadata exceeds exact bound"));
        }
        memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)
            .map_err(CiError::Message)?;
        Ok(serde_json::from_slice(&bytes)?)
    };
    let run = read_json(read(
        &run_url,
        MAX_METADATA_BYTES,
        "application/vnd.github+json",
    )?)?;
    if run.get("id").and_then(Value::as_u64) != Some(origin.run_id.get())
        || run.get("run_attempt").and_then(Value::as_u64) != Some(u64::from(run_attempt.get()))
        || run.get("head_sha").and_then(Value::as_str) != Some(origin.source_commit.as_str())
        || run.pointer("/repository/full_name").and_then(Value::as_str)
            != Some(origin.repository.as_str())
    {
        return Err(fail("GitHub Actions run differs from expected origin"));
    }
    let jobs = read_complete_inventory(&jobs_url, "jobs", &mut read)?;
    complete_inventory(&jobs, "jobs")?;
    let artifacts = read_complete_inventory(&artifacts_url, "artifacts", &mut read)?;
    let matching: Vec<_> = complete_inventory(&artifacts, "artifacts")?
        .iter()
        .filter(|artifact| artifact.get("name").and_then(Value::as_str) == Some(spec.artifact_name))
        .collect();
    let [artifact] = matching.as_slice() else {
        return Err(fail(
            "GitHub Actions private artifact is absent or duplicated",
        ));
    };
    let artifact_id = artifact
        .get("id")
        .and_then(Value::as_u64)
        .filter(|id| *id != 0)
        .ok_or_else(|| fail("GitHub Actions private artifact id absent"))?;
    if artifact.get("expired").and_then(Value::as_bool) != Some(false)
        || artifact.pointer("/workflow_run/id").and_then(Value::as_u64) != Some(origin.run_id.get())
    {
        return Err(fail("GitHub Actions private artifact ownership differs"));
    }
    let archive_url = format!(
        "{API_ROOT}/repos/{}/actions/artifacts/{artifact_id}/zip",
        origin.repository
    );
    let archive_bytes = read(&archive_url, MAX_ARCHIVE_BYTES, "application/zip")?;
    if archive_bytes.is_empty() || archive_bytes.len() > MAX_ARCHIVE_BYTES {
        return Err(fail("GitHub Actions private ZIP is empty or unbounded"));
    }
    Ok(StructuralActionsNativeArtifactV2 {
        run,
        jobs,
        artifact: (*artifact).clone(),
        archive_bytes,
    })
}

/// Production transport for the fixed Actions API. The returned data remains
/// structural until ZIP, platform, and native supervisor checks all succeed.
pub fn read_actions_native_artifact(
    origin: &ExpectedCertificationOrigin,
    spec: PrivateNativeProducerSpec,
    run_attempt: NonZeroU32,
    token: &str,
) -> Result<StructuralActionsNativeArtifactV2> {
    read_actions_native_artifact_with(origin, spec, run_attempt, |url, limit, accept| {
        fetch_actions_url(token, url, limit, accept)
    })
}

/// Joins the independently downloaded platform records to the exact ZIP
/// inventory. `expected` must be assembled from B/M0/H0 or M1/A/H1 readback,
/// never from the downloaded envelope. The result is still structural and
/// cannot be used as a trusted native completion or Q producer.
pub fn read_and_validate_actions_native_artifact(
    origin: &ExpectedCertificationOrigin,
    expected: &ExpectedNativeRunV2<'_>,
    token: &str,
) -> Result<StructuralNativeArtifactV2> {
    let spec = PRODUCERS
        .into_iter()
        .find(|spec| spec.stage == expected.stage && spec.target == expected.target)
        .ok_or_else(|| fail("private Actions producer stage/target is unsupported"))?;
    let attempt = NonZeroU32::new(expected.workflow_attempt)
        .ok_or_else(|| fail("private Actions run attempt is zero"))?;
    let fetched = read_actions_native_artifact(origin, spec, attempt, token)?;
    validate_native_artifact_zip(
        &fetched.archive_bytes,
        expected,
        origin,
        &fetched.run,
        &fetched.jobs,
        &fetched.artifact,
    )
}
