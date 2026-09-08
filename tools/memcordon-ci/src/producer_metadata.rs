//! Independent GitHub job metadata checks for uploaded standard certificates.
use crate::certification_context::{CertificationProvenance, ExpectedCertificationOrigin};
use crate::standard_contract::{StandardContract, StandardTarget};
use crate::{CiError, Result};
use serde_json::Value;

pub fn validate(
    origin: &ExpectedCertificationOrigin,
    provenance: &CertificationProvenance,
    contract: StandardContract,
    run: &Value,
    jobs: &Value,
) -> Result<()> {
    let fail = || CiError::Message("standard certificate producer run/job metadata differs".into());
    let path = provenance
        .workflow_ref
        .split_once("/.github/workflows/")
        .and_then(|(_, value)| value.split_once('@'))
        .map(|(file, _)| [".github/workflows/", file].concat())
        .ok_or_else(fail)?;
    if origin.workflow_commit != origin.source_commit
        || provenance.repository != origin.repository
        || provenance.run_id != origin.run_id
        || provenance.workflow_commit != origin.workflow_commit
        || provenance.workflow_ref != origin.workflow_ref
        || provenance.job != contract.release_job
        || provenance.runner_environment != "github-hosted"
        || run.get("id").and_then(Value::as_u64) != Some(origin.run_id.get())
        || run.get("run_attempt").and_then(Value::as_u64)
            != Some(u64::from(provenance.run_attempt.get()))
        || run.get("head_sha").and_then(Value::as_str) != Some(origin.source_commit.as_str())
        || run.get("path").and_then(Value::as_str) != Some(path.as_str())
        || run.pointer("/repository/full_name").and_then(Value::as_str)
            != Some(origin.repository.as_str())
        || !matches!(
            run.get("event").and_then(Value::as_str),
            Some("push" | "workflow_dispatch")
        )
    {
        return Err(fail());
    }
    let jobs = jobs
        .get("jobs")
        .and_then(Value::as_array)
        .ok_or_else(fail)?;
    let expected_name = match contract.target {
        StandardTarget::LinuxX64 => "Release / Linux standard certification / x64",
        StandardTarget::WindowsX64 => "Release / Windows standard certification / x64",
    };
    let matching: Vec<_> = jobs
        .iter()
        .filter(|job| job.get("name").and_then(Value::as_str) == Some(expected_name))
        .collect();
    if matching.len() != 1 {
        return Err(fail());
    }
    let job = matching[0];
    if job.get("run_id").and_then(Value::as_u64) != Some(origin.run_id.get())
        || job.get("run_attempt").and_then(Value::as_u64)
            != Some(u64::from(provenance.run_attempt.get()))
        || job.get("head_sha").and_then(Value::as_str) != Some(origin.source_commit.as_str())
        || job.get("status").and_then(Value::as_str) != Some("completed")
        || job.get("conclusion").and_then(Value::as_str) != Some("success")
        || !job
            .get("labels")
            .and_then(Value::as_array)
            .is_some_and(|labels| {
                labels
                    .iter()
                    .any(|label| label.as_str() == Some(contract.runner_label))
            })
        || job
            .get("runner_id")
            .and_then(Value::as_u64)
            .is_none_or(|id| id == 0)
    {
        return Err(fail());
    }
    Ok(())
}
