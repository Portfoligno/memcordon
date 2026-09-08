use std::num::{NonZeroU32, NonZeroU64};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{CiError, Result};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationProvenance {
    pub repository: String,
    pub run_id: NonZeroU64,
    pub run_attempt: NonZeroU32,
    pub job: String,
    pub workflow_ref: String,
    pub workflow_commit: String,
    pub runner_environment: String,
    pub runner_os: String,
    pub runner_arch: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationContext {
    pub schema_version: u32,
    pub source_commit: String,
    pub contract_id: String,
    pub provenance: Option<CertificationProvenance>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedCertificationOrigin {
    pub source_commit: String,
    pub repository: String,
    pub run_id: NonZeroU64,
    pub workflow_ref: String,
    pub workflow_commit: String,
}

impl CertificationContext {
    pub fn capture(root: &Path, contract_id: &str) -> Result<Self> {
        let source_commit = String::from_utf8(crate::command::git(root, ["rev-parse", "HEAD"])?)
            .map_err(|error| CiError::Message(error.to_string()))?
            .trim()
            .to_owned();
        let dirty = crate::command::git(root, ["status", "--porcelain", "--untracked-files=no"])?;
        if !dirty.is_empty() {
            return Err(CiError::Message(
                "certification requires a clean tracked checkout".into(),
            ));
        }
        let names = [
            "GITHUB_REPOSITORY",
            "GITHUB_RUN_ID",
            "GITHUB_RUN_ATTEMPT",
            "GITHUB_JOB",
            "GITHUB_WORKFLOW_REF",
            "GITHUB_WORKFLOW_SHA",
            "RUNNER_ENVIRONMENT",
            "RUNNER_OS",
            "RUNNER_ARCH",
        ];
        let values = names.map(std::env::var);
        let provenance = if values
            .iter()
            .all(|value| matches!(value, Err(std::env::VarError::NotPresent)))
        {
            None
        } else {
            let [
                repository,
                run_id,
                run_attempt,
                job,
                workflow_ref,
                workflow_commit,
                runner_environment,
                runner_os,
                runner_arch,
            ] = values;
            let read = |value: std::result::Result<String, std::env::VarError>| {
                value.map_err(|error| {
                    CiError::Message(format!("incomplete certification provenance: {error}"))
                })
            };
            Some(CertificationProvenance {
                repository: read(repository)?,
                run_id: read(run_id)?
                    .parse()
                    .map_err(|_| CiError::Message("invalid run id".into()))?,
                run_attempt: read(run_attempt)?
                    .parse()
                    .map_err(|_| CiError::Message("invalid run attempt".into()))?,
                job: read(job)?,
                workflow_ref: read(workflow_ref)?,
                workflow_commit: read(workflow_commit)?,
                runner_environment: read(runner_environment)?,
                runner_os: read(runner_os)?,
                runner_arch: read(runner_arch)?,
            })
        };
        let context = Self {
            schema_version: 1,
            source_commit,
            contract_id: contract_id.to_owned(),
            provenance,
        };
        context.validate(contract_id)?;
        Ok(context)
    }

    pub fn validate(&self, contract_id: &str) -> Result<()> {
        if self.schema_version != 1
            || self.contract_id != contract_id
            || !valid_commit(&self.source_commit)
        {
            return Err(CiError::Message("invalid certification context".into()));
        }
        if let Some(p) = &self.provenance {
            if !valid_commit(&p.workflow_commit)
                || p.repository.split('/').count() != 2
                || p.repository.split('/').any(|part| {
                    part.is_empty()
                        || !part.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                        })
                })
                || p.job.is_empty()
                || !p
                    .job
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                || !valid_workflow_ref(&p.repository, &p.workflow_ref)
                || p.runner_environment != "github-hosted"
                || !matches!(p.runner_os.as_str(), "Linux" | "Windows")
                || p.runner_arch != "X64"
            {
                return Err(CiError::Message(
                    "invalid hosted certification provenance".into(),
                ));
            }
        }
        Ok(())
    }
}

pub fn valid_commit(value: &str) -> bool {
    value.len() == std::mem::size_of::<[u8; 20]>() * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_workflow_ref(repository: &str, value: &str) -> bool {
    let Some(relative) = value
        .strip_prefix(repository)
        .and_then(|tail| tail.strip_prefix("/.github/workflows/"))
    else {
        return false;
    };
    let Some((file, reference)) = relative.split_once('@') else {
        return false;
    };
    matches!(file, "backend-certification.yml" | "release.yml")
        && (reference.starts_with("refs/heads/") || reference.starts_with("refs/tags/"))
        && !reference.ends_with('/')
        && !reference.contains("..")
        && reference
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'))
}
