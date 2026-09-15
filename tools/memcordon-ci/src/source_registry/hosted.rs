//! Hosted metadata binds native evidence to the workflow which actually emitted it.
//! Callers must obtain these records from the authenticated GitHub API, not artifacts.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::{Cursor, Read};
use std::path::{Component, Path};

use super::observation::Attestation;
use crate::{CiError, Result};

#[derive(Debug, Deserialize, Serialize)]
pub struct Repository {
    pub id: u64,
    pub full_name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorkflowRun {
    pub id: u64,
    #[serde(default)]
    pub run_number: u64,
    pub run_attempt: u64,
    pub head_sha: String,
    pub path: String,
    pub name: String,
    pub event: String,
    pub status: String,
    pub conclusion: Option<String>,
    pub repository: Repository,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Job {
    pub id: u64,
    pub run_id: u64,
    pub run_attempt: u64,
    pub head_sha: String,
    pub name: String,
    pub status: String,
    pub conclusion: Option<String>,
    pub runner_name: String,
    pub runner_id: u64,
    pub labels: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ArtifactRun {
    pub id: u64,
    pub repository_id: u64,
    pub head_sha: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Artifact {
    pub id: u64,
    pub name: String,
    pub size_in_bytes: u64,
    pub digest: Option<String>,
    pub expired: bool,
    pub workflow_run: ArtifactRun,
}

/// Current-run collection may occur before its final merge job completes. Release
/// admission always requires the whole upstream workflow to have succeeded.
#[derive(Clone, Copy)]
pub enum Admission<'a> {
    Completed,
    Current { run_id: u64, checkout: &'a str },
}

pub fn validate_run(
    run: &WorkflowRun,
    repository: &str,
    workflow_path: &str,
    commit: &str,
    admission: Admission<'_>,
) -> Result<()> {
    crate::source_identity::validate(commit)?;
    if run.id == 0
        || run.run_attempt == 0
        || run.repository.id == 0
        || run.repository.full_name != repository
        || run.path != workflow_path
        || run.name.is_empty()
    {
        return Err(CiError::Message("hosted workflow identity mismatch".into()));
    }
    let current = match admission {
        Admission::Completed => false,
        Admission::Current { run_id, checkout } => run.id == run_id && checkout == commit,
    };
    // pull_request checks out the synthetic merge commit, while the API names
    // the pull-request head. Only the collecting run's own trusted context can
    // authorize this spelling difference; release admission cannot.
    if run.head_sha != commit && !(current && run.event == "pull_request") {
        return Err(CiError::Message("hosted workflow commit mismatch".into()));
    }
    if !(run.status == "completed" && run.conclusion.as_deref() == Some("success"))
        && !(current && run.status == "in_progress" && run.conclusion.is_none())
    {
        return Err(CiError::Message("hosted workflow has not succeeded".into()));
    }
    Ok(())
}

pub fn validate_archive(artifact: &Artifact, run: &WorkflowRun, bytes: &[u8]) -> Result<()> {
    let expected = artifact
        .digest
        .as_deref()
        .and_then(|digest| digest.strip_prefix("sha256:"))
        .ok_or_else(|| CiError::Message("hosted artifact lacks SHA-256 digest".into()))?;
    let actual = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if artifact.id == 0
        || artifact.expired
        || usize::try_from(artifact.size_in_bytes).ok() != Some(bytes.len())
        || artifact.workflow_run.id != run.id
        || artifact.workflow_run.repository_id != run.repository.id
        || artifact.workflow_run.head_sha != run.head_sha
        || expected != actual
    {
        return Err(CiError::Message(
            "hosted artifact provenance or digest mismatch".into(),
        ));
    }
    Ok(())
}

pub fn validate_emitter(
    run: &WorkflowRun,
    jobs: &[Job],
    artifact: &Artifact,
    attestation: &Attestation,
) -> Result<u64> {
    let run_id = run.id.to_string();
    let prefix = ["source-observations-", attestation.job.as_str(), "-"].concat();
    if attestation.run_id != run_id
        || attestation.run_attempt != run.run_attempt.to_string()
        || attestation.workflow != run.name
        || attestation.runner_name.is_empty()
        || attestation.job.is_empty()
        || !artifact.name.starts_with(&prefix)
    {
        return Err(CiError::Message(
            "hosted evidence emitter identity mismatch".into(),
        ));
    }
    let matches = jobs
        .iter()
        .filter(|job| {
            job.run_id == run.id
                && job.run_attempt == run.run_attempt
                && job.head_sha == run.head_sha
                && job.runner_name == attestation.runner_name
        })
        .collect::<Vec<_>>();
    let [job] = matches.as_slice() else {
        return Err(CiError::Message(
            "hosted evidence runner is absent or ambiguous".into(),
        ));
    };
    if job.id == 0
        || job.runner_id == 0
        || job.status != "completed"
        || job.conclusion.as_deref() != Some("success")
    {
        return Err(CiError::Message(
            "hosted evidence job did not succeed".into(),
        ));
    }
    Ok(job.id)
}

/// Limits reject the entire archive, never truncate the accepted evidence set.
pub fn read_journals(
    bytes: &[u8],
    maximum_bytes: u64,
    maximum_entries: usize,
) -> Result<Vec<Vec<u8>>> {
    let fail = || {
        CiError::Message("source evidence archive is unsafe, duplicate or exceeds its limit".into())
    };
    if u64::try_from(bytes.len())
        .ok()
        .is_none_or(|size| size > maximum_bytes)
    {
        return Err(fail());
    }
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes))?;
    if zip.len() > maximum_entries {
        return Err(fail());
    }
    let mut names = BTreeSet::new();
    let mut total = 0_u64;
    let mut journals = Vec::new();
    for index in 0..zip.len() {
        let mut entry = zip.by_index(index)?;
        let name = entry.name().to_owned();
        let path = Path::new(&name);
        if name.is_empty()
            || name.contains('\\')
            || name.contains(':')
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
            || !names.insert(name.clone())
            || entry
                .unix_mode()
                .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            return Err(fail());
        }
        total = total.checked_add(entry.size()).ok_or_else(fail)?;
        if total > maximum_bytes {
            return Err(fail());
        }
        if !entry.is_dir()
            && path
                .file_name()
                .is_some_and(|name| name == "source-command-observations-v1.json")
        {
            let expected = entry.size();
            let mut journal = Vec::new();
            entry
                .by_ref()
                .take(expected.checked_add(1).ok_or_else(fail)?)
                .read_to_end(&mut journal)?;
            if u64::try_from(journal.len()).ok() != Some(expected) {
                return Err(fail());
            }
            journals.push(journal);
        }
    }
    if journals.is_empty() {
        return Err(CiError::Message(
            "source evidence archive has no journals".into(),
        ));
    }
    Ok(journals)
}

pub struct ExpectedRun<'a> {
    pub repository: &'a str,
    pub workflow_path: &'a str,
    pub admission: Admission<'a>,
}

pub struct ExpectedLane<'a> {
    pub job: &'a str,
    pub job_name: &'a str,
    pub runner: &'a str,
    pub runner_label: &'a str,
}

/// API-origin metadata and the downloaded archive are kept together. Artifact
/// contents must never supply their own run/job metadata to this boundary.
pub struct HostedArchive<'a> {
    pub run: &'a WorkflowRun,
    pub jobs: &'a [Job],
    pub artifact: &'a Artifact,
    pub bytes: &'a [u8],
}

pub fn attest_archive(
    plan: &super::coverage::Plan,
    expected: &ExpectedRun<'_>,
    lane: &ExpectedLane<'_>,
    archive: &HostedArchive<'_>,
    maximum_bytes: u64,
) -> Result<Attestation> {
    validate_run(
        archive.run,
        expected.repository,
        expected.workflow_path,
        &plan.commit,
        expected.admission,
    )?;
    validate_archive(archive.artifact, archive.run, archive.bytes)?;
    let mut matching = Vec::new();
    for bytes in read_journals(archive.bytes, maximum_bytes, 4096)? {
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        if value.get("suite").and_then(serde_json::Value::as_str) != Some(plan.suite.as_str()) {
            continue;
        }
        let attestation = super::observation::attest_bytes(plan, &bytes)?;
        let job_id = validate_emitter(archive.run, archive.jobs, archive.artifact, &attestation)?;
        let job = archive
            .jobs
            .iter()
            .find(|job| job.id == job_id)
            .ok_or_else(|| CiError::Message("verified emitting job disappeared".into()))?;
        if attestation.job != lane.job
            || attestation.runner != lane.runner
            || job.name != lane.job_name
            || !job.labels.iter().any(|label| label == lane.runner_label)
        {
            return Err(CiError::Message(
                "source evidence belongs to a different workflow lane or architecture".into(),
            ));
        }
        matching.push(attestation);
    }
    if matching.len() != 1 {
        return Err(CiError::Message(
            "source evidence requires exactly one current suite journal per lane".into(),
        ));
    }
    Ok(matching.remove(0))
}
