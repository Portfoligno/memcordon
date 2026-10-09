//! Read-only transport of original producer archives and actual job outcomes.
//! This module never supplies an input to publication or admits a workload.
use super::{
    artifacts,
    http::{self, ReadBudget, Transport},
};
use crate::{
    CiError, Result,
    consumer_readiness_ledger::{CellEvidence, SourceIdentity},
};
use memcordon_readiness_verifier::{
    Artifact, JobOutcome, JobResult, ProducerManifest, ProducerOrigin,
};
use std::{
    collections::BTreeMap,
    fs,
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
};

pub struct DownloadedProducer {
    pub origin: ProducerOrigin,
    pub cell: CellEvidence,
    pub directory: PathBuf,
    pub archive: Artifact,
}

fn positive(value: &serde_json::Value, field: &str) -> Result<u64> {
    value
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            CiError::Message(format!("original producer metadata lacks positive {field}"))
        })
}
fn text<'a>(value: &'a serde_json::Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| CiError::Message(format!("original producer metadata lacks {field}")))
}
fn get(
    transport: &impl Transport,
    budget: &ReadBudget,
    headers: &[(String, String)],
    repository: &str,
    parts: &[&str],
) -> Result<serde_json::Value> {
    let response = budget.read(
        transport,
        &http::github_url(repository, parts)?,
        headers,
        16 * 1024 * 1024,
    )?;
    if response.status != 200 {
        return Err(CiError::Message(
            "original producer API metadata unavailable".into(),
        ));
    }
    http::json(&response)
}

pub fn producer_artifact_id(
    transport: &impl Transport,
    budget: &ReadBudget,
    headers: &[(String, String)],
    repository: &str,
    run: u64,
    attempt: u64,
    job: &str,
) -> Result<u64> {
    let expected = format!("readiness-{job}-{run}-{attempt}");
    let mut selected = None;
    for page in 1..=10 {
        let mut url = http::github_url(
            repository,
            &["actions", "runs", &run.to_string(), "artifacts"],
        )?;
        url.query_pairs_mut()
            .append_pair("per_page", "100")
            .append_pair("page", &page.to_string());
        let response = budget.read(transport, &url, headers, 16 * 1024 * 1024)?;
        if response.status != 200 {
            return Err(CiError::Message(
                "original producer artifact inventory unavailable".into(),
            ));
        }
        let document = http::json(&response)?;
        let entries = document
            .get("artifacts")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| CiError::Message("producer artifacts array absent".into()))?;
        for entry in entries {
            if entry.get("name").and_then(serde_json::Value::as_str) == Some(expected.as_str())
                && selected.replace(positive(entry, "id")?).is_some()
            {
                return Err(CiError::Message(
                    "original producer artifact is ambiguous".into(),
                ));
            }
        }
        if entries.len() < 100 {
            return selected.ok_or_else(|| {
                CiError::Message("required original producer artifact missing".into())
            });
        }
    }
    Err(CiError::Message(
        "producer artifact inventory exceeds finite bound".into(),
    ))
}

/// Uses only the original pair already independently validated by recovery.
pub fn original_preparation_attempt(
    transport: &impl Transport,
    budget: &ReadBudget,
    headers: &[(String, String)],
    repository: &str,
    run: u64,
    prepared_artifact_id: u64,
) -> Result<u64> {
    let metadata = get(
        transport,
        budget,
        headers,
        repository,
        &["actions", "artifacts", &prepared_artifact_id.to_string()],
    )?;
    let suffix = text(&metadata, "name")?
        .strip_prefix("prepared-")
        .ok_or_else(|| CiError::Message("original prepared artifact role differs".into()))?;
    let (named_run, attempt) = suffix
        .split_once('-')
        .ok_or_else(|| CiError::Message("original prepared artifact attempt absent".into()))?;
    if named_run != run.to_string()
        || attempt.is_empty()
        || !attempt.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(CiError::Message(
            "original prepared artifact run/attempt differs".into(),
        ));
    }
    attempt
        .parse::<u64>()
        .ok()
        .filter(|attempt| *attempt > 0)
        .ok_or_else(|| CiError::Message("original prepared attempt invalid".into()))
}

/// Reads the exact attempt, not a latest-success discovery set. Missing required
/// names remain explicit observations supplied to the independently fixed gate.
pub fn job_outcomes(
    transport: &impl Transport,
    budget: &ReadBudget,
    headers: &[(String, String)],
    repository: &str,
    run: u64,
    attempt: u64,
    required: &[&str],
) -> Result<Vec<JobOutcome>> {
    if run == 0 || attempt == 0 {
        return Err(CiError::Message(
            "producer run/attempt must be positive".into(),
        ));
    }
    let run_text = run.to_string();
    let attempt_text = attempt.to_string();
    let mut actual = BTreeMap::new();
    for page in 1..=10 {
        let mut url = http::github_url(
            repository,
            &[
                "actions",
                "runs",
                &run_text,
                "attempts",
                &attempt_text,
                "jobs",
            ],
        )?;
        url.query_pairs_mut()
            .append_pair("per_page", "100")
            .append_pair("page", &page.to_string());
        let response = budget.read(transport, &url, headers, 16 * 1024 * 1024)?;
        if response.status != 200 {
            return Err(CiError::Message(
                "producer job attempt inventory unavailable".into(),
            ));
        }
        let document = http::json(&response)?;
        let jobs = document
            .get("jobs")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| CiError::Message("producer jobs array absent".into()))?;
        for job in jobs {
            let name = text(job, "name")?;
            if !required.contains(&name) {
                continue;
            }
            if positive(job, "run_id")? != run || positive(job, "run_attempt")? != attempt {
                return Err(CiError::Message(
                    "producer job actual attempt association differs".into(),
                ));
            }
            let result = match job.get("conclusion").and_then(serde_json::Value::as_str) {
                Some("success") => JobResult::Success,
                Some("cancelled") => JobResult::Cancelled,
                Some("skipped") => JobResult::Skipped,
                _ => JobResult::Failure,
            };
            if actual.insert(name.to_owned(), result).is_some() {
                return Err(CiError::Message(
                    "duplicate actual named producer job".into(),
                ));
            }
        }
        if jobs.len() < 100 {
            return Ok(required
                .iter()
                .map(|job| JobOutcome {
                    job: (*job).into(),
                    result: actual.get(*job).copied().unwrap_or(JobResult::Missing),
                })
                .collect());
        }
    }
    Err(CiError::Message(
        "producer job inventory exceeds finite pagination bound".into(),
    ))
}

/// Retains the actual GitHub ZIP unchanged. Extraction copies only the strict
/// original manifest's finite files; it never relabels their run or attempt.
#[expect(
    clippy::too_many_arguments,
    reason = "Download custody independently binds transport budget, run, attempt, artifact, producer, source, and destination"
)]
pub fn download_producer(
    transport: &impl Transport,
    budget: &ReadBudget,
    headers: &[(String, String)],
    repository: &str,
    run: u64,
    attempt: u64,
    artifact_id: u64,
    job: &str,
    identity: &SourceIdentity,
    manifest_sha256: &str,
    destination: &Path,
) -> Result<DownloadedProducer> {
    if run == 0 || attempt == 0 || artifact_id == 0 {
        return Err(CiError::Message(
            "producer artifact/run/attempt IDs must be positive".into(),
        ));
    }
    artifacts::safe_basename(job)?;
    let id = artifact_id.to_string();
    let metadata = get(
        transport,
        budget,
        headers,
        repository,
        &["actions", "artifacts", &id],
    )?;
    let expected_name = format!("readiness-{job}-{run}-{attempt}");
    if positive(&metadata, "id")? != artifact_id
        || metadata.get("expired").and_then(serde_json::Value::as_bool) != Some(false)
        || text(&metadata, "name")? != expected_name
        || metadata
            .get("workflow_run")
            .and_then(|run_metadata| run_metadata.get("id"))
            .and_then(serde_json::Value::as_u64)
            != Some(run)
        || metadata
            .get("workflow_run")
            .and_then(|run_metadata| run_metadata.get("head_sha"))
            .and_then(serde_json::Value::as_str)
            != Some(identity.source_commit.as_str())
    {
        return Err(CiError::Message(
            "actual producer artifact role/source/run differs".into(),
        ));
    }
    let declared = text(&metadata, "digest")?
        .strip_prefix("sha256:")
        .ok_or_else(|| CiError::Message("producer upload lacks actual SHA256 digest".into()))?;
    let bytes = http::download(
        transport,
        budget,
        &http::github_url(repository, &["actions", "artifacts", &id, "zip"])?,
        headers,
        512 * 1024 * 1024,
    )?;
    let sha256 = artifacts::checksum(&bytes);
    if sha256 != declared
        || metadata
            .get("size_in_bytes")
            .and_then(serde_json::Value::as_u64)
            != Some(bytes.len() as u64)
    {
        return Err(CiError::Message(
            "downloaded producer ZIP differs from actual immutable upload".into(),
        ));
    }
    fs::create_dir(destination)?;
    let archive_name = format!("producer-{artifact_id}.zip");
    let archive_path = destination.join(&archive_name);
    let mut retained = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&archive_path)?;
    retained.write_all(&bytes)?;
    retained.sync_all()?;
    let mut zip = zip::ZipArchive::new(Cursor::new(&bytes))
        .map_err(|error| CiError::Message(error.to_string()))?;
    if zip.len() > 65_536 {
        return Err(CiError::Message(
            "producer ZIP member count exceeds bound".into(),
        ));
    }
    let mut zip_names = std::collections::BTreeSet::new();
    for index in 0..zip.len() {
        let member = zip
            .by_index(index)
            .map_err(|error| CiError::Message(error.to_string()))?;
        let name = member.name();
        artifacts::safe_relative(Path::new(name.trim_end_matches('/')))?;
        if !zip_names.insert(name.to_owned())
            || member
                .unix_mode()
                .is_some_and(|mode| !matches!(mode & 0o170000, 0 | 0o100000 | 0o040000))
        {
            return Err(CiError::Message(
                "producer ZIP contains duplicate or special member".into(),
            ));
        }
    }
    let manifest_bytes = {
        let member = zip
            .by_name("producer-manifest.json")
            .map_err(|_| CiError::Message("producer ZIP lacks original manifest".into()))?;
        let size = member.size();
        if member.is_dir() || size > 16 * 1024 * 1024 {
            return Err(CiError::Message(
                "producer manifest exceeds bound/type".into(),
            ));
        }
        let mut data = Vec::new();
        member.take(size + 1).read_to_end(&mut data)?;
        if data.len() as u64 != size {
            return Err(CiError::Message(
                "producer manifest decompression length differs".into(),
            ));
        }
        data
    };
    memcordon_core::canonical_json::reject_duplicate_json_keys(&manifest_bytes)
        .map_err(CiError::Message)?;
    let manifest: ProducerManifest = serde_json::from_slice(&manifest_bytes)?;
    if manifest.format != "memcordon.consumer-readiness.producer"
        || manifest.revision != 1
        || manifest.job != job
        || manifest.run_id != run.to_string()
        || manifest.run_attempt != attempt
        || manifest.source_commit != identity.source_commit
        || manifest.source_tree_sha256 != identity.source_tree_sha256
        || manifest.version != identity.version
        || manifest.manifest_sha256 != manifest_sha256
    {
        return Err(CiError::Message(
            "original producer manifest identity differs".into(),
        ));
    }
    let mut names = std::collections::BTreeSet::new();
    if manifest.artifacts.len() > 65_536
        || manifest.records.len() > 65_536
        || manifest.products.len() > 16
        || manifest.component_builds.len() > 4
    {
        return Err(CiError::Message(
            "producer payload collections exceed finite bounds".into(),
        ));
    }
    let mut total = 0u64;
    for artifact in &manifest.artifacts {
        total = total
            .checked_add(artifact.length)
            .filter(|total| *total <= 4 * 1024 * 1024 * 1024)
            .ok_or_else(|| {
                CiError::Message("producer decoded payload exceeds aggregate bound".into())
            })?;
        if artifact.length > 512 * 1024 * 1024 {
            return Err(CiError::Message("producer raw file exceeds bound".into()));
        }
    }
    for artifact in &manifest.artifacts {
        let relative = artifacts::safe_relative(Path::new(&artifact.path))?;
        if relative == Path::new("cell.json")
            || relative == Path::new("producer-manifest.json")
            || relative == Path::new(&archive_name)
            || !names.insert(relative.clone())
            || artifact.length > 1024 * 1024 * 1024
        {
            return Err(CiError::Message(
                "producer original artifact inventory duplicate, reserved or excessive".into(),
            ));
        }
        let member = zip.by_name(&artifact.path).map_err(|_| {
            CiError::Message("original raw artifact missing from producer ZIP".into())
        })?;
        if member.size() != artifact.length || member.is_dir() {
            return Err(CiError::Message(
                "producer ZIP member length/type differs".into(),
            ));
        }
        let mut data = Vec::new();
        member.take(artifact.length + 1).read_to_end(&mut data)?;
        if data.len() as u64 != artifact.length || artifacts::checksum(&data) != artifact.sha256 {
            return Err(CiError::Message(
                "producer original raw artifact bytes differ".into(),
            ));
        }
        let path = destination.join(relative);
        fs::create_dir_all(path.parent().expect("artifact parent"))?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        file.write_all(&data)?;
        file.sync_all()?;
    }
    let cell_bytes = {
        let member = zip
            .by_name("cell.json")
            .map_err(|_| CiError::Message("producer ZIP lacks original cell index".into()))?;
        let size = member.size();
        if member.is_dir() || size > 32 * 1024 * 1024 {
            return Err(CiError::Message(
                "producer cell index exceeds bound/type".into(),
            ));
        }
        let mut data = Vec::new();
        member.take(size + 1).read_to_end(&mut data)?;
        if data.len() as u64 != size {
            return Err(CiError::Message(
                "producer cell decompression length differs".into(),
            ));
        }
        data
    };
    memcordon_core::canonical_json::reject_duplicate_json_keys(&cell_bytes)
        .map_err(CiError::Message)?;
    let cell: CellEvidence = serde_json::from_slice(&cell_bytes)?;
    if cell.format != "memcordon.consumer-readiness.cell"
        || cell.revision != 1
        || cell.identity.run_id != manifest.run_id
        || cell.identity.source_commit != manifest.source_commit
        || cell.identity.source_tree_sha256 != manifest.source_tree_sha256
        || cell.identity.version != manifest.version
        || serde_json::to_value(&cell.records)? != serde_json::to_value(&manifest.records)?
        || serde_json::to_value(&cell.artifacts)? != serde_json::to_value(&manifest.artifacts)?
        || serde_json::to_value(cell.product.iter().collect::<Vec<_>>())?
            != serde_json::to_value(&manifest.products)?
        || serde_json::to_value(cell.component_build.iter().collect::<Vec<_>>())?
            != serde_json::to_value(&manifest.component_builds)?
    {
        return Err(CiError::Message(
            "original cell index differs from sealed producer manifest".into(),
        ));
    }
    let origin = ProducerOrigin {
        repository: Some(repository.into()),
        job: job.into(),
        run_id: run.to_string(),
        run_attempt: attempt,
        artifact_id: id,
        artifact_sha256: sha256.clone(),
        bundle_artifact: archive_name.clone(),
        source_commit: manifest.source_commit,
        source_tree_sha256: manifest.source_tree_sha256,
        version: manifest.version,
        manifest_sha256: manifest.manifest_sha256,
    };
    // Unix supports syncing directory entries. Windows has no equivalent
    // directory FlushFileBuffers operation; every retained file was synced
    // above. This download directory is scratch transport custody, not a
    // recovery journal or an installed publication boundary.
    #[cfg(unix)]
    fs::File::open(destination)?.sync_all()?;
    Ok(DownloadedProducer {
        origin,
        cell,
        directory: destination.into(),
        archive: Artifact {
            path: archive_name,
            length: bytes.len() as u64,
            sha256,
        },
    })
}
