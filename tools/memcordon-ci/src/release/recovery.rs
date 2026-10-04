//! Same-tag recovery checks only the original run's actual artifact routing.
use super::{
    http::{self, ReadBudget, Transport},
    source::{self, SelectedSource},
    tag::TagPlan,
};
use crate::{CiError, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    path::Path,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum RecoveryMode {
    Reprepare,
    PublicationOnly,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedArtifactLocator {
    pub run_id: u64,
    pub prepared_artifact_id: u64,
    pub tool_artifact_id: u64,
}
impl PreparedArtifactLocator {
    pub fn validate(&self) -> Result<()> {
        if self.run_id == 0
            || self.prepared_artifact_id == 0
            || self.tool_artifact_id == 0
            || self.prepared_artifact_id == self.tool_artifact_id
        {
            return Err(CiError::Message("recovery artifact/run IDs invalid".into()));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct RecoveryInput {
    pub tag: String,
    pub mode: RecoveryMode,
    pub original: Option<PreparedArtifactLocator>,
}
fn decimal(value: &str) -> Result<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CiError::Message(
            "recovery ID must be positive decimal".into(),
        ));
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| CiError::Message("recovery ID invalid/overflowing".into()))
}
pub fn parse_event(bytes: &[u8]) -> Result<RecoveryInput> {
    if bytes.len() > 1024 * 1024 {
        return Err(CiError::Message("recovery event exceeds bound".into()));
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(bytes).map_err(CiError::Message)?;
    let value: Value = serde_json::from_slice(bytes)?;
    let inputs = value
        .get("inputs")
        .and_then(Value::as_object)
        .ok_or_else(|| CiError::Message("workflow dispatch inputs absent".into()))?;
    let get = |name: &str| {
        inputs
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| CiError::Message(format!("dispatch input missing: {name}")))
    };
    let tag = get("tag")?.to_owned();
    source::version(&tag)?;
    let mode = match get("recovery-mode")? {
        "reprepare" => RecoveryMode::Reprepare,
        "publication-only" => RecoveryMode::PublicationOnly,
        _ => return Err(CiError::Message("unknown recovery mode".into())),
    };
    let original = if mode == RecoveryMode::PublicationOnly {
        Some(PreparedArtifactLocator {
            run_id: decimal(get("original-run-id")?)?,
            prepared_artifact_id: decimal(get("prepared-artifact-id")?)?,
            tool_artifact_id: decimal(get("tool-artifact-id")?)?,
        })
    } else {
        if [
            "original-run-id",
            "prepared-artifact-id",
            "tool-artifact-id",
        ]
        .into_iter()
        .any(|name| {
            inputs
                .get(name)
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty())
        }) {
            return Err(CiError::Message(
                "original artifact IDs belong only to publication-only recovery".into(),
            ));
        }
        None
    };
    if let Some(original) = &original {
        original.validate()?;
    }
    Ok(RecoveryInput {
        tag,
        mode,
        original,
    })
}

fn headers() -> Result<Vec<(String, String)>> {
    let token = std::env::var("GH_TOKEN")
        .or_else(|_| std::env::var("GITHUB_TOKEN"))
        .map_err(|_| CiError::Message("GitHub read/dispatch credential missing".into()))?;
    if token.is_empty() || token.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(CiError::Message("invalid GitHub credential".into()));
    }
    Ok(vec![
        ("Authorization".into(), format!("Bearer {token}")),
        ("User-Agent".into(), "memcordon-ci".into()),
        ("Accept".into(), "application/vnd.github+json".into()),
        ("X-GitHub-Api-Version".into(), "2022-11-28".into()),
    ])
}
fn string<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| CiError::Message(format!("recovery metadata lacks {name}")))
}

pub fn validate_original(
    transport: &impl Transport,
    budget: &ReadBudget,
    headers: &[(String, String)],
    source: &SelectedSource,
    original: &PreparedArtifactLocator,
) -> Result<()> {
    original.validate()?;
    let get = |parts: &[&str]| -> Result<Value> {
        let response = budget.read(
            transport,
            &http::github_url(&source.repository, parts)?,
            headers,
            4 * 1024 * 1024,
        )?;
        if response.status != 200 {
            return Err(CiError::Message(
                "original recovery metadata unavailable".into(),
            ));
        }
        http::json(&response)
    };
    let run_id = original.run_id.to_string();
    let run = get(&["actions", "runs", &run_id])?;
    let event = string(&run, "event")?;
    if run.get("id").and_then(Value::as_u64) != Some(original.run_id)
        || string(&run, "head_sha")? != source.commit
        || string(&run, "head_branch")? != source.version.to_string()
        || string(&run, "path")? != ".github/workflows/release.yml"
        || !matches!(event, "push" | "workflow_dispatch")
        || run
            .get("repository")
            .and_then(|repository| repository.get("full_name"))
            .and_then(Value::as_str)
            != Some(source.repository.as_str())
    {
        return Err(CiError::Message(
            "original run is not this tag/source/repository release preparation".into(),
        ));
    }
    let mut jobs = Vec::new();
    let mut job_ids = std::collections::BTreeSet::new();
    let attempts = run
        .get("run_attempt")
        .and_then(Value::as_u64)
        .filter(|attempt| (1..=8).contains(attempt))
        .ok_or_else(|| {
            CiError::Message("original run attempt inventory unavailable or exceeds bound".into())
        })?;
    for attempt in 1..=attempts {
        let mut complete = false;
        for page in 1..=8_u16 {
            let mut url = http::github_url(
                &source.repository,
                &[
                    "actions",
                    "runs",
                    &run_id,
                    "attempts",
                    &attempt.to_string(),
                    "jobs",
                ],
            )?;
            url.query_pairs_mut()
                .append_pair("per_page", "100")
                .append_pair("page", &page.to_string());
            let response = budget.read(transport, &url, headers, 4 * 1024 * 1024)?;
            if response.status != 200 {
                return Err(CiError::Message(
                    "original preparation jobs unavailable".into(),
                ));
            }
            let value = http::json(&response)?;
            let rows = value
                .get("jobs")
                .and_then(Value::as_array)
                .ok_or_else(|| CiError::Message("job list absent".into()))?;
            for row in rows {
                let id = row
                    .get("id")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| CiError::Message("job ID absent".into()))?;
                if !job_ids.insert(id) {
                    return Err(CiError::Message("duplicate job ID".into()));
                }
                jobs.push((attempt, row.clone()));
            }
            if rows.len() < 100
                && !response
                    .headers
                    .get("link")
                    .is_some_and(|link| link.contains("rel=\"next\""))
            {
                complete = true;
                break;
            }
        }
        if !complete {
            return Err(CiError::Message(
                "original preparation job pagination incomplete".into(),
            ));
        }
    }
    let mut producing_attempt = None;
    for (artifact_id, kind) in [
        (original.prepared_artifact_id, "prepared"),
        (original.tool_artifact_id, "publication-tool"),
    ] {
        let artifact = get(&["actions", "artifacts", &artifact_id.to_string()])?;
        let run = artifact
            .get("workflow_run")
            .ok_or_else(|| CiError::Message("artifact run binding absent".into()))?;
        if artifact.get("id").and_then(Value::as_u64) != Some(artifact_id)
            || artifact.get("expired").and_then(Value::as_bool) != Some(false)
            || artifact
                .get("size_in_bytes")
                .and_then(Value::as_u64)
                .is_none_or(|size| size == 0 || size > 1024 * 1024 * 1024)
            || run.get("id").and_then(Value::as_u64) != Some(original.run_id)
            || string(run, "head_sha")? != source.commit
            || string(&artifact, "name")? != format!("{kind}-{}", original.run_id)
        {
            return Err(CiError::Message(
                "recovery artifact association/expiry/size differs".into(),
            ));
        }
        let timestamp = |value: &Value, field: &str| -> Result<time::OffsetDateTime> {
            time::OffsetDateTime::parse(
                string(value, field)?,
                &time::format_description::well_known::Rfc3339,
            )
            .map_err(|_| CiError::Message("original artifact/job timestamp invalid".into()))
        };
        let created = timestamp(&artifact, "created_at")?;
        let producer = if kind == "prepared" {
            "assemble"
        } else {
            "select"
        };
        let mut matching = Vec::new();
        for (attempt, job) in &jobs {
            if job.get("name").and_then(Value::as_str) != Some(producer)
                || job.get("conclusion").and_then(Value::as_str) != Some("success")
                || job.get("status").and_then(Value::as_str) != Some("completed")
                || job.get("head_sha").and_then(Value::as_str) != Some(source.commit.as_str())
                || job.get("run_id").and_then(Value::as_u64) != Some(original.run_id)
            {
                continue;
            }
            let started = timestamp(job, "started_at")?;
            let finished = timestamp(job, "completed_at")?;
            if started <= created && created <= finished {
                matching.push(*attempt);
            }
        }
        if matching.len() != 1 || producing_attempt.is_some_and(|attempt| attempt != matching[0]) {
            return Err(CiError::Message("original artifact is not uniquely bound to successful producers in one actual run attempt".into()));
        }
        producing_attempt = Some(matching[0]);
        let digest = string(&artifact, "digest")?
            .strip_prefix("sha256:")
            .ok_or_else(|| CiError::Message("artifact digest absent".into()))?;
        let bytes = http::download(
            transport,
            budget,
            &http::github_url(
                &source.repository,
                &["actions", "artifacts", &artifact_id.to_string(), "zip"],
            )?,
            headers,
            1024 * 1024 * 1024,
        )?;
        if artifacts_digest(&bytes) != digest {
            return Err(CiError::Message(
                "original artifact downloaded checksum differs".into(),
            ));
        }
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;
        let extracted = tempfile::tempdir()?;
        let mut names = std::collections::BTreeSet::new();
        let mut folded_names = std::collections::BTreeSet::new();
        let mut expanded = 0_u64;
        for index in 0..archive.len() {
            let mut file = archive.by_index(index)?;
            super::artifacts::safe_relative(Path::new(file.name()))?;
            expanded = expanded
                .checked_add(file.size())
                .ok_or_else(|| CiError::Message("recovery artifact expanded overflow".into()))?;
            if file.is_symlink()
                || file.is_dir()
                || !folded_names.insert(file.name().to_ascii_lowercase())
                || folded_names.len() > 256
                || expanded > 1024 * 1024 * 1024
            {
                return Err(CiError::Message(
                    "unsafe/duplicate/oversized original artifact".into(),
                ));
            }
            names.insert(file.name().to_owned());
            let output = extracted.path().join(file.name());
            if let Some(parent) = output.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut destination = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output)?;
            let expected = file.size();
            let copied = std::io::copy(&mut file.by_ref().take(expected + 1), &mut destination)?;
            if copied != expected {
                return Err(CiError::Message(
                    "original artifact member length differs".into(),
                ));
            }
            destination.flush()?;
        }
        if kind == "publication-tool"
            && names
                != std::collections::BTreeSet::from(["memcordon-publication-tool.tar.gz".into()])
        {
            return Err(CiError::Message(
                "publication executable inventory differs".into(),
            ));
        }
        if kind == "prepared" && !names.contains("prepared.json") {
            return Err(CiError::Message("prepared artifact metadata absent".into()));
        }
        if kind == "prepared" {
            let loaded = super::bundle::PreparedBundle::load(extracted.path())?;
            if loaded.metadata.source != *source {
                return Err(CiError::Message("original prepared source differs".into()));
            }
            let expected: std::collections::BTreeSet<String> = loaded
                .metadata
                .files
                .iter()
                .map(|file| file.name.clone())
                .chain(["prepared.json".into()])
                .collect();
            if expected != names {
                return Err(CiError::Message(
                    "original prepared file inventory differs".into(),
                ));
            }
        } else {
            let bytes = super::artifacts::read_file(
                &extracted.path().join("memcordon-publication-tool.tar.gz"),
            )?;
            let members = super::target::decode_archive(&bytes, "x86_64-unknown-linux-gnu")?;
            if members
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>()
                != std::collections::BTreeSet::from(["memcordon-ci"])
            {
                return Err(CiError::Message(
                    "publication tool archive inventory differs".into(),
                ));
            }
            super::target::validate_executable(
                &members["memcordon-ci"],
                "x86_64-unknown-linux-gnu",
            )?;
        }
    }
    Ok(())
}
fn artifacts_digest(bytes: &[u8]) -> String {
    super::artifacts::checksum(bytes)
}

pub fn recovery_inputs(root: &Path) -> Result<()> {
    if std::env::var("GITHUB_EVENT_NAME").ok().as_deref() != Some("workflow_dispatch") {
        return Err(CiError::Message(
            "publication-only recovery requires same-tag dispatch".into(),
        ));
    }
    let event_path = std::env::var_os("GITHUB_EVENT_PATH")
        .ok_or_else(|| CiError::Message("event path absent".into()))?;
    let input = parse_event(&super::artifacts::read_file(Path::new(&event_path))?)?;
    if input.mode != RecoveryMode::PublicationOnly {
        return Err(CiError::Message(
            "recovery-inputs requires publication-only mode".into(),
        ));
    }
    let repository = std::env::var("GITHUB_REPOSITORY")
        .map_err(|_| CiError::Message("repository context absent".into()))?;
    let selected: SelectedSource = source::read_json(&root.join(".release/source.json"))?;
    selected.recheck(root)?;
    if selected.repository != repository {
        return Err(CiError::Message("recovery repository differs".into()));
    }
    if input.tag != selected.version.to_string() {
        return Err(CiError::Message(
            "dispatch tag and selected source differ".into(),
        ));
    }
    let original = input.original.expect("validated publication-only IDs");
    validate_original(
        &http::HttpsTransport,
        &ReadBudget::new(Instant::now() + Duration::from_secs(300)),
        &headers()?,
        &selected,
        &original,
    )?;
    crate::workflow_output::write(&[
        ("original-run-id", original.run_id.to_string()),
        (
            "prepared-artifact-id",
            original.prepared_artifact_id.to_string(),
        ),
        ("tool-artifact-id", original.tool_artifact_id.to_string()),
        ("selected-commit", selected.commit),
    ])
}

pub fn dispatch(
    plan: &TagPlan,
    mode: RecoveryMode,
    original: Option<&PreparedArtifactLocator>,
) -> Result<Value> {
    plan.validate()?;
    if (mode == RecoveryMode::PublicationOnly) != original.is_some() {
        return Err(CiError::Message(
            "recovery mode/artifact arguments differ".into(),
        ));
    }
    if let Some(original) = original {
        original.validate()?;
    }
    let headers = headers()?;
    let budget = ReadBudget::new(Instant::now() + Duration::from_secs(120));
    let transport = http::HttpsTransport;
    let workflow = http::github_url(&plan.repository, &["actions", "workflows", "release.yml"])?;
    let response = budget.read(&transport, &workflow, &headers, 1024 * 1024)?;
    if response.status != 200
        || http::json(&response)?.get("state").and_then(Value::as_str) != Some("active")
    {
        return Err(CiError::Message(
            "release dispatch workflow unavailable on default branch".into(),
        ));
    }
    let mut inputs = serde_json::Map::from_iter([
        ("tag".into(), Value::String(plan.version.to_string())),
        (
            "recovery-mode".into(),
            Value::String(
                if mode == RecoveryMode::Reprepare {
                    "reprepare"
                } else {
                    "publication-only"
                }
                .into(),
            ),
        ),
    ]);
    if let Some(original) = original {
        for (name, value) in [
            ("original-run-id", original.run_id),
            ("prepared-artifact-id", original.prepared_artifact_id),
            ("tool-artifact-id", original.tool_artifact_id),
        ] {
            inputs.insert(name.into(), Value::String(value.to_string()));
        }
    }
    let mut headers = headers;
    headers.push(("Content-Type".into(), "application/json".into()));
    let body = serde_json::to_vec(&json!({"ref":plan.version,"inputs":inputs}))?;
    let response = transport.request(
        "POST",
        &http::github_url(
            &plan.repository,
            &["actions", "workflows", "release.yml", "dispatches"],
        )?,
        &headers,
        &body,
        budget.deadline,
        1024 * 1024,
    );
    if response.is_ok_and(|response| response.status == 204) {
        return Ok(json!({"status":"accepted","publication":"not-observed","tag":plan.version}));
    }
    let mut url = http::github_url(
        &plan.repository,
        &["actions", "workflows", "release.yml", "runs"],
    )?;
    url.query_pairs_mut()
        .append_pair("event", "workflow_dispatch")
        .append_pair("branch", &plan.version.to_string())
        .append_pair("per_page", "100");
    let response = budget.read(&transport, &url, &headers, 4 * 1024 * 1024)?;
    if response.status != 200 {
        return Ok(json!({"status":"unknown","publication":"not-observed"}));
    }
    let value = http::json(&response)?;
    let rows = value
        .get("workflow_runs")
        .and_then(Value::as_array)
        .ok_or_else(|| CiError::Message("dispatch run list absent".into()))?;
    let matching: Vec<_> = rows
        .iter()
        .filter(|run| run.get("head_sha").and_then(Value::as_str) == Some(plan.commit.as_str()))
        .map(|run| run.get("id").cloned().unwrap_or(Value::Null))
        .collect();
    Ok(
        json!({"status":if matching.len()==1{"pending"}else{"unknown"},"matching-run-ids":matching,"publication":"not-observed"}),
    )
}
