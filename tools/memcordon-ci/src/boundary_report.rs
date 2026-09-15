//! Tracked-source collection and provenance for advisory boundary measurements.
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Component, Path};
use std::time::Duration;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::boundary_metrics::{FileMetrics, analyze_files};
use crate::command::CommandSpec;
use crate::source_registry::{Domain, Source};
use crate::{CiError, Result};

const MAX_HISTORY_COMMITS: usize = 1000;

#[derive(Debug, Serialize)]
pub struct HistoryCommit {
    pub commit: String,
    pub parent_comparison_available: bool,
    pub registered_paths: BTreeSet<String>,
}

#[derive(Debug, Serialize)]
pub struct BoundaryReport {
    pub schema: u32,
    pub producer: ProducerIdentity,
    pub head: String,
    pub tracked_dirty: bool,
    pub tracked_status_sha256: String,
    pub tracked_inventory_sha256: String,
    pub registry_sha256: BTreeMap<String, String>,
    pub source_sha256: BTreeMap<String, String>,
    pub excluded_untracked_registry_sources: BTreeSet<String>,
    pub excluded_deleted_registry_sources: BTreeSet<String>,
    pub unregistered_tracked_sources: BTreeSet<String>,
    pub history_limit: usize,
    pub history_truncated: bool,
    pub shallow_repository: bool,
    pub shallow_boundary_commits: BTreeSet<String>,
    pub history: Vec<HistoryCommit>,
    pub limitations: Vec<String>,
    pub candidates: Vec<CandidateReport>,
}

#[derive(Debug, Serialize)]
pub struct ProducerIdentity {
    pub algorithm: &'static str,
    pub package_version: &'static str,
    pub collector_source_sha256: String,
    pub metrics_source_sha256: String,
    pub build_lock_sha256: String,
}

#[derive(Debug, Serialize)]
pub struct CandidateReport {
    pub id: String,
    pub owner: String,
    pub metrics: FileMetrics,
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn git(root: &Path, arguments: &[&str]) -> Result<Vec<u8>> {
    let output = CommandSpec::new("git", root, Duration::from_secs(120))
        .args(["--no-replace-objects"])
        .args(arguments.iter().copied())
        .output()?;
    if !output.status.success() {
        return Err(CiError::Message(format!(
            "boundary report Git operation failed ({arguments:?}): {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(output.stdout)
}

fn reject_grafts(root: &Path) -> Result<()> {
    let location = utf8(git(root, &["rev-parse", "--git-path", "info/grafts"])?)?;
    match fs::symlink_metadata(root.join(location.trim())) {
        Ok(_) => Err(CiError::Message(
            "boundary history rejects Git graft metadata".into(),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn utf8(bytes: Vec<u8>) -> Result<String> {
    String::from_utf8(bytes)
        .map_err(|error| CiError::Message(format!("boundary report requires UTF-8 paths: {error}")))
}

fn paths(bytes: &[u8]) -> Result<BTreeSet<String>> {
    bytes
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(|path| {
            let path = std::str::from_utf8(path)
                .map_err(|error| CiError::Message(format!("non-UTF-8 tracked path: {error}")))?;
            validate_relative(path)?;
            Ok(path.to_owned())
        })
        .collect()
}

fn validate_relative(path: &str) -> Result<()> {
    if path.is_empty()
        || path.contains('\\')
        || !Path::new(path)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        return Err(CiError::Message(format!(
            "unsafe boundary source path: {path:?}"
        )));
    }
    Ok(())
}

fn read_regular(root: &Path, path: &str) -> Result<Vec<u8>> {
    validate_relative(path)?;
    let mut current = root.to_path_buf();
    for part in Path::new(path).components() {
        current.push(part.as_os_str());
        if fs::symlink_metadata(&current)?.file_type().is_symlink() {
            return Err(CiError::Message(format!(
                "symlink in boundary source path: {path}"
            )));
        }
    }
    if !fs::metadata(&current)?.is_file() {
        return Err(CiError::Message(format!(
            "boundary source is not a file: {path}"
        )));
    }
    Ok(fs::read(current)?)
}

fn source_path(path: &str) -> bool {
    path.ends_with(".rs")
        && ["crates/", "tools/", "fuzz/fuzz_targets/"]
            .iter()
            .any(|prefix| path.starts_with(prefix))
}

fn shallow_state(root: &Path) -> Result<(bool, BTreeSet<String>)> {
    match utf8(git(root, &["rev-parse", "--is-shallow-repository"])?)?.trim() {
        "false" => Ok((false, BTreeSet::new())),
        "true" => {
            let location = utf8(git(root, &["rev-parse", "--git-path", "shallow"])?)?;
            let boundaries = fs::read_to_string(root.join(location.trim()))?
                .lines()
                .map(str::to_owned)
                .collect();
            Ok((true, boundaries))
        }
        other => Err(CiError::Message(format!(
            "unexpected shallow status: {other}"
        ))),
    }
}

/// Reports current tracked working-tree content, not a claim of a clean HEAD.
/// Untracked files are neither read nor included in dirty-state observation.
pub fn collect(root: &Path, history_limit: usize) -> Result<BoundaryReport> {
    if !(1..=MAX_HISTORY_COMMITS).contains(&history_limit) {
        return Err(CiError::Message(format!(
            "boundary history limit must be between 1 and {MAX_HISTORY_COMMITS}"
        )));
    }
    reject_grafts(root)?;
    let head = utf8(git(root, &["rev-parse", "--verify", "HEAD"])?)?
        .trim()
        .to_owned();
    let status = git(
        root,
        &["status", "--porcelain=v1", "-z", "--untracked-files=no"],
    )?;
    let inventory_bytes = git(root, &["ls-files", "--cached", "-z"])?;
    let tracked = paths(&inventory_bytes)?;
    let mut records: BTreeMap<String, Source> = BTreeMap::new();
    let mut ids = BTreeSet::new();
    let mut registry_sha256 = BTreeMap::new();
    for path in tracked.iter().filter(|path| {
        Path::new(path).parent() == Some(Path::new("ci/source-presence")) && path.ends_with(".toml")
    }) {
        let bytes = read_regular(root, path)?;
        let domain: Domain = toml::from_str(&utf8(bytes.clone())?)?;
        if domain.schema != 1 || domain.source.is_empty() {
            return Err(CiError::Message(format!(
                "unsupported or empty source domain: {path}"
            )));
        }
        registry_sha256.insert(path.clone(), digest(&bytes));
        for source in domain.source {
            validate_relative(&source.path)?;
            if !source_path(&source.path) || !ids.insert(source.id.clone()) {
                return Err(CiError::Message(format!(
                    "invalid or duplicate boundary source: {}",
                    source.id
                )));
            }
            if records.insert(source.path.clone(), source).is_some() {
                return Err(CiError::Message("duplicate boundary source path".into()));
            }
        }
    }
    if records.is_empty() {
        return Err(CiError::Message(
            "no tracked source registry domains".into(),
        ));
    }
    let excluded_untracked_registry_sources: BTreeSet<_> = records
        .keys()
        .filter(|path| !tracked.contains(*path))
        .cloned()
        .collect();
    if records.values().any(|source| {
        source
            .work_packages
            .iter()
            .any(|package| package == "GOV-06")
            && !tracked.contains(&source.path)
    }) {
        return Err(CiError::Message("GOV-06 candidate is not tracked".into()));
    }
    let unregistered_tracked_sources = tracked
        .iter()
        .filter(|path| source_path(path) && !records.contains_key(*path))
        .cloned()
        .collect();
    let mut sources = BTreeMap::new();
    let mut source_sha256 = BTreeMap::new();
    let mut excluded_deleted_registry_sources = BTreeSet::new();
    for path in records.keys().filter(|path| tracked.contains(*path)) {
        match fs::symlink_metadata(root.join(path)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if records[path]
                    .work_packages
                    .iter()
                    .any(|package| package == "GOV-06")
                {
                    return Err(CiError::Message(format!(
                        "GOV-06 candidate is missing: {path}"
                    )));
                }
                excluded_deleted_registry_sources.insert(path.clone());
                continue;
            }
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        let bytes = read_regular(root, path)?;
        source_sha256.insert(path.clone(), digest(&bytes));
        sources.insert(path.clone(), utf8(bytes)?);
    }
    let (shallow_repository, shallow_boundary_commits) = shallow_state(root)?;
    let count = (history_limit + 1).to_string();
    let revisions = utf8(git(
        root,
        &[
            "rev-list",
            "--topo-order",
            "--max-count",
            &count,
            &head,
            "--",
        ],
    )?)?;
    let commits: Vec<_> = revisions.lines().collect();
    let history_truncated = commits.len() > history_limit;
    let mut history = Vec::new();
    for commit in commits.into_iter().take(history_limit) {
        let parent_comparison_available = !shallow_boundary_commits.contains(commit);
        // A shallow boundary is not a root commit. Do not manufacture an
        // all-files-added change set when its actual parents are unavailable.
        let changed = if parent_comparison_available {
            paths(&git(
                root,
                &[
                    "diff-tree",
                    "--root",
                    "-m",
                    "--no-commit-id",
                    "--name-only",
                    "--no-renames",
                    "-r",
                    "-z",
                    commit,
                    "--",
                ],
            )?)?
        } else {
            BTreeSet::new()
        };
        history.push(HistoryCommit {
            commit: commit.to_owned(),
            parent_comparison_available,
            registered_paths: changed
                .into_iter()
                .filter(|path| sources.contains_key(path))
                .collect(),
        });
    }
    let history_paths: Vec<_> = history
        .iter()
        .map(|commit| commit.registered_paths.clone())
        .collect();
    let metrics = analyze_files(&sources, &history_paths)
        .map_err(|error| CiError::Message(format!("boundary source parse failed: {error}")))?;
    let mut candidates = Vec::new();
    for metrics in metrics {
        let source = &records[&metrics.path];
        if source
            .work_packages
            .iter()
            .any(|package| package == "GOV-06")
        {
            candidates.push(CandidateReport {
                id: source.id.clone(),
                owner: source.owner.clone(),
                metrics,
            });
        }
    }
    candidates.sort_by(|left, right| left.id.cmp(&right.id));
    // Fail if tracked observation changed while reading. This detects ordinary
    // concurrent edits; it is not an atomic filesystem snapshot.
    for (path, expected) in registry_sha256.iter().chain(source_sha256.iter()) {
        if digest(&read_regular(root, path)?) != *expected {
            return Err(CiError::Message(format!(
                "boundary input changed during collection: {path}"
            )));
        }
    }
    if utf8(git(root, &["rev-parse", "--verify", "HEAD"])?)?.trim() != head
        || git(
            root,
            &["status", "--porcelain=v1", "-z", "--untracked-files=no"],
        )? != status
        || git(root, &["ls-files", "--cached", "-z"])? != inventory_bytes
        || shallow_state(root)? != (shallow_repository, shallow_boundary_commits.clone())
    {
        return Err(CiError::Message(
            "tracked repository state changed during boundary collection".into(),
        ));
    }
    reject_grafts(root)?;
    Ok(BoundaryReport {
        schema: 1,
        producer: ProducerIdentity {
            algorithm: "memcordon-boundary-metrics-v1",
            package_version: env!("CARGO_PKG_VERSION"),
            collector_source_sha256: digest(include_bytes!("boundary_report.rs")),
            metrics_source_sha256: digest(include_bytes!("boundary_metrics.rs")),
            build_lock_sha256: digest(include_bytes!("../../../Cargo.lock")),
        },
        head,
        tracked_dirty: !status.is_empty(),
        tracked_status_sha256: digest(&status),
        tracked_inventory_sha256: digest(&inventory_bytes),
        registry_sha256,
        source_sha256,
        excluded_untracked_registry_sources,
        excluded_deleted_registry_sources,
        unregistered_tracked_sources,
        history_limit,
        history_truncated,
        shallow_repository,
        shallow_boundary_commits,
        history,
        limitations: [
            "Advisory lexical metrics; no architectural decision or execution evidence.",
            "Current tracked working-tree bytes; hashes bind content, not necessarily HEAD content.",
            "Only tracked registered Rust sources are read; untracked content is excluded even from dirty status.",
            "Deleted noncandidate sources are explicitly excluded; any missing GOV-06 candidate fails collection. This report does not validate registry policy.",
            "Function occurrence ids are snapshot-local; imports/calls are approximate and do not resolve macros or cfg.",
            "Test references are lexical references, not observed tests or coverage.",
            "History is bounded topological ancestry of HEAD; merge paths are unioned across parents and renames are not followed.",
            "Git replacement objects are disabled for all observations; any graft metadata causes rejection.",
            "Cochanges are pair counts, not statistical clusters or causal coupling; shallow/truncated history limits conclusions.",
            "Shallow boundary commits have unavailable parent comparisons and contribute no pair counts; their empty paths do not mean no changes.",
            "Before/after consistency checks detect concurrent changes but do not create an atomic filesystem snapshot.",
        ].into_iter().map(str::to_owned).collect(),
        candidates,
    })
}

pub fn write(root: &Path, output: &Path, history_limit: usize) -> Result<()> {
    if fs::symlink_metadata(output).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(CiError::Message(
            "boundary output must not be a symlink".into(),
        ));
    }
    let destination = if output.exists() {
        fs::canonicalize(output)?
    } else {
        let parent = output
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::canonicalize(parent)?.join(
            output
                .file_name()
                .ok_or_else(|| CiError::Message("boundary output requires a file name".into()))?,
        )
    };
    let canonical_root = fs::canonicalize(root)?;
    for tracked in paths(&git(root, &["ls-files", "--cached", "-z"])?)? {
        let path = canonical_root.join(tracked);
        if path == destination || fs::canonicalize(&path).is_ok_and(|path| path == destination) {
            return Err(CiError::Message(
                "boundary output would overwrite a tracked file".into(),
            ));
        }
    }
    let report = collect(root, history_limit)?;
    let mut bytes = serde_json::to_vec_pretty(&report)?;
    bytes.push(b'\n');
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.as_file_mut().write_all(&bytes)?;
    temporary
        .persist(&destination)
        .map_err(|error| CiError::Io(error.error))?;
    Ok(())
}
