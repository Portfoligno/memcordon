//! Bounded collection of caller-selected, actually executed native test results.

use crate::{CiError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path};

pub const MAX_REPORT_BYTES: u64 = 64 * 1024;

pub struct NativeReportSpec<'a> {
    pub artifact_directory: &'a str,
    pub report_name: &'a str,
    pub backend: &'a str,
    pub scenario_names: &'a [&'a str],
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeTestReport {
    pub schema_version: u32,
    pub backend: String,
    pub source_commit: String,
    pub tests: Vec<NativeTestResult>,
    pub tests_run: usize,
    pub tests_skipped: usize,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeTestResult {
    pub name: String,
    pub result: NativeTestOutcome,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NativeTestOutcome {
    Passed,
    Failed,
    Skipped,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CollectedNativeReport {
    pub evidence_path: String,
    pub sha256: String,
}
fn failure(message: impl Into<String>) -> CiError {
    CiError::Message(message.into())
}
fn filename(value: &str) -> bool {
    let mut components = Path::new(value).components();
    matches!(components.next(), Some(Component::Normal(part)) if part == value)
        && components.next().is_none()
}
fn regular_bytes(path: &Path) -> Result<Vec<u8>> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_REPORT_BYTES {
        return Err(failure("native report is not a bounded regular file"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_REPORT_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_REPORT_BYTES {
        return Err(failure("native report exceeds byte bound"));
    }
    Ok(bytes)
}

pub fn collect_native_results(
    input: &Path,
    output: &Path,
    expected_commit: &str,
    specs: &[NativeReportSpec<'_>],
) -> Result<BTreeMap<String, CollectedNativeReport>> {
    let mut directories = BTreeSet::new();
    let mut backends = BTreeSet::new();
    let mut names = BTreeSet::new();
    if specs.is_empty() {
        return Err(failure("native report selection is empty"));
    }
    for spec in specs {
        if !filename(spec.artifact_directory)
            || !filename(spec.report_name)
            || spec.backend.is_empty()
            || !directories.insert(spec.artifact_directory)
            || !backends.insert(spec.backend)
            || !names.insert(spec.report_name)
            || spec.scenario_names.is_empty()
            || spec.scenario_names.iter().any(|name| name.is_empty())
            || spec
                .scenario_names
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len()
                != spec.scenario_names.len()
        {
            return Err(failure("native report selection is invalid or duplicated"));
        }
    }
    if !fs::symlink_metadata(input)?.file_type().is_dir() {
        return Err(failure("native report input is not a directory"));
    }
    // Canonical roots bind the selected physical directories; children still
    // require no-follow checks. System aliases such as /tmp remain usable.
    let input = input.canonicalize()?;
    for entry in fs::read_dir(&input)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir()
            || !directories.contains(entry.file_name().to_str().unwrap_or_default())
        {
            return Err(failure("native report input has unexpected inventory"));
        }
    }
    let mut validated = Vec::new();
    for spec in specs {
        let directory = input.join(spec.artifact_directory);
        if !fs::symlink_metadata(&directory)?.file_type().is_dir() {
            return Err(failure("native report artifact is not a directory"));
        }
        let entries = fs::read_dir(&directory)?.collect::<std::io::Result<Vec<_>>>()?;
        if entries.len() != 1 || entries[0].file_name() != spec.report_name {
            return Err(failure("native report artifact cardinality differs"));
        }
        let bytes = regular_bytes(&directory.join(spec.report_name))?;
        let report: NativeTestReport = serde_json::from_slice(&bytes)?;
        if report.schema_version != 1
            || report.backend != spec.backend
            || report.source_commit != expected_commit
            || report.tests_run == 0
            || report.tests_run != spec.scenario_names.len()
            || report.tests_skipped != 0
            || report.tests.len() != spec.scenario_names.len()
            || !report
                .tests
                .iter()
                .zip(spec.scenario_names)
                .all(|(actual, expected)| {
                    actual.name == *expected && actual.result == NativeTestOutcome::Passed
                })
        {
            return Err(failure(
                "native report does not contain the selected executed successes",
            ));
        }
        validated.push((spec, bytes));
    }
    fs::create_dir_all(output)?;
    if !fs::symlink_metadata(output)?.file_type().is_dir() {
        return Err(failure("native report output is not a directory"));
    }
    let output = output.canonicalize()?;
    for entry in fs::read_dir(&output)? {
        let entry = entry?;
        if !entry.file_type()?.is_file()
            || !names.contains(entry.file_name().to_str().unwrap_or_default())
        {
            return Err(failure("native report output has unexpected inventory"));
        }
    }
    let mut records = BTreeMap::new();
    for (spec, bytes) in validated {
        if !fs::symlink_metadata(&output)?.file_type().is_dir() {
            return Err(failure("native report output parent changed"));
        }
        let mut staged = tempfile::NamedTempFile::new_in(&output)?;
        staged.write_all(&bytes)?;
        staged.as_file().sync_all()?;
        // Rename a fresh inode: an existing leaf symlink is never followed.
        staged
            .persist(output.join(spec.report_name))
            .map_err(|error| failure(error.to_string()))?;
        records.insert(
            spec.backend.to_owned(),
            CollectedNativeReport {
                evidence_path: spec.report_name.to_owned(),
                sha256: hex::encode(Sha256::digest(&bytes)),
            },
        );
    }
    Ok(records)
}
