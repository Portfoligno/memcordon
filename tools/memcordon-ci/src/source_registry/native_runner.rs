//! Native argv adapter used by Cargo's structured runner configuration.
//! Cargo retains target selection and the test's working directory/environment.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use memcordon_core::NativeArgument;
use serde::{Deserialize, Serialize};

use crate::{CiError, Result};

use super::coverage::parse_test_list;
use super::observation::digest;

#[derive(Clone, Debug)]
pub struct RunnerConfiguration {
    path: PathBuf,
    digest: String,
    executable: PathBuf,
    executable_digest: String,
    root: PathBuf,
}

impl RunnerConfiguration {
    pub fn create(root: &Path, directory: &Path, deadline: Duration) -> Result<Self> {
        let relative = directory.strip_prefix(root).map_err(|_| {
            CiError::Message("native runner directory is not within its supplied workspace".into())
        })?;
        let root = root.canonicalize()?;
        let directory = root.join(relative);
        let directory = directory.as_path();
        if !directory.starts_with(root.join("target/ci/source-observations"))
            || directory
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(CiError::Message(
                "native runner output path is outside its declared boundary".into(),
            ));
        }
        let existing = directory
            .ancestors()
            .find(|path| path.exists())
            .expect("absolute path has an existing root");
        if existing.canonicalize()? != existing {
            return Err(CiError::Message(
                "native runner output ancestor is redirected".into(),
            ));
        }
        std::fs::create_dir_all(directory)?;
        let directory = directory.canonicalize()?;
        if !directory.starts_with(root.join("target/ci/source-observations")) {
            return Err(CiError::Message(
                "native runner configuration is outside the evidence output boundary".into(),
            ));
        }
        let executable = std::env::current_exe()?.canonicalize()?;
        let path = write_configuration(&directory, &executable, deadline)?;
        Ok(Self {
            digest: digest(&std::fs::read(&path)?),
            executable_digest: digest(&std::fs::read(&executable)?),
            path,
            executable,
            root,
        })
    }

    pub fn verify(&self, root: &Path) -> Result<()> {
        if root.canonicalize()? != self.root
            || !std::fs::symlink_metadata(&self.path)?.file_type().is_file()
            || self.path.canonicalize()? != self.path
            || digest(&std::fs::read(&self.path)?) != self.digest
            || digest(&std::fs::read(&self.executable)?) != self.executable_digest
        {
            return Err(CiError::Message(
                "native runner configuration or executable changed after enrollment".into(),
            ));
        }
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

pub fn write_configuration(
    directory: &Path,
    executable: &Path,
    deadline: Duration,
) -> Result<PathBuf> {
    #[derive(Serialize)]
    struct Runner {
        runner: Vec<String>,
    }
    #[derive(Serialize)]
    struct Configuration {
        target: std::collections::BTreeMap<String, Runner>,
    }
    let text_path = |path: &Path| {
        path.to_str().map(str::to_owned).ok_or_else(|| {
            CiError::Message(
                "Cargo runner configuration requires representable native paths".into(),
            )
        })
    };
    let configuration = Configuration {
        target: std::collections::BTreeMap::from([(
            "cfg(all())".into(),
            Runner {
                runner: vec![
                    text_path(executable)?,
                    "native-test-runner".into(),
                    "--directory".into(),
                    text_path(directory)?,
                    "--deadline-ms".into(),
                    deadline.as_millis().to_string(),
                    "--".into(),
                ],
            },
        )]),
    };
    std::fs::create_dir_all(directory)?;
    let path = directory.join("cargo-runner.toml");
    std::fs::write(
        &path,
        toml::to_string(&configuration).map_err(|error| CiError::Message(error.to_string()))?,
    )?;
    Ok(path)
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExecution {
    pub schema: u32,
    pub binary: PathBuf,
    pub binary_sha256: String,
    pub arguments: Vec<NativeArgument>,
    pub listed_tests: BTreeSet<String>,
    pub selected_tests: BTreeSet<String>,
    pub ignored_tests: BTreeSet<String>,
    pub executed_tests: BTreeSet<String>,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub success: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BoundExecution {
    pub package_id: String,
    pub package_name: String,
    pub manifest_path: PathBuf,
    pub target_name: String,
    pub target_kinds: Vec<String>,
    pub features: Vec<String>,
    pub execution: NativeExecution,
}

pub fn bind_artifacts(
    directory: &Path,
    cargo_stdout: &[u8],
    require_complete: bool,
) -> Result<Vec<BoundExecution>> {
    let mut artifacts = std::collections::BTreeMap::new();
    for message in cargo_metadata::Message::parse_stream(std::io::Cursor::new(cargo_stdout)) {
        if let cargo_metadata::Message::CompilerArtifact(artifact) = message?
            && artifact.profile.test
            && let Some(executable) = &artifact.executable
        {
            artifacts.insert(executable.as_std_path().canonicalize()?, artifact);
        }
    }
    let mut records = Vec::new();
    for entry in std::fs::read_dir(directory)? {
        let path = entry?.path();
        if path.extension().is_none_or(|extension| extension != "json") {
            continue;
        }
        let execution: NativeExecution = serde_json::from_slice(&std::fs::read(path)?)?;
        if execution.schema != 1
            || execution.binary_sha256 != digest(&std::fs::read(&execution.binary)?)
            || !execution.selected_tests.is_subset(&execution.listed_tests)
            || !execution.ignored_tests.is_subset(&execution.listed_tests)
            || !execution
                .executed_tests
                .is_subset(&execution.selected_tests)
        {
            return Err(CiError::Message(
                "native execution schema, binary identity or test inventory is inconsistent".into(),
            ));
        }
        let artifact = artifacts
            .get(&execution.binary.canonicalize()?)
            .ok_or_else(|| {
                CiError::Message("native execution has no matching Cargo test artifact".into())
            })?;
        records.push(BoundExecution {
            package_id: artifact.package_id.to_string(),
            package_name: {
                let manifest: toml::Value =
                    toml::from_str(&std::fs::read_to_string(&artifact.manifest_path)?)?;
                manifest
                    .get("package")
                    .and_then(|package| package.get("name"))
                    .and_then(toml::Value::as_str)
                    .ok_or_else(|| {
                        CiError::Message("Cargo artifact package manifest has no name".into())
                    })?
                    .to_owned()
            },
            manifest_path: artifact.manifest_path.as_std_path().to_path_buf(),
            target_name: artifact.target.name.clone(),
            target_kinds: artifact
                .target
                .kind
                .iter()
                .map(ToString::to_string)
                .collect(),
            features: artifact.features.clone(),
            execution,
        });
    }
    records.sort_by(|left, right| left.execution.binary.cmp(&right.execution.binary));
    let observed = records
        .iter()
        .map(|record| record.execution.binary.canonicalize())
        .collect::<std::io::Result<BTreeSet<_>>>()?;
    if require_complete && observed != artifacts.keys().cloned().collect() {
        return Err(CiError::Message(
            "Cargo test artifacts are missing native runner execution records".into(),
        ));
    }
    Ok(records)
}

pub fn verify_successful_execution(
    stdout: &[u8],
    selected: &BTreeSet<String>,
    ignored: &BTreeSet<String>,
    arguments: &[OsString],
) -> Result<BTreeSet<String>> {
    if arguments.iter().any(|argument| argument == "--list") {
        return Ok(BTreeSet::new());
    }
    let run_ignored = arguments
        .iter()
        .any(|argument| argument == "--ignored" || argument == "--include-ignored");
    let executed: BTreeSet<_> = selected
        .iter()
        .filter(|name| run_ignored || !ignored.contains(*name))
        .cloned()
        .collect();
    let expected_ignored = selected.len() - executed.len();
    let stdout =
        std::str::from_utf8(stdout).map_err(|error| CiError::Message(error.to_string()))?;
    let summaries: Vec<_> = stdout
        .lines()
        .filter_map(|line| line.strip_prefix("test result: ok. "))
        .collect();
    if summaries.len() != 1 {
        return Err(CiError::Message(
            "native test execution requires exactly one successful libtest summary".into(),
        ));
    }
    let mut passed = None;
    let mut failed = None;
    let mut skipped = None;
    for field in summaries[0].split(';').map(str::trim) {
        if let Some(value) = field.strip_suffix(" passed") {
            passed = value.parse::<usize>().ok();
        }
        if let Some(value) = field.strip_suffix(" failed") {
            failed = value.parse::<usize>().ok();
        }
        if let Some(value) = field.strip_suffix(" ignored") {
            skipped = value.parse::<usize>().ok();
        }
    }
    if passed != Some(executed.len()) || failed != Some(0) || skipped != Some(expected_ignored) {
        return Err(CiError::Message(
            "native execution counts disagree with exact selected and ignored inventories".into(),
        ));
    }
    Ok(executed)
}

pub fn listing_arguments(arguments: &[OsString]) -> Result<Vec<OsString>> {
    let mut listing = Vec::new();
    let mut arguments = arguments.iter();
    while let Some(argument) = arguments.next() {
        if argument == "--format" || argument == "--color" {
            arguments
                .next()
                .ok_or_else(|| CiError::Message("missing libtest rendering argument".into()))?;
        } else if argument == "--quiet"
            || argument == "-q"
            || argument
                .to_str()
                .is_some_and(|text| text.starts_with("--format=") || text.starts_with("--color="))
        {
            continue;
        } else {
            listing.push(argument.clone());
        }
    }
    listing.extend(["--list", "--format", "terse"].map(OsString::from));
    Ok(listing)
}

pub fn run(directory: &Path, deadline: Duration, arguments: &[OsString]) -> Result<()> {
    let started = Instant::now();
    let (binary, arguments) = arguments
        .split_first()
        .ok_or_else(|| CiError::Message("native runner requires executable argv".into()))?;
    let binary = PathBuf::from(binary);
    let cwd = std::env::current_dir()?;
    let binary_sha256 = digest(&std::fs::read(&binary)?);
    let remaining = || {
        deadline
            .checked_sub(started.elapsed())
            .filter(|value| !value.is_zero())
            .ok_or_else(|| {
                CiError::Message("native evidence exhausted the original command deadline".into())
            })
    };
    let list = |arguments: &[OsString]| -> Result<BTreeSet<String>> {
        remaining()?;
        let output = std::process::Command::new(&binary)
            .current_dir(&cwd)
            .args(listing_arguments(arguments)?)
            .stdin(std::process::Stdio::inherit())
            .output()?;
        if !output.status.success() {
            return Err(CiError::Message(format!(
                "native test listing failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        parse_test_list(
            std::str::from_utf8(&output.stdout)
                .map_err(|error| CiError::Message(error.to_string()))?,
        )
    };
    let listed_tests = list(&[])?;
    let ignored_tests = list(&[OsString::from("--ignored")])?;
    let selected_tests = list(arguments)?;
    if !selected_tests.is_subset(&listed_tests) || !ignored_tests.is_subset(&listed_tests) {
        return Err(CiError::Message(
            "native test inventory changed between list invocations".into(),
        ));
    }
    remaining()?;
    // Deliberately inherit Cargo's containment. The outer Cargo CommandSpec
    // owns the single deadline and descendant cleanup for this entire adapter.
    let output = std::process::Command::new(&binary)
        .current_dir(&cwd)
        .args(arguments)
        .stdin(std::process::Stdio::inherit())
        .output()?;
    use std::io::Write;
    // Cargo multiplexes compiler protocol messages and runner stdout. Encode
    // native bytes before entering that stream so JSON-shaped test output can
    // never be mistaken for (and removed as) a compiler artifact message.
    std::io::stdout().write_all(&encode_native_stdout(directory, &output.stdout)?)?;
    std::io::stderr().write_all(&output.stderr)?;
    let executed_tests = if output.status.success() {
        verify_successful_execution(&output.stdout, &selected_tests, &ignored_tests, arguments)?
    } else {
        BTreeSet::new()
    };
    let record = NativeExecution {
        schema: 1,
        binary: binary.clone(),
        binary_sha256,
        arguments: arguments
            .iter()
            .map(|argument| NativeArgument::from_os(argument))
            .collect(),
        listed_tests,
        selected_tests,
        ignored_tests,
        executed_tests,
        stdout_sha256: digest(&output.stdout),
        stderr_sha256: digest(&output.stderr),
        success: output.status.success(),
    };
    if digest(&std::fs::read(&binary)?) != record.binary_sha256 {
        return Err(CiError::Message(
            "native binary changed during execution".into(),
        ));
    }
    std::fs::create_dir_all(directory)?;
    let mut bytes = serde_json::to_vec_pretty(&record)?;
    bytes.push(b'\n');
    let path = directory
        .join(digest(&serde_json::to_vec(&(
            &record.binary,
            &record.arguments,
        ))?))
        .with_extension("json");
    std::fs::write(path, bytes)?;
    if !output.status.success() {
        return Err(CiError::Message(format!(
            "native test binary failed: {}",
            output.status
        )));
    }
    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeStdout {
    native_stdout_schema: u32,
    native_stdout_token: String,
    bytes: Vec<u8>,
}

fn stdout_token(directory: &Path) -> Result<String> {
    Ok(digest(&serde_json::to_vec(&NativeArgument::from_os(
        directory.as_os_str(),
    ))?))
}

pub fn encode_native_stdout(directory: &Path, bytes: &[u8]) -> Result<Vec<u8>> {
    let mut frame = serde_json::to_vec(&NativeStdout {
        native_stdout_schema: 1,
        native_stdout_token: stdout_token(directory)?,
        bytes: bytes.to_vec(),
    })?;
    frame.push(b'\n');
    Ok(frame)
}

/// Decode only the adapter's framed native bytes; ordinary Cargo text (including
/// doctest output) remains intact. Compiler protocol messages stay in the raw
/// observation used for artifact binding and never enter a libtest transcript.
pub fn decode_cargo_stdout(directory: &Path, bytes: &[u8]) -> Result<Vec<u8>> {
    let token = stdout_token(directory)?;
    let mut decoded = Vec::new();
    let mut build_finished = false;
    for line in bytes.split_inclusive(|byte| *byte == b'\n') {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(line) else {
            decoded.extend_from_slice(line);
            continue;
        };
        if value
            .get("native_stdout_token")
            .and_then(serde_json::Value::as_str)
            == Some(token.as_str())
        {
            let frame: NativeStdout = serde_json::from_value(value)?;
            if frame.native_stdout_schema != 1 {
                return Err(CiError::Message("unsupported native stdout frame".into()));
            }
            decoded.extend_from_slice(&frame.bytes);
        } else if !build_finished {
            match serde_json::from_value::<cargo_metadata::Message>(value) {
                Ok(cargo_metadata::Message::BuildFinished(_)) => build_finished = true,
                Ok(
                    cargo_metadata::Message::CompilerArtifact(_)
                    | cargo_metadata::Message::CompilerMessage(_)
                    | cargo_metadata::Message::BuildScriptExecuted(_),
                ) => {}
                _ => decoded.extend_from_slice(line),
            }
        } else {
            decoded.extend_from_slice(line);
        }
    }
    Ok(decoded)
}
