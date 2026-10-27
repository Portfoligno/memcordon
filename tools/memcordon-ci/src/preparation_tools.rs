//! Exact same-run preparation inputs. These files never certify test results.
use crate::{
    CiError, Result,
    release::{artifacts, distribution, source::BuildSourceIdentity},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const FORMAT: u32 = 1;
const FILE_LIMIT: u64 = 256 * 1024 * 1024;
const TOTAL_LIMIT: u64 = 768 * 1024 * 1024;
const RECORD_LIMIT: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Readiness,
    Private,
    PrivateDriver,
    ReleaseFuzz,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum Operation {
    Package,
    Check,
}

#[derive(Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Invocation {
    repository: String,
    workflow: String,
    run: String,
    attempt: String,
}

#[derive(Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    kind: Kind,
    source: BuildSourceIdentity,
    host: String,
    toolchains: String,
    invocation: Invocation,
    producer: String,
}

#[derive(Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FileRecord {
    path: String,
    size: u64,
    sha256: String,
    executable: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    format: u32,
    inputs: Inputs,
    files: Vec<FileRecord>,
}

fn invalid(message: &str) -> CiError {
    CiError::Message(message.into())
}

fn environment(name: &str) -> Result<String> {
    let value = std::env::var(name)
        .map_err(|_| invalid("preparation transport requires the actual workflow invocation"))?;
    if value.is_empty() || value.len() > 1024 || value.contains(['\n', '\r', '\0']) {
        return Err(invalid("preparation invocation field is invalid"));
    }
    Ok(value)
}

fn producer(kind: Kind, host: &str) -> Result<String> {
    let suffix = match host {
        "x86_64-unknown-linux-gnu" => "linux-x64",
        "aarch64-unknown-linux-gnu" => "linux-arm64",
        "x86_64-apple-darwin" => "macos-x64",
        "aarch64-apple-darwin" => "macos-arm64",
        "x86_64-pc-windows-msvc" => "windows-x64",
        "aarch64-pc-windows-msvc" => "windows-arm64",
        _ => return Err(invalid("preparation transport host is unsupported")),
    };
    Ok(match kind {
        Kind::Readiness => format!("readiness-tools-{suffix}"),
        Kind::Private => match suffix {
            "linux-x64" => "private-linux-prepare-x64".into(),
            "linux-arm64" => "private-linux-prepare-arm64".into(),
            _ => {
                return Err(invalid(
                    "private preparation requires its native Linux host",
                ));
            }
        },
        Kind::PrivateDriver => match suffix {
            "linux-x64" => "private-linux-tools-x64".into(),
            "linux-arm64" => "private-linux-tools-arm64".into(),
            _ => {
                return Err(invalid(
                    "private driver preparation requires its native Linux host",
                ));
            }
        },
        Kind::ReleaseFuzz if suffix == "linux-x64" => "fuzz-setup".into(),
        Kind::ReleaseFuzz => {
            return Err(invalid(
                "release fuzz preparation requires its selected Linux host",
            ));
        }
    })
}

fn inputs(root: &Path, kind: Kind) -> Result<Inputs> {
    let source = BuildSourceIdentity::working(root)?;
    let host = distribution::native_target()?.to_owned();
    let invocation = Invocation {
        repository: environment("GITHUB_REPOSITORY")?,
        workflow: environment("GITHUB_WORKFLOW")?,
        run: environment("GITHUB_RUN_ID")?,
        attempt: environment("GITHUB_RUN_ATTEMPT")?,
    };
    if !invocation.run.bytes().all(|byte| byte.is_ascii_digit())
        || !invocation.attempt.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid("preparation invocation numbers are invalid"));
    }
    let toolchains =
        artifacts::checksum(&read(root, Path::new("ci/toolchains.toml"), RECORD_LIMIT)?);
    let producer = producer(kind, &host)?;
    Ok(Inputs {
        kind,
        source,
        host,
        toolchains,
        invocation,
        producer,
    })
}

fn manifest(kind: Kind) -> &'static str {
    match kind {
        Kind::Readiness => "target/ci-preparation/readiness.json",
        Kind::Private => "target/ci-preparation/private.json",
        Kind::PrivateDriver => "target/ci-preparation/private-driver.json",
        Kind::ReleaseFuzz => "target/ci-preparation/release-fuzz.json",
    }
}

fn read(root: &Path, relative: &Path, limit: u64) -> Result<Vec<u8>> {
    let path = crate::ci_operation_time::record_path(root, relative)?;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(&path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(invalid("preparation file kind or size is invalid"));
    }
    let mut bytes = Vec::new();
    (&file).take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > limit {
        return Err(invalid("preparation file changed or exceeds its bound"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let key = |m: &fs::Metadata| {
            (
                m.dev(),
                m.ino(),
                m.len(),
                m.nlink(),
                m.uid(),
                m.mode(),
                m.mtime(),
                m.mtime_nsec(),
                m.ctime(),
                m.ctime_nsec(),
            )
        };
        if key(&metadata) != key(&file.metadata()?)
            || key(&metadata) != key(&fs::symlink_metadata(&path)?)
        {
            return Err(invalid("preparation held/named file changed while reading"));
        }
    }
    Ok(bytes)
}

fn executable() -> &'static str {
    if cfg!(windows) {
        "memcordon-ci.exe"
    } else {
        "memcordon-ci"
    }
}
fn helper() -> &'static str {
    if cfg!(windows) {
        "consumer-readiness.exe"
    } else {
        "consumer-readiness"
    }
}

fn files(root: &Path, kind: Kind) -> Result<Vec<PathBuf>> {
    let files = if kind == Kind::ReleaseFuzz {
        vec![
            Path::new(".release/tool").join(executable()),
            PathBuf::from("target/ci-tools/bin/cargo-fuzz"),
        ]
    } else {
        crate::driver_cache::preparation_members(root)?
    };
    Ok(complete_files(kind, files))
}

fn complete_files(kind: Kind, mut files: Vec<PathBuf>) -> Vec<PathBuf> {
    if kind == Kind::Readiness {
        files.push(Path::new("target/ci-driver-cold/release").join(helper()));
        files.push(Path::new("target/ci/release").join(helper()));
    }
    files.sort();
    files
}

fn transported_files(root: &Path, record: &Record) -> Result<Vec<PathBuf>> {
    if record.inputs.kind == Kind::ReleaseFuzz {
        return files(root, record.inputs.kind);
    }
    let manifest = Path::new("target/ci-runtime/current").join("image.json");
    let mut matches = record
        .files
        .iter()
        .filter(|member| Path::new(&member.path) == manifest);
    let member = matches
        .next()
        .ok_or_else(|| invalid("preparation image manifest record is absent"))?;
    if matches.next().is_some() || member.executable || member.size == 0 || member.size > FILE_LIMIT
    {
        return Err(invalid("preparation image manifest record is invalid"));
    }
    // This record belongs to the exact required same-run producer artifact.
    // Its hash binds those transported bytes; it is not an independent signature.
    let files =
        crate::driver_cache::transported_preparation_members(root, member.size, &member.sha256)?;
    Ok(complete_files(record.inputs.kind, files))
}

fn records(root: &Path, paths: &[PathBuf]) -> Result<Vec<FileRecord>> {
    let mut seen = BTreeSet::new();
    let mut total = 0u64;
    paths
        .iter()
        .map(|relative| {
            let path = crate::ci_operation_time::record_path(root, relative)?;
            if !seen.insert(relative.clone()) {
                return Err(invalid("preparation has duplicate members"));
            }
            let bytes = read(root, relative, FILE_LIMIT)?;
            if bytes.is_empty() {
                return Err(invalid("preparation member is empty"));
            }
            total = total
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| invalid("preparation size overflow"))?;
            if total > TOTAL_LIMIT {
                return Err(invalid("preparation payload exceeds its bound"));
            }
            let executable =
                relative.file_name().and_then(|name| name.to_str()) != Some("image.json");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if executable && fs::metadata(&path)?.permissions().mode() & 0o111 == 0 {
                    return Err(invalid("preparation executable lost its executable mode"));
                }
            }
            #[cfg(not(unix))]
            let _ = path;
            Ok(FileRecord {
                path: relative
                    .to_str()
                    .ok_or_else(|| invalid("preparation member path is not UTF-8"))?
                    .into(),
                size: bytes.len() as u64,
                sha256: artifacts::checksum(&bytes),
                executable,
            })
        })
        .collect()
}

fn validate(root: &Path, record: &Record, expected: &Inputs) -> Result<()> {
    if record.format != FORMAT || &record.inputs != expected {
        return Err(invalid(
            "preparation source, host, protocol or invocation differs",
        ));
    }
    let paths = transported_files(root, record)?;
    if records(root, &paths)? != record.files {
        return Err(invalid("preparation bytes or member inventory differs"));
    }
    let driver = if expected.kind == Kind::ReleaseFuzz {
        Path::new(".release/tool").join(executable())
    } else {
        Path::new("target/ci-runtime/current").join(executable())
    };
    let running = artifacts::read_file(&std::env::current_exe()?)?;
    if running != read(root, &driver, FILE_LIMIT)? {
        return Err(invalid(
            "preparation must run its exact transported current program",
        ));
    }
    if expected.kind == Kind::Readiness {
        let cold = read(
            root,
            &Path::new("target/ci-driver-cold/release").join(helper()),
            FILE_LIMIT,
        )?;
        let legacy = read(
            root,
            &Path::new("target/ci/release").join(helper()),
            FILE_LIMIT,
        )?;
        if cold != legacy {
            return Err(invalid("preparation helper roles have different bytes"));
        }
    }
    Ok(())
}

fn private_relay_records(root: &Path) -> Result<Vec<FileRecord>> {
    let upstream = Path::new(manifest(Kind::PrivateDriver));
    let bytes = read(root, upstream, RECORD_LIMIT)?;
    let record: Record = serde_json::from_slice(&bytes)?;
    let expected = inputs(root, Kind::PrivateDriver)?;
    validate(root, &record, &expected)?;
    let files = records(root, &transported_files(root, &record)?)?;
    if files != record.files {
        return Err(invalid("private relay changed its admitted driver members"));
    }
    expected_source_recheck(root, Kind::PrivateDriver)?;
    if read(root, upstream, RECORD_LIMIT)? != bytes {
        return Err(invalid(
            "private relay producer record changed during packaging",
        ));
    }
    Ok(files)
}

/// Resolved in the original runner, never reconstructed from sudo's environment.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessHelperContext {
    pub repository: String,
    pub workflow: String,
    pub run: String,
    pub attempt: u64,
    pub source_commit: String,
    pub version: String,
}

pub fn running_readiness_helper_digest(root: &Path) -> Result<String> {
    let executable = std::env::current_exe()?;
    let relative = executable
        .strip_prefix(root)
        .map_err(|_| invalid("running helper escapes workspace"))?;
    if ![
        Path::new("target/ci-driver-cold/release").join(helper()),
        Path::new("target/ci/release").join(helper()),
    ]
    .contains(&relative.to_path_buf())
    {
        return Err(invalid("running helper is not a selected preparation role"));
    }
    Ok(artifacts::checksum(&read(root, relative, FILE_LIMIT)?))
}

/// Admit only the transported consumer helper. This does not certify results or
/// replace the complete driver preparation check. The CI runner remains trusted.
fn validate_helper_record(
    root: &Path,
    context: &ReadinessHelperContext,
    expected_digest: &str,
) -> Result<u64> {
    let record: Record = serde_json::from_slice(&read(
        root,
        Path::new(manifest(Kind::Readiness)),
        RECORD_LIMIT,
    )?)?;
    record.inputs.source.validate()?;
    for value in [&context.repository, &context.workflow, &context.run] {
        if value.is_empty() || value.len() > 1024 || value.contains(['\0', '\r', '\n']) {
            return Err(invalid("resolved helper invocation invalid"));
        }
    }
    let host = distribution::native_target()?;
    if record.format != FORMAT
        || record.inputs.kind != Kind::Readiness
        || record.inputs.host != host
        || record.inputs.producer != producer(Kind::Readiness, host)?
        || record.inputs.source.commit() != context.source_commit
        || record.inputs.source.version().to_string() != context.version
        || record.inputs.invocation
            != (Invocation {
                repository: context.repository.clone(),
                workflow: context.workflow.clone(),
                run: context.run.clone(),
                attempt: context.attempt.to_string(),
            })
        || context.attempt == 0
        || record.inputs.toolchains
            != artifacts::checksum(&read(root, Path::new("ci/toolchains.toml"), RECORD_LIMIT)?)
    {
        return Err(invalid("transported helper source/host/invocation differs"));
    }
    let paths = [
        Path::new("target/ci-driver-cold/release").join(helper()),
        Path::new("target/ci/release").join(helper()),
    ];
    let actual = records(root, &paths)?;
    for member in &actual {
        if !member.executable
            || member.sha256 != expected_digest
            || record
                .files
                .iter()
                .filter(|value| value.path == member.path)
                .count()
                != 1
            || !record.files.iter().any(|value| value == member)
        {
            return Err(invalid("transported helper role/bytes differ"));
        }
    }
    if actual[0].size != actual[1].size {
        return Err(invalid("transported helper sizes differ"));
    }
    Ok(actual[0].size)
}

pub fn validate_readiness_helper(
    root: &Path,
    context: &ReadinessHelperContext,
    expected_digest: &str,
) -> Result<()> {
    let size = validate_helper_record(root, context, expected_digest)?;
    let paths = [
        Path::new("target/ci-driver-cold/release").join(helper()),
        Path::new("target/ci/release").join(helper()),
    ];
    let executable = std::env::current_exe()?;
    if !paths.iter().any(|path| root.join(path) == executable) {
        return Err(invalid("running helper is not an exact selected role"));
    }
    let relative = executable
        .strip_prefix(root)
        .map_err(|_| invalid("running helper escapes workspace"))?;
    let bytes = read(root, relative, FILE_LIMIT)?;
    if bytes.len() as u64 != size || artifacts::checksum(&bytes) != expected_digest {
        return Err(invalid("running helper digest differs"));
    }
    Ok(())
}

pub fn run(root: &Path, operation: Operation, kind: Kind) -> Result<()> {
    crate::preparation::with_operation(
        crate::failure_mode::FailureMode::CollectAll,
        Instant::now() + Duration::from_secs(5 * 60),
        || {
            let expected = inputs(root, kind)?;
            let path = crate::ci_operation_time::record_path(root, Path::new(manifest(kind)))?;
            match operation {
                Operation::Package => {
                    if environment("GITHUB_JOB")? != expected.producer {
                        return Err(invalid(
                            "preparation package is not in its declared producer job",
                        ));
                    }
                    if kind == Kind::Readiness {
                        let source = crate::ci_operation_time::record_path(
                            root,
                            &Path::new("target/ci-driver-cold/release").join(helper()),
                        )?;
                        let target = crate::ci_operation_time::record_path(
                            root,
                            &Path::new("target/ci/release").join(helper()),
                        )?;
                        let bytes = read(
                            root,
                            &Path::new("target/ci-driver-cold/release").join(helper()),
                            FILE_LIMIT,
                        )?;
                        fs::create_dir_all(target.parent().expect("fixed helper parent"))?;
                        if target.try_exists()? {
                            return Err(invalid("preparation helper destination already exists"));
                        }
                        let mut output = fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(&target)?;
                        output.write_all(&bytes)?;
                        output.sync_all()?;
                        fs::set_permissions(&target, fs::metadata(source)?.permissions())?;
                    }
                    let record = Record {
                        format: FORMAT,
                        files: if kind == Kind::Private {
                            private_relay_records(root)?
                        } else {
                            records(root, &files(root, kind)?)?
                        },
                        inputs: expected,
                    };
                    validate(root, &record, &record.inputs)?;
                    fs::create_dir_all(path.parent().expect("fixed preparation parent"))?;
                    let mut bytes = serde_json::to_vec(&record)?;
                    bytes.push(b'\n');
                    if bytes.len() as u64 > RECORD_LIMIT {
                        return Err(invalid("preparation record exceeds its bound"));
                    }
                    let mut output = fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(path)?;
                    output.write_all(&bytes)?;
                    output.sync_all()?;
                }
                Operation::Check => {
                    let bytes = read(root, Path::new(manifest(kind)), RECORD_LIMIT)?;
                    let record: Record = serde_json::from_slice(&bytes)?;
                    validate(root, &record, &expected)?;
                }
            }
            expected_source_recheck(root, kind)
        },
    )
}

fn expected_source_recheck(root: &Path, kind: Kind) -> Result<()> {
    // Re-query after all hashing/copying; no compilation or passed-work state is
    // serialized into the input manifest.
    let actual = inputs(root, kind)?;
    let record: Record =
        serde_json::from_slice(&read(root, Path::new(manifest(kind)), RECORD_LIMIT)?)?;
    if actual != record.inputs {
        return Err(invalid("preparation inputs changed during verification"));
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/private/preparation_tools.rs"]
mod tests;
