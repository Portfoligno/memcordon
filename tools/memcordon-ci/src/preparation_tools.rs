//! Member inventories identify transported executable bytes, never test results.
use crate::{
    CiError, Result,
    release::{artifacts, distribution, source::BuildSourceIdentity},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

const FILE_LIMIT: u64 = 256 * 1024 * 1024;
const TOTAL_LIMIT: u64 = 768 * 1024 * 1024;
const RECORD_LIMIT: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Test,
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
struct FileRecord {
    path: String,
    size: u64,
    sha256: String,
    executable: bool,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    kind: Kind,
    source: BuildSourceIdentity,
    host: String,
    files: Vec<FileRecord>,
}

fn invalid(message: &str) -> CiError {
    CiError::Message(message.into())
}
pub(crate) fn manifest(kind: Kind) -> &'static str {
    match kind {
        Kind::Test => "target/ci-preparation/test-tools.json",
        Kind::Private => "target/ci-preparation/private.json",
        Kind::PrivateDriver => "target/ci-preparation/private-driver.json",
        Kind::ReleaseFuzz => "target/ci-preparation/release-fuzz.json",
    }
}
fn executable() -> &'static str {
    if cfg!(windows) {
        "memcordon-ci.exe"
    } else {
        "memcordon-ci"
    }
}
fn read(root: &Path, relative: &Path, limit: u64) -> Result<Vec<u8>> {
    let path = crate::native_paths::record_path(root, relative)?;
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(invalid("tool member is not a bounded regular file"));
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(&path)?;
    let mut bytes = Vec::new();
    (&file).take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > limit {
        return Err(invalid("tool member changed or exceeds bound"));
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
            || key(&metadata) != key(&fs::symlink_metadata(path)?)
        {
            return Err(invalid("held tool member changed while reading"));
        }
    }
    Ok(bytes)
}
fn records(root: &Path, paths: &[PathBuf]) -> Result<Vec<FileRecord>> {
    let mut seen = BTreeSet::new();
    let mut total = 0u64;
    paths
        .iter()
        .map(|relative| {
            if !seen.insert(relative) {
                return Err(invalid("tool archive repeats a member"));
            }
            let bytes = read(root, relative, FILE_LIMIT)?;
            if bytes.is_empty() {
                return Err(invalid("tool member is empty"));
            }
            total = total
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| invalid("tool size overflow"))?;
            if total > TOTAL_LIMIT {
                return Err(invalid("tool archive exceeds bound"));
            }
            let executable =
                relative.file_name().and_then(|name| name.to_str()) != Some("image.json");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if executable
                    && fs::metadata(root.join(relative))?.permissions().mode() & 0o111 == 0
                {
                    return Err(invalid("tool executable mode missing"));
                }
            }
            Ok(FileRecord {
                path: relative
                    .to_str()
                    .ok_or_else(|| invalid("tool member path is not UTF8"))?
                    .into(),
                size: bytes.len() as u64,
                sha256: artifacts::checksum(&bytes),
                executable,
            })
        })
        .collect()
}
fn files(root: &Path, kind: Kind) -> Result<Vec<PathBuf>> {
    if kind == Kind::ReleaseFuzz {
        return Ok(vec![
            Path::new(".release/tool").join(executable()),
            PathBuf::from("target/ci-tools/bin/cargo-fuzz"),
        ]);
    }
    crate::driver_cache::preparation_members(root)
}
fn transported_files(root: &Path, record: &Record) -> Result<Vec<PathBuf>> {
    if record.kind == Kind::ReleaseFuzz {
        return files(root, record.kind);
    }
    let path = Path::new("target/ci-runtime/current/image.json");
    let member = record
        .files
        .iter()
        .find(|member| Path::new(&member.path) == path)
        .ok_or_else(|| invalid("tool image inventory is absent"))?;
    if member.executable || member.size == 0 || member.size > FILE_LIMIT {
        return Err(invalid("tool image member is invalid"));
    }
    crate::driver_cache::transported_preparation_members(root, member.size, &member.sha256)
}
fn validate(root: &Path, record: &Record, kind: Kind) -> Result<()> {
    if record.kind != kind
        || record.source != BuildSourceIdentity::working(root)?
        || record.host != distribution::native_target()?
    {
        return Err(invalid("tool source/host/kind differs"));
    }
    if records(root, &transported_files(root, record)?)? != record.files {
        return Err(invalid("tool bytes or member inventory differs"));
    }
    let driver = if kind == Kind::ReleaseFuzz {
        Path::new(".release/tool").join(executable())
    } else {
        Path::new("target/ci-runtime/current").join(executable())
    };
    if artifacts::read_file(&std::env::current_exe()?)? != read(root, &driver, FILE_LIMIT)? {
        return Err(invalid("tool check must execute the transported driver"));
    }
    Ok(())
}
pub fn run(root: &Path, operation: Operation, kind: Kind) -> Result<()> {
    let path = crate::native_paths::record_path(root, Path::new(manifest(kind)))?;
    match operation {
        Operation::Package => {
            let paths = if kind == Kind::Private {
                let bytes = read(root, Path::new(manifest(Kind::PrivateDriver)), RECORD_LIMIT)?;
                let upstream: Record = serde_json::from_slice(&bytes)?;
                validate(root, &upstream, Kind::PrivateDriver)?;
                transported_files(root, &upstream)?
            } else {
                files(root, kind)?
            };
            let record = Record {
                kind,
                source: BuildSourceIdentity::working(root)?,
                host: distribution::native_target()?.into(),
                files: records(root, &paths)?,
            };
            validate(root, &record, kind)?;
            fs::create_dir_all(path.parent().expect("fixed tool inventory parent"))?;
            super::release::source::write_json(&path, &record)
        }
        Operation::Check => {
            let bytes = read(root, Path::new(manifest(kind)), RECORD_LIMIT)?;
            memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)
                .map_err(CiError::Message)?;
            validate(root, &serde_json::from_slice(&bytes)?, kind)
        }
    }
}

#[cfg(test)]
#[path = "../tests/private/preparation_tools.rs"]
mod tests;
