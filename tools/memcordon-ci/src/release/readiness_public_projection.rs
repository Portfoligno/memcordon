//! A readable copy of selected evidence, never the private execution tree.
use crate::consumer_readiness_ledger::CellEvidence;
use crate::{CiError, Result};
use memcordon_readiness_verifier::Artifact;
use rustix::fs::{AtFlags, Mode, OFlags, mkdirat, openat, renameat, unlinkat};
use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Component, Path},
    time::Instant,
};

use memcordon_readiness_verifier::{
    MAX_ARTIFACT_BYTES as MAX_FILE, MAX_INDEX_BYTES, MAX_PRODUCER_ARTIFACTS, MAX_PRODUCER_BYTES,
};

fn error(message: &str) -> CiError {
    CiError::Message(message.into())
}
fn native<T>(result: rustix::io::Result<T>) -> Result<T> {
    result.map_err(std::io::Error::from).map_err(CiError::from)
}
fn check_deadline(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        return Err(error("original public projection cutoff exhausted"));
    }
    Ok(())
}
fn directory(parent: &File, name: &std::ffi::OsStr, create: bool) -> Result<File> {
    let mut created = false;
    if create {
        match mkdirat(parent, name, Mode::from_bits_truncate(0o755)) {
            Ok(()) => created = true,
            Err(rustix::io::Errno::EXIST) => {}
            Err(cause) => return Err(std::io::Error::from(cause).into()),
        }
    }
    let file: File = native(openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ))?
    .into();
    if created {
        native(rustix::fs::fchmod(&file, Mode::from_bits_truncate(0o755)))?;
    }
    if create {
        let metadata = file.metadata()?;
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o7777 != 0o755
        {
            return Err(error("public projection directory ownership differs"));
        }
    }
    Ok(file)
}
fn root(path: &Path) -> Result<File> {
    let path = std::path::absolute(path)?;
    let mut held = File::open("/")?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => held = directory(&held, name, false)?,
            _ => return Err(error("public projection root is not normalized")),
        }
    }
    Ok(held)
}
fn parent(root: &File, relative: &Path, create: bool) -> Result<File> {
    let mut held = root.try_clone()?;
    for component in relative.parent().unwrap_or(Path::new("")).components() {
        let Component::Normal(name) = component else {
            return Err(error("public artifact parent escapes root"));
        };
        held = directory(&held, name, create)?;
        let metadata = held.metadata()?;
        if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o022 != 0 {
            return Err(error("public artifact parent custody differs"));
        }
    }
    Ok(held)
}
fn metadata_key(m: &std::fs::Metadata) -> (u64, u64, u64, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.nlink(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn read_selected(parent: &File, name: &std::ffi::OsStr, record: &Artifact) -> Result<Vec<u8>> {
    let mut file: File = native(openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ))?
    .into();
    let before = file.metadata()?;
    if !before.is_file()
        || before.uid() != rustix::process::geteuid().as_raw()
        || before.nlink() != 1
        || before.mode() & 0o022 != 0
        || before.len() != record.length
        || before.len() > MAX_FILE
    {
        return Err(error(
            "public artifact source type/owner/alias/length differs",
        ));
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(MAX_FILE + 1)
        .read_to_end(&mut bytes)?;
    let named: File = native(openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ))?
    .into();
    if metadata_key(&file.metadata()?) != metadata_key(&before)
        || metadata_key(&named.metadata()?) != metadata_key(&before)
        || bytes.len() as u64 != record.length
        || crate::release::artifacts::checksum(&bytes) != record.sha256
    {
        return Err(error(
            "public artifact held identity or selected digest changed",
        ));
    }
    Ok(bytes)
}
fn write_new(parent: &File, name: &std::ffi::OsStr, bytes: &[u8]) -> Result<()> {
    let file: File = native(openat(
        parent,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o644),
    ))?
    .into();
    native(rustix::fs::fchmod(&file, Mode::from_bits_truncate(0o644)))?;
    let mut file = file;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn write_cell(bundle: &File, cell: &CellEvidence) -> Result<()> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let name = format!(
        ".cell-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let bytes = serde_json::to_vec_pretty(cell)?;
    if bytes.len() > MAX_INDEX_BYTES {
        return Err(error("public cell record exceeds bound"));
    }
    write_new(bundle, name.as_ref(), &bytes)?;
    let renamed = renameat(bundle, name.as_str(), bundle, "cell.json");
    if renamed.is_err() {
        let _ = unlinkat(bundle, name.as_str(), AtFlags::empty());
    }
    native(renamed)?;
    bundle.sync_all()?;
    Ok(())
}

pub(super) fn publish(source: &Path, cell: &CellEvidence, deadline: Instant) -> Result<()> {
    check_deadline(deadline)?;
    let source_path = std::path::absolute(source)?;
    let source = root(&source_path)?;
    let bundle = directory(&source, std::ffi::OsStr::new("producer"), true)?;
    // An interrupted refresh must not leave an earlier successful verdict.
    let mut incomplete = cell.clone();
    incomplete.cache_quiescent = false;
    incomplete
        .cleanup_failures
        .push("public evidence projection incomplete".into());
    write_cell(&bundle, &incomplete)?;
    // Reserve the verifier's bounded original manifest, plus the actual cell.
    let overhead = (serde_json::to_vec_pretty(cell)?.len() as u64)
        .checked_add(MAX_INDEX_BYTES as u64)
        .ok_or_else(|| error("public projection overhead overflow"))?;
    copy_selected(&source, &bundle, &cell.artifacts, overhead, deadline)?;
    check_deadline(deadline)?;
    let source_named = root(&source_path)?;
    let named = directory(&source_named, std::ffi::OsStr::new("producer"), false)?.metadata()?;
    let held = bundle.metadata()?;
    if metadata_key(&source_named.metadata()?) != metadata_key(&source.metadata()?)
        || named.dev() != held.dev()
        || named.ino() != held.ino()
    {
        return Err(error("public projection root named custody changed"));
    }
    write_cell(&bundle, cell)
}

fn copy_selected(
    source: &File,
    bundle: &File,
    records: &[Artifact],
    overhead: u64,
    deadline: Instant,
) -> Result<()> {
    if records.len() > MAX_PRODUCER_ARTIFACTS {
        return Err(error("public artifact catalog exceeds bound"));
    }
    let total = records
        .iter()
        .try_fold(overhead, |total, record| total.checked_add(record.length))
        .ok_or_else(|| error("public artifact total overflow"))?;
    if total > MAX_PRODUCER_BYTES || records.iter().any(|record| record.length > MAX_FILE) {
        return Err(error("public artifact byte plan exceeds producer bound"));
    }
    let mut directories = BTreeSet::new();
    for record in records {
        check_deadline(deadline)?;
        let relative = crate::release::artifacts::safe_relative(Path::new(&record.path))?;
        for ancestor in relative
            .ancestors()
            .skip(1)
            .filter(|path| !path.as_os_str().is_empty())
        {
            directories.insert(ancestor.to_path_buf());
        }
    }
    if records
        .len()
        .checked_add(directories.len())
        .and_then(|count| count.checked_add(2))
        .is_none_or(|count| count > MAX_PRODUCER_ARTIFACTS)
    {
        return Err(error("public producer member plan exceeds bound"));
    }
    let mut paths = BTreeSet::new();
    for record in records {
        check_deadline(deadline)?;
        let relative = crate::release::artifacts::safe_relative(Path::new(&record.path))?;
        if relative.starts_with("producer")
            || relative == Path::new("cell.json")
            || relative == Path::new("producer-manifest.json")
            || !paths.insert(relative.clone())
        {
            return Err(error(
                "public artifact catalog repeats or substitutes a reserved path",
            ));
        }
        let name = relative
            .file_name()
            .ok_or_else(|| error("public artifact basename absent"))?;
        let source_parent = parent(source, &relative, false)?;
        let bytes = read_selected(&source_parent, name, record)?;
        let destination_parent = parent(bundle, &relative, true)?;
        match write_new(&destination_parent, name, &bytes) {
            Ok(()) => {}
            Err(CiError::Io(cause)) if cause.kind() == std::io::ErrorKind::AlreadyExists => {
                if read_selected(&destination_parent, name, record)? != bytes {
                    return Err(error("existing public artifact differs"));
                }
            }
            Err(cause) => return Err(cause),
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/private/readiness_public_projection.rs"]
mod tests;
