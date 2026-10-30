//! Readable copies of existing observations, never recovery authority.
use crate::diagnostic_projection::{
    Limit, MAX_BYTES, MAX_DEPTH, MAX_ENTRIES, MAX_FILE_BYTES, Projection,
};
use crate::{CiError, Result};
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Component, Path},
    time::Instant,
};

fn live(cutoff: Instant) -> Result<()> {
    if Instant::now() >= cutoff {
        return Err(CiError::Message(
            "smoke diagnostic export cutoff exhausted".into(),
        ));
    }
    Ok(())
}

fn open_directory(parent: &File, name: &std::ffi::CStr) -> Result<File> {
    rustix::fs::openat(
        parent,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| CiError::Message(error.to_string()))
}

fn absolute_directory(path: &Path) -> Result<File> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(CiError::Message(
            "smoke diagnostic path is not absolute and normalized".into(),
        ));
    }
    let mut held = File::open("/")?;
    for part in path.components() {
        if let Component::Normal(name) = part {
            use std::os::unix::ffi::OsStrExt;
            let name = std::ffi::CString::new(name.as_bytes())
                .map_err(|error| CiError::Message(error.to_string()))?;
            held = open_directory(&held, &name)?;
        }
    }
    Ok(held)
}

fn stamp(metadata: &std::fs::Metadata) -> (u64, u64, u32, u32, u32, u64, u64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
        metadata.nlink(),
        metadata.len(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

fn write_file(parent: &File, name: &std::ffi::CStr, bytes: &[u8]) -> Result<()> {
    let fd = rustix::fs::openat(
        parent,
        name,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::from_raw_mode(0o644),
    )
    .map_err(|error| CiError::Message(error.to_string()))?;
    let mut file = File::from(fd);
    // Do not depend on the privileged caller's umask for upload readability.
    rustix::fs::fchmod(&file, rustix::fs::Mode::from_raw_mode(0o644))
        .map_err(|error| CiError::Message(error.to_string()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

struct Budget {
    entries: usize,
    bytes: u64,
    records: Vec<serde_json::Value>,
    projection: Projection,
}

fn observation(name: &std::ffi::CStr) -> bool {
    let Ok(name) = name.to_str() else {
        return false;
    };
    matches!(name, "stdout" | "stderr" | "stdout.bin" | "stderr.bin")
        || [
            ".json",
            ".jsonl",
            ".stdout",
            ".stderr",
            ".log",
            ".stdout.bin",
            ".stderr.bin",
        ]
        .iter()
        .any(|suffix| name.ends_with(suffix))
}

fn copy_tree(
    source: &File,
    destination: &File,
    relative: &Path,
    depth: usize,
    cutoff: Instant,
    budget: &mut Budget,
) -> Result<()> {
    live(cutoff)?;
    if depth > MAX_DEPTH {
        budget.projection.record_limit(Limit::Depth);
        return Ok(());
    }
    let mut entries =
        rustix::fs::Dir::read_from(source).map_err(|error| CiError::Message(error.to_string()))?;
    for entry in &mut entries {
        live(cutoff)?;
        let entry = entry.map_err(|error| CiError::Message(error.to_string()))?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        if let Some(limit) = crate::diagnostic_projection::entry_limit(budget.entries) {
            budget.projection.record_limit(limit);
            return Ok(());
        }
        budget.entries += 1;
        let before = rustix::fs::statat(source, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| CiError::Message(error.to_string()))?;
        use std::os::unix::ffi::OsStrExt;
        let path = relative.join(std::ffi::OsStr::from_bytes(name.to_bytes()));
        let kind = rustix::fs::FileType::from_raw_mode(before.st_mode);
        if kind != rustix::fs::FileType::Directory {
            let selected = observation(name);
            let reason = if !selected {
                Some("outside-observation-projection")
            } else if kind != rustix::fs::FileType::RegularFile || before.st_nlink != 1 {
                return Err(CiError::Message(
                    "smoke diagnostic unsafe type/link custody".into(),
                ));
            } else if before.st_size < 0 {
                return Err(CiError::Message(
                    "smoke diagnostic negative file extent".into(),
                ));
            } else {
                match crate::diagnostic_projection::extent_limit(
                    depth,
                    budget.bytes,
                    before.st_size as u64,
                ) {
                    Some(Limit::FileBytes) => Some("per-file-byte-bound"),
                    Some(Limit::AggregateBytes) => Some("aggregate-byte-bound"),
                    None => None,
                    Some(_) => unreachable!("depth admitted before entry traversal"),
                }
            };
            if let Some(reason) = reason {
                if selected {
                    budget
                        .projection
                        .record_limit(if reason == "per-file-byte-bound" {
                            Limit::FileBytes
                        } else {
                            Limit::AggregateBytes
                        });
                }
                budget.records.push(serde_json::json!({"path":path,"copied":false,"reason":reason,"selected_observation":selected,"uid":before.st_uid,"gid":before.st_gid,"mode":before.st_mode,"device":before.st_dev,"inode":before.st_ino,"length":before.st_size,"links":before.st_nlink}));
                continue;
            }
        }
        if kind == rustix::fs::FileType::Directory {
            let child = open_directory(source, name)?;
            let metadata = child.metadata()?;
            let held =
                rustix::fs::fstat(&child).map_err(|error| CiError::Message(error.to_string()))?;
            if held.st_dev != before.st_dev || held.st_ino != before.st_ino {
                return Err(CiError::Message(
                    "smoke diagnostic directory identity changed".into(),
                ));
            }
            budget.records.push(serde_json::json!({"path":path,"kind":"directory","uid":metadata.uid(),"gid":metadata.gid(),"mode":metadata.mode(),"device":metadata.dev(),"inode":metadata.ino()}));
            rustix::fs::mkdirat(destination, name, rustix::fs::Mode::from_raw_mode(0o755))
                .map_err(|error| CiError::Message(error.to_string()))?;
            let output = open_directory(destination, name)?;
            rustix::fs::fchmod(&output, rustix::fs::Mode::from_raw_mode(0o755))
                .map_err(|error| CiError::Message(error.to_string()))?;
            copy_tree(&child, &output, &path, depth + 1, cutoff, budget)?;
            let named = rustix::fs::statat(source, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|error| CiError::Message(error.to_string()))?;
            if stamp(&metadata) != stamp(&child.metadata()?)
                || named.st_dev != held.st_dev
                || named.st_ino != held.st_ino
            {
                return Err(CiError::Message(
                    "smoke diagnostic directory changed during export".into(),
                ));
            }
        } else if kind == rustix::fs::FileType::RegularFile {
            let fd = rustix::fs::openat(
                source,
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::NONBLOCK
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|error| CiError::Message(error.to_string()))?;
            let mut file = File::from(fd);
            let metadata = file.metadata()?;
            let held =
                rustix::fs::fstat(&file).map_err(|error| CiError::Message(error.to_string()))?;
            if !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.len() > 16 * 1024 * 1024
                || held.st_dev != before.st_dev
                || held.st_ino != before.st_ino
            {
                return Err(CiError::Message(
                    "smoke diagnostic file custody changed".into(),
                ));
            }
            let copied_bytes = budget
                .bytes
                .checked_add(metadata.len())
                .filter(|bytes| *bytes <= MAX_BYTES)
                .ok_or_else(|| {
                    CiError::Message("smoke diagnostic export byte bound exceeded".into())
                })?;
            let mut bytes = Vec::new();
            Read::by_ref(&mut file)
                .take(metadata.len() + 1)
                .read_to_end(&mut bytes)?;
            live(cutoff)?;
            let named = rustix::fs::statat(source, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|error| CiError::Message(error.to_string()))?;
            if bytes.len() as u64 != metadata.len()
                || stamp(&metadata) != stamp(&file.metadata()?)
                || named.st_dev != held.st_dev
                || named.st_ino != held.st_ino
                || named.st_nlink != 1
            {
                return Err(CiError::Message(
                    "smoke diagnostic read identity changed".into(),
                ));
            }
            write_file(destination, name, &bytes)?;
            budget.bytes = copied_bytes;
            use sha2::Digest;
            budget.records.push(serde_json::json!({"path":path,"kind":"file","copied":true,"uid":metadata.uid(),"gid":metadata.gid(),"mode":metadata.mode(),"device":metadata.dev(),"inode":metadata.ino(),"length":metadata.len(),"sha256":hex::encode(sha2::Sha256::digest(&bytes))}));
        } else {
            return Err(CiError::Message(
                "smoke diagnostic export refuses symlink/special entry".into(),
            ));
        }
    }
    Ok(())
}

/// The destination is a fresh sibling projection; private originals stay intact.
pub fn export(
    source: &Path,
    destination: &Path,
    cutoff: Instant,
    operation: &str,
    outcome: &Result<()>,
) -> Result<Projection> {
    live(cutoff)?;
    if !destination.is_absolute()
        || destination
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        || destination.starts_with(source)
        || source.starts_with(destination)
    {
        return Err(CiError::Message(
            "smoke diagnostics must be separate from authority".into(),
        ));
    }
    let input = absolute_directory(source)?;
    let parent = absolute_directory(
        destination
            .parent()
            .ok_or_else(|| CiError::Message("diagnostic parent missing".into()))?,
    )?;
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(
        destination
            .file_name()
            .ok_or_else(|| CiError::Message("diagnostic leaf missing".into()))?
            .as_bytes(),
    )
    .map_err(|error| CiError::Message(error.to_string()))?;
    rustix::fs::mkdirat(
        &parent,
        name.as_c_str(),
        rustix::fs::Mode::from_raw_mode(0o755),
    )
    .map_err(|error| CiError::Message(error.to_string()))?;
    let output = open_directory(&parent, &name)?;
    rustix::fs::fchmod(&output, rustix::fs::Mode::from_raw_mode(0o755))
        .map_err(|error| CiError::Message(error.to_string()))?;
    let mut budget = Budget {
        entries: 0,
        bytes: 0,
        records: Vec::new(),
        projection: Projection::Complete,
    };
    rustix::fs::mkdirat(
        &output,
        c"observations",
        rustix::fs::Mode::from_raw_mode(0o755),
    )
    .map_err(|error| CiError::Message(error.to_string()))?;
    let observations = open_directory(&output, c"observations")?;
    rustix::fs::fchmod(&observations, rustix::fs::Mode::from_raw_mode(0o755))
        .map_err(|error| CiError::Message(error.to_string()))?;
    let copied = copy_tree(&input, &observations, Path::new(""), 0, cutoff, &mut budget);
    let root = input.metadata()?;
    let copied_files = budget
        .records
        .iter()
        .filter(|record| record["copied"] == true)
        .count();
    let summary = serde_json::json!({"format":"memcordon.private-smoke-diagnostics","revision":1,"diagnostic_only":true,"certification_authority":false,"projection":"observation-json-and-captured-streams; other entries metadata-only","incomplete":copied.is_err() || budget.projection != Projection::Complete,"completeness":budget.projection,"limits":{"entries":MAX_ENTRIES,"bytes":MAX_BYTES,"file_bytes":MAX_FILE_BYTES,"depth":MAX_DEPTH},"visited_entries":budget.entries,"copied_bytes":budget.bytes,"operation":operation.chars().take(128).collect::<String>(),"operation_error":outcome.as_ref().err().map(|error| error.to_string().chars().take(4096).collect::<String>()),"copy_error":copied.as_ref().err().map(|error|error.to_string()),"source_root":{"uid":root.uid(),"gid":root.gid(),"mode":root.mode(),"device":root.dev(),"inode":root.ino()},"records":budget.records});
    let mut summary = summary;
    if copied.is_err() {
        summary["completeness"] = serde_json::Value::Null;
    }
    summary["copied_files"] = serde_json::json!(copied_files);
    write_file(
        &output,
        c"diagnostic-export.json",
        &serde_json::to_vec(&summary)?,
    )?;
    output.sync_all()?;
    parent.sync_all()?;
    copied.map(|()| budget.projection)
}
