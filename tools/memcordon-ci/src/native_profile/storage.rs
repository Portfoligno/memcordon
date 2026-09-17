//! Task-owned publication and strict copy primitives. Links/reparse points are
//! rejected, not silently followed or omitted from qualification.
use std::collections::BTreeSet;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use crate::{CiError, Result};

fn reject(message: &str) -> CiError {
    CiError::Message(message.into())
}

fn regular(metadata: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return false;
        }
    }
    !metadata.file_type().is_symlink() && (metadata.is_dir() || metadata.is_file())
}

pub(super) fn validate_ancestors(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(reject(
            "qualification paths must be absolute without parent traversal",
        ));
    }
    for ancestor in path.ancestors() {
        if !regular(&fs::symlink_metadata(ancestor)?) {
            return Err(reject(
                "qualification rejects links, reparses and special files",
            ));
        }
    }
    Ok(())
}

fn component(name: &std::ffi::OsStr) -> Result<String> {
    let name = name
        .to_str()
        .ok_or_else(|| reject("non-Unicode native entry"))?;
    if name.is_empty() || name.ends_with([' ', '.']) || name.contains([':', '\\', '/']) {
        return Err(reject("invalid Windows native entry name"));
    }
    let upper = name.to_uppercase();
    let stem = upper.split('.').next().unwrap_or_default();
    if ["CON", "PRN", "AUX", "NUL"].contains(&stem)
        || ["COM", "LPT"].iter().any(|prefix| {
            stem.strip_prefix(prefix).is_some_and(|number| {
                number
                    .parse::<u8>()
                    .is_ok_and(|number| (1..=9).contains(&number))
            })
        })
    {
        return Err(reject("reserved Windows native entry name"));
    }
    Ok(upper)
}

fn children(path: &Path) -> Result<Vec<PathBuf>> {
    let mut names = BTreeSet::new();
    let mut children = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if !names.insert(component(&entry.file_name())?) {
            return Err(reject("case-colliding Windows native entries"));
        }
        children.push(entry.path());
    }
    children.sort();
    Ok(children)
}

pub(super) fn validate_tree(path: &Path) -> Result<()> {
    validate_ancestors(path)?;
    let mut pending = vec![path.to_path_buf()];
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)?;
        if !regular(&metadata) {
            return Err(reject(
                "qualification rejects links, reparses and special files",
            ));
        }
        if metadata.is_dir() {
            pending.extend(children(&path)?);
        }
    }
    Ok(())
}

fn stamp(metadata: &Metadata) -> Result<(u64, std::time::SystemTime, bool)> {
    Ok((
        metadata.len(),
        metadata.modified()?,
        metadata.permissions().readonly(),
    ))
}

fn same_file(file: &File, path: &Path, expected: &Metadata) -> Result<()> {
    let current = fs::symlink_metadata(path)?;
    if !regular(&current)
        || !current.is_file()
        || stamp(&current)? != stamp(expected)?
        || stamp(&file.metadata()?)? != stamp(expected)?
    {
        return Err(reject("native file changed during copying"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = file.metadata()?;
        if opened.dev() != current.dev()
            || opened.ino() != current.ino()
            || opened.dev() != expected.dev()
            || opened.ino() != expected.ino()
            || opened.ctime() != expected.ctime()
            || opened.ctime_nsec() != expected.ctime_nsec()
        {
            return Err(reject("native file identity changed during copying"));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        let opened = file.metadata()?;
        if opened.creation_time() != expected.creation_time()
            || opened.file_attributes() != expected.file_attributes()
            || current.creation_time() != expected.creation_time()
            || current.file_attributes() != expected.file_attributes()
        {
            return Err(reject("native file stamp changed during copying"));
        }
        let current = File::open(path)?;
        if memcordon_testkit::windows_file_identity(file)?
            != memcordon_testkit::windows_file_identity(&current)?
        {
            return Err(reject("native file identity changed during copying"));
        }
    }
    Ok(())
}

fn copy_file(source: &Path, destination: &Path) -> Result<()> {
    let expected = fs::symlink_metadata(source)?;
    if !regular(&expected) || !expected.is_file() {
        return Err(reject("unsupported native copy input"));
    }
    let mut input = File::open(source)?;
    same_file(&input, source, &expected)?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)?;
    if std::io::copy(&mut input, &mut output)? != expected.len() {
        return Err(reject("native copy length changed"));
    }
    output.sync_all()?;
    same_file(&input, source, &expected)?;
    drop(output);
    let mut input = File::open(source)?;
    let mut copied = File::open(destination)?;
    let copied_metadata = copied.metadata()?;
    let mut left = vec![0; crate::inventory_reader::BUFFER_SIZE];
    let mut right = vec![0; crate::inventory_reader::BUFFER_SIZE];
    let mut remaining = expected.len();
    while remaining != 0 {
        let count =
            usize::try_from(remaining.min(left.len() as u64)).expect("buffer bounded length");
        input.read_exact(&mut left[..count])?;
        copied.read_exact(&mut right[..count])?;
        if left[..count] != right[..count] {
            return Err(reject("native copy byte mismatch"));
        }
        remaining -= count as u64;
    }
    if input.read(&mut left[..1])? != 0 || copied.read(&mut right[..1])? != 0 {
        return Err(reject("native copy grew during comparison"));
    }
    same_file(&input, source, &expected)?;
    same_file(&copied, destination, &copied_metadata)?;
    fs::set_permissions(destination, expected.permissions())?;
    Ok(())
}

pub(super) fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    validate_tree(source)?;
    fs::create_dir_all(destination)?;
    let mut pending = vec![(source.to_path_buf(), destination.to_path_buf())];
    let mut permissions = Vec::new();
    while let Some((source, destination)) = pending.pop() {
        let metadata = fs::symlink_metadata(&source)?;
        if !regular(&metadata) || !metadata.is_dir() {
            return Err(reject("native copy directory changed"));
        }
        permissions.push((destination.clone(), metadata.permissions()));
        for child in children(&source)? {
            let name = child
                .file_name()
                .ok_or_else(|| reject("missing native child name"))?;
            let copied = destination.join(name);
            let metadata = fs::symlink_metadata(&child)?;
            if !regular(&metadata) {
                return Err(reject("unsupported native child"));
            }
            if metadata.is_dir() {
                fs::create_dir(&copied)?;
                pending.push((child, copied));
            } else {
                copy_file(&child, &copied)?;
            }
        }
    }
    for (directory, permissions) in permissions.into_iter().rev() {
        fs::set_permissions(directory, permissions)?;
    }
    Ok(())
}

/// A create-new lease is retained after failure or completion. A subsequent
/// caller fails instead of adopting/replacing a candidate or its evidence.
pub(super) struct Publication {
    incoming: Option<PathBuf>,
    active: PathBuf,
    control: PathBuf,
    _lease: File,
}

impl Publication {
    pub(super) fn new(base: &Path, contract: &str, arch: &str) -> Result<Self> {
        validate_ancestors(base)?;
        let scope = base.join(contract).join(arch);
        fs::create_dir_all(&scope)?;
        validate_ancestors(&scope)?;
        let lease = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(scope.join("lease"))?;
        let control = scope.join("control");
        fs::create_dir(&control)?;
        let active = scope.join("active");
        // Exclusive reservation makes the final name unavailable to another
        // cooperating acquisition, even if its lease handling is defective.
        fs::create_dir(&active)?;
        let incoming = tempfile::Builder::new()
            .prefix("incoming-")
            .tempdir_in(&scope)?
            .keep();
        Ok(Self {
            incoming: Some(incoming),
            active: active.join("tree"),
            control,
            _lease: lease,
        })
    }

    pub(super) fn active(&self) -> &Path {
        &self.active
    }
    pub(super) fn incoming(&self) -> &Path {
        self.incoming.as_deref().expect("unpublished candidate")
    }
    pub(super) fn control(&self) -> &Path {
        &self.control
    }

    pub(super) fn publish(&mut self) -> Result<()> {
        match fs::symlink_metadata(&self.active) {
            Ok(_) => return Err(reject("native destination already occupied")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        validate_ancestors(self.active.parent().expect("active parent"))?;
        fs::rename(self.incoming(), &self.active)?;
        // No path-based cleanup after transfer of ownership. Failed candidates
        // likewise remain for diagnosis and normal whole-job cleanup.
        let _ = self.incoming.take();
        Ok(())
    }
}

pub(super) fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| reject("output parent missing"))?;
    validate_ancestors(parent)?;
    let mut pending = tempfile::NamedTempFile::new_in(parent)?;
    pending.write_all(bytes)?;
    pending.write_all(b"\n")?;
    pending.as_file().sync_all()?;
    pending
        .persist_noclobber(path)
        .map_err(|error| CiError::Io(error.error))?;
    Ok(())
}
