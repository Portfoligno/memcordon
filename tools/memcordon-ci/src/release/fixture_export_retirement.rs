//! Retire only an authenticated fixture export after all products are retained.
//! The caller supplies the original carrier-bound receipt, never a store census.
use crate::{CiError, Result};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::File;
use std::io::Read;
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

fn refusal(detail: &str) -> CiError {
    CiError::Message(format!("fixture export retirement: {detail}"))
}
fn live(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        return Err(refusal("original cutoff exhausted"));
    }
    Ok(())
}
fn open(parent: &File, name: &OsStr, directory: bool) -> Result<File> {
    let mut flags = rustix::fs::OFlags::RDONLY
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::CLOEXEC
        | rustix::fs::OFlags::NONBLOCK;
    if directory {
        flags |= rustix::fs::OFlags::DIRECTORY;
    }
    rustix::fs::openat(parent.as_fd(), name, flags, rustix::fs::Mode::empty())
        .map(File::from)
        .map_err(|error| refusal(&error.to_string()))
}
fn protected(file: &File, uid: u32, device: Option<u64>, directory: bool) -> Result<()> {
    let metadata = file.metadata()?;
    if metadata.uid() != uid
        || metadata.mode() & 0o7777 != if directory { 0o700 } else { 0o400 }
        || metadata.is_dir() != directory
        || (!directory && (!metadata.is_file() || metadata.nlink() != 1))
        || device.is_some_and(|device| metadata.dev() != device)
    {
        return Err(refusal("native ownership/type/link/device custody changed"));
    }
    Ok(())
}
fn named(parent: &File, name: &OsStr, held: &File, directory: bool) -> Result<()> {
    let reopened = open(parent, name, directory)?;
    let actual = held.metadata()?;
    let current = reopened.metadata()?;
    if (actual.dev(), actual.ino()) != (current.dev(), current.ino()) {
        return Err(refusal("named member differs from retained inode"));
    }
    Ok(())
}
fn names(directory: &File, deadline: Instant) -> Result<BTreeSet<std::ffi::OsString>> {
    live(deadline)?;
    // read_from opens an independent stream relative to the held directory;
    // repeated censuses start at the beginning without consuming its descriptor.
    let mut stream = rustix::fs::Dir::read_from(directory.as_fd()).map_err(std::io::Error::from)?;
    let mut result = BTreeSet::new();
    loop {
        live(deadline)?;
        let Some(entry) = stream.next() else {
            break;
        };
        let entry = entry.map_err(std::io::Error::from)?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        use std::os::unix::ffi::OsStrExt;
        result.insert(OsStr::from_bytes(bytes).to_owned());
        if result.len() > 8192 {
            return Err(refusal("directory census exceeds finite bound"));
        }
    }
    Ok(result)
}
fn contents(file: &File, length: u64, digest: &str, deadline: Instant) -> Result<Vec<u8>> {
    use std::io::{Seek, SeekFrom};
    let mut reader = file;
    reader.seek(SeekFrom::Start(0))?;
    let before = file.metadata()?;
    let mut bytes = Vec::new();
    let mut limited = reader.take(length + 1);
    let mut buffer = [0; 65536];
    loop {
        live(deadline)?;
        let count = limited.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    let after = file.metadata()?;
    if bytes.len() as u64 != length
        || before.len() != length
        || (before.len(), before.mtime(), before.mtime_nsec())
            != (after.len(), after.mtime(), after.mtime_nsec())
        || hex::encode(Sha256::digest(&bytes)) != digest
    {
        return Err(refusal(
            "retained product differs from authenticated receipt",
        ));
    }
    Ok(bytes)
}

/// Receipt authentication and original attempt ownership are checked by the caller.
/// `retain` must durably preserve each product before this function unlinks anything.
pub fn prepare(
    root: &Path,
    authenticated_receipt: &[u8],
    protected_uid: u32,
    deadline: Instant,
    journal_path: &Path,
    mut retain: impl FnMut(&str, &[u8]) -> Result<()>,
) -> Result<Owner> {
    live(deadline)?;
    if authenticated_receipt.len() > 4 * 1024 * 1024 {
        return Err(refusal("receipt exceeds bound"));
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(authenticated_receipt)
        .map_err(CiError::Message)?;
    let receipt: serde_json::Value = serde_json::from_slice(authenticated_receipt)?;
    let attempt = receipt["attempt_id"]
        .as_str()
        .ok_or_else(|| refusal("attempt absent"))?;
    if attempt.is_empty()
        || !attempt.bytes().all(|byte| byte.is_ascii_hexdigit())
        || root.file_name() != Some(OsStr::new(&format!("private-export-{attempt}")))
        || receipt["format"] != "memcordon.private-export"
        || receipt["revision"] != 1
    {
        return Err(refusal(
            "receipt does not identify the exact fixture export",
        ));
    }
    let components = root.components().collect::<Vec<_>>();
    if components.first() != Some(&Component::RootDir) || components.len() > 128 {
        return Err(refusal("export root must be absolute"));
    }
    let mut ancestry = vec![File::from(
        rustix::fs::open(
            "/",
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| refusal(&error.to_string()))?,
    )];
    let mut ancestry_names = Vec::new();
    for component in components.iter().skip(1) {
        let Component::Normal(name) = component else {
            return Err(refusal("aliased export root"));
        };
        let child = open(ancestry.last().expect("root held"), name, true)?;
        // System ancestors may have another owner only in portable test fixtures.
        if ![0, protected_uid].contains(&child.metadata()?.uid())
            || (child.metadata()?.mode() & 0o022 != 0 && child.metadata()?.mode() & 0o1000 == 0)
        {
            return Err(refusal("export ancestor is writable"));
        }
        ancestry_names.push(*name);
        ancestry.push(child);
    }
    let root_file = ancestry.last().expect("export held");
    protected(root_file, protected_uid, None, true)?;
    let device = root_file.metadata()?.dev();
    let mut directories = BTreeMap::new();
    directories.insert(PathBuf::new(), root_file.try_clone()?);
    let mut expected: BTreeMap<PathBuf, BTreeSet<std::ffi::OsString>> = BTreeMap::new();
    expected
        .entry(PathBuf::new())
        .or_default()
        .insert("export-receipt.json".into());
    let receipt_file = open(root_file, OsStr::new("export-receipt.json"), false)?;
    protected(&receipt_file, protected_uid, Some(device), false)?;
    contents(
        &receipt_file,
        authenticated_receipt.len() as u64,
        &hex::encode(Sha256::digest(authenticated_receipt)),
        deadline,
    )?;
    let members = receipt["files"]
        .as_array()
        .ok_or_else(|| refusal("file table absent"))?;
    if members.len() > 128 {
        return Err(refusal("file table exceeds bound"));
    }
    let mut files = BTreeMap::new();
    let mut total = 0u64;
    for member in members {
        live(deadline)?;
        let name = member["path"]
            .as_str()
            .ok_or_else(|| refusal("member path absent"))?;
        let parts = name.split('/').collect::<Vec<_>>();
        if parts.is_empty()
            || name.len() > 4096
            || parts.len() > 64
            || parts
                .iter()
                .any(|part| part.is_empty() || *part == "." || *part == "..")
            || name.contains(['\\', ':', '\0'])
            || name == "export-receipt.json"
        {
            return Err(refusal("member path aliases another authority"));
        }
        let length = member["length"]
            .as_u64()
            .ok_or_else(|| refusal("member length absent"))?;
        let digest = member["sha256"]
            .as_str()
            .ok_or_else(|| refusal("member digest absent"))?;
        total = total
            .checked_add(length)
            .ok_or_else(|| refusal("byte total overflow"))?;
        if length > 64 * 1024 * 1024 || total > 256 * 1024 * 1024 {
            return Err(refusal("products exceed bounded capture"));
        }
        let mut parent = PathBuf::new();
        for part in &parts[..parts.len() - 1] {
            expected
                .entry(parent.clone())
                .or_default()
                .insert((*part).into());
            let child_path = parent.join(part);
            if !directories.contains_key(&child_path) {
                let child = open(&directories[&parent], OsStr::new(part), true)?;
                protected(&child, protected_uid, Some(device), true)?;
                directories.insert(child_path.clone(), child);
            }
            parent = child_path;
        }
        let leaf = OsStr::new(parts.last().expect("finite member"));
        expected
            .entry(parent.clone())
            .or_default()
            .insert(leaf.to_owned());
        let file = open(&directories[&parent], leaf, false)?;
        protected(&file, protected_uid, Some(device), false)?;
        let bytes = contents(&file, length, digest, deadline)?;
        if files
            .insert(
                PathBuf::from(name),
                (file, length, digest.to_owned(), bytes),
            )
            .is_some()
        {
            return Err(refusal("duplicate member path"));
        }
    }
    let verify_tree = || -> Result<()> {
        live(deadline)?;
        for (index, name) in ancestry_names.iter().enumerate() {
            named(&ancestry[index], name, &ancestry[index + 1], true)?;
        }
        for (path, directory) in &directories {
            protected(directory, protected_uid, Some(device), true)?;
            if names(directory, deadline)? != expected.get(path).cloned().unwrap_or_default() {
                return Err(refusal("export contains undeclared or missing members"));
            }
            if !path.as_os_str().is_empty() {
                named(
                    &directories[path.parent().expect("parent")],
                    path.file_name().expect("name"),
                    directory,
                    true,
                )?;
            }
        }
        for (path, (file, length, digest, _)) in &files {
            protected(file, protected_uid, Some(device), false)?;
            named(
                &directories[path.parent().expect("parent")],
                path.file_name().expect("name"),
                file,
                false,
            )?;
            contents(file, *length, digest, deadline)?;
        }
        named(
            root_file,
            OsStr::new("export-receipt.json"),
            &receipt_file,
            false,
        )?;
        contents(
            &receipt_file,
            authenticated_receipt.len() as u64,
            &hex::encode(Sha256::digest(authenticated_receipt)),
            deadline,
        )?;
        Ok(())
    };
    verify_tree()?;
    for (path, (_, _, _, bytes)) in &files {
        live(deadline)?;
        retain(path.to_str().expect("validated UTF-8"), bytes)?;
    }
    verify_tree()?;
    let mut identities = BTreeSet::new();
    for file in directories
        .values()
        .chain(files.values().map(|(file, _, _, _)| file))
        .chain(std::iter::once(&receipt_file))
    {
        let metadata = file.metadata()?;
        if !identities.insert((metadata.dev(), metadata.ino())) {
            return Err(refusal("native members alias one retained inode"));
        }
    }
    let root_identity = (root_file.metadata()?.dev(), root_file.metadata()?.ino());
    for (_, _, _, bytes) in files.values_mut() {
        bytes.clear();
        bytes.shrink_to_fit();
    }
    let proof = serde_json::json!({
        "format": "memcordon.ci-fixture-export-retirement", "revision": 1,
        "attempt_id": attempt, "receipt_sha256": hex::encode(Sha256::digest(authenticated_receipt)),
        "device": root_identity.0, "inode": root_identity.1,
        "captured_files": files.len(), "named_absent": false,
    });
    let inventory = files
        .iter()
        .map(|(path, (file, length, digest, _))| {
            let metadata = file.metadata()?;
            Ok(
                serde_json::json!({"path":path,"length":length,"sha256":digest,
            "device":metadata.dev(),"inode":metadata.ino()}),
            )
        })
        .collect::<Result<Vec<_>>>()?;
    use std::os::unix::fs::OpenOptionsExt;
    let journal = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(journal_path)?;
    let owner = Owner {
        root: root.to_owned(),
        ancestry_names: ancestry_names.into_iter().map(OsStr::to_owned).collect(),
        ancestry,
        directories,
        files,
        receipt_file: Some(receipt_file),
        receipt: authenticated_receipt.to_vec(),
        expected,
        protected_uid,
        device,
        deadline,
        journal: Some(journal),
        proof,
        removed_files: BTreeSet::new(),
        removed_directories: BTreeSet::new(),
        receipt_removed: false,
        root_removed: false,
        #[cfg(test)]
        fail_progress: std::cell::Cell::new(false),
    };
    let directory_inventory = owner
        .directories
        .iter()
        .map(|(path, file)| {
            let metadata = file.metadata()?;
            Ok(serde_json::json!({"path":path,"device":metadata.dev(),"inode":metadata.ino()}))
        })
        .collect::<Result<Vec<_>>>()?;
    owner.record(
        &serde_json::json!({"kind":"intent","original":owner.proof,"captured":inventory,"directories":directory_inventory}),
    )?;
    File::open(
        journal_path
            .parent()
            .ok_or_else(|| refusal("journal parent absent"))?,
    )?
    .sync_all()?;
    Ok(owner)
}

/// This native owner is never reconstructed from the evidence journal.
pub struct Owner {
    root: PathBuf,
    ancestry_names: Vec<std::ffi::OsString>,
    ancestry: Vec<File>,
    directories: BTreeMap<PathBuf, File>,
    files: BTreeMap<PathBuf, (File, u64, String, Vec<u8>)>,
    receipt_file: Option<File>,
    receipt: Vec<u8>,
    expected: BTreeMap<PathBuf, BTreeSet<std::ffi::OsString>>,
    protected_uid: u32,
    device: u64,
    deadline: Instant,
    journal: Option<File>,
    proof: serde_json::Value,
    removed_files: BTreeSet<PathBuf>,
    removed_directories: BTreeSet<PathBuf>,
    receipt_removed: bool,
    root_removed: bool,
    #[cfg(test)]
    pub(super) fail_progress: std::cell::Cell<bool>,
}
impl Owner {
    fn record(&self, value: &serde_json::Value) -> Result<()> {
        #[cfg(test)]
        if self.fail_progress.replace(false) {
            return Err(refusal("injected progress persistence failure"));
        }
        use std::io::{Seek, SeekFrom, Write};
        let mut journal = self.journal.as_ref().expect("unsettled journal owner");
        let original = journal.seek(SeekFrom::End(0))?;
        let mut bytes = serde_json::to_vec(value)?;
        bytes.push(b'\n');
        if let Err(error) = journal.write_all(&bytes).and_then(|()| journal.sync_all()) {
            let rollback = journal.set_len(original).and_then(|()| journal.sync_all());
            return Err(refusal(&format!(
                "progress persistence failed: {error}; incomplete-frame rollback={rollback:?}"
            )));
        }
        Ok(())
    }
    pub fn settled(&self) -> bool {
        self.root_removed && self.proof["named_absent"] == true
    }
    fn validate(&self) -> Result<()> {
        live(self.deadline)?;
        for (index, name) in self.ancestry_names.iter().enumerate() {
            if self.root_removed && index + 1 == self.ancestry_names.len() {
                continue;
            }
            named(&self.ancestry[index], name, &self.ancestry[index + 1], true)?;
        }
        for (path, directory) in &self.directories {
            if self.removed_directories.contains(path)
                || (self.root_removed && path.as_os_str().is_empty())
            {
                let parent = if path.as_os_str().is_empty() {
                    &self.ancestry[self.ancestry.len() - 2]
                } else {
                    &self.directories[path.parent().expect("parent")]
                };
                let leaf = if path.as_os_str().is_empty() {
                    self.root.file_name().expect("name")
                } else {
                    path.file_name().expect("name")
                };
                if (cfg!(target_os = "linux") && directory.metadata()?.nlink() != 0)
                    || !matches!(
                        rustix::fs::statat(
                            parent.as_fd(),
                            leaf,
                            rustix::fs::AtFlags::SYMLINK_NOFOLLOW
                        ),
                        Err(rustix::io::Errno::NOENT)
                    )
                {
                    return Err(refusal("removed directory identity/absence changed"));
                }
                continue;
            }
            protected(directory, self.protected_uid, Some(self.device), true)?;
            let mut expected = self.expected.get(path).cloned().unwrap_or_default();
            for removed in self.removed_files.iter().chain(&self.removed_directories) {
                if removed.parent() == Some(path.as_path()) {
                    expected.remove(removed.file_name().expect("name"));
                }
            }
            if self.receipt_removed && path.as_os_str().is_empty() {
                expected.remove(OsStr::new("export-receipt.json"));
            }
            if names(directory, self.deadline)? != expected {
                return Err(refusal("remaining export inventory changed"));
            }
            if !path.as_os_str().is_empty() {
                named(
                    &self.directories[path.parent().expect("parent")],
                    path.file_name().expect("name"),
                    directory,
                    true,
                )?;
            }
        }
        for (path, (file, length, digest, _)) in &self.files {
            if self.removed_files.contains(path) {
                let parent = &self.directories[path.parent().expect("parent")];
                if file.metadata()?.nlink() != 0
                    || !matches!(
                        rustix::fs::statat(
                            parent.as_fd(),
                            path.file_name().expect("name"),
                            rustix::fs::AtFlags::SYMLINK_NOFOLLOW
                        ),
                        Err(rustix::io::Errno::NOENT)
                    )
                {
                    return Err(refusal("removed product identity/absence changed"));
                }
                continue;
            }
            protected(file, self.protected_uid, Some(self.device), false)?;
            named(
                &self.directories[path.parent().expect("parent")],
                path.file_name().expect("name"),
                file,
                false,
            )?;
            contents(file, *length, digest, self.deadline)?;
        }
        if !self.receipt_removed {
            protected(
                self.receipt_file.as_ref().expect("receipt owner"),
                self.protected_uid,
                Some(self.device),
                false,
            )?;
            named(
                &self.directories[Path::new("")],
                OsStr::new("export-receipt.json"),
                self.receipt_file.as_ref().expect("receipt owner"),
                false,
            )?;
            contents(
                self.receipt_file.as_ref().expect("receipt owner"),
                self.receipt.len() as u64,
                &hex::encode(Sha256::digest(&self.receipt)),
                self.deadline,
            )?;
        } else if self
            .receipt_file
            .as_ref()
            .expect("receipt owner")
            .metadata()?
            .nlink()
            != 0
        {
            return Err(refusal("removed receipt inode regained links"));
        }
        Ok(())
    }
    /// Retry only this retained owner; no supplied cutoff can extend its lifetime.
    pub fn retire(&mut self) -> Result<serde_json::Value> {
        if self.settled() {
            return Ok(self.proof.clone());
        }
        self.validate()?;
        for (path, (file, _, _, _)) in &self.files {
            if self.removed_files.contains(path) {
                continue;
            }
            live(self.deadline)?;
            let parent = &self.directories[path.parent().expect("parent")];
            let leaf = path.file_name().expect("name");
            named(parent, leaf, file, false)?;
            rustix::fs::unlinkat(parent.as_fd(), leaf, rustix::fs::AtFlags::empty())
                .map_err(|error| refusal(&error.to_string()))?;
            self.removed_files.insert(path.clone());
            parent.sync_all()?;
            if file.metadata()?.nlink() != 0 {
                return Err(refusal("product unlink not observed"));
            }
            self.record(&serde_json::json!({"kind":"product-unlinked","path":path}))?;
        }
        if !self.receipt_removed {
            live(self.deadline)?;
            let root = &self.directories[Path::new("")];
            named(
                root,
                OsStr::new("export-receipt.json"),
                self.receipt_file.as_ref().expect("receipt owner"),
                false,
            )?;
            rustix::fs::unlinkat(
                root.as_fd(),
                "export-receipt.json",
                rustix::fs::AtFlags::empty(),
            )
            .map_err(|error| refusal(&error.to_string()))?;
            self.receipt_removed = true;
            root.sync_all()?;
            if self
                .receipt_file
                .as_ref()
                .expect("receipt owner")
                .metadata()?
                .nlink()
                != 0
            {
                return Err(refusal("receipt unlink not observed"));
            }
            self.record(&serde_json::json!({"kind":"receipt-unlinked"}))?;
        }
        let mut paths = self
            .directories
            .keys()
            .filter(|path| !path.as_os_str().is_empty())
            .cloned()
            .collect::<Vec<_>>();
        paths.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
        for path in paths {
            if self.removed_directories.contains(&path) {
                continue;
            }
            live(self.deadline)?;
            let parent = &self.directories[path.parent().expect("parent")];
            let leaf = path.file_name().expect("name");
            named(parent, leaf, &self.directories[&path], true)?;
            rustix::fs::unlinkat(parent.as_fd(), leaf, rustix::fs::AtFlags::REMOVEDIR)
                .map_err(|error| refusal(&error.to_string()))?;
            self.removed_directories.insert(path.clone());
            parent.sync_all()?;
            self.record(&serde_json::json!({"kind":"directory-unlinked","path":path}))?;
        }
        let parent = &self.ancestry[self.ancestry.len() - 2];
        let root = &self.directories[Path::new("")];
        let leaf = self.root.file_name().expect("name");
        if !self.root_removed {
            live(self.deadline)?;
            named(parent, leaf, root, true)?;
            rustix::fs::unlinkat(parent.as_fd(), leaf, rustix::fs::AtFlags::REMOVEDIR)
                .map_err(|error| refusal(&error.to_string()))?;
            self.root_removed = true;
        }
        parent.sync_all()?;
        let links = root.metadata()?.nlink();
        if (cfg!(target_os = "linux") && links != 0)
            || !matches!(
                rustix::fs::statat(parent.as_fd(), leaf, rustix::fs::AtFlags::SYMLINK_NOFOLLOW),
                Err(rustix::io::Errno::NOENT)
            )
        {
            return Err(refusal("root retirement absence not observed"));
        }
        let mut proof = self.proof.clone();
        proof["named_absent"] = true.into();
        proof["held_link_count"] = links.into();
        self.record(&serde_json::json!({"kind":"settled","proof":proof}))?;
        self.files.clear();
        self.directories.clear();
        self.ancestry.clear();
        self.receipt_file.take();
        self.journal.take();
        self.proof = proof;
        Ok(self.proof.clone())
    }
}
