//! Complete caller-owned files are published atomically under held custody.
#![cfg(target_os = "linux")]

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path};

pub struct StagedCallerObservation {
    parent: File,
    ancestors: Vec<(std::ffi::OsString, File)>,
    pending: std::ffi::OsString,
    leaf: std::ffi::OsString,
    file: File,
    bytes: Vec<u8>,
    uid: u32,
}

impl StagedCallerObservation {
    pub fn stage(path: &Path, bytes: &[u8], uid: u32) -> Result<Self, String> {
        let parent_path = path.parent().ok_or("caller observation parent absent")?;
        if !path.is_absolute()
            || path
                .as_os_str()
                .as_bytes()
                .split(|byte| *byte == b'/')
                .any(|part| part == b"." || part == b"..")
        {
            return Err("caller observation requires an absolute normalized path".into());
        }
        let leaf = path
            .file_name()
            .ok_or("caller observation final leaf absent")?;
        if Path::new(leaf)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err("caller observation requires one normal leaf".into());
        }
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(Path::new("/"))
            .map_err(|error| format!("caller observation parent open: {error}"))?;
        let mut ancestors = vec![(std::ffi::OsString::new(), root)];
        for component in parent_path.components() {
            match component {
                Component::RootDir => (),
                Component::Normal(name) => {
                    let held = File::from(
                        rustix::fs::openat(
                            &ancestors.last().expect("root ancestor").1,
                            name,
                            rustix::fs::OFlags::RDONLY
                                | rustix::fs::OFlags::DIRECTORY
                                | rustix::fs::OFlags::NOFOLLOW
                                | rustix::fs::OFlags::CLOEXEC,
                            rustix::fs::Mode::empty(),
                        )
                        .map_err(|error| format!("caller observation ancestor open: {error}"))?,
                    );
                    ancestors.push((name.to_os_string(), held));
                }
                _ => return Err("caller observation ancestor invalid".into()),
            }
        }
        validate_ancestors(&ancestors)?;
        let parent = ancestors
            .last()
            .expect("root ancestor")
            .1
            .try_clone()
            .map_err(|error| format!("caller observation parent hold: {error}"))?;
        let held = parent
            .metadata()
            .map_err(|error| format!("caller observation parent metadata: {error}"))?;
        let named = std::fs::symlink_metadata(parent_path)
            .map_err(|error| format!("caller observation parent name: {error}"))?;
        if !held.is_dir()
            || held.uid() != uid
            || held.mode() & 0o022 != 0
            || !named.is_dir()
            || (held.dev(), held.ino()) != (named.dev(), named.ino())
        {
            return Err("caller observation parent custody differs".into());
        }
        let mut pending = leaf.to_os_string();
        pending.push(".pending");
        let fd = rustix::fs::openat(
            &parent,
            &pending,
            rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::RDWR,
            rustix::fs::Mode::from_raw_mode(0o600),
        )
        .map_err(|error| format!("caller observation pending create: {error}"))?;
        let mut file = File::from(fd);
        file.write_all(bytes)
            .map_err(|error| format!("caller observation pending write: {error}"))?;
        rustix::fs::fchown(&file, Some(rustix::process::Uid::from_raw(uid)), None)
            .map_err(|error| format!("caller observation pending ownership: {error}"))?;
        rustix::fs::fchmod(&file, rustix::fs::Mode::from_raw_mode(0o600))
            .map_err(|error| format!("caller observation pending mode: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("caller observation pending sync: {error}"))?;
        let mut staged = Self {
            parent,
            ancestors,
            pending,
            leaf: leaf.to_os_string(),
            file,
            bytes: bytes.to_vec(),
            uid,
        };
        staged.validate_named(true)?;
        Ok(staged)
    }

    fn validate_named(&mut self, pending: bool) -> Result<(), String> {
        let held_parent = self
            .parent
            .metadata()
            .map_err(|error| format!("caller observation held parent metadata: {error}"))?;
        validate_ancestors(&self.ancestors)?;
        if !held_parent.is_dir() || held_parent.uid() != self.uid || held_parent.mode() & 0o022 != 0
        {
            return Err("caller observation parent association changed".into());
        }
        let leaf = if pending { &self.pending } else { &self.leaf };
        let mut named = File::from(
            rustix::fs::openat(
                &self.parent,
                leaf,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NONBLOCK,
                rustix::fs::Mode::empty(),
            )
            .map_err(|error| format!("caller observation named open: {error}"))?,
        );
        let held = self
            .file
            .metadata()
            .map_err(|error| format!("caller observation held metadata: {error}"))?;
        let before = named
            .metadata()
            .map_err(|error| format!("caller observation named metadata: {error}"))?;
        let valid = |metadata: &std::fs::Metadata| {
            metadata.is_file()
                && metadata.uid() == self.uid
                && metadata.mode() & 0o7777 == 0o600
                && metadata.nlink() == 1
                && metadata.len() == self.bytes.len() as u64
        };
        if !valid(&held)
            || !valid(&before)
            || (held.dev(), held.ino()) != (before.dev(), before.ino())
        {
            return Err("caller observation file custody differs".into());
        }
        let mut observed = Vec::new();
        Read::by_ref(&mut named)
            .take(self.bytes.len() as u64 + 1)
            .read_to_end(&mut observed)
            .map_err(|error| format!("caller observation named readback: {error}"))?;
        self.file
            .rewind()
            .map_err(|error| format!("caller observation held rewind: {error}"))?;
        let mut held_bytes = Vec::new();
        Read::by_ref(&mut self.file)
            .take(self.bytes.len() as u64 + 1)
            .read_to_end(&mut held_bytes)
            .map_err(|error| format!("caller observation held readback: {error}"))?;
        let after = named
            .metadata()
            .map_err(|error| format!("caller observation readback metadata: {error}"))?;
        if observed != self.bytes
            || held_bytes != self.bytes
            || !valid(&after)
            || (
                before.dev(),
                before.ino(),
                before.ctime(),
                before.ctime_nsec(),
            ) != (after.dev(), after.ino(), after.ctime(), after.ctime_nsec())
        {
            return Err("caller observation readback custody differs".into());
        }
        let final_named =
            rustix::fs::statat(&self.parent, leaf, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|error| format!("caller observation final name metadata: {error}"))?;
        if (final_named.st_dev as u64, final_named.st_ino as u64) != (held.dev(), held.ino()) {
            return Err("caller observation name changed during readback".into());
        }
        validate_ancestors(&self.ancestors)?;
        Ok(())
    }

    pub fn publish(mut self) -> Result<(), String> {
        self.validate_named(true)?;
        rustix::fs::renameat_with(
            &self.parent,
            &self.pending,
            &self.parent,
            &self.leaf,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|error| format!("caller observation no-replace publication: {error}"))?;
        self.validate_named(false)?;
        self.parent
            .sync_all()
            .map_err(|error| format!("caller observation parent sync: {error}"))
    }
}

fn validate_ancestors(ancestors: &[(std::ffi::OsString, File)]) -> Result<(), String> {
    let mut current = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")
        .map_err(|error| format!("caller observation root recheck: {error}"))?;
    for (index, (name, held)) in ancestors.iter().enumerate() {
        if index != 0 {
            current = File::from(
                rustix::fs::openat(
                    &current,
                    name,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::DIRECTORY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map_err(|error| format!("caller observation ancestor recheck: {error}"))?,
            );
        }
        let original = held
            .metadata()
            .map_err(|error| format!("caller observation held ancestor metadata: {error}"))?;
        let named = current
            .metadata()
            .map_err(|error| format!("caller observation named ancestor metadata: {error}"))?;
        if !original.is_dir()
            || !named.is_dir()
            || (original.dev(), original.ino()) != (named.dev(), named.ino())
        {
            return Err("caller observation ancestor association changed".into());
        }
    }
    Ok(())
}

pub fn publish(path: &Path, bytes: &[u8], uid: u32) -> Result<(), String> {
    StagedCallerObservation::stage(path, bytes, uid)?.publish()
}
