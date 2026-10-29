//! Failure evidence publication; these artifacts never authorize intervention.
use crate::readiness_identity::SourceIdentity;
use crate::{CiError, Result};
use memcordon_readiness_verifier::Artifact;
use memcordon_readiness_verifier::ProductKey;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
};

pub struct HeldCellPublication {
    namespace: PathBuf,
    mapping: Vec<(PathBuf, File)>,
    uid: u32,
    namespace_uid: u32,
    namespace_mode: u32,
    selection: Vec<u8>,
    lease_id: String,
    target_receipt: Vec<u8>,
}

fn custody(
    stage: &str,
    path: &Path,
    role: &str,
    expected: u32,
    observed: &std::fs::Metadata,
    predicate: &str,
) -> CiError {
    CiError::Message(format!(
        "publication custody stage={stage} path={:?} role={role} expected_uid={expected} observed_uid={} gid={} mode={:#o} device={} inode={} predicate={predicate}",
        path.to_string_lossy().chars().take(256).collect::<String>(),
        observed.uid(),
        observed.gid(),
        observed.mode(),
        observed.dev(),
        observed.ino()
    ))
}

fn directory(parent: &File, name: &std::ffi::OsStr) -> Result<File> {
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
    .map_err(|error| CiError::Message(format!("open publication component {name:?}: {error}")))
}

fn named_matches(parent: &File, leaf: &std::ffi::OsStr, before: &rustix::fs::Stat) -> Result<()> {
    let actual = rustix::fs::statat(parent, leaf, rustix::fs::AtFlags::SYMLINK_NOFOLLOW).map_err(
        |error| CiError::Message(format!("final named publication stat {leaf:?}: {error}")),
    )?;
    let stamp = |value: &rustix::fs::Stat| {
        (
            value.st_dev,
            value.st_ino,
            value.st_uid,
            value.st_gid,
            value.st_mode,
            value.st_nlink,
            value.st_size,
            value.st_ctime,
            value.st_ctime_nsec,
        )
    };
    if stamp(&actual) != stamp(before) {
        return Err(CiError::Message(format!(
            "final named publication leaf {leaf:?} identity/custody differs"
        )));
    }
    Ok(())
}

impl HeldCellPublication {
    /// Establish the selected controller-owned cell before launching attempts.
    /// The outer namespace is transport custody, never privileged authority.
    pub fn create(namespace: &Path, identity: &SourceIdentity, cell: &ProductKey) -> Result<Self> {
        let single = |name: &str| {
            !name.is_empty()
                && Path::new(name).components().count() == 1
                && matches!(
                    Path::new(name).components().next(),
                    Some(Component::Normal(_))
                )
        };
        if !namespace.is_absolute()
            || namespace
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
            || !single(&cell.target)
            || !single(&cell.channel)
        {
            return Err(CiError::Message(
                "publication selected namespace/cell is not normalized".into(),
            ));
        }
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(namespace)?;
        let root_metadata = root.metadata()?;
        if root_metadata.mode() & 0o022 != 0 {
            return Err(custody(
                "establish",
                namespace,
                "transport namespace",
                root_metadata.uid(),
                &root_metadata,
                "group/world writable",
            ));
        }
        let uid = rustix::process::geteuid().as_raw();
        let target_path = namespace.join(&cell.target);
        let created = match rustix::fs::mkdirat(
            &root,
            cell.target.as_str(),
            rustix::fs::Mode::from_raw_mode(0o755),
        ) {
            Ok(()) => true,
            Err(rustix::io::Errno::EXIST) => false,
            Err(error) => {
                return Err(CiError::Message(format!(
                    "create selected publication target {target_path:?}: {error}"
                )));
            }
        };
        let target = directory(&root, std::ffi::OsStr::new(&cell.target))?;
        let target_metadata = target.metadata()?;
        if target_metadata.uid() != uid || target_metadata.mode() & 0o022 != 0 {
            return Err(custody(
                "establish",
                &target_path,
                "controller target",
                uid,
                &target_metadata,
                "owner/mode",
            ));
        }
        let target_receipt = serde_json::to_vec(
            &serde_json::json!({"format":"memcordon.cell-publication-target","revision":1,"identity":identity,"target":cell.target,"namespace":{"device":root_metadata.dev(),"inode":root_metadata.ino(),"uid":root_metadata.uid(),"mode":root_metadata.mode()}}),
        )?;
        let receipt_leaf = "publication-target-owner.json";
        if created {
            let fd = rustix::fs::openat(
                &target,
                receipt_leaf,
                rustix::fs::OFlags::WRONLY
                    | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::EXCL
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::from_raw_mode(0o600),
            )
            .map_err(|error| CiError::Message(error.to_string()))?;
            let mut file = File::from(fd);
            file.write_all(&target_receipt)?;
            file.sync_all()?;
            target.sync_all()?;
            root.sync_all()?;
        }
        let prefix_path = target_path.join(&cell.channel);
        // An existing cell is never adopted from its current path/owner.
        let mut value = Self {
            namespace: namespace.to_path_buf(),
            mapping: vec![(namespace.to_path_buf(), root), (target_path, target)],
            uid,
            namespace_uid: root_metadata.uid(),
            namespace_mode: root_metadata.mode(),
            selection: serde_json::to_vec(&(identity, cell))?,
            lease_id: format!("{}-{}-{}", identity.run_id, cell.target, cell.channel),
            target_receipt,
        };
        value.verify()?;
        let target = &value.mapping.last().expect("retained target").1;
        rustix::fs::mkdirat(
            target,
            cell.channel.as_str(),
            rustix::fs::Mode::from_raw_mode(0o755),
        )
        .map_err(|error| {
            CiError::Message(format!(
                "create original publication cell {prefix_path:?}: {error}"
            ))
        })?;
        let prefix = directory(target, std::ffi::OsStr::new(&cell.channel))?;
        target.sync_all()?;
        value.mapping.push((prefix_path, prefix));
        value.verify()?;
        Ok(value)
    }

    pub fn prefix(&self) -> &Path {
        &self.mapping.last().expect("held selected cell").0
    }

    pub fn verify_selection(
        &self,
        identity: &SourceIdentity,
        cell: &ProductKey,
        lease_id: &str,
    ) -> Result<()> {
        if serde_json::to_vec(&(identity, cell))? != self.selection || lease_id != self.lease_id {
            return Err(CiError::Message(
                "publication original source/cell/lease binding differs".into(),
            ));
        }
        self.verify()
    }

    pub fn verify(&self) -> Result<()> {
        for (index, (path, held)) in self.mapping.iter().enumerate() {
            let actual = std::fs::symlink_metadata(path)?;
            let retained = held.metadata()?;
            let uid = if index == 0 {
                self.namespace_uid
            } else {
                self.uid
            };
            let role = if index == 0 {
                "transport namespace"
            } else {
                "controller cell ancestry"
            };
            if !actual.is_dir()
                || actual.dev() != retained.dev()
                || actual.ino() != retained.ino()
                || actual.uid() != uid
                || actual.mode() & 0o022 != 0
                || (index == 0 && actual.mode() != self.namespace_mode)
            {
                return Err(custody(
                    "verify mapping",
                    path,
                    role,
                    uid,
                    &actual,
                    "named identity/owner/mode",
                ));
            }
        }
        let target = &self.mapping[1].1;
        let fd = rustix::fs::openat(
            target,
            "publication-target-owner.json",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| {
            CiError::Message(format!("read original publication target binding: {error}"))
        })?;
        let mut file = File::from(fd);
        let before = file.metadata()?;
        let raw_before =
            rustix::fs::fstat(&file).map_err(|error| CiError::Message(error.to_string()))?;
        let mut bytes = Vec::new();
        std::io::Read::by_ref(&mut file)
            .take(65537)
            .read_to_end(&mut bytes)?;
        let after = file.metadata()?;
        if !before.is_file()
            || before.uid() != self.uid
            || before.nlink() != 1
            || before.mode() & 0o077 != 0
            || before.len() > 65536
            || bytes != self.target_receipt
            || (
                before.dev(),
                before.ino(),
                before.len(),
                before.ctime(),
                before.ctime_nsec(),
            ) != (
                after.dev(),
                after.ino(),
                after.len(),
                after.ctime(),
                after.ctime_nsec(),
            )
        {
            return Err(custody(
                "verify receipt",
                &self.mapping[1].0.join("publication-target-owner.json"),
                "controller target binding",
                self.uid,
                &before,
                "receipt bytes/custody",
            ));
        }
        named_matches(
            target,
            std::ffi::OsStr::new("publication-target-owner.json"),
            &raw_before,
        )?;
        Ok(())
    }
}

/// The caller's artifact list is updated before fallible case normalization.
/// Both errors remain observable; normalization cannot roll back diagnostics.
pub fn capture_before_normalize<T>(
    artifacts: &mut Vec<Artifact>,
    capture: impl FnOnce(&mut Vec<Artifact>) -> Result<()>,
    normalize: impl FnOnce() -> Result<T>,
) -> (Result<()>, Result<T>) {
    let captured = capture(artifacts);
    (captured, normalize())
}

type Parents = (String, Vec<(PathBuf, File)>);

#[cfg(all(test, target_os = "linux"))]
#[path = "../../tests/support/linux_lifecycle_publication_native.rs"]
mod native_tests;

fn parents(anchor: &HeldCellPublication, path: &Path) -> Result<Parents> {
    anchor.verify()?;
    let root = &anchor.namespace;
    let relative = path
        .strip_prefix(root)
        .map_err(|_| CiError::Message("lifecycle diagnostic escapes artifact root".into()))?;
    if !root.is_absolute()
        || relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(CiError::Message(
            "lifecycle diagnostic path/extent differs".into(),
        ));
    }
    let relative = relative
        .to_str()
        .ok_or_else(|| CiError::Message("lifecycle diagnostic path is not UTF-8".into()))?;
    let parent = path
        .parent()
        .ok_or_else(|| CiError::Message("lifecycle diagnostic parent absent".into()))?;
    let uid = anchor.uid;
    let prefix = anchor.prefix();
    let root_file = anchor
        .mapping
        .last()
        .expect("held selected prefix")
        .1
        .try_clone()?;
    let mut directories = vec![(prefix.to_path_buf(), root_file)];
    for part in parent
        .strip_prefix(prefix)
        .map_err(|_| CiError::Message("diagnostic parent escapes original cell prefix".into()))?
        .components()
    {
        let Component::Normal(name) = part else {
            return Err(CiError::Message(
                "diagnostic parent is not normalized".into(),
            ));
        };
        let (previous_path, previous) = directories.last().expect("retained diagnostic root");
        let fd = rustix::fs::openat(
            previous,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| {
            CiError::Message(format!("open diagnostic directory {name:?}: {error}"))
        })?;
        directories.push((previous_path.join(name), File::from(fd)));
    }
    for (path, directory) in &directories {
        let metadata = directory.metadata()?;
        if metadata.uid() != uid || metadata.mode() & 0o022 != 0 {
            return Err(custody(
                "publish descendant",
                path,
                "controller descendant",
                uid,
                &metadata,
                "owner/mode",
            ));
        }
    }
    Ok((relative.to_owned(), directories))
}

pub fn publish(
    anchor: &HeldCellPublication,
    path: &Path,
    bytes: &[u8],
    artifacts: &mut Vec<Artifact>,
) -> Result<File> {
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(CiError::Message("publication bytes exceed bound".into()));
    }
    let (relative, directories) = parents(anchor, path)?;
    let uid = anchor.uid;
    let directory = &directories.last().expect("retained diagnostic parent").1;
    let leaf = path
        .file_name()
        .ok_or_else(|| CiError::Message("lifecycle diagnostic leaf absent".into()))?;
    let fd = rustix::fs::openat(
        directory,
        leaf,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::from_raw_mode(0o600),
    )
    .map_err(|error| CiError::Message(format!("publish lifecycle diagnostic {path:?}: {error}")))?;
    let mut file = File::from(fd);
    file.write_all(bytes)?;
    file.sync_all()?;
    directory.sync_all()?;
    let stamp = |metadata: &std::fs::Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.uid(),
            metadata.mode(),
            metadata.nlink(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        )
    };
    let before = file.metadata()?;
    let raw_before =
        rustix::fs::fstat(&file).map_err(|error| CiError::Message(error.to_string()))?;
    let named_fd = rustix::fs::openat(
        directory,
        leaf,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| CiError::Message(format!("read diagnostic publication {path:?}: {error}")))?;
    let mut named = File::from(named_fd);
    let mut readback = Vec::new();
    std::io::Read::by_ref(&mut named)
        .take(bytes.len() as u64 + 1)
        .read_to_end(&mut readback)?;
    if !before.is_file()
        || before.uid() != uid
        || before.nlink() != 1
        || before.mode() & 0o077 != 0
        || before.len() != bytes.len() as u64
        || readback != bytes
        || stamp(&before) != stamp(&file.metadata()?)
        || stamp(&before) != stamp(&named.metadata()?)
    {
        return Err(CiError::Message(
            "lifecycle diagnostic published bytes/custody differ".into(),
        ));
    }
    named_matches(directory, leaf, &raw_before)?;
    verify_parents(anchor, &directories)?;
    artifacts.push(Artifact {
        path: relative,
        length: bytes.len() as u64,
        sha256: super::artifacts::checksum(bytes),
    });
    Ok(file)
}

fn verify_parents(anchor: &HeldCellPublication, directories: &[(PathBuf, File)]) -> Result<()> {
    for (path, held) in directories {
        let actual = std::fs::symlink_metadata(path)?;
        let retained = held.metadata()?;
        if actual.file_type().is_symlink()
            || !actual.is_dir()
            || actual.dev() != retained.dev()
            || actual.ino() != retained.ino()
            || actual.uid() != anchor.uid
            || actual.mode() & 0o022 != 0
        {
            return Err(custody(
                "final descendant mapping",
                path,
                "controller descendant",
                anchor.uid,
                &actual,
                "named identity/owner/mode",
            ));
        }
    }
    anchor.verify()?;
    Ok(())
}

pub fn register_existing(
    anchor: &HeldCellPublication,
    path: &Path,
    artifacts: &mut Vec<Artifact>,
) -> Result<File> {
    let (relative, directories) = parents(anchor, path)?;
    let directory = &directories.last().expect("held diagnostic parent").1;
    let leaf = path
        .file_name()
        .ok_or_else(|| CiError::Message("existing context leaf absent".into()))?;
    let fd = rustix::fs::openat(
        directory,
        leaf,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| CiError::Message(format!("open existing context {relative}: {error}")))?;
    let mut file = File::from(fd);
    let before = file.metadata()?;
    let raw_before =
        rustix::fs::fstat(&file).map_err(|error| CiError::Message(error.to_string()))?;
    if !before.is_file()
        || before.uid() != anchor.uid
        || before.nlink() != 1
        || before.mode() & 0o022 != 0
        || before.len() > 16 * 1024 * 1024
    {
        return Err(custody(
            "existing context",
            path,
            "controller context",
            anchor.uid,
            &before,
            "file type/owner/mode/link/extent",
        ));
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    let named_fd = rustix::fs::openat(
        directory,
        leaf,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| CiError::Message(format!("reopen existing context {relative}: {error}")))?;
    let mut named = File::from(named_fd);
    let mut readback = Vec::new();
    std::io::Read::by_ref(&mut named)
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut readback)?;
    let stamp = |metadata: &std::fs::Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.uid(),
            metadata.mode(),
            metadata.nlink(),
            metadata.len(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        )
    };
    if bytes.len() as u64 != before.len()
        || bytes != readback
        || stamp(&before) != stamp(&file.metadata()?)
        || stamp(&before) != stamp(&named.metadata()?)
    {
        return Err(CiError::Message(format!(
            "existing context {relative} changed during bounded capture"
        )));
    }
    named_matches(directory, leaf, &raw_before)?;
    verify_parents(anchor, &directories)?;
    artifacts.push(Artifact {
        path: relative,
        length: bytes.len() as u64,
        sha256: super::artifacts::checksum(&bytes),
    });
    Ok(file)
}
