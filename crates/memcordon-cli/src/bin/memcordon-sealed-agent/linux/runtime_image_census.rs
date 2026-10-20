//! Administrative read-only census through the original installed-image owner.
use super::*;
use memcordon_core::runtime_image_census::{
    RuntimeImageCensusIdentityV1 as Identity, RuntimeImageCensusMemberV1 as Member,
    RuntimeImageCensusObjectV1 as Object, RuntimeImageCensusV1 as Census,
};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn identity(metadata: &std::fs::Metadata) -> Identity {
    Identity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode(),
        nlink: metadata.nlink(),
        length: metadata.len(),
    }
}

fn within(deadline: Instant) -> Result<(), String> {
    if Instant::now() >= deadline {
        Err("image census original cutoff exhausted".into())
    } else {
        Ok(())
    }
}

fn hash(file: &File, deadline: Instant) -> Result<DiagnosticSha256, String> {
    use std::os::unix::fs::FileExt;
    let before = file.metadata().map_err(io)?;
    if !before.is_file() {
        return Err("image census hash object is not regular".into());
    }
    let mut digest = Sha256::new();
    let mut offset = 0u64;
    let mut bytes = [0u8; 64 * 1024];
    loop {
        within(deadline)?;
        let count = file.read_at(&mut bytes, offset).map_err(io)?;
        if count == 0 {
            break;
        }
        offset = offset
            .checked_add(u64::try_from(count).map_err(|_| "census byte overflow")?)
            .ok_or("census byte overflow")?;
        if offset > before.len() {
            return Err("image census member grew".into());
        }
        digest.update(&bytes[..count]);
    }
    let after = file.metadata().map_err(io)?;
    if identity(&before) != identity(&after)
        || offset != before.len()
        || (
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        )
    {
        return Err("image census member changed during held read".into());
    }
    Ok(DiagnosticSha256::from_bytes(digest.finalize().into()))
}

fn link(parent: BorrowedFd<'_>, name: &CString) -> Result<String, String> {
    let mut bytes = vec![0u8; 4097];
    let length = unsafe {
        libc::readlinkat(
            parent.as_raw_fd(),
            name.as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if length < 0 {
        return Err(io(std::io::Error::last_os_error()));
    }
    let length = usize::try_from(length).map_err(|_| "image census link length invalid")?;
    if length == bytes.len() {
        return Err("image census link exceeds native bound".into());
    }
    bytes.truncate(length);
    String::from_utf8(bytes).map_err(|_| "image census link is not native UTF8".into())
}

pub fn inspect(definition_path: &Path, cutoff_unix_millis: u64) -> Result<(), String> {
    if unsafe { libc::getuid() } != 0 || unsafe { libc::geteuid() } != 0 {
        return Err("runtime image census requires real/effective root".into());
    }
    let cutoff = UNIX_EPOCH
        .checked_add(Duration::from_millis(cutoff_unix_millis))
        .ok_or("image census cutoff overflow")?;
    let clock = Instant::now();
    let remaining = cutoff
        .duration_since(SystemTime::now())
        .map_err(|_| "image census cutoff exhausted")?;
    let deadline = clock
        .checked_add(remaining)
        .ok_or("image census deadline overflow")?;
    let bytes = super::super::protected_read::read_protected_absolute(
        definition_path,
        IMAGE_MANIFEST_BYTES as u64,
        None,
    )?;
    let definition = RuntimeImageDefinitionV1::parse(&bytes)?;
    let raw_hash = DiagnosticSha256::from_bytes(Sha256::digest(&bytes).into());
    within(deadline)?;
    let image = open_installed(&definition)?;
    let expected: BTreeSet<_> = Census::expected_paths(&definition)?
        .into_iter()
        .map(|path| path.as_str().to_owned())
        .collect();
    let capacity = super::super::image_fd_budget::ensure(expected.len(), expected.len())?;
    let store_owner = store(false)?;
    let selected = cstr(&image_name(image.reference()))?;
    require_named_inode(store_owner.as_fd(), &selected, &image.root)?;
    let store_before = store_owner.metadata().map_err(io)?;
    let root_before = image.root.metadata().map_err(io)?;
    let mut pending = vec![(String::new(), image.root.try_clone().map_err(io)?)];
    let mut members = BTreeMap::new();
    let mut held = BTreeMap::new();
    while let Some((prefix, parent)) = pending.pop() {
        within(deadline)?;
        protected_directory(&parent)?;
        for entry in rustix::fs::Dir::read_from(&parent).map_err(|error| error.to_string())? {
            within(deadline)?;
            let entry = entry.map_err(|error| error.to_string())?;
            let raw = entry.file_name().to_bytes();
            if raw == b"." || raw == b".." {
                continue;
            }
            let name = std::str::from_utf8(raw).map_err(|_| "image census member is not UTF8")?;
            let path = if prefix.is_empty() {
                PathBuf::from(name)
            } else {
                Path::new(&prefix).join(name)
            };
            let path = RootRelativePath::new(
                path.to_str()
                    .ok_or("image census path unavailable")?
                    .to_owned(),
            )?;
            if !expected.contains(path.as_str()) || members.contains_key(path.as_str()) {
                return Err("image census unexpected or repeated namespace member".into());
            }
            let name = cstr(name)?;
            let owner = native(unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            })?;
            let metadata = owner.metadata().map_err(io)?;
            let object = if metadata.is_dir() {
                let directory = native(unsafe {
                    libc::openat(
                        parent.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                })?;
                if identity(&directory.metadata().map_err(io)?) != identity(&metadata) {
                    return Err("image census directory reassociated".into());
                }
                pending.push((path.as_str().to_owned(), directory));
                Object::Directory
            } else if metadata.is_file() {
                let file = if path.as_str() == ".memcordon-image.json" {
                    open_protected_relative(image.root(), &path)?
                } else {
                    File::from(image.object(&path)?.try_clone_to_owned().map_err(io)?)
                };
                if identity(&file.metadata().map_err(io)?) != identity(&metadata) {
                    return Err("image census regular inode reassociated".into());
                }
                no_file_capability(&file)?;
                Object::Regular {
                    sha256: hash(&file, deadline)?,
                    capability_absent: true,
                }
            } else if metadata.file_type().is_symlink() {
                Object::Symlink {
                    target: link(parent.as_fd(), &name)?,
                }
            } else {
                return Err("image census unexpected socket/FIFO/device authority".into());
            };
            require_named_inode(parent.as_fd(), &name, &owner)?;
            members.insert(
                path.as_str().to_owned(),
                Member {
                    path: path.clone(),
                    identity: identity(&metadata),
                    object,
                },
            );
            held.insert(path.as_str().to_owned(), (owner, metadata));
        }
    }
    within(deadline)?;
    image.revalidate()?;
    for (path, (owner, before)) in &held {
        within(deadline)?;
        let path = RootRelativePath::new(path.clone())?;
        let (parent, name) = protected_parent_at(image.root(), &path)?;
        require_named_inode(parent.as_fd(), &name, owner)?;
        let original = members
            .get(path.as_str())
            .ok_or("image census held member absent")?;
        let after = owner.metadata().map_err(io)?;
        if identity(&after) != original.identity
            || (
                before.mtime(),
                before.mtime_nsec(),
                before.ctime(),
                before.ctime_nsec(),
            ) != (
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec(),
            )
        {
            return Err("image census retained metadata changed".into());
        }
        if let Object::Symlink { target } = &original.object {
            if &link(parent.as_fd(), &name)? != target {
                return Err("image census link changed".into());
            }
        }
        if path.as_str() == ".memcordon-image.json" {
            let manifest = open_protected_relative(image.root(), &path)?;
            require_named_inode(parent.as_fd(), &name, &manifest)?;
            if identity(&manifest.metadata().map_err(io)?) != original.identity
                || hash(&manifest, deadline)? != raw_hash
            {
                return Err("image census manifest changed after namespace traversal".into());
            }
            no_file_capability(&manifest)?;
        }
    }
    require_named_inode(store_owner.as_fd(), &selected, &image.root)?;
    let named_store = store(false)?;
    let store_after = store_owner.metadata().map_err(io)?;
    let root_after = image.root.metadata().map_err(io)?;
    if identity(&store_before) != identity(&named_store.metadata().map_err(io)?)
        || identity(&store_before) != identity(&store_after)
        || identity(&root_before) != identity(&root_after)
        || (
            store_before.mtime(),
            store_before.mtime_nsec(),
            store_before.ctime(),
            store_before.ctime_nsec(),
        ) != (
            store_after.mtime(),
            store_after.mtime_nsec(),
            store_after.ctime(),
            store_after.ctime_nsec(),
        )
        || (
            root_before.mtime(),
            root_before.mtime_nsec(),
            root_before.ctime(),
            root_before.ctime_nsec(),
        ) != (
            root_after.mtime(),
            root_after.mtime_nsec(),
            root_after.ctime(),
            root_after.ctime_nsec(),
        )
    {
        return Err("image census root/store metadata changed".into());
    }
    let census = Census {
        format: "memcordon.runtime-image-census".into(),
        revision: 1,
        reference: image.reference().clone(),
        target: definition.target.clone(),
        definition_sha256: raw_hash.clone(),
        cutoff_unix_millis,
        store: identity(&store_before),
        root: identity(&root_before),
        members: members.into_values().collect(),
    };
    census.validate_for_definition(&definition, &raw_hash)?;
    within(deadline)?;
    drop(capacity);
    let output = memcordon_core::bounded_json_bytes(&census, 32 * 1024 * 1024, false)
        .map_err(|error| error.to_string())?;
    within(deadline)?;
    std::io::stdout().write_all(&output).map_err(io)?;
    Ok(())
}
