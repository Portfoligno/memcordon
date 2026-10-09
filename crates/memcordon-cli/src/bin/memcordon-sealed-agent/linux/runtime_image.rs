//! Fresh immutable image installation and held object custody for the combined runtime.
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_contract_v3::{BoundObjectRef, RootRelativePath};
use memcordon_core::workload_registry_v3::{
    IMAGE_MANIFEST_BYTES, ImageEntryV1, RuntimeImageDefinitionV1,
};
use sha2::{Digest, Sha256};

const IMAGE_STORE: &str = "/var/lib/memcordon/runtime-images";

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ImageRetirementIntent {
    format: String,
    revision: u32,
    reference: BoundObjectRef,
    device: u64,
    inode: u64,
}

/// Administrative retirement is distinct from execution authority. The policy
/// lease prevents new image admissions while exact held storage is retired.
pub fn retire(definition_path: &Path) -> Result<(), String> {
    if unsafe { libc::getuid() } != 0 || unsafe { libc::geteuid() } != 0 {
        return Err("runtime image retirement requires real/effective root".into());
    }
    let definition =
        RuntimeImageDefinitionV1::parse(&super::protected_read::read_protected_absolute(
            definition_path,
            IMAGE_MANIFEST_BYTES as u64,
            None,
        )?)?;
    if definition.target != native_target()? {
        return Err("retirement image target differs from native provider".into());
    }
    let lease = crate::policy_registry::native::Lease::acquire()?;
    if matches!(
        lease.read_any()?,
        Some(crate::policy_registry::VersionedActivation::V3(_))
    ) || lease.versioned_live_bindings()?.iter().any(|(_, binding)| {
        matches!(
            binding,
            crate::policy_registry::VersionedLiveBinding::Mixed(_)
        )
    }) {
        return Err(
            "restore nonmixed policy and settle all mixed admissions before image retirement"
                .into(),
        );
    }
    let reference = definition.reference()?;
    let store = store(false)?;
    let selected = image_name(&reference);
    let retiring = format!(".retiring-{selected}");
    let intent_name = format!(".retirement-{selected}.json");
    let intent_c = cstr(&intent_name)?;
    let open_directory = |name: &str| -> Result<Option<File>, String> {
        match directory_at(store.as_fd(), name, false) {
            Ok(file) => {
                protected_directory(&file)?;
                Ok(Some(file))
            }
            Err(error) => {
                let name = cstr(name)?;
                let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
                if unsafe {
                    libc::fstatat(
                        store.as_raw_fd(),
                        name.as_ptr(),
                        stat.as_mut_ptr(),
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                } < 0
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT)
                {
                    Ok(None)
                } else {
                    Err(error)
                }
            }
        }
    };
    let intent_fd = unsafe {
        libc::openat(
            store.as_raw_fd(),
            intent_c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    let (intent, intent_owner) = if intent_fd >= 0 {
        let file = native(intent_fd)?;
        let metadata = file.metadata().map_err(io)?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
            || metadata.len() > 4096
        {
            return Err("image retirement intent custody differs".into());
        }
        let mut bytes = Vec::new();
        (&file).take(4097).read_to_end(&mut bytes).map_err(io)?;
        memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)?;
        let intent: ImageRetirementIntent =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        if intent.format != "memcordon.image-retirement-intent"
            || intent.revision != 1
            || intent.reference != reference
            || intent.device == 0
            || intent.inode == 0
        {
            return Err("image retirement intent association differs".into());
        }
        (intent, file)
    } else {
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
            return Err(io(std::io::Error::last_os_error()));
        }
        if open_directory(&retiring)?.is_some() {
            return Err("retiring image lacks owned native intent".into());
        }
        let Some(root) = open_directory(&selected)? else {
            store.sync_all().map_err(io)?;
            println!(
                "{}",
                serde_json::json!({"format":"memcordon.runtime-image-retirement","revision":1,"reference":reference,"storage_absent":true,"already_absent":true})
            );
            return Ok(());
        };
        let verified = open_installed(&definition)?;
        verified.revalidate()?;
        let actual = verified.root.metadata().map_err(io)?;
        let selected_metadata = root.metadata().map_err(io)?;
        if (actual.dev(), actual.ino()) != (selected_metadata.dev(), selected_metadata.ino()) {
            return Err("image root changed before native retirement intent".into());
        }
        let metadata = root.metadata().map_err(io)?;
        let intent = ImageRetirementIntent {
            format: "memcordon.image-retirement-intent".into(),
            revision: 1,
            reference: reference.clone(),
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        let staging_name = cstr(&format!(".retirement-staging-{selected}.json"))?;
        let stale = unsafe {
            libc::openat(
                store.as_raw_fd(),
                staging_name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if stale >= 0 {
            let stale = native(stale)?;
            let metadata = stale.metadata().map_err(io)?;
            if !metadata.is_file()
                || metadata.uid() != 0
                || metadata.nlink() != 1
                || metadata.mode() & 0o077 != 0
                || metadata.len() > 4096
            {
                return Err("uncommitted image retirement staging custody differs".into());
            }
            require_named_inode(store.as_fd(), &staging_name, &stale)?;
            if unsafe { libc::unlinkat(store.as_raw_fd(), staging_name.as_ptr(), 0) } < 0 {
                return Err(io(std::io::Error::last_os_error()));
            }
            if stale.metadata().map_err(io)?.nlink() != 0 {
                return Err("uncommitted retirement staging remains linked".into());
            }
            store.sync_all().map_err(io)?;
        } else if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
            return Err(io(std::io::Error::last_os_error()));
        }
        let mut file = native(unsafe {
            libc::openat(
                store.as_raw_fd(),
                staging_name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        })?;
        file.write_all(&serde_json::to_vec(&intent).map_err(|error| error.to_string())?)
            .map_err(io)?;
        file.sync_all().map_err(io)?;
        require_named_inode(store.as_fd(), &staging_name, &file)?;
        if unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                store.as_raw_fd(),
                staging_name.as_ptr(),
                store.as_raw_fd(),
                intent_c.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } < 0
        {
            return Err(io(std::io::Error::last_os_error()));
        }
        store.sync_all().map_err(io)?;
        (intent, file)
    };
    let original = open_directory(&selected)?;
    let mut root = open_directory(&retiring)?;
    if original.is_some() && root.is_some() {
        return Err("image has simultaneous live and retiring storage".into());
    }
    if let Some(original) = original {
        let metadata = original.metadata().map_err(io)?;
        if (metadata.dev(), metadata.ino()) != (intent.device, intent.inode) {
            return Err("image native retirement owner changed".into());
        }
        let from = cstr(&selected)?;
        let to = cstr(&retiring)?;
        require_named_inode(store.as_fd(), &from, &original)?;
        if unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                store.as_raw_fd(),
                from.as_ptr(),
                store.as_raw_fd(),
                to.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } < 0
        {
            return Err(io(std::io::Error::last_os_error()));
        }
        store.sync_all().map_err(io)?;
        root = Some(original);
    }
    if let Some(root) = root {
        let metadata = root.metadata().map_err(io)?;
        if (metadata.dev(), metadata.ino()) != (intent.device, intent.inode) {
            return Err("retiring image inode differs from durable owner".into());
        }
        let manifest_path = RootRelativePath::new(".memcordon-image.json".into())?;
        let manifest_owner = if !root_member_absent(&root, &manifest_path)? {
            let file = open_protected_relative(root.as_fd(), &manifest_path)?;
            let metadata = file.metadata().map_err(io)?;
            if !metadata.is_file()
                || metadata.uid() != 0
                || metadata.nlink() != 1
                || metadata.mode() & 0o6222 != 0
                || metadata.len() > IMAGE_MANIFEST_BYTES as u64
            {
                return Err("retiring manifest custody differs".into());
            }
            no_file_capability(&file)?;
            let mut bytes = Vec::new();
            (&file)
                .take(IMAGE_MANIFEST_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(io)?;
            if RuntimeImageDefinitionV1::parse(&bytes)? != definition {
                return Err("retiring manifest definition differs".into());
            }
            Some(file)
        } else {
            None
        };
        let mut directories = std::collections::BTreeSet::new();
        for entry in definition.entries.as_slice() {
            let mut ancestor = Path::new(entry.path().as_str()).parent();
            while let Some(path) = ancestor {
                if path.as_os_str().is_empty() {
                    break;
                }
                directories.insert(path.to_path_buf());
                ancestor = path.parent();
            }
            let (parent, name) = match protected_parent_at(root.as_fd(), entry.path()) {
                Ok(value) => value,
                Err(error) => {
                    if !root_member_absent(&root, entry.path())? {
                        return Err(error);
                    }
                    continue;
                }
            };
            let raw = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if raw < 0 {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                    continue;
                }
                return Err(io(std::io::Error::last_os_error()));
            }
            let held = native(raw)?;
            let metadata = held.metadata().map_err(io)?;
            match entry {
                ImageEntryV1::Regular { .. } => {
                    let file = open_protected_relative(root.as_fd(), entry.path())?;
                    verify_regular(&file, entry, true)?;
                    let actual = file.metadata().map_err(io)?;
                    if (actual.dev(), actual.ino()) != (metadata.dev(), metadata.ino()) {
                        return Err("retiring image member identity changed".into());
                    }
                }
                ImageEntryV1::Symlink { path, target } => {
                    if !metadata.file_type().is_symlink() || metadata.uid() != 0 {
                        return Err("retiring image link custody differs".into());
                    }
                    let mut bytes = vec![0_u8; 4097];
                    let count = unsafe {
                        libc::readlinkat(
                            parent.as_raw_fd(),
                            name.as_ptr(),
                            bytes.as_mut_ptr().cast(),
                            bytes.len(),
                        )
                    };
                    if count < 0 {
                        return Err(io(std::io::Error::last_os_error()));
                    }
                    bytes.truncate(count as usize);
                    use std::os::unix::ffi::OsStrExt;
                    if bytes != relative_link(path, target).as_os_str().as_bytes() {
                        return Err("retiring image link definition differs".into());
                    }
                }
            }
            require_named_inode(parent.as_fd(), &name, &held)?;
            if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } < 0 {
                return Err(io(std::io::Error::last_os_error()));
            }
            if held.metadata().map_err(io)?.nlink() != 0 {
                return Err("retired image member still has native links".into());
            }
            parent.sync_all().map_err(io)?;
        }
        let mut directories = directories.into_iter().collect::<Vec<_>>();
        directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
        for path in directories {
            let path = RootRelativePath::new(
                path.to_str()
                    .ok_or("image directory encoding differs")?
                    .into(),
            )?;
            if root_member_absent(&root, &path)? {
                continue;
            }
            let (parent, name) = protected_parent_at(root.as_fd(), &path)?;
            let held = directory_at(
                parent.as_fd(),
                path.as_str()
                    .rsplit('/')
                    .next()
                    .ok_or("image directory leaf absent")?,
                false,
            )?;
            protected_directory(&held)?;
            require_named_inode(parent.as_fd(), &name, &held)?;
            if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } < 0
            {
                return Err(io(std::io::Error::last_os_error()));
            }
            if held.metadata().map_err(io)?.nlink() != 0 {
                return Err("retired image directory remains linked".into());
            }
            parent.sync_all().map_err(io)?;
        }
        let manifest = c".memcordon-image.json";
        if let Some(held) = manifest_owner {
            require_named_inode(root.as_fd(), &cstr(".memcordon-image.json")?, &held)?;
            if unsafe { libc::unlinkat(root.as_raw_fd(), manifest.as_ptr(), 0) } < 0 {
                return Err(io(std::io::Error::last_os_error()));
            }
            if held.metadata().map_err(io)?.nlink() != 0 {
                return Err("retired image manifest remains linked".into());
            }
        } else if !root_member_absent(&root, &manifest_path)? {
            return Err("retiring manifest appeared after authenticated partial absence".into());
        }
        root.sync_all().map_err(io)?;
        let name = cstr(&retiring)?;
        require_named_inode(store.as_fd(), &name, &root)?;
        if unsafe { libc::unlinkat(store.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } < 0 {
            return Err(io(std::io::Error::last_os_error()));
        }
        if root.metadata().map_err(io)?.nlink() != 0 {
            return Err("retired image root remains linked".into());
        }
        store.sync_all().map_err(io)?;
    }
    require_named_inode(store.as_fd(), &intent_c, &intent_owner)?;
    if unsafe { libc::unlinkat(store.as_raw_fd(), intent_c.as_ptr(), 0) } < 0 {
        return Err(io(std::io::Error::last_os_error()));
    }
    if intent_owner.metadata().map_err(io)?.nlink() != 0 {
        return Err("retired image intent remains linked".into());
    }
    store.sync_all().map_err(io)?;
    println!(
        "{}",
        serde_json::json!({"format":"memcordon.runtime-image-retirement","revision":1,"reference":reference,"storage_absent":true,"device":intent.device,"inode":intent.inode})
    );
    Ok(())
}

fn require_named_inode(parent: BorrowedFd<'_>, name: &CString, held: &File) -> Result<(), String> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } < 0
    {
        return Err(io(std::io::Error::last_os_error()));
    }
    let stat = unsafe { stat.assume_init() };
    let metadata = held.metadata().map_err(io)?;
    if (stat.st_dev, stat.st_ino) != (metadata.dev(), metadata.ino()) {
        return Err("native image named custody changed before retirement".into());
    }
    Ok(())
}

fn root_member_absent(root: &File, path: &RootRelativePath) -> Result<bool, String> {
    let mut parent = native(unsafe { libc::fcntl(root.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) })?;
    protected_directory(&parent)?;
    let mut components = path.as_str().split('/').peekable();
    while let Some(component) = components.next() {
        let name = cstr(component)?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } < 0
        {
            return if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                Ok(true)
            } else {
                Err(io(std::io::Error::last_os_error()))
            };
        }
        if components.peek().is_none() {
            return Ok(false);
        }
        parent = directory_at(parent.as_fd(), component, false)?;
        protected_directory(&parent)?;
    }
    Err("empty image member path".into())
}

/// Private fields and no deserializer: serialized observations cannot reopen custody.
pub struct InstalledRuntimeImage {
    definition: RuntimeImageDefinitionV1,
    reference: BoundObjectRef,
    root: File,
    objects: Vec<(RootRelativePath, File)>,
}
impl InstalledRuntimeImage {
    pub fn definition(&self) -> &RuntimeImageDefinitionV1 {
        &self.definition
    }
    pub fn reference(&self) -> &BoundObjectRef {
        &self.reference
    }
    pub fn root(&self) -> BorrowedFd<'_> {
        self.root.as_fd()
    }
    pub fn object(&self, path: &RootRelativePath) -> Result<BorrowedFd<'_>, String> {
        self.objects
            .iter()
            .find(|(selected, _)| selected == path)
            .map(|(_, file)| file.as_fd())
            .ok_or_else(|| "held regular image member absent".into())
    }
    pub fn revalidate(&self) -> Result<(), String> {
        protected_directory(&self.root)?;
        for (path, file) in &self.objects {
            let entry = self
                .definition
                .entries
                .as_slice()
                .iter()
                .find(|entry| entry.path() == path)
                .ok_or("image definition member absent")?;
            verify_regular(file, entry, true)?;
            let reopened = open_protected_relative(self.root.as_fd(), path)?;
            let held = file.metadata().map_err(io)?;
            let current = reopened.metadata().map_err(io)?;
            if (held.dev(), held.ino()) != (current.dev(), current.ino()) {
                return Err("held image inode replaced".into());
            }
        }
        Ok(())
    }
}

fn io(error: std::io::Error) -> String {
    error.to_string()
}
fn cstr(text: &str) -> Result<CString, String> {
    CString::new(text).map_err(|_| "native path contains NUL".into())
}
fn native(raw: i32) -> Result<File, String> {
    if raw < 0 {
        Err(io(std::io::Error::last_os_error()))
    } else {
        Ok(unsafe { File::from_raw_fd(raw) })
    }
}

pub(crate) fn directory_at(
    parent: BorrowedFd<'_>,
    name: &str,
    create: bool,
) -> Result<File, String> {
    let name = cstr(name)?;
    if create && unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(io(error));
        }
    }
    native(unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    })
}

pub(crate) fn parent_at(
    root: BorrowedFd<'_>,
    path: &RootRelativePath,
    create: bool,
) -> Result<(File, CString), String> {
    let mut components = path.as_str().split('/').peekable();
    let mut parent = native(unsafe { libc::fcntl(root.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) })?;
    while let Some(component) = components.next() {
        if components.peek().is_none() {
            return Ok((parent, cstr(component)?));
        }
        parent = directory_at(parent.as_fd(), component, create)?;
    }
    Err("empty image path".into())
}

pub(crate) fn open_relative(
    root: BorrowedFd<'_>,
    path: &RootRelativePath,
    create: bool,
) -> Result<File, String> {
    let (parent, name) = parent_at(root, path, create)?;
    let flags = if create {
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL
    } else {
        libc::O_RDONLY
    };
    native(unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0o600,
        )
    })
}

fn open_protected_relative(root: BorrowedFd<'_>, path: &RootRelativePath) -> Result<File, String> {
    let mut parent = native(unsafe { libc::fcntl(root.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) })?;
    protected_directory(&parent)?;
    let mut components = path.as_str().split('/').peekable();
    while let Some(component) = components.next() {
        if components.peek().is_none() {
            let name = cstr(component)?;
            return native(unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                )
            });
        }
        parent = directory_at(parent.as_fd(), component, false)?;
        protected_directory(&parent)?;
    }
    Err("empty protected image path".into())
}

fn protected_parent_at(
    root: BorrowedFd<'_>,
    path: &RootRelativePath,
) -> Result<(File, CString), String> {
    let mut parent = native(unsafe { libc::fcntl(root.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) })?;
    protected_directory(&parent)?;
    let mut components = path.as_str().split('/').peekable();
    while let Some(component) = components.next() {
        if components.peek().is_none() {
            return Ok((parent, cstr(component)?));
        }
        parent = directory_at(parent.as_fd(), component, false)?;
        protected_directory(&parent)?;
    }
    Err("empty protected image path".into())
}

fn sync_image_directories(
    root: &File,
    definition: &RuntimeImageDefinitionV1,
) -> Result<(), String> {
    let mut paths = std::collections::BTreeSet::new();
    for entry in definition.entries.as_slice() {
        let mut parent = Path::new(entry.path().as_str()).parent();
        while let Some(path) = parent {
            if path.as_os_str().is_empty() {
                break;
            }
            paths.insert(path.to_path_buf());
            parent = path.parent();
        }
    }
    let mut paths: Vec<_> = paths.into_iter().collect();
    paths.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for path in paths {
        let mut directory = root.try_clone().map_err(io)?;
        for component in path.components() {
            let name = component
                .as_os_str()
                .to_str()
                .ok_or("image directory is not UTF-8")?;
            directory = directory_at(directory.as_fd(), name, false)?;
            protected_directory(&directory)?;
        }
        directory.sync_all().map_err(io)?;
    }
    root.sync_all().map_err(io)
}

fn open_source_relative(root: BorrowedFd<'_>, path: &RootRelativePath) -> Result<File, String> {
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    // Linux openat2 ABI: BENEATH, NO_MAGICLINKS, NO_SYMLINKS, NO_XDEV.
    let how = OpenHow {
        flags: u64::try_from(libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .map_err(|_| "invalid source open flags")?,
        mode: 0,
        resolve: 0x08 | 0x02 | 0x04 | 0x01,
    };
    let path = cstr(path.as_str())?;
    native(unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            path.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    } as i32)
}

fn native_target() -> Result<&'static str, String> {
    match std::env::consts::ARCH {
        "x86_64" => Ok("x86_64-unknown-linux-gnu"),
        "aarch64" => Ok("aarch64-unknown-linux-gnu"),
        _ => Err("unsupported native image target".into()),
    }
}

pub(crate) fn protected_directory(directory: &File) -> Result<(), String> {
    let metadata = directory.metadata().map_err(io)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err("image directory is not root-owned protected custody".into());
    }
    Ok(())
}

fn store(create: bool) -> Result<File, String> {
    let mut root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open("/")
        .map_err(io)?;
    for component in Path::new(IMAGE_STORE)
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(value) => value.to_str(),
            _ => None,
        })
    {
        root = directory_at(root.as_fd(), component, create)?;
        protected_directory(&root)?;
    }
    Ok(root)
}

fn image_name(reference: &BoundObjectRef) -> String {
    // A standalone filesystem component, never a command argument string.
    reference
        .digest
        .bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn no_file_capability(file: &File) -> Result<(), String> {
    let name = c"security.capability";
    let size = unsafe { libc::fgetxattr(file.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if size >= 0 {
        return Err("image file has capability metadata".into());
    }
    let error = std::io::Error::last_os_error();
    if matches!(error.raw_os_error(), Some(libc::ENODATA | libc::ENOTSUP)) {
        Ok(())
    } else {
        Err(io(error))
    }
}

pub(crate) fn verify_regular(
    file: &File,
    entry: &ImageEntryV1,
    protected: bool,
) -> Result<(), String> {
    let ImageEntryV1::Regular {
        sha256,
        size,
        executable,
        ..
    } = entry
    else {
        return Err("regular object expected".into());
    };
    let metadata = file.metadata().map_err(io)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.len() != *size
        || metadata.mode() & 0o6000 != 0
        || (*executable && metadata.mode() & 0o111 == 0)
        || (protected && (metadata.uid() != 0 || metadata.mode() & 0o222 != 0))
    {
        return Err("image member type/size/mode/alias differs".into());
    }
    no_file_capability(file)?;
    let mut hash = Sha256::new();
    let mut offset = 0_u64;
    let mut bytes = [0_u8; 64 * 1024];
    use std::os::unix::fs::FileExt;
    loop {
        let count = file.read_at(&mut bytes, offset).map_err(io)?;
        if count == 0 {
            break;
        }
        offset = offset
            .checked_add(u64::try_from(count).map_err(|_| "image byte count exceeds u64")?)
            .ok_or("image byte count overflow")?;
        if offset > *size {
            return Err("image grew during verification".into());
        }
        hash.update(&bytes[..count]);
    }
    if offset != *size || DiagnosticSha256::from_bytes(hash.finalize().into()) != *sha256 {
        return Err("image content digest differs".into());
    }
    Ok(())
}

fn relative_link(path: &RootRelativePath, target: &RootRelativePath) -> PathBuf {
    let parent = Path::new(path.as_str())
        .parent()
        .expect("relative path has parent");
    let mut result = PathBuf::new();
    for _ in parent.components() {
        result.push("..");
    }
    result.push(target.as_str());
    result
}

pub fn install(definition_path: &Path, source_path: &Path) -> Result<(), String> {
    if unsafe { libc::getuid() } != 0 || unsafe { libc::geteuid() } != 0 {
        return Err("runtime image installation requires real/effective root".into());
    }
    let bytes = super::protected_read::read_protected_absolute(
        definition_path,
        u64::try_from(IMAGE_MANIFEST_BYTES).map_err(|_| "image bound exceeds native range")?,
        None,
    )?;
    let definition = RuntimeImageDefinitionV1::parse(&bytes)?;
    if definition.target != native_target()? {
        return Err("image target differs from executing native provider".into());
    }
    if !source_path.is_absolute() {
        return Err("absolute image source root required".into());
    }
    let source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(source_path)
        .map_err(io)?;
    let source_device = source.metadata().map_err(io)?.dev();
    let store = store(true)?;
    let reference = definition.reference()?;
    // tempfile creates a fresh exclusive root-owned staging tree. Failed imports
    // remove only this owned unpublished tree; existing image bytes are untouched.
    let store_path = Path::new(IMAGE_STORE);
    let temporary = tempfile::Builder::new()
        .prefix("image-import-")
        .tempdir_in(store_path)
        .map_err(io)?;
    let staging = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(temporary.path())
        .map_err(io)?;
    protected_directory(&staging)?;
    for entry in definition.entries.as_slice() {
        if let ImageEntryV1::Regular {
            size, executable, ..
        } = entry
        {
            let mut input = open_source_relative(source.as_fd(), entry.path())?;
            if input.metadata().map_err(io)?.dev() != source_device {
                return Err("image import crosses source mount".into());
            }
            verify_regular(&input, entry, false)?;
            let mut output = open_relative(staging.as_fd(), entry.path(), true)?;
            let copied = std::io::copy(
                &mut std::io::Read::by_ref(&mut input)
                    .take(size.checked_add(1).ok_or("image size overflow")?),
                &mut output,
            )
            .map_err(io)?;
            if copied != *size {
                return Err("image changed during copy".into());
            }
            output.sync_all().map_err(io)?;
            output
                .set_permissions(std::fs::Permissions::from_mode(if *executable {
                    0o555
                } else {
                    0o444
                }))
                .map_err(io)?;
            output.sync_all().map_err(io)?;
            verify_regular(&output, entry, true)?;
        }
    }
    for entry in definition.entries.as_slice() {
        if let ImageEntryV1::Symlink { path, target } = entry {
            let (parent, name) = parent_at(staging.as_fd(), path, true)?;
            let relative = relative_link(path, target);
            use std::os::unix::ffi::OsStrExt;
            let target = CString::new(relative.as_os_str().as_bytes())
                .map_err(|_| "link target contains NUL")?;
            if unsafe { libc::symlinkat(target.as_ptr(), parent.as_raw_fd(), name.as_ptr()) } < 0 {
                return Err(io(std::io::Error::last_os_error()));
            }
        }
    }
    let manifest_path = RootRelativePath::new(".memcordon-image.json".into())?;
    if definition
        .entries
        .as_slice()
        .iter()
        .any(|entry| entry.path() == &manifest_path)
    {
        return Err("reserved image manifest path".into());
    }
    let mut manifest = open_relative(staging.as_fd(), &manifest_path, true)?;
    manifest.write_all(&bytes).map_err(io)?;
    manifest.sync_all().map_err(io)?;
    manifest
        .set_permissions(std::fs::Permissions::from_mode(0o444))
        .map_err(io)?;
    manifest.sync_all().map_err(io)?;
    sync_image_directories(&staging, &definition)?;
    let name = cstr(&image_name(&reference))?;
    let temporary_name = cstr(
        temporary
            .path()
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("staging image basename unavailable")?,
    )?;
    if unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            store.as_raw_fd(),
            temporary_name.as_ptr(),
            store.as_raw_fd(),
            name.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } < 0
    {
        return Err(io(std::io::Error::last_os_error()));
    }
    let _persisted = temporary.keep();
    store.sync_all().map_err(io)?;
    let held = open_installed(&definition)?;
    println!(
        "{}",
        serde_json::json!({"format":"memcordon.runtime-image-installation","revision":1,"image":held.reference(),"target":definition.target,"policy_activated":false,"member_count":definition.entries.as_slice().len()})
    );
    Ok(())
}

pub fn open_installed(
    definition: &RuntimeImageDefinitionV1,
) -> Result<InstalledRuntimeImage, String> {
    definition.validate()?;
    if definition.target != native_target()? {
        return Err("image target differs from executing native provider".into());
    }
    let reference = definition.reference()?;
    let store = store(false)?;
    let root = directory_at(store.as_fd(), &image_name(&reference), false)?;
    protected_directory(&root)?;
    let manifest = open_protected_relative(
        root.as_fd(),
        &RootRelativePath::new(".memcordon-image.json".into())?,
    )?;
    let metadata = manifest.metadata().map_err(io)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o6222 != 0
        || metadata.len() > IMAGE_MANIFEST_BYTES as u64
    {
        return Err("installed image manifest is not bounded protected regular custody".into());
    }
    no_file_capability(&manifest)?;
    let mut bytes = Vec::new();
    manifest
        .take((IMAGE_MANIFEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if RuntimeImageDefinitionV1::parse(&bytes)? != *definition {
        return Err("installed image manifest differs".into());
    }
    let mut objects = Vec::new();
    for entry in definition.entries.as_slice() {
        if matches!(entry, ImageEntryV1::Regular { .. }) {
            let file = open_protected_relative(root.as_fd(), entry.path())?;
            verify_regular(&file, entry, true)?;
            objects.push((entry.path().clone(), file));
        } else if let ImageEntryV1::Symlink { path, target } = entry {
            let (parent, name) = protected_parent_at(root.as_fd(), path)?;
            let mut value = vec![0_u8; 4097];
            let length = unsafe {
                libc::readlinkat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    value.as_mut_ptr().cast(),
                    value.len(),
                )
            };
            if length < 0 {
                return Err(io(std::io::Error::last_os_error()));
            }
            value.truncate(usize::try_from(length).map_err(|_| "invalid image link length")?);
            use std::os::unix::ffi::OsStrExt;
            if value != relative_link(path, target).as_os_str().as_bytes() {
                return Err("installed image link changed".into());
            }
        }
    }
    let held = InstalledRuntimeImage {
        definition: definition.clone(),
        reference,
        root,
        objects,
    };
    held.revalidate()?;
    Ok(held)
}
