//! Fresh copied root construction. Only the single-threaded namespace init calls enter.
use super::runtime_image::{InstalledRuntimeImage, directory_at, open_relative, parent_at};
use memcordon_core::workload_contract_v3::RootRelativePath;
use memcordon_core::workload_registry_v3::{ImageEntryV1, RootLayoutDefinitionV1};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[path = "image_copy.rs"]
mod image_copy;

fn io(error: std::io::Error) -> String {
    error.to_string()
}
fn text(path: &Path) -> Result<CString, String> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(path.as_os_str().as_bytes()).map_err(|_| "root path contains NUL".into())
}
fn mount(
    source: Option<&str>,
    target: &Path,
    kind: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> Result<(), String> {
    let source = source
        .map(CString::new)
        .transpose()
        .map_err(|_| "mount source contains NUL")?;
    let target = text(target)?;
    let kind = kind
        .map(CString::new)
        .transpose()
        .map_err(|_| "mount type contains NUL")?;
    let data = data
        .map(CString::new)
        .transpose()
        .map_err(|_| "mount data contains NUL")?;
    let pointer = |value: &Option<CString>| {
        value
            .as_ref()
            .map_or(std::ptr::null(), |value| value.as_ptr())
    };
    if unsafe {
        libc::mount(
            pointer(&source),
            target.as_ptr(),
            pointer(&kind),
            flags,
            pointer(&data).cast(),
        )
    } < 0
    {
        return Err(io(std::io::Error::last_os_error()));
    }
    Ok(())
}
fn directory(path: &Path) -> Result<(), String> {
    std::fs::create_dir_all(path).map_err(io)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).map_err(io)
}

/// Provider-created exclusive staging custody, never supplied by the frontend.
pub struct NativeRootStaging {
    provider_owner: bool,
    path: PathBuf,
    held: File,
}
impl NativeRootStaging {
    pub(super) fn native_identity(
        &self,
    ) -> Result<super::private_attempt::MixedDirectoryIdentityV2, String> {
        use std::os::unix::fs::MetadataExt;
        let metadata = self.held.metadata().map_err(io)?;
        Ok(super::private_attempt::MixedDirectoryIdentityV2 {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    pub(super) fn intended_path(attempt: &str) -> Result<PathBuf, String> {
        if attempt.len() != 32
            || !attempt
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("staging attempt identity differs".into());
        }
        Ok(Path::new("/run/memcordon").join(format!("private-root-{attempt}")))
    }
    pub(super) fn create(attempt: &str) -> Result<Self, String> {
        let path = Self::intended_path(attempt)?;
        let mut parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/")
            .map_err(io)?;
        for component in ["run", "memcordon"] {
            parent = directory_at(parent.as_fd(), component, true)?;
            super::runtime_image::protected_directory(&parent)?;
        }
        let name = CString::new(format!("private-root-{attempt}"))
            .map_err(|_| "staging name contains NUL")?;
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } < 0 {
            return Err(io(std::io::Error::last_os_error()));
        }
        let held = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(io)?;
        super::runtime_image::protected_directory(&held)?;
        parent.sync_all().map_err(io)?;
        Ok(Self {
            provider_owner: true,
            path,
            held,
        })
    }
    /// The provider retains the only pathname cleanup owner across clone. The
    /// namespace child receives a held copy, never a second TempDir owner.
    pub(super) fn for_namespace_child(&self) -> Result<Self, String> {
        super::runtime_image::protected_directory(&self.held)?;
        if !self.provider_owner {
            return Err("namespace staging cleanup owner is absent".into());
        }
        Ok(Self {
            provider_owner: false,
            path: self.path.clone(),
            held: self.held.try_clone().map_err(io)?,
        })
    }
    pub(super) fn retire_path(&mut self) -> Result<(), String> {
        if !self.provider_owner {
            return Err("only outer provider may retire staging pathname".into());
        }
        use std::os::unix::fs::MetadataExt;
        super::runtime_image::protected_directory(&self.held)?;
        let held = self.held.metadata().map_err(io)?;
        match std::fs::symlink_metadata(&self.path) {
            Ok(current) => {
                if !current.is_dir() || (held.dev(), held.ino()) != (current.dev(), current.ino()) {
                    return Err("staging path native identity differs during retirement".into());
                }
                std::fs::remove_dir(&self.path).map_err(io)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && held.nlink() == 0 => {}
            Err(error) => return Err(io(error)),
        }
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/run/memcordon")
            .map_err(io)?;
        super::runtime_image::protected_directory(&parent)?;
        parent.sync_all().map_err(io)?;
        Ok(())
    }
}

/// No deserializer or public constructor: this is the actual mounted root inode.
pub struct MountedPrivateRoot {
    root: File,
    layout: RootLayoutDefinitionV1,
    attempt_id: String,
    identity: memcordon_core::workload_contract_v3::ExclusiveAdministratorIdentityRef,
    init_nondumpable: bool,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeRootTransferV2 {
    format: String,
    revision: u32,
    layout: memcordon_core::workload_contract_v3::BoundObjectRef,
    entrypoint: RootRelativePath,
    root_device: u64,
    root_inode: u64,
    identity: memcordon_core::workload_contract_v3::ExclusiveAdministratorIdentityRef,
    init_nondumpable: bool,
}
/// A dedicated startup channel; it is never an extension of the old runtime
/// carrier or a caller-selectable descriptor payload.
pub(super) fn native_root_channel() -> Result<
    (
        std::os::unix::net::UnixStream,
        std::os::unix::net::UnixStream,
    ),
    String,
> {
    let (provider, init) = std::os::unix::net::UnixStream::pair().map_err(io)?;
    let enabled = 1_i32;
    if unsafe {
        libc::setsockopt(
            provider.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            (&enabled as *const i32).cast(),
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    } < 0
    {
        return Err(io(std::io::Error::last_os_error()));
    }
    Ok((provider, init))
}
/// Minted only by the owned export-and-close operation after aggregate retirement.
/// No serialized observation or ordinary cgroup retirement can construct this proof.
pub struct PrivateRootRetirement {
    attempt: String,
    layout: memcordon_core::workload_contract_v3::BoundObjectRef,
    identity: memcordon_core::workload_contract_v3::ExclusiveAdministratorIdentityRef,
}
pub(super) struct RootExportFailure {
    pub detail: String,
    pub root: MountedPrivateRoot,
    pub staging: NativeRootStaging,
    pub exported: Option<PathBuf>,
    pub destination: NativeExportDirectory,
}
/// Native phase ownership exists before mkdir/copy. There is no implicit
/// recursive cleanup and no deserializer that can adopt an existing output.
pub(super) struct NativeExportDirectory {
    path: PathBuf,
    held: Option<File>,
    created: bool,
    published: bool,
    #[cfg(test)]
    component_empty_publication: bool,
}
impl NativeExportDirectory {
    #[cfg(test)]
    pub(super) fn component_retire_empty(
        &mut self,
        attempt: &str,
        original_receipt: &[u8],
        deadline: std::time::Instant,
    ) -> Result<serde_json::Value, String> {
        use std::os::unix::fs::MetadataExt;
        self.verify()?;
        if !self.published
            || !self.component_empty_publication
            || Self::intended(attempt)?.path != self.path
        {
            return Err("component export publication/attempt differs".into());
        }
        let receipt: serde_json::Value =
            serde_json::from_slice(original_receipt).map_err(|e| e.to_string())?;
        if receipt["format"] != "memcordon.private-export"
            || receipt["revision"] != 1
            || receipt["attempt_id"] != attempt
            || receipt["files"]
                .as_array()
                .is_none_or(|files| !files.is_empty())
        {
            return Err("component export is not the original empty publication".into());
        }
        let held = self.held.as_ref().ok_or("component export owner absent")?;
        let before = held.metadata().map_err(io)?;
        let entries = rustix::fs::Dir::read_from(held).map_err(|e| e.to_string())?;
        let mut names = Vec::new();
        for entry in entries {
            if std::time::Instant::now() >= deadline {
                return Err("component export enumeration cutoff exhausted".into());
            }
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            if names.len() == 1 || name != b"export-receipt.json" {
                return Err("component empty export contains an unexpected member".into());
            }
            names.push(name.to_vec());
        }
        if names.len() != 1 {
            return Err("component export receipt absent".into());
        }
        let flags =
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC;
        let file = File::from(
            rustix::fs::openat(
                held,
                "export-receipt.json",
                flags,
                rustix::fs::Mode::empty(),
            )
            .map_err(|e| e.to_string())?,
        );
        let metadata = file.metadata().map_err(io)?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o400
            || metadata.len() > memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES as u64
        {
            return Err("component export receipt custody differs".into());
        }
        let mut bytes = Vec::new();
        (&file)
            .take(metadata.len() + 1)
            .read_to_end(&mut bytes)
            .map_err(io)?;
        if bytes != original_receipt {
            return Err("component export receipt bytes changed".into());
        }
        let after = file.metadata().map_err(io)?;
        if (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mode(),
            metadata.uid(),
            metadata.nlink(),
            metadata.ctime(),
            metadata.ctime_nsec(),
            metadata.mtime(),
            metadata.mtime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.len(),
            after.mode(),
            after.uid(),
            after.nlink(),
            after.ctime(),
            after.ctime_nsec(),
            after.mtime(),
            after.mtime_nsec(),
        ) {
            return Err("component export receipt changed through readback".into());
        }
        let named = rustix::fs::statat(
            held,
            "export-receipt.json",
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|e| e.to_string())?;
        if (named.st_dev, named.st_ino, named.st_nlink) != (metadata.dev(), metadata.ino(), 1) {
            return Err("component export receipt identity changed".into());
        }
        self.verify()?;
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/run/memcordon")
            .map_err(io)?;
        super::runtime_image::protected_directory(&parent)?;
        let name = self
            .path
            .file_name()
            .ok_or("component export basename absent")?;
        let named = rustix::fs::statat(&parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|e| e.to_string())?;
        if (named.st_dev, named.st_ino) != (before.dev(), before.ino())
            || std::time::Instant::now() >= deadline
        {
            return Err("component export owner/cutoff changed".into());
        }
        rustix::fs::unlinkat(held, "export-receipt.json", rustix::fs::AtFlags::empty())
            .map_err(|e| e.to_string())?;
        held.sync_all().map_err(io)?;
        rustix::fs::unlinkat(&parent, name, rustix::fs::AtFlags::REMOVEDIR)
            .map_err(|e| e.to_string())?;
        parent.sync_all().map_err(io)?;
        match rustix::fs::statat(&parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
            Err(error) if error == rustix::io::Errno::NOENT => {}
            Err(error) => return Err(error.to_string()),
            Ok(_) => return Err("component export pathname remains present".into()),
        }
        if held.metadata().map_err(io)?.nlink() != 0
            || file.metadata().map_err(io)?.nlink() != 0
            || std::time::Instant::now() >= deadline
        {
            return Err("component export retirement/cutoff differs".into());
        }
        Ok(
            serde_json::json!({"attempt_id":attempt,"path":self.path,"device":before.dev(),"inode":before.ino(),"receipt_sha256":memcordon_core::workload_codec::hash_bytes(original_receipt),"named_absent":true}),
        )
    }
    pub(super) fn intended(attempt: &str) -> Result<Self, String> {
        if !super::cgroup::valid_attempt_identity(attempt) {
            return Err("invalid export attempt identity".into());
        }
        Ok(Self {
            path: Path::new("/run/memcordon").join(format!("private-export-{attempt}")),
            held: None,
            created: false,
            published: false,
            #[cfg(test)]
            component_empty_publication: false,
        })
    }
    pub(super) fn path(&self) -> &Path {
        &self.path
    }
    pub(super) fn native_identity(
        &self,
    ) -> Result<super::private_attempt::MixedDirectoryIdentityV2, String> {
        self.verify()?;
        use std::os::unix::fs::MetadataExt;
        let metadata = self
            .held
            .as_ref()
            .expect("verified export handle")
            .metadata()
            .map_err(io)?;
        Ok(super::private_attempt::MixedDirectoryIdentityV2 {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    pub(super) fn allocate(&mut self) -> Result<(), String> {
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/run/memcordon")
            .map_err(io)?;
        super::runtime_image::protected_directory(&parent)?;
        let name = text(Path::new(
            self.path.file_name().ok_or("export basename absent")?,
        ))?;
        if !self.created {
            if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } < 0 {
                return Err(io(std::io::Error::last_os_error()));
            }
            self.created = true;
        }
        if self.held.is_none() {
            let raw = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if raw < 0 {
                return Err(io(std::io::Error::last_os_error()));
            }
            use std::os::fd::FromRawFd;
            self.held = Some(unsafe { File::from_raw_fd(raw) });
        }
        self.verify()?;
        parent.sync_all().map_err(io)
    }
    fn verify(&self) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt;
        let held = self
            .held
            .as_ref()
            .ok_or("export directory native handle absent")?;
        super::runtime_image::protected_directory(held)?;
        let expected = held.metadata().map_err(io)?;
        let current = std::fs::symlink_metadata(&self.path).map_err(io)?;
        if !self.created
            || !current.is_dir()
            || current.uid() != 0
            || current.mode() & 0o7777 != 0o700
            || (current.dev(), current.ino()) != (expected.dev(), expected.ino())
        {
            return Err("export directory native custody differs".into());
        }
        Ok(())
    }
}
impl PrivateRootRetirement {
    pub(super) fn unmaterialized_after_native_retirement(
        retired: &super::private_lifecycle::PrivateRetirementObservation,
        layout: memcordon_core::workload_contract_v3::BoundObjectRef,
        identity: memcordon_core::workload_contract_v3::ExclusiveAdministratorIdentityRef,
    ) -> Self {
        Self {
            attempt: retired.attempt_id().to_owned(),
            layout,
            identity,
        }
    }
    pub(super) fn require_binding(
        &self,
        attempt: &str,
        layout: &memcordon_core::workload_contract_v3::BoundObjectRef,
        identity: &memcordon_core::workload_contract_v3::ExclusiveAdministratorIdentityRef,
    ) -> Result<(), String> {
        if self.attempt != attempt || &self.layout != layout || &self.identity != identity {
            return Err("private root/export retirement binding differs".into());
        }
        Ok(())
    }
}
impl MountedPrivateRoot {
    pub(super) fn publish_to_provider(
        &self,
        channel: &std::os::unix::net::UnixStream,
        entry: &ImageEntryV1,
        executable: &super::entrypoint::VerifiedEntrypoint,
        nonce: [u8; 16],
        attempt: [u8; 16],
    ) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt;
        let root = self.root.metadata().map_err(io)?;
        let attempt_text = attempt
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if attempt_text != self.attempt_id {
            return Err("root publication originating attempt differs".into());
        }
        let init_nondumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } == 0;
        if !init_nondumpable || unsafe { libc::getuid() } != 0 {
            return Err("native namespace init privilege/dumpability differs".into());
        }
        let payload = NativeRootTransferV2 {
            format: "memcordon.native-root-transfer".into(),
            revision: 2,
            layout: self.layout.reference()?,
            entrypoint: entry.path().clone(),
            root_device: root.dev(),
            root_inode: root.ino(),
            identity: self.identity.clone(),
            init_nondumpable,
        };
        let frame = crate::protocol::Frame {
            kind: crate::protocol::MessageKind::LaunchPrepared,
            nonce,
            attempt_id: attempt,
            payload: serde_json::to_vec(&payload).map_err(|error| error.to_string())?,
        };
        let mut encoded = Vec::new();
        crate::protocol::write_frame(&mut encoded, &frame).map_err(|error| error.to_string())?;
        super::transport::send(
            channel,
            &encoded,
            &[self.root.as_raw_fd(), executable.as_fd().as_raw_fd()],
        )
    }
    /// Native socket credentials, exact held init pidfd/birth and exact
    /// transaction bindings authenticate these copied objects. JSON alone
    /// cannot manufacture this root handle.
    #[expect(
        clippy::too_many_arguments,
        reason = "Root transfer independently authenticates channel, held init identity, transaction, layout, administrator, and entrypoint"
    )]
    pub(super) fn receive_from_init(
        channel: &std::os::unix::net::UnixStream,
        init: &super::private_attempt::ProcessIdentityV4,
        init_pidfd: BorrowedFd<'_>,
        nonce: [u8; 16],
        attempt: [u8; 16],
        layout: RootLayoutDefinitionV1,
        identity: memcordon_core::workload_contract_v3::ExclusiveAdministratorIdentityRef,
        entry: &ImageEntryV1,
    ) -> Result<(Self, super::entrypoint::VerifiedEntrypoint), String> {
        use std::os::unix::fs::MetadataExt;
        let observe = || {
            super::private_attempt::ProcessIdentityV4::observe(
                i32::try_from(init.pid).map_err(|_| "init PID exceeds native bound")?,
                init_pidfd,
            )
        };
        if observe()? != *init {
            return Err("native root init birth differs before transfer".into());
        }
        let (frame, descriptors, credentials) =
            super::transport::receive_with_credentials(channel)?;
        let credentials = credentials.ok_or("native root transfer credentials absent")?;
        if frame.kind != crate::protocol::MessageKind::LaunchPrepared
            || frame.nonce != nonce
            || frame.attempt_id != attempt
            || descriptors.len() != 2
            || credentials.uid != 0
            || u32::try_from(credentials.pid).ok() != Some(init.pid)
            || observe()? != *init
        {
            return Err("native root transfer transaction/source differs".into());
        }
        if frame.payload.len() > 4096 {
            return Err("native root transfer exceeds bound".into());
        }
        memcordon_core::workload_contract::reject_duplicate_json_keys(&frame.payload)?;
        let transfer: NativeRootTransferV2 =
            serde_json::from_slice(&frame.payload).map_err(|error| error.to_string())?;
        layout.validate()?;
        if transfer.format != "memcordon.native-root-transfer"
            || transfer.revision != 2
            || transfer.layout != layout.reference()?
            || transfer.entrypoint != *entry.path()
            || transfer.identity != identity
        {
            return Err("native root transfer layout/image/identity differs".into());
        }
        let mut descriptors = descriptors.into_iter();
        let root = File::from(descriptors.next().expect("checked root descriptor count"));
        let executable = File::from(
            descriptors
                .next()
                .expect("checked executable descriptor count"),
        );
        let metadata = root.metadata().map_err(io)?;
        if !metadata.is_dir()
            || metadata.uid() != 0
            || (metadata.dev(), metadata.ino()) != (transfer.root_device, transfer.root_inode)
        {
            return Err("native root inode readback differs".into());
        }
        let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
        if unsafe { libc::fstatfs(root.as_raw_fd(), filesystem.as_mut_ptr()) } < 0 {
            return Err(io(std::io::Error::last_os_error()));
        }
        let filesystem = unsafe { filesystem.assume_init() };
        if filesystem.f_type != libc::TMPFS_MAGIC {
            return Err("private root is not a fresh tmpfs object".into());
        }
        let mut flags = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        if unsafe { libc::fstatvfs(root.as_raw_fd(), flags.as_mut_ptr()) } < 0 {
            return Err(io(std::io::Error::last_os_error()));
        }
        if unsafe { flags.assume_init() }.f_flag & libc::ST_RDONLY == 0 {
            return Err("private root is not readonly".into());
        }
        let attempt_id = attempt.iter().map(|byte| format!("{byte:02x}")).collect();
        if !transfer.init_nondumpable {
            return Err("native namespace init was dumpable at root publication".into());
        }
        let root = Self {
            root,
            layout,
            attempt_id,
            identity,
            init_nondumpable: transfer.init_nondumpable,
        };
        let independently_opened = root.open_entrypoint(entry)?;
        let expected = File::from(
            independently_opened
                .as_fd()
                .try_clone_to_owned()
                .map_err(io)?,
        )
        .metadata()
        .map_err(io)?;
        let actual = executable.metadata().map_err(io)?;
        if (expected.dev(), expected.ino()) != (actual.dev(), actual.ino()) {
            return Err("native executable does not belong to transferred root".into());
        }
        let executable =
            super::entrypoint::VerifiedEntrypoint::from_private_root_image(executable, entry)?;
        Ok((root, executable))
    }
    pub(super) fn open_entrypoint(
        &self,
        entry: &ImageEntryV1,
    ) -> Result<super::entrypoint::VerifiedEntrypoint, String> {
        let file = open_relative(self.root.as_fd(), entry.path(), false)?;
        super::entrypoint::VerifiedEntrypoint::from_private_root_image(file, entry)
    }
    /// Copies only administrator-selected regular outputs after the native owner
    /// has retired the entire workload. The namespace root stays held until the
    /// last output is durably published; it is never returned to the frontend.
    #[expect(
        clippy::result_large_err,
        reason = "Publication failure retains the original mounted root, staging, export state, and destination for mandatory cleanup"
    )]
    pub(super) fn export_and_close(
        self,
        retirement: &super::private_lifecycle::PrivateRetirementObservation,
        identity: &memcordon_core::workload_registry_v3::ExclusiveIdentityDefinitionV3,
        mut staging: NativeRootStaging,
        mut destination: NativeExportDirectory,
    ) -> Result<(PrivateRootRetirement, NativeExportDirectory), RootExportFailure> {
        let mut exported = None;
        let publish = (|| -> Result<_, String> {
            let layout = self.layout.reference()?;
            let identity_reference = identity.reference()?;
            if self.attempt_id != retirement.attempt_id() || self.identity != identity_reference {
                return Err("root export originating attempt/identity differs".into());
            }
            let path = self.export_selected(retirement, identity, &staging, &mut destination)?;
            exported = Some(path.clone());
            staging.retire_path()?;
            Ok((layout, identity_reference, path))
        })();
        let (layout, identity, path) = match publish {
            Ok(published) => published,
            Err(detail) => {
                return Err(RootExportFailure {
                    detail,
                    root: self,
                    staging,
                    exported,
                    destination,
                });
            }
        };
        drop(self);
        drop(staging);
        let _published_path = path;
        Ok((
            PrivateRootRetirement {
                attempt: retirement.attempt_id().to_owned(),
                layout,
                identity,
            },
            destination,
        ))
    }
    fn export_selected(
        &self,
        retirement: &super::private_lifecycle::PrivateRetirementObservation,
        identity: &memcordon_core::workload_registry_v3::ExclusiveIdentityDefinitionV3,
        staging: &NativeRootStaging,
        destination: &mut NativeExportDirectory,
    ) -> Result<PathBuf, String> {
        use sha2::{Digest, Sha256};
        use std::io::Write;
        use std::os::unix::fs::MetadataExt;
        if !identity.enabled {
            return Err("export identity is disabled".into());
        }
        let identity_reference = identity.reference()?;
        let layout_reference = self.layout.reference()?;
        super::runtime_image::protected_directory(&staging.held)?;
        destination.verify()?;
        let output_root = destination
            .held
            .as_ref()
            .expect("verified native export directory")
            .try_clone()
            .map_err(io)?;
        super::runtime_image::protected_directory(&output_root)?;
        let mut budgets = std::collections::BTreeMap::<String, u64>::new();
        let mut receipts = Vec::new();
        let mut export_directories = std::collections::BTreeSet::new();
        if !destination.published {
            // A failed copy keeps its native directory owner. Retire only the
            // finite declared output paths before retrying from the held root.
            let mut allowed = std::collections::BTreeSet::new();
            for selected in self.layout.output_files.as_slice() {
                allowed.insert(PathBuf::from(selected.as_str()));
                let mut parent = Path::new(selected.as_str()).parent();
                while let Some(path) = parent {
                    if path.as_os_str().is_empty() {
                        break;
                    }
                    allowed.insert(path.to_path_buf());
                    parent = path.parent();
                }
            }
            allowed.insert(PathBuf::from("export-receipt.json"));
            fn clear(
                directory: &Path,
                relative: &Path,
                allowed: &std::collections::BTreeSet<PathBuf>,
                remaining: &mut usize,
            ) -> Result<(), String> {
                use std::os::unix::fs::MetadataExt;
                for entry in std::fs::read_dir(directory).map_err(io)? {
                    *remaining = remaining
                        .checked_sub(1)
                        .ok_or("partial export entry bound exceeded")?;
                    let entry = entry.map_err(io)?;
                    let member = relative.join(entry.file_name());
                    if !allowed.contains(&member) {
                        return Err("partial export contains an undeclared member".into());
                    }
                    let metadata = std::fs::symlink_metadata(entry.path()).map_err(io)?;
                    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                        return Err("partial export custody differs".into());
                    }
                    if metadata.is_dir() {
                        clear(&entry.path(), &member, allowed, remaining)?;
                        std::fs::remove_dir(entry.path()).map_err(io)?;
                    } else if metadata.is_file() && metadata.nlink() == 1 {
                        std::fs::remove_file(entry.path()).map_err(io)?;
                    } else {
                        return Err("partial export contains an unsafe member".into());
                    }
                }
                Ok(())
            }
            clear(
                &destination.path,
                Path::new(""),
                &allowed,
                &mut allowed.len(),
            )?;
            output_root.sync_all().map_err(io)?;
        }
        for selected in self.layout.output_files.as_slice() {
            let writable = self
                .layout
                .writable_roots
                .as_slice()
                .iter()
                .find(|root| memcordon_core::workload_registry_v3::is_beneath(selected, &root.path))
                .ok_or("selected output is outside writable roots")?;
            let mut source_root = self.root.try_clone().map_err(io)?;
            // Crossing into the single declared work mount is intentional. All
            // subsequent member traversal is confined to that held mount.
            for component in writable.path.as_str().split('/') {
                source_root = directory_at(source_root.as_fd(), component, false)?;
            }
            let relative = selected
                .as_str()
                .strip_prefix(writable.path.as_str())
                .and_then(|value| value.strip_prefix('/'))
                .ok_or("output relative path differs")?;
            #[repr(C)]
            struct OpenHow {
                flags: u64,
                mode: u64,
                resolve: u64,
            }
            let how = OpenHow {
                flags: (libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC) as u64,
                mode: 0,
                resolve: 0x08 | 0x02 | 0x04 | 0x01,
            };
            let member = CString::new(relative).map_err(|_| "output path contains NUL")?;
            let raw = unsafe {
                libc::syscall(
                    libc::SYS_openat2,
                    source_root.as_raw_fd(),
                    member.as_ptr(),
                    &how,
                    std::mem::size_of::<OpenHow>(),
                )
            } as i32;
            if raw < 0 {
                return Err(io(std::io::Error::last_os_error()));
            }
            use std::os::fd::FromRawFd;
            let mut source = unsafe { File::from_raw_fd(raw) };
            let before = source.metadata().map_err(io)?;
            if !before.is_file()
                || before.nlink() != 1
                || before.uid() != identity.uid.get()
                || before.mode() & 0o6000 != 0
            {
                return Err("selected output lacks exclusive regular-file custody".into());
            }
            let used = budgets.entry(writable.id.as_str().to_owned()).or_default();
            *used = used
                .checked_add(before.len())
                .ok_or("output budget overflow")?;
            if *used > writable.byte_limit.get() {
                return Err("selected outputs exceed work-root bound".into());
            }
            let mut output = if destination.published {
                open_relative(output_root.as_fd(), selected, false)?
            } else {
                open_relative(output_root.as_fd(), selected, true)?
            };
            let mut hash = Sha256::new();
            let mut copied = 0_u64;
            let mut buffer = [0_u8; 65536];
            loop {
                let count = source.read(&mut buffer).map_err(io)?;
                if count == 0 {
                    break;
                }
                copied = copied
                    .checked_add(count as u64)
                    .ok_or("output copy overflow")?;
                if copied > before.len() {
                    return Err("selected output changed during copy".into());
                }
                hash.update(&buffer[..count]);
                if destination.published {
                    let mut existing = vec![0_u8; count];
                    output.read_exact(&mut existing).map_err(io)?;
                    if existing != buffer[..count] {
                        return Err("published export bytes differ from held output".into());
                    }
                } else {
                    output.write_all(&buffer[..count]).map_err(io)?;
                }
            }
            let after = source.metadata().map_err(io)?;
            let stamp = |value: &std::fs::Metadata| {
                (
                    value.dev(),
                    value.ino(),
                    value.len(),
                    value.nlink(),
                    value.uid(),
                    value.mode(),
                    value.mtime(),
                    value.mtime_nsec(),
                    value.ctime(),
                    value.ctime_nsec(),
                )
            };
            if copied != before.len() || stamp(&before) != stamp(&after) {
                return Err("selected output native identity/content changed".into());
            }
            if destination.published {
                let metadata = output.metadata().map_err(io)?;
                let mut extra = [0_u8; 1];
                if metadata.uid() != 0
                    || metadata.nlink() != 1
                    || metadata.mode() & 0o777 != 0o400
                    || output.read(&mut extra).map_err(io)? != 0
                {
                    return Err("published export native custody differs".into());
                }
            } else {
                output
                    .set_permissions(std::fs::Permissions::from_mode(0o400))
                    .map_err(io)?;
                output.sync_all().map_err(io)?;
            }
            let digest = memcordon_core::DiagnosticSha256::from_bytes(hash.finalize().into());
            receipts.push(
                serde_json::json!({"path":selected.as_str(),"length":copied,"sha256":digest}),
            );
            let (parent, _) = parent_at(output_root.as_fd(), selected, false)?;
            parent.sync_all().map_err(io)?;
            let mut parent = Path::new(selected.as_str()).parent();
            while let Some(path) = parent {
                if path.as_os_str().is_empty() {
                    break;
                }
                export_directories.insert(path.to_path_buf());
                parent = path.parent();
            }
        }
        let receipt=serde_json::to_vec(&serde_json::json!({"format":"memcordon.private-export","revision":1,"attempt_id":retirement.attempt_id(),"root_layout":layout_reference,"identity":identity_reference,"files":receipts})).map_err(|error|error.to_string())?;
        let receipt_path = RootRelativePath::new("export-receipt.json".to_owned())?;
        let mut receipt_file =
            open_relative(output_root.as_fd(), &receipt_path, !destination.published)?;
        if destination.published {
            let metadata = receipt_file.metadata().map_err(io)?;
            let mut bytes = Vec::new();
            receipt_file
                .take((receipt.len() + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(io)?;
            if bytes != receipt
                || metadata.uid() != 0
                || metadata.nlink() != 1
                || metadata.mode() & 0o777 != 0o400
            {
                return Err("published export receipt differs".into());
            }
        } else {
            receipt_file.write_all(&receipt).map_err(io)?;
            receipt_file
                .set_permissions(std::fs::Permissions::from_mode(0o400))
                .map_err(io)?;
            receipt_file.sync_all().map_err(io)?;
        }
        let mut directories: Vec<_> = export_directories.into_iter().collect();
        directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
        for path in directories {
            let mut directory = output_root.try_clone().map_err(io)?;
            for component in path.components() {
                let name = component
                    .as_os_str()
                    .to_str()
                    .ok_or("export directory is not UTF-8")?;
                directory = directory_at(directory.as_fd(), name, false)?;
            }
            directory.sync_all().map_err(io)?;
        }
        output_root.sync_all().map_err(io)?;
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/run/memcordon")
            .map_err(io)?;
        parent.sync_all().map_err(io)?;
        drop(output_root);
        destination.published = true;
        #[cfg(test)]
        {
            destination.component_empty_publication =
                self.layout.output_files.as_slice().is_empty();
        }
        Ok(destination.path.clone())
    }
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.root.as_fd()
    }
    pub(super) fn init_nondumpable(&self) -> bool {
        self.init_nondumpable
    }
    pub fn layout(&self) -> &RootLayoutDefinitionV1 {
        &self.layout
    }
    /// Readonly image directories are traversable by the exclusive target account.
    /// Runtime store directories remain separately protected at mode 0700.
    #[expect(
        clippy::too_many_arguments,
        reason = "Private root entry binds independent owned images, layout, staging, exclusive account, attempt, and administrator identity"
    )]
    pub fn enter(
        runtime: InstalledRuntimeImage,
        input: InstalledRuntimeImage,
        layout: RootLayoutDefinitionV1,
        staging: NativeRootStaging,
        uid: u32,
        gid: u32,
        attempt: [u8; 16],
        identity: memcordon_core::workload_contract_v3::ExclusiveAdministratorIdentityRef,
    ) -> Result<Self, String> {
        layout.validate()?;
        if uid == 0
            || gid == 0
            || layout.runtime_image != *runtime.reference()
            || layout.input_image != *input.reference()
        {
            return Err("private root image/account binding differs".into());
        }
        runtime.revalidate()?;
        input.revalidate()?;
        let entries: Vec<_> = [runtime.definition(), input.definition()]
            .into_iter()
            .flat_map(|image| image.entries.as_slice())
            .collect();
        if runtime.definition().target != input.definition().target
            || runtime.reference() == input.reference()
        {
            return Err("private root requires distinct same-target images".into());
        }
        for (index, entry) in entries.iter().enumerate() {
            use memcordon_core::workload_registry_v3::is_beneath;
            if entries[..index].iter().any(|prior| {
                prior.path() == entry.path()
                    || is_beneath(prior.path(), entry.path())
                    || is_beneath(entry.path(), prior.path())
            }) || layout.writable_roots.as_slice().iter().any(|writable| {
                &writable.path == entry.path()
                    || is_beneath(&writable.path, entry.path())
                    || is_beneath(entry.path(), &writable.path)
            }) {
                return Err("private root merged image/writable authority overlaps".into());
            }
        }
        super::runtime_image::protected_directory(&staging.held)?;
        // This is the fork child's owned copy. The outer native owner retains
        // its original TempDir until aggregate retirement; disarm only the
        // child's pathname cleanup before pivoting out of the host root.
        let NativeRootStaging {
            provider_owner: _,
            path: staging_path,
            held: staging_held,
        } = staging;
        let staging = staging_path.as_path();
        for image in [&runtime, &input] {
            if image.definition().entries.as_slice().iter().any(|entry| {
                matches!(
                    entry.path().as_str().split('/').next(),
                    Some("proc" | "dev" | "sys" | ".old-root")
                )
            }) {
                return Err("image collides with private kernel root entries".into());
            }
        }
        if unsafe { libc::getpid() } != 1 {
            return Err("private root must be constructed by native namespace init".into());
        }
        if unsafe { libc::unshare(libc::CLONE_NEWIPC) } < 0 {
            return Err(io(std::io::Error::last_os_error()));
        }
        mount(
            None,
            Path::new("/"),
            None,
            libc::MS_REC | libc::MS_PRIVATE,
            None,
        )?;
        mount(
            Some("tmpfs"),
            staging,
            Some("tmpfs"),
            libc::MS_NOSUID | libc::MS_NODEV,
            Some("mode=0755,size=17179869184"),
        )?;
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(staging)
            .map_err(io)?;
        for image in [&runtime, &input] {
            for entry in image.definition().entries.as_slice() {
                if let ImageEntryV1::Regular {
                    size, executable, ..
                } = entry
                {
                    let source = File::from(
                        image
                            .object(entry.path())?
                            .try_clone_to_owned()
                            .map_err(io)?,
                    );
                    let mut destination = open_relative(root.as_fd(), entry.path(), true)?;
                    image_copy::copy_exact(&source, &mut destination, *size).map_err(io)?;
                    destination
                        .set_permissions(std::fs::Permissions::from_mode(if *executable {
                            0o555
                        } else {
                            0o444
                        }))
                        .map_err(io)?;
                    super::runtime_image::verify_regular(&destination, entry, true)?;
                }
            }
        }
        for image in [&runtime, &input] {
            for entry in image.definition().entries.as_slice() {
                let parent = Path::new(entry.path().as_str())
                    .parent()
                    .expect("validated relative path");
                let _ = parent_at(root.as_fd(), entry.path(), true)?;
                let mut current = staging.to_path_buf();
                for component in parent.components() {
                    current.push(component);
                    std::fs::set_permissions(&current, std::fs::Permissions::from_mode(0o755))
                        .map_err(io)?;
                }
                if let ImageEntryV1::Symlink { path, target } = entry {
                    let (parent, name) = parent_at(root.as_fd(), path, true)?;
                    let mut reconstructed = PathBuf::new();
                    for _ in Path::new(path.as_str())
                        .parent()
                        .expect("validated relative path")
                        .components()
                    {
                        reconstructed.push("..");
                    }
                    reconstructed.push(target.as_str());
                    let target = text(&reconstructed)?;
                    if unsafe {
                        libc::symlinkat(target.as_ptr(), parent.as_raw_fd(), name.as_ptr())
                    } < 0
                    {
                        return Err(io(std::io::Error::last_os_error()));
                    }
                }
            }
        }
        runtime.revalidate()?;
        input.revalidate()?;
        for writable in layout.writable_roots.as_slice() {
            let path = staging.join(writable.path.as_str());
            directory(&path)?;
            let flags = libc::MS_NOSUID
                | libc::MS_NODEV
                | if writable.generated_execution {
                    0
                } else {
                    libc::MS_NOEXEC
                };
            mount(
                Some("tmpfs"),
                &path,
                Some("tmpfs"),
                flags,
                Some(&format!(
                    "mode=0700,size={},uid={uid},gid={gid}",
                    writable.byte_limit.get()
                )),
            )?;
        }
        let proc = staging.join("proc");
        directory(&proc)?;
        mount(
            Some("proc"),
            &proc,
            Some("proc"),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_RDONLY,
            Some("hidepid=2"),
        )?;
        let dev = staging.join("dev");
        directory(&dev)?;
        mount(
            Some("tmpfs"),
            &dev,
            Some("tmpfs"),
            libc::MS_NOSUID | libc::MS_NOEXEC,
            Some("mode=0755,size=65536"),
        )?;
        for (name, minor) in [("null", 3), ("zero", 5), ("random", 8), ("urandom", 9)] {
            let path = text(&dev.join(name))?;
            if unsafe {
                libc::mknod(
                    path.as_ptr(),
                    libc::S_IFCHR | 0o666,
                    libc::makedev(1, minor),
                )
            } < 0
            {
                return Err(io(std::io::Error::last_os_error()));
            }
        }
        let shm = dev.join("shm");
        directory(&shm)?;
        mount(
            Some("tmpfs"),
            &shm,
            Some("tmpfs"),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            Some(&format!("mode=0700,size=67108864,uid={uid},gid={gid}")),
        )?;
        mount(
            None,
            &dev,
            None,
            libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NOEXEC,
            None,
        )?;
        directory(&staging.join(".old-root"))?;
        drop(staging_held);
        let target = text(staging)?;
        if unsafe { libc::chdir(target.as_ptr()) } < 0 {
            return Err(io(std::io::Error::last_os_error()));
        }
        if unsafe { libc::syscall(libc::SYS_pivot_root, c".".as_ptr(), c".old-root".as_ptr()) } < 0
        {
            return Err(io(std::io::Error::last_os_error()));
        }
        if unsafe { libc::chdir(c"/".as_ptr()) } < 0 {
            return Err(io(std::io::Error::last_os_error()));
        }
        if unsafe { libc::umount2(c"/.old-root".as_ptr(), libc::MNT_DETACH) } < 0 {
            return Err(io(std::io::Error::last_os_error()));
        }
        if unsafe { libc::rmdir(c"/.old-root".as_ptr()) } < 0 {
            return Err(io(std::io::Error::last_os_error()));
        }
        mount(
            None,
            Path::new("/"),
            None,
            libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
            None,
        )?;
        // Drop every held host image/source object before target fork. The
        // target's descriptor seal closes the namespace-init root capability.
        drop(runtime);
        drop(input);
        let attempt_id = attempt.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(Self {
            root,
            layout,
            attempt_id,
            identity,
            init_nondumpable: false,
        })
    }
    pub fn open_working_directory(&self, path: &RootRelativePath) -> Result<File, String> {
        if !self.layout.writable_roots.as_slice().iter().any(|root| {
            path == &root.path || memcordon_core::workload_registry_v3::is_beneath(path, &root.path)
        }) {
            return Err("working directory is outside declared writable roots".into());
        }
        let mut directory = self.root.try_clone().map_err(io)?;
        for component in path.as_str().split('/') {
            directory = directory_at(directory.as_fd(), component, false)?;
        }
        Ok(directory)
    }
}
