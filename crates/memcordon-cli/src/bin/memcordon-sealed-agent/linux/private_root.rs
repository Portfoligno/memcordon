//! Fresh copied root construction. Only the single-threaded namespace init calls enter.
use super::workload_snapshot::{HeldSnapshot, directory_at, open_relative, parent_at};
use memcordon_core::workload_files::ImageEntryV1;
use memcordon_core::workload_files::RootRelativePath;
use memcordon_core::workload_request::PrivateRootLayoutV1;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
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
    ) -> Result<super::native_process::MixedDirectoryIdentityV2, String> {
        use std::os::unix::fs::MetadataExt;
        let metadata = self.held.metadata().map_err(io)?;
        Ok(super::native_process::MixedDirectoryIdentityV2 {
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
            super::workload_snapshot::protected_directory(&parent)?;
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
        super::workload_snapshot::protected_directory(&held)?;
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
        super::workload_snapshot::protected_directory(&self.held)?;
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
        super::workload_snapshot::protected_directory(&self.held)?;
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
        super::workload_snapshot::protected_directory(&parent)?;
        parent.sync_all().map_err(io)?;
        Ok(())
    }
}

/// No deserializer or public constructor: this is the actual mounted root inode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RootOwnership {
    Workload {
        request_sha256: memcordon_core::DiagnosticSha256,
        target_uid: u32,
    },
}
pub struct MountedPrivateRoot {
    root: File,
    // Only the provider exports after namespace retirement. Init owns no extra
    // pins, so its target descriptor seal and transfer inventory stay exact.
    writable_mounts: Option<Vec<HeldWritableMount>>,
    layout: PrivateRootLayoutV1,
    attempt_id: String,
    identity: RootOwnership,
    init_nondumpable: bool,
}
struct HeldWritableMount {
    definition: memcordon_core::workload_files::WritableRootV1,
    directory: File,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkloadRootTransferV1 {
    format: String,
    revision: u32,
    layout_sha256: memcordon_core::DiagnosticSha256,
    request_sha256: memcordon_core::DiagnosticSha256,
    target_uid: u32,
    entrypoint: RootRelativePath,
    root_device: u64,
    root_inode: u64,
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
        let payload = match &self.identity {
            RootOwnership::Workload {
                request_sha256,
                target_uid,
            } => serde_json::to_vec(&WorkloadRootTransferV1 {
                format: "memcordon.workload-root-transfer".into(),
                revision: 1,
                layout_sha256: self.layout.digest().map_err(|e| e.to_string())?,
                request_sha256: request_sha256.clone(),
                target_uid: *target_uid,
                entrypoint: entry.path().clone(),
                root_device: root.dev(),
                root_inode: root.ino(),
                init_nondumpable,
            }),
        }
        .map_err(|error| error.to_string())?;
        let frame = crate::protocol::Frame {
            kind: crate::protocol::MessageKind::LaunchPrepared,
            nonce,
            attempt_id: attempt,
            payload,
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
        reason = "Root transfer independently authenticates channel, held init identity, original request, layout, package account, and entrypoint"
    )]
    pub(super) fn receive_from_init(
        channel: &std::os::unix::net::UnixStream,
        init: &super::native_process::ProcessIdentityV4,
        init_pidfd: BorrowedFd<'_>,
        nonce: [u8; 16],
        attempt: [u8; 16],
        layout: PrivateRootLayoutV1,
        identity: RootOwnership,
        entry: &ImageEntryV1,
        deadline: std::time::Instant,
    ) -> Result<(Self, super::entrypoint::VerifiedEntrypoint), String> {
        use std::os::unix::fs::MetadataExt;
        let observe = || {
            super::native_process::ProcessIdentityV4::observe(
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
        memcordon_core::canonical_json::reject_duplicate_json_keys(&frame.payload)?;
        layout.validate().map_err(|e| e.to_string())?;
        let (root_device, root_inode, init_nondumpable) = match &identity {
            RootOwnership::Workload {
                request_sha256,
                target_uid,
            } => {
                let transfer: WorkloadRootTransferV1 =
                    serde_json::from_slice(&frame.payload).map_err(|e| e.to_string())?;
                if transfer.format != "memcordon.workload-root-transfer"
                    || transfer.revision != 1
                    || transfer.layout_sha256 != layout.digest().map_err(|e| e.to_string())?
                    || transfer.entrypoint != *entry.path()
                    || &transfer.request_sha256 != request_sha256
                    || transfer.target_uid != *target_uid
                {
                    return Err("workload native root transfer differs".into());
                }
                (
                    transfer.root_device,
                    transfer.root_inode,
                    transfer.init_nondumpable,
                )
            }
        };
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
            || (metadata.dev(), metadata.ino()) != (root_device, root_inode)
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
        if !init_nondumpable {
            return Err("native namespace init was dumpable at root publication".into());
        }
        let mut root = Self {
            root,
            writable_mounts: None,
            layout,
            attempt_id,
            identity,
            init_nondumpable,
        };
        root.writable_mounts = Some(root.capture_writable_mounts(deadline)?);
        let independently_opened = root.open_entrypoint(entry, deadline)?;
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
        let executable = super::entrypoint::VerifiedEntrypoint::from_private_root_image(
            executable, entry, deadline,
        )?;
        if std::time::Instant::now() >= deadline {
            return Err("native root writable mount capture exceeded original setup cutoff".into());
        }
        if observe()? != *init {
            return Err("native root init birth differs after writable mount capture".into());
        }
        Ok((root, executable))
    }
    fn capture_writable_mounts(
        &self,
        deadline: std::time::Instant,
    ) -> Result<Vec<HeldWritableMount>, String> {
        let mut mounts = Vec::new();
        for definition in self.layout.writable_roots.as_slice() {
            let capture = (|| -> Result<File, String> {
                if std::time::Instant::now() >= deadline {
                    return Err("original setup cutoff expired".into());
                }
                let mut directory = self.root.try_clone().map_err(io)?;
                for component in definition.path.as_str().split('/') {
                    if std::time::Instant::now() >= deadline {
                        return Err("original setup cutoff expired".into());
                    }
                    directory = directory_at(directory.as_fd(), component, false)?;
                }
                if !directory.metadata().map_err(io)?.is_dir() {
                    return Err("declared writable mount is not a directory".into());
                }
                let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
                if unsafe { libc::fstatfs(directory.as_raw_fd(), filesystem.as_mut_ptr()) } < 0 {
                    return Err(io(std::io::Error::last_os_error()));
                }
                if unsafe { filesystem.assume_init() }.f_type != libc::TMPFS_MAGIC {
                    return Err("declared writable mount is not tmpfs".into());
                }
                let mut flags = std::mem::MaybeUninit::<libc::statvfs>::uninit();
                if unsafe { libc::fstatvfs(directory.as_raw_fd(), flags.as_mut_ptr()) } < 0 {
                    return Err(io(std::io::Error::last_os_error()));
                }
                let flags = unsafe { flags.assume_init() }.f_flag;
                let required = libc::ST_NOSUID
                    | libc::ST_NODEV
                    | if definition.generated_execution {
                        0
                    } else {
                        libc::ST_NOEXEC
                    };
                if flags & libc::ST_RDONLY != 0
                    || flags & required != required
                    || (definition.generated_execution && flags & libc::ST_NOEXEC != 0)
                {
                    return Err("declared writable mount flags differ".into());
                }
                Ok(directory)
            })()
            .map_err(|error| {
                format!(
                    "capture writable mount {} at {}: {error}",
                    definition.id.as_str(),
                    definition.path.as_str()
                )
            })?;
            mounts.push(HeldWritableMount {
                definition: definition.clone(),
                directory: capture,
            });
        }
        Ok(mounts)
    }
    fn held_writable_mount(
        &self,
        definition: &memcordon_core::workload_files::WritableRootV1,
    ) -> Result<&File, String> {
        let mounts = self.validated_writable_mounts()?;
        mounts
            .iter()
            .find(|held| held.definition == *definition)
            .map(|held| &held.directory)
            .ok_or_else(|| {
                format!(
                    "held writable mount {} at {} absent",
                    definition.id.as_str(),
                    definition.path.as_str()
                )
            })
    }
    fn validated_writable_mounts(&self) -> Result<&[HeldWritableMount], String> {
        let mounts = self
            .writable_mounts
            .as_ref()
            .ok_or("provider writable mount pins absent")?;
        if mounts.len() != self.layout.writable_roots.as_slice().len()
            || mounts
                .iter()
                .zip(self.layout.writable_roots.as_slice())
                .any(|(held, declared)| held.definition != *declared)
        {
            return Err("provider writable mount pins differ from immutable layout".into());
        }
        Ok(mounts)
    }
    fn open_pinned_output(
        &self,
        writable: &memcordon_core::workload_files::WritableRootV1,
        selected: &RootRelativePath,
        uid: u32,
    ) -> Result<(File, std::fs::Metadata), String> {
        use std::os::fd::FromRawFd;
        use std::os::unix::fs::MetadataExt;
        let source_root = self.held_writable_mount(writable)?;
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
            return Err(format!(
                "openat2 selected output {} from writable mount {}: {}",
                selected.as_str(),
                writable.id.as_str(),
                std::io::Error::last_os_error()
            ));
        }
        let source = unsafe { File::from_raw_fd(raw) };
        let before = source.metadata().map_err(io)?;
        if !before.is_file()
            || before.nlink() != 1
            || before.uid() != uid
            || before.mode() & 0o6000 != 0
        {
            return Err("selected output lacks exclusive regular-file custody".into());
        }
        Ok((source, before))
    }
    pub(super) fn open_entrypoint(
        &self,
        entry: &ImageEntryV1,
        deadline: std::time::Instant,
    ) -> Result<super::entrypoint::VerifiedEntrypoint, String> {
        let file = open_relative(self.root.as_fd(), entry.path(), false)?;
        super::entrypoint::VerifiedEntrypoint::from_private_root_image(file, entry, deadline)
    }
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.root.as_fd()
    }
    pub(super) fn init_nondumpable(&self) -> bool {
        self.init_nondumpable
    }
    pub fn layout(&self) -> &PrivateRootLayoutV1 {
        &self.layout
    }
    /// Collect only declared regular files from the original writable mount pins
    /// after exact native process/relay retirement. No host output path is accepted.
    pub(super) fn export_workload(
        &self,
        retired: &super::private_lifecycle::WorkloadProcessesRetired,
        destination: &File,
        deadline: std::time::Instant,
    ) -> Result<
        memcordon_core::BoundedVec<memcordon_core::result_v3::WorkloadOutputFileV1, 64>,
        String,
    > {
        use sha2::{Digest, Sha256};
        use std::io::{Read, Write};
        use std::os::unix::fs::MetadataExt;
        if self.attempt_id != retired.attempt()
            || !matches!(&self.identity, RootOwnership::Workload { target_uid, .. } if *target_uid == retired.target_uid())
        {
            return Err("output custody differs from original retired attempt".into());
        }
        super::workload_snapshot::protected_directory(destination)?;
        self.validated_writable_mounts()?;
        let mut used = std::collections::BTreeMap::<String, u64>::new();
        let mut files = memcordon_core::BoundedVec::default();
        let mut buffer = [0; memcordon_core::workload_bundle::STREAM_BYTES];
        for selected in self.layout.output_files.as_slice() {
            if std::time::Instant::now() >= deadline {
                return Err("original output collection cutoff expired".into());
            }
            let writable = self
                .layout
                .writable_roots
                .as_slice()
                .iter()
                .find(|root| memcordon_core::workload_files::is_beneath(selected, &root.path))
                .ok_or("output is outside declared writable roots")?;
            let (mut source, before) =
                self.open_pinned_output(writable, selected, retired.target_uid())?;
            let charge = used.entry(writable.id.as_str().into()).or_default();
            *charge = charge
                .checked_add(before.len())
                .ok_or("output footprint overflow")?;
            if *charge > writable.byte_limit.get() {
                return Err("output inventory exceeds declared writable bound".into());
            }
            let mut output =
                super::workload_snapshot::open_relative(destination.as_fd(), selected, true)?;
            let mut remaining = before.len();
            let mut digest = Sha256::new();
            while remaining != 0 {
                if std::time::Instant::now() >= deadline {
                    return Err("original output copy cutoff expired".into());
                }
                let amount = usize::try_from(
                    remaining.min(u64::try_from(buffer.len()).expect("buffer fits u64")),
                )
                .expect("bounded amount fits usize");
                source.read_exact(&mut buffer[..amount]).map_err(io)?;
                output.write_all(&buffer[..amount]).map_err(io)?;
                digest.update(&buffer[..amount]);
                remaining -= u64::try_from(amount).expect("bounded amount fits u64");
            }
            let after = source.metadata().map_err(io)?;
            if (
                before.dev(),
                before.ino(),
                before.len(),
                before.uid(),
                before.mode(),
                before.mtime(),
                before.mtime_nsec(),
                before.ctime(),
                before.ctime_nsec(),
            ) != (
                after.dev(),
                after.ino(),
                after.len(),
                after.uid(),
                after.mode(),
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec(),
            ) {
                return Err("output native content/custody changed during collection".into());
            }
            output
                .set_permissions(std::fs::Permissions::from_mode(0o400))
                .map_err(io)?;
            output.sync_all().map_err(io)?;
            files
                .try_push(memcordon_core::result_v3::WorkloadOutputFileV1 {
                    path: selected.clone(),
                    size: before.len(),
                    sha256: memcordon_core::DiagnosticSha256::from_bytes(digest.finalize().into()),
                })
                .map_err(|_| "output inventory exceeds bound")?;
        }
        destination.sync_all().map_err(io)?;
        Ok(files)
    }
    /// Readonly snapshot directories are traversable by the locked package account.
    /// Original provider staging remains separately protected at mode 0700.
    #[expect(
        clippy::too_many_arguments,
        reason = "Private root entry binds independent held snapshots, layout, staging, package account, and original attempt"
    )]
    pub fn enter(
        runtime: HeldSnapshot,
        input: HeldSnapshot,
        layout: PrivateRootLayoutV1,
        staging: NativeRootStaging,
        uid: u32,
        gid: u32,
        attempt: [u8; 16],
        identity: impl Into<RootOwnership>,
    ) -> Result<Self, String> {
        let identity = identity.into();
        let copy_cutoff = runtime.validation_cutoff().min(input.validation_cutoff());
        layout.validate().map_err(|e| e.to_string())?;
        if uid == 0 || gid == 0 {
            return Err("private root image/account binding differs".into());
        }
        runtime.revalidate()?;
        input.revalidate()?;
        if runtime.definition().target != input.definition().target {
            return Err("private root requires distinct same-target images".into());
        }
        memcordon_core::workload_bundle::validate_layout(
            runtime.definition(),
            input.definition(),
            &layout,
        )?;
        super::workload_snapshot::protected_directory(&staging.held)?;
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
                super::workload_snapshot::check_validation_cutoff(copy_cutoff)?;
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
                    image_copy::copy_exact(&source, &mut destination, *size, copy_cutoff)
                        .map_err(io)?;
                    destination
                        .set_permissions(std::fs::Permissions::from_mode(if *executable {
                            0o555
                        } else {
                            0o444
                        }))
                        .map_err(io)?;
                    super::workload_snapshot::verify_regular_until(
                        &destination,
                        entry,
                        true,
                        copy_cutoff,
                    )?;
                }
            }
        }
        for image in [&runtime, &input] {
            for entry in image.definition().entries.as_slice() {
                super::workload_snapshot::check_validation_cutoff(copy_cutoff)?;
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
            super::workload_snapshot::check_validation_cutoff(copy_cutoff)?;
            let inodes = super::workload_resources::writable_inode_limit(
                writable.byte_limit.get(),
                super::workload_resources::native_page_size()?,
            )?;
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
                    "mode=0700,size={},nr_inodes={inodes},uid={uid},gid={gid}",
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
                let error = std::io::Error::last_os_error();
                return Err(format!(
                    "private root mknod dev/{name} character major=1 minor={minor}: {error}"
                ));
            }
        }
        let shm = dev.join("shm");
        directory(&shm)?;
        mount(
            Some("tmpfs"),
            &shm,
            Some("tmpfs"),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            Some(&format!(
                "mode=0700,size={},nr_inodes={},uid={uid},gid={gid}",
                super::workload_resources::SHARED_MEMORY_BYTES,
                super::workload_resources::writable_inode_limit(
                    super::workload_resources::SHARED_MEMORY_BYTES,
                    super::workload_resources::native_page_size()?
                )?
            )),
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
            writable_mounts: None,
            layout,
            attempt_id,
            identity,
            init_nondumpable: false,
        })
    }
    pub fn open_working_directory(&self, path: &RootRelativePath) -> Result<File, String> {
        if !self.layout.writable_roots.as_slice().iter().any(|root| {
            path == &root.path || memcordon_core::workload_files::is_beneath(path, &root.path)
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
