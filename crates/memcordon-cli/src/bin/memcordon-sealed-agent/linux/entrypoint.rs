//! Held executable identity, verified from fresh snapshot bytes before release.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntrypointObjectIdentity {
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub sha256: [u8; 32],
}

#[derive(Debug)]
pub struct VerifiedEntrypoint {
    file: File,
    identity: EntrypointObjectIdentity,
}

/// Opaque identity carried while the trusted child rearranges fd 0–4. The
/// selected ELF descriptor itself is moved, never reopened by pathname.
#[derive(Debug)]
pub struct EntrypointSealTicket {
    identity: EntrypointObjectIdentity,
}

#[cfg(feature = "test-support")]
pub fn seal_ticket_for_test(identity: EntrypointObjectIdentity) -> EntrypointSealTicket {
    EntrypointSealTicket { identity }
}

impl VerifiedEntrypoint {
    /// Fresh copied immutable image members share the same held native object
    /// checks as the immutable manifest, with the exact caller content digest.
    pub(super) fn from_private_root_image(
        file: File,
        entry: &memcordon_core::workload_files::ImageEntryV1,
        cutoff: std::time::Instant,
    ) -> Result<Self, String> {
        let memcordon_core::workload_files::ImageEntryV1::Regular {
            sha256,
            size,
            executable: true,
            ..
        } = entry
        else {
            return Err(error(
                "private image entrypoint is not executable regular content",
            ));
        };
        super::workload_snapshot::verify_regular_until(&file, entry, true, cutoff)?;
        let verified = Self::from_snapshot_image(file, sha256, cutoff)?;
        if verified.identity.size != *size {
            return Err(error("private image executable size differs"));
        }
        Ok(verified)
    }
    /// Verify the held current snapshot object against its exact content digest.
    fn from_snapshot_image(
        file: File,
        expected_digest: &memcordon_core::DiagnosticSha256,
        cutoff: std::time::Instant,
    ) -> Result<Self, String> {
        let before = stat(file.as_raw_fd())?;
        verify_executable_metadata(file.as_raw_fd(), &before)?;
        let limit =
            u64::try_from(before.st_size).map_err(|_| error("negative probe image size"))?;
        let (digest, count) = hash_opened_file(&file, limit, cutoff)?;
        let after = stat(file.as_raw_fd())?;
        if !same_change_metadata(&before, &after)
            || count != limit
            || digest != *expected_digest.bytes()
        {
            return Err(error(
                "pinned probe image changed or differs from installed package",
            ));
        }
        Ok(Self {
            file,
            identity: EntrypointObjectIdentity {
                device: after.st_dev,
                inode: after.st_ino,
                size: count,
                sha256: digest,
            },
        })
    }

    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }

    pub fn into_sealing_parts(self) -> (OwnedFd, EntrypointSealTicket) {
        (
            self.file.into(),
            EntrypointSealTicket {
                identity: self.identity,
            },
        )
    }

    /// Rebind the same verified object after descriptor custody has placed it
    /// at the CLOEXEC fd-4 slot. Only a ticket from `into_sealing_parts` can
    /// authorize reconstruction; caller-supplied fd numbers are insufficient.
    pub fn from_sealed_slot(fd: OwnedFd, ticket: EntrypointSealTicket) -> Result<Self, String> {
        if fd.as_raw_fd() != 4 {
            return Err(error("sealed executable is not at fd 4"));
        }
        let current = stat(fd.as_raw_fd())?;
        // SAFETY: F_GETFD takes a live owned descriptor and no pointer arguments.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        if current.st_dev != ticket.identity.device
            || current.st_ino != ticket.identity.inode
            || current.st_size as u64 != ticket.identity.size
            || flags < 0
            || flags & libc::FD_CLOEXEC == 0
        {
            return Err(error("sealed executable identity or flags changed"));
        }
        Ok(Self {
            file: fd.into(),
            identity: ticket.identity,
        })
    }

    pub fn raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    pub const fn identity(&self) -> EntrypointObjectIdentity {
        self.identity
    }

    /// Move the pinned descriptor into the private profile's reserved fd 4.
    /// The trusted setup must call this before `close_range(5, ..)`, with slot
    /// 4 vacant; this deliberately refuses to overwrite another live object.
    pub fn into_exec_slot(self) -> Result<Self, String> {
        const EXEC_SLOT: RawFd = 4;
        if self.file.as_raw_fd() == EXEC_SLOT {
            return Ok(self);
        }
        let occupant = unsafe { libc::fcntl(EXEC_SLOT, libc::F_GETFD) };
        if occupant >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EBADF) {
            return Err(error("reserved executable descriptor is occupied"));
        }
        // SAFETY: fd 4 was confirmed vacant, the source is owned and live,
        // and dup3 marks the new descriptor close-on-exec from creation.
        if unsafe { libc::dup3(self.file.as_raw_fd(), EXEC_SLOT, libc::O_CLOEXEC) } == -1 {
            return Err(native_error("place pinned executable at fd 4"));
        }
        let identity = self.identity;
        drop(self.file);
        Ok(Self {
            file: unsafe { File::from_raw_fd(EXEC_SLOT) },
            identity,
        })
    }

    /// Native descriptor execution; only the trusted pre-exec stub may call
    /// this after arranging the reviewed fd inventory and target credentials.
    /// No pathname is selected and no shell interprets the argv/environment.
    pub fn execveat(&self, argv: &[CString], environment: &[CString]) -> Result<(), String> {
        self.execveat_inner(argv, environment, libc::AT_EMPTY_PATH, false)
    }

    /// The fixed host fault case reaches the same target-side syscall after
    /// the ordinary gate, but omits AT_EMPTY_PATH for the empty path. Linux
    /// must reject this with ENOENT; no alternate executable is selected.
    pub(crate) fn execveat_probe_rejected(
        &self,
        argv: &[CString],
        environment: &[CString],
    ) -> Result<(), String> {
        self.execveat_inner(argv, environment, 0, true)
    }

    fn execveat_inner(
        &self,
        argv: &[CString],
        environment: &[CString],
        flags: i32,
        expect_probe_enoent: bool,
    ) -> Result<(), String> {
        if argv.is_empty() {
            return Err(error("execveat requires argv[0]"));
        }
        let current = stat(self.file.as_raw_fd())?;
        if current.st_dev != self.identity.device
            || current.st_ino != self.identity.inode
            || current.st_size as u64 != self.identity.size
        {
            return Err(error("pinned executable changed before exec"));
        }
        let descriptor_flags = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GETFD) };
        if descriptor_flags < 0 || descriptor_flags & libc::FD_CLOEXEC == 0 {
            return Err(error("executable descriptor is not close-on-exec"));
        }
        let mut argv_ptrs: Vec<*const libc::c_char> =
            argv.iter().map(|value| value.as_ptr()).collect();
        argv_ptrs.push(std::ptr::null());
        let mut env_ptrs: Vec<*const libc::c_char> =
            environment.iter().map(|value| value.as_ptr()).collect();
        env_ptrs.push(std::ptr::null());
        // SAFETY: all C strings and pointer vectors remain live until the
        // syscall returns, and the empty path selects only the held descriptor.
        let result = unsafe {
            libc::syscall(
                libc::SYS_execveat,
                self.file.as_raw_fd(),
                c"".as_ptr(),
                argv_ptrs.as_ptr(),
                env_ptrs.as_ptr(),
                flags,
            )
        };
        if result == -1 {
            if expect_probe_enoent
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT)
            {
                return Err("MCSEALED-PROBE-EXECVEAT-ENOENT".into());
            }
            Err(native_error("execveat"))
        } else {
            Err(error("execveat unexpectedly returned"))
        }
    }
}

fn verify_executable_metadata(fd: RawFd, metadata: &libc::stat) -> Result<(), String> {
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
        || metadata.st_uid != 0
        || metadata.st_nlink != 1
        || metadata.st_mode & (libc::S_ISUID | libc::S_ISGID) != 0
        || metadata.st_mode & 0o022 != 0
        || metadata.st_mode & 0o111 == 0
        || metadata.st_size <= 0
    {
        return Err(error(
            "entrypoint metadata is not protected executable authority",
        ));
    }
    reject_xattr(fd, c"security.capability")?;
    reject_xattr(fd, c"system.posix_acl_access")?;
    Ok(())
}

fn reject_xattr(fd: RawFd, name: &CStr) -> Result<(), String> {
    // SAFETY: querying a live fd with a valid NUL-terminated attribute name;
    // no output buffer is supplied because only presence matters.
    let result = unsafe { libc::fgetxattr(fd, name.as_ptr(), std::ptr::null_mut(), 0) };
    if result >= 0 {
        return Err(error("forbidden executable or ancestor xattr is present"));
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(code) if code == libc::ENODATA || code == libc::ENOTSUP => Ok(()),
        _ => Err(native_error("inspect protected xattr")),
    }
}

fn hash_opened_file(
    file: &File,
    limit: u64,
    cutoff: std::time::Instant,
) -> Result<([u8; 32], u64), String> {
    super::workload_snapshot::check_validation_cutoff(cutoff)?;
    let mut reader = file
        .try_clone()
        .map_err(|e| native_io("clone executable fd", e))?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|e| native_io("rewind executable", e))?;
    let mut header = [0_u8; 64];
    reader
        .read_exact(&mut header)
        .map_err(|e| native_io("read ELF header", e))?;
    validate_elf(&header)?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|e| native_io("rewind ELF", e))?;
    let mut digest = Sha256::new();
    let mut count = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        super::workload_snapshot::check_validation_cutoff(cutoff)?;
        let read = reader
            .read(&mut buffer)
            .map_err(|e| native_io("read pinned ELF", e))?;
        if read == 0 {
            break;
        }
        count = count
            .checked_add(read as u64)
            .ok_or_else(|| error("ELF byte count overflow"))?;
        if count > limit {
            return Err(error("ELF exceeds declared byte count"));
        }
        digest.update(&buffer[..read]);
    }
    Ok((digest.finalize().into(), count))
}

pub(crate) fn validate_elf(header: &[u8; 64]) -> Result<(), String> {
    let expected_machine: u16 = if cfg!(target_arch = "x86_64") {
        62
    } else if cfg!(target_arch = "aarch64") {
        183
    } else {
        return Err(error("unsupported ELF host ABI"));
    };
    let kind = u16::from_le_bytes([header[16], header[17]]);
    let machine = u16::from_le_bytes([header[18], header[19]]);
    let version = u32::from_le_bytes([header[20], header[21], header[22], header[23]]);
    if &header[..4] != b"\x7fELF"
        || header[4] != 2
        || header[5] != 1
        || header[6] != 1
        || !matches!(kind, 2 | 3)
        || machine != expected_machine
        || version != 1
    {
        return Err(error("entrypoint is not a native ELF for this ABI"));
    }
    Ok(())
}

fn same_change_metadata(a: &libc::stat, b: &libc::stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_size == b.st_size
        && a.st_mode == b.st_mode
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
        && a.st_nlink == b.st_nlink
        && a.st_mtime == b.st_mtime
        && a.st_mtime_nsec == b.st_mtime_nsec
        && a.st_ctime == b.st_ctime
        && a.st_ctime_nsec == b.st_ctime_nsec
}

fn stat(fd: RawFd) -> Result<libc::stat, String> {
    let mut value = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat initializes the provided stat on success.
    if unsafe { libc::fstat(fd, value.as_mut_ptr()) } == -1 {
        Err(native_error("stat protected object"))
    } else {
        Ok(unsafe { value.assume_init() })
    }
}

fn error(detail: &str) -> String {
    format!("MCSEALED-ENTRYPOINT: {detail}")
}
fn native_error(phase: &str) -> String {
    native_io(phase, std::io::Error::last_os_error())
}
fn native_io(phase: &str, cause: impl std::fmt::Display) -> String {
    format!("MCSEALED-ENTRYPOINT: {phase}: {cause}")
}
