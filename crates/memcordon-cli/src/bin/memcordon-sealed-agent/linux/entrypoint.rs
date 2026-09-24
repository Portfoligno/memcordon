//! Protected-from-creation executable authority for the optional private profile.
//!
//! This module does not make the private profile available. The trusted installer
//! creates both the executable and its receipt in a protected directory. A
//! pathname, digest, or later chmod alone must never become executable authority.

use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};

use memcordon_core::workload_registry_v2::ApprovedEntrypointV2;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_IN_ROOT: u64 = 0x10;
const RESOLUTION: u64 = RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_IN_ROOT;
const RECEIPT_SUFFIX: &[u8] = b".memcordon-receipt";
const MAX_RECEIPT_BYTES: u64 = 8192;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

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
                libc::AT_EMPTY_PATH,
            )
        };
        if result == -1 {
            Err(native_error("execveat"))
        } else {
            Err(error("execveat unexpectedly returned"))
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreationReceiptV1 {
    version: u8,
    absolute_path: String,
    device: u64,
    inode: u64,
    size: u64,
    sha256: [u8; 32],
}

impl CreationReceiptV1 {
    fn identity(&self) -> EntrypointObjectIdentity {
        EntrypointObjectIdentity {
            device: self.device,
            inode: self.inode,
            size: self.size,
            sha256: self.sha256,
        }
    }
}

/// Open an approved ELF and its protected creation receipt within the
/// authenticated caller's root/mount context. The root descriptor must come
/// from the trusted caller capture, never from a request or candidate fd.
pub fn open_verified_entrypoint(
    caller_root: BorrowedFd<'_>,
    approved: &ApprovedEntrypointV2,
) -> Result<VerifiedEntrypoint, String> {
    let path = approved_path(approved)?;
    verify_ancestors(caller_root, &path)?;
    let file = open_in_root(caller_root, &path, libc::O_RDONLY | libc::O_CLOEXEC)?;
    let before = stat(file.as_raw_fd())?;
    verify_executable_metadata(file.as_raw_fd(), &before)?;
    let (digest, byte_count) = hash_opened_file(&file, approved.size.get())?;
    let after = stat(file.as_raw_fd())?;
    if !same_change_metadata(&before, &after)
        || byte_count != approved.size.get()
        || digest != *approved.sha256.bytes()
    {
        return Err(error("approved executable content or metadata mismatch"));
    }
    let identity = EntrypointObjectIdentity {
        device: after.st_dev,
        inode: after.st_ino,
        size: byte_count,
        sha256: digest,
    };
    let receipt_path = receipt_path(&path)?;
    let receipt_file = open_in_root(caller_root, &receipt_path, libc::O_RDONLY | libc::O_CLOEXEC)?;
    let receipt_stat = stat(receipt_file.as_raw_fd())?;
    verify_receipt_metadata(receipt_file.as_raw_fd(), &receipt_stat)?;
    let receipt = read_receipt(receipt_file)?;
    if receipt.version != 1
        || receipt.absolute_path != approved.absolute_path.as_str()
        || receipt.identity() != identity
    {
        return Err(error("creation receipt does not bind opened executable"));
    }
    Ok(VerifiedEntrypoint { file, identity })
}

/// Trusted administrative setup only. The source bytes are copied into a
/// *new* root-owned inode created root-only, hashed and read back on that same
/// inode, then its writer is closed before no-replace publication. A protected
/// receipt is separately published afterwards; a crash between publications
/// leaves an untrusted file, never an admitted executable.
pub fn install_protected_entrypoint<R: Read>(
    installation_root: BorrowedFd<'_>,
    approved: &ApprovedEntrypointV2,
    source: &mut R,
) -> Result<EntrypointObjectIdentity, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(error("entrypoint installation requires root"));
    }
    let path = approved_path(approved)?;
    verify_ancestors(installation_root, &path)?;
    let parent = path
        .parent()
        .ok_or_else(|| error("entrypoint has no parent"))?;
    let parent_fd = open_in_root(
        installation_root,
        parent,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
    )?;
    let name = file_name(&path)?;
    let receipt_name = file_name(&receipt_path(&path)?)?;
    if path_exists(parent_fd.as_raw_fd(), &name)?
        || path_exists(parent_fd.as_raw_fd(), &receipt_name)?
    {
        return Err(error("entrypoint or receipt already exists"));
    }
    let mut pending = create_staging(parent_fd.as_raw_fd(), &name)?;
    let mut input_digest = Sha256::new();
    let mut count = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = source
            .read(&mut buffer)
            .map_err(|e| native_io("read source", e))?;
        if read == 0 {
            break;
        }
        count = count
            .checked_add(read as u64)
            .ok_or_else(|| error("entrypoint too large"))?;
        if count > approved.size.get() {
            return Err(error("entrypoint exceeds approved size"));
        }
        input_digest.update(&buffer[..read]);
        pending
            .file_mut()
            .write_all(&buffer[..read])
            .map_err(|e| native_io("write staging executable", e))?;
    }
    if count != approved.size.get() || input_digest.finalize().as_slice() != approved.sha256.bytes()
    {
        return Err(error("source content differs from approved entrypoint"));
    }
    pending
        .file()
        .sync_all()
        .map_err(|e| native_io("sync staging executable", e))?;
    let before = stat(pending.file().as_raw_fd())?;
    let (digest, readback_count) = hash_opened_file(pending.file(), approved.size.get())?;
    let after = stat(pending.file().as_raw_fd())?;
    if !same_change_metadata(&before, &after)
        || readback_count != count
        || digest != *approved.sha256.bytes()
    {
        return Err(error("staging executable readback mismatch"));
    }
    // SAFETY: the trusted root writer owns this freshly created inode. The
    // mode allows candidate execution but never group/other modification.
    if unsafe { libc::fchmod(pending.file().as_raw_fd(), 0o555) } == -1 {
        return Err(native_error("set final executable mode"));
    }
    pending
        .file()
        .sync_all()
        .map_err(|e| native_io("sync final executable", e))?;
    let final_stat = stat(pending.file().as_raw_fd())?;
    verify_executable_metadata(pending.file().as_raw_fd(), &final_stat)?;
    let identity = EntrypointObjectIdentity {
        device: final_stat.st_dev,
        inode: final_stat.st_ino,
        size: count,
        sha256: digest,
    };
    let staging_name = pending.name.clone();
    pending.close_writer();
    rename_no_replace(parent_fd.as_raw_fd(), &staging_name, &name)?;
    pending.open = false;

    let receipt = CreationReceiptV1 {
        version: 1,
        absolute_path: approved.absolute_path.as_str().to_owned(),
        device: identity.device,
        inode: identity.inode,
        size: identity.size,
        sha256: identity.sha256,
    };
    let bytes = serde_json::to_vec(&receipt).map_err(|e| native_io("encode receipt", e))?;
    if bytes.len() as u64 > MAX_RECEIPT_BYTES {
        return Err(error("creation receipt too large"));
    }
    let mut receipt_pending = create_staging(parent_fd.as_raw_fd(), &receipt_name)?;
    receipt_pending
        .file_mut()
        .write_all(&bytes)
        .map_err(|e| native_io("write receipt", e))?;
    receipt_pending
        .file_mut()
        .write_all(b"\n")
        .map_err(|e| native_io("finish receipt", e))?;
    receipt_pending
        .file()
        .sync_all()
        .map_err(|e| native_io("sync receipt", e))?;
    if unsafe { libc::fchmod(receipt_pending.file().as_raw_fd(), 0o400) } == -1 {
        return Err(native_error("set receipt mode"));
    }
    receipt_pending
        .file()
        .sync_all()
        .map_err(|e| native_io("sync protected receipt", e))?;
    let staging_receipt_name = receipt_pending.name.clone();
    receipt_pending.close_writer();
    rename_no_replace(parent_fd.as_raw_fd(), &staging_receipt_name, &receipt_name)?;
    receipt_pending.open = false;
    // SAFETY: fsync on the live directory fd persists both name publications.
    if unsafe { libc::fsync(parent_fd.as_raw_fd()) } == -1 {
        return Err(native_error("sync entrypoint directory"));
    }
    Ok(identity)
}

struct Staging {
    parent: RawFd,
    name: CString,
    file: Option<File>,
    open: bool,
}

impl Drop for Staging {
    fn drop(&mut self) {
        if self.open {
            // SAFETY: this name was exclusively created by this installation.
            unsafe { libc::unlinkat(self.parent, self.name.as_ptr(), 0) };
        }
    }
}

impl Staging {
    fn file(&self) -> &File {
        self.file.as_ref().expect("staging writer already closed")
    }

    fn file_mut(&mut self) -> &mut File {
        self.file.as_mut().expect("staging writer already closed")
    }

    fn close_writer(&mut self) {
        self.file.take();
    }
}

fn create_staging(parent: RawFd, target: &CStr) -> Result<Staging, String> {
    let mut nonce = [0_u8; 16];
    // SAFETY: getrandom writes at most the initialized nonce buffer length.
    if unsafe { libc::getrandom(nonce.as_mut_ptr().cast(), nonce.len(), 0) } != nonce.len() as isize
    {
        return Err(native_error("create staging nonce"));
    }
    let mut name = OsString::from(".");
    name.push(OsStr::from_bytes(target.to_bytes()));
    name.push(".memcordon-staging-");
    for byte in nonce {
        name.push(format!("{byte:02x}"));
    }
    let name = CString::new(name.into_vec()).map_err(|_| error("invalid staging name"))?;
    // SAFETY: O_EXCL and O_NOFOLLOW ensure a fresh, non-symlink inode. The
    // root-only birth mode precedes any write, regardless of the process umask.
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_RDWR | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(native_error("create staging inode"));
    }
    Ok(Staging {
        parent,
        name,
        file: Some(unsafe { File::from_raw_fd(fd) }),
        open: true,
    })
}

fn approved_path(approved: &ApprovedEntrypointV2) -> Result<PathBuf, String> {
    let path = Path::new(approved.absolute_path.as_str());
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
        || path.file_name().is_none()
    {
        return Err(error(
            "entrypoint path is not an absolute normalized file path",
        ));
    }
    Ok(path.to_owned())
}

fn receipt_path(path: &Path) -> Result<PathBuf, String> {
    let mut name = path
        .file_name()
        .ok_or_else(|| error("entrypoint filename absent"))?
        .to_os_string();
    name.push(OsStr::from_bytes(RECEIPT_SUFFIX));
    Ok(path.with_file_name(name))
}

fn file_name(path: &Path) -> Result<CString, String> {
    CString::new(
        path.file_name()
            .ok_or_else(|| error("entrypoint filename absent"))?
            .as_bytes(),
    )
    .map_err(|_| error("NUL in entrypoint filename"))
}

fn verify_ancestors(root: BorrowedFd<'_>, path: &Path) -> Result<(), String> {
    let reopened_root = open_in_root(
        root,
        Path::new("/"),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
    )?;
    let root_stat = stat(reopened_root.as_raw_fd())?;
    verify_protected_directory(reopened_root.as_raw_fd(), &root_stat)?;
    let mut prefix = PathBuf::from("/");
    for component in path
        .parent()
        .ok_or_else(|| error("entrypoint parent absent"))?
        .components()
    {
        match component {
            Component::RootDir => continue,
            Component::Normal(name) => prefix.push(name),
            _ => return Err(error("invalid entrypoint ancestor")),
        }
        let directory = open_in_root(
            root,
            &prefix,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )?;
        let metadata = stat(directory.as_raw_fd())?;
        verify_protected_directory(directory.as_raw_fd(), &metadata)?;
    }
    Ok(())
}

fn verify_protected_directory(fd: RawFd, metadata: &libc::stat) -> Result<(), String> {
    if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR
        || metadata.st_uid != 0
        || metadata.st_mode & 0o022 != 0
    {
        return Err(error("entrypoint ancestor is not root-controlled"));
    }
    reject_xattr(fd, c"system.posix_acl_access")?;
    reject_xattr(fd, c"system.posix_acl_default")?;
    Ok(())
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

fn verify_receipt_metadata(fd: RawFd, metadata: &libc::stat) -> Result<(), String> {
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
        || metadata.st_uid != 0
        || metadata.st_nlink != 1
        || metadata.st_mode & 0o377 != 0
        || metadata.st_size <= 0
        || metadata.st_size as u64 > MAX_RECEIPT_BYTES
    {
        return Err(error("creation receipt is not protected"));
    }
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

fn hash_opened_file(file: &File, limit: u64) -> Result<([u8; 32], u64), String> {
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
            return Err(error("ELF exceeds approved byte count"));
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

fn read_receipt(file: File) -> Result<CreationReceiptV1, String> {
    let mut bytes = Vec::new();
    file.take(MAX_RECEIPT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| native_io("read creation receipt", e))?;
    if bytes.len() as u64 > MAX_RECEIPT_BYTES {
        return Err(error("creation receipt exceeds bound"));
    }
    serde_json::from_slice(&bytes).map_err(|e| native_io("decode creation receipt", e))
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

fn open_in_root(root: BorrowedFd<'_>, path: &Path, flags: i32) -> Result<File, String> {
    let relative = path
        .strip_prefix("/")
        .map_err(|_| error("path must be absolute"))?;
    let name = if relative.as_os_str().is_empty() {
        CString::new(".").expect("static path has no NUL")
    } else {
        CString::new(relative.as_os_str().as_bytes()).map_err(|_| error("NUL in path"))?
    };
    let how = OpenHow {
        flags: flags as u64,
        mode: 0,
        resolve: RESOLUTION,
    };
    // SAFETY: openat2 receives a live trusted root fd, valid path and UAPI
    // struct; kernel resolves every component under that root without links.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            name.as_ptr(),
            &raw const how,
            size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        Err(native_error("open protected path"))
    } else {
        Ok(unsafe { File::from_raw_fd(fd as RawFd) })
    }
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

fn path_exists(parent: RawFd, name: &CStr) -> Result<bool, String> {
    let mut value = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstatat writes the stat on success and does not follow links.
    let result = unsafe {
        libc::fstatat(
            parent,
            name.as_ptr(),
            value.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        Ok(true)
    } else if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
        Ok(false)
    } else {
        Err(native_error("inspect publication path"))
    }
}

fn rename_no_replace(parent: RawFd, old: &CStr, new: &CStr) -> Result<(), String> {
    // SAFETY: both names are local to the same protected directory; the
    // kernel's NOREPLACE flag prevents adoption or overwrite of any inode.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            parent,
            old.as_ptr(),
            parent,
            new.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == -1 {
        Err(native_error("publish protected object"))
    } else {
        Ok(())
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
