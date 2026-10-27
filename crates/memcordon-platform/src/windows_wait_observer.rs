//! Isolated diagnostic process ownership. No helper mutation capability is inherited.
use super::{ProcessIdentity, windows_held_file_metadata};
use memcordon_core::WindowsCallerTokenEnvelopeV1;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;
use windows_sys::Win32::{
    Foundation::*,
    Security::*,
    Storage::FileSystem::*,
    System::{Diagnostics::ToolHelp::*, JobObjects::*, Memory::*, Pipes::*, Threading::*},
};

const REQUEST_BYTES: usize = 16 * 1024;
const OUTPUT_BYTES: usize = 128 * 1024;
const THREADS: usize = 64;
pub const WINDOWS_WAIT_OBSERVER_BOUND: usize = 64;
const LEDGER_BOUND: usize = WINDOWS_WAIT_OBSERVER_BOUND;

#[cfg(test)]
#[path = "../tests/private/windows_wait_observer.rs"]
mod tests;

pub(super) struct WaitThreadOwner {
    pub(super) handle: OwnedHandle,
    pub(super) tid: u32,
    pub(super) birth: u64,
}

pub struct WindowsWaitObserverSnapshot {
    pub(super) process: OwnedHandle,
    pub(super) identity: ProcessIdentity,
    pub(super) threads: Vec<WaitThreadOwner>,
    pub(super) omitted_threads: usize,
    pub(super) deadline: Instant,
}

#[derive(Clone, Debug)]
pub struct WindowsWaitThreadHandle {
    pub handle: u64,
    pub tid: u32,
    pub birth: u64,
}
#[derive(Clone, Debug)]
pub struct WindowsWaitInherited {
    pub process_handle: u64,
    pub process: ProcessIdentity,
    pub threads: Vec<WindowsWaitThreadHandle>,
    pub omitted_threads: usize,
}
#[derive(Clone, Debug)]
pub struct WindowsWaitObserverRetirement {
    pub identity: ProcessIdentity,
    pub native_exit_status: u32,
    pub job_empty: bool,
    pub forced: bool,
    pub observed_qpc: u64,
    pub qpc_frequency: u64,
}

fn live(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "original isolated observer cutoff exhausted",
        ))
    } else {
        Ok(())
    }
}
fn owned(raw: HANDLE) -> io::Result<OwnedHandle> {
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: callers pass a newly returned native owner exactly once.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}
fn duplicate(handle: HANDLE, access: u32, inherit: bool) -> io::Result<OwnedHandle> {
    let mut raw = std::ptr::null_mut();
    // SAFETY: duplicate only an original retained handle into this process.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle,
            GetCurrentProcess(),
            &mut raw,
            access,
            i32::from(inherit),
            0,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    owned(raw)
}
fn ticks(value: FILETIME) -> u128 {
    (u128::from(value.dwHighDateTime) << 32) | u128::from(value.dwLowDateTime)
}
fn process_identity(handle: HANDLE) -> io::Result<ProcessIdentity> {
    let mut birth = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: retained process handle and initialized fixed outputs.
    let pid = unsafe { GetProcessId(handle) };
    if pid == 0
        || unsafe { GetProcessTimes(handle, &mut birth, &mut exit, &mut kernel, &mut user) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(ProcessIdentity {
        pid,
        birth: ticks(birth),
    })
}
fn signaled(handle: HANDLE) -> io::Result<bool> {
    // SAFETY: zero-duration observation on a continuously retained process owner.
    match unsafe { WaitForSingleObject(handle, 0) } {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        _ => Err(io::Error::last_os_error()),
    }
}
fn token(process: HANDLE) -> io::Result<OwnedHandle> {
    let mut raw = std::ptr::null_mut();
    // SAFETY: query-only token open on this retained process.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    owned(raw)
}
fn envelope(token: HANDLE) -> io::Result<WindowsCallerTokenEnvelopeV1> {
    memcordon_windows_launch_core::query_token_envelope(token).map_err(io::Error::other)
}
fn caller_token() -> io::Result<(OwnedHandle, WindowsCallerTokenEnvelopeV1)> {
    let mut thread = std::ptr::null_mut();
    // SAFETY: inspect effective caller authority; never substitute on unexpected failure.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut thread) } != 0 {
        drop(owned(thread)?);
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "isolated observer requires original process-token authority",
        ));
    }
    let cause = io::Error::last_os_error();
    if cause.raw_os_error() != Some(ERROR_NO_TOKEN as i32) {
        return Err(cause);
    }
    let token = token(unsafe { GetCurrentProcess() })?;
    let mut luid = LUID::default();
    let name: Vec<u16> = "SeDebugPrivilege".encode_utf16().chain(Some(0)).collect();
    // SAFETY: fixed privilege query, no privilege adjustment.
    if unsafe { LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut bytes = 0;
    // SAFETY: bounded TokenPrivileges size query; no privilege checking/adjustment side effects.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenPrivileges,
            std::ptr::null_mut(),
            0,
            &mut bytes,
        );
    }
    if bytes == 0 || bytes as usize > 64 * 1024 {
        return Err(io::Error::other(
            "observer token privilege query bound differs",
        ));
    }
    let mut storage = vec![0usize; (bytes as usize).div_ceil(std::mem::size_of::<usize>())];
    let capacity = bytes;
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenPrivileges,
            storage.as_mut_ptr().cast(),
            capacity,
            &mut bytes,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let offset = std::mem::offset_of!(TOKEN_PRIVILEGES, Privileges);
    if bytes > capacity || (bytes as usize) < offset {
        return Err(io::Error::other("observer token privilege extent differs"));
    }
    let count = unsafe { std::ptr::read_unaligned(storage.as_ptr().cast::<u32>()) } as usize;
    let extent = count
        .checked_mul(std::mem::size_of::<LUID_AND_ATTRIBUTES>())
        .and_then(|length| offset.checked_add(length))
        .ok_or_else(|| io::Error::other("observer token privilege extent overflow"))?;
    if extent > bytes as usize {
        return Err(io::Error::other(
            "observer token privilege inventory truncated",
        ));
    }
    let mut enabled = false;
    let mut matches = 0usize;
    for index in 0..count {
        let item = unsafe {
            std::ptr::read_unaligned(
                storage
                    .as_ptr()
                    .cast::<u8>()
                    .add(offset + index * std::mem::size_of::<LUID_AND_ATTRIBUTES>())
                    .cast::<LUID_AND_ATTRIBUTES>(),
            )
        };
        if item.Luid.LowPart == luid.LowPart && item.Luid.HighPart == luid.HighPart {
            matches += 1;
            enabled = item.Attributes & SE_PRIVILEGE_ENABLED != 0;
        }
    }
    if !enabled || matches != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "isolated observer requires already-enabled SeDebugPrivilege",
        ));
    }
    let facts = envelope(token.as_raw_handle())?;
    Ok((token, facts))
}

struct Attributes {
    words: Vec<usize>,
    initialized: bool,
}
impl Attributes {
    fn new(handles: &[HANDLE]) -> io::Result<Self> {
        let mut bytes = 0;
        // SAFETY: documented size query has no initialized list to destroy.
        unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut bytes);
        }
        if bytes == 0 || bytes > REQUEST_BYTES {
            return Err(io::Error::other("handle-list bound differs"));
        }
        let mut result = Self {
            words: vec![0; bytes.div_ceil(std::mem::size_of::<usize>())],
            initialized: false,
        };
        // SAFETY: aligned allocation meets queried extent and lives through CreateProcess.
        if unsafe {
            InitializeProcThreadAttributeList(result.words.as_mut_ptr().cast(), 1, 0, &mut bytes)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        result.initialized = true;
        if unsafe {
            UpdateProcThreadAttribute(
                result.words.as_mut_ptr().cast(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast(),
                std::mem::size_of_val(handles),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(result)
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: only successfully initialized lists are constructed by new.
        if self.initialized {
            unsafe {
                DeleteProcThreadAttributeList(self.words.as_mut_ptr().cast());
            }
        }
    }
}

struct NativeOwner {
    process: OwnedHandle,
    thread: OwnedHandle,
    job: OwnedHandle,
    assigned: bool,
    _reservation: Reservation,
}
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
static HANDED_OFF: AtomicBool = AtomicBool::new(false);
struct Reservation;
impl Reservation {
    fn acquire() -> io::Result<Self> {
        ACTIVE
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < LEDGER_BOUND).then_some(count + 1)
            })
            .map(|_| Self)
            .map_err(|_| io::Error::other("isolated observer owner bound exhausted"))
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        ACTIVE.fetch_sub(1, Ordering::AcqRel);
    }
}
struct UnresolvedOwner {
    native: NativeOwner,
    _image: Option<File>,
    _snapshot: Option<WindowsWaitObserverSnapshot>,
}
fn ledger() -> &'static Mutex<Vec<UnresolvedOwner>> {
    static OWNERS: OnceLock<Mutex<Vec<UnresolvedOwner>>> = OnceLock::new();
    OWNERS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Nonblocking observation of the same transferred native owners. A prior
/// handoff remains failed even if a later observation can finally release them.
pub fn windows_observe_transferred_wait_cleanup() -> io::Result<()> {
    let mut owners = ledger().lock().unwrap_or_else(|cause| cause.into_inner());
    let mut index = 0;
    while index < owners.len() {
        let owner = &owners[index].native;
        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        let empty = unsafe {
            QueryInformationJobObject(
                owner.job.as_raw_handle(),
                JobObjectBasicAccountingInformation,
                (&raw mut accounting).cast(),
                std::mem::size_of_val(&accounting) as u32,
                std::ptr::null_mut(),
            )
        } != 0
            && accounting.ActiveProcesses == 0;
        if signaled(owner.process.as_raw_handle()).unwrap_or(false) && empty {
            owners.swap_remove(index);
        } else {
            index += 1;
        }
    }
    if HANDED_OFF.load(Ordering::Acquire) {
        Err(io::Error::other(format!(
            "isolated observer cleanup handoff remains failed; unresolved={}",
            owners.len()
        )))
    } else {
        Ok(())
    }
}

pub fn windows_unresolved_wait_owner_count() -> usize {
    ledger()
        .lock()
        .unwrap_or_else(|cause| cause.into_inner())
        .len()
}
pub struct WindowsWaitObserver {
    native: Option<NativeOwner>,
    image: Option<File>,
    image_path: PathBuf,
    snapshot: Option<WindowsWaitObserverSnapshot>,
    _inherited: Vec<OwnedHandle>,
    _mapping: OwnedHandle,
    output: OwnedHandle,
    caller_token: OwnedHandle,
    caller: WindowsCallerTokenEnvelopeV1,
    parent: ProcessIdentity,
    identity: Option<ProcessIdentity>,
    work: Instant,
    cleanup: Instant,
    output_bytes: usize,
    started: bool,
    failed: bool,
    forced: bool,
    retirement: Option<WindowsWaitObserverRetirement>,
}

impl WindowsWaitObserver {
    /// Observe only the actual created diagnostic process, never a reopened PID.
    pub fn identity(&self) -> io::Result<ProcessIdentity> {
        live(self.work)?;
        let native = self
            .native
            .as_ref()
            .ok_or_else(|| io::Error::other("observer owner absent"))?;
        let identity = process_identity(native.process.as_raw_handle())?;
        live(self.work)?;
        Ok(identity)
    }

    pub fn prepare(
        path: &Path,
        image: &File,
        snapshot: WindowsWaitObserverSnapshot,
        work: Instant,
        cleanup: Instant,
        build: impl FnOnce(&WindowsWaitInherited) -> io::Result<Vec<u8>>,
    ) -> io::Result<Self> {
        let work = work.min(snapshot.deadline);
        live(work)?;
        if cleanup < work || snapshot.threads.len() > THREADS {
            return Err(io::Error::other(
                "observer original clock or thread bound differs",
            ));
        }
        if HANDED_OFF.load(Ordering::Acquire) {
            return Err(io::Error::other(
                "unresolved isolated observer ownership remains",
            ));
        }
        let reservation = Reservation::acquire()?;
        let (caller_token, caller) = caller_token()?;
        let parent = process_identity(unsafe { GetCurrentProcess() })?;
        let image_path = path.to_owned();
        let named = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        same_image(image, &named, work)?;
        // Retain the independently identity-checked named pin without write/delete
        // sharing through observer settlement. CI separately retains its selected owner.
        let image = named;
        let process = duplicate(
            snapshot.process.as_raw_handle(),
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            true,
        )?;
        let mut inherited = vec![process];
        let mut threads = Vec::new();
        for original in &snapshot.threads {
            live(work)?;
            let handle = duplicate(
                original.handle.as_raw_handle(),
                THREAD_QUERY_LIMITED_INFORMATION | THREAD_SYNCHRONIZE,
                true,
            )?;
            threads.push(WindowsWaitThreadHandle {
                handle: handle.as_raw_handle() as usize as u64,
                tid: original.tid,
                birth: original.birth,
            });
            inherited.push(handle);
        }
        let request = build(&WindowsWaitInherited {
            process_handle: inherited[0].as_raw_handle() as usize as u64,
            process: snapshot.identity,
            threads,
            omitted_threads: snapshot.omitted_threads,
        })?;
        let prefix = std::mem::size_of::<u32>();
        if request.is_empty() || request.len() > REQUEST_BYTES - prefix {
            return Err(io::Error::other("observer request exceeds fixed bound"));
        }
        // SAFETY: anonymous mapping, bounded extent, no name/ambient capability.
        let writable = owned(unsafe {
            CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                std::ptr::null(),
                PAGE_READWRITE,
                0,
                REQUEST_BYTES as u32,
                std::ptr::null(),
            )
        })?;
        let view = unsafe {
            MapViewOfFile(
                writable.as_raw_handle(),
                FILE_MAP_WRITE,
                0,
                0,
                REQUEST_BYTES,
            )
        };
        if view.Value.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: initialized mapping extent is REQUEST_BYTES; request occupies its bounded prefix.
        unsafe {
            std::ptr::write_bytes(view.Value.cast::<u8>(), 0, REQUEST_BYTES);
            std::ptr::copy_nonoverlapping(
                (request.len() as u32).to_le_bytes().as_ptr(),
                view.Value.cast(),
                prefix,
            );
            std::ptr::copy_nonoverlapping(
                request.as_ptr(),
                view.Value.cast::<u8>().add(prefix),
                request.len(),
            );
        }
        // SAFETY: this exact view is no longer used after unmapping.
        if unsafe { UnmapViewOfFile(view) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mapping = duplicate(writable.as_raw_handle(), FILE_MAP_READ, true)?;
        drop(writable);
        let mut reader = std::ptr::null_mut();
        let mut writer = std::ptr::null_mut();
        let security = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: 1,
        };
        // SAFETY: two owned anonymous pipe ends, no request writes or namespace.
        if unsafe { CreatePipe(&mut reader, &mut writer, &security, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let output = owned(reader)?;
        let writer = owned(writer)?;
        if unsafe { SetHandleInformation(output.as_raw_handle(), HANDLE_FLAG_INHERIT, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut handles: Vec<HANDLE> = inherited.iter().map(AsRawHandle::as_raw_handle).collect();
        handles.push(mapping.as_raw_handle());
        handles.push(writer.as_raw_handle());
        let mut attributes = Attributes::new(&handles)?;
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        startup.lpAttributeList = attributes.words.as_mut_ptr().cast();
        let job = owned(unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) })?;
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if unsafe {
            SetInformationJobObject(
                job.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                std::mem::size_of_val(&limits) as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut application: Vec<u16> = path.as_os_str().encode_wide().take(32_769).collect();
        if application.is_empty() || application.len() > 32_767 || application.contains(&0) {
            return Err(io::Error::other("observer selected path is invalid"));
        }
        application.push(0);
        let arguments = [
            path.as_os_str().to_owned(),
            "observe-toolchain-wait".into(),
            "--request-mapping".into(),
            (mapping.as_raw_handle() as usize).to_string().into(),
            "--output".into(),
            (writer.as_raw_handle() as usize).to_string().into(),
            "--protocol".into(),
            "2".into(),
        ];
        let arguments: Vec<Vec<u16>> = arguments
            .iter()
            .map(|argument: &std::ffi::OsString| argument.encode_wide().collect())
            .collect();
        let mut command = memcordon_core::encode_windows_command_line(&arguments);
        command.push(0);
        let mut result = PROCESS_INFORMATION::default();
        live(work)?;
        // SAFETY: fixed argv encoding, explicit closed inheritance list, selected application,
        // and suspended primary thread. Every output owner is adopted immediately below.
        if unsafe {
            memcordon_windows_launch_core::create_process_native(
                application.as_ptr(),
                command.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
                CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
                std::ptr::null(),
                std::ptr::null(),
                &startup.StartupInfo,
                &mut result,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful CreateProcess transfers these two non-null handles. No fallible
        // operation follows creation before this callback-independent owner is returned.
        let native = NativeOwner {
            process: unsafe { OwnedHandle::from_raw_handle(result.hProcess) },
            thread: unsafe { OwnedHandle::from_raw_handle(result.hThread) },
            job,
            assigned: false,
            _reservation: reservation,
        };
        Ok(Self {
            native: Some(native),
            image: Some(image),
            image_path,
            snapshot: Some(snapshot),
            _inherited: inherited,
            _mapping: mapping,
            output,
            caller_token,
            caller,
            parent,
            identity: None,
            work,
            cleanup,
            output_bytes: 0,
            started: false,
            failed: false,
            forced: false,
            retirement: None,
        })
    }

    pub fn start(&mut self) -> io::Result<()> {
        if self.started || self.failed {
            return Err(io::Error::other("observer start already consumed"));
        }
        let result = self.start_inner();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn start_inner(&mut self) -> io::Result<()> {
        live(self.work)?;
        let native = self
            .native
            .as_mut()
            .ok_or_else(|| io::Error::other("observer owner absent"))?;
        let image = self
            .image
            .as_ref()
            .ok_or_else(|| io::Error::other("observer image owner absent"))?;
        let snapshot = self
            .snapshot
            .as_ref()
            .ok_or_else(|| io::Error::other("observer snapshot owner absent"))?;
        if unsafe {
            AssignProcessToJobObject(native.job.as_raw_handle(), native.process.as_raw_handle())
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        native.assigned = true;
        let identity = process_identity(native.process.as_raw_handle())?;
        self.identity = Some(identity);
        if process_identity(unsafe { GetCurrentProcess() })? != self.parent {
            return Err(io::Error::other("observer original parent differs"));
        }
        verify_parent(identity.pid, self.parent.pid, self.work)?;
        let mut units = vec![0u16; 32_768];
        let mut length = units.len() as u32;
        if unsafe {
            QueryFullProcessImageNameW(
                native.process.as_raw_handle(),
                0,
                units.as_mut_ptr(),
                &mut length,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        units.truncate(length as usize);
        let actual_path = PathBuf::from(std::ffi::OsString::from_wide(&units));
        let actual = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&actual_path)?;
        same_image(image, &actual, self.work)?;
        let named = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&self.image_path)?;
        same_image(image, &named, self.work)?;
        let child_token = token(native.process.as_raw_handle())?;
        if envelope(child_token.as_raw_handle())? != self.caller
            || envelope(self.caller_token.as_raw_handle())? != self.caller
        {
            return Err(io::Error::other("observer actual token envelope differs"));
        }
        if process_identity(snapshot.process.as_raw_handle())? != snapshot.identity
            || signaled(snapshot.process.as_raw_handle())?
        {
            return Err(io::Error::other(
                "observer original helper changed or retired",
            ));
        }
        live(self.work)?;
        // SAFETY: exact original suspended primary thread, exactly one resume attempt.
        self.started = true;
        if unsafe { ResumeThread(native.thread.as_raw_handle()) } != 1 {
            return Err(io::Error::other("observer primary resume count differs"));
        }
        live(self.work)
    }
    pub fn poll_available(&mut self, work: Instant) -> io::Result<Vec<u8>> {
        let result = self.poll_inner(work.min(self.work));
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    /// Request containment of only the owned observer. This is not process or
    /// Job retirement proof; `finish` must still run under original cleanup.
    pub fn request_stop(&mut self) -> io::Result<()> {
        let result = (|| {
            live(self.cleanup)?;
            let native = self
                .native
                .as_ref()
                .ok_or_else(|| io::Error::other("observer owner absent"))?;
            self.forced = true;
            // SAFETY: only this diagnostic Job/original created process is targeted.
            let success = if native.assigned {
                unsafe { TerminateJobObject(native.job.as_raw_handle(), 1) }
            } else {
                unsafe { TerminateProcess(native.process.as_raw_handle(), 1) }
            };
            if success == 0 {
                return Err(io::Error::last_os_error());
            }
            live(self.cleanup)
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn poll_inner(&mut self, work: Instant) -> io::Result<Vec<u8>> {
        live(work)?;
        let mut available = 0;
        // SAFETY: query available bytes only; never block waiting for a frame.
        if unsafe {
            PeekNamedPipe(
                self.output.as_raw_handle(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        } == 0
        {
            let cause = io::Error::last_os_error();
            if cause.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
                return Ok(Vec::new());
            }
            return Err(cause);
        }
        let amount = available as usize;
        if amount > OUTPUT_BYTES.saturating_sub(self.output_bytes) {
            return Err(io::Error::other("observer aggregate output bound exceeded"));
        }
        if amount == 0 {
            return Ok(Vec::new());
        }
        let mut bytes = vec![0; amount];
        let mut read = 0;
        live(work)?;
        // SAFETY: single reader consumes no more than the immediately observed available extent.
        if unsafe {
            ReadFile(
                self.output.as_raw_handle(),
                bytes.as_mut_ptr(),
                available,
                &mut read,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        bytes.truncate(read as usize);
        self.output_bytes += bytes.len();
        live(work)?;
        Ok(bytes)
    }

    pub fn finish(&mut self, cleanup: Instant) -> io::Result<WindowsWaitObserverRetirement> {
        let result = self.finish_inner(cleanup);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn finish_inner(&mut self, cleanup: Instant) -> io::Result<WindowsWaitObserverRetirement> {
        let cleanup = cleanup.min(self.cleanup);
        if let Some(result) = &self.retirement {
            return if self.failed {
                Err(io::Error::other("observer failure remains sticky"))
            } else {
                Ok(result.clone())
            };
        }
        let native = self
            .native
            .as_ref()
            .ok_or_else(|| io::Error::other("observer owner absent"))?;
        if !signaled(native.process.as_raw_handle())? {
            self.forced = true;
            // SAFETY: only this diagnostic Job/process is mutable, never helper/compiler owners.
            let success = if native.assigned {
                unsafe { TerminateJobObject(native.job.as_raw_handle(), 1) }
            } else {
                unsafe { TerminateProcess(native.process.as_raw_handle(), 1) }
            };
            if success == 0 {
                self.failed = true;
                return Err(io::Error::last_os_error());
            }
        }
        loop {
            if let Err(cause) = live(cleanup) {
                self.failed = true;
                return Err(cause);
            }
            let exited = signaled(native.process.as_raw_handle())?;
            let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
            if unsafe {
                QueryInformationJobObject(
                    native.job.as_raw_handle(),
                    JobObjectBasicAccountingInformation,
                    (&raw mut accounting).cast(),
                    std::mem::size_of_val(&accounting) as u32,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                self.failed = true;
                return Err(io::Error::last_os_error());
            }
            live(cleanup).inspect_err(|_| self.failed = true)?;
            if exited && accounting.ActiveProcesses == 0 {
                let mut code = 0;
                if unsafe { GetExitCodeProcess(native.process.as_raw_handle(), &mut code) } == 0 {
                    self.failed = true;
                    return Err(io::Error::last_os_error());
                }
                let identity = process_identity(native.process.as_raw_handle())?;
                if self.identity.is_some_and(|expected| expected != identity) {
                    return Err(io::Error::other(
                        "observer original child birth differs at retirement",
                    ));
                }
                live(cleanup).inspect_err(|_| self.failed = true)?;
                let (observed_qpc, qpc_frequency) = super::windows_performance_counter()?;
                live(cleanup)?;
                let result = WindowsWaitObserverRetirement {
                    identity,
                    native_exit_status: code,
                    job_empty: true,
                    forced: self.forced,
                    observed_qpc,
                    qpc_frequency,
                };
                self.retirement = Some(result.clone());
                self.native.take();
                return if self.failed {
                    Err(io::Error::other("observer failed before native retirement"))
                } else {
                    Ok(result)
                };
            }
            std::thread::yield_now();
        }
    }
}
impl Drop for WindowsWaitObserver {
    fn drop(&mut self) {
        if let Some(native) = self.native.take() {
            HANDED_OFF.store(true, Ordering::Release);
            // SAFETY: fallback containment is never reported as retirement proof.
            unsafe {
                if native.assigned {
                    TerminateJobObject(native.job.as_raw_handle(), 1);
                } else {
                    TerminateProcess(native.process.as_raw_handle(), 1);
                }
            }
            let mut owners = ledger().lock().unwrap_or_else(|cause| cause.into_inner());
            if owners.len() >= LEDGER_BOUND {
                std::process::abort();
            }
            owners.push(UnresolvedOwner {
                native,
                _image: self.image.take(),
                _snapshot: self.snapshot.take(),
            });
        }
    }
}
fn verify_parent(child: u32, parent: u32, deadline: Instant) -> io::Result<()> {
    let snapshot = owned(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) })?;
    let mut entry = PROCESSENTRY32W::default();
    entry.dwSize = std::mem::size_of_val(&entry) as u32;
    let mut next = unsafe { Process32FirstW(snapshot.as_raw_handle(), &mut entry) };
    for _ in 0..131_072 {
        live(deadline)?;
        if next == 0 {
            return Err(io::Error::other("observer actual parent not observed"));
        }
        if entry.th32ProcessID == child {
            live(deadline)?;
            return if entry.th32ParentProcessID == parent {
                Ok(())
            } else {
                Err(io::Error::other("observer actual parent PID differs"))
            };
        }
        next = unsafe { Process32NextW(snapshot.as_raw_handle(), &mut entry) };
    }
    Err(io::Error::other("observer parent scan bound exceeded"))
}
fn same_image(expected: &File, actual: &File, deadline: Instant) -> io::Result<()> {
    use sha2::{Digest, Sha256};
    use std::os::windows::fs::FileExt;
    live(deadline)?;
    let left = windows_held_file_metadata(expected)?;
    live(deadline)?;
    let right = windows_held_file_metadata(actual)?;
    live(deadline)?;
    let stamp = |value: &super::WindowsHeldFileMetadata| {
        (
            value.volume_serial,
            value.file_index,
            value.length,
            value.attributes,
            value.links,
        )
    };
    if stamp(&left) != stamp(&right)
        || left.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || left.links != 1
        || left.length == 0
        || left.length > 128 * 1024 * 1024
    {
        return Err(io::Error::other(
            "observer suspended image native identity differs",
        ));
    }
    let hash = |file: &File| -> io::Result<[u8; 32]> {
        let mut result = Sha256::new();
        let mut offset = 0;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            live(deadline)?;
            let count = file.seek_read(&mut buffer, offset)?;
            if count == 0 {
                break;
            }
            result.update(&buffer[..count]);
            offset += count as u64;
            if offset > left.length {
                return Err(io::Error::other("observer image grew"));
            }
        }
        if offset != left.length {
            return Err(io::Error::other("observer image length differs"));
        }
        Ok(result.finalize().into())
    };
    if hash(expected)? != hash(actual)?
        || stamp(&windows_held_file_metadata(expected)?) != stamp(&left)
        || stamp(&windows_held_file_metadata(actual)?) != stamp(&right)
    {
        return Err(io::Error::other("observer suspended image bytes changed"));
    }
    live(deadline)
}
