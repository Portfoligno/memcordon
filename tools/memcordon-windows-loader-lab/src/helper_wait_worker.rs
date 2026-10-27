//! Synchronous WCT is confined to the separately owned diagnostic process.
use crate::helper_wait_protocol as wire;
#[path = "helper_wait_binding.rs"]
mod binding;
use std::{
    ffi::c_void,
    fs::File,
    io::{self, Write},
    mem::{offset_of, size_of},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{ERROR_MORE_DATA, ERROR_NO_TOKEN, ERROR_TOO_MANY_THREADS, FILETIME, HANDLE},
    Security::{
        GetTokenInformation, LookupPrivilegeValueW, TOKEN_PRIVILEGES, TOKEN_QUERY, TokenPrivileges,
    },
    System::{
        Diagnostics::Debug::{
            CloseThreadWaitChainSession, GetThreadWaitChain, OpenThreadWaitChainSession,
            WAITCHAIN_NODE_INFO, WCT_OUT_OF_PROC_CS_FLAG, WCT_OUT_OF_PROC_FLAG,
        },
        Memory::{FILE_MAP_READ, MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFile, UnmapViewOfFile},
        Performance::{QueryPerformanceCounter, QueryPerformanceFrequency},
        Threading::{
            CreateThread, GetCurrentProcess, GetCurrentThread, GetProcessId, GetProcessTimes,
            OpenProcessToken, OpenThreadToken, TerminateProcess, WaitForSingleObject,
        },
    },
};

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "helper wait native binding differs",
    )
}
fn clock(frequency: u64) -> io::Result<u64> {
    let (mut value, mut actual) = (0, 0);
    // SAFETY: both native output scalars remain valid for these calls.
    if unsafe { QueryPerformanceCounter(&mut value) } == 0
        || unsafe { QueryPerformanceFrequency(&mut actual) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let actual = u64::try_from(actual).map_err(|_| invalid())?;
    if actual != frequency || frequency == 0 {
        return Err(invalid());
    }
    u64::try_from(value).map_err(|_| invalid())
}
fn live(request: &wire::Request) -> io::Result<u64> {
    let value = clock(request.frequency)?;
    if value >= request.work_cutoff_qpc {
        return Err(io::ErrorKind::TimedOut.into());
    }
    Ok(value)
}
fn ticks(time: FILETIME) -> u64 {
    (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime)
}
fn self_identity() -> io::Result<wire::Identity> {
    let (mut birth, mut exit, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: query the diagnostic process itself, never reopen a PID.
    let pid = unsafe { GetProcessId(GetCurrentProcess()) };
    if pid == 0
        || unsafe {
            GetProcessTimes(
                GetCurrentProcess(),
                &mut birth,
                &mut exit,
                &mut kernel,
                &mut user,
            )
        } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(wire::Identity {
        pid,
        birth: u128::from(ticks(birth)),
    })
}

struct View(MEMORY_MAPPED_VIEW_ADDRESS);
impl Drop for View {
    fn drop(&mut self) {
        // SAFETY: this exact view remains owned and is unmapped once.
        unsafe { UnmapViewOfFile(self.0) };
    }
}
fn read_request(mapping: &OwnedHandle) -> io::Result<wire::Request> {
    // SAFETY: request is read-only, bounded to the fixed native mapping extent.
    let raw = unsafe {
        MapViewOfFile(
            mapping.as_raw_handle(),
            FILE_MAP_READ,
            0,
            0,
            wire::MAPPING_BOUND,
        )
    };
    if raw.Value.is_null() {
        return Err(io::Error::last_os_error());
    }
    let view = View(raw);
    // SAFETY: successful MapViewOfFile admitted this exact readable extent.
    let bytes =
        unsafe { std::slice::from_raw_parts(view.0.Value.cast::<u8>(), wire::MAPPING_BOUND) };
    let prefix = size_of::<u32>();
    let length = usize::try_from(u32::from_le_bytes(
        bytes[..prefix].try_into().map_err(|_| invalid())?,
    ))
    .map_err(|_| invalid())?;
    if length == 0
        || length > wire::REQUEST_BOUND
        || bytes[prefix + length..].iter().any(|byte| *byte != 0)
    {
        return Err(invalid());
    }
    wire::Request::decode(&bytes[prefix..prefix + length])
}

struct Watchdog {
    cutoff: u64,
    frequency: u64,
}
unsafe extern "system" fn watchdog(context: *mut c_void) -> u32 {
    // SAFETY: CreateThread owns exactly this Box after successful creation.
    let state = unsafe { Box::from_raw(context.cast::<Watchdog>()) };
    loop {
        let now = clock(state.frequency);
        if !now.as_ref().is_ok_and(|now| *now < state.cutoff) {
            // SAFETY: only this diagnostic process is terminated. No target handle is used.
            unsafe { TerminateProcess(GetCurrentProcess(), 0xe057_4354) };
            std::process::abort();
        }
        let remaining = state.cutoff - now.expect("checked original clock");
        let milliseconds = (u128::from(remaining) * 1000)
            .div_ceil(u128::from(state.frequency))
            .clamp(1, 1000) as u32;
        // SAFETY: finite wait on this diagnostic process itself, never target work.
        unsafe { WaitForSingleObject(GetCurrentProcess(), milliseconds) };
    }
}
fn arm_watchdog(request: &wire::Request) -> io::Result<OwnedHandle> {
    live(request)?;
    let state = Box::into_raw(Box::new(Watchdog {
        cutoff: request.work_cutoff_qpc,
        frequency: request.frequency,
    }));
    // SAFETY: native thread receives only its heap-owned immutable original cutoff.
    let raw = unsafe {
        CreateThread(
            ptr::null(),
            0,
            Some(watchdog),
            state.cast(),
            0,
            ptr::null_mut(),
        )
    };
    if raw.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: failed CreateThread never acquired the allocation.
        drop(unsafe { Box::from_raw(state) });
        return Err(error);
    }
    // SAFETY: successful native thread handle is uniquely owned; no join occurs.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

fn debug_enabled() -> io::Result<bool> {
    let mut token = ptr::null_mut();
    // SAFETY: query actual thread authority first; existing impersonation is unsupported.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } != 0 {
        // SAFETY: successful query handle is closed without adjusting any token.
        drop(unsafe { OwnedHandle::from_raw_handle(token) });
        return Ok(false);
    }
    if io::Error::last_os_error().raw_os_error() != Some(ERROR_NO_TOKEN as i32) {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: query only this process token after ERROR_NO_TOKEN.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: native token query ownership is unique.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut needed = 0;
    // SAFETY: sizing only, no output buffer.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenPrivileges,
            ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    if needed as usize > 64 * 1024 || (needed as usize) < offset_of!(TOKEN_PRIVILEGES, Privileges) {
        return Err(invalid());
    }
    let mut storage = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    let capacity = needed;
    // SAFETY: aligned bounded token storage, valid returned-length scalar.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenPrivileges,
            storage.as_mut_ptr().cast(),
            capacity,
            &mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if needed > capacity || (needed as usize) < offset_of!(TOKEN_PRIVILEGES, Privileges) {
        return Err(invalid());
    }
    let privileges = storage.as_ptr().cast::<TOKEN_PRIVILEGES>();
    // SAFETY: fixed header admitted above.
    let count = unsafe { (*privileges).PrivilegeCount } as usize;
    let entry = size_of::<windows_sys::Win32::Security::LUID_AND_ATTRIBUTES>();
    if count > 512
        || count
            .checked_mul(entry)
            .and_then(|n| n.checked_add(offset_of!(TOKEN_PRIVILEGES, Privileges)))
            .is_none_or(|n| n > needed as usize)
    {
        return Err(invalid());
    }
    let name: Vec<u16> = "SeDebugPrivilege".encode_utf16().chain(Some(0)).collect();
    let mut expected = Default::default();
    // SAFETY: fixed terminated privilege name and complete LUID output.
    if unsafe { LookupPrivilegeValueW(ptr::null(), name.as_ptr(), &mut expected) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: complete bounded count of native privilege entries admitted above.
    let entries = unsafe {
        std::slice::from_raw_parts(
            std::ptr::addr_of!((*privileges).Privileges)
                .cast::<windows_sys::Win32::Security::LUID_AND_ATTRIBUTES>(),
            count,
        )
    };
    Ok(entries.iter().any(|p| {
        p.Luid.LowPart == expected.LowPart
            && p.Luid.HighPart == expected.HighPart
            && p.Attributes & 2 != 0
    }))
}

struct Writer {
    file: File,
    binding: [u8; 32],
    sequence: u32,
    total: usize,
}
impl Writer {
    fn send(&mut self, request: &wire::Request, result: wire::ResultKind) -> io::Result<()> {
        let qpc = live(request)?;
        let frame = wire::Frame {
            binding: self.binding,
            sequence: self.sequence,
            qpc,
            result,
        };
        let bytes = frame.encode()?;
        self.total = self
            .total
            .checked_add(bytes.len())
            .filter(|n| *n <= wire::OUTPUT_BOUND)
            .ok_or_else(invalid)?;
        // A blocked child writer remains inside the diagnostic Job/watchdog.
        self.file.write_all(&bytes)?;
        live(request)?;
        self.sequence = self.sequence.checked_add(1).ok_or_else(invalid)?;
        Ok(())
    }
    fn refuse(
        &mut self,
        request: &wire::Request,
        stage: wire::Stage,
        error: Option<u32>,
        processed: u32,
        queried: u32,
    ) -> io::Result<()> {
        self.send(
            request,
            wire::ResultKind::Refused {
                stage,
                native_error: error,
                binding_failure: None,
            },
        )?;
        self.send(
            request,
            wire::ResultKind::End {
                processed,
                queried,
                complete: false,
            },
        )
    }
    fn refuse_binding(
        &mut self,
        request: &wire::Request,
        failure: wire::BindingFailure,
        processed: u32,
        queried: u32,
    ) -> io::Result<()> {
        self.send(
            request,
            wire::ResultKind::Refused {
                stage: wire::Stage::Binding,
                native_error: failure.native_error,
                binding_failure: Some(failure),
            },
        )?;
        self.send(
            request,
            wire::ResultKind::End {
                processed,
                queried,
                complete: false,
            },
        )
    }
}
fn failure_window(
    request: &wire::Request,
    mut failure: wire::BindingFailure,
    before: u64,
) -> io::Result<wire::BindingFailure> {
    failure.before_qpc = before;
    failure.after_qpc = live(request)?;
    Ok(failure)
}
struct Session(*mut c_void);
impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: session is used only synchronously in the isolated watchdog process.
        unsafe { CloseThreadWaitChainSession(self.0) };
    }
}
fn raw_handle(value: u64) -> io::Result<HANDLE> {
    let value = usize::try_from(value).map_err(|_| invalid())?;
    if value == 0 || value == usize::MAX {
        return Err(invalid());
    }
    Ok(value as HANDLE)
}

/// This entrypoint has no arbitrary PID/path/command or privilege adjustment.
pub fn run(mapping: u64, output: u64, protocol: u32) -> io::Result<()> {
    if protocol != wire::VERSION || mapping == output {
        return Err(invalid());
    }
    // SAFETY: this closed role consumes only its explicit inherited mapping/output handles.
    let mapping_owner = unsafe { OwnedHandle::from_raw_handle(raw_handle(mapping)?) };
    let output_owner = unsafe { OwnedHandle::from_raw_handle(raw_handle(output)?) };
    let request = read_request(&mapping_owner)?;
    if [mapping, output].contains(&request.process_handle)
        || request
            .threads
            .iter()
            .any(|t| [mapping, output].contains(&t.handle))
    {
        return Err(invalid());
    }
    #[cfg(target_arch = "aarch64")]
    if request.target_machine != 0xaa64 {
        return Err(invalid());
    }
    #[cfg(target_arch = "x86_64")]
    if request.target_machine != 0x8664 {
        return Err(invalid());
    }
    let _watchdog = arm_watchdog(&request)?;
    // SAFETY: uniqueness was checked by the request decoder and against both role handles.
    let process = unsafe { OwnedHandle::from_raw_handle(raw_handle(request.process_handle)?) };
    let mut threads = Vec::with_capacity(request.threads.len());
    for thread in &request.threads {
        // SAFETY: every inherited query-only handle is unique and bound before use.
        threads.push(unsafe { OwnedHandle::from_raw_handle(raw_handle(thread.handle)?) });
    }
    let mut writer = Writer {
        file: File::from(output_owner),
        binding: request.digest()?,
        sequence: 0,
        total: 0,
    };
    writer.send(
        &request,
        wire::ResultKind::Begin {
            observer: self_identity()?,
            threads: request.threads.len() as u32,
            omitted: request.omitted_threads,
        },
    )?;
    if !debug_enabled()? {
        return writer.refuse(&request, wire::Stage::Privilege, None, 0, 0);
    }
    let initial_before = live(&request)?;
    if let Err(failure) = binding::process(
        &process,
        request.helper,
        None,
        wire::BindingBoundary::BeforeQuery,
    ) {
        let failure = failure_window(&request, *failure, initial_before)?;
        return writer.refuse_binding(&request, failure, 0, 0);
    }
    live(&request)?;
    // SAFETY: synchronous session: no callbacks, no parent-owned storage.
    let raw = unsafe { OpenThreadWaitChainSession(0, None) };
    if raw.is_null() {
        return writer.refuse(
            &request,
            wire::Stage::OpenSession,
            io::Error::last_os_error()
                .raw_os_error()
                .and_then(|c| u32::try_from(c).ok()),
            0,
            0,
        );
    }
    let session = Session(raw);
    let mut complete = request.omitted_threads == 0;
    let mut results = 0;
    let mut queried = 0;
    for (ordinal, (thread, handle)) in request.threads.iter().zip(&threads).enumerate() {
        let ordinal = u32::try_from(ordinal).map_err(|_| invalid())?;
        let before = live(&request)?;
        let prebinding = binding::process(
            &process,
            request.helper,
            Some(ordinal),
            wire::BindingBoundary::BeforeQuery,
        )
        .and_then(|()| {
            binding::thread(
                handle,
                thread,
                request.helper.pid,
                ordinal,
                wire::BindingBoundary::BeforeQuery,
            )
        });
        let state = match prebinding {
            Ok(state) => state,
            Err(failure) => {
                let failure = failure_window(&request, *failure, before)?;
                drop(session);
                return writer.refuse_binding(&request, failure, results, queried);
            }
        };
        if let binding::ThreadState::Exited(status) = state {
            if let Err(failure) = binding::process(
                &process,
                request.helper,
                Some(ordinal),
                wire::BindingBoundary::BeforeQuery,
            ) {
                let failure = failure_window(&request, *failure, before)?;
                drop(session);
                return writer.refuse_binding(&request, failure, results, queried);
            }
            let after = live(&request)?;
            complete = false;
            writer.send(
                &request,
                wire::ResultKind::Thread(wire::ThreadResult {
                    ordinal,
                    lifecycle: wire::ThreadLifecycle::ExitedBeforeQuery,
                    exit_status: Some(status),
                    tid: thread.tid,
                    birth: thread.birth,
                    before_qpc: before,
                    after_qpc: after,
                    binding_before: false,
                    binding_after: false,
                    cycle: None,
                    complete: false,
                    native_error: None,
                    reported_nodes: None,
                    nodes: Vec::new(),
                }),
            )?;
            results += 1;
            continue;
        }
        live(&request)?;
        queried += 1;
        let mut nodes = [WAITCHAIN_NODE_INFO::default(); wire::NODE_BOUND];
        let mut count = nodes.len() as u32;
        let mut cycle = 0;
        // SAFETY: fixed native array and same continuously held matching live thread TID.
        let success = unsafe {
            GetThreadWaitChain(
                session.0,
                0,
                WCT_OUT_OF_PROC_FLAG | WCT_OUT_OF_PROC_CS_FLAG,
                thread.tid,
                &mut count,
                nodes.as_mut_ptr(),
                &mut cycle,
            )
        } != 0;
        let native_error = if success {
            None
        } else {
            Some(unsafe { windows_sys::Win32::Foundation::GetLastError() })
        };
        let postbinding = binding::process(
            &process,
            request.helper,
            Some(ordinal),
            wire::BindingBoundary::AfterQuery,
        )
        .and_then(|()| {
            binding::thread(
                handle,
                thread,
                request.helper.pid,
                ordinal,
                wire::BindingBoundary::AfterQuery,
            )
        });
        let state = match postbinding {
            Ok(state) => state,
            Err(failure) => {
                let failure = failure_window(&request, *failure, before)?;
                drop(session);
                return writer.refuse_binding(&request, failure, results, queried);
            }
        };
        if matches!(state, binding::ThreadState::Exited(_)) {
            if let Err(failure) = binding::process(
                &process,
                request.helper,
                Some(ordinal),
                wire::BindingBoundary::AfterQuery,
            ) {
                let failure = failure_window(&request, *failure, before)?;
                drop(session);
                return writer.refuse_binding(&request, failure, results, queried);
            }
        }
        let after = live(&request)?;
        let (lifecycle, exit_status, bound) = match state {
            binding::ThreadState::Live => (wire::ThreadLifecycle::QueriedLive, None, true),
            binding::ThreadState::Exited(status) => {
                (wire::ThreadLifecycle::ExitedAfterQuery, Some(status), false)
            }
        };
        live(&request)?;
        let mut captured = Vec::new();
        // Only success or documented bounded partial-chain errors admit nodes.
        let valid_output = success
            || native_error == Some(ERROR_MORE_DATA)
            || native_error == Some(ERROR_TOO_MANY_THREADS);
        if valid_output {
            for node in nodes.iter().take((count as usize).min(wire::NODE_BOUND)) {
                if !(1..13).contains(&node.ObjectType) || !(1..11).contains(&node.ObjectStatus) {
                    complete = false;
                    break;
                }
                let mut record = wire::Node {
                    object_type: node.ObjectType as u32,
                    status: node.ObjectStatus as u32,
                    process_id: 0,
                    thread_id: 0,
                    wait_time: 0,
                    context_switches: 0,
                };
                if node.ObjectType == 8 {
                    // SAFETY: native discriminant selects the thread union member.
                    let value = unsafe { node.Anonymous.ThreadObject };
                    record.process_id = value.ProcessId;
                    record.thread_id = value.ThreadId;
                    record.wait_time = value.WaitTime;
                    record.context_switches = value.ContextSwitches;
                }
                captured.push(record);
            }
        }
        let query_complete =
            success && bound && !captured.is_empty() && captured.len() == count as usize;
        complete &= query_complete;
        writer.send(
            &request,
            wire::ResultKind::Thread(wire::ThreadResult {
                ordinal,
                lifecycle,
                exit_status,
                tid: thread.tid,
                birth: thread.birth,
                before_qpc: before,
                after_qpc: after,
                binding_before: true,
                binding_after: bound,
                cycle: valid_output.then_some(cycle != 0),
                complete: query_complete,
                native_error,
                reported_nodes: valid_output.then_some(count),
                nodes: captured,
            }),
        )?;
        results += 1;
        if !valid_output {
            drop(session);
            return writer.refuse(&request, wire::Stage::Query, native_error, results, queried);
        }
    }
    // Watchdog remains armed while Close or final pipe output may block.
    drop(session);
    live(&request)?;
    writer.send(
        &request,
        wire::ResultKind::End {
            processed: results,
            queried,
            complete,
        },
    )
}
