//! Query-only two-pass activity diagnostics on original held native objects.
use super::ProcessIdentity;
use serde_json::{Value, json};
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::time::Instant;
use windows_sys::Win32::Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle, FILETIME};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessId, GetProcessIdOfThread, GetProcessTimes, GetThreadId,
    GetThreadTimes, WaitForSingleObject,
};
use windows_sys::Win32::System::WindowsProgramming::QueryThreadCycleTime;

const THREAD_BOUND: usize = 64;
const SCAN_BOUND: usize = 131_072;
const PASS_BOUND: usize = 32 * 1024;
const RECORD_BOUND: usize = 96 * 1024;
const ERROR_BOUND: usize = 512;
const QUERY_SYNC: u32 = 0x0800 | 0x0010_0000;

#[cfg(test)]
#[path = "../tests/private/windows_thread_activity.rs"]
mod tests;

fn native(operation: &'static str) -> io::Error {
    labelled(operation, io::Error::last_os_error())
}

fn labelled(operation: &'static str, cause: io::Error) -> io::Error {
    io::Error::new(
        cause.kind(),
        format!(
            "native-operation={operation}; raw-os-error={:?}; {cause}",
            cause.raw_os_error()
        ),
    )
}

fn live(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "original thread activity cutoff exhausted",
        ))
    } else {
        Ok(())
    }
}

fn error(operation: &'static str, cause: io::Error) -> Value {
    let detail = cause.to_string();
    let mut length = detail.len().min(ERROR_BOUND);
    while !detail.is_char_boundary(length) {
        length -= 1;
    }
    json!({"operation":operation,"kind":format!("{:?}",cause.kind()),"raw_os_error":cause.raw_os_error(),
        "detail":&detail[..length],"detail_truncated":length!=detail.len()})
}

fn captured(operation: &'static str, result: io::Result<Value>) -> Value {
    match result {
        Ok(value) => json!({"observed":value}),
        Err(cause) => json!({"error":error(operation,cause)}),
    }
}

fn ticks(time: FILETIME) -> u64 {
    (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime)
}

fn retired(handle: &OwnedHandle) -> io::Result<bool> {
    // SAFETY: the caller retains the same original synchronization handle; no wait is introduced.
    match unsafe { WaitForSingleObject(handle.as_raw_handle(), 0) } {
        0 => Ok(true),
        258 => Ok(false),
        _ => Err(native("WaitForSingleObject-zero")),
    }
}

fn process(
    handle: &OwnedHandle,
    identity: ProcessIdentity,
    deadline: Instant,
) -> io::Result<Value> {
    live(deadline)?;
    // SAFETY: query the exact duplicated original process handle, never reopen a PID.
    let pid = unsafe { GetProcessId(handle.as_raw_handle()) };
    if pid == 0 {
        return Err(native("GetProcessId"));
    }
    if pid != identity.pid {
        return Err(io::Error::other("original process handle PID differs"));
    }
    let before = retired(handle)?;
    let mut birth = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: all native outputs have their required initialized writable extent.
    if unsafe {
        GetProcessTimes(
            handle.as_raw_handle(),
            &mut birth,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return Err(native("GetProcessTimes"));
    }
    let after = retired(handle)?;
    if after && !before {
        // SAFETY: retirement is now signaled; requery before observing defined exit-time output.
        if unsafe {
            GetProcessTimes(
                handle.as_raw_handle(),
                &mut birth,
                &mut exit,
                &mut kernel,
                &mut user,
            )
        } == 0
        {
            return Err(native("GetProcessTimes-after-signaled-retirement"));
        }
    }
    if u128::from(ticks(birth)) != identity.birth {
        return Err(io::Error::other("original process birth differs"));
    }
    live(deadline)?;
    Ok(
        json!({"pid":identity.pid,"birth":identity.birth,"retired":after,
        "exit_time_100ns":if after {Some(ticks(exit))}else{None},"kernel_100ns":ticks(kernel),"user_100ns":ticks(user)}),
    )
}

#[derive(Clone, Copy)]
struct Counters {
    birth: u64,
    kernel: u64,
    user: u64,
    cycles: Option<u64>,
}

struct ThreadOwner {
    handle: OwnedHandle,
    tid: u32,
    first: Option<Counters>,
}

#[derive(Debug)]
struct SettlementFailure {
    pid: u32,
    tid: u32,
    birth: Option<u64>,
    cause: io::Error,
}

impl std::fmt::Display for SettlementFailure {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            output,
            "original-thread-settlement pid={} tid={} birth={:?}: {}",
            self.pid, self.tid, self.birth, self.cause
        )
    }
}

impl std::error::Error for SettlementFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

fn thread_binding(owner: &ThreadOwner, pid: u32) -> io::Result<()> {
    // SAFETY: query only this original retained thread handle.
    let tid = unsafe { GetThreadId(owner.handle.as_raw_handle()) };
    if tid == 0 {
        return Err(native("GetThreadId"));
    }
    // SAFETY: the same original query-only thread handle remains held.
    let process = unsafe { GetProcessIdOfThread(owner.handle.as_raw_handle()) };
    if process == 0 {
        return Err(native("GetProcessIdOfThread"));
    }
    if tid != owner.tid || process != pid {
        return Err(io::Error::other(format!(
            "held thread native binding differs: snapshot-tid={} held-tid={tid} expected-pid={pid} held-owner-pid={process}",
            owner.tid
        )));
    }
    Ok(())
}

fn thread_sample(
    owner: &ThreadOwner,
    pid: u32,
    deadline: Instant,
) -> io::Result<(Value, Counters)> {
    live(deadline)?;
    thread_binding(owner, pid)?;
    let before = retired(&owner.handle)?;
    let mut birth = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: same retained thread handle and full native output scalars.
    if unsafe {
        GetThreadTimes(
            owner.handle.as_raw_handle(),
            &mut birth,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return Err(native("GetThreadTimes"));
    }
    let mut cycles = 0;
    // SAFETY: query-only same thread; cycle totals are never converted into elapsed time.
    let cycle_result =
        if unsafe { QueryThreadCycleTime(owner.handle.as_raw_handle(), &mut cycles) } == 0 {
            Err(native("QueryThreadCycleTime"))
        } else {
            Ok(cycles)
        };
    let after = retired(&owner.handle)?;
    if after && !before {
        // SAFETY: exit-time is sampled again only after native retirement is signaled.
        if unsafe {
            GetThreadTimes(
                owner.handle.as_raw_handle(),
                &mut birth,
                &mut exit,
                &mut kernel,
                &mut user,
            )
        } == 0
        {
            return Err(native("GetThreadTimes-after-signaled-retirement"));
        }
    }
    let birth = ticks(birth);
    if birth == 0 || owner.first.is_some_and(|first| first.birth != birth) {
        return Err(io::Error::other(
            "held thread original birth differs or is unavailable",
        ));
    }
    thread_binding(owner, pid)?;
    live(deadline)?;
    let counters = Counters {
        birth,
        kernel: ticks(kernel),
        user: ticks(user),
        cycles: cycle_result.as_ref().ok().copied(),
    };
    let counter_regression = owner.first.is_some_and(|first| {
        counters.kernel < first.kernel
            || counters.user < first.user
            || first
                .cycles
                .zip(counters.cycles)
                .is_some_and(|(before, after)| after < before)
    });
    let activity = owner.first.and_then(|first| {
        if counters.kernel < first.kernel || counters.user < first.user {
            return None;
        }
        if counters.kernel > first.kernel || counters.user > first.user {
            return Some(true);
        }
        match (first.cycles, counters.cycles) {
            (Some(a), Some(b)) if b >= a => Some(b > a),
            _ => None,
        }
    });
    let cycle_value = match cycle_result {
        Ok(value) => json!({"observed":value}),
        Err(cause) => json!({"error":error("QueryThreadCycleTime",cause)}),
    };
    Ok((
        json!({"tid":owner.tid,"owner_pid":pid,"birth":birth,"retired":after,
        "exit_time_100ns":if after {Some(ticks(exit))}else{None},"kernel_100ns":counters.kernel,"user_100ns":counters.user,
        "cycles":cycle_value,"activity_observed":activity,"counter_regression":counter_regression,
        "unchanged_counters_are_not_deadlock":true}),
        counters,
    ))
}

fn bounded_pass(mut value: Value) -> Value {
    let mut omitted = 0usize;
    while !serde_json::to_vec(&value).is_ok_and(|bytes| bytes.len() <= PASS_BOUND) {
        if value["threads"].as_array_mut().and_then(Vec::pop).is_none() {
            return json!({"complete":false,"error":"bounded activity pass serialization failed","threads":[]});
        }
        omitted += 1;
        value["record_omitted_count"] = json!(omitted);
        value["complete"] = json!(false);
    }
    value
}

pub struct WindowsThreadActivitySample {
    process: Option<OwnedHandle>,
    identity: ProcessIdentity,
    deadline: Instant,
    epoch: Instant,
    threads: Vec<ThreadOwner>,
    first: Value,
    finished: Option<Value>,
}

impl WindowsThreadActivitySample {
    /// Explicit fixture settlement on the original retained thread objects.
    /// This neither samples nor finishes the activity round, and retains every
    /// owner on refusal. Installed diagnostic paths do not call this method.
    pub fn wait_original_threads_retired_until(&self, deadline: Instant) -> io::Result<()> {
        let deadline = deadline.min(self.deadline);
        live(deadline)?;
        if self.finished.is_some() || self.process.is_none() || self.threads.is_empty() {
            return Err(io::Error::other(
                "original thread settlement owners unavailable",
            ));
        }
        for owner in &self.threads {
            let settle = || -> io::Result<()> {
                live(deadline)?;
                thread_binding(owner, self.identity.pid)?;
                let mut birth = FILETIME::default();
                let mut exit = FILETIME::default();
                let mut kernel = FILETIME::default();
                let mut user = FILETIME::default();
                // SAFETY: query the same retained original thread owner only.
                if unsafe {
                    GetThreadTimes(
                        owner.handle.as_raw_handle(),
                        &mut birth,
                        &mut exit,
                        &mut kernel,
                        &mut user,
                    )
                } == 0
                {
                    return Err(native("settlement-GetThreadTimes"));
                }
                if !owner
                    .first
                    .as_ref()
                    .is_some_and(|first| first.birth == ticks(birth))
                {
                    return Err(io::Error::other(
                        "original thread settlement birth unavailable or changed",
                    ));
                }
                live(deadline)?;
                let remaining = deadline.saturating_duration_since(Instant::now());
                // Floor to milliseconds: never ask the kernel for a renewed or
                // rounded-up allowance, and never use INFINITE.
                let milliseconds = remaining.as_millis().min(u128::from(u32::MAX - 1)) as u32;
                // SAFETY: bounded wait on this original SYNCHRONIZE owner.
                let status =
                    unsafe { WaitForSingleObject(owner.handle.as_raw_handle(), milliseconds) };
                let failure = (status == u32::MAX).then(io::Error::last_os_error);
                live(deadline)?;
                match status {
                    0 => Ok(()),
                    258 => Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "original thread settlement wait status=258",
                    )),
                    u32::MAX => Err(failure.expect("captured failed wait")),
                    _ => Err(io::Error::other(format!(
                        "original thread settlement unexpected wait status={status}"
                    ))),
                }
            };
            settle().map_err(|cause| {
                io::Error::new(
                    cause.kind(),
                    SettlementFailure {
                        pid: self.identity.pid,
                        tid: owner.tid,
                        birth: owner.first.as_ref().map(|first| first.birth),
                        cause,
                    },
                )
            })?;
        }
        live(deadline)
    }

    /// Retain independently duplicated originals before `finish` releases this
    /// activity round. This does not admit a process or open a numeric PID/TID.
    pub fn wait_observer_snapshot(
        &self,
        deadline: Instant,
    ) -> io::Result<super::windows_wait_observer::WindowsWaitObserverSnapshot> {
        use super::windows_wait_observer::{WaitThreadOwner, WindowsWaitObserverSnapshot};
        let deadline = deadline.min(self.deadline);
        live(deadline)?;
        if self.first["first"]["complete"] != true {
            return Err(io::Error::other("original activity census is incomplete"));
        }
        let original = self
            .process
            .as_ref()
            .ok_or_else(|| io::Error::other("activity originals already released"))?;
        if process(original, self.identity, deadline)?["retired"] != false {
            return Err(io::Error::other("original helper has retired"));
        }
        let duplicate = |handle: &OwnedHandle| -> io::Result<OwnedHandle> {
            live(deadline)?;
            let mut raw = std::ptr::null_mut();
            // SAFETY: duplicate only this retained original with unchanged access.
            if unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    handle.as_raw_handle(),
                    GetCurrentProcess(),
                    &mut raw,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            } == 0
            {
                return Err(native("DuplicateHandle-wait-snapshot"));
            }
            // SAFETY: successful duplication transfers exactly one native owner.
            Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
        };
        let process_owner = duplicate(original)?;
        let mut threads = Vec::new();
        let mut omitted = 0usize;
        for owner in &self.threads {
            live(deadline)?;
            thread_binding(owner, self.identity.pid)?;
            let (_, current) = thread_sample(owner, self.identity.pid, deadline)?;
            if owner.first.is_none_or(|first| first.birth != current.birth) {
                return Err(io::Error::other("original thread birth changed"));
            }
            if retired(&owner.handle)? {
                omitted += 1;
                continue;
            }
            threads.push(WaitThreadOwner {
                handle: duplicate(&owner.handle)?,
                tid: owner.tid,
                birth: current.birth,
            });
        }
        if threads.len() > THREAD_BOUND {
            return Err(io::Error::other("wait snapshot thread bound exceeded"));
        }
        if process(original, self.identity, deadline)?["retired"] != false {
            return Err(io::Error::other("original helper retired during snapshot"));
        }
        live(deadline)?;
        Ok(WindowsWaitObserverSnapshot {
            process: process_owner,
            identity: self.identity,
            threads,
            omitted_threads: omitted,
            deadline,
        })
    }

    pub fn first_observation(&self) -> &Value {
        &self.first
    }

    pub fn finish(&mut self, deadline: Instant) -> Value {
        if let Some(value) = &self.finished {
            return value.clone();
        }
        let deadline = deadline.min(self.deadline);
        let mut value = self.first.clone();
        let second = (|| -> io::Result<Value> {
            live(deadline)?;
            let handle = self
                .process
                .as_ref()
                .ok_or_else(|| io::Error::other("original sample process owner absent"))?;
            let start = self.epoch.elapsed().as_nanos();
            let before = process(handle, self.identity, deadline)?;
            let mut records = Vec::new();
            let mut complete = true;
            for owner in &self.threads {
                let observation = thread_sample(owner, self.identity.pid, deadline);
                if !observation
                    .as_ref()
                    .is_ok_and(|(_, counters)| counters.cycles.is_some())
                {
                    complete = false;
                }
                records.push(match observation {
                    Ok((record, _)) => json!({"observed":record}),
                    Err(cause) => {
                        json!({"tid":owner.tid,"error":error("same-held-thread-second-pass",cause)})
                    }
                });
            }
            let after = captured(
                "held-process-after-second-pass",
                process(handle, self.identity, deadline),
            );
            if after.get("error").is_some() {
                complete = false;
            }
            Ok(bounded_pass(
                json!({"offset_before_ns":start,"offset_after_ns":self.epoch.elapsed().as_nanos(),
                "process_before":before,"process_after":after,"threads":records,"record_omitted_count":0,"complete":complete}),
            ))
        })();
        value["second"] = captured("second-pass", second);
        value["complete"] = json!(
            value["first"]["complete"] == true && value["second"]["observed"]["complete"] == true
        );
        // Thread handles are released synchronously after this pass/refusal; there is no worker.
        self.threads.clear();
        drop(self.process.take());
        if !serde_json::to_vec(&value).is_ok_and(|bytes| bytes.len() <= RECORD_BOUND) {
            value = self.first.clone();
            value["second"] =
                json!({"error":"activity record exceeds finite bound","complete":false});
            value["complete"] = json!(false);
        }
        self.finished = Some(value.clone());
        value
    }
}

pub(super) fn begin(
    original: &OwnedHandle,
    identity: ProcessIdentity,
    deadline: Instant,
) -> io::Result<WindowsThreadActivitySample> {
    live(deadline)?;
    let epoch = Instant::now();
    let mut duplicate = std::ptr::null_mut();
    // SAFETY: duplicate only the retained original process with identical access, no inheritance.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            original.as_raw_handle(),
            GetCurrentProcess(),
            &mut duplicate,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(native("DuplicateHandle-original-process-SAME_ACCESS"));
    }
    // SAFETY: successful duplication transfers one independent owned native reference.
    let process_owner = unsafe { OwnedHandle::from_raw_handle(duplicate) };
    let before_offset = epoch.elapsed().as_nanos();
    let before = process(&process_owner, identity, deadline)?;
    if before["retired"] != false {
        return Err(io::Error::other(
            "original held sample process is already retired",
        ));
    }
    let mut threads = Vec::new();
    let mut records = Vec::new();
    let census = enumerate(identity.pid, deadline, &mut threads, &mut records);
    let after = captured(
        "held-process-after-first-pass",
        process(&process_owner, identity, deadline),
    );
    let first_pass = bounded_pass(
        json!({"offset_before_ns":before_offset,"offset_after_ns":epoch.elapsed().as_nanos(),
        "process_before":before,"process_after":after,"threads":records,"enumeration":census,
        "record_omitted_count":0,"complete":census["complete"]==true && after.get("error").is_none()}),
    );
    let first = json!({"format":"memcordon.windows-held-thread-activity","revision":1,"diagnostic_only":true,
        "identity":{"pid":identity.pid,"birth":identity.birth},"thread_access_mask":QUERY_SYNC,
        "process_access":"duplicated-original-same-access","first":first_pass,"second":null,"complete":false,
        "effective_token_debug_privilege":captured("effective-token-SeDebugPrivilege",debug_privilege(deadline)),
        "interpretation":"CPU/cycle activity only; unchanged is not deadlock, no wait-object attribution"});
    if serde_json::to_vec(&first).map_err(io::Error::other)?.len() > RECORD_BOUND {
        return Err(io::Error::other(
            "first activity record exceeds finite bound",
        ));
    }
    Ok(WindowsThreadActivitySample {
        process: Some(process_owner),
        identity,
        deadline,
        epoch,
        threads,
        first,
        finished: None,
    })
}

fn enumerate(
    pid: u32,
    deadline: Instant,
    threads: &mut Vec<ThreadOwner>,
    records: &mut Vec<Value>,
) -> Value {
    use windows_sys::Win32::Foundation::{ERROR_NO_MORE_FILES, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::Threading::OpenThread;
    let outcome = (|| -> io::Result<Value> {
        live(deadline)?;
        // SAFETY: query-only native thread snapshot; no process/thread mutation.
        let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if raw == INVALID_HANDLE_VALUE {
            return Err(native("CreateToolhelp32Snapshot-threads"));
        }
        // SAFETY: successful snapshot transfers one owned native reference.
        let snapshot = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut entry = THREADENTRY32::default();
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        // SAFETY: initialized full native entry and retained snapshot.
        let mut found = unsafe { Thread32First(snapshot.as_raw_handle(), &mut entry) };
        let mut scanned = 0usize;
        let mut matching = 0usize;
        let mut failed = 0usize;
        while found != 0 {
            live(deadline)?;
            if scanned >= SCAN_BOUND {
                return Ok(
                    json!({"scanned":scanned,"matching":matching,"omitted":matching.saturating_sub(threads.len()),"complete":false,"scan_truncated":true}),
                );
            }
            scanned += 1;
            if entry.th32OwnerProcessID == pid {
                matching += 1;
                if matching <= THREAD_BOUND {
                    // SAFETY: query/sync only, noninheritable; snapshot PID is verified on the opened thread handle.
                    let handle = unsafe { OpenThread(QUERY_SYNC, 0, entry.th32ThreadID) };
                    if handle.is_null() {
                        failed += 1;
                        records.push(json!({"snapshot_tid":entry.th32ThreadID,"error":error("OpenThread-query-sync",io::Error::last_os_error())}));
                    } else {
                        // SAFETY: successful OpenThread transfers one owned reference.
                        let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
                        let mut owner = ThreadOwner {
                            handle,
                            tid: entry.th32ThreadID,
                            first: None,
                        };
                        match thread_binding(&owner, pid) {
                            Err(cause) => {
                                failed += 1;
                                records.push(json!({"snapshot_tid":owner.tid,"error":error("opened-thread-snapshot-PID-TID-binding",cause)}));
                            }
                            Ok(()) => {
                                match thread_sample(&owner, pid, deadline) {
                                    Ok((record, counters)) => {
                                        if counters.cycles.is_none() {
                                            failed += 1;
                                        }
                                        owner.first = Some(counters);
                                        records.push(json!({"observed":record}));
                                    }
                                    Err(cause) => {
                                        failed += 1;
                                        records.push(json!({"snapshot_tid":owner.tid,"error":error("first-held-thread-binding-and-counters",cause)}));
                                    }
                                }
                                threads.push(owner);
                            }
                        }
                    }
                }
            }
            entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
            // SAFETY: same snapshot and correctly sized writable native entry.
            found = unsafe { Thread32Next(snapshot.as_raw_handle(), &mut entry) };
        }
        let last = io::Error::last_os_error();
        if last.raw_os_error() != Some(ERROR_NO_MORE_FILES as i32) {
            return Err(labelled("Thread32First-or-Next", last));
        }
        live(deadline)?;
        Ok(
            json!({"scanned":scanned,"matching":matching,"retained":threads.len(),"query_failures":failed,
            "omitted":matching.saturating_sub(THREAD_BOUND),"complete":matching<=THREAD_BOUND && failed==0,"scan_truncated":false}),
        )
    })();
    match outcome {
        Ok(value) => value,
        Err(cause) => json!({"complete":false,"error":error("thread-snapshot-census",cause)}),
    }
}

fn debug_privilege(deadline: Instant) -> io::Result<Value> {
    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_NO_TOKEN, LUID};
    use windows_sys::Win32::Security::{
        GetTokenInformation, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
        TOKEN_PRIVILEGES, TOKEN_QUERY, TokenPrivileges,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentThread, OpenProcessToken, OpenThreadToken,
    };
    live(deadline)?;
    let mut token = std::ptr::null_mut();
    // SAFETY: query-only effective thread token, no token mutation or privilege enabling.
    let source = if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0
    {
        let cause = io::Error::last_os_error();
        if cause.raw_os_error() != Some(ERROR_NO_TOKEN as i32) {
            return Err(labelled("OpenThreadToken-effective-TOKEN_QUERY", cause));
        }
        // SAFETY: only ERROR_NO_TOKEN permits falling back to the unchanged process token.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(native("OpenProcessToken-no-thread-token-TOKEN_QUERY"));
        }
        "process-token-no-thread-token"
    } else {
        "effective-thread-token"
    };
    // SAFETY: successful native token open transfers one owned query-only handle.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    live(deadline)?;
    let mut required = 0;
    // SAFETY: bounded sizing query with no data buffer.
    let sized = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenPrivileges,
            std::ptr::null_mut(),
            0,
            &mut required,
        )
    };
    let sizing = io::Error::last_os_error();
    if sized == 0 && sizing.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
        return Err(labelled(
            "GetTokenInformation-TokenPrivileges-sizing",
            sizing,
        ));
    }
    if sized != 0 || required as usize > 64 * 1024 || required < std::mem::size_of::<u32>() as u32 {
        return Err(io::Error::other(format!(
            "TokenPrivileges sizing unavailable; returned={required}"
        )));
    }
    let mut buffer = vec![0usize; (required as usize).div_ceil(std::mem::size_of::<usize>())];
    let mut returned = 0;
    // SAFETY: naturally aligned buffer has at least required bytes; native API receives that exact capacity.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenPrivileges,
            buffer.as_mut_ptr().cast(),
            required,
            &mut returned,
        )
    } == 0
    {
        return Err(native("GetTokenInformation-TokenPrivileges"));
    }
    let offset = std::mem::offset_of!(TOKEN_PRIVILEGES, Privileges);
    // SAFETY: successful query returned at least the fixed DWORD count, verified below before entries are read.
    if returned < std::mem::size_of::<u32>() as u32 || returned > required {
        return Err(io::Error::other("TokenPrivileges returned extent differs"));
    }
    let count = unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<u32>()) } as usize;
    let end = count
        .checked_mul(std::mem::size_of::<LUID_AND_ATTRIBUTES>())
        .and_then(|length| length.checked_add(offset))
        .ok_or_else(|| io::Error::other("TokenPrivileges extent overflow"))?;
    if end > returned as usize {
        return Err(io::Error::other(
            "TokenPrivileges entry extent exceeds returned bytes",
        ));
    }
    let name: Vec<_> = "SeDebugPrivilege".encode_utf16().chain(Some(0)).collect();
    let mut luid = LUID::default();
    // SAFETY: fixed terminated privilege name and correctly sized native LUID output.
    if unsafe { LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) } == 0 {
        return Err(native("LookupPrivilegeValueW-SeDebugPrivilege"));
    }
    let mut attributes = None;
    for index in 0..count {
        live(deadline)?;
        // SAFETY: complete entry extent was checked against returned buffer bytes above.
        let entry = unsafe {
            std::ptr::read_unaligned(
                buffer
                    .as_ptr()
                    .cast::<u8>()
                    .add(offset + index * std::mem::size_of::<LUID_AND_ATTRIBUTES>())
                    .cast::<LUID_AND_ATTRIBUTES>(),
            )
        };
        if entry.Luid.LowPart == luid.LowPart && entry.Luid.HighPart == luid.HighPart {
            attributes = Some(entry.Attributes);
        }
    }
    live(deadline)?;
    Ok(
        json!({"token_source":source,"query_only":true,"present":attributes.is_some(),"enabled":attributes.is_some_and(|attributes|attributes&SE_PRIVILEGE_ENABLED!=0)}),
    )
}
