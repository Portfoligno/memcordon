//! Creation-time custody for the owned real compiler and its descendants.
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;

use std::io::{self, Read, Seek, SeekFrom};
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::PathBuf;
use windows_sys::Win32::Foundation::{
    CloseHandle, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, DUPLICATE_SAME_ACCESS, DuplicateHandle,
    EXCEPTION_BREAKPOINT, FILETIME,
};
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessTimes, QueryFullProcessImageNameW, TerminateProcess,
    WaitForSingleObject,
};

pub(super) fn operation_error(
    operation: &'static str,
    pid: Option<u32>,
    error: io::Error,
) -> io::Error {
    let kind = error.kind();
    let raw = error.raw_os_error();
    io::Error::new(
        kind,
        format!(
            "{error}; toolchain-operation={operation}; pid={pid:?}; original-raw-os-error={raw:?}"
        ),
    )
}

pub(super) struct Created {
    pub identity: memcordon_core::WindowsProcessIdentityV1,
    pub image: PathBuf,
    pub image_sha256: String,
    pub parent_pid: u32,
    pub parent_birth: u64,
}

pub(super) fn wait_retired(owner: &OwnedHandle, milliseconds: u32) -> io::Result<()> {
    // SAFETY: the borrowed owned process handle remains valid throughout the finite wait.
    match unsafe { WaitForSingleObject(owner.as_raw_handle(), milliseconds) } {
        0 => Ok(()),
        u32::MAX => Err(io::Error::last_os_error()),
        _ => Err(io::Error::other(
            "compiler retirement not signaled before original cutoff",
        )),
    }
}

pub(super) fn validate_clock(cutoff: u64, frequency: u64) -> io::Result<()> {
    let mut actual = 0i64;
    // SAFETY: the initialized native scalar has the required writable size.
    if unsafe { windows_sys::Win32::System::Performance::QueryPerformanceFrequency(&mut actual) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    if u64::try_from(actual).ok() != Some(frequency) {
        return Err(io::Error::other("toolchain native clock frequency differs"));
    }
    remaining(cutoff, frequency).map(|_| ())
}

pub(super) fn remaining(cutoff: u64, frequency: u64) -> io::Result<u32> {
    let mut now = 0i64;
    if unsafe { windows_sys::Win32::System::Performance::QueryPerformanceCounter(&mut now) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let now = u64::try_from(now).map_err(io::Error::other)?;
    let remaining = cutoff
        .checked_sub(now)
        .filter(|value| *value > 0)
        .ok_or_else(|| io::Error::other("original toolchain work cutoff expired"))?;
    if frequency == 0 {
        return Err(io::Error::other("toolchain native frequency is zero"));
    }
    let milliseconds = u128::from(remaining) * 1000 / u128::from(frequency);
    Ok(milliseconds.min(u128::from(u32::MAX - 1)) as u32)
}

/// The caller created DEBUG_PROCESS on this same thread. Event-owned process and
/// thread handles remain Windows-owned; only our duplicates and image files close here.
pub(super) fn run(
    cutoff: u64,
    frequency: u64,
    root: &memcordon_core::WindowsProcessIdentityV1,
    original_child: &std::process::Child,
    mut acknowledge: impl FnMut(&Created) -> io::Result<()>,
    mut observe: impl FnMut(&str, serde_json::Value) -> io::Result<()>,
) -> io::Result<()> {
    let mut held = BTreeMap::<u32, OwnedHandle>::new();
    let mut breakpoints = BTreeSet::new();
    let mut pending = None;
    let mut pending_process = None;
    let mut active = BTreeSet::new();
    let mut identities = BTreeMap::<u32, u64>::new();
    let mut diagnostic_members =
        BTreeMap::<u32, super::toolchain_diagnostics::CreationIdentity>::new();
    let mut exits = super::toolchain_diagnostics::ExitState::new(original_child.id());
    let mut last_event = serde_json::Value::Null;
    let mut changed = true;
    let mut ack_validated = false;
    let mut continued = false;
    let outcome = (|| {
        for _ in 0..131_072 {
            let mut event: DEBUG_EVENT = unsafe { std::mem::zeroed() };
            // Persist only meaningful state transitions, never DLL/poll iterations.
            if changed {
                observe(
                    "before-debug-wait",
                    serde_json::json!({"active":super::toolchain_diagnostics::inventory(diagnostic_members.values(), held.len()),
                    "last_event":last_event,"pending_event":pending,"ack_validated":ack_validated,"continued":continued,
                    "original_child_pid":original_child.id(),"exit_observations":exits.snapshot()}),
                )?;
                changed = false;
            }
            if unsafe { WaitForDebugEvent(&mut event, remaining(cutoff, frequency)?) } == 0 {
                return Err(operation_error(
                    "WaitForDebugEvent",
                    Some(original_child.id()),
                    io::Error::last_os_error(),
                ));
            }
            pending = Some((event.dwProcessId, event.dwThreadId));
            let mut observed_exit = None;
            let mut continuation = DBG_CONTINUE;
            match event.dwDebugEventCode {
                CREATE_PROCESS_DEBUG_EVENT => {
                    let created = unsafe { event.u.CreateProcessInfo };
                    active.insert(event.dwProcessId);
                    pending_process = Some(created.hProcess);
                    // Image handles have independent documented caller ownership.
                    let image_file = if created.hFile.is_null() {
                        None
                    } else {
                        Some(unsafe { File::from_raw_handle(created.hFile) })
                    };
                    if held.len() >= 4096 || held.contains_key(&event.dwProcessId) {
                        return Err(io::Error::other(
                            "toolchain debug process inventory invalid",
                        ));
                    }
                    let mut duplicate = std::ptr::null_mut();
                    if unsafe {
                        DuplicateHandle(
                            GetCurrentProcess(),
                            created.hProcess,
                            GetCurrentProcess(),
                            &mut duplicate,
                            0,
                            0,
                            DUPLICATE_SAME_ACCESS,
                        )
                    } == 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                    let owner = unsafe { OwnedHandle::from_raw_handle(duplicate) };
                    held.insert(event.dwProcessId, owner);
                    let (parent_pid, live) = super::native::held_parent_and_liveness(
                        held.get(&event.dwProcessId)
                            .expect("inserted process owner"),
                        event.dwProcessId,
                    )?;
                    if !live {
                        return Err(io::Error::other(
                            "creation-held toolchain child is not live",
                        ));
                    }
                    let parent_birth = if parent_pid == root.process_id {
                        root.creation_time_100ns
                    } else {
                        let parent = held.get(&parent_pid).ok_or_else(|| io::Error::other(
                            "creation-held toolchain parent is not independently retained by creator"))?;
                        if unsafe { WaitForSingleObject(parent.as_raw_handle(), 0) } != 258 {
                            return Err(io::Error::other(
                                "creation-held toolchain parent is not live",
                            ));
                        }
                        *identities.get(&parent_pid).ok_or_else(|| {
                            io::Error::other("creation-held toolchain parent birth is unavailable")
                        })?
                    };
                    let mut birth = FILETIME::default();
                    let mut exit = FILETIME::default();
                    let mut kernel = FILETIME::default();
                    let mut user = FILETIME::default();
                    if unsafe {
                        GetProcessTimes(
                            created.hProcess,
                            &mut birth,
                            &mut exit,
                            &mut kernel,
                            &mut user,
                        )
                    } == 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                    let mut path = vec![0u16; 32768];
                    let mut length = path.len() as u32;
                    if unsafe {
                        QueryFullProcessImageNameW(
                            created.hProcess,
                            0,
                            path.as_mut_ptr(),
                            &mut length,
                        )
                    } == 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                    path.truncate(length as usize);
                    let child_birth =
                        (u64::from(birth.dwHighDateTime) << 32) | u64::from(birth.dwLowDateTime);
                    if event.dwProcessId == 0 || child_birth == 0 || parent_birth > child_birth {
                        return Err(io::Error::other(
                            "toolchain creation identity/ancestry invalid",
                        ));
                    }
                    identities.insert(event.dwProcessId, child_birth);
                    let image = PathBuf::from(std::ffi::OsString::from_wide(&path));
                    let mut file = image_file.ok_or_else(|| {
                        io::Error::other("toolchain creation event lacks original image file")
                    })?;
                    use std::os::windows::fs::MetadataExt;
                    let metadata = file.metadata().map_err(|error| {
                        operation_error(
                            "creation-image-held-metadata",
                            Some(event.dwProcessId),
                            error,
                        )
                    })?;
                    if !metadata.is_file()
                        || metadata.len() > 512 * 1024 * 1024
                        || metadata.file_attributes()
                            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                            != 0
                    {
                        return Err(io::Error::other(
                            "toolchain creation image is not bounded ordinary code",
                        ));
                    }
                    let mut bytes = Vec::new();
                    file.seek(SeekFrom::Start(0)).map_err(|error| {
                        operation_error(
                            "creation-image-held-rewind",
                            Some(event.dwProcessId),
                            error,
                        )
                    })?;
                    file.take(512 * 1024 * 1024 + 1)
                        .read_to_end(&mut bytes)
                        .map_err(|error| {
                            operation_error(
                                "creation-image-held-read",
                                Some(event.dwProcessId),
                                error,
                            )
                        })?;
                    if bytes.len() > 512 * 1024 * 1024 || bytes.len() as u64 != metadata.len() {
                        return Err(io::Error::other("toolchain creation image exceeds bound"));
                    }
                    use sha2::Digest;
                    let created = Created {
                        identity: memcordon_core::WindowsProcessIdentityV1 {
                            process_id: event.dwProcessId,
                            creation_time_100ns: child_birth,
                        },
                        image,
                        parent_pid,
                        parent_birth,
                        image_sha256: String::from(memcordon_core::DiagnosticSha256::from_bytes(
                            sha2::Sha256::digest(&bytes).into(),
                        )),
                    };
                    let member = super::toolchain_diagnostics::CreationIdentity {
                        pid: created.identity.process_id,
                        birth: created.identity.creation_time_100ns,
                        parent_pid: created.parent_pid,
                        parent_birth: created.parent_birth,
                        image_sha256: created.image_sha256.clone(),
                        held_process_owner: true,
                        image_observation: "creation-event-owned-file",
                    };
                    exits.created(&member);
                    diagnostic_members.insert(event.dwProcessId, member);
                    last_event = serde_json::json!({"kind":"create-process","pid":event.dwProcessId,"tid":event.dwThreadId});
                    ack_validated = false;
                    continued = false;
                    observe(
                        "creation-held-before-ack",
                        serde_json::json!({"active":super::toolchain_diagnostics::inventory(diagnostic_members.values(),held.len()),"event":last_event,"pending_event":pending,"ack_validated":false,"continued":false,"exit_observations":exits.snapshot()}),
                    )?;
                    acknowledge(&created)?;
                    ack_validated = true;
                    observe(
                        "creation-ack-validated-before-continue",
                        serde_json::json!({"active":super::toolchain_diagnostics::inventory(diagnostic_members.values(),held.len()),"event":last_event,"pending_event":pending,"ack_validated":true,"continued":false,"exit_observations":exits.snapshot()}),
                    )?;
                    remaining(cutoff, frequency)?;
                    changed = true;
                }
                EXIT_PROCESS_DEBUG_EVENT => {
                    // The discriminant establishes this union member. Copy its
                    // scalar while original creation owners are still retained.
                    let native_exit_status = unsafe { event.u.ExitProcess.dwExitCode };
                    let creation = diagnostic_members.get(&event.dwProcessId).filter(|member| {
                        held.contains_key(&event.dwProcessId)
                            && identities.get(&event.dwProcessId) == Some(&member.birth)
                    });
                    let observation = exits.observe_exit(
                        event.dwProcessId,
                        event.dwThreadId,
                        native_exit_status,
                        creation,
                    );
                    last_event = serde_json::to_value(&observation)
                        .expect("finite scalar exit observation serializes");
                    observed_exit = Some(observation);
                    continued = false;
                    ack_validated = false;
                }
                LOAD_DLL_DEBUG_EVENT => {
                    let file = unsafe { event.u.LoadDll.hFile };
                    if !file.is_null() {
                        unsafe { CloseHandle(file) };
                    }
                }
                EXCEPTION_DEBUG_EVENT => {
                    let exception = unsafe { event.u.Exception };
                    // Only the debugger's initial breakpoint is consumed. Every
                    // other exception keeps its original application disposition.
                    if exception.dwFirstChance == 0
                        || exception.ExceptionRecord.ExceptionCode != EXCEPTION_BREAKPOINT
                        || !breakpoints.insert(event.dwProcessId)
                    {
                        continuation = DBG_EXCEPTION_NOT_HANDLED;
                    }
                }
                _ => {}
            }
            if unsafe { ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continuation) } == 0
            {
                let error = io::Error::last_os_error();
                if let Some(observation) = observed_exit.as_mut() {
                    exits.continuation_result(observation, Err(error.raw_os_error()));
                    last_event = serde_json::to_value(observation)
                        .expect("finite scalar exit observation serializes");
                }
                return Err(operation_error(
                    "ContinueDebugEvent",
                    Some(event.dwProcessId),
                    error,
                ));
            }
            pending = None;
            pending_process = None;
            if let Some(observation) = observed_exit.as_mut() {
                exits.continuation_result(observation, Ok(()));
                last_event = serde_json::to_value(observation)
                    .expect("finite scalar exit observation serializes");
                continued = true;
            }
            if event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT {
                continued = true;
                observe(
                    "creation-continued",
                    serde_json::json!({"active":super::toolchain_diagnostics::inventory(diagnostic_members.values(),held.len()),"event":last_event,"pending_event":pending,"ack_validated":ack_validated,"continued":true,"exit_observations":exits.snapshot()}),
                )?;
            }
            if event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT {
                held.remove(&event.dwProcessId).ok_or_else(|| {
                    io::Error::other("toolchain exit event lacks original creation owner")
                })?;
                active.remove(&event.dwProcessId);
                identities.remove(&event.dwProcessId);
                diagnostic_members.remove(&event.dwProcessId);
                continued = true;
                ack_validated = false;
                changed = true;
                observe(
                    "exit-continued",
                    serde_json::json!({"active":super::toolchain_diagnostics::inventory(diagnostic_members.values(),held.len()),"event":last_event,"pending_event":pending,"continued":true,"exit_observations":exits.snapshot()}),
                )?;
                if held.is_empty() {
                    return Ok(());
                }
            }
        }
        Err(io::Error::other(
            "toolchain debug event count exceeds bound",
        ))
    })();
    if let Err(original) = outcome {
        let retained_state = serde_json::json!({"active":super::toolchain_diagnostics::inventory(diagnostic_members.values(),held.len()),
            "last_event":last_event,"pending_event":pending,"ack_validated":ack_validated,
            "continued":continued,"original_child_pid":original_child.id(),"exit_observations":exits.snapshot()});
        let diagnostic_retention = observe("debug-error-before-cleanup", retained_state.clone());
        // Do not detach a live failed child and let it continue unobserved.
        let mut cleanup = Vec::new();
        // The original creation owner exists even if the cutoff expired before
        // the first debug event or duplicating that event's handle failed.
        if unsafe { TerminateProcess(original_child.as_raw_handle(), 125) } == 0 {
            let terminate_error = io::Error::last_os_error();
            if unsafe { WaitForSingleObject(original_child.as_raw_handle(), 0) } != 0 {
                cleanup.push(format!("terminate original compiler: {terminate_error}"));
            }
        }
        for (pid, owner) in &held {
            if unsafe { TerminateProcess(owner.as_raw_handle(), 125) } == 0 {
                cleanup.push(format!("terminate {pid}: {}", io::Error::last_os_error()));
            }
        }
        if let Some(process) = pending_process {
            if unsafe { TerminateProcess(process, 125) } == 0 {
                cleanup.push(format!(
                    "terminate pending creation: {}",
                    io::Error::last_os_error()
                ));
            }
        }
        if let Some((pid, tid)) = pending {
            if unsafe { ContinueDebugEvent(pid, tid, DBG_EXCEPTION_NOT_HANDLED) } == 0 {
                cleanup.push(format!(
                    "continue pending {pid}: {}",
                    io::Error::last_os_error()
                ));
            }
        }
        // Drain termination events while retaining debugger kill-on-exit safety.
        // Detaching after asynchronous TerminateProcess is not retirement proof.
        for _ in 0..131_072 {
            let milliseconds = match remaining(cutoff, frequency) {
                Ok(value) => value,
                Err(_) => 0,
            };
            let mut event: DEBUG_EVENT = unsafe { std::mem::zeroed() };
            if unsafe { WaitForDebugEvent(&mut event, milliseconds) } == 0 {
                if !active.is_empty() {
                    cleanup.push(format!(
                        "drain termination event: {}",
                        io::Error::last_os_error()
                    ));
                }
                break;
            }
            if event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT {
                let created = unsafe { event.u.CreateProcessInfo };
                active.insert(event.dwProcessId);
                if !created.hFile.is_null() {
                    unsafe { CloseHandle(created.hFile) };
                }
                if unsafe { TerminateProcess(created.hProcess, 125) } == 0 {
                    cleanup.push(format!(
                        "terminate cleanup creation: {}",
                        io::Error::last_os_error()
                    ));
                }
            } else if event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT {
                let file = unsafe { event.u.LoadDll.hFile };
                if !file.is_null() {
                    unsafe { CloseHandle(file) };
                }
            }
            let continuation = if event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT {
                DBG_EXCEPTION_NOT_HANDLED
            } else {
                DBG_CONTINUE
            };
            if unsafe { ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continuation) } == 0
            {
                cleanup.push(format!(
                    "continue cleanup event: {}",
                    io::Error::last_os_error()
                ));
                break;
            }
            if event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT {
                active.remove(&event.dwProcessId);
            }
            if active.is_empty() {
                break;
            }
        }
        if !active.is_empty() {
            cleanup.push(format!("unresolved debug process count={}", active.len()));
        }
        for (pid, owner) in &held {
            let milliseconds = remaining(cutoff, frequency).unwrap_or(0);
            if unsafe { WaitForSingleObject(owner.as_raw_handle(), milliseconds) } != 0 {
                cleanup.push(format!("retirement unproved for {pid}"));
            }
        }
        if unsafe { WaitForSingleObject(original_child.as_raw_handle(), 0) } != 0 {
            cleanup.push("original compiler retirement unproved".into());
        }
        return Err(io::Error::other(format!(
            "{original}; original-raw-os-error={:?}; held-debug-state={retained_state}; diagnostic-retention={diagnostic_retention:?}; debug cleanup={cleanup:?}",
            original.raw_os_error()
        )));
    }
    Ok(())
}
