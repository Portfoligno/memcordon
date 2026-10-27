//! Query-only binding of continuously held native objects, including exited threads.
#![allow(unsafe_code)]
use crate::helper_wait_protocol as wire;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use windows_sys::Win32::{
    Foundation::{FILETIME, GetLastError, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::Threading::{
        GetExitCodeThread, GetProcessId, GetProcessIdOfThread, GetProcessTimes, GetThreadId,
        GetThreadTimes, WaitForSingleObject,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ThreadState {
    Live,
    Exited(u32),
}

fn ticks(time: FILETIME) -> u128 {
    (u128::from(time.dwHighDateTime) << u32::BITS) | u128::from(time.dwLowDateTime)
}
fn failure(
    scope: wire::BindingScope,
    boundary: wire::BindingBoundary,
    ordinal: Option<u32>,
    expected: wire::BindingIdentity,
) -> wire::BindingFailure {
    wire::BindingFailure {
        scope,
        boundary,
        operation: wire::BindingOperation::GetId,
        reason: wire::BindingReason::NativeError,
        ordinal,
        expected,
        observed: wire::BindingIdentity::default(),
        wait_status: None,
        native_error: None,
        before_qpc: 0,
        after_qpc: 0,
    }
}
fn native(
    mut record: wire::BindingFailure,
    operation: wire::BindingOperation,
    code: u32,
) -> Box<wire::BindingFailure> {
    record.operation = operation;
    record.reason = wire::BindingReason::NativeError;
    record.native_error = Some(code);
    Box::new(record)
}
fn wait(
    handle: &OwnedHandle,
    mut record: wire::BindingFailure,
) -> Result<bool, Box<wire::BindingFailure>> {
    // SAFETY: observes only the same owned query/synchronize handle, without waiting.
    let status = unsafe { WaitForSingleObject(handle.as_raw_handle(), 0) };
    record.operation = wire::BindingOperation::Wait;
    record.wait_status = Some(status);
    match status {
        WAIT_TIMEOUT => Ok(false),
        WAIT_OBJECT_0 => Ok(true),
        WAIT_FAILED => {
            let code = unsafe { GetLastError() };
            Err(native(record, wire::BindingOperation::Wait, code))
        }
        _ => {
            record.reason = wire::BindingReason::UnexpectedWait;
            Err(Box::new(record))
        }
    }
}

pub(crate) fn process(
    handle: &OwnedHandle,
    expected: wire::Identity,
    ordinal: Option<u32>,
    boundary: wire::BindingBoundary,
) -> Result<(), Box<wire::BindingFailure>> {
    let mut record = failure(
        wire::BindingScope::Process,
        boundary,
        ordinal,
        wire::BindingIdentity {
            pid: Some(expected.pid),
            tid: None,
            birth: Some(expected.birth),
        },
    );
    // SAFETY: all queries refer to this continuously retained process object.
    let pid = unsafe { GetProcessId(handle.as_raw_handle()) };
    if pid == 0 {
        let code = unsafe { GetLastError() };
        return Err(native(record, wire::BindingOperation::GetId, code));
    }
    record.observed.pid = Some(pid);
    let (mut birth, mut exit, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
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
        let code = unsafe { GetLastError() };
        return Err(native(record, wire::BindingOperation::GetTimes, code));
    }
    record.observed.birth = Some(ticks(birth));
    if record.observed != record.expected {
        record.operation = wire::BindingOperation::CompareIdentity;
        record.reason = wire::BindingReason::IdentityMismatch;
        return Err(Box::new(record));
    }
    if wait(handle, record)? {
        record.operation = wire::BindingOperation::Wait;
        record.reason = wire::BindingReason::Exited;
        record.wait_status = Some(WAIT_OBJECT_0);
        return Err(Box::new(record));
    }
    Ok(())
}

pub(crate) fn thread(
    handle: &OwnedHandle,
    expected: &wire::Thread,
    pid: u32,
    ordinal: u32,
    boundary: wire::BindingBoundary,
) -> Result<ThreadState, Box<wire::BindingFailure>> {
    let mut record = failure(
        wire::BindingScope::Thread,
        boundary,
        Some(ordinal),
        wire::BindingIdentity {
            pid: Some(pid),
            tid: Some(expected.tid),
            birth: Some(u128::from(expected.birth)),
        },
    );
    // Identity is checked BEFORE signal state so an exited unrelated object can never be skipped.
    let tid = unsafe { GetThreadId(handle.as_raw_handle()) };
    if tid == 0 {
        let code = unsafe { GetLastError() };
        return Err(native(record, wire::BindingOperation::GetId, code));
    }
    record.observed.tid = Some(tid);
    let owner = unsafe { GetProcessIdOfThread(handle.as_raw_handle()) };
    if owner == 0 {
        let code = unsafe { GetLastError() };
        return Err(native(record, wire::BindingOperation::GetOwner, code));
    }
    record.observed.pid = Some(owner);
    let (mut birth, mut exit, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    if unsafe {
        GetThreadTimes(
            handle.as_raw_handle(),
            &mut birth,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        let code = unsafe { GetLastError() };
        return Err(native(record, wire::BindingOperation::GetTimes, code));
    }
    record.observed.birth = Some(ticks(birth));
    if record.observed != record.expected {
        record.operation = wire::BindingOperation::CompareIdentity;
        record.reason = wire::BindingReason::IdentityMismatch;
        return Err(Box::new(record));
    }
    if !wait(handle, record)? {
        return Ok(ThreadState::Live);
    }
    let mut status = 0;
    if unsafe { GetExitCodeThread(handle.as_raw_handle(), &mut status) } == 0 {
        let code = unsafe { GetLastError() };
        record.wait_status = Some(WAIT_OBJECT_0);
        return Err(native(record, wire::BindingOperation::GetExitCode, code));
    }
    Ok(ThreadState::Exited(status))
}
