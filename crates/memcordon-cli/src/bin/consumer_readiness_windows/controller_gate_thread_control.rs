//! Failure-only control on the supervised original thread, never a workload fallback.
use super::{controller_gate_access as access, controller_gate_token::AccessRequest};
use serde_json::{Value, json};
use std::{
    marker::PhantomData,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
    rc::Rc,
};
use windows_sys::Win32::{
    Foundation::{ERROR_NO_TOKEN, GetLastError, HANDLE},
    Security::{
        ImpersonateLoggedOnUser, RevertToSelf, SecurityImpersonation, TOKEN_QUERY,
        TokenImpersonation, TokenPrimary,
    },
    System::Threading::{
        GetCurrentProcess, GetCurrentThread, GetCurrentThreadId, OpenEventW, OpenProcessToken,
        OpenThreadToken,
    },
};

struct Restore {
    armed: bool,
    _thread: PhantomData<Rc<()>>,
}
impl Restore {
    fn restored(&mut self, succeeded: bool) {
        if !succeeded {
            std::process::abort();
        }
        self.armed = false;
    }
    fn finish(mut self) {
        self.restored(unsafe { RevertToSelf() } != 0);
    }
}
impl Drop for Restore {
    fn drop(&mut self) {
        if self.armed {
            self.restored(unsafe { RevertToSelf() } != 0);
        }
    }
}
fn install(source: HANDLE) -> Result<Restore, access::Failure> {
    if unsafe { ImpersonateLoggedOnUser(source) } == 0 {
        return Err(failure("ImpersonateLoggedOnUser-original-primary"));
    }
    Ok(Restore {
        armed: true,
        _thread: PhantomData,
    })
}

fn failure(operation: &'static str) -> access::Failure {
    let raw = unsafe { GetLastError() };
    access::Failure {
        operation,
        reason: "native-call-failed",
        raw: Some(raw),
    }
}
fn refused(operation: &'static str) -> access::Failure {
    access::Failure {
        operation,
        reason: "original-binding-unavailable-or-different",
        raw: None,
    }
}
fn no_thread_token() -> Result<(), access::Failure> {
    let mut raw = ptr::null_mut();
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) } != 0 {
        let _owner = unsafe { OwnedHandle::from_raw_handle(raw) };
        return Err(refused("unexpected-current-thread-token"));
    }
    let error = failure("OpenThreadToken-no-token-proof");
    if error.raw == Some(ERROR_NO_TOKEN) {
        Ok(())
    } else {
        Err(error)
    }
}
fn source_unchanged(
    request: &AccessRequest<'_>,
    source: HANDLE,
    identity: (u64, u64),
    expected: &memcordon_core::WindowsCallerTokenEnvelopeV1,
) -> Result<(), access::Failure> {
    access::cutoff(request)?;
    let mut raw = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(failure("OpenProcessToken-original-source-readback"));
    }
    let current = unsafe { OwnedHandle::from_raw_handle(raw) };
    access::cutoff(request)?;
    for token in [source, current.as_raw_handle()] {
        if access::statistics(token, request)? != identity
            || &access::envelope(token, request)? != expected
        {
            return Err(refused("original-primary-source-readback"));
        }
    }
    Ok(())
}

pub(super) fn observe(
    request: &AccessRequest<'_>,
    source: HANDLE,
    identity: (u64, u64),
    expected: &memcordon_core::WindowsCallerTokenEnvelopeV1,
    _permit: super::controller_gate_control_publication::Permit,
) -> Value {
    let mut attempted = false;
    let mut opened = None;
    let mut open_error = None;
    let mut installed_identity = None;
    let mut installed_semantics_match = None;
    let mut original_process = None;
    let mut original_thread = None;
    let mut restored = false;
    let mut restoration_verified = false;
    let run = (|| -> Result<(), access::Failure> {
        access::cutoff(request)?;
        request
            .input
            .validate(request.name, request.challenge)
            .map_err(|_| refused("original-input-validation"))?;
        if expected.token_type != TokenPrimary as u32 {
            return Err(refused("original-source-not-primary"));
        }
        access::cutoff(request)?;
        no_thread_token()?;
        access::cutoff(request)?;
        source_unchanged(request, source, identity, expected)?;
        let process = super::controller_gate_token::process_identity(Some(request));
        if process["observed"] != true {
            return Err(refused("original-process-identity"));
        }
        original_process = Some(process.clone());
        access::cutoff(request)?;
        let thread = unsafe { GetCurrentThreadId() };
        original_thread = Some(thread);
        access::cutoff(request)?;
        let name: Vec<u16> = request.name.iter().copied().chain(Some(0)).collect();
        access::cutoff(request)?;
        no_thread_token()?;
        access::cutoff(request)?;
        // No allocation or fallible action can intervene before this restoration owner.
        let guard = install(source)?;
        attempted = true;
        let controlled = (|| -> Result<(), access::Failure> {
            access::cutoff(request)?;
            let mut raw = ptr::null_mut();
            if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) } == 0 {
                return Err(failure("OpenThreadToken-installed-control"));
            }
            let installed = unsafe { OwnedHandle::from_raw_handle(raw) };
            access::cutoff(request)?;
            let installed_stats = access::statistics(installed.as_raw_handle(), request)?;
            installed_identity = Some(installed_stats);
            let mut equivalent = expected.clone();
            equivalent.token_type = TokenImpersonation as u32;
            equivalent.impersonation_level = SecurityImpersonation as u32;
            if access::envelope(installed.as_raw_handle(), request)? != equivalent {
                return Err(refused("installed-full-canonical-envelope"));
            }
            installed_semantics_match = Some(true);
            source_unchanged(request, source, identity, expected)?;
            // Requery current, not just the held installed token, before the control.
            let mut raw = ptr::null_mut();
            access::cutoff(request)?;
            if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) } == 0 {
                return Err(failure("OpenThreadToken-current-control-binding"));
            }
            let current = unsafe { OwnedHandle::from_raw_handle(raw) };
            if access::statistics(current.as_raw_handle(), request)? != installed_stats
                || access::envelope(current.as_raw_handle(), request)? != equivalent
            {
                return Err(refused("current-installed-token-binding"));
            }
            access::cutoff(request)?;
            let raw = unsafe { OpenEventW(0x0010_0000, 0, name.as_ptr()) };
            open_error = if raw.is_null() {
                Some(unsafe { GetLastError() })
            } else {
                None
            };
            let owner = if raw.is_null() {
                None
            } else {
                Some(unsafe { OwnedHandle::from_raw_handle(raw.cast()) })
            };
            opened = Some(owner.is_some());
            drop(owner);
            access::cutoff(request)?;
            let mut raw = ptr::null_mut();
            if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) } == 0 {
                return Err(failure("OpenThreadToken-post-open-control-binding"));
            }
            let after = unsafe { OwnedHandle::from_raw_handle(raw) };
            if access::statistics(after.as_raw_handle(), request)? != installed_stats
                || access::envelope(after.as_raw_handle(), request)? != equivalent
            {
                return Err(refused("post-open-installed-token-binding"));
            }
            Ok(())
        })();
        guard.finish();
        restored = true;
        // Restoration is mandatory even after work expiry; an actual remaining token is fatal.
        if let Err(error) = no_thread_token() {
            if error.operation == "unexpected-current-thread-token" {
                std::process::abort();
            }
            return Err(error);
        }
        access::cutoff(request)?;
        source_unchanged(request, source, identity, expected)?;
        if super::controller_gate_token::process_identity(Some(request)) != process
            || unsafe { GetCurrentThreadId() } != thread
        {
            return Err(refused("restored-process-thread-identity"));
        }
        access::cutoff(request)?;
        restoration_verified = true;
        controlled
    })();
    json!({"diagnostic_only":true,"applicable_context":"original process-primary with ERROR_NO_TOKEN; explicit equivalent thread control",
        "impersonation_succeeded":attempted,"control_open_succeeded":opened,"control_raw_os_error":open_error,"desired_access":0x0010_0000_u32,
        "original_process":original_process,"original_thread_id":original_thread,
        "installed_token_statistics":installed_identity,"installed_full_semantics_match":installed_semantics_match,"reverted":restored,"restoration_verified":restoration_verified,
        "failure":run.err().map(|error|json!({"operation":error.operation,"reason":error.reason,"raw_os_error":error.raw})),
        "original_failure_unchanged":true,"same_original_event_identity_proved":false,"acceptance_authority":false,
        "interpretation":"explicit thread context only; no fallback success or original event identity proof"})
}
#[cfg(test)]
#[path = "../../../tests/private/windows_gate_thread_guard.rs"]
mod native_guard_tests;
