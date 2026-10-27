//! Read-only effective token facts at the original failed OpenEventW call.
use super::controller_gate_diagnostic as limits;
use serde_json::{Value, json};
use std::{
    mem::{offset_of, size_of},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{FILETIME, GetLastError, HANDLE},
    Security::{
        GetTokenInformation, SID_AND_ATTRIBUTES, TOKEN_GROUPS, TOKEN_MANDATORY_LABEL, TOKEN_OWNER,
        TOKEN_QUERY, TOKEN_USER, TokenGroups, TokenImpersonationLevel, TokenIntegrityLevel,
        TokenMandatoryPolicy, TokenOwner, TokenRestrictedSids, TokenSessionId, TokenType,
        TokenUser,
    },
    System::Threading::{
        GetCurrentProcess, GetCurrentThread, GetCurrentThreadId, GetProcessId, GetProcessTimes,
        OpenProcessToken, OpenThreadToken,
    },
};

#[derive(Clone, Copy)]
pub(super) enum TokenOrigin {
    Thread,
    Process,
}
impl TokenOrigin {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Thread => "thread",
            Self::Process => "process",
        }
    }
}
pub(super) struct AccessRequest<'a> {
    pub input: &'a super::descriptor::gate_access::Input,
    pub name: &'a [u16],
    pub challenge: &'a [u8],
}

#[derive(Clone, Copy)]
struct Failure {
    operation: &'static str,
    reason: &'static str,
    raw: Option<u32>,
    class: Option<i32>,
}
impl Failure {
    fn value(self) -> Value {
        json!({"observed":false,"operation":self.operation,"reason":self.reason,"raw_os_error":self.raw,"class":self.class})
    }
}
fn invalid(class: i32, reason: &'static str) -> Failure {
    Failure {
        operation: "GetTokenInformation",
        reason,
        raw: None,
        class: Some(class),
    }
}
fn clock(access: Option<&AccessRequest<'_>>) -> Result<(), Failure> {
    if let Some(request) = access {
        super::controller_gate_access::check(request.input).map_err(|error| Failure {
            operation: "original-QPC-cutoff",
            reason: "expired-or-clock-unavailable",
            raw: error.raw_os_error().map(|v| v as u32),
            class: None,
        })?;
    }
    Ok(())
}
struct Buffer {
    words: Vec<usize>,
    length: usize,
}
impl Buffer {
    fn bytes(&self) -> &[u8] {
        // SAFETY: length is checked against the initialized aligned allocation.
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast(), self.length) }
    }
    fn fixed<T: Copy>(&self, class: i32) -> Result<T, Failure> {
        if self.length < size_of::<T>() {
            return Err(invalid(class, "truncated-fixed-value"));
        }
        // SAFETY: the checked buffer contains the complete native fixed value.
        Ok(unsafe { ptr::read_unaligned(self.words.as_ptr().cast()) })
    }
    fn sid(&self, address: *mut std::ffi::c_void, class: i32) -> Result<Value, Failure> {
        let start = self.words.as_ptr() as usize;
        let offset = (address as usize)
            .checked_sub(start)
            .ok_or_else(|| invalid(class, "SID-outside-response"))?;
        let tail = self
            .bytes()
            .get(offset..)
            .ok_or_else(|| invalid(class, "SID-outside-response"))?;
        let length =
            limits::sid_extent(tail).ok_or_else(|| invalid(class, "invalid-or-unbounded-SID"))?;
        Ok(json!({"binary_hex":limits::hex(&tail[..length]),"subauthority_count":tail[1]}))
    }
}
fn query(token: HANDLE, class: i32, access: Option<&AccessRequest<'_>>) -> Result<Buffer, Failure> {
    clock(access)?;
    let mut length = 0;
    // SAFETY: sizing request has no output buffer.
    let sized = unsafe { GetTokenInformation(token, class, ptr::null_mut(), 0, &mut length) };
    let code = if sized == 0 {
        Some(unsafe { GetLastError() })
    } else {
        None
    };
    clock(access)?;
    if sized != 0 || code != Some(122) || !limits::query_length(length as usize) {
        return Err(Failure {
            operation: "GetTokenInformation-sizing",
            reason: "native-error-or-size-bound",
            raw: code,
            class: Some(class),
        });
    }
    let capacity = length;
    let mut words = vec![0usize; (length as usize).div_ceil(size_of::<usize>())];
    clock(access)?;
    // SAFETY: aligned allocation covers the exact finite advertised capacity.
    if unsafe {
        GetTokenInformation(
            token,
            class,
            words.as_mut_ptr().cast(),
            capacity,
            &mut length,
        )
    } == 0
    {
        let raw = unsafe { GetLastError() };
        let failure = Failure {
            operation: "GetTokenInformation-read",
            reason: "native-error",
            raw: Some(raw),
            class: Some(class),
        };
        clock(access)?;
        return Err(failure);
    }
    clock(access)?;
    if length == 0 || length > capacity {
        return Err(invalid(class, "returned-length-differs"));
    }
    Ok(Buffer {
        words,
        length: length as usize,
    })
}
fn scalar(token: HANDLE, class: i32, access: Option<&AccessRequest<'_>>) -> Result<u32, Failure> {
    query(token, class, access)?.fixed(class)
}
fn field(result: Result<Value, Failure>) -> Value {
    match result {
        Ok(value) => json!({"observed":true,"value":value}),
        Err(error) => error.value(),
    }
}
fn groups(token: HANDLE, class: i32, access: Option<&AccessRequest<'_>>) -> Result<Value, Failure> {
    let buffer = query(token, class, access)?;
    let count = buffer.fixed::<u32>(class)? as usize;
    let start = offset_of!(TOKEN_GROUPS, Groups);
    if !limits::group_extent(count, size_of::<SID_AND_ATTRIBUTES>(), start, buffer.length) {
        return Err(invalid(
            class,
            "group-count-or-response-extent-exceeds-bound",
        ));
    }
    let mut values = Vec::with_capacity(count);
    for index in 0..count {
        // SAFETY: every complete entry is bounded above; unaligned read avoids ABI assumptions.
        let entry: SID_AND_ATTRIBUTES = unsafe {
            ptr::read_unaligned(
                buffer
                    .bytes()
                    .as_ptr()
                    .add(start + index * size_of::<SID_AND_ATTRIBUTES>())
                    .cast(),
            )
        };
        values.push(json!({"sid":buffer.sid(entry.Sid,class)?,"attributes":entry.Attributes}));
    }
    Ok(json!(values))
}
fn sid_field(
    token: HANDLE,
    class: i32,
    access: Option<&AccessRequest<'_>>,
) -> Result<Value, Failure> {
    let buffer = query(token, class, access)?;
    let sid = if class == TokenUser {
        buffer.fixed::<TOKEN_USER>(class)?.User.Sid
    } else {
        buffer.fixed::<TOKEN_OWNER>(class)?.Owner
    };
    buffer.sid(sid, class)
}
fn integrity(token: HANDLE, access: Option<&AccessRequest<'_>>) -> Result<Value, Failure> {
    let buffer = query(token, TokenIntegrityLevel, access)?;
    let label = buffer.fixed::<TOKEN_MANDATORY_LABEL>(TokenIntegrityLevel)?;
    Ok(
        json!({"sid":buffer.sid(label.Label.Sid,TokenIntegrityLevel)?,"attributes":label.Label.Attributes}),
    )
}
pub(super) fn process_identity(access: Option<&AccessRequest<'_>>) -> Value {
    match checked_process_identity(access) {
        Ok(value) => value,
        Err(error) => error.value(),
    }
}
fn checked_process_identity(access: Option<&AccessRequest<'_>>) -> Result<Value, Failure> {
    clock(access)?;
    let process = unsafe { GetCurrentProcess() };
    let (mut birth, mut exit, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    let pid = unsafe { GetProcessId(process) };
    let pid_error = if pid == 0 {
        Some(unsafe { GetLastError() })
    } else {
        None
    };
    clock(access)?;
    let birth_ok =
        unsafe { GetProcessTimes(process, &mut birth, &mut exit, &mut kernel, &mut user) };
    let birth_error = if birth_ok == 0 {
        Some(unsafe { GetLastError() })
    } else {
        None
    };
    clock(access)?;
    let birth = (u128::from(birth.dwHighDateTime) << u32::BITS) | u128::from(birth.dwLowDateTime);
    Ok(
        json!({"observed":pid_error.is_none()&&birth_error.is_none(),"pid":(pid!=0).then_some(pid),"pid_error":pid_error,"birth":(birth_ok!=0).then(||birth.to_string()),"birth_error":birth_error}),
    )
}

pub(super) fn capture(access: Option<AccessRequest<'_>>) -> Value {
    capture_with_control(access, None)
}

pub(super) fn capture_with_control(
    access: Option<AccessRequest<'_>>,
    permit: Option<super::controller_gate_control_publication::Permit>,
) -> Value {
    if let Err(error) = clock(access.as_ref()) {
        return capture_failure(error);
    }
    let process = unsafe { GetCurrentProcess() };
    let mut token = ptr::null_mut();
    // SAFETY: query-only access to the actual calling thread; OpenAsSelf does not impersonate.
    let thread_open = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) };
    let thread_error = if thread_open == 0 {
        Some(unsafe { GetLastError() })
    } else {
        None
    };
    let (origin, token) = if thread_open != 0 {
        // SAFETY: adopt the successful query handle before any fallible clock read.
        (TokenOrigin::Thread, unsafe {
            OwnedHandle::from_raw_handle(token)
        })
    } else if limits::process_fallback(thread_error.expect("failed thread open captured error")) {
        if let Err(error) = clock(access.as_ref()) {
            return capture_failure(error);
        }
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
            let raw = unsafe { GetLastError() };
            return json!({"observed":false,"query_complete":false,"origin":"process-fallback","thread_open_error":thread_error,"operation":"OpenProcessToken","raw_os_error":raw,"process":process_identity(access.as_ref()),"access_check":{"observed":false,"reason":"effective-token-unavailable"}});
        }
        // SAFETY: adopt before a post-open clock query can fail.
        (TokenOrigin::Process, unsafe {
            OwnedHandle::from_raw_handle(token)
        })
    } else {
        return json!({"observed":false,"query_complete":false,"origin":"thread-unavailable","operation":"OpenThreadToken","raw_os_error":thread_error,"process":process_identity(access.as_ref()),"access_check":{"observed":false,"reason":"effective-token-unavailable"}});
    };
    if let Err(error) = clock(access.as_ref()) {
        return capture_failure(error);
    }
    let raw = token.as_raw_handle();
    let kind = scalar(raw, TokenType, access.as_ref());
    let impersonation = match kind.ok().and_then(limits::impersonation_applicable) {
        Some(false) => json!({"applicable":false}),
        Some(true) => field(
            scalar(raw, TokenImpersonationLevel, access.as_ref()).and_then(|v| {
                if v <= 3 {
                    Ok(json!(v))
                } else {
                    Err(invalid(
                        TokenImpersonationLevel,
                        "unknown-impersonation-level",
                    ))
                }
            }),
        ),
        _ => json!({"observed":false,"reason":"token-type-unavailable-or-unknown"}),
    };
    let thread_id = clock(access.as_ref()).and_then(|()| {
        let id = unsafe { GetCurrentThreadId() };
        clock(access.as_ref())?;
        Ok(json!(id))
    });
    let mut result = json!({"observed":true,"origin":origin.label(),"thread_open_error":thread_error,
        "calling_thread_id":thread_id.as_ref().ok().cloned(),"calling_thread_query":field(thread_id),
        "process":process_identity(access.as_ref()),
        "session":field(scalar(raw,TokenSessionId,access.as_ref()).map(|v|json!(v))),
        "token_type":field(kind.map(|v|json!(v))),"impersonation_level":impersonation,
        "user":field(sid_field(raw,TokenUser,access.as_ref())),"owner":field(sid_field(raw,TokenOwner,access.as_ref())),
        "groups":field(groups(raw,TokenGroups,access.as_ref())),"restricted_sids":field(groups(raw,TokenRestrictedSids,access.as_ref())),
        "integrity":field(integrity(raw,access.as_ref())),"mandatory_policy":field(scalar(raw,TokenMandatoryPolicy,access.as_ref()).map(|v|json!(v)))});
    let complete = [
        "session",
        "token_type",
        "user",
        "owner",
        "groups",
        "restricted_sids",
        "integrity",
        "mandatory_policy",
    ]
    .iter()
    .all(|name| result[*name]["observed"] == true)
        && matches!(kind, Ok(1 | 2))
        && result["process"]["observed"] == true
        && result["process"]["pid_error"].is_null()
        && result["process"]["birth_error"].is_null()
        && (matches!(kind, Ok(1)) || result["impersonation_level"]["observed"] == true);
    result["query_complete"] = json!(complete);
    let eligible = complete
        && matches!(origin, TokenOrigin::Process)
        && matches!(kind, Ok(1))
        && thread_error == Some(1008);
    result["thread_context_control_eligibility"] = json!({"requested":permit.is_some(),"eligible":permit.is_some()&&eligible,"requires":"complete original primary process token and actual ERROR_NO_TOKEN"});
    result["access_check"] = match access {
        Some(request) => match permit.filter(|_| eligible) {
            Some(permit) => super::controller_gate_access::observe_with_control(
                &request,
                raw,
                origin,
                Some(permit),
            ),
            None => super::controller_gate_access::observe(&request, raw, origin),
        },
        None => {
            json!({"observed":false,"diagnostic_only":true,"reason":"original-held-event-snapshot-unavailable"})
        }
    };
    result
}

fn capture_failure(error: Failure) -> Value {
    let mut value = error.value();
    value["query_complete"] = json!(false);
    value["access_check"] = json!({"observed":false,"diagnostic_only":true,"reason":"effective-token-capture-unavailable"});
    value
}
