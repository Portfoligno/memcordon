//! One failure-only discretionary comparison; this never opens or releases the gate.
use super::controller_gate_token::{AccessRequest, TokenOrigin};
use serde_json::{Value, json};
use std::{
    io,
    mem::size_of,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{GetLastError, HANDLE, LUID},
    Security::{
        AccessCheck, DuplicateTokenEx, GENERIC_MAPPING, GetSecurityDescriptorLength,
        GetTokenInformation, IsValidSecurityDescriptor, SecurityImpersonation, TOKEN_DUPLICATE,
        TOKEN_QUERY, TOKEN_STATISTICS, TokenImpersonation, TokenStatistics,
    },
    System::{
        Performance::{QueryPerformanceCounter, QueryPerformanceFrequency},
        Threading::{GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken},
    },
};

pub(super) fn check(input: &super::descriptor::gate_access::Input) -> io::Result<()> {
    let (mut frequency, mut now) = (0, 0);
    if unsafe { QueryPerformanceFrequency(&mut frequency) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { QueryPerformanceCounter(&mut now) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if u64::try_from(frequency).ok() != Some(input.qpc_frequency) || u64::try_from(now).is_err() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "original gate comparison clock unavailable",
        ));
    }
    if now as u64 >= input.work_cutoff_qpc {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "original gate comparison cutoff elapsed",
        ));
    }
    Ok(())
}
#[derive(Clone, Copy)]
pub(super) struct Failure {
    pub operation: &'static str,
    pub reason: &'static str,
    pub raw: Option<u32>,
}
fn failure(operation: &'static str, reason: &'static str) -> Failure {
    Failure {
        operation,
        reason,
        raw: None,
    }
}
fn native(operation: &'static str) -> Failure {
    let raw = unsafe { GetLastError() };
    Failure {
        operation,
        reason: "native-call-failed",
        raw: Some(raw),
    }
}
pub(super) fn cutoff(request: &AccessRequest<'_>) -> Result<(), Failure> {
    check(request.input).map_err(|error| Failure {
        operation: "original-QPC-cutoff",
        reason: if error.kind() == io::ErrorKind::TimedOut {
            "original-work-elapsed"
        } else {
            "clock-unavailable"
        },
        raw: error.raw_os_error().map(|code| code as u32),
    })
}
fn luid(value: LUID) -> u64 {
    (u64::from(value.HighPart as u32) << u32::BITS) | u64::from(value.LowPart)
}
pub(super) fn statistics(
    token: HANDLE,
    request: &AccessRequest<'_>,
) -> Result<(u64, u64), Failure> {
    cutoff(request)?;
    let mut value: TOKEN_STATISTICS = unsafe { std::mem::zeroed() };
    let mut length = 0;
    if unsafe {
        GetTokenInformation(
            token,
            TokenStatistics,
            (&mut value as *mut TOKEN_STATISTICS).cast(),
            size_of::<TOKEN_STATISTICS>() as u32,
            &mut length,
        )
    } == 0
    {
        return Err(native("GetTokenInformation-TokenStatistics"));
    }
    cutoff(request)?;
    if length as usize != size_of::<TOKEN_STATISTICS>() {
        return Err(failure("TokenStatistics", "returned-size-differs"));
    }
    Ok((luid(value.TokenId), luid(value.ModifiedId)))
}
pub(super) fn envelope(
    token: HANDLE,
    request: &AccessRequest<'_>,
) -> Result<memcordon_core::WindowsCallerTokenEnvelopeV1, Failure> {
    let mut clock =
        || check(request.input).map_err(|_| "original gate comparison cutoff elapsed".to_owned());
    memcordon_windows_launch_core::query_token_envelope_bounded(token, &mut clock)
        .map_err(|_| failure("canonical-token-envelope", "bounded-query-unavailable"))
}

pub(super) fn observe(request: &AccessRequest<'_>, original: HANDLE, origin: TokenOrigin) -> Value {
    observe_with_control(request, original, origin, None)
}

fn current_source_matches(
    request: &AccessRequest<'_>,
    origin: TokenOrigin,
    identity: (u64, u64),
    source: &memcordon_core::WindowsCallerTokenEnvelopeV1,
) -> Result<bool, Failure> {
    cutoff(request)?;
    let mut raw = ptr::null_mut();
    if matches!(origin, TokenOrigin::Process) {
        let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) };
        let error = if opened == 0 {
            Some(unsafe { GetLastError() })
        } else {
            None
        };
        if opened != 0 {
            let owner = unsafe { OwnedHandle::from_raw_handle(raw) };
            drop(owner);
            return Ok(false);
        }
        if error != Some(1008) {
            return Err(failure(
                "current-source-context",
                "no-thread-token-not-proved",
            ));
        }
        cutoff(request)?;
    }
    let opened = match origin {
        TokenOrigin::Thread => unsafe {
            OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw)
        },
        TokenOrigin::Process => unsafe {
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw)
        },
    };
    if opened == 0 {
        return Err(native("current-source-query-only"));
    }
    let owner = unsafe { OwnedHandle::from_raw_handle(raw) };
    cutoff(request)?;
    Ok(statistics(owner.as_raw_handle(), request)? == identity
        && envelope(owner.as_raw_handle(), request)? == *source)
}

pub(super) fn observe_with_control(
    request: &AccessRequest<'_>,
    original: HANDLE,
    origin: TokenOrigin,
    mut permit: Option<super::controller_gate_control_publication::Permit>,
) -> Value {
    let mut control =
        json!({"diagnostic_only":true,"observed":false,"reason":"not-requested-or-inapplicable"});
    let mut namespace = json!({"diagnostic_only":true,"state":"unavailable","reason":"no-bound-controller-native-path"});
    let mut run = || -> Result<Value, Failure> {
        cutoff(request)?;
        request
            .input
            .validate(request.name, request.challenge)
            .map_err(|_| failure("snapshot-validation", "invalid-or-unbound-input"))?;
        let source_identity = statistics(original, request)?;
        let source = envelope(original, request)?;
        cutoff(request)?;
        let mut raw = ptr::null_mut();
        let opened = match origin {
            TokenOrigin::Thread => unsafe {
                OpenThreadToken(
                    GetCurrentThread(),
                    TOKEN_QUERY | TOKEN_DUPLICATE,
                    1,
                    &mut raw,
                )
            },
            TokenOrigin::Process => unsafe {
                OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut raw)
            },
        };
        if opened == 0 {
            return Err(native("open-same-effective-token-for-duplicate"));
        }
        // SAFETY: successful self-token open transfers exactly one owned reference.
        let duplicate_source = unsafe { OwnedHandle::from_raw_handle(raw) };
        cutoff(request)?;
        if statistics(duplicate_source.as_raw_handle(), request)? != source_identity
            || envelope(duplicate_source.as_raw_handle(), request)? != source
        {
            return Err(failure(
                "duplicate-source-binding",
                "TokenId-ModifiedId-or-full-envelope-differs",
            ));
        }
        if request.input.namespace.is_some() && permit.is_none() {
            namespace["reason"] = json!("original-error-prepublication-unverified");
        }
        if let Some(proof) = request
            .input
            .namespace
            .as_ref()
            .filter(|_| permit.is_some())
        {
            if !current_source_matches(request, origin, source_identity, &source)? {
                return Err(failure(
                    "native-path-effective-token",
                    "original-context-differs",
                ));
            }
            cutoff(request)?;
            let mut started_qpc = 0;
            if unsafe { QueryPerformanceCounter(&mut started_qpc) } == 0 {
                return Err(native("native-path-start-QPC"));
            }
            cutoff(request)?;
            namespace = super::descriptor::gate_access::namespace::native::probe(proof, || {
                check(request.input)
            });
            namespace["name_utf16_sha256"] = json!(request.input.name_utf16_sha256);
            namespace["challenge_sha256"] = json!(request.input.challenge_sha256);
            namespace["descriptor_sha256"] = json!(request.input.descriptor_sha256);
            namespace["original_work_cutoff_qpc"] = json!(request.input.work_cutoff_qpc);
            namespace["qpc_frequency"] = json!(request.input.qpc_frequency);
            namespace["started_qpc"] = json!(u64::try_from(started_qpc).ok());
            let finished_qpc = if check(request.input).is_ok() {
                let mut now = 0;
                let queried = unsafe { QueryPerformanceCounter(&mut now) } != 0;
                if queried && check(request.input).is_ok() {
                    u64::try_from(now).ok()
                } else {
                    None
                }
            } else {
                None
            };
            namespace["finished_qpc"] = json!(finished_qpc);
            namespace["token_origin"] = json!(origin.label());
            namespace["source_token_id"] = json!(source_identity.0);
            namespace["source_modified_id"] = json!(source_identity.1);
            namespace["current_full_source_before"] = json!(true);
            let readback = current_source_matches(request, origin, source_identity, &source);
            namespace["current_full_source_after"] = json!(readback.as_ref().ok());
            namespace["unprefixed_win32_comparison"]["source_confirmed"] =
                json!(readback.as_ref().ok());
            if !matches!(readback, Ok(true)) {
                namespace["unprefixed_win32_comparison"]["completion"] = json!({"state":"unavailable","reason":"inconclusive-current-full-source-readback"});
                namespace["comparison"] =
                    json!("inconclusive: current full source readback unavailable or changed");
                return Err(failure(
                    "native-path-effective-token-readback",
                    "incomplete-or-changed",
                ));
            }
        }
        if let Some(permit) = permit.take() {
            control = super::controller_gate_thread_control::observe(
                request,
                duplicate_source.as_raw_handle(),
                source_identity,
                &source,
                permit,
            );
            if control["restoration_verified"] != true {
                return Err(failure(
                    "thread-context-control",
                    "restoration-or-source-readback-incomplete",
                ));
            }
            cutoff(request)?;
        }
        let mut raw = ptr::null_mut();
        cutoff(request)?;
        if unsafe {
            DuplicateTokenEx(
                duplicate_source.as_raw_handle(),
                TOKEN_QUERY,
                ptr::null(),
                SecurityImpersonation,
                TokenImpersonation,
                &mut raw,
            )
        } == 0
        {
            return Err(native("DuplicateTokenEx-query-only-impersonation"));
        }
        // SAFETY: successful duplication transfers one query-only token owner.
        let duplicate = unsafe { OwnedHandle::from_raw_handle(raw) };
        cutoff(request)?;
        let actual = envelope(duplicate.as_raw_handle(), request)?;
        let mut expected = source.clone();
        expected.token_type = TokenImpersonation as u32;
        expected.impersonation_level = SecurityImpersonation as u32;
        if actual != expected {
            return Err(failure(
                "impersonation-token-binding",
                "full-semantic-envelope-differs",
            ));
        }
        let bytes = &request.input.descriptor;
        let mut descriptor = vec![0usize; bytes.len().div_ceil(size_of::<usize>())];
        // SAFETY: aligned destination spans the entire already bounded snapshot.
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), descriptor.as_mut_ptr().cast(), bytes.len())
        };
        cutoff(request)?;
        if unsafe { IsValidSecurityDescriptor(descriptor.as_ptr().cast_mut().cast()) } == 0 {
            return Err(failure("IsValidSecurityDescriptor", "snapshot-refused"));
        }
        cutoff(request)?;
        let length = unsafe { GetSecurityDescriptorLength(descriptor.as_ptr().cast_mut().cast()) };
        cutoff(request)?;
        if length as usize != bytes.len() {
            return Err(failure(
                "GetSecurityDescriptorLength",
                "snapshot-size-differs",
            ));
        }
        let mapping = GENERIC_MAPPING {
            GenericRead: 0x0002_0001,
            GenericWrite: 0x0002_0002,
            GenericExecute: 0x0012_0000,
            GenericAll: 0x001f_0003,
        };
        let privilege_bound = 64_usize * 1024;
        let mut privileges = vec![0usize; privilege_bound.div_ceil(size_of::<usize>())];
        let mut privilege_bytes = (privileges.len() * size_of::<usize>()) as u32;
        let (mut granted, mut status) = (0, 0);
        cutoff(request)?;
        // SAFETY: complete validated self-relative snapshot, same-bound impersonation token,
        // finite privilege output, and exact event SYNCHRONIZE request; never MAXIMUM_ALLOWED.
        let api = unsafe {
            AccessCheck(
                descriptor.as_mut_ptr().cast(),
                duplicate.as_raw_handle(),
                0x0010_0000,
                &mapping,
                privileges.as_mut_ptr().cast(),
                &mut privilege_bytes,
                &mut granted,
                &mut status,
            )
        };
        let raw_error = if api == 0 {
            Some(unsafe { GetLastError() })
        } else {
            None
        };
        let post_clock = cutoff(request);
        let original_work_elapsed = match post_clock {
            Ok(()) => Some(false),
            Err(error) if error.reason == "original-work-elapsed" => Some(true),
            Err(_) => None,
        };
        let readback = match post_clock {
            Ok(()) => (|| {
                Ok::<_, Failure>(
                    statistics(original, request)? == source_identity
                        && envelope(original, request)? == source,
                )
            })(),
            Err(error) => Err(error), // No more native queries after expiry/clock failure.
        };
        let original_work_elapsed = if original_work_elapsed == Some(false) && readback.is_err() {
            readback
                .as_ref()
                .err()
                .and_then(|error| (error.reason == "original-work-elapsed").then_some(true))
        } else {
            original_work_elapsed
        };
        let unchanged = readback.as_ref().ok().copied();
        let readback_error=readback.err().map(|error|json!({"operation":error.operation,"reason":error.reason,"raw_os_error":error.raw}));
        let privilege_capacity = privileges.len() * size_of::<usize>();
        let returned_privilege_bytes =
            (api != 0 || raw_error == Some(122)).then_some(privilege_bytes);
        let within_bound =
            returned_privilege_bytes.is_some_and(|bytes| bytes as usize <= privilege_capacity);
        let decision = super::controller_gate_diagnostic::access_result(
            api != 0,
            raw_error,
            granted,
            status != 0,
            post_clock.is_ok(),
            unchanged,
            within_bound,
        );
        let mut observation = json!({"observed":true,"diagnostic_only":true,"descriptor_sha256":request.input.descriptor_sha256,
            "name_utf16_sha256":request.input.name_utf16_sha256,"challenge_sha256":request.input.challenge_sha256,
            "token_origin":origin.label(),"source_token_unchanged":unchanged,"source_readback_error":readback_error,
            "source_token_envelope":source,"duplicate_token_envelope":actual,"duplicate_full_semantics_match":true,
            "original_work_elapsed":original_work_elapsed,"requested_access":0x0010_0000_u32,
            "privilege_set_buffer_bytes":privilege_capacity,"privilege_set_bytes":returned_privilege_bytes,"privilege_set_within_bound":returned_privilege_bytes.map(|bytes|bytes as usize<=privilege_capacity),"models_named_resolution":false,"models_mandatory_label":false});
        observation
            .as_object_mut()
            .expect("fixed observation object")
            .extend(decision.as_object().expect("fixed decision object").clone());
        Ok(observation)
    };
    let mut observation = match run() {
        Ok(value) => value,
        Err(error) => {
            json!({"observed":false,"diagnostic_only":true,"operation":error.operation,"reason":error.reason,"raw_os_error":error.raw})
        }
    };
    observation["thread_context_control"] = control;
    observation["native_namespace_probe"] = namespace;
    observation
}
