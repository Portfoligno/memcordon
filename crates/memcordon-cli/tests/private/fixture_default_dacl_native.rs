use super::*;
use std::os::windows::{
    ffi::OsStrExt,
    io::{AsRawHandle, FromRawHandle, OwnedHandle},
};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_NO_TOKEN, GetLastError, SetLastError,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::{
    CreateRestrictedToken, DACL_SECURITY_INFORMATION, DISABLE_MAX_PRIVILEGE, DuplicateTokenEx,
    GENERIC_MAPPING, GetKernelObjectSecurity, GetLengthSid, GetSecurityDescriptorDacl,
    InitializeSecurityDescriptor, MapGenericMask, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
    SecurityImpersonation, SetSecurityDescriptorDacl, TOKEN_ADJUST_DEFAULT, TOKEN_DUPLICATE,
    TOKEN_IMPERSONATE, TOKEN_QUERY, TOKEN_USER, TokenImpersonation, TokenUser,
};
use windows_sys::Win32::System::Threading::{
    CREATE_EVENT_MANUAL_RESET, CreateEventExW, EVENT_ALL_ACCESS, EVENT_MODIFY_STATE,
    GetCurrentProcess, GetCurrentThread, OpenEventW, OpenProcessToken, OpenThreadToken,
    SYNCHRONIZATION_READ_CONTROL, SYNCHRONIZATION_SYNCHRONIZE, SetEvent, SetThreadToken,
    WaitForSingleObject,
};

const TEST_WAIT: Duration = Duration::from_secs(30);
const GENERIC_ALL: u32 = 0x1000_0000;
const EVENT_USE: u32 = EVENT_MODIFY_STATE | SYNCHRONIZATION_SYNCHRONIZE;

#[path = "fixture_event_namespace.rs"]
mod event_namespace;
#[path = "fixture_default_event_controls.rs"]
mod failure_controls;

fn live(deadline: Instant) {
    assert!(
        Instant::now() < deadline,
        "original native regression cutoff exhausted"
    );
}

fn owned(handle: HANDLE) -> OwnedHandle {
    assert!(!handle.is_null(), "{}", io::Error::last_os_error());
    assert_ne!(handle, windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE);
    // SAFETY: each successful native constructor transfers one owned handle.
    unsafe { OwnedHandle::from_raw_handle(handle) }
}

fn owned_event(handle: HANDLE, raw_error: u32) -> Result<OwnedHandle, u32> {
    if handle.is_null() || handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return Err(raw_error);
    }
    // SAFETY: this successful event constructor transfers one owned handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

fn duplicate(token: HANDLE, kind: i32) -> OwnedHandle {
    let mut handle = std::ptr::null_mut();
    // SAFETY: held source, bounded access and output; no inheritance requested.
    assert_ne!(
        unsafe {
            DuplicateTokenEx(
                token,
                TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_IMPERSONATE,
                std::ptr::null(),
                SecurityImpersonation,
                kind,
                &mut handle,
            )
        },
        0,
        "{}",
        io::Error::last_os_error()
    );
    owned(handle)
}

fn set_private_acl(token: HANDLE, bytes: &[u8]) {
    let mut storage = vec![0usize; bytes.len().div_ceil(size_of::<usize>())];
    // SAFETY: aligned allocation covers the complete test-built ACL.
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            storage.as_mut_ptr().cast::<u8>(),
            bytes.len(),
        )
    };
    let selected = TOKEN_DEFAULT_DACL {
        DefaultDacl: storage.as_mut_ptr().cast(),
    };
    // SAFETY: ONLY this test's private primary duplicate is adjusted; the
    // process token remains read/query-only and backing ACL outlives the call.
    assert_ne!(
        unsafe {
            SetTokenInformation(
                token,
                TokenDefaultDacl,
                (&selected as *const TOKEN_DEFAULT_DACL).cast(),
                size_of::<TOKEN_DEFAULT_DACL>() as u32,
            )
        },
        0,
        "{}",
        io::Error::last_os_error()
    );
}

fn user_acl(token: HANDLE) -> Vec<u8> {
    let user = query(token, TokenUser).unwrap();
    assert!(user.length >= size_of::<TOKEN_USER>());
    // SAFETY: fixed native header admitted in the aligned query.
    let sid = unsafe { user.words.as_ptr().cast::<TOKEN_USER>().read_unaligned() }
        .User
        .Sid;
    pointer_range(&user, sid.cast(), 8).unwrap();
    // SAFETY: inspect bounded SID header before asking native SID length.
    let header = unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), 8) };
    assert_eq!(header[0], 1);
    assert!(header[1] <= 15);
    let length = 8 + usize::from(header[1]) * size_of::<u32>();
    pointer_range(&user, sid.cast(), length).unwrap();
    // SAFETY: admitted complete OS-returned SID is live in user.
    assert_eq!(unsafe { GetLengthSid(sid) } as usize, length);
    let ace_length = u16::try_from(8 + length).unwrap();
    let total = u16::try_from(8 + usize::from(ace_length)).unwrap();
    let mut acl = vec![2, 0];
    acl.extend_from_slice(&total.to_le_bytes());
    acl.extend_from_slice(&1u16.to_le_bytes());
    acl.extend_from_slice(&[0, 0, 0, 0]);
    acl.extend_from_slice(&ace_length.to_le_bytes());
    acl.extend_from_slice(&GENERIC_ALL.to_le_bytes());
    // SAFETY: full SID range was admitted above; preserve its exact bytes.
    acl.extend_from_slice(unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), length) });
    assert_eq!(acl.len(), usize::from(total));
    policy::plan(Some(&acl)).unwrap();
    acl
}

struct ThreadIdentity {
    prior: Option<OwnedHandle>,
    active: bool,
}

impl ThreadIdentity {
    fn enter(token: HANDLE) -> Self {
        let mut prior = std::ptr::null_mut();
        // SAFETY: query only the current thread, retaining prior identity for restoration.
        let present = unsafe {
            OpenThreadToken(
                GetCurrentThread(),
                TOKEN_QUERY | TOKEN_IMPERSONATE,
                1,
                &mut prior,
            )
        };
        let prior = if present != 0 {
            Some(owned(prior))
        } else {
            assert_eq!(
                io::Error::last_os_error().raw_os_error(),
                Some(ERROR_NO_TOKEN as i32)
            );
            None
        };
        // SAFETY: change only this test thread to its private impersonation token.
        assert_ne!(
            unsafe { SetThreadToken(std::ptr::null(), token) },
            0,
            "{}",
            io::Error::last_os_error()
        );
        Self {
            prior,
            active: true,
        }
    }

    fn restore(&mut self) {
        if self.active {
            let token = self
                .prior
                .as_ref()
                .map_or(std::ptr::null_mut(), AsRawHandle::as_raw_handle);
            // SAFETY: restore the exact retained prior thread token, or its
            // original absence, without changing any process token.
            assert_ne!(
                unsafe { SetThreadToken(std::ptr::null(), token) },
                0,
                "{}",
                io::Error::last_os_error()
            );
            self.active = false;
        }
    }
}

impl Drop for ThreadIdentity {
    fn drop(&mut self) {
        if self.active {
            let token = self
                .prior
                .as_ref()
                .map_or(std::ptr::null_mut(), AsRawHandle::as_raw_handle);
            // SAFETY: unconditional exact restoration also runs during panic.
            // A failed restoration must not return a contaminated test thread.
            if unsafe { SetThreadToken(std::ptr::null(), token) } == 0 {
                std::process::abort();
            }
            self.active = false;
        }
    }
}

fn thread_token_identity() -> Option<(u64, u64)> {
    let mut token = std::ptr::null_mut();
    // SAFETY: query only this test thread's current effective token.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0 {
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(ERROR_NO_TOKEN as i32)
        );
        return None;
    }
    let token = owned(token);
    let information = query(token.as_raw_handle(), TokenStatistics).unwrap();
    assert!(information.length >= size_of::<TOKEN_STATISTICS>());
    // SAFETY: native statistics extent admitted above.
    let statistics = unsafe {
        information
            .words
            .as_ptr()
            .cast::<TOKEN_STATISTICS>()
            .read_unaligned()
    };
    Some((luid(statistics.TokenId), luid(statistics.ModifiedId)))
}

fn create_event(
    name: &[u16],
    security: *const SECURITY_ATTRIBUTES,
    deadline: Instant,
) -> Result<OwnedHandle, u32> {
    live(deadline);
    // SAFETY: native string and optional descriptor remain live; zero error
    // distinguishes fresh creation from a reused preexisting object.
    unsafe { SetLastError(0) };
    // SAFETY: nonsignaled private manual-reset event; never a readiness gate.
    let event = unsafe {
        CreateEventExW(
            security,
            name.as_ptr(),
            CREATE_EVENT_MANUAL_RESET,
            EVENT_USE | SYNCHRONIZATION_READ_CONTROL,
        )
    };
    // SAFETY: query this thread's creation status before any other native call.
    let code = unsafe { GetLastError() };
    let event = owned_event(event, code)?;
    assert_ne!(
        code, ERROR_ALREADY_EXISTS,
        "fresh random native event must not be reused; raw-os-error={code}"
    );
    live(deadline);
    Ok(event)
}

fn event_acl(event: HANDLE, deadline: Instant) -> Vec<u8> {
    live(deadline);
    let mut needed = 0;
    // SAFETY: sizing query for this held kernel object only.
    assert_eq!(
        unsafe {
            GetKernelObjectSecurity(
                event,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                0,
                &mut needed,
            )
        },
        0
    );
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(ERROR_INSUFFICIENT_BUFFER as i32)
    );
    assert!(needed > 0 && needed as usize <= TOKEN_QUERY_BOUND);
    let mut words = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    let mut actual = needed;
    live(deadline);
    // SAFETY: bounded aligned descriptor allocation covers advertised capacity.
    assert_ne!(
        unsafe {
            GetKernelObjectSecurity(
                event,
                DACL_SECURITY_INFORMATION,
                words.as_mut_ptr().cast(),
                needed,
                &mut actual,
            )
        },
        0,
        "{}",
        io::Error::last_os_error()
    );
    assert!(actual > 0 && actual <= needed);
    let query = Query {
        words,
        length: actual as usize,
    };
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl = std::ptr::null_mut();
    // SAFETY: complete native self-relative descriptor remains held by query.
    assert_ne!(
        unsafe {
            GetSecurityDescriptorDacl(
                query.words.as_ptr().cast_mut().cast(),
                &mut present,
                &mut acl,
                &mut defaulted,
            )
        },
        0
    );
    assert_ne!(present, 0);
    assert!(!acl.is_null());
    pointer_range(&query, acl.cast(), size_of::<ACL>()).unwrap();
    // SAFETY: fixed ACL header is inside the owned descriptor.
    let length = usize::from(unsafe { acl.read_unaligned() }.AclSize);
    assert!((size_of::<ACL>()..=MAX_ACL_BYTES).contains(&length));
    pointer_range(&query, acl.cast(), length).unwrap();
    // SAFETY: complete bounded ACL is contained by the live native descriptor.
    let bytes = unsafe { std::slice::from_raw_parts(acl.cast::<u8>(), length) }.to_vec();
    live(deadline);
    bytes
}

fn event_rc_grants(raw: &[u8]) -> usize {
    assert!(raw.len() >= size_of::<ACL>() && raw.len() <= MAX_ACL_BYTES);
    let count = usize::from(u16::from_le_bytes([raw[4], raw[5]]));
    assert!(count <= policy::MAX_ACES);
    let mut offset = size_of::<ACL>();
    let mut found = 0;
    for _ in 0..count {
        let header = raw.get(offset..offset + 4).unwrap();
        let length = usize::from(u16::from_le_bytes([header[2], header[3]]));
        assert!(length >= 16 && length % size_of::<u32>() == 0);
        let ace = raw.get(offset..offset + length).unwrap();
        assert!(matches!(ace[0], 0 | 1));
        let sid = &ace[8..];
        assert!(sid.len() >= 8 && sid[0] == 1 && sid[1] <= 15);
        assert_eq!(sid.len(), 8 + usize::from(sid[1]) * size_of::<u32>());
        if sid == RESTRICTED_CODE_SID {
            assert_eq!(ace[0], 0);
            assert_eq!(ace[1], 0);
            let mut mask = u32::from_le_bytes(ace[4..8].try_into().unwrap());
            let mapping = GENERIC_MAPPING {
                GenericRead: SYNCHRONIZATION_READ_CONTROL | SYNCHRONIZATION_SYNCHRONIZE,
                GenericWrite: SYNCHRONIZATION_READ_CONTROL | EVENT_MODIFY_STATE,
                GenericExecute: SYNCHRONIZATION_READ_CONTROL | SYNCHRONIZATION_SYNCHRONIZE,
                GenericAll: EVENT_ALL_ACCESS,
            };
            // SAFETY: map only the captured mask using this object's documented mapping.
            unsafe { MapGenericMask(&mut mask, &mapping) };
            assert_eq!(mask, EVENT_ALL_ACCESS);
            found += 1;
        }
        offset += length;
    }
    // A native ACL may reserve unused capacity after its complete declared ACE
    // inventory. Every declared ACE above remains bounded and validated.
    assert!(offset <= raw.len());
    found
}

#[test]
fn private_rc_fixture_default_objects_work_without_changing_source_or_external_denials() {
    let deadline = Instant::now() + TEST_WAIT;
    let original_thread = thread_token_identity();
    let mut current = std::ptr::null_mut();
    // SAFETY: query/duplicate only the actual process token; never adjust it.
    assert_ne!(
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE,
                &mut current,
            )
        },
        0
    );
    let current = owned(current);
    let process_before = snapshot(current.as_raw_handle()).unwrap();
    let source = duplicate(current.as_raw_handle(), TokenPrimary);
    let controlled = user_acl(source.as_raw_handle());
    set_private_acl(source.as_raw_handle(), &controlled);
    let source_before = snapshot(source.as_raw_handle()).unwrap();
    let mut rc_storage = vec![0usize; RESTRICTED_CODE_SID.len().div_ceil(size_of::<usize>())];
    // SAFETY: aligned SID allocation covers the entire canonical RC SID.
    unsafe {
        std::ptr::copy_nonoverlapping(
            RESTRICTED_CODE_SID.as_ptr(),
            rc_storage.as_mut_ptr().cast::<u8>(),
            RESTRICTED_CODE_SID.len(),
        )
    };
    let restricting = SID_AND_ATTRIBUTES {
        Sid: rc_storage.as_mut_ptr().cast(),
        Attributes: 0,
    };
    let mut derived = std::ptr::null_mut();
    live(deadline);
    // SAFETY: same actual fixture recipe, but derived ONLY from our private
    // primary duplicate; no process token/policy/filesystem ACL is mutated.
    assert_ne!(
        unsafe {
            CreateRestrictedToken(
                source.as_raw_handle(),
                DISABLE_MAX_PRIVILEGE,
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
                1,
                &restricting,
                &mut derived,
            )
        },
        0,
        "{}",
        io::Error::last_os_error()
    );
    let derived = owned(derived);
    let before = snapshot(derived.as_raw_handle()).unwrap();
    assert_eq!(before.default_acl.as_deref(), Some(controlled.as_slice()));
    prepare(source.as_raw_handle(), derived.as_raw_handle()).unwrap();
    live(deadline);
    let after = snapshot(derived.as_raw_handle()).unwrap();
    assert_eq!(after.stable, before.stable);
    assert_eq!(
        after.default_acl,
        Some(policy::plan(Some(&controlled)).unwrap())
    );
    assert_eq!(snapshot(source.as_raw_handle()).unwrap(), source_before);
    assert_eq!(snapshot(current.as_raw_handle()).unwrap(), process_before);
    prepare(source.as_raw_handle(), derived.as_raw_handle()).unwrap();
    assert_eq!(snapshot(derived.as_raw_handle()).unwrap(), after);
    assert!(prepare(source.as_raw_handle(), source.as_raw_handle()).is_err());
    assert_eq!(snapshot(source.as_raw_handle()).unwrap(), source_before);

    let namespace_name_owner = tempfile::Builder::new()
        .prefix("memcordon-fixture-namespace-")
        .tempdir()
        .unwrap();
    // Declared before every event and the impersonation guard: unwinding
    // closes events and restores identity before privileged namespace cleanup.
    let mut namespace = event_namespace::EventNamespace::create(
        source.as_raw_handle(),
        &controlled,
        &namespace_name_owner,
        deadline,
    )
    .unwrap();
    let default_name = namespace.name("self").unwrap();
    let external_name = namespace.name("external").unwrap();
    let mut storage = vec![0usize; controlled.len().div_ceil(size_of::<usize>())];
    // SAFETY: source-controlled explicit ACL remains aligned/live through creation.
    unsafe {
        std::ptr::copy_nonoverlapping(
            controlled.as_ptr(),
            storage.as_mut_ptr().cast::<u8>(),
            controlled.len(),
        )
    };
    let mut descriptor = SECURITY_DESCRIPTOR::default();
    // SAFETY: initialized writable absolute descriptor and live explicit ACL.
    assert_ne!(
        unsafe {
            InitializeSecurityDescriptor((&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(), 1)
        },
        0
    );
    // SAFETY: initialized absolute descriptor borrows the live aligned ACL.
    assert_ne!(
        unsafe {
            SetSecurityDescriptorDacl(
                (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                1,
                storage.as_ptr().cast(),
                0,
            )
        },
        0
    );
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
        bInheritHandle: 0,
    };
    let external = match create_event(&external_name, &attributes, deadline) {
        Ok(event) => event,
        Err(code) => panic!(
            "external event creation failed; access={:#x}; raw-os-error={code}",
            EVENT_USE | SYNCHRONIZATION_READ_CONTROL
        ),
    };
    assert_eq!(
        event_rc_grants(&event_acl(external.as_raw_handle(), deadline)),
        0
    );
    let effective = duplicate(derived.as_raw_handle(), TokenImpersonation);
    let mut expected_effective = after.stable.envelope.clone();
    expected_effective.token_type = TokenImpersonation as u32;
    expected_effective.impersonation_level = SecurityImpersonation as u32;
    assert_eq!(
        memcordon_windows_launch_core::query_token_envelope(effective.as_raw_handle()).unwrap(),
        expected_effective
    );
    assert_eq!(
        default_acl(effective.as_raw_handle()).unwrap(),
        after.default_acl
    );
    require_restricted_code(effective.as_raw_handle()).unwrap();
    let mut identity = ThreadIdentity::enter(effective.as_raw_handle());
    let event = match create_event(&default_name, std::ptr::null(), deadline) {
        Ok(event) => event,
        Err(code) => {
            let controls = match after.default_acl.as_deref() {
                Some(prepared_acl) => std::panic::catch_unwind(|| {
                    namespace
                        .name("explicit-control")
                        .map(|name| failure_controls::observe(&name, prepared_acl, deadline))
                })
                .map_err(|_| "control collection panicked"),
                None => Err("prepared ACL unavailable"),
            };
            // Controls are diagnostic only. The initiating named/default
            // failure remains the test result, even if collection fails.
            panic!(
                "default event creation failed; access={:#x}; raw-os-error={code}; controls={controls:?}",
                EVENT_USE | SYNCHRONIZATION_READ_CONTROL
            )
        }
    };
    let actual_event_acl = event_acl(event.as_raw_handle(), deadline);
    assert_eq!(event_rc_grants(&actual_event_acl), 1);
    assert!(
        failure_controls::event_acl_matches(
            &actual_event_acl,
            after.default_acl.as_deref().expect("attested prepared ACL"),
            deadline,
        ),
        "self event ACL must match every prepared ACE without inherited grants"
    );
    // SAFETY: nonblocking native liveness query of our exact owned event.
    assert_eq!(
        unsafe { WaitForSingleObject(event.as_raw_handle(), 0) },
        WAIT_TIMEOUT
    );
    live(deadline);
    // SAFETY: reopen exact fresh name under the SAME restricted thread token.
    let reopened = unsafe { OpenEventW(EVENT_USE, 0, default_name.as_ptr()) };
    // SAFETY: capture this exact API's numeric error before adoption/formatting.
    let reopened_error = unsafe { GetLastError() };
    let reopened = match owned_event(reopened, reopened_error) {
        Ok(event) => event,
        Err(code) => {
            panic!("default event reopening failed; access={EVENT_USE:#x}; raw-os-error={code}")
        }
    };
    // SAFETY: owned event capabilities; zero wait proves both handles address
    // the same fresh nonsignaled object, without a blocking wait allowance.
    assert_ne!(unsafe { SetEvent(reopened.as_raw_handle()) }, 0);
    // SAFETY: nonblocking observation of the original retained event.
    assert_eq!(
        unsafe { WaitForSingleObject(event.as_raw_handle(), 0) },
        WAIT_OBJECT_0
    );
    live(deadline);
    // SAFETY: same target token; explicit user-only external descriptor lacks RC.
    let denied = unsafe { OpenEventW(EVENT_USE, 0, external_name.as_ptr()) };
    let denied_error = io::Error::last_os_error();
    if !denied.is_null() {
        drop(owned(denied));
        panic!("external object without RC unexpectedly opened");
    }
    assert_eq!(
        denied_error.raw_os_error(),
        Some(ERROR_ACCESS_DENIED as i32)
    );
    identity.restore();
    assert_eq!(thread_token_identity(), original_thread);
    drop(identity);
    // Exercise restoration during unwinding as well as the normal path.
    assert!(
        std::panic::catch_unwind(|| {
            let _identity = ThreadIdentity::enter(effective.as_raw_handle());
            panic!("injected native test-body refusal");
        })
        .is_err()
    );
    assert_eq!(thread_token_identity(), original_thread);
    assert_eq!(
        default_acl(current.as_raw_handle()).unwrap(),
        process_before.default_acl
    );
    assert_eq!(
        default_acl(source.as_raw_handle()).unwrap(),
        source_before.default_acl
    );
    drop(reopened);
    drop(event);
    drop(external);
    for name in [&default_name, &external_name] {
        live(deadline);
        // SAFETY: exact random names after all their owned event handles close.
        let absent = unsafe { OpenEventW(EVENT_USE, 0, name.as_ptr()) };
        let error = io::Error::last_os_error();
        if !absent.is_null() {
            drop(owned(absent));
            panic!("owned native event leaked after retirement");
        }
        assert_eq!(
            error.raw_os_error(),
            Some(windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND as i32)
        );
    }
    namespace.close(deadline).unwrap();
    live(deadline);
}
