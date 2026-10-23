//! Disposable Security-only user-object creation authority, never workload authority.
#![cfg(windows)]
#![allow(unsafe_code)] // Exact owned native token queries and scoped thread attachment.

use memcordon_core::WindowsCallerTokenEnvelopeV1;
use memcordon_windows_launch_core::NativeSecurityDescriptorV1;
use memcordon_windows_launch_core::query_token_envelope;
use std::{
    ffi::c_void,
    marker::PhantomData,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
    rc::Rc,
};
use windows_sys::Win32::{Foundation::*, Security::*, System::Threading::*};

fn failure(operation: &str) -> String {
    format!("{operation}: {}", std::io::Error::last_os_error())
}

fn own(raw: HANDLE) -> Result<OwnedHandle, String> {
    if raw.is_null() {
        return Err("creation carrier returned null token".into());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(raw.cast()) })
}

fn absent_thread() -> Result<(), String> {
    let mut raw = ptr::null_mut();
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) } != 0 {
        drop(own(raw)?);
        return Err("creation role refuses nested impersonation".into());
    }
    let code = unsafe { GetLastError() };
    if code != ERROR_NO_TOKEN {
        return Err(format!(
            "creation OpenThreadToken preflight: native_code={code}"
        ));
    }
    Ok(())
}

fn primary() -> Result<OwnedHandle, String> {
    let mut raw = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut raw) }
        == 0
    {
        return Err(failure("creation OpenProcessToken"));
    }
    own(raw)
}

fn query(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Result<Vec<u64>, String> {
    let mut needed = 0;
    let result = unsafe { GetTokenInformation(token, class, ptr::null_mut(), 0, &mut needed) };
    let code = unsafe { GetLastError() };
    if result != 0 || code != ERROR_INSUFFICIENT_BUFFER || needed == 0 || needed > 64 * 1024 {
        return Err(format!(
            "creation token sizing class={class} returned={result} code={code} bytes={needed}"
        ));
    }
    let allocated = needed;
    // Reserve the extent word before the native call: TOKEN_USER/GROUPS carry
    // pointers into this allocation, which must never move after publication.
    let mut words = vec![0u64; (allocated as usize).div_ceil(size_of::<u64>()) + 1];
    if unsafe {
        GetTokenInformation(
            token,
            class,
            words.as_mut_ptr().cast(),
            allocated,
            &mut needed,
        )
    } == 0
    {
        let code = unsafe { GetLastError() };
        return Err(format!(
            "creation GetTokenInformation class={class} allocated={allocated} returned={needed}: native_code={code}"
        ));
    }
    if needed == 0 || needed > allocated {
        return Err(format!(
            "creation token query class={class} returned invalid extent: allocated={allocated} returned={needed}"
        ));
    }
    // Store the exact native extent separately in a final word. All consumers
    // validate their own fixed/variable layout against it before pointer reads.
    *words.last_mut().expect("reserved token extent word") = u64::from(needed);
    Ok(words)
}

fn entries(token: HANDLE) -> Result<Vec<LUID_AND_ATTRIBUTES>, String> {
    let words = query(token, TokenPrivileges)?;
    let bytes = *words.last().ok_or("creation token extent absent")? as usize;
    let offset = std::mem::offset_of!(TOKEN_PRIVILEGES, Privileges);
    if bytes < offset {
        return Err("creation privilege header truncated".into());
    }
    let count = unsafe { words.as_ptr().cast::<u32>().read_unaligned() } as usize;
    let end = count
        .checked_mul(size_of::<LUID_AND_ATTRIBUTES>())
        .and_then(|size| offset.checked_add(size))
        .ok_or("creation privilege extent overflow")?;
    if end > bytes {
        return Err("creation privilege inventory truncated".into());
    }
    let base = unsafe {
        words
            .as_ptr()
            .cast::<u8>()
            .add(offset)
            .cast::<LUID_AND_ATTRIBUTES>()
    };
    Ok((0..count)
        .map(|index| unsafe { base.add(index).read_unaligned() })
        .collect())
}

fn security_luid() -> Result<LUID, String> {
    let name = "SeSecurityPrivilege"
        .encode_utf16()
        .chain([0])
        .collect::<Vec<_>>();
    let mut luid = LUID::default();
    if unsafe { LookupPrivilegeValueW(ptr::null(), name.as_ptr(), &mut luid) } == 0 {
        return Err(failure("creation LookupPrivilegeValueW Security"));
    }
    Ok(luid)
}

fn same_luid(left: LUID, right: LUID) -> bool {
    left.LowPart == right.LowPart && left.HighPart == right.HighPart
}

fn adjust(token: HANDLE, luid: LUID, attributes: u32) -> Result<(), String> {
    let change = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: attributes,
        }],
    };
    unsafe { SetLastError(ERROR_SUCCESS) };
    let result =
        unsafe { AdjustTokenPrivileges(token, 0, &change, 0, ptr::null_mut(), ptr::null_mut()) };
    let code = unsafe { GetLastError() };
    if result == 0 || code != ERROR_SUCCESS {
        return Err(format!(
            "creation AdjustTokenPrivileges attributes={attributes:#x}: native_code={code}"
        ));
    }
    Ok(())
}

fn duplicate(source: HANDLE, access: u32) -> Result<OwnedHandle, String> {
    let mut raw = ptr::null_mut();
    if unsafe {
        DuplicateTokenEx(
            source,
            access,
            ptr::null(),
            SecurityImpersonation,
            TokenImpersonation,
            &mut raw,
        )
    } == 0
    {
        return Err(failure("creation DuplicateTokenEx"));
    }
    own(raw)
}

fn derive_security_only(source: HANDLE) -> Result<OwnedHandle, String> {
    let mutable = duplicate(
        source,
        TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_PRIVILEGES,
    )?;
    let security = security_luid()?;
    for privilege in entries(mutable.as_raw_handle().cast())? {
        if !same_luid(privilege.Luid, security) {
            adjust(
                mutable.as_raw_handle().cast(),
                privilege.Luid,
                SE_PRIVILEGE_REMOVED,
            )?;
        }
    }
    adjust(
        mutable.as_raw_handle().cast(),
        security,
        SE_PRIVILEGE_ENABLED,
    )?;
    let token = duplicate(
        mutable.as_raw_handle().cast(),
        TOKEN_QUERY | TOKEN_IMPERSONATE,
    )?;
    attest_access(
        token.as_raw_handle().cast(),
        TOKEN_QUERY | TOKEN_IMPERSONATE,
    )?;
    Ok(token)
}

fn attest_access(token: HANDLE, expected: u32) -> Result<(), String> {
    #[repr(C)]
    struct Basic {
        attributes: u32,
        access: u32,
        handles: u32,
        pointers: u32,
        reserved: [u32; 10],
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQueryObject(
            handle: HANDLE,
            class: u32,
            buffer: *mut c_void,
            length: u32,
            returned: *mut u32,
        ) -> i32;
    }
    let mut basic = Basic {
        attributes: 0,
        access: 0,
        handles: 0,
        pointers: 0,
        reserved: [0; 10],
    };
    let mut returned = 0;
    let status = unsafe {
        NtQueryObject(
            token,
            0,
            (&mut basic as *mut Basic).cast(),
            size_of::<Basic>() as u32,
            &mut returned,
        )
    };
    if status < 0 || returned != size_of::<Basic>() as u32 || basic.access != expected {
        return Err(format!(
            "creation handle authority differs: ntstatus={status:#x} bytes={returned} access={:#x} expected={expected:#x}",
            basic.access
        ));
    }
    Ok(())
}

fn attest(
    token: HANDLE,
    original: &WindowsCallerTokenEnvelopeV1,
) -> Result<WindowsCallerTokenEnvelopeV1, String> {
    attest_phase(token, original, "derived")
}

fn attest_phase(
    token: HANDLE,
    original: &WindowsCallerTokenEnvelopeV1,
    phase: &str,
) -> Result<WindowsCallerTokenEnvelopeV1, String> {
    let inventory = entries(token)?;
    let security = security_luid()?;
    if !matches!(inventory.as_slice(), [entry] if same_luid(entry.Luid, security)
        && entry.Attributes & SE_PRIVILEGE_ENABLED != 0 && entry.Attributes & SE_PRIVILEGE_REMOVED == 0)
    {
        return Err("creation carrier is not exactly enabled Security-only".into());
    }
    let envelope = query_token_envelope(token)?;
    let mut expected = original.clone();
    expected.token_type = TokenImpersonation as u32;
    expected.impersonation_level = SecurityImpersonation as u32;
    // The inventory above independently proves the only permitted authority
    // change. Every other measured source property must survive unchanged.
    expected.privileges_sha256 = envelope.privileges_sha256.clone();
    if envelope != expected {
        return Err("creation carrier lineage/session/token shape differs".into());
    }
    attest_sid_state(token, phase)?;
    Ok(envelope)
}

fn attest_sid_state(token: HANDLE, phase: &str) -> Result<(), String> {
    unsafe { SetLastError(ERROR_SUCCESS) };
    let restricted_result = unsafe { IsTokenRestricted(token) };
    let restricted_status = unsafe { GetLastError() };
    if restricted_result == 0 && restricted_status != ERROR_SUCCESS {
        return Err(format!(
            "creation IsTokenRestricted: native_code={restricted_status}"
        ));
    }
    if restricted_result != 0 {
        return Err("creation carrier is restricted".into());
    }
    // Historical filtering is diagnostic evidence, not a current SID inventory.
    let historical = historical_filtering(token, phase)?;
    require_no_deny_only(token)
        .map_err(|error| format!("{error}; phase={phase} historical_filtering={historical}"))?;
    let restricted = query(token, TokenRestrictedSids)?;
    if *restricted
        .last()
        .ok_or("creation restrictions extent absent")?
        < size_of::<u32>() as u64
        || unsafe { restricted.as_ptr().cast::<u32>().read_unaligned() } != 0
    {
        return Err("creation carrier is restricted".into());
    }
    let mut admin = [0u64; (SECURITY_MAX_SID_SIZE as usize).div_ceil(size_of::<u64>())];
    let mut size = SECURITY_MAX_SID_SIZE;
    if unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            ptr::null_mut(),
            admin.as_mut_ptr().cast(),
            &mut size,
        )
    } == 0
    {
        return Err(failure("creation administrator SID"));
    }
    let mut member = 0;
    if unsafe { CheckTokenMembership(token, admin.as_mut_ptr().cast::<c_void>(), &mut member) } == 0
    {
        return Err(failure("creation administrator membership"));
    }
    if member == 0 {
        return Err("creation carrier lacks enabled Administrators".into());
    }
    let mut flags = 0;
    if unsafe { GetHandleInformation(token, &mut flags) } == 0 {
        return Err(failure("creation token handle flags"));
    }
    if flags & HANDLE_FLAG_INHERIT != 0 {
        return Err("creation carrier handle is inheritable".into());
    }
    Ok(())
}

fn historical_filtering(token: HANDLE, phase: &str) -> Result<u32, String> {
    // Class 21 has a BOOLEAN payload despite requiring DWORD-aligned storage.
    // Microsoft clarification: github.com/microsoft/win32metadata/discussions/2308.
    // This native contract does not apply to the pointer-bearing query helper.
    let mut backing = 0_u32;
    let capacity = size_of::<u32>() as u32;
    let mut returned = 0;
    if unsafe {
        GetTokenInformation(
            token,
            TokenHasRestrictions,
            (&mut backing as *mut u32).cast(),
            capacity,
            &mut returned,
        )
    } == 0
    {
        let code = unsafe { GetLastError() };
        return Err(format!(
            "creation historical filtering phase={phase} class={TokenHasRestrictions} capacity={capacity} returned={returned}: native_code={code}"
        ));
    }
    let storage = unsafe {
        std::slice::from_raw_parts((&backing as *const u32).cast::<u8>(), size_of::<u32>())
    };
    crate::holder_filtering_history::decode(storage, returned)
        .map_err(|error| format!("creation historical filtering phase={phase} class={TokenHasRestrictions} capacity={capacity} returned={returned}: {error}"))
}

fn require_no_deny_only(token: HANDLE) -> Result<(), String> {
    let (user, groups) = sid_attributes(token)?;
    crate::holder_sid_attributes::require_no_deny_only(user, groups)
}

fn sid_attributes(token: HANDLE) -> Result<(u32, Vec<u32>), String> {
    let user = query(token, TokenUser)?;
    let extent = *user.last().ok_or("creation user extent absent")?;
    if extent < size_of::<TOKEN_USER>() as u64 {
        return Err(format!("creation TokenUser truncated: bytes={extent}"));
    }
    let user = unsafe { user.as_ptr().cast::<TOKEN_USER>().read_unaligned() };
    let groups = query(token, TokenGroups)?;
    let extent = *groups.last().ok_or("creation group extent absent")? as usize;
    let offset = std::mem::offset_of!(TOKEN_GROUPS, Groups);
    if extent < offset {
        return Err("creation TokenGroups header truncated".into());
    }
    let count = unsafe { groups.as_ptr().cast::<u32>().read_unaligned() } as usize;
    let end = count
        .checked_mul(size_of::<SID_AND_ATTRIBUTES>())
        .and_then(|bytes| offset.checked_add(bytes))
        .ok_or("creation TokenGroups extent overflow")?;
    if end > extent {
        return Err("creation TokenGroups inventory truncated".into());
    }
    let base = unsafe {
        groups
            .as_ptr()
            .cast::<u8>()
            .add(offset)
            .cast::<SID_AND_ATTRIBUTES>()
    };
    let attributes = (0..count)
        .map(|index| unsafe { base.add(index).read_unaligned().Attributes })
        .collect();
    Ok((user.User.Attributes, attributes))
}

#[derive(Debug, PartialEq, Eq)]
struct PrimarySnapshot {
    envelope: WindowsCallerTokenEnvelopeV1,
    identity: (u32, i32, u32, i32),
}

pub const STATION_ACCESS: u32 = 0x000f_016f;
pub const STATION_CREATE_ONLY: u32 = 1;

/// Absolute USER creation descriptor borrowing the unchanged selected SID/ACLs.
pub struct CreationSecurity<'a> {
    descriptor: Box<SECURITY_DESCRIPTOR>,
    _source: &'a NativeSecurityDescriptorV1,
}
impl<'a> CreationSecurity<'a> {
    pub fn new(source: &'a NativeSecurityDescriptorV1) -> Result<Self, String> {
        let raw = source
            .security_attributes()
            .map_err(|e| format!("creation selected attributes: {e:?}"))?
            .lpSecurityDescriptor;
        let mut owner = ptr::null_mut();
        let mut group = ptr::null_mut();
        let mut dacl = ptr::null_mut();
        let mut sacl = ptr::null_mut();
        let mut owner_default = 0;
        let mut group_default = 0;
        let mut dacl_default = 0;
        let mut sacl_default = 0;
        let mut dacl_present = 0;
        let mut sacl_present = 0;
        let mut control = 0;
        let mut revision = 0;
        if unsafe { GetSecurityDescriptorOwner(raw, &mut owner, &mut owner_default) } == 0
            || unsafe { GetSecurityDescriptorGroup(raw, &mut group, &mut group_default) } == 0
            || unsafe {
                GetSecurityDescriptorDacl(raw, &mut dacl_present, &mut dacl, &mut dacl_default)
            } == 0
            || unsafe {
                GetSecurityDescriptorSacl(raw, &mut sacl_present, &mut sacl, &mut sacl_default)
            } == 0
            || unsafe { GetSecurityDescriptorControl(raw, &mut control, &mut revision) } == 0
        {
            return Err(failure("selected creation descriptor components"));
        }
        let mut descriptor = Box::<SECURITY_DESCRIPTOR>::default();
        let absolute = (&mut *descriptor as *mut SECURITY_DESCRIPTOR).cast();
        if unsafe { InitializeSecurityDescriptor(absolute, 1) } == 0
            || unsafe { SetSecurityDescriptorOwner(absolute, owner, owner_default) } == 0
            || unsafe { SetSecurityDescriptorGroup(absolute, group, group_default) } == 0
            || unsafe { SetSecurityDescriptorDacl(absolute, dacl_present, dacl, dacl_default) } == 0
            || unsafe { SetSecurityDescriptorSacl(absolute, sacl_present, sacl, sacl_default) } == 0
        {
            return Err(failure("absolute creation descriptor components"));
        }
        let retained = SE_DACL_PROTECTED
            | SE_SACL_PROTECTED
            | SE_DACL_AUTO_INHERITED
            | SE_SACL_AUTO_INHERITED
            | SE_DACL_AUTO_INHERIT_REQ
            | SE_SACL_AUTO_INHERIT_REQ;
        let represented = retained
            | SE_OWNER_DEFAULTED
            | SE_GROUP_DEFAULTED
            | SE_DACL_DEFAULTED
            | SE_SACL_DEFAULTED
            | SE_DACL_PRESENT
            | SE_SACL_PRESENT
            | SE_SELF_RELATIVE;
        if control & !represented != 0 {
            return Err(format!(
                "selected creation descriptor has unsupported control bits: {control:#x}"
            ));
        }
        if unsafe { SetSecurityDescriptorControl(absolute, retained, control & retained) } == 0 {
            return Err(failure("absolute creation descriptor control"));
        }
        if unsafe { IsValidSecurityDescriptor(absolute) } == 0 {
            return Err("absolute creation descriptor invalid".into());
        }
        Ok(Self {
            descriptor,
            _source: source,
        })
    }

    pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: (&*self.descriptor as *const SECURITY_DESCRIPTOR)
                .cast_mut()
                .cast(),
            bInheritHandle: 0,
        }
    }
}
fn snapshot(token: HANDLE) -> Result<PrimarySnapshot, String> {
    let words = query(token, TokenStatistics)?;
    if *words.last().ok_or("creation statistics extent absent")?
        < size_of::<TOKEN_STATISTICS>() as u64
    {
        return Err("creation token statistics truncated".into());
    }
    let statistics = unsafe { words.as_ptr().cast::<TOKEN_STATISTICS>().read_unaligned() };
    Ok(PrimarySnapshot {
        envelope: query_token_envelope(token)?,
        identity: (
            statistics.TokenId.LowPart,
            statistics.TokenId.HighPart,
            statistics.ModifiedId.LowPart,
            statistics.ModifiedId.HighPart,
        ),
    })
}

/// Unrestricted SYSTEM target-session role used only for private object creation.
pub struct SecurityCreationCarrier {
    token: OwnedHandle,
    original: PrimarySnapshot,
    active: bool,
    _thread: PhantomData<Rc<()>>,
}
impl SecurityCreationCarrier {
    pub fn enter(expected_session: u32) -> Result<Self, String> {
        absent_thread()?;
        let source = primary()?;
        let original = snapshot(source.as_raw_handle().cast())?;
        if original.envelope.user_sid != "S-1-5-18"
            || original.envelope.session_id != expected_session
            || original.envelope.token_type != TokenPrimary as u32
        {
            return Err("holder creation role requires exact SYSTEM target session primary".into());
        }
        Self::attach(source.as_raw_handle().cast(), original)
    }

    fn attach(source: HANDLE, original: PrimarySnapshot) -> Result<Self, String> {
        absent_thread()?;
        let source_history = historical_filtering(source, "source")?;
        require_no_deny_only(source).map_err(|error| {
            format!("{error}; phase=source historical_filtering={source_history}")
        })?;
        {
            // CheckTokenMembership requires an impersonation token. This
            // query-only copy cannot be installed on a thread or adjusted.
            let source_query = duplicate(source, TOKEN_QUERY)?;
            attest_access(source_query.as_raw_handle().cast(), TOKEN_QUERY)?;
            attest_sid_state(source_query.as_raw_handle().cast(), "source-query-copy").map_err(
                |error| format!("{error}; source historical_filtering={source_history}"),
            )?;
        }
        let token = derive_security_only(source)?;
        let expected = attest(token.as_raw_handle().cast(), &original.envelope)
            .map_err(|error| format!("{error}; source historical_filtering={source_history}"))?;
        if unsafe { SetThreadToken(ptr::null(), token.as_raw_handle().cast()) } == 0 {
            return Err(failure("creation SetThreadToken"));
        }
        let guard = Self {
            token,
            original,
            active: true,
            _thread: PhantomData,
        };
        let validation = (|| {
            let mut raw = ptr::null_mut();
            if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) } == 0 {
                return Err(failure("creation effective OpenThreadToken"));
            }
            let effective = own(raw)?;
            attest_access(effective.as_raw_handle().cast(), TOKEN_QUERY)?;
            if attest_phase(
                effective.as_raw_handle().cast(),
                &guard.original.envelope,
                "effective",
            )? != expected
            {
                return Err("creation effective thread token differs from measured carrier".into());
            }
            Ok(())
        })();
        if let Err(primary) = validation {
            let restoration = guard.finish();
            return Err(format!("{primary}; creation restoration={restoration:?}"));
        }
        Ok(guard)
    }

    fn restore(&mut self) -> Result<(), String> {
        if unsafe { RevertToSelf() } == 0 {
            return Err(failure("creation RevertToSelf"));
        }
        self.active = false;
        absent_thread()?;
        let source = primary()?;
        if snapshot(source.as_raw_handle().cast())? != self.original {
            return Err("holder primary changed across creation role".into());
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<(), String> {
        self.restore()
    }
}
impl Drop for SecurityCreationCarrier {
    fn drop(&mut self) {
        if self.active && self.restore().is_err() {
            std::process::abort();
        }
        let _ = &self.token;
    }
}

#[cfg(test)]
#[path = "../tests/support/holder_creation.rs"]
mod tests;
