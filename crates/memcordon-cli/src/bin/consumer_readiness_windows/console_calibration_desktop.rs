//! Disposable desktop for the paired fixture launch on the caller's station.
use super::descriptor::gate_precondition::sha256;

// Reuse the trusted System32 loader so the measured fixture's ordinary
// startup never acquires eager USER32 imports from this calibration.
#[path = "../memcordon-sealed-agent/windows/user_api.rs"]
#[allow(dead_code, reason = "only the disposable desktop APIs are used here")]
mod user_api;
use std::{
    io,
    mem::size_of_val,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
};
use user_api::{
    close_desktop as CloseDesktop, create_desktop_w as CreateDesktopW,
    get_process_window_station as GetProcessWindowStation, get_thread_desktop as GetThreadDesktop,
    get_user_object_information_w as GetUserObjectInformationW,
    get_user_object_security as GetUserObjectSecurity, open_desktop_w as OpenDesktopW,
    set_thread_desktop as SetThreadDesktop,
};
use windows_sys::Win32::{
    Foundation::HANDLE,
    Security::{
        AccessCheck, DACL_SECURITY_INFORMATION, DuplicateTokenEx, GENERIC_MAPPING,
        GROUP_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetSecurityDescriptorGroup,
        GetSecurityDescriptorOwner, IsValidSecurityDescriptor, LABEL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, PRIVILEGE_SET, SecurityImpersonation, TOKEN_QUERY,
        TokenImpersonation,
    },
    System::{
        StationsAndDesktops::{
            DESKTOP_CREATEWINDOW, DESKTOP_READOBJECTS, DESKTOP_WRITEOBJECTS, HDESK, UOI_FLAGS,
            UOI_NAME, USEROBJECTFLAGS,
        },
        Threading::GetCurrentThreadId,
    },
};

const READ_CONTROL: u32 = 0x0002_0000;
const DESKTOP_ACCESS: u32 = DESKTOP_CREATEWINDOW | DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS;
const DESKTOP_MAPPING: GENERIC_MAPPING = GENERIC_MAPPING {
    GenericRead: READ_CONTROL | 0x0041,
    GenericWrite: READ_CONTROL | 0x00be,
    GenericExecute: READ_CONTROL | 0x0100,
    GenericAll: 0x000f_01ff,
};

fn station_mapping(visible: bool) -> GENERIC_MAPPING {
    // A visible station also defines the interactive read-screen/write-attributes rights.
    GENERIC_MAPPING {
        GenericRead: READ_CONTROL | 0x0103 | if visible { 0x0200 } else { 0 },
        GenericWrite: READ_CONTROL | 0x000c | if visible { 0x0010 } else { 0 },
        GenericExecute: READ_CONTROL | 0x0060,
        GenericAll: if visible { 0x000f_037f } else { 0x000f_016f },
    }
}

pub(super) struct Desktop {
    handle: HDESK,
    name: Vec<u16>,
    evidence: serde_json::Value,
}

pub(super) fn valid_digest(value: &str) -> bool {
    use sha2::digest::OutputSizeUser;
    value.len() == sha2::Sha256::output_size() * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl Desktop {
    pub(super) fn create(
        challenge_sha256: &str,
        logon_sid: &[u8],
        caller: HANDLE,
    ) -> io::Result<Self> {
        if !valid_digest(challenge_sha256)
            || logon_sid.len() != 20
            || logon_sid[..12] != [1, 3, 0, 0, 0, 0, 0, 5, 5, 0, 0, 0]
        {
            return Err(io::Error::other(
                "calibration desktop inputs are not a challenge and measured logon SID",
            ));
        }
        user_api::load().map_err(|_| desktop_error("load-user32", None))?;
        // SAFETY: both returned handles are borrowed from this process/thread.
        let station = unsafe { GetProcessWindowStation() };
        let thread_id = unsafe { GetCurrentThreadId() };
        if station.is_null() {
            return Err(native_error("read-current-station"));
        }
        let original_thread_desktop = unsafe { GetThreadDesktop(thread_id) };
        if original_thread_desktop.is_null() {
            return Err(native_error("read-current-thread-desktop"));
        }
        let station_name = user_object_name(station)?;
        let mut flags = USEROBJECTFLAGS::default();
        let mut needed = 0;
        // SAFETY: query one fixed-size USEROBJECTFLAGS from our borrowed station.
        if unsafe {
            GetUserObjectInformationW(
                station,
                UOI_FLAGS,
                (&raw mut flags).cast(),
                size_of_val(&flags) as u32,
                &mut needed,
            )
        } == 0
        {
            return Err(native_error("read-station-flags"));
        }
        // Keep only the existing station reference. If its handle does not
        // permit security readback, this station cannot qualify.
        let station_security = object_security(station)?;
        let mut token = ptr::null_mut();
        // SAFETY: caller supplies a held primary token. This creates a query
        // handle for AccessCheck and does not impersonate on the thread.
        if unsafe {
            DuplicateTokenEx(
                caller,
                TOKEN_QUERY,
                ptr::null(),
                SecurityImpersonation,
                TokenImpersonation,
                &mut token,
            )
        } == 0
        {
            return Err(native_error("duplicate-caller-for-access-check"));
        }
        let token = unsafe { OwnedHandle::from_raw_handle(token.cast()) };
        let visible = flags.dwFlags & 1 != 0;
        check_access(
            &station_security,
            &token,
            station_mapping(visible),
            "station-access-denied",
        )?;
        // One desktop per attempt. Use the complete digest of the controller's
        // fresh challenge so ordinary fixture startup gains no RNG import.
        let leaf: Vec<_> = format!("MemCordonCalibration-{challenge_sha256}")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        // SAFETY: query only the generated name on the current station.
        let existing = unsafe { OpenDesktopW(leaf.as_ptr(), 0, 0, DESKTOP_READOBJECTS) };
        if !existing.is_null() {
            unsafe { CloseDesktop(existing) };
            return Err(desktop_error("desktop-name-collision", None));
        }
        let absent = io::Error::last_os_error();
        if absent.raw_os_error() != Some(2) {
            return Err(desktop_error("verify-name-unused", absent.raw_os_error()));
        }
        // SAFETY: locally generated name, caller's current window station and
        // default security descriptor. The handle is not inherited.
        let handle = unsafe {
            CreateDesktopW(
                leaf.as_ptr(),
                ptr::null(),
                ptr::null_mut(),
                0,
                DESKTOP_ACCESS | READ_CONTROL,
                ptr::null(),
            )
        };
        if handle.is_null() {
            return Err(native_error("create-desktop"));
        }
        let mut desktop = Self {
            handle,
            name: Vec::new(),
            evidence: serde_json::Value::Null,
        };
        // SAFETY: create may attach the calling thread. Restore its borrowed
        // original desktop before querying or returning the new owned desktop.
        let current_thread = unsafe { GetThreadDesktop(thread_id) };
        if current_thread != original_thread_desktop {
            if unsafe { SetThreadDesktop(original_thread_desktop) } == 0 {
                return Err(native_error("restore-thread-desktop"));
            }
            if unsafe { GetThreadDesktop(thread_id) } != original_thread_desktop {
                return Err(io::Error::other(
                    "calibration thread desktop restoration differs",
                ));
            }
        }
        if unsafe { GetProcessWindowStation() } != station
            || user_object_name(handle)? != leaf[..leaf.len() - 1]
        {
            return Err(io::Error::other(
                "calibration desktop native station or name differs",
            ));
        }
        let desktop_security = object_security(handle)?;
        check_access(
            &desktop_security,
            &token,
            DESKTOP_MAPPING,
            "desktop-access-denied",
        )?;
        let station_name_bytes: Vec<_> = station_name
            .iter()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        desktop.name = station_name
            .into_iter()
            .chain(Some(b'\\' as u16))
            .chain(leaf[..leaf.len() - 1].iter().copied())
            .collect();
        let desktop_name_bytes: Vec<_> = desktop
            .name
            .iter()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        desktop.evidence = serde_json::json!({
            "new_desktop":true,
            "current_station_visible":visible,
            "station_name_sha256":sha256(&station_name_bytes),
            "desktop_name_sha256":sha256(&desktop_name_bytes),
            "station_security_sha256":station_security.1,
            "desktop_security_sha256":desktop_security.1,
            "security_projection":"observed owner, primary group, DACL and label projection",
            "defaults_inherited_from_caller_station":true,
            "reduced_caller_station_and_desktop_access_checked":true,
            "enabled_logon_sid_sha256":sha256(logon_sid),
        });
        Ok(desktop)
    }

    pub(super) fn name(&self) -> &[u16] {
        &self.name
    }

    pub(super) fn evidence(&self) -> &serde_json::Value {
        &self.evidence
    }

    pub(super) fn close(mut self) -> io::Result<()> {
        // SAFETY: this handle is fresh, owned and no longer the thread's desktop.
        if unsafe { CloseDesktop(self.handle) } == 0 {
            return Err(native_error("close-desktop"));
        }
        self.handle = ptr::null_mut();
        let leaf: Vec<_> = self
            .name
            .rsplit(|unit| *unit == b'\\' as u16)
            .next()
            .expect("owned desktop name")
            .iter()
            .copied()
            .chain(Some(0))
            .collect();
        // SAFETY: probe only the fresh named desktop on the unchanged station.
        let remaining = unsafe { OpenDesktopW(leaf.as_ptr(), 0, 0, DESKTOP_READOBJECTS) };
        if !remaining.is_null() {
            unsafe { CloseDesktop(remaining) };
            return Err(desktop_error("desktop-remains-after-close", None));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(2) {
            return Err(desktop_error("verify-desktop-absent", error.raw_os_error()));
        }
        Ok(())
    }
}

impl Drop for Desktop {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: release this owner's desktop reference, including on failure.
            unsafe { CloseDesktop(self.handle) };
        }
    }
}

#[derive(Debug)]
struct DesktopFailure {
    stage: &'static str,
    native_code: Option<i32>,
}

impl std::fmt::Display for DesktopFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "calibration desktop stage={} native_code={:?}",
            self.stage, self.native_code
        )
    }
}

impl std::error::Error for DesktopFailure {}

pub(super) fn failure(error: &io::Error) -> Option<(&'static str, Option<i32>)> {
    let error = error.get_ref()?.downcast_ref::<DesktopFailure>()?;
    Some((error.stage, error.native_code))
}

fn desktop_error(stage: &'static str, native_code: Option<i32>) -> io::Error {
    io::Error::other(DesktopFailure { stage, native_code })
}

fn native_error(stage: &'static str) -> io::Error {
    desktop_error(stage, io::Error::last_os_error().raw_os_error())
}

fn user_object_name(object: HANDLE) -> io::Result<Vec<u16>> {
    let mut name = [0u16; 256];
    let mut needed = 0;
    // SAFETY: bounded writable buffer for a NUL-terminated USER object name.
    if unsafe {
        GetUserObjectInformationW(
            object,
            UOI_NAME,
            name.as_mut_ptr().cast(),
            size_of_val(&name) as u32,
            &mut needed,
        )
    } == 0
    {
        return Err(native_error("read-user-object-name"));
    }
    let end = name
        .iter()
        .position(|unit| *unit == 0)
        .filter(|end| *end > 0)
        .ok_or_else(|| io::Error::other("calibration USER object name is empty or unterminated"))?;
    Ok(name[..end].to_vec())
}

fn object_security(object: HANDLE) -> io::Result<(Vec<usize>, String)> {
    let information = OWNER_SECURITY_INFORMATION
        | GROUP_SECURITY_INFORMATION
        | DACL_SECURITY_INFORMATION
        | LABEL_SECURITY_INFORMATION;
    let mut needed = 0;
    // SAFETY: fixed sizing request for the live USER object.
    unsafe { GetUserObjectSecurity(object, &information, ptr::null_mut(), 0, &mut needed) };
    if needed == 0 || needed > 16 * 1024 {
        return Err(native_error("size-user-object-security"));
    }
    let mut buffer = vec![0usize; (needed as usize).div_ceil(size_of_val(&0usize))];
    let capacity = needed;
    // SAFETY: bounded aligned buffer for the requested security projection.
    if unsafe {
        GetUserObjectSecurity(
            object,
            &information,
            buffer.as_mut_ptr().cast(),
            capacity,
            &mut needed,
        )
    } == 0
    {
        return Err(native_error("read-user-object-security"));
    }
    let descriptor = buffer.as_mut_ptr().cast();
    // SAFETY: USER returned a descriptor in the live aligned buffer.
    if needed > capacity || unsafe { IsValidSecurityDescriptor(descriptor) } == 0 {
        return Err(io::Error::other(
            "calibration USER security descriptor is invalid",
        ));
    }
    let mut owner = ptr::null_mut();
    let mut group = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let mut present = 0;
    let mut defaulted = 0;
    // SAFETY: previously validated descriptor and writable out parameters.
    if unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut defaulted) } == 0
        || unsafe { GetSecurityDescriptorGroup(descriptor, &mut group, &mut defaulted) } == 0
        || unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) }
            == 0
        || owner.is_null()
        || group.is_null()
        || present == 0
        || dacl.is_null()
    {
        return Err(io::Error::other(
            "calibration USER object lacks an owner, group or non-null DACL",
        ));
    }
    // SAFETY: descriptor occupies the reported prefix of the live allocation.
    let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast(), capacity as usize) };
    let digest = sha256(bytes);
    Ok((buffer, digest))
}

fn check_access(
    security: &(Vec<usize>, String),
    token: &OwnedHandle,
    mut mapping: GENERIC_MAPPING,
    object: &'static str,
) -> io::Result<()> {
    let mut privileges = [0usize; 64];
    let mut length = size_of_val(&privileges) as u32;
    let mut granted = 0;
    let mut allowed = 0;
    // CreateProcessAsUser's explicit USER-object connection requires full
    // access under the selected token. The desktop owner itself keeps only
    // the create and inspection handle, and this check grants nothing.
    let access = mapping.GenericAll;
    // SAFETY: a valid descriptor, identification-independent impersonation
    // token, and bounded writable AccessCheck observation buffers.
    if unsafe {
        AccessCheck(
            security.0.as_ptr().cast_mut().cast(),
            token.as_raw_handle(),
            access,
            &mut mapping,
            privileges.as_mut_ptr().cast::<PRIVILEGE_SET>(),
            &mut length,
            &mut granted,
            &mut allowed,
        )
    } == 0
    {
        return Err(native_error("query-user-object-access"));
    }
    if allowed == 0 || granted & access != access {
        return Err(desktop_error(object, None));
    }
    Ok(())
}
