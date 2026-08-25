use std::ffi::c_void;
use std::io;
use std::ptr;

use windows_sys::Wdk::Storage::FileSystem::RtlCreateServiceSid;
use windows_sys::Win32::Foundation::{HLOCAL, LocalFree, UNICODE_STRING};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, GetFileSecurityW, GetKernelObjectSecurity,
    LABEL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    SetFileSecurityW, SetKernelObjectSecurity,
};
use windows_sys::Win32::System::Services::{
    QueryServiceObjectSecurity, SC_HANDLE, SetServiceObjectSecurity,
};

use super::pipe::wide_null;

pub const SERVICE_CONTROL_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";

pub fn public_pipe_sddl() -> Result<String, String> {
    let control = service_sid(memcordon_core::WINDOWS_CONTROL_SERVICE_NAME)?;
    Ok(format!(
        "D:P(A;;GA;;;SY)(A;;GA;;;{control})(A;;0x0012019b;;;AU)(A;;0x0012019b;;;RC)(A;;0x0012019b;;;AC)S:(ML;;NW;;;LW)"
    ))
}

pub fn private_pipe_sddl() -> Result<String, String> {
    let control = service_sid(memcordon_core::WINDOWS_CONTROL_SERVICE_NAME)?;
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    Ok(format!(
        "D:P(A;;GA;;;SY)(A;;0x0012019b;;;{control})(A;;GA;;;{launcher})"
    ))
}

pub fn state_sddl() -> Result<String, String> {
    let control = service_sid(memcordon_core::WINDOWS_CONTROL_SERVICE_NAME)?;
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    Ok(format!(
        "O:BAD:P(D;;WDWO;;;OW)(A;OICI;FA;;;SY)(A;;GXSD;;;BA)(A;OICI;FA;;;{control})(A;OICI;FA;;;{launcher})"
    ))
}

pub fn package_state_sddl() -> Result<String, String> {
    let control = service_sid(memcordon_core::WINDOWS_CONTROL_SERVICE_NAME)?;
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    Ok(format!(
        "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;{control})(A;OICI;GRGX;;;{launcher})"
    ))
}

pub fn launcher_state_sddl() -> Result<String, String> {
    let control = service_sid(memcordon_core::WINDOWS_CONTROL_SERVICE_NAME)?;
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    Ok(format!(
        "O:BAD:P(D;;WDWO;;;OW)(A;OICI;FA;;;SY)(A;OICI;FA;;;{launcher})(A;;GRGXSD;;;{control})"
    ))
}

pub fn replay_state_sddl() -> Result<String, String> {
    let control = service_sid(memcordon_core::WINDOWS_CONTROL_SERVICE_NAME)?;
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    Ok(format!(
        "O:BAD:P(D;;WDWO;;;OW)(A;OICI;FA;;;SY)(A;OICI;FA;;;{launcher})(A;OICI;GRGXSD;;;{control})"
    ))
}

pub fn admission_state_sddl() -> Result<String, String> {
    let control = service_sid(memcordon_core::WINDOWS_CONTROL_SERVICE_NAME)?;
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    Ok(format!(
        "O:BAD:P(D;;WDWO;;;OW)(A;OICI;FA;;;SY)(A;OICI;FA;;;{control})(A;OICI;FA;;;{launcher})"
    ))
}

pub fn package_mutex_sddl() -> Result<String, String> {
    let control = service_sid(memcordon_core::WINDOWS_CONTROL_SERVICE_NAME)?;
    Ok(format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{control})"))
}

pub fn launcher_process_sddl() -> Result<String, String> {
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    Ok(format!("O:SYD:P(A;;GA;;;SY)(A;;GA;;;{launcher})"))
}

pub fn protect_current_service_process(service_name: &str) -> Result<(), String> {
    let descriptor = match service_name {
        memcordon_core::WINDOWS_CONTROL_SERVICE_NAME => {
            let control = service_sid(service_name)?;
            let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
            // Clients authenticate the control image with
            // PROCESS_QUERY_LIMITED_INFORMATION. Both AU and RC ACEs are
            // required because a restricted token must pass both access
            // checks. No client receives terminate, write, or duplicate rights.
            SecurityDescriptor::from_sddl(&format!(
                "O:LSD:P(D;;WDWO;;;OW)(A;;GA;;;SY)(A;;GA;;;{control})(A;;0x00001000;;;{launcher})(A;;0x00001000;;;AU)(A;;0x00001000;;;RC)"
            ))?
        }
        memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME => {
            let launcher = service_sid(service_name)?;
            let control = service_sid(memcordon_core::WINDOWS_CONTROL_SERVICE_NAME)?;
            // The control service needs exactly PROCESS_DUP_HANDLE and
            // PROCESS_QUERY_LIMITED_INFORMATION to broker authenticated
            // handles to the launcher.
            SecurityDescriptor::from_sddl(&format!(
                "O:SYD:P(A;;GA;;;SY)(A;;GA;;;{launcher})(A;;0x00001040;;;{control})(A;;0x00001000;;;BA)"
            ))?
        }
        other => {
            return Err(format!(
                "unknown protected Windows service process: {other}"
            ));
        }
    };
    // SAFETY: the pseudo-handle denotes this live service process.
    let process = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() };
    descriptor.apply_to_kernel_object(process)?;
    descriptor.verify_kernel_object(process)
}

pub fn prepare_current_process_for_restricted_broker() -> Result<(), String> {
    // The authenticated control service opens the frontend while impersonating
    // it. A restricted token must pass both the caller SID and restricting-SID
    // checks, so grant RC only query, duplicate-handle, and synchronize access.
    let process = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() };
    let user = super::token::process_user_sid(process)?;
    let descriptor = SecurityDescriptor::from_sddl(&format!(
        "D:P(D;;WDWO;;;OW)(A;;GA;;;SY)(A;;GA;;;{user})(A;;0x00101040;;;RC)"
    ))?;
    descriptor.apply_to_kernel_object(process)?;
    descriptor.verify_kernel_object(process)
}

pub fn service_sid(service_name: &str) -> Result<String, String> {
    let name = service_name.encode_utf16().collect::<Vec<_>>();
    let byte_length = name
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(|| "service name exceeds UNICODE_STRING length".to_owned())?;
    let unicode = UNICODE_STRING {
        Length: byte_length,
        MaximumLength: byte_length,
        Buffer: name.as_ptr().cast_mut(),
    };
    let mut sid_bytes = 0_u32;
    // SAFETY: the first call is the documented size query for a live name.
    unsafe { RtlCreateServiceSid(&raw const unicode, ptr::null_mut(), &raw mut sid_bytes) };
    if sid_bytes == 0 {
        return Err(format!(
            "cannot derive the virtual service SID for {service_name}"
        ));
    }
    let sid_words = usize::try_from(sid_bytes)
        .map_err(|_| "virtual service SID size is not representable".to_owned())?
        .div_ceil(std::mem::size_of::<u32>());
    let mut sid = vec![0_u32; sid_words];
    // SAFETY: SID storage is DWORD-aligned and sized by the preceding query.
    let status = unsafe {
        RtlCreateServiceSid(
            &raw const unicode,
            sid.as_mut_ptr().cast(),
            &raw mut sid_bytes,
        )
    };
    if status < 0 {
        return Err(format!(
            "cannot derive the virtual service SID for {service_name}: NTSTATUS {status:#x}"
        ));
    }
    super::token::sid_string(sid.as_mut_ptr().cast())
}

pub struct SecurityDescriptor(*mut c_void, u32);

unsafe impl Send for SecurityDescriptor {}
unsafe impl Sync for SecurityDescriptor {}

impl SecurityDescriptor {
    pub fn from_sddl(sddl: &str) -> Result<Self, String> {
        memcordon_core::validate_windows_security_descriptor_text(sddl).map_err(str::to_owned)?;
        let information = DACL_SECURITY_INFORMATION
            | if sddl.starts_with("O:") {
                OWNER_SECURITY_INFORMATION
            } else {
                0
            }
            | if sddl.contains("S:(ML") {
                LABEL_SECURITY_INFORMATION
            } else {
                0
            };
        let sddl = wide_null(sddl);
        let mut descriptor = ptr::null_mut();
        // SAFETY: sddl is NUL-terminated and descriptor points to writable
        // storage. LocalFree owns the returned allocation in Drop.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &raw mut descriptor,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error().to_string());
        }
        Ok(Self(descriptor, information))
    }

    pub fn attributes(&self, inherit: bool) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0,
            bInheritHandle: u32::from(inherit) as i32,
        }
    }

    pub fn apply_to_path(&self, path: &std::path::Path) -> Result<(), String> {
        use std::os::windows::ffi::OsStrExt;

        let path: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: path is NUL-terminated and the descriptor remains live for
        // the synchronous security update.
        if unsafe {
            SetFileSecurityW(
                path.as_ptr(),
                self.1 | PROTECTED_DACL_SECURITY_INFORMATION,
                self.0,
            )
        } == 0
        {
            Err(io::Error::last_os_error().to_string())
        } else {
            Ok(())
        }
    }

    pub fn verify_path(&self, path: &std::path::Path) -> Result<(), String> {
        use std::os::windows::ffi::OsStrExt;

        let path: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut needed = 0_u32;
        // SAFETY: sizing call writes only the required descriptor length.
        unsafe { GetFileSecurityW(path.as_ptr(), self.1, ptr::null_mut(), 0, &raw mut needed) };
        let mut descriptor = descriptor_buffer(needed)?;
        // SAFETY: descriptor has the exact requested byte capacity.
        if unsafe {
            GetFileSecurityW(
                path.as_ptr(),
                self.1,
                descriptor.as_mut_ptr().cast(),
                needed,
                &raw mut needed,
            )
        } == 0
        {
            return Err(io::Error::last_os_error().to_string());
        }
        self.verify_descriptor(descriptor.as_mut_ptr().cast())
    }

    pub fn apply_to_service(&self, service: SC_HANDLE) -> Result<(), String> {
        // SAFETY: service is a live SCM handle with WRITE_DAC and the descriptor
        // remains live for the synchronous security update.
        if unsafe {
            SetServiceObjectSecurity(
                service,
                self.1 | PROTECTED_DACL_SECURITY_INFORMATION,
                self.0,
            )
        } == 0
        {
            Err(io::Error::last_os_error().to_string())
        } else {
            Ok(())
        }
    }

    pub fn verify_service(&self, service: SC_HANDLE) -> Result<(), String> {
        let mut needed = 0_u32;
        // SAFETY: sizing call writes only the required descriptor length.
        unsafe { QueryServiceObjectSecurity(service, self.1, ptr::null_mut(), 0, &raw mut needed) };
        let mut descriptor = descriptor_buffer(needed)?;
        // SAFETY: descriptor has the exact requested byte capacity.
        if unsafe {
            QueryServiceObjectSecurity(
                service,
                self.1,
                descriptor.as_mut_ptr().cast(),
                needed,
                &raw mut needed,
            )
        } == 0
        {
            return Err(io::Error::last_os_error().to_string());
        }
        self.verify_descriptor(descriptor.as_mut_ptr().cast())
    }

    fn verify_descriptor(&self, actual: *mut c_void) -> Result<(), String> {
        let expected = descriptor_sddl(self.0, self.1)?;
        let actual = descriptor_sddl(actual, self.1)?;
        if actual == expected {
            Ok(())
        } else {
            Err(format!(
                "security descriptor differs: expected={expected} actual={actual}"
            ))
        }
    }

    pub fn apply_to_kernel_object(
        &self,
        handle: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<(), String> {
        // SAFETY: handle denotes a live kernel object with WRITE_DAC and the
        // descriptor remains live for the synchronous security update.
        if unsafe {
            SetKernelObjectSecurity(handle, self.1 | PROTECTED_DACL_SECURITY_INFORMATION, self.0)
        } == 0
        {
            Err(io::Error::last_os_error().to_string())
        } else {
            Ok(())
        }
    }

    pub fn verify_kernel_object(
        &self,
        handle: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<(), String> {
        let mut needed = 0_u32;
        // SAFETY: sizing call writes only the required descriptor length.
        unsafe { GetKernelObjectSecurity(handle, self.1, ptr::null_mut(), 0, &raw mut needed) };
        let mut descriptor = descriptor_buffer(needed)?;
        // SAFETY: descriptor has the exact requested byte capacity.
        if unsafe {
            GetKernelObjectSecurity(
                handle,
                self.1,
                descriptor.as_mut_ptr().cast(),
                needed,
                &raw mut needed,
            )
        } == 0
        {
            return Err(io::Error::last_os_error().to_string());
        }
        self.verify_descriptor(descriptor.as_mut_ptr().cast())
    }
}

fn descriptor_buffer(bytes: u32) -> Result<Vec<u32>, String> {
    if bytes == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let words = usize::try_from(bytes)
        .map_err(|_| "security descriptor size is not representable".to_owned())?
        .div_ceil(std::mem::size_of::<u32>());
    Ok(vec![0_u32; words])
}

fn descriptor_sddl(descriptor: *mut c_void, information: u32) -> Result<String, String> {
    let mut string = ptr::null_mut();
    let mut length = 0_u32;
    // SAFETY: descriptor is a live absolute or self-relative descriptor and
    // the conversion API returns one LocalAlloc UTF-16 allocation.
    if unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            information,
            &raw mut string,
            &raw mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    let value = String::from_utf16(
        // SAFETY: length excludes the terminator and refers to the returned allocation.
        unsafe { std::slice::from_raw_parts(string, length as usize) },
    )
    .map_err(|error| error.to_string());
    // SAFETY: string is the exact LocalAlloc result and is released once.
    unsafe { LocalFree(string.cast()) };
    value
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the descriptor is the exact LocalAlloc allocation
            // returned by the conversion API and is freed once.
            unsafe { LocalFree(self.0 as HLOCAL) };
        }
    }
}
