//! Actual reparse-object reads stay opaque and never activate app execution links.
#![cfg(windows)]

use std::fs::{self, OpenOptions};
use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
use std::path::Path;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_NO_TOKEN, ERROR_SUCCESS, GetLastError, HANDLE, SetLastError,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, ImpersonateSelf, LookupPrivilegeValueW, RevertToSelf,
    SE_PRIVILEGE_ENABLED, SecurityImpersonation, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
    TOKEN_QUERY,
};
use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::Ioctl::FSCTL_SET_REPARSE_POINT;
use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

const APP_EXEC_LINK: u32 = 0x8000_001b;

struct ReparsePrivilege {
    token: HANDLE,
}

impl ReparsePrivilege {
    fn acquire() -> Self {
        // SAFETY: the current-thread pseudo-handle is valid and the output
        // handle storage remains live. Reject an existing impersonation context
        // rather than replacing authority owned by the test harness.
        let mut previous = std::ptr::null_mut();
        let had_token =
            unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut previous) };
        if had_token != 0 {
            // SAFETY: successful OpenThreadToken returned an owned handle.
            unsafe { CloseHandle(previous) };
            panic!(
                "native reparse fixture requires a thread without an existing impersonation token"
            );
        }
        assert_eq!(unsafe { GetLastError() }, ERROR_NO_TOKEN);
        // SAFETY: establish a thread-local copy of the caller's token; no
        // process-global privilege changes or external principal are used.
        assert_ne!(unsafe { ImpersonateSelf(SecurityImpersonation) }, 0);
        let mut guard = Self {
            token: std::ptr::null_mut(),
        };
        assert_ne!(
            unsafe {
                OpenThreadToken(
                    GetCurrentThread(),
                    TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                    1,
                    &mut guard.token,
                )
            },
            0
        );
        let name: Vec<u16> = "SeCreateSymbolicLinkPrivilege"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut privileges: TOKEN_PRIVILEGES = unsafe { std::mem::zeroed() };
        privileges.PrivilegeCount = 1;
        // SAFETY: name is NUL-terminated and output LUID storage is valid.
        assert_ne!(
            unsafe {
                LookupPrivilegeValueW(
                    std::ptr::null(),
                    name.as_ptr(),
                    &mut privileges.Privileges[0].Luid,
                )
            },
            0
        );
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        // SAFETY: the owned token and correctly initialized single privilege
        // are valid; no previous-state output is needed for a disposable token.
        unsafe { SetLastError(ERROR_SUCCESS) };
        let adjusted = unsafe {
            AdjustTokenPrivileges(
                guard.token,
                0,
                &privileges,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        let error = unsafe { GetLastError() };
        assert!(
            adjusted != 0 && error == ERROR_SUCCESS,
            "native AppExecLink fixture requires runner SeCreateSymbolicLinkPrivilege; AdjustTokenPrivileges status={adjusted}, Win32 error={error}"
        );
        guard
    }
}

impl Drop for ReparsePrivilege {
    fn drop(&mut self) {
        // SAFETY: this guard owns the temporary thread impersonation context
        // and token. Reversion precedes handle release, including during panic.
        let restored = unsafe { RevertToSelf() };
        if !self.token.is_null() {
            unsafe { CloseHandle(self.token) };
        }
        if restored == 0 {
            std::process::abort();
        }
    }
}

fn frame(payload: &[u8]) -> Vec<u8> {
    [
        APP_EXEC_LINK.to_le_bytes().as_slice(),
        u16::try_from(payload.len())
            .unwrap()
            .to_le_bytes()
            .as_slice(),
        0_u16.to_le_bytes().as_slice(),
        payload,
    ]
    .concat()
}

fn set_reparse(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let _privilege = ReparsePrivilege::acquire();
    let file = OpenOptions::new()
        .write(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let mut returned = 0;
    // SAFETY: owned file and input bytes live through this synchronous native
    // call; no output buffer or asynchronous operation is requested.
    let status = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            FSCTL_SET_REPARSE_POINT,
            data.as_ptr().cast(),
            u32::try_from(data.len()).unwrap(),
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if status == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[test]
fn app_execution_link_bytes_are_observed_without_resolving_target() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("application-alias.exe");
    fs::write(&path, []).unwrap();
    let mut payload = 3_u32.to_le_bytes().to_vec();
    for field in [
        "Memcordon.Inspection.Fixture",
        "UninstalledApplication",
        "C:\\memcordon-absent-target\\missing.exe",
        "0",
    ] {
        for unit in field.encode_utf16().chain(std::iter::once(0)) {
            payload.extend_from_slice(&unit.to_le_bytes());
        }
    }
    let data = frame(&payload);
    set_reparse(&path, &data).unwrap_or_else(|error| panic!("native AppExecLink fixture creation failed for {path:?}: {error}; requires a local filesystem supporting application execution reparse links"));
    assert_eq!(
        memcordon_native_inspect::windows_reparse_data(&path).unwrap(),
        data
    );
}

#[test]
fn malformed_native_reparse_request_is_rejected_without_creating_evidence() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("malformed-alias.exe");
    fs::write(&path, []).unwrap();
    let mut invalid = frame(&[]);
    invalid.pop();
    assert!(set_reparse(&path, &invalid).is_err());
    assert!(memcordon_native_inspect::windows_reparse_data(&path).is_err());
}
