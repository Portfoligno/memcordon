//! Isolated calibration resources; never an original workload or access authority.
use crate::windows_access_failure_preparation::{
    PreparationOperation as PrepOp, RequestFacts, State as PreparationState,
};
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::time::Instant;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_NO_TOKEN, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::{
    Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT,
        SetSecurityInfo,
    },
    CreateRestrictedToken, CreateWellKnownSid, DACL_SECURITY_INFORMATION, DISABLE_MAX_PRIVILEGE,
    EqualSid, GetSecurityDescriptorDacl, GetTokenInformation, ImpersonateLoggedOnUser,
    IsTokenRestricted, PROTECTED_DACL_SECURITY_INFORMATION, RevertToSelf, SID_AND_ATTRIBUTES,
    TOKEN_DUPLICATE, TOKEN_GROUPS, TOKEN_QUERY, TokenRestrictedSids, WinRestrictedCodeSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, GetCurrentThreadId, OpenProcessToken, OpenThreadToken,
};

fn live(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "original access probe cutoff expired",
        ))
    } else {
        Ok(())
    }
}

#[derive(Debug)]
struct RestorationSecondary {
    primary: io::Error,
    secondary: io::Error,
}
impl std::fmt::Display for RestorationSecondary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}; restoration secondary: {}",
            self.primary, self.secondary
        )
    }
}
impl std::error::Error for RestorationSecondary {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
fn restoration_error(
    primary: io::Result<serde_json::Value>,
    secondary: io::Error,
) -> io::Result<serde_json::Value> {
    match primary {
        Err(primary) => Err(io::Error::new(
            primary.kind(),
            RestorationSecondary { primary, secondary },
        )),
        Ok(_) => Err(secondary),
    }
}
fn abort_restoration(phase: &str) -> ! {
    let error = io::Error::last_os_error();
    use std::io::Write;
    let _ = writeln!(
        io::stderr().lock(),
        "calibration mandatory RevertToSelf failed; phase={phase}; native-code={:?}; aborting owned helper",
        error.raw_os_error()
    );
    // A fixed structured terminal frame preserves the native restoration code
    // for the separate controller even though this helper must now abort.
    let record = serde_json::json!({"format":"memcordon.access-calibration-fatal","restoration_failed":true,"native_error":error.raw_os_error(),"phase":phase});
    let mut output = io::stdout().lock();
    let _ = serde_json::to_writer(&mut output, &record);
    let _ = output.write_all(b"\n");
    let _ = output.flush();
    std::process::abort()
}

fn rc_profile(
    token: &OwnedHandle,
    rc: *mut core::ffi::c_void,
    mut preparation: Option<&mut PreparationState>,
) -> io::Result<()> {
    let mut operation = |operation| {
        if let Some(state) = preparation.as_deref_mut() {
            state.operation = operation;
        }
    };
    let mut bytes = [0usize; 256];
    let mut length = 0;
    operation(PrepOp::QueryRestrictedSids);
    // SAFETY: aligned bounded writable token buffer and held query token.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenRestrictedSids,
            bytes.as_mut_ptr().cast(),
            std::mem::size_of_val(&bytes) as u32,
            &mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    operation(PrepOp::ValidateRestrictedSidsExtent);
    if length as usize > std::mem::size_of_val(&bytes)
        || (length as usize) < std::mem::size_of::<TOKEN_GROUPS>()
    {
        return Err(io::Error::other("restricted SID query has invalid extent"));
    }
    // SAFETY: successful bounded TOKEN_GROUPS output, checked fixed prefix.
    let groups = unsafe { &*bytes.as_ptr().cast::<TOKEN_GROUPS>() };
    operation(PrepOp::ValidateRestrictedSidCount);
    if groups.GroupCount != 1 {
        return Err(io::Error::other(
            "calibration requires exactly RestrictedCode",
        ));
    }
    let base = bytes.as_ptr() as usize;
    let end = base + length as usize;
    let sid = groups.Groups[0].Sid as usize;
    operation(PrepOp::ValidateRestrictedSidPointer);
    if sid < base || sid.checked_add(8).is_none_or(|limit| limit > end) {
        return Err(io::Error::other(
            "restricted SID pointer outside token output",
        ));
    }
    // SAFETY: the fixed SID header is within the successful native output extent.
    let header = unsafe { std::slice::from_raw_parts(sid as *const u8, 8) };
    operation(PrepOp::ValidateRestrictedSidExtent);
    if header[0] != 1
        || header[1] > 15
        || sid
            .checked_add(8 + usize::from(header[1]) * 4)
            .is_none_or(|limit| limit > end)
    {
        return Err(io::Error::other("restricted SID extent invalid"));
    }
    // SAFETY: complete native SID extent is now proved inside the held output buffer.
    operation(PrepOp::CompareRestrictedSid);
    if unsafe { EqualSid(groups.Groups[0].Sid, rc) } == 0 {
        return Err(io::Error::other(
            "calibration requires exactly RestrictedCode",
        ));
    }
    // SAFETY: held token query only.
    operation(PrepOp::ValidateTokenRestricted);
    if unsafe { IsTokenRestricted(token.as_raw_handle()) } == 0 {
        return Err(io::Error::other("calibration token is not restricted"));
    }
    Ok(())
}

pub struct Calibration {
    path: std::path::PathBuf,
    file: Option<File>,
    object_name: Vec<u16>,
    restricted: OwnedHandle,
    rc: [u32; 17],
}

impl Calibration {
    pub fn prepare(directory: &Path, deadline: Instant) -> io::Result<Self> {
        let mut state = PreparationState {
            request: RequestFacts {
                owner_file_desired_access: windows_sys::Win32::Storage::FileSystem::WRITE_DAC
                    | FILE_READ_DATA
                    | windows_sys::Win32::Storage::FileSystem::FILE_WRITE_DATA,
                owner_file_share: FILE_SHARE_READ | FILE_SHARE_WRITE,
                owner_file_flags:
                    windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
                security_information: DACL_SECURITY_INFORMATION
                    | PROTECTED_DACL_SECURITY_INFORMATION,
                source_token_access: TOKEN_QUERY | TOKEN_DUPLICATE,
            },
            ..Default::default()
        };
        Self::prepare_observed(directory, deadline, &mut state)
            .map_err(|primary| state.failure(primary))
    }

    fn prepare_observed(
        directory: &Path,
        deadline: Instant,
        state: &mut PreparationState,
    ) -> io::Result<Self> {
        state.operation = PrepOp::CutoffInitial;
        live(deadline)?;
        let mut existing = std::ptr::null_mut();
        state.operation = PrepOp::OpenCurrentThreadToken;
        // SAFETY: current thread/query output; this probe refuses an existing impersonation.
        if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut existing) } != 0 {
            // SAFETY: successful native token acquisition is uniquely owned.
            drop(unsafe { OwnedHandle::from_raw_handle(existing) });
            state.operation = PrepOp::ValidateNoThreadToken;
            return Err(io::Error::other("calibration helper already impersonates"));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_NO_TOKEN as i32) {
            return Err(error);
        }
        state.operation = PrepOp::CutoffBeforeOwnedFile;
        live(deadline)?;
        let path = directory.join("ordinary-rc-denied-input.bin");
        // The parent owns this separate calibration namespace through helper settlement.
        use std::io::Write;
        state.operation = PrepOp::CreateOwnedFile;
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .access_mode(state.request.owner_file_desired_access)
            .share_mode(state.request.owner_file_share)
            .custom_flags(state.request.owner_file_flags)
            .open(&path)?;
        state.progress.file_created = true;
        state.operation = PrepOp::WriteOwnedFile;
        file.write_all(b"owned access-check calibration\n")?;
        state.progress.fixed_bytes_written = true;
        let mut descriptor = std::ptr::null_mut();
        let sddl: Vec<u16> = "D:P(D;;0x1;;;RC)(A;;FA;;;OW)(A;;FA;;;SY)"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        state.operation = PrepOp::ConvertOwnedDacl;
        // SAFETY: fixed NUL-terminated DACL only; no host object or SACL is modified.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        struct Descriptor(*mut core::ffi::c_void);
        impl Drop for Descriptor {
            fn drop(&mut self) {
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
        let descriptor = Descriptor(descriptor);
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl = std::ptr::null_mut();
        state.operation = PrepOp::ExtractOwnedDacl;
        // SAFETY: held valid converted descriptor and writable ACL outputs.
        if unsafe {
            GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        state.operation = PrepOp::ValidateOwnedDacl;
        if present == 0 || dacl.is_null() {
            return Err(io::Error::other("owned calibration DACL absent"));
        }
        state.operation = PrepOp::ApplyOwnedDacl;
        // SAFETY: mutate ONLY the same create-new held file object; never a pathname target.
        let status = unsafe {
            SetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                state.request.security_information,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null(),
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        state.progress.dacl_applied = true;
        state.operation = PrepOp::CutoffAfterOwnedDacl;
        live(deadline)?;
        // This reads through the pre-DACL held handle, not a fresh ordinary access check.
        use std::io::{Read, Seek};
        state.operation = PrepOp::RewindOwnedFile;
        file.rewind()?;
        let mut ordinary = [0u8; 1];
        state.operation = PrepOp::ReadOwnedFile;
        file.read_exact(&mut ordinary)?;
        state.progress.ordinary_held_read_completed = true;
        let mut object_name = vec![0u16; 32768];
        state.operation = PrepOp::QueryOwnedNativeName;
        // SAFETY: held owned file and bounded writable native name buffer.
        let units = unsafe {
            windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                object_name.as_mut_ptr(),
                object_name.len() as u32,
                windows_sys::Win32::Storage::FileSystem::VOLUME_NAME_NT,
            )
        };
        if units == 0 {
            return Err(io::Error::last_os_error());
        }
        state.operation = PrepOp::ValidateOwnedNativeName;
        if units as usize >= object_name.len() {
            return Err(io::Error::other("owned probe native path exceeds bound"));
        }
        object_name.truncate(units as usize);
        state.progress.native_name_observed = true;
        let mut source = std::ptr::null_mut();
        state.operation = PrepOp::OpenSourceToken;
        // SAFETY: current process token only, query/duplicate rights as required to derive a token.
        if unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                state.request.source_token_access,
                &mut source,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: new uniquely owned token handle.
        let source = unsafe { OwnedHandle::from_raw_handle(source) };
        state.progress.source_token_opened = true;
        let mut rc = [0u32; 17];
        let mut length = std::mem::size_of_val(&rc) as u32;
        state.operation = PrepOp::CreateRestrictedCodeSid;
        // SAFETY: aligned maximum SID buffer with writable native extent.
        if unsafe {
            CreateWellKnownSid(
                WinRestrictedCodeSid,
                std::ptr::null_mut(),
                rc.as_mut_ptr().cast(),
                &mut length,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let sid = SID_AND_ATTRIBUTES {
            Sid: rc.as_mut_ptr().cast(),
            Attributes: 0,
        };
        let mut restricted = std::ptr::null_mut();
        state.operation = PrepOp::DeriveRestrictedToken;
        // SAFETY: same RC construction as the installed fixture; no privilege enablement.
        if unsafe {
            CreateRestrictedToken(
                source.as_raw_handle(),
                DISABLE_MAX_PRIVILEGE,
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
                1,
                &sid,
                &mut restricted,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful native creation transfers a unique handle.
        let restricted = unsafe { OwnedHandle::from_raw_handle(restricted) };
        state.progress.restricted_token_created = true;
        rc_profile(&restricted, rc.as_mut_ptr().cast(), Some(state))?;
        state.progress.restricted_profile_validated = true;
        state.operation = PrepOp::CutoffFinal;
        live(deadline)?;
        Ok(Self {
            path,
            file: Some(file),
            object_name,
            restricted,
            rc,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn object_name(&self) -> &[u16] {
        &self.object_name
    }

    pub fn run(&mut self, deadline: Instant) -> io::Result<serde_json::Value> {
        let path: Vec<u16> = self.path.as_os_str().encode_wide().chain(Some(0)).collect();
        live(deadline)?;
        // SAFETY: newly derived held RC token; this ordinary helper began with no thread token.
        if unsafe { ImpersonateLoggedOnUser(self.restricted.as_raw_handle()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        struct Revert(bool);
        impl Drop for Revert {
            fn drop(&mut self) {
                if self.0 && unsafe { RevertToSelf() } == 0 {
                    abort_restoration("unwind-fallback");
                }
            }
        }
        let mut revert = Revert(true);
        let attempted = (|| -> io::Result<serde_json::Value> {
            live(deadline)?;
            let mut effective = std::ptr::null_mut();
            // SAFETY: capture the actual effective thread token, query only.
            if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut effective) } == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: successful native token acquisition transfers a unique handle.
            let effective = unsafe { OwnedHandle::from_raw_handle(effective) };
            rc_profile(&effective, self.rc.as_mut_ptr().cast(), None)?;
            let mut effective_type = 0i32;
            let mut effective_level = 0i32;
            let mut native_length = 0;
            let scalar_bytes = std::mem::size_of::<i32>() as u32;
            // SAFETY: same effective query token and fixed writable scalar outputs.
            if unsafe {
                GetTokenInformation(
                    effective.as_raw_handle(),
                    windows_sys::Win32::Security::TokenType,
                    (&mut effective_type as *mut i32).cast(),
                    scalar_bytes,
                    &mut native_length,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            if native_length != scalar_bytes {
                return Err(io::Error::other("effective token type extent differs"));
            }
            // SAFETY: same actual impersonation token and writable level scalar.
            if unsafe {
                GetTokenInformation(
                    effective.as_raw_handle(),
                    windows_sys::Win32::Security::TokenImpersonationLevel,
                    (&mut effective_level as *mut i32).cast(),
                    scalar_bytes,
                    &mut native_length,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            if native_length != scalar_bytes
                || effective_type != windows_sys::Win32::Security::TokenImpersonation
                || effective_level != windows_sys::Win32::Security::SecurityImpersonation
            {
                return Err(io::Error::other(
                    "effective calibration impersonation profile differs",
                ));
            }
            let (started_qpc, frequency) = crate::test_support::windows_performance_counter()?;
            live(deadline)?;
            // SAFETY: one intentional access denial on the newly owned known-DACL object.
            let opened = unsafe {
                CreateFileW(
                    path.as_ptr(),
                    FILE_READ_DATA,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    std::ptr::null_mut(),
                )
            };
            let error = if opened == INVALID_HANDLE_VALUE {
                Some(io::Error::last_os_error())
            } else {
                None
            };
            if opened != INVALID_HANDLE_VALUE {
                unsafe {
                    CloseHandle(opened);
                }
            }
            let (finished_qpc, observed_frequency) =
                crate::test_support::windows_performance_counter()?;
            live(deadline)?;
            if frequency != observed_frequency {
                return Err(io::Error::other("calibration QPC frequency changed"));
            }
            Ok(
                serde_json::json!({"pid":std::process::id(),"thread_id":unsafe { GetCurrentThreadId() },"started_qpc":started_qpc,"finished_qpc":finished_qpc,"frequency":frequency,"requested_win32_access":FILE_READ_DATA,"native_open_error":error.as_ref().and_then(io::Error::raw_os_error),"denial_observed":error.as_ref().is_some_and(|error|error.raw_os_error()==Some(5)),"ordinary_rc_profile_verified":true,"token_execution":"effective-thread-impersonation","fresh_primary_execution_coverage":false,"dacl_scope":"newly owned calibration file only","host_policy_modified":false}),
            )
        })();
        // SAFETY: sole restoration of the helper's original no-impersonation state.
        if unsafe { RevertToSelf() } == 0 {
            abort_restoration("explicit-restore");
        }
        revert.0 = false;
        let mut restored = std::ptr::null_mut();
        // SAFETY: query verifies the original absent thread token was restored.
        if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut restored) } != 0 {
            drop(unsafe { OwnedHandle::from_raw_handle(restored) });
            return restoration_error(
                attempted,
                io::Error::other("calibration thread token restoration differs"),
            );
        }
        let restoration = io::Error::last_os_error();
        if restoration.raw_os_error() != Some(ERROR_NO_TOKEN as i32) {
            return restoration_error(attempted, restoration);
        }
        let mut attempted = attempted?;
        attempted["thread_token_restored"] = serde_json::json!(true);
        live(deadline)?;
        Ok(attempted)
    }

    pub fn finish(mut self) -> io::Result<()> {
        drop(self.file.take());
        std::fs::remove_file(&self.path)
    }
}

impl Drop for Calibration {
    fn drop(&mut self) {
        drop(self.file.take());
    }
}
