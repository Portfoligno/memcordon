use std::collections::BTreeSet;
use std::ffi::c_void;
use std::io;
use std::ptr;

use serde::{Deserialize, Serialize};

use super::user_api::get_user_object_security as GetUserObjectSecurity;
use windows_sys::Wdk::Storage::FileSystem::RtlCreateServiceSid;
use windows_sys::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, HLOCAL, LocalFree, UNICODE_STRING,
};
use windows_sys::Win32::Security::Authorization::{
    BuildTrusteeWithSidW, ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW,
    EXPLICIT_ACCESS_W, GetSecurityInfo, REVOKE_ACCESS, SDDL_REVISION_1, SE_FILE_OBJECT,
    SE_KERNEL_OBJECT, SE_SERVICE, SET_ACCESS, SetEntriesInAclW, SetSecurityInfo, TRUSTEE_W,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Security::{
    ACL, ACL_SIZE_INFORMATION, AccessCheck, AclSizeInformation, DACL_SECURITY_INFORMATION,
    DuplicateTokenEx, EqualSid, GENERIC_MAPPING, GROUP_SECURITY_INFORMATION, GetAce,
    GetAclInformation, GetFileSecurityW, GetKernelObjectSecurity, GetLengthSid,
    GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorGroup,
    GetSecurityDescriptorLength, GetSecurityDescriptorOwner, GetSecurityDescriptorSacl, IsValidAcl,
    IsValidSecurityDescriptor, IsValidSid, LABEL_SECURITY_INFORMATION, MakeAbsoluteSD,
    MapGenericMask, OWNER_SECURITY_INFORMATION, PRIVILEGE_SET, PROTECTED_DACL_SECURITY_INFORMATION,
    SE_DACL_PRESENT, SE_DACL_PROTECTED, SE_SELF_RELATIVE, SecurityImpersonation, SetFileSecurityW,
    SetKernelObjectSecurity, SetSecurityDescriptorControl, TOKEN_ALL_ACCESS, TOKEN_EXECUTE,
    TOKEN_QUERY, TOKEN_READ, TOKEN_WRITE, TokenImpersonation,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ALL_ACCESS, FILE_DELETE_CHILD, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
};
use windows_sys::Win32::System::Memory::LocalSize;
use windows_sys::Win32::System::Services::{
    QueryServiceObjectSecurity, SC_HANDLE, SC_MANAGER_CONNECT, SERVICE_ALL_ACCESS,
    SERVICE_CHANGE_CONFIG, SERVICE_ENUMERATE_DEPENDENTS, SERVICE_INTERROGATE,
    SERVICE_PAUSE_CONTINUE, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_START,
    SERVICE_STOP, SERVICE_USER_DEFINED_CONTROL, SetServiceObjectSecurity,
};
use windows_sys::Win32::System::SystemServices::{
    JOB_OBJECT_ASSIGN_PROCESS, JOB_OBJECT_IMPERSONATE, JOB_OBJECT_QUERY, JOB_OBJECT_SET_ATTRIBUTES,
    JOB_OBJECT_SET_SECURITY_ATTRIBUTES, JOB_OBJECT_TERMINATE,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, MUTEX_ALL_ACCESS, MUTEX_MODIFY_STATE, OpenProcessToken,
    PROCESS_ALL_ACCESS, PROCESS_CREATE_PROCESS, PROCESS_CREATE_THREAD, PROCESS_DUP_HANDLE,
    PROCESS_QUERY_INFORMATION, PROCESS_SET_INFORMATION, PROCESS_SET_QUOTA, PROCESS_VM_OPERATION,
    PROCESS_VM_READ, PROCESS_VM_WRITE, THREAD_ALL_ACCESS, THREAD_GET_CONTEXT,
    THREAD_QUERY_INFORMATION, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, THREAD_SET_CONTEXT,
    THREAD_SET_INFORMATION, THREAD_SET_THREAD_TOKEN,
};

use super::pipe::{OwnedHandle, wide_null};

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
const ACCESS_DENIED_ACE_TYPE: u8 = 0x01;
const MAX_SDDL_UTF16_UNITS: usize = 1_048_576;
const READ_CONTROL_ACCESS: u32 = 0x0002_0000;
const WRITE_DAC_ACCESS: u32 = 0x0004_0000;
const PROTECTED_KERNEL_DACL_INFORMATION: u32 =
    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
const STANDARD_RIGHTS_REQUIRED_ACCESS: u32 = 0x000f_0000;
const STANDARD_RIGHTS_READ_ACCESS: u32 = READ_CONTROL_ACCESS;
const STANDARD_RIGHTS_WRITE_ACCESS: u32 = READ_CONTROL_ACCESS;
const STANDARD_RIGHTS_EXECUTE_ACCESS: u32 = READ_CONTROL_ACCESS;
const WINSTA_ENUMDESKTOPS: u32 = 0x0000_0001;
const WINSTA_READATTRIBUTES: u32 = 0x0000_0002;
const WINSTA_ACCESSCLIPBOARD: u32 = 0x0000_0004;
const WINSTA_CREATEDESKTOP: u32 = 0x0000_0008;
const WINSTA_ACCESSGLOBALATOMS: u32 = 0x0000_0020;
const WINSTA_EXITWINDOWS: u32 = 0x0000_0040;
const WINSTA_ENUMERATE: u32 = 0x0000_0100;
// MemCordon-authored noninteractive station policies deliberately exclude
// WRITEATTRIBUTES and READSCREEN, which belong to the interactive station
// contract. Arbitrary Windows-provisioned station equality fingerprints do
// not use this role-specific mapping because a target station may be WinSta0.
const NONINTERACTIVE_WINDOW_STATION_ALL_ACCESS: u32 = 0x000f_016f;
const DESKTOP_READOBJECTS: u32 = 0x0000_0001;
const DESKTOP_CREATEWINDOW: u32 = 0x0000_0002;
const DESKTOP_CREATEMENU: u32 = 0x0000_0004;
const DESKTOP_HOOKCONTROL: u32 = 0x0000_0008;
const DESKTOP_JOURNALRECORD: u32 = 0x0000_0010;
const DESKTOP_JOURNALPLAYBACK: u32 = 0x0000_0020;
const DESKTOP_ENUMERATE: u32 = 0x0000_0040;
const DESKTOP_WRITEOBJECTS: u32 = 0x0000_0080;
const DESKTOP_SWITCHDESKTOP: u32 = 0x0000_0100;
const DESKTOP_ALL_ACCESS: u32 = 0x000f_01ff;
// CreateProcessAsUserW's explicit station\desktop connection contract requires
// full access to both USER objects. These grants are applied only to the
// nonce-private noninteractive namespace and its exact target-token trustees;
// readback handles retain their separate reduced attestation masks.
pub const TARGET_PRIVATE_WINDOW_STATION_ACCESS: u32 = NONINTERACTIVE_WINDOW_STATION_ALL_ACCESS;
pub const TARGET_PRIVATE_DESKTOP_ACCESS: u32 = DESKTOP_ALL_ACCESS;
const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;
const SYSTEM_MANDATORY_LABEL_ACE_TYPE: u8 = 0x11;
const OBJECT_INHERIT_ACE_FLAG: u8 = 0x01;
const CONTAINER_INHERIT_ACE_FLAG: u8 = 0x02;
const NO_PROPAGATE_INHERIT_ACE_FLAG: u8 = 0x04;
const INHERIT_ONLY_ACE_FLAG: u8 = 0x08;
const SE_DACL_AUTO_INHERIT_REQ_CONTROL: u16 = 0x0100;
const SE_SACL_PRESENT_CONTROL: u16 = 0x0010;
const SE_SACL_AUTO_INHERIT_REQ_CONTROL: u16 = 0x0200;
const SE_SACL_AUTO_INHERITED_CONTROL: u16 = 0x0800;
const SE_SACL_PROTECTED_CONTROL: u16 = 0x2000;
// NPFS pipe instances have no child-object inheritance relationship. Keep the
// creator D:P policy, but attest its enforceable ordered ACEs rather than this
// creator/resultant representation bit.
const NAMED_PIPE_DACL_PROTECTION_REQUIRED: bool = false;

pub const SERVICE_CONTROL_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";

pub fn guardian_slot_service_sddl(slot_name: &str) -> Result<String, String> {
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    let slot = service_sid(slot_name)?;
    // SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_START |
    // SERVICE_STOP | READ_CONTROL. Runtime receives no configuration, delete,
    // ownership, DACL, pause, or user-control authority.
    Ok(format!(
        "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00020035;;;{launcher})(A;;0x00020005;;;{slot})"
    ))
}

pub fn session_broker_service_sddl() -> Result<String, String> {
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    let broker = service_sid(memcordon_core::WINDOWS_SESSION_BROKER_SERVICE_NAME)?;
    Ok(format!(
        "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00000014;;;{launcher})(A;;0x00020005;;;{broker})"
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScmLauncherAceState {
    Absent,
    Exact,
}

pub fn scm_launcher_connect_state(manager: SC_HANDLE) -> Result<ScmLauncherAceState, String> {
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    let (_descriptor, dacl) = read_service_object_dacl(manager)?;
    let mut matching = Vec::new();
    for ace in acl_entries(dacl)? {
        let Some(sid) = basic_ace_sid(&ace)? else {
            continue;
        };
        if super::token::sid_string(sid)? == launcher {
            matching.push(ace);
        }
    }
    match matching.as_slice() {
        [] => Ok(ScmLauncherAceState::Absent),
        [ace]
            if ace[0] == ACCESS_ALLOWED_ACE_TYPE
                && ace[1] == 0
                && u32::from_le_bytes([ace[4], ace[5], ace[6], ace[7]]) == SC_MANAGER_CONNECT =>
        {
            Ok(ScmLauncherAceState::Exact)
        }
        _ => Err("SCM has a non-canonical launcher service SID ACE".to_owned()),
    }
}

pub fn set_scm_launcher_connect(manager: SC_HANDLE, present: bool) -> Result<(), String> {
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    let launcher_sid = LocalSid::parse(&launcher)?;
    let (before_descriptor, before_dacl) = read_service_object_dacl(manager)?;
    let preserved = acl_entries_except_sid(before_dacl, &launcher)?;
    let mut trustee = TRUSTEE_W::default();
    unsafe { BuildTrusteeWithSidW(&raw mut trustee, launcher_sid.0) };
    let access = EXPLICIT_ACCESS_W {
        grfAccessPermissions: if present { SC_MANAGER_CONNECT } else { 0 },
        grfAccessMode: if present { SET_ACCESS } else { REVOKE_ACCESS },
        grfInheritance: 0,
        Trustee: trustee,
    };
    let mut merged = ptr::null_mut();
    let status = unsafe { SetEntriesInAclW(1, &raw const access, before_dacl, &raw mut merged) };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32).to_string());
    }
    let merged = LocalAcl::new(merged)?;
    let status = unsafe {
        SetSecurityInfo(
            manager,
            SE_SERVICE,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            merged.0,
            ptr::null_mut(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32).to_string());
    }
    drop(before_descriptor);
    let state = scm_launcher_connect_state(manager)?;
    if (present && state != ScmLauncherAceState::Exact)
        || (!present && state != ScmLauncherAceState::Absent)
    {
        return Err("SCM launcher connect ACE did not converge".to_owned());
    }
    let (_after_descriptor, after_dacl) = read_service_object_dacl(manager)?;
    if acl_entries_except_sid(after_dacl, &launcher)? != preserved {
        return Err("SCM non-launcher ACL entries changed during convergence".to_owned());
    }
    Ok(())
}

fn read_service_object_dacl(
    object: SC_HANDLE,
) -> Result<(LocalSecurityDescriptor, *mut ACL), String> {
    let mut dacl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            object,
            SE_SERVICE,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut dacl,
            ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32).to_string());
    }
    let descriptor = LocalSecurityDescriptor::new(descriptor)?;
    if dacl.is_null() {
        return Err("SCM has a null DACL".to_owned());
    }
    Ok((descriptor, dacl))
}

pub fn public_pipe_sddl() -> Result<String, String> {
    let control = service_sid(memcordon_core::WINDOWS_CONTROL_SERVICE_NAME)?;
    Ok(format!(
        "O:LSD:P(A;;GA;;;SY)(A;;GA;;;{control})(A;;0x0012019b;;;AU)(A;;0x0012019b;;;RC)(A;;0x0012019b;;;WR)(A;;0x0012019b;;;AC)S:(ML;;NW;;;LW)"
    ))
}

pub fn private_pipe_sddl() -> Result<String, String> {
    let control = service_sid(memcordon_core::WINDOWS_CONTROL_SERVICE_NAME)?;
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    Ok(format!(
        "O:SYD:P(A;;GA;;;SY)(A;;0x0012019b;;;{control})(A;;GA;;;{launcher})"
    ))
}

pub fn session_broker_pipe_sddl() -> Result<String, String> {
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    let broker = service_sid(memcordon_core::WINDOWS_SESSION_BROKER_SERVICE_NAME)?;
    Ok(format!(
        "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;{broker})(A;;0x0012019b;;;{launcher})S:(ML;;NW;;;HI)"
    ))
}

pub fn holder_bootstrap_pipe_sddl() -> Result<String, String> {
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    Ok(format!(
        "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;{launcher})S:(ML;;NW;;;HI)"
    ))
}

/// The guardian broker accepts only the restricted LocalSystem launcher.
/// The broker service SID owns the endpoint; the launcher receives the fixed
/// pipe client rights required by the bounded launch protocol.
pub fn guardian_slot_name(index: usize) -> Result<String, String> {
    if index >= memcordon_core::WINDOWS_GUARDIAN_SLOT_COUNT {
        return Err("guardian slot index exceeds the installed pool".to_owned());
    }
    Ok(format!(
        "{}{:03}",
        memcordon_core::WINDOWS_GUARDIAN_SERVICE_PREFIX,
        index
    ))
}

pub fn guardian_slot_pipe_sddl(index: usize) -> Result<String, String> {
    let slot = service_sid(&guardian_slot_name(index)?)?;
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    Ok(format!(
        "O:SYD:P(A;;GA;;;SY)(A;;0x0012019b;;;{slot})(A;;GA;;;{launcher})"
    ))
}

pub fn state_sddl() -> Result<String, String> {
    let control = service_sid(memcordon_core::WINDOWS_CONTROL_SERVICE_NAME)?;
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    Ok(format!(
        "O:BAD:P(D;;WDWO;;;OW)(A;OICI;FA;;;SY)(A;;GXSD;;;BA)(A;OICI;FA;;;{control})(A;OICI;FA;;;{launcher})"
    ))
}

pub fn state_parent_sddl() -> Result<String, String> {
    let control = service_sid(memcordon_core::WINDOWS_CONTROL_SERVICE_NAME)?;
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    Ok(format!(
        "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;{control})(A;OICI;GRGX;;;{launcher})"
    ))
}

pub fn state_bootstrap_sddl() -> Result<String, String> {
    let control = service_sid(memcordon_core::WINDOWS_CONTROL_SERVICE_NAME)?;
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    Ok(format!(
        "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{control})(A;OICI;FA;;;{launcher})"
    ))
}

pub fn package_state_sddl() -> Result<String, String> {
    let control = service_sid(memcordon_core::WINDOWS_CONTROL_SERVICE_NAME)?;
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    Ok(format!(
        "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;{control})(A;OICI;GRGX;;;{launcher})"
    ))
}

pub(crate) const CERTIFICATION_ADMIN_DIRECTORY_ACCESS: u32 = FILE_ALL_ACCESS & !FILE_DELETE_CHILD;

pub fn certification_marker_state_sddl() -> Result<String, String> {
    let control = service_sid(memcordon_core::WINDOWS_CONTROL_SERVICE_NAME)?;
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    // Neither the normal Administrators pass nor a producer's restricting-SID
    // pass grants parent-wide delete-child or reopenable child DELETE. The
    // create-once publisher retains its one-use DELETE capability only on the
    // exact staging handle returned by CREATE_NEW.
    Ok(format!(
        "O:BAD:P(D;;0x00000004;;;{control})(D;;0x00000004;;;{launcher})(A;OICI;FA;;;SY)(A;OICI;0x{CERTIFICATION_ADMIN_DIRECTORY_ACCESS:08x};;;BA)(A;;GRGX;;;{control})(A;OICIIO;GRGX;;;{control})(A;;GX;;;{launcher})(A;OICIIO;GRGWGX;;;{launcher})(A;;0x00000024;;;AU)(A;OICIIO;GRGWGX;;;AU)(A;;0x00000024;;;RC)(A;OICIIO;GRGWGX;;;RC)(A;;0x00000024;;;WR)(A;OICIIO;GRGWGX;;;WR)S:(ML;OICI;NW;;;LW)"
    ))
}

pub(crate) fn pre_destructive_authority_hardening_certification_marker_state_sddl()
-> Result<String, String> {
    let control = service_sid(memcordon_core::WINDOWS_CONTROL_SERVICE_NAME)?;
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    Ok(format!(
        "O:BAD:P(D;;0x00000004;;;{control})(D;;0x00000004;;;{launcher})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;GRGX;;;{control})(A;OICIIO;GRGX;;;{control})(A;;GX;;;{launcher})(A;OICIIO;GRGWGXSD;;;{launcher})(A;;0x00000024;;;AU)(A;OICIIO;GRGWGXSD;;;AU)(A;;0x00000024;;;RC)(A;OICIIO;GRGWGXSD;;;RC)(A;;0x00000024;;;WR)(A;OICIIO;GRGWGXSD;;;WR)S:(ML;OICI;NW;;;LW)"
    ))
}

pub(crate) fn pre_write_restricted_certification_marker_state_sddl() -> Result<String, String> {
    let control = service_sid(memcordon_core::WINDOWS_CONTROL_SERVICE_NAME)?;
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    Ok(format!(
        "O:BAD:P(D;;0x00000004;;;{control})(D;;0x00000004;;;{launcher})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;GRGX;;;{control})(A;OICIIO;GRGX;;;{control})(A;;GX;;;{launcher})(A;OICIIO;GRGWGXSD;;;{launcher})(A;;0x00000024;;;AU)(A;OICIIO;GRGWGXSD;;;AU)(A;;0x00000024;;;RC)(A;OICIIO;GRGWGXSD;;;RC)S:(ML;OICI;NW;;;LW)"
    ))
}

pub fn launcher_state_sddl() -> Result<String, String> {
    let control = service_sid(memcordon_core::WINDOWS_CONTROL_SERVICE_NAME)?;
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    Ok(format!(
        "O:BAD:P(D;;WDWO;;;OW)(A;OICI;FA;;;SY)(A;;RC;;;BA)(A;OICI;FA;;;{launcher})(A;;GRGXSD;;;{control})"
    ))
}

pub fn replay_state_sddl() -> Result<String, String> {
    let control = service_sid(memcordon_core::WINDOWS_CONTROL_SERVICE_NAME)?;
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    Ok(format!(
        "O:BAD:P(D;;WDWO;;;OW)(A;OICI;FA;;;SY)(A;;RC;;;BA)(A;OICI;FA;;;{launcher})(A;OICI;GRGXSD;;;{control})"
    ))
}

pub fn admission_state_sddl() -> Result<String, String> {
    let control = service_sid(memcordon_core::WINDOWS_CONTROL_SERVICE_NAME)?;
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    Ok(format!(
        "O:BAD:P(D;;WDWO;;;OW)(A;OICI;FA;;;SY)(A;;RC;;;BA)(A;OICI;FA;;;{control})(A;OICI;FA;;;{launcher})"
    ))
}

pub fn package_mutex_sddl() -> Result<String, String> {
    let control = service_sid(memcordon_core::WINDOWS_CONTROL_SERVICE_NAME)?;
    Ok(format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{control})"))
}

pub fn launcher_process_sddl() -> Result<String, String> {
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    let broker = service_sid(memcordon_core::WINDOWS_SESSION_BROKER_SERVICE_NAME)?;
    Ok(format!(
        "O:SYD:P(A;;GA;;;SY)(A;;GA;;;{launcher})(A;;0x00101040;;;{broker})"
    ))
}

pub fn session_broker_process_sddl() -> Result<String, String> {
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    Ok(format!(
        "O:SYG:SYD:P(D;;WDWO;;;OW)(A;;GA;;;SY)(A;;0x00101000;;;{launcher})(A;;0x00101000;;;BA)"
    ))
}

pub fn session_broker_token_sddl() -> Result<String, String> {
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    Ok(format!(
        "O:SYG:SYD:P(D;;WDWO;;;OW)(A;;GA;;;SY)(A;;0x00020008;;;{launcher})"
    ))
}

pub fn session_holder_token_sddl() -> Result<String, String> {
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    let broker = service_sid(memcordon_core::WINDOWS_SESSION_BROKER_SERVICE_NAME)?;
    Ok(format!(
        "O:SYG:SYD:P(D;;WDWO;;;OW)(A;;GA;;;SY)(A;;0x00020008;;;{broker})(A;;0x00020008;;;{launcher})"
    ))
}

pub fn session_creation_carrier_token_sddl() -> Result<String, String> {
    let broker = service_sid(memcordon_core::WINDOWS_SESSION_BROKER_SERVICE_NAME)?;
    Ok(format!(
        "O:SYG:SYD:P(D;;WDWO;;;OW)(A;;0x00020018;;;SY)(A;;0x00020018;;;{broker})"
    ))
}

pub fn session_holder_default_dacl_sddl() -> Result<String, String> {
    let broker = service_sid(memcordon_core::WINDOWS_SESSION_BROKER_SERVICE_NAME)?;
    Ok(format!("O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;{broker})"))
}

pub fn session_holder_process_sddl() -> Result<String, String> {
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    Ok(format!(
        "O:SYG:SYD:P(D;;WDWO;;;OW)(A;;GA;;;SY)(A;;0x00101040;;;{launcher})"
    ))
}

pub fn session_holder_thread_sddl() -> Result<String, String> {
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    let broker = service_sid(memcordon_core::WINDOWS_SESSION_BROKER_SERVICE_NAME)?;
    Ok(format!(
        "O:SYG:SYD:P(D;;WDWO;;;OW)(A;;GA;;;SY)(A;;0x00001800;;;{launcher})(A;;0x000000c0;;;{broker})"
    ))
}

pub fn session_holder_job_sddl() -> Result<String, String> {
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    Ok(format!(
        "O:SYG:SYD:P(D;;WDWO;;;OW)(A;;GA;;;SY)(A;;GA;;;{launcher})"
    ))
}

pub fn launcher_thread_sddl() -> Result<String, String> {
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    Ok(format!("O:SYD:P(A;;GA;;;SY)(A;;GA;;;{launcher})"))
}

pub fn launcher_job_sddl() -> Result<String, String> {
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    Ok(format!("O:SYD:P(A;;GA;;;SY)(A;;GA;;;{launcher})"))
}

pub fn nested_canary_job_sddl() -> Result<String, String> {
    let creator = super::token::process_user_sid(unsafe {
        windows_sys::Win32::System::Threading::GetCurrentProcess()
    })?;
    // A restricted-token access check evaluates both the ordinary user SID
    // and the Write Restricted Code SID. The nested certification fixture retains
    // full control only for that creator intersection and verifies the exact
    // descriptor after each object is created.
    Ok(format!("O:{creator}D:P(A;;GA;;;{creator})(A;;GA;;;WR)"))
}

pub fn nested_canary_process_sddl() -> Result<String, String> {
    let creator = super::token::process_user_sid(unsafe {
        windows_sys::Win32::System::Threading::GetCurrentProcess()
    })?;
    // SYSTEM may inspect/control the native process object independently of
    // USER32 station/desktop connection authority. The private USER namespace
    // has its own exact user and Write Restricted Code policies.
    Ok(format!(
        "O:{creator}D:P(A;;GA;;;SY)(A;;GA;;;{creator})(A;;GA;;;WR)"
    ))
}

pub fn nested_canary_thread_sddl() -> Result<String, String> {
    nested_canary_process_sddl()
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum TargetUserObjectPolicyRoleV1 {
    DirectTarget,
    NestedWriteRestrictedDelegation,
}

impl TargetUserObjectPolicyRoleV1 {
    pub(crate) const fn diagnostic(self) -> &'static str {
        match self {
            Self::DirectTarget => "direct-target",
            Self::NestedWriteRestrictedDelegation => "nested-write-restricted-delegation",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TargetRestrictionSemantics {
    Unrestricted,
    Restricted { restricting_sids: Vec<String> },
    WriteRestricted { restricting_sids: Vec<String> },
}

fn classify_target_restriction(
    token_is_restricted: bool,
    restricting_sids: Vec<String>,
    write_restricted: bool,
) -> Result<TargetRestrictionSemantics, &'static str> {
    let has_write_restricted_sid = restricting_sids.iter().any(|sid| sid == "S-1-5-33");
    if token_is_restricted != !restricting_sids.is_empty() {
        return Err("IsTokenRestricted contradicts the exact restricting-SID inventory");
    }
    if write_restricted != has_write_restricted_sid {
        return Err("write-restricted oracle contradicts the exact restricting-SID inventory");
    }
    Ok(if write_restricted {
        TargetRestrictionSemantics::WriteRestricted { restricting_sids }
    } else if token_is_restricted {
        TargetRestrictionSemantics::Restricted { restricting_sids }
    } else {
        TargetRestrictionSemantics::Unrestricted
    })
}

#[cfg(test)]
pub(crate) fn classify_target_restriction_for_test(
    token_is_restricted: bool,
    restricting_sids: &[&str],
    write_restricted: bool,
) -> Result<TargetRestrictionSemantics, &'static str> {
    classify_target_restriction(
        token_is_restricted,
        restricting_sids
            .iter()
            .map(|sid| (*sid).to_owned())
            .collect(),
        write_restricted,
    )
}

#[derive(Debug)]
pub(crate) struct TargetUserObjectPolicyError {
    stage: &'static str,
    role: TargetUserObjectPolicyRoleV1,
    token_is_restricted: Option<bool>,
    restricting_sid_count: Option<usize>,
    write_restricted: Option<bool>,
    detail: String,
}

impl TargetUserObjectPolicyError {
    fn new(
        stage: &'static str,
        role: TargetUserObjectPolicyRoleV1,
        token_is_restricted: Option<bool>,
        restricting_sid_count: Option<usize>,
        write_restricted: Option<bool>,
        detail: impl ToString,
    ) -> Self {
        Self {
            stage,
            role,
            token_is_restricted,
            restricting_sid_count,
            write_restricted,
            detail: detail.to_string(),
        }
    }
}

impl std::fmt::Display for TargetUserObjectPolicyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "MCSEALED-WINDOWS-USER-OBJECT-POLICY: stage={} role={} token_is_restricted={:?} restricting_sid_count={:?} write_restricted={:?} detail={}",
            self.stage,
            self.role.diagnostic(),
            self.token_is_restricted,
            self.restricting_sid_count,
            self.write_restricted,
            self.detail,
        )
    }
}

impl std::error::Error for TargetUserObjectPolicyError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TargetUserObjectPolicy {
    pub restriction: TargetRestrictionSemantics,
    role: TargetUserObjectPolicyRoleV1,
    target_logon_sid: String,
    target_integrity_sid: String,
    holder_restricting_sid: String,
}

impl TargetUserObjectPolicy {
    pub(crate) fn capture(
        token: windows_sys::Win32::Foundation::HANDLE,
        role: TargetUserObjectPolicyRoleV1,
    ) -> Result<Self, TargetUserObjectPolicyError> {
        let snapshot_before =
            super::token::token_attestation_snapshot(token).map_err(|detail| {
                TargetUserObjectPolicyError::new("snapshot-before", role, None, None, None, detail)
            })?;
        let restricting =
            super::token::token_restricting_sid_inventory(token).map_err(|detail| {
                TargetUserObjectPolicyError::new(
                    "restricting-sid-inventory",
                    role,
                    Some(snapshot_before.behavior.token_is_restricted),
                    None,
                    None,
                    detail,
                )
            })?;
        let token_is_restricted = super::token::token_is_restricted(token);
        let write_restricted = write_restricted_behavior_attested(token).map_err(|detail| {
            TargetUserObjectPolicyError::new(
                "write-restricted-oracle",
                role,
                Some(token_is_restricted),
                Some(restricting.trustees.len()),
                None,
                detail,
            )
        })?;
        let target_logon_sid = super::token::token_logon_sid(token).map_err(|detail| {
            TargetUserObjectPolicyError::new(
                "target-logon-sid",
                role,
                Some(token_is_restricted),
                Some(restricting.trustees.len()),
                Some(write_restricted),
                detail,
            )
        })?;
        let snapshot_after = super::token::token_attestation_snapshot(token).map_err(|detail| {
            TargetUserObjectPolicyError::new(
                "snapshot-after",
                role,
                Some(token_is_restricted),
                Some(restricting.trustees.len()),
                Some(write_restricted),
                detail,
            )
        })?;
        if snapshot_before != snapshot_after
            || snapshot_before.behavior.restricting_sids != restricting.evidence
            || snapshot_before.behavior.token_is_restricted != token_is_restricted
            || snapshot_before.behavior.envelope.appcontainer
        {
            return Err(TargetUserObjectPolicyError::new(
                "classification",
                role,
                Some(token_is_restricted),
                Some(restricting.trustees.len()),
                Some(write_restricted),
                "target restriction, write-restriction, AppContainer, or snapshot evidence is contradictory",
            ));
        }
        let restricting_sid_count = restricting.trustees.len();
        let restriction = classify_target_restriction(
            token_is_restricted,
            restricting.trustees,
            write_restricted,
        )
        .map_err(|detail| {
            TargetUserObjectPolicyError::new(
                "classification",
                role,
                Some(token_is_restricted),
                Some(restricting_sid_count),
                Some(write_restricted),
                detail,
            )
        })?;
        let holder_restricting_sid = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)
            .map_err(|detail| {
                TargetUserObjectPolicyError::new(
                    "holder-restricting-sid",
                    role,
                    Some(token_is_restricted),
                    Some(match &restriction {
                        TargetRestrictionSemantics::Unrestricted => 0,
                        TargetRestrictionSemantics::Restricted { restricting_sids }
                        | TargetRestrictionSemantics::WriteRestricted { restricting_sids } => {
                            restricting_sids.len()
                        }
                    }),
                    Some(write_restricted),
                    detail,
                )
            })?;
        Ok(Self {
            restriction,
            role,
            target_logon_sid,
            target_integrity_sid: snapshot_before.behavior.envelope.integrity_level,
            holder_restricting_sid,
        })
    }

    fn sddl(&self, access: u32) -> String {
        let mut trustees = BTreeSet::from([
            "S-1-5-18".to_owned(),
            self.holder_restricting_sid.clone(),
            self.target_logon_sid.clone(),
        ]);
        if matches!(
            self.role,
            TargetUserObjectPolicyRoleV1::NestedWriteRestrictedDelegation
        ) {
            trustees.insert("S-1-5-33".to_owned());
        }
        match &self.restriction {
            TargetRestrictionSemantics::Unrestricted => {}
            TargetRestrictionSemantics::Restricted { restricting_sids }
            | TargetRestrictionSemantics::WriteRestricted { restricting_sids } => {
                trustees.extend(restricting_sids.iter().cloned());
            }
        }
        let mut sddl = "O:SYG:SYD:P".to_owned();
        for trustee in trustees {
            sddl.push_str(&format!("(A;;0x{access:08x};;;{trustee})"));
        }
        sddl.push_str(&format!("S:P(ML;;NW;;;{})", self.target_integrity_sid));
        sddl
    }

    pub(crate) fn window_station_sddl(&self) -> String {
        self.sddl(TARGET_PRIVATE_WINDOW_STATION_ACCESS)
    }

    pub(crate) fn desktop_sddl(&self) -> String {
        self.sddl(TARGET_PRIVATE_DESKTOP_ACCESS)
    }
}

pub(crate) fn target_user_object_policy(
    token: windows_sys::Win32::Foundation::HANDLE,
    role: TargetUserObjectPolicyRoleV1,
) -> Result<TargetUserObjectPolicy, TargetUserObjectPolicyError> {
    TargetUserObjectPolicy::capture(token, role)
}

fn target_user_object_sddl(
    token: windows_sys::Win32::Foundation::HANDLE,
    access: u32,
) -> Result<String, String> {
    let policy = target_user_object_policy(token, TargetUserObjectPolicyRoleV1::DirectTarget)
        .map_err(|error| error.to_string())?;
    Ok(policy.sddl(access))
}

pub fn target_window_station_sddl(
    token: windows_sys::Win32::Foundation::HANDLE,
) -> Result<String, String> {
    target_user_object_sddl(token, TARGET_PRIVATE_WINDOW_STATION_ACCESS)
}

pub fn target_desktop_sddl(
    token: windows_sys::Win32::Foundation::HANDLE,
) -> Result<String, String> {
    target_user_object_sddl(token, TARGET_PRIVATE_DESKTOP_ACCESS)
}

pub fn target_desktop_bootstrap_pipe_sddl(
    target_token: windows_sys::Win32::Foundation::HANDLE,
) -> Result<String, String> {
    let envelope = super::token::envelope(target_token)?;
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    let full_access = BTreeSet::from(["SY".to_owned(), launcher]);
    let mut client_access = BTreeSet::from([envelope.user_sid]);
    client_access.extend(super::token::token_restricting_sids(target_token)?);
    for trustee in &full_access {
        client_access.remove(trustee);
    }

    let mut sddl = "O:SYG:SYD:P".to_owned();
    for trustee in full_access.iter() {
        sddl.push_str(&format!("(A;;GA;;;{trustee})"));
    }
    for trustee in client_access {
        sddl.push_str(&format!("(A;;0x0012019b;;;{trustee})"));
    }
    sddl.push_str(&format!("S:(ML;;NW;;;{})", envelope.integrity_level));
    Ok(sddl)
}

fn access_check_descriptor(
    descriptor: *mut c_void,
    token: windows_sys::Win32::Foundation::HANDLE,
    desired: u32,
    mapping: GENERIC_MAPPING,
) -> Result<(bool, u32), String> {
    let token_envelope = super::token::envelope(token)
        .map_err(|error| format!("inspect token for AccessCheck: {error}"))?;
    let duplicated =
        if token_envelope.token_type == windows_sys::Win32::Security::TokenPrimary as u32 {
            let mut impersonation = ptr::null_mut();
            // SAFETY: token is a live primary token with duplicate access; output
            // becomes an independently owned impersonation token.
            if unsafe {
                DuplicateTokenEx(
                    token,
                    TOKEN_QUERY,
                    ptr::null(),
                    SecurityImpersonation,
                    TokenImpersonation,
                    &raw mut impersonation,
                )
            } == 0
            {
                let error = io::Error::last_os_error();
                return Err(format!(
                    "duplicate primary token for AccessCheck: native_code={:?} detail={error}",
                    error.raw_os_error()
                ));
            }
            Some(OwnedHandle::new(impersonation)?)
        } else {
            None
        };
    let access_token = duplicated.as_ref().map_or(token, OwnedHandle::raw);
    let mut privilege_words = [0_usize; 64];
    let mut privilege_bytes = u32::try_from(std::mem::size_of_val(&privilege_words))
        .map_err(|_| "AccessCheck privilege buffer is not representable".to_owned())?;
    let mut granted = 0_u32;
    let mut allowed = 0_i32;
    let mut mapping = mapping;
    // SAFETY: descriptor and impersonation token remain live; all outputs and
    // the native-aligned privilege buffer have their exact writable sizes.
    if unsafe {
        AccessCheck(
            descriptor,
            access_token,
            desired,
            &raw mut mapping,
            privilege_words.as_mut_ptr().cast::<PRIVILEGE_SET>(),
            &raw mut privilege_bytes,
            &raw mut granted,
            &raw mut allowed,
        )
    } == 0
    {
        let error = io::Error::last_os_error();
        return Err(format!(
            "invoke AccessCheck: native_code={:?} detail={error}",
            error.raw_os_error()
        ));
    }
    Ok((allowed != 0, granted))
}

#[cfg(test)]
struct LiveKernelAccessCheckError {
    stage: &'static str,
    api: &'static str,
    native_code: Option<i32>,
    policy_information: u32,
    access_check_information: u32,
    detail: String,
}

#[cfg(test)]
impl LiveKernelAccessCheckError {
    fn native(
        stage: &'static str,
        api: &'static str,
        policy_information: u32,
        access_check_information: u32,
        error: io::Error,
    ) -> Self {
        Self {
            stage,
            api,
            native_code: error.raw_os_error(),
            policy_information,
            access_check_information,
            detail: error.to_string(),
        }
    }

    fn semantic(
        stage: &'static str,
        api: &'static str,
        policy_information: u32,
        access_check_information: u32,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            stage,
            api,
            native_code: None,
            policy_information,
            access_check_information,
            detail: detail.into(),
        }
    }
}

#[cfg(test)]
impl std::fmt::Display for LiveKernelAccessCheckError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "MCSEALED-WINDOWS-LIVE-ACCESS-CHECK: stage={} api={} native_code={:?} policy_information=0x{:08x} access_check_information=0x{:08x} detail={}",
            self.stage,
            self.api,
            self.native_code,
            self.policy_information,
            self.access_check_information,
            self.detail,
        )
    }
}

#[cfg(test)]
fn require_live_access_check_descriptor_shape(
    descriptor: *mut c_void,
    policy_information: u32,
    access_check_information: u32,
) -> Result<(), LiveKernelAccessCheckError> {
    if unsafe { IsValidSecurityDescriptor(descriptor) } == 0 {
        return Err(LiveKernelAccessCheckError::semantic(
            "descriptor-shape",
            "IsValidSecurityDescriptor",
            policy_information,
            access_check_information,
            "live descriptor is structurally invalid",
        ));
    }

    let mut control = 0_u16;
    let mut revision = 0_u32;
    if unsafe { GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision) } == 0
    {
        return Err(LiveKernelAccessCheckError::native(
            "descriptor-shape",
            "GetSecurityDescriptorControl",
            policy_information,
            access_check_information,
            io::Error::last_os_error(),
        ));
    }
    if revision != 1 || control & SE_SELF_RELATIVE == 0 {
        return Err(LiveKernelAccessCheckError::semantic(
            "descriptor-shape",
            "GetSecurityDescriptorControl",
            policy_information,
            access_check_information,
            format!(
                "revision={revision} control=0x{control:04x} self_relative={}",
                control & SE_SELF_RELATIVE != 0
            ),
        ));
    }

    let mut owner = ptr::null_mut();
    let mut owner_defaulted = 0_i32;
    if unsafe { GetSecurityDescriptorOwner(descriptor, &raw mut owner, &raw mut owner_defaulted) }
        == 0
    {
        return Err(LiveKernelAccessCheckError::native(
            "descriptor-shape",
            "GetSecurityDescriptorOwner",
            policy_information,
            access_check_information,
            io::Error::last_os_error(),
        ));
    }
    if owner.is_null() || unsafe { IsValidSid(owner) } == 0 {
        return Err(LiveKernelAccessCheckError::semantic(
            "descriptor-shape",
            "GetSecurityDescriptorOwner",
            policy_information,
            access_check_information,
            format!(
                "owner_present={} owner_valid={} owner_defaulted={}",
                !owner.is_null(),
                !owner.is_null() && unsafe { IsValidSid(owner) } != 0,
                owner_defaulted != 0
            ),
        ));
    }

    let mut group = ptr::null_mut();
    let mut group_defaulted = 0_i32;
    if unsafe { GetSecurityDescriptorGroup(descriptor, &raw mut group, &raw mut group_defaulted) }
        == 0
    {
        return Err(LiveKernelAccessCheckError::native(
            "descriptor-shape",
            "GetSecurityDescriptorGroup",
            policy_information,
            access_check_information,
            io::Error::last_os_error(),
        ));
    }
    if group.is_null() || unsafe { IsValidSid(group) } == 0 {
        return Err(LiveKernelAccessCheckError::semantic(
            "descriptor-shape",
            "GetSecurityDescriptorGroup",
            policy_information,
            access_check_information,
            format!(
                "group_present={} group_valid={} group_defaulted={}",
                !group.is_null(),
                !group.is_null() && unsafe { IsValidSid(group) } != 0,
                group_defaulted != 0
            ),
        ));
    }

    let mut dacl_present = 0_i32;
    let mut dacl = ptr::null_mut();
    let mut dacl_defaulted = 0_i32;
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &raw mut dacl_present,
            &raw mut dacl,
            &raw mut dacl_defaulted,
        )
    } == 0
    {
        return Err(LiveKernelAccessCheckError::native(
            "descriptor-shape",
            "GetSecurityDescriptorDacl",
            policy_information,
            access_check_information,
            io::Error::last_os_error(),
        ));
    }
    if dacl_present == 0 || dacl.is_null() || unsafe { IsValidAcl(dacl) } == 0 {
        return Err(LiveKernelAccessCheckError::semantic(
            "descriptor-shape",
            "GetSecurityDescriptorDacl",
            policy_information,
            access_check_information,
            format!(
                "dacl_present={} dacl_null={} dacl_valid={} dacl_defaulted={}",
                dacl_present != 0,
                dacl.is_null(),
                !dacl.is_null() && unsafe { IsValidAcl(dacl) } != 0,
                dacl_defaulted != 0
            ),
        ));
    }
    Ok(())
}

pub(crate) fn write_restricted_behavior_attested(
    token: windows_sys::Win32::Foundation::HANDLE,
) -> Result<bool, String> {
    const READ: u32 = 0x1;
    const WRITE: u32 = 0x2;
    let user = super::token::token_user_sid(token)?;
    let mapping = GENERIC_MAPPING {
        GenericRead: READ,
        GenericWrite: WRITE,
        GenericExecute: READ,
        GenericAll: READ | WRITE,
    };
    let user_only = SecurityDescriptor::from_sddl(&format!("O:SYG:SYD:P(A;;0x3;;;{user})"))?;
    let user_wr =
        SecurityDescriptor::from_sddl(&format!("O:SYG:SYD:P(A;;0x3;;;{user})(A;;0x2;;;WR)"))?;
    let user_rc =
        SecurityDescriptor::from_sddl(&format!("O:SYG:SYD:P(A;;0x3;;;{user})(A;;0x2;;;RC)"))?;
    Ok(
        access_check_descriptor(user_only.raw(), token, READ, mapping)
            .map_err(|error| format!("write-restricted oracle user-only/read: {error}"))?
            .0
            && !access_check_descriptor(user_only.raw(), token, WRITE, mapping)
                .map_err(|error| format!("write-restricted oracle user-only/write: {error}"))?
                .0
            && access_check_descriptor(user_wr.raw(), token, WRITE, mapping)
                .map_err(|error| format!("write-restricted oracle user-WR/write: {error}"))?
                .0
            && !access_check_descriptor(user_rc.raw(), token, WRITE, mapping)
                .map_err(|error| format!("write-restricted oracle user-RC/write: {error}"))?
                .0,
    )
}

fn guardian_thread_sddl() -> Result<String, String> {
    let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
    Ok(format!("O:SYD:P(A;;GA;;;SY)(A;;GA;;;{launcher})"))
}

pub fn protect_current_service_process(service_name: &str) -> Result<(), String> {
    let descriptor = SecurityDescriptor::from_sddl(&service_process_sddl(service_name)?)?;
    // SAFETY: the pseudo-handle denotes this live service process.
    let process = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() };
    descriptor.apply_to_kernel_object(process)?;
    descriptor.verify_kernel_object(process, SecurityObjectKind::Process)
}

pub fn protect_current_session_broker() -> Result<(), SessionBrokerProtectionError> {
    let process_descriptor =
        SecurityDescriptor::from_sddl(&session_broker_process_sddl().map_err(|detail| {
            SessionBrokerProtectionError::descriptor(
                SessionBrokerProtectionStage::ProcessDescriptor,
                detail,
            )
        })?)
        .map_err(|detail| {
            SessionBrokerProtectionError::descriptor(
                SessionBrokerProtectionStage::ProcessDescriptor,
                detail,
            )
        })?;
    // SAFETY: pseudo-handle denotes this live broker process.
    let process = unsafe { GetCurrentProcess() };
    process_descriptor
        .apply_to_kernel_object_detailed(process)
        .map_err(|error| {
            SessionBrokerProtectionError::from_kernel(
                SessionBrokerProtectionStage::ProcessApply,
                error,
            )
        })?;
    process_descriptor
        .verify_kernel_object_detailed(process, SecurityObjectKind::Process)
        .map_err(|error| {
            SessionBrokerProtectionError::from_kernel(
                SessionBrokerProtectionStage::ProcessReadback,
                error,
            )
        })?;

    let mut token = ptr::null_mut();
    const BROKER_TOKEN_PROTECTION_ACCESS: u32 =
        TOKEN_QUERY | READ_CONTROL_ACCESS | WRITE_DAC_ACCESS;
    // SAFETY: broker owns its process token and output receives one private
    // query/DACL-convergence capability.
    if unsafe { OpenProcessToken(process, BROKER_TOKEN_PROTECTION_ACCESS, &raw mut token) } == 0 {
        return Err(SessionBrokerProtectionError::native(
            SessionBrokerProtectionStage::TokenOpen,
            "OpenProcessToken",
            BROKER_TOKEN_PROTECTION_ACCESS,
        ));
    }
    let token = super::pipe::OwnedHandle::new(token).map_err(|detail| {
        SessionBrokerProtectionError::descriptor(SessionBrokerProtectionStage::TokenOpen, detail)
    })?;
    let token_descriptor =
        SecurityDescriptor::from_sddl(&session_broker_token_sddl().map_err(|detail| {
            SessionBrokerProtectionError::descriptor(
                SessionBrokerProtectionStage::TokenDescriptor,
                detail,
            )
        })?)
        .map_err(|detail| {
            SessionBrokerProtectionError::descriptor(
                SessionBrokerProtectionStage::TokenDescriptor,
                detail,
            )
        })?;
    token_descriptor
        .apply_dacl_to_kernel_object_detailed(token.raw())
        .map_err(|error| {
            SessionBrokerProtectionError::from_kernel(
                SessionBrokerProtectionStage::TokenDaclApply,
                error,
            )
        })?;
    token_descriptor
        .verify_kernel_object_detailed(token.raw(), SecurityObjectKind::Token)
        .map_err(|error| {
            SessionBrokerProtectionError::from_kernel(
                SessionBrokerProtectionStage::TokenReadback,
                error,
            )
        })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionBrokerProtectionStage {
    ProcessDescriptor,
    ProcessApply,
    ProcessReadback,
    TokenOpen,
    TokenDescriptor,
    TokenDaclApply,
    TokenReadback,
}

impl SessionBrokerProtectionStage {
    pub const fn label(self) -> &'static str {
        match self {
            Self::ProcessDescriptor => "process-descriptor",
            Self::ProcessApply => "process-apply",
            Self::ProcessReadback => "process-readback",
            Self::TokenOpen => "token-open",
            Self::TokenDescriptor => "token-descriptor",
            Self::TokenDaclApply => "token-dacl-apply",
            Self::TokenReadback => "token-readback",
        }
    }
}

#[derive(Debug)]
pub struct SessionBrokerProtectionError {
    pub stage: SessionBrokerProtectionStage,
    pub native_code: Option<i32>,
    pub api: Option<&'static str>,
    pub requested_authority: Option<u32>,
    detail: String,
}

impl SessionBrokerProtectionError {
    fn descriptor(stage: SessionBrokerProtectionStage, detail: String) -> Self {
        Self {
            stage,
            native_code: None,
            api: None,
            requested_authority: None,
            detail,
        }
    }

    fn native(
        stage: SessionBrokerProtectionStage,
        api: &'static str,
        requested_authority: u32,
    ) -> Self {
        let error = io::Error::last_os_error();
        Self {
            stage,
            native_code: error.raw_os_error(),
            api: Some(api),
            requested_authority: Some(requested_authority),
            detail: error.to_string(),
        }
    }

    fn from_kernel(stage: SessionBrokerProtectionStage, error: KernelObjectSecurityError) -> Self {
        Self {
            stage,
            native_code: error.native_code,
            api: Some(error.api),
            requested_authority: Some(error.security_information),
            detail: error.detail,
        }
    }
}

impl std::fmt::Display for SessionBrokerProtectionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "MCSEALED-WINDOWS-SESSION-BROKER-PROTECTION: subphase={}",
            self.stage.label()
        )?;
        if let Some(api) = self.api {
            write!(formatter, " api={api}")?;
        }
        if let Some(requested) = self.requested_authority {
            write!(formatter, " requested_authority={requested:#010x}")?;
        }
        if let Some(native_code) = self.native_code {
            write!(formatter, " native_code={native_code}")?;
        }
        write!(formatter, " detail={}", self.detail)
    }
}

/// Applies the steady-state guardian policy only after native loader startup.
///
/// The process and its primary thread deliberately start with OS-derived
/// descriptors. No privileged workload capability exists in the process while
/// those loader-safe descriptors are in effect. This function is the first
/// guardian action before bootstrap authentication or capability transfer.
pub fn protect_current_guardian() -> Result<(), GuardianHardeningError> {
    let process_descriptor =
        SecurityDescriptor::from_sddl(&launcher_process_sddl().map_err(|detail| {
            GuardianHardeningError::new(GuardianHardeningStage::ProcessApply, None, detail)
        })?)
        .map_err(|detail| {
            GuardianHardeningError::new(GuardianHardeningStage::ProcessApply, None, detail)
        })?;
    let thread_descriptor =
        SecurityDescriptor::from_sddl(&guardian_thread_sddl().map_err(|detail| {
            GuardianHardeningError::new(GuardianHardeningStage::ThreadApply, None, detail)
        })?)
        .map_err(|detail| {
            GuardianHardeningError::new(GuardianHardeningStage::ThreadApply, None, detail)
        })?;
    // SAFETY: both pseudo-handles identify live objects owned by this process.
    let process = unsafe { GetCurrentProcess() };
    let thread = unsafe { GetCurrentThread() };
    process_descriptor
        .apply_to_kernel_object_detailed(process)
        .map_err(|error| {
            GuardianHardeningError::from_kernel(GuardianHardeningStage::ProcessApply, error)
        })?;
    process_descriptor
        .verify_kernel_object_detailed(process, SecurityObjectKind::Process)
        .map_err(|error| {
            GuardianHardeningError::from_kernel(GuardianHardeningStage::ProcessReadback, error)
        })?;
    thread_descriptor
        .apply_to_kernel_object_detailed(thread)
        .map_err(|error| {
            GuardianHardeningError::from_kernel(GuardianHardeningStage::ThreadApply, error)
        })?;
    thread_descriptor
        .verify_kernel_object_detailed(thread, SecurityObjectKind::Thread)
        .map_err(|error| {
            GuardianHardeningError::from_kernel(GuardianHardeningStage::ThreadReadback, error)
        })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuardianHardeningStage {
    ProcessApply,
    ProcessReadback,
    ThreadApply,
    ThreadReadback,
}

#[derive(Debug)]
pub struct GuardianHardeningError {
    pub stage: GuardianHardeningStage,
    pub native_code: Option<i32>,
    detail: String,
}

impl GuardianHardeningError {
    fn new(stage: GuardianHardeningStage, native_code: Option<i32>, detail: String) -> Self {
        Self {
            stage,
            native_code,
            detail,
        }
    }

    fn from_kernel(stage: GuardianHardeningStage, error: KernelObjectSecurityError) -> Self {
        Self::new(stage, error.native_code, error.detail)
    }
}

impl std::fmt::Display for GuardianHardeningError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.detail)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenDaclStage {
    Open,
    Readback,
    Merge,
    Set,
    Mismatch,
}

#[derive(Debug)]
pub struct TokenDaclError {
    stage: TokenDaclStage,
    detail: String,
}

impl TokenDaclError {
    pub const fn stage(&self) -> TokenDaclStage {
        self.stage
    }

    fn new(stage: TokenDaclStage, detail: impl ToString) -> Self {
        Self {
            stage,
            detail: detail.to_string(),
        }
    }
}

impl std::fmt::Display for TokenDaclError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "MCSEALED-WINDOWS-TOKEN-DACL: stage={} error={}",
            match self.stage {
                TokenDaclStage::Open => "open",
                TokenDaclStage::Readback => "readback",
                TokenDaclStage::Merge => "merge",
                TokenDaclStage::Set => "set",
                TokenDaclStage::Mismatch => "mismatch",
            },
            self.detail
        )
    }
}

pub(crate) fn token_dacl_startup_error(service_name: &str, error: TokenDaclError) -> (u32, String) {
    let base = match service_name {
        memcordon_core::WINDOWS_CONTROL_SERVICE_NAME => 0x4d43_0110,
        memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME => 0x4d43_0210,
        _ => 0x4d43_0190,
    };
    let offset = match error.stage() {
        TokenDaclStage::Open => 0,
        TokenDaclStage::Readback => 1,
        TokenDaclStage::Merge => 2,
        TokenDaclStage::Set => 3,
        TokenDaclStage::Mismatch => 4,
    };
    (base + offset, error.to_string())
}

pub(crate) const fn token_dacl_diagnostic_from_exit(
    code: u32,
) -> Option<(&'static str, &'static str)> {
    let (role, offset) = if code >= 0x4d43_0110 && code <= 0x4d43_0114 {
        ("control", code - 0x4d43_0110)
    } else if code >= 0x4d43_0210 && code <= 0x4d43_0214 {
        ("launcher", code - 0x4d43_0210)
    } else {
        return None;
    };
    let subphase = match offset {
        0 => "token-dacl-open",
        1 => "token-dacl-readback",
        2 => "token-dacl-merge",
        3 => "token-dacl-set",
        4 => "token-dacl-mismatch",
        _ => return None,
    };
    Some((role, subphase))
}

pub fn converge_current_service_token_peer_query(service_name: &str) -> Result<(), TokenDaclError> {
    let peer_names = match service_name {
        memcordon_core::WINDOWS_CONTROL_SERVICE_NAME => {
            vec![memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME.to_owned()]
        }
        memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME => {
            let mut peers = vec![memcordon_core::WINDOWS_CONTROL_SERVICE_NAME.to_owned()];
            for index in 0..memcordon_core::WINDOWS_GUARDIAN_SLOT_COUNT {
                peers.push(
                    guardian_slot_name(index)
                        .map_err(|error| TokenDaclError::new(TokenDaclStage::Open, error))?,
                );
            }
            peers
        }
        other if other.starts_with(memcordon_core::WINDOWS_GUARDIAN_SERVICE_PREFIX) => {
            vec![memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME.to_owned()]
        }
        other => {
            return Err(TokenDaclError::new(
                TokenDaclStage::Open,
                format!("unknown protected Windows service token: {other}"),
            ));
        }
    };
    let mut token = ptr::null_mut();
    // SAFETY: the current process pseudo-handle is live and the returned token
    // handle is owned locally. The rights are the minimum needed to query,
    // merge, and attest the token object's DACL.
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | READ_CONTROL_ACCESS | WRITE_DAC_ACCESS,
            &raw mut token,
        )
    } == 0
    {
        return Err(TokenDaclError::new(
            TokenDaclStage::Open,
            io::Error::last_os_error(),
        ));
    }
    let token = OwnedHandle::new(token)
        .map_err(|error| TokenDaclError::new(TokenDaclStage::Open, error))?;
    for peer_name in peer_names {
        let peer_sid = service_sid(&peer_name).map_err(|error| {
            TokenDaclError::new(TokenDaclStage::Open, format!("peer SID: {error}"))
        })?;
        converge_token_peer_query(token.raw(), &peer_sid)?;
    }
    Ok(())
}

pub(crate) fn converge_token_peer_query(
    token: windows_sys::Win32::Foundation::HANDLE,
    peer_sid: &str,
) -> Result<(), TokenDaclError> {
    let peer = LocalSid::parse(peer_sid)
        .map_err(|error| TokenDaclError::new(TokenDaclStage::Merge, error))?;
    let (before_descriptor, before_dacl) = read_token_dacl(token)
        .map_err(|error| TokenDaclError::new(TokenDaclStage::Readback, error))?;
    let preserved = acl_entries_except_sid(before_dacl, peer_sid)
        .map_err(|error| TokenDaclError::new(TokenDaclStage::Readback, error))?;

    let mut trustee = TRUSTEE_W::default();
    // SAFETY: peer owns a live SID for the duration of the synchronous merge.
    unsafe { BuildTrusteeWithSidW(&raw mut trustee, peer.0) };
    let access = EXPLICIT_ACCESS_W {
        grfAccessPermissions: TOKEN_QUERY,
        grfAccessMode: SET_ACCESS,
        grfInheritance: 0,
        Trustee: trustee,
    };
    let mut merged = ptr::null_mut();
    // SAFETY: before_dacl points into before_descriptor, which remains live;
    // access and peer remain live; merged receives one LocalAlloc allocation.
    let status = unsafe { SetEntriesInAclW(1, &raw const access, before_dacl, &raw mut merged) };
    if status != ERROR_SUCCESS {
        return Err(TokenDaclError::new(
            TokenDaclStage::Merge,
            io::Error::from_raw_os_error(status as i32),
        ));
    }
    let merged =
        LocalAcl::new(merged).map_err(|error| TokenDaclError::new(TokenDaclStage::Merge, error))?;
    // Keep the SCM-owned descriptor control state and all non-peer ACEs. Only
    // the DACL is updated; SET_ACCESS converges this peer trustee to one exact
    // TOKEN_QUERY grant rather than accumulating or widening ACEs.
    let status = unsafe {
        SetSecurityInfo(
            token,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            merged.0,
            ptr::null_mut(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(TokenDaclError::new(
            TokenDaclStage::Set,
            io::Error::from_raw_os_error(status as i32),
        ));
    }
    drop(before_descriptor);

    let (_after_descriptor, after_dacl) = read_token_dacl(token)
        .map_err(|error| TokenDaclError::new(TokenDaclStage::Readback, error))?;
    attest_exact_peer_query(after_dacl, peer_sid)
        .map_err(|error| TokenDaclError::new(TokenDaclStage::Mismatch, error))?;
    let after_preserved = acl_entries_except_sid(after_dacl, peer_sid)
        .map_err(|error| TokenDaclError::new(TokenDaclStage::Readback, error))?;
    if after_preserved != preserved {
        return Err(TokenDaclError::new(
            TokenDaclStage::Mismatch,
            "token DACL merge did not preserve every non-peer ACE",
        ));
    }
    Ok(())
}

pub(crate) fn service_process_sddl(service_name: &str) -> Result<String, String> {
    match service_name {
        memcordon_core::WINDOWS_CONTROL_SERVICE_NAME => {
            let control = service_sid(service_name)?;
            let launcher = service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
            // The control service runs as LocalService, so LocalService is the
            // assignable process owner. Keep owner rights explicitly denied;
            // changing this to SYSTEM would require cross-principal ownership.
            // Clients authenticate the control image with
            // PROCESS_QUERY_LIMITED_INFORMATION. Both AU and RC ACEs are
            // required because a restricted token must pass both access
            // checks. Administrators receive only query and synchronize so the
            // package transaction can pin shutdown. No client receives
            // terminate, write, or duplicate rights.
            Ok(format!(
                "O:LSD:P(D;;WDWO;;;OW)(A;;GA;;;SY)(A;;GA;;;{control})(A;;0x00001000;;;{launcher})(A;;0x00001000;;;AU)(A;;0x00001000;;;RC)(A;;0x00101000;;;BA)"
            ))
        }
        memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME => {
            let launcher = service_sid(service_name)?;
            let control = service_sid(memcordon_core::WINDOWS_CONTROL_SERVICE_NAME)?;
            // The control service needs exactly PROCESS_DUP_HANDLE and
            // PROCESS_QUERY_LIMITED_INFORMATION to broker authenticated
            // handles to the launcher. Every restricted guardian slot needs
            // only process query access to authenticate this launcher peer.
            let mut sddl = format!(
                "O:SYD:P(A;;GA;;;SY)(A;;GA;;;{launcher})(A;;0x00001040;;;{control})(A;;0x00101000;;;BA)"
            );
            for index in 0..memcordon_core::WINDOWS_GUARDIAN_SLOT_COUNT {
                let slot = service_sid(&guardian_slot_name(index)?)?;
                sddl.push_str(&format!("(A;;0x00001000;;;{slot})"));
            }
            Ok(sddl)
        }
        other => Err(format!(
            "unknown protected Windows service process: {other}"
        )),
    }
}

pub fn prepare_current_process_for_restricted_broker() -> Result<(), String> {
    // The authenticated control service opens the frontend while impersonating
    // it. A restricted token must pass both the caller SID and restricting-SID
    // checks, so grant RC and WR only query, duplicate-handle, and synchronize access.
    let process = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() };
    let user = super::token::process_user_sid(process)?;
    let descriptor = SecurityDescriptor::from_sddl(&format!(
        "D:P(D;;WDWO;;;OW)(A;;GA;;;SY)(A;;GA;;;{user})(A;;0x00101040;;;RC)(A;;0x00101040;;;WR)"
    ))?;
    descriptor.apply_to_kernel_object(process)?;
    descriptor.verify_kernel_object(process, SecurityObjectKind::Process)
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

struct AlignedSecurityBuffer {
    storage: Vec<usize>,
    bytes: u32,
}

impl AlignedSecurityBuffer {
    fn new(bytes: u32) -> Result<Self, String> {
        let bytes_usize = usize::try_from(bytes)
            .map_err(|_| "absolute security descriptor buffer is not representable".to_owned())?;
        let words = bytes_usize.div_ceil(std::mem::size_of::<usize>());
        Ok(Self {
            storage: vec![0; words],
            bytes,
        })
    }

    fn as_mut_ptr(&mut self) -> *mut c_void {
        if self.bytes == 0 {
            ptr::null_mut()
        } else {
            self.storage.as_mut_ptr().cast()
        }
    }
}

pub struct AbsoluteSecurityDescriptor {
    descriptor: AlignedSecurityBuffer,
    _dacl: AlignedSecurityBuffer,
    _sacl: AlignedSecurityBuffer,
    _owner: AlignedSecurityBuffer,
    _group: AlignedSecurityBuffer,
}

impl AbsoluteSecurityDescriptor {
    pub fn attributes(&self, inherit: bool) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.descriptor.storage.as_ptr().cast_mut().cast(),
            bInheritHandle: u32::from(inherit) as i32,
        }
    }

    pub(crate) fn raw(&self) -> *mut c_void {
        self.descriptor.storage.as_ptr().cast_mut().cast()
    }
}

#[derive(Debug)]
pub struct KernelObjectSecurityError {
    native_code: Option<i32>,
    api: &'static str,
    security_information: u32,
    detail: String,
}

impl KernelObjectSecurityError {
    fn native(api: &'static str, security_information: u32) -> Self {
        let error = io::Error::last_os_error();
        Self {
            native_code: error.raw_os_error(),
            api,
            security_information,
            detail: error.to_string(),
        }
    }

    fn detail(api: &'static str, security_information: u32, detail: String) -> Self {
        Self {
            native_code: None,
            api,
            security_information,
            detail,
        }
    }
}

impl std::fmt::Display for KernelObjectSecurityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "api={} security_information={:#010x}",
            self.api, self.security_information
        )?;
        if let Some(native_code) = self.native_code {
            write!(formatter, " native_code={native_code}")?;
        }
        write!(formatter, " detail={}", self.detail)
    }
}

#[derive(Debug)]
pub enum NamedPipeSecurityError {
    Readback(String),
    Mismatch(NamedPipeSecurityMismatch),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NamedPipeSecurityMismatch {
    Owner {
        expected: String,
        actual: String,
    },
    DaclPresence {
        actual: bool,
    },
    DaclProtection {
        expected: bool,
        actual: bool,
    },
    AceCount {
        expected: u32,
        actual: u32,
    },
    AceType {
        index: u32,
        expected: u8,
        actual: u8,
    },
    AceFlags {
        index: u32,
        expected: u8,
        actual: u8,
    },
    AceMask {
        index: u32,
        expected: u32,
        actual: u32,
    },
    AceTrustee {
        index: u32,
        expected: String,
        actual: String,
    },
    LabelPresence {
        actual: bool,
    },
    LabelAceCount {
        expected: u32,
        actual: u32,
    },
    LabelAceType {
        index: u32,
        expected: u8,
        actual: u8,
    },
    LabelAceFlags {
        index: u32,
        expected: u8,
        actual: u8,
    },
    LabelAceMask {
        index: u32,
        expected: u32,
        actual: u32,
    },
    LabelAceTrustee {
        index: u32,
        expected: String,
        actual: String,
    },
}

impl NamedPipeSecurityMismatch {
    pub(crate) const fn scm_offset(&self) -> u32 {
        match self {
            Self::Owner { .. } => 0,
            Self::DaclPresence { .. } => 1,
            Self::DaclProtection { .. } => 2,
            Self::AceCount { .. } => 3,
            Self::AceType { .. } => 4,
            Self::AceFlags { .. } => 5,
            Self::AceMask { .. } => 6,
            Self::AceTrustee { .. } => 7,
            Self::LabelPresence { .. } => 8,
            Self::LabelAceCount { .. } => 9,
            Self::LabelAceType { .. } => 10,
            Self::LabelAceFlags { .. } => 11,
            Self::LabelAceMask { .. } => 12,
            Self::LabelAceTrustee { .. } => 13,
        }
    }
}

impl std::fmt::Display for NamedPipeSecurityMismatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Owner { expected, actual } => {
                write!(
                    formatter,
                    "component=owner expected={expected} actual={actual}"
                )
            }
            Self::DaclPresence { actual } => {
                write!(
                    formatter,
                    "component=dacl-presence expected=true actual={actual}"
                )
            }
            Self::DaclProtection { expected, actual } => write!(
                formatter,
                "component=dacl-protection expected={expected} actual={actual}"
            ),
            Self::AceCount { expected, actual } => write!(
                formatter,
                "component=dacl-ace-count expected={expected} actual={actual}"
            ),
            Self::AceType {
                index,
                expected,
                actual,
            } => write!(
                formatter,
                "component=dacl-ace-type index={index} expected={expected:#04x} actual={actual:#04x}"
            ),
            Self::AceFlags {
                index,
                expected,
                actual,
            } => write!(
                formatter,
                "component=dacl-ace-flags index={index} expected={expected:#04x} actual={actual:#04x}"
            ),
            Self::AceMask {
                index,
                expected,
                actual,
            } => write!(
                formatter,
                "component=dacl-ace-mask index={index} expected={expected:#010x} actual={actual:#010x}"
            ),
            Self::AceTrustee {
                index,
                expected,
                actual,
            } => write!(
                formatter,
                "component=dacl-ace-trustee index={index} expected={expected} actual={actual}"
            ),
            Self::LabelPresence { actual } => write!(
                formatter,
                "component=mandatory-label-presence expected=true actual={actual}"
            ),
            Self::LabelAceCount { expected, actual } => write!(
                formatter,
                "component=mandatory-label-ace-count expected={expected} actual={actual}"
            ),
            Self::LabelAceType {
                index,
                expected,
                actual,
            } => write!(
                formatter,
                "component=mandatory-label-ace-type index={index} expected={expected:#04x} actual={actual:#04x}"
            ),
            Self::LabelAceFlags {
                index,
                expected,
                actual,
            } => write!(
                formatter,
                "component=mandatory-label-ace-flags index={index} expected={expected:#04x} actual={actual:#04x}"
            ),
            Self::LabelAceMask {
                index,
                expected,
                actual,
            } => write!(
                formatter,
                "component=mandatory-label-ace-mask index={index} expected={expected:#010x} actual={actual:#010x}"
            ),
            Self::LabelAceTrustee {
                index,
                expected,
                actual,
            } => write!(
                formatter,
                "component=mandatory-label-ace-trustee index={index} expected={expected} actual={actual}"
            ),
        }
    }
}

#[derive(Debug)]
struct PipeAce {
    ace_type: u8,
    flags: u8,
    mask: u32,
    trustee: String,
}

struct PipeSecurityComponents {
    owner: String,
    dacl_protected: bool,
    dacl: Option<Vec<PipeAce>>,
    label: Option<Vec<PipeAce>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileAce {
    ace_type: u8,
    flags: u8,
    mask: u32,
    // Preserve the complete ACE-specific representation. This includes the
    // trustee SID for basic ACEs and any object GUIDs preceding a trustee for
    // object ACEs, so typed projection never broadens what is considered
    // equivalent.
    body: Vec<u8>,
}

#[derive(Debug, Eq, PartialEq)]
enum FileAcl {
    Absent,
    Null,
    Entries(Vec<FileAce>),
}

struct FileSecurityComponents {
    owner: Option<String>,
    dacl_protected: bool,
    dacl_auto_inherit_requested: bool,
    dacl: FileAcl,
    label_protected: Option<bool>,
    label_auto_inherit_requested: Option<bool>,
    label: Option<FileAcl>,
}

struct FileAclProjection {
    effective: Vec<FileAce>,
    inheritance: Vec<FileAce>,
}

impl std::fmt::Display for NamedPipeSecurityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Readback(error) => {
                write!(formatter, "named-pipe security readback failed: {error}")
            }
            Self::Mismatch(error) => write!(formatter, "named-pipe security mismatch: {error}"),
        }
    }
}

struct LocalSecurityDescriptor(*mut c_void);

impl LocalSecurityDescriptor {
    fn new(descriptor: *mut c_void) -> Result<Self, String> {
        if descriptor.is_null() {
            Err("GetSecurityInfo returned a null security descriptor".to_owned())
        } else {
            Ok(Self(descriptor))
        }
    }
}

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this is the exact LocalAlloc allocation returned by
            // GetSecurityInfo and is released once.
            unsafe { LocalFree(self.0 as HLOCAL) };
        }
    }
}

struct LocalAcl(*mut ACL);

impl LocalAcl {
    fn new(acl: *mut ACL) -> Result<Self, String> {
        if acl.is_null() {
            Err("SetEntriesInAclW returned a null ACL".to_owned())
        } else {
            Ok(Self(acl))
        }
    }
}

impl Drop for LocalAcl {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this is the exact LocalAlloc result returned by
            // SetEntriesInAclW and is released once.
            unsafe { LocalFree(self.0.cast()) };
        }
    }
}

struct LocalSid(*mut c_void);

impl LocalSid {
    fn parse(value: &str) -> Result<Self, String> {
        let value = wide_null(value);
        let mut sid = ptr::null_mut();
        // SAFETY: value is NUL-terminated and output receives LocalAlloc memory.
        if unsafe { ConvertStringSidToSidW(value.as_ptr(), &raw mut sid) } == 0 {
            Err(io::Error::last_os_error().to_string())
        } else {
            Ok(Self(sid))
        }
    }
}

impl Drop for LocalSid {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this is the exact LocalAlloc SID allocation and is freed once.
            unsafe { LocalFree(self.0.cast()) };
        }
    }
}

struct LocalWideString(*mut u16);

impl LocalWideString {
    fn new(string: *mut u16) -> Result<Self, String> {
        if string.is_null() {
            Err("security descriptor string conversion returned a null allocation".to_owned())
        } else {
            Ok(Self(string))
        }
    }

    const fn raw(&self) -> *mut u16 {
        self.0
    }
}

impl Drop for LocalWideString {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this is the exact LocalAlloc string returned by
            // ConvertSecurityDescriptorToStringSecurityDescriptorW and is
            // released exactly once.
            unsafe { LocalFree(self.0.cast()) };
        }
    }
}

fn read_token_dacl(
    token: windows_sys::Win32::Foundation::HANDLE,
) -> Result<(LocalSecurityDescriptor, *mut ACL), String> {
    let mut dacl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: token is a live access-token handle with READ_CONTROL. The DACL
    // pointer aliases the LocalAlloc descriptor returned through descriptor.
    let status = unsafe {
        GetSecurityInfo(
            token,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut dacl,
            ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32).to_string());
    }
    let descriptor = LocalSecurityDescriptor::new(descriptor)?;
    if dacl.is_null() {
        return Err("access-token object has a missing or null DACL".to_owned());
    }
    Ok((descriptor, dacl))
}

fn acl_entries_except_sid(dacl: *mut ACL, excluded_sid: &str) -> Result<Vec<Vec<u8>>, String> {
    let mut entries = Vec::new();
    for ace in acl_entries(dacl)? {
        if basic_ace_sid(&ace)?
            .map(super::token::sid_string)
            .transpose()?
            .as_deref()
            == Some(excluded_sid)
        {
            continue;
        }
        entries.push(ace);
    }
    entries.sort();
    Ok(entries)
}

fn attest_exact_peer_query(dacl: *mut ACL, peer_sid: &str) -> Result<(), String> {
    let mut peer_entries = 0_u32;
    for ace in acl_entries(dacl)? {
        let Some(sid) = basic_ace_sid(&ace)? else {
            continue;
        };
        if super::token::sid_string(sid)? != peer_sid {
            continue;
        }
        peer_entries += 1;
        let ace_type = ace[0];
        let ace_flags = ace[1];
        let mask = normalized_access_mask(
            SecurityObjectKind::Token,
            u32::from_le_bytes([ace[4], ace[5], ace[6], ace[7]]),
        );
        if ace_type != ACCESS_ALLOWED_ACE_TYPE || ace_flags != 0 || mask != TOKEN_QUERY {
            return Err(format!(
                "peer token ACE is not exact query-only access: type={ace_type:#04x} flags={ace_flags:#04x} mask={mask:#010x}"
            ));
        }
    }
    if peer_entries != 1 {
        Err(format!(
            "peer token query policy has {peer_entries} matching ACEs instead of one"
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[allow(dead_code)] // Used by the integration test module that includes this source tree.
pub(crate) fn token_dacl_nonpeer_fingerprint(
    token: windows_sys::Win32::Foundation::HANDLE,
    peer_sid: &str,
) -> Result<Vec<Vec<u8>>, String> {
    let (_descriptor, dacl) = read_token_dacl(token)?;
    acl_entries_except_sid(dacl, peer_sid)
}

#[cfg(test)]
#[allow(dead_code)] // Used by the integration test module that includes this source tree.
pub(crate) fn attest_token_peer_query(
    token: windows_sys::Win32::Foundation::HANDLE,
    peer_sid: &str,
) -> Result<(), String> {
    let (_descriptor, dacl) = read_token_dacl(token)?;
    attest_exact_peer_query(dacl, peer_sid)
}

fn acl_entries(dacl: *mut ACL) -> Result<Vec<Vec<u8>>, String> {
    // SAFETY: zero is a valid initial representation for this output-only POD.
    let mut information = unsafe { std::mem::zeroed::<ACL_SIZE_INFORMATION>() };
    // SAFETY: dacl is live and output storage has the documented size.
    if unsafe {
        GetAclInformation(
            dacl,
            (&raw mut information).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    let mut entries = Vec::with_capacity(information.AceCount as usize);
    for index in 0..information.AceCount {
        let mut ace = ptr::null_mut();
        // SAFETY: index is bounded by the queried ACE count.
        if unsafe { GetAce(dacl, index, &raw mut ace) } == 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        let bytes = ace.cast::<u8>();
        // SAFETY: GetAce returned at least an ACE_HEADER.
        let size = u16::from_le_bytes([unsafe { *bytes.add(2) }, unsafe { *bytes.add(3) }]);
        if size < 4 {
            return Err(format!("token DACL ACE {index} has an invalid size"));
        }
        // SAFETY: the ACL owns a live ACE of the header-declared size.
        entries.push(unsafe { std::slice::from_raw_parts(bytes, size as usize) }.to_vec());
    }
    Ok(entries)
}

fn basic_ace_sid(ace: &[u8]) -> Result<Option<*mut c_void>, String> {
    if !matches!(
        ace.first().copied(),
        Some(ACCESS_ALLOWED_ACE_TYPE) | Some(ACCESS_DENIED_ACE_TYPE)
    ) {
        return Ok(None);
    }
    if ace.len() < 12 {
        return Err("token DACL access ACE is truncated before its SID".to_owned());
    }
    Ok(Some(ace.as_ptr().wrapping_add(8).cast_mut().cast()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityObjectKind {
    File,
    NamedPipe,
    Mutex,
    Job,
    Process,
    Thread,
    Token,
    Service,
    WindowStation,
    Desktop,
}

impl SecurityObjectKind {
    const fn generic_mapping(self) -> GENERIC_MAPPING {
        match self {
            Self::File | Self::NamedPipe => GENERIC_MAPPING {
                GenericRead: FILE_GENERIC_READ,
                GenericWrite: FILE_GENERIC_WRITE,
                GenericExecute: FILE_GENERIC_EXECUTE,
                GenericAll: FILE_ALL_ACCESS,
            },
            Self::Mutex => GENERIC_MAPPING {
                GenericRead: READ_CONTROL_ACCESS | SYNCHRONIZE_ACCESS,
                GenericWrite: READ_CONTROL_ACCESS | MUTEX_MODIFY_STATE,
                GenericExecute: READ_CONTROL_ACCESS | SYNCHRONIZE_ACCESS,
                GenericAll: MUTEX_ALL_ACCESS,
            },
            Self::Job => GENERIC_MAPPING {
                GenericRead: READ_CONTROL_ACCESS | JOB_OBJECT_QUERY,
                GenericWrite: READ_CONTROL_ACCESS
                    | JOB_OBJECT_ASSIGN_PROCESS
                    | JOB_OBJECT_SET_ATTRIBUTES
                    | JOB_OBJECT_TERMINATE,
                GenericExecute: READ_CONTROL_ACCESS | SYNCHRONIZE_ACCESS,
                GenericAll: STANDARD_RIGHTS_REQUIRED_ACCESS
                    | SYNCHRONIZE_ACCESS
                    | JOB_OBJECT_ASSIGN_PROCESS
                    | JOB_OBJECT_SET_ATTRIBUTES
                    | JOB_OBJECT_QUERY
                    | JOB_OBJECT_TERMINATE
                    | JOB_OBJECT_SET_SECURITY_ATTRIBUTES
                    | JOB_OBJECT_IMPERSONATE,
            },
            Self::Process => GENERIC_MAPPING {
                GenericRead: READ_CONTROL_ACCESS | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                GenericWrite: READ_CONTROL_ACCESS
                    | PROCESS_CREATE_PROCESS
                    | PROCESS_CREATE_THREAD
                    | PROCESS_DUP_HANDLE
                    | PROCESS_SET_INFORMATION
                    | PROCESS_SET_QUOTA
                    | PROCESS_VM_OPERATION
                    | PROCESS_VM_WRITE,
                GenericExecute: READ_CONTROL_ACCESS | SYNCHRONIZE_ACCESS,
                GenericAll: PROCESS_ALL_ACCESS,
            },
            Self::Thread => GENERIC_MAPPING {
                GenericRead: READ_CONTROL_ACCESS | THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT,
                GenericWrite: READ_CONTROL_ACCESS
                    | THREAD_SET_INFORMATION
                    | THREAD_SET_CONTEXT
                    | THREAD_SET_THREAD_TOKEN,
                GenericExecute: READ_CONTROL_ACCESS
                    | SYNCHRONIZE_ACCESS
                    | THREAD_QUERY_LIMITED_INFORMATION
                    | THREAD_RESUME,
                GenericAll: THREAD_ALL_ACCESS,
            },
            Self::Token => GENERIC_MAPPING {
                GenericRead: TOKEN_READ,
                GenericWrite: TOKEN_WRITE,
                GenericExecute: TOKEN_EXECUTE,
                GenericAll: TOKEN_ALL_ACCESS,
            },
            Self::Service => GENERIC_MAPPING {
                GenericRead: READ_CONTROL_ACCESS
                    | SERVICE_QUERY_CONFIG
                    | SERVICE_QUERY_STATUS
                    | SERVICE_INTERROGATE
                    | SERVICE_ENUMERATE_DEPENDENTS,
                GenericWrite: READ_CONTROL_ACCESS | SERVICE_CHANGE_CONFIG,
                GenericExecute: READ_CONTROL_ACCESS
                    | SERVICE_START
                    | SERVICE_STOP
                    | SERVICE_PAUSE_CONTINUE
                    | SERVICE_USER_DEFINED_CONTROL,
                GenericAll: SERVICE_ALL_ACCESS,
            },
            Self::WindowStation => GENERIC_MAPPING {
                GenericRead: STANDARD_RIGHTS_READ_ACCESS
                    | WINSTA_ENUMDESKTOPS
                    | WINSTA_ENUMERATE
                    | WINSTA_READATTRIBUTES,
                GenericWrite: STANDARD_RIGHTS_WRITE_ACCESS
                    | WINSTA_ACCESSCLIPBOARD
                    | WINSTA_CREATEDESKTOP,
                GenericExecute: STANDARD_RIGHTS_EXECUTE_ACCESS
                    | WINSTA_ACCESSGLOBALATOMS
                    | WINSTA_EXITWINDOWS,
                GenericAll: NONINTERACTIVE_WINDOW_STATION_ALL_ACCESS,
            },
            Self::Desktop => GENERIC_MAPPING {
                GenericRead: STANDARD_RIGHTS_READ_ACCESS | DESKTOP_ENUMERATE | DESKTOP_READOBJECTS,
                GenericWrite: STANDARD_RIGHTS_WRITE_ACCESS
                    | DESKTOP_CREATEMENU
                    | DESKTOP_CREATEWINDOW
                    | DESKTOP_HOOKCONTROL
                    | DESKTOP_JOURNALPLAYBACK
                    | DESKTOP_JOURNALRECORD
                    | DESKTOP_WRITEOBJECTS,
                GenericExecute: STANDARD_RIGHTS_EXECUTE_ACCESS | DESKTOP_SWITCHDESKTOP,
                GenericAll: DESKTOP_ALL_ACCESS,
            },
        }
    }
}

unsafe impl Send for SecurityDescriptor {}
unsafe impl Sync for SecurityDescriptor {}

impl SecurityDescriptor {
    pub(crate) fn dacl(&self) -> Result<*mut windows_sys::Win32::Security::ACL, String> {
        let mut present = 0_i32;
        let mut defaulted = 0_i32;
        let mut dacl = ptr::null_mut();
        // SAFETY: self owns a live self-relative descriptor and outputs are writable.
        if unsafe {
            GetSecurityDescriptorDacl(
                self.raw(),
                &raw mut present,
                &raw mut dacl,
                &raw mut defaulted,
            )
        } == 0
        {
            return Err(io::Error::last_os_error().to_string());
        }
        if present == 0 || dacl.is_null() {
            return Err("security descriptor does not contain an explicit DACL".to_owned());
        }
        Ok(dacl)
    }

    pub fn from_sddl(sddl: &str) -> Result<Self, String> {
        memcordon_core::validate_windows_security_descriptor_text(sddl).map_err(str::to_owned)?;
        let information = DACL_SECURITY_INFORMATION
            | if sddl.starts_with("O:") {
                OWNER_SECURITY_INFORMATION
            } else {
                0
            }
            | if sddl.contains("G:") {
                GROUP_SECURITY_INFORMATION
            } else {
                0
            }
            | if sddl.contains("(ML;") {
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

    pub fn absolute_for_user_object_creation(&self) -> Result<AbsoluteSecurityDescriptor, String> {
        let required_information =
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        if self.1 & required_information != required_information {
            return Err(format!(
                "USER-object creation descriptor is missing required owner, group, or DACL selection: information={:#010x}",
                self.1
            ));
        }
        let (source_control, source_revision) = descriptor_control(self.0).map_err(|error| {
            format!("cannot inspect self-relative creation descriptor: {error}")
        })?;
        if source_revision != 1
            || source_control & SE_SELF_RELATIVE == 0
            || source_control & SE_DACL_PRESENT == 0
            || source_control & SE_DACL_PROTECTED == 0
        {
            return Err(format!(
                "USER-object creation source descriptor has invalid control: revision={source_revision} control={source_control:#06x}"
            ));
        }
        if self.applies_mandatory_label() {
            let sacl_present = source_control & SE_SACL_PRESENT_CONTROL != 0;
            let sacl_protected = source_control & SE_SACL_PROTECTED_CONTROL != 0;
            let sacl_auto_inherit_requested =
                source_control & SE_SACL_AUTO_INHERIT_REQ_CONTROL != 0;
            let sacl_auto_inherited = source_control & SE_SACL_AUTO_INHERITED_CONTROL != 0;
            if !sacl_present
                || !sacl_protected
                || sacl_auto_inherit_requested
                || sacl_auto_inherited
            {
                return Err(format!(
                    "USER-object creation source descriptor has an unprotected or auto-inherited mandatory-label SACL: control={source_control:#06x} present={sacl_present} protected={sacl_protected} auto_inherit_requested={sacl_auto_inherit_requested} auto_inherited={sacl_auto_inherited}"
                ));
            }
        }
        let (source_owner, source_group) =
            descriptor_owner_and_group(self.0, "self-relative USER-object creation")?;

        let mut descriptor_bytes = 0_u32;
        let mut dacl_bytes = 0_u32;
        let mut sacl_bytes = 0_u32;
        let mut owner_bytes = 0_u32;
        let mut group_bytes = 0_u32;
        // SAFETY: this sizing call uses a live self-relative descriptor and
        // writable size outputs; null component outputs request their sizes.
        let sized = unsafe {
            MakeAbsoluteSD(
                self.0,
                ptr::null_mut(),
                &raw mut descriptor_bytes,
                ptr::null_mut(),
                &raw mut dacl_bytes,
                ptr::null_mut(),
                &raw mut sacl_bytes,
                ptr::null_mut(),
                &raw mut owner_bytes,
                ptr::null_mut(),
                &raw mut group_bytes,
            )
        };
        let sizing_error = io::Error::last_os_error();
        if sized != 0 || sizing_error.raw_os_error() != Some(122) {
            return Err(format!(
                "cannot size absolute USER-object creation descriptor: {sizing_error}"
            ));
        }
        if descriptor_bytes == 0
            || dacl_bytes == 0
            || owner_bytes == 0
            || group_bytes == 0
            || (self.applies_mandatory_label() && sacl_bytes == 0)
        {
            return Err(format!(
                "absolute USER-object creation descriptor sizing omitted a required component: descriptor={descriptor_bytes} dacl={dacl_bytes} owner={owner_bytes} group={group_bytes}"
            ));
        }

        let descriptor_capacity = descriptor_bytes;
        let dacl_capacity = dacl_bytes;
        let sacl_capacity = sacl_bytes;
        let owner_capacity = owner_bytes;
        let group_capacity = group_bytes;
        let mut descriptor = AlignedSecurityBuffer::new(descriptor_bytes)?;
        let mut dacl = AlignedSecurityBuffer::new(dacl_bytes)?;
        let mut sacl = AlignedSecurityBuffer::new(sacl_bytes)?;
        let mut owner = AlignedSecurityBuffer::new(owner_bytes)?;
        let mut group = AlignedSecurityBuffer::new(group_bytes)?;
        // SAFETY: every output is native-aligned, has the exact size obtained
        // above, and remains immobile for the lifetime of the absolute view.
        if unsafe {
            MakeAbsoluteSD(
                self.0,
                descriptor.as_mut_ptr(),
                &raw mut descriptor_bytes,
                dacl.as_mut_ptr().cast(),
                &raw mut dacl_bytes,
                sacl.as_mut_ptr().cast(),
                &raw mut sacl_bytes,
                owner.as_mut_ptr(),
                &raw mut owner_bytes,
                group.as_mut_ptr(),
                &raw mut group_bytes,
            )
        } == 0
        {
            return Err(format!(
                "cannot populate absolute USER-object creation descriptor: {}",
                io::Error::last_os_error()
            ));
        }
        if descriptor_bytes == 0
            || dacl_bytes == 0
            || owner_bytes == 0
            || group_bytes == 0
            || descriptor_bytes > descriptor_capacity
            || dacl_bytes > dacl_capacity
            || sacl_bytes > sacl_capacity
            || owner_bytes > owner_capacity
            || group_bytes > group_capacity
        {
            return Err(format!(
                "absolute USER-object creation descriptor exceeded or omitted sized storage: descriptor={descriptor_bytes}/{descriptor_capacity} dacl={dacl_bytes}/{dacl_capacity} sacl={sacl_bytes}/{sacl_capacity} owner={owner_bytes}/{owner_capacity} group={group_bytes}/{group_capacity}"
            ));
        }
        let absolute = AbsoluteSecurityDescriptor {
            descriptor,
            _dacl: dacl,
            _sacl: sacl,
            _owner: owner,
            _group: group,
        };
        if unsafe { IsValidSecurityDescriptor(absolute.raw()) } == 0 {
            return Err("absolute USER-object creation descriptor is invalid".to_owned());
        }
        let (absolute_owner, absolute_group) =
            descriptor_owner_and_group(absolute.raw(), "absolute USER-object creation")?;
        if absolute_owner != absolute._owner.storage.as_ptr().cast_mut().cast()
            || absolute_group != absolute._group.storage.as_ptr().cast_mut().cast()
        {
            return Err(
                "absolute USER-object creation descriptor does not reference retained owner and group storage"
                    .to_owned(),
            );
        }
        // SAFETY: both source and absolute identity pointers were validated above.
        if unsafe { EqualSid(source_owner, absolute_owner) } == 0
            || unsafe { EqualSid(source_group, absolute_group) } == 0
        {
            return Err(
                "absolute USER-object creation descriptor changed owner or primary group"
                    .to_owned(),
            );
        }
        let (absolute_control, absolute_revision) = descriptor_control(absolute.raw())?;
        if absolute_revision != source_revision
            || absolute_control & SE_SELF_RELATIVE != 0
            || absolute_control & !SE_SELF_RELATIVE != source_control & !SE_SELF_RELATIVE
        {
            return Err(format!(
                "absolute USER-object creation descriptor changed control: source={source_control:#06x} absolute={absolute_control:#06x}"
            ));
        }
        if self.applies_mandatory_label() {
            let sacl_present = absolute_control & SE_SACL_PRESENT_CONTROL != 0;
            let sacl_protected = absolute_control & SE_SACL_PROTECTED_CONTROL != 0;
            let sacl_auto_inherit_requested =
                absolute_control & SE_SACL_AUTO_INHERIT_REQ_CONTROL != 0;
            let sacl_auto_inherited = absolute_control & SE_SACL_AUTO_INHERITED_CONTROL != 0;
            if !sacl_present
                || !sacl_protected
                || sacl_auto_inherit_requested
                || sacl_auto_inherited
            {
                return Err(format!(
                    "absolute USER-object creation descriptor has an unprotected or auto-inherited mandatory-label SACL: control={absolute_control:#06x} present={sacl_present} protected={sacl_protected} auto_inherit_requested={sacl_auto_inherit_requested} auto_inherited={sacl_auto_inherited}"
                ));
            }
        }
        let expected = descriptor_sddl(self.0, self.1).map_err(|error| {
            format!("cannot stringify self-relative USER-object creation descriptor: {error}")
        })?;
        let actual = descriptor_sddl(absolute.raw(), self.1).map_err(|error| {
            format!("cannot stringify absolute USER-object creation descriptor: {error}")
        })?;
        if actual != expected {
            return Err(format!(
                "absolute USER-object creation descriptor changed policy: expected={expected} actual={actual}"
            ));
        }
        Ok(absolute)
    }

    pub(crate) const fn raw(&self) -> *mut c_void {
        self.0
    }

    pub fn applies_mandatory_label(&self) -> bool {
        self.1 & LABEL_SECURITY_INFORMATION != 0
    }

    pub fn apply_to_path(&self, path: &std::path::Path) -> Result<(), String> {
        use std::os::windows::ffi::OsStrExt;

        let wide_path: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: path is NUL-terminated and the descriptor remains live for
        // the synchronous security update.
        if unsafe {
            SetFileSecurityW(
                wide_path.as_ptr(),
                self.1 | PROTECTED_DACL_SECURITY_INFORMATION,
                self.0,
            )
        } == 0
        {
            let error = io::Error::last_os_error();
            let native_code = error
                .raw_os_error()
                .map_or_else(|| "unavailable".to_owned(), |code| code.to_string());
            Err(format!(
                "MCSEALED-WINDOWS-SECURITY: stage=path-security-apply api=SetFileSecurityW path={} information=0x{:08x} native_code={native_code} detail={error}",
                path.display(),
                self.1 | PROTECTED_DACL_SECURITY_INFORMATION,
            ))
        } else {
            Ok(())
        }
    }

    pub fn verify_path(&self, path: &std::path::Path) -> Result<(), String> {
        let mut descriptor = self.read_path_descriptor(path)?;
        self.verify_descriptor(descriptor.as_mut_ptr().cast(), SecurityObjectKind::File)
    }

    #[cfg(test)]
    pub(crate) fn access_check_descriptor_shape_for_test(&self) -> Result<(), String> {
        let access_check_information = self.1
            | OWNER_SECURITY_INFORMATION
            | GROUP_SECURITY_INFORMATION
            | DACL_SECURITY_INFORMATION;
        require_live_access_check_descriptor_shape(self.0, self.1, access_check_information)
            .map_err(|error| error.to_string())
    }

    #[cfg(test)]
    pub(crate) fn kernel_object_access_check_for_test(
        &self,
        handle: windows_sys::Win32::Foundation::HANDLE,
        token: windows_sys::Win32::Foundation::HANDLE,
        desired: u32,
    ) -> Result<(bool, u32), String> {
        // Policy comparison may intentionally omit identity fields, but
        // AccessCheck requires owner, group, and a decision-bearing DACL.
        let policy_information = self.1;
        let access_check_information = policy_information
            | OWNER_SECURITY_INFORMATION
            | GROUP_SECURITY_INFORMATION
            | DACL_SECURITY_INFORMATION;
        let mut needed = 0_u32;
        // SAFETY: handle is a retained object with READ_CONTROL; this sizing
        // call writes only the required descriptor length.
        let sized = unsafe {
            GetKernelObjectSecurity(
                handle,
                access_check_information,
                ptr::null_mut(),
                0,
                &raw mut needed,
            )
        };
        let sizing_error = io::Error::last_os_error();
        if sized != 0
            || sizing_error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
            || needed == 0
        {
            return Err(LiveKernelAccessCheckError::native(
                "descriptor-size",
                "GetKernelObjectSecurity",
                policy_information,
                access_check_information,
                sizing_error,
            )
            .to_string());
        }
        let allocated_bytes = needed;
        let mut descriptor = descriptor_buffer(allocated_bytes).map_err(|error| {
            LiveKernelAccessCheckError::semantic(
                "descriptor-size",
                "descriptor_buffer",
                policy_information,
                access_check_information,
                format!("requested_bytes={allocated_bytes} detail={error}"),
            )
            .to_string()
        })?;
        // SAFETY: descriptor has the exact requested capacity and the retained
        // handle remains live across verification and AccessCheck.
        if unsafe {
            GetKernelObjectSecurity(
                handle,
                access_check_information,
                descriptor.as_mut_ptr().cast(),
                allocated_bytes,
                &raw mut needed,
            )
        } == 0
        {
            return Err(LiveKernelAccessCheckError::native(
                "descriptor-read",
                "GetKernelObjectSecurity",
                policy_information,
                access_check_information,
                io::Error::last_os_error(),
            )
            .to_string());
        }
        if needed == 0 || needed > allocated_bytes {
            return Err(LiveKernelAccessCheckError::semantic(
                "descriptor-read",
                "GetKernelObjectSecurity",
                policy_information,
                access_check_information,
                format!("allocated_bytes={allocated_bytes} returned_bytes={needed}"),
            )
            .to_string());
        }
        let actual = descriptor.as_mut_ptr().cast();
        require_live_access_check_descriptor_shape(
            actual,
            policy_information,
            access_check_information,
        )
        .map_err(|error| error.to_string())?;
        self.verify_descriptor(actual, SecurityObjectKind::File)
            .map_err(|error| {
                LiveKernelAccessCheckError::semantic(
                    "descriptor-policy",
                    "verify_descriptor",
                    policy_information,
                    access_check_information,
                    error,
                )
                .to_string()
            })?;
        access_check_descriptor(
            actual,
            token,
            desired,
            SecurityObjectKind::File.generic_mapping(),
        )
        .map_err(|error| {
            LiveKernelAccessCheckError::semantic(
                "access-check",
                "AccessCheck",
                policy_information,
                access_check_information,
                error,
            )
            .to_string()
        })
    }

    pub fn converge_path(&self, applied_dacl: &Self, path: &std::path::Path) -> Result<(), String> {
        let mut descriptor = self.read_path_descriptor(path)?;
        if self
            .descriptor_difference(descriptor.as_mut_ptr().cast(), SecurityObjectKind::File)?
            .is_none()
        {
            return Ok(());
        }
        applied_dacl.apply_to_path(path)?;
        self.verify_path(path)
    }

    fn read_path_descriptor(&self, path: &std::path::Path) -> Result<Vec<u32>, String> {
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
        Ok(descriptor)
    }

    fn apply_service_security(&self, service: SC_HANDLE) -> Result<(), String> {
        // SAFETY: service is a live SCM handle with rights corresponding to the
        // selected information. DACL updates require WRITE_DAC. Owner/group
        // updates additionally require WRITE_OWNER and an effective token
        // authorized to assign the requested owner. The descriptor remains
        // live for the synchronous security update.
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

    pub fn apply_dacl_to_service(&self, service: SC_HANDLE) -> Result<(), String> {
        if self.1 != DACL_SECURITY_INFORMATION {
            return Err(format!(
                "DACL-only service application received owner, group, or SACL selection: information={:#010x}",
                self.1
            ));
        }
        self.apply_service_security(service)
    }

    pub fn apply_owner_group_dacl_to_service(&self, service: SC_HANDLE) -> Result<(), String> {
        let required =
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        if self.1 != required {
            return Err(format!(
                "owner/group service application requires exactly owner, group, and DACL selection: information={:#010x}",
                self.1
            ));
        }
        self.apply_service_security(service)
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
        self.verify_descriptor(descriptor.as_mut_ptr().cast(), SecurityObjectKind::Service)
    }

    fn verify_descriptor(
        &self,
        actual: *mut c_void,
        kind: SecurityObjectKind,
    ) -> Result<(), String> {
        match self.descriptor_difference(actual, kind)? {
            None => Ok(()),
            Some(difference) => Err(difference),
        }
    }

    fn descriptor_difference(
        &self,
        actual: *mut c_void,
        kind: SecurityObjectKind,
    ) -> Result<Option<String>, String> {
        if kind == SecurityObjectKind::File {
            let expected = file_security_components(self.0, self.1)?;
            let actual_components = file_security_components(actual, self.1)?;
            if let Some(difference) = file_security_difference(&expected, &actual_components) {
                let expected_sddl = descriptor_sddl(self.0, self.1)?;
                let actual_sddl = descriptor_sddl(actual, self.1)?;
                return Ok(Some(format!(
                    "file security descriptor differs: {difference} expected={expected_sddl} actual={actual_sddl}"
                )));
            }
            return Ok(None);
        }
        let expected = normalized_descriptor_sddl(self.0, self.1, kind)?;
        let actual = if kind == SecurityObjectKind::Desktop {
            normalized_resultant_user_object_sddl(self.0, actual, self.1, kind)?
        } else {
            normalized_descriptor_sddl(actual, self.1, kind)?
        };
        if actual == expected {
            Ok(None)
        } else {
            Ok(Some(format!(
                "security descriptor differs: expected={expected} actual={actual}"
            )))
        }
    }

    pub fn apply_to_kernel_object(
        &self,
        handle: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<(), String> {
        self.apply_to_kernel_object_detailed(handle)
            .map_err(|error| error.to_string())
    }

    pub fn apply_to_kernel_object_detailed(
        &self,
        handle: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<(), KernelObjectSecurityError> {
        let information = self.1 | PROTECTED_DACL_SECURITY_INFORMATION;
        // SAFETY: handle denotes a live kernel object with WRITE_DAC, plus
        // WRITE_OWNER when the descriptor carries a mandatory label, and the
        // descriptor remains live for the synchronous security update.
        if unsafe { SetKernelObjectSecurity(handle, information, self.0) } == 0 {
            Err(KernelObjectSecurityError::native(
                "SetKernelObjectSecurity",
                information,
            ))
        } else {
            Ok(())
        }
    }

    pub fn apply_dacl_to_kernel_object_detailed(
        &self,
        handle: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<(), KernelObjectSecurityError> {
        self.dacl().map_err(|detail| {
            KernelObjectSecurityError::detail(
                "GetSecurityDescriptorDacl",
                PROTECTED_KERNEL_DACL_INFORMATION,
                detail,
            )
        })?;
        // SAFETY: handle denotes a live kernel object with WRITE_DAC. The
        // descriptor's explicit DACL remains live for the synchronous update;
        // owner, group, SACL, and label components are deliberately unselected.
        if unsafe { SetKernelObjectSecurity(handle, PROTECTED_KERNEL_DACL_INFORMATION, self.0) }
            == 0
        {
            Err(KernelObjectSecurityError::native(
                "SetKernelObjectSecurity",
                PROTECTED_KERNEL_DACL_INFORMATION,
            ))
        } else {
            Ok(())
        }
    }

    pub fn apply_to_file_object(
        &self,
        handle: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<(), String> {
        let mut owner = ptr::null_mut();
        if self.1 & OWNER_SECURITY_INFORMATION != 0 {
            let mut defaulted = 0_i32;
            // SAFETY: the descriptor is live and outputs point to initialized storage.
            if unsafe { GetSecurityDescriptorOwner(self.0, &raw mut owner, &raw mut defaulted) }
                == 0
            {
                return Err(io::Error::last_os_error().to_string());
            }
            if owner.is_null() {
                return Err("file-object security descriptor has no owner SID".to_owned());
            }
        }

        let mut dacl = ptr::null_mut();
        if self.1 & DACL_SECURITY_INFORMATION != 0 {
            let mut present = 0_i32;
            let mut defaulted = 0_i32;
            // SAFETY: the descriptor is live and outputs point to initialized storage.
            if unsafe {
                GetSecurityDescriptorDacl(
                    self.0,
                    &raw mut present,
                    &raw mut dacl,
                    &raw mut defaulted,
                )
            } == 0
            {
                return Err(io::Error::last_os_error().to_string());
            }
            if present == 0 || dacl.is_null() {
                return Err("file-object security descriptor has no DACL".to_owned());
            }
        }

        let mut label = ptr::null_mut();
        if self.1 & LABEL_SECURITY_INFORMATION != 0 {
            let mut present = 0_i32;
            let mut defaulted = 0_i32;
            // SAFETY: the descriptor is live and outputs point to initialized storage.
            if unsafe {
                GetSecurityDescriptorSacl(
                    self.0,
                    &raw mut present,
                    &raw mut label,
                    &raw mut defaulted,
                )
            } == 0
            {
                return Err(io::Error::last_os_error().to_string());
            }
            if present == 0 || label.is_null() {
                return Err("file-object security descriptor has no mandatory label".to_owned());
            }
        }

        // SAFETY: handle denotes a live file object with WRITE_DAC, plus
        // WRITE_OWNER when setting an owner or mandatory label. All selected
        // descriptor components remain live for the synchronous update.
        let status = unsafe {
            SetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                self.1 | PROTECTED_DACL_SECURITY_INFORMATION,
                owner,
                ptr::null_mut(),
                dacl,
                label,
            )
        };
        if status == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(status as i32).to_string())
        }
    }

    pub fn verify_file_object(
        &self,
        handle: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<(), String> {
        let mut owner = ptr::null_mut();
        let mut dacl = ptr::null_mut();
        let mut label = ptr::null_mut();
        let mut descriptor = ptr::null_mut();
        // SAFETY: handle denotes a live file object with READ_CONTROL. Each
        // requested component points into the one LocalAlloc descriptor below.
        let status = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                self.1,
                &raw mut owner,
                ptr::null_mut(),
                &raw mut dacl,
                &raw mut label,
                &raw mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32).to_string());
        }
        let descriptor = LocalSecurityDescriptor::new(descriptor)?;
        self.verify_descriptor(descriptor.0, SecurityObjectKind::File)
    }

    pub fn verify_kernel_object(
        &self,
        handle: windows_sys::Win32::Foundation::HANDLE,
        kind: SecurityObjectKind,
    ) -> Result<(), String> {
        self.verify_kernel_object_detailed(handle, kind)
            .map_err(|error| error.to_string())
    }

    pub fn verify_user_object(
        &self,
        handle: windows_sys::Win32::Foundation::HANDLE,
        kind: SecurityObjectKind,
    ) -> Result<(), String> {
        require_user_object_kind(kind)?;
        let mut descriptor = read_user_object_security(handle, self.1)?;
        self.verify_descriptor(descriptor.as_mut_ptr().cast(), kind)
    }

    pub fn user_object_policy_fingerprint(
        &self,
        kind: SecurityObjectKind,
    ) -> Result<String, String> {
        require_target_user_object_policy_selection(self.1, kind)?;
        let canonical = normalized_descriptor_sddl(self.0, self.1, kind)?;
        Ok(super::record::digest(canonical.as_bytes()))
    }

    pub fn user_object_resultant_fingerprint(
        &self,
        handle: windows_sys::Win32::Foundation::HANDLE,
        kind: SecurityObjectKind,
    ) -> Result<String, String> {
        require_target_user_object_policy_selection(self.1, kind)?;
        let mut descriptor = read_user_object_security(handle, self.1)?;
        let actual = descriptor.as_mut_ptr().cast();
        let canonical = if kind == SecurityObjectKind::Desktop {
            normalized_resultant_user_object_sddl(self.0, actual, self.1, kind)?
        } else {
            normalized_descriptor_sddl(actual, self.1, kind)?
        };
        Ok(super::record::digest(canonical.as_bytes()))
    }

    pub fn user_object_security_equality_fingerprint(
        handle: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<String, String> {
        let information =
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        let mut descriptor = read_user_object_security(handle, information)?;
        // This fingerprint is an exact before/after equality proof for an
        // arbitrary Windows-owned USER object. Do not apply a role-specific
        // generic-rights mapping: the source station may legitimately be
        // interactive WinSta0 or a noninteractive service station.
        let exact = descriptor_sddl(descriptor.as_mut_ptr().cast(), information)?;
        Ok(super::record::digest(exact.as_bytes()))
    }

    pub fn private_desktop_access_check(
        &self,
        token: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<(bool, u32), String> {
        access_check_descriptor(
            self.0,
            token,
            TARGET_PRIVATE_DESKTOP_ACCESS,
            SecurityObjectKind::Desktop.generic_mapping(),
        )
        .map_err(|error| format!("private desktop AccessCheck failed: {error}"))
    }

    pub fn private_window_station_access_check(
        &self,
        token: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<(bool, u32), String> {
        access_check_descriptor(
            self.0,
            token,
            TARGET_PRIVATE_WINDOW_STATION_ACCESS,
            SecurityObjectKind::WindowStation.generic_mapping(),
        )
        .map_err(|error| format!("private window station AccessCheck failed: {error}"))
    }

    #[cfg(test)]
    pub fn private_window_station_access_check_for_test(
        &self,
        token: windows_sys::Win32::Foundation::HANDLE,
        desired: u32,
    ) -> Result<(bool, u32), String> {
        access_check_descriptor(
            self.0,
            token,
            desired,
            SecurityObjectKind::WindowStation.generic_mapping(),
        )
        .map_err(|error| format!("private window station per-bit AccessCheck failed: {error}"))
    }

    #[cfg(test)]
    pub fn private_desktop_access_check_for_test(
        &self,
        token: windows_sys::Win32::Foundation::HANDLE,
        desired: u32,
    ) -> Result<(bool, u32), String> {
        access_check_descriptor(
            self.0,
            token,
            desired,
            SecurityObjectKind::Desktop.generic_mapping(),
        )
        .map_err(|error| format!("private desktop per-bit AccessCheck failed: {error}"))
    }

    pub fn verify_kernel_object_detailed(
        &self,
        handle: windows_sys::Win32::Foundation::HANDLE,
        kind: SecurityObjectKind,
    ) -> Result<(), KernelObjectSecurityError> {
        let mut needed = 0_u32;
        // SAFETY: sizing call writes only the required descriptor length.
        unsafe { GetKernelObjectSecurity(handle, self.1, ptr::null_mut(), 0, &raw mut needed) };
        if needed == 0 {
            return Err(KernelObjectSecurityError::native(
                "GetKernelObjectSecurity",
                self.1,
            ));
        }
        let mut descriptor = descriptor_buffer(needed).map_err(|detail| {
            KernelObjectSecurityError::detail("GetKernelObjectSecurity", self.1, detail)
        })?;
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
            return Err(KernelObjectSecurityError::native(
                "GetKernelObjectSecurity",
                self.1,
            ));
        }
        self.verify_descriptor(descriptor.as_mut_ptr().cast(), kind)
            .map_err(|detail| {
                KernelObjectSecurityError::detail("GetKernelObjectSecurity", self.1, detail)
            })
    }

    #[cfg(test)]
    pub(crate) fn kernel_object_owner_group_sddl_for_test(
        handle: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<String, String> {
        const INFORMATION: u32 = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION;
        let mut needed = 0_u32;
        // SAFETY: sizing call writes only the required descriptor length.
        unsafe {
            GetKernelObjectSecurity(handle, INFORMATION, ptr::null_mut(), 0, &raw mut needed)
        };
        let mut descriptor = descriptor_buffer(needed)?;
        // SAFETY: descriptor has the exact requested byte capacity.
        if unsafe {
            GetKernelObjectSecurity(
                handle,
                INFORMATION,
                descriptor.as_mut_ptr().cast(),
                needed,
                &raw mut needed,
            )
        } == 0
        {
            return Err(io::Error::last_os_error().to_string());
        }
        descriptor_sddl(descriptor.as_mut_ptr().cast(), INFORMATION)
    }

    pub fn verify_named_pipe(
        &self,
        handle: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<(), NamedPipeSecurityError> {
        const PIPE_ATTEST_INFORMATION: u32 =
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
        let mut owner = ptr::null_mut();
        let mut dacl: *mut ACL = ptr::null_mut();
        let mut label: *mut ACL = ptr::null_mut();
        let mut descriptor = ptr::null_mut();
        // SAFETY: a named-pipe endpoint is an NPFS file object. Each component
        // output points into the one LocalAlloc descriptor owned below.
        let status = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                PIPE_ATTEST_INFORMATION,
                &raw mut owner,
                ptr::null_mut(),
                &raw mut dacl,
                &raw mut label,
                &raw mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(NamedPipeSecurityError::Readback(
                io::Error::from_raw_os_error(status as i32).to_string(),
            ));
        }
        let descriptor =
            LocalSecurityDescriptor::new(descriptor).map_err(NamedPipeSecurityError::Readback)?;
        let expected = pipe_security_components(self.0, None, None, None, self.1)
            .map_err(NamedPipeSecurityError::Readback)?;
        let actual = pipe_security_components(
            descriptor.0,
            Some(owner),
            Some(dacl),
            Some(label),
            PIPE_ATTEST_INFORMATION,
        )
        .map_err(NamedPipeSecurityError::Readback)?;
        compare_pipe_security(&expected, &actual).map_err(NamedPipeSecurityError::Mismatch)
    }
}

fn file_security_components(
    descriptor: *mut c_void,
    information: u32,
) -> Result<FileSecurityComponents, String> {
    let owner = if information & OWNER_SECURITY_INFORMATION == 0 {
        None
    } else {
        let mut owner = ptr::null_mut();
        let mut defaulted = 0_i32;
        // SAFETY: descriptor is live and outputs point to initialized storage.
        if unsafe { GetSecurityDescriptorOwner(descriptor, &raw mut owner, &raw mut defaulted) }
            == 0
        {
            return Err(io::Error::last_os_error().to_string());
        }
        if owner.is_null() {
            return Err("file security descriptor has no selected owner SID".to_owned());
        }
        Some(super::token::sid_string(owner)?)
    };

    let dacl = file_descriptor_acl(descriptor, false)?;
    let label = if information & LABEL_SECURITY_INFORMATION == 0 {
        None
    } else {
        Some(file_descriptor_acl(descriptor, true)?)
    };

    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: descriptor is live and outputs point to initialized storage.
    if unsafe { GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision) } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }

    Ok(FileSecurityComponents {
        owner,
        dacl_protected: control & SE_DACL_PROTECTED != 0,
        dacl_auto_inherit_requested: control & SE_DACL_AUTO_INHERIT_REQ_CONTROL != 0,
        dacl,
        label_protected: label
            .as_ref()
            .map(|_| control & SE_SACL_PROTECTED_CONTROL != 0),
        label_auto_inherit_requested: label
            .as_ref()
            .map(|_| control & SE_SACL_AUTO_INHERIT_REQ_CONTROL != 0),
        label,
    })
}

fn file_descriptor_acl(descriptor: *mut c_void, label: bool) -> Result<FileAcl, String> {
    let mut present = 0_i32;
    let mut acl = ptr::null_mut();
    let mut defaulted = 0_i32;
    // SAFETY: descriptor is live and outputs point to initialized storage.
    let succeeded = if label {
        unsafe {
            GetSecurityDescriptorSacl(
                descriptor,
                &raw mut present,
                &raw mut acl,
                &raw mut defaulted,
            )
        }
    } else {
        unsafe {
            GetSecurityDescriptorDacl(
                descriptor,
                &raw mut present,
                &raw mut acl,
                &raw mut defaulted,
            )
        }
    };
    if succeeded == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    if present == 0 {
        Ok(FileAcl::Absent)
    } else if acl.is_null() {
        Ok(FileAcl::Null)
    } else {
        Ok(FileAcl::Entries(file_acl(acl)?))
    }
}

fn file_acl(acl: *mut ACL) -> Result<Vec<FileAce>, String> {
    // SAFETY: zero is a valid initial representation for this output-only POD.
    let mut information = unsafe { std::mem::zeroed::<ACL_SIZE_INFORMATION>() };
    // SAFETY: acl is live and the output size exactly matches its type.
    if unsafe {
        GetAclInformation(
            acl,
            (&raw mut information).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }

    let mut entries = Vec::with_capacity(information.AceCount as usize);
    for index in 0..information.AceCount {
        let mut ace = ptr::null_mut();
        // SAFETY: index is bounded by the queried ACE count.
        if unsafe { GetAce(acl, index, &raw mut ace) } == 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        let bytes = ace.cast::<u8>();
        // SAFETY: GetAce returned a live ACE_HEADER.
        let ace_type = unsafe { *bytes };
        // SAFETY: GetAce returned a live ACE_HEADER.
        let flags = unsafe { *bytes.add(1) };
        let ace_size = u16::from_le_bytes([
            // SAFETY: GetAce returned a live ACE_HEADER.
            unsafe { *bytes.add(2) },
            // SAFETY: GetAce returned a live ACE_HEADER.
            unsafe { *bytes.add(3) },
        ]) as usize;
        if ace_size < 8 {
            return Err(format!("file security ACE {index} has no access mask"));
        }
        // SAFETY: the validated ACE contains a four-byte access mask at offset four.
        let mask = unsafe { ptr::read_unaligned(bytes.add(4).cast::<u32>()) };
        // SAFETY: the header-declared ACE remains live with at least ace_size
        // bytes, and the first eight bytes were validated above.
        let body = unsafe { std::slice::from_raw_parts(bytes.add(8), ace_size - 8) }.to_vec();
        entries.push(FileAce {
            ace_type,
            flags,
            mask: normalized_access_mask(SecurityObjectKind::File, mask),
            body,
        });
    }
    Ok(entries)
}

fn file_acl_projection(entries: &[FileAce]) -> FileAclProjection {
    let mut effective = Vec::with_capacity(entries.len());
    let mut inheritance = Vec::with_capacity(entries.len());
    for entry in entries {
        if entry.flags & INHERIT_ONLY_ACE_FLAG == 0 {
            let mut projected = entry.clone();
            projected.flags &= !(OBJECT_INHERIT_ACE_FLAG
                | CONTAINER_INHERIT_ACE_FLAG
                | NO_PROPAGATE_INHERIT_ACE_FLAG
                | INHERIT_ONLY_ACE_FLAG);
            effective.push(projected);
        }
        if entry.flags & (OBJECT_INHERIT_ACE_FLAG | CONTAINER_INHERIT_ACE_FLAG) != 0 {
            let mut projected = entry.clone();
            projected.flags &= !INHERIT_ONLY_ACE_FLAG;
            inheritance.push(projected);
        }
    }
    FileAclProjection {
        effective,
        inheritance,
    }
}

fn file_security_difference(
    expected: &FileSecurityComponents,
    actual: &FileSecurityComponents,
) -> Option<String> {
    if expected.owner != actual.owner {
        return Some(format!(
            "component=file-owner expected={:?} actual={:?}",
            expected.owner, actual.owner
        ));
    }
    if expected.dacl_protected != actual.dacl_protected {
        return Some(format!(
            "component=file-dacl-protection expected={} actual={}",
            expected.dacl_protected, actual.dacl_protected
        ));
    }
    if expected.dacl_auto_inherit_requested != actual.dacl_auto_inherit_requested {
        return Some(format!(
            "component=file-dacl-auto-inherit-request expected={} actual={}",
            expected.dacl_auto_inherit_requested, actual.dacl_auto_inherit_requested
        ));
    }
    if let Some(difference) = file_acl_difference("file-dacl", &expected.dacl, &actual.dacl) {
        return Some(difference);
    }
    if expected.label_protected != actual.label_protected {
        return Some(format!(
            "component=file-label-protection expected={:?} actual={:?}",
            expected.label_protected, actual.label_protected
        ));
    }
    if expected.label_auto_inherit_requested != actual.label_auto_inherit_requested {
        return Some(format!(
            "component=file-label-auto-inherit-request expected={:?} actual={:?}",
            expected.label_auto_inherit_requested, actual.label_auto_inherit_requested
        ));
    }
    match (&expected.label, &actual.label) {
        (Some(expected), Some(actual)) => file_acl_difference("file-label", expected, actual),
        (None, None) => None,
        _ => Some(format!(
            "component=file-label-presence expected={} actual={}",
            expected.label.is_some(),
            actual.label.is_some()
        )),
    }
}

fn file_acl_difference(prefix: &str, expected: &FileAcl, actual: &FileAcl) -> Option<String> {
    let (FileAcl::Entries(expected), FileAcl::Entries(actual)) = (expected, actual) else {
        return (expected != actual).then(|| {
            format!(
                "component={prefix}-presence expected={} actual={}",
                file_acl_state(expected),
                file_acl_state(actual)
            )
        });
    };
    let expected = file_acl_projection(expected);
    let actual = file_acl_projection(actual);
    file_ace_sequence_difference(
        &format!("{prefix}-effective-ace"),
        &expected.effective,
        &actual.effective,
    )
    .or_else(|| {
        file_ace_sequence_difference(
            &format!("{prefix}-inheritance-ace"),
            &expected.inheritance,
            &actual.inheritance,
        )
    })
}

fn file_acl_state(acl: &FileAcl) -> &'static str {
    match acl {
        FileAcl::Absent => "absent",
        FileAcl::Null => "null",
        FileAcl::Entries(_) => "present",
    }
}

fn file_ace_sequence_difference(
    component: &str,
    expected: &[FileAce],
    actual: &[FileAce],
) -> Option<String> {
    if expected.len() != actual.len() {
        return Some(format!(
            "component={component}-count expected={} actual={}",
            expected.len(),
            actual.len()
        ));
    }
    expected
        .iter()
        .zip(actual)
        .enumerate()
        .find_map(|(index, (expected, actual))| {
            (expected != actual).then(|| {
                format!("component={component}[{index}] expected={expected:?} actual={actual:?}")
            })
        })
}

#[cfg(test)]
pub(crate) fn compare_file_security_sddl_for_test(
    expected: &str,
    actual: &str,
) -> Result<(), String> {
    let expected = SecurityDescriptor::from_sddl(expected)?;
    let actual = SecurityDescriptor::from_sddl(actual)?;
    expected.verify_descriptor(actual.0, SecurityObjectKind::File)
}

#[cfg(test)]
pub(crate) fn compare_user_object_security_sddl_for_test(
    expected: &str,
    actual: &str,
    kind: SecurityObjectKind,
) -> Result<(), String> {
    if !matches!(
        kind,
        SecurityObjectKind::WindowStation | SecurityObjectKind::Desktop
    ) {
        return Err("USER-object comparison requires a station or desktop kind".to_owned());
    }
    let expected = SecurityDescriptor::from_sddl(expected)?;
    let actual = SecurityDescriptor::from_sddl(actual)?;
    expected.verify_descriptor(actual.0, kind)
}

#[cfg(test)]
pub(crate) fn user_object_policy_fingerprint_for_test(
    sddl: &str,
    kind: SecurityObjectKind,
) -> Result<String, String> {
    SecurityDescriptor::from_sddl(sddl)?.user_object_policy_fingerprint(kind)
}

#[cfg(test)]
pub(crate) fn user_object_resultant_fingerprint_for_test(
    expected: &str,
    actual: &str,
    kind: SecurityObjectKind,
) -> Result<String, String> {
    let expected = SecurityDescriptor::from_sddl(expected)?;
    let actual = SecurityDescriptor::from_sddl(actual)?;
    require_target_user_object_policy_selection(expected.1, kind)?;
    require_target_user_object_policy_selection(actual.1, kind)?;
    let canonical = if kind == SecurityObjectKind::Desktop {
        normalized_resultant_user_object_sddl(expected.0, actual.0, expected.1, kind)?
    } else {
        normalized_descriptor_sddl(actual.0, actual.1, kind)?
    };
    Ok(super::record::digest(canonical.as_bytes()))
}

fn pipe_security_components(
    descriptor: *mut c_void,
    owner: Option<*mut c_void>,
    dacl: Option<*mut ACL>,
    label: Option<*mut ACL>,
    information: u32,
) -> Result<PipeSecurityComponents, String> {
    let owner = match owner {
        Some(owner) => owner,
        None => {
            let mut owner = ptr::null_mut();
            let mut defaulted = 0_i32;
            // SAFETY: descriptor is live and outputs point to initialized storage.
            if unsafe { GetSecurityDescriptorOwner(descriptor, &raw mut owner, &raw mut defaulted) }
                == 0
            {
                return Err(io::Error::last_os_error().to_string());
            }
            owner
        }
    };
    if owner.is_null() {
        return Err("named-pipe policy has no owner SID".to_owned());
    }

    let dacl = match dacl {
        Some(dacl) => Some(dacl).filter(|dacl| !dacl.is_null()),
        None => {
            let mut present = 0_i32;
            let mut dacl = ptr::null_mut();
            let mut defaulted = 0_i32;
            // SAFETY: descriptor is live and outputs point to initialized storage.
            if unsafe {
                GetSecurityDescriptorDacl(
                    descriptor,
                    &raw mut present,
                    &raw mut dacl,
                    &raw mut defaulted,
                )
            } == 0
            {
                return Err(io::Error::last_os_error().to_string());
            }
            (present != 0 && !dacl.is_null()).then_some(dacl)
        }
    };

    let label = if information & LABEL_SECURITY_INFORMATION == 0 {
        None
    } else {
        match label {
            Some(label) => Some(label).filter(|label| !label.is_null()),
            None => {
                let mut present = 0_i32;
                let mut label = ptr::null_mut();
                let mut defaulted = 0_i32;
                // SAFETY: descriptor is live and outputs point to initialized storage.
                if unsafe {
                    GetSecurityDescriptorSacl(
                        descriptor,
                        &raw mut present,
                        &raw mut label,
                        &raw mut defaulted,
                    )
                } == 0
                {
                    return Err(io::Error::last_os_error().to_string());
                }
                (present != 0 && !label.is_null()).then_some(label)
            }
        }
    };

    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: descriptor is live and outputs point to initialized storage.
    if unsafe { GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision) } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }

    Ok(PipeSecurityComponents {
        owner: super::token::sid_string(owner)?,
        dacl_protected: control & SE_DACL_PROTECTED != 0,
        dacl: dacl
            .map(|acl| pipe_acl(acl, SecurityObjectKind::NamedPipe))
            .transpose()?,
        label: label
            .map(|acl| pipe_acl(acl, SecurityObjectKind::NamedPipe))
            .transpose()?,
    })
}

fn pipe_acl(acl: *mut ACL, kind: SecurityObjectKind) -> Result<Vec<PipeAce>, String> {
    // SAFETY: zero is a valid initial representation for this output-only POD.
    let mut information = unsafe { std::mem::zeroed::<ACL_SIZE_INFORMATION>() };
    // SAFETY: acl is a live ACL and the output size exactly matches its type.
    if unsafe {
        GetAclInformation(
            acl,
            (&raw mut information).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    let mut entries = Vec::with_capacity(information.AceCount as usize);
    for index in 0..information.AceCount {
        let mut ace = ptr::null_mut();
        // SAFETY: index is bounded by the queried ACE count.
        if unsafe { GetAce(acl, index, &raw mut ace) } == 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        let bytes = ace.cast::<u8>();
        // SAFETY: GetAce returned a live ACE_HEADER.
        let ace_type = unsafe { *bytes };
        // SAFETY: GetAce returned a live ACE_HEADER.
        let flags = unsafe { *bytes.add(1) };
        let ace_size = u16::from_le_bytes([
            // SAFETY: GetAce returned a live ACE_HEADER.
            unsafe { *bytes.add(2) },
            // SAFETY: GetAce returned a live ACE_HEADER.
            unsafe { *bytes.add(3) },
        ]);
        if ace_size < 12 {
            return Err(format!(
                "named-pipe ACE {index} is shorter than an access ACE"
            ));
        }
        // SAFETY: the validated ACE contains a mask at offset four.
        let mask = unsafe { ptr::read_unaligned(bytes.add(4).cast::<u32>()) };
        // The reviewed pipe and mandatory-label contracts use the basic ACE
        // layouts whose SID begins at offset eight. Unexpected ACE types are
        // retained for the typed comparison but do not get reinterpreted.
        let trustee = if matches!(
            ace_type,
            ACCESS_ALLOWED_ACE_TYPE | SYSTEM_MANDATORY_LABEL_ACE_TYPE
        ) {
            // SAFETY: the validated basic ACE contains its SID at offset eight.
            let sid = unsafe { bytes.add(8).cast() };
            // SAFETY: sid points into the live ACE and is queried only.
            if unsafe { IsValidSid(sid) } == 0 {
                return Err(format!("named-pipe ACE {index} contains an invalid SID"));
            }
            // SAFETY: IsValidSid accepted this live SID.
            let sid_size = unsafe { GetLengthSid(sid) };
            if sid_size > u32::from(ace_size - 8) {
                return Err(format!(
                    "named-pipe ACE {index} SID extends beyond the ACE boundary"
                ));
            }
            super::token::sid_string(sid)?
        } else {
            String::new()
        };
        entries.push(PipeAce {
            ace_type,
            flags,
            mask: normalized_access_mask(kind, mask),
            trustee,
        });
    }
    Ok(entries)
}

fn compare_pipe_security(
    expected: &PipeSecurityComponents,
    actual: &PipeSecurityComponents,
) -> Result<(), NamedPipeSecurityMismatch> {
    if actual.owner != expected.owner {
        return Err(NamedPipeSecurityMismatch::Owner {
            expected: expected.owner.clone(),
            actual: actual.owner.clone(),
        });
    }
    let expected_dacl = expected
        .dacl
        .as_ref()
        .expect("converted named-pipe policy must contain a DACL");
    let Some(actual_dacl) = actual.dacl.as_ref() else {
        return Err(NamedPipeSecurityMismatch::DaclPresence { actual: false });
    };

    // `SE_DACL_PROTECTED` controls child-object inheritance. NPFS named-pipe
    // instances have no inheritable object hierarchy, so the enforceable
    // invariant is the exact ordered ACE policy below, not preservation of
    // that creator/resultant representation bit.
    if NAMED_PIPE_DACL_PROTECTION_REQUIRED && expected.dacl_protected != actual.dacl_protected {
        return Err(NamedPipeSecurityMismatch::DaclProtection {
            expected: expected.dacl_protected,
            actual: actual.dacl_protected,
        });
    }
    compare_pipe_acl(expected_dacl, actual_dacl, false)?;

    match (&expected.label, &actual.label) {
        (Some(_), None) => Err(NamedPipeSecurityMismatch::LabelPresence { actual: false }),
        (Some(expected), Some(actual)) => compare_pipe_acl(expected, actual, true),
        (None, _) => Ok(()),
    }
}

fn compare_pipe_acl(
    expected: &[PipeAce],
    actual: &[PipeAce],
    mandatory_label: bool,
) -> Result<(), NamedPipeSecurityMismatch> {
    if expected.len() != actual.len() {
        let expected = expected.len() as u32;
        let actual = actual.len() as u32;
        return Err(if mandatory_label {
            NamedPipeSecurityMismatch::LabelAceCount { expected, actual }
        } else {
            NamedPipeSecurityMismatch::AceCount { expected, actual }
        });
    }
    for (index, (expected, actual)) in expected.iter().zip(actual).enumerate() {
        let index = index as u32;
        if expected.ace_type != actual.ace_type {
            return Err(if mandatory_label {
                NamedPipeSecurityMismatch::LabelAceType {
                    index,
                    expected: expected.ace_type,
                    actual: actual.ace_type,
                }
            } else {
                NamedPipeSecurityMismatch::AceType {
                    index,
                    expected: expected.ace_type,
                    actual: actual.ace_type,
                }
            });
        }
        if expected.flags != actual.flags {
            return Err(if mandatory_label {
                NamedPipeSecurityMismatch::LabelAceFlags {
                    index,
                    expected: expected.flags,
                    actual: actual.flags,
                }
            } else {
                NamedPipeSecurityMismatch::AceFlags {
                    index,
                    expected: expected.flags,
                    actual: actual.flags,
                }
            });
        }
        if expected.mask != actual.mask {
            return Err(if mandatory_label {
                NamedPipeSecurityMismatch::LabelAceMask {
                    index,
                    expected: expected.mask,
                    actual: actual.mask,
                }
            } else {
                NamedPipeSecurityMismatch::AceMask {
                    index,
                    expected: expected.mask,
                    actual: actual.mask,
                }
            });
        }
        if expected.trustee != actual.trustee {
            return Err(if mandatory_label {
                NamedPipeSecurityMismatch::LabelAceTrustee {
                    index,
                    expected: expected.trustee.clone(),
                    actual: actual.trustee.clone(),
                }
            } else {
                NamedPipeSecurityMismatch::AceTrustee {
                    index,
                    expected: expected.trustee.clone(),
                    actual: actual.trustee.clone(),
                }
            });
        }
    }
    Ok(())
}

pub(crate) const fn pipe_mismatch_diagnostic_from_exit(
    code: u32,
) -> Option<(&'static str, &'static str)> {
    let (role, offset) = if code >= 0x4d43_0108 && code <= 0x4d43_0115 {
        ("public", code - 0x4d43_0108)
    } else if code >= 0x4d43_0207 && code <= 0x4d43_0214 {
        ("private", code - 0x4d43_0207)
    } else {
        return None;
    };
    let component = match offset {
        0 => "owner",
        1 => "dacl-presence",
        2 => "dacl-protection",
        3 => "dacl-ace-count",
        4 => "dacl-ace-type",
        5 => "dacl-ace-flags",
        6 => "dacl-ace-mask",
        7 => "dacl-ace-trustee",
        8 => "mandatory-label-presence",
        9 => "mandatory-label-ace-count",
        10 => "mandatory-label-ace-type",
        11 => "mandatory-label-ace-flags",
        12 => "mandatory-label-ace-mask",
        13 => "mandatory-label-ace-trustee",
        _ => return None,
    };
    Some((role, component))
}

fn require_user_object_kind(kind: SecurityObjectKind) -> Result<(), String> {
    if matches!(
        kind,
        SecurityObjectKind::WindowStation | SecurityObjectKind::Desktop
    ) {
        Ok(())
    } else {
        Err("USER-object operation requires a station or desktop kind".to_owned())
    }
}

fn require_target_user_object_policy_selection(
    information: u32,
    kind: SecurityObjectKind,
) -> Result<(), String> {
    require_user_object_kind(kind)?;
    let required = OWNER_SECURITY_INFORMATION
        | GROUP_SECURITY_INFORMATION
        | DACL_SECURITY_INFORMATION
        | LABEL_SECURITY_INFORMATION;
    if information == required {
        Ok(())
    } else {
        Err(format!(
            "target USER-object policy fingerprint requires exactly owner, group, DACL, and mandatory label: information={information:#010x}"
        ))
    }
}

fn read_user_object_security(
    handle: windows_sys::Win32::Foundation::HANDLE,
    information: u32,
) -> Result<Vec<u32>, String> {
    let mut needed = 0_u32;
    // SAFETY: the sizing call writes only the required descriptor length.
    unsafe {
        GetUserObjectSecurity(
            handle,
            &raw const information,
            ptr::null_mut(),
            0,
            &raw mut needed,
        )
    };
    let mut descriptor = descriptor_buffer(needed)?;
    // SAFETY: descriptor has the exact requested byte capacity and handle
    // denotes a live window station or desktop with READ_CONTROL.
    if unsafe {
        GetUserObjectSecurity(
            handle,
            &raw const information,
            descriptor.as_mut_ptr().cast(),
            needed,
            &raw mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok(descriptor)
}

pub(crate) fn normalized_descriptor_sddl(
    descriptor: *mut c_void,
    information: u32,
    kind: SecurityObjectKind,
) -> Result<String, String> {
    let mut normalized = normalized_descriptor_copy(descriptor, kind)?;
    descriptor_sddl(normalized.as_mut_ptr().cast(), information)
}

fn normalized_resultant_user_object_sddl(
    expected: *mut c_void,
    actual: *mut c_void,
    information: u32,
    kind: SecurityObjectKind,
) -> Result<String, String> {
    if kind != SecurityObjectKind::Desktop {
        return Err("resultant USER-object SACL normalization is desktop-only".to_owned());
    }
    let (expected_control, _) = descriptor_control(expected)?;
    let expected_sacl_present = expected_control & SE_SACL_PRESENT_CONTROL != 0;
    let expected_sacl_protected = expected_control & SE_SACL_PROTECTED_CONTROL != 0;
    let expected_sacl_auto_inherit_requested =
        expected_control & SE_SACL_AUTO_INHERIT_REQ_CONTROL != 0;
    let expected_sacl_auto_inherited = expected_control & SE_SACL_AUTO_INHERITED_CONTROL != 0;
    if !expected_sacl_present
        || !expected_sacl_protected
        || expected_sacl_auto_inherit_requested
        || expected_sacl_auto_inherited
    {
        return Err(
            "expected desktop descriptor has an unprotected or auto-inherited mandatory-label SACL"
                .to_owned(),
        );
    }

    let (actual_control, _) = descriptor_control(actual)?;
    if actual_control == expected_control {
        return normalized_descriptor_sddl(actual, information, kind);
    }
    let actual_sacl_present = actual_control & SE_SACL_PRESENT_CONTROL != 0;
    let actual_sacl_protected = actual_control & SE_SACL_PROTECTED_CONTROL != 0;
    let actual_sacl_auto_inherit_requested = actual_control & SE_SACL_AUTO_INHERIT_REQ_CONTROL != 0;
    let only_resultant_sacl_auto_inherited_differs =
        (expected_control ^ actual_control) == SE_SACL_AUTO_INHERITED_CONTROL;
    if !actual_sacl_present
        || !actual_sacl_protected
        || actual_sacl_auto_inherit_requested
        || !only_resultant_sacl_auto_inherited_differs
    {
        return normalized_descriptor_sddl(actual, information, kind);
    }

    let mut normalized = normalized_descriptor_copy(actual, kind)?;
    // SAFETY: normalized is a writable copy of the live self-relative descriptor.
    if unsafe {
        SetSecurityDescriptorControl(
            normalized.as_mut_ptr().cast(),
            SE_SACL_AUTO_INHERITED_CONTROL,
            0,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    descriptor_sddl(normalized.as_mut_ptr().cast(), information)
}

fn normalized_descriptor_copy(
    descriptor: *mut c_void,
    kind: SecurityObjectKind,
) -> Result<Vec<u32>, String> {
    let (control, _) = descriptor_control(descriptor)?;
    if control & SE_SELF_RELATIVE == 0 {
        return Err("cannot normalize an absolute security descriptor by byte copy".to_owned());
    }
    // SAFETY: descriptor is a live self-relative descriptor.
    let bytes = unsafe { GetSecurityDescriptorLength(descriptor) };
    let mut normalized = descriptor_buffer(bytes)?;
    // SAFETY: normalized has at least `bytes` bytes and descriptors are plain
    // self-contained byte representations for the inputs used here.
    unsafe {
        ptr::copy_nonoverlapping(
            descriptor.cast::<u8>(),
            normalized.as_mut_ptr().cast::<u8>(),
            bytes as usize,
        );
    }
    normalize_descriptor_dacl(normalized.as_mut_ptr().cast(), kind)?;
    Ok(normalized)
}

fn normalize_descriptor_dacl(
    descriptor: *mut c_void,
    kind: SecurityObjectKind,
) -> Result<(), String> {
    let mut present = 0_i32;
    let mut defaulted = 0_i32;
    let mut acl = ptr::null_mut();
    // SAFETY: descriptor is a writable descriptor copy and all outputs point
    // to initialized writable storage.
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &raw mut present,
            &raw mut acl,
            &raw mut defaulted,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    if present == 0 || acl.is_null() {
        return Ok(());
    }

    // SAFETY: zero is a valid initial representation for this output-only POD.
    let mut information = unsafe { std::mem::zeroed::<ACL_SIZE_INFORMATION>() };
    // SAFETY: acl belongs to the writable descriptor copy and the output size
    // exactly matches ACL_SIZE_INFORMATION.
    if unsafe {
        GetAclInformation(
            acl,
            (&raw mut information).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    for index in 0..information.AceCount {
        let mut ace = ptr::null_mut();
        // SAFETY: index is bounded by the queried ACE count and output is writable.
        if unsafe { GetAce(acl, index, &raw mut ace) } == 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        let bytes = ace.cast::<u8>();
        // Every ACE form accepted in a discretionary ACL starts with the
        // four-byte ACE_HEADER followed by a four-byte ACCESS_MASK. Read and
        // write unaligned because the API does not promise Rust alignment.
        let ace_size = u16::from_le_bytes([
            // SAFETY: GetAce returned a live ACE_HEADER.
            unsafe { *bytes.add(2) },
            // SAFETY: GetAce returned a live ACE_HEADER.
            unsafe { *bytes.add(3) },
        ]);
        if ace_size < 8 {
            return Err(format!(
                "security descriptor ACE {index} has no access mask"
            ));
        }
        // SAFETY: the validated ACE contains a four-byte access mask at offset four.
        let mask = unsafe { ptr::read_unaligned(bytes.add(4).cast::<u32>()) };
        let mask = normalized_access_mask(kind, mask);
        // SAFETY: the descriptor copy is writable and the ACE contains this mask.
        unsafe { ptr::write_unaligned(bytes.add(4).cast::<u32>(), mask) };
    }
    Ok(())
}

pub(crate) fn normalized_access_mask(kind: SecurityObjectKind, mut mask: u32) -> u32 {
    let mapping = kind.generic_mapping();
    // SAFETY: both pointers reference initialized values for this synchronous call.
    unsafe { MapGenericMask(&raw mut mask, &raw const mapping) };
    mask
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

fn descriptor_control(descriptor: *mut c_void) -> Result<(u16, u32), String> {
    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: descriptor is live and both outputs point to initialized storage.
    if unsafe { GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision) } == 0
    {
        Err(io::Error::last_os_error().to_string())
    } else {
        Ok((control, revision))
    }
}

fn descriptor_owner_and_group(
    descriptor: *mut c_void,
    phase: &str,
) -> Result<(*mut c_void, *mut c_void), String> {
    let mut owner = ptr::null_mut();
    let mut owner_defaulted = 0_i32;
    // SAFETY: descriptor is live and both outputs point to writable storage.
    if unsafe { GetSecurityDescriptorOwner(descriptor, &raw mut owner, &raw mut owner_defaulted) }
        == 0
    {
        return Err(format!(
            "cannot inspect {phase} descriptor owner: {}",
            io::Error::last_os_error()
        ));
    }
    if owner.is_null() {
        return Err(format!("{phase} descriptor owner is missing"));
    }
    // SAFETY: the descriptor returned a non-null owner SID pointer.
    if unsafe { IsValidSid(owner) } == 0 {
        return Err(format!("{phase} descriptor owner SID is invalid"));
    }
    if owner_defaulted != 0 {
        return Err(format!("{phase} descriptor owner is defaulted"));
    }

    let mut group = ptr::null_mut();
    let mut group_defaulted = 0_i32;
    // SAFETY: descriptor is live and both outputs point to writable storage.
    if unsafe { GetSecurityDescriptorGroup(descriptor, &raw mut group, &raw mut group_defaulted) }
        == 0
    {
        return Err(format!(
            "cannot inspect {phase} descriptor group: {}",
            io::Error::last_os_error()
        ));
    }
    if group.is_null() {
        return Err(format!("{phase} descriptor group is missing"));
    }
    // SAFETY: the descriptor returned a non-null group SID pointer.
    if unsafe { IsValidSid(group) } == 0 {
        return Err(format!("{phase} descriptor group SID is invalid"));
    }
    if group_defaulted != 0 {
        return Err(format!("{phase} descriptor group is defaulted"));
    }
    Ok((owner, group))
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
    let string = LocalWideString::new(string)?;
    if length == 0 {
        return Err("security descriptor string conversion returned no output".to_owned());
    }
    // SAFETY: string is a live local-memory allocation retained by the owner.
    let allocated_bytes = unsafe { LocalSize(string.raw().cast()) };
    if allocated_bytes == 0 {
        return Err(format!(
            "cannot inspect security descriptor string allocation: {}",
            io::Error::last_os_error()
        ));
    }
    // SAFETY: LocalSize supplies the byte extent used to validate every read,
    // and string remains owned until decoding returns.
    let value = unsafe { decode_local_alloc_utf16(string.raw(), length, allocated_bytes) }?;
    if value.is_empty() {
        Err("security descriptor string conversion returned empty text".to_owned())
    } else {
        Ok(value)
    }
}

unsafe fn decode_local_alloc_utf16(
    string: *const u16,
    reported_length: u32,
    allocated_bytes: usize,
) -> Result<String, String> {
    let (reported, readable_units) =
        sddl_utf16_allocation_window(reported_length, allocated_bytes)?;

    let mut end = None;
    for index in 0..readable_units {
        // SAFETY: the allocation-window helper proved this unit lies in the
        // LocalSize extent. The conversion API initializes the NUL-terminated
        // string through its first terminator, and the loop stops there without
        // inspecting allocator slack.
        if unsafe { *string.add(index) } == 0 {
            end = Some(index);
            break;
        }
    }
    let end = end.ok_or_else(|| {
        if readable_units == reported {
            "security descriptor text is not NUL-terminated within its allocation".to_owned()
        } else {
            "security descriptor text is not NUL-terminated at its reported boundary".to_owned()
        }
    })?;
    // SAFETY: every unit through end was read before the first terminator and
    // was therefore initialized by the conversion API.
    let text = unsafe { std::slice::from_raw_parts(string, end) };
    String::from_utf16(text).map_err(|error| error.to_string())
}

pub(crate) fn sddl_utf16_allocation_window(
    reported_length: u32,
    allocated_bytes: usize,
) -> Result<(usize, usize), String> {
    let reported = usize::try_from(reported_length)
        .map_err(|_| "security descriptor text length is not representable".to_owned())?;
    if reported == 0 {
        return Err("security descriptor text length is zero".to_owned());
    }
    if reported > MAX_SDDL_UTF16_UNITS {
        return Err(format!(
            "security descriptor text length exceeds the safety bound: {reported}"
        ));
    }
    let unit_bytes = std::mem::size_of::<u16>();
    if allocated_bytes == 0 {
        return Err("security descriptor text allocation is empty".to_owned());
    }
    if allocated_bytes % unit_bytes != 0 {
        return Err(format!(
            "security descriptor text allocation has a partial UTF-16 unit: allocated_bytes={allocated_bytes}"
        ));
    }
    let allocation_units = allocated_bytes / unit_bytes;
    if reported > allocation_units {
        return Err(format!(
            "security descriptor text length exceeds its LocalAlloc allocation: reported_units={reported} allocation_units={allocation_units} allocated_bytes={allocated_bytes}"
        ));
    }
    let readable_units = reported
        .checked_add(usize::from(reported < allocation_units))
        .ok_or_else(|| "security descriptor text boundary overflows".to_owned())?;
    Ok((reported, readable_units))
}

pub(crate) fn utf16_nul_terminated_with_reported_length(
    buffer: &[u16],
    reported_length: u32,
) -> Result<String, String> {
    let reported = usize::try_from(reported_length)
        .map_err(|_| "security descriptor text length is not representable".to_owned())?;
    if reported == 0 || buffer.len() < reported {
        return Err("security descriptor text length is outside the provided buffer".to_owned());
    }
    let end = buffer[..reported]
        .iter()
        .position(|unit| *unit == 0)
        .or_else(|| (buffer.get(reported) == Some(&0)).then_some(reported))
        .ok_or_else(|| {
            "security descriptor text is not NUL-terminated at its reported boundary".to_owned()
        })?;
    String::from_utf16(&buffer[..end]).map_err(|error| error.to_string())
}

pub(crate) fn utf16_nul_terminated(buffer: &[u16]) -> Result<String, String> {
    let end = buffer
        .iter()
        .position(|unit| *unit == 0)
        .ok_or_else(|| "security descriptor text is not NUL-terminated".to_owned())?;
    String::from_utf16(&buffer[..end]).map_err(|error| error.to_string())
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
