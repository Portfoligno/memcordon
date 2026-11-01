//! Later controller observations of an original-call retained parent reference.
//! A later child open never proves the failed call's child-object identity.
use serde_json::{Value, json};
use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;
use windows_sys::Win32::Foundation::{
    CompareObjectHandles, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE,
};
use windows_sys::Win32::Security::{
    AccessCheck, DuplicateTokenEx, GENERIC_MAPPING, SecurityImpersonation, TOKEN_QUERY,
    TokenImpersonation,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

#[repr(C)]
struct Unicode {
    length: u16,
    maximum: u16,
    buffer: *mut u16,
}
#[repr(C)]
struct Attributes {
    length: u32,
    root: HANDLE,
    name: *mut Unicode,
    flags: u32,
    descriptor: *mut c_void,
    quality: *mut c_void,
}
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryObject(
        handle: HANDLE,
        class: u32,
        data: *mut c_void,
        size: u32,
        returned: *mut u32,
    ) -> i32;
    fn NtOpenDirectoryObject(
        output: *mut HANDLE,
        access: u32,
        attributes: *const Attributes,
    ) -> i32;
    fn NtQuerySecurityObject(
        handle: HANDLE,
        information: u32,
        data: *mut c_void,
        size: u32,
        returned: *mut u32,
    ) -> i32;
}

fn error(operation: &'static str, error: io::Error) -> Value {
    json!({"operation":operation,"unavailable":true,"raw_os_error":error.raw_os_error()})
}

fn query_name(handle: HANDLE) -> Value {
    let mut bytes = vec![0_usize; 8192 / size_of::<usize>()];
    let mut returned = 0;
    // SAFETY: bounded aligned buffer and a held original object reference.
    let status =
        unsafe { NtQueryObject(handle, 1, bytes.as_mut_ptr().cast(), 8192, &mut returned) };
    if status < 0 || returned as usize > 8192 || (returned as usize) < size_of::<Unicode>() {
        return json!({"native_status":status,"returned_bytes":returned,"unavailable":true});
    }
    // SAFETY: successful bounded ObjectNameInformation begins with UNICODE_STRING.
    let name = unsafe { &*bytes.as_ptr().cast::<Unicode>() };
    let begin = bytes.as_ptr() as usize;
    let address = name.buffer as usize;
    if name.length % 2 != 0
        || name.length > name.maximum
        || address % std::mem::align_of::<u16>() != 0
        || address < begin
        || address
            .checked_add(name.length as usize)
            .is_none_or(|end| end > begin + 8192)
    {
        return json!({"native_status":status,"unavailable":"invalid bounded object name"});
    }
    // SAFETY: the native pointer and complete UTF16 extent were checked within the owned buffer.
    let units = unsafe { std::slice::from_raw_parts(name.buffer, name.length as usize / 2) };
    json!({"native_status":status,"utf16":units})
}

fn security(handle: HANDLE) -> Result<(Vec<usize>, usize), Value> {
    let mut bytes = vec![0_usize; 8192 / size_of::<usize>()];
    let mut returned = 0;
    // OWNER|GROUP|DACL|LABEL, bounded read only. No SACL privilege or mutation.
    let status = unsafe {
        NtQuerySecurityObject(handle, 0x17, bytes.as_mut_ptr().cast(), 8192, &mut returned)
    };
    if status < 0 || returned == 0 || returned as usize > 8192 {
        return Err(json!({"native_status":status,"returned_bytes":returned,"unavailable":true}));
    }
    bytes.truncate((returned as usize).div_ceil(size_of::<usize>()));
    Ok((bytes, returned as usize))
}

fn readable_parent(
    parent: HANDLE,
    name: &Value,
    flags: u32,
    check: &mut impl FnMut() -> io::Result<()>,
) -> io::Result<(Option<OwnedHandle>, Value)> {
    let units: Option<Vec<u16>> = name["utf16"].as_array().and_then(|v| {
        v.iter()
            .map(|v| v.as_u64().and_then(|v| u16::try_from(v).ok()))
            .collect()
    });
    let Some(mut units) = units.filter(|v| !v.is_empty() && v.len() <= 4096 && !v.contains(&0))
    else {
        return Ok((None, json!({"unavailable":"held parent name unavailable"})));
    };
    let length = (units.len() * 2) as u16;
    let mut name = Unicode {
        length,
        maximum: length,
        buffer: units.as_mut_ptr(),
    };
    let attributes = Attributes {
        length: size_of::<Attributes>() as u32,
        root: ptr::null_mut(),
        name: &mut name,
        flags,
        descriptor: ptr::null_mut(),
        quality: ptr::null_mut(),
    };
    check()?;
    let mut raw = ptr::null_mut();
    let status = unsafe { NtOpenDirectoryObject(&mut raw, 0x0002_0003, &attributes) };
    let mut record = json!({"native_status":status,"requested_read_access":0x0002_0003,"same_as_retained_parent":false});
    if status < 0 || raw.is_null() {
        return Ok((None, record));
    }
    let reopened = unsafe { OwnedHandle::from_raw_handle(raw) };
    check()?;
    let same = unsafe { CompareObjectHandles(parent, reopened.as_raw_handle()) } != 0;
    record["same_as_retained_parent"] = same.into();
    if !same {
        return Ok((None, record));
    }
    Ok((Some(reopened), record))
}

fn compare(
    token: HANDLE,
    descriptor: &mut [usize],
    check: &mut impl FnMut() -> io::Result<()>,
) -> io::Result<Value> {
    check()?;
    let mut raw = ptr::null_mut();
    // Same source token, query-only impersonation duplicate; no SID/privilege edits.
    if unsafe {
        DuplicateTokenEx(
            token,
            TOKEN_QUERY,
            ptr::null(),
            SecurityImpersonation,
            TokenImpersonation,
            &mut raw,
        )
    } == 0
    {
        return Ok(error(
            "DuplicateTokenEx-same-source",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: the successful API transferred one token reference.
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mapping = GENERIC_MAPPING {
        GenericRead: 0x0002_0003,
        GenericWrite: 0x0002_000c,
        GenericExecute: 0x0002_0002,
        GenericAll: 0x000f_000f,
    };
    let mut privileges = vec![0_usize; 8192 / size_of::<usize>()];
    let mut size = 8192;
    let (mut granted, mut allowed) = (0, 0);
    check()?;
    // SAFETY: complete native descriptor, exact source token and bounded privilege output.
    let api = unsafe {
        AccessCheck(
            descriptor.as_mut_ptr().cast(),
            token.as_raw_handle(),
            0xf,
            &mapping,
            privileges.as_mut_ptr().cast(),
            &mut size,
            &mut granted,
            &mut allowed,
        )
    };
    let native_error = (api == 0)
        .then(io::Error::last_os_error)
        .and_then(|e| e.raw_os_error());
    Ok(
        json!({"desired_access":15,"api_succeeded":api!=0,"raw_os_error":native_error,
        "combined_ordinary_and_restricting_sid_decision":if api!=0 {Some(allowed!=0)} else {None},
        "granted_access":if api!=0 {Some(granted)} else {None},"privilege_bytes":size,
        "separate_ordinary_decision":"unavailable; token was not modified",
        "separate_restricting_decision":"unavailable; token was not modified",
        "mandatory_label_enforcement_reproduced":false}),
    )
}

pub(super) fn observe(
    child: HANDLE,
    token: HANDLE,
    observation: &Value,
    check: &mut impl FnMut() -> io::Result<()>,
) -> io::Result<Value> {
    let plans = super::gate_directory_record::plan(&observation["original_call_trace"])
        .map_err(io::Error::other)?;
    let mut results = Vec::new();
    for plan in plans {
        check()?;
        let mut duplicate = ptr::null_mut();
        // The raw value is only an input to duplication from the original held,
        // still-live child. It never becomes authority by deserialization.
        if unsafe {
            DuplicateHandle(
                child,
                plan.raw_handle as usize as HANDLE,
                GetCurrentProcess(),
                &mut duplicate,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            results.push(error(
                "DuplicateHandle-original-live-child",
                io::Error::last_os_error(),
            ));
            continue;
        }
        let parent = unsafe { OwnedHandle::from_raw_handle(duplicate) };
        check()?;
        let before = query_name(parent.as_raw_handle());
        let (readable_parent, parent_reopen) =
            readable_parent(parent.as_raw_handle(), &before, plan.flags, check)?;
        let security_parent = readable_parent
            .as_ref()
            .map_or(parent.as_raw_handle(), AsRawHandle::as_raw_handle);
        check()?;
        let parent_security = security(security_parent);
        let mut relative = Vec::new();
        for failed in plan.children {
            check()?;
            let mut name = failed.name;
            let length = (name.len() * 2) as u16;
            let mut unicode = Unicode {
                length,
                maximum: length,
                buffer: name.as_mut_ptr(),
            };
            let attributes = Attributes {
                length: size_of::<Attributes>() as u32,
                root: parent.as_raw_handle(),
                name: &mut unicode,
                flags: failed.flags,
                descriptor: ptr::null_mut(),
                quality: ptr::null_mut(),
            };
            let mut raw = ptr::null_mut();
            // A later candidate read, not a retry of the original 0xF call.
            let status = unsafe { NtOpenDirectoryObject(&mut raw, 0x0002_0003, &attributes) };
            let candidate = if status >= 0 && !raw.is_null() {
                Some(unsafe { OwnedHandle::from_raw_handle(raw) })
            } else {
                None
            };
            let mut item = json!({"sequence":failed.sequence,"native_status":status,"requested_read_access":0x0002_0003,
                "candidate_identity_at_original_denial_proved":false,"acceptance_authority":false});
            check()?;
            if let Some(candidate) = candidate {
                item["name"] = query_name(candidate.as_raw_handle());
                check()?;
                match security(candidate.as_raw_handle()) {
                    Ok(mut sd) => {
                        check()?;
                        item["access_comparison"] = compare(token, &mut sd.0, check)?;
                        check()?;
                        let second = security(candidate.as_raw_handle());
                        item["descriptor_readback_equal"] =
                            json!(second.as_ref().is_ok_and(|v| v == &sd));
                        item["descriptor_readback_error"] = json!(second.as_ref().err());
                        let bytes =
                            unsafe { std::slice::from_raw_parts(sd.0.as_ptr().cast::<u8>(), sd.1) };
                        item["security_descriptor_owner_group_dacl_label_bytes"] = json!(bytes);
                    }
                    Err(error) => item["security_descriptor"] = error,
                }
            }
            relative.push(item);
        }
        check()?;
        let after = query_name(parent.as_raw_handle());
        check()?;
        let parent_security_after = security(security_parent);
        let parent_security_readback_equal = parent_security.as_ref().ok().is_some_and(|before| {
            parent_security_after
                .as_ref()
                .is_ok_and(|after| before == after)
        });
        let parent_security_readback_error = parent_security_after.as_ref().err();
        let parent_security = match parent_security {
            Ok((bytes, length)) => {
                json!({"owner_group_dacl_label_bytes":unsafe {std::slice::from_raw_parts(bytes.as_ptr().cast::<u8>(),length)}})
            }
            Err(error) => error,
        };
        results.push(json!({"sequence":plan.sequence,"parent_name_before":before,"parent_name_after":after,
            "parent_name_readback_equal":before["utf16"].is_array()&&before==after,"parent_security":parent_security,
            "parent_readonly_reopen":parent_reopen,
            "parent_security_readback_error":parent_security_readback_error,
            "parent_security_readback_equal":parent_security_readback_equal,"relative_candidates":relative,
            "original_parent_reference_retained":true,"candidate_identity_at_original_denial_proved":false}));
    }
    Ok(
        json!({"diagnostic_only":true,"acceptance_authority":false,"target_identity_proved":false,
        "uninterrupted_child_identity_proved":false,"no_parent_reference_retained":results.is_empty(),
        "capture_errors":observation["original_call_trace"]["retained_directories"]["errors"],"parents":results}),
    )
}
