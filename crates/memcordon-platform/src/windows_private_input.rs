//! Native read/execute sealing of an explicitly owned setup-file handle.
use crate::windows_private_input_record::{Context, expected_sddl, readback_diagnostic};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io,
    os::windows::{fs::MetadataExt, io::AsRawHandle},
    time::Instant,
};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::{
        ACL,
        Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
            SE_FILE_OBJECT, SetSecurityInfo,
        },
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
        GetSecurityDescriptorLength, PROTECTED_DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED,
    },
};

/// The strict comparison remains primary; diagnostics never substitute a policy.
#[derive(Debug)]
pub struct ReadbackFailure {
    pub primary: io::Error,
    pub diagnostic: serde_json::Value,
}
impl std::fmt::Display for ReadbackFailure {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            output,
            "{}; owned-input-readback={}",
            self.primary, self.diagnostic
        )
    }
}
impl std::error::Error for ReadbackFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}

fn mismatch_diagnostic(
    context: &Context,
    expected: &[u8],
    observed: &[u8],
    control: u16,
    revision: u32,
    work: Instant,
) -> serde_json::Value {
    let mut value = if Instant::now() < work {
        readback_diagnostic(context, expected, observed, control, revision)
    } else {
        serde_json::json!({"format":"memcordon.private-input-dacl-readback","revision":1,"context":context,"diagnostic_state":"unavailable-original-cutoff","protection_missing":control & SE_DACL_PROTECTED == 0,"raw_acl_equal":expected==observed,"acceptance_authority":false})
    };
    value["failure_branch"] = serde_json::json!(if control & SE_DACL_PROTECTED == 0 {
        "protected-bit-missing"
    } else {
        "raw-acl-byte-mismatch"
    });
    value["failure_domain"] = serde_json::json!("semantic-readback-comparison");
    value["set_security_info_status"] = serde_json::json!(0);
    value["get_security_info_status"] = serde_json::json!(0);
    value["get_descriptor_control_succeeded"] = serde_json::json!(true);
    value["expected_protected_requested"] = serde_json::json!(true);
    value["expected_native_control_queried"] = serde_json::json!(false);
    value["original_loader_cause_proved"] = serde_json::json!(false);
    value["completed_before_original_cutoff"] = serde_json::json!(Instant::now() < work);
    if serde_json::to_vec(&value).map_or(true, |bytes| {
        bytes.len() > crate::windows_private_input_record::RECORD_BYTES
    }) {
        value["expected"]["aces"] = serde_json::json!([]);
        value["observed"]["aces"] = serde_json::json!([]);
        value["ace_details_omitted_for_record_bound"] = serde_json::json!(true);
    }
    value
}
struct Descriptor(*mut std::ffi::c_void);
impl Drop for Descriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}
fn live(work: Instant) -> io::Result<()> {
    if Instant::now() >= work {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "owned input original work cutoff expired",
        ))
    } else {
        Ok(())
    }
}
fn acl_bytes(sd: *mut std::ffi::c_void, acl: *mut ACL) -> io::Result<Vec<u8>> {
    if sd.is_null() || acl.is_null() {
        return Err(io::Error::other("owned input DACL is absent"));
    }
    let length = unsafe { GetSecurityDescriptorLength(sd) } as usize;
    let start = sd as usize;
    let end = start
        .checked_add(length)
        .ok_or_else(|| io::Error::other("owned SD extent overflow"))?;
    let pointer = acl as usize;
    if length > 64 * 1024
        || pointer < start
        || pointer
            .checked_add(std::mem::size_of::<ACL>())
            .is_none_or(|value| value > end)
    {
        return Err(io::Error::other("owned DACL pointer extent invalid"));
    }
    let size = unsafe { (*acl).AclSize } as usize;
    if size < std::mem::size_of::<ACL>()
        || pointer.checked_add(size).is_none_or(|value| value > end)
    {
        return Err(io::Error::other("owned DACL byte extent invalid"));
    }
    Ok(unsafe { std::slice::from_raw_parts(acl.cast::<u8>(), size) }.to_vec())
}
/// The caller owns this newly created input and retains its no-reparse ancestry
/// and native identity. This API changes only this borrowed file object; it
/// cannot adopt a scalar handle, open a pathname or change a token/host policy.
pub fn seal_read_execute(
    file: &File,
    directory: bool,
    sid: &str,
    work: Instant,
    context: &Context,
) -> io::Result<serde_json::Value> {
    live(work)?;
    let metadata = file.metadata()?;
    if metadata.is_dir() != directory || metadata.file_attributes() & 0x400 != 0 {
        return Err(io::Error::other(
            "owned input type or reparse state differs",
        ));
    }
    if context.directory != directory {
        return Err(io::Error::other("owned input diagnostic type differs"));
    }
    let sddl = expected_sddl(directory, sid).map_err(io::Error::other)?;
    let wide = sddl.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let mut raw = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            SDDL_REVISION_1,
            &mut raw,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let expected = Descriptor(raw);
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl = std::ptr::null_mut();
    if unsafe { GetSecurityDescriptorDacl(expected.0, &mut present, &mut acl, &mut defaulted) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if present == 0 || acl.is_null() {
        return Err(io::Error::other("owned expected DACL absent"));
    }
    let expected_bytes = acl_bytes(expected.0, acl)?;
    live(work)?;
    let status = unsafe {
        SetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            acl,
            std::ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    live(work)?;
    let mut observed_acl = std::ptr::null_mut();
    let mut observed_sd = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut observed_acl,
            std::ptr::null_mut(),
            &mut observed_sd,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let observed = Descriptor(observed_sd);
    let observed_bytes = acl_bytes(observed.0, observed_acl)?;
    let mut control = 0;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(observed.0, &mut control, &mut revision) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if control & SE_DACL_PROTECTED == 0 || expected_bytes != observed_bytes {
        let primary = io::Error::other(if control & SE_DACL_PROTECTED == 0 {
            "owned protected DACL readback differs: protection bit missing"
        } else {
            "owned protected DACL readback differs: raw ACL bytes differ"
        });
        let diagnostic = mismatch_diagnostic(
            context,
            &expected_bytes,
            &observed_bytes,
            control,
            revision,
            work,
        );
        return Err(io::Error::new(
            primary.kind(),
            ReadbackFailure {
                primary,
                diagnostic,
            },
        ));
    }
    live(work)?;
    let hash = Sha256::digest(&observed_bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(
        serde_json::json!({"dacl_sha256":hash,"dacl_bytes":observed_bytes.len(),"protected":true,"control":control,"readback_equal":true}),
    )
}
