//! Passive snapshots of the current native gate; no diagnostic replay is run.
#[path = "windows_sddl_text.rs"]
mod sddl_text;
use crate::{CiError, Result};
use std::{
    os::windows::io::{AsRawHandle, OwnedHandle},
    time::{Duration, Instant},
};

#[allow(unsafe_code)] // Query only the original held event; no name reopen or mutation.
pub(super) fn gate_sddl(gate: &OwnedHandle) -> Result<String> {
    use windows_sys::Win32::{
        Foundation::{ERROR_INSUFFICIENT_BUFFER, GetLastError},
        Security::{
            GetKernelObjectSecurity, GetSecurityDescriptorControl, GetSecurityDescriptorLength,
            IsValidSecurityDescriptor, SE_SELF_RELATIVE,
        },
    };
    let mut needed = 0;
    let success = unsafe {
        GetKernelObjectSecurity(
            gate.as_raw_handle(),
            0x17,
            std::ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    let error = unsafe { GetLastError() };
    if success != 0 || error != ERROR_INSUFFICIENT_BUFFER || needed == 0 || needed > 64 * 1024 {
        return Err(CiError::Message(format!(
            "original event descriptor sizing failed: status={error} length={needed}"
        )));
    }
    let capacity = needed;
    let mut buffer = vec![0_u64; (capacity as usize).div_ceil(size_of::<u64>())];
    let pointer = buffer.as_mut_ptr().cast();
    if unsafe {
        GetKernelObjectSecurity(gate.as_raw_handle(), 0x17, pointer, capacity, &mut needed)
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    if needed > capacity || unsafe { IsValidSecurityDescriptor(pointer) } == 0 {
        return Err(CiError::Message(
            "original event descriptor invalid or outside allocation".into(),
        ));
    }
    let actual = unsafe { GetSecurityDescriptorLength(pointer) };
    let mut control = 0;
    let mut revision = 0;
    if actual == 0
        || actual > capacity
        || (needed != 0 && actual > needed)
        || unsafe { GetSecurityDescriptorControl(pointer, &mut control, &mut revision) } == 0
        || control & SE_SELF_RELATIVE == 0
    {
        return Err(CiError::Message(
            "original event descriptor actual length differs".into(),
        ));
    }
    // SAFETY: the owned, validated self-relative descriptor remains live here.
    unsafe { sddl_text::from_descriptor(pointer, 0x17) }
        .map(|(text, _, _)| text)
        .map_err(CiError::Message)
}

pub(super) fn gate_security_snapshot(
    gate: &OwnedHandle,
    deadline: Instant,
) -> std::io::Result<super::gate_security::Snapshot> {
    let snapshot =
        super::gate_security::parse(&gate_descriptor_bytes(gate, deadline, 0x0000_0007)?)?;
    gate_snapshot_live(deadline)?;
    Ok(snapshot)
}

pub(super) fn gate_mandatory_label_snapshot(
    gate: &OwnedHandle,
    deadline: Instant,
) -> std::io::Result<super::gate_label::Snapshot> {
    // LABEL_SECURITY_INFORMATION alone requires the owner's existing READ_CONTROL.
    let snapshot = super::gate_label::parse(&gate_descriptor_bytes(gate, deadline, 0x0000_0010)?)?;
    gate_snapshot_live(deadline)?;
    Ok(snapshot)
}

fn gate_snapshot_live(deadline: Instant) -> std::io::Result<()> {
    if Instant::now() >= deadline {
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "original gate snapshot cutoff elapsed",
        ))
    } else {
        Ok(())
    }
}

#[allow(unsafe_code)] // Only bounded queries on the original READ_CONTROL event owner.
fn gate_descriptor_bytes(
    gate: &OwnedHandle,
    deadline: Instant,
    information: u32,
) -> std::io::Result<Vec<u8>> {
    use windows_sys::Win32::{
        Foundation::{ERROR_INSUFFICIENT_BUFFER, GetLastError},
        Security::{
            GetKernelObjectSecurity, GetSecurityDescriptorControl, GetSecurityDescriptorLength,
            IsValidSecurityDescriptor, SE_SELF_RELATIVE,
        },
    };
    let live = || gate_snapshot_live(deadline);
    live()?;
    let mut needed = 0;
    let status = unsafe {
        GetKernelObjectSecurity(
            gate.as_raw_handle(),
            information,
            std::ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    let error = unsafe { GetLastError() };
    live()?;
    if status == 0 && error != ERROR_INSUFFICIENT_BUFFER {
        return Err(std::io::Error::from_raw_os_error(error as i32));
    }
    if status != 0
        || error != ERROR_INSUFFICIENT_BUFFER
        || needed == 0
        || needed as usize > super::gate_security::BYTE_BOUND
    {
        return Err(std::io::Error::other(
            "original gate descriptor sizing or bound differs",
        ));
    }
    let capacity = needed;
    let mut storage = vec![0_u64; (capacity as usize).div_ceil(size_of::<u64>())];
    let pointer = storage.as_mut_ptr().cast();
    live()?;
    if unsafe {
        GetKernelObjectSecurity(
            gate.as_raw_handle(),
            information,
            pointer,
            capacity,
            &mut needed,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    live()?;
    if needed == 0 || needed > capacity || unsafe { IsValidSecurityDescriptor(pointer) } == 0 {
        return Err(std::io::Error::other(
            "original gate descriptor returned extent or validity differs",
        ));
    }
    let actual = unsafe { GetSecurityDescriptorLength(pointer) };
    let mut control = 0;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(pointer, &mut control, &mut revision) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    if actual == 0 || actual > needed || actual > capacity || control & SE_SELF_RELATIVE == 0 {
        return Err(std::io::Error::other(
            "original gate descriptor self-relative extent differs",
        ));
    }
    // SAFETY: validated native descriptor length is inside the aligned owned allocation.
    let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), actual as usize) };
    let snapshot = bytes.to_vec();
    live()?;
    Ok(snapshot)
}

#[allow(unsafe_code)] // Query current process identity and its session; no token mutation.
pub(super) fn gate_controller_context(deadline: Instant) -> std::io::Result<serde_json::Value> {
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::{
        Foundation::FILETIME,
        Security::{GetTokenInformation, TOKEN_QUERY, TokenSessionId},
        System::Threading::{
            GetCurrentProcess, GetCurrentProcessId, GetProcessTimes, OpenProcessToken,
        },
    };
    let live = || {
        if Instant::now() >= deadline {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "original gate controller context cutoff elapsed",
            ))
        } else {
            Ok(())
        }
    };
    live()?;
    let process = unsafe { GetCurrentProcess() };
    let pid = unsafe { GetCurrentProcessId() };
    let mut creation = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exit = creation;
    let mut kernel = creation;
    let mut user = creation;
    if unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let birth =
        (u64::from(creation.dwHighDateTime) << u32::BITS) | u64::from(creation.dwLowDateTime);
    live()?;
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut session = 0_u32;
    let mut returned = 0;
    live()?;
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenSessionId,
            (&mut session as *mut u32).cast(),
            size_of::<u32>() as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    if returned as usize != size_of::<u32>() || pid == 0 || birth == 0 {
        return Err(std::io::Error::other(
            "original gate controller identity/session extent differs",
        ));
    }
    live()?;
    Ok(
        serde_json::json!({"pid":pid,"birth":birth.to_string(),"process_token_session":session,
        "authority":"current-process-query-only; not a fixture token observation"}),
    )
}

#[allow(unsafe_code)] // Read only the machine-wide monotonic uptime clock.
fn uptime() -> u64 {
    unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount64() }
}
