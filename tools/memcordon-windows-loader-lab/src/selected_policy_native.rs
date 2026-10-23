//! Native bounded readback shared by the real holder and native fixtures.
use crate::selected_policy::{self, Snapshot};
use memcordon_windows_launch_core::NativeSecurityDescriptorV1;
use std::{ffi::c_void, ptr};
use windows_sys::Win32::{Foundation::*, Security::*};

fn failure(api: &str, code: u32) -> String {
    format!("{api}: native_code={code}")
}

/// Capture a descriptor owned and validated by launch-core.
pub fn expected(policy: &NativeSecurityDescriptorV1, selection: u32) -> Result<Snapshot, String> {
    let attributes = policy
        .security_attributes()
        .map_err(|e| format!("expected descriptor: {e:?}"))?;
    let raw = attributes.lpSecurityDescriptor;
    if raw.is_null() || unsafe { IsValidSecurityDescriptor(raw) } == 0 {
        return Err("expected descriptor invalid".into());
    }
    let length = unsafe { GetSecurityDescriptorLength(raw) } as usize;
    if !(20..=64 * 1024).contains(&length) {
        return Err("expected descriptor extent outside bound".into());
    }
    let bytes = unsafe { std::slice::from_raw_parts(raw.cast::<u8>(), length) };
    if selection == 7 {
        // This gate contract intentionally selects no label. An explicitly
        // labelled source requires a separate supported contract.
        let full = selected_policy::capture(bytes)?;
        let control = u16::from_le_bytes([bytes[2], bytes[3]]);
        let sacl_offset = u32::from_le_bytes(
            bytes[12..16]
                .try_into()
                .expect("validated descriptor header"),
        );
        if control & (0x10 | 0x20 | 0x200 | 0x800 | 0x2000) != 0 || sacl_offset != 0 {
            return Err(format!(
                "gate source explicitly selects SACL: {}",
                selected_policy::describe(&full)
            ));
        }
    }
    selected_policy::capture_selected(bytes, selection)
}

fn read(handle: HANDLE, selection: u32, kernel: bool) -> Result<Snapshot, String> {
    if (kernel && selection != 7) || (!kernel && selection != 0x17) {
        return Err("native object policy selection differs".into());
    }
    let query = |raw: *mut c_void, capacity: u32, needed: &mut u32| unsafe {
        if kernel {
            GetKernelObjectSecurity(handle, selection, raw, capacity, needed)
        } else {
            GetUserObjectSecurity(handle, &selection, raw, capacity, needed)
        }
    };
    let mut needed = 0;
    let sized = query(ptr::null_mut(), 0, &mut needed);
    let status = unsafe { GetLastError() };
    if sized != 0 || status != ERROR_INSUFFICIENT_BUFFER || !(20..=64 * 1024).contains(&needed) {
        return Err(format!(
            "native policy sizing selection={selection:#x} returned={needed}: {}",
            failure("security query", status)
        ));
    }
    let capacity = needed;
    let mut words = vec![0_u32; (capacity as usize).div_ceil(size_of::<u32>())];
    let raw: *mut c_void = words.as_mut_ptr().cast();
    if query(raw, capacity, &mut needed) == 0 {
        let code = unsafe { GetLastError() };
        return Err(failure("native policy readback", code));
    }
    if needed > capacity || (!kernel && needed == 0) {
        return Err(format!(
            "native policy returned extent differs: selection={selection:#x} returned={needed} allocated={capacity}"
        ));
    }
    // Windows may leave the auxiliary size zero after successful kernel
    // queries. The owned initialized capacity is the first parse bound; the
    // validated native descriptor's positive actual length is authoritative.
    let initialized = if needed == 0 { capacity } else { needed } as usize;
    let bytes = unsafe { std::slice::from_raw_parts(raw.cast::<u8>(), initialized) };
    // Bound every selected component before native pointer-walking APIs.
    selected_policy::capture_selected(bytes, selection)?;
    if unsafe { IsValidSecurityDescriptor(raw) } == 0 {
        return Err("native policy descriptor invalid".into());
    }
    let actual = unsafe { GetSecurityDescriptorLength(raw) } as usize;
    if !(20..=initialized).contains(&actual) {
        return Err(format!(
            "native policy actual extent differs: selection={selection:#x} actual={actual} returned={needed} allocated={capacity}"
        ));
    }
    selected_policy::capture_selected(&bytes[..actual], selection)
}

/// Read the selected USER object policy from a live retained object handle.
/// # Safety
/// The caller must retain the valid USER object handle throughout this call.
pub unsafe fn read_user(handle: HANDLE) -> Result<Snapshot, String> {
    read(handle, 0x17, false)
}

/// Read owner/group/DACL from the live retained gate, without selecting LABEL.
/// # Safety
/// The caller must retain the valid kernel object handle throughout this call.
pub unsafe fn read_gate(handle: HANDLE) -> Result<Snapshot, String> {
    read(handle, 7, true)
}
