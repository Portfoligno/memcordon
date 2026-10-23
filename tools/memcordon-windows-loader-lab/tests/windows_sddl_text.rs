#![cfg(windows)]

#[path = "../../memcordon-ci/src/windows_sddl_text.rs"]
mod text;

use std::{ffi::c_void, ptr};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_ALREADY_EXISTS, ERROR_INSUFFICIENT_BUFFER, GetLastError, HANDLE,
        LocalFree,
    },
    Security::{
        Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
        Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom},
        GetKernelObjectSecurity, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
        GetSecurityDescriptorGroup, GetSecurityDescriptorLength, GetSecurityDescriptorOwner,
        IsValidSecurityDescriptor, SE_SELF_RELATIVE, SECURITY_ATTRIBUTES,
    },
    System::Threading::CreateEventW,
};

struct Event(HANDLE);
impl Drop for Event {
    fn drop(&mut self) {
        assert_ne!(unsafe { CloseHandle(self.0) }, 0);
    }
}
struct Descriptor(*mut c_void);
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

fn query(event: &Event) -> Vec<u64> {
    let mut needed = 0;
    assert_eq!(
        unsafe { GetKernelObjectSecurity(event.0, 0x17, ptr::null_mut(), 0, &mut needed) },
        0
    );
    assert_eq!(unsafe { GetLastError() }, ERROR_INSUFFICIENT_BUFFER);
    assert!(needed > 0 && needed <= 64 * 1024);
    let mut buffer = vec![0_u64; (needed as usize).div_ceil(size_of::<u64>())];
    let capacity = needed;
    assert_ne!(
        unsafe {
            GetKernelObjectSecurity(
                event.0,
                0x17,
                buffer.as_mut_ptr().cast(),
                capacity,
                &mut needed,
            )
        },
        0
    );
    assert!(needed <= capacity);
    let descriptor = buffer.as_mut_ptr().cast();
    assert_ne!(unsafe { IsValidSecurityDescriptor(descriptor) }, 0);
    let actual = unsafe { GetSecurityDescriptorLength(descriptor) };
    assert!(actual > 0 && actual <= capacity);
    assert!(needed == 0 || actual <= needed);
    let mut control = 0;
    let mut revision = 0;
    assert_ne!(
        unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) },
        0
    );
    assert_ne!(control & SE_SELF_RELATIVE, 0);
    buffer
}

fn components(descriptor: *mut c_void) -> (bool, bool, bool) {
    let mut owner = ptr::null_mut();
    let mut group = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let mut defaulted = 0;
    let mut present = 0;
    assert_ne!(
        unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut defaulted) },
        0
    );
    assert_ne!(
        unsafe { GetSecurityDescriptorGroup(descriptor, &mut group, &mut defaulted) },
        0
    );
    assert_ne!(
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) },
        0
    );
    (
        !owner.is_null(),
        !group.is_null(),
        present != 0 && !dacl.is_null(),
    )
}

fn named_gate() -> Event {
    let mut nonce = [0u8; 32];
    assert!(
        unsafe {
            BCryptGenRandom(
                ptr::null_mut(),
                nonce.as_mut_ptr(),
                nonce.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        } >= 0
    );
    assert!(nonce.iter().any(|byte| *byte != 0));
    let name = format!("Local\\memcordon-sddl-test-{}", hex::encode(nonce))
        .encode_utf16()
        .chain([0])
        .collect::<Vec<_>>();
    let sddl = "D:P(A;;GA;;;OW)(A;;GA;;;SY)(A;;0x00100000;;;RC)"
        .encode_utf16()
        .chain([0])
        .collect::<Vec<_>>();
    let mut descriptor = ptr::null_mut();
    assert_ne!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                ptr::null_mut(),
            )
        },
        0
    );
    let descriptor = Descriptor(descriptor);
    assert!(!descriptor.0.is_null());
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let handle = unsafe { CreateEventW(&attributes, 1, 0, name.as_ptr()) };
    let error = unsafe { GetLastError() };
    assert!(!handle.is_null(), "CreateEventW failed: {error}");
    let event = Event(handle);
    assert_ne!(
        error, ERROR_ALREADY_EXISTS,
        "test gate must be newly created"
    );
    event
}

#[test]
fn held_event_sddl_roundtrip_preserves_observed_native_policy() {
    assert!(unsafe { text::from_descriptor(ptr::null_mut(), 0x17) }.is_err());
    let event = named_gate();
    let mut original = query(&event);
    assert_eq!(components(original.as_mut_ptr().cast()), (true, true, true));
    let (captured, reported_units, allocation_bytes) =
        unsafe { text::from_descriptor(original.as_mut_ptr().cast(), 0x17) }.unwrap();
    eprintln!(
        "native SDDL reported_units={reported_units} allocation_bytes={allocation_bytes} scan_limit={}",
        text::MAX_CAPACITY
    );
    assert!(allocation_bytes >= (captured.encode_utf16().count() + 1) * size_of::<u16>());
    assert!(!captured.is_empty());
    assert!(!captured.contains('\0'));
    let encoded = captured.encode_utf16().chain([0]).collect::<Vec<_>>();
    let mut parsed = ptr::null_mut();
    let mut length = 0;
    assert_ne!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                encoded.as_ptr(),
                1,
                &mut parsed,
                &mut length,
            )
        },
        0
    );
    let parsed = Descriptor(parsed);
    assert!(!parsed.0.is_null() && length > 0);
    assert_eq!(
        unsafe { text::from_descriptor(parsed.0, 0x17) }.unwrap().0,
        captured
    );
    let mut unchanged = query(&event);
    assert_eq!(
        unsafe { text::from_descriptor(unchanged.as_mut_ptr().cast(), 0x17) }
            .unwrap()
            .0,
        captured
    );
}

#[test]
fn unnamed_event_without_policy_is_rejected_as_empty() {
    let handle = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    assert!(!handle.is_null());
    let event = Event(handle);
    let mut observed = query(&event);
    assert_eq!(
        components(observed.as_mut_ptr().cast()),
        (false, false, false)
    );
    let error = unsafe { text::from_descriptor(observed.as_mut_ptr().cast(), 0x17) }.unwrap_err();
    assert!(error.contains("event descriptor text is empty"), "{error}");
}
