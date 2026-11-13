//! Owned aligned security bytes from the exact live standard-stream handle.
use super::super::matched_control_process::live;
use super::diagnostic::{QueryFacts, QueryStage, StreamRole, descriptor};
use std::{io, time::Instant};
use windows_sys::Win32::{Foundation::HANDLE, Security::GetKernelObjectSecurity};

#[path = "matched_control_security_components.rs"]
pub mod components;
#[path = "matched_control_security_components_native.rs"]
mod components_native;

pub struct OwnedDescriptor {
    words: Vec<u32>,
    extent: usize,
}
impl OwnedDescriptor {
    pub fn as_ptr(&self) -> *mut std::ffi::c_void {
        self.words.as_ptr().cast_mut().cast()
    }
    pub fn bytes(&self) -> Vec<u8> {
        descriptor::bytes_for_extent(&self.words, self.extent)
            .expect("owned native descriptor extent remains in its allocation")
    }
    pub fn component_diagnostic(&self, cutoff: Instant) -> components::Components {
        components_native::capture(self, cutoff)
    }
}

pub fn capture(handle: HANDLE, role: StreamRole, cutoff: Instant) -> io::Result<OwnedDescriptor> {
    let mut required = 0;
    live(cutoff)?;
    let first =
        unsafe { GetKernelObjectSecurity(handle, 23, std::ptr::null_mut(), 0, &mut required) };
    let error = if first == 0 {
        Some(io::Error::last_os_error())
    } else {
        None
    };
    let mut facts = QueryFacts {
        role,
        first_result: first,
        first_required: required,
        first_native_error: error.as_ref().and_then(io::Error::raw_os_error),
        supplied_capacity: None,
        physical_capacity: None,
        second_result: None,
        second_required_observed: None,
        second_native_error: None,
        descriptor: None,
    };
    if error.as_ref().and_then(io::Error::raw_os_error) != Some(122)
        || required == 0
        || required > 8192
    {
        return Err(facts.error(QueryStage::Sizing, error));
    }
    let mut words = vec![0u32; (required as usize).div_ceil(std::mem::size_of::<u32>())];
    let capacity = required;
    facts.supplied_capacity = Some(capacity);
    facts.physical_capacity = Some(std::mem::size_of_val(words.as_slice()));
    live(cutoff)?;
    let copied = unsafe {
        GetKernelObjectSecurity(
            handle,
            23,
            words.as_mut_ptr().cast(),
            capacity,
            &mut required,
        )
    };
    let error = if copied == 0 {
        Some(io::Error::last_os_error())
    } else {
        None
    };
    facts.second_result = Some(copied);
    facts.second_required_observed = Some(required);
    facts.second_native_error = error.as_ref().and_then(io::Error::raw_os_error);
    if copied == 0 {
        return Err(facts.error(QueryStage::Copy, error));
    }
    // An oversized returned requirement means the API copied no descriptor.
    if required > capacity {
        return Err(facts.error(QueryStage::ReturnedExtent, None));
    }
    let extent = if required == 0 {
        let pointer = words.as_mut_ptr().cast();
        match descriptor::validate_zero(
            &words,
            capacity,
            || live(cutoff).is_ok(),
            |bound| relative_descriptor_structure(pointer, bound, cutoff),
            // SAFETY: the length-aware structural validator first proves all
            // readable relative component ranges in this exact owned buffer.
            || unsafe { windows_sys::Win32::Security::IsValidSecurityDescriptor(pointer) },
            // SAFETY: the preceding native validators both succeeded.
            || unsafe { windows_sys::Win32::Security::GetSecurityDescriptorLength(pointer) },
        ) {
            Ok(extent) => extent.byte_len(),
            Err(observed) => {
                facts.descriptor = Some(observed);
                return Err(facts.error(QueryStage::ReturnedExtent, None));
            }
        }
    } else {
        // Preserve the existing successful positive reported-extent contract.
        required as usize
    };
    live(cutoff)?;
    Ok(OwnedDescriptor { words, extent })
}

fn relative_descriptor_structure(
    descriptor: *mut std::ffi::c_void,
    supplied: u32,
    cutoff: Instant,
) -> descriptor::RelativeResult {
    use descriptor::RelativeResult;
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
    if live(cutoff).is_err() {
        return RelativeResult::Cutoff;
    }
    let module_name: Vec<u16> = "ntdll.dll".encode_utf16().chain(Some(0)).collect();
    // SAFETY: lookup borrows only the process's already-loaded native module.
    let module = unsafe { GetModuleHandleW(module_name.as_ptr()) };
    if module.is_null() {
        return RelativeResult::Unavailable;
    }
    if live(cutoff).is_err() {
        return RelativeResult::Cutoff;
    }
    // Optional BOOLEAN/ULONG ABI also used by Google Project Zero's NtCoreLib.
    // No DLL is loaded, borrowed module freed, or alternative export attempted.
    let Some(address) = (unsafe {
        GetProcAddress(
            module,
            c"RtlValidRelativeSecurityDescriptor".as_ptr().cast(),
        )
    }) else {
        return RelativeResult::Unavailable;
    };
    type Validate = unsafe extern "system" fn(*mut std::ffi::c_void, u32, u32) -> u8;
    // SAFETY: the exact export uses this documented native BOOLEAN/ULONG ABI.
    let validate: Validate = unsafe { std::mem::transmute(address) };
    if live(cutoff).is_err() {
        return RelativeResult::Cutoff;
    }
    // SAFETY: initialized aligned words cover supplied bytes. Zero required
    // information validates structure only, never selected component policy.
    RelativeResult::Returned(unsafe { validate(descriptor, supplied, 0) })
}
