//! Decode Win32 SDDL output by its terminator, never by allocation capacity.

pub const MAX_CAPACITY: usize = 16 * 1024;

/// The reader is called only for indices preceding or including the first NUL.
pub fn decode(
    readable_units: usize,
    mut read_unit: impl FnMut(usize) -> u16,
) -> Result<String, String> {
    if readable_units == 0 {
        return Err("event descriptor text has no verified readable WCHARs".into());
    }
    let mut text = Vec::new();
    for index in 0..readable_units.min(MAX_CAPACITY) {
        let unit = read_unit(index);
        if unit == 0 {
            if text.is_empty() {
                return Err("event descriptor text is empty".into());
            }
            return String::from_utf16(&text).map_err(|error| error.to_string());
        }
        text.push(unit);
    }
    Err("event descriptor text lacks a bounded terminator".into())
}

#[cfg(windows)]
pub use native::from_descriptor;

#[cfg(windows)]
#[allow(unsafe_code)] // Exact Win32 allocation ownership and bounded initialized text reads.
mod native {
    use std::ffi::c_void;
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW,
        System::Memory::LocalSize,
    };

    struct LocalText(*mut u16);
    impl Drop for LocalText {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the conversion API transfers this LocalAlloc buffer.
                unsafe { LocalFree(self.0.cast()) };
            }
        }
    }

    /// Convert the selected components without changing descriptor authority.
    ///
    /// # Safety
    /// `descriptor` must address a valid native security descriptor which stays
    /// readable for the duration of the conversion.
    pub unsafe fn from_descriptor(
        descriptor: *mut c_void,
        information: u32,
    ) -> Result<(String, u32, usize), String> {
        if descriptor.is_null() {
            return Err("native event descriptor pointer is null".into());
        }
        let mut text = std::ptr::null_mut();
        let mut capacity = 0;
        // SAFETY: caller guarantees the descriptor, and both output scalars are writable.
        let converted = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                1,
                information,
                &mut text,
                &mut capacity,
            )
        };
        let failure = (converted == 0).then(std::io::Error::last_os_error);
        let text = LocalText(text);
        if let Some(error) = failure {
            return Err(format!(
                "ConvertSecurityDescriptorToStringSecurityDescriptorW: {error}"
            ));
        }
        if text.0.is_null() {
            return Err(format!(
                "native event descriptor conversion returned null text; reported_wchars={capacity}"
            ));
        }
        // SAFETY: this is the exact fixed LocalAlloc buffer returned by the
        // conversion API, still owned by LocalText. LocalSize returns bytes.
        let allocation_bytes = unsafe { LocalSize(text.0.cast()) };
        if allocation_bytes == 0 {
            let error = std::io::Error::last_os_error();
            return Err(format!(
                "LocalSize: {error}; reported_wchars={capacity}; allocation_bytes=0; scan_limit={}",
                super::MAX_CAPACITY
            ));
        }
        // The optional conversion count is advisory evidence; only LocalSize
        // establishes the readable range, and the terminator establishes text.
        let readable_units = allocation_bytes / size_of::<u16>();
        let decoded = super::decode(readable_units, |index| {
            // SAFETY: reads are within independently verified allocation bytes
            // and the finite scan cap, stopping at the first initialized NUL.
            // No allocation padding is read after the terminator.
            unsafe { text.0.add(index).read() }
        })
        .map_err(|error| format!("{error}; reported_wchars={capacity}; allocation_bytes={allocation_bytes}; scan_limit={}", super::MAX_CAPACITY))?;
        Ok((decoded, capacity, allocation_bytes))
    }
}
