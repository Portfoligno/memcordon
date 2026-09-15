#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = std::str::from_utf8(data) {
        if memcordon_core::validate_windows_security_descriptor_text(value).is_ok() {
            assert!(!value.contains('\0'));
            assert!(value.contains("D:"));
            assert!(value.contains('('));
            let mut poisoned = value.to_owned();
            poisoned.push('\0');
            assert!(memcordon_core::validate_windows_security_descriptor_text(&poisoned).is_err());
        }
    }
});
