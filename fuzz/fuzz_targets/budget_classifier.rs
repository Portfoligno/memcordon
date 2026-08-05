#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    #[cfg(unix)]
    let token = {
        use std::os::unix::ffi::OsStringExt;
        std::ffi::OsString::from_vec(data.to_vec())
    };
    #[cfg(not(unix))]
    let token = std::ffi::OsString::from(String::from_utf8_lossy(data).into_owned());
    let parsed = memcordon::invocation::parse_budget(token.clone());
    if token.to_str().is_none_or(|text| !text.is_ascii()) {
        assert!(parsed.is_err());
    }
});
