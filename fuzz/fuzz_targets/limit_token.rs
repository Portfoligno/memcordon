#![no_main]

use std::ffi::OsString;

use libfuzzer_sys::fuzz_target;
use memcordon::invocation::LimitToken;

fuzz_target!(|data: &[u8]| {
    #[cfg(unix)]
    let token = {
        use std::os::unix::ffi::OsStringExt;
        OsString::from_vec(data.to_vec())
    };
    #[cfg(not(unix))]
    let token = OsString::from(String::from_utf8_lossy(data).into_owned());
    let _ = LimitToken::parse(token);
});
