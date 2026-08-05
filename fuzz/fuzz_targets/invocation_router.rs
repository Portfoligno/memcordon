#![no_main]

use std::ffi::OsString;

use libfuzzer_sys::fuzz_target;
use memcordon::invocation::route;

fuzz_target!(|data: &[u8]| {
    let arguments: Vec<OsString> = data
        .split(|byte| *byte == 0)
        .map(|field| {
            #[cfg(unix)]
            {
                use std::os::unix::ffi::OsStringExt;
                OsString::from_vec(field.to_vec())
            }
            #[cfg(not(unix))]
            {
                OsString::from(String::from_utf8_lossy(field).into_owned())
            }
        })
        .collect();
    let _ = route(&arguments);
});
