#![no_main]

use std::ffi::OsString;

use libfuzzer_sys::fuzz_target;
use memcordon_core::NativeArgument;

fuzz_target!(|data: &[u8]| {
    #[cfg(unix)]
    let value = {
        use std::os::unix::ffi::OsStringExt;
        OsString::from_vec(data.to_vec())
    };
    #[cfg(not(unix))]
    let value = OsString::from(String::from_utf8_lossy(data).into_owned());
    let encoded = NativeArgument::from_os(&value);
    let bytes = serde_json::to_vec(&encoded).expect("native argument should serialize");
    let decoded: NativeArgument =
        serde_json::from_slice(&bytes).expect("native argument should deserialize");
    assert_eq!(decoded, encoded);
});
