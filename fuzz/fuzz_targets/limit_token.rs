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
    let seed_record = token
        .to_str()
        .and_then(|text| text.strip_suffix('\n'))
        .map(OsString::from);
    for token in std::iter::once(token).chain(seed_record) {
        if let Ok(parsed) = LimitToken::parse(token.clone()) {
            assert_eq!(parsed.raw, token);
            assert_eq!(
                LimitToken::parse(parsed.bytes.to_string().into())
                    .unwrap()
                    .bytes,
                parsed.bytes
            );
        }
    }
});
