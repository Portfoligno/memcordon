#![no_main]

use libfuzzer_sys::fuzz_target;
use memcordon_core::WindowsCallerTokenEnvelopeV1;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<WindowsCallerTokenEnvelopeV1>(data);
});
