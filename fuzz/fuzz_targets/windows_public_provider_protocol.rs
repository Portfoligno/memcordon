#![no_main]

use libfuzzer_sys::fuzz_target;
use memcordon_core::{WindowsProviderRequestV1, WindowsProviderResponseV1};

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<WindowsProviderRequestV1>(data);
    let _ = serde_json::from_slice::<WindowsProviderResponseV1>(data);
});
