#![no_main]

use libfuzzer_sys::fuzz_target;
use memcordon_core::{WindowsProviderRequestV4, WindowsProviderResponseV4};

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<WindowsProviderRequestV4>(data);
    let _ = serde_json::from_slice::<WindowsProviderResponseV4>(data);
});
