#![no_main]

use libfuzzer_sys::fuzz_target;
use memcordon_core::{WindowsLauncherRequestV1, WindowsLauncherResponseV1};

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<WindowsLauncherRequestV1>(data);
    let _ = serde_json::from_slice::<WindowsLauncherResponseV1>(data);
});
