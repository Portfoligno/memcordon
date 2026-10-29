#![no_main]

use libfuzzer_sys::fuzz_target;
use memcordon_core::{WindowsLauncherRequestV4, WindowsLauncherResponseV4};

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<WindowsLauncherRequestV4>(data);
    let _ = serde_json::from_slice::<WindowsLauncherResponseV4>(data);
});
