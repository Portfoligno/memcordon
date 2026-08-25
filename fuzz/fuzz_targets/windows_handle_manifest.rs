#![no_main]

use libfuzzer_sys::fuzz_target;
use memcordon_core::{WindowsRemoteStreamV1, validate_windows_stream_manifest};

fuzz_target!(|data: &[u8]| {
    if let Ok(streams) = serde_json::from_slice::<Vec<WindowsRemoteStreamV1>>(data) {
        let _ = validate_windows_stream_manifest(&streams);
    }
});
