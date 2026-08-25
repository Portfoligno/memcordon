#![no_main]

use libfuzzer_sys::fuzz_target;
use memcordon_core::{WindowsEnvironmentEntryV1, encode_windows_environment_block};

fuzz_target!(|data: &[u8]| {
    let Ok(entries) = serde_json::from_slice::<Vec<WindowsEnvironmentEntryV1>>(data) else {
        return;
    };
    if let Ok(block) = encode_windows_environment_block(&entries) {
        assert!(block.ends_with(&[0, 0]) || block == [0]);
    }
});
