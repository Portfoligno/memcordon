#![no_main]

use libfuzzer_sys::fuzz_target;
use memcordon_core::WindowsTerminalReceiptV3;

fuzz_target!(|data: &[u8]| {
    if data.len() <= memcordon_core::WINDOWS_MAX_FRAME_BYTES
        && memcordon_core::canonical_json::reject_duplicate_json_keys(data).is_ok()
        && let Ok(receipt) = serde_json::from_slice::<WindowsTerminalReceiptV3>(data)
        && receipt.validate_for_attempt().is_ok()
    {
        let encoded = serde_json::to_vec(&receipt).unwrap();
        let decoded: WindowsTerminalReceiptV3 = serde_json::from_slice(&encoded).unwrap();
        assert!(decoded.validate_for_attempt().is_ok());
    }
});
