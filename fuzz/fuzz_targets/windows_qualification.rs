#![no_main]

use libfuzzer_sys::fuzz_target;
use memcordon_core::WindowsQualificationReceiptV1;

fuzz_target!(|data: &[u8]| {
    if let Ok(receipt) = serde_json::from_slice::<WindowsQualificationReceiptV1>(data) {
        let _ = receipt.is_consistent();
    }
});
