#![no_main]

use libfuzzer_sys::fuzz_target;
use memcordon_core::WindowsQualificationReceiptV1;

fuzz_target!(|data: &[u8]| {
    if let Ok(receipt) = serde_json::from_slice::<WindowsQualificationReceiptV1>(data) {
        let encoded = serde_json::to_vec(&receipt).unwrap();
        let decoded: WindowsQualificationReceiptV1 = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.is_consistent(), receipt.is_consistent());
        assert_eq!(
            serde_json::to_value(&decoded).unwrap(),
            serde_json::to_value(&receipt).unwrap()
        );
    }
});
