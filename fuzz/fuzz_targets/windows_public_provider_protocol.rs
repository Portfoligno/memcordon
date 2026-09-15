#![no_main]

use libfuzzer_sys::fuzz_target;
use memcordon_core::{WindowsProviderRequestV1, WindowsProviderResponseV1};

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = serde_json::from_slice::<WindowsProviderRequestV1>(data) {
        let encoded = serde_json::to_vec(&value).unwrap();
        let decoded: WindowsProviderRequestV1 = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(
            serde_json::to_value(&value).unwrap(),
            serde_json::to_value(&decoded).unwrap()
        );
    }
    if let Ok(value) = serde_json::from_slice::<WindowsProviderResponseV1>(data) {
        let encoded = serde_json::to_vec(&value).unwrap();
        let decoded: WindowsProviderResponseV1 = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(
            serde_json::to_value(&value).unwrap(),
            serde_json::to_value(&decoded).unwrap()
        );
    }
});
