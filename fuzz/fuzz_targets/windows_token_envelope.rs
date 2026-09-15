#![no_main]

use libfuzzer_sys::fuzz_target;
use memcordon_core::WindowsCallerTokenEnvelopeV1;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = serde_json::from_slice::<WindowsCallerTokenEnvelopeV1>(data) {
        let encoded = serde_json::to_vec(&value).unwrap();
        let decoded: WindowsCallerTokenEnvelopeV1 = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(
            serde_json::to_value(&value).unwrap(),
            serde_json::to_value(&decoded).unwrap()
        );
    }
});
