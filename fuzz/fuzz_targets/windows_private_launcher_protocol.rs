#![no_main]

use libfuzzer_sys::fuzz_target;
use memcordon_core::{WindowsLauncherRequestV1, WindowsLauncherResponseV1};

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = serde_json::from_slice::<WindowsLauncherRequestV1>(data) {
        let encoded = serde_json::to_vec(&value).unwrap();
        let decoded: WindowsLauncherRequestV1 = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(
            serde_json::to_value(&value).unwrap(),
            serde_json::to_value(&decoded).unwrap()
        );
    }
    if let Ok(value) = serde_json::from_slice::<WindowsLauncherResponseV1>(data) {
        let encoded = serde_json::to_vec(&value).unwrap();
        let decoded: WindowsLauncherResponseV1 = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(
            serde_json::to_value(&value).unwrap(),
            serde_json::to_value(&decoded).unwrap()
        );
    }
});
