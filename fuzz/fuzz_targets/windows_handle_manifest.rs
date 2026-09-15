#![no_main]

use libfuzzer_sys::fuzz_target;
use memcordon_core::{WindowsRemoteStreamV1, validate_windows_stream_manifest};

fuzz_target!(|data: &[u8]| {
    if let Ok(streams) = serde_json::from_slice::<Vec<WindowsRemoteStreamV1>>(data) {
        let encoded = serde_json::to_vec(&streams).unwrap();
        let decoded: Vec<WindowsRemoteStreamV1> = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(
            validate_windows_stream_manifest(&decoded),
            validate_windows_stream_manifest(&streams)
        );
        if validate_windows_stream_manifest(&streams).is_ok() {
            let mut duplicate = streams.clone();
            duplicate[1] = duplicate[0].clone();
            assert!(validate_windows_stream_manifest(&duplicate).is_err());
        }
    }
});
