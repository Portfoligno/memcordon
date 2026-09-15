#![no_main]

use libfuzzer_sys::fuzz_target;

use memcordon_core::sealed_provider::inspection as inspection_schema;

fn check<T: serde::de::DeserializeOwned + serde::Serialize>(data: &[u8]) {
    if let Ok(decoded) = serde_json::from_slice::<T>(data) {
        let encoded = serde_json::to_vec(&decoded).expect("decoded inspection serializes");
        let roundtrip: T = serde_json::from_slice(&encoded).expect("canonical inspection decodes");
        assert_eq!(
            serde_json::to_value(&decoded).unwrap(),
            serde_json::to_value(&roundtrip).unwrap()
        );
        let mut extra = serde_json::to_value(&decoded).unwrap();
        extra
            .as_object_mut()
            .unwrap()
            .insert("unreviewed_authority".into(), true.into());
        assert!(serde_json::from_value::<T>(extra).is_err());
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES {
        return;
    }
    check::<inspection_schema::InstalledProviderInspectionV3>(data);
    check::<inspection_schema::InstalledProviderInspectionV4>(data);
});
