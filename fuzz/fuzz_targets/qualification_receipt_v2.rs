#![no_main]

use libfuzzer_sys::fuzz_target;

use memcordon_core::sealed_provider::qualification;

fuzz_target!(|data: &[u8]| {
    memcordon_ci::release_evidence::fuzz_linux_qualification_receipt(data);
    #[cfg(target_os = "linux")]
    let _ = memcordon_platform::test_support::sealed_qualification_v2_is_valid(data);
    if let Ok(receipt) = serde_json::from_slice::<qualification::QualificationReceipt>(data) {
        let encoded = receipt.render();
        let roundtrip: qualification::QualificationReceipt =
            serde_json::from_str(&encoded).unwrap();
        assert_eq!(receipt.complete(), roundtrip.complete());
        assert_eq!(encoded, roundtrip.render());
        if receipt.complete() {
            let original = serde_json::to_value(&receipt).unwrap();
            for (field, value) in original.as_object().unwrap() {
                if value == &serde_json::Value::Bool(true) {
                    let mut missing_fact = original.clone();
                    missing_fact[field] = serde_json::Value::Bool(false);
                    let incomplete: qualification::QualificationReceipt =
                        serde_json::from_value(missing_fact).unwrap();
                    assert!(
                        !incomplete.complete(),
                        "mandatory qualification fact: {field}"
                    );
                }
            }
        }
    }
});
