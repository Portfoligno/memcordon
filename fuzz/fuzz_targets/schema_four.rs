#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(report) = serde_json::from_slice::<memcordon_core::MemcordonReport>(data) {
        assert_eq!(
            report.schema_version,
            memcordon_core::EXECUTION_REPORT_SCHEMA_VERSION
        );
        let encoded = serde_json::to_vec(&report).expect("validated report serializes");
        let _: memcordon_core::MemcordonReport =
            serde_json::from_slice(&encoded).expect("validated report round trips");
    }
});
