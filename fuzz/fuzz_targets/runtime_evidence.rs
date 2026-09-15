#![no_main]

use libfuzzer_sys::fuzz_target;
use memcordon_core::runtime_evidence::{ReleaseEvidence, RuntimeEvidenceV1};

fuzz_target!(|data: &[u8]| {
    if let Ok(evidence) = serde_json::from_slice::<RuntimeEvidenceV1>(data) {
        assert!(evidence.is_consistent());
        let encoded = serde_json::to_vec(&evidence).unwrap();
        let decoded: RuntimeEvidenceV1 = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, evidence);
        let mut unknown = serde_json::to_value(&evidence).unwrap();
        unknown["unknown-authority"] = serde_json::json!(true);
        assert!(serde_json::from_value::<RuntimeEvidenceV1>(unknown).is_err());
        if evidence.retirement.is_complete() {
            let mut altered = evidence.clone();
            altered.release = ReleaseEvidence::Unknown;
            assert!(!altered.is_consistent());
            let mut incomplete = serde_json::to_value(&evidence).unwrap();
            incomplete["retirement"]["native_obligations_settled"] = serde_json::json!(false);
            assert!(serde_json::from_value::<RuntimeEvidenceV1>(incomplete).is_err());
        }
        if let ReleaseEvidence::Issued { exec_confirmed, .. } = evidence.release {
            let mut altered = evidence.clone();
            altered.release = ReleaseEvidence::Issued {
                at: evidence.startup_expires,
                exec_confirmed,
            };
            assert!(!altered.is_consistent());
        }
    }
});
