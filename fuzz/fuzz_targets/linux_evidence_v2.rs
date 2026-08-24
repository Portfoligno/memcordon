#![no_main]

use libfuzzer_sys::fuzz_target;
use memcordon_core::BoundaryMechanismEvidence;

fuzz_target!(|data: &[u8]| {
    if let Ok(evidence) = serde_json::from_slice::<BoundaryMechanismEvidence>(data) {
        let encoded =
            serde_json::to_vec(&evidence).expect("accepted Linux evidence is serializable");
        let _: BoundaryMechanismEvidence =
            serde_json::from_slice(&encoded).expect("serialized Linux evidence is accepted");
    }
});
