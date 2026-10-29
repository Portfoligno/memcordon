#![no_main]
use libfuzzer_sys::fuzz_target;
use memcordon_core::result_v3::{ReleaseKnowledgeV3,ResultV3};

fuzz_target!(|data: &[u8]| {
    if let Ok(result)=ResultV3::parse(data) {
        assert!(result.validate().is_ok());
        assert!(ResultV3::parse(&serde_json::to_vec(&result).unwrap()).is_ok());
        let mut unsupported=result.clone();unsupported.revision=0;
        assert!(unsupported.validate().is_err());
        if result.outcome.native_termination.is_some() {
            let mut unreleased=result;unreleased.release=ReleaseKnowledgeV3::NotReleased;
            assert!(unreleased.validate().is_err());
        }
    }
});
