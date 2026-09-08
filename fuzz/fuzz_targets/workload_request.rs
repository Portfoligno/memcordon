#![no_main]
use libfuzzer_sys::fuzz_target;
use memcordon_core::workload_codec::{decode_contract, encode_contract};
use memcordon_core::workload_contract::WorkloadContractV1;

fuzz_target!(|data: &[u8]| {
    if let Ok(request) = WorkloadContractV1::parse(data) {
        assert!(request.validate().is_ok());
        let canonical = encode_contract(&request).unwrap();
        let decoded = decode_contract(&canonical).unwrap();
        assert_eq!(encode_contract(&decoded).unwrap(), canonical);
        let json = serde_json::to_vec_pretty(&request).unwrap();
        if json.len() <= memcordon_core::workload_limits::CONTRACT_BYTES {
            assert_eq!(WorkloadContractV1::parse(&json).unwrap(), request);
        }
    }
});
