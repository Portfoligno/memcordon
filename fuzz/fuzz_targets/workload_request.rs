#![no_main]
use libfuzzer_sys::fuzz_target;
use memcordon_core::workload_codec::{
    decode_contract, decode_contract_v2, encode_contract, encode_contract_v2,
};
use memcordon_core::workload_contract::{
    WorkloadContract, WorkloadContractV1, WorkloadContractV2,
};

fuzz_target!(|data: &[u8]| {
    match WorkloadContract::parse(data) {
        Ok(WorkloadContract::V1(request)) => {
            assert_eq!(WorkloadContractV1::parse(data).unwrap(), request);
            assert!(WorkloadContractV2::parse(data).is_err());
        }
        Ok(WorkloadContract::V2(request)) => {
            assert_eq!(WorkloadContractV2::parse(data).unwrap(), request);
            assert!(WorkloadContractV1::parse(data).is_err());
        }
        Err(_) => {}
    }
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
    if let Ok(request) = WorkloadContractV2::parse(data) {
        assert!(request.validate().is_ok());
        let canonical = encode_contract_v2(&request).unwrap();
        let decoded = decode_contract_v2(&canonical).unwrap();
        assert_eq!(encode_contract_v2(&decoded).unwrap(), canonical);
        let json = serde_json::to_vec_pretty(&request).unwrap();
        if json.len() <= memcordon_core::workload_limits::CONTRACT_BYTES {
            assert_eq!(WorkloadContractV2::parse(&json).unwrap(), request);
        }
    }
});
