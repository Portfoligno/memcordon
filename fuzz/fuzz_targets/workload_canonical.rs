#![no_main]
use libfuzzer_sys::fuzz_target;
use memcordon_core::workload_codec::{decode_contract, encode_contract};

fuzz_target!(|data: &[u8]| {
    if let Ok(request) = decode_contract(data) {
        assert!(request.validate().is_ok());
        assert_eq!(encode_contract(&request).unwrap(), data);
        let mut trailing = data.to_vec();
        trailing.push(0);
        assert!(decode_contract(&trailing).is_err());
    }
});
