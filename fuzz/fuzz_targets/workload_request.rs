#![no_main]
use libfuzzer_sys::fuzz_target;
use memcordon_core::workload_request::WorkloadRequestV1;

fuzz_target!(|data: &[u8]| {
    if let Ok(request) = WorkloadRequestV1::parse(data) {
        let canonical = request.canonical_bytes().unwrap();
        let decoded = WorkloadRequestV1::parse(&canonical).unwrap();
        assert_eq!(request, decoded);
        assert_eq!(request.digest().unwrap(), decoded.digest().unwrap());
    }
});
