#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    memcordon_ci::release_evidence::fuzz_linux_qualification_receipt(data);
    #[cfg(target_os = "linux")]
    let _ = memcordon_platform::test_support::sealed_qualification_v2_is_valid(data);
    #[cfg(target_os = "linux")]
    if let Ok(receipt) = serde_json::from_slice::<
        memcordon_sealed_agent::linux::qualification::QualificationReceipt,
    >(data)
    {
        let _ = receipt.complete();
    }
});
