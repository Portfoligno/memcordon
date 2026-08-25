#![no_main]

use libfuzzer_sys::fuzz_target;

#[cfg(target_os = "linux")]
#[path = "../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/linux/qualification_schema.rs"]
mod qualification;

fuzz_target!(|data: &[u8]| {
    memcordon_ci::release_evidence::fuzz_linux_qualification_receipt(data);
    #[cfg(target_os = "linux")]
    let _ = memcordon_platform::test_support::sealed_qualification_v2_is_valid(data);
    #[cfg(target_os = "linux")]
    if let Ok(receipt) = serde_json::from_slice::<qualification::QualificationReceipt>(data) {
        let _ = receipt.complete();
    }
});
