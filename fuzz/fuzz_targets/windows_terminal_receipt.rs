#![no_main]

use libfuzzer_sys::fuzz_target;
use memcordon_core::WindowsTerminalReceiptV1;

fuzz_target!(|data: &[u8]| {
    if let Ok(receipt) = serde_json::from_slice::<WindowsTerminalReceiptV1>(data) {
        if receipt.process_identity_inventory_is_bounded() {
            assert!(
                receipt.job_process_identities.len()
                    <= memcordon_core::WINDOWS_MAX_JOB_PROCESS_IDENTITIES
            );
        }
    }
});
