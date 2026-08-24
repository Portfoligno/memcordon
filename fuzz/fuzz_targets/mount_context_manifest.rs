#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    memcordon_ci::release_evidence::fuzz_linux_mount_context_manifest(data);
});
