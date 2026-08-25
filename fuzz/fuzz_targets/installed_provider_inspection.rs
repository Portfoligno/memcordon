#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/inspection_schema.rs"]
mod inspection_schema;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<inspection_schema::InstalledProviderInspectionV2>(data);
});
