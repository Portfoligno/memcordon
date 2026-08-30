#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/inspection_schema.rs"]
mod inspection_schema;

fuzz_target!(|data: &[u8]| {
    if let Ok([cli_channel, provider_channel]) =
        serde_json::from_slice::<[inspection_schema::AgentPackageInspectionV3; 2]>(data)
    {
        let _ = cli_channel.version == provider_channel.version
            && cli_channel.source_commit == provider_channel.source_commit;
    }
});
