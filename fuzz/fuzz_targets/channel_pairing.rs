#![no_main]

use libfuzzer_sys::fuzz_target;

use memcordon_core::sealed_provider::inspection as inspection_schema;

fn check(cli_version: &str, provider_version: &str) {
    let paired = inspection_schema::validate_exact_provider_pairing(
        cli_version,
        provider_version,
        "cli",
        "provider",
    );
    assert_eq!(paired.is_ok(), cli_version == provider_version);
    assert!(
        inspection_schema::validate_exact_provider_pairing(
            cli_version,
            cli_version,
            "cli",
            "provider"
        )
        .is_ok()
    );
    let mut different = cli_version.to_owned();
    different.push('\0');
    assert!(
        inspection_schema::validate_exact_provider_pairing(
            cli_version,
            &different,
            "cli",
            "provider"
        )
        .is_err()
    );
}

fuzz_target!(|data: &[u8]| {
    if let Ok([cli_channel, provider_channel]) =
        serde_json::from_slice::<[inspection_schema::AgentPackageInspectionV3; 2]>(data)
    {
        check(&cli_channel.version, &provider_channel.version);
    }
    if let Ok([cli_channel, provider_channel]) =
        serde_json::from_slice::<[inspection_schema::AgentPackageInspectionV4; 2]>(data)
    {
        check(&cli_channel.version, &provider_channel.version);
    }
});
