#![cfg(feature = "test-support")]

#[test]
fn shipped_helpers_report_the_same_production_contract() {
    let expected = memcordon_core::sealed_provider::fingerprint::provider_contract_fingerprint();
    for helper in [
        env!("CARGO_BIN_EXE_memcordon-sealed-agent"),
        env!("CARGO_BIN_EXE_memcordon-session-broker"),
        env!("CARGO_BIN_EXE_memcordon-target-desktop-bootstrap"),
    ] {
        let output = std::process::Command::new(helper)
            .args(["--provider-contract-fingerprint"])
            .output()
            .expect("run shipped helper fingerprint route");
        assert!(
            output.status.success(),
            "helper {helper}: {:?}",
            output.stderr
        );
        let observed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(observed, expected, "independently linked helper {helper}");
    }
}
