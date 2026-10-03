#[test]
fn retired_public_tool_transport_is_not_an_exported_ci_service() {
    let exports = include_str!("../src/lib.rs");
    assert!(!exports.contains("pub mod release_hosted_service;"));
    let cli = include_str!("../src/main.rs");
    assert!(!cli.contains("release-hosted-service"));
}
