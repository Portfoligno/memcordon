#![cfg(all(target_os = "linux", feature = "test-support"))]

use std::os::unix::fs::PermissionsExt;

use memcordon_sealed_agent::linux::startup::StartupPhase;
use tempfile::TempDir;

#[test]
fn startup_failure_is_typed_bounded_and_atomically_clearable() {
    let temporary = TempDir::new().unwrap();
    let path = temporary.path().join("startup.json");
    let detail = format!("MCSEALED-PROVIDER-UNAVAILABLE: {}", "x".repeat(20 * 1024));

    memcordon_sealed_agent::linux::startup::record_for_test(
        &path,
        StartupPhase::Qualification,
        &detail,
    )
    .unwrap();
    let record = memcordon_sealed_agent::linux::startup::read_for_test(&path)
        .unwrap()
        .unwrap();

    assert_eq!(record.schema_version, 1);
    assert_eq!(record.code, "MCSEALED-PROVIDER-UNAVAILABLE");
    assert!(record.detail.len() <= 8 * 1024);
    assert!(record.detail.ends_with("...[truncated]"));
    assert_eq!(record.provider_pid, std::process::id());

    memcordon_sealed_agent::linux::startup::clear_for_test(&path).unwrap();
    assert!(
        memcordon_sealed_agent::linux::startup::read_for_test(&path)
            .unwrap()
            .is_none()
    );
}

#[test]
fn startup_failure_rejects_unknown_fields_and_unstable_codes() {
    let temporary = TempDir::new().unwrap();
    let path = temporary.path().join("startup.json");
    let error = memcordon_sealed_agent::linux::startup::record_for_test(
        &path,
        StartupPhase::SocketActivation,
        "ordinary error without a stable code",
    )
    .unwrap_err();
    assert!(error.contains("stable error code"));

    std::fs::write(
        &path,
        b"{\"schema_version\":1,\"phase\":\"qualification\",\"code\":\"MCSEALED-X\",\"detail\":\"x\",\"provider_pid\":1,\"unknown\":true}\n",
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let error = memcordon_sealed_agent::linux::startup::read_for_test(&path).unwrap_err();
    assert!(error.contains("unknown field"));
}
