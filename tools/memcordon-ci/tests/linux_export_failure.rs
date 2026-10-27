#[path = "../src/release/linux_export_failure.rs"]
mod evidence;
use memcordon_ci::producer_failure_forwarding;
use std::{io, path::Path};

#[test]
fn complete_and_truncated_producer_bytes_remain_diagnostic_only() {
    for size in [0, 3, evidence::PREFIX_BYTES, evidence::PREFIX_BYTES + 1] {
        let bytes = vec![0xab; size];
        let record = evidence::capture(Ok(bytes.clone()));
        assert_eq!(record["original_bytes"], size);
        assert_eq!(
            record["omitted_bytes"],
            size.saturating_sub(evidence::PREFIX_BYTES)
        );
        assert_eq!(
            record["prefix_hex"],
            hex::encode(&bytes[..size.min(evidence::PREFIX_BYTES)])
        );
        assert_eq!(record["diagnostic_only"], true);
    }
}
#[test]
fn absent_capture_retains_native_error_without_inventing_bytes() {
    let record = evidence::capture(Err(io::Error::from_raw_os_error(2)));
    assert_eq!(record["state"], "unavailable");
    assert_eq!(record["raw_os_error"], 2);
    assert!(record.get("prefix_hex").is_none());
}
#[test]
fn only_original_attempt_and_launch_path_can_supply_diagnostics() {
    let result = Path::new("/owned/export-symlink/launch/result.json");
    let attempt = "0123456789abcdef0123456789abcdef";
    let request = result
        .parent()
        .unwrap()
        .join("observations")
        .join(Path::new(attempt).with_extension("provider-request.bin"));
    let request = request.as_path();
    evidence::binding(attempt, result, result, request).unwrap();
    for (attempt, actual, request) in [
        ("dcba", result, request),
        (attempt, Path::new("/other/result.json"), request),
        (
            attempt,
            result,
            Path::new("/other/abcd.provider-request.bin"),
        ),
    ] {
        assert!(evidence::binding(attempt, result, actual, request).is_err());
    }
    assert!(evidence::binding(&attempt.to_uppercase(), result, result, request).is_err());
}
