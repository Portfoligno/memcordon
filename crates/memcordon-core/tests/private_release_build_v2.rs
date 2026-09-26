use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_build_v2::{PrivateCandidateRecordV2, PrivateCandidateStageV2};

#[test]
fn installed_build_record_rejects_noncanonical_or_extra_fields() {
    let record = PrivateCandidateRecordV2 {
        schema_version: 2,
        stage: PrivateCandidateStageV2::UnqualifiedCandidate,
        version: "0.5.7-dev".into(),
        source_commit: "a".repeat(40),
        target: "x86_64-unknown-linux-gnu".into(),
        runtime_manifest_sha256: DiagnosticSha256::from_bytes([1; 32]),
        component_sha256: DiagnosticSha256::from_bytes([2; 32]),
        unit_sha256: DiagnosticSha256::from_bytes([3; 32]),
        filter_sha256: DiagnosticSha256::from_bytes([4; 32]),
    };
    let bytes = serde_json::to_vec(&record).unwrap();
    assert_eq!(PrivateCandidateRecordV2::parse(&bytes).unwrap(), record);
    let mut extra: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    extra["qualified"] = serde_json::json!(true);
    assert!(PrivateCandidateRecordV2::parse(&serde_json::to_vec(&extra).unwrap()).is_err());
    let text = std::str::from_utf8(&bytes).unwrap();
    let duplicate = format!("{},\"schema_version\":2}}", text.strip_suffix('}').unwrap());
    assert!(PrivateCandidateRecordV2::parse(duplicate.as_bytes()).is_err());
    assert!(PrivateCandidateRecordV2::parse(&vec![b' '; 16 * 1024 + 1]).is_err());
}
