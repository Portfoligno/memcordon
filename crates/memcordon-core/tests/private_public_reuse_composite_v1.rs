use memcordon_core::private_public_case_v2::FinalPublicChildIdentityV2;
use memcordon_core::private_public_reuse_composite_v1::{
    PUBLIC_REUSE_SELECTOR_V1, PublicReuseCompositeCaseV1,
};
use memcordon_core::workload_codec::hash_bytes;
use memcordon_core::{BoundedText, DiagnosticSha256};

fn digest(name: &str) -> DiagnosticSha256 {
    hash_bytes(name.as_bytes())
}

fn fixture() -> PublicReuseCompositeCaseV1 {
    PublicReuseCompositeCaseV1 {
        schema_version: 1,
        selector: PUBLIC_REUSE_SELECTOR_V1.into(),
        challenge: [7; 32],
        source_commit: "a".repeat(40),
        release_version: BoundedText::new("0.5.7-dev").unwrap(),
        target: "x86_64-unknown-linux-gnu".into(),
        native_machine: "x86_64".into(),
        archive_sha256: digest("A"),
        manifest_sha256: digest("M1"),
        qualification_sha256: digest("Q"),
        active_h1_receipt_sha256: digest("H1"),
        installation_epoch: digest("E1"),
        child: FinalPublicChildIdentityV2 {
            pid: 123,
            start_time_ticks: 456,
            boot_identity: BoundedText::new("boot-1").unwrap(),
            uid: 1000,
            gid: 1000,
            supplementary_groups_empty: true,
            executable_sha256: digest("cli"),
            argv_sha256: digest("argv"),
            working_directory_sha256: digest("cwd"),
        },
        provider_sha256: digest("provider"),
        report_sha256: digest("report"),
        stdio_sha256: digest("stdio"),
        first_failure_sha256: digest("first-failure"),
        blocked_rejection_sha256: digest("blocked"),
        recovered_cleanup_sha256: digest("recovered"),
        durable_incomplete_snapshot_sha256: digest("incomplete-v4"),
        protected_reuse_transcript_sha256: digest("reuse.json"),
        semantic_join_sha256: digest("joined proof"),
        first_kernel_capture_sha256: digest("first capture"),
        blocked_kernel_capture_sha256: digest("blocked capture"),
        recovery_kernel_capture_sha256: digest("recovery capture"),
    }
}

#[test]
fn public_reuse_composite_cannot_relabel_failure_as_terminal_or_alias_intervals() {
    let case = fixture();
    let bytes = serde_json::to_vec(&case).unwrap();
    assert_eq!(PublicReuseCompositeCaseV1::parse(&bytes).unwrap(), case);
    let mut wrong = case.clone();
    wrong.blocked_kernel_capture_sha256 = wrong.first_kernel_capture_sha256.clone();
    assert!(wrong.validate().is_err());
    let mut wrong = case.clone();
    wrong.first_failure_sha256 = wrong.blocked_rejection_sha256.clone();
    assert!(wrong.validate().is_err());
    let mut wrong = case;
    wrong.child.uid = 0;
    assert!(wrong.validate().is_err());
}
