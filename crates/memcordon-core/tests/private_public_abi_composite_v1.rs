use memcordon_core::private_public_abi_composite_v1::{
    PUBLIC_ABI_SELECTOR_V1, PublicAbiCompositeCaseV1,
};
use memcordon_core::private_public_case_v2::FinalPublicChildIdentityV2;
use memcordon_core::workload_codec::hash_bytes;
use memcordon_core::{BoundedText, DiagnosticSha256};

fn digest(name: &str) -> DiagnosticSha256 {
    hash_bytes(name.as_bytes())
}

fn fixture() -> PublicAbiCompositeCaseV1 {
    let mut case = PublicAbiCompositeCaseV1 {
        schema_version: 1,
        selector: PUBLIC_ABI_SELECTOR_V1.into(),
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
        filtered_child: FinalPublicChildIdentityV2 {
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
        filtered_provider_sha256: digest("provider"),
        filtered_report_sha256: digest("report"),
        filtered_stdio_sha256: digest("stdio"),
        filtered_terminal_sha256: digest("terminal"),
        filtered_cleanup_sha256: digest("cleanup"),
        filtered_target_report_sha256: digest("filtered target stdout"),
        filtered_service_journal_sha256: digest("filtered service journal"),
        filtered_checkpoint_file_sha256: digest("filtered checkpoint JSON"),
        filtered_kernel_capture_sha256: digest("filtered kernel"),
        outer_auxiliary_key: digest("placeholder"),
        outer_request_sha256: digest("outer request"),
        outer_raw_sha256: digest("outer raw"),
        outer_kernel_capture_sha256: digest("outer kernel"),
    };
    case.outer_auxiliary_key = case.expected_outer_auxiliary_key().unwrap();
    case
}

#[test]
fn public_abi_composite_keeps_filtered_and_outer_actors_separate() {
    let case = fixture();
    let bytes = serde_json::to_vec(&case).unwrap();
    assert_eq!(PublicAbiCompositeCaseV1::parse(&bytes).unwrap(), case);
    let mut wrong = case.clone();
    wrong.outer_auxiliary_key = digest("other key");
    assert!(wrong.validate().is_err());
    let mut wrong = case.clone();
    wrong.outer_kernel_capture_sha256 = wrong.filtered_kernel_capture_sha256.clone();
    assert!(wrong.validate().is_err());
    let mut wrong = case.clone();
    wrong.filtered_service_journal_sha256 = wrong.filtered_target_report_sha256.clone();
    assert!(wrong.validate().is_err());
    let mut wrong = case;
    wrong.filtered_child.uid = 0;
    assert!(wrong.validate().is_err());
}
