use std::path::Path;

#[cfg(unix)]
use memcordon_ci::private_public_v2::{
    ExpectedFrontendLossEvidenceV2, ExpectedPublicV2Outcome, ExpectedPublicV2Readback,
    StructuralPublicV2ReportPresence, read_structural_public_v2_report,
    read_structural_public_v2_report_presence, validate_structural_public_v2_readback,
};
use memcordon_ci::private_public_v2::{public_v2_argv, public_v2_argv_with_expected_plan};
#[cfg(unix)]
use memcordon_ci::private_supervisor::{LinuxChildIdentityV1, SupervisedProcessV2};
#[cfg(unix)]
use memcordon_core::DiagnosticSha256;
#[cfg(unix)]
use memcordon_core::private_public_report_v2::PublicCliReportEvidenceV2;
#[cfg(unix)]
use memcordon_core::private_release_case_v1::PrivateReleaseAllocatedOutcomeV1;
#[cfg(unix)]
use memcordon_core::workload_evidence_v2::QualifiedNativeAbiV2;

#[test]
fn public_dispatch_uses_real_cli_options_not_root_release_case() {
    let argv = public_v2_argv(
        Path::new("/protected/contract.json"),
        Path::new("/protected/report.json"),
        Path::new("/usr/libexec/fixed-public-fixture"),
    )
    .unwrap();
    let visible: Vec<_> = argv.iter().map(|arg| arg.to_str().unwrap()).collect();
    assert_eq!(
        visible,
        [
            "--sealed",
            "--workload-contract",
            "/protected/contract.json",
            "--report",
            "/protected/report.json",
            "--",
            "/usr/libexec/fixed-public-fixture",
        ]
    );
    assert!(!visible.contains(&"release-case"));
    assert!(public_v2_argv(Path::new("relative"), Path::new("/r"), Path::new("/f")).is_err());
    assert!(public_v2_argv(Path::new("/same"), Path::new("/same"), Path::new("/f")).is_err());
}

#[test]
fn public_replay_places_expected_plan_before_command_boundary() {
    let argv = public_v2_argv_with_expected_plan(
        Path::new("/protected/contract.json"),
        Path::new("/protected/report.json"),
        Path::new("/usr/libexec/fixed-public-fixture"),
        Some(Path::new("/protected/old-plan.json")),
    )
    .unwrap();
    let visible: Vec<_> = argv.iter().map(|arg| arg.to_str().unwrap()).collect();
    assert_eq!(
        &visible[5..],
        [
            "--expected-private-plan",
            "/protected/old-plan.json",
            "--",
            "/usr/libexec/fixed-public-fixture",
        ]
    );
    assert!(
        public_v2_argv_with_expected_plan(
            Path::new("/c"),
            Path::new("/r"),
            Path::new("/f"),
            Some(Path::new("/c")),
        )
        .is_err()
    );
}

#[cfg(unix)]
#[test]
fn public_report_file_readback_requires_single_nofollow_leaf_and_owner() {
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, symlink};
    use std::os::unix::process::ExitStatusExt;

    let mut file = tempfile::NamedTempFile::new().unwrap();
    let report = br#"{"schema_version":11,"result":{"kind":"before-submission-failure","reason":"admission unavailable"}}"#;
    file.write_all(report).unwrap();
    file.flush().unwrap();
    let digest = DiagnosticSha256::from_bytes([7; 32]);
    let source = "a".repeat(40);
    let expected = ExpectedPublicV2Readback {
        source_commit: &source,
        native_abi: QualifiedNativeAbiV2::X86_64LinuxGnu,
        archive_sha256: &digest,
        runtime_manifest_sha256: &digest,
        qualification_sha256: &digest,
        host_receipt_sha256: &digest,
        report_owner_uid: file.as_file().metadata().unwrap().uid(),
        outcome: ExpectedPublicV2Outcome::BeforeSubmissionFailure,
    };
    let observed = SupervisedProcessV2 {
        status: std::process::ExitStatus::from_raw(125 << 8),
        stdout: Vec::new(),
        stderr: Vec::new(),
        linux_child: Some(LinuxChildIdentityV1 {
            pid: 41,
            start_time_ticks: 9,
        }),
    };
    let result = read_structural_public_v2_report(file.path(), &observed, &expected).unwrap();
    assert_eq!(result.child_pid, 41);
    let link = file.path().with_extension("link");
    symlink(file.path(), &link).unwrap();
    assert!(read_structural_public_v2_report(&link, &observed, &expected).is_err());
    let wrong_owner = ExpectedPublicV2Readback {
        report_owner_uid: expected.report_owner_uid.wrapping_add(1),
        ..expected
    };
    assert!(read_structural_public_v2_report(file.path(), &observed, &wrong_owner).is_err());
}

#[cfg(unix)]
#[test]
fn structural_public_failure_requires_exact_child_exit_and_separate_final_inputs() {
    use std::os::unix::process::ExitStatusExt;

    let digest = DiagnosticSha256::from_bytes([7; 32]);
    let expected = ExpectedPublicV2Readback {
        source_commit: &"a".repeat(40),
        native_abi: QualifiedNativeAbiV2::X86_64LinuxGnu,
        archive_sha256: &digest,
        runtime_manifest_sha256: &digest,
        qualification_sha256: &digest,
        host_receipt_sha256: &digest,
        report_owner_uid: 0,
        outcome: ExpectedPublicV2Outcome::BeforeSubmissionFailure,
    };
    let report = br#"{"schema_version":11,"result":{"kind":"before-submission-failure","reason":"admission unavailable"}}"#;
    let mut observed = SupervisedProcessV2 {
        status: std::process::ExitStatus::from_raw(125 << 8),
        stdout: Vec::new(),
        stderr: Vec::new(),
        linux_child: Some(LinuxChildIdentityV1 {
            pid: 41,
            start_time_ticks: 9,
        }),
    };
    let structural = validate_structural_public_v2_readback(&observed, report, &expected).unwrap();
    assert_eq!(structural.child_pid, 41);
    observed.status = std::process::ExitStatus::from_raw(0);
    assert!(validate_structural_public_v2_readback(&observed, report, &expected).is_err());
    observed.status = std::process::ExitStatus::from_raw(125 << 8);
    observed.linux_child = None;
    assert!(validate_structural_public_v2_readback(&observed, report, &expected).is_err());
    assert!(validate_structural_public_v2_readback(
        &SupervisedProcessV2 {
            linux_child: Some(LinuxChildIdentityV1 { pid: 41, start_time_ticks: 9 }),
            ..observed
        },
        br#"{"schema_version":11,"schema_version":11,"result":{"kind":"before-submission-failure","reason":"admission unavailable"}}"#,
        &expected
    ).is_err());
}

#[cfg(unix)]
#[test]
fn lost_frontend_requires_absent_file_and_independent_replacement_hashes() {
    use std::os::unix::process::ExitStatusExt;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("public-report.json");
    let digest = DiagnosticSha256::from_bytes([7; 32]);
    let other = DiagnosticSha256::from_bytes([8; 32]);
    let expected = ExpectedPublicV2Readback {
        source_commit: &"a".repeat(40),
        native_abi: QualifiedNativeAbiV2::X86_64LinuxGnu,
        archive_sha256: &digest,
        runtime_manifest_sha256: &digest,
        qualification_sha256: &digest,
        host_receipt_sha256: &digest,
        report_owner_uid: 1234,
        outcome: ExpectedPublicV2Outcome::FrontendLost,
    };
    let observed = SupervisedProcessV2 {
        status: std::process::ExitStatus::from_raw(9),
        stdout: Vec::new(),
        stderr: Vec::new(),
        linux_child: Some(LinuxChildIdentityV1 {
            pid: 41,
            start_time_ticks: 9,
        }),
    };
    let evidence = PublicCliReportEvidenceV2::AbsentFrontendLoss {
        authenticated_terminal_sha256: digest.clone(),
        supervised_transport_sha256: digest.clone(),
        independent_recovery_sha256: digest.clone(),
    };
    let replacement = ExpectedFrontendLossEvidenceV2 {
        authenticated_terminal_sha256: &digest,
        supervised_transport_sha256: &digest,
        independent_recovery_sha256: &digest,
    };
    assert!(matches!(
        read_structural_public_v2_report_presence(
            &path,
            &observed,
            &evidence,
            PrivateReleaseAllocatedOutcomeV1::FrontendLost,
            &expected,
            Some(&replacement),
        )
        .unwrap(),
        StructuralPublicV2ReportPresence::AbsentFrontendLoss { child_pid: 41, .. }
    ));
    let wrong_replacement = ExpectedFrontendLossEvidenceV2 {
        independent_recovery_sha256: &other,
        ..replacement
    };
    assert!(
        read_structural_public_v2_report_presence(
            &path,
            &observed,
            &evidence,
            PrivateReleaseAllocatedOutcomeV1::FrontendLost,
            &expected,
            Some(&wrong_replacement),
        )
        .is_err()
    );
    assert!(
        read_structural_public_v2_report_presence(
            &path,
            &observed,
            &evidence,
            PrivateReleaseAllocatedOutcomeV1::TargetCompleted,
            &expected,
            Some(&replacement),
        )
        .is_err()
    );
    std::fs::write(&path, b"unexpected report").unwrap();
    assert!(
        read_structural_public_v2_report_presence(
            &path,
            &observed,
            &evidence,
            PrivateReleaseAllocatedOutcomeV1::FrontendLost,
            &expected,
            Some(&replacement),
        )
        .is_err()
    );
}
