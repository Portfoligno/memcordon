use memcordon_ci::certification_context::{CertificationContext, CertificationProvenance};
use memcordon_ci::private_native::NativeRunStageV2;
use memcordon_ci::private_protected_readback::{
    ProtectedCandidateReleaseRequestV1, ProtectedCoordinatorIdentityV1,
};
use memcordon_ci::private_suite::{
    REQUIRED_CASES, producer_for_host, release_case_result_path, require_public_dispatch_evidence,
    validate_candidate_child_observation, validate_catalogue, validate_private_job_context,
};
use memcordon_ci::private_supervisor::{LinuxChildIdentityV1, SupervisedProcessV2};
use std::num::{NonZeroU32, NonZeroU64};
use std::process::Command;

const CATALOGUE: &str = include_str!("../../../ci/private-native-v2.toml");

#[test]
fn compiled_selectors_match_the_exact_catalogue() {
    validate_catalogue(CATALOGUE).unwrap();
    assert_eq!(REQUIRED_CASES.len(), 25);
}

#[test]
fn final_public_cannot_enter_root_release_case_fixture_dispatch() {
    assert!(require_public_dispatch_evidence(NativeRunStageV2::CandidateCapability).is_ok());
    let error = require_public_dispatch_evidence(NativeRunStageV2::FinalPublic)
        .unwrap_err()
        .to_string();
    assert!(error.contains("installed public V2 plan/grant/launch"));
}

#[test]
fn missing_extra_duplicate_and_reordered_cases_fail_closed() {
    let first = REQUIRED_CASES[0];
    let second = REQUIRED_CASES[1];
    assert!(validate_catalogue(&CATALOGUE.replace(first, "private_tcp::wrong_name")).is_err());
    assert!(validate_catalogue(&CATALOGUE.replace(first, second)).is_err());
    assert!(validate_catalogue(&CATALOGUE.replace(first, "")).is_err());
    let reordered = CATALOGUE
        .replace(first, "private_tcp::temporary_selector")
        .replace(second, first)
        .replace("private_tcp::temporary_selector", second);
    assert!(validate_catalogue(&reordered).is_err());
}

#[test]
fn unsupported_target_cannot_enter_the_private_suite() {
    assert!(
        producer_for_host(
            NativeRunStageV2::CandidateCapability,
            "x86_64-unknown-linux-musl"
        )
        .is_err()
    );
}

#[test]
fn release_case_path_binds_stage_selector_and_raw_challenge() {
    let candidate = release_case_result_path(
        NativeRunStageV2::CandidateCapability,
        REQUIRED_CASES[0],
        [0xab; 32],
    )
    .unwrap();
    let final_public =
        release_case_result_path(NativeRunStageV2::FinalPublic, REQUIRED_CASES[0], [0xab; 32])
            .unwrap();
    assert_eq!(
        candidate.file_name().unwrap().to_str(),
        Some("2fd68a0c106ed6322f1b3494812268015c9634b5bf1dabcab3e1b5d78ce41944.json")
    );
    assert_ne!(candidate, final_public);
    assert_eq!(
        candidate.parent().unwrap().to_str(),
        Some("/var/lib/memcordon/sealed/private-release-cases")
    );
    assert!(
        release_case_result_path(
            NativeRunStageV2::CandidateCapability,
            "private_tcp::unknown",
            [0xab; 32]
        )
        .is_err()
    );
    assert!(
        release_case_result_path(
            NativeRunStageV2::CandidateCapability,
            REQUIRED_CASES[0],
            [0; 32]
        )
        .is_err()
    );
}

#[test]
fn hosted_private_job_context_requires_exact_release_job_arch_and_commit() {
    let producer = memcordon_ci::private_native::PRODUCERS
        .into_iter()
        .find(|row| {
            row.stage == NativeRunStageV2::CandidateCapability
                && row.target == "x86_64-unknown-linux-gnu"
        })
        .unwrap();
    let source_commit = "a".repeat(40);
    let mut context = CertificationContext {
        schema_version: 1,
        source_commit: source_commit.clone(),
        contract_id: "backend-linux-private-v4".into(),
        provenance: Some(CertificationProvenance {
            repository: "owner/repo".into(),
            run_id: NonZeroU64::new(42).unwrap(),
            run_attempt: NonZeroU32::new(1).unwrap(),
            job: producer.job_id.into(),
            workflow_ref: "owner/repo/.github/workflows/release.yml@refs/heads/main".into(),
            workflow_commit: source_commit,
            runner_environment: "github-hosted".into(),
            runner_os: "Linux".into(),
            runner_arch: "X64".into(),
        }),
    };
    validate_private_job_context(&context, &producer).unwrap();
    context.provenance.as_mut().unwrap().job = "assemble".into();
    assert!(validate_private_job_context(&context, &producer).is_err());
    context.provenance.as_mut().unwrap().job = producer.job_id.into();
    context.provenance.as_mut().unwrap().runner_arch = "ARM64".into();
    assert!(validate_private_job_context(&context, &producer).is_err());
    context.provenance.as_mut().unwrap().runner_arch = "X64".into();
    context.provenance.as_mut().unwrap().workflow_commit = "b".repeat(40);
    assert!(validate_private_job_context(&context, &producer).is_err());
    context.provenance = None;
    assert!(validate_private_job_context(&context, &producer).is_err());
}

#[cfg(unix)]
#[test]
fn candidate_child_custody_rejects_reported_success_without_distinct_observed_process() {
    use std::os::unix::process::ExitStatusExt;

    let digest = memcordon_core::DiagnosticSha256::from_bytes([0x5a; 32]);
    let mut request = ProtectedCandidateReleaseRequestV1 {
        schema_version: 1,
        stage: "candidate-capability".into(),
        selector: REQUIRED_CASES[16].into(),
        challenge: "ab".repeat(32),
        result_key: digest.clone(),
        installation_epoch: digest.clone(),
        candidate_manifest_sha256: digest.clone(),
        service_generation_sha256: digest,
        coordinator: ProtectedCoordinatorIdentityV1 {
            pid: 200,
            start_time: 20,
        },
    };
    let mut observed = SupervisedProcessV2 {
        status: std::process::ExitStatus::from_raw(0),
        stdout: Vec::new(),
        stderr: Vec::new(),
        linux_child: Some(LinuxChildIdentityV1 {
            pid: 100,
            start_time_ticks: 10,
        }),
    };
    validate_candidate_child_observation(&observed, &request).unwrap();
    observed.stdout.push(1);
    assert!(validate_candidate_child_observation(&observed, &request).is_err());
    observed.stdout.clear();
    observed.status = std::process::ExitStatus::from_raw(1 << 8);
    assert!(validate_candidate_child_observation(&observed, &request).is_err());
    observed.status = std::process::ExitStatus::from_raw(0);
    request.coordinator.pid = 100;
    request.coordinator.start_time = 10;
    assert!(validate_candidate_child_observation(&observed, &request).is_err());
    request.coordinator.pid = 200;
    observed.linux_child = None;
    assert!(validate_candidate_child_observation(&observed, &request).is_err());
}

#[test]
fn private_suite_cli_requires_exact_stage_and_target() {
    let binary = env!("CARGO_BIN_EXE_memcordon-ci");
    let missing = Command::new(binary)
        .args(["suite", "backend-linux-private-v4"])
        .output()
        .unwrap();
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("requires --stage"));

    let wrong_target = Command::new(binary)
        .args([
            "suite",
            "backend-linux-private-v4",
            "--stage",
            "candidate-capability",
            "--target",
            "x86_64-unknown-linux-musl",
        ])
        .output()
        .unwrap();
    assert!(!wrong_target.status.success());
    assert!(
        String::from_utf8_lossy(&wrong_target.stderr)
            .contains("unsupported private native stage or target")
    );

    let native_alias = Command::new(binary)
        .args([
            "suite",
            "backend-linux-private-v4",
            "--stage",
            "candidate-capability",
            "--target",
            "native",
        ])
        .output()
        .unwrap();
    assert!(!native_alias.status.success());
    assert!(
        !String::from_utf8_lossy(&native_alias.stderr)
            .contains("unsupported private native stage or target")
    );

    let legacy_options = Command::new(binary)
        .args([
            "suite",
            "quality",
            "--stage",
            "candidate-capability",
            "--target",
            "x86_64-unknown-linux-gnu",
        ])
        .output()
        .unwrap();
    assert!(!legacy_options.status.success());
    assert!(
        String::from_utf8_lossy(&legacy_options.stderr).contains("private native suite options")
    );
}
