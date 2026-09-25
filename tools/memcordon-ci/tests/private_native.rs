use std::collections::BTreeMap;
use std::io::{Cursor, Write};
use std::num::{NonZeroU32, NonZeroU64};

use memcordon_ci::certification_context::{
    CertificationContext, CertificationProvenance, ExpectedCertificationOrigin,
};
use memcordon_ci::private_native::{
    CandidateInstalledBindingV2, ExpectedFinalPublicJoinV2, ExpectedNativeRunV2,
    FinalInstalledBindingV2, NativeAttachmentRoleV2, NativeAttachmentV2, NativeCaseCompletionV2,
    NativeCaseOutcomeV2, NativeCasePhaseV2, NativeRunEnvelopeV2, NativeRunStageV2,
    NativeSupervisorObservationV2, validate_final_public_structural_join,
    validate_native_artifact_zip, validate_native_run_envelope,
    validate_native_run_platform_provenance,
};
use memcordon_ci::workload_qualification::private_component_digest_v2;
use memcordon_core::DiagnosticSha256;
use memcordon_core::runtime_manifest::{RuntimeComponentRecord, RuntimeComponentRole};
use memcordon_core::workload_codec::hash_bytes;

const SOURCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TARGET: &str = "x86_64-unknown-linux-gnu";
const CHALLENGE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ATTEMPT: &str = "cccccccccccccccccccccccccccccccc";

fn digest(byte: u8) -> DiagnosticSha256 {
    DiagnosticSha256::from_bytes([byte; 32])
}

#[test]
fn component_build_identity_is_order_independent_and_byte_sensitive() {
    let mut components = vec![
        RuntimeComponentRecord {
            id: "sealed-agent".into(),
            path: "memcordon-sealed-agent".into(),
            role: RuntimeComponentRole::SealedAgent,
            size: 700,
            mode: 0o755,
            sha256: "11".repeat(32),
        },
        RuntimeComponentRecord {
            id: "public-cli".into(),
            path: "memcordon".into(),
            role: RuntimeComponentRole::PublicCli,
            size: 500,
            mode: 0o755,
            sha256: "22".repeat(32),
        },
    ];
    let first = private_component_digest_v2(TARGET, SOURCE, "0.5.7-dev", &components).unwrap();
    components.reverse();
    assert_eq!(
        first,
        private_component_digest_v2(TARGET, SOURCE, "0.5.7-dev", &components).unwrap()
    );
    components[0].sha256 = "33".repeat(32);
    assert_ne!(
        first,
        private_component_digest_v2(TARGET, SOURCE, "0.5.7-dev", &components).unwrap()
    );
    components[0].sha256 = "GG".repeat(32);
    assert!(private_component_digest_v2(TARGET, SOURCE, "0.5.7-dev", &components).is_err());
}

#[test]
fn hosted_arm64_context_is_valid_without_weakening_target_joins() {
    let context = CertificationContext {
        schema_version: 1,
        source_commit: SOURCE.into(),
        contract_id: "private-native-v2".into(),
        provenance: Some(CertificationProvenance {
            repository: "owner/memcordon".into(),
            run_id: NonZeroU64::new(123456).unwrap(),
            run_attempt: NonZeroU32::new(1).unwrap(),
            job: "linux-private-candidate".into(),
            workflow_ref: "owner/memcordon/.github/workflows/release.yml@refs/tags/0.5.7".into(),
            workflow_commit: SOURCE.into(),
            runner_environment: "github-hosted".into(),
            runner_os: "Linux".into(),
            runner_arch: "ARM64".into(),
        }),
    };
    context.validate("private-native-v2").unwrap();
    let mut wrong = context;
    wrong.provenance.as_mut().unwrap().runner_arch = "PPC64".into();
    assert!(wrong.validate("private-native-v2").is_err());
}

fn fixture() -> (NativeRunEnvelopeV2, BTreeMap<String, Vec<u8>>) {
    let inventory: toml::Value =
        toml::from_str(include_str!("../../../ci/private-native-v2.toml")).unwrap();
    let mut attachments = BTreeMap::new();
    let mut cases = Vec::new();
    for (index, name) in inventory["tests"].as_array().unwrap().iter().enumerate() {
        let mut case_attachments = Vec::new();
        for (role, stem) in [
            (NativeAttachmentRoleV2::Request, "request"),
            (NativeAttachmentRoleV2::Report, "report"),
            (NativeAttachmentRoleV2::Stdio, "stdio"),
            (NativeAttachmentRoleV2::Observer, "observer"),
            (NativeAttachmentRoleV2::Cleanup, "cleanup"),
        ] {
            let path = format!("attachments/{index}/{stem}.bin");
            let raw = format!("{index}:{stem}").into_bytes();
            case_attachments.push(NativeAttachmentV2 {
                role,
                path: path.clone(),
                sha256: hash_bytes(&raw),
            });
            attachments.insert(path, raw);
        }
        cases.push(NativeCaseCompletionV2 {
            name: name.as_str().unwrap().into(),
            attempt_id: (name.as_str().unwrap()
                != "private_tcp::wrong_grant_profile_and_port_rejected")
                .then(|| ATTEMPT.into()),
            passed: true,
            phase: match name.as_str().unwrap() {
                "private_tcp::wrong_grant_profile_and_port_rejected" => {
                    NativeCasePhaseV2::PreallocationRejected
                }
                "private_tcp::retirement_failure_blocks_reuse" => {
                    NativeCasePhaseV2::RetirementFailureBlockedReuse
                }
                _ => NativeCasePhaseV2::AllocatedRetired,
            },
            outcome: match name.as_str().unwrap() {
                "private_tcp::wrong_grant_profile_and_port_rejected" => {
                    NativeCaseOutcomeV2::GrantRejected
                }
                "private_tcp::retirement_failure_blocks_reuse" => {
                    NativeCaseOutcomeV2::RetirementUnprovedReuseBlocked
                }
                "private_tcp::authorization_uncertainty_retired" => {
                    NativeCaseOutcomeV2::AuthorizationUncertain
                }
                "private_tcp::frontend_loss_retired" => NativeCaseOutcomeV2::FrontendLost,
                "private_tcp::guardian_loss_retired" => NativeCaseOutcomeV2::GuardianLost,
                _ => NativeCaseOutcomeV2::TargetCompleted,
            },
            supervisor_observed_exec: !matches!(
                name.as_str().unwrap(),
                "private_tcp::authorization_uncertainty_retired"
                    | "private_tcp::frontend_loss_retired"
                    | "private_tcp::guardian_loss_retired"
                    | "private_tcp::retirement_failure_blocks_reuse"
                    | "private_tcp::wrong_grant_profile_and_port_rejected"
            ),
            retirement_proved: name.as_str().unwrap()
                != "private_tcp::wrong_grant_profile_and_port_rejected"
                && name.as_str().unwrap() != "private_tcp::retirement_failure_blocks_reuse",
            reuse_blocked: name.as_str().unwrap() == "private_tcp::retirement_failure_blocks_reuse",
            attachments: case_attachments,
        });
        let case = cases.last_mut().unwrap();
        let observer = NativeSupervisorObservationV2 {
            schema_version: 2,
            challenge: CHALLENGE.into(),
            case_name: case.name.clone(),
            stage: NativeRunStageV2::CandidateCapability,
            target: TARGET.into(),
            phase: case.phase,
            outcome: case.outcome,
            attempt_id: case.attempt_id.clone(),
            target_exec_observed: case.supervisor_observed_exec,
            retirement_proved: case.retirement_proved,
            reuse_blocked: case.reuse_blocked,
        };
        let raw = serde_json::to_vec(&observer).unwrap();
        let attachment = case
            .attachments
            .iter_mut()
            .find(|attachment| attachment.role == NativeAttachmentRoleV2::Observer)
            .unwrap();
        attachment.sha256 = hash_bytes(&raw);
        attachments.insert(attachment.path.clone(), raw);
    }
    (
        NativeRunEnvelopeV2 {
            schema_version: 2,
            stage: NativeRunStageV2::CandidateCapability,
            version: "0.5.7-dev".into(),
            source_commit: SOURCE.into(),
            target: TARGET.into(),
            native_machine: "x86_64".into(),
            workflow_run_id: "123456".into(),
            workflow_job: "linux-private-candidate".into(),
            workflow_attempt: 1,
            challenge: CHALLENGE.into(),
            invocation_argv: vec![
                "memcordon-ci".into(),
                "suite".into(),
                "backend-linux-private-v4".into(),
            ],
            build_context_sha256: digest(1),
            runner_sha256: digest(2),
            host_prerequisites_sha256: digest(3),
            release_catalogue_sha256: hash_bytes(include_bytes!(
                "../../../ci/private-native-v2.toml"
            )),
            component_sha256: digest(4),
            unit_sha256: digest(5),
            filter_sha256: digest(6),
            started_unix_ms: 100,
            completed_unix_ms: 101,
            candidate_installed: Some(CandidateInstalledBindingV2 {
                runtime_manifest_sha256: digest(7),
                installed_inspection_sha256: digest(8),
            }),
            final_installed: None,
            cases,
        },
        attachments,
    )
}

fn expected(envelope: &NativeRunEnvelopeV2) -> ExpectedNativeRunV2<'_> {
    ExpectedNativeRunV2 {
        stage: NativeRunStageV2::CandidateCapability,
        version: "0.5.7-dev",
        source_commit: SOURCE,
        target: TARGET,
        native_machine: "x86_64",
        workflow_run_id: "123456",
        workflow_job: "linux-private-candidate",
        workflow_attempt: 1,
        challenge: CHALLENGE,
        invocation_argv: &envelope.invocation_argv,
        build_context_sha256: &envelope.build_context_sha256,
        runner_sha256: &envelope.runner_sha256,
        host_prerequisites_sha256: &envelope.host_prerequisites_sha256,
        release_catalogue_sha256: &envelope.release_catalogue_sha256,
        component_sha256: &envelope.component_sha256,
        unit_sha256: &envelope.unit_sha256,
        filter_sha256: &envelope.filter_sha256,
        candidate_installed: envelope.candidate_installed.as_ref(),
        final_installed: None,
    }
}

#[test]
fn complete_candidate_inventory_and_raw_bytes_validate_structurally() {
    let (envelope, attachments) = fixture();
    let expected = expected(&envelope);
    let bytes = serde_json::to_vec(&envelope).unwrap();
    assert_eq!(
        validate_native_run_envelope(&bytes, &attachments, &expected).unwrap(),
        envelope
    );
}

#[test]
fn missing_case_skip_wrong_target_or_swapped_raw_bytes_fail() {
    let (envelope, mut attachments) = fixture();
    let expected = expected(&envelope);
    let mut changed = envelope.clone();
    changed.cases.pop();
    assert!(
        validate_native_run_envelope(
            &serde_json::to_vec(&changed).unwrap(),
            &attachments,
            &expected
        )
        .is_err()
    );
    changed = envelope.clone();
    changed.cases[0].passed = false;
    assert!(
        validate_native_run_envelope(
            &serde_json::to_vec(&changed).unwrap(),
            &attachments,
            &expected
        )
        .is_err()
    );
    changed = envelope.clone();
    changed.target = "aarch64-unknown-linux-gnu".into();
    assert!(
        validate_native_run_envelope(
            &serde_json::to_vec(&changed).unwrap(),
            &attachments,
            &expected
        )
        .is_err()
    );
    let path = envelope.cases[0].attachments[0].path.clone();
    attachments.insert(path, b"substitution".to_vec());
    assert!(
        validate_native_run_envelope(
            &serde_json::to_vec(&envelope).unwrap(),
            &attachments,
            &expected
        )
        .is_err()
    );
}

#[test]
fn run_freshness_and_denial_phase_cannot_be_substituted() {
    let (envelope, attachments) = fixture();
    let expected = expected(&envelope);
    let mut changed = envelope.clone();
    changed.challenge = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into();
    assert!(
        validate_native_run_envelope(
            &serde_json::to_vec(&changed).unwrap(),
            &attachments,
            &expected
        )
        .is_err()
    );
    changed = envelope.clone();
    changed.host_prerequisites_sha256 = digest(9);
    assert!(
        validate_native_run_envelope(
            &serde_json::to_vec(&changed).unwrap(),
            &attachments,
            &expected
        )
        .is_err()
    );
    changed = envelope.clone();
    changed.native_machine = "aarch64".into();
    assert!(
        validate_native_run_envelope(
            &serde_json::to_vec(&changed).unwrap(),
            &attachments,
            &expected
        )
        .is_err()
    );
    changed = envelope.clone();
    changed.invocation_argv.push("--ignored".into());
    assert!(
        validate_native_run_envelope(
            &serde_json::to_vec(&changed).unwrap(),
            &attachments,
            &expected
        )
        .is_err()
    );
    changed = envelope.clone();
    let denied = changed
        .cases
        .iter_mut()
        .find(|case| case.name == "private_tcp::wrong_grant_profile_and_port_rejected")
        .unwrap();
    denied.attempt_id = Some(ATTEMPT.into());
    assert!(
        validate_native_run_envelope(
            &serde_json::to_vec(&changed).unwrap(),
            &attachments,
            &expected
        )
        .is_err()
    );
    changed = envelope.clone();
    let denied = changed
        .cases
        .iter_mut()
        .find(|case| case.name == "private_tcp::wrong_grant_profile_and_port_rejected")
        .unwrap();
    denied.supervisor_observed_exec = true;
    assert!(
        validate_native_run_envelope(
            &serde_json::to_vec(&changed).unwrap(),
            &attachments,
            &expected
        )
        .is_err()
    );
    changed = envelope.clone();
    let denied = changed
        .cases
        .iter_mut()
        .find(|case| case.name == "private_tcp::wrong_grant_profile_and_port_rejected")
        .unwrap();
    denied.outcome = NativeCaseOutcomeV2::TargetCompleted;
    assert!(
        validate_native_run_envelope(
            &serde_json::to_vec(&changed).unwrap(),
            &attachments,
            &expected
        )
        .is_err()
    );
    changed = envelope.clone();
    let tcp = changed
        .cases
        .iter_mut()
        .find(|case| case.name == "private_tcp::native_tcp_bind_listen_connect")
        .unwrap();
    tcp.supervisor_observed_exec = false;
    assert!(
        validate_native_run_envelope(
            &serde_json::to_vec(&changed).unwrap(),
            &attachments,
            &expected
        )
        .is_err()
    );
    changed = envelope.clone();
    let retirement_failure = changed
        .cases
        .iter_mut()
        .find(|case| case.name == "private_tcp::retirement_failure_blocks_reuse")
        .unwrap();
    retirement_failure.reuse_blocked = false;
    assert!(
        validate_native_run_envelope(
            &serde_json::to_vec(&changed).unwrap(),
            &attachments,
            &expected
        )
        .is_err()
    );
}

#[test]
fn raw_supervisor_observation_must_match_bound_case_and_challenge() {
    let (mut envelope, mut attachments) = fixture();
    let observer = envelope.cases[0]
        .attachments
        .iter_mut()
        .find(|attachment| attachment.role == NativeAttachmentRoleV2::Observer)
        .unwrap();
    let mut raw: NativeSupervisorObservationV2 =
        serde_json::from_slice(&attachments[&observer.path]).unwrap();
    raw.challenge = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into();
    let bytes = serde_json::to_vec(&raw).unwrap();
    observer.sha256 = hash_bytes(&bytes);
    attachments.insert(observer.path.clone(), bytes);
    let expected = expected(&envelope);
    assert!(
        validate_native_run_envelope(
            &serde_json::to_vec(&envelope).unwrap(),
            &attachments,
            &expected
        )
        .is_err()
    );
}

#[test]
fn final_public_stage_requires_public_denial_observation() {
    let (mut envelope, mut attachments) = fixture();
    envelope.stage = NativeRunStageV2::FinalPublic;
    envelope.workflow_job = "linux-private-final".into();
    envelope.candidate_installed = None;
    envelope.final_installed = Some(FinalInstalledBindingV2 {
        archive_sha256: digest(21),
        runtime_manifest_sha256: digest(22),
        installed_receipt_sha256: digest(23),
    });
    for case in &mut envelope.cases {
        if case.name == "private_tcp::wrong_grant_profile_and_port_rejected" {
            case.outcome = NativeCaseOutcomeV2::PublicGrantRejected;
        }
        let observer = case
            .attachments
            .iter_mut()
            .find(|attachment| attachment.role == NativeAttachmentRoleV2::Observer)
            .unwrap();
        let mut raw: NativeSupervisorObservationV2 =
            serde_json::from_slice(&attachments[&observer.path]).unwrap();
        raw.stage = NativeRunStageV2::FinalPublic;
        raw.outcome = case.outcome;
        let bytes = serde_json::to_vec(&raw).unwrap();
        observer.sha256 = hash_bytes(&bytes);
        attachments.insert(observer.path.clone(), bytes);
    }
    let mut expected = expected(&envelope);
    expected.stage = NativeRunStageV2::FinalPublic;
    expected.workflow_job = "linux-private-final";
    expected.candidate_installed = None;
    expected.final_installed = envelope.final_installed.as_ref();
    assert!(
        validate_native_run_envelope(
            &serde_json::to_vec(&envelope).unwrap(),
            &attachments,
            &expected
        )
        .is_ok()
    );
    let mut substituted = envelope.clone();
    let denied = substituted
        .cases
        .iter_mut()
        .find(|case| case.name == "private_tcp::wrong_grant_profile_and_port_rejected")
        .unwrap();
    denied.outcome = NativeCaseOutcomeV2::GrantRejected;
    assert!(
        validate_native_run_envelope(
            &serde_json::to_vec(&substituted).unwrap(),
            &attachments,
            &expected
        )
        .is_err()
    );
}

#[test]
fn final_public_structural_join_requires_fresh_stage_and_independent_a_m1_h1() {
    let (candidate, _) = fixture();
    let archive = digest(21);
    let manifest = digest(22);
    let installed = digest(23);
    let mut final_public = candidate.clone();
    final_public.stage = NativeRunStageV2::FinalPublic;
    final_public.workflow_job = "linux-private-final".into();
    final_public.candidate_installed = None;
    final_public
        .cases
        .iter_mut()
        .find(|case| case.name == "private_tcp::wrong_grant_profile_and_port_rejected")
        .unwrap()
        .outcome = NativeCaseOutcomeV2::PublicGrantRejected;
    final_public.challenge =
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into();
    final_public.started_unix_ms = candidate.completed_unix_ms + 1;
    final_public.completed_unix_ms = final_public.started_unix_ms + 1;
    final_public.final_installed = Some(FinalInstalledBindingV2 {
        archive_sha256: archive.clone(),
        runtime_manifest_sha256: manifest.clone(),
        installed_receipt_sha256: installed.clone(),
    });
    let expected = ExpectedFinalPublicJoinV2 {
        source_commit: SOURCE,
        version: "0.5.7-dev",
        target: TARGET,
        workflow_run_id: "123456",
        workflow_attempt: 1,
        component_sha256: &candidate.component_sha256,
        unit_sha256: &candidate.unit_sha256,
        filter_sha256: &candidate.filter_sha256,
        candidate_manifest_sha256: &candidate
            .candidate_installed
            .as_ref()
            .unwrap()
            .runtime_manifest_sha256,
        candidate_inspection_sha256: &candidate
            .candidate_installed
            .as_ref()
            .unwrap()
            .installed_inspection_sha256,
        archive_sha256: &archive,
        runtime_manifest_sha256: &manifest,
        installed_receipt_sha256: &installed,
    };
    assert!(validate_final_public_structural_join(&candidate, &final_public, &expected).is_ok());

    let mut wrong = final_public.clone();
    wrong.cases.clear();
    assert!(validate_final_public_structural_join(&candidate, &wrong, &expected).is_err());
    let mut wrong = final_public.clone();
    wrong.final_installed.as_mut().unwrap().archive_sha256 = digest(24);
    assert!(validate_final_public_structural_join(&candidate, &wrong, &expected).is_err());
    let mut wrong = final_public.clone();
    wrong.challenge = candidate.challenge.clone();
    assert!(validate_final_public_structural_join(&candidate, &wrong, &expected).is_err());
    let mut wrong = final_public.clone();
    wrong.started_unix_ms = candidate.started_unix_ms;
    assert!(validate_final_public_structural_join(&candidate, &wrong, &expected).is_err());
    let mut wrong = final_public.clone();
    wrong.workflow_run_id = "different-run".into();
    assert!(validate_final_public_structural_join(&candidate, &wrong, &expected).is_err());
}

#[test]
fn candidate_m0_h0_must_match_independent_expected_binding() {
    let (envelope, attachments) = fixture();
    let mut changed = envelope.clone();
    changed
        .candidate_installed
        .as_mut()
        .unwrap()
        .installed_inspection_sha256 = digest(90);
    assert!(
        validate_native_run_envelope(
            &serde_json::to_vec(&changed).unwrap(),
            &attachments,
            &expected(&envelope),
        )
        .is_err()
    );
    changed.candidate_installed = None;
    assert!(
        validate_native_run_envelope(
            &serde_json::to_vec(&changed).unwrap(),
            &attachments,
            &expected(&envelope),
        )
        .is_err()
    );
}

#[test]
fn self_consistent_substitute_catalogue_digest_is_rejected() {
    let (mut envelope, attachments) = fixture();
    envelope.release_catalogue_sha256 = digest(91);
    assert!(
        validate_native_run_envelope(
            &serde_json::to_vec(&envelope).unwrap(),
            &attachments,
            &expected(&envelope),
        )
        .is_err()
    );
}

#[test]
fn github_run_job_and_downloaded_zip_must_join_the_candidate_target() {
    let (envelope, attachments) = fixture();
    let origin = ExpectedCertificationOrigin {
        source_commit: SOURCE.into(),
        repository: "owner/memcordon".into(),
        run_id: NonZeroU64::new(123456).unwrap(),
        workflow_ref: "owner/memcordon/.github/workflows/release.yml@refs/tags/0.5.7".into(),
        workflow_commit: SOURCE.into(),
    };
    let run = serde_json::json!({
        "id": 123456,
        "run_attempt": 1,
        "head_sha": SOURCE,
        "path": ".github/workflows/release.yml@refs/tags/0.5.7",
        "repository": { "id": 44, "full_name": "owner/memcordon" },
        "event": "push",
        "status": "completed",
        "conclusion": "success"
    });
    let jobs = serde_json::json!({ "jobs": [{
        "name": "Release / Linux private candidate / x64",
        "run_id": 123456,
        "run_attempt": 1,
        "head_sha": SOURCE,
        "status": "completed",
        "conclusion": "success",
        "runner_id": 25,
        "labels": ["ubuntu-24.04"]
    }] });
    let zip = b"downloaded artifact ZIP bytes";
    let artifact = serde_json::json!({
        "id": 31,
        "name": "release-private-candidate-x64",
        "expired": false,
        "size_in_bytes": zip.len(),
        "digest": format!("sha256:{}", String::from(hash_bytes(zip))),
        "workflow_run": {
            "id": 123456,
            "repository_id": 44,
            "head_repository_id": 44,
            "head_sha": SOURCE
        }
    });
    let spec =
        validate_native_run_platform_provenance(&envelope, &origin, &run, &jobs, &artifact, zip)
            .unwrap();
    assert_eq!(spec.target, TARGET);
    let mut collecting_run = run.clone();
    collecting_run["status"] = serde_json::json!("in_progress");
    collecting_run["conclusion"] = serde_json::Value::Null;
    assert!(
        validate_native_run_platform_provenance(
            &envelope,
            &origin,
            &collecting_run,
            &jobs,
            &artifact,
            zip,
        )
        .is_ok(),
        "a downstream collector must accept a completed producer job while its workflow runs"
    );
    let mut unfinished_job = jobs.clone();
    unfinished_job["jobs"][0]["status"] = serde_json::json!("in_progress");
    unfinished_job["jobs"][0]["conclusion"] = serde_json::Value::Null;
    assert!(
        validate_native_run_platform_provenance(
            &envelope,
            &origin,
            &collecting_run,
            &unfinished_job,
            &artifact,
            zip,
        )
        .is_err(),
        "an unfinished producer cannot authenticate its own artifact"
    );
    let mut failed_job = jobs.clone();
    failed_job["jobs"][0]["conclusion"] = serde_json::json!("failure");
    assert!(
        validate_native_run_platform_provenance(
            &envelope,
            &origin,
            &collecting_run,
            &failed_job,
            &artifact,
            zip,
        )
        .is_err(),
        "an unsuccessful producer cannot authenticate its artifact"
    );
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default()
        .system(zip::System::Unix)
        .unix_permissions(0o644);
    writer
        .start_file("private-native-run-v2.json", options)
        .unwrap();
    writer
        .write_all(&serde_json::to_vec(&envelope).unwrap())
        .unwrap();
    for (path, raw) in &attachments {
        writer.start_file(path, options).unwrap();
        writer.write_all(raw).unwrap();
    }
    let real_zip = writer.finish().unwrap().into_inner();
    let mut real_artifact = artifact.clone();
    real_artifact["size_in_bytes"] = serde_json::json!(real_zip.len());
    real_artifact["digest"] =
        serde_json::json!(format!("sha256:{}", String::from(hash_bytes(&real_zip))));
    let verified = validate_native_artifact_zip(
        &real_zip,
        &expected(&envelope),
        &origin,
        &run,
        &jobs,
        &real_artifact,
    )
    .unwrap();
    assert_eq!(verified.envelope, envelope);
    assert_eq!(verified.producer.target, TARGET);
    assert_eq!(verified.attachment_count(), attachments.len());
    for (path, bytes) in &attachments {
        assert_eq!(verified.attachment(path), Some(bytes.as_slice()));
    }
    let mut substituted_artifact = real_artifact.clone();
    substituted_artifact["digest"] =
        serde_json::json!(format!("sha256:{}", String::from(hash_bytes(b"other ZIP"))));
    assert!(
        validate_native_artifact_zip(
            &real_zip,
            &expected(&envelope),
            &origin,
            &run,
            &jobs,
            &substituted_artifact,
        )
        .is_err()
    );
    let mut unsafe_writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    unsafe_writer
        .start_file("private-native-run-v2.json", options)
        .unwrap();
    unsafe_writer
        .write_all(&serde_json::to_vec(&envelope).unwrap())
        .unwrap();
    for (index, (path, raw)) in attachments.iter().enumerate() {
        let name = if index == 0 { "../escaped" } else { path };
        unsafe_writer.start_file(name, options).unwrap();
        unsafe_writer.write_all(raw).unwrap();
    }
    let unsafe_zip = unsafe_writer.finish().unwrap().into_inner();
    let mut unsafe_artifact = real_artifact.clone();
    unsafe_artifact["size_in_bytes"] = serde_json::json!(unsafe_zip.len());
    unsafe_artifact["digest"] =
        serde_json::json!(format!("sha256:{}", String::from(hash_bytes(&unsafe_zip))));
    assert!(
        validate_native_artifact_zip(
            &unsafe_zip,
            &expected(&envelope),
            &origin,
            &run,
            &jobs,
            &unsafe_artifact,
        )
        .is_err()
    );
    let mut wrong_run = run.clone();
    wrong_run["path"] = serde_json::json!(".github/workflows/release.yml@other-tag");
    assert!(
        validate_native_run_platform_provenance(
            &envelope, &origin, &wrong_run, &jobs, &artifact, zip,
        )
        .is_err()
    );
    let mut arm_envelope = envelope.clone();
    arm_envelope.target = "aarch64-unknown-linux-gnu".into();
    arm_envelope.native_machine = "aarch64".into();
    let mut arm_jobs = jobs.clone();
    arm_jobs["jobs"][0]["name"] = serde_json::json!("Release / Linux private candidate / arm64");
    arm_jobs["jobs"][0]["labels"] = serde_json::json!(["ubuntu-24.04-arm"]);
    let mut arm_artifact = artifact.clone();
    arm_artifact["name"] = serde_json::json!("release-private-candidate-arm64");
    assert_eq!(
        validate_native_run_platform_provenance(
            &arm_envelope,
            &origin,
            &run,
            &arm_jobs,
            &arm_artifact,
            zip,
        )
        .unwrap()
        .runner_label,
        "ubuntu-24.04-arm"
    );
    let mut final_envelope = envelope.clone();
    final_envelope.stage = NativeRunStageV2::FinalPublic;
    final_envelope.workflow_job = "linux-private-final".into();
    final_envelope.candidate_installed = None;
    final_envelope.final_installed = Some(FinalInstalledBindingV2 {
        archive_sha256: digest(10),
        runtime_manifest_sha256: digest(11),
        installed_receipt_sha256: digest(12),
    });
    let mut final_jobs = jobs.clone();
    final_jobs["jobs"][0]["name"] = serde_json::json!("Release / Linux private final / x64");
    let mut final_artifact = artifact.clone();
    final_artifact["name"] = serde_json::json!("release-private-final-x64");
    assert_eq!(
        validate_native_run_platform_provenance(
            &final_envelope,
            &origin,
            &run,
            &final_jobs,
            &final_artifact,
            zip,
        )
        .unwrap()
        .stage,
        NativeRunStageV2::FinalPublic
    );
    let mut wrong_job = jobs.clone();
    wrong_job["jobs"][0]["name"] = serde_json::json!("Release / Linux private candidate / arm64");
    assert!(
        validate_native_run_platform_provenance(
            &envelope, &origin, &run, &wrong_job, &artifact, zip,
        )
        .is_err()
    );
    assert!(
        validate_native_run_platform_provenance(
            &envelope,
            &origin,
            &run,
            &jobs,
            &artifact,
            b"different ZIP bytes",
        )
        .is_err()
    );
    let mut wrong_artifact = artifact.clone();
    wrong_artifact["workflow_run"]["id"] = serde_json::json!(123457);
    assert!(
        validate_native_run_platform_provenance(
            &envelope,
            &origin,
            &run,
            &jobs,
            &wrong_artifact,
            zip,
        )
        .is_err()
    );
    wrong_artifact = artifact.clone();
    wrong_artifact["workflow_run"]["head_repository_id"] = serde_json::json!(45);
    assert!(
        validate_native_run_platform_provenance(
            &envelope,
            &origin,
            &run,
            &jobs,
            &wrong_artifact,
            zip,
        )
        .is_err()
    );
}
