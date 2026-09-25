#![cfg(target_os = "linux")]

use memcordon_core::{ErrorCategory, InitialSpawnFailure};

#[test]
fn exact_channel_pairing_refuses_both_version_directions_before_authorization() {
    assert!(
        memcordon_platform::test_support::sealed_provider_pairing_is_exact(
            "0.5.2",
            "0.5.2",
            "Cargo CLI",
            "Cargo provider",
        )
        .is_ok()
    );
    for (cli_version, provider_version, cli_channel, provider_channel) in [
        ("0.5.2", "0.5.1", "Cargo CLI", "native provider"),
        ("0.5.1", "0.5.2", "native CLI", "Cargo provider"),
        ("0.5.2", "0.5.1", "native CLI", "native provider"),
        ("0.5.1", "0.5.2", "Cargo CLI", "Cargo provider"),
    ] {
        let error = memcordon_platform::test_support::sealed_provider_pairing_is_exact(
            cli_version,
            provider_version,
            cli_channel,
            provider_channel,
        )
        .expect_err("a cross-version provider must be refused");
        assert!(error.contains(cli_version));
        assert!(error.contains(provider_version));
        assert!(error.contains(cli_channel));
        assert!(error.contains(provider_channel));
        assert!(error.contains("before target authorization"));
        assert!(error.contains("package upgrade"));
    }
}

#[test]
fn missing_provider_names_both_installation_channels_and_companion() {
    let diagnostic = memcordon_platform::test_support::sealed_provider_installation_diagnostic();
    for required in [
        "sealed provider is not installed or reachable",
        "provider endpoint unavailable",
        "Cargo installation:",
        "memcordon-sealed-agent package install",
        "Native archive:",
        "included beside this executable",
    ] {
        assert!(
            diagnostic.contains(required),
            "missing-provider diagnostic omitted {required}"
        );
    }
}

fn terminal(status: i32, exec_status: &str, os_code: &str) -> Vec<u8> {
    const CALLER_ENVELOPE_DIGEST: &str =
        "0000000000000000000000000000000000000000000000000000000000000000";
    const CALLER_CAPABILITY_BOUNDING_SET_DIGEST: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";
    const CALLER_MOUNT_NAMESPACE_DIGEST: &str =
        "2222222222222222222222222222222222222222222222222222222222222222";
    format!(
        concat!(
            "schema-version=2\n",
            "mechanism=linux-pid-namespace-cgroup-v2\n",
            "policy-enforcement={policy_enforcement}\n",
            "status={status}\n",
            "exec-status={exec_status}\n",
            "exec-os-code={os_code}\n",
            "spawn-error-reported=true\n",
            "target-pid=71\n",
            "authorization-offset-millis=9\n",
            "memory-limit-exceeded=false\n",
            "deadline-exceeded=false\n",
            "assignment-verified=true\n",
            "namespaces-verified=true\n",
            "target-initial-credentials-verified=true\n",
            "initial-provider-capabilities-absent=true\n",
            "caller-envelope-digest={caller_envelope_digest}\n",
            "caller-no-new-privs=false\n",
            "target-no-new-privs-matched=true\n",
            "caller-capability-bounding-set-digest={caller_capability_bounding_set_digest}\n",
            "target-capability-bounding-set-matched=true\n",
            "caller-mount-namespace-digest={caller_mount_namespace_digest}\n",
            "target-mount-context-derived-from-caller=true\n",
            "credential-transition-disposition=preserve-caller-envelope\n",
            "boundary-independent-of-credentials=true\n",
            "descriptors-verified=true\n",
            "writable-ancestor-cgroup-denied=true\n",
            "parent-namespace-handles-denied=true\n",
            "recursive-provider-request-denied=true\n",
            "guardian-ready-before-authorization=true\n",
            "frontend-loss-authority-verified=true\n",
            "cgroup-kill-invoked=true\n",
            "cgroup-empty=true\n",
            "init-reaped=true\n",
            "guardian-reaped=true\n",
            "boundary-retired=true\n",
        ),
        status = status,
        exec_status = exec_status,
        os_code = os_code,
        policy_enforcement = serde_json::to_string(
            &memcordon_core::workload_evidence::AttemptPolicyEnforcementV1::LegacyUnspecified,
        )
        .unwrap(),
        caller_envelope_digest = CALLER_ENVELOPE_DIGEST,
        caller_capability_bounding_set_digest = CALLER_CAPABILITY_BOUNDING_SET_DIGEST,
        caller_mount_namespace_digest = CALLER_MOUNT_NAMESPACE_DIGEST,
    )
    .into_bytes()
}

#[test]
fn private_v4_indeterminate_and_rejection_never_create_restart_proof() {
    use memcordon_core::DiagnosticSha256;
    use memcordon_core::workload_evidence_v2::QualifiedNativeAbiV2;
    use memcordon_platform::{
        PrivateExpectedResultV2, PrivateReleaseKnowledgeV2, PrivateReplayDispositionV2,
        private_response_disposition_for_test,
    };

    let attempt = [0x12; 16];
    let digest = DiagnosticSha256::from_bytes([0x34; 32]);
    let expected = PrivateExpectedResultV2 {
        source_commit: "a",
        native_abi: QualifiedNativeAbiV2::X86_64LinuxGnu,
        runtime_manifest_sha256: &digest,
        installed_qualification_sha256: &digest,
    };
    let indeterminate = serde_json::json!({
        "schema_version": 11,
        "attempt_id": "12121212121212121212121212121212",
        "release_knowledge": "possibly-released",
        "retirement_knowledge": "unverified",
        "replay_disposition": "do-not-replay",
        "reason_code": "MCSEALED-PRIVATE-TERMINAL-UNVERIFIED"
    });
    let bytes = serde_json::to_vec(&indeterminate).unwrap();
    let (release, replay, restart_safe, raw) = private_response_disposition_for_test(
        110, [0x56; 16], attempt, [0x56; 16], attempt, &bytes, &expected,
    )
    .unwrap();
    assert_eq!(release, PrivateReleaseKnowledgeV2::PossiblyReleased);
    assert_eq!(replay, PrivateReplayDispositionV2::DoNotReplay);
    assert!(!restart_safe);
    assert_eq!(raw, bytes);

    let swapped_attempt = String::from_utf8(bytes.clone()).unwrap().replace(
        "12121212121212121212121212121212",
        "34343434343434343434343434343434",
    );
    let error = private_response_disposition_for_test(
        110,
        [0x56; 16],
        attempt,
        [0x56; 16],
        attempt,
        swapped_attempt.as_bytes(),
        &expected,
    )
    .expect_err("swapped attempt must be rejected");
    assert_eq!(
        error.release_knowledge(),
        PrivateReleaseKnowledgeV2::PossiblyReleased
    );
    assert_eq!(
        error.replay_disposition(),
        PrivateReplayDispositionV2::DoNotReplay
    );
    assert_eq!(error.raw_response, Some(swapped_attempt.into_bytes()));

    let rejection = br#"{
        "schema_version":1,
        "code":"MCSEALED-PRIVATE-QUALIFICATION",
        "phase":"request-validation",
        "detail":"no installed qualification",
        "os_code":null,
        "target_created":false,
        "target_released":false,
        "cleanup":{"attempted":false,"direct_child_reaped":false,
            "workload_empty":null,"helpers_reaped":false,
            "containment_removed":false,"sealed_boundary_retired":false,"errors":[]}
    }"#;
    let (release, replay, restart_safe, raw) = private_response_disposition_for_test(
        106, [0x56; 16], attempt, [0x56; 16], attempt, rejection, &expected,
    )
    .unwrap();
    assert_eq!(release, PrivateReleaseKnowledgeV2::NotReleased);
    assert_eq!(
        replay,
        PrivateReplayDispositionV2::NewAttemptWithFreshAdmission
    );
    assert!(!restart_safe);
    assert_eq!(raw, rejection);

    let error = private_response_disposition_for_test(
        106, [0x56; 16], attempt, [0x57; 16], attempt, rejection, &expected,
    )
    .expect_err("response nonce mismatch must reject even a valid rejection");
    assert_eq!(
        error.replay_disposition(),
        PrivateReplayDispositionV2::DoNotReplay
    );
}

#[test]
fn private_v4_terminal_needs_exact_installed_binding_and_retirement() {
    use std::num::NonZeroU64;

    use memcordon_core::report_v11::{
        PRIVATE_EXECUTION_REPORT_SCHEMA_V11, PrivateExecutionReportV11, PrivateTerminalOutcomeV11,
    };
    use memcordon_core::workload_admission_v2::AttemptBindingV2;
    use memcordon_core::workload_contract::{LogicalId, Nonce128, ProfileRef};
    use memcordon_core::workload_evidence_v2::{
        EntryResourceObservationV2, NamespaceObservationV2, PrivatePortPolicyV1,
        PrivateTcpCheckpointV2, PrivateTcpRetiredV2, QualifiedNativeAbiV2, TargetIdentityKindV2,
        TargetIdentityObservationV2, VerifiedTrue,
    };
    use memcordon_core::{BoundedText, DiagnosticSha256};
    use memcordon_platform::{
        PrivateExpectedResultV2, PrivateReleaseKnowledgeV2, PrivateReplayDispositionV2,
        private_response_disposition_for_test,
    };

    fn digest(byte: u8) -> DiagnosticSha256 {
        DiagnosticSha256::from_bytes([byte; 32])
    }
    fn yes() -> VerifiedTrue {
        VerifiedTrue::observed(true).unwrap()
    }
    let attempt_bytes = [0x12; 16];
    let attempt = AttemptBindingV2 {
        attempt_id: BoundedText::new("12121212121212121212121212121212").unwrap(),
        admission_digest: digest(7),
        caller_envelope_digest: digest(8),
        native_invocation_digest: digest(9),
    };
    let checkpoint = PrivateTcpCheckpointV2 {
        attempt_binding: attempt.canonical_digest().unwrap(),
        profile: ProfileRef {
            id: LogicalId::new("linux-tcp4-private-v1".into()).unwrap(),
            semantic_digest: digest(2),
        },
        identity: TargetIdentityObservationV2 {
            kind: TargetIdentityKindV2::PreserveCaller,
            entrypoint_digest: digest(3),
            exact_credentials_verified: yes(),
            no_new_privileges_verified: yes(),
            capability_sets_empty: yes(),
            bounding_set_empty: yes(),
        },
        caller_envelope_reference: Nonce128([4; 16]),
        target_network_namespace: NamespaceObservationV2::observed(
            NonZeroU64::new(11).unwrap(),
            NonZeroU64::new(22).unwrap(),
            true,
            true,
        )
        .unwrap(),
        topology_digest: digest(5),
        filter_digest: digest(6),
        native_abi: QualifiedNativeAbiV2::X86_64LinuxGnu,
        port_policy: PrivatePortPolicyV1::observed(0, 32768, 60999, true).unwrap(),
        resources: EntryResourceObservationV2::observed(5, 3, true, true, true, true, true)
            .unwrap(),
        guardian_verified: yes(),
        epoch_revalidated: yes(),
        checkpoint_durable: yes(),
    };
    let retirement =
        PrivateTcpRetiredV2::observed(&checkpoint, true, true, true, true, true, true).unwrap();
    let report = PrivateExecutionReportV11 {
        schema_version: PRIVATE_EXECUTION_REPORT_SCHEMA_V11,
        source_commit: "a".repeat(40),
        native_abi: QualifiedNativeAbiV2::X86_64LinuxGnu,
        runtime_manifest_sha256: digest(10),
        installed_qualification_sha256: digest(11),
        attempt,
        checkpoint,
        retirement,
        terminal_receipt_sha256: digest(12),
        outcome: PrivateTerminalOutcomeV11::Exited { code: 0 },
    };
    let bytes = serde_json::to_vec(&report).unwrap();
    let expected = PrivateExpectedResultV2 {
        source_commit: &report.source_commit,
        native_abi: report.native_abi,
        runtime_manifest_sha256: &report.runtime_manifest_sha256,
        installed_qualification_sha256: &report.installed_qualification_sha256,
    };
    let (release, replay, restart_safe, raw) = private_response_disposition_for_test(
        105,
        [0x56; 16],
        attempt_bytes,
        [0x56; 16],
        attempt_bytes,
        &bytes,
        &expected,
    )
    .unwrap();
    assert_eq!(release, PrivateReleaseKnowledgeV2::Released);
    assert_eq!(replay, PrivateReplayDispositionV2::QuerySameAttemptOnly);
    assert!(restart_safe);
    assert_eq!(raw, bytes);

    let wrong_manifest = digest(99);
    let swapped_expected = PrivateExpectedResultV2 {
        runtime_manifest_sha256: &wrong_manifest,
        ..expected
    };
    let error = private_response_disposition_for_test(
        105,
        [0x56; 16],
        attempt_bytes,
        [0x56; 16],
        attempt_bytes,
        &bytes,
        &swapped_expected,
    )
    .expect_err("swapped installed manifest must be rejected");
    assert_eq!(
        error.release_knowledge(),
        PrivateReleaseKnowledgeV2::PossiblyReleased
    );
    assert_eq!(
        error.replay_disposition(),
        PrivateReplayDispositionV2::DoNotReplay
    );

    let mut unretired = serde_json::to_value(&report).unwrap();
    unretired["retirement"]["provider_network_references_closed"] = serde_json::json!(false);
    let unretired = serde_json::to_vec(&unretired).unwrap();
    assert!(
        private_response_disposition_for_test(
            105,
            [0x56; 16],
            attempt_bytes,
            [0x56; 16],
            attempt_bytes,
            &unretired,
            &expected,
        )
        .is_err()
    );
}

fn revoked_terminal() -> Vec<u8> {
    use memcordon_core::workload_contract::*;
    use memcordon_core::workload_evidence::*;
    use memcordon_core::workload_registry::*;
    use memcordon_core::{BoundedText, DiagnosticSha256};
    use std::num::NonZeroU64;
    let digest = DiagnosticSha256::from_bytes([7; 32]);
    let profile = BaselineProfile::LinuxUnixCreate;
    let request = WorkloadContractV1 {
        schema_version: Default::default(),
        workload_plan_digest: digest.clone(),
        authorized_profile: profile.reference(),
        authorization: AuthorizationRef {
            grant_id: LogicalId::new("revocation-grant".to_owned()).unwrap(),
            grant_revision: NonZeroU64::MIN,
            approved_plan_digest: digest.clone(),
        },
        ceiling: profile.ceiling(),
        requirements: Default::default(),
        endpoints: Default::default(),
        expected_epoch: PolicyEpoch {
            service_instance: Nonce128([3; 16]),
            revision: NonZeroU64::MIN,
        },
    };
    let snapshot = ProviderAdmissionSnapshotV1 {
        request_digest: memcordon_core::workload_codec::contract_digest(&request).unwrap(),
        request,
        registry_digest: digest.clone(),
        qualification_digest: digest.clone(),
        admission_nonce: Nonce128([4; 16]),
        caller_invocation_reference: Nonce128([5; 16]),
        private_invocation_digest: digest.clone(),
        caller: CallerSelector::Linux { uid: 1000 },
        native_profile: profile,
    };
    let source = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let binding = AttemptBindingV1::from_snapshot(
        &snapshot,
        memcordon_core::PublicProviderBindingV1 {
            generation: BoundedText::new(&format!("0.5.3-dev:{source}")).unwrap(),
            source_commit: BoundedText::new(source).unwrap(),
            runtime_manifest_sha256: digest,
        },
        BoundedText::new("boot-a").unwrap(),
        BoundedText::new("attempt-a").unwrap(),
        1,
    )
    .unwrap();
    let checkpoint = VerifiedCheckpointV1::observed(
        &binding,
        baseline_observation(profile),
        true,
        true,
        true,
        true,
        true,
        true,
    )
    .unwrap();
    let enforcement = AttemptPolicyEnforcementV1::retired(binding, checkpoint, true, true).unwrap();
    let ordinary = String::from_utf8(terminal(0, "success", "none")).unwrap();
    let mut payload = String::new();
    for line in ordinary.lines() {
        if line.starts_with("policy-enforcement=") {
            payload.push_str("policy-enforcement=");
            payload.push_str(&serde_json::to_string(&enforcement).unwrap());
        } else if line == "status=0" {
            payload.push_str("status=none\npolicy-revoked=true");
        } else {
            payload.push_str(line);
        }
        payload.push('\n');
    }
    payload.into_bytes()
}

#[test]
fn policy_revocation_preserves_authorized_attempt_and_verified_retirement() {
    let payload = revoked_terminal();
    let error =
        memcordon_platform::test_support::sealed_terminal_revocation_error(&payload).unwrap();
    assert_eq!(error.category, ErrorCategory::Monitor);
    assert_eq!(error.code, "MCSEALED-POLICY-DRIFT");
    assert!(error.target_released);
    assert_eq!(error.target_pid, Some(71));
    assert_eq!(
        error.authorization_offset,
        Some(std::time::Duration::from_millis(9))
    );
    let expected_policy = std::str::from_utf8(&payload)
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("policy-enforcement="))
        .unwrap();
    assert_eq!(
        error.policy_enforcement,
        Some(serde_json::from_str(expected_policy).unwrap())
    );
    assert!(error.cleanup.direct_child_reaped);
    assert_eq!(error.cleanup.workload_empty, Some(true));
    assert!(!error.workload_may_be_alive);
    assert!(
        error
            .restart_safety
            .unwrap()
            .is_safe_for(memcordon_core::BoundaryRequirement::Sealed)
    );
    let text = String::from_utf8(payload).unwrap();
    for (from, to) in [
        ("status=none", "status=0"),
        ("policy-revoked=true", "policy-revoked=false"),
        ("policy-revoked=true", "policy-revoked=invalid"),
        ("deadline-exceeded=false", "deadline-exceeded=true"),
        ("cgroup-empty=true", "cgroup-empty=false"),
        ("init-reaped=true", "init-reaped=false"),
        ("guardian-reaped=true", "guardian-reaped=false"),
        ("boundary-retired=true", "boundary-retired=false"),
        (
            "\"controls_preserved\":true",
            "\"controls_preserved\":false",
        ),
        (
            "\"provider_resources_closed\":true",
            "\"provider_resources_closed\":false",
        ),
    ] {
        assert!(text.contains(from), "missing mutation source {from}");
        assert!(
            memcordon_platform::test_support::sealed_terminal_revocation_error(
                text.replace(from, to).as_bytes()
            )
            .is_err(),
            "accepted {to}"
        );
    }
    let legacy = serde_json::to_string(
        &memcordon_core::workload_evidence::AttemptPolicyEnforcementV1::LegacyUnspecified,
    )
    .unwrap();
    let mut unbound = String::new();
    for line in text.lines() {
        if line.starts_with("policy-enforcement=") {
            unbound.push_str("policy-enforcement=");
            unbound.push_str(&legacy);
        } else {
            unbound.push_str(line);
        }
        unbound.push('\n');
    }
    assert!(
        memcordon_platform::test_support::sealed_terminal_revocation_error(unbound.as_bytes())
            .is_err()
    );
}

#[test]
fn genuine_native_exit_126_and_127_are_not_spawn_failures() {
    for status in [126, 127] {
        let error = memcordon_platform::test_support::sealed_terminal_spawn_error(&terminal(
            status, "success", "none",
        ))
        .unwrap();
        assert!(error.is_none());
    }
}

#[test]
fn enoent_and_eacces_retain_typed_authenticated_spawn_provenance() {
    for (os_code, status, exec_status, code, initial) in [
        (
            libc::ENOENT,
            127,
            "not-found",
            "MCSPAWN-NOT-FOUND",
            InitialSpawnFailure::NotFound,
        ),
        (
            libc::EACCES,
            126,
            "not-executable",
            "MCSPAWN-NOT-EXECUTABLE",
            InitialSpawnFailure::NotExecutable,
        ),
    ] {
        let error = memcordon_platform::test_support::sealed_terminal_spawn_error(&terminal(
            status,
            exec_status,
            &os_code.to_string(),
        ))
        .unwrap()
        .expect("typed exec failure must become a categorized error");
        assert_eq!(error.category, ErrorCategory::Spawn);
        assert_eq!(error.code, code);
        assert_eq!(error.os_code, Some(os_code));
        assert_eq!(error.initial_spawn_failure, Some(initial));
        assert_eq!(error.launch_phase, Some("target-spawn-failed"));
        assert!(error.target_released);
        assert_eq!(error.target_pid, Some(71));
        assert!(error.authorization_offset.is_some());
        assert!(error.cgroup_verified_before_release);
        assert!(error.guardian_ready_before_release);
        assert!(!error.workload_may_be_alive);
        let rejection = error
            .provider_rejection
            .expect("authenticated terminal provenance must remain in the report");
        assert_eq!(rejection.code, code);
        assert_eq!(rejection.os_code, Some(os_code));
        assert!(rejection.target_created);
        assert!(rejection.target_released);
        assert!(rejection.restart_safety.sealed_boundary_retired);
    }
}

#[test]
fn request_validation_rejection_is_typed_and_unknown_phases_fail_closed() {
    let payload = br#"{
        "schema_version": 1,
        "code": "MCSEALED-PACKAGE-LEASE",
        "phase": "request-validation",
        "detail": "stable package lease is unavailable",
        "os_code": 30,
        "target_created": false,
        "target_released": false,
        "cleanup": {
            "attempted": false,
            "direct_child_reaped": false,
            "workload_empty": null,
            "helpers_reaped": false,
            "containment_removed": false,
            "sealed_boundary_retired": false,
            "errors": []
        }
    }"#;
    let rejection = memcordon_platform::test_support::sealed_rejection_v1(payload)
        .expect("request-validation must be part of the strict provider vocabulary");
    assert_eq!(rejection.code, "MCSEALED-PACKAGE-LEASE");
    assert_eq!(
        rejection.phase,
        memcordon_core::BoundarySetupPhase::RequestValidation
    );
    assert_eq!(rejection.detail, "stable package lease is unavailable");
    assert_eq!(rejection.os_code, Some(30));
    assert!(!rejection.target_created);
    assert!(!rejection.target_released);
    assert!(!rejection.cleanup_attempted);
    assert_eq!(
        rejection.restart_safety,
        memcordon_core::RestartSafetyProof::default()
    );

    let unknown = String::from_utf8(payload.to_vec())
        .unwrap()
        .replace("request-validation", "future-request-validation");
    assert!(
        memcordon_platform::test_support::sealed_rejection_v1(unknown.as_bytes())
            .unwrap_err()
            .contains("unknown variant")
    );
}

#[test]
fn terminal_spawn_provenance_is_strict_and_fail_closed() {
    let missing_schema = String::from_utf8(terminal(0, "success", "none"))
        .unwrap()
        .replace("schema-version=2\n", "");
    assert!(
        memcordon_platform::test_support::sealed_terminal_v2_is_valid(missing_schema.as_bytes())
            .unwrap_err()
            .contains("schema-version missing")
    );

    let wrong_schema = String::from_utf8(terminal(0, "success", "none"))
        .unwrap()
        .replace("schema-version=2", "schema-version=1");
    assert!(
        memcordon_platform::test_support::sealed_terminal_v2_is_valid(wrong_schema.as_bytes())
            .unwrap_err()
            .contains("incompatible")
    );

    let missing_mechanism = String::from_utf8(terminal(0, "success", "none"))
        .unwrap()
        .replace("mechanism=linux-pid-namespace-cgroup-v2\n", "");
    assert!(
        memcordon_platform::test_support::sealed_terminal_v2_is_valid(missing_mechanism.as_bytes())
            .unwrap_err()
            .contains("mechanism missing")
    );

    let wrong_mechanism = String::from_utf8(terminal(0, "success", "none"))
        .unwrap()
        .replace(
            "mechanism=linux-pid-namespace-cgroup-v2",
            "mechanism=legacy-credential-boundary",
        );
    assert!(
        memcordon_platform::test_support::sealed_terminal_v2_is_valid(wrong_mechanism.as_bytes())
            .unwrap_err()
            .contains("incompatible")
    );

    let mut obsolete_v1_field = terminal(0, "success", "none");
    obsolete_v1_field.extend_from_slice(b"credentials-verified=true\n");
    assert!(
        memcordon_platform::test_support::sealed_terminal_v2_is_valid(&obsolete_v1_field)
            .unwrap_err()
            .contains("unknown fields")
    );

    let mut unknown_field = terminal(0, "success", "none");
    unknown_field.extend_from_slice(b"unexpected-proof=true\n");
    assert!(
        memcordon_platform::test_support::sealed_terminal_v2_is_valid(&unknown_field)
            .unwrap_err()
            .contains("unknown fields")
    );

    let invalid_digest = String::from_utf8(terminal(0, "success", "none"))
        .unwrap()
        .replace(
            "caller-envelope-digest=0000000000000000000000000000000000000000000000000000000000000000",
            "caller-envelope-digest=not-a-sha256-digest",
        );
    assert!(
        memcordon_platform::test_support::sealed_terminal_v2_is_valid(invalid_digest.as_bytes())
            .unwrap_err()
            .contains("digest is invalid")
    );

    let mismatch = terminal(126, "not-found", &libc::ENOENT.to_string());
    assert!(
        memcordon_platform::test_support::sealed_terminal_spawn_error(&mismatch)
            .unwrap_err()
            .contains("child status")
    );

    let wrong_class = terminal(126, "not-executable", &libc::ENOENT.to_string());
    assert!(
        memcordon_platform::test_support::sealed_terminal_spawn_error(&wrong_class)
            .unwrap_err()
            .contains("classification mismatch")
    );

    let mut duplicate = terminal(0, "success", "none");
    duplicate.extend_from_slice(b"status=0\n");
    assert!(
        memcordon_platform::test_support::sealed_terminal_spawn_error(&duplicate)
            .unwrap_err()
            .contains("duplicate")
    );

    let mut not_newline_terminated = terminal(0, "success", "none");
    assert_eq!(not_newline_terminated.pop(), Some(b'\n'));
    assert!(
        memcordon_platform::test_support::sealed_terminal_v2_is_valid(&not_newline_terminated)
            .unwrap_err()
            .contains("not newline terminated")
    );

    let omitted_proof = String::from_utf8(terminal(0, "success", "none"))
        .unwrap()
        .replace("spawn-error-reported=true", "spawn-error-reported=false");
    assert!(
        memcordon_platform::test_support::sealed_terminal_spawn_error(omitted_proof.as_bytes())
            .unwrap_err()
            .contains("omitted verified")
    );
}
