use std::num::NonZeroU64;

use memcordon_core::BoundedText;
use memcordon_core::DiagnosticSha256;
use memcordon_core::report_v11::{
    PRIVATE_EXECUTION_REPORT_SCHEMA_V11, PrivateExecutionReportV11, PrivatePublicOutcomeV11,
    PrivatePublicResultV11, PrivateTerminalOutcomeV11, TrustedPrivateExecutionV11,
};
use memcordon_core::workload_admission_v2::AttemptBindingV2;
use memcordon_core::workload_contract::{LogicalId, Nonce128, ProfileRef};
use memcordon_core::workload_evidence_v2::{
    EntryResourceObservationV2, NamespaceObservationV2, PrivatePortPolicyV1,
    PrivateTcpCheckpointV2, PrivateTcpRetiredV2, QualifiedNativeAbiV2, TargetIdentityKindV2,
    TargetIdentityObservationV2, VerifiedTrue,
};

fn digest(byte: u8) -> DiagnosticSha256 {
    DiagnosticSha256::from_bytes([byte; 32])
}

fn yes() -> VerifiedTrue {
    VerifiedTrue::observed(true).unwrap()
}

fn checkpoint() -> PrivateTcpCheckpointV2 {
    PrivateTcpCheckpointV2 {
        attempt_binding: digest(1),
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
    }
}

#[test]
fn schema11_private_projection_requires_trusted_terminal_and_exact_native_bindings() {
    let attempt = AttemptBindingV2 {
        attempt_id: BoundedText::new("00112233445566778899aabbccddeeff").unwrap(),
        admission_digest: digest(7),
        caller_envelope_digest: digest(8),
        native_invocation_digest: digest(9),
    };
    let checkpoint = PrivateTcpCheckpointV2 {
        attempt_binding: attempt.canonical_digest().unwrap(),
        ..checkpoint()
    };
    let retirement =
        PrivateTcpRetiredV2::observed(&checkpoint, true, true, true, true, true, true).unwrap();
    let outcome = PrivateTerminalOutcomeV11::Exited { code: 0 };
    let report = PrivateExecutionReportV11 {
        schema_version: PRIVATE_EXECUTION_REPORT_SCHEMA_V11,
        source_commit: "a".repeat(40),
        native_abi: QualifiedNativeAbiV2::X86_64LinuxGnu,
        runtime_manifest_sha256: digest(10),
        installed_qualification_sha256: digest(11),
        attempt: attempt.clone(),
        checkpoint: checkpoint.clone(),
        retirement: retirement.clone(),
        terminal_receipt_sha256: digest(12),
        outcome: outcome.clone(),
    };
    let checkpoint_sha256 = checkpoint.canonical_digest().unwrap();
    let retirement_sha256 = retirement.canonical_digest().unwrap();
    let trusted = TrustedPrivateExecutionV11 {
        source_commit: &report.source_commit,
        native_abi: QualifiedNativeAbiV2::X86_64LinuxGnu,
        runtime_manifest_sha256: &report.runtime_manifest_sha256,
        installed_qualification_sha256: &report.installed_qualification_sha256,
        attempt: &attempt,
        checkpoint_sha256: &checkpoint_sha256,
        retirement_sha256: &retirement_sha256,
        terminal_receipt_sha256: &report.terminal_receipt_sha256,
        outcome: &outcome,
    };
    assert_eq!(
        PrivateExecutionReportV11::from_trusted_native(
            checkpoint.clone(),
            retirement.clone(),
            &trusted,
        )
        .unwrap(),
        report
    );
    assert!(
        PrivateExecutionReportV11::from_trusted_native(
            PrivateTcpCheckpointV2 {
                topology_digest: digest(15),
                ..checkpoint.clone()
            },
            retirement.clone(),
            &trusted,
        )
        .is_err()
    );
    let bytes = serde_json::to_vec(&report).unwrap();
    assert_eq!(
        PrivateExecutionReportV11::parse_and_validate(
            &bytes,
            PRIVATE_EXECUTION_REPORT_SCHEMA_V11,
            &trusted,
        )
        .unwrap(),
        report
    );
    assert!(PrivateExecutionReportV11::parse_and_validate(&bytes, 10, &trusted).is_err());

    let mut wrong = serde_json::to_value(&report).unwrap();
    wrong["schema_version"] = serde_json::json!(10);
    assert!(
        PrivateExecutionReportV11::parse_and_validate(
            &serde_json::to_vec(&wrong).unwrap(),
            11,
            &trusted
        )
        .is_err()
    );
    let mut wrong = serde_json::to_value(&report).unwrap();
    wrong["terminal_receipt_sha256"] = serde_json::to_value(digest(13)).unwrap();
    assert!(
        PrivateExecutionReportV11::parse_and_validate(
            &serde_json::to_vec(&wrong).unwrap(),
            11,
            &trusted
        )
        .is_err()
    );
    let mut wrong = serde_json::to_value(&report).unwrap();
    wrong["native_abi"] = serde_json::json!("aarch64-unknown-linux-gnu");
    assert!(
        PrivateExecutionReportV11::parse_and_validate(
            &serde_json::to_vec(&wrong).unwrap(),
            11,
            &trusted
        )
        .is_err()
    );
    let mut wrong = serde_json::to_value(&report).unwrap();
    wrong["attempt"]["admission_digest"] = serde_json::to_value(digest(14)).unwrap();
    assert!(
        PrivateExecutionReportV11::parse_and_validate(
            &serde_json::to_vec(&wrong).unwrap(),
            11,
            &trusted
        )
        .is_err()
    );
    let mut wrong = serde_json::to_value(&report).unwrap();
    wrong["outcome"]["code"] = serde_json::json!(1);
    assert!(
        PrivateExecutionReportV11::parse_and_validate(
            &serde_json::to_vec(&wrong).unwrap(),
            11,
            &trusted
        )
        .is_err()
    );
    let mut wrong = serde_json::to_value(&report).unwrap();
    wrong["checkpoint"]["guardian_verified"] = serde_json::json!(false);
    assert!(
        PrivateExecutionReportV11::parse_and_validate(
            &serde_json::to_vec(&wrong).unwrap(),
            11,
            &trusted
        )
        .is_err()
    );
    let mut wrong = serde_json::to_value(&report).unwrap();
    wrong["retirement"]["checkpoint_digest"] = serde_json::to_value(digest(14)).unwrap();
    assert!(
        PrivateExecutionReportV11::parse_and_validate(
            &serde_json::to_vec(&wrong).unwrap(),
            11,
            &trusted
        )
        .is_err()
    );
    let mut wrong = serde_json::to_value(&report).unwrap();
    wrong["unknown"] = serde_json::json!(true);
    assert!(
        PrivateExecutionReportV11::parse_and_validate(
            &serde_json::to_vec(&wrong).unwrap(),
            11,
            &trusted
        )
        .is_err()
    );
    let raw = String::from_utf8(bytes).unwrap();
    let duplicate = raw.replace(
        "\"schema_version\":11",
        "\"schema_version\":11,\"schema_version\":11",
    );
    assert_ne!(duplicate, raw);
    assert!(
        PrivateExecutionReportV11::parse_and_validate(duplicate.as_bytes(), 11, &trusted).is_err()
    );
    let mut public = PrivatePublicResultV11 {
        schema_version: PRIVATE_EXECUTION_REPORT_SCHEMA_V11,
        result: PrivatePublicOutcomeV11::Complete {
            terminal: Box::new(report.clone()),
            raw_response: serde_json::to_vec(&report).unwrap(),
        },
    };
    public.validate_structure().unwrap();
    if let PrivatePublicOutcomeV11::Complete { raw_response, .. } = &mut public.result {
        *raw_response = br#"{"schema_version":11}"#.to_vec();
    }
    assert!(public.validate_structure().is_err());
}

#[test]
fn checkpoint_preimage_has_independently_constructed_field_order() {
    let checkpoint = checkpoint();
    let mut expected = b"private-tcp-checkpoint-v2\0\0\x01".to_vec();
    expected.extend_from_slice(&[1; 32]);
    let profile_id = b"linux-tcp4-private-v1";
    expected.extend_from_slice(&(profile_id.len() as u16).to_be_bytes());
    expected.extend_from_slice(profile_id);
    expected.extend_from_slice(&[2; 32]);
    expected.push(1); // preserve-caller
    expected.extend_from_slice(&[3; 32]);
    expected.extend_from_slice(&[1; 4]); // exact credentials, NNP, capability sets, bounding set
    expected.extend_from_slice(&[4; 16]);
    expected.extend_from_slice(&11_u64.to_be_bytes());
    expected.extend_from_slice(&22_u64.to_be_bytes());
    expected.extend_from_slice(&[1; 2]); // loopback-only and IPv6 disabled
    expected.extend_from_slice(&[5; 32]);
    expected.extend_from_slice(&[6; 32]);
    expected.push(1); // x86_64 Linux GNU
    expected.extend_from_slice(&0_u16.to_be_bytes());
    expected.extend_from_slice(&32768_u16.to_be_bytes());
    expected.extend_from_slice(&60999_u16.to_be_bytes());
    expected.push(1); // no reserved ports
    expected.extend_from_slice(&[5, 3]); // gated and post-exec descriptor counts
    expected.extend_from_slice(&[1; 5]); // descriptor properties
    expected.extend_from_slice(&[1; 3]); // guardian, epoch and durable checkpoint

    assert_eq!(checkpoint.canonical_preimage().unwrap(), expected);
    let digest: String = checkpoint.canonical_digest().unwrap().into();
    assert_eq!(
        digest,
        "eccea5cc72146be107a5913a0d7a0fb0cc4f53799a0e797b89e2e649ea20f1a4"
    );
}

#[test]
fn terminal_preimage_and_success_require_exact_checkpoint() {
    let checkpoint = checkpoint();
    let retired =
        PrivateTcpRetiredV2::observed(&checkpoint, true, true, true, true, true, true).unwrap();
    assert!(retired.terminal_success(&checkpoint));
    assert!(!retired.terminal_success(&PrivateTcpCheckpointV2 {
        topology_digest: digest(7),
        ..checkpoint.clone()
    }));
    assert!(
        PrivateTcpRetiredV2::observed(&checkpoint, true, true, true, false, true, true,).is_err()
    );

    let mut expected = b"private-tcp-terminal-v2\0\0\x01".to_vec();
    expected.extend_from_slice(&[1; 32]);
    expected.extend_from_slice(checkpoint.canonical_digest().unwrap().bytes());
    expected.extend_from_slice(&[1; 6]);
    assert_eq!(retired.canonical_preimage().unwrap(), expected);
    let digest: String = retired.canonical_digest().unwrap().into();
    assert_eq!(
        digest,
        "7dba00078c910876d8df28169bbb9b16cb78d36a761142854433390c3f26e7f4"
    );
}

#[test]
fn decoded_claims_reject_missing_native_facts_and_wrong_inventories() {
    let checkpoint = checkpoint();
    let mut value = serde_json::to_value(&checkpoint).unwrap();
    assert_eq!(
        serde_json::from_value::<PrivateTcpCheckpointV2>(value.clone()).unwrap(),
        checkpoint
    );

    value["guardian_verified"] = serde_json::json!(false);
    assert!(serde_json::from_value::<PrivateTcpCheckpointV2>(value).is_err());

    let mut value = serde_json::to_value(&checkpoint).unwrap();
    value["resources"]["post_exec_descriptor_count"] = serde_json::json!(4);
    assert!(serde_json::from_value::<PrivateTcpCheckpointV2>(value).is_err());

    let mut value = serde_json::to_value(&checkpoint).unwrap();
    value["target_network_namespace"]["target_network_inode"] = serde_json::json!(11);
    assert!(serde_json::from_value::<PrivateTcpCheckpointV2>(value).is_err());

    let mut value = serde_json::to_value(&checkpoint).unwrap();
    value["unrecognized"] = serde_json::json!(true);
    assert!(serde_json::from_value::<PrivateTcpCheckpointV2>(value).is_err());

    let mut value = serde_json::to_value(&checkpoint).unwrap();
    value["port_policy"]["ephemeral_last"] = serde_json::json!(61000);
    assert!(serde_json::from_value::<PrivateTcpCheckpointV2>(value).is_err());
}

#[test]
fn every_missing_retirement_fact_blocks_terminal_claim() {
    let checkpoint = checkpoint();
    let complete =
        PrivateTcpRetiredV2::observed(&checkpoint, true, true, true, true, true, true).unwrap();
    for missing in 0..6 {
        let mut facts = [true; 6];
        facts[missing] = false;
        assert!(
            PrivateTcpRetiredV2::observed(
                &checkpoint,
                facts[0],
                facts[1],
                facts[2],
                facts[3],
                facts[4],
                facts[5],
            )
            .is_err(),
            "missing retirement fact {missing} must fail"
        );
    }
    for field in [
        "workload_empty",
        "required_helpers_reaped",
        "cgroup_retired",
        "provider_network_references_closed",
        "stdio_and_setup_resources_closed",
        "policy_snapshot_released",
    ] {
        let mut value = serde_json::to_value(&complete).unwrap();
        value[field] = serde_json::json!(false);
        assert!(
            serde_json::from_value::<PrivateTcpRetiredV2>(value).is_err(),
            "false serialized retirement fact {field} must fail"
        );
    }
}

#[test]
fn public_claims_do_not_expose_account_or_executable_path() {
    let json = serde_json::to_string(&checkpoint()).unwrap();
    assert!(!json.contains("uid"));
    assert!(!json.contains("gid"));
    assert!(!json.contains("absolute_path"));
    assert!(!json.contains("argv"));
    assert!(!json.contains("environment"));
}
