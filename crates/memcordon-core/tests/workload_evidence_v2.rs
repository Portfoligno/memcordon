use std::num::NonZeroU64;

use memcordon_core::DiagnosticSha256;
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
fn public_claims_do_not_expose_account_or_executable_path() {
    let json = serde_json::to_string(&checkpoint()).unwrap();
    assert!(!json.contains("uid"));
    assert!(!json.contains("gid"));
    assert!(!json.contains("absolute_path"));
    assert!(!json.contains("argv"));
    assert!(!json.contains("environment"));
}
