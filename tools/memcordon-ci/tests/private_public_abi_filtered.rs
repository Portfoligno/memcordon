use memcordon_ci::private_public_abi_filtered::{
    ExpectedPublicAbiFilteredV1, readback_public_abi_filtered_v1,
};
use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_codec::hash_bytes;
use memcordon_core::workload_contract::{LogicalId, Nonce128, ProfileRef};
use memcordon_core::workload_evidence_v2::{
    EntryResourceObservationV2, NamespaceObservationV2, PrivatePortPolicyV1,
    PrivateTcpCheckpointV2, QualifiedNativeAbiV2, TargetIdentityKindV2,
    TargetIdentityObservationV2, VerifiedTrue,
};
use std::num::NonZeroU64;

fn checkpoint(filter: DiagnosticSha256) -> PrivateTcpCheckpointV2 {
    let yes = || VerifiedTrue::observed(true).unwrap();
    PrivateTcpCheckpointV2 {
        attempt_binding: hash_bytes(b"attempt"),
        profile: ProfileRef {
            id: LogicalId::new("linux-tcp4-private-v1".into()).unwrap(),
            semantic_digest: hash_bytes(b"profile"),
        },
        identity: TargetIdentityObservationV2 {
            kind: TargetIdentityKindV2::PreserveCaller,
            entrypoint_digest: hash_bytes(b"entrypoint"),
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
        topology_digest: hash_bytes(b"topology"),
        filter_digest: filter,
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
fn filtered_target_claim_requires_exact_protected_binding() {
    let challenge = [7_u8; 32];
    let challenge_hex = hex::encode(challenge);
    let key = hash_bytes(b"public-abi-result-key");
    let epoch = hash_bytes(b"public-abi-epoch");
    let h1 = hash_bytes(b"public-abi-h1");
    let filter = hash_bytes(b"public-abi-filter");
    let checkpoint_value = checkpoint(filter.clone());
    let checkpoint_bytes = serde_json::to_vec(&checkpoint_value).unwrap();
    let checkpoint = checkpoint_value.canonical_digest().unwrap();
    let key_hex = String::from(key.clone());
    let epoch_hex = String::from(epoch.clone());
    let h1_hex = String::from(h1.clone());
    let checkpoint_hex = String::from(checkpoint.clone());
    let filter_hex = String::from(filter.clone());
    let report = format!(
        "{{\"schema_version\":1,\"evidence_scope\":\"filtered-public-target-claims-require-kernel-join\",\"challenge\":\"{challenge_hex}\",\"target_pid\":101,\"target_start_time_ticks\":1001,\"target_uid\":1000,\"target_gid\":1000,\"no_new_privs\":true,\"seccomp_mode\":2,\"seccomp_filters\":2,\"native_getpid\":101,\"children\":[{{\"branch\":\"x32\",\"pid\":102,\"start_time_ticks\":1002,\"audit_arch\":3221225534,\"syscall_number\":1073741863,\"terminal_signal\":31,\"helper_device\":null,\"helper_inode\":null}},{{\"branch\":\"i386\",\"pid\":103,\"start_time_ticks\":1003,\"audit_arch\":1073741827,\"syscall_number\":20,\"terminal_signal\":31,\"helper_device\":null,\"helper_inode\":null}}]}}"
    );
    let protected = format!(
        "{{\"schema_version\":1,\"selector\":\"private_tcp::abi_alternate_entry_denied\",\"evidence_scope\":\"service-captured-filtered-target-stdout\",\"result_key\":\"{key_hex}\",\"challenge\":\"{challenge_hex}\",\"boot_id\":\"boot-1\",\"installation_epoch\":\"{epoch_hex}\",\"active_h1_receipt_sha256\":\"{h1_hex}\",\"attempt_id\":\"00112233445566778899aabbccddeeff\",\"target_pid\":101,\"target_start_time_ticks\":1001,\"checkpoint_sha256\":\"{checkpoint_hex}\",\"filter_sha256\":\"{filter_hex}\",\"target_report_sha256\":\"{}\",\"helper_device\":null,\"helper_inode\":null}}",
        String::from(hash_bytes(report.as_bytes()))
    );
    let expected = ExpectedPublicAbiFilteredV1 {
        target: "x86_64-unknown-linux-gnu",
        challenge: &challenge,
        result_key: &key,
        boot_id: "boot-1",
        installation_epoch: &epoch,
        active_h1_receipt_sha256: &h1,
        attempt_id: "00112233445566778899aabbccddeeff",
        target_pid: 101,
        target_start_ticks: 1001,
        target_uid: 1000,
        target_gid: 1000,
        checkpoint_sha256: &checkpoint,
        filter_sha256: &filter,
        network_namespace_inode: 22,
        helper_device: None,
        helper_inode: None,
    };
    let parsed = readback_public_abi_filtered_v1(
        report.as_bytes(),
        protected.as_bytes(),
        &checkpoint_bytes,
        &expected,
    )
    .expect("exact protected target and ordered child claims");
    assert_eq!(parsed.report_sha256, hash_bytes(report.as_bytes()));
    assert_eq!(parsed.protected_sha256, hash_bytes(protected.as_bytes()));
    assert_eq!(parsed.checkpoint_file_sha256, hash_bytes(&checkpoint_bytes));
    let wrong_signal = report.replace("\"terminal_signal\":31", "\"terminal_signal\":0");
    assert!(
        readback_public_abi_filtered_v1(
            wrong_signal.as_bytes(),
            protected.as_bytes(),
            &checkpoint_bytes,
            &expected
        )
        .is_err()
    );
    let wrong_hash = protected.replace(
        &String::from(hash_bytes(report.as_bytes())),
        &hex::encode([0_u8; 32]),
    );
    assert!(
        readback_public_abi_filtered_v1(
            report.as_bytes(),
            wrong_hash.as_bytes(),
            &checkpoint_bytes,
            &expected
        )
        .is_err()
    );
    let wrong_challenge = DiagnosticSha256::from_bytes([9_u8; 32]);
    let wrong_expected = ExpectedPublicAbiFilteredV1 {
        challenge: wrong_challenge.bytes(),
        ..expected
    };
    assert!(
        readback_public_abi_filtered_v1(
            report.as_bytes(),
            protected.as_bytes(),
            &checkpoint_bytes,
            &wrong_expected
        )
        .is_err()
    );
}
