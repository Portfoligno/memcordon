use crate::request::{
    CallerExecutionEnvelopeV2, DeadlineScope, DescriptorPurpose, FileIdentity,
    LaunchBrokerRequestV2, LaunchPolicyV2, LaunchRequestV2, Lifetime, NamespaceIdentity,
    RequestCodecError, SwapLimit, decode_launch_broker_request, decode_launch_request,
    encode_launch_broker_request, encode_launch_request,
};
use sha2::{Digest, Sha256};

fn request() -> LaunchRequestV2 {
    LaunchRequestV2 {
        restart_attempt: 0,
        workload_contract: None,
        program: b"/usr/bin/printf".to_vec(),
        arguments: vec![b"%s".to_vec(), b"native argument".to_vec()],
        environment: vec![(b"LANG".to_vec(), b"C".to_vec())],
        policy: LaunchPolicyV2 {
            memory_limit_bytes: Some(1024),
            swap_limit: SwapLimit::Bytes(0),
            absolute_deadline_millis: Some(50_000),
            deadline_scope: DeadlineScope::Supervision,
            lifetime: Lifetime::Workload,
            poll_interval_millis: 10,
            signal_grace_millis: 1_000,
            command_exit_grace_millis: 2_000,
            limit_grace_millis: 3_000,
        },
        descriptors: vec![
            DescriptorPurpose::CurrentDirectory,
            DescriptorPurpose::Stdin,
            DescriptorPurpose::Stdout,
            DescriptorPurpose::Stderr,
            DescriptorPurpose::FrontendLiveness,
        ],
    }
}

#[test]
fn launch_request_round_trips_native_counted_values() {
    let request = request();
    let encoded = encode_launch_request(&request).unwrap();
    assert_eq!(decode_launch_request(&encoded).unwrap(), request);
}

#[test]
fn descriptor_inventory_is_exact_and_ordered() {
    let mut request = request();
    request.descriptors.swap(1, 2);
    assert_eq!(
        encode_launch_request(&request),
        Err(RequestCodecError::InvalidValue)
    );
}

#[test]
fn truncated_and_trailing_payloads_fail_closed() {
    let encoded = encode_launch_request(&request()).unwrap();
    assert_eq!(
        decode_launch_request(&encoded[..encoded.len() - 1]),
        Err(RequestCodecError::Truncated)
    );
    let mut trailing = encoded;
    trailing.push(0);
    assert_eq!(
        decode_launch_request(&trailing),
        Err(RequestCodecError::TrailingBytes)
    );
}

fn caller_envelope() -> CallerExecutionEnvelopeV2 {
    let namespace = |device, inode| NamespaceIdentity { device, inode };
    CallerExecutionEnvelopeV2 {
        pid: 41,
        process_start_time: 99,
        uid: 1_000,
        gid: 1_000,
        supplementary_groups: vec![4, 27, 1_000],
        no_new_privs: true,
        capability_bounding_set: 0x0000_0000_a804_25fb,
        mount_namespace_identity: namespace(1, 2),
        pid_namespace_identity: namespace(3, 4),
        user_namespace_identity: namespace(5, 6),
        network_namespace_identity: namespace(7, 8),
        ipc_namespace_identity: namespace(9, 10),
        uts_namespace_identity: namespace(11, 12),
        time_namespace_identity: namespace(13, 14),
        current_directory_identity: FileIdentity {
            device: 15,
            inode: 16,
        },
        root_identity: FileIdentity {
            device: 17,
            inode: 18,
        },
    }
}

fn broker_manifest() -> Vec<DescriptorPurpose> {
    vec![
        DescriptorPurpose::CurrentDirectory,
        DescriptorPurpose::Stdin,
        DescriptorPurpose::Stdout,
        DescriptorPurpose::Stderr,
        DescriptorPurpose::FrontendLiveness,
        DescriptorPurpose::CallerMountNamespace,
        DescriptorPurpose::CallerRoot,
    ]
}

fn broker_request() -> LaunchBrokerRequestV2 {
    let launch = request();
    let request_digest: [u8; 32] =
        Sha256::digest(encode_launch_request(&launch).expect("public request encodes")).into();
    LaunchBrokerRequestV2::authenticated(
        [0x5a; 16],
        request_digest,
        73,
        99,
        launch,
        caller_envelope(),
        broker_manifest(),
    )
    .expect("broker request binds")
}

#[test]
fn broker_request_round_trips_canonical_caller_envelope() {
    let request = broker_request();
    let encoded = encode_launch_broker_request(&request).expect("broker request encodes");
    let decoded = decode_launch_broker_request(&encoded).expect("broker request decodes");
    assert_eq!(decoded, request);
    assert_eq!(decoded.caller.digest_hex().len(), 64);
}

#[test]
fn broker_request_rejects_digest_tampering_and_noncanonical_descriptor_inventory() {
    let request = broker_request();
    let mut encoded = encode_launch_broker_request(&request).expect("broker request encodes");
    let final_byte = encoded
        .last_mut()
        .expect("encoded broker request cannot be empty");
    *final_byte ^= 1;
    assert!(decode_launch_broker_request(&encoded).is_err());

    let mut invalid = request;
    invalid.descriptor_manifest.swap(0, 1);
    assert!(encode_launch_broker_request(&invalid).is_err());
}

#[test]
fn private_forwarding_keeps_native_broker_and_public_envelope_digests_distinct() {
    use memcordon_core::private_runtime::PrivateRuntimeRequest;
    use memcordon_core::workload_contract::WorkloadContractV2;
    let launch = request();
    let public = PrivateRuntimeRequest {
        format: "memcordon.private-runtime-request".into(),
        revision: 1,
        contract: WorkloadContractV2::parse(include_bytes!(
            "../../../../fuzz/corpus/workload-request/baseline-v2.json"
        ))
        .unwrap(),
        native_launch: encode_launch_request(&launch).unwrap(),
        attempt_deadline_millis: None,
    };
    let payload = public.encode().unwrap();
    let expected_native: [u8; 32] = Sha256::digest(&public.native_launch).into();
    let expected_public: [u8; 32] = Sha256::digest(&payload).into();
    assert_ne!(expected_native, expected_public);
    // The old forwarding call used the outer digest; the retained native
    // broker validator must continue rejecting that byte-domain substitution.
    assert_eq!(
        LaunchBrokerRequestV2::authenticated(
            [0x5a; 16],
            expected_public,
            73,
            99,
            launch.clone(),
            caller_envelope(),
            broker_manifest(),
        ),
        Err(RequestCodecError::InvalidValue)
    );
    let (broker, outer) = LaunchBrokerRequestV2::authenticated_private(
        [0x5a; 16],
        &payload,
        73,
        99,
        launch,
        caller_envelope(),
        broker_manifest(),
    )
    .unwrap();
    let decoded =
        decode_launch_broker_request(&encode_launch_broker_request(&broker).unwrap()).unwrap();
    assert_eq!(decoded, broker);
    assert_eq!(decoded.request_digest, expected_native);
    assert_eq!(
        outer,
        memcordon_core::DiagnosticSha256::from_bytes(expected_public)
    );
}

#[test]
fn private_reply_binding_rejects_native_digest_in_place_of_public_envelope_digest() {
    use memcordon_core::private_runtime::{
        PrivateRuntimeRejection, PrivateRuntimeRequest, PrivateRuntimeTerminal,
    };
    use memcordon_core::result_v1::{CleanupStateV1, LaunchStateV1, OutcomeKindV1};
    use memcordon_core::workload_admission_v2::RuntimePrivateAdmissionSnapshot;
    use memcordon_core::workload_contract::{Nonce128, WorkloadContractV2};
    use memcordon_core::workload_registry::CallerSelector;
    use memcordon_core::workload_registry_v2::ProfileKindV2;
    use memcordon_core::{BoundedText, DiagnosticSha256, PublicProviderBindingV1};
    let launch = request();
    let mut contract = WorkloadContractV2::parse(include_bytes!(
        "../../../../fuzz/corpus/workload-request/baseline-v2.json"
    ))
    .unwrap();
    contract.authorized_profile = ProfileKindV2::LinuxTcp4PrivateV1.reference();
    contract.ceiling = ProfileKindV2::LinuxTcp4PrivateV1.ceiling();
    contract.requirements = Default::default();
    let public = PrivateRuntimeRequest {
        format: "memcordon.private-runtime-request".into(),
        revision: 1,
        contract: contract.clone(),
        native_launch: encode_launch_request(&launch).unwrap(),
        attempt_deadline_millis: None,
    };
    let payload = public.encode().unwrap();
    let expected_public = DiagnosticSha256::from_bytes(Sha256::digest(&payload).into());
    let expected_native =
        DiagnosticSha256::from_bytes(Sha256::digest(&public.native_launch).into());
    let (broker, public_digest) = LaunchBrokerRequestV2::authenticated_private(
        [0x5a; 16],
        &payload,
        73,
        99,
        launch,
        caller_envelope(),
        broker_manifest(),
    )
    .unwrap();
    assert_eq!(public_digest, expected_public);
    assert_eq!(
        DiagnosticSha256::from_bytes(broker.request_digest),
        expected_native
    );
    let provider = PublicProviderBindingV1 {
        generation: BoundedText::new("1.2.3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
        source_commit: BoundedText::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
        runtime_manifest_sha256: DiagnosticSha256::from_bytes([7; 32]),
    };
    let rejection = PrivateRuntimeRejection {
        format: "memcordon.private-runtime-rejection".into(),
        revision: 1,
        provider: provider.clone(),
        attempt_id: broker.attempt_id,
        request_sha256: public_digest.clone(),
        invocation_sha256: expected_native.clone(),
        contract: contract.clone(),
        boundary_allocated: false,
        reservation_may_remain: false,
        detail: BoundedText::new("native grant denied before allocation").unwrap(),
    };
    let terminal = PrivateRuntimeTerminal {
        format: "memcordon.private-runtime-terminal".into(),
        revision: 1,
        provider: provider.clone(),
        native_abi: "aarch64-unknown-linux-gnu".into(),
        attempt_id: broker.attempt_id,
        request_sha256: public_digest,
        admission_metadata: RuntimePrivateAdmissionSnapshot {
            format: "memcordon.private-admission-metadata".into(),
            revision: 1,
            request_sha256: memcordon_core::workload_codec::contract_digest_v2(&contract).unwrap(),
            invocation_sha256: expected_native.clone(),
            caller: CallerSelector::Linux { uid: 1000 },
            registry_digest: DiagnosticSha256::from_bytes([8; 32]),
            epoch: contract.expected_epoch.clone(),
            admission_nonce: Nonce128([9; 16]),
            profile_id: contract.authorized_profile.clone(),
            request: contract.clone(),
        },
        launch: LaunchStateV1::NotCreated,
        authorization_offset_millis: None,
        authorization_monotonic_millis: None,
        target_pid: None,
        network_namespace: None,
        exec_observed: false,
        post_exec_descriptor_count: None,
        outcome: OutcomeKindV1::LaunchFailure,
        native_termination: None,
        cleanup: CleanupStateV1::Complete,
        account_reservation_retired: true,
        namespace_references_closed: true,
        error: Some(BoundedText::new("actual gated setup rejected").unwrap()),
    };
    let parse_rejection = |value: &PrivateRuntimeRejection| {
        PrivateRuntimeRejection::parse_bound(
            &serde_json::to_vec(value).unwrap(),
            &provider,
            broker.attempt_id,
            &expected_public,
            &contract,
            &expected_native,
        )
    };
    let parse_terminal = |value: &PrivateRuntimeTerminal| {
        PrivateRuntimeTerminal::parse_bound(
            &serde_json::to_vec(value).unwrap(),
            &provider,
            broker.attempt_id,
            &expected_public,
            &contract,
            &expected_native,
        )
    };
    parse_rejection(&rejection).unwrap();
    parse_terminal(&terminal).unwrap();
    let mut wrong_rejection = rejection;
    wrong_rejection.request_sha256 = expected_native.clone();
    assert!(parse_rejection(&wrong_rejection).is_err());
    let mut wrong_terminal = terminal;
    wrong_terminal.request_sha256 = expected_native.clone();
    assert!(parse_terminal(&wrong_terminal).is_err());
}
