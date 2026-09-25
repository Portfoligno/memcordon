use crate::request::{
    CallerExecutionEnvelopeV2, DeadlineScope, DescriptorPurpose, FileIdentity,
    LaunchBrokerRequestV2, LaunchPolicyV2, LaunchRequestV2, Lifetime, NamespaceIdentity,
    NetworkBrokerExchangeError, NetworkLaunchBrokerRequestV4, NetworkLaunchRequestV4,
    RequestCodecError, SwapLimit, decode_launch_broker_request, decode_launch_request,
    decode_network_launch_broker_request, decode_network_launch_request,
    encode_launch_broker_request, encode_launch_request, encode_network_launch_broker_request,
    encode_network_launch_request, parse_network_broker_exchange,
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

fn network_request() -> NetworkLaunchRequestV4 {
    use memcordon_core::workload_contract::{
        AuthorizationRef, ContractVersionTwo, ExecutionIdentityRequestV2, LogicalId, Nonce128,
        PolicyEpoch, WorkloadContractV2,
    };
    use memcordon_core::workload_registry_v2::ProfileKindV2;
    use memcordon_core::{BoundedVec, DiagnosticSha256};
    use std::num::NonZeroU64;

    let digest = DiagnosticSha256::from_bytes([7; 32]);
    let profile = ProfileKindV2::LinuxTcp4PrivateV1;
    NetworkLaunchRequestV4 {
        contract: WorkloadContractV2 {
            schema_version: ContractVersionTwo::default(),
            workload_plan_digest: digest.clone(),
            authorized_profile: profile.reference(),
            authorization: AuthorizationRef {
                grant_id: LogicalId::new("private-grant".into()).unwrap(),
                grant_revision: NonZeroU64::MIN,
                approved_plan_digest: digest.clone(),
            },
            ceiling: profile.ceiling(),
            requirements: BoundedVec::default(),
            endpoints: BoundedVec::default(),
            expected_epoch: PolicyEpoch {
                service_instance: Nonce128([3; 16]),
                revision: NonZeroU64::MIN,
            },
            execution_identity: ExecutionIdentityRequestV2::PreserveCaller,
        },
        registry_digest: DiagnosticSha256::from_bytes([8; 32]),
        qualification_digest: DiagnosticSha256::from_bytes([9; 32]),
        launch: request(),
    }
}

#[test]
fn network_v4_request_round_trips_without_legacy_fallback() {
    let request = network_request();
    let encoded = encode_network_launch_request(&request).unwrap();
    assert_eq!(decode_network_launch_request(&encoded).unwrap(), request);
    assert_eq!(
        decode_launch_request(&encoded),
        Err(RequestCodecError::UnsupportedVersion(4))
    );
    let mut invalid = request;
    invalid.contract.authorized_profile =
        memcordon_core::workload_registry_v2::ProfileKindV2::LinuxUnixCreateV1.reference();
    assert_eq!(
        encode_network_launch_request(&invalid),
        Err(RequestCodecError::InvalidValue)
    );
}

#[test]
fn network_v4_broker_binds_contract_identity_and_exact_descriptor_manifest() {
    let broker = NetworkLaunchBrokerRequestV4::authenticated(
        [0x51; 16],
        memcordon_core::DiagnosticSha256::from_bytes([0x44; 32]),
        73,
        99,
        network_request(),
        caller_envelope(),
    )
    .unwrap();
    let encoded = encode_network_launch_broker_request(&broker).unwrap();
    assert_eq!(
        decode_network_launch_broker_request(&encoded).unwrap(),
        broker
    );
    assert_eq!(
        decode_launch_broker_request(&encoded),
        Err(RequestCodecError::UnsupportedVersion(4))
    );
    let mut altered = broker.clone();
    altered.launch.registry_digest = memcordon_core::DiagnosticSha256::from_bytes([10; 32]);
    assert_eq!(
        encode_network_launch_broker_request(&altered),
        Err(RequestCodecError::InvalidValue)
    );
    let mut wrong_generation = broker.clone();
    wrong_generation.installed_generation_digest =
        memcordon_core::DiagnosticSha256::from_bytes([0x45; 32]);
    assert_eq!(
        encode_network_launch_broker_request(&wrong_generation),
        Err(RequestCodecError::InvalidValue)
    );
    let mut reordered = broker;
    reordered.descriptor_manifest.swap(6, 7);
    assert_eq!(
        encode_network_launch_broker_request(&reordered),
        Err(RequestCodecError::InvalidValue)
    );
}

#[test]
fn network_exchange_rejects_each_unbound_transport_claim_before_allocation() {
    let broker = NetworkLaunchBrokerRequestV4::authenticated(
        [0x51; 16],
        memcordon_core::DiagnosticSha256::from_bytes([0x44; 32]),
        73,
        99,
        network_request(),
        caller_envelope(),
    )
    .unwrap();
    let count = broker.descriptor_manifest.len();
    let encoded = encode_network_launch_broker_request(&broker).unwrap();
    let parse = |payload: &[u8], attempt_id, pid, start, count| {
        parse_network_broker_exchange(payload, attempt_id, pid, start, count)
    };
    assert_eq!(parse(&encoded, [0x51; 16], 73, 99, count), Ok(broker));
    assert_eq!(
        parse(&encoded, [0x52; 16], 73, 99, count),
        Err(NetworkBrokerExchangeError::AttemptBinding)
    );
    assert_eq!(
        parse(&encoded, [0x51; 16], 74, 99, count),
        Err(NetworkBrokerExchangeError::ControlPeerBinding)
    );
    assert_eq!(
        parse(&encoded, [0x51; 16], 73, 100, count),
        Err(NetworkBrokerExchangeError::ControlPeerBinding)
    );
    assert_eq!(
        parse(&encoded, [0x51; 16], 73, 99, count - 1),
        Err(NetworkBrokerExchangeError::DescriptorInventory)
    );
    assert!(matches!(
        parse(&encoded[..encoded.len() - 1], [0x51; 16], 73, 99, count),
        Err(NetworkBrokerExchangeError::Decode(_))
    ));
}
