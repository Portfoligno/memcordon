use memcordon_core::workload_codec::{contract_digest, decode_contract, encode_contract};
use memcordon_core::workload_contract::*;
use memcordon_core::workload_evidence::*;
use memcordon_core::workload_registry::*;
use memcordon_core::{BoundedText, BoundedVec, DiagnosticSha256, PublicProviderBindingV1};
use sha2::{Digest, Sha256};
use std::num::NonZeroU64;

const CONTRACT_HASH: &str = "44c496721bec21fa8cc0e7e3f9dc1cd14077e263c7c2683f9ea5c2fe25b92b3c";
const REGISTRY_HASH: &str = "a102255bf66093d7b7398a0d92a05b57007fa7cfc8cc70ee661e3e95d638fe76";
const EFFECTIVE_HASH: &str = "2c50d523b361ef9ecb08efea05a7a09ec25fc3e29c6d5d80202d64830c284592";
const ATTEMPT_HASH: &str = "974cebb1ed337a16b68a949070b26a331ad559b5cd32899e40c237941d73d496";
const CHECKPOINT_HASH: &str = "3e68071a6e9971b6e0ac37ac38d43aebcddbad2487939d510e557abe1c9e7eb1";
const CONTRACT: &str = include_str!("fixtures/workload_independent/contract.hex");

fn bytes(hex: &str) -> Vec<u8> {
    let hex = hex.trim();
    assert_eq!(hex.len() % 2, 0);
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

fn id(value: &str) -> LogicalId {
    LogicalId::new(value.into()).unwrap()
}
fn digest(byte: u8) -> DiagnosticSha256 {
    DiagnosticSha256::from_bytes([byte; 32])
}
fn bounded<T, const N: usize>(values: impl IntoIterator<Item = T>) -> BoundedVec<T, N> {
    let mut result = BoundedVec::default();
    for value in values {
        assert!(result.try_push(value).is_ok());
    }
    result
}

fn request() -> WorkloadContractV1 {
    WorkloadContractV1 {
        schema_version: ContractVersionOne::default(),
        workload_plan_digest: digest(0x11),
        authorized_profile: BaselineProfile::LinuxUnixCreate.reference(),
        authorization: AuthorizationRef {
            grant_id: id("grant-a"),
            grant_revision: NonZeroU64::MIN,
            approved_plan_digest: digest(0x11),
        },
        ceiling: BaselineProfile::LinuxUnixCreate.ceiling(),
        requirements: bounded([
            RequirementV1::UnixSocketPair {
                id: id("a-pair"),
                socket_kind: UnixSocketKind::Datagram,
            },
            RequirementV1::UnixSocketCreation {
                id: id("z-create"),
                socket_kind: UnixSocketKind::Stream,
            },
        ]),
        endpoints: BoundedVec::default(),
        expected_epoch: PolicyEpoch {
            service_instance: Nonce128([3; 16]),
            revision: NonZeroU64::MIN,
        },
    }
}

fn registry() -> PolicyRegistryV1 {
    PolicyRegistryV1 {
        schema_version: ContractVersionOne::default(),
        profiles: bounded([ProfileDefinitionV1 {
            profile: BaselineProfile::LinuxUnixCreate,
            reference: BaselineProfile::LinuxUnixCreate.reference(),
            enabled: true,
            qualification_digest: digest(0x22),
        }]),
        grants: bounded([PolicyGrantV1 {
            id: id("grant-a"),
            revision: NonZeroU64::MIN,
            profile: BaselineProfile::LinuxUnixCreate.reference(),
            ceiling: BaselineProfile::LinuxUnixCreate.ceiling(),
            enabled: true,
            callers: bounded([
                CallerSelector::Linux { uid: 1000 },
                CallerSelector::Linux { uid: 1001 },
            ]),
            approved_plans: bounded([digest(0x11), digest(0x33)]),
        }]),
        active_attempt_disposition: GrantChangeDisposition::DrainExisting,
    }
}

fn attempt() -> AttemptBindingV1 {
    let snapshot = ProviderAdmissionSnapshotV1 {
        request: request(),
        request_digest: DiagnosticSha256::from_bytes(bytes(CONTRACT_HASH).try_into().unwrap()),
        registry_digest: DiagnosticSha256::from_bytes(bytes(REGISTRY_HASH).try_into().unwrap()),
        qualification_digest: digest(0x22),
        admission_nonce: Nonce128([4; 16]),
        caller_invocation_reference: Nonce128([5; 16]),
        private_invocation_digest: digest(0x66),
        caller: CallerSelector::Linux { uid: 1000 },
        native_profile: BaselineProfile::LinuxUnixCreate,
    };
    AttemptBindingV1::from_snapshot(
        &snapshot,
        PublicProviderBindingV1 {
            generation: BoundedText::new("0.5.3-dev:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap(),
            source_commit: BoundedText::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            runtime_manifest_sha256: digest(0x22),
        },
        BoundedText::new("boot-a").unwrap(),
        BoundedText::new("attempt-a").unwrap(),
        2,
    )
    .unwrap()
}

#[test]
fn fixed_preimages_have_independently_calculated_sha256_answers() {
    for (preimage, expected) in [
        (CONTRACT, CONTRACT_HASH),
        (
            include_str!("fixtures/workload_independent/registry.hex"),
            REGISTRY_HASH,
        ),
        (
            include_str!("fixtures/workload_independent/effective.hex"),
            EFFECTIVE_HASH,
        ),
        (
            include_str!("fixtures/workload_independent/attempt.hex"),
            ATTEMPT_HASH,
        ),
        (
            include_str!("fixtures/workload_independent/checkpoint.hex"),
            CHECKPOINT_HASH,
        ),
    ] {
        assert_eq!(Sha256::digest(bytes(preimage)).as_slice(), bytes(expected));
    }
}

#[test]
fn independent_contract_bytes_and_all_commitment_digests_match() {
    assert_eq!(encode_contract(&request()).unwrap(), bytes(CONTRACT));
    assert_eq!(decode_contract(&bytes(CONTRACT)).unwrap(), request());
    assert_eq!(
        String::from(contract_digest(&request()).unwrap()),
        CONTRACT_HASH
    );
    assert_eq!(
        String::from(registry().canonical_digest().unwrap()),
        REGISTRY_HASH
    );
    let attempt = attempt();
    assert_eq!(
        String::from(attempt.plan.effective_policy_digest.clone()),
        EFFECTIVE_HASH
    );
    assert_eq!(
        String::from(attempt.canonical_digest().unwrap()),
        ATTEMPT_HASH
    );
    let checkpoint = VerifiedCheckpointV1::observed(
        &attempt,
        baseline_observation(BaselineProfile::LinuxUnixCreate),
        true,
        true,
        true,
        true,
        true,
        true,
    )
    .unwrap();
    assert_eq!(String::from(checkpoint.digest().clone()), CHECKPOINT_HASH);
}

#[test]
fn set_order_and_json_format_do_not_change_known_answers() {
    let mut request = request();
    request.requirements = bounded(request.requirements.as_slice().iter().rev().cloned());
    assert_eq!(encode_contract(&request).unwrap(), bytes(CONTRACT));
    for json in [
        serde_json::to_vec(&request).unwrap(),
        serde_json::to_vec_pretty(&request).unwrap(),
    ] {
        assert_eq!(
            String::from(contract_digest(&WorkloadContractV1::parse(&json).unwrap()).unwrap()),
            CONTRACT_HASH
        );
    }
    let mut registry = registry();
    let mut grant = registry.grants.as_slice()[0].clone();
    grant.callers = bounded(grant.callers.as_slice().iter().rev().cloned());
    grant.approved_plans = bounded(grant.approved_plans.as_slice().iter().rev().cloned());
    registry.grants = bounded([grant]);
    assert_eq!(
        String::from(registry.canonical_digest().unwrap()),
        REGISTRY_HASH
    );
}

#[test]
fn canonical_decoder_rejects_every_truncation_trailing_data_and_unsorted_requirements() {
    let canonical = bytes(CONTRACT);
    for end in 0..canonical.len() {
        assert!(decode_contract(&canonical[..end]).is_err());
    }
    let mut trailing = canonical.clone();
    trailing.push(0);
    assert!(decode_contract(&trailing).is_err());
    // Locate complete fixed rule encodings, without depending on field offsets.
    let rules = b"\x02\0\x06a-pair\x02\x01\0\x08z-create\x01";
    let start = canonical
        .windows(rules.len())
        .position(|window| window == rules)
        .unwrap();
    let mut unsorted = canonical.clone();
    unsorted.splice(
        start..start + rules.len(),
        b"\x01\0\x08z-create\x01\x02\0\x06a-pair\x02"
            .iter()
            .copied(),
    );
    assert!(decode_contract(&unsorted).is_err());
    for tag in [0, 6, u8::MAX] {
        let mut unknown = canonical.clone();
        unknown[start] = tag;
        assert!(decode_contract(&unknown).is_err());
    }
}

#[test]
fn semantic_changes_invalidate_commitments_and_checkpoints() {
    let mut changed = request();
    changed.expected_epoch.revision = NonZeroU64::new(2).unwrap();
    assert_ne!(
        String::from(contract_digest(&changed).unwrap()),
        CONTRACT_HASH
    );
    let mut registry = registry();
    registry.active_attempt_disposition = GrantChangeDisposition::RevokeActive;
    assert_ne!(
        String::from(registry.canonical_digest().unwrap()),
        REGISTRY_HASH
    );
    let original = attempt();
    let checkpoint = VerifiedCheckpointV1::observed(
        &original,
        baseline_observation(BaselineProfile::LinuxUnixCreate),
        true,
        true,
        true,
        true,
        true,
        true,
    )
    .unwrap();
    let mut mutations = vec![original.clone(); 5];
    mutations[0].admission_nonce = Nonce128([9; 16]);
    mutations[1].caller_invocation_reference = Nonce128([9; 16]);
    mutations[2].restart_attempt += 1;
    mutations[3].plan.boot_identity = BoundedText::new("boot-b").unwrap();
    mutations[4].attempt_id = BoundedText::new("attempt-b").unwrap();
    for mutation in mutations {
        assert_ne!(
            String::from(mutation.canonical_digest().unwrap()),
            ATTEMPT_HASH
        );
        assert!(!checkpoint.matches_binding(&mutation));
        assert!(
            AttemptPolicyEnforcementV1::retired(mutation, checkpoint.clone(), true, true).is_err()
        );
    }
    for missing in 0..6 {
        let mut facts = [true; 6];
        facts[missing] = false;
        assert!(
            VerifiedCheckpointV1::observed(
                &original,
                baseline_observation(BaselineProfile::LinuxUnixCreate),
                facts[0],
                facts[1],
                facts[2],
                facts[3],
                facts[4],
                facts[5]
            )
            .is_err()
        );
    }
    for (controls, resources) in [(false, false), (false, true), (true, false)] {
        assert!(
            AttemptPolicyEnforcementV1::retired(
                original.clone(),
                checkpoint.clone(),
                controls,
                resources
            )
            .is_err()
        );
    }
}

fn discovery(
    registry: &PolicyRegistryV1,
    uid: u32,
) -> Result<memcordon_core::workload_discovery::WorkloadDiscoveryV1, String> {
    memcordon_core::workload_discovery::WorkloadDiscoveryV1::authenticated(
        Some((registry, &request().expected_epoch)),
        &CallerSelector::Linux { uid },
        BaselineProfile::LinuxUnixCreate,
        digest(0x22),
        attempt().plan.provider,
        BoundedText::new("boot-a").unwrap(),
    )
}

#[test]
fn discovery_filters_callers_and_rejects_duplicate_or_incompatible_grants() {
    let registry = registry();
    let authorized = discovery(&registry, 1000).unwrap();
    assert!(authorized.validate(BaselineProfile::LinuxUnixCreate));
    assert_eq!(authorized.grants.as_slice().len(), 2);
    let unauthorized = discovery(&registry, 2000).unwrap();
    assert!(unauthorized.grants.as_slice().is_empty());
    assert!(unauthorized.complete);
    assert!(unauthorized.validate(BaselineProfile::LinuxUnixCreate));

    let mut duplicated = authorized.clone();
    duplicated
        .grants
        .try_push(authorized.grants.as_slice()[0].clone())
        .unwrap();
    assert!(!duplicated.validate(BaselineProfile::LinuxUnixCreate));
    let mut incompatible = authorized.clone();
    let mut grant = authorized.grants.as_slice()[0].clone();
    grant.ceiling.direct_socket_authority = DirectSocketCeiling::NoNewInetSockets;
    incompatible.grants = bounded([grant]);
    assert!(!incompatible.validate(BaselineProfile::LinuxUnixCreate));
    let mut incomplete = authorized;
    incomplete.complete = false;
    assert!(!incomplete.validate(BaselineProfile::LinuxUnixCreate));
}

#[test]
fn maximal_valid_registry_errors_instead_of_truncating_complete_discovery() {
    use memcordon_core::workload_limits::{GRANTS, PLANS_PER_GRANT, PUBLIC_OBJECT_BYTES};

    let mut registry = registry();
    let mut prototype = registry.grants.as_slice()[0].clone();
    let id_width = GRANTS.to_string().len();
    let grant_id = |index| id(&format!("grant-{index:0id_width$}"));
    prototype.id = grant_id(0);
    prototype.callers = bounded([CallerSelector::Linux { uid: 1000 }]);
    prototype.approved_plans = bounded([digest(0)]);
    registry.grants = bounded([prototype.clone()]);
    let single = discovery(&registry, 1000).unwrap();
    let entry_bytes = serde_json::to_vec(&single.grants.as_slice()[0])
        .unwrap()
        .len();
    let envelope_bytes = serde_json::to_vec(&single).unwrap().len() - entry_bytes;
    let discovery_bytes = |grants: usize| {
        let entries = grants * PLANS_PER_GRANT;
        envelope_bytes + entries * entry_bytes + entries.saturating_sub(1) * b",".len()
    };
    // Equal-width ids and fixed-width digests make this serialized size exact.
    // Miri still crosses the real public byte limit and exercises rejection;
    // native execution retains the complete registry and plan capacity case.
    let minimum_overflow_grants = (1..=GRANTS)
        .find(|grants| discovery_bytes(*grants) > PUBLIC_OBJECT_BYTES)
        .unwrap();
    assert!(discovery_bytes(minimum_overflow_grants - 1) <= PUBLIC_OBJECT_BYTES);
    for grants in std::iter::once(minimum_overflow_grants).chain((!cfg!(miri)).then_some(GRANTS)) {
        registry.grants = bounded((0..grants).map(|index| {
            let mut grant = prototype.clone();
            grant.id = grant_id(index);
            grant.approved_plans =
                bounded((0..PLANS_PER_GRANT).map(|plan| digest(u8::try_from(plan).unwrap())));
            grant
        }));
        assert!(registry.validate().is_ok());
        let encoded = serde_json::to_vec(&registry).unwrap();
        assert!(PolicyRegistryV1::parse(&encoded).is_ok());
        let error = discovery(&registry, 1000).unwrap_err();
        assert_eq!(error, "caller discovery exceeds public object capacity");
        // The same registry remains usable for callers with no matching grants.
        let unrelated = discovery(&registry, 2000).unwrap();
        assert!(unrelated.complete);
        assert!(unrelated.grants.as_slice().is_empty());
    }
}

#[test]
fn recomputed_cross_profile_checkpoint_cannot_synthesize_admission() {
    let binding = attempt();
    let wrong = VerifiedCheckpointV1::observed(
        &binding,
        BaselineRestrictionObservationV1::WindowsNetworkExternallyGoverned,
        true,
        true,
        true,
        true,
        true,
        true,
    )
    .unwrap();
    assert!(!wrong.matches_binding(&binding));
    if let Ok(receipt) = AttemptPolicyEnforcementV1::retired(binding, wrong, true, true) {
        assert!(!receipt.terminal_success());
        assert!(!receipt.is_consistent());
        assert!(receipt.resolution().is_none());
    }
}

#[test]
fn receipt_decoding_rejects_unknown_fields_and_false_checkpoints() {
    let binding = attempt();
    let checkpoint = VerifiedCheckpointV1::observed(
        &binding,
        baseline_observation(BaselineProfile::LinuxUnixCreate),
        true,
        true,
        true,
        true,
        true,
        true,
    )
    .unwrap();
    let receipt = AttemptPolicyEnforcementV1::retired(binding, checkpoint, true, true).unwrap();
    let original = serde_json::to_value(&receipt).unwrap();
    for field in [
        "target_gated",
        "caller_verified",
        "resources_verified",
        "guardian_verified",
        "epoch_verified",
        "durable",
    ] {
        let mut value = original.clone();
        value["before_authorization"][field] = serde_json::Value::Bool(false);
        assert!(serde_json::from_value::<AttemptPolicyEnforcementV1>(value).is_err());
    }
    let mut unknown = original.clone();
    unknown["unrecognized"] = serde_json::Value::Bool(true);
    assert!(serde_json::from_value::<AttemptPolicyEnforcementV1>(unknown).is_err());
    for field in ["controls_preserved", "provider_resources_closed"] {
        let mut value = original.clone();
        value["terminal"][field] = serde_json::Value::Bool(false);
        let decoded: AttemptPolicyEnforcementV1 = serde_json::from_value(value).unwrap();
        assert!(!decoded.terminal_success());
        assert!(decoded.resolution().is_none());
    }
    let mut unavailable = original;
    unavailable["terminal"] =
        serde_json::json!({"state":"unavailable", "reason":"terminal-unavailable"});
    let decoded: AttemptPolicyEnforcementV1 = serde_json::from_value(unavailable).unwrap();
    assert!(!decoded.terminal_success());
    assert!(!decoded.matches_terminal_request(Some(&request())));
}

fn tcp_request() -> WorkloadContractV1 {
    use std::num::NonZeroU16;
    let mut contract = request();
    contract.requirements = bounded([
        RequirementV1::Tcp {
            id: id("listener"),
            family: IpFamily::V4,
            operations: TcpOperations::new(bounded([
                TcpOperation::Create,
                TcpOperation::Bind,
                TcpOperation::Listen,
                TcpOperation::Accept,
                TcpOperation::StreamRead,
                TcpOperation::StreamWrite,
            ]))
            .unwrap(),
            scope: TcpScope::AttemptPrivateStack,
            local_ports: LocalPortRequirement::KernelAssigned,
            peer: TcpPeerRequirement::ExactAddress {
                endpoint: TcpEndpoint::V4 {
                    address: [127, 0, 0, 1],
                    port: NonZeroU16::new(8080).unwrap(),
                },
            },
        },
        RequirementV1::Tcp {
            id: id("client"),
            family: IpFamily::V4,
            operations: TcpOperations::new(bounded([
                TcpOperation::Create,
                TcpOperation::Connect,
                TcpOperation::StreamRead,
                TcpOperation::StreamWrite,
            ]))
            .unwrap(),
            scope: TcpScope::AttemptPrivateStack,
            local_ports: LocalPortRequirement::InclusiveRange {
                first: NonZeroU16::new(1024).unwrap(),
                last: NonZeroU16::new(65535).unwrap(),
            },
            peer: TcpPeerRequirement::SameAttemptEndpoint {
                endpoint: id("server"),
            },
        },
    ]);
    contract.endpoints = bounded([EndpointDeclarationV1 {
        id: id("server"),
        requirement: id("listener"),
    }]);
    contract
}

// These are fuzz starting points, not expected-value oracles. The fixed contract
// seed comes directly from the independent bytes; the other valid seeds use
// public constructors and are validated before publication to the ignored corpus.
fn portable_seeds() -> Vec<(&'static str, &'static str, Vec<u8>)> {
    let baseline = decode_contract(&bytes(CONTRACT)).unwrap();
    let tcp = tcp_request();
    assert!(tcp.validate().is_ok());
    let registry = registry();
    let discovery = discovery(&registry, 1000).unwrap();
    assert!(discovery.validate(BaselineProfile::LinuxUnixCreate));
    let report = memcordon_core::workload_discovery::DiscoveryReportV1::Authenticated {
        discovery: Box::new(discovery),
    };
    let binding = attempt();
    let checkpoint = VerifiedCheckpointV1::observed(
        &binding,
        baseline_observation(BaselineProfile::LinuxUnixCreate),
        true,
        true,
        true,
        true,
        true,
        true,
    )
    .unwrap();
    let receipt = AttemptPolicyEnforcementV1::retired(binding, checkpoint, true, true).unwrap();
    assert!(receipt.terminal_success());
    let receipt_json = serde_json::to_vec(&receipt).unwrap();
    let mut seeds = vec![
        (
            "workload-request",
            "baseline.json",
            serde_json::to_vec(&baseline).unwrap(),
        ),
        (
            "workload-request",
            "tcp-endpoint.json",
            serde_json::to_vec(&tcp).unwrap(),
        ),
        (
            "workload-registry",
            "authorized.json",
            serde_json::to_vec(&registry).unwrap(),
        ),
        (
            "workload-discovery",
            "authenticated.json",
            serde_json::to_vec(&report).unwrap(),
        ),
        ("workload-receipt", "retired.json", receipt_json.clone()),
        ("workload-transitions", "retired.json", receipt_json),
        ("workload-canonical", "independent-v1", bytes(CONTRACT)),
        (
            "workload-canonical",
            "tcp-endpoint-v1",
            encode_contract(&tcp).unwrap(),
        ),
    ];
    let mut unknown = serde_json::to_value(&baseline).unwrap();
    unknown["schema_version"] = serde_json::json!(2);
    seeds.push((
        "workload-request",
        "unknown-version.json",
        serde_json::to_vec(&unknown).unwrap(),
    ));
    let mut unresolved = tcp.clone();
    unresolved.endpoints = BoundedVec::default();
    assert!(unresolved.validate().is_err());
    seeds.push((
        "workload-request",
        "unresolved-endpoint.json",
        serde_json::to_vec(&unresolved).unwrap(),
    ));
    let mut duplicate = tcp;
    duplicate
        .endpoints
        .try_push(duplicate.endpoints.as_slice()[0].clone())
        .unwrap();
    assert!(duplicate.validate().is_err());
    seeds.push((
        "workload-request",
        "duplicate-endpoint.json",
        serde_json::to_vec(&duplicate).unwrap(),
    ));
    let mut malformed_registry = serde_json::to_value(&registry).unwrap();
    malformed_registry["grants"][0]["profile"]["semantic_digest"] =
        serde_json::json!("00".repeat(32));
    seeds.push((
        "workload-registry",
        "wrong-profile.json",
        serde_json::to_vec(&malformed_registry).unwrap(),
    ));
    let mut malformed_discovery = serde_json::to_value(&report).unwrap();
    malformed_discovery["discovery"]["complete"] = serde_json::json!(false);
    seeds.push((
        "workload-discovery",
        "incomplete.json",
        serde_json::to_vec(&malformed_discovery).unwrap(),
    ));
    let mut unavailable = serde_json::to_value(&receipt).unwrap();
    unavailable["terminal"] =
        serde_json::json!({"state":"unavailable", "reason":"terminal-unavailable"});
    for target in ["workload-receipt", "workload-transitions"] {
        seeds.push((
            target,
            "unavailable.json",
            serde_json::to_vec(&unavailable).unwrap(),
        ));
    }
    let mut trailing = bytes(CONTRACT);
    trailing.push(0);
    seeds.push(("workload-canonical", "trailing-byte", trailing));
    seeds
}

#[test]
fn portable_fuzz_seeds_reach_valid_and_invalid_semantic_branches() {
    let seeds = portable_seeds();
    assert_eq!(
        seeds
            .iter()
            .filter(|(target, _, _)| *target == "workload-canonical")
            .count(),
        3
    );
    let tcp = tcp_request();
    let canonical = encode_contract(&tcp).unwrap();
    assert_eq!(
        encode_contract(&decode_contract(&canonical).unwrap()).unwrap(),
        canonical
    );
    assert!(WorkloadContractV1::parse(&serde_json::to_vec(&tcp).unwrap()).is_ok());
    // Parsing an expressible TCP workload does not authorize baseline TCP.
    let registry = registry();
    let denied = resolve(
        &registry,
        &tcp.expected_epoch,
        &tcp,
        &CallerSelector::Linux { uid: 1000 },
        BaselineProfile::LinuxUnixCreate,
        &digest(0x22),
    );
    assert!(denied.is_err());
}

#[test]
fn tcp_endpoint_cycles_scope_mismatch_and_operation_omissions_reject() {
    let original = serde_json::to_value(tcp_request()).unwrap();
    let mut cycle = original.clone();
    cycle["requirements"][0]["peer"] = serde_json::json!({
        "kind": "same-attempt-endpoint", "endpoint": "server"
    });
    assert!(WorkloadContractV1::parse(&serde_json::to_vec(&cycle).unwrap()).is_err());
    let mut scope = original.clone();
    scope["requirements"][1]["scope"] = serde_json::json!("host-shared-loopback");
    assert!(WorkloadContractV1::parse(&serde_json::to_vec(&scope).unwrap()).is_err());
    let mut operations = original;
    operations["requirements"][0]["operations"] = serde_json::json!(["create", "listen", "accept"]);
    assert!(WorkloadContractV1::parse(&serde_json::to_vec(&operations).unwrap()).is_err());
}

#[test]
#[ignore = "explicitly publishes reproducible seeds into ignored fuzz/corpus directories"]
fn write_portable_fuzz_seed_corpora() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    for (target, name, data) in portable_seeds() {
        let directory = root.join("fuzz").join("corpus").join(target);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join(name), data).unwrap();
    }
}
