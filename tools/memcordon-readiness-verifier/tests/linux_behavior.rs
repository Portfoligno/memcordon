//! Decoder mutation vectors only; no Linux namespace or installed proof.
use memcordon_readiness_verifier::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn assess(canary: Value, denial: Value, binding: Value) -> VerificationResult<()> {
    let directory = tempfile::tempdir().unwrap();
    let challenge = vec![7u8; 32];
    let key = CaseKey {
        target: "x86_64-unknown-linux-gnu".into(),
        channel: Some("candidate-native".into()),
        evidence_class: EvidenceClass::InstalledProduct,
        family: "L-ISO-01".into(),
        scenario: "host-tcp".into(),
    };
    let native:NativeObservation=serde_json::from_value(json!({"format":"memcordon.consumer-readiness.native","revision":1,"run_id":"123","lease_id":"lease","target":key.target,
        "executable_sha256":"1".repeat(64),"invocation_sha256":"2".repeat(64),"execution_invocation_sha256":null,"request_sha256":null,"provider_sha256":null,"provider_generation":null,"runtime_manifest_sha256":null,
        "attempt_id":"attempt","root_pid":500,"root_birth":99,"attempt_nonce":null,"held_processes":[],"frontend_status":0,"origin":"target","target_status":0,
        "authenticated_provider_exchange":true,"relay_complete":true,"result_named_identity_verified":true,"result_readback_verified":true,"application_stage":null})).unwrap();
    let input = FixtureInput {
        format: "memcordon.consumer-readiness.input".into(),
        revision: 1,
        run_id: "123".into(),
        key: key.clone(),
        challenge_sha256: hex::encode(Sha256::digest(&challenge)),
        binary: Vec::new(),
        target_argv: NativeArguments::UnixBytes(Vec::new()),
        deadline_millis: None,
        memory_bytes: None,
        toolchain_identity: None,
    };
    let row = json!({"format":"memcordon.linux-readiness-transcript","revision":1,"sequence":1,"challenge":hex::encode(&challenge),"root_pid":2,"root_birth":99,"operation":"forbidden-tcp-denied","observation":denial});
    let mut transcript = serde_json::to_vec(&row).unwrap();
    transcript.push(b'\n');
    let mut artifacts = Vec::new();
    for (path, bytes) in [
        ("challenge.bin", challenge),
        ("transcript.jsonl", transcript),
        ("canary.json", serde_json::to_vec(&canary).unwrap()),
        ("binding.json", serde_json::to_vec(&binding).unwrap()),
    ] {
        std::fs::write(directory.path().join(path), &bytes).unwrap();
        artifacts.push(Artifact {
            path: path.into(),
            length: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(bytes)),
        });
    }
    let semantic = SemanticObservation {
        format: "memcordon.consumer-readiness.semantic".into(),
        revision: 1,
        run_id: "123".into(),
        key,
        challenge: "challenge.bin".into(),
        operations: vec![OperationObservation {
            operation: "native-authority-probe".into(),
            observer: "owned-fixture-behavior".into(),
            attempt_id: Some("attempt".into()),
            root_pid: Some(500),
            native_receipt: "transcript.jsonl".into(),
        }],
        comparisons: Vec::new(),
        counters: Default::default(),
        negative_probe: Some(NegativeProbe {
            stage: "host-tcp".into(),
            domain: "linux".into(),
            native_code: 111,
            receipt: "transcript.jsonl".into(),
        }),
        component_test: None,
        component_actors: None,
        windows_capacity: None,
        windows_refusal: None,
        fixture_behavior: Some(FixtureBehavior {
            descriptor: "binding.json".into(),
            transcript: "transcript.jsonl".into(),
            expected_token: None,
            peer_artifacts: vec![BehaviorArtifact {
                role: "host-tcp-canary".into(),
                path: "canary.json".into(),
            }],
            native_binding: Some("binding.json".into()),
        }),
    };
    validate_fixture_behavior(&semantic, &native, &input, &artifacts, directory.path())
}

#[test]
fn host_denial_requires_real_baseline_endpoint_and_distinct_native_namespace() {
    let canary = json!({"format":"memcordon.linux-host-tcp-canary","revision":1,"challenge":hex::encode([7u8;32]),"endpoint":"127.0.0.1:45000","socket_inode":100,"network_namespace_inode":200,"baseline_client_connected":true,"baseline_server_accepted":true});
    let denial = json!({"endpoint":"127.0.0.1:45000","native_errno":111});
    let binding = json!({"run_id":"123","target":{"process_id":500,"birth":99,"namespace_pids":[500,2],"network":{"inode":201}},"caller":{"network":{"inode":200}}});
    assert!(assess(canary.clone(), denial.clone(), binding.clone()).is_ok());
    let mut changed = canary.clone();
    changed["baseline_server_accepted"] = json!(false);
    assert!(assess(changed, denial.clone(), binding.clone()).is_err());
    let mut changed = canary.clone();
    changed["endpoint"] = json!("127.0.0.1:45001");
    assert!(assess(changed, denial.clone(), binding.clone()).is_err());
    let mut changed = binding.clone();
    changed["target"]["network"]["inode"] = json!(200);
    assert!(assess(canary.clone(), denial.clone(), changed).is_err());
    let mut changed = binding.clone();
    changed["caller"]["network"]["inode"] = json!(999);
    assert!(assess(canary.clone(), denial.clone(), changed).is_err());
    let mut changed = denial.clone();
    changed["native_errno"] = json!(0);
    assert!(assess(canary.clone(), changed, binding.clone()).is_err());
    let mut changed = canary;
    changed["unknown"] = json!(true);
    assert!(assess(changed, denial, binding).is_err());
}
