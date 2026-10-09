#![cfg(target_os = "linux")]
use memcordon_ci::consumer_readiness_ledger::SourceIdentity;
use memcordon_ci::linux_consumer_readiness::{LinuxCollectionInput, collect};
use memcordon_readiness_verifier::{CaseKey, EvidenceClass};

fn setup() -> (tempfile::TempDir, tempfile::TempDir, LinuxCollectionInput) {
    let source = tempfile::tempdir().unwrap();
    let destination = tempfile::tempdir().unwrap();
    let challenge = "a".repeat(64);
    let transcript = serde_json::json!({"format":"memcordon.linux-readiness-transcript","revision":1,
        "sequence":1,"challenge":challenge,"root_pid":2,"root_birth":3,"operation":"test-vector","observation":{}});
    let mut stdout = serde_json::to_vec(&transcript).unwrap();
    stdout.push(b'\n');
    for (name, bytes) in [
        ("result", b"provider-result-vector".as_slice()),
        ("stdout", stdout.as_slice()),
        ("stderr", &[0, 255]),
        ("request", b"request-vector".as_slice()),
        ("contract", b"contract-vector".as_slice()),
    ] {
        std::fs::write(source.path().join(name), bytes).unwrap();
    }
    let input = LinuxCollectionInput {
        identity: SourceIdentity {
            run_id: "structural-test".into(),
            source_commit: "b".repeat(40),
            source_tree_sha256: "c".repeat(64),
            version: "0.5.8-dev".into(),
        },
        key: CaseKey {
            target: "x86_64-unknown-linux-gnu".into(),
            channel: Some("candidate-native".into()),
            evidence_class: EvidenceClass::InstalledProduct,
            family: "L-MIX-01".into(),
            scenario: "joint".into(),
        },
        challenge,
        artifact_prefix: "x86_64-unknown-linux-gnu/candidate-native/test".into(),
        result: source.path().join("result"),
        stdout: source.path().join("stdout"),
        stderr: source.path().join("stderr"),
        transcript: None,
        provider_request: source.path().join("request"),
        contract: source.path().join("contract"),
    };
    (source, destination, input)
}

#[test]
fn collection_preserves_raw_provider_and_binary_bytes_without_certifying_them() {
    let (_source, destination, input) = setup();
    let collection = collect(input, destination.path()).unwrap();
    assert_eq!(collection.artifacts.len(), 5);
    assert_eq!(collection.transcript.len(), 1);
    assert_eq!(
        std::fs::read(destination.path().join(&collection.artifacts[0].path)).unwrap(),
        b"provider-result-vector"
    );
    assert_eq!(
        std::fs::read(destination.path().join(&collection.artifacts[2].path)).unwrap(),
        [0, 255]
    );
    // The collector deliberately does not turn these protocol vectors into a
    // readiness verdict; the independent decoder must reject them as proof.
}

#[test]
fn transcript_changed_challenge_or_sequence_is_rejected() {
    let (_source, destination, input) = setup();
    let mut row: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&input.stdout).unwrap()).unwrap();
    row["sequence"] = serde_json::json!(2);
    let mut bytes = serde_json::to_vec(&row).unwrap();
    bytes.push(b'\n');
    std::fs::write(&input.stdout, bytes).unwrap();
    assert!(
        collect(input, destination.path())
            .unwrap_err()
            .contains("sequence")
    );
}

#[test]
fn hardlink_and_prefix_escape_cannot_enter_collected_custody() {
    let (source, destination, mut input) = setup();
    std::fs::hard_link(&input.result, source.path().join("result-alias")).unwrap();
    assert!(
        collect(input.clone(), destination.path())
            .unwrap_err()
            .contains("exclusive")
    );
    input.artifact_prefix = "../foreign".into();
    assert!(
        collect(input, destination.path())
            .unwrap_err()
            .contains("prefix")
    );
}
