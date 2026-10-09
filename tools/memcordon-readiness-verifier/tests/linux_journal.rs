//! Journal decoder vectors only; no native inode, process or publication is claimed.
use memcordon_readiness_verifier::*;
use serde_json::json;
use sha2::{Digest, Sha256};
fn encode(payload: &serde_json::Value) -> Vec<u8> {
    let body = format!(
        "format=memcordon.private-native-journal\nrevision=1\ncgroup=component-attempt\npayload={payload}\n"
    );
    format!(
        "{body}digest={}\n",
        hex::encode(Sha256::digest(body.as_bytes()))
    )
    .into_bytes()
}
#[test]
fn journal_decoder_rejects_rechecksummed_authority_and_publication_substitutions() {
    let payload = json!({"attempt_id":"component-attempt","boot_identity":"owned-component-boot","frontend":{"pid":42,"start_time":17},"caller_envelope_digest":"11".repeat(32),"admission_metadata":null,"phase":"allocated","release_knowledge":"not-released","binding":null,"guardian":null,"namespace_init":null,"target":null,"network_namespace_inode":null,"checkpoint":null,"checkpoint_digest":null,"gated_facts":null,"cleanup_error":null});
    let bytes = encode(&payload);
    let key = CaseKey {
        target: "x86_64-unknown-linux-gnu".into(),
        channel: None,
        evidence_class: EvidenceClass::NativeComponentRegression,
        family: "L-VER-01".into(),
        scenario: "journal-barrier".into(),
    };
    let receipt = LinuxJournalReceipt {
        format: "memcordon.linux-journal-component".into(),
        revision: 1,
        run_id: "1".into(),
        recipe_id: "native-linux-x64".into(),
        test_name: "private_attempt::durable_journal_barriers_emit_actual_component_receipts"
            .into(),
        native_target: key.target.clone(),
        executable_sha256: "22".repeat(32),
        challenge_sha256: "33".repeat(32),
        operation: "durable-preboundary-journal-barriers".into(),
        attempt_id: "component-attempt".into(),
        frontend: JournalProcess {
            pid: 42,
            start_time: 17,
        },
        boot_id: "owned-component-boot".into(),
        record_before: "before.bin".into(),
        record_after_refusal: "after.bin".into(),
        canonical_device: 1,
        canonical_inode: 2,
        canonical_unchanged: true,
        release_refusal: "private release requires durable gated observations".into(),
        journal_refusal: "File exists (os error 17)".into(),
        native_publication_errno: 17,
        owned_competing_device: 1,
        owned_competing_inode: 3,
        owned_competing_unlinked: true,
        unallocated_record_retired: true,
    };
    validate_linux_journal_receipt(&receipt, &key, &bytes, &bytes).unwrap();
    let mut changed = payload.clone();
    changed["phase"] = "release-intent".into();
    let bytes_changed = encode(&changed);
    assert!(
        validate_linux_journal_receipt(&receipt, &key, &bytes_changed, &bytes_changed).is_err()
    );
    let mut changed = payload.clone();
    changed["unknown_authority"] = true.into();
    let bytes_changed = encode(&changed);
    assert!(
        validate_linux_journal_receipt(&receipt, &key, &bytes_changed, &bytes_changed).is_err()
    );
    let mut changed = receipt.clone();
    changed.native_publication_errno = 0;
    assert!(validate_linux_journal_receipt(&changed, &key, &bytes, &bytes).is_err());
    let mut changed = receipt.clone();
    changed.owned_competing_inode = 2;
    assert!(validate_linux_journal_receipt(&changed, &key, &bytes, &bytes).is_err());
    assert!(validate_linux_journal_receipt(&receipt, &key, &bytes, &bytes_changed).is_err());
}
