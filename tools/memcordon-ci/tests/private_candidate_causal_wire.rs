use memcordon_ci::private_candidate_replay::{CaseFactV1, ReplayTaskV1};
use memcordon_ci::private_case_semantics::CaseFactKindV1;

fn checkpoint() -> serde_json::Value {
    serde_json::to_value(CaseFactV1::Checkpoint {
        checkpoint_path: "journal/release-intent-v1.json".into(),
        file_dev: 1,
        file_inode: 2,
        owner: ReplayTaskV1 {
            tid: 3,
            tgid: 3,
            start_boottime_ns: 4,
            cgroup_inode: 5,
            time_ns_inode: 6,
        },
        fd: 7,
        directory_fd: 8,
        file_sync_sequence: 9,
        directory_sync_sequence: 10,
        release_sequence: 11,
    })
    .unwrap()
}
fn wire() -> serde_json::Value {
    serde_json::json!({
        "kind":"native-causal-v1", "family":"checkpoint",
        "sources": {
            "result_path":"result.json", "request_path":"request.json", "attempt_path":"attempt.json",
            "attachments":["request.bin","report.bin","stdio.bin","observer.bin","cleanup.bin"],
            "checkpoint_gate_path":"checkpoint-gate.json",
            "reopen_metadata_path":"journal/release-intent-v1.metadata.json"
            ,"terminal_sources":null
            ,"streams_metadata_path":null
        }, "measurement":checkpoint()
    })
}

#[test]
fn versioned_causal_wire_keeps_original_sources_and_family() {
    let value = wire();
    let parsed: CaseFactV1 = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(parsed.kind(), CaseFactKindV1::Checkpoint);
    assert_eq!(serde_json::to_value(parsed).unwrap(), value);
}

#[test]
fn causal_wire_rejects_extra_owner_verdict_and_wrong_inventory_shape() {
    let mut value = wire();
    value["sources"]["owner_verified"] = serde_json::json!(true);
    assert!(serde_json::from_value::<CaseFactV1>(value).is_err());
    let mut value = wire();
    value["sources"]["attachments"] = serde_json::json!(["request.bin", "report.bin"]);
    assert!(serde_json::from_value::<CaseFactV1>(value).is_err());
}
