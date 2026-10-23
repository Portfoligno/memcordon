use memcordon_ci::release::{
    artifacts::checksum,
    linux_memory_worker_checkpoint::{Checkpoint, checkpoint},
};
use serde_json::{Value, json};

fn source(phase: &str, knowledge: &str, wrong_worker: bool) -> Value {
    let attempt = "0123456789abcdef0123456789abcdef";
    let admission = json!({"attempt_id":attempt,"original":"bound admission"});
    let journal = json!({"attempt_id":attempt,"mixed_admission_metadata":admission,
        "mixed_worker":{"pid":if wrong_worker {43}else{42},"start_time":100},
        "phase":phase,"release_knowledge":knowledge});
    let body = format!(
        "format=memcordon.private-native-journal\nrevision=1\ncgroup={attempt}\npayload={}\n",
        serde_json::to_string(&journal).unwrap()
    );
    let bytes = format!("{body}digest={}\n", checksum(body.as_bytes())).into_bytes();
    json!({"attempt_id":attempt,"admission":admission,"worker":{"pid":42,"birth":100},
        "journal_sha256":checksum(&bytes),"journal_bytes":bytes})
}

#[test]
fn only_current_execution_checkpoint_permits_memory_stop() {
    assert_eq!(
        checkpoint(&source("execution-observed", "exec-observed", false)).unwrap(),
        Checkpoint::Executing
    );
    assert_eq!(
        checkpoint(&source("release-intent", "possibly-released", false)).unwrap(),
        Checkpoint::PendingExecution
    );
    for (phase, knowledge) in [
        ("target-gated", "not-released"),
        ("target-gated", "possibly-released"),
        ("execution-observed", "not-released"),
        ("execution-observed", "possibly-released"),
        ("retiring", "exec-observed"),
        ("retired", "exec-observed"),
    ] {
        assert!(
            checkpoint(&source(phase, knowledge, false)).is_err(),
            "accepted {phase}/{knowledge}"
        );
    }
}

#[test]
fn checkpoint_projection_preserves_bound_source_bytes_and_worker() {
    let mut current = source("execution-observed", "exec-observed", false);
    let before = current.clone();
    checkpoint(&current).unwrap();
    assert_eq!(current, before);
    current["journal_sha256"] = json!("00".repeat(32));
    assert!(checkpoint(&current).is_err());
    assert!(checkpoint(&source("execution-observed", "exec-observed", true)).is_err());
    let mut malformed = before;
    for field in ["attempt_id", "admission", "worker"] {
        let mut absent = malformed.clone();
        absent[field] = Value::Null;
        assert!(checkpoint(&absent).is_err());
    }
    malformed["journal_bytes"] = json!(b"not a durable journal".to_vec());
    assert!(checkpoint(&malformed).is_err());
}
