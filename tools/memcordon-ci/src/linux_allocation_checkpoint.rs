//! Running-test selection of partial allocation before TargetGated publication.
use serde_json::Value;

pub fn unpublished_guardian_ready(record: &Value) -> bool {
    record["phase"] == "guardian-ready"
        && record["release"] == "not-released"
        && record["intents"]["namespace_init"] == true
        && record["intents"]["target"] == true
        && record["intents"]["guardian"] == true
        && ["namespace_init", "target", "native", "outcome", "terminal"]
            .iter()
            .all(|field| record.get(*field).is_some_and(Value::is_null))
}

pub fn matches_gate(record: &Value, worker_pid: u32, request: &str, caller_uid: u32) -> bool {
    record["format"] == "memcordon.private-workload-journal"
        && record["revision"] == 1
        && record["request_sha256"] == request
        && record["caller_uid"] == caller_uid
        && record["worker"]["pid"] == worker_pid
        && unpublished_guardian_ready(record)
}
