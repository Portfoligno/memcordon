//! Running-test selection of partial allocation before TargetGated publication.
use serde_json::Value;

pub fn acquired_guardian_ready(record: &Value) -> bool {
    record["phase"] == "guardian-ready"
        && record["release"] == "not-released"
        && record["intents"]["namespace_init"] == true
        && record["intents"]["target"] == true
        && record["intents"]["guardian"] == true
        && ["namespace_init", "target"].iter().all(|field| {
            record[*field]["pid"]
                .as_u64()
                .is_some_and(|pid| pid > 0 && u32::try_from(pid).is_ok())
                && record[*field]["start_time"].as_u64().is_some()
        })
        && record["namespace_init"]["pid"] != record["target"]["pid"]
        && ["native", "outcome", "terminal"]
            .iter()
            .all(|field| record.get(*field).is_some_and(Value::is_null))
}

pub fn matches_gate(record: &Value, worker_pid: u32, request: &str, caller_uid: u32) -> bool {
    record["format"] == "memcordon.private-workload-journal"
        && record["revision"] == 1
        && record["request_sha256"] == request
        && record["caller_uid"] == caller_uid
        && record["worker"]["pid"] == worker_pid
        && acquired_guardian_ready(record)
}
