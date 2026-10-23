//! The memory fixture pauses an executing supervisor, never a prepared target.
use serde_json::Value;

#[derive(Debug, Eq, PartialEq)]
pub enum Checkpoint {
    PendingExecution,
    Executing,
}

/// Project the checkpoint from the exact source already retained and validated
/// by the native worker acquisition. Pending is not intervention permission.
pub fn checkpoint(source: &Value) -> Result<Checkpoint, String> {
    let array = source["journal_bytes"]
        .as_array()
        .ok_or("memory journal bytes absent")?;
    if array.is_empty() || array.len() > 1024 * 1024 {
        return Err("memory checkpoint journal extent differs".into());
    }
    let bytes: Vec<u8> =
        serde_json::from_value(source["journal_bytes"].clone()).map_err(|e| e.to_string())?;
    if source["journal_sha256"] != super::artifacts::checksum(&bytes) {
        return Err("memory checkpoint source hash differs".into());
    }
    let text = std::str::from_utf8(&bytes).map_err(|e| e.to_string())?;
    let (body, digest) = text
        .rsplit_once("digest=")
        .ok_or("memory checkpoint checksum absent")?;
    if digest != format!("{}\n", super::artifacts::checksum(body.as_bytes())) {
        return Err("memory checkpoint durable checksum differs".into());
    }
    let attempt = source["attempt_id"]
        .as_str()
        .ok_or("memory checkpoint attempt absent")?;
    if attempt.len() != 32
        || !attempt
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || !source["admission"].is_object()
        || source["admission"]["attempt_id"] != attempt
        || source["worker"]["pid"]
            .as_u64()
            .is_none_or(|pid| pid == 0 || pid > u32::MAX as u64)
        || source["worker"]["birth"]
            .as_u64()
            .is_none_or(|birth| birth == 0)
    {
        return Err("memory checkpoint original source identity absent or invalid".into());
    }
    let mut lines = body.lines();
    if lines.next() != Some("format=memcordon.private-native-journal")
        || lines.next() != Some("revision=1")
        || lines.next() != Some(format!("cgroup={attempt}").as_str())
    {
        return Err("memory checkpoint journal envelope differs".into());
    }
    let payload = lines
        .next()
        .and_then(|line| line.strip_prefix("payload="))
        .ok_or("memory checkpoint payload absent")?;
    if lines.next().is_some() {
        return Err("memory checkpoint extra envelope fields".into());
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(payload.as_bytes())?;
    let journal: Value = serde_json::from_str(payload).map_err(|e| e.to_string())?;
    if journal["attempt_id"] != attempt
        || journal["mixed_admission_metadata"] != source["admission"]
        || journal["mixed_worker"]["pid"] != source["worker"]["pid"]
        || journal["mixed_worker"]["start_time"] != source["worker"]["birth"]
    {
        return Err("memory checkpoint crosses original retained worker/admission".into());
    }
    match (
        journal["phase"].as_str(),
        journal["release_knowledge"].as_str(),
    ) {
        (Some("execution-observed"), Some("exec-observed")) => Ok(Checkpoint::Executing),
        (Some("release-intent"), Some("possibly-released")) => Ok(Checkpoint::PendingExecution),
        _ => Err(format!(
            "memory worker checkpoint is not pending/executing: phase={} release_knowledge={}",
            journal["phase"], journal["release_knowledge"]
        )),
    }
}
