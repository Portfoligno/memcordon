//! Independent decoding of diagnostic native control-site metadata.
use crate::VerificationResult;
use serde_json::Value;

fn shape(value: &Value, fields: &[&str]) -> VerificationResult<()> {
    let object = value.as_object().ok_or("control site is not an object")?;
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err("control site has missing or unknown fields".into());
    }
    Ok(())
}

pub fn validate(
    site: &Value,
    attempt: &str,
    nonce: &str,
    request: &str,
    fault: &str,
    target: u64,
) -> VerificationResult<()> {
    shape(
        site,
        &[
            "format",
            "revision",
            "attempt_id",
            "nonce",
            "request_sha256",
            "fault",
            "process",
            "thread",
            "target_pid",
            "target_authorization_observed",
        ],
    )?;
    shape(&site["process"], &["process_id", "creation_time_100ns"])?;
    shape(&site["thread"], &["thread_id", "creation_time_100ns"])?;
    crate::digest(attempt)?;
    crate::digest(request)?;
    if site["format"] != "memcordon.windows-component-control-worker-site"
        || site["revision"] != 1
        || site["attempt_id"] != attempt
        || site["nonce"] != nonce
        || nonce.is_empty()
        || site["request_sha256"] != request
        || site["fault"] != fault
        || !matches!(
            fault,
            "control-worker-killed-after-authorization"
                | "control-service-killed-after-authorization"
        )
        || target == 0
        || target > u64::from(u32::MAX)
        || site["target_pid"] != target
        || site["target_authorization_observed"] != true
        || site["process"]["process_id"]
            .as_u64()
            .is_none_or(|pid| pid == 0 || pid > u64::from(u32::MAX))
        || site["thread"]["thread_id"]
            .as_u64()
            .is_none_or(|tid| tid == 0 || tid > u64::from(u32::MAX))
        || site["process"]["creation_time_100ns"]
            .as_u64()
            .is_none_or(|birth| birth == 0)
        || site["thread"]["creation_time_100ns"]
            .as_u64()
            .is_none_or(|birth| birth == 0)
    {
        return Err("control site native identity or request binding differs".into());
    }
    Ok(())
}
