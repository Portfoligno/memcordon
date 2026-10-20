//! Private measured-fixture association validation, not wire request admission.

/// Join the real acquired-resource checkpoint to the independently validated
/// lease owner. Lease id and deadlines remain bound by the enclosing harness.
pub fn validate_interrupted_checkpoint(
    owner: &serde_json::Value,
    acquired: &serde_json::Value,
) -> Result<(), String> {
    if acquired["format"] != "memcordon.owned-readiness-resources"
        || acquired["revision"] != 1
        || !acquired["identity"].is_object()
        || !acquired["cell"].is_object()
        || !acquired["legacy"].is_object()
        || acquired["admin_root"]
            .as_str()
            .is_none_or(|path| !std::path::Path::new(path).is_absolute())
        || !acquired["device"].is_u64()
        || !acquired["inode"].is_u64()
        || [
            "identity",
            "cell",
            "admin_root",
            "device",
            "inode",
            "legacy",
        ]
        .iter()
        .any(|field| acquired[*field] != owner[*field])
    {
        return Err("original recovery partial acquisition association differs".into());
    }
    Ok(())
}
