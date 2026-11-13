//! Explicit Unix operand bytes; matching them never substitutes for native custody.
pub fn observation(
    kind: &str,
    source: &[u8],
    probe: &[u8],
    native_errno: Option<i32>,
) -> serde_json::Value {
    serde_json::json!({
        "kind": kind,
        "source": source,
        "probe": probe,
        "native_import_errno": native_errno,
    })
}
