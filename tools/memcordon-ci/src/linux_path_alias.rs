//! Exact lexical Unix path operands from the native isolation transcript.
use crate::{CiError, Result};
use serde_json::Value;

pub fn binary(value: &Value) -> Result<Vec<u8>> {
    Ok(serde_json::from_value(value.clone())?)
}

pub fn verify_alias(alias: &Value, kind: &str, source: &[u8], probe: &[u8]) -> Result<()> {
    if alias["kind"] != kind {
        return Err(CiError::Message("target path alias kind differs".into()));
    }
    for (field, expected) in [("source", source), ("probe", probe)] {
        let actual = binary(&alias[field]).map_err(|error| {
            error.context(format!("target path alias {field} must be a byte array"))
        })?;
        if actual != expected {
            return Err(CiError::Message(format!(
                "target path alias {field} bytes differ; observed-length={}; expected-length={}; observed-sha256={}; expected-sha256={}",
                actual.len(),
                expected.len(),
                String::from(memcordon_core::hash_bytes(&actual)),
                String::from(memcordon_core::hash_bytes(expected))
            )));
        }
    }
    Ok(())
}
