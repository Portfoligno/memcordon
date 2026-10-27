//! Bounded producer evidence; never an authenticated export result.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{io, path::Path};

pub const PREFIX_BYTES: usize = crate::producer_failure_forwarding::CAPTURE_PREFIX_BYTES;

pub fn binding(
    attempt: &str,
    expected_result: &Path,
    actual_result: &Path,
    request: &Path,
) -> io::Result<()> {
    if attempt.len() != size_of::<[u8; 16]>() * 2
        || !attempt
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        || expected_result != actual_result
        || actual_result.file_name() != Some(std::ffi::OsStr::new("result.json"))
        || request
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".provider-request.bin"))
            != Some(attempt)
        || request.parent()
            != actual_result
                .parent()
                .map(|parent| parent.join("observations"))
                .as_deref()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "original export producer attempt/path binding differs",
        ));
    }
    Ok(())
}

pub fn capture(result: io::Result<Vec<u8>>) -> Value {
    match result {
        Ok(bytes) => {
            let prefix = &bytes[..bytes.len().min(PREFIX_BYTES)];
            json!({"state":"observed","original_bytes":bytes.len(),"sha256":hex::encode(Sha256::digest(&bytes)),"prefix_hex":hex::encode(prefix),"omitted_bytes":bytes.len()-prefix.len(),"diagnostic_only":true})
        }
        Err(error) => {
            json!({"state":"unavailable","kind":format!("{:?}",error.kind()),"raw_os_error":error.raw_os_error(),"diagnostic_only":true})
        }
    }
}
