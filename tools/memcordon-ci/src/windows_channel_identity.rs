//! Semantic parity of independently built Windows package channels.
//!
//! Each channel retains its actual installed image hashes separately.

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{CiError, Result};

pub fn package_contract(mut package: Value) -> Result<Value> {
    let object = package.as_object_mut().ok_or_else(|| {
        CiError::Message("Windows package inspection is not an object".to_owned())
    })?;
    // Never strip security/configuration or loader-contract hashes here.
    for field in [
        "executable_sha256",
        "target_desktop_bootstrap_sha256",
        "session_broker_sha256",
    ] {
        if !object
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(|digest| {
                digest.len() == Sha256::output_size() * 2
                    && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        {
            return Err(CiError::Message(format!(
                "Windows package inspection has an invalid {field}"
            )));
        }
        object.remove(field);
    }
    Ok(package)
}
