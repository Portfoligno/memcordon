use crate::CiError;
use serde_json::Value;

fn invalid(field: &str) -> CiError {
    CiError::Message(format!(
        "source-FD substitution required {field} is absent or malformed"
    ))
}

fn pid(value: &Value, field: &str) -> Result<u32, CiError> {
    value
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value != 0)
        .ok_or_else(|| invalid(field))
}

fn inode(receipt: &Value, field: &str) -> Result<u64, CiError> {
    receipt
        .get(field)
        .and_then(|value| value.get("inode"))
        .and_then(Value::as_u64)
        .filter(|value| *value != 0)
        .ok_or_else(|| invalid(&format!("{field}.inode")))
}

fn digest<'a>(receipt: &'a Value, field: &str) -> Result<&'a str, CiError> {
    receipt
        .get(field)
        .and_then(|value| value.get("sha256"))
        .and_then(Value::as_str)
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| invalid(&format!("{field}.sha256")))
}

/// Compare captured observations; native custody remains with the original caller.
pub fn validate(permission: &Value, frontend: &Value, receipt: &Value) -> Result<(), CiError> {
    let expected = pid(&frontend["pid"], "frontend.pid")?;
    let observed = pid(&permission["pid"], "permission.pid")?;
    if observed != expected {
        return Err(CiError::Message(format!(
            "source-FD substitution permission PID differs; observed-pid={observed}; held-frontend-pid={expected}"
        )));
    }
    let opened = inode(receipt, "opened")?;
    let named = inode(receipt, "named")?;
    if opened == named {
        return Err(CiError::Message(format!(
            "source-FD substitution inode unchanged; opened-inode={opened}; changed-name-inode={named}; held-frontend-pid={expected}"
        )));
    }
    let opened_digest = digest(receipt, "opened")?;
    let named_digest = digest(receipt, "named")?;
    if opened_digest.eq_ignore_ascii_case(named_digest) {
        return Err(CiError::Message(format!(
            "source-FD substitution digest unchanged; opened-inode={opened}; changed-name-inode={named}; held-frontend-pid={expected}"
        )));
    }
    Ok(())
}
