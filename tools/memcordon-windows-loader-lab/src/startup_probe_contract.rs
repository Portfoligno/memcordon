//! Diagnostic token equivalence; never authorization or startup certification.
use memcordon_core::WindowsCallerTokenEnvelopeV1;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const DEFAULT_DACL_BYTES: usize = 8 * 1024;
const DEFAULT_DACL_ACES: usize = 64;

/// Decode only a bounded retained ACL slice, never a native pointer. Raw bytes
/// remain available even when an ACE's semantic form is not decoded here.
pub fn describe_default_dacl(raw: Option<&[u8]>) -> Result<Value, String> {
    let Some(raw) = raw else {
        return Ok(json!({"null":true,"raw_hex":null,"sha256":null}));
    };
    if raw.len() < 8 || raw.len() > DEFAULT_DACL_BYTES {
        return Err("default DACL size outside diagnostic bound".into());
    }
    let size = usize::from(u16::from_le_bytes([raw[2], raw[3]]));
    let count = usize::from(u16::from_le_bytes([raw[4], raw[5]]));
    if !matches!(raw[0], 2 | 4) || size != raw.len() || count > DEFAULT_DACL_ACES {
        return Err("default DACL header or ACE count outside diagnostic bound".into());
    }
    let mut offset: usize = 8;
    let mut aces = Vec::with_capacity(count);
    for _ in 0..count {
        let header = raw
            .get(offset..offset + 4)
            .ok_or("default DACL ACE header truncated")?;
        let length = usize::from(u16::from_le_bytes([header[2], header[3]]));
        if length < 4 || length % 4 != 0 {
            return Err("default DACL ACE size invalid".into());
        }
        let end = offset
            .checked_add(length)
            .ok_or("default DACL ACE extent overflow")?;
        let ace = raw.get(offset..end).ok_or("default DACL ACE escapes ACL")?;
        let mut entry = json!({"type":ace[0],"flags":ace[1],"size":length,"raw_hex":hex::encode(ace),"parsed":false});
        if matches!(ace[0], 0 | 1 | 2 | 3 | 17) {
            let mask = ace.get(4..8).ok_or("default DACL ACE mask truncated")?;
            let sid = ace.get(8..).ok_or("default DACL ACE SID truncated")?;
            if sid.len() < 8
                || sid[0] != 1
                || sid[1] > 15
                || sid.len() != 8 + usize::from(sid[1]) * size_of::<u32>()
            {
                return Err("default DACL ACE SID extent invalid".into());
            }
            let authority = sid[2..8]
                .iter()
                .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte));
            let mut text = format!("S-{}-{authority}", sid[0]);
            for part in sid[8..].chunks_exact(size_of::<u32>()) {
                use std::fmt::Write;
                write!(
                    &mut text,
                    "-{}",
                    u32::from_le_bytes(part.try_into().expect("SID subauthority width"))
                )
                .map_err(|error| error.to_string())?;
            }
            entry["mask"] = json!(u32::from_le_bytes(mask.try_into().expect("ACE mask width")));
            entry["sid"] = json!(text);
            entry["parsed"] = json!(true);
        } else {
            entry["semantic_omission"] = json!("ACE kind not decoded; complete raw ACE retained");
        }
        aces.push(entry);
        offset = end;
    }
    Ok(
        json!({"null":false,"revision":raw[0],"size":size,"ace_count":count,
        "raw_hex":hex::encode(raw),"sha256":hex::encode(Sha256::digest(raw)),"aces":aces,
        "unused_bytes":raw.len()-offset}),
    )
}

/// Failed captures never stand in for a null or empty ACL.
pub fn default_dacl_equality(source: &Value, actual: &Value) -> Option<bool> {
    fn complete_bytes(capture: &Value) -> Option<Option<Vec<u8>>> {
        if !capture.get("captured")?.as_bool()? {
            return None;
        }
        let facts = capture.get("facts")?;
        let raw = if facts.get("null")?.as_bool()? {
            if !facts.get("raw_hex")?.is_null() {
                return None;
            }
            None
        } else {
            let encoded = facts.get("raw_hex")?.as_str()?;
            if encoded.len() > DEFAULT_DACL_BYTES * hex::encode([0_u8]).len() {
                return None;
            }
            Some(hex::decode(encoded).ok()?)
        };
        // Reconstruct every bounded fact from the raw representation, so
        // missing, contradictory or malformed metadata remains unknown.
        let expected = describe_default_dacl(raw.as_deref()).ok()?;
        if facts != &expected {
            return None;
        }
        Some(raw)
    }
    Some(complete_bytes(source)? == complete_bytes(actual)?)
}

/// Bind a diagnostic reread to the retained resultant before applying the
/// unchanged creation-to-resultant policy contract.
pub fn verify_observed_policy(
    domain: crate::selected_policy::Domain,
    selected: &crate::selected_policy::Snapshot,
    held: &crate::selected_policy::Snapshot,
    actual: &crate::selected_policy::Snapshot,
) -> Result<crate::selected_policy::VerifiedPolicy, String> {
    if actual.raw_sha256 != held.raw_sha256
        || actual.length != held.length
        || actual.selection != held.selection
    {
        return Err("startup USER descriptor differs from original held observation".into());
    }
    crate::selected_policy::verify_and_fingerprint(domain, selected, actual)
}

pub fn validate_token_pair(
    primary: &WindowsCallerTokenEnvelopeV1,
    probe: &WindowsCallerTokenEnvelopeV1,
) -> Result<(), String> {
    // Native TOKEN_TYPE and SECURITY_IMPERSONATION_LEVEL wire values.
    if primary.token_type != 1 || probe.token_type != 2 || probe.impersonation_level != 2 {
        return Err("startup probe token type/impersonation level differs".into());
    }
    let mut comparable = probe.clone();
    comparable.token_type = primary.token_type;
    comparable.impersonation_level = primary.impersonation_level;
    if &comparable != primary {
        return Err("startup probe token differs from original primary beyond its explicit impersonation type/level".into());
    }
    Ok(())
}
