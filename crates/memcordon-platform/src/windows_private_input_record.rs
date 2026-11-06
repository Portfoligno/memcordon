//! Bounded observations only: native sealing retains exact ACL equality.
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const RECORD_BYTES: usize = 8192;
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObjectRole {
    Fixture,
    Provider,
    LocalDirectory,
    InputDirectory,
    OwnedBase,
}
#[derive(Clone, Debug, Serialize)]
pub struct Context {
    pub role: ObjectRole,
    pub object_index: Option<u32>,
    pub directory: bool,
    pub volume_serial: Option<u32>,
    pub file_index: Option<u64>,
}

pub fn expected_sddl(directory: bool, sid: &str) -> Result<String, String> {
    let mut parts = sid.split('-');
    if parts.next() != Some("S") || parts.next() != Some("1") {
        return Err("unsupported creator SID".into());
    }
    let parts = parts.collect::<Vec<_>>();
    if !(2..=16).contains(&parts.len())
        || parts.iter().any(|part| {
            part.is_empty()
                || !part.bytes().all(|byte| byte.is_ascii_digit())
                || (part.len() > 1 && part.starts_with('0'))
        })
        || !parts[0]
            .parse::<u64>()
            .is_ok_and(|value| value <= 0x0000_ffff_ffff_ffff)
        || parts[1..].iter().any(|part| part.parse::<u32>().is_err())
    {
        return Err("unsupported creator SID".into());
    }
    let flags = if directory { "OICI" } else { "" };
    Ok(format!(
        "D:P(A;{flags};FRFX;;;OW)(A;{flags};FA;;;{sid})(A;{flags};FRFX;;;RC)(A;{flags};FA;;;SY)"
    ))
}
fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn word(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}
fn summary(bytes: &[u8]) -> Value {
    let mut value =
        json!({"bytes":bytes.len(),"sha256":hash(bytes),"status":"malformed","aces":[]});
    if bytes.len() < 8 {
        return value;
    }
    let size = usize::from(word(bytes, 2).unwrap());
    let count = usize::from(word(bytes, 4).unwrap());
    value["revision"] = json!(bytes[0]);
    value["declared_size"] = json!(size);
    value["ace_count"] = json!(count);
    if !matches!(bytes[0], 2 | 4) || size < 8 || size != bytes.len() {
        return value;
    }
    let mut offset: usize = 8;
    let mut rows = Vec::new();
    for index in 0..count {
        let Some(length) = word(bytes, offset.saturating_add(2)).map(usize::from) else {
            return value;
        };
        let Some(end) = offset.checked_add(length).filter(|end| *end <= size) else {
            return value;
        };
        if length < 4 || length & 3 != 0 {
            return value;
        }
        let ace = &bytes[offset..end];
        if matches!(ace[0], 0 | 1) {
            if length < 16 {
                return value;
            }
            let sid = &ace[8..];
            if sid[0] != 1 || sid[1] > 15 || 8usize + usize::from(sid[1]) * 4 != sid.len() {
                return value;
            }
        }
        if index < 8 {
            let mut row = json!({"index":index,"type":ace[0],"flags":ace[1],"bytes":length,"status":"unsupported-ace-type"});
            if matches!(ace[0], 0 | 1) {
                let sid = &ace[8..];
                let sid_len = 8usize + usize::from(sid[1]) * 4;
                row["status"] = json!("decoded");
                row["mask"] = json!(u32::from_le_bytes(ace[4..8].try_into().unwrap()));
                row["sid_bytes"] = json!(sid_len);
                row["sid_sha256"] = json!(hash(sid));
            }
            rows.push(row);
        }
        offset = end;
    }
    value["status"] = json!("bounded-structure-decoded");
    value["used_bytes"] = json!(offset);
    value["aces_omitted"] = json!(count.saturating_sub(8));
    value["aces"] = json!(rows);
    value
}
pub fn readback_diagnostic(
    context: &Context,
    expected: &[u8],
    observed: &[u8],
    control: u16,
    descriptor_revision: u32,
) -> Value {
    let mut value = json!({"format":"memcordon.private-input-dacl-readback","revision":1,
        "diagnostic_only":true,"acceptance_authority":false,"context":context,
        "control":control,"descriptor_revision":descriptor_revision,
        "protection_missing":control & 0x1000 == 0,"raw_acl_equal":expected==observed,
        "comparison":"strict-raw-bytes-and-protected-bit",
        "first_differing_byte":expected.iter().zip(observed).position(|(a,b)|a!=b).or_else(||(expected.len()!=observed.len()).then_some(expected.len().min(observed.len()))),
        "expected":summary(expected),"observed":summary(observed),"raw_sid_or_acl_exported":false});
    if serde_json::to_vec(&value).expect("fixed JSON").len() > RECORD_BYTES {
        value["expected"]["aces"] = json!([]);
        value["observed"]["aces"] = json!([]);
        value["ace_details_omitted_for_record_bound"] = json!(true);
    }
    value
}
