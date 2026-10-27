//! Exact diagnostic-only counterfactual contract; never readiness authority.
use crate::startup_probe_contract::{DEFAULT_DACL_BYTES, describe_default_dacl};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const RESTRICTED_CODE: &str = "S-1-5-12";
const GENERIC_ALL: u32 = 0x1000_0000;

/// Token object identity and mutation counters are observations, not stable
/// security properties of a new token object. All other captured facts remain
/// equal across the private duplicate and the actual suspended primary.
pub fn unchanged_security(left: &Value, right: &Value) -> bool {
    fn stable(value: &Value) -> Option<Value> {
        let security = value.get("security")?.as_object()?;
        let mut statistics = value.get("statistics")?.as_object()?.clone();
        let token_type = statistics.get("token_type")?.as_u64()?;
        if security.get("envelope")?.get("token_type")?.as_u64()? != token_type {
            return None;
        }
        match token_type {
            1 if statistics.get("impersonation_level")?.is_null() => {}
            2 if statistics.get("impersonation_level")?.as_u64()? <= 3 => {}
            _ => return None,
        }
        for field in ["token_id", "modified_id"] {
            statistics.remove(field)?.as_u64()?;
        }
        Some(json!({"security":security,"statistics":statistics}))
    }
    match (stable(left), stable(right)) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

/// Bounded evidence for a refusal before any ACL change or changed target.
/// Full snapshots are deliberately omitted; hashes bind their exact bytes.
pub fn duplicate_refusal(source: &Value, duplicate: &Value) -> Value {
    fn summary(value: &Value) -> Value {
        let bytes = serde_json::to_vec(value).expect("JSON value serializes");
        json!({"bytes":bytes.len(),"sha256":hex::encode(Sha256::digest(&bytes)),"snapshot_omitted":true})
    }
    let field_value = |value: &Value| {
        let bytes = serde_json::to_vec(value).expect("JSON value serializes");
        json!({"bytes":bytes.len(),"sha256":hex::encode(Sha256::digest(&bytes)),
            "value":(bytes.len() <= 512).then_some(value),"value_omitted":bytes.len() > 512})
    };
    let mut fields = Vec::new();
    for (section, keys) in [
        (
            "security",
            &[
                "envelope",
                "user",
                "owner",
                "primary_group",
                "integrity",
                "groups",
                "restricting_sids",
            ][..],
        ),
        (
            "statistics",
            &[
                "authentication_id",
                "expiration",
                "token_type",
                "impersonation_level",
                "group_count",
                "privilege_count",
            ][..],
        ),
    ] {
        for key in keys {
            if source[section][key] != duplicate[section][key] {
                fields.push(json!({"section":section,"field":key,
                    "source":field_value(&source[section][key]),"duplicate":field_value(&duplicate[section][key])}));
            }
        }
    }
    let acl = |value: &Value| {
        let raw = value["default_dacl"]["facts"]["raw_hex"].as_str();
        json!({"capture":summary(&value["default_dacl"]),
            "raw_hex":raw.filter(|raw| raw.len() <= DEFAULT_DACL_BYTES * hex::encode([0_u8]).len()),
            "raw_omitted":raw.is_some_and(|raw| raw.len() > DEFAULT_DACL_BYTES * hex::encode([0_u8]).len())})
    };
    json!({"stage":"duplicate-before-intervention","acl_set_attempted":false,"changed_target_started":false,
        "duplicate_created":true,"noninheritable_handle_checked":true,"inconclusive":true,
        "security_equal":unchanged_security(source,duplicate),
        "source_security_valid":unchanged_security(source,source),"duplicate_security_valid":unchanged_security(duplicate,duplicate),
        "default_acl_equal":crate::startup_probe_contract::default_dacl_equality(&source["default_dacl"],&duplicate["default_dacl"]),
        "source_token_type":source["statistics"]["token_type"],"duplicate_token_type":duplicate["statistics"]["token_type"],
        "source":summary(source),"duplicate":summary(duplicate),"source_acl":acl(source),"duplicate_acl":acl(duplicate),
        "differing_fields":fields,"field_inventory":"closed token snapshot fields; full snapshots omitted"})
}

#[derive(Clone, Copy)]
pub struct BaselineEvidence {
    pub work_exit: Option<u32>,
    pub natural_exit: bool,
    pub fixture_entry: bool,
    pub native_retirement_complete: bool,
    pub pending_debug_event: bool,
    pub event_omissions: u64,
    pub stream_omissions: u64,
    pub source_default_acl_equal: Option<bool>,
    pub original_work_deadline_live: bool,
}

pub fn eligible_baseline(evidence: BaselineEvidence) -> bool {
    evidence.work_exit == Some(0xc000_0142)
        && evidence.natural_exit
        && !evidence.fixture_entry
        && evidence.native_retirement_complete
        && !evidence.pending_debug_event
        && evidence.event_omissions == 0
        && evidence.stream_omissions == 0
        && evidence.source_default_acl_equal == Some(true)
        && evidence.original_work_deadline_live
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Interpretation {
    BoundFixtureEntry,
    SameNaturalInitializationFailure,
    Inconclusive,
}

pub fn interpret_changed(
    bound_fixture_entry: bool,
    work_exit: Option<u32>,
    cleanup_forced: bool,
    complete_retirement: bool,
    omitted: bool,
    original_work_deadline_expired: bool,
) -> Interpretation {
    if !complete_retirement || omitted || original_work_deadline_expired {
        Interpretation::Inconclusive
    } else if bound_fixture_entry {
        // Terminating the never-released gate holder after proven entry is
        // expected cleanup, and never evidence of a natural startup failure.
        Interpretation::BoundFixtureEntry
    } else if !cleanup_forced && work_exit == Some(0xc000_0142) {
        Interpretation::SameNaturalInitializationFailure
    } else {
        Interpretation::Inconclusive
    }
}

pub fn expected_acl(source: &Value, restricting: &Value) -> Result<Vec<u8>, String> {
    if source["captured"] != true
        || restricting["captured"] != true
        || restricting["facts"]["complete"] != true
    {
        return Err("counterfactual requires complete original token captures".into());
    }
    let entries = restricting["facts"]["entries"]
        .as_array()
        .ok_or("restricting SID inventory absent")?;
    if entries.len() != 1
        || entries[0]["sid"] != RESTRICTED_CODE
        || entries[0]["enabled"] != true
        || entries[0]["deny_only"] != false
        || entries[0]["attributes"]
            .as_u64()
            .is_none_or(|attributes| attributes & 4 == 0 || attributes & 16 != 0)
    {
        return Err("counterfactual requires the sole enabled RestrictedCode SID".into());
    }
    let encoded = source["facts"]["raw_hex"]
        .as_str()
        .ok_or("counterfactual default ACL is null or absent")?;
    if encoded.len() > DEFAULT_DACL_BYTES * hex::encode([0_u8]).len() {
        return Err("counterfactual source ACL exceeds bound".into());
    }
    let mut raw = hex::decode(encoded).map_err(|error| error.to_string())?;
    let parsed = describe_default_dacl(Some(&raw))?;
    if parsed != source["facts"] || parsed["null"] != false || parsed["unused_bytes"] != 0 {
        return Err(
            "counterfactual source ACL capture is inconsistent or has opaque padding".into(),
        );
    }
    let aces = parsed["aces"]
        .as_array()
        .ok_or("counterfactual ACE inventory absent")?;
    if aces.is_empty()
        || aces.iter().any(|ace| {
            ace["type"] != 0
                || ace["flags"] != 0
                || ace["parsed"] != true
                || ace["sid"] == RESTRICTED_CODE
        })
    {
        return Err(
            "counterfactual accepts only original explicit noninherited allow ACEs without RC"
                .into(),
        );
    }
    let mut ace = vec![0, 0, 0, 0];
    ace.extend_from_slice(&GENERIC_ALL.to_le_bytes());
    ace.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 5]);
    ace.extend_from_slice(&12_u32.to_le_bytes());
    let ace_size = u16::try_from(ace.len()).map_err(|error| error.to_string())?;
    ace[2..4].copy_from_slice(&ace_size.to_le_bytes());
    let size = raw
        .len()
        .checked_add(ace.len())
        .filter(|size| *size <= DEFAULT_DACL_BYTES)
        .ok_or("counterfactual appended ACL exceeds original bound")?;
    let size = u16::try_from(size).map_err(|error| error.to_string())?;
    let count = u16::try_from(aces.len() + 1).map_err(|error| error.to_string())?;
    raw.extend_from_slice(&ace);
    raw[2..4].copy_from_slice(&size.to_le_bytes());
    raw[4..6].copy_from_slice(&count.to_le_bytes());
    describe_default_dacl(Some(&raw))?;
    Ok(raw)
}

pub fn verify_delta(
    source: &Value,
    source_after: &Value,
    restricting: &Value,
    changed: &Value,
) -> Result<(), String> {
    if crate::startup_probe_contract::default_dacl_equality(source, source_after) != Some(true) {
        return Err("counterfactual original source default ACL changed or is incomplete".into());
    }
    let expected = expected_acl(source, restricting)?;
    if changed["captured"] != true || changed["facts"] != describe_default_dacl(Some(&expected))? {
        return Err("counterfactual duplicate differs from the sole intended ACL delta".into());
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Started {
    sequence: u32,
    stage: String,
    pid: u32,
    ordinal: Option<u32>,
    value: Vec<u8>,
}

/// A partial first frame is not entry evidence. The native caller additionally
/// holds and rechecks the fresh target's birth and liveness while reading it.
pub fn bound_entry(bytes: &[u8], pid: u32, challenge: &[u8], bound: usize) -> Result<bool, String> {
    let width = size_of::<u32>();
    if bytes.len() > bound || pid == 0 || challenge.is_empty() {
        return Err("counterfactual entry identity or transcript bound differs".into());
    }
    let Some(header) = bytes.get(..width) else {
        return Ok(false);
    };
    let length = usize::try_from(u32::from_le_bytes(header.try_into().expect("frame width")))
        .map_err(|error| error.to_string())?;
    let end = width
        .checked_add(length)
        .filter(|end| *end <= bound)
        .ok_or("counterfactual first frame exceeds transcript bound")?;
    let Some(frame) = bytes.get(width..end) else {
        return Ok(false);
    };
    memcordon_core::canonical_json::reject_duplicate_json_keys(frame)?;
    let event: Started = serde_json::from_slice(frame).map_err(|error| error.to_string())?;
    if event.sequence != 0
        || event.stage != "started"
        || event.pid != pid
        || event.ordinal.is_some()
        || event.value != challenge
    {
        return Err("counterfactual fixture entry differs from fresh held target/challenge".into());
    }
    Ok(true)
}
