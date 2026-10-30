//! Conservative descriptor projection; never an access-granting authority.
use serde::Serialize;

pub const MAX_SD_BYTES: usize = 4096;
pub const DIRECTORY_BITS: [u32; 4] = [1, 2, 4, 8];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct BindingFacts {
    pub root_same: Option<bool>,
    pub child_same: Option<bool>,
    pub sd_equal: Option<bool>,
    pub label_equal: Option<bool>,
    pub token_equal: Option<bool>,
    pub requested_token_matches: bool,
}
/// Sequential matching samples qualify an explanation, never attest atomicity
/// or the kernel-resolved identity of a denied lookup that returned no handle.
pub fn stable_binding(facts: &BindingFacts) -> bool {
    facts.requested_token_matches
        && [
            facts.root_same,
            facts.child_same,
            facts.sd_equal,
            facts.label_equal,
            facts.token_equal,
        ]
        .into_iter()
        .all(|fact| fact == Some(true))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum PolicyError {
    Bound,
    Header,
    Offset,
    Sid,
    Acl,
    Ace,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SidEntry {
    pub sid: String,
    pub attributes: u32,
}
#[derive(Clone, Debug, Serialize)]
pub struct Subject {
    pub user: SidEntry,
    pub groups: Vec<SidEntry>,
    pub restricted: Vec<SidEntry>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Ace {
    pub index: usize,
    pub ace_type: u8,
    pub flags: u8,
    pub mask: Option<u32>,
    pub sid: Option<String>,
    pub raw_hex: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum Acl {
    Absent,
    Null,
    Present { revision: u8, aces: Vec<Ace> },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Descriptor {
    pub control: u16,
    pub owner: Option<String>,
    pub group: Option<String>,
    pub dacl: Acl,
    pub sacl: Acl,
}
fn region(bytes: &[u8], at: usize, length: usize) -> Result<&[u8], PolicyError> {
    bytes
        .get(at..at.checked_add(length).ok_or(PolicyError::Offset)?)
        .ok_or(PolicyError::Offset)
}
fn word(bytes: &[u8], at: usize) -> Result<u16, PolicyError> {
    Ok(u16::from_le_bytes(
        region(bytes, at, 2)?.try_into().unwrap(),
    ))
}
fn dword(bytes: &[u8], at: usize) -> Result<u32, PolicyError> {
    Ok(u32::from_le_bytes(
        region(bytes, at, 4)?.try_into().unwrap(),
    ))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn sid(bytes: &[u8]) -> Result<(String, usize), PolicyError> {
    if bytes.len() < 8 || bytes[0] != 1 || bytes[1] > 15 {
        return Err(PolicyError::Sid);
    }
    let length = 8 + usize::from(bytes[1]) * 4;
    let bytes = region(bytes, 0, length).map_err(|_| PolicyError::Sid)?;
    let authority = bytes[2..8]
        .iter()
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
    if authority > u64::from(u32::MAX) {
        return Err(PolicyError::Sid);
    }
    let mut parts = vec!["S".to_owned(), "1".to_owned(), authority.to_string()];
    for value in bytes[8..].chunks_exact(4) {
        parts.push(u32::from_le_bytes(value.try_into().unwrap()).to_string());
    }
    Ok((parts.join("-"), length))
}
fn optional_sid(bytes: &[u8], offset: u32) -> Result<Option<String>, PolicyError> {
    if offset == 0 {
        return Ok(None);
    }
    let at = offset as usize;
    if at < 20 || at % 4 != 0 {
        return Err(PolicyError::Offset);
    }
    Ok(Some(
        sid(region(
            bytes,
            at,
            bytes.len().checked_sub(at).ok_or(PolicyError::Offset)?,
        )?)?
        .0,
    ))
}
fn acl(bytes: &[u8], present: bool, offset: u32) -> Result<Acl, PolicyError> {
    if !present {
        if offset != 0 {
            return Err(PolicyError::Acl);
        }
        return Ok(Acl::Absent);
    }
    if offset == 0 {
        return Ok(Acl::Null);
    }
    let at = offset as usize;
    if at < 20 || at % 4 != 0 {
        return Err(PolicyError::Offset);
    }
    let header = region(bytes, at, 8)?;
    if !matches!(header[0], 2 | 4) {
        return Err(PolicyError::Acl);
    }
    let length = usize::from(word(header, 2)?);
    let count = usize::from(word(header, 4)?);
    if length < 8 || length % 4 != 0 || count > 256 {
        return Err(PolicyError::Acl);
    }
    let body = region(bytes, at, length)?;
    let mut next = 8;
    let mut aces = Vec::new();
    for index in 0..count {
        let header = region(body, next, 4).map_err(|_| PolicyError::Ace)?;
        let length = usize::from(word(header, 2)?);
        if length < 4 || length % 4 != 0 {
            return Err(PolicyError::Ace);
        }
        let raw = region(body, next, length).map_err(|_| PolicyError::Ace)?;
        let (mask, identity) = if matches!(header[0], 0 | 1 | 17) {
            if length < 16 {
                return Err(PolicyError::Ace);
            }
            let (identity, used) = sid(&raw[8..])?;
            if 8 + used != length {
                return Err(PolicyError::Ace);
            }
            (Some(dword(raw, 4)?), Some(identity))
        } else {
            (None, None)
        };
        aces.push(Ace {
            index,
            ace_type: header[0],
            flags: header[1],
            mask,
            sid: identity,
            raw_hex: hex(raw),
        });
        next += length;
    }
    Ok(Acl::Present {
        revision: body[0],
        aces,
    })
}
pub fn decode_descriptor(bytes: &[u8]) -> Result<Descriptor, PolicyError> {
    if bytes.len() < 20 || bytes.len() > MAX_SD_BYTES {
        return Err(PolicyError::Bound);
    }
    if bytes[0] != 1 {
        return Err(PolicyError::Header);
    }
    let control = word(bytes, 2)?;
    if control & 0x8000 == 0 {
        return Err(PolicyError::Header);
    }
    Ok(Descriptor {
        control,
        owner: optional_sid(bytes, dword(bytes, 4)?)?,
        group: optional_sid(bytes, dword(bytes, 8)?)?,
        sacl: acl(bytes, control & 0x10 != 0, dword(bytes, 12)?)?,
        dacl: acl(bytes, control & 4 != 0, dword(bytes, 16)?)?,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum Decision {
    Allowed { ace: Option<usize> },
    Denied { ace: Option<usize> },
    Unresolved { reason: &'static str },
    NotApplicable,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BitDecision {
    pub bit: u32,
    pub decision: Decision,
}
#[derive(Clone, Debug, Serialize)]
pub struct Explanation {
    pub diagnostic_only: bool,
    pub acceptance_authority: bool,
    pub normal: Vec<BitDecision>,
    pub restricted: Vec<BitDecision>,
}
fn pass(acl: &Acl, subject: &Subject, bit: u32, restricted: bool) -> Decision {
    if restricted && subject.restricted.is_empty() {
        return Decision::NotApplicable;
    }
    let Acl::Present { aces, .. } = acl else {
        return Decision::Allowed { ace: None };
    };
    // Unsupported applicable ACEs withhold the projection, including any earlier grant.
    if aces.iter().any(|ace| {
        ace.flags & 8 == 0
            && (!matches!(ace.ace_type, 0 | 1)
                || ace.flags & !0x1f != 0
                || ace
                    .sid
                    .as_ref()
                    .is_some_and(|sid| sid.starts_with("S-1-3-") || sid == "S-1-5-10")
                || ace.mask.is_none_or(|mask| mask & 0xf0000000 != 0))
    }) {
        return Decision::Unresolved {
            reason: "unsupported ACE, flags, substituted trustee or generic mapping",
        };
    }
    for ace in aces {
        if ace.flags & 8 != 0 || ace.mask.unwrap() & bit == 0 {
            continue;
        }
        let identity = ace.sid.as_ref().expect("ordinary ACE has SID");
        let deny = ace.ace_type == 1;
        let matches = if restricted {
            subject
                .restricted
                .iter()
                .any(|entry| entry.sid == *identity && (deny || entry.attributes & 0x10 == 0))
        } else {
            (subject.user.sid == *identity && (deny || subject.user.attributes & 0x10 == 0))
                || subject.groups.iter().any(|entry| {
                    entry.sid == *identity
                        && if deny {
                            entry.attributes & (4 | 0x10) != 0
                        } else {
                            entry.attributes & 4 != 0 && entry.attributes & 0x10 == 0
                        }
                })
        };
        if matches {
            return if deny {
                Decision::Denied {
                    ace: Some(ace.index),
                }
            } else {
                Decision::Allowed {
                    ace: Some(ace.index),
                }
            };
        }
    }
    Decision::Denied { ace: None }
}
pub fn explain(descriptor: &Descriptor, subject: &Subject, desired: u32) -> Explanation {
    let bits: Vec<_> = (0..u32::BITS)
        .map(|bit| 1u32 << bit)
        .filter(|bit| desired & bit != 0)
        .collect();
    let project = |restricted| {
        bits.iter()
            .map(|bit| BitDecision {
                bit: *bit,
                decision: if DIRECTORY_BITS.contains(bit) {
                    pass(&descriptor.dacl, subject, *bit, restricted)
                } else {
                    Decision::Unresolved {
                        reason: "outside directory-specific projection",
                    }
                },
            })
            .collect()
    };
    Explanation {
        diagnostic_only: true,
        acceptance_authority: false,
        normal: project(false),
        restricted: project(true),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum Label {
    Observed {
        integrity_sid: String,
        integrity_rid: u32,
        mask: u32,
    },
    DefaultMedium,
    Unavailable,
    Unsupported,
}
pub fn mandatory_label(descriptor: Option<&Descriptor>) -> Label {
    let Some(descriptor) = descriptor else {
        return Label::Unavailable;
    };
    let Acl::Present { aces, .. } = &descriptor.sacl else {
        return Label::DefaultMedium;
    };
    let labels: Vec<_> = aces
        .iter()
        .filter(|ace| ace.ace_type == 17 && ace.flags & 8 == 0)
        .collect();
    if labels.is_empty() {
        return Label::DefaultMedium;
    }
    if labels.len() != 1 {
        return Label::Unsupported;
    }
    let ace = labels[0];
    if ace.flags & !0x1f != 0 {
        return Label::Unsupported;
    }
    let identity = ace.sid.as_ref().unwrap();
    let Some(rid) = identity
        .strip_prefix("S-1-16-")
        .and_then(|value| value.parse::<u32>().ok())
    else {
        return Label::Unsupported;
    };
    if ace.mask.unwrap() & !7 != 0 {
        return Label::Unsupported;
    }
    Label::Observed {
        integrity_sid: identity.clone(),
        integrity_rid: rid,
        mask: ace.mask.unwrap(),
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct MicFacts {
    pub token_integrity_sid: String,
    pub token_mandatory_policy: u32,
    pub object_integrity_rid: Option<u32>,
    pub object_label_mask: Option<u32>,
    pub token_lower_than_object: Option<bool>,
    pub scope: &'static str,
}
pub fn mic_facts(label: &Label, token_integrity: &str, mandatory_policy: u32) -> MicFacts {
    let token = token_integrity
        .strip_prefix("S-1-16-")
        .and_then(|value| value.parse::<u32>().ok());
    let object = match label {
        Label::Observed {
            integrity_rid,
            mask,
            ..
        } => Some((*integrity_rid, *mask)),
        Label::DefaultMedium => Some((0x2000, 1)),
        _ => None,
    };
    MicFacts {
        token_integrity_sid: token_integrity.to_owned(),
        token_mandatory_policy: mandatory_policy,
        object_integrity_rid: object.map(|value| value.0),
        object_label_mask: object.map(|value| value.1),
        token_lower_than_object: token.zip(object).map(|(token, object)| token < object.0),
        scope: "MIC input facts only; Authz and DACL projection do not attest the kernel mandatory-policy decision",
    }
}
