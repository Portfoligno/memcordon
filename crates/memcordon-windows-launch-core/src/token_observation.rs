//! Optional owned token facts. These are diagnostic correspondence, never authority.
use memcordon_core::WindowsCallerTokenEnvelopeV1;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{self, Write};

pub const TOKEN_OBSERVATION_ENTRY_BOUND: usize = 256;
pub const TOKEN_OBSERVATION_BYTE_BOUND: usize = 8 * 1024;
const SID_SUBAUTHORITIES: usize = 15;
const SID_BOUND: usize =
    "S-1-".len() + "281474976710655".len() + SID_SUBAUTHORITIES * ("-".len() + "4294967295".len());

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SidAttributesV1 {
    pub sid: String,
    pub attributes: u32,
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivilegeAttributesV1 {
    pub luid_high: i32,
    pub luid_low: u32,
    pub attributes: u32,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenStatisticsObservationV1 {
    pub token_id: u64,
    pub modified_id: u64,
    pub expiration_time: i64,
    pub dynamic_charged: u32,
    pub dynamic_available: u32,
    pub group_count: u32,
    pub privilege_count: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObservationUnavailable {
    CountBound,
    SizeBound,
    InvalidSid,
    DigestMismatch,
    CountMismatch,
    NonCanonical,
    NotRequested,
    NativeExtent,
}
impl std::fmt::Display for ObservationUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ObservationUnavailable {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenObservationV1 {
    pub envelope: WindowsCallerTokenEnvelopeV1,
    pub user_attributes: u32,
    pub statistics: TokenStatisticsObservationV1,
    pub normal_groups: Vec<SidAttributesV1>,
    pub restricted_sids: Vec<SidAttributesV1>,
    pub privileges: Vec<PrivilegeAttributesV1>,
}

/// Identical length-prefixed sorted records to the existing native envelope.
/// Diagnostic limits belong to TokenObservationV1, not this production digest.
pub fn sid_attributes_digest(values: &[SidAttributesV1]) -> Result<String, String> {
    let mut values: Vec<_> = values.iter().collect();
    values.sort();
    let mut hash = Sha256::new();
    for value in values {
        let length = value
            .sid
            .len()
            .checked_add(size_of::<u32>())
            .and_then(|length| u32::try_from(length).ok())
            .ok_or_else(|| "token record length overflow".to_owned())?;
        hash.update(length.to_le_bytes());
        hash.update(value.sid.as_bytes());
        hash.update(value.attributes.to_le_bytes());
    }
    Ok(hex::encode(hash.finalize()))
}
pub fn privilege_attributes_digest(values: &[PrivilegeAttributesV1]) -> Result<String, String> {
    let mut values: Vec<_> = values.iter().collect();
    values.sort();
    let mut hash = Sha256::new();
    for value in values {
        let length = u32::try_from(size_of::<i32>() + 2 * size_of::<u32>())
            .map_err(|_| "token record length overflow".to_owned())?;
        hash.update(length.to_le_bytes());
        hash.update(value.luid_high.to_le_bytes());
        hash.update(value.luid_low.to_le_bytes());
        hash.update(value.attributes.to_le_bytes());
    }
    Ok(hex::encode(hash.finalize()))
}
fn decimal(value: &str, bound: u64) -> bool {
    !value.is_empty()
        && (value == "0" || !value.starts_with('0'))
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u64>().is_ok_and(|value| value <= bound)
}
fn sid(value: &str) -> bool {
    if value.len() > SID_BOUND {
        return false;
    }
    let Some(value) = value.strip_prefix("S-1-") else {
        return false;
    };
    let mut pieces = value.split('-');
    let Some(authority) = pieces.next() else {
        return false;
    };
    let authority_valid = if let Some(hex) = authority.strip_prefix("0x") {
        hex.len() == size_of::<[u8; 6]>() * 2
            && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
            && u64::from_str_radix(hex, 16).is_ok_and(|value| value > u64::from(u32::MAX))
    } else {
        decimal(authority, (1u64 << 48) - 1)
    };
    if !authority_valid {
        return false;
    }
    let mut count = 0;
    for piece in pieces {
        count += 1;
        if count > SID_SUBAUTHORITIES || !decimal(piece, u64::from(u32::MAX)) {
            return false;
        }
    }
    // A SID can have zero subauthorities (for example the identifier authority).
    true
}
struct Size(usize);
impl Write for Size {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .filter(|size| *size <= TOKEN_OBSERVATION_BYTE_BOUND)
            .ok_or_else(|| io::Error::other("token observation byte bound"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl TokenObservationV1 {
    pub fn from_parts(
        envelope: WindowsCallerTokenEnvelopeV1,
        user_attributes: u32,
        statistics: TokenStatisticsObservationV1,
        mut normal_groups: Vec<SidAttributesV1>,
        mut restricted_sids: Vec<SidAttributesV1>,
        mut privileges: Vec<PrivilegeAttributesV1>,
    ) -> Result<Self, ObservationUnavailable> {
        if normal_groups.len() > TOKEN_OBSERVATION_ENTRY_BOUND
            || restricted_sids.len() > TOKEN_OBSERVATION_ENTRY_BOUND
            || privileges.len() > TOKEN_OBSERVATION_ENTRY_BOUND
        {
            return Err(ObservationUnavailable::CountBound);
        }
        normal_groups.sort();
        restricted_sids.sort();
        privileges.sort();
        let value = Self {
            envelope,
            user_attributes,
            statistics,
            normal_groups,
            restricted_sids,
            privileges,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), ObservationUnavailable> {
        if self.normal_groups.len() > TOKEN_OBSERVATION_ENTRY_BOUND
            || self.restricted_sids.len() > TOKEN_OBSERVATION_ENTRY_BOUND
            || self.privileges.len() > TOKEN_OBSERVATION_ENTRY_BOUND
        {
            return Err(ObservationUnavailable::CountBound);
        }
        if [
            &self.envelope.user_sid,
            &self.envelope.owner_sid,
            &self.envelope.primary_group_sid,
            &self.envelope.integrity_level,
        ]
        .iter()
        .any(|value| !sid(value))
            || self
                .normal_groups
                .iter()
                .chain(&self.restricted_sids)
                .any(|value| !sid(&value.sid))
        {
            return Err(ObservationUnavailable::InvalidSid);
        }
        if !self
            .normal_groups
            .windows(2)
            .all(|values| values[0] <= values[1])
            || !self
                .restricted_sids
                .windows(2)
                .all(|values| values[0] <= values[1])
            || !self
                .privileges
                .windows(2)
                .all(|values| values[0] <= values[1])
        {
            return Err(ObservationUnavailable::NonCanonical);
        }
        if usize::try_from(self.statistics.group_count).ok() != Some(self.normal_groups.len())
            || usize::try_from(self.statistics.privilege_count).ok() != Some(self.privileges.len())
        {
            return Err(ObservationUnavailable::CountMismatch);
        }
        if sid_attributes_digest(&self.normal_groups)
            .map_err(|_| ObservationUnavailable::DigestMismatch)?
            != self.envelope.groups_sha256
            || sid_attributes_digest(&self.restricted_sids)
                .map_err(|_| ObservationUnavailable::DigestMismatch)?
                != self.envelope.restricted_sids_sha256
            || privilege_attributes_digest(&self.privileges)
                .map_err(|_| ObservationUnavailable::DigestMismatch)?
                != self.envelope.privileges_sha256
        {
            return Err(ObservationUnavailable::DigestMismatch);
        }
        serde_json::to_writer(&mut Size(0), self).map_err(|_| ObservationUnavailable::SizeBound)?;
        Ok(())
    }
}
