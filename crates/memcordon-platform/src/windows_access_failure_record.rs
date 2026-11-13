//! Gate-only access-failure emission observations. Never admission evidence.
use serde::{Deserialize, Serialize};

pub const INPUT_BYTES: usize = 8192;
pub const RECORD_BYTES: usize = 32768;
pub const MAX_ROWS: usize = 4;
pub const MAX_PROPERTY_BYTES: usize = 65536;
pub const PROVIDER: u128 = 0xa68ca8b7_004f_d7b6_a698_07e2de0f1f5d;
pub const KEYWORD: u64 = 0x20;

/// Validate only a self-contained binary SID's native extent, not its authority.
pub fn validate_sid_extent(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() < 8
        || bytes[0] != 1
        || bytes[1] > 15
        || bytes.len() != 8 + 4 * usize::from(bytes[1])
    {
        return Err("access-failure SID extent unsupported".into());
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub cutoff_qpc: u64,
    pub frequency: u64,
    pub attempt_sha256: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumerSpec {
    pub version: u32,
    pub object_name: Vec<u16>,
    pub session_name: String,
    pub session_guid: [u8; 16],
    pub pid: u32,
    pub birth: u64,
    pub binding: Binding,
}
impl ConsumerSpec {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1
            || self.object_name.is_empty()
            || self.object_name.len() > 512
            || self.object_name.contains(&0)
            || String::from_utf16(&self.object_name).is_err()
            || self.pid == 0
            || self.birth == 0
            || self.binding.cutoff_qpc == 0
            || self.binding.frequency == 0
            || self.session_guid == [0; 16]
            || self.session_name
                != format!(
                    "Memcordon-AccessFailure-{:032x}",
                    u128::from_be_bytes(self.session_guid)
                )
        {
            return Err("access-failure consumer binding invalid".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ready {
    pub spec: ConsumerSpec,
    pub open_trace_succeeded: bool,
    pub native_error: Option<u32>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SensitiveField {
    TokenGroups,
    TokenPackage,
    TokenCapabilities,
    TokenTrustLevel,
    Owner,
    Group,
    Dacl,
    Sacl,
}
impl SensitiveField {
    pub const ALL: [Self; 8] = [
        Self::TokenGroups,
        Self::TokenPackage,
        Self::TokenCapabilities,
        Self::TokenTrustLevel,
        Self::Owner,
        Self::Group,
        Self::Dacl,
        Self::Sacl,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Self::TokenGroups => "TokenGroups",
            Self::TokenPackage => "TokenPackage",
            Self::TokenCapabilities => "TokenCapabilities",
            Self::TokenTrustLevel => "TokenTrustLevel",
            Self::Owner => "SecurityDescriptorOwner",
            Self::Group => "SecurityDescriptorGroup",
            Self::Dacl => "DaclAce",
            Self::Sacl => "SaclAce",
        }
    }
    pub fn count_name(self) -> Option<&'static str> {
        match self {
            Self::TokenGroups => Some("TokenGroupsCount"),
            Self::TokenPackage => Some("TokenPackageCount"),
            Self::TokenCapabilities => Some("TokenCapabilityCount"),
            Self::TokenTrustLevel => Some("TokenTrustLevelCount"),
            Self::Dacl => Some("DaclAceCount"),
            Self::Sacl => Some("SaclAceCount"),
            Self::Owner | Self::Group => None,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SanitizedField {
    pub field: SensitiveField,
    pub in_type: u16,
    pub out_type: u16,
    pub count: u32,
    pub bytes: u32,
    pub sha256: [u8; 32],
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    pub qpc: u64,
    pub pid: u32,
    pub tid: u32,
    pub access_mask: u32,
    pub object_type: Vec<u16>,
    pub object_name: Vec<u16>,
    pub token_type: u32,
    pub impersonation_level: u32,
    pub session_id: u32,
    pub security_descriptor_revision: u8,
    pub security_descriptor_control: u16,
    pub sensitive_fields: Vec<SanitizedField>,
}
impl Row {
    pub fn validate(&self, spec: &ConsumerSpec) -> Result<(), String> {
        if self.pid != spec.pid
            || self.object_name != spec.object_name
            || self.tid == 0
            || self.qpc == 0
            || self.qpc > spec.binding.cutoff_qpc
            || self.object_name.is_empty()
            || self.object_name.len() > 512
            || self.object_type.is_empty()
            || self.object_type.len() > 64
            || self.object_name.contains(&0)
            || self.object_type.contains(&0)
            || String::from_utf16(&self.object_name).is_err()
            || String::from_utf16(&self.object_type).is_err()
            || self.sensitive_fields.len() != SensitiveField::ALL.len()
        {
            return Err("access-failure row identity/extent invalid".into());
        }
        for field in SensitiveField::ALL {
            let matches = self
                .sensitive_fields
                .iter()
                .filter(|item| item.field == field)
                .collect::<Vec<_>>();
            if matches.len() != 1
                || matches[0].count > 256
                || matches[0].bytes as usize > MAX_PROPERTY_BYTES
                || (matches[0].count > 0 && matches[0].bytes == 0)
            {
                return Err("access-failure sensitive field inventory invalid".into());
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub version: u32,
    pub spec: ConsumerSpec,
    pub consumer_completed: bool,
    pub process_trace_status: u32,
    pub close_trace_status: u32,
    pub cutoff_reached: bool,
    pub matched_events: u64,
    pub unsupported_events: u64,
    pub overflow: u64,
    pub filtered_objects: u64,
    pub rows: Vec<Row>,
    pub last_native_error: Option<u32>,
    pub last_decode_stage: Option<DecodeStage>,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecodeStage {
    EventIdentity,
    Schema,
    SensitiveFields,
    Scalars,
    ObjectNames,
    RowValidation,
    CallbackPanic,
}
impl Observation {
    pub fn new(spec: ConsumerSpec) -> Self {
        Self {
            version: 1,
            spec,
            consumer_completed: false,
            process_trace_status: 0,
            close_trace_status: 0,
            cutoff_reached: false,
            matched_events: 0,
            unsupported_events: 0,
            overflow: 0,
            filtered_objects: 0,
            rows: Vec::new(),
            last_native_error: None,
            last_decode_stage: None,
        }
    }
    pub fn validate(&self) -> Result<(), String> {
        self.spec.validate()?;
        if self.version != 1
            || self.rows.len() > MAX_ROWS
            || self.matched_events
                != (self.rows.len() as u64)
                    .saturating_add(self.unsupported_events)
                    .saturating_add(self.overflow)
                    .saturating_add(self.filtered_objects)
        {
            return Err("access-failure observation inventory invalid".into());
        }
        for row in &self.rows {
            row.validate(&self.spec)?;
        }
        if serde_json::to_vec(self)
            .map_err(|error| error.to_string())?
            .len()
            > RECORD_BYTES
        {
            return Err("access-failure record exceeds finite output bound".into());
        }
        Ok(())
    }
    pub fn record(&mut self, row: Row) -> Result<(), String> {
        row.validate(&self.spec)?;
        self.matched_events = self.matched_events.saturating_add(1);
        if self.rows.len() == MAX_ROWS {
            self.overflow = self.overflow.saturating_add(1);
        } else {
            self.rows.push(row);
        }
        Ok(())
    }
    /// Probe-only unique temporal/name association, not security-mechanism proof.
    pub fn probe_match(
        &self,
        expected: &ConsumerSpec,
        tid: u32,
        started: u64,
        finished: u64,
        path: &[u16],
        required_denied_right: u32,
    ) -> Result<&Row, String> {
        self.validate()?;
        if required_denied_right == 0
            || &self.spec != expected
            || !self.consumer_completed
            || self.process_trace_status != 0
            || self.close_trace_status != 0
            || self.cutoff_reached
            || self.unsupported_events != 0
            || self.overflow != 0
            || tid == 0
            || started == 0
            || started >= finished
            || finished > expected.binding.cutoff_qpc
        {
            return Err("access-failure probe coverage unavailable".into());
        }
        let mut rows = self.rows.iter().filter(|row| {
            row.tid == tid
                && row.qpc >= started
                && row.qpc <= finished
                && row.object_name == path
                && row.object_type == "File".encode_utf16().collect::<Vec<_>>()
                && row.access_mask & required_denied_right == required_denied_right
                && row.token_type == 2
                && row.impersonation_level == 2
        });
        let row = rows
            .next()
            .ok_or("ordinary RC access-failure event not observed")?;
        if rows.next().is_some() {
            return Err("access-failure probe association ambiguous".into());
        }
        Ok(row)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopRecord {
    pub status: u32,
    pub disable_status: u32,
    pub stopped: bool,
    pub late: bool,
    pub elapsed_ms: u64,
    pub events_lost: u32,
    pub log_buffers_lost: u32,
    pub realtime_buffers_lost: u32,
}
