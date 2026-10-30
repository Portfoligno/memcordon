//! Bounded transport data for the standalone fresh-primary native experiment.
use memcordon_windows_launch_core::{ObservationUnavailable, TokenObservationV1};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io;

pub const REVISION: u32 = 6;
pub const API_SET_CONTRACT: &str = "api-ms-win-core-synch-l1-1-0.dll";
pub const API_SET_SYMBOL: &str = "OpenEventW";
pub const API_SET_METHOD: &str = "LoadLibraryExW/GetProcAddress";
pub const FRAME_BOUND: usize = 16 * 1024;
pub const NAME_UNITS_BOUND: usize = 128;
const SID_SUBAUTHORITIES_BOUND: usize = 15;
const SID_TEXT_BOUND: usize = "S-1-".len()
    + "281474976710655".len()
    + SID_SUBAUTHORITIES_BOUND * ("-".len() + "4294967295".len());

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Cell {
    Local,
    Private,
    NamespaceDenied,
    EventDenied,
    WrongBoundary,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    Primary,
    Namespace,
    Event,
    Held,
    Completed,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub revision: u32,
    pub nonce: String,
    pub cell: Cell,
    pub alias: String,
    pub boundary: String,
    pub event: String,
    pub user_sid: String,
    pub deadline_qpc: u64,
    pub qpc_frequency: u64,
    pub expected_token: memcordon_core::WindowsCallerTokenEnvelopeV1,
    pub expected_default_acl_sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub revision: u32,
    pub nonce: String,
    pub phase: Phase,
    pub success: bool,
    #[serde(deserialize_with = "required_option")]
    pub raw_error: Option<i32>,
    #[serde(deserialize_with = "required_option")]
    pub event_handle: Option<u64>,
    #[serde(deserialize_with = "required_option")]
    pub modify_denied: Option<bool>,
    pub diagnostics: DiagnosticState,
    #[serde(deserialize_with = "required_option")]
    pub native_open: Option<NativeOpen>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeOpen {
    pub cell: Cell,
    pub name_utf16: Vec<u16>,
    pub desired_access: u32,
    pub inherit: bool,
    pub probe_desired_access: u32,
    pub namespace_held: bool,
    pub probe: ZeroProbe,
    #[serde(deserialize_with = "required_option")]
    pub native_root: Option<NativeRoot>,
    #[serde(deserialize_with = "required_option")]
    pub module_provenance: Option<ModuleProvenance>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModuleRole {
    #[serde(rename = "import-address-owner")]
    ImportAddress,
    #[serde(rename = "kernel32-export-table-owner")]
    Kernel32ExportTable,
    #[serde(rename = "resolved-export-owner")]
    ResolvedExport,
    #[serde(rename = "nt-open-event-owner")]
    NtOpenEvent,
    #[serde(rename = "api-set-open-event-owner")]
    ApiSetOpenEvent,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApiSetStage {
    LoadContract,
    ResolveExport,
    ObserveOwner,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ApiSetObservation {
    Resolved {
        same_as_original_thunk: bool,
    },
    Unavailable {
        stage: ApiSetStage,
        raw_error: Option<i32>,
        deadline: bool,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiSetResolution {
    pub contract: String,
    pub symbol: String,
    pub resolution_method: String,
    pub observation: ApiSetObservation,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleLocation {
    pub role: ModuleRole,
    pub base: u64,
    pub address: u64,
    pub rva: u32,
    pub path_utf16: Vec<u16>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ModuleProvenance {
    Present {
        started_qpc: u64,
        finished_qpc: u64,
        diagnostic_only: bool,
        acceptance_authority: bool,
        import_matches_resolved: bool,
        api_set_resolution: ApiSetResolution,
        modules: Vec<ModuleLocation>,
    },
    Unavailable {
        reason: memcordon_core::BoundedText<128>,
        raw_error: Option<i32>,
        deadline: bool,
    },
}
impl ModuleProvenance {
    pub fn validate(&self) -> io::Result<()> {
        if let Self::Present {
            started_qpc,
            finished_qpc,
            diagnostic_only,
            acceptance_authority,
            import_matches_resolved,
            api_set_resolution,
            modules,
        } = self
        {
            if !diagnostic_only
                || *acceptance_authority
                || started_qpc > finished_qpc
                || api_set_resolution.contract != API_SET_CONTRACT
                || api_set_resolution.symbol != API_SET_SYMBOL
                || api_set_resolution.resolution_method != API_SET_METHOD
                || modules.len()
                    != if matches!(
                        api_set_resolution.observation,
                        ApiSetObservation::Resolved { .. }
                    ) {
                        5
                    } else {
                        4
                    }
            {
                return Err(invalid());
            }
            for (index, module) in modules.iter().enumerate() {
                if module.base == 0
                    || module.address.checked_sub(module.base) != Some(u64::from(module.rva))
                    || module.path_utf16.is_empty()
                    || module.path_utf16.len() > 32768
                    || module.path_utf16.contains(&0)
                    || String::from_utf16(&module.path_utf16).is_err()
                    || modules[..index]
                        .iter()
                        .any(|previous| previous.role == module.role)
                    || (module.role == ModuleRole::Kernel32ExportTable && module.rva != 0)
                    || modules[..index].iter().any(|previous| {
                        previous.base == module.base && previous.path_utf16 != module.path_utf16
                    })
                {
                    return Err(invalid());
                }
            }
            let import = modules
                .iter()
                .find(|module| module.role == ModuleRole::ImportAddress)
                .ok_or_else(invalid)?;
            let resolved = modules
                .iter()
                .find(|module| module.role == ModuleRole::ResolvedExport)
                .ok_or_else(invalid)?;
            if *import_matches_resolved != (import.address == resolved.address) {
                return Err(invalid());
            }
            let host = modules
                .iter()
                .find(|module| module.role == ModuleRole::ApiSetOpenEvent);
            match (&api_set_resolution.observation, host) {
                (
                    ApiSetObservation::Resolved {
                        same_as_original_thunk,
                    },
                    Some(host),
                ) if *same_as_original_thunk == (import.address == host.address) => {}
                (ApiSetObservation::Unavailable { .. }, None) => {}
                _ => return Err(invalid()),
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRoot {
    pub root_handle: u64,
    pub type_status: Option<i32>,
    pub basic_status: Option<i32>,
    pub type_name: Option<String>,
    pub granted_access: Option<u32>,
    pub handle_attributes: Option<u32>,
    pub leaf_utf16: Vec<u16>,
    pub desired_access: u32,
    pub object_attributes: u32,
    pub open_status: Option<i32>,
    pub handle: Option<u64>,
    pub unavailable: Option<String>,
    pub reason: Option<memcordon_core::BoundedText<512>>,
    pub deadline: bool,
    pub native_error: Option<i32>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ZeroProbe {
    Unavailable { deadline: bool },
    Failed { raw_error: i32 },
    Held { handle: u64 },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceRole {
    BeforeOpen,
    AfterFailedOpen,
    #[serde(rename = "after-replay-open")]
    ReplayAfter,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceObservation {
    pub role: SourceRole,
    pub started_qpc: u64,
    pub finished_qpc: u64,
    pub token: TokenObservationV1,
    pub default_acl_sha256: String,
    #[serde(deserialize_with = "required_option")]
    pub default_acl_bytes: Option<Vec<u8>>,
    pub no_thread_token_raw_error: i32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DiagnosticUnavailableReason {
    EncodingBoundOrRefused,
    Observation {
        role: SourceRole,
        reason: ObservationUnavailable,
    },
}
impl<'de> Deserialize<'de> for DiagnosticUnavailableReason {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Empty struct variants enforce unknown-field refusal; serde's tagged
        // unit variants otherwise discard arbitrary fields despite deny_unknown_fields.
        #[derive(Deserialize)]
        #[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
        enum Wire {
            EncodingBoundOrRefused {},
            Observation {
                role: SourceRole,
                reason: ObservationUnavailable,
            },
        }
        Ok(match Wire::deserialize(deserializer)? {
            Wire::EncodingBoundOrRefused {} => Self::EncodingBoundOrRefused,
            Wire::Observation { role, reason } => Self::Observation { role, reason },
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DiagnosticState {
    NotApplicable,
    Present {
        before: Box<SourceObservation>,
        after: Box<SourceObservation>,
    },
    Unavailable {
        reason: DiagnosticUnavailableReason,
    },
}
impl<'de> Deserialize<'de> for DiagnosticState {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
        enum Wire {
            NotApplicable {},
            Present {
                before: Box<SourceObservation>,
                after: Box<SourceObservation>,
            },
            Unavailable {
                reason: DiagnosticUnavailableReason,
            },
        }
        Ok(match Wire::deserialize(deserializer)? {
            Wire::NotApplicable {} => Self::NotApplicable,
            Wire::Present { before, after } => Self::Present { before, after },
            Wire::Unavailable { reason } => Self::Unavailable { reason },
        })
    }
}
impl SourceObservation {
    pub(super) fn validate(&self) -> io::Result<()> {
        self.token.validate().map_err(|_| invalid())?;
        if self
            .default_acl_bytes
            .as_ref()
            .is_some_and(|bytes| bytes.len() > 64 * 1024)
        {
            return Err(invalid());
        }
        let preimage = serde_json::to_vec(&self.default_acl_bytes).map_err(|_| invalid())?;
        let mut digest = String::new();
        use std::fmt::Write;
        for byte in Sha256::digest(&preimage) {
            write!(&mut digest, "{byte:02x}").expect("String writes are infallible");
        }
        if digest != self.default_acl_sha256 {
            return Err(invalid());
        }
        if self.started_qpc == 0
            || self.finished_qpc < self.started_qpc
            || self.no_thread_token_raw_error != 1008
            || self.default_acl_sha256.len() != size_of::<[u8; 32]>() * 2
            || !self
                .default_acl_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(invalid());
        }
        Ok(())
    }
}
impl DiagnosticState {
    fn validate(&self) -> io::Result<()> {
        if let Self::Present { before, after } = self {
            before.validate()?;
            after.validate()?;
            if before.role != SourceRole::BeforeOpen
                || after.role != SourceRole::AfterFailedOpen
                || before.finished_qpc > after.started_qpc
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
    pub fn validate_correspondence(&self, request: &Request) -> io::Result<()> {
        request.validate()?;
        self.validate()?;
        if let Self::Present { before, after } = self {
            for observation in [before, after] {
                if observation.finished_qpc >= request.deadline_qpc
                    || observation.token.envelope != request.expected_token
                    || observation.default_acl_sha256 != request.expected_default_acl_sha256
                {
                    return Err(invalid());
                }
            }
        }
        Ok(())
    }
}
fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    Option::deserialize(deserializer)
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "fresh-primary namespace protocol refused",
    )
}
fn nonce(value: &str) -> bool {
    value.len() == size_of::<[u8; 16]>() * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
fn component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value.encode_utf16().take(NAME_UNITS_BOUND + 1).count() <= NAME_UNITS_BOUND
        && !value
            .chars()
            .any(|unit| matches!(unit, '\0' | '/' | '\\' | '\n' | '\r'))
}
fn number(value: &str, bound: u64) -> bool {
    !value.is_empty()
        && (value == "0" || !value.starts_with('0'))
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u64>().is_ok_and(|value| value <= bound)
}
fn sid(value: &str) -> bool {
    if value.len() > SID_TEXT_BOUND {
        return false;
    }
    let Some(body) = value.strip_prefix("S-1-") else {
        return false;
    };
    let mut parts = body.split('-');
    if !parts
        .next()
        .is_some_and(|authority| number(authority, (1u64 << 48) - 1))
    {
        return false;
    }
    let mut count = 0usize;
    for part in parts {
        count += 1;
        if count > SID_SUBAUTHORITIES_BOUND || !number(part, u64::from(u32::MAX)) {
            return false;
        }
    }
    count != 0
}
impl Request {
    fn validate(&self) -> io::Result<()> {
        if self.revision != REVISION
            || !nonce(&self.nonce)
            || !component(&self.alias)
            || !component(&self.boundary)
            || !component(&self.event)
            || !sid(&self.user_sid)
            || self.deadline_qpc == 0
            || self.qpc_frequency == 0
            || self.expected_token.user_sid != self.user_sid
            || self.expected_default_acl_sha256.len() != size_of::<[u8; 32]>() * 2
            || !self
                .expected_default_acl_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            || !sid(&self.expected_token.owner_sid)
            || !sid(&self.expected_token.primary_group_sid)
            || !sid(&self.expected_token.integrity_level)
            || [
                &self.expected_token.groups_sha256,
                &self.expected_token.privileges_sha256,
                &self.expected_token.restricted_sids_sha256,
            ]
            .iter()
            .any(|value| {
                value.len() != size_of::<[u8; 32]>() * 2
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            })
        {
            return Err(invalid());
        }
        Ok(())
    }
}
impl Response {
    fn validate_core(&self) -> io::Result<()> {
        if let Some(call) = &self.native_open {
            if let Some(modules) = &call.module_provenance {
                modules.validate()?;
            }
            if let Some(root) = &call.native_root {
                let queried = root.type_status.is_some_and(|status| status >= 0)
                    && root.basic_status.is_some_and(|status| status >= 0)
                    && root.type_name.as_deref() == Some("Directory")
                    && root.granted_access.is_some()
                    && root.handle_attributes.is_some();
                if call.cell != Cell::Private
                    || root.root_handle == 0
                    || root.desired_access != 0x0010_0000
                    || root.object_attributes != 0
                    || root.leaf_utf16.is_empty()
                    || root.leaf_utf16.len() > NAME_UNITS_BOUND
                    || root
                        .leaf_utf16
                        .iter()
                        .any(|unit| matches!(*unit, 0 | 47 | 92))
                    || String::from_utf16(&root.leaf_utf16).is_err()
                    || root
                        .type_name
                        .as_ref()
                        .is_some_and(|name| name.encode_utf16().count() > NAME_UNITS_BOUND)
                    || root
                        .unavailable
                        .as_ref()
                        .is_some_and(|stage| stage.len() > NAME_UNITS_BOUND)
                    || (root.open_status.is_some() && !queried)
                    || (root.handle.is_some()
                        && (!queried
                            || root.open_status.is_none_or(|status| status < 0)
                            || root.handle == Some(0)))
                {
                    return Err(invalid());
                }
            }
            if self.success
                || self.phase != Phase::Event
                || self.event_handle.is_some()
                || self.modify_denied.is_some()
                || !matches!(call.cell, Cell::Local | Cell::Private)
                || call.name_utf16.is_empty()
                || call.name_utf16.len() > 2 * NAME_UNITS_BOUND + 1
                || call.name_utf16.contains(&0)
                || String::from_utf16(&call.name_utf16).is_err()
                || call.desired_access != 0x0010_0000
                || call.inherit
                || call.probe_desired_access != 0
                || call.namespace_held != (call.cell == Cell::Private)
                || matches!(call.probe, ZeroProbe::Held { handle: 0 })
            {
                return Err(invalid());
            }
        }
        if self.revision != REVISION
            || !nonce(&self.nonce)
            || (self.phase == Phase::Held
                && (!self.success || self.event_handle.is_none_or(|value| value == 0)))
            || (self.phase != Phase::Held && self.event_handle.is_some())
            || (!self.success && self.raw_error.is_none())
            || (self.success && self.raw_error.is_some())
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn validate(&self) -> io::Result<()> {
        self.validate_core()?;
        self.diagnostics.validate()?;
        if !matches!(self.diagnostics, DiagnosticState::NotApplicable)
            && (self.success || self.phase != Phase::Event)
        {
            return Err(invalid());
        }
        Ok(())
    }
}
fn encode<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    struct Bounded(Vec<u8>);
    impl io::Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self
                .0
                .len()
                .checked_add(bytes.len())
                .is_none_or(|size| size >= FRAME_BOUND)
            {
                return Err(invalid());
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut bounded = Bounded(Vec::new());
    serde_json::to_writer(&mut bounded, value).map_err(|_| invalid())?;
    bounded.0.push(b'\n');
    Ok(bounded.0)
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> io::Result<T> {
    if bytes.len() > FRAME_BOUND {
        return Err(invalid());
    }
    let body = bytes.strip_suffix(b"\n").ok_or_else(invalid)?;
    if body.is_empty() || body.iter().any(|byte| matches!(*byte, b'\n' | b'\r')) {
        return Err(invalid());
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(body).map_err(|_| invalid())?;
    serde_json::from_slice(body).map_err(|_| invalid())
}
pub fn encode_request(value: &Request) -> io::Result<Vec<u8>> {
    value.validate()?;
    encode(value)
}
pub fn decode_request(bytes: &[u8]) -> io::Result<Request> {
    let value: Request = decode(bytes)?;
    value.validate()?;
    Ok(value)
}
pub fn encode_response(value: &Response) -> io::Result<Vec<u8>> {
    value.validate_core()?;
    if value.validate().is_ok() {
        if let Ok(bytes) = encode(value) {
            return Ok(bytes);
        }
    }
    // Only optional failure diagnostics can fall back. Core facts never change.
    if value.success || value.phase != Phase::Event {
        return Err(invalid());
    }
    let mut fallback = Response {
        revision: value.revision,
        nonce: value.nonce.clone(),
        phase: value.phase,
        success: value.success,
        raw_error: value.raw_error,
        event_handle: value.event_handle,
        modify_denied: value.modify_denied,
        native_open: value.native_open.clone(),
        diagnostics: DiagnosticState::Unavailable {
            reason: DiagnosticUnavailableReason::EncodingBoundOrRefused,
        },
    };
    if let Some(call) = &mut fallback.native_open {
        if matches!(
            call.module_provenance,
            Some(ModuleProvenance::Present { .. })
        ) {
            call.module_provenance = Some(ModuleProvenance::Unavailable {
                reason: memcordon_core::BoundedText::new("record-bound").map_err(|_| invalid())?,
                raw_error: None,
                deadline: false,
            });
        }
    }
    fallback.validate()?;
    encode(&fallback)
}
pub fn decode_response(bytes: &[u8]) -> io::Result<Response> {
    let value: Response = decode(bytes)?;
    value.validate()?;
    Ok(value)
}

pub fn encode_ack(value: &str) -> io::Result<Vec<u8>> {
    #[derive(Serialize)]
    struct Ack<'a> {
        revision: u32,
        nonce: &'a str,
    }
    if !nonce(value) {
        return Err(invalid());
    }
    encode(&Ack {
        revision: REVISION,
        nonce: value,
    })
}

pub fn encode_probe_ack(value: &str) -> io::Result<Vec<u8>> {
    if !nonce(value) {
        return Err(invalid());
    }
    #[derive(Serialize)]
    struct Ack<'a> {
        revision: u32,
        nonce: &'a str,
        kind: &'static str,
    }
    encode(&Ack {
        revision: REVISION,
        nonce: value,
        kind: "diagnostic-release",
    })
}

#[derive(Debug, Serialize)]
pub struct FailureCore {
    pub revision: u32,
    pub nonce: String,
    pub phase: Phase,
    pub success: bool,
    pub raw_error: i32,
    pub event_handle: Option<u64>,
    pub modify_denied: Option<bool>,
    pub frame_bytes: usize,
    pub frame_sha256: String,
    pub full_frame_canonical_validated: bool,
    pub diagnostics_validated: bool,
}
pub fn decode_failure_core(bytes: &[u8]) -> io::Result<FailureCore> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Wire {
        revision: u32,
        nonce: String,
        phase: Phase,
        success: bool,
        #[serde(deserialize_with = "required_option")]
        raw_error: Option<i32>,
        #[serde(deserialize_with = "required_option")]
        event_handle: Option<u64>,
        #[serde(deserialize_with = "required_option")]
        modify_denied: Option<bool>,
        #[serde(default)]
        diagnostics: Option<serde_json::Value>,
        #[serde(default)]
        native_open: Option<serde_json::Value>,
    }
    let wire: Wire = decode(bytes)?;
    if wire.revision != REVISION
        || !nonce(&wire.nonce)
        || wire.success
        || !matches!(wire.phase, Phase::Namespace | Phase::Event)
        || wire.raw_error.is_none()
        || wire.event_handle.is_some()
        || wire.modify_denied.is_some()
    {
        return Err(invalid());
    }
    let _ = wire.diagnostics;
    let _ = wire.native_open;
    let mut digest = String::new();
    use std::fmt::Write;
    for byte in Sha256::digest(bytes) {
        write!(&mut digest, "{byte:02x}").expect("String writes are infallible");
    }
    Ok(FailureCore {
        revision: wire.revision,
        nonce: wire.nonce,
        phase: wire.phase,
        success: false,
        raw_error: wire.raw_error.expect("checked original error"),
        event_handle: wire.event_handle,
        modify_denied: wire.modify_denied,
        frame_bytes: bytes.len(),
        frame_sha256: digest,
        full_frame_canonical_validated: false,
        diagnostics_validated: false,
    })
}
