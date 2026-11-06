//! Finite diagnostic FileIo observations; numeric identities are never capabilities.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const INPUT_BYTES: usize = 8192;
pub const RECORD_BYTES: usize = 65536;
pub const MAX_ROWS: usize = 32;
pub const MAX_PENDING: usize = 128;
pub const CORRELATION_BYTES: usize = 49152;
pub const DECODE_BYTES: usize = 12 * 1024;
// Leave space for the renderer's fixed native-status-domain annotation.
const DECODE_STORAGE_BYTES: usize = DECODE_BYTES - 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
pub enum RejectStage {
    EventVersion,
    SchemaSizeQuery,
    SchemaExtent,
    SchemaRead,
    SchemaIdentity,
    SchemaDescriptor,
    SchemaInventory,
    PropertyExtent,
    PropertyFlags,
    PropertyName,
    DuplicateProperty,
    PropertyType,
    PropertySize,
    PropertyRead,
    PointerWidth,
    ScalarExtent,
    ThreadId,
    PathEncoding,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FieldId {
    IrpPtr,
    ExtraInfo,
    NtStatus,
    OpenPath,
    Ttid,
    FileObject,
    CreateOptions,
    FileAttributes,
    ShareAccess,
}
impl FieldId {
    pub fn name(self) -> &'static str {
        match self {
            Self::IrpPtr => "IrpPtr",
            Self::ExtraInfo => "ExtraInfo",
            Self::NtStatus => "NtStatus",
            Self::OpenPath => "OpenPath",
            Self::Ttid => "TTID",
            Self::FileObject => "FileObject",
            Self::CreateOptions => "CreateOptions",
            Self::FileAttributes => "FileAttributes",
            Self::ShareAccess => "ShareAccess",
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecodeRejection {
    pub stage: RejectStage,
    pub field: Option<FieldId>,
    pub native_status: Option<u32>,
    pub required_bytes: Option<u32>,
    pub returned_bytes: Option<u32>,
    pub expected_type: Option<u16>,
    pub actual_type: Option<u16>,
    pub expected_width: Option<u8>,
    pub actual_width: Option<u32>,
}
impl DecodeRejection {
    pub fn new(stage: RejectStage) -> Self {
        Self {
            stage,
            field: None,
            native_status: None,
            required_bytes: None,
            returned_bytes: None,
            expected_type: None,
            actual_type: None,
            expected_width: None,
            actual_width: None,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PropertyPreview {
    pub index: u32,
    pub flags: u32,
    pub in_type: Option<u16>,
    pub out_type: Option<u16>,
    pub name_prefix: Vec<u16>,
    pub name_units: Option<u32>,
    pub name_truncated: bool,
    pub name_unavailable: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaPreview {
    pub decoding_source: i32,
    pub provider_guid: [u8; 16],
    pub event_guid: [u8; 16],
    pub descriptor_id: u16,
    pub descriptor_version: u8,
    pub descriptor_opcode: u8,
    pub property_count: u32,
    pub top_level_property_count: u32,
    pub properties: Vec<PropertyPreview>,
    pub properties_omitted: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RejectSample {
    pub opcode: u8,
    pub event_version: u8,
    pub header_flags: u16,
    pub user_data_length: u16,
    pub rejection: DecodeRejection,
    pub metadata: Option<SchemaPreview>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecodeDiagnostics {
    pub create_header_matched: u64,
    pub create_decoded: u64,
    pub create_rejected: u64,
    pub completion_received: u64,
    pub completion_decoded: u64,
    pub completion_rejected: u64,
    pub stage_counts: [[u64; 18]; 2],
    pub samples: Vec<RejectSample>,
    pub sample_omitted: u64,
    pub detail_truncated: bool,
    pub metadata_omitted: u32,
}
fn opcode_index(opcode: u8) -> Option<usize> {
    match opcode {
        64 => Some(0),
        76 => Some(1),
        _ => None,
    }
}
fn same_sample(
    sample: &RejectSample,
    opcode: u8,
    version: u8,
    stage: RejectStage,
    field: Option<FieldId>,
) -> bool {
    sample.opcode == opcode
        && sample.event_version == version
        && sample.rejection.stage == stage
        && sample.rejection.field == field
}
impl DecodeDiagnostics {
    fn bound(&mut self) {
        // Split sample space so an unbound completion flood cannot spend the
        // eligible-Create metadata reservation. Fixed counters keep 2KiB.
        for opcode in [64, 76] {
            while serde_json::to_vec(
                &self
                    .samples
                    .iter()
                    .filter(|sample| sample.opcode == opcode)
                    .collect::<Vec<_>>(),
            )
            .map_or(true, |bytes| bytes.len() > (DECODE_BYTES - 2048) / 2)
            {
                if let Some(sample) = self
                    .samples
                    .iter_mut()
                    .rev()
                    .find(|sample| sample.opcode == opcode && sample.metadata.is_some())
                {
                    sample.metadata = None;
                    self.metadata_omitted = self.metadata_omitted.saturating_add(1);
                    self.detail_truncated = true;
                } else {
                    break;
                }
            }
        }
        while serde_json::to_vec(self).map_or(true, |bytes| bytes.len() > DECODE_STORAGE_BYTES) {
            // Samples keep their opcode/error facts; discard metadata only.
            if let Some(sample) = self
                .samples
                .iter_mut()
                .rev()
                .find(|sample| sample.metadata.is_some())
            {
                sample.metadata = None;
                self.metadata_omitted = self.metadata_omitted.saturating_add(1);
                self.detail_truncated = true;
            } else if self.samples.pop().is_some() {
                self.sample_omitted = self.sample_omitted.saturating_add(1);
                self.detail_truncated = true;
            } else {
                break;
            }
        }
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.samples.len() > 8
            || serde_json::to_vec(self).map_or(true, |bytes| bytes.len() > DECODE_BYTES)
        {
            return Err("FileIo decode diagnostic extent differs".into());
        }
        let mut quotas = [0; 2];
        for (index, sample) in self.samples.iter().enumerate() {
            let opcode = opcode_index(sample.opcode).ok_or("FileIo rejection opcode differs")?;
            quotas[opcode] += 1;
            if quotas[opcode] > 4
                || self.samples[..index].iter().any(|prior| {
                    same_sample(
                        prior,
                        sample.opcode,
                        sample.event_version,
                        sample.rejection.stage,
                        sample.rejection.field,
                    )
                })
                || self.stage_counts[opcode][sample.rejection.stage as usize] == 0
            {
                return Err("FileIo rejection quota/identity differs".into());
            }
            if sample
                .rejection
                .expected_width
                .is_some_and(|width| !matches!(width, 4 | 8))
            {
                return Err("FileIo expected scalar width differs".into());
            }
            if let Some(metadata) = &sample.metadata {
                if metadata.properties.len() > 8
                    || metadata.properties_omitted
                        != metadata
                            .property_count
                            .saturating_sub(metadata.properties.len() as u32)
                {
                    return Err("FileIo schema preview inventory differs".into());
                }
                for (index, property) in metadata.properties.iter().enumerate() {
                    if property.index >= metadata.property_count
                        || metadata.properties[..index]
                            .iter()
                            .any(|prior| prior.index == property.index)
                        || property.name_prefix.len() > 32
                        || property.name_prefix.contains(&0)
                        || (property.flags != 0
                            && (property.in_type.is_some() || property.out_type.is_some()))
                        || if property.name_unavailable {
                            property.name_units.is_some()
                                || !property.name_prefix.is_empty()
                                || property.name_truncated
                        } else {
                            property.name_units.is_none_or(|units| {
                                units > 32768
                                    || property.name_prefix.len() != (units as usize).min(32)
                                    || property.name_truncated != (units > 32)
                            })
                        }
                    {
                        return Err("FileIo schema property preview differs".into());
                    }
                }
            }
        }
        let sums = self.stage_counts.map(|counts| {
            counts
                .iter()
                .fold(0u64, |total, count| total.saturating_add(*count))
        });
        if sums != [self.create_rejected, self.completion_rejected]
            || self.create_decoded.saturating_add(self.create_rejected) > self.create_header_matched
            || self
                .completion_decoded
                .saturating_add(self.completion_rejected)
                > self.completion_received
        {
            return Err("FileIo rejection counter totals differ".into());
        }
        Ok(())
    }
}
pub fn decode_diagnostic(value: &DecodeDiagnostics) -> Value {
    let mut value = value.clone();
    value.bound();
    let mut value = serde_json::to_value(value).expect("fixed FileIo diagnostic fields serialize");
    value["native_status_domain"] = json!("Win32 TDH direct return");
    value
}

/// Decode only the pointer width actually declared by the event header.
pub fn pointer(bytes: &[u8], width: usize) -> Result<u64, String> {
    match (width, bytes.len()) {
        (4, 4) => Ok(u32::from_le_bytes(bytes.try_into().unwrap()) as u64),
        (8, 8) => Ok(u64::from_le_bytes(bytes.try_into().unwrap())),
        _ => Err("FileIo pointer extent differs from event width".into()),
    }
}
/// A native pointer-qualified thread identifier must still fit the DWORD domain.
pub fn thread_id(value: u64) -> Result<u32, String> {
    u32::try_from(value).map_err(|_| "FileIo thread identifier exceeds DWORD".into())
}

/// Preserve native UTF-16 units; no replacement characters or path normalization.
pub fn path_units(bytes: &[u8]) -> Result<Vec<u16>, String> {
    if bytes.len() > 65536 || bytes.len() % 2 != 0 {
        return Err("FileIo path extent differs".into());
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    let Some(end) = units.iter().position(|unit| *unit == 0) else {
        return Err("FileIo path terminator unavailable".into());
    };
    if units[end..].iter().any(|unit| *unit != 0) {
        return Err("FileIo path has nonzero trailing units".into());
    }
    Ok(units[..end].to_vec())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub descriptor_sha256: [u8; 32],
    pub challenge_sha256: [u8; 32],
    pub cutoff_qpc: u64,
    pub frequency: u64,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RetentionMode {
    #[default]
    Prefix,
    RollingCompleted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumerSpec {
    pub version: u32,
    pub retention: RetentionMode,
    pub session_name: String,
    pub session_guid: [u8; 16],
    pub pid: u32,
    pub birth: u64,
    pub binding: Binding,
}
impl ConsumerSpec {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != 2
            || self.pid == 0
            || self.birth == 0
            || self.binding.frequency == 0
            || self.binding.cutoff_qpc == 0
            || self.session_guid == [0; 16]
            || !self.session_name.starts_with("Memcordon-FileIo-")
            || self.session_name.len() > 128
            || self.session_name.len() == "Memcordon-FileIo-".len()
            || !self
                .session_name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err("invalid bounded FileIo consumer specification".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopRecord {
    pub attempted: bool,
    pub status: u32,
    pub stopped: bool,
    pub late: bool,
    pub elapsed_ms: u64,
    pub events_lost: u32,
    pub log_buffers_lost: u32,
    pub realtime_buffers_lost: u32,
    pub buffers: u32,
    pub buffer_kib: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Create {
    pub irp: u64,
    pub qpc: u64,
    pub header_pid: u32,
    pub header_tid: u32,
    pub ttid: u32,
    pub file_object: u64,
    pub create_options: u32,
    pub file_attributes: u32,
    pub share_access: u32,
    pub path_prefix: Vec<u16>,
    pub path_units: u32,
    pub path_sha256: Option<[u8; 32]>,
    pub path_truncated: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Completion {
    pub irp: u64,
    pub qpc: u64,
    pub extra_info: u64,
    pub ntstatus: i32,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    pub create: Create,
    pub completion: Option<Completion>,
    pub ambiguous: bool,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Counters {
    pub seen: u64,
    pub filtered: u64,
    pub unsupported: u64,
    pub malformed: u64,
    pub overflow: u64,
    pub orphan: u64,
    pub ambiguous: u64,
    pub reversed: u64,
    pub unmatched: u64,
}
/// Bounded accounting over the entire decoded callback stream, including
/// events whose rows cannot be retained. This is not a global ETW order claim.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct History {
    pub decoded_events: u64,
    pub maximum_qpc: u64,
    pub timestamp_regression: bool,
    pub dropped_creates: u64,
    pub earliest_dropped_create_qpc: Option<u64>,
    pub evicted_pairs: u64,
    pub maximum_evicted_pair_qpc: Option<u64>,
}
impl History {
    fn record(&mut self, qpc: u64) {
        self.decoded_events = self.decoded_events.saturating_add(1);
        self.timestamp_regression |= qpc == 0 || qpc < self.maximum_qpc;
        self.maximum_qpc = self.maximum_qpc.max(qpc);
    }
    fn dropped(&mut self, qpc: u64) {
        self.dropped_creates = self.dropped_creates.saturating_add(1);
        self.earliest_dropped_create_qpc = Some(
            self.earliest_dropped_create_qpc
                .map_or(qpc, |previous| previous.min(qpc)),
        );
    }
    fn evicted(&mut self, create: u64, completion: u64) {
        self.evicted_pairs = self.evicted_pairs.saturating_add(1);
        self.maximum_evicted_pair_qpc = Some(
            self.maximum_evicted_pair_qpc
                .unwrap_or(0)
                .max(create)
                .max(completion),
        );
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub version: u32,
    pub spec: ConsumerSpec,
    pub rows: Vec<Row>,
    pub counters: Counters,
    pub history: History,
    pub decode: DecodeDiagnostics,
    pub process_trace_status: u32,
    pub close_trace_status: u32,
    pub consumer_completed: bool,
    pub cutoff_reached: bool,
}
impl Observation {
    pub fn validate(&self) -> Result<(), String> {
        self.spec.validate()?;
        if self.version != 4 || self.rows.len() > MAX_ROWS {
            return Err("FileIo record bound/version differs".into());
        }
        let history = &self.history;
        let retained_events = self.rows.iter().fold(0u64, |count, row| {
            count.saturating_add(1 + u64::from(row.completion.is_some()))
        });
        if history.decoded_events != self.counters.seen
            || history.dropped_creates != self.counters.overflow
            || (history.decoded_events == 0) != (history.maximum_qpc == 0)
            || history.maximum_qpc > self.spec.binding.cutoff_qpc
            || (history.dropped_creates == 0) != history.earliest_dropped_create_qpc.is_none()
            || history.dropped_creates > history.decoded_events
            || retained_events.saturating_add(history.dropped_creates) > history.decoded_events
            || history.evicted_pairs
                > history
                    .decoded_events
                    .saturating_sub(retained_events.saturating_add(history.dropped_creates))
                    / 2
            || (history.evicted_pairs == 0) != history.maximum_evicted_pair_qpc.is_none()
            || (self.spec.retention == RetentionMode::Prefix && history.evicted_pairs != 0)
            || (history.evicted_pairs != 0 && self.rows.len() != MAX_ROWS)
            || history
                .maximum_evicted_pair_qpc
                .is_some_and(|qpc| qpc == 0 || qpc > history.maximum_qpc)
            || history
                .earliest_dropped_create_qpc
                .is_some_and(|qpc| qpc == 0 || qpc > history.maximum_qpc)
        {
            return Err("FileIo decoded history differs from retention counters".into());
        }
        self.decode.validate()?;
        if self.counters.unsupported
            != self
                .decode
                .create_rejected
                .saturating_add(self.decode.completion_rejected)
        {
            return Err("FileIo unsupported/rejection totals differ".into());
        }
        for row in &self.rows {
            let create = &row.create;
            if create.header_pid != self.spec.pid
                || create.path_prefix.len() > 128
                || create.path_prefix.len() > create.path_units as usize
                || create.path_prefix.contains(&0)
                || create.qpc == 0
                || create.path_prefix.len() != (create.path_units as usize).min(128)
                || create.path_truncated != (create.path_prefix.len() < create.path_units as usize)
                || (!create.path_truncated
                    && create.path_prefix.len() != create.path_units as usize)
                || create.qpc > self.spec.binding.cutoff_qpc
                || create.qpc > history.maximum_qpc
                || create.path_units > 32767
                || create.path_sha256.is_none()
                || row.completion.as_ref().is_some_and(|end| {
                    end.irp != create.irp
                        || end.qpc == 0
                        || end.qpc > self.spec.binding.cutoff_qpc
                        || end.qpc > history.maximum_qpc
                        || (end.qpc < create.qpc && !row.ambiguous)
                })
            {
                return Err("FileIo observed field extent/binding differs".into());
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Window {
    pub dependency_sequence: u64,
    pub loader_dependency_sequence: u64,
    pub parent_listener_sequence: u64,
    pub started_qpc: u64,
    pub finished_qpc: u64,
}

pub struct Collector {
    observation: Observation,
    pending: BTreeMap<u64, Option<usize>>,
}
impl Collector {
    pub fn new(spec: ConsumerSpec) -> Result<Self, String> {
        spec.validate()?;
        Ok(Self {
            observation: Observation {
                version: 4,
                spec,
                rows: vec![],
                counters: Counters::default(),
                history: History::default(),
                decode: DecodeDiagnostics::default(),
                process_trace_status: 0,
                close_trace_status: 0,
                consumer_completed: false,
                cutoff_reached: false,
            },
            pending: BTreeMap::new(),
        })
    }
    pub fn counters(&mut self) -> &mut Counters {
        &mut self.observation.counters
    }
    pub fn received(&mut self, opcode: u8) {
        let decode = &mut self.observation.decode;
        match opcode {
            64 => decode.create_header_matched = decode.create_header_matched.saturating_add(1),
            76 => decode.completion_received = decode.completion_received.saturating_add(1),
            _ => {}
        }
    }
    pub fn decoded(&mut self, opcode: u8) {
        let decode = &mut self.observation.decode;
        match opcode {
            64 => decode.create_decoded = decode.create_decoded.saturating_add(1),
            76 => decode.completion_decoded = decode.completion_decoded.saturating_add(1),
            _ => {}
        }
    }
    pub fn wants_sample(
        &self,
        opcode: u8,
        version: u8,
        stage: RejectStage,
        field: Option<FieldId>,
    ) -> bool {
        opcode_index(opcode).is_some()
            && self
                .observation
                .decode
                .samples
                .iter()
                .filter(|sample| sample.opcode == opcode)
                .count()
                < 4
            && !self
                .observation
                .decode
                .samples
                .iter()
                .any(|sample| same_sample(sample, opcode, version, stage, field))
    }
    pub fn rejected(&mut self, sample: RejectSample) {
        let Some(opcode) = opcode_index(sample.opcode) else {
            return;
        };
        let wanted = self.wants_sample(
            sample.opcode,
            sample.event_version,
            sample.rejection.stage,
            sample.rejection.field,
        );
        let duplicate = self.observation.decode.samples.iter().any(|prior| {
            same_sample(
                prior,
                sample.opcode,
                sample.event_version,
                sample.rejection.stage,
                sample.rejection.field,
            )
        });
        let decode = &mut self.observation.decode;
        match opcode {
            0 => decode.create_rejected = decode.create_rejected.saturating_add(1),
            _ => decode.completion_rejected = decode.completion_rejected.saturating_add(1),
        }
        let count = &mut decode.stage_counts[opcode][sample.rejection.stage as usize];
        *count = count.saturating_add(1);
        self.observation.counters.unsupported =
            self.observation.counters.unsupported.saturating_add(1);
        if wanted {
            decode.samples.push(sample);
        } else if !duplicate {
            decode.sample_omitted = decode.sample_omitted.saturating_add(1);
        }
        decode.bound();
    }
    pub fn create(&mut self, create: Create) {
        self.observation.history.record(create.qpc);
        let counters = &mut self.observation.counters;
        counters.seen = counters.seen.saturating_add(1);
        if create.header_pid != self.observation.spec.pid
            || create.qpc > self.observation.spec.binding.cutoff_qpc
        {
            counters.filtered = counters.filtered.saturating_add(1);
            return;
        }
        if create.irp == 0 {
            counters.malformed = counters.malformed.saturating_add(1);
            return;
        }
        let mut ambiguous = false;
        for row in &mut self.observation.rows {
            if row.create.irp == create.irp
                && row
                    .completion
                    .as_ref()
                    .is_some_and(|end| end.qpc == create.qpc)
            {
                row.ambiguous = true;
                ambiguous = true;
            }
        }
        if ambiguous {
            counters.ambiguous = counters.ambiguous.saturating_add(1);
        }
        if let Some(old) = self.pending.get_mut(&create.irp) {
            if let Some(index) = old.take() {
                self.observation.rows[index].ambiguous = true;
            }
            counters.ambiguous = counters.ambiguous.saturating_add(1);
            return;
        }
        let reusable = if self.observation.spec.retention == RetentionMode::RollingCompleted
            && self.observation.rows.len() == MAX_ROWS
        {
            self.observation
                .rows
                .iter()
                .enumerate()
                .filter_map(|(index, row)| {
                    let completion = row.completion.as_ref()?;
                    (!row.ambiguous
                        && !self.pending.contains_key(&row.create.irp)
                        && !self.pending.values().any(|pending| *pending == Some(index)))
                    .then_some((index, completion.qpc, row.create.qpc))
                })
                .min_by_key(|(index, completion, create)| (*completion, *create, *index))
                .map(|(index, _, _)| index)
        } else {
            None
        };
        if self.pending.len() == MAX_PENDING
            || (self.observation.rows.len() == MAX_ROWS && reusable.is_none())
        {
            counters.overflow = counters.overflow.saturating_add(1);
            self.observation.history.dropped(create.qpc);
            return;
        }
        let index = reusable.unwrap_or(self.observation.rows.len());
        self.pending.insert(create.irp, Some(index));
        let row = Row {
            create,
            completion: None,
            ambiguous,
        };
        if let Some(index) = reusable {
            let evicted = &self.observation.rows[index];
            self.observation.history.evicted(
                evicted.create.qpc,
                evicted
                    .completion
                    .as_ref()
                    .expect("completed reusable slot")
                    .qpc,
            );
            self.observation.rows[index] = row;
        } else {
            self.observation.rows.push(row);
        }
    }
    pub fn completion(&mut self, end: Completion) {
        self.observation.history.record(end.qpc);
        self.observation.counters.seen = self.observation.counters.seen.saturating_add(1);
        let mut ambiguous = false;
        for row in &mut self.observation.rows {
            if row.create.irp == end.irp
                && row
                    .completion
                    .as_ref()
                    .is_some_and(|prior| prior.qpc == end.qpc)
            {
                row.ambiguous = true;
                ambiguous = true;
            }
        }
        if ambiguous {
            self.observation.counters.ambiguous =
                self.observation.counters.ambiguous.saturating_add(1);
        }
        if self.pending.get(&end.irp).is_some_and(Option::is_none) {
            self.observation.counters.ambiguous =
                self.observation.counters.ambiguous.saturating_add(1);
            return;
        }
        let Some(index) = self.pending.remove(&end.irp) else {
            self.observation.counters.orphan = self.observation.counters.orphan.saturating_add(1);
            return;
        };
        let Some(index) = index else {
            return;
        };
        let row = &mut self.observation.rows[index];
        row.ambiguous |= ambiguous;
        if end.qpc == row.create.qpc {
            row.ambiguous = true;
            self.observation.counters.ambiguous =
                self.observation.counters.ambiguous.saturating_add(1);
        }
        if end.qpc < row.create.qpc {
            row.ambiguous = true;
            self.observation.counters.reversed =
                self.observation.counters.reversed.saturating_add(1);
        }
        row.completion = Some(end);
    }
    pub fn finish(mut self, status: u32, cutoff_reached: bool) -> Observation {
        self.observation.counters.unmatched = self.pending.len() as u64;
        self.observation.process_trace_status = status;
        self.observation.consumer_completed = true;
        self.observation.cutoff_reached = cutoff_reached;
        self.observation
    }
}

pub fn correlate(
    observation: &Observation,
    expected: &ConsumerSpec,
    original_thread: u32,
    windows: &[Window],
) -> Value {
    let binding = &expected.binding;
    let valid = observation.validate().is_ok()
        && observation.spec == *expected
        && original_thread != 0
        && windows.len() <= 17;
    let complete = observation.consumer_completed
        && !observation.cutoff_reached
        && observation.process_trace_status == 0
        && observation.close_trace_status == 0
        && !observation.history.timestamp_regression
        && observation.counters.malformed == 0
        && observation.counters.unsupported == 0;
    let mut rows = if valid {
        observation.rows.iter().map(|row|{
        let matched=windows.iter().filter(|window|window.dependency_sequence!=0&&window.loader_dependency_sequence!=0&&window.parent_listener_sequence!=0
            &&window.started_qpc!=0&&window.started_qpc<=window.finished_qpc&&window.finished_qpc<=binding.cutoff_qpc
            &&row.create.ttid==original_thread&&row.create.qpc>=window.started_qpc
            &&row.completion.as_ref().is_some_and(|end|end.qpc>=row.create.qpc&&end.qpc<=window.finished_qpc)).collect::<Vec<_>>();
        let before_drop = matched.len()==1 && (observation.counters.overflow==0
            || observation.history.earliest_dropped_create_qpc.is_some_and(|frontier|matched[0].finished_qpc<frontier));
        let after_eviction = matched.len()==1 && (observation.history.evicted_pairs==0
            || observation.history.maximum_evicted_pair_qpc.is_some_and(|frontier|matched[0].started_qpc>frontier));
        let interval = before_drop && after_eviction;
        let strict_pair = row.completion.as_ref().is_some_and(|end| row.create.qpc<end.qpc);
        let attributed=complete&&interval&&strict_pair&&!row.ambiguous&&row.create.irp!=0&&matched.len()==1;
        let scope=if observation.spec.retention==RetentionMode::RollingCompleted && observation.history.evicted_pairs!=0 {"retained-decoded-interval-between-loss-frontiers"}
            else if observation.counters.overflow==0 {"retained-decoded-history"} else {"retained-prefix-before-first-dropped-create"};
        json!({"create":row.create,"completion":row.completion,"ambiguous":row.ambiguous,"temporal_original_call_association":attributed,"association_scope":if attributed{Some(scope)}else{None},"capacity_truncation_blocks_window":matched.len()==1&&!interval,"eviction_frontier_blocks_window":matched.len()==1&&!after_eviction,"dropped_create_frontier_blocks_window":matched.len()==1&&!before_drop,"window":if attributed{Some(matched[0])}else{None},"observed_failed_create":attributed&&row.completion.as_ref().is_some_and(|end|end.ntstatus<0),"denied_object_proved":false})
    }).collect::<Vec<_>>()
    } else {
        vec![]
    };
    // Keep associated failures, then associated successes, ahead of context.
    rows.sort_by_key(|row| {
        (
            !row["observed_failed_create"].as_bool().unwrap_or(false),
            observation.spec.retention == RetentionMode::RollingCompleted
                && !row["temporal_original_call_association"]
                    .as_bool()
                    .unwrap_or(false),
        )
    });
    let mut result = json!({"format":"memcordon.loader-fileio-observation","revision":4,"diagnostic_only":true,"acceptance_authority":false,"global_routes_complete":false,"denied_object_proved":false,"valid_binding_and_record":valid,"consumer_side_header_pid_filter":true,"header_pid_may_miss_requestor_context":true,"absence_proves_no_file_activity":false,"retention_mode":observation.spec.retention,"retained_interval":{"strictly_after_evicted_pair_qpc":observation.history.maximum_evicted_pair_qpc,"strictly_before_dropped_create_qpc":observation.history.earliest_dropped_create_qpc,"global_completeness":false},"counters":observation.counters,"history":observation.history,"capacity_truncated":observation.counters.overflow!=0||observation.history.evicted_pairs!=0,"timestamp_regression_prevents_association":observation.history.timestamp_regression,"decode":decode_diagnostic(&observation.decode),"unsupported_history_prevents_association":observation.counters.unsupported!=0,"process_trace_status":observation.process_trace_status,"close_trace_status":observation.close_trace_status,"consumer_completed":observation.consumer_completed,"cutoff_reached":observation.cutoff_reached,"rows":rows,"rows_omitted":0});
    let mut omitted = 0;
    while serde_json::to_vec(&result).map_or(true, |bytes| bytes.len() > CORRELATION_BYTES) {
        let Some(rows) = result["rows"].as_array_mut() else {
            break;
        };
        if rows.pop().is_none() {
            break;
        }
        omitted += 1;
        result["rows_omitted"] = json!(omitted);
    }
    result
}
