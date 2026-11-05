//! Finite diagnostic FileIo observations; numeric identities are never capabilities.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const INPUT_BYTES: usize = 8192;
pub const RECORD_BYTES: usize = 65536;
pub const MAX_ROWS: usize = 32;
pub const MAX_PENDING: usize = 128;
pub const CORRELATION_BYTES: usize = 49152;

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
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumerSpec {
    pub version: u32,
    pub session_name: String,
    pub session_guid: [u8; 16],
    pub pid: u32,
    pub birth: u64,
    pub binding: Binding,
}
impl ConsumerSpec {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1
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
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub version: u32,
    pub spec: ConsumerSpec,
    pub rows: Vec<Row>,
    pub counters: Counters,
    pub process_trace_status: u32,
    pub close_trace_status: u32,
    pub consumer_completed: bool,
    pub cutoff_reached: bool,
}
impl Observation {
    pub fn validate(&self) -> Result<(), String> {
        self.spec.validate()?;
        if self.version != 1 || self.rows.len() > MAX_ROWS {
            return Err("FileIo record bound/version differs".into());
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
                || create.path_units > 32767
                || create.path_sha256.is_none()
                || row.completion.as_ref().is_some_and(|end| {
                    end.irp != create.irp
                        || end.qpc == 0
                        || end.qpc > self.spec.binding.cutoff_qpc
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
                version: 1,
                spec,
                rows: vec![],
                counters: Counters::default(),
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
    pub fn create(&mut self, create: Create) {
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
        if let Some(old) = self.pending.get_mut(&create.irp) {
            if let Some(index) = old.take() {
                self.observation.rows[index].ambiguous = true;
            }
            counters.ambiguous = counters.ambiguous.saturating_add(1);
            return;
        }
        if self.pending.len() == MAX_PENDING || self.observation.rows.len() == MAX_ROWS {
            counters.overflow = counters.overflow.saturating_add(1);
            return;
        }
        let index = self.observation.rows.len();
        self.pending.insert(create.irp, Some(index));
        self.observation.rows.push(Row {
            create,
            completion: None,
            ambiguous: false,
        });
    }
    pub fn completion(&mut self, end: Completion) {
        self.observation.counters.seen = self.observation.counters.seen.saturating_add(1);
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
        && observation.counters.overflow == 0
        && observation.counters.malformed == 0;
    let mut rows = if valid {
        observation.rows.iter().map(|row|{
        let matched=windows.iter().filter(|window|window.dependency_sequence!=0&&window.loader_dependency_sequence!=0&&window.parent_listener_sequence!=0
            &&window.started_qpc!=0&&window.started_qpc<=window.finished_qpc&&window.finished_qpc<=binding.cutoff_qpc
            &&row.create.ttid==original_thread&&row.create.qpc>=window.started_qpc
            &&row.completion.as_ref().is_some_and(|end|end.qpc>=row.create.qpc&&end.qpc<=window.finished_qpc)).collect::<Vec<_>>();
        let attributed=complete&&!row.ambiguous&&row.create.irp!=0&&matched.len()==1;
        json!({"create":row.create,"completion":row.completion,"ambiguous":row.ambiguous,"temporal_original_call_association":attributed,"window":if attributed{Some(matched[0])}else{None},"observed_failed_create":attributed&&row.completion.as_ref().is_some_and(|end|end.ntstatus<0),"denied_object_proved":false})
    }).collect::<Vec<_>>()
    } else {
        vec![]
    };
    // Keep the first associated failed create when bounded output omits later rows.
    rows.sort_by_key(|row| !row["observed_failed_create"].as_bool().unwrap_or(false));
    let mut result = json!({"format":"memcordon.loader-fileio-observation","revision":1,"diagnostic_only":true,"acceptance_authority":false,"global_routes_complete":false,"denied_object_proved":false,"valid_binding_and_record":valid,"consumer_side_header_pid_filter":true,"header_pid_may_miss_requestor_context":true,"absence_proves_no_file_activity":false,"counters":observation.counters,"process_trace_status":observation.process_trace_status,"close_trace_status":observation.close_trace_status,"consumer_completed":observation.consumer_completed,"cutoff_reached":observation.cutoff_reached,"rows":rows,"rows_omitted":0});
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
