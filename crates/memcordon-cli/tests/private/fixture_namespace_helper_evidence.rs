//! Bounded x64 ABI observations; opaque handles never imply object identity.
//! OBJECT_ATTRIBUTES/UNICODE_STRING use their public x64 layouts. Only documented
//! DWORD token classes12(SessionId) and29(IsAppContainer) are decoded.
use super::hit_receipt::{Metadata, Receipt};
use super::profile::{DebugRegisters, Stop, helper_profile};
use helper_profile::CallKind;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io;

pub const TRACE_BYTES: usize = 20 * 1024;
pub const DIRECTORY_POLICY_BYTES: usize = 12 * 1024;
pub const MEMORY_BYTES: usize = 4096;
pub const NAME_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum CaptureError {
    Null,
    Overflow,
    Partial,
    Read(Option<i32>),
    OddUnicode,
    InvalidLength,
    MemoryBudget,
    TraceBudget,
    PairMismatch,
}
impl CaptureError {
    pub fn io_error(self) -> io::Error {
        io::Error::other(format!("helper evidence: {self:?}"))
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Name {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: u64,
    pub utf16_le_hex: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct ObjectAttributes {
    pub length: u32,
    pub root_handle: u64,
    pub name_pointer: u64,
    pub attributes: u32,
    pub security_descriptor_pointer: u64,
    pub security_qos_pointer: u64,
    pub name: Option<Name>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Input {
    pub call: u32,
    pub kind: CallKind,
    pub args: [u64; 4],
    pub fifth_argument: Option<u64>,
    pub object_attributes: Option<ObjectAttributes>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Output {
    pub call: u32,
    pub status: Option<i32>,
    pub successful_output_handle: Option<u64>,
    pub observed_return_length: Option<u32>,
    pub scalar: Option<u32>,
    pub content_scope: &'static str,
}
#[derive(Clone, Debug, Serialize)]
pub enum Operands {
    Before(Input),
    After(Output),
}

#[derive(Default)]
pub struct MemoryBudget {
    used: usize,
}
impl MemoryBudget {
    fn read(
        &mut self,
        address: u64,
        size: usize,
        read: &mut impl FnMut(u64, usize) -> io::Result<Vec<u8>>,
    ) -> Result<Vec<u8>, CaptureError> {
        if address == 0 {
            return Err(CaptureError::Null);
        }
        address
            .checked_add(size as u64)
            .ok_or(CaptureError::Overflow)?;
        let used = self
            .used
            .checked_add(size)
            .ok_or(CaptureError::MemoryBudget)?;
        if used > MEMORY_BYTES {
            return Err(CaptureError::MemoryBudget);
        }
        self.used = used;
        let bytes =
            read(address, size).map_err(|error| CaptureError::Read(error.raw_os_error()))?;
        if bytes.len() != size {
            return Err(CaptureError::Partial);
        }
        Ok(bytes)
    }
    pub fn object_attributes(
        &mut self,
        address: u64,
        read: &mut impl FnMut(u64, usize) -> io::Result<Vec<u8>>,
    ) -> Result<ObjectAttributes, CaptureError> {
        let bytes = self.read(address, 48, read)?;
        let length = u32_at(&bytes, 0);
        if length != 48 {
            return Err(CaptureError::InvalidLength);
        }
        let name_pointer = u64_at(&bytes, 16);
        let name = if name_pointer == 0 {
            None
        } else {
            let descriptor = self.read(name_pointer, 16, read)?;
            let length = u16::from_le_bytes(descriptor[..2].try_into().unwrap());
            let maximum_length = u16::from_le_bytes(descriptor[2..4].try_into().unwrap());
            let buffer = u64_at(&descriptor, 8);
            if length % 2 != 0 || maximum_length % 2 != 0 {
                return Err(CaptureError::OddUnicode);
            }
            if length > maximum_length || usize::from(length) > NAME_BYTES {
                return Err(CaptureError::InvalidLength);
            }
            let bytes = if length == 0 {
                Vec::new()
            } else {
                self.read(buffer, usize::from(length), read)?
            };
            Some(Name {
                length,
                maximum_length,
                buffer,
                utf16_le_hex: hex(&bytes),
            })
        };
        Ok(ObjectAttributes {
            length,
            root_handle: u64_at(&bytes, 8),
            name_pointer,
            attributes: u32_at(&bytes, 24),
            security_descriptor_pointer: u64_at(&bytes, 32),
            security_qos_pointer: u64_at(&bytes, 40),
            name,
        })
    }
}
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + size_of::<u32>()].try_into().unwrap())
}
fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + size_of::<u64>()].try_into().unwrap())
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                DIGITS[usize::from(byte >> 4)] as char,
                DIGITS[usize::from(byte & 15)] as char,
            ]
        })
        .collect()
}

/// Lossless unsigned LEB128, encoded as hexadecimal; no pointer truncation.
pub fn pack(values: &[u64]) -> String {
    let mut bytes = Vec::new();
    for value in values {
        let mut value = *value;
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            bytes.push(byte | if value == 0 { 0 } else { 0x80 });
            if value == 0 {
                break;
            }
        }
    }
    hex(&bytes)
}

pub const RAW_FIELDS: &[&str] = &[
    "event_ordinal",
    "flags",
    "raw_first_chance",
    "qpc_present",
    "qpc",
    "pid",
    "tid",
    "exception",
    "first_chance",
    "exception_address",
    "rip",
    "dr0",
    "dr1",
    "dr2",
    "dr3",
    "dr6",
    "dr7",
    "eflags",
    "rax",
    "r14",
    "rbx",
    "rcx",
    "rdx",
    "r8",
    "r9",
    "rsp",
];
pub fn raw_values(metadata: Metadata, stop: Stop) -> [u64; 26] {
    [
        metadata.event_ordinal as u64,
        u64::from(metadata.flags),
        u64::from(metadata.first_chance),
        u64::from(metadata.received_qpc.is_some()),
        metadata.received_qpc.unwrap_or(0),
        u64::from(stop.pid),
        u64::from(stop.tid),
        u64::from(stop.exception),
        u64::from(stop.first_chance),
        stop.exception_address,
        stop.rip,
        stop.registers.dr[0],
        stop.registers.dr[1],
        stop.registers.dr[2],
        stop.registers.dr[3],
        stop.registers.dr6,
        stop.registers.dr7,
        u64::from(stop.registers.eflags),
        stop.rax,
        stop.r14,
        stop.rbx,
        stop.rcx,
        stop.rdx,
        stop.r8,
        stop.r9,
        stop.rsp,
    ]
}
fn debug_values(value: DebugRegisters) -> [u64; 7] {
    [
        value.dr[0],
        value.dr[1],
        value.dr[2],
        value.dr[3],
        value.dr6,
        value.dr7,
        u64::from(value.eflags),
    ]
}
fn delta(values: &[u64], previous: &[u64]) -> String {
    pack(
        &values
            .iter()
            .zip(previous)
            .map(|(a, b)| a ^ b)
            .collect::<Vec<_>>(),
    )
}

/// Each tuple is RVA,slot,raw-delta,expected-XOR-raw,planned-XOR-raw,
/// readback-XOR-planned,transition_verified,paired operands. Register order is
/// DR0..3,DR6,DR7,EFLAGS; active mappings are physical DR0..2 and the catalog.
#[derive(Serialize)]
pub struct Compact(
    pub u32,
    pub usize,
    pub String,
    pub String,
    pub String,
    pub String,
    pub bool,
    pub Option<Operands>,
);

#[derive(Serialize)]
pub struct Trace {
    pub catalog: &'static str,
    pub encoding: &'static str,
    pub raw_fields: &'static [&'static str],
    pub record_fields: &'static [&'static str],
    pub debug_fields: &'static [&'static str],
    pub records: Vec<Compact>,
    pub failure: Option<(u32, CaptureError)>,
    pub omitted: usize,
    #[serde(skip)]
    previous_raw: [u64; 26],
    #[serde(skip)]
    pending: Option<Input>,
    #[serde(skip)]
    memory: MemoryBudget,
}
impl Default for Trace {
    fn default() -> Self {
        Self {
            catalog: "kernelbase-96c0459f-helper-v1",
            encoding: "hex-uleb128; raw XOR previous raw (initial zeros); debug XOR indicated raw/planned; tuple fields documented in source",
            raw_fields: RAW_FIELDS,
            record_fields: &[
                "rva",
                "physical_slot",
                "raw_xor_previous",
                "expected_debug_xor_raw",
                "planned_debug_xor_raw",
                "readback_debug_xor_planned",
                "transition_verified",
                "paired_operands",
            ],
            debug_fields: &["dr0", "dr1", "dr2", "dr3", "dr6", "dr7", "eflags"],
            records: Vec::new(),
            failure: None,
            omitted: 0,
            previous_raw: [0; 26],
            pending: None,
            memory: MemoryBudget::default(),
        }
    }
}
impl Trace {
    pub fn operands(
        &mut self,
        rva: u32,
        stop: Stop,
        read: &mut impl FnMut(u64, usize) -> io::Result<Vec<u8>>,
    ) -> Result<Option<Operands>, CaptureError> {
        let result = self.capture_operands(rva, stop, read);
        if let Err(error) = result {
            self.failure = Some((rva, error));
        }
        result
    }
    fn capture_operands(
        &mut self,
        rva: u32,
        stop: Stop,
        read: &mut impl FnMut(u64, usize) -> io::Result<Vec<u8>>,
    ) -> Result<Option<Operands>, CaptureError> {
        let node = helper_profile::checkpoint(rva).ok_or(CaptureError::PairMismatch)?;
        if node.kind == "call-entry" {
            if self.pending.is_some() {
                return Err(CaptureError::PairMismatch);
            }
            let kind = helper_profile::call_kind(rva);
            let fifth = if kind == CallKind::TokenQuery {
                let address = stop.rsp.checked_add(32).ok_or(CaptureError::Overflow)?;
                Some(u64_at(&self.memory.read(address, 8, read)?, 0))
            } else {
                None
            };
            let input = Input {
                call: rva,
                kind,
                args: [stop.rcx, stop.rdx, stop.r8, stop.r9],
                fifth_argument: fifth,
                object_attributes: if kind == CallKind::DirectoryOpen {
                    Some(self.memory.object_attributes(stop.r8, read)?)
                } else {
                    None
                },
            };
            self.pending = Some(input.clone());
            return Ok(Some(Operands::Before(input)));
        }
        if node.kind != "call-return" {
            return Ok(None);
        }
        let input = self.pending.take().ok_or(CaptureError::PairMismatch)?;
        if helper_profile::paired_call(rva).map(|call| call.rva) != Some(input.call) {
            return Err(CaptureError::PairMismatch);
        }
        let status = (input.kind != CallKind::Other).then_some(stop.rax as u32 as i32);
        let mut output = Output {
            call: input.call,
            status,
            successful_output_handle: None,
            observed_return_length: None,
            scalar: None,
            content_scope: "not a decoded public scalar; runtime call target unobserved",
        };
        if input.kind == CallKind::DirectoryOpen && status.is_some_and(|status| status >= 0) {
            output.successful_output_handle =
                Some(u64_at(&self.memory.read(input.args[0], 8, read)?, 0));
            output.content_scope = "successful output handle observed; opaque identity only";
        }
        if input.kind == CallKind::TokenQuery {
            if let Some(pointer) = input.fifth_argument.filter(|pointer| *pointer != 0) {
                output.observed_return_length =
                    Some(u32_at(&self.memory.read(pointer, 4, read)?, 0));
            }
            output.content_scope = "raw return-length pointer observation; failed outputs invalid; unsupported token content unobserved";
            if status.is_some_and(|status| status >= 0) && matches!(input.args[1] as u32, 12 | 29) {
                let returned = output
                    .observed_return_length
                    .ok_or(CaptureError::InvalidLength)?;
                if returned < 4 || u64::from(returned) > u64::from(input.args[3] as u32) {
                    return Err(CaptureError::InvalidLength);
                }
                output.scalar = Some(u32_at(&self.memory.read(input.args[2], 4, read)?, 0));
                output.content_scope =
                    "documented DWORD token class; bounded by provided and observed return lengths";
            }
        }
        Ok(Some(Operands::After(output)))
    }
    pub fn record(
        &mut self,
        rva: u32,
        slot: usize,
        receipt: &Receipt,
        planned: DebugRegisters,
        operands: Option<Operands>,
    ) -> Result<usize, CaptureError> {
        if self.records.len() >= helper_profile::MAX_CHECKPOINT_STOPS {
            self.failure = Some((rva, CaptureError::TraceBudget));
            self.omitted += 1;
            return Err(CaptureError::TraceBudget);
        }
        let raw = raw_values(receipt.metadata, receipt.raw);
        let expected = receipt
            .expected
            .map(|value| value.registers)
            .unwrap_or(receipt.raw.registers);
        self.records.push(Compact(
            rva,
            slot,
            delta(&raw, &self.previous_raw),
            delta(
                &debug_values(expected),
                &debug_values(receipt.raw.registers),
            ),
            delta(&debug_values(planned), &debug_values(receipt.raw.registers)),
            String::new(),
            false,
            operands,
        ));
        // Reserve seven worst-case u64 readback deltas and a terminal failure.
        if serde_json::to_vec(&self).map_or(true, |bytes| bytes.len() + 256 > TRACE_BYTES) {
            self.records.pop();
            self.omitted += 1;
            self.failure = Some((rva, CaptureError::TraceBudget));
            return Err(CaptureError::TraceBudget);
        }
        self.previous_raw = raw;
        Ok(self.records.len() - 1)
    }
    pub fn readback(
        &mut self,
        index: usize,
        planned: DebugRegisters,
        actual: DebugRegisters,
        verified: bool,
    ) {
        let record = &mut self.records[index];
        record.5 = delta(&debug_values(actual), &debug_values(planned));
        record.6 = verified;
    }
}

/// Reserve the fixed 64KiB artifact envelope for raw receipts, ordered helper
/// evidence, selected-status correlation and terminal cleanup. Large redundant
/// summaries may be omitted explicitly; raw rejected stops are never removed.
pub fn fit_report(mut report: serde_json::Value) -> Result<serde_json::Value, CaptureError> {
    const LIMIT: usize = 64 * 1024 - 1; // persist appends one newline.
    let mut omitted = Vec::new();
    for key in [
        "host_profile",
        "hits",
        "events",
        "context_calls",
        "replay_result",
        "envelope",
        "late_markers",
        "marker_receipts",
        "entry_arguments",
        "session_directory_policy",
    ] {
        if serde_json::to_vec(&report).is_ok_and(|bytes| bytes.len() <= LIMIT) {
            return Ok(report);
        }
        if let Some(value) = report.get(key) {
            let size = serde_json::to_vec(value)
                .map_err(|_| CaptureError::TraceBudget)?
                .len();
            // Context API first failure remains independently useful evidence.
            let first_failure = if key == "context_calls" {
                value
                    .get("first_failure")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null)
            } else {
                serde_json::Value::Null
            };
            let handles_released = value
                .get("handles_released")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let candidate_sha256 = if key == "session_directory_policy" {
                Some(hex(&Sha256::digest(
                    serde_json::to_vec(value).map_err(|_| CaptureError::TraceBudget)?,
                )))
            } else {
                None
            };
            report[key] = serde_json::json!({"unavailable":"record-byte-budget","omitted_serialized_bytes":size,"candidate_sha256":candidate_sha256,"scope":"optional supplied-data diagnostic; original trace/strict result retained","first_failure":first_failure,"handles_released":handles_released});
            omitted.push(serde_json::json!({"field":key,"serialized_bytes":size}));
            report["capture_evidence_complete"] = serde_json::json!(false);
            report["record_budget"] = serde_json::json!({"reason":"record-byte-budget; original failure, raw receipts, helper trace and terminal cleanup retained","omitted_summaries":omitted});
        }
    }
    if serde_json::to_vec(&report).is_ok_and(|bytes| bytes.len() <= LIMIT) {
        Ok(report)
    } else {
        Err(CaptureError::TraceBudget)
    }
}
