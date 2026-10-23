//! Bounded diagnostic associations, never loaded-file identity or launch authority.
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum EventKind {
    Exception,
    CreateThread,
    CreateProcess,
    ExitThread,
    ExitProcess,
    LoadDll,
    UnloadDll,
    OutputDebugString,
    Rip,
    Unknown(u32),
}
impl EventKind {
    pub fn from_code(code: u32) -> Self {
        match code {
            1 => Self::Exception,
            2 => Self::CreateThread,
            3 => Self::CreateProcess,
            4 => Self::ExitThread,
            5 => Self::ExitProcess,
            6 => Self::LoadDll,
            7 => Self::UnloadDll,
            8 => Self::OutputDebugString,
            9 => Self::Rip,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum LoadOutcome {
    FirstLoad,
    ReusedBase,
    DuplicateLive,
    TableExhausted,
    GenerationExhausted,
}
#[derive(Debug, Serialize)]
pub struct LoadAssociation {
    pub base: u64,
    pub sequence: u64,
    pub outcome: LoadOutcome,
    pub generation: Option<u64>,
    pub load_sequence: Option<u64>,
    pub previous_generation: Option<u64>,
    pub previous_load_sequence: Option<u64>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum UnloadOutcome {
    Matched,
    UnknownBase,
    AlreadyUnloaded,
    GenerationExhausted,
}
#[derive(Debug, Serialize)]
pub struct UnloadAssociation {
    pub base: u64,
    pub sequence: u64,
    pub outcome: UnloadOutcome,
    pub generation: Option<u64>,
    pub load_sequence: Option<u64>,
    pub previous_unload_sequence: Option<u64>,
}
struct Entry {
    generation: u64,
    load_sequence: u64,
    unload_sequence: Option<u64>,
    exhausted: bool,
}
pub struct ModuleTable {
    capacity: usize,
    entries: BTreeMap<u64, Entry>,
}
impl ModuleTable {
    pub fn new(capacity: usize) -> Self {
        assert!(
            (1..=256).contains(&capacity),
            "module table capacity must be within 1..=256"
        );
        Self {
            capacity,
            entries: BTreeMap::new(),
        }
    }
    pub fn load(&mut self, base: u64, sequence: u64) -> LoadAssociation {
        let mut observation = LoadAssociation {
            base,
            sequence,
            outcome: LoadOutcome::FirstLoad,
            generation: None,
            load_sequence: None,
            previous_generation: None,
            previous_load_sequence: None,
        };
        if let Some(entry) = self.entries.get_mut(&base) {
            observation.previous_generation = Some(entry.generation);
            observation.previous_load_sequence = Some(entry.load_sequence);
            let Some(generation) = entry.generation.checked_add(1).filter(|_| !entry.exhausted)
            else {
                entry.exhausted = true;
                observation.outcome = LoadOutcome::GenerationExhausted;
                return observation;
            };
            observation.outcome = if entry.unload_sequence.is_some() {
                LoadOutcome::ReusedBase
            } else {
                LoadOutcome::DuplicateLive
            };
            entry.generation = generation;
            entry.load_sequence = sequence;
            entry.unload_sequence = None;
            observation.generation = Some(generation);
            observation.load_sequence = Some(sequence);
        } else if self.entries.len() == self.capacity {
            observation.outcome = LoadOutcome::TableExhausted;
        } else {
            self.entries.insert(
                base,
                Entry {
                    generation: 1,
                    load_sequence: sequence,
                    unload_sequence: None,
                    exhausted: false,
                },
            );
            observation.generation = Some(1);
            observation.load_sequence = Some(sequence);
        }
        observation
    }
    pub fn unload(&mut self, base: u64, sequence: u64) -> UnloadAssociation {
        let mut observation = UnloadAssociation {
            base,
            sequence,
            outcome: UnloadOutcome::UnknownBase,
            generation: None,
            load_sequence: None,
            previous_unload_sequence: None,
        };
        if let Some(entry) = self.entries.get_mut(&base) {
            if entry.exhausted {
                observation.outcome = UnloadOutcome::GenerationExhausted;
                return observation;
            }
            observation.generation = Some(entry.generation);
            observation.load_sequence = Some(entry.load_sequence);
            observation.previous_unload_sequence = entry.unload_sequence;
            observation.outcome = if entry.unload_sequence.is_some() {
                UnloadOutcome::AlreadyUnloaded
            } else {
                entry.unload_sequence = Some(sequence);
                UnloadOutcome::Matched
            };
        }
        observation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum MappedNameOutcome {
    Complete,
    Truncated,
    NativeFailure,
    InvalidUtf16,
    InvalidText,
    SkippedDeadline,
}
#[derive(Debug, Serialize)]
pub struct MappedName {
    pub api: &'static str,
    pub source: &'static str,
    pub outcome: MappedNameOutcome,
    pub path: Option<String>,
    pub raw_return: u32,
    pub native_error: Option<u32>,
    pub capacity_units: usize,
    pub truncated: bool,
}
impl MappedName {
    pub fn skipped_deadline(capacity_units: usize) -> Self {
        Self {
            api: "K32GetMappedFileNameW",
            source: "held-process-mapped-section-path",
            outcome: MappedNameOutcome::SkippedDeadline,
            path: None,
            raw_return: 0,
            native_error: None,
            capacity_units,
            truncated: false,
        }
    }
}
pub fn classify_mapped_name(buffer: &[u16], returned: u32, error: Option<u32>) -> MappedName {
    let mut observation = MappedName::skipped_deadline(buffer.len());
    observation.raw_return = returned;
    if returned == 0 {
        observation.outcome = MappedNameOutcome::NativeFailure;
        observation.native_error = error;
        return observation;
    }
    let truncated = returned as usize >= buffer.len();
    observation.truncated = truncated;
    let units = &buffer[..(returned as usize).min(buffer.len())];
    if units.contains(&0) {
        observation.outcome = MappedNameOutcome::InvalidText;
        return observation;
    }
    match String::from_utf16(units) {
        Ok(path) => {
            observation.path = Some(path);
            observation.outcome = if truncated {
                MappedNameOutcome::Truncated
            } else {
                MappedNameOutcome::Complete
            };
        }
        Err(_) => observation.outcome = MappedNameOutcome::InvalidUtf16,
    }
    observation
}
