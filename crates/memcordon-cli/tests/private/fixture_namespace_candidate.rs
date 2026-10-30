//! Bounded observations of existing loader-event admission checks; no authority.
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage {
    NotProcessed,
    MissingHandle,
    MappedBase,
    MappedName,
    MappedBasenameMismatch,
    MappedSystemDirectory,
    MappedRootOpen,
    MappedRootIdentity,
    MappedRootPath,
    MappedRootMismatch,
    MappedFileOpen,
    MappedFilePath,
    MappedFileMismatch,
    MappedRecheck,
    Inactive,
    FileMetadata,
    LengthMismatch,
    FinalPath,
    SystemDirectory,
    MissingSeparator,
    ParentMismatch,
    BasenameMismatch,
    FileIdentityBefore,
    Read,
    FileMetadataAfter,
    FileProfile,
    FileIdentityAfter,
    RuntimeHeader,
    Mapping,
    RuntimeBytes,
    Accepted,
}

#[derive(Debug, Serialize)]
pub struct PathEvidence {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub units: Vec<u16>,
    pub total_units: usize,
    pub truncated: bool,
    pub utf16le_sha256: String,
}
impl PathEvidence {
    pub fn new(units: &[u16]) -> Self {
        Self {
            units: units.iter().copied().take(256).collect(),
            total_units: units.len(),
            truncated: units.len() > 256,
            utf16le_sha256: Sha256::digest(
                units
                    .iter()
                    .flat_map(|unit| unit.to_le_bytes())
                    .collect::<Vec<_>>(),
            )
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Candidate {
    /// [debug-event ordinal, PID, TID, module base]; labels also retained in summary.
    pub event: (usize, u32, u32, u64),
    pub handle: HandleState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<Provider>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mapped: Option<MappedEvidence>,
    pub stage: Stage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "path")]
    pub final_path: Option<PathEvidence>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "system")]
    pub system_directory: Option<PathEvidence>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "parent")]
    pub parent_matches: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "basename")]
    pub basename_matches: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_raw_error: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basename_raw_error: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_rva: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_error: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub deadline: bool,
    #[serde(
        skip_serializing_if = "std::ops::Not::not",
        rename = "prefixes_omitted"
    )]
    pub paths_omitted_for_record_bound: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub extended_dos_prefix_stripped: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HandleState {
    Null,
    Invalid,
    Present,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Provider {
    EventFile,
    MappedImageFile,
}
impl Provider {
    pub fn for_handle(handle: HandleState) -> Self {
        match handle {
            HandleState::Present => Self::EventFile,
            HandleState::Null | HandleState::Invalid => Self::MappedImageFile,
        }
    }
}
#[derive(Default, Debug, Serialize)]
pub struct MappedEvidence {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<PathEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<PathEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_nt: Option<PathEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_dos: Option<PathEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opened_nt: Option<PathEvidence>,
    pub root_matches: Option<bool>,
    pub opened_matches: Option<bool>,
    pub requery_matches: Option<bool>,
    pub canonical_system_matches: Option<bool>,
    pub selected: bool,
}
impl Candidate {
    pub fn new(event: (usize, u32, u32, u64), handle: HandleState, active: bool) -> Self {
        Self {
            event,
            handle,
            provider: None,
            mapped: None,
            stage: if !active {
                Stage::Inactive
            } else if handle != HandleState::Present {
                Stage::MissingHandle
            } else {
                Stage::FileMetadata
            },
            length: None,
            final_path: None,
            system_directory: None,
            parent_matches: None,
            basename_matches: None,
            parent_raw_error: None,
            basename_raw_error: None,
            site_rva: None,
            raw_error: None,
            error: None,
            deadline: false,
            paths_omitted_for_record_bound: false,
            extended_dos_prefix_stripped: false,
        }
    }
    pub fn length_matches(&mut self, observed: u64, expected: u64) -> bool {
        self.length = Some(observed);
        if observed != expected {
            self.stage = Stage::LengthMismatch;
            return false;
        }
        self.stage = Stage::FinalPath;
        true
    }
    pub fn final_path(&mut self, units: &[u16]) {
        self.final_path = Some(PathEvidence::new(units));
        self.stage = Stage::SystemDirectory;
    }
    pub fn system_directory(&mut self, units: &[u16]) {
        self.system_directory = Some(PathEvidence::new(units));
    }
    pub fn predicates(&mut self, separator: bool, parent: bool, basename: bool) -> bool {
        if !separator {
            self.stage = Stage::MissingSeparator;
            return false;
        }
        self.parent_matches = Some(parent);
        self.basename_matches = Some(basename);
        self.stage = if !parent {
            Stage::ParentMismatch
        } else if !basename {
            Stage::BasenameMismatch
        } else {
            Stage::FileIdentityBefore
        };
        parent && basename
    }
    pub fn failed(&mut self, error: &io::Error) {
        self.raw_error = error.raw_os_error();
        self.deadline = error.kind() == io::ErrorKind::TimedOut;
        self.error = Some(error.to_string().chars().take(256).collect());
    }
    pub fn selected_result(&self, accepted: bool) -> io::Result<bool> {
        if !accepted
            && self
                .mapped
                .as_ref()
                .is_some_and(|evidence| evidence.selected)
        {
            return Err(io::Error::other(
                "selected mapped host failed existing candidate predicates",
            ));
        }
        Ok(accepted)
    }
}

#[derive(Default, Serialize)]
pub struct Candidates {
    pub events: Vec<Candidate>,
    pub omitted_for_record_bound: usize,
}
impl Candidates {
    pub fn push(&mut self, value: Candidate) -> io::Result<()> {
        if self.events.len() >= 256 {
            self.omitted_for_record_bound += 1;
            return Err(io::Error::other("loader candidate event bound"));
        }
        self.events.push(value);
        // Preserve one outcome per event even when paths exhaust the evidence budget.
        // This is a separate <=64KiB physical record including its terminal newline.
        if serde_json::to_vec(self).map_err(io::Error::other)?.len() >= 60000 {
            for event in self.events.iter_mut().rev() {
                for path in [&mut event.final_path, &mut event.system_directory]
                    .into_iter()
                    .flatten()
                {
                    path.units.clear();
                    path.truncated = path.total_units != 0;
                    event.paths_omitted_for_record_bound = true;
                }
                if let Some(mapped) = &mut event.mapped {
                    for path in [
                        &mut mapped.before,
                        &mut mapped.after,
                        &mut mapped.root_nt,
                        &mut mapped.root_dos,
                        &mut mapped.opened_nt,
                    ]
                    .into_iter()
                    .flatten()
                    {
                        path.units.clear();
                        path.truncated = path.total_units != 0;
                        event.paths_omitted_for_record_bound = true;
                    }
                }
            }
        }
        if serde_json::to_vec(self).map_err(io::Error::other)?.len() >= 65536 {
            self.events.pop();
            self.omitted_for_record_bound += 1;
            return Err(io::Error::other("loader candidate record bound"));
        }
        Ok(())
    }
    pub fn retain<T>(&mut self, value: Candidate, outcome: io::Result<T>) -> io::Result<T> {
        let retention = self.push(value);
        // Native/ownership failure is authoritative even if evidence also overflowed.
        outcome.and_then(|value| retention.map(|()| value))
    }
    pub fn classification(&self) -> &'static str {
        if self.omitted_for_record_bound != 0 {
            return "candidate-evidence-limit";
        }
        if self
            .events
            .iter()
            .any(|event| event.stage == Stage::Accepted)
        {
            "accepted-candidate"
        } else if self.events.iter().any(|event| event.error.is_some()) {
            "candidate-validation-unavailable"
        } else if self
            .events
            .iter()
            .any(|event| event.parent_matches.is_some() || event.stage == Stage::MissingSeparator)
        {
            "path-candidates-rejected"
        } else if self.events.iter().any(|event| event.length.is_some()) {
            "no-length-match"
        } else {
            "no-usable-event-file"
        }
    }
    pub fn summary(&self) -> serde_json::Value {
        let mut counts = std::collections::BTreeMap::new();
        for event in &self.events {
            let stage = serde_json::to_value(event.stage).expect("closed stage serializes");
            *counts
                .entry(stage.as_str().expect("stage string").to_owned())
                .or_insert(0usize) += 1;
        }
        serde_json::json!({"classification":self.classification(),"events":self.events.len(),"stages":counts,"event_fields":["debug_event_ordinal","pid","tid","module_base"],"omitted_for_record_bound":self.omitted_for_record_bound})
    }
}
