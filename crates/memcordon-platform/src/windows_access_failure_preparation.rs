//! Finite preparation failure custody for the isolated calibration only.
use serde::{Deserialize, Serialize};
use std::io;

pub const RECORD_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PreparationOperation {
    #[default]
    CutoffInitial,
    OpenCurrentThreadToken,
    ValidateNoThreadToken,
    CutoffBeforeOwnedFile,
    CreateOwnedFile,
    WriteOwnedFile,
    ConvertOwnedDacl,
    ExtractOwnedDacl,
    ValidateOwnedDacl,
    ApplyOwnedDacl,
    CutoffAfterOwnedDacl,
    RewindOwnedFile,
    ReadOwnedFile,
    QueryOwnedNativeName,
    ValidateOwnedNativeName,
    OpenSourceToken,
    CreateRestrictedCodeSid,
    DeriveRestrictedToken,
    QueryRestrictedSids,
    ValidateRestrictedSidsExtent,
    ValidateRestrictedSidCount,
    ValidateRestrictedSidPointer,
    ValidateRestrictedSidExtent,
    CompareRestrictedSid,
    ValidateTokenRestricted,
    CutoffFinal,
}
impl PreparationOperation {
    fn kind(self) -> FailureKind {
        match self {
            Self::CutoffInitial
            | Self::CutoffBeforeOwnedFile
            | Self::CutoffAfterOwnedDacl
            | Self::CutoffFinal => FailureKind::Cutoff,
            Self::ValidateNoThreadToken
            | Self::ValidateOwnedDacl
            | Self::ValidateOwnedNativeName
            | Self::ValidateRestrictedSidsExtent
            | Self::ValidateRestrictedSidCount
            | Self::ValidateRestrictedSidPointer
            | Self::ValidateRestrictedSidExtent
            | Self::CompareRestrictedSid
            | Self::ValidateTokenRestricted => FailureKind::Semantic,
            _ => FailureKind::Native,
        }
    }
    fn preceding_milestones(self) -> usize {
        match self {
            Self::CutoffInitial
            | Self::OpenCurrentThreadToken
            | Self::ValidateNoThreadToken
            | Self::CutoffBeforeOwnedFile
            | Self::CreateOwnedFile => 0,
            Self::WriteOwnedFile => 1,
            Self::ConvertOwnedDacl
            | Self::ExtractOwnedDacl
            | Self::ValidateOwnedDacl
            | Self::ApplyOwnedDacl => 2,
            Self::CutoffAfterOwnedDacl | Self::RewindOwnedFile | Self::ReadOwnedFile => 3,
            Self::QueryOwnedNativeName | Self::ValidateOwnedNativeName => 4,
            Self::OpenSourceToken => 5,
            Self::CreateRestrictedCodeSid | Self::DeriveRestrictedToken => 6,
            Self::QueryRestrictedSids
            | Self::ValidateRestrictedSidsExtent
            | Self::ValidateRestrictedSidCount
            | Self::ValidateRestrictedSidPointer
            | Self::ValidateRestrictedSidExtent
            | Self::CompareRestrictedSid
            | Self::ValidateTokenRestricted => 7,
            Self::CutoffFinal => 8,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FailureKind {
    Native,
    Cutoff,
    Semantic,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Milestones {
    pub file_created: bool,
    pub fixed_bytes_written: bool,
    pub dacl_applied: bool,
    pub ordinary_held_read_completed: bool,
    pub native_name_observed: bool,
    pub source_token_opened: bool,
    pub restricted_token_created: bool,
    pub restricted_profile_validated: bool,
}
impl Milestones {
    fn values(self) -> [bool; 8] {
        [
            self.file_created,
            self.fixed_bytes_written,
            self.dacl_applied,
            self.ordinary_held_read_completed,
            self.native_name_observed,
            self.source_token_opened,
            self.restricted_token_created,
            self.restricted_profile_validated,
        ]
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Configured Win32/SetSecurityInfo caller values, never an observed kernel access mask.
pub struct RequestFacts {
    pub owner_file_desired_access: u32,
    pub owner_file_share: u32,
    pub owner_file_flags: u32,
    pub security_information: u32,
    pub source_token_access: u32,
}
impl Default for RequestFacts {
    fn default() -> Self {
        Self {
            owner_file_desired_access: 0x60003,
            owner_file_share: 3,
            owner_file_flags: 0x200000,
            security_information: 0x80000004,
            source_token_access: 0xA,
        }
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub struct State {
    pub operation: PreparationOperation,
    pub progress: Milestones,
    pub request: RequestFacts,
}
impl State {
    pub fn failure(&self, primary: io::Error) -> io::Error {
        let kind = primary.kind();
        let record = Record::from_error(self, &primary);
        io::Error::new(kind, PreparationFailure { primary, record })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub operation: PreparationOperation,
    pub kind: FailureKind,
    pub native_error: Option<i32>,
    pub progress: Milestones,
    pub request: RequestFacts,
}
fn native_code(error: &io::Error) -> Option<i32> {
    let mut current: &(dyn std::error::Error + 'static) = error;
    for _ in 0..8 {
        if let Some(code) = current
            .downcast_ref::<io::Error>()
            .and_then(io::Error::raw_os_error)
        {
            return Some(code);
        }
        current = current.source()?;
    }
    None
}
impl Record {
    pub fn from_error(state: &State, error: &io::Error) -> Self {
        Self {
            operation: state.operation,
            kind: state.operation.kind(),
            native_error: native_code(error),
            progress: state.progress,
            request: state.request,
        }
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.kind != self.operation.kind() || self.request != RequestFacts::default() {
            return Err("calibration preparation operation/request facts contradict schema".into());
        }
        let completed = self.operation.preceding_milestones();
        if self
            .progress
            .values()
            .iter()
            .enumerate()
            .any(|(index, done)| *done != (index < completed))
        {
            return Err("calibration preparation milestones contradict terminal operation".into());
        }
        if self.native_error == Some(0)
            || (self.kind != FailureKind::Native && self.native_error.is_some())
            || (self.operation == PreparationOperation::OpenCurrentThreadToken
                && self.native_error == Some(1008))
        {
            return Err("calibration preparation native status contradicts operation".into());
        }
        if serde_json::to_vec(self)
            .map_err(|error| error.to_string())?
            .len()
            > RECORD_BYTES
        {
            return Err("calibration preparation record exceeds finite bound".into());
        }
        Ok(())
    }
}
#[derive(Debug)]
pub struct PreparationFailure {
    pub primary: io::Error,
    pub record: Record,
}
impl std::fmt::Display for PreparationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}; calibration preparation operation={:?}; failure-kind={:?}; native-error={:?}",
            self.primary, self.record.operation, self.record.kind, self.record.native_error
        )
    }
}
impl std::error::Error for PreparationFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
