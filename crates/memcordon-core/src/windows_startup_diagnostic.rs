//! Bounded, non-authoritative observations of a failed launcher startup.
//! These records never establish attempt, admission, or retirement authority.

use serde::{Deserialize, Serialize};

use crate::{PublicProviderBindingV1, WindowsProcessIdentityV1};

pub const WINDOWS_LAUNCHER_STARTUP_DIAGNOSTIC_BYTES: usize = 4096;
pub const WINDOWS_LAUNCHER_STARTUP_DIAGNOSTIC_MAX_AGE_MILLIS: u64 = 180_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsLauncherStartupStageV1 {
    ProcessProtection,
    TokenPolicy,
    GuardianSlots,
    WriterQuarantine,
    StagedAck,
    GuardianDirectory,
    ReaderAdmission,
    WriterAdmission,
    OwnedAdmission,
    RecordRead,
    RecordAuthentication,
    PendingOutbox,
    GuardianReceiptBinding,
    UnresolvedContract,
    NativeOwnerClosure,
    FinalAmbiguity,
    PipePreparation,
    RunningAnnouncement,
    ServiceLoop,
}

impl WindowsLauncherStartupStageV1 {
    fn accepts_service_exit(self, code: u32) -> bool {
        match self {
            Self::ProcessProtection => code == 0x4d43_0201,
            Self::TokenPolicy => (0x4d43_0210..=0x4d43_0214).contains(&code),
            Self::PipePreparation => matches!(code, 0x4d43_0203 | 0x4d43_0206 | 0x4d43_0207),
            Self::RunningAnnouncement => code == 0x4d43_0204,
            Self::ServiceLoop => code == 0x4d43_0205,
            _ => code == 0x4d43_0202,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsLauncherStartupReasonV1 {
    OperationFailed,
    RetainedAmbiguity,
    InvalidRecord,
    UnknownGuardianChild,
    UnjoinedAdmission,
    LiveReader,
    UnconfirmedWriter,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsLauncherStartupDiagnosticV1 {
    pub schema_version: u32,
    pub provider: PublicProviderBindingV1,
    pub startup_process: WindowsProcessIdentityV1,
    pub boot_identity: String,
    pub recorded_tick_millis: u64,
    pub service_exit: u32,
    pub stage: WindowsLauncherStartupStageV1,
    pub reason: WindowsLauncherStartupReasonV1,
    pub native_code: Option<u32>,
}

impl WindowsLauncherStartupDiagnosticV1 {
    /// Reject an otherwise fresh observation from before this authenticated episode.
    pub fn validate_since(&self, minimum_tick_millis: u64) -> Result<(), &'static str> {
        self.validate_structure()?;
        if self.recorded_tick_millis < minimum_tick_millis {
            return Err("startup_diagnostic.predates_authenticated_episode");
        }
        Ok(())
    }

    fn validate_structure(&self) -> Result<(), &'static str> {
        if self.schema_version != 1
            || !self.provider.is_consistent()
            || self.startup_process.process_id == 0
            || self.startup_process.creation_time_100ns == 0
            || self
                .boot_identity
                .parse::<i64>()
                .ok()
                .filter(|value| *value > 0)
                .is_none_or(|value| value.to_string() != self.boot_identity)
            || !self.stage.accepts_service_exit(self.service_exit)
        {
            return Err("startup_diagnostic.invalid_binding_or_stage");
        }
        Ok(())
    }

    /// Validate only diagnostic relevance. Success grants no operational authority.
    pub fn validate_for(
        &self,
        provider: &PublicProviderBindingV1,
        boot_identity: &str,
        now_tick_millis: u64,
        scm_service_exit: u32,
        expected_process: Option<&WindowsProcessIdentityV1>,
    ) -> Result<(), &'static str> {
        self.validate_structure()?;
        if &self.provider != provider
            || self.boot_identity != boot_identity
            || self.service_exit != scm_service_exit
            || expected_process.is_some_and(|expected| expected != &self.startup_process)
            || now_tick_millis
                .checked_sub(self.recorded_tick_millis)
                .is_none_or(|age| age > WINDOWS_LAUNCHER_STARTUP_DIAGNOSTIC_MAX_AGE_MILLIS)
        {
            return Err("startup_diagnostic.stale_or_unjoined");
        }
        Ok(())
    }

    pub fn from_json_for(
        bytes: &[u8],
        provider: &PublicProviderBindingV1,
        boot_identity: &str,
        now_tick_millis: u64,
        scm_service_exit: u32,
        expected_process: Option<&WindowsProcessIdentityV1>,
    ) -> Result<Self, &'static str> {
        if bytes.len() > WINDOWS_LAUNCHER_STARTUP_DIAGNOSTIC_BYTES {
            return Err("startup_diagnostic.byte_bound");
        }
        let report: Self =
            serde_json::from_slice(bytes).map_err(|_| "startup_diagnostic.invalid_json")?;
        report.validate_for(
            provider,
            boot_identity,
            now_tick_millis,
            scm_service_exit,
            expected_process,
        )?;
        Ok(report)
    }

    pub fn to_bounded_json(&self) -> Result<Vec<u8>, &'static str> {
        self.validate_structure()?;
        let bytes = serde_json::to_vec(self).map_err(|_| "startup_diagnostic.serialization")?;
        if bytes.len() > WINDOWS_LAUNCHER_STARTUP_DIAGNOSTIC_BYTES {
            return Err("startup_diagnostic.byte_bound");
        }
        Ok(bytes)
    }
}
