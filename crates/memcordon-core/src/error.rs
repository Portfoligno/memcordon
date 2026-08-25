use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

use crate::{BoundaryRequirement, CleanupSummary, RestartSafetyProof};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BoundarySetupPhase {
    RequestValidation,
    ProviderConnection,
    ProviderIdentity,
    CallerEnvelopeCapture,
    LauncherServiceAuthentication,
    CallerMountNamespaceAdoption,
    CallerCapabilityEnvelope,
    CredentialTransitionPolicy,
    BoundaryCreation,
    GuardianStartup,
    TargetCreation,
    AssignmentVerification,
    ResourceVerification,
    Authorization,
    Monitoring,
    Retirement,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BoundarySetupFailure {
    pub requested: BoundaryRequirement,
    pub mechanism: Option<String>,
    pub phase: BoundarySetupPhase,
    pub target_created: bool,
    pub target_released: bool,
    pub cleanup_attempted: bool,
    pub restart_safety: RestartSafetyProof,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderRejectionEvidence {
    pub schema_version: u32,
    pub code: String,
    pub phase: BoundarySetupPhase,
    pub detail: String,
    pub os_code: Option<i32>,
    pub target_created: bool,
    pub target_released: bool,
    pub cleanup_attempted: bool,
    pub restart_safety: RestartSafetyProof,
}

impl ProviderRejectionEvidence {
    pub(crate) fn is_consistent(&self) -> bool {
        const MAX_CODE_BYTES: usize = 128;
        const MAX_DETAIL_BYTES: usize = 8 * 1024;
        const MAX_CLEANUP_ERRORS: usize = 16;
        const MAX_CLEANUP_ERROR_BYTES: usize = 1024;
        self.schema_version == 1
            && !self.code.is_empty()
            && self.code.len() <= MAX_CODE_BYTES
            && self
                .code
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
            && !self.detail.is_empty()
            && self.detail.len() <= MAX_DETAIL_BYTES
            && !self.detail.contains('\0')
            && (!self.target_released || self.target_created)
            && self.restart_safety.errors.len() <= MAX_CLEANUP_ERRORS
            && self
                .restart_safety
                .errors
                .iter()
                .all(|error| error.len() <= MAX_CLEANUP_ERROR_BYTES && !error.contains('\0'))
            && (self.cleanup_attempted || self.restart_safety == RestartSafetyProof::default())
            && (!self.restart_safety.sealed_boundary_retired
                || self.restart_safety.is_safe_for(BoundaryRequirement::Sealed))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InitialSpawnFailure {
    NotFound,
    NotExecutable,
}

impl InitialSpawnFailure {
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::NotFound => 127,
            Self::NotExecutable => 126,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorCategory {
    Usage,
    Unsupported,
    Setup,
    Spawn,
    Monitor,
    Wait,
    Termination,
    Cleanup,
    Report,
}

#[derive(Clone, Debug, Error)]
#[error("{message} ({code})")]
pub struct Error {
    pub category: ErrorCategory,
    pub code: &'static str,
    pub message: String,
    pub backend: Option<String>,
    pub os_code: Option<i32>,
    pub target_pid: Option<u32>,
    pub launch_phase: Option<&'static str>,
    pub target_released: bool,
    pub authorization_offset: Option<Duration>,
    pub cgroup_verified_before_release: bool,
    pub guardian_ready_before_release: bool,
    pub workload_may_be_alive: bool,
    pub cleanup: CleanupSummary,
    pub restart_safety: Option<RestartSafetyProof>,
    pub initial_spawn_failure: Option<InitialSpawnFailure>,
    pub boundary_setup_failure: Option<BoundarySetupFailure>,
    pub provider_rejection: Option<ProviderRejectionEvidence>,
}

impl Error {
    pub fn new(category: ErrorCategory, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            category,
            code,
            message: message.into(),
            backend: None,
            os_code: None,
            target_pid: None,
            launch_phase: None,
            target_released: false,
            authorization_offset: None,
            cgroup_verified_before_release: false,
            guardian_ready_before_release: false,
            workload_may_be_alive: false,
            cleanup: CleanupSummary::default(),
            restart_safety: None,
            initial_spawn_failure: None,
            boundary_setup_failure: None,
            provider_rejection: None,
        }
    }

    pub fn with_os_error(mut self, error: &std::io::Error) -> Self {
        self.os_code = error.raw_os_error();
        self
    }

    pub fn with_restart_safety(mut self, restart_safety: RestartSafetyProof) -> Self {
        self.restart_safety = Some(restart_safety);
        self
    }

    pub fn with_initial_spawn_failure(mut self, failure: InitialSpawnFailure) -> Self {
        self.initial_spawn_failure = Some(failure);
        self
    }

    pub fn with_authorization_offset(mut self, authorization_offset: Duration) -> Self {
        self.target_released = true;
        self.authorization_offset = Some(authorization_offset);
        self
    }

    pub fn with_boundary_setup_failure(mut self, failure: BoundarySetupFailure) -> Self {
        self.boundary_setup_failure = Some(failure);
        self
    }

    pub fn with_provider_rejection(mut self, rejection: ProviderRejectionEvidence) -> Self {
        self.os_code = rejection.os_code;
        self.target_released = rejection.target_released;
        self.restart_safety = Some(rejection.restart_safety.clone());
        self.provider_rejection = Some(rejection);
        self
    }
}
