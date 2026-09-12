use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

use crate::{
    BoundaryMechanismEvidence, BoundaryRequirement, CleanupSummary, RestartSafetyProof,
    WindowsTerminalReceiptV1,
};

pub const PROVIDER_REJECTION_MAX_DETAIL_BYTES: usize = 8 * 1024;

/// Observations from native helper startup, separate from the primary error and
/// from the authority required to authorize or retire a workload. This optional
/// V1 extension appears only on failed envelopes; strict older consumers may
/// reject its presence, while absent fields retain the existing wire shape.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "NativeStartupDiagnosticWireV1")]
pub struct NativeStartupDiagnosticV1 {
    pub schema_version: u32,
    pub requested_helper: crate::NativeArgument,
    pub canonical_helper: Option<crate::NativeArgument>,
    pub helper_identity: Option<NativeHelperIdentityV1>,
    pub cwd: Option<crate::NativeArgument>,
    pub phase: NativeStartupPhaseV1,
    pub operation: NativeStartupOperationV1,
    pub native_errno: Option<i32>,
    pub guardian_pid: Option<u32>,
    pub guardian_ready: bool,
    pub launcher_pid: Option<u32>,
    pub release_sent: bool,
    pub exec_confirmed: bool,
    pub cleanup: NativeStartupCleanupV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeHelperIdentityV1 {
    pub device: u64,
    pub inode: u64,
    pub size_bytes: u64,
    pub sha256: Option<crate::DiagnosticSha256>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeStartupPhaseV1 {
    HelperResolution,
    HelperValidation,
    GuardianSpawn,
    GuardianReadiness,
    LauncherSpawn,
    LauncherReadiness,
    WorkloadBinding,
    TargetRelease,
    TargetExec,
    Cleanup,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeStartupOperationV1 {
    ResolveHelper,
    InspectHelper,
    InspectWorkingDirectory,
    SpawnGuardian,
    ReadGuardianReadiness,
    SpawnLauncher,
    ReadLauncherReadiness,
    BindWorkload,
    ReleaseTarget,
    ConfirmTargetExec,
    ProtocolValidation,
    TerminateLauncher,
    ReapLauncher,
    TerminateGuardian,
    ReapGuardian,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeStartupCleanupStateV1 {
    Complete,
    Incomplete,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeStartupCleanupV1 {
    pub state: NativeStartupCleanupStateV1,
    pub errors: Vec<NativeStartupCleanupErrorV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeStartupCleanupErrorV1 {
    pub operation: NativeStartupOperationV1,
    pub native_errno: Option<i32>,
    pub detail: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeStartupDiagnosticWireV1 {
    schema_version: u32,
    requested_helper: NativeStartupPathWireV1,
    canonical_helper: Option<NativeStartupPathWireV1>,
    helper_identity: Option<NativeHelperIdentityV1>,
    cwd: Option<NativeStartupPathWireV1>,
    phase: NativeStartupPhaseV1,
    operation: NativeStartupOperationV1,
    native_errno: Option<i32>,
    guardian_pid: Option<u32>,
    guardian_ready: bool,
    launcher_pid: Option<u32>,
    release_sent: bool,
    exec_confirmed: bool,
    cleanup: NativeStartupCleanupV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeStartupPathWireV1 {
    display: String,
    raw: Option<NativeStartupPathRawWireV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeStartupPathRawWireV1 {
    encoding: String,
    data: String,
}

impl From<NativeStartupPathWireV1> for crate::NativeArgument {
    fn from(value: NativeStartupPathWireV1) -> Self {
        Self {
            display: value.display,
            raw: value.raw.map(|raw| crate::NativeArgumentRaw {
                encoding: raw.encoding,
                data: raw.data,
            }),
        }
    }
}

impl TryFrom<NativeStartupDiagnosticWireV1> for NativeStartupDiagnosticV1 {
    type Error = &'static str;

    fn try_from(value: NativeStartupDiagnosticWireV1) -> Result<Self, Self::Error> {
        let diagnostic = Self {
            schema_version: value.schema_version,
            requested_helper: value.requested_helper.into(),
            canonical_helper: value.canonical_helper.map(Into::into),
            helper_identity: value.helper_identity,
            cwd: value.cwd.map(Into::into),
            phase: value.phase,
            operation: value.operation,
            native_errno: value.native_errno,
            guardian_pid: value.guardian_pid,
            guardian_ready: value.guardian_ready,
            launcher_pid: value.launcher_pid,
            release_sent: value.release_sent,
            exec_confirmed: value.exec_confirmed,
            cleanup: value.cleanup,
        };
        if !diagnostic.is_consistent() {
            return Err("native startup diagnostic is inconsistent");
        }
        Ok(diagnostic)
    }
}

impl NativeStartupDiagnosticV1 {
    pub fn matches_error_observations(
        &self,
        target_released: bool,
        workload_may_be_alive: bool,
        os_code: Option<i32>,
    ) -> bool {
        self.is_consistent()
            && self.release_sent == target_released
            && (self.cleanup.state != NativeStartupCleanupStateV1::Complete
                || !workload_may_be_alive)
            && match (self.native_errno, os_code) {
                (Some(observed), Some(primary)) => observed == primary,
                _ => true,
            }
    }

    pub fn is_consistent(&self) -> bool {
        self.schema_version == 1
            && native_startup_path_is_consistent(&self.requested_helper)
            && self
                .canonical_helper
                .as_ref()
                .is_none_or(native_startup_path_is_consistent)
            && self
                .cwd
                .as_ref()
                .is_none_or(native_startup_path_is_consistent)
            && (self.helper_identity.is_none() || self.canonical_helper.is_some())
            && self.native_errno.is_none_or(|code| code > 0)
            && self.guardian_pid.is_none_or(|pid| pid != 0)
            && self.launcher_pid.is_none_or(|pid| pid != 0)
            && (!self.guardian_ready || self.guardian_pid.is_some())
            && (self.launcher_pid.is_none() || self.guardian_ready)
            && (!self.release_sent || (self.guardian_ready && self.launcher_pid.is_some()))
            && (!self.exec_confirmed || self.release_sent)
            && self.cleanup.errors.len() <= 16
            && self.cleanup.errors.iter().all(|error| {
                error.native_errno.is_none_or(|code| code > 0)
                    && !error.detail.is_empty()
                    && error.detail.len() <= 1024
                    && !error.detail.contains('\0')
            })
    }
}

fn native_startup_path_is_consistent(path: &crate::NativeArgument) -> bool {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    const MAX_PATH_BYTES: usize = 64 * 1024;
    if path.display.is_empty() || path.display.len() > MAX_PATH_BYTES || path.display.contains('\0')
    {
        return false;
    }
    let Some(raw) = &path.raw else {
        return true;
    };
    if raw.data.len() > MAX_PATH_BYTES * 2 {
        return false;
    }
    let Ok(bytes) = STANDARD.decode(&raw.data) else {
        return false;
    };
    if bytes.is_empty() || bytes.len() > MAX_PATH_BYTES || STANDARD.encode(&bytes) != raw.data {
        return false;
    }
    match raw.encoding.as_str() {
        "unix-bytes-base64" => {
            !bytes.contains(&0) && String::from_utf8_lossy(&bytes) == path.display
        }
        "windows-u16le-base64" => {
            let mut chunks = bytes.chunks_exact(std::mem::size_of::<u16>());
            let words: Vec<_> = chunks
                .by_ref()
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            chunks.remainder().is_empty()
                && !words.contains(&0)
                && String::from_utf16_lossy(&words) == path.display
        }
        _ => false,
    }
}

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_admission: Option<crate::workload_evidence::WorkloadAdmissionRejectionV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_failure: Option<crate::ProviderFailureDiagnosticV1>,
    pub schema_version: u32,
    pub code: String,
    pub phase: BoundarySetupPhase,
    pub detail: String,
    pub os_code: Option<i32>,
    /// Typed Windows loader qualification evidence when target creation failed
    /// in the production loader-control probe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loader_qualification: Option<crate::WindowsLoaderQualificationOutcomeV2>,
    pub target_created: bool,
    pub target_released: bool,
    pub cleanup_attempted: bool,
    pub restart_safety: RestartSafetyProof,
    /// The provider durably retained this exact rejection until the caller
    /// acknowledges it. This is independent of `terminal_receipt`: a launch
    /// can fail after its streams became visible but before a target exists.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub terminal_ack_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_receipt: Option<Box<WindowsTerminalReceiptV1>>,
}

impl ProviderRejectionEvidence {
    pub fn is_consistent(&self) -> bool {
        const MAX_CODE_BYTES: usize = 128;
        const MAX_CLEANUP_ERRORS: usize = 16;
        const MAX_CLEANUP_ERROR_BYTES: usize = 1024;
        self.schema_version == 1
            && self.workload_admission.as_ref().is_none_or(|admission| {
                !self.target_released
                    && admission.request.authorization.approved_plan_digest
                        == admission.request.workload_plan_digest
            })
            && self.provider_failure.as_ref().is_none_or(|projection| {
                projection.is_consistent()
                    && projection.canonical_digest() == projection.projection_sha256
            })
            && !self.code.is_empty()
            && self.code.len() <= MAX_CODE_BYTES
            && self
                .code
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
            && !self.detail.is_empty()
            && self.detail.len() <= PROVIDER_REJECTION_MAX_DETAIL_BYTES
            && !self.detail.contains('\0')
            && self
                .loader_qualification
                .as_ref()
                .is_none_or(crate::WindowsLoaderQualificationOutcomeV2::is_consistent)
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
            && (!self.terminal_ack_required
                || (self.cleanup_attempted
                    && self.restart_safety.is_safe_for(BoundaryRequirement::Sealed)))
            && self.terminal_receipt.as_ref().is_none_or(|terminal| {
                let target_release_matches = matches!(
                    &terminal.boundary_detail,
                    BoundaryMechanismEvidence::WindowsJobObjectV2(native)
                        if native.target_released == self.target_released
                );
                self.terminal_ack_required
                    && self.target_created
                    && target_release_matches
                    && self.cleanup_attempted
                    && terminal.schema_version == 1
                    && terminal.restart_safety == self.restart_safety
                    && terminal.process_identity_inventory_shape_is_bounded()
            })
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
    pub native_startup: Option<NativeStartupDiagnosticV1>,
    pub policy_enforcement: Option<crate::workload_evidence::AttemptPolicyEnforcementV1>,
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
    pub provider_failure: Option<crate::ProviderFailureDiagnosticV1>,
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
            provider_failure: None,
            policy_enforcement: None,
            native_startup: None,
        }
    }

    pub fn with_os_error(mut self, error: &std::io::Error) -> Self {
        self.os_code = error.raw_os_error();
        self
    }

    /// The caller must establish the provider transport and exact attempt binding first.
    pub fn with_provider_failure(
        mut self,
        failure: crate::ValidatedProviderFailureDiagnosticV1,
    ) -> Self {
        self.provider_failure = Some(failure.into_projection());
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
        if let Some(admission) = rejection
            .workload_admission
            .as_ref()
            .filter(|_| rejection.is_consistent())
        {
            self.policy_enforcement = Some(
                crate::workload_evidence::AttemptPolicyEnforcementV1::NotAuthorized {
                    request: admission.request.clone(),
                    rejection: admission.rejection.clone(),
                },
            );
        }
        self.os_code = rejection.os_code;
        self.target_released = rejection.target_released;
        self.restart_safety = Some(rejection.restart_safety.clone());
        self.provider_rejection = Some(rejection);
        self
    }
}
