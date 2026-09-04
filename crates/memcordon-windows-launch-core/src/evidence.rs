use crate::HandshakeOutcomeV1;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_FAILURE_DETAIL_BYTES: usize = 512;
pub const MAX_DIAGNOSTIC_ID_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsLoaderQualificationStageV2 {
    PlanValidation,
    DesktopPreflight,
    ProcessCreate,
    SuspendedAttestation,
    Resume,
    LoaderReadyHandshake,
    ContainmentReadback,
    ExitDrain,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeStatusV1 {
    Win32 { code: u32 },
    NtStatus { code: u32 },
    TargetExit { code: u32 },
    Stable { code: String },
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum NativeStatusWireV1 {
    Win32 { code: u32 },
    NtStatus { code: u32 },
    TargetExit { code: u32 },
    Stable { code: String },
}

impl<'de> Deserialize<'de> for NativeStatusV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match NativeStatusWireV1::deserialize(deserializer)? {
            NativeStatusWireV1::Win32 { code } => Ok(Self::Win32 { code }),
            NativeStatusWireV1::NtStatus { code } => Ok(Self::NtStatus { code }),
            NativeStatusWireV1::TargetExit { code } => Ok(Self::TargetExit { code }),
            NativeStatusWireV1::Stable { code }
                if !code.is_empty() && code.len() <= MAX_DIAGNOSTIC_ID_BYTES =>
            {
                Ok(Self::Stable { code })
            }
            NativeStatusWireV1::Stable { .. } => {
                Err(serde::de::Error::custom("invalid native stable code"))
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CleanupStatusV1 {
    NotStarted,
    Complete,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CleanupOutcomeV1 {
    status: CleanupStatusV1,
    stable_code: Option<String>,
}

impl CleanupOutcomeV1 {
    #[must_use]
    pub const fn not_started() -> Self {
        Self {
            status: CleanupStatusV1::NotStarted,
            stable_code: None,
        }
    }

    #[must_use]
    pub const fn complete() -> Self {
        Self {
            status: CleanupStatusV1::Complete,
            stable_code: None,
        }
    }

    #[must_use]
    pub fn failed(stable_code: impl Into<String>) -> Self {
        Self {
            status: CleanupStatusV1::Failed,
            stable_code: Some(bound_utf8(stable_code.into(), MAX_FAILURE_DETAIL_BYTES)),
        }
    }

    #[must_use]
    pub const fn status(&self) -> CleanupStatusV1 {
        self.status
    }

    #[must_use]
    pub fn stable_code(&self) -> Option<&str> {
        self.stable_code.as_deref()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CleanupOutcomeWireV1 {
    status: CleanupStatusV1,
    stable_code: Option<String>,
}

impl<'de> Deserialize<'de> for CleanupOutcomeV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = CleanupOutcomeWireV1::deserialize(deserializer)?;
        match (&wire.status, &wire.stable_code) {
            (CleanupStatusV1::Failed, Some(code))
                if !code.is_empty() && code.len() <= MAX_FAILURE_DETAIL_BYTES => {}
            (CleanupStatusV1::NotStarted | CleanupStatusV1::Complete, None) => {}
            _ => return Err(serde::de::Error::custom("invalid cleanup outcome")),
        }
        Ok(Self {
            status: wire.status,
            stable_code: wire.stable_code,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LoaderReadyEvidenceV1 {
    schema_version: u32,
    launch_plan_sha256: String,
    elapsed_millis: u64,
    handshake: HandshakeOutcomeV1,
}

impl LoaderReadyEvidenceV1 {
    #[must_use]
    pub fn authenticated(plan: &crate::ProductionLoaderPlanV1, elapsed_millis: u64) -> Self {
        Self {
            schema_version: 1,
            launch_plan_sha256: String::from(plan.launch_plan_sha256()),
            elapsed_millis,
            handshake: HandshakeOutcomeV1::Authenticated {
                protocol_version: crate::PRODUCTION_LOADER_READY_SCHEMA_VERSION,
            },
        }
    }

    #[must_use]
    pub fn launch_plan_sha256(&self) -> &str {
        &self.launch_plan_sha256
    }

    #[must_use]
    pub const fn elapsed_millis(&self) -> u64 {
        self.elapsed_millis
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoaderReadyEvidenceWireV1 {
    schema_version: u32,
    launch_plan_sha256: String,
    elapsed_millis: u64,
    handshake: HandshakeOutcomeV1,
}

impl<'de> Deserialize<'de> for LoaderReadyEvidenceV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = LoaderReadyEvidenceWireV1::deserialize(deserializer)?;
        if wire.schema_version != 1
            || !is_digest(&wire.launch_plan_sha256)
            || wire.handshake
                != (HandshakeOutcomeV1::Authenticated {
                    protocol_version: crate::PRODUCTION_LOADER_READY_SCHEMA_VERSION,
                })
        {
            return Err(serde::de::Error::custom("invalid loader-ready evidence"));
        }
        Ok(Self {
            schema_version: wire.schema_version,
            launch_plan_sha256: wire.launch_plan_sha256,
            elapsed_millis: wire.elapsed_millis,
            handshake: wire.handshake,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsLoaderQualificationFailureV2 {
    pub schema_version: u32,
    pub stable_code: String,
    pub stage: WindowsLoaderQualificationStageV2,
    pub win32_error: Option<u32>,
    pub nt_status: Option<u32>,
    pub target_exit_code: Option<u32>,
    pub elapsed_millis: u64,
    pub launch_plan_sha256: String,
    pub qualification_id: String,
    pub cleanup: CleanupOutcomeV1,
    pub diagnostic_id: Option<String>,
    pub detail: String,
}

impl WindowsLoaderQualificationFailureV2 {
    #[must_use]
    pub fn new(
        stable_code: impl Into<String>,
        stage: WindowsLoaderQualificationStageV2,
        native_status: Option<NativeStatusV1>,
        elapsed_millis: u64,
        plan: &crate::ProductionLoaderPlanV1,
        qualification_id: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        let (win32_error, nt_status, target_exit_code) = match native_status {
            Some(NativeStatusV1::Win32 { code }) => (Some(code), None, None),
            Some(NativeStatusV1::NtStatus { code }) => (None, Some(code), None),
            Some(NativeStatusV1::TargetExit { code }) => (None, None, Some(code)),
            Some(NativeStatusV1::Stable { .. }) | None => (None, None, None),
        };
        Self {
            schema_version: 2,
            stable_code: bound_utf8(stable_code.into(), MAX_DIAGNOSTIC_ID_BYTES),
            stage,
            win32_error,
            nt_status,
            target_exit_code,
            elapsed_millis,
            launch_plan_sha256: String::from(plan.launch_plan_sha256()),
            qualification_id: bound_utf8(qualification_id.into(), MAX_DIAGNOSTIC_ID_BYTES),
            cleanup: CleanupOutcomeV1::not_started(),
            diagnostic_id: None,
            detail: bound_utf8(detail.into(), MAX_FAILURE_DETAIL_BYTES),
        }
    }

    #[must_use]
    pub fn with_cleanup(mut self, cleanup: CleanupOutcomeV1) -> Self {
        self.cleanup = cleanup;
        self
    }

    #[must_use]
    pub fn with_diagnostic_id(mut self, diagnostic_id: impl Into<String>) -> Self {
        self.diagnostic_id = Some(bound_utf8(diagnostic_id.into(), MAX_DIAGNOSTIC_ID_BYTES));
        self
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsLoaderQualificationFailureWireV2 {
    schema_version: u32,
    stable_code: String,
    stage: WindowsLoaderQualificationStageV2,
    win32_error: Option<u32>,
    nt_status: Option<u32>,
    target_exit_code: Option<u32>,
    elapsed_millis: u64,
    launch_plan_sha256: String,
    qualification_id: String,
    cleanup: CleanupOutcomeV1,
    diagnostic_id: Option<String>,
    detail: String,
}

impl<'de> Deserialize<'de> for WindowsLoaderQualificationFailureV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = WindowsLoaderQualificationFailureWireV2::deserialize(deserializer)?;
        if wire.schema_version != 2
            || wire.stable_code.is_empty()
            || wire.stable_code.len() > MAX_DIAGNOSTIC_ID_BYTES
            || wire.qualification_id.is_empty()
            || wire.qualification_id.len() > MAX_DIAGNOSTIC_ID_BYTES
            || wire.detail.len() > MAX_FAILURE_DETAIL_BYTES
            || wire
                .diagnostic_id
                .as_ref()
                .is_some_and(|value| value.len() > MAX_DIAGNOSTIC_ID_BYTES)
            || !is_digest(&wire.launch_plan_sha256)
        {
            return Err(serde::de::Error::custom(
                "invalid or unbounded loader qualification failure",
            ));
        }
        let native_fields = usize::from(wire.win32_error.is_some())
            + usize::from(wire.nt_status.is_some())
            + usize::from(wire.target_exit_code.is_some());
        if native_fields > 1 {
            return Err(serde::de::Error::custom(
                "loader failure has conflicting native status fields",
            ));
        }
        Ok(Self {
            schema_version: wire.schema_version,
            stable_code: wire.stable_code,
            stage: wire.stage,
            win32_error: wire.win32_error,
            nt_status: wire.nt_status,
            target_exit_code: wire.target_exit_code,
            elapsed_millis: wire.elapsed_millis,
            launch_plan_sha256: wire.launch_plan_sha256,
            qualification_id: wire.qualification_id,
            cleanup: wire.cleanup,
            diagnostic_id: wire.diagnostic_id,
            detail: wire.detail,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", content = "result", rename_all = "kebab-case")]
pub enum WindowsLoaderQualificationOutcomeV2 {
    Ready(LoaderReadyEvidenceV1),
    Failed(WindowsLoaderQualificationFailureV2),
}

impl WindowsLoaderQualificationOutcomeV2 {
    /// Converts the launch-core outcome into the canonical public report schema.
    #[must_use]
    pub fn to_wire(&self) -> memcordon_core::WindowsLoaderQualificationOutcomeV2 {
        match self {
            Self::Ready(ready) => memcordon_core::WindowsLoaderQualificationOutcomeV2::Ready(
                memcordon_core::WindowsLoaderReadyEvidenceV1 {
                    schema_version: 1,
                    launch_plan_sha256: ready.launch_plan_sha256().to_owned(),
                    launch_plan_json: None,
                    elapsed_millis: ready.elapsed_millis(),
                },
            ),
            Self::Failed(failure) => {
                let native_status = if let Some(code) = failure.win32_error {
                    Some(memcordon_core::WindowsLoaderNativeStatusV1::Win32 { code })
                } else if let Some(code) = failure.nt_status {
                    Some(memcordon_core::WindowsLoaderNativeStatusV1::NtStatus { code })
                } else {
                    failure.target_exit_code.map(|code| {
                        memcordon_core::WindowsLoaderNativeStatusV1::TargetExit { code }
                    })
                };
                let cleanup = memcordon_core::WindowsLoaderCleanupOutcomeV1 {
                    status: match failure.cleanup.status() {
                        CleanupStatusV1::NotStarted => {
                            memcordon_core::WindowsLoaderCleanupStatusV1::NotStarted
                        }
                        CleanupStatusV1::Complete => {
                            memcordon_core::WindowsLoaderCleanupStatusV1::Complete
                        }
                        CleanupStatusV1::Failed => {
                            memcordon_core::WindowsLoaderCleanupStatusV1::Failed
                        }
                    },
                    stable_code: failure.cleanup.stable_code().map(str::to_owned),
                };
                memcordon_core::WindowsLoaderQualificationOutcomeV2::Failed(
                    memcordon_core::WindowsLoaderQualificationFailureV2 {
                        schema_version: failure.schema_version,
                        stable_code: failure.stable_code.clone(),
                        stage: match failure.stage {
                            WindowsLoaderQualificationStageV2::PlanValidation => {
                                memcordon_core::WindowsLoaderQualificationStageV2::PlanValidation
                            }
                            WindowsLoaderQualificationStageV2::DesktopPreflight => {
                                memcordon_core::WindowsLoaderQualificationStageV2::DesktopPreflight
                            }
                            WindowsLoaderQualificationStageV2::ProcessCreate => {
                                memcordon_core::WindowsLoaderQualificationStageV2::ProcessCreate
                            }
                            WindowsLoaderQualificationStageV2::SuspendedAttestation => {
                                memcordon_core::WindowsLoaderQualificationStageV2::SuspendedAttestation
                            }
                            WindowsLoaderQualificationStageV2::Resume => {
                                memcordon_core::WindowsLoaderQualificationStageV2::Resume
                            }
                            WindowsLoaderQualificationStageV2::LoaderReadyHandshake => {
                                memcordon_core::WindowsLoaderQualificationStageV2::LoaderReadyHandshake
                            }
                            WindowsLoaderQualificationStageV2::ContainmentReadback => {
                                memcordon_core::WindowsLoaderQualificationStageV2::ContainmentReadback
                            }
                            WindowsLoaderQualificationStageV2::ExitDrain => {
                                memcordon_core::WindowsLoaderQualificationStageV2::ExitDrain
                            }
                        },
                        native_status,
                        elapsed_millis: failure.elapsed_millis,
                        launch_plan_sha256: Some(failure.launch_plan_sha256.clone()),
                        launch_plan_json: None,
                        qualification_id: failure.qualification_id.clone(),
                        cleanup,
                        diagnostic_id: failure.diagnostic_id.clone(),
                        detail: failure.detail.clone(),
                    },
                )
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeCallOutcomeV1 {
    pub completed: bool,
    pub status: Option<NativeStatusV1>,
}

fn bound_utf8(mut value: String, maximum: usize) -> String {
    if value.len() <= maximum {
        return value;
    }
    let mut boundary = maximum;
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value.truncate(boundary);
    value
}

fn is_digest(value: &str) -> bool {
    value.len() == Sha256::output_size() * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
