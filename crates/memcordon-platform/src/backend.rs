use std::time::Duration;

use memcordon_core::{
    BoundaryCapability, BoundaryMechanismEvidence, CommandSpec, Error, ErrorCategory,
    LaunchEvidence, Policy, RestartSafetyProof, RunOutcome,
};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct BackendInfo {
    pub name: &'static str,
    pub containment_supported: bool,
    pub memory_supported: bool,
    pub class: &'static str,
    pub metric: &'static str,
    pub hard_limit: bool,
    pub startup_containment: &'static str,
    pub limitations: Vec<&'static str>,
    pub boundary_support: BoundarySupport,
}

#[derive(Clone, Debug, Serialize)]
pub struct BoundarySupport {
    pub standard: BoundaryCapability,
    pub sealed: SealedAvailability,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum SealedAvailability {
    Available {
        capability: BoundaryCapability,
        qualification: BoundaryQualification,
    },
    Unavailable {
        reason: String,
        prerequisites: Vec<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BoundaryQualification {
    pub provider_identity: String,
    pub receipt_digest: String,
    pub mechanism: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProbeReport {
    pub selected: Option<BackendInfo>,
    pub available: Vec<BackendInfo>,
    pub unavailable: Vec<UnavailableBackend>,
}

#[derive(Clone, Debug, Serialize)]
pub struct UnavailableBackend {
    pub name: &'static str,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct Execution {
    pub outcome: RunOutcome,
    pub backend: BackendInfo,
    pub child_pid: u32,
    pub duration: Duration,
    pub authorization_offset: Option<Duration>,
    pub launch: LaunchEvidence,
    pub restart_safety: RestartSafetyProof,
    pub boundary_detail: BoundaryMechanismEvidence,
}

#[derive(Clone, Debug, Default)]
pub struct BackendCleanupFacts {
    pub direct_child_reaped: bool,
    pub workload_empty: Option<bool>,
    pub helpers_reaped: bool,
    pub containment_removed: bool,
    pub containment_incapable_of_live_members: bool,
    pub errors: Vec<String>,
}

impl BackendInfo {
    pub fn supports_boundary(&self, requirement: memcordon_core::BoundaryRequirement) -> bool {
        match requirement {
            memcordon_core::BoundaryRequirement::Standard => {
                self.boundary_support.standard.class != memcordon_core::BoundaryClass::Unavailable
            }
            memcordon_core::BoundaryRequirement::Sealed => matches!(
                &self.boundary_support.sealed,
                SealedAvailability::Available { .. }
            ),
        }
    }
}

impl ProbeReport {
    pub fn selected_for(
        &self,
        requirement: memcordon_core::BoundaryRequirement,
    ) -> Option<&BackendInfo> {
        self.selected
            .as_ref()
            .filter(|backend| backend.supports_boundary(requirement))
            .or_else(|| {
                self.available
                    .iter()
                    .find(|backend| backend.supports_boundary(requirement))
            })
    }
}

pub(crate) fn standard_boundary_support(
    mechanism: &str,
    containment_supported: bool,
    sealed_reason: &str,
    prerequisites: &[&str],
) -> BoundarySupport {
    BoundarySupport {
        standard: BoundaryCapability {
            class: memcordon_core::BoundaryClass::Standard,
            mechanism: mechanism.to_owned(),
            target_gated: containment_supported,
            boundary_verified_before_authorization: containment_supported,
            target_can_reconfigure_boundary: true,
            frontend_loss_cleanup_authority: false,
            workload_empty_proof: containment_supported,
            limitations: vec!["standard supervision is not a sealed boundary".to_owned()],
        },
        sealed: SealedAvailability::Unavailable {
            reason: sealed_reason.to_owned(),
            prerequisites: prerequisites
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        },
    }
}

pub(crate) fn standard_execution_evidence(
    backend: &BackendInfo,
    facts: BackendCleanupFacts,
) -> (
    LaunchEvidence,
    RestartSafetyProof,
    BoundaryMechanismEvidence,
) {
    (
        LaunchEvidence {
            mechanism: backend.boundary_support.standard.mechanism.clone(),
            target_released: true,
            containment_verified_before_authorization: backend
                .boundary_support
                .standard
                .boundary_verified_before_authorization,
            guardian_started_before_authorization: false,
            target_spawn_error_reported: false,
            boundary_requested: memcordon_core::BoundaryRequirement::Standard,
            boundary_effective: memcordon_core::BoundaryClass::Standard,
            boundary_assignment_verified: false,
            boundary_reconfiguration_denied: false,
            inherited_resources_restricted: false,
            frontend_loss_cleanup_authority_verified: false,
        },
        RestartSafetyProof {
            direct_child_reaped: facts.direct_child_reaped,
            workload_empty: facts.workload_empty,
            helpers_reaped: facts.helpers_reaped,
            containment_removed: facts.containment_removed,
            containment_incapable_of_live_members: facts.containment_incapable_of_live_members,
            sealed_boundary_retired: false,
            errors: facts.errors,
        },
        BoundaryMechanismEvidence::Standard {
            backend: backend.name.to_owned(),
        },
    )
}

pub fn probe() -> ProbeReport {
    #[cfg(target_os = "macos")]
    {
        let backend = crate::macos_watchdog::info();
        ProbeReport {
            selected: Some(backend.clone()),
            available: vec![backend],
            unavailable: vec![UnavailableBackend {
                name: "kernel-backed",
                reason: "macOS has no supported public aggregate workload memory controller"
                    .to_owned(),
            }],
        }
    }
    #[cfg(target_os = "linux")]
    {
        crate::linux_cgroup::probe()
    }
    #[cfg(target_os = "windows")]
    {
        crate::windows_job::probe()
    }
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
    {
        crate::unix_watchdog::probe()
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        ProbeReport {
            selected: None,
            available: Vec::new(),
            unavailable: vec![UnavailableBackend {
                name: "platform",
                reason: "this target is not supported".to_owned(),
            }],
        }
    }
}

#[cfg(target_os = "linux")]
#[allow(
    clippy::result_large_err,
    reason = "the backend boundary preserves the public categorized Error contract"
)]
pub fn run(
    policy: Policy,
    command: &CommandSpec,
    memcordon_executable: &std::path::Path,
) -> Result<Execution, Error> {
    if policy.poll_interval < Duration::from_millis(10) {
        return Err(Error::new(
            ErrorCategory::Usage,
            "MCUSAGE-POLL-INTERVAL",
            "watchdog poll interval must be at least 10ms",
        ));
    }

    let signal = crate::signal::SignalSource::install().map_err(|error| {
        Error::new(ErrorCategory::Setup, "MCSETUP-SIGNAL", error.to_string()).with_os_error(&error)
    })?;
    crate::linux_cgroup::run_attempt(
        policy,
        command,
        memcordon_executable,
        &signal,
        crate::supervisor::AttemptContext {
            supervision_offset: Duration::ZERO,
            supervision_deadline_remaining: None,
        },
    )
}

#[cfg(target_os = "macos")]
#[allow(clippy::result_large_err)]
pub fn run(
    policy: Policy,
    command: &CommandSpec,
    memcordon_executable: &std::path::Path,
) -> Result<Execution, Error> {
    if policy.poll_interval < Duration::from_millis(10) {
        return Err(Error::new(
            ErrorCategory::Usage,
            "MCUSAGE-POLL-INTERVAL",
            "watchdog poll interval must be at least 10ms",
        ));
    }
    let signal = crate::signal::SignalSource::install().map_err(|error| {
        Error::new(ErrorCategory::Setup, "MCSETUP-SIGNAL", error.to_string()).with_os_error(&error)
    })?;
    crate::macos_watchdog::run_attempt(
        policy,
        command,
        memcordon_executable,
        &signal,
        crate::supervisor::AttemptContext {
            supervision_offset: Duration::ZERO,
            supervision_deadline_remaining: None,
        },
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[allow(
    clippy::result_large_err,
    reason = "the backend boundary preserves the public categorized Error contract"
)]
pub fn run(policy: Policy, command: &CommandSpec) -> Result<Execution, Error> {
    if policy.poll_interval < Duration::from_millis(10) {
        return Err(Error::new(
            ErrorCategory::Usage,
            "MCUSAGE-POLL-INTERVAL",
            "watchdog poll interval must be at least 10ms",
        ));
    }

    #[cfg(target_os = "windows")]
    {
        let console = crate::windows_job::ConsoleControl::install().map_err(|error| {
            Error::new(ErrorCategory::Setup, "MCSETUP-CONSOLE", error.to_string())
                .with_os_error(&error)
        })?;
        let context = crate::supervisor::AttemptContext {
            supervision_offset: Duration::ZERO,
            supervision_deadline_remaining: None,
        };
        if policy.boundary() == memcordon_core::BoundaryRequirement::Sealed {
            crate::sealed::windows::run(&policy, command, &console, context)
        } else {
            crate::windows_job::run_attempt(policy, command, &console, context)
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        crate::unix_watchdog::run(policy, command)
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let _ = (policy, command);
        Err(Error::new(
            ErrorCategory::Unsupported,
            "MCUNSUPPORTED-PLATFORM",
            "this target is not supported",
        ))
    }
}

#[allow(
    clippy::result_large_err,
    reason = "the cleanup boundary preserves the public categorized Error contract"
)]
pub fn cleanup_stale(dry_run: bool) -> Result<Vec<String>, Error> {
    #[cfg(target_os = "linux")]
    {
        crate::linux_cgroup::cleanup_stale(dry_run)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = dry_run;
        Ok(Vec::new())
    }
}
