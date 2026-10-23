//! Native certification observations are collected from a separately measured
//! test-support installation, never from the selected production distribution.
#[cfg(windows)]
use crate::{CiError, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[cfg(windows)]
#[path = "windows_component_worker_wait.rs"]
mod worker_wait;

/// These losses leave the launcher service alive to finish the original
/// attempt's closure publication. Their terminal recovery must follow that
/// exact worker thread, not just the lost peer or frontend's exit.
pub fn launcher_settlement_before_recovery(
    fault: Option<memcordon_core::WindowsSealedFault>,
) -> bool {
    matches!(
        fault,
        Some(
            memcordon_core::WindowsSealedFault::FrontendDisconnectedAfterAuthorization
                | memcordon_core::WindowsSealedFault::FrontendKilledAfterAuthorization
                | memcordon_core::WindowsSealedFault::ControlWorkerKilledAfterAuthorization
                | memcordon_core::WindowsSealedFault::ControlServiceKilledAfterAuthorization
        )
    )
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentInput {
    pub format: String,
    pub revision: u32,
    pub run_id: String,
    pub recipe_id: String,
    pub source_commit: String,
    pub native_target: String,
    pub features: Vec<String>,
    pub selected_components: Vec<crate::windows_installed_cases::SelectedArtifact>,
    pub suite_input: PathBuf,
    pub artifact_prefix: PathBuf,
    pub original_work_deadline_unix_millis: u64,
    pub original_cleanup_deadline_unix_millis: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentAssessment {
    pub selector: serde_json::Value,
    pub behavior: std::result::Result<(), String>,
    pub collection: std::result::Result<(), String>,
    pub retirement: std::result::Result<(), String>,
    pub artifacts: Vec<crate::windows_installed_cases::SelectedArtifact>,
}

/// The guardian observer records the physical loss before the support-only
/// injection label. Both ordered observations are required for this fault.
pub fn guardian_injection_authority(
    failure: &memcordon_core::ProviderFailureDiagnosticV1,
    selected: memcordon_core::WindowsSealedFault,
    provider: &memcordon_core::PublicProviderBindingV1,
    attempt: &str,
    request: &str,
) -> bool {
    use memcordon_core::*;
    if selected != WindowsSealedFault::GuardianKilledBeforeAuthorization
        || !failure.is_consistent()
        || &failure.provider_binding != provider
        || String::from(failure.attempt_id.clone()) != attempt
        || String::from(failure.request_sha256.clone()) != request
    {
        return false;
    }
    let OriginalFailureV1::Observed { event: original } = &failure.original else {
        return false;
    };
    original.sequence == 1
        && original.origin == DiagnosticOriginV1::Launcher
        && original.category == FailureCategoryV1::Monitor
        && original.operation == FailureOperationV1::CheckGuardian
        && original.code == FailureCodeV1::GuardianLoss
        && original.native_code.is_none()
        && original.observed_phase == AttemptObservationPhaseV1::BeforeAuthorization
        && original.safe_detail == SafeDiagnosticDetailV1::NoAdditionalDetail
        && failure.secondary.as_slice().iter().any(|event| {
            event.sequence == 2
                && event.origin == DiagnosticOriginV1::Launcher
                && event.category == FailureCategoryV1::Launch
                && event.operation == FailureOperationV1::UnclassifiedProviderOperation
                && event.code == FailureCodeV1::UnexpectedProviderFailure
                && event.native_code.is_none()
                && event.observed_phase == AttemptObservationPhaseV1::BeforeAuthorization
                && event.safe_detail
                    == (SafeDiagnosticDetailV1::InjectedWindowsFault { fault: selected })
        })
}

/// Only factual, bound control loss can explain a selected transport fault.
pub fn transport_injection_authority(
    failure: &memcordon_core::ProviderFailureDiagnosticV1,
    selected: memcordon_core::WindowsSealedFault,
    provider: &memcordon_core::PublicProviderBindingV1,
    attempt: &str,
    request: &str,
) -> bool {
    use memcordon_core::*;
    if !matches!(
        selected,
        WindowsSealedFault::FrontendDisconnectedAfterAuthorization
            | WindowsSealedFault::FrontendKilledAfterAuthorization
            | WindowsSealedFault::ControlWorkerKilledAfterAuthorization
            | WindowsSealedFault::ControlServiceKilledAfterAuthorization
    ) || !failure.is_consistent()
        || &failure.provider_binding != provider
        || String::from(failure.attempt_id.clone()) != attempt
        || String::from(failure.request_sha256.clone()) != request
    {
        return false;
    }
    let OriginalFailureV1::Observed { event } = &failure.original else {
        return false;
    };
    if event.sequence == 0
        || event.origin != DiagnosticOriginV1::Launcher
        || event.category != FailureCategoryV1::Transport
        || event.code != FailureCodeV1::ControlTransport
        || event.safe_detail != (SafeDiagnosticDetailV1::InjectedWindowsFault { fault: selected })
    {
        return false;
    }
    match (event.operation, event.observed_phase) {
        (FailureOperationV1::ReadControlFrame, AttemptObservationPhaseV1::Monitoring) => matches!(
            event.native_code,
            None | Some(NativeFailureCodeV1::Win32(1..=u32::MAX))
        ),
        (FailureOperationV1::ReadControlFrame, AttemptObservationPhaseV1::Cleaning) => matches!(
            event.native_code,
            None | Some(NativeFailureCodeV1::Win32(109 | 232 | 233))
        ),
        (FailureOperationV1::DeliverResponse, AttemptObservationPhaseV1::Cleaning) => matches!(
            event.native_code,
            Some(NativeFailureCodeV1::Win32(109 | 232 | 233))
        ),
        _ => false,
    }
}

/// Consume original authenticated transport authority before terminal ACK can
/// retire its receipt. A later tombstone never substitutes for this observation.
pub fn authenticated_transport_injection_authority(
    response: &memcordon_core::WindowsProviderResponseV3,
    selected: memcordon_core::WindowsSealedFault,
    provider: &memcordon_core::PublicProviderBindingV1,
    attempt: &str,
    nonce: &str,
    request: &str,
) -> bool {
    use memcordon_core::*;
    let WindowsProviderResponseV3::Reject {
        schema_version,
        attempt_id,
        nonce: actual_nonce,
        request_sha256,
        rejection,
    } = response
    else {
        return false;
    };
    if *schema_version != WINDOWS_PUBLIC_PROTOCOL_VERSION
        || attempt_id != attempt
        || actual_nonce != nonce
        || request_sha256 != request
        || !rejection.is_consistent()
        || !rejection.provider_failure.as_ref().is_some_and(|failure| {
            transport_injection_authority(failure, selected, provider, attempt, request)
        })
    {
        return false;
    }
    let WindowsProviderRejectionDispositionV2::PostauthorizationFailure { receipt } =
        &rejection.disposition
    else {
        return false;
    };
    receipt.validate_for_attempt().is_ok()
        && receipt.attempt_id == attempt
        && receipt.nonce == nonce
        && receipt.request_sha256 == request
        && receipt.retirement_proof.provider_generation == provider.generation.as_str()
        && receipt
            .execution()
            .is_some_and(|(_, outcome, _)| matches!(outcome, RunOutcome::MonitorFailed { .. }))
}

/// These are actual native injection points, not installed-product case rows.
#[derive(Clone, Debug)]
pub struct ObservedFrontendLoss {
    selected: memcordon_core::WindowsSealedFault,
    identity: memcordon_core::WindowsProcessIdentityV1,
    native_status: u32,
}

/// The caller supplies facts queried from its original held process; this joins
/// them to the existing selected controller action, never to an arbitrary PID.
pub fn frontend_kill_observation(
    action: &serde_json::Value,
    held: &memcordon_core::WindowsProcessIdentityV1,
    native_status: u32,
) -> Option<ObservedFrontendLoss> {
    (held.process_id != 0
        && held.creation_time_100ns != 0
        && native_status == 0xC000_013A
        && action["format"] == "memcordon.windows-component-frontend-action"
        && action["revision"] == 1
        && action["kind"] == "exit-process"
        && action["process"]["process_id"].as_u64() == Some(u64::from(held.process_id))
        && action["process"]["creation_time_100ns"].as_u64() == Some(held.creation_time_100ns)
        && action["target_authorization_observed"] == true
        && action["controller_release_observed"] == true
        && action["requested_exit_status"].as_u64() == Some(u64::from(native_status)))
    .then(|| ObservedFrontendLoss {
        selected: memcordon_core::WindowsSealedFault::FrontendKilledAfterAuthorization,
        identity: held.clone(),
        native_status,
    })
}

/// A disconnect is not a process-kill witness: retain its actual wrapper exit.
pub fn frontend_disconnect_observation(
    action: &serde_json::Value,
    held: &memcordon_core::WindowsProcessIdentityV1,
    native_status: u32,
) -> Option<ObservedFrontendLoss> {
    (held.process_id != 0
        && held.creation_time_100ns != 0
        && native_status == 125
        && action["format"] == "memcordon.windows-component-frontend-action"
        && action["revision"] == 1
        && action["kind"] == "disconnect-public-channel"
        && action["process"]["process_id"].as_u64() == Some(u64::from(held.process_id))
        && action["process"]["creation_time_100ns"].as_u64() == Some(held.creation_time_100ns)
        && action["target_authorization_observed"] == true
        && action["controller_release_observed"] == true
        && action.get("requested_exit_status") == Some(&serde_json::Value::Null))
    .then(|| ObservedFrontendLoss {
        selected: memcordon_core::WindowsSealedFault::FrontendDisconnectedAfterAuthorization,
        identity: held.clone(),
        native_status,
    })
}

pub fn frontend_guardian_injection_authority(
    rejection: &memcordon_core::WindowsProviderRejectionV2,
    selected: memcordon_core::WindowsSealedFault,
    provider: &memcordon_core::PublicProviderBindingV1,
    attempt: &str,
    request: &str,
    live: &memcordon_core::WindowsGuardianAttemptObservation,
    observed: &ObservedFrontendLoss,
) -> bool {
    use memcordon_core::*;
    if !matches!(
        selected,
        WindowsSealedFault::FrontendKilledAfterAuthorization
            | WindowsSealedFault::FrontendDisconnectedAfterAuthorization
    ) || observed.selected != selected
        || !rejection.is_consistent()
    {
        return false;
    }
    guardian_frontend_chain_authority(
        rejection, selected, provider, attempt, request, live, observed,
    )
}

/// Values queried from the original retained native process/thread owners.
pub struct ControlServiceRetirement {
    pub process: memcordon_core::WindowsProcessIdentityV1,
    pub thread: memcordon_core::WindowsWorkerThreadIdentityV1,
    pub process_status: Option<u32>,
    pub thread_status: u32,
    pub frontend: memcordon_core::WindowsProcessIdentityV1,
    pub frontend_status: u32,
}

pub struct ObservedControlServiceLoss {
    site: memcordon_core::WindowsControlWorkerSiteV1,
    frontend: ObservedFrontendLoss,
}

/// Shared by pre-authority observation and the mandatory later retirement check.
pub fn control_retirement_matches(
    selected: memcordon_core::WindowsSealedFault,
    thread_status: u32,
    process_retired: bool,
    process_status: Option<u32>,
) -> bool {
    use memcordon_core::WindowsSealedFault::*;
    match selected {
        ControlServiceKilledAfterAuthorization => {
            process_retired && thread_status == 0xC000_013A && process_status == Some(0xC000_013A)
        }
        ControlWorkerKilledAfterAuthorization => !process_retired && thread_status == 0,
        _ => false,
    }
}

pub fn control_service_loss_observation(
    site: &memcordon_core::WindowsControlWorkerSiteV1,
    held: &ControlServiceRetirement,
    live: &memcordon_core::WindowsGuardianAttemptObservation,
) -> Option<ObservedControlServiceLoss> {
    use memcordon_core::WindowsSealedFault::ControlServiceKilledAfterAuthorization as Selected;
    let nonce = live.live_nonce.as_deref()?;
    let target = live.live_target_identity.as_ref()?;
    (live.is_consistent()
        && site.binds(
            &String::from(live.association.attempt_id.clone()),
            nonce,
            &String::from(live.association.request_sha256.clone()),
            Selected,
            target.process_id,
        )
        && site.process == held.process
        && site.thread == held.thread
        && control_retirement_matches(
            Selected,
            held.thread_status,
            held.process_status.is_some(),
            held.process_status,
        )
        && held.frontend.process_id != 0
        && held.frontend.creation_time_100ns != 0
        && held.frontend_status == 125)
        .then(|| ObservedControlServiceLoss {
            site: site.clone(),
            frontend: ObservedFrontendLoss {
                selected: Selected,
                identity: held.frontend.clone(),
                native_status: held.frontend_status,
            },
        })
}

pub fn control_service_guardian_injection_authority(
    rejection: &memcordon_core::WindowsProviderRejectionV2,
    selected: memcordon_core::WindowsSealedFault,
    provider: &memcordon_core::PublicProviderBindingV1,
    attempt: &str,
    request: &str,
    live: &memcordon_core::WindowsGuardianAttemptObservation,
    observed: &ObservedControlServiceLoss,
) -> bool {
    selected == memcordon_core::WindowsSealedFault::ControlServiceKilledAfterAuthorization
        && live.live_nonce.as_deref().is_some_and(|nonce| {
            live.live_target_identity.as_ref().is_some_and(|target| {
                observed
                    .site
                    .binds(attempt, nonce, request, selected, target.process_id)
            })
        })
        && guardian_frontend_chain_authority(
            rejection,
            selected,
            provider,
            attempt,
            request,
            live,
            &observed.frontend,
        )
}

pub fn control_service_recovery_authority(
    response: &memcordon_core::WindowsProviderResponseV3,
    delivery: &memcordon_core::WindowsTerminalDeliveryEvidenceV1,
    live: &memcordon_core::WindowsGuardianAttemptObservation,
    observed: &ObservedControlServiceLoss,
) -> bool {
    use memcordon_core::*;
    let WindowsProviderResponseV3::Reject {
        schema_version,
        attempt_id,
        nonce,
        request_sha256,
        rejection,
    } = response
    else {
        return false;
    };
    let Ok(authority) = response.terminal_authority_json() else {
        return false;
    };
    *schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
        && delivery.is_consistent()
        && delivery.attempt_id == *attempt_id
        && delivery.nonce == *nonce
        && delivery.request_sha256 == *request_sha256
        && delivery.authority_sha256
            == crate::windows_causal_acceptance::sha256(authority.as_bytes())
        && live.live_nonce.as_ref() == Some(nonce)
        && control_service_guardian_injection_authority(
            rejection,
            WindowsSealedFault::ControlServiceKilledAfterAuthorization,
            &live.association.provider,
            attempt_id,
            request_sha256,
            live,
            observed,
        )
}

fn guardian_frontend_chain_authority(
    rejection: &memcordon_core::WindowsProviderRejectionV2,
    selected: memcordon_core::WindowsSealedFault,
    provider: &memcordon_core::PublicProviderBindingV1,
    attempt: &str,
    request: &str,
    live: &memcordon_core::WindowsGuardianAttemptObservation,
    observed: &ObservedFrontendLoss,
) -> bool {
    use memcordon_core::*;
    if observed.selected != selected || !rejection.is_consistent() {
        return false;
    }
    let (Some(failure), Some(guardian), Some(terminal)) = (
        rejection.provider_failure.as_ref(),
        rejection.guardian_causal_receipt.as_ref(),
        rejection.terminal_receipt(),
    ) else {
        return false;
    };
    if !failure.is_consistent()
        || &failure.provider_binding != provider
        || String::from(failure.attempt_id.clone()) != attempt
        || String::from(failure.request_sha256.clone()) != request
        || !live.is_consistent()
        || &live.association.provider != provider
        || String::from(live.association.attempt_id.clone()) != attempt
        || String::from(live.association.request_sha256.clone()) != request
        || live.guardian_identity != guardian.guardian_identity
        || live.worker_process_identity.as_ref() != Some(&guardian.worker_identity)
        || terminal.attempt_id != attempt
        || terminal.request_sha256 != request
        || terminal.validate_for_attempt().is_err()
        || terminal.process_observation.root_identity != live.live_target_identity
        || live.live_nonce.as_ref() != Some(&terminal.nonce)
        || !matches!(&guardian.cleanup_trigger, Some(WindowsGuardianCleanupTriggerV1::FrontendLost { frontend, native_exit_status })
            if frontend == &observed.identity && *native_exit_status == observed.native_status)
        || !terminal
            .execution()
            .is_some_and(|(_, outcome, _)| matches!(outcome, RunOutcome::MonitorFailed { .. }))
    {
        return false;
    }
    let OriginalFailureV1::Observed { event: original } = &failure.original else {
        return false;
    };
    if original.sequence == 0
        || original.origin != DiagnosticOriginV1::Launcher
        || original.category != FailureCategoryV1::Monitor
        || original.operation != FailureOperationV1::CheckGuardian
        || original.code != FailureCodeV1::GuardianLoss
        || original.observed_phase != AttemptObservationPhaseV1::Monitoring
        || original.native_code.is_some()
        || original.safe_detail != SafeDiagnosticDetailV1::NoAdditionalDetail
    {
        return false;
    }
    failure.secondary.as_slice().iter().any(|event| {
        event.sequence > original.sequence
            && event.origin == DiagnosticOriginV1::Launcher
            && event.category == FailureCategoryV1::Transport
            && event.operation == FailureOperationV1::DeliverResponse
            && event.code == FailureCodeV1::ControlTransport
            && event.observed_phase == AttemptObservationPhaseV1::Cleaning
            && matches!(
                event.native_code,
                Some(NativeFailureCodeV1::Win32(109 | 232 | 233))
            )
            && event.safe_detail
                == (SafeDiagnosticDetailV1::InjectedWindowsFault { fault: selected })
    })
}

pub fn fault_selectors() -> Vec<memcordon_core::WindowsSealedFault> {
    use memcordon_core::WindowsSealedFault::*;
    vec![
        PublicPipeCreate,
        CallerPidLookup,
        CallerTokenImpersonation,
        PrimaryTokenDuplicate,
        PrivatePipeConnect,
        LauncherPeerVerify,
        TokenHandleDuplicate,
        JobCreate,
        JobConfigure,
        CompletionPort,
        GuardianCreate,
        GuardianKilledBeforeAuthorization,
        GuardianKilledAfterAuthorization,
        FrontendDisconnectedAfterAuthorization,
        FrontendKilledAfterAuthorization,
        ControlWorkerKilledAfterAuthorization,
        ControlServiceKilledAfterAuthorization,
        LauncherWorkerKilledAfterAuthorization,
        LauncherServiceKilledAfterAuthorization,
        AllJobOwnersClosedAfterAuthorization,
        StreamCreate,
        RelayHandleDuplicate,
        RelayReady,
        AttributeList,
        JobList,
        HandleList,
        CreateProcessAsUser,
        TargetTokenReadback,
        JobMembershipReadback,
        BeforeResume,
        Resume,
        TerminateJob,
        ActiveProcessQuery,
        RelayRetire,
        GuardianReap,
        FinalHandleClose,
        RecordRetire,
    ]
}

pub fn envelope_mutants() -> Vec<memcordon_core::WindowsSealedMutant> {
    use memcordon_core::WindowsSealedMutant::*;
    vec![
        OmitJobList,
        ResumeBeforeGuardian,
        CreateUnderServiceToken,
        OmitHandleList,
    ]
}

/// A replacement recovery executor must be a different native process and must
/// match the SCM observation. It never substitutes for the original owner.
pub fn control_service_recovery_process_matches(
    original: &memcordon_core::WindowsProcessIdentityV1,
    replacement: &memcordon_core::WindowsProcessIdentityV1,
    scm_process_id: u32,
) -> bool {
    original.process_id != 0
        && original.creation_time_100ns != 0
        && replacement.process_id != 0
        && replacement.creation_time_100ns != 0
        && replacement != original
        && replacement.process_id == scm_process_id
}

/// Select only deliberate service-process loss, never worker-only loss.
/// Endpoint availability admits recovery work; it supplies no terminal authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceRecoveryRole {
    Control,
    Launcher,
}

impl ServiceRecoveryRole {
    pub fn for_fault(fault: Option<memcordon_core::WindowsSealedFault>) -> Option<Self> {
        use memcordon_core::WindowsSealedFault;
        match fault {
            Some(WindowsSealedFault::ControlServiceKilledAfterAuthorization) => Some(Self::Control),
            Some(
                WindowsSealedFault::LauncherServiceKilledAfterAuthorization
                | WindowsSealedFault::AllJobOwnersClosedAfterAuthorization,
            ) => Some(Self::Launcher),
            _ => None,
        }
    }

    pub fn service_name(self) -> &'static str {
        match self {
            Self::Control => memcordon_core::WINDOWS_CONTROL_SERVICE_NAME,
            Self::Launcher => memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME,
        }
    }

    pub fn pipe_name(self) -> &'static str {
        match self {
            Self::Control => memcordon_core::WINDOWS_CONTROL_PIPE,
            Self::Launcher => memcordon_core::WINDOWS_LAUNCHER_PIPE,
        }
    }

    #[cfg(windows)]
    fn observe_status(self) -> std::io::Result<serde_json::Value> {
        match self {
            Self::Control => crate::windows_readiness_faults::observe_control_service_status(),
            Self::Launcher => crate::windows_readiness_faults::observe_launcher_service_status(),
        }
    }
}

#[cfg(windows)]
#[path = "windows_extinction_staging.rs"]
mod extinction_staging;

#[cfg(windows)]
pub fn run_installed(
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
    input: &ComponentInput,
    records: &mut Vec<ComponentAssessment>,
) -> Result<()> {
    run_installed_until(
        config,
        input,
        records,
        crate::windows_installed_cases::WindowsLeaseDeadlines::finite_default(),
    )
}

#[cfg(windows)]
pub fn run_installed_until(
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
    input: &ComponentInput,
    records: &mut Vec<ComponentAssessment>,
    deadlines: crate::windows_installed_cases::WindowsLeaseDeadlines,
) -> Result<()> {
    native::run(config, input, records, deadlines)
}

#[cfg(windows)]
mod native {
    use super::*;
    use crate::windows_consumer_readiness::{SuiteInput, native::read, public_component_command};
    use crate::windows_owned_guardian::GuardianBaseline;
    use std::{
        ffi::OsString,
        fs::{self, OpenOptions},
        io::{self, Write},
        os::windows::ffi::OsStrExt,
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    struct HeldWorker {
        thread: std::os::windows::io::OwnedHandle,
        process: memcordon_testkit::WindowsImageProcess,
        identity: memcordon_core::WindowsWorkerThreadIdentityV1,
    }

    #[allow(unsafe_code)] // WaitNamedPipe is a query only; the later recovery command authenticates provider authority.
    fn wait_service_recovery(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        input: &ComponentInput,
        original: &HeldWorker,
        role: super::ServiceRecoveryRole,
        directory: &std::path::Path,
        record: &mut ComponentAssessment,
        cutoff: Instant,
    ) -> Result<memcordon_testkit::WindowsImageProcess> {
        use windows_sys::Win32::{
            Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, ERROR_SEM_TIMEOUT},
            System::Pipes::{NMPWAIT_NOWAIT, WaitNamedPipeW},
        };
        let service_label = match role {
            super::ServiceRecoveryRole::Control => "control",
            super::ServiceRecoveryRole::Launcher => "launcher",
        };
        let status = super::worker_wait::wait_until(&original.thread, cutoff)?;
        if status != 0xC000_013A {
            return Err(CiError::Message(format!(
                "original {service_label} service fault exit differs"
            )));
        }
        let original_identity = memcordon_core::WindowsProcessIdentityV1 {
            process_id: original.process.identity.pid,
            creation_time_100ns: u64::try_from(original.process.identity.birth).map_err(|_| {
                CiError::Message(format!(
                    "original {service_label} service birth exceeds bound"
                ))
            })?,
        };
        let pipe: Vec<_> = role.pipe_name().encode_utf16().chain(Some(0)).collect();
        loop {
            let remaining = cutoff
                .checked_duration_since(Instant::now())
                .filter(|remaining| *remaining > Duration::from_millis(10))
                .ok_or_else(|| {
                    CiError::Message(format!(
                        "original {service_label} service recovery cutoff exhausted"
                    ))
                })?;
            if original.process.has_exited()? {
                let scm = role.observe_status()?;
                if scm["name"] != role.service_name() {
                    return Err(CiError::Message(
                        "recovery SCM service identity differs".into(),
                    ));
                }
                if scm["current_state"] == windows_sys::Win32::System::Services::SERVICE_RUNNING {
                    let pid = scm["process_id"]
                        .as_u64()
                        .and_then(|pid| u32::try_from(pid).ok())
                        .filter(|pid| *pid != 0)
                        .ok_or_else(|| {
                            CiError::Message("recovery SCM process identity absent".into())
                        })?;
                    let mut matches = memcordon_testkit::windows_processes_for_image_until(
                        &config.installed_agent.path,
                        cutoff,
                    )?
                    .into_iter()
                    .filter(|held| held.identity.pid == pid);
                    if let Some(replacement) = matches.next() {
                        if matches.next().is_some() {
                            return Err(CiError::Message(
                                "recovery SCM process image is ambiguous".into(),
                            ));
                        }
                        let replacement_identity = memcordon_core::WindowsProcessIdentityV1 {
                            process_id: replacement.identity.pid,
                            creation_time_100ns: u64::try_from(replacement.identity.birth)
                                .map_err(|_| {
                                    CiError::Message("recovery SCM birth exceeds bound".into())
                                })?,
                        };
                        if !super::control_service_recovery_process_matches(
                            &original_identity,
                            &replacement_identity,
                            pid,
                        ) || replacement.has_exited()?
                        {
                            return Err(CiError::Message(
                                "recovery SCM replacement identity differs".into(),
                            ));
                        }
                        if role.observe_status()? == scm {
                            if crate::windows_causal_acceptance::sha256(&read(
                                &config.installed_agent.path,
                                512 * 1024 * 1024,
                            )?) != config.installed_agent.sha256
                            {
                                return Err(CiError::Message(
                                    "recovery service selected image changed".into(),
                                ));
                            }
                            // SAFETY: the fixed endpoint is NUL terminated and NOWAIT cannot renew the cutoff.
                            let available =
                                unsafe { WaitNamedPipeW(pipe.as_ptr(), NMPWAIT_NOWAIT) } != 0;
                            if available {
                                if Instant::now() >= cutoff
                                    || replacement.has_exited()?
                                    || role.observe_status()? != scm
                                {
                                    return Err(CiError::Message(
                                        "recovery service changed at endpoint readiness".into(),
                                    ));
                                }
                                let (leaf, format, status_key) = match role {
                                    super::ServiceRecoveryRole::Control => (
                                        "control-service-recovery-ready.json",
                                        "memcordon.windows-component-control-service-recovery",
                                        "control_service",
                                    ),
                                    super::ServiceRecoveryRole::Launcher => (
                                        "launcher-service-recovery-ready.json",
                                        "memcordon.windows-component-launcher-service-recovery",
                                        "launcher_service",
                                    ),
                                };
                                retain(
                                    &directory.join(leaf),
                                    &serde_json::to_vec(&serde_json::json!({
                                        "format":format,"revision":1,
                                        "original_process":original_identity,"original_process_exit_observed":true,
                                        "original_thread_exit_status":status,"replacement_process":replacement_identity,
                                        "selected_image_sha256":config.installed_agent.sha256,(status_key):scm,
                                        "endpoint_available":true,"provider_authority_authenticated":false,
                                        "original_cleanup_deadline_unix_millis":input.original_cleanup_deadline_unix_millis
                                    }))?,
                                    record,
                                )?;
                                return Ok(replacement);
                            }
                            let error = io::Error::last_os_error();
                            if !matches!(
                                error
                                    .raw_os_error()
                                    .and_then(|code| u32::try_from(code).ok()),
                                Some(ERROR_FILE_NOT_FOUND | ERROR_PIPE_BUSY | ERROR_SEM_TIMEOUT)
                            ) {
                                return Err(error.into());
                            }
                        }
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(10).min(remaining));
        }
    }
    #[allow(unsafe_code)] // Query-only held thread is joined to authenticated native process birth.
    fn hold_worker(
        observed: &memcordon_core::WindowsGuardianAttemptObservation,
        image: &std::path::Path,
        deadline: Instant,
    ) -> io::Result<HeldWorker> {
        let expected = observed
            .worker_process_identity
            .as_ref()
            .ok_or_else(|| io::Error::other("component worker process absent"))?;
        let identity = observed
            .worker_thread_identity
            .as_ref()
            .ok_or_else(|| io::Error::other("component worker thread absent"))?;
        hold_worker_identity(expected, identity, image, deadline)
    }
    #[allow(unsafe_code)] // Retains exact observed process/thread native births before the owned actor barrier release.
    fn hold_worker_identity(
        expected: &memcordon_core::WindowsProcessIdentityV1,
        identity: &memcordon_core::WindowsWorkerThreadIdentityV1,
        image: &std::path::Path,
        deadline: Instant,
    ) -> io::Result<HeldWorker> {
        use std::os::windows::io::FromRawHandle;
        use windows_sys::Win32::System::Threading::{
            GetProcessIdOfThread, GetThreadTimes, OpenThread, THREAD_QUERY_LIMITED_INFORMATION,
            WaitForSingleObject,
        };
        let identity = identity.clone();
        let process = memcordon_testkit::windows_processes_for_image_until(image, deadline)?
            .into_iter()
            .find(|held| {
                held.identity.pid == expected.process_id
                    && held.identity.birth == u128::from(expected.creation_time_100ns)
            })
            .ok_or_else(|| {
                io::Error::other("component worker process differs from held selected image")
            })?;
        if process.has_exited()? {
            return Err(io::Error::other("component worker process already retired"));
        }
        // SAFETY: the explicit query-only handle is owned until observed native retirement.
        let raw = unsafe {
            OpenThread(
                THREAD_QUERY_LIMITED_INFORMATION | 0x00100000,
                0,
                identity.thread_id,
            )
        };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        let thread = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(raw.cast()) };
        let mut birth = windows_sys::Win32::Foundation::FILETIME::default();
        let mut exit = birth;
        let mut kernel = birth;
        let mut user = birth;
        if unsafe { GetThreadTimes(raw, &mut birth, &mut exit, &mut kernel, &mut user) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let actual = u64::from(birth.dwLowDateTime) | (u64::from(birth.dwHighDateTime) << 32);
        if actual != identity.creation_time_100ns
            || unsafe { GetProcessIdOfThread(raw) } != expected.process_id
            || unsafe { WaitForSingleObject(raw, 0) }
                != windows_sys::Win32::Foundation::WAIT_TIMEOUT
        {
            return Err(io::Error::other(
                "component worker thread birth/owner/liveness differs",
            ));
        }
        Ok(HeldWorker {
            thread,
            process,
            identity,
        })
    }
    #[allow(unsafe_code)] // Same retained query/synchronization handle, no reopened numeric thread id.
    fn worker_exit(worker: &HeldWorker) -> io::Result<u32> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::Threading::{GetExitCodeThread, WaitForSingleObject};
        let raw = worker.thread.as_raw_handle();
        if unsafe { WaitForSingleObject(raw, 0) } != windows_sys::Win32::Foundation::WAIT_OBJECT_0 {
            return Err(io::Error::other(
                "component held worker thread has not retired",
            ));
        }
        let mut status = 0;
        if unsafe { GetExitCodeThread(raw, &mut status) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(status)
    }

    #[allow(unsafe_code)] // Query only the original retained synchronization handle.
    fn worker_retired(worker: &HeldWorker) -> io::Result<bool> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::{WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
        match unsafe {
            windows_sys::Win32::System::Threading::WaitForSingleObject(
                worker.thread.as_raw_handle(),
                0,
            )
        } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            WAIT_FAILED => Err(io::Error::last_os_error()),
            _ => Err(io::Error::other(
                "unexpected held worker synchronization status",
            )),
        }
    }

    fn retain(
        path: &std::path::Path,
        bytes: &[u8],
        record: &mut ComponentAssessment,
    ) -> Result<()> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        if read(path, bytes.len())? != bytes {
            return Err(CiError::Message(
                "component named artifact readback differs".into(),
            ));
        }
        record
            .artifacts
            .push(crate::windows_installed_cases::SelectedArtifact {
                path: path.to_owned(),
                sha256: crate::windows_causal_acceptance::sha256(bytes),
            });
        Ok(())
    }

    pub fn run(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        input: &ComponentInput,
        records: &mut Vec<ComponentAssessment>,
        deadlines: crate::windows_installed_cases::WindowsLeaseDeadlines,
    ) -> Result<()> {
        if input.format != "memcordon.windows-readiness-component"
            || input.revision != 1
            || input.artifact_prefix.as_os_str().is_empty()
            || input
                .artifact_prefix
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
            || input.run_id.is_empty()
            || input.run_id.len() > 128
            || input.recipe_id.is_empty()
            || input.recipe_id.len() > 128
            || input.source_commit != config.provider.source_commit.as_str()
            || !matches!(
                input.native_target.as_str(),
                "x86_64-pc-windows-msvc" | "aarch64-pc-windows-msvc"
            )
            || input.features != ["test-support", "windows-sealed-runtime"]
            || serde_json::to_vec(&input.selected_components)?
                != serde_json::to_vec(&config.components)?
        {
            return Err(CiError::Message(
                "component runner requires exact separately measured support package descriptor"
                    .into(),
            ));
        }
        for artifact in &input.selected_components {
            if crate::windows_causal_acceptance::sha256(&read(&artifact.path, 512 * 1024 * 1024)?)
                != artifact.sha256
            {
                return Err(CiError::Message(
                    "component package bytes differ from explicit selected measurement".into(),
                ));
            }
        }
        let suite: SuiteInput =
            serde_json::from_slice(&read(&input.suite_input, 4 * 1024 * 1024)?)?;
        let base = suite
            .cases
            .iter()
            .find(|case| case.key.family == "W-JOINT" && case.key.scenario == "ordinary")
            .ok_or_else(|| {
                CiError::Message("component runner finite joint fixture absent".into())
            })?;
        let policy_budget = deadlines.work_budget(Duration::from_secs(90))?;
        let mut apply = crate::command::CommandSpec::new(
            &config.installed_agent.path,
            &config.output_directory,
            policy_budget,
        )
        .args([
            OsString::from("package"),
            "policy".into(),
            "apply".into(),
            "--file".into(),
            suite.local_policy.clone().into_os_string(),
        ])
        .materialize()?;
        apply.env_clear();
        let activated = memcordon_testkit::run_with_deadline_output_limit(
            &mut apply,
            policy_budget,
            256 * 1024,
        )
        .map_err(|error| CiError::Message(error.to_string()))?;
        let _activation_stdout = crate::windows_readiness_adapter::publish_receipt(
            &config.output_directory.join("policy-activation.stdout.bin"),
            &activated.stdout,
        )?;
        let _activation_stderr = crate::windows_readiness_adapter::publish_receipt(
            &config.output_directory.join("policy-activation.stderr.bin"),
            &activated.stderr,
        )?;
        crate::command::require_successful_output("component policy activation", &activated)?;
        let activation: serde_json::Value =
            serde_json::from_slice(&activated.stdout).map_err(|error| {
                CiError::Message(format!("successful component activation decode: {error}"))
            })?;
        let configured = memcordon_core::workload_registry::RuntimePolicyRegistry::parse(&read(
            &suite.local_policy,
            256 * 1024,
        )?)
        .map_err(CiError::Message)?;
        let registry: memcordon_core::workload_registry::RuntimePolicyRegistry =
            serde_json::from_value(activation.get("registry").cloned().ok_or_else(|| {
                CiError::Message("component activation omitted registry".into())
            })?)?;
        if configured != registry
            || activation.get("format").and_then(serde_json::Value::as_str)
                != Some("memcordon.local-activation")
            || activation
                .get("revision")
                .and_then(serde_json::Value::as_u64)
                != Some(1)
            || activation
                .get("registry_digest")
                .and_then(serde_json::Value::as_str)
                != Some(
                    String::from(registry.canonical_digest().map_err(CiError::Message)?).as_str(),
                )
        {
            return Err(CiError::Message(
                "native component policy activation differs from exact configured registry".into(),
            ));
        }
        let epoch = serde_json::from_value(
            activation
                .get("epoch")
                .cloned()
                .ok_or_else(|| CiError::Message("component activation epoch absent".into()))?,
        )?;
        let mut contract = memcordon_core::workload_contract::WorkloadContractV1::parse(&read(
            &base.workload_contract,
            256 * 1024,
        )?)
        .map_err(CiError::Message)?;
        contract.expected_epoch = epoch;
        let contract_directory = config.output_directory.join("W-JOINT").join("ordinary");
        fs::create_dir_all(&contract_directory)?;
        let bytes = serde_json::to_vec(&contract)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(contract_directory.join("requested-contract.json"))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        if read(
            &contract_directory.join("requested-contract.json"),
            256 * 1024,
        )? != bytes
        {
            return Err(CiError::Message(
                "component activated request readback differs".into(),
            ));
        }
        let mut first_error = None;
        for (ordinal, fault) in fault_selectors().into_iter().enumerate() {
            let selector = serde_json::json!({"kind":"fault", "fault":fault});
            records.push(ComponentAssessment {
                selector: selector.clone(),
                behavior: Err("not observed".into()),
                collection: Err("not collected".into()),
                retirement: Err("not observed".into()),
                artifacts: Vec::new(),
            });
            let record = records.last_mut().expect("owned component row");
            let directory = config
                .output_directory
                .join("native-components")
                .join(format!("fault-{ordinal}"));
            fs::create_dir_all(&directory)?;
            let result = exercise(
                config,
                input,
                base,
                &suite.local_policy,
                Some(fault),
                None,
                &selector,
                &directory,
                record,
                deadlines,
            );
            if let Err(error) = result {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
            if record.retirement.is_err() {
                break;
            }
        }
        if records
            .last()
            .is_some_and(|record| record.retirement.is_err())
        {
            return Err(first_error.unwrap_or_else(|| {
                CiError::Message("component fault retirement unresolved".into())
            }));
        }
        for (ordinal, mutant) in envelope_mutants().into_iter().enumerate() {
            let selector = serde_json::json!({"kind":"mutant", "mutant":mutant});
            records.push(ComponentAssessment {
                selector: selector.clone(),
                behavior: Err("not observed".into()),
                collection: Err("not collected".into()),
                retirement: Err("not observed".into()),
                artifacts: Vec::new(),
            });
            let record = records.last_mut().expect("owned native mutant row");
            let directory = config
                .output_directory
                .join("native-components")
                .join(format!("mutant-{ordinal}"));
            fs::create_dir_all(&directory)?;
            if let Err(error) = exercise(
                config,
                input,
                base,
                &suite.local_policy,
                None,
                Some(mutant),
                &selector,
                &directory,
                record,
                deadlines,
            ) {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
            if record.retirement.is_err() {
                break;
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        if records.len() != fault_selectors().len() + envelope_mutants().len()
            || records.iter().any(|row| {
                row.behavior.is_err() || row.collection.is_err() || row.retirement.is_err()
            })
        {
            return Err(CiError::Message(
                "native component fault observations incomplete".into(),
            ));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn recover_held_attempt(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        input: &ComponentInput,
        directory: &std::path::Path,
        record: &mut ComponentAssessment,
        held: &memcordon_core::WindowsGuardianAttemptObservation,
        cutoff: Instant,
        capture_stem: &str,
        certification_failure_preserved: bool,
        pending_frontend: Option<&memcordon_core::WindowsProcessIdentityV1>,
    ) -> Result<bool> {
        let binding = crate::windows_component_failed_recovery::RecoveryBinding::from_held(
            held,
            &config.provider,
        )
        .map_err(CiError::Message)?;
        let remaining = cutoff
            .checked_duration_since(Instant::now())
            .filter(|budget| !budget.is_zero())
            .ok_or_else(|| {
                CiError::Message("original failed collection recovery cutoff exhausted".into())
            })?;
        let mut command = crate::command::CommandSpec::new(&config.cli.path, directory, remaining)
            .args([
                "windows-recover",
                "attempt",
                binding.attempt.as_str(),
                binding.nonce.as_str(),
                binding.request.as_str(),
            ])
            .materialize()?;
        command.env_clear();
        let invocation = serde_json::to_vec(&serde_json::json!({
            "format":"memcordon.windows-failed-collection-recovery-command","revision":1,
            "run_id":input.run_id,"recipe_id":input.recipe_id,"source_commit":input.source_commit,
            "provider":config.provider,"held_association":held,"certification_failure_preserved":certification_failure_preserved,
            "executable_sha256":config.cli.sha256,
            "program_utf16":command.get_program().encode_wide().collect::<Vec<_>>(),
            "argv_utf16":command.get_args().map(|arg|arg.encode_wide().collect::<Vec<_>>()).collect::<Vec<_>>(),
            "cwd_utf16":directory.as_os_str().encode_wide().collect::<Vec<_>>(),"environment_cleared":true,
            "original_cleanup_deadline_unix_millis":input.original_cleanup_deadline_unix_millis,
        }))?;
        retain(
            &directory.join(format!("{capture_stem}-invocation.json")),
            &invocation,
            record,
        )?;
        let remaining = cutoff
            .checked_duration_since(Instant::now())
            .filter(|budget| !budget.is_zero())
            .ok_or_else(|| {
                CiError::Message("original failed collection recovery cutoff exhausted".into())
            })?;
        let captured = memcordon_testkit::run_with_deadline_output_limit(
            &mut command,
            remaining,
            2 * 1024 * 1024,
        );
        if let Err(error) = &captured {
            if let memcordon_testkit::ProcessTestError::Timeout { stdout, stderr, .. }
            | memcordon_testkit::ProcessTestError::OutputLimit { stdout, stderr, .. } = error
            {
                retain(
                    &directory.join(format!("{capture_stem}.partial.stdout.bin")),
                    stdout,
                    record,
                )?;
                retain(
                    &directory.join(format!("{capture_stem}.partial.stderr.bin")),
                    stderr,
                    record,
                )?;
            }
            retain(
                &directory.join(format!("{capture_stem}-failure.json")),
                &serde_json::to_vec(&serde_json::json!({
                    "format":"memcordon.windows-failed-collection-recovery-failure","revision":1,
                    "invocation_sha256":crate::windows_causal_acceptance::sha256(&invocation),
                    "failure":error.to_string(),"capture_complete":false,
                    "certification_failure_preserved":certification_failure_preserved,
                }))?,
                record,
            )?;
        }
        let output = captured.map_err(|error| CiError::Message(error.to_string()))?;
        retain(
            &directory.join(format!("{capture_stem}.json")),
            &output.stdout,
            record,
        )?;
        retain(
            &directory.join(format!("{capture_stem}.stderr.bin")),
            &output.stderr,
            record,
        )?;
        retain(
            &directory.join(format!("{capture_stem}-exit.json")),
            &serde_json::to_vec(&serde_json::json!({
                "format":"memcordon.windows-failed-collection-recovery-exit","revision":1,
                "invocation_sha256":crate::windows_causal_acceptance::sha256(&invocation),
                "stdout_sha256":crate::windows_causal_acceptance::sha256(&output.stdout),
                "stderr_sha256":crate::windows_causal_acceptance::sha256(&output.stderr),
                "native_status":output.status.code(),"certification_failure_preserved":certification_failure_preserved,
            }))?,
            record,
        )?;
        if let Some(frontend) = pending_frontend {
            if output.status.code() == Some(1) {
                memcordon_core::canonical_json::reject_duplicate_json_keys(&output.stdout)
                    .map_err(CiError::Message)?;
                let recovered: serde_json::Value = serde_json::from_slice(&output.stdout)?;
                if crate::windows_component_failed_recovery::pending_original_frontend_relay(
                    &recovered,
                    held,
                    &config.provider,
                    frontend,
                    output.status.code(),
                )
                .map_err(CiError::Message)?
                {
                    return Ok(false);
                }
            }
        }
        crate::command::require_successful_output("failed collection owner recovery", &output)?;
        memcordon_core::canonical_json::reject_duplicate_json_keys(&output.stdout)
            .map_err(CiError::Message)?;
        let recovered: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        if recovered.get("schema_version") != Some(&serde_json::json!(1)) {
            return Err(CiError::Message(
                "failed collection recovery wrapper schema differs".into(),
            ));
        }
        let response: memcordon_core::WindowsProviderResponseV3 =
            serde_json::from_value(recovered.get("provider_response").cloned().ok_or_else(
                || CiError::Message("failed collection recovery omitted provider response".into()),
            )?)?;
        binding
            .validate_response(&response)
            .map_err(CiError::Message)?;
        Ok(true)
    }

    fn worker_recovery_receipt_authority(
        receipt: &memcordon_core::WindowsTerminalReceiptV2,
        provider_generation: &str,
        attempt: &str,
        nonce: &str,
        request: &str,
    ) -> Result<bool> {
        receipt
            .validate_for_attempt()
            .map_err(|error| CiError::Message(error.into()))?;
        Ok(receipt.attempt_id == attempt
            && receipt.nonce == nonce
            && receipt.request_sha256 == request
            && receipt.retirement_proof.provider_generation == provider_generation
            && matches!(
                &receipt.payload,
                memcordon_core::WindowsTerminalPayloadV2::RecoveredClosure {
                    primary_failure: memcordon_core::OriginalFailureV1::Unavailable {
                        reason:
                            memcordon_core::OriginalUnavailableReasonV1::WorkerLostBeforeObservation
                    },
                    ..
                }
            ))
    }

    fn exercise(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        input: &ComponentInput,
        base: &crate::windows_consumer_readiness::CaseInput,
        local_policy: &std::path::Path,
        fault: Option<memcordon_core::WindowsSealedFault>,
        mutant: Option<memcordon_core::WindowsSealedMutant>,
        selector: &serde_json::Value,
        directory: &std::path::Path,
        record: &mut ComponentAssessment,
        deadlines: crate::windows_installed_cases::WindowsLeaseDeadlines,
    ) -> Result<()> {
        let baseline = GuardianBaseline::quiescent(
            &config.installed_agent.path,
            &config.installed_manifest.path,
            &config.installed_agent.sha256,
            &config.installed_manifest.sha256,
        )?;
        let mut case = base.clone();
        case.descriptor.start_gate = None;
        case.descriptor.challenge =
            crate::windows_consumer_readiness::native::random_challenge()?.to_vec();
        retain(
            &directory.join("challenge.bin"),
            &case.descriptor.challenge,
            record,
        )?;
        let held_phase =
            fault.is_some_and(|fault| {
                matches!(fault,
            memcordon_core::WindowsSealedFault::GuardianKilledAfterAuthorization
            | memcordon_core::WindowsSealedFault::FrontendDisconnectedAfterAuthorization
            | memcordon_core::WindowsSealedFault::FrontendKilledAfterAuthorization
            | memcordon_core::WindowsSealedFault::ControlWorkerKilledAfterAuthorization
            | memcordon_core::WindowsSealedFault::ControlServiceKilledAfterAuthorization
            | memcordon_core::WindowsSealedFault::LauncherWorkerKilledAfterAuthorization
            | memcordon_core::WindowsSealedFault::LauncherServiceKilledAfterAuthorization
            | memcordon_core::WindowsSealedFault::AllJobOwnersClosedAfterAuthorization)
            });
        if held_phase {
            let name = format!(
                "memcordon-component-{}",
                crate::windows_causal_acceptance::sha256(&serde_json::to_vec(selector)?)
            );
            case.descriptor.start_gate = Some(name);
        }
        case.descriptor.output_root = base
            .descriptor
            .output_root
            .parent()
            .ok_or_else(|| CiError::Message("component candidate parent absent".into()))?
            .join(directory.file_name().expect("component ordinal directory"));
        case.descriptor.transcript = case.descriptor.output_root.join("fixture-events.bin");
        case.descriptor_path = directory.join("input.json");
        fs::create_dir_all(&case.descriptor.output_root)?;
        let prepared_contract = config
            .output_directory
            .join("W-JOINT")
            .join("ordinary")
            .join("requested-contract.json");
        let requested = memcordon_core::workload_contract::WorkloadContractV1::parse(&read(
            &prepared_contract,
            256 * 1024,
        )?)
        .map_err(CiError::Message)?;
        let configured = memcordon_core::workload_registry::RuntimePolicyRegistry::parse(&read(
            local_policy,
            256 * 1024,
        )?)
        .map_err(CiError::Message)?;
        let policy_budget = deadlines.work_budget(Duration::from_secs(90))?;
        let mut apply = crate::command::CommandSpec::new(
            &config.installed_agent.path,
            directory,
            policy_budget,
        )
        .args(["package", "policy", "apply", "--file"])
        .arg(local_policy)
        .materialize()?;
        apply.env_clear();
        let activated = memcordon_testkit::run_with_deadline_output_limit(
            &mut apply,
            policy_budget,
            256 * 1024,
        )
        .map_err(|error| CiError::Message(error.to_string()))?;
        retain(
            &directory.join("policy-activation.stdout.bin"),
            &activated.stdout,
            record,
        )?;
        retain(
            &directory.join("policy-activation.stderr.bin"),
            &activated.stderr,
            record,
        )?;
        crate::command::require_successful_output("component case policy activation", &activated)?;
        let contract = crate::windows_policy_activation::refresh_contract(
            &requested,
            &configured,
            &activated.stdout,
        )?;
        case.workload_contract = directory.join("requested-contract.json");
        retain(
            &case.workload_contract,
            &serde_json::to_vec(&contract)?,
            record,
        )?;
        retain(
            &case.descriptor_path,
            &serde_json::to_vec(&case.descriptor)?,
            record,
        )?;
        let selection_path = directory.join("selection.json");
        retain(&selection_path, &serde_json::to_vec(selector)?, record)?;
        let observation_path = directory.join("native-observation.json");
        let report = directory.join("result.json");
        let execution = public_component_command(
            &config.cli.path,
            &config.fixture.path,
            directory,
            &report,
            &case,
        )?;
        let execution = execution.materialize()?;
        let mut arguments: Vec<OsString> = vec![
            "__windows-certification".into(),
            selection_path.into_os_string(),
            observation_path.clone().into_os_string(),
        ];
        let frontend_gate_name = format!(
            "Local\\MemcordonComponentFrontend{}",
            crate::windows_causal_acceptance::sha256(&case.descriptor.challenge)
        );
        let frontend_gate_owner = Arc::new(
            crate::windows_consumer_readiness::native::event_create(&frontend_gate_name)?,
        );
        // The callback may finish before the child opens this named event.
        // Keep the original event alive through the entire owned child lifetime.
        let frontend_gate = Arc::clone(&frontend_gate_owner);
        arguments.extend([
            OsString::from("--controller-start-gate"),
            OsString::from(frontend_gate_name),
        ]);
        arguments.extend(execution.get_args().map(std::ffi::OsStr::to_os_string));
        let actor_budget = deadlines.work_budget(Duration::from_secs(90))?;
        let actor_cutoff = deadlines.work.min(Instant::now() + actor_budget);
        let actor_command =
            crate::command::CommandSpec::new(&config.cli.path, directory, actor_budget)
                .args(arguments)
                .materialize()?;
        let wrapper_arguments = [
            OsString::from("consumer-readiness-windows"),
            OsString::from("system-frontend"),
            config.cli.path.clone().into_os_string(),
        ]
        .into_iter()
        .chain(actor_command.get_args().map(std::ffi::OsStr::to_os_string));
        let mut command =
            crate::command::CommandSpec::new(&config.fixture.path, directory, actor_budget)
                .args(wrapper_arguments)
                .materialize()?;
        command.env_clear();
        // The owned TCP fixture needs the native Winsock provider's SystemRoot
        // expansion. Keep ambient controller data excluded, and use the same
        // measured OS prerequisites as the positive readiness frontend.
        // The measured wrapper supplies the explicit native environment block;
        // no controller environment mutation or inherited ambient data is used.
        let frontend_environment =
            crate::windows_consumer_readiness::fixture_environment::entries()?;
        let invocation_path = directory.join("actor-invocation.json");
        retain(
            &invocation_path,
            &serde_json::to_vec(&serde_json::json!({
                "format":"memcordon.windows-native-component-invocation","revision":1,
                "run_id":input.run_id,"recipe_id":input.recipe_id,"native_target":input.native_target,
                "executable_sha256":config.cli.sha256,
                "program_utf16":actor_command.get_program().encode_wide().collect::<Vec<_>>(),
                "argv_utf16":actor_command.get_args().map(|arg| arg.encode_wide().collect::<Vec<_>>()).collect::<Vec<_>>(),
                "wrapper_executable_sha256":config.fixture.sha256,
                "wrapper_program_utf16":command.get_program().encode_wide().collect::<Vec<_>>(),
                "wrapper_argv_utf16":command.get_args().map(|arg| arg.encode_wide().collect::<Vec<_>>()).collect::<Vec<_>>(),
                "cwd_utf16":directory.as_os_str().encode_wide().collect::<Vec<_>>(),
                "frontend_environment":frontend_environment,
                "environment_cleared":true
            }))?,
            record,
        )?;
        let gate = case
            .descriptor
            .start_gate
            .as_ref()
            .map(|name| crate::windows_consumer_readiness::native::event_create(name))
            .transpose()?;
        let family = Arc::new(Mutex::new(Vec::new()));
        let held_family = Arc::clone(&family);
        let guardian = Arc::new(Mutex::new(None));
        let held_guardian = Arc::clone(&guardian);
        let live = Arc::new(Mutex::new(None));
        let held_live = Arc::clone(&live);
        let worker = Arc::new(Mutex::new(None));
        let held_worker = Arc::clone(&worker);
        let control_worker = Arc::new(Mutex::new(None));
        let held_control_worker = Arc::clone(&control_worker);
        let control_site = Arc::new(Mutex::new(None));
        let held_control_site = Arc::clone(&control_site);
        let frontend = Arc::new(Mutex::new(None));
        let held_frontend = Arc::clone(&frontend);
        let wrapper = Arc::new(Mutex::new(None));
        let held_wrapper = Arc::clone(&wrapper);
        let wrapper_image = config.fixture.path.clone();
        let fixture = config.fixture.path.clone();
        let cli = config.cli.path.clone();
        let cwd = directory.to_owned();
        let transcript = case.descriptor.transcript.clone();
        let provider = config.provider.clone();
        let worker_image = config.installed_agent.path.clone();
        let worker_loss = matches!(
            fault,
            Some(
                memcordon_core::WindowsSealedFault::LauncherWorkerKilledAfterAuthorization
                    | memcordon_core::WindowsSealedFault::LauncherServiceKilledAfterAuthorization
                    | memcordon_core::WindowsSealedFault::AllJobOwnersClosedAfterAuthorization
            )
        );
        let frontend_loss = matches!(
            fault,
            Some(
                memcordon_core::WindowsSealedFault::FrontendDisconnectedAfterAuthorization
                    | memcordon_core::WindowsSealedFault::FrontendKilledAfterAuthorization
            )
        );
        let launcher_process_loss = matches!(
            fault,
            Some(
                memcordon_core::WindowsSealedFault::LauncherServiceKilledAfterAuthorization
                    | memcordon_core::WindowsSealedFault::AllJobOwnersClosedAfterAuthorization
            )
        );
        let control_loss = matches!(
            fault,
            Some(
                memcordon_core::WindowsSealedFault::ControlWorkerKilledAfterAuthorization
                    | memcordon_core::WindowsSealedFault::ControlServiceKilledAfterAuthorization
            )
        );
        let progression_config = config.clone();
        let progression_input = input.clone();
        let mut progression_record = record.clone();
        progression_record.artifacts.clear();
        let progression_record = Arc::new(Mutex::new(progression_record));
        let callback_progression_record = Arc::clone(&progression_record);
        let progression_response = Arc::new(Mutex::new(None));
        let callback_progression_response = Arc::clone(&progression_response);
        let output = memcordon_testkit::run_with_deadline_owned_spawn_with_io_output_limit(
            command,
            actor_cutoff
                .checked_duration_since(Instant::now())
                .ok_or_else(|| {
                    CiError::Message("original actor cutoff exhausted before spawn".into())
                })?,
            4 * 1024 * 1024,
            |mut command| command.spawn(),
            move |wrapper_pid, _, _| {
                let wrapper = memcordon_testkit::windows_processes_for_image_until(
                    &wrapper_image,
                    actor_cutoff,
                )?
                .into_iter()
                .find(|held| held.identity.pid == wrapper_pid)
                .ok_or_else(|| {
                    io::Error::other("component wrapper image/identity could not be held")
                })?;
                let wrapper_identity = wrapper.identity;
                let held = loop {
                    let mut matches =
                        wrapper.direct_children_for_image_until(&cli, actor_cutoff)?;
                    if matches.len() > 1 {
                        return Err(io::Error::other(
                            "component wrapper created multiple frontend identities",
                        ));
                    }
                    if let Some(held) = matches.pop() {
                        break held;
                    }
                    if Instant::now() >= actor_cutoff {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "original frontend discovery cutoff exhausted",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                };
                *held_wrapper
                    .lock()
                    .map_err(|_| io::Error::other("wrapper ownership poisoned"))? = Some(wrapper);
                if held.has_exited()? {
                    return Err(io::Error::other(
                        "component frontend already exited before fault",
                    ));
                }
                let bytes = serde_json::to_vec(&serde_json::json!({
                    "format":"memcordon.windows-component-frontend-held","revision":1,
                    "process_id":held.identity.pid,"creation_time_100ns":held.identity.birth,
                    "held_before_execution":true,"native_live_before_release":true,
                    "wrapper_process_id":wrapper_identity.pid,"wrapper_creation_time_100ns":wrapper_identity.birth,
                    "native_parent_process_id":held.native_parent_process_id()?
                }))
                .map_err(io::Error::other)?;
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(cwd.join("held-frontend-before.json"))?;
                file.write_all(&bytes)?;
                file.sync_all()?;
                *held_frontend
                    .lock()
                    .map_err(|_| io::Error::other("frontend ownership poisoned"))? = Some(held);
                crate::windows_consumer_readiness::native::signal(&frontend_gate)?;
                let Some(gate) = gate else {
                    return Ok(());
                };
                let deadline = deadlines.work.min(Instant::now() + Duration::from_secs(30));
                let roots = loop {
                    let roots: Vec<_> =
                        memcordon_testkit::windows_processes_for_image_until(&fixture, deadline)?
                            .into_iter()
                            .filter(|process| process.identity != wrapper_identity)
                            .collect();
                    if transcript.is_file() && roots.len() == 1 && !roots[0].has_exited()? {
                        break roots;
                    }
                    if Instant::now() >= deadline {
                        return Err(io::Error::other(
                            "component target did not reach owned native barrier",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                };
                let guardian = baseline.hold_new_guardian().map_err(io::Error::other)?;
                let query_budget = deadlines
                    .work_budget(Duration::from_secs(30))
                    .map_err(io::Error::other)?;
                let query_cutoff = deadlines.work.min(Instant::now() + query_budget);
                let mut query = crate::command::CommandSpec::new(&cli, &cwd, query_budget)
                    .args([
                        OsString::from("__observe-windows-guardian"),
                        guardian.identity.process_id.to_string().into(),
                        guardian.identity.creation_time_100ns.to_string().into(),
                    ])
                    .materialize()
                    .map_err(io::Error::other)?;
                query.env_clear();
                crate::windows_component_query_evidence::retain_invocation(
                    &cwd,
                    &serde_json::to_vec(&serde_json::json!({
                        "format":"memcordon.windows-live-association-query-invocation", "revision":1,
                        "guardian":{"process_id":guardian.identity.process_id,
                            "creation_time_100ns":guardian.identity.creation_time_100ns},
                        "provider":provider,
                        "program_utf16":query.get_program().encode_wide().collect::<Vec<_>>(),
                        "argv_utf16":query.get_args().map(|arg| arg.encode_wide().collect::<Vec<_>>()).collect::<Vec<_>>(),
                        "cwd_utf16":cwd.as_os_str().encode_wide().collect::<Vec<_>>(),
                        "environment_cleared":true,"planned_budget_ms":query_budget.as_millis(),
                    })).map_err(io::Error::other)?,
                )?;
                let Some(query_remaining) = query_cutoff
                    .checked_duration_since(Instant::now())
                    .filter(|remaining| !remaining.is_zero())
                else {
                    crate::windows_component_query_evidence::retain_not_started(&cwd)?;
                    return Err(io::Error::other(
                        "original live association query work cutoff expired before spawn",
                    ));
                };
                let observation = memcordon_testkit::run_with_deadline_output_limit(
                    &mut query,
                    query_remaining,
                    memcordon_core::WindowsGuardianAttemptObservation::MAX_FRAME_BYTES,
                );
                let retained =
                    crate::windows_component_query_evidence::retain_result(&cwd, &observation);
                let observation = observation.map_err(|error| {
                    io::Error::other(format!(
                        "{error}; live-association-query evidence retention={retained:?}"
                    ))
                })?;
                if let Err(error) = retained {
                    return Err(io::Error::other(format!(
                        "live association query status={:?}; evidence retention failed: {error}",
                        observation.status
                    )));
                }
                let observation: memcordon_core::WindowsGuardianAttemptObservation =
                    if observation.status.success() {
                        serde_json::from_slice(&observation.stdout).map_err(io::Error::other)?
                    } else {
                        return Err(io::Error::other("component live association query failed"));
                    };
                let target = observation
                    .live_target_identity
                    .as_ref()
                    .ok_or_else(|| io::Error::other("component released target absent"))?
                    .clone();
                if !observation.is_consistent()
                    || observation.association.provider != provider
                    || observation.guardian_identity.process_id != guardian.identity.process_id
                    || observation.guardian_identity.creation_time_100ns
                        != guardian.identity.creation_time_100ns
                    || roots[0].identity.pid != target.process_id
                    || roots[0].identity.birth != u128::from(target.creation_time_100ns)
                {
                    return Err(io::Error::other(
                        "component native held root/guardian association differs",
                    ));
                }
                *held_family
                    .lock()
                    .map_err(|_| io::Error::other("component ownership poisoned"))? = roots;
                *held_guardian
                    .lock()
                    .map_err(|_| io::Error::other("component guardian ownership poisoned"))? =
                    Some(guardian);
                *held_live
                    .lock()
                    .map_err(|_| io::Error::other("component association poisoned"))? =
                    Some(observation);
                if worker_loss || super::launcher_settlement_before_recovery(fault) {
                    let observed = held_live
                        .lock()
                        .map_err(|_| io::Error::other("component association poisoned"))?;
                    *held_worker
                        .lock()
                        .map_err(|_| io::Error::other("component worker ownership poisoned"))? =
                        Some(hold_worker(
                            observed.as_ref().expect("captured association"),
                            &worker_image,
                            deadline,
                        )?);
                }
                if control_loss {
                    let selected_fault = match fault {
                        Some(selected @ (memcordon_core::WindowsSealedFault::ControlWorkerKilledAfterAuthorization
                        | memcordon_core::WindowsSealedFault::ControlServiceKilledAfterAuthorization)) => selected,
                        _ => {
                            return Err(io::Error::other(
                                "control worker site requires an actual control-loss selection",
                            ));
                        }
                    };
                    let path = cwd.join("control-worker-native.json");
                    while !path.try_exists()? {
                        if Instant::now() >= deadline {
                            return Err(io::Error::other(
                                "actual control worker site did not publish before barrier deadline",
                            ));
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    let bytes = read(&path, 64 * 1024).map_err(io::Error::other)?;
                    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)
                        .map_err(io::Error::other)?;
                    let observed: memcordon_core::WindowsControlWorkerSiteV1 =
                        serde_json::from_slice(&bytes).map_err(io::Error::other)?;
                    let live = held_live
                        .lock()
                        .map_err(|_| io::Error::other("component association poisoned"))?;
                    let association = live
                        .as_ref()
                        .ok_or_else(|| io::Error::other("component held association absent"))?;
                    let nonce = association
                        .live_nonce
                        .as_deref()
                        .ok_or_else(|| io::Error::other("component live nonce absent"))?;
                    if !observed.binds(
                        &hex::encode(association.association.attempt_id.bytes()),
                        nonce,
                        &hex::encode(association.association.request_sha256.bytes()),
                        selected_fault,
                        target.process_id,
                    ) {
                        return Err(io::Error::other(
                            "control worker site differs from actual selected target/fault",
                        ));
                    }
                    drop(live);
                    let process = observed.process.clone();
                    let thread = observed.thread;
                    let scm = crate::windows_readiness_faults::observe_running_control_service()?;
                    if scm["process_id"] != process.process_id {
                        return Err(io::Error::other(
                            "held control worker does not belong to actual running SCM service",
                        ));
                    }
                    let held = hold_worker_identity(&process, &thread, &worker_image, deadline)?;
                    if crate::windows_readiness_faults::observe_running_control_service()? != scm {
                        return Err(io::Error::other(
                            "SCM control service changed during native worker acquisition",
                        ));
                    }
                    let bytes=serde_json::to_vec(&serde_json::json!({"format":"memcordon.windows-component-control-worker-held","revision":1,
                        "process":process,"thread":thread,"target_pid":target.process_id,"held_before_fault":true,"control_service":scm})).map_err(io::Error::other)?;
                    let mut file = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(cwd.join("held-control-worker-before.json"))?;
                    file.write_all(&bytes)?;
                    file.sync_all()?;
                    *held_control_worker
                        .lock()
                        .map_err(|_| io::Error::other("control worker ownership poisoned"))? =
                        Some(held);
                    *held_control_site
                        .lock()
                        .map_err(|_| io::Error::other("control site ownership poisoned"))? =
                        Some(observed);
                }
                crate::windows_consumer_readiness::native::signal(&gate)?;
                if fault
                    == Some(
                        memcordon_core::WindowsSealedFault::LauncherWorkerKilledAfterAuthorization,
                    )
                {
                    // The original frontend continues capturing authenticated
                    // replay while this callback settles the exact held owner.
                    // Replay alone cannot stage a recovered terminal outbox.
                    loop {
                        if Instant::now() >= actor_cutoff {
                            return Err(io::Error::other(
                                "original worker recovery progression cutoff exhausted",
                            ));
                        }
                        let worker = held_worker
                            .lock()
                            .map_err(|_| io::Error::other("component worker ownership poisoned"))?;
                        let worker = worker.as_ref().ok_or_else(|| {
                            io::Error::other("original worker was not held before fault")
                        })?;
                        let retired = worker_retired(worker)?;
                        if retired && worker_exit(worker)? != 0xC000_013A {
                            return Err(io::Error::other(
                                "original worker exit differs from selected native loss",
                            ));
                        }
                        let guardian = held_guardian.lock().map_err(|_| {
                            io::Error::other("component guardian ownership poisoned")
                        })?;
                        let guardian = guardian.as_ref().ok_or_else(|| {
                            io::Error::other("original guardian was not held before fault")
                        })?;
                        if retired && guardian.has_retired().map_err(io::Error::other)? {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    let association = held_live
                        .lock()
                        .map_err(|_| io::Error::other("component association poisoned"))?
                        .clone()
                        .ok_or_else(|| io::Error::other("original held association absent"))?;
                    let mut evidence = callback_progression_record
                        .lock()
                        .map_err(|_| io::Error::other("component recovery evidence poisoned"))?;
                    let frontend = held_frontend
                        .lock()
                        .map_err(|_| io::Error::other("component frontend ownership poisoned"))?;
                    let frontend = frontend
                        .as_ref()
                        .ok_or_else(|| io::Error::other("original frontend was not held"))?;
                    let frontend_identity = memcordon_core::WindowsProcessIdentityV1 {
                        process_id: frontend.identity.pid,
                        creation_time_100ns: frontend
                            .identity
                            .birth
                            .try_into()
                            .map_err(io::Error::other)?,
                    };
                    let mut sequence = 0_usize;
                    loop {
                        // Keep ordering retries within the original finite
                        // capture envelope; every outcome remains retained.
                        if evidence
                            .artifacts
                            .len()
                            .checked_add(4)
                            .is_none_or(|files| files > 128)
                            || Instant::now() >= actor_cutoff
                        {
                            return Err(io::Error::other(
                                "original worker recovery evidence/cutoff exhausted",
                            ));
                        }
                        let stem = format!("worker-retirement-recovery-{sequence}");
                        let completed = recover_held_attempt(
                            &progression_config,
                            &progression_input,
                            &cwd,
                            &mut evidence,
                            &association,
                            actor_cutoff,
                            &stem,
                            false,
                            Some(&frontend_identity),
                        )
                        .map_err(io::Error::other)?;
                        let retained_bytes =
                            evidence
                                .artifacts
                                .iter()
                                .try_fold(0_u64, |total, artifact| {
                                    total
                                        .checked_add(std::fs::metadata(&artifact.path)?.len())
                                        .ok_or_else(|| {
                                            io::Error::other("recovery evidence size overflow")
                                        })
                                })?;
                        if retained_bytes > 4 * 1024 * 1024 || evidence.artifacts.len() > 128 {
                            return Err(io::Error::other(
                                "original worker recovery evidence bound exceeded",
                            ));
                        }
                        if completed {
                            *callback_progression_response.lock().map_err(|_| {
                                io::Error::other("component recovery response poisoned")
                            })? = Some(cwd.join(format!("{stem}.json")));
                            break;
                        }
                        sequence = sequence.checked_add(1).ok_or_else(|| {
                            io::Error::other("recovery evidence sequence overflow")
                        })?;
                        let remaining = actor_cutoff
                            .checked_duration_since(Instant::now())
                            .ok_or_else(|| {
                                io::Error::other(
                                    "original worker recovery progression cutoff exhausted",
                                )
                            })?;
                        std::thread::sleep(remaining.min(Duration::from_millis(25)));
                    }
                }
                Ok(())
            },
        );
        record.artifacts.extend(
            progression_record
                .lock()
                .map_err(|_| CiError::Message("component recovery evidence poisoned".into()))?
                .artifacts
                .iter()
                .cloned(),
        );
        if let Some(live) = live
            .lock()
            .map_err(|_| CiError::Message("component observation poisoned".into()))?
            .as_ref()
        {
            retain(
                &directory.join("held-before-fault.json"),
                &serde_json::to_vec(live)?,
                record,
            )?;
        }
        if let Err(error) = &output {
            match error {
                memcordon_testkit::ProcessTestError::Timeout { stdout, stderr, .. }
                | memcordon_testkit::ProcessTestError::OutputLimit { stdout, stderr, .. } => {
                    retain(&directory.join("partial-stdout.bin"), stdout, record)?;
                    retain(&directory.join("partial-stderr.bin"), stderr, record)?;
                }
                _ => {}
            }
            retain(
                &directory.join("capture-failure.json"),
                &serde_json::to_vec(&serde_json::json!({
                    "format":"memcordon.windows-native-component-capture-failure","revision":1,
                    "run_id":input.run_id,"recipe_id":input.recipe_id,"failure":error.to_string(),
                    "capture_complete":false
                }))?,
                record,
            )?;
        }
        drop(frontend_gate_owner);
        let collection = (|| -> Result<()> {
            let output = output
                .as_ref()
                .map_err(|error| CiError::Message(error.to_string()))?;
            let before = read(&directory.join("held-frontend-before.json"), 4096)?;
            record
                .artifacts
                .push(crate::windows_installed_cases::SelectedArtifact {
                    path: directory.join("held-frontend-before.json"),
                    sha256: crate::windows_causal_acceptance::sha256(&before),
                });
            {
                let held = frontend.lock().map_err(|_| {
                    CiError::Message("component frontend ownership poisoned".into())
                })?;
                let held = held.as_ref().ok_or_else(|| {
                    CiError::Message("component frontend was not held before execution".into())
                })?;
                let wrapper = wrapper
                    .lock()
                    .map_err(|_| CiError::Message("wrapper ownership poisoned".into()))?;
                let wrapper = wrapper.as_ref().ok_or_else(|| {
                    CiError::Message("component wrapper was not held before execution".into())
                })?;
                if !held.has_exited()?
                    || !wrapper.has_exited()?
                    || wrapper.native_exit_status()? != held.native_exit_status()?
                    || held.native_exit_status()?
                        != output.status.code().map(|status| status as u32)
                {
                    return Err(CiError::Message(
                        "actual component frontend did not retire with captured native status"
                            .into(),
                    ));
                }
                retain(
                    &directory.join("native-actor-retirement.json"),
                    &serde_json::to_vec(&serde_json::json!({
                        "format":"memcordon.windows-component-actor-retirement","revision":1,
                        "process_id":held.identity.pid,"creation_time_100ns":held.identity.birth,
                        "image_sha256":config.cli.sha256,"held_before_execution":true,
                        "retirement_observed":true,"native_status":held.native_exit_status()?,
                        "wrapper_process_id":wrapper.identity.pid,"wrapper_creation_time_100ns":wrapper.identity.birth,
                        "wrapper_image_sha256":config.fixture.sha256,"wrapper_retirement_observed":true,
                        "wrapper_native_status":wrapper.native_exit_status()?
                    }))?,
                    record,
                )?;
            }
            retain(
                &directory.join("actor-exit.json"),
                &serde_json::to_vec(&serde_json::json!({
                    "format":"memcordon.windows-native-component-exit","revision":1,
                    "run_id":input.run_id,"recipe_id":input.recipe_id,"native_target":input.native_target,
                    "executable_sha256":config.cli.sha256,"native_status":output.status.code(),
                    "capture_complete":true
                }))?,
                record,
            )?;
            retain(&directory.join("stdout.bin"), &output.stdout, record)?;
            retain(&directory.join("stderr.bin"), &output.stderr, record)?;
            let raw = read(&observation_path, 32 * 1024 * 1024)?;
            record
                .artifacts
                .push(crate::windows_installed_cases::SelectedArtifact {
                    path: observation_path.clone(),
                    sha256: crate::windows_causal_acceptance::sha256(&raw),
                });
            let observed: serde_json::Value = serde_json::from_slice(&raw)?;
            if observed.get("selection") != Some(selector)
                || !observed
                    .get("capture_failure")
                    .is_some_and(serde_json::Value::is_null)
            {
                return Err(CiError::Message(
                    "native component selection/custody differs".into(),
                ));
            }
            let actual_request: memcordon_core::WindowsLaunchRequestV1 =
                serde_json::from_value(observed["launch"].clone())?;
            retain(
                &directory.join("provider-request.bin"),
                &serde_json::to_vec(&actual_request)?,
                record,
            )?;
            let attempt = observed
                .get("attempt_id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| CiError::Message("actual component attempt absent".into()))?;
            let request = observed
                .get("request_sha256")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| CiError::Message("actual component request absent".into()))?;
            let nonce = observed
                .pointer("/launch/nonce")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| CiError::Message("component launch nonce absent".into()))?;
            let mut observed_frontend_loss = None;
            let mut observed_control_service_loss = None;
            if fault.is_some_and(|fault| {
                matches!(
                    fault,
                    memcordon_core::WindowsSealedFault::FrontendDisconnectedAfterAuthorization
                        | memcordon_core::WindowsSealedFault::FrontendKilledAfterAuthorization
                )
            }) {
                let frontend = frontend
                    .lock()
                    .map_err(|_| CiError::Message("frontend ownership poisoned".into()))?;
                let frontend = frontend.as_ref().ok_or_else(|| {
                    CiError::Message("component frontend not held before release".into())
                })?;
                let action = observed.get("frontend_action").ok_or_else(|| {
                    CiError::Message("selected frontend fault has no actual action".into())
                })?;
                let kill = fault
                    == Some(memcordon_core::WindowsSealedFault::FrontendKilledAfterAuthorization);
                if action.get("format").and_then(serde_json::Value::as_str)
                    != Some("memcordon.windows-component-frontend-action")
                    || action.get("revision").and_then(serde_json::Value::as_u64) != Some(1)
                    || action.get("kind").and_then(serde_json::Value::as_str)
                        != Some(if kill {
                            "exit-process"
                        } else {
                            "disconnect-public-channel"
                        })
                    || action
                        .pointer("/process/process_id")
                        .and_then(serde_json::Value::as_u64)
                        != Some(u64::from(frontend.identity.pid))
                    || action
                        .pointer("/process/creation_time_100ns")
                        .and_then(serde_json::Value::as_u64)
                        .map(u128::from)
                        != Some(frontend.identity.birth)
                    || action.get("target_authorization_observed")
                        != Some(&serde_json::Value::Bool(true))
                    || action.get("controller_release_observed")
                        != Some(&serde_json::Value::Bool(true))
                    || !frontend.has_exited()?
                    || output.status.success()
                    || frontend.native_exit_status()?
                        != output.status.code().map(|status| status as u32)
                    || (kill && frontend.native_exit_status()? != Some(0xC000_013A))
                {
                    return Err(CiError::Message(
                        "actual frontend action/status differs from held selected process".into(),
                    ));
                }
                retain(
                    &directory.join("held-frontend-exit.json"),
                    &serde_json::to_vec(&serde_json::json!({
                        "format":"memcordon.windows-component-frontend-exit","revision":1,
                        "process_id":frontend.identity.pid,"creation_time_100ns":frontend.identity.birth,
                        "held_before_fault":true,"retirement_observed":true,"native_status":frontend.native_exit_status()?
                    }))?,
                    record,
                )?;
                {
                    let identity = memcordon_core::WindowsProcessIdentityV1 {
                        process_id: frontend.identity.pid,
                        creation_time_100ns: u64::try_from(frontend.identity.birth).map_err(
                            |_| {
                                CiError::Message(
                                    "held native frontend birth exceeds native u64".into(),
                                )
                            },
                        )?,
                    };
                    let native_status = frontend.native_exit_status()?.ok_or_else(|| {
                        CiError::Message("held frontend has no native exit status".into())
                    })?;
                    observed_frontend_loss = Some(
                        (if kill {
                            frontend_kill_observation(action, &identity, native_status)
                        } else {
                            frontend_disconnect_observation(action, &identity, native_status)
                        })
                        .ok_or_else(|| {
                            CiError::Message(
                                "held frontend loss action is not exactly bound".into(),
                            )
                        })?,
                    );
                }
            }
            if held_phase {
                let held = live
                    .lock()
                    .map_err(|_| CiError::Message("component association poisoned".into()))?;
                let held = held.as_ref().ok_or_else(|| {
                    CiError::Message("component native held association absent".into())
                })?;
                if String::from(held.association.attempt_id.clone()) != attempt
                    || String::from(held.association.request_sha256.clone()) != request
                    || held.live_nonce.as_deref() != Some(nonce)
                {
                    return Err(CiError::Message(
                        "component native held phase belongs to another actual request".into(),
                    ));
                }
            }
            let frames = observed
                .get("authenticated_provider_frames")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| CiError::Message("component native frames absent".into()))?;
            let mut rejected = false;
            let mut recovery_failure = None;
            for raw in frames {
                let bytes: Vec<u8> = serde_json::from_value(raw.clone())?;
                let response: memcordon_core::WindowsProviderResponseV3 =
                    serde_json::from_slice(&bytes)?;
                if fault
                    == Some(memcordon_core::WindowsSealedFault::GuardianKilledAfterAuthorization)
                {
                    let held = live
                        .lock()
                        .map_err(|_| CiError::Message("component association poisoned".into()))?;
                    rejected |=
                        crate::windows_component_failed_recovery::guardian_loss_original_authority(
                            &response,
                            memcordon_core::WindowsSealedFault::GuardianKilledAfterAuthorization,
                            held.as_ref().ok_or_else(|| {
                                CiError::Message("original held guardian association absent".into())
                            })?,
                            &config.provider,
                        )
                        .map_err(CiError::Message)?;
                }
                if fault
                    == Some(
                        memcordon_core::WindowsSealedFault::LauncherWorkerKilledAfterAuthorization,
                    )
                {
                    let held = live
                        .lock()
                        .map_err(|_| CiError::Message("component association poisoned".into()))?;
                    rejected |=
                        crate::windows_component_failed_recovery::worker_loss_recovery_authority(
                            &response,
                            held.as_ref().ok_or_else(|| {
                                CiError::Message("original held association absent".into())
                            })?,
                            &config.provider,
                        )
                        .map_err(CiError::Message)?;
                }
                if fault.is_some_and(|selected| {
                    authenticated_transport_injection_authority(
                        &response,
                        selected,
                        &config.provider,
                        attempt,
                        nonce,
                        request,
                    )
                }) {
                    rejected = true;
                }
                if let memcordon_core::WindowsProviderResponseV3::CertificationMutantObserved(
                    ref receipt,
                ) = response
                {
                    if let Some(expected) = mutant {
                        if receipt.mutant == expected
                            && receipt.binding_matches(attempt, nonce, request)
                            && matches!(&receipt.hook_observation, memcordon_core::WindowsMutantHookObservationV1::Native { observation }
                                if observation.rejects(expected))
                        {
                            rejected = true;
                        }
                    }
                }
                if let (
                    Some(expected),
                    memcordon_core::WindowsProviderResponseV3::Reject {
                        schema_version,
                        attempt_id,
                        nonce: actual_nonce,
                        request_sha256,
                        rejection,
                        ..
                    },
                ) = (mutant, &response)
                {
                    if let memcordon_core::WindowsProviderRejectionDispositionV2::PrematureReleaseFailure { receipt }
                        = &rejection.disposition
                    {
                        let held = live.lock().map_err(|_| CiError::Message("component association poisoned".into()))?;
                        rejected |= *schema_version == memcordon_core::WINDOWS_PUBLIC_PROTOCOL_VERSION
                            && attempt_id == attempt && actual_nonce == nonce && request_sha256 == request
                            && rejection.is_consistent()
                            && receipt.validate_for_attempt().is_ok()
                            && receipt.attempt_id == attempt && receipt.nonce == nonce
                            && receipt.request_sha256 == request
                            && receipt.retirement_proof.provider_generation == config.provider.generation.as_str()
                            && held.as_ref().is_none_or(|held| held.is_consistent()
                                && held.association.provider == config.provider
                                && String::from(held.association.attempt_id.clone()) == attempt
                                && String::from(held.association.request_sha256.clone()) == request
                                && held.live_nonce.as_deref() == Some(nonce)
                                && receipt.process_observation.root_identity == held.live_target_identity)
                            && matches!(&receipt.payload,
                                memcordon_core::WindowsTerminalPayloadV2::PrematureReleaseFailure { witness, .. }
                                    if witness.mutant == expected && witness.is_consistent());
                    }
                }
                if let memcordon_core::WindowsProviderResponseV3::Reject {
                    attempt_id,
                    nonce: actual_nonce,
                    request_sha256,
                    rejection,
                    ..
                } = response
                {
                    if attempt_id == attempt && actual_nonce == nonce && request_sha256 == request
                        && rejection.code == "MCSEALED-WINDOWS-CERTIFICATION-FAULT"
                        && fault.is_some_and(|fault| {
                            rejection.detail == format!("MCSEALED-WINDOWS-CERTIFICATION-FAULT: injected {fault:?}")
                                || serde_json::to_value(fault).is_ok_and(|rendered|
                                    rejection.detail == format!("injected certification fault: {rendered}"))
                        })
                        && rejection.provider_failure.as_ref().is_some_and(|failure| {
                            failure.is_consistent()&&failure.provider_binding==config.provider
                                && String::from(failure.attempt_id.clone())==attempt
                                && String::from(failure.request_sha256.clone())==request
                                && (matches!(&failure.original,memcordon_core::OriginalFailureV1::Observed {event}
                                    if fault.is_some_and(|selected|event.safe_detail==memcordon_core::SafeDiagnosticDetailV1::InjectedWindowsFault {fault:selected}))
                                    || fault.is_some_and(|selected| guardian_injection_authority(failure, selected, &config.provider, attempt, request)))
                        }) {
                        rejected = true;
                    }
                }
            }
            if !rejected
                && fault
                    == Some(
                        memcordon_core::WindowsSealedFault::LauncherWorkerKilledAfterAuthorization,
                    )
            {
                // The concurrent exact recovery may already ACK its delivery.
                // Assess its retained authenticated receipt, not a second
                // recovery's receipt-free retirement tombstone or helper Ok.
                let response_path = progression_response
                    .lock()
                    .map_err(|_| CiError::Message("component recovery response poisoned".into()))?
                    .clone()
                    .ok_or_else(|| {
                        CiError::Message("original worker recovery response absent".into())
                    })?;
                let bytes = read(&response_path, 2 * 1024 * 1024)?;
                memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)
                    .map_err(CiError::Message)?;
                let recovered: serde_json::Value = serde_json::from_slice(&bytes)?;
                if recovered.get("schema_version") != Some(&serde_json::json!(1)) {
                    return Err(CiError::Message(
                        "worker recovery wrapper schema differs".into(),
                    ));
                }
                let response: memcordon_core::WindowsProviderResponseV3 = serde_json::from_value(
                    recovered.get("provider_response").cloned().ok_or_else(|| {
                        CiError::Message("worker recovery omitted provider response".into())
                    })?,
                )?;
                let held = live
                    .lock()
                    .map_err(|_| CiError::Message("component association poisoned".into()))?;
                rejected =
                    crate::windows_component_failed_recovery::worker_loss_recovery_authority(
                        &response,
                        held.as_ref().ok_or_else(|| {
                            CiError::Message("original held association absent".into())
                        })?,
                        &config.provider,
                    )
                    .map_err(CiError::Message)?;
            }
            if !rejected && fault.is_some() {
                let recovery_budget = deadlines.cleanup_budget(Duration::from_secs(90))?;
                let recovery_cutoff = Instant::now()
                    .checked_add(recovery_budget)
                    .ok_or_else(|| CiError::Message("terminal recovery cutoff overflow".into()))?;
                let recovery_cutoff = recovery_cutoff.min(deadlines.cleanup);
                if super::launcher_settlement_before_recovery(fault) {
                    let worker = worker.lock().map_err(|_| {
                        CiError::Message("component worker ownership poisoned".into())
                    })?;
                    let worker = worker.as_ref().ok_or_else(|| {
                        CiError::Message(
                            "selected peer loss lacks its original held launcher worker".into(),
                        )
                    })?;
                    let wait_started = Instant::now();
                    let native_status =
                        super::worker_wait::wait_until(&worker.thread, recovery_cutoff)?;
                    let process_retired = worker.process.has_exited()?;
                    retain(
                        &directory.join("held-launcher-settlement-before-recovery.json"),
                        &serde_json::to_vec(&serde_json::json!({
                            "format":"memcordon.windows-component-launcher-settlement","revision":1,
                            "attempt_id":attempt,"request_sha256":request,
                            "process_id":worker.process.identity.pid,"process_creation_time_100ns":worker.process.identity.birth,
                            "thread":worker.identity,"held_before_fault":true,"thread_exit_observed":true,
                            "selected_fault":fault,
                            "native_exit_status":native_status,"process_retirement_observed":process_retired,
                            "phase_budget_ms":recovery_budget.as_millis(),"wait_elapsed_ms":wait_started.elapsed().as_millis(),
                            "original_cleanup_deadline_unix_millis":input.original_cleanup_deadline_unix_millis,
                            "terminal_authority_still_required":true
                        }))?,
                        record,
                    )?;
                    if process_retired {
                        return Err(CiError::Message(
                            "selected peer loss unexpectedly retired its launcher service process"
                                .into(),
                        ));
                    }
                }
                let _restarted_service =
                    if let Some(role) = super::ServiceRecoveryRole::for_fault(fault) {
                        let owner = match role {
                            super::ServiceRecoveryRole::Control => &control_worker,
                            super::ServiceRecoveryRole::Launcher => &worker,
                        };
                        let original = owner.lock().map_err(|_| {
                            CiError::Message("service recovery worker ownership poisoned".into())
                        })?;
                        let original = original.as_ref().ok_or_else(|| {
                            CiError::Message("service recovery lacks original held owner".into())
                        })?;
                        Some(wait_service_recovery(
                            config,
                            input,
                            original,
                            role,
                            directory,
                            record,
                            recovery_cutoff,
                        )?)
                    } else {
                        None
                    };
                if fault
                    == Some(
                        memcordon_core::WindowsSealedFault::ControlServiceKilledAfterAuthorization,
                    )
                {
                    let control = control_worker.lock().map_err(|_| {
                        CiError::Message("control worker ownership poisoned".into())
                    })?;
                    let control = control.as_ref().ok_or_else(|| {
                        CiError::Message("original held control owner absent".into())
                    })?;
                    let frontend = frontend
                        .lock()
                        .map_err(|_| CiError::Message("frontend ownership poisoned".into()))?;
                    let frontend = frontend
                        .as_ref()
                        .ok_or_else(|| CiError::Message("original held frontend absent".into()))?;
                    let identity = |process: &memcordon_testkit::WindowsImageProcess| -> Result<memcordon_core::WindowsProcessIdentityV1> {
                        Ok(memcordon_core::WindowsProcessIdentityV1 { process_id: process.identity.pid,
                            creation_time_100ns: u64::try_from(process.identity.birth).map_err(|_| CiError::Message("native process birth exceeds u64".into()))? })
                    };
                    let site = control_site
                        .lock()
                        .map_err(|_| CiError::Message("control site ownership poisoned".into()))?;
                    let site = site.as_ref().ok_or_else(|| {
                        CiError::Message("original verified control site absent".into())
                    })?;
                    let association = live
                        .lock()
                        .map_err(|_| CiError::Message("component association poisoned".into()))?;
                    let association = association.as_ref().ok_or_else(|| {
                        CiError::Message("original held association absent".into())
                    })?;
                    if control.process.has_exited()? && frontend.has_exited()? {
                        observed_control_service_loss = control_service_loss_observation(
                            site,
                            &ControlServiceRetirement {
                                process: identity(&control.process)?,
                                thread: control.identity,
                                process_status: control.process.native_exit_status()?,
                                thread_status: worker_exit(control)?,
                                frontend: identity(frontend)?,
                                frontend_status: frontend.native_exit_status()?.ok_or_else(
                                    || {
                                        CiError::Message(
                                            "original frontend native exit absent".into(),
                                        )
                                    },
                                )?,
                            },
                            association,
                        );
                    }
                }
                let recovery_budget = recovery_cutoff
                    .checked_duration_since(Instant::now())
                    .filter(|budget| !budget.is_zero())
                    .ok_or_else(|| {
                        CiError::Message(
                            "original terminal recovery cutoff exhausted after worker settlement"
                                .into(),
                        )
                    })?;
                let mut recovery =
                    crate::command::CommandSpec::new(&config.cli.path, directory, recovery_budget)
                        .args(["windows-recover", "attempt", attempt, nonce, request])
                        .materialize()?;
                recovery.env_clear();
                retain(
                    &directory.join("terminal-recovery-invocation.json"),
                    &serde_json::to_vec(&serde_json::json!({
                        "format":"memcordon.windows-component-recovery-command","revision":1,
                        "run_id":input.run_id,"recipe_id":input.recipe_id,"native_target":input.native_target,
                        "executable_sha256":config.cli.sha256,
                        "program_utf16":recovery.get_program().encode_wide().collect::<Vec<_>>(),
                        "argv_utf16":recovery.get_args().map(|arg|arg.encode_wide().collect::<Vec<_>>()).collect::<Vec<_>>(),
                        "cwd_utf16":directory.as_os_str().encode_wide().collect::<Vec<_>>(),"environment_cleared":true,
                    }))?,
                    record,
                )?;
                let remaining = recovery_cutoff.checked_duration_since(Instant::now())
                    .filter(|budget| !budget.is_zero())
                    .ok_or_else(|| CiError::Message("original terminal recovery cutoff exhausted during command preparation".into()))?;
                let output = memcordon_testkit::run_with_deadline_output_limit(
                    &mut recovery,
                    remaining,
                    2 * 1024 * 1024,
                )
                .map_err(|error| CiError::Message(error.to_string()))?;
                retain(
                    &directory.join("terminal-recovery.json"),
                    &output.stdout,
                    record,
                )?;
                retain(
                    &directory.join("terminal-recovery.stderr.bin"),
                    &output.stderr,
                    record,
                )?;
                retain(
                    &directory.join("terminal-recovery-exit.json"),
                    &serde_json::to_vec(&serde_json::json!({
                        "format":"memcordon.windows-component-recovery-exit","revision":1,
                        "invocation_sha256":crate::windows_causal_acceptance::sha256(&read(&directory.join("terminal-recovery-invocation.json"),256*1024)?),
                        "stdout_sha256":crate::windows_causal_acceptance::sha256(&output.stdout),
                        "stderr_sha256":crate::windows_causal_acceptance::sha256(&output.stderr),"native_status":output.status.code(),
                    }))?,
                    record,
                )?;
                if let Err(error) = crate::command::require_successful_output(
                    "terminal authority recovery",
                    &output,
                ) {
                    recovery_failure = Some(error.to_string());
                }
                if output.status.success() || (fault==Some(memcordon_core::WindowsSealedFault::AllJobOwnersClosedAfterAuthorization)
                    &&output.status.code()==Some(1)) {
                    let recovered: serde_json::Value = serde_json::from_slice(&output.stdout)?;
                    let response: memcordon_core::WindowsProviderResponseV3 = serde_json::from_value(recovered.get("provider_response").cloned()
                        .ok_or_else(|| CiError::Message("component recovery omitted actual provider response".into()))?)?;
                    if fault==Some(memcordon_core::WindowsSealedFault::AllJobOwnersClosedAfterAuthorization)
                        &&recovered.get("schema_version")==Some(&serde_json::json!(1))
                        &&recovered.get("frontend_delivery").is_some_and(serde_json::Value::is_null)
                        &&matches!(&response,memcordon_core::WindowsProviderResponseV3::RecoveryAttemptUnavailable {
                            schema_version,attempt_id,challenge,detail } if *schema_version==memcordon_core::WINDOWS_PUBLIC_PROTOCOL_VERSION
                                &&attempt_id==attempt&&!challenge.is_empty()
                                &&detail=="exact recovery authority remains retained pending checked closure") {
                        // Exact authenticated uncertainty is the expected
                        // first observation. The later native convergence and
                        // retained process waits must independently settle
                        // physical ownership; this is never a terminal ACK.
                        rejected=true;
                    }
                    let selected_worker_original = if fault == Some(memcordon_core::WindowsSealedFault::LauncherWorkerKilledAfterAuthorization) {
                        let held = live.lock().map_err(|_| CiError::Message("component association poisoned".into()))?;
                        crate::windows_component_failed_recovery::worker_loss_recovery_authority(
                            &response, held.as_ref().ok_or_else(|| CiError::Message("original held association absent".into()))?,
                            &config.provider).map_err(CiError::Message)?
                    } else { false };
                    let receipt = match &response {
                        memcordon_core::WindowsProviderResponseV3::Terminal(receipt) => Some(receipt),
                        memcordon_core::WindowsProviderResponseV3::Reject { rejection, .. } => rejection.terminal_receipt(),
                        _ => None,
                    };
                    let selected_transport_original = fault.is_some_and(|selected|
                        matches!(&response, memcordon_core::WindowsProviderResponseV3::Reject { rejection, .. }
                            if rejection.provider_failure.as_ref().is_some_and(|failure|
                                transport_injection_authority(failure, selected, &config.provider, attempt, request))));
                    let selected_frontend_guardian_original = if let (Some(selected),Some(observed)) = (fault,observed_frontend_loss.as_ref()) {
                        let association = live.lock().map_err(|_| CiError::Message("component association poisoned".into()))?;
                        association.as_ref().is_some_and(|association|
                            matches!(&response,memcordon_core::WindowsProviderResponseV3::Reject {rejection,..}
                                if frontend_guardian_injection_authority(rejection,selected,&config.provider,attempt,request,association,observed)))
                    } else { false };
                    let selected_control_guardian_original = if let (Some(selected), Some(observed)) = (fault, observed_control_service_loss.as_ref()) {
                        let association = live.lock().map_err(|_| CiError::Message("component association poisoned".into()))?;
                        let delivery = recovered.get("frontend_delivery").cloned().and_then(|value|
                            serde_json::from_value::<memcordon_core::WindowsTerminalDeliveryEvidenceV1>(value).ok());
                        selected == memcordon_core::WindowsSealedFault::ControlServiceKilledAfterAuthorization
                            && association.as_ref().zip(delivery.as_ref()).is_some_and(|(association, delivery)|
                                control_service_recovery_authority(&response, delivery, association, observed))
                    } else { false };
                    if let Some(receipt) = receipt {
                        receipt.validate_for_attempt().map_err(|error| CiError::Message(error.into()))?;
                        if receipt.attempt_id == attempt && receipt.nonce == nonce && receipt.request_sha256 == request
                            && receipt.retirement_proof.provider_generation == config.provider.generation.as_str()
                            && ((fault == Some(memcordon_core::WindowsSealedFault::GuardianKilledAfterAuthorization)
                            && matches!(&receipt.payload, memcordon_core::WindowsTerminalPayloadV2::RecoveredClosure {
                                primary_failure: memcordon_core::OriginalFailureV1::Observed { event }, .. }
                                if event.sequence != 0 && event.operation == memcordon_core::FailureOperationV1::CheckGuardian
                                    && event.code == memcordon_core::FailureCodeV1::GuardianLoss
                                    && event.observed_phase == memcordon_core::AttemptObservationPhaseV1::Monitoring
                                    && event.native_code.is_none()))
                                || ((selected_transport_original || selected_frontend_guardian_original || selected_control_guardian_original) && receipt.execution().is_some_and(|(_, outcome, _)|
                                    matches!(outcome, memcordon_core::RunOutcome::MonitorFailed { .. })))
                                || (worker_loss && fault!=Some(memcordon_core::WindowsSealedFault::AllJobOwnersClosedAfterAuthorization)
                                    && if fault == Some(memcordon_core::WindowsSealedFault::LauncherWorkerKilledAfterAuthorization) {
                                        selected_worker_original
                                    } else { worker_recovery_receipt_authority(receipt, config.provider.generation.as_str(), attempt, nonce, request)? })
                                || fault.is_some_and(|selected| {
                                    use memcordon_core::WindowsSealedFault::*;
                                    matches!(selected, Resume | TerminateJob | ActiveProcessQuery | RelayRetire | GuardianReap | FinalHandleClose)
                                        && matches!(&receipt.payload, memcordon_core::WindowsTerminalPayloadV2::RecoveredClosure {
                                            primary_failure: memcordon_core::OriginalFailureV1::Observed { event }, .. }
                                            if event.sequence > 0
                                                && event.operation == memcordon_core::FailureOperationV1::UnclassifiedProviderOperation
                                                && event.code == memcordon_core::FailureCodeV1::UnexpectedProviderFailure
                                                && event.category == memcordon_core::FailureCategoryV1::Launch
                                                && event.native_code.is_none()
                                                && event.safe_detail == (memcordon_core::SafeDiagnosticDetailV1::InjectedWindowsFault { fault: selected })
                                                && event.observed_phase == if selected == Resume {
                                                    memcordon_core::AttemptObservationPhaseV1::AuthorizedBeforeResume
                                                } else { memcordon_core::AttemptObservationPhaseV1::Cleaning })
                                })) {
                            rejected = true;
                        }
                    }
                }
            }
            if !rejected {
                return Err(CiError::Message(format!(
                    "native injected fault lacks bound failure authority; natural/policy completion cannot substitute; selected-fault={fault:?}; attempt={attempt}; request={request}; retained-directory={}; recovery-context={}",
                    directory.display(),
                    recovery_failure
                        .as_deref()
                        .unwrap_or("no nonzero recovery command observed")
                )));
            }
            record.collection = Ok(());
            record.behavior = Ok(());
            Ok(())
        })();
        let retirement = (|| -> Result<()> {
            let recovery_budget = deadlines.cleanup_budget(Duration::from_secs(90))?;
            let recovery_cutoff = Instant::now()
                .checked_add(recovery_budget)
                .ok_or_else(|| {
                    CiError::Message("failed collection recovery cutoff overflow".into())
                })?
                .min(deadlines.cleanup);
            // Certification custody failure must remain a failure, but cannot
            // suppress the separately authenticated settlement of an attempt
            // whose original native association we held before the fault.
            if let Err(error) = &collection {
                // Query the original retained handles before recovery can
                // return early. This text is diagnostic only: live processes,
                // absent handles and query failures are all retained verbatim.
                // None of these observations supplies terminal authority.
                let mut status = Vec::new();
                writeln!(status, "diagnostic-only; certification-authority=false")?;
                writeln!(status, "original-collection-error={error}")?;
                match guardian.lock() {
                    Ok(held) => match held.as_ref() {
                        Some(held) => writeln!(
                            status,
                            "original-guardian={:?}; retired={:?}; native-exit-status={:?}; held-slot-current-state-pid-win32-service-specific={:?}",
                            held.identity,
                            held.has_retired(),
                            held.native_exit_status(),
                            held.service_exit_status()
                        )?,
                        None => writeln!(status, "original-guardian=not-held")?,
                    },
                    Err(error) => writeln!(status, "original-guardian-lock-error={error}")?,
                }
                match worker.lock() {
                    Ok(held) => match held.as_ref() {
                        Some(held) => writeln!(
                            status,
                            "original-worker-process={:?}; process-retired={:?}; process-native-exit-status={:?}; original-thread={:?}; thread-native-exit-status={:?}",
                            held.process.identity,
                            held.process.has_exited(),
                            held.process.native_exit_status(),
                            held.identity,
                            worker_exit(held)
                        )?,
                        None => writeln!(status, "original-worker=not-held")?,
                    },
                    Err(error) => writeln!(status, "original-worker-lock-error={error}")?,
                }
                match family.lock() {
                    Ok(held) => {
                        writeln!(status, "original-target-handle-count={}", held.len())?;
                        for target in held.iter() {
                            writeln!(
                                status,
                                "original-target={:?}; retired={:?}; native-exit-status={:?}",
                                target.identity,
                                target.has_exited(),
                                target.native_exit_status()
                            )?;
                        }
                    }
                    Err(error) => writeln!(status, "original-target-lock-error={error}")?,
                }
                retain(
                    &directory.join("held-owner-status-after-collection.txt"),
                    &status,
                    record,
                )?;
            }
            if fault
                == Some(memcordon_core::WindowsSealedFault::AllJobOwnersClosedAfterAuthorization)
            {
                let remaining = recovery_cutoff
                    .checked_duration_since(Instant::now())
                    .ok_or_else(|| {
                        CiError::Message("extinction staging deadline exhausted".into())
                    })?;
                let millis = remaining.as_millis().to_string();
                let mut staging =
                    crate::command::CommandSpec::new(&config.cli.path, directory, remaining)
                        .args(["windows-recover", "converge", millis.as_str()])
                        .materialize()?;
                staging.env_clear();
                let invocation = serde_json::to_vec(&serde_json::json!({
                    "format":"memcordon.windows-capability-extinction-staging-command","revision":1,
                    "run_id":input.run_id,"recipe_id":input.recipe_id,"source_commit":input.source_commit,
                    "provider":config.provider,"executable_sha256":config.cli.sha256,
                    "program_utf16":staging.get_program().encode_wide().collect::<Vec<_>>(),
                    "argv_utf16":staging.get_args().map(|arg|arg.encode_wide().collect::<Vec<_>>()).collect::<Vec<_>>(),
                    "cwd_utf16":directory.as_os_str().encode_wide().collect::<Vec<_>>(),"environment_cleared":true,
                    "original_cleanup_deadline_unix_millis":input.original_cleanup_deadline_unix_millis
                }))?;
                retain(
                    &directory.join("extinction-staging-invocation.json"),
                    &invocation,
                    record,
                )?;
                let output = memcordon_testkit::run_with_deadline_output_limit(
                    &mut staging,
                    remaining,
                    256 * 1024,
                )
                .map_err(|error| CiError::Message(error.to_string()))?;
                retain(
                    &directory.join("extinction-staging.json"),
                    &output.stdout,
                    record,
                )?;
                retain(
                    &directory.join("extinction-staging.stderr.bin"),
                    &output.stderr,
                    record,
                )?;
                retain(
                    &directory.join("extinction-staging-exit.json"),
                    &serde_json::to_vec(&serde_json::json!({
                        "format":"memcordon.windows-capability-extinction-staging-exit","revision":1,
                        "invocation_sha256":crate::windows_causal_acceptance::sha256(&invocation),
                        "stdout_sha256":crate::windows_causal_acceptance::sha256(&output.stdout),
                        "stderr_sha256":crate::windows_causal_acceptance::sha256(&output.stderr),"native_status":output.status.code()
                    }))?,
                    record,
                )?;
                let inventory: memcordon_core::WindowsRecoveryInventoryV1 =
                    serde_json::from_slice(&output.stdout)?;
                if !super::extinction_staging::accepts_pending_authority(
                    output.status.code(),
                    &inventory,
                    config.provider.generation.as_str(),
                ) {
                    return Err(CiError::Message(
                        "extinction staging did not retain exact terminal authority for caller ACK"
                            .into(),
                    ));
                }
                let held = live
                    .lock()
                    .map_err(|_| CiError::Message("component association poisoned".into()))?
                    .clone()
                    .ok_or_else(|| {
                        CiError::Message("extinction original association absent".into())
                    })?;
                recover_held_attempt(
                    config,
                    input,
                    directory,
                    record,
                    &held,
                    recovery_cutoff,
                    "extinction-terminal-recovery",
                    collection.is_err(),
                    None,
                )?;
                let recovered: serde_json::Value = serde_json::from_slice(&read(
                    &directory.join("extinction-terminal-recovery.json"),
                    256 * 1024,
                )?)?;
                let response: memcordon_core::WindowsProviderResponseV3 = serde_json::from_value(
                    recovered.get("provider_response").cloned().ok_or_else(|| {
                        CiError::Message("extinction terminal response absent".into())
                    })?,
                )?;
                retain(
                    &directory.join("extinction-terminal-authority.json"),
                    response
                        .terminal_authority_json()
                        .map_err(|error| CiError::Message(error.to_string()))?
                        .as_bytes(),
                    record,
                )?;
            }
            let failed_collection_recovery = if collection.is_err() {
                let held = live
                    .lock()
                    .map_err(|_| CiError::Message("component association poisoned".into()))?
                    .clone();
                held.as_ref()
                    .map(|held| {
                        recover_held_attempt(
                            config,
                            input,
                            directory,
                            record,
                            held,
                            recovery_cutoff,
                            "failed-collection-recovery",
                            true,
                            None,
                        )
                    })
                    .transpose()
                    .map(|_| ())
            } else {
                Ok(())
            };
            let recovery_budget = recovery_cutoff
                .checked_duration_since(Instant::now())
                .filter(|budget| !budget.is_zero())
                .ok_or_else(|| {
                    CiError::Message("original failed collection recovery cutoff exhausted".into())
                })?;
            let recovery_millis = recovery_budget.as_millis().to_string();
            let mut converge =
                crate::command::CommandSpec::new(&config.cli.path, directory, recovery_budget)
                    .args(["windows-recover", "converge", recovery_millis.as_str()])
                    .materialize()?;
            converge.env_clear();
            retain(
                &directory.join("recovery-invocation.json"),
                &serde_json::to_vec(&serde_json::json!({
                    "format":"memcordon.windows-component-settlement-command","revision":1,
                    "run_id":input.run_id,"recipe_id":input.recipe_id,"native_target":input.native_target,
                    "source_commit":input.source_commit,"executable_sha256":config.cli.sha256,
                    "program_utf16":converge.get_program().encode_wide().collect::<Vec<_>>(),
                    "argv_utf16":converge.get_args().map(|arg|arg.encode_wide().collect::<Vec<_>>()).collect::<Vec<_>>(),
                    "cwd_utf16":directory.as_os_str().encode_wide().collect::<Vec<_>>(),"environment_cleared":true,
                    "work_deadline_unix_millis":input.original_work_deadline_unix_millis,
                    "cleanup_deadline_unix_millis":input.original_cleanup_deadline_unix_millis
                }))?,
                record,
            )?;
            let output = memcordon_testkit::run_with_deadline_output_limit(
                &mut converge,
                recovery_budget,
                256 * 1024,
            )
            .map_err(|error| CiError::Message(error.to_string()))?;
            retain(&directory.join("recovery.json"), &output.stdout, record)?;
            retain(
                &directory.join("recovery.stderr.bin"),
                &output.stderr,
                record,
            )?;
            retain(
                &directory.join("recovery-exit.json"),
                &serde_json::to_vec(&serde_json::json!({
                    "format":"memcordon.windows-component-settlement-exit","revision":1,
                    "invocation_sha256":crate::windows_causal_acceptance::sha256(&read(&directory.join("recovery-invocation.json"),256*1024)?),
                    "stdout_sha256":crate::windows_causal_acceptance::sha256(&output.stdout),
                    "stderr_sha256":crate::windows_causal_acceptance::sha256(&output.stderr),"native_status":output.status.code()
                }))?,
                record,
            )?;
            if !output.status.success() {
                let excerpt = &output.stderr[..output.stderr.len().min(4096)];
                return Err(CiError::Message(format!(
                    "component native recovery command failed; status={:?}; stdout-bytes={}; stderr-bytes={}; stderr-truncated={}; stderr={:?}; original recovery records retained",
                    output.status,
                    output.stdout.len(),
                    output.stderr.len(),
                    excerpt.len() != output.stderr.len(),
                    String::from_utf8_lossy(excerpt),
                )));
            }
            failed_collection_recovery?;
            let inventory: memcordon_core::WindowsRecoveryInventoryV1 =
                serde_json::from_slice(&output.stdout)?;
            if !inventory.is_consistent()
                || inventory.authority_unsettled()
                || inventory.provider_generation != config.provider.generation.as_str()
                || !memcordon_testkit::windows_processes_for_image_until(
                    &config.fixture.path,
                    deadlines.cleanup,
                )?
                .is_empty()
            {
                return Err(CiError::Message(
                    "component native recovery retained authority or live fixture family".into(),
                ));
            }
            GuardianBaseline::quiescent(
                &config.installed_agent.path,
                &config.installed_manifest.path,
                &config.installed_agent.sha256,
                &config.installed_manifest.sha256,
            )?;
            if held_phase {
                let family = family
                    .lock()
                    .map_err(|_| CiError::Message("component family ownership poisoned".into()))?;
                let guardian = guardian.lock().map_err(|_| {
                    CiError::Message("component guardian ownership poisoned".into())
                })?;
                if family.len() != 1
                    || !family[0].has_exited()?
                    || !guardian
                        .as_ref()
                        .is_some_and(|guardian| guardian.has_retired().unwrap_or(false))
                {
                    return Err(CiError::Message(
                        "component held native family did not retire after fault".into(),
                    ));
                }
                let guardian_status = guardian
                    .as_ref()
                    .expect("checked held guardian")
                    .native_exit_status()?;
                if matches!(fault,Some(memcordon_core::WindowsSealedFault::GuardianKilledAfterAuthorization
                    |memcordon_core::WindowsSealedFault::AllJobOwnersClosedAfterAuthorization))&&guardian_status!=Some(0xC000_013A) {
                    return Err(CiError::Message("actual held guardian exit differs from selected native termination".into()));
                }
                retain(
                    &directory.join("held-after-fault.json"),
                    &serde_json::to_vec(&serde_json::json!({
                        "format":"memcordon.windows-component-held-retirement","revision":1,
                        "target_process_id":family[0].identity.pid,"target_creation_time_100ns":family[0].identity.birth,
                        "guardian":guardian.as_ref().expect("checked held guardian").identity,
                        "held_before_fault":true,"target_retired":true,"guardian_retired":true,"guardian_native_exit_status":guardian_status,
                        "target_native_exit_status":family[0].native_exit_status()?
                    }))?,
                    record,
                )?;
                if worker_loss {
                    let worker = worker.lock().map_err(|_| {
                        CiError::Message("component worker ownership poisoned".into())
                    })?;
                    let worker = worker.as_ref().ok_or_else(|| {
                        CiError::Message("component worker was not retained before release".into())
                    })?;
                    let status = worker_exit(worker)?;
                    if status != 0xC000_013A {
                        return Err(CiError::Message(
                            "component worker exit did not match selected native fault".into(),
                        ));
                    }
                    let process_retired = worker.process.has_exited()?;
                    if process_retired != launcher_process_loss {
                        return Err(CiError::Message("component launcher process retirement differs from selected thread/process action".into()));
                    }
                    if process_retired && worker.process.native_exit_status()? != Some(0xC000_013A)
                    {
                        return Err(CiError::Message(
                            "held launcher process status differs from actual selected termination"
                                .into(),
                        ));
                    }
                    retain(
                        &directory.join("held-worker-exit.json"),
                        &serde_json::to_vec(&serde_json::json!({
                            "format":"memcordon.windows-component-worker-exit","revision":1,
                            "process_id":worker.process.identity.pid,"process_creation_time_100ns":worker.process.identity.birth,
                            "thread":worker.identity,"held_before_fault":true,"exit_observed":true,"native_exit_status":status,
                            "process_retirement_observed":process_retired,"process_native_exit_status":worker.process.native_exit_status()?
                        }))?,
                        record,
                    )?;
                }
                if control_loss {
                    let worker = control_worker.lock().map_err(|_| {
                        CiError::Message("control worker ownership poisoned".into())
                    })?;
                    let worker = worker.as_ref().ok_or_else(|| {
                        CiError::Message("actual control worker was not held before release".into())
                    })?;
                    let status = worker_exit(worker)?;
                    let process_retired = worker.process.has_exited()?;
                    let process_status = worker.process.native_exit_status()?;
                    if !fault.is_some_and(|selected| {
                        control_retirement_matches(
                            selected,
                            status,
                            process_retired,
                            process_status,
                        )
                    }) {
                        return Err(CiError::Message(
                            "actual held control service status differs".into(),
                        ));
                    }
                    retain(
                        &directory.join("held-control-worker-exit.json"),
                        &serde_json::to_vec(&serde_json::json!({
                        "format":"memcordon.windows-component-control-worker-exit","revision":1,"process_id":worker.process.identity.pid,
                        "process_creation_time_100ns":worker.process.identity.birth,"thread":worker.identity,"held_before_fault":true,
                        "exit_observed":true,"native_exit_status":status,"process_retirement_observed":process_retired,
                        "process_native_exit_status":worker.process.native_exit_status()?}))?,
                        record,
                    )?;
                }
            }
            Ok(())
        })();
        record.retirement = retirement.as_ref().map(|_| ()).map_err(ToString::to_string);
        if let Err(error) = &collection {
            record.behavior = Err(error.to_string());
            record.collection = Err(error.to_string());
        }
        collection?;
        retirement
    }
}
