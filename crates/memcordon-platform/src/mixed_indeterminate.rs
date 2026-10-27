//! Preserve validated mixed terminal uncertainty without manufacturing target facts.
use crate::backend::Execution;
use memcordon_core::{
    BoundaryClass, BoundaryMechanismEvidence, BoundaryRequirement, CleanupErrorRecord,
    CleanupSummary, LaunchEvidence, RestartSafetyProof, RunOutcome,
    result_v2::{MixedAuthorizationKnowledgeV2, MixedRuntimeExecutionV2, MixedRuntimeOutcomeV2},
    workload_contract_v3::WorkloadContractV3,
};

const MONITOR_ERROR: &str =
    "mixed native ownership remains indeterminate; inspect retained protected obligations";
const CLEANUP_OPERATION: &str = "mixed-frontend/retirement";
pub(crate) const UNDRAINED: &str = "frontend mixed byte relay was not completely drained/restored";
pub(crate) const RELAY_OVERSIZE: &str = "mixed frontend relay error exceeded diagnostic bound";
pub(crate) const OBSERVATION_OVERSIZE: &str =
    "mixed retirement observation error exceeded diagnostic bound";

fn frontend_errors_match(native: &MixedRuntimeExecutionV2, prefix: &[&str]) -> bool {
    let mut actual = prefix.iter().copied();
    for (expected, oversize) in [
        (native.frontend.relay_error.as_ref(), RELAY_OVERSIZE),
        (
            native.frontend.observation_error.as_ref(),
            OBSERVATION_OVERSIZE,
        ),
    ] {
        if let Some(expected) = expected {
            let Some(value) = actual.next() else {
                return false;
            };
            if value != expected.as_str() && !(expected.as_str() == oversize && value.len() > 4096)
            {
                return false;
            }
        }
    }
    if !native.frontend.relay_drained && actual.next() != Some(UNDRAINED) {
        return false;
    }
    actual.next().is_none()
}

fn launch(mechanism: &str, released: bool) -> LaunchEvidence {
    LaunchEvidence {
        mechanism: mechanism.into(),
        target_released: released,
        containment_verified_before_authorization: released,
        guardian_started_before_authorization: released,
        target_spawn_error_reported: false,
        boundary_requested: BoundaryRequirement::Sealed,
        boundary_effective: if released {
            BoundaryClass::Sealed
        } else {
            BoundaryClass::Unavailable
        },
        boundary_assignment_verified: released,
        boundary_reconfiguration_denied: released,
        inherited_resources_restricted: released,
        frontend_loss_cleanup_authority_verified: released,
    }
}

fn binding<'a>(
    native: &'a MixedRuntimeExecutionV2,
    contract: &WorkloadContractV3,
) -> Option<(bool, Vec<&'a str>)> {
    native.runtime.validate().ok()?;
    contract.validate().ok()?;
    let MixedRuntimeOutcomeV2::Indeterminate {
        request_sha256,
        retained_obligations,
        ..
    } = &native.runtime.outcome
    else {
        return None;
    };
    if *request_sha256 != contract.digest().ok()? {
        return None;
    }
    Some((
        matches!(
            retained_obligations.authorization,
            MixedAuthorizationKnowledgeV2::Authorized
        ),
        retained_obligations
            .obligations
            .as_slice()
            .iter()
            .map(|value| value.as_str())
            .collect(),
    ))
}

/// Validate exactly the projection represented by the authenticated terminal schema.
pub(crate) fn consistent(execution: &Execution, contract: Option<&WorkloadContractV3>) -> bool {
    let Some(contract) = contract else {
        return false;
    };
    let BoundaryMechanismEvidence::LinuxMixedPrivate(native) = &execution.boundary_detail else {
        return false;
    };
    let Some((released, obligations)) = binding(native, contract) else {
        return false;
    };
    let RunOutcome::MonitorFailed {
        error,
        child_after_termination,
        cleanup,
    } = &execution.outcome
    else {
        return false;
    };
    let errors: Vec<_> = cleanup
        .errors
        .iter()
        .map(|value| value.message.as_str())
        .collect();
    execution.private_execution.is_none()
        && execution.runtime.is_none()
        && matches!(&execution.backend.boundary_support.sealed,crate::backend::SealedAvailability::Available{capability,..} if capability.class == BoundaryClass::Sealed && capability.mechanism == contract.authorized_profile.id.as_str())
        && execution.child_pid.is_none()
        && execution.authorization_offset.is_none()
        && matches!(
            execution.policy_enforcement,
            memcordon_core::workload_evidence::RuntimePolicyEnforcement::LegacyUnspecified
        )
        && execution.launch == launch(contract.authorized_profile.id.as_str(), released)
        && error == MONITOR_ERROR
        && child_after_termination.is_none()
        && !cleanup.graceful_attempted
        && !cleanup.force_attempted
        && !cleanup.direct_child_reaped
        && cleanup.workload_empty.is_none()
        && cleanup
            .errors
            .iter()
            .all(|value| value.operation == CLEANUP_OPERATION)
        && errors.ends_with(&obligations)
        && errors
            .len()
            .checked_sub(obligations.len())
            .is_some_and(|count| frontend_errors_match(native, &errors[..count]))
        && execution.restart_safety
            == RestartSafetyProof {
                errors: cleanup
                    .errors
                    .iter()
                    .map(|value| value.message.clone())
                    .collect(),
                ..RestartSafetyProof::default()
            }
}

#[cfg(any(target_os = "linux", feature = "test-support"))]
pub(crate) struct Projection<'a> {
    pub contract: &'a WorkloadContractV3,
    pub native: MixedRuntimeExecutionV2,
    pub frontend_errors: Vec<String>,
    pub backend: crate::backend::BackendInfo,
    pub duration: std::time::Duration,
}

#[cfg(any(target_os = "linux", feature = "test-support"))]
pub(crate) fn project(input: Projection<'_>) -> Result<Execution, Box<memcordon_core::Error>> {
    let invalid = || {
        let mut error = memcordon_core::Error::new(
            memcordon_core::ErrorCategory::Monitor,
            "MCSEALED-MIXED-TRANSACTION",
            "mixed indeterminate carrier or original request projection differs",
        );
        error.backend = Some(input.contract.authorized_profile.id.as_str().into());
        error.workload_may_be_alive = true;
        Box::new(error)
    };
    let (released, obligations) = binding(&input.native, input.contract).ok_or_else(invalid)?;
    let mut errors = input.frontend_errors;
    errors.extend(obligations.into_iter().map(str::to_owned));
    let cleanup = CleanupSummary {
        graceful_attempted: false,
        force_attempted: false,
        direct_child_reaped: false,
        workload_empty: None,
        errors: errors
            .iter()
            .map(|message| CleanupErrorRecord {
                operation: CLEANUP_OPERATION.into(),
                message: message.clone(),
            })
            .collect(),
    };
    let execution = Execution {
        private_execution: None,
        policy_enforcement: Default::default(),
        outcome: RunOutcome::MonitorFailed {
            error: MONITOR_ERROR.into(),
            child_after_termination: None,
            cleanup,
        },
        backend: input.backend,
        child_pid: None,
        runtime: None,
        duration: input.duration,
        authorization_offset: None,
        launch: launch(input.contract.authorized_profile.id.as_str(), released),
        restart_safety: RestartSafetyProof {
            errors,
            ..RestartSafetyProof::default()
        },
        boundary_detail: BoundaryMechanismEvidence::LinuxMixedPrivate(Box::new(input.native)),
    };
    if !consistent(&execution, Some(input.contract)) {
        return Err(invalid());
    }
    Ok(execution)
}

#[cfg(feature = "test-support")]
pub fn test_project(
    contract: &WorkloadContractV3,
    native: MixedRuntimeExecutionV2,
    backend: crate::backend::BackendInfo,
) -> Result<Execution, Box<memcordon_core::Error>> {
    let mut frontend_errors = native
        .frontend
        .relay_error
        .iter()
        .chain(native.frontend.observation_error.iter())
        .map(|text| text.as_str().to_owned())
        .collect::<Vec<_>>();
    if !native.frontend.relay_drained {
        frontend_errors.push(UNDRAINED.into());
    }
    project(Projection {
        contract,
        native,
        frontend_errors,
        backend,
        duration: std::time::Duration::ZERO,
    })
}
