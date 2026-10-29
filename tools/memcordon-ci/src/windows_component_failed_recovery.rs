//! Settlement binding for a failed certification capture. This does not grant
//! certification authority to either partial frames or a cleanup response.

use memcordon_core::{
    PublicProviderBindingV1, WindowsGuardianAttemptObservation, WindowsProviderResponseV4,
};

#[path = "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/publication_wait.rs"]
mod publication_wait;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryBinding {
    pub attempt: String,
    pub nonce: String,
    pub request: String,
    provider: PublicProviderBindingV1,
}

impl RecoveryBinding {
    pub fn from_held(
        held: &WindowsGuardianAttemptObservation,
        provider: &PublicProviderBindingV1,
    ) -> Result<Self, String> {
        if !held.is_consistent()
            || &held.association.provider != provider
            || held.live_target_identity.is_none()
            || held.worker_process_identity.is_none()
            || held.worker_thread_identity.is_none()
        {
            return Err("failed collection recovery association differs".into());
        }
        let nonce = held
            .live_nonce
            .as_ref()
            .filter(|nonce| !nonce.is_empty())
            .ok_or_else(|| "failed collection recovery nonce absent".to_owned())?;
        Ok(Self {
            attempt: String::from(held.association.attempt_id.clone()),
            nonce: nonce.clone(),
            request: String::from(held.association.request_sha256.clone()),
            provider: provider.clone(),
        })
    }

    pub fn validate_response(&self, response: &WindowsProviderResponseV4) -> Result<(), String> {
        if let WindowsProviderResponseV4::TerminalRetiredV2(retired) = response {
            if retired.provider_generation != self.provider.generation.as_str()
                || !retired.is_consistent_for(
                    &self.attempt,
                    &self.nonce,
                    &self.request,
                    &retired.terminal_response_sha256,
                )
            {
                return Err("failed collection retired binding differs".into());
            }
            return Ok(());
        }
        let receipt = match response {
            WindowsProviderResponseV4::Terminal(receipt) => Some(receipt),
            WindowsProviderResponseV4::Reject {
                schema_version,
                attempt_id,
                nonce,
                request_sha256,
                rejection,
            } if *schema_version == memcordon_core::WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION
                && attempt_id == &self.attempt
                && nonce == &self.nonce
                && request_sha256 == &self.request =>
            {
                rejection.terminal_receipt()
            }
            _ => None,
        }
        .ok_or_else(|| "failed collection recovery lacks terminal receipt".to_owned())?;
        receipt.validate_for_attempt().map_err(str::to_owned)?;
        if receipt.attempt_id != self.attempt
            || receipt.nonce != self.nonce
            || receipt.request_sha256 != self.request
            || receipt.retirement_proof.provider_generation != self.provider.generation.as_str()
        {
            return Err("failed collection recovery terminal binding differs".into());
        }
        Ok(())
    }
}

/// Admit an original guardian-loss execution receipt before its frontend ACK.
/// The caller still independently verifies the selected held guardian's native
/// termination and retirement; a later receipt-free tombstone is not authority.
pub fn guardian_loss_original_authority(
    response: &WindowsProviderResponseV4,
    selected: memcordon_core::WindowsSealedFault,
    held: &WindowsGuardianAttemptObservation,
    provider: &PublicProviderBindingV1,
) -> Result<bool, String> {
    use memcordon_core::*;
    if selected != WindowsSealedFault::GuardianKilledAfterAuthorization {
        return Ok(false);
    }
    let WindowsProviderResponseV4::Reject { rejection, .. } = response else {
        return Ok(false);
    };
    if rejection.code != "MCSEALED-WINDOWS-JOB-QUERY"
        || rejection.phase != BoundarySetupPhase::Monitoring
        || !rejection.target_created
        || !rejection.target_released
        || !rejection.cleanup_attempted
    {
        return Ok(false);
    }
    let binding = RecoveryBinding::from_held(held, provider)?;
    binding.validate_response(response)?;
    if !rejection.is_consistent() {
        return Err("original guardian rejection is inconsistent".into());
    }
    let Some(receipt) = rejection.terminal_receipt() else {
        return Ok(false);
    };
    let Some(failure) = rejection.provider_failure.as_ref() else {
        return Ok(false);
    };
    Ok(failure.is_consistent()
        && failure.provider_binding == *provider
        && String::from(failure.attempt_id.clone()) == binding.attempt
        && String::from(failure.request_sha256.clone()) == binding.request
        && matches!(&failure.original, OriginalFailureV1::Observed { event }
            if event.sequence > 0
                && event.origin == DiagnosticOriginV1::Launcher
                && event.category == FailureCategoryV1::Monitor
                && event.operation == FailureOperationV1::CheckGuardian
                && event.code == FailureCodeV1::GuardianLoss
                && event.native_code.is_none()
                && event.observed_phase == AttemptObservationPhaseV1::Monitoring
                && event.safe_detail == SafeDiagnosticDetailV1::NoAdditionalDetail)
        && receipt.process_observation.root_identity.as_ref() == held.live_target_identity.as_ref()
        && matches!(
            &receipt.payload,
            WindowsTerminalPayloadV3::Execution {
                outcome: RunOutcome::MonitorFailed { .. },
                ..
            }
        ))
}

/// Certifies only the actual authenticated worker-loss recovery response,
/// after the caller has independently required a complete original capture.
pub fn worker_loss_recovery_authority(
    response: &WindowsProviderResponseV4,
    held: &WindowsGuardianAttemptObservation,
    provider: &PublicProviderBindingV1,
) -> Result<bool, String> {
    let WindowsProviderResponseV4::Reject { rejection, .. } = response else {
        return Ok(false);
    };
    if rejection.code != "MCSEALED-WINDOWS-OWNER-LOST" {
        return Ok(false);
    }
    let binding = RecoveryBinding::from_held(held, provider)?;
    binding.validate_response(response)?;
    if !rejection.is_consistent() {
        return Err("worker recovery rejection is inconsistent".into());
    }
    let Some(receipt) = rejection.terminal_receipt() else {
        return Ok(false);
    };
    let Some(guardian) = rejection.guardian_causal_receipt.as_ref() else {
        return Ok(false);
    };
    Ok(matches!(
        guardian.cleanup_trigger,
        Some(memcordon_core::WindowsGuardianCleanupTriggerV1::WorkerLost)
    ) && guardian.guardian_identity == held.guardian_identity
        && Some(&guardian.worker_identity) == held.worker_process_identity.as_ref()
        && receipt.process_observation.root_identity.as_ref() == held.live_target_identity.as_ref()
        && receipt.retirement_proof.guardian_receipt_sha256.as_deref()
            == Some(guardian.integrity_sha256.as_str())
        && matches!(
            &receipt.payload,
            memcordon_core::WindowsTerminalPayloadV3::RecoveredClosure {
                primary_failure: memcordon_core::OriginalFailureV1::Unavailable {
                    reason:
                        memcordon_core::OriginalUnavailableReasonV1::WorkerLostBeforeObservation
                },
                ..
            }
        )
        && rejection.provider_failure.as_ref().is_none_or(|failure| {
            failure.provider_binding == *provider
                && String::from(failure.attempt_id.clone()) == binding.attempt
                && String::from(failure.request_sha256.clone()) == binding.request
        }))
}

/// The caller additionally requires duplicate-key-free captured bytes.
/// Only exact original relay closure or an observed publication WAIT_TIMEOUT
/// is a scheduling dependency. Neither response grants recovery authority.
pub fn pending_original_frontend_relay(
    wrapper: &serde_json::Value,
    held: &WindowsGuardianAttemptObservation,
    provider: &PublicProviderBindingV1,
    frontend: &memcordon_core::WindowsProcessIdentityV1,
    native_status: Option<i32>,
) -> Result<bool, String> {
    if native_status != Some(1) {
        return Ok(false);
    }
    if frontend.process_id == 0 || frontend.creation_time_100ns == 0 {
        return Err("original frontend recovery identity is invalid".into());
    }
    let binding = RecoveryBinding::from_held(held, provider)?;
    if wrapper.get("schema_version") != Some(&serde_json::json!(2))
        || !wrapper
            .get("frontend_delivery")
            .is_some_and(serde_json::Value::is_null)
    {
        return Ok(false);
    }
    let request: memcordon_core::WindowsProviderRequestV4 = serde_json::from_value(
        wrapper
            .get("provider_request")
            .cloned()
            .ok_or("recovery request absent")?,
    )
    .map_err(|error| error.to_string())?;
    let memcordon_core::WindowsProviderRequestV4::RecoverAttempt {
        schema_version,
        attempt_id,
        nonce,
        request_sha256,
        challenge,
    } = request
    else {
        return Ok(false);
    };
    if schema_version != memcordon_core::WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION
        || attempt_id != binding.attempt
        || nonce != binding.nonce
        || request_sha256 != binding.request
        || challenge.is_empty()
    {
        return Ok(false);
    }
    let response: WindowsProviderResponseV4 = serde_json::from_value(
        wrapper
            .get("provider_response")
            .cloned()
            .ok_or("recovery response absent")?,
    )
    .map_err(|error| error.to_string())?;
    let WindowsProviderResponseV4::RecoveryAttemptUnavailable {
        schema_version,
        attempt_id,
        challenge: response_challenge,
        detail,
    } = response
    else {
        return Ok(false);
    };
    let expected = format!(
        "exact recovery pending checked closure: frozen owner remains live without checked owner retirement; role=FrontendRelay; pid={}; birth={}",
        frontend.process_id, frontend.creation_time_100ns
    );
    let publication_busy =
        publication_wait::failure_detail(publication_wait::WAIT_TIMEOUT_STATUS, None)
            .expect("WAIT_TIMEOUT has a publication dependency detail");
    Ok(
        schema_version == memcordon_core::WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION
            && attempt_id == binding.attempt
            && response_challenge == challenge
            && (detail == expected || detail == publication_busy),
    )
}
