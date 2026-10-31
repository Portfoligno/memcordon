//! Current Windows native terminal and durable record formats.
use super::*;

/// Current public-wire4 launch input. Caller identity is always captured natively.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsLaunchRequestV2 {
    pub schema_version: u32,
    pub expected_provider_binding: crate::PublicProviderBindingV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_request: Option<crate::workload_request::WorkloadRequestV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loader_diagnostic: Option<Box<WindowsLoaderDiagnosticSelectionV1>>,
    pub restart_attempt: u64,
    pub nonce: String,
    pub command: NativeWindowsCommandV1,
    pub environment: Vec<WindowsEnvironmentEntryV1>,
    pub current_directory: Vec<u16>,
    pub policy: WindowsLaunchPolicyV1,
}

impl WindowsLaunchRequestV2 {
    pub fn validate_workload(&self) -> Result<(), String> {
        if self.schema_version != WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION {
            return Err("unsupported Windows launch format".into());
        }
        if let Some(request) = &self.workload_request {
            request.validate().map_err(|error| error.to_string())?;
            if !matches!(
                request.runtime,
                crate::workload_request::RuntimeRequestV1::WindowsSealed { .. }
            ) {
                return Err("unsupported Windows workload profile".into());
            }
            if !request.requirements.as_slice().is_empty() {
                return Err("unsupported Windows workload requirement".into());
            }
        }
        Ok(())
    }
}

/// Frozen current native terminal input retained only inside durable record5.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsTerminalSeedV2 {
    pub schema_version: u32,
    pub attempt_id: String,
    pub nonce: String,
    pub request_sha256: String,
    pub process_observation: crate::WindowsProcessObservationV2,
    pub primary_failure: Option<crate::ProviderFailureDiagnosticV1>,
    pub premature_release: Option<WindowsPrematureReleaseWitnessV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsTerminalReceiptV3 {
    pub schema_version: u32,
    pub attempt_id: String,
    pub nonce: String,
    pub request_sha256: String,
    pub payload: WindowsTerminalPayloadV3,
    pub process_observation: crate::WindowsProcessObservationV2,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup_process_creation: Option<WindowsCleanupProcessCreationEvidenceV1>,
    pub restart_safety: RestartSafetyProof,
    pub retirement_proof: WindowsRetirementProofV3,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum WindowsTerminalPayloadV3 {
    Execution {
        child_pid: u32,
        duration_millis: u64,
        authorization_offset_millis: u64,
        outcome: RunOutcome,
        boundary_detail: Box<BoundaryMechanismEvidence>,
    },
    RecoveredClosure {
        primary_failure: crate::OriginalFailureV1,
        target_creation_observed: bool,
        resume_attempted: bool,
    },
    PrematureReleaseFailure {
        witness: WindowsPrematureReleaseWitnessV1,
        child_pid: u32,
        duration_millis: u64,
        outcome: RunOutcome,
    },
}

impl WindowsTerminalReceiptV3 {
    pub fn execution(&self) -> Option<(u32, &RunOutcome, &BoundaryMechanismEvidence)> {
        match &self.payload {
            WindowsTerminalPayloadV3::Execution {
                child_pid,
                outcome,
                boundary_detail,
                ..
            } => Some((*child_pid, outcome, boundary_detail)),
            WindowsTerminalPayloadV3::RecoveredClosure { .. }
            | WindowsTerminalPayloadV3::PrematureReleaseFailure { .. } => None,
        }
    }

    pub fn validate_for_attempt(&self) -> Result<(), &'static str> {
        if self.schema_version != 3 {
            return Err("schema_version");
        }
        if self.attempt_id.is_empty() || self.nonce.is_empty() || self.request_sha256.is_empty() {
            return Err("attempt_binding");
        }
        self.process_observation
            .validate(&self.attempt_id, &self.nonce, &self.request_sha256)?;
        let proof = &self.retirement_proof;
        proof.validate()?;
        if proof.schema_version != 3
            || proof.attempt_id != self.attempt_id
            || proof.nonce != self.nonce
            || proof.request_sha256 != self.request_sha256
            || proof.provider_generation.is_empty()
            || proof.launch_incarnation.is_empty()
            || proof.original_boot_id.is_empty()
            || proof.job_identity.is_empty()
            || proof.owner_manifest_sha256.is_empty()
            || !proof.owner_capabilities_closed
            || !proof.launch_gate_closed
        {
            return Err("retirement_proof");
        }
        if proof.source != WindowsRetirementProofSourceV2::CapabilityExtinction
            && proof.capability_extinction.is_some()
        {
            return Err("retirement_proof.unexpected_capability_extinction");
        }
        match (&self.payload, proof.source) {
            (
                WindowsTerminalPayloadV3::PrematureReleaseFailure {
                    witness,
                    child_pid,
                    outcome,
                    ..
                },
                WindowsRetirementProofSourceV2::LiveNative,
            ) if witness.is_consistent()
                && self.cleanup_process_creation.is_none()
                && matches!(
                    outcome,
                    RunOutcome::MonitorFailed {
                        child_after_termination: Some(_),
                        ..
                    }
                )
                && proof.target_completion_observed
                && proof.native_job_empty_observed
                && proof.relay_closure_observed
                && proof.guardian_completion_observed
                && proof.guardian_receipt_sha256.is_none()
                && proof.current_boot_id.is_none()
                && *child_pid != 0
                && self
                    .process_observation
                    .root_identity
                    .as_ref()
                    .is_some_and(|root| root.process_id == *child_pid)
                && self.restart_safety.is_safe_for(BoundaryRequirement::Sealed) => {}
            (
                WindowsTerminalPayloadV3::Execution { child_pid, .. },
                WindowsRetirementProofSourceV2::LiveNative,
            ) if proof.target_completion_observed
                && proof.native_job_empty_observed
                && proof.relay_closure_observed
                && proof.guardian_completion_observed
                && proof.guardian_receipt_sha256.is_none()
                && proof.current_boot_id.is_none()
                && *child_pid != 0
                && self
                    .process_observation
                    .root_identity
                    .as_ref()
                    .is_some_and(|root| root.process_id == *child_pid) => {}
            (
                WindowsTerminalPayloadV3::RecoveredClosure {
                    primary_failure, ..
                },
                WindowsRetirementProofSourceV2::GuardianRecovery,
            ) if match primary_failure {
                crate::OriginalFailureV1::Observed { event } => event.sequence != 0,
                crate::OriginalFailureV1::Unavailable { reason } => {
                    *reason != crate::OriginalUnavailableReasonV1::NoEarlierErrorObserved
                }
            } && proof.native_job_empty_observed
                && proof.guardian_completion_observed
                && proof
                    .guardian_receipt_sha256
                    .as_deref()
                    .is_some_and(windows_sha256_text_is_valid)
                && proof.current_boot_id.is_none()
                && self.cleanup_process_creation.is_none() => {}
            (
                WindowsTerminalPayloadV3::RecoveredClosure {
                    primary_failure, ..
                },
                WindowsRetirementProofSourceV2::PriorBoot,
            ) if match primary_failure {
                crate::OriginalFailureV1::Observed { event } => event.sequence != 0,
                crate::OriginalFailureV1::Unavailable { reason } => {
                    *reason != crate::OriginalUnavailableReasonV1::NoEarlierErrorObserved
                }
            } && !proof.target_completion_observed
                && !proof.native_job_empty_observed
                && !proof.relay_closure_observed
                && !proof.guardian_completion_observed
                && proof.guardian_receipt_sha256.is_none()
                && proof
                    .current_boot_id
                    .as_deref()
                    .is_some_and(|boot| !boot.is_empty() && boot != proof.original_boot_id)
                && self.cleanup_process_creation.is_none() => {}
            (
                WindowsTerminalPayloadV3::RecoveredClosure {
                    primary_failure, ..
                },
                WindowsRetirementProofSourceV2::CapabilityExtinction,
            ) if match primary_failure {
                crate::OriginalFailureV1::Observed { event } => event.sequence != 0,
                crate::OriginalFailureV1::Unavailable { reason } => {
                    *reason != crate::OriginalUnavailableReasonV1::NoEarlierErrorObserved
                }
            } && !proof.target_completion_observed
                && !proof.native_job_empty_observed
                && !proof.relay_closure_observed
                && !proof.guardian_completion_observed
                && proof.guardian_receipt_sha256.is_none()
                && proof.current_boot_id.is_none()
                && self.cleanup_process_creation.is_none()
                && !self.restart_safety.direct_child_reaped
                && !self.restart_safety.helpers_reaped
                && !self.restart_safety.sealed_boundary_retired
                && self.restart_safety.workload_empty == Some(true)
                && self.restart_safety.containment_removed
                && self.restart_safety.containment_incapable_of_live_members
                && self.restart_safety.errors.is_empty()
                && proof
                    .capability_extinction
                    .as_ref()
                    .is_some_and(|extinction| {
                        let contract = &extinction.contract;
                        extinction.validate().is_ok()
                            && contract.attempt_id == proof.attempt_id
                            && contract.nonce == proof.nonce
                            && contract.request_sha256 == proof.request_sha256
                            && contract.provider_generation == proof.provider_generation
                            && contract.launch_incarnation == proof.launch_incarnation
                            && contract.original_boot_id == proof.original_boot_id
                            && contract.job_identity == proof.job_identity
                            && contract.owner_manifest_sha256 == proof.owner_manifest_sha256
                            && extinction
                                .owner_manifest
                                .entries
                                .iter()
                                .find(|entry| {
                                    entry.role
                                        == crate::WindowsCapabilityOwnerRoleV2::DirectTargetProcess
                                })
                                .and_then(|entry| entry.process_identity.as_ref())
                                == self.process_observation.root_identity.as_ref()
                    }) => {}
            _ => return Err("retirement_proof.source"),
        }
        if let WindowsTerminalPayloadV3::Execution {
            boundary_detail, ..
        } = &self.payload
        {
            if let BoundaryMechanismEvidence::WindowsJobObjectV3(native) = boundary_detail.as_ref()
            {
                native.validate()?;
                if native.target_identity != self.process_observation.root_identity
                    || native.process_observation.as_deref() != Some(&self.process_observation)
                {
                    return Err("boundary_detail.target_process_observation");
                }
                if native.frontend_delivery.is_some()
                    || native.frontend_provider_association.is_some()
                {
                    return Err("boundary_detail.frontend_delivery_before_ack");
                }
            } else {
                return Err("boundary_detail.current_windows_evidence");
            }
        }
        if matches!(self.payload, WindowsTerminalPayloadV3::Execution { .. })
            && !self.restart_safety.is_safe_for(BoundaryRequirement::Sealed)
        {
            return Err("restart_safety");
        }
        if self
            .cleanup_process_creation
            .as_ref()
            .is_some_and(|cleanup| !cleanup.is_consistent())
        {
            return Err("cleanup_process_creation");
        }
        Ok(())
    }

    pub fn validate_for_certification(
        &self,
        expected_attempt_binding: &str,
        required_job_total_processes: u32,
    ) -> Result<ValidatedWindowsCertificationTerminalV3<'_>, String> {
        self.validate_for_attempt().map_err(str::to_owned)?;
        let Some((_, outcome, boundary_detail)) = self.execution() else {
            return Err("kind".to_owned());
        };
        let accounting = self
            .process_observation
            .final_accounting
            .as_ref()
            .ok_or_else(|| "process_observation.final_accounting".to_owned())?;
        if accounting.total_processes_native_u32 < required_job_total_processes
            || !accounting.observed_after_target_retirement
            || accounting.active_processes_native_u32 != 0
        {
            return Err("process_observation.final_accounting".to_owned());
        }
        let cleanup = self
            .cleanup_process_creation
            .as_ref()
            .ok_or_else(|| "cleanup_process_creation".to_owned())?;
        if !cleanup.is_consistent()
            || cleanup.attempt_binding != expected_attempt_binding
            || accounting.total_processes_native_u32 < cleanup.total_processes_after
        {
            return Err("cleanup_process_creation".to_owned());
        }
        if !matches!(
            outcome,
            RunOutcome::Exited {
                child: ChildTermination::ExitCode { code: 0 },
                ..
            }
        ) {
            return Err("outcome.child".to_owned());
        }
        let BoundaryMechanismEvidence::WindowsJobObjectV3(native) = boundary_detail else {
            return Err("boundary_detail.variant".to_owned());
        };
        if !native.active_processes_zero
            || !native.direct_target_reaped
            || !native.guardian_reaped
            || !native.relays_retired
            || !native.final_job_handles_closed
        {
            return Err("boundary_detail.retirement".to_owned());
        }
        Ok(ValidatedWindowsCertificationTerminalV3 { native })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "disposition", rename_all = "kebab-case", deny_unknown_fields)]
pub enum WindowsProviderRejectionDispositionV3 {
    Preauthorization {
        terminal_ack_required: bool,
    },
    PostauthorizationFailure {
        receipt: Box<WindowsTerminalReceiptV3>,
    },
    PrematureReleaseFailure {
        receipt: Box<WindowsTerminalReceiptV3>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsProviderRejectionV3 {
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_failure: Option<crate::ProviderFailureDiagnosticV1>,
    /// Rehydrated only after authenticating the protected native receipt.
    /// This causal projection is excluded from immutable outbox/ACK authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guardian_causal_receipt: Option<Box<crate::WindowsGuardianReceiptV2>>,
    pub code: String,
    pub phase: crate::BoundarySetupPhase,
    pub detail: String,
    pub os_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loader_qualification: Option<crate::WindowsLoaderQualificationOutcomeV2>,
    pub target_created: bool,
    pub target_released: bool,
    pub cleanup_attempted: bool,
    pub restart_safety: RestartSafetyProof,
    pub disposition: WindowsProviderRejectionDispositionV3,
}

impl WindowsProviderRejectionV3 {
    pub fn terminal_ack_required(&self) -> bool {
        match self.disposition {
            WindowsProviderRejectionDispositionV3::Preauthorization {
                terminal_ack_required,
            } => terminal_ack_required,
            WindowsProviderRejectionDispositionV3::PostauthorizationFailure { .. }
            | WindowsProviderRejectionDispositionV3::PrematureReleaseFailure { .. } => true,
        }
    }

    pub fn terminal_receipt(&self) -> Option<&WindowsTerminalReceiptV3> {
        match &self.disposition {
            WindowsProviderRejectionDispositionV3::PostauthorizationFailure { receipt }
            | WindowsProviderRejectionDispositionV3::PrematureReleaseFailure { receipt } => {
                Some(receipt)
            }
            _ => None,
        }
    }

    pub fn is_consistent(&self) -> bool {
        if self.schema_version != 3
            || self.code.is_empty()
            || self.code.len() > 128
            || !self
                .code
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
            || self.detail.is_empty()
            || self.detail.len() > crate::PROVIDER_REJECTION_MAX_DETAIL_BYTES
            || self.detail.contains('\0')
            || (!self.target_created && self.target_released)
            || self
                .loader_qualification
                .as_ref()
                .is_some_and(|item| !item.is_consistent())
            || self.provider_failure.as_ref().is_some_and(|failure| {
                !failure.is_consistent() || failure.projection_sha256 != failure.canonical_digest()
            })
            || self
                .guardian_causal_receipt
                .as_ref()
                .is_some_and(|guardian| {
                    let Some(terminal) = self.terminal_receipt() else {
                        return true;
                    };
                    let proof = &terminal.retirement_proof;
                    !guardian.is_consistent()
                        || guardian.attempt_id != terminal.attempt_id
                        || guardian.nonce != terminal.nonce
                        || guardian.request_sha256 != terminal.request_sha256
                        || guardian.provider_generation != proof.provider_generation
                        || guardian.launch_incarnation != proof.launch_incarnation
                        || guardian.original_boot_id != proof.original_boot_id
                        || guardian.job_identity != proof.job_identity
                        || guardian.owner_manifest_sha256 != proof.owner_manifest_sha256
                })
        {
            return false;
        }
        match &self.disposition {
            WindowsProviderRejectionDispositionV3::PrematureReleaseFailure { receipt } => {
                self.target_created && self.target_released && self.cleanup_attempted
                    && receipt.validate_for_attempt().is_ok()
                    && matches!(receipt.payload, WindowsTerminalPayloadV3::PrematureReleaseFailure { .. })
                    && receipt.restart_safety == self.restart_safety
                    && self.provider_failure.as_ref().is_none_or(|failure| {
                        failure.provider_binding.generation.as_str() == receipt.retirement_proof.provider_generation
                            && String::from(failure.attempt_id.clone()) == receipt.attempt_id
                            && String::from(failure.request_sha256.clone()) == receipt.request_sha256
                            && matches!(failure.original, crate::OriginalFailureV1::Observed { ref event }
                            if event.sequence > 0)
                    })
            }
            WindowsProviderRejectionDispositionV3::Preauthorization {
                terminal_ack_required,
            } => !self.target_released && (!terminal_ack_required || self.cleanup_attempted),
            WindowsProviderRejectionDispositionV3::PostauthorizationFailure { receipt } => {
                let matching_authority = match &receipt.payload {
                    WindowsTerminalPayloadV3::Execution {
                        boundary_detail, ..
                    } => matches!(
                        boundary_detail.as_ref(),
                        crate::BoundaryMechanismEvidence::WindowsJobObjectV3(native)
                            if native.target_released == self.target_released
                    ),
                    WindowsTerminalPayloadV3::RecoveredClosure {
                        target_creation_observed,
                        resume_attempted,
                        ..
                    } => {
                        *target_creation_observed == self.target_created
                            && (!self.target_released || *resume_attempted)
                    }
                    WindowsTerminalPayloadV3::PrematureReleaseFailure { .. } => false,
                };
                // Expirable diagnostics are omitted from the immutable terminal
                // outbox. When present, they must still match its primary cause.
                let matching_primary = match (&receipt.payload, self.provider_failure.as_ref()) {
                    (
                        WindowsTerminalPayloadV3::Execution {
                            outcome: RunOutcome::MonitorFailed { .. },
                            ..
                        },
                        Some(failure),
                    ) => matches!(
                        failure.original,
                        crate::OriginalFailureV1::Observed { ref event }
                            if event.sequence > 0
                    ),
                    (
                        WindowsTerminalPayloadV3::Execution {
                            outcome: RunOutcome::MonitorFailed { .. },
                            ..
                        },
                        None,
                    ) => true,
                    // A held target cancelled before resume retires through the
                    // Reject carrier with its truthful Interrupted outcome.
                    (
                        WindowsTerminalPayloadV3::Execution {
                            outcome: RunOutcome::Interrupted { .. },
                            ..
                        },
                        diagnostic,
                    ) => !self.target_released && diagnostic.is_none_or(|failure| {
                        failure.provider_binding.generation.as_str() == receipt.retirement_proof.provider_generation
                            && String::from(failure.attempt_id.clone()) == receipt.attempt_id
                            && String::from(failure.request_sha256.clone()) == receipt.request_sha256
                            && matches!(failure.original,
                                crate::OriginalFailureV1::Observed { ref event } if event.sequence > 0)
                    }),
                    (
                        WindowsTerminalPayloadV3::RecoveredClosure {
                            primary_failure, ..
                        },
                        Some(failure),
                    ) => &failure.original == primary_failure,
                    (WindowsTerminalPayloadV3::RecoveredClosure { .. }, None) => true,
                    _ => false,
                };
                self.target_created
                    && self.cleanup_attempted
                    && receipt.validate_for_attempt().is_ok()
                    && receipt.restart_safety == self.restart_safety
                    && matching_authority
                    && matching_primary
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsDurableAttemptRecordV5 {
    pub schema_version: u32,
    pub attempt_id: String,
    pub provider_generation: String,
    pub boot_identity: String,
    pub launch_incarnation: String,
    pub nonce: String,
    pub request_sha256: String,
    pub caller_process_identity: WindowsProcessIdentityV1,
    pub caller_token_sha256: String,
    pub job_identity_sha256: String,
    pub guardian_identity: Option<WindowsProcessIdentityV1>,
    pub worker_identity: Option<WindowsProcessIdentityV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_thread_identity: Option<WindowsWorkerThreadIdentityV1>,
    pub target_identity: Option<WindowsProcessIdentityV1>,
    pub state: WindowsAttemptStateV1,
    pub lifecycle: WindowsTerminalLifecycleV1,
    pub authorization_unix_millis: Option<u64>,
    pub resume_attempted: bool,
    pub target_released: bool,
    pub cleanup_state: WindowsDurableCleanupStateV1,
    pub owner_manifest: Option<crate::WindowsCapabilityOwnerManifestV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_closure_contract: Option<crate::WindowsJobClosureContractV2>,
    pub recovery_authorization: Option<crate::WindowsRecoveryAuthorizationV1>,
    pub terminal_publication_reserved: bool,
    pub terminal_seed: Option<WindowsTerminalSeedV2>,
    pub retirement_proof: Option<WindowsRetirementProofV3>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::deserialize_record_outbox"
    )]
    pub terminal_response_json: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_disposition: Option<WindowsAttemptTerminalDispositionV1>,
    pub terminalization: WindowsTerminalizationStatusV1,
    pub causal_diagnostics: crate::WindowsCausalDiagnosticsV1,
    pub diagnostic_retention: crate::DiagnosticRetentionV1,
    pub record_revision: u64,
    pub provider_incarnation: String,
    pub integrity_sha256: String,
}

pub fn parse_and_authenticate_windows_attempt_record_v5(
    bytes: &[u8],
    expected_attempt_id: &str,
    expected_provider_generation: &str,
) -> Result<WindowsDurableAttemptRecordV5, &'static str> {
    if bytes.len() > WINDOWS_MAX_FRAME_BYTES
        || crate::validate_record_json_structure(bytes).is_err()
    {
        return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=structural-budget");
    }
    let mut record: WindowsDurableAttemptRecordV5 = serde_json::from_slice(bytes)
        .map_err(|_| "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=json-invalid")?;
    authenticate_decoded_windows_attempt_record_v5(
        &mut record,
        expected_attempt_id,
        expected_provider_generation,
    )?;
    Ok(record)
}

pub fn authenticate_decoded_windows_attempt_record_v5(
    record: &mut WindowsDurableAttemptRecordV5,
    expected_attempt_id: &str,
    expected_provider_generation: &str,
) -> Result<(), &'static str> {
    if record.schema_version != 5
        || record.attempt_id != expected_attempt_id
        || record.provider_generation != expected_provider_generation
        || !windows_sha256_text_is_valid(&record.attempt_id)
        || !windows_sha256_text_is_valid(&record.request_sha256)
        || !windows_sha256_text_is_valid(&record.job_identity_sha256)
        || !windows_sha256_text_is_valid(&record.caller_token_sha256)
        || !windows_sha256_text_is_valid(&record.provider_incarnation)
        || record.boot_identity.is_empty()
        || record.launch_incarnation.is_empty()
        || record.nonce.is_empty()
        || record.record_revision == 0
        || !windows_process_identity_is_valid(&record.caller_process_identity)
        || record
            .guardian_identity
            .as_ref()
            .is_some_and(|identity| !windows_process_identity_is_valid(identity))
        || record
            .worker_identity
            .as_ref()
            .is_some_and(|identity| !windows_process_identity_is_valid(identity))
        || record
            .target_identity
            .as_ref()
            .is_some_and(|identity| !windows_process_identity_is_valid(identity))
        || !record.causal_diagnostics.is_consistent()
        || !record.diagnostic_retention.is_consistent()
    {
        return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=v5-binding");
    }
    if let Some(error) = windows_durable_attempt_v5_state_error(record) {
        return Err(error);
    }
    if let Some(manifest) = &record.owner_manifest {
        if manifest.validate().is_err()
            || manifest.attempt_id != record.attempt_id
            || manifest.provider_generation != record.provider_generation
            || manifest.launch_incarnation != record.launch_incarnation
        {
            return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=owner-manifest");
        }
    }
    if let Some(contract) = &record.job_closure_contract {
        if contract.validate().is_err()
            || contract.attempt_id != record.attempt_id
            || contract.nonce != record.nonce
            || contract.request_sha256 != record.request_sha256
            || contract.provider_generation != record.provider_generation
            || contract.launch_incarnation != record.launch_incarnation
            || contract.original_boot_id != record.boot_identity
            || contract.job_identity != record.job_identity_sha256
            || record
                .owner_manifest
                .as_ref()
                .and_then(|manifest| manifest.canonical_sha256().ok())
                .as_deref()
                != Some(contract.owner_manifest_sha256.as_str())
        {
            return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=job-closure-contract");
        }
    }
    let preauthorization_abort_release = record.target_released
        && record.authorization_unix_millis.is_none()
        && !record.resume_attempted
        && record.terminal_disposition
            == Some(WindowsAttemptTerminalDispositionV1::PreauthorizationAbort);
    let authorized_intent = record.authorization_unix_millis.is_some()
        || record.resume_attempted
        || (record.target_released && !preauthorization_abort_release);
    if authorized_intent && record.owner_manifest.is_none() {
        return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=owner-manifest-absent");
    }
    if record
        .recovery_authorization
        .as_ref()
        .is_some_and(|authorization| !authorization.is_consistent())
    {
        return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=recovery-authorization");
    }
    if authorized_intent
        && (record.recovery_authorization.is_none()
            || !record.terminal_publication_reserved
            || record.worker_identity.is_none())
    {
        return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=authorization-reservation");
    }
    if let Some(seed) = &record.terminal_seed {
        if seed.schema_version != 2
            || seed.attempt_id != record.attempt_id
            || seed.nonce != record.nonce
            || seed.request_sha256 != record.request_sha256
            || seed
                .process_observation
                .validate(&record.attempt_id, &record.nonce, &record.request_sha256)
                .is_err()
            || seed
                .primary_failure
                .as_ref()
                .is_some_and(|failure| !failure.is_consistent())
            || match (
                record
                    .terminal_disposition
                    .and_then(|value| value.premature_release_mutant()),
                seed.premature_release.as_ref(),
            ) {
                (Some(mutant), Some(witness)) => {
                    !witness.is_consistent()
                        || witness.mutant != mutant
                        || !record.target_released
                        || record.authorization_unix_millis.is_some()
                        || record.resume_attempted
                }
                (None, None) => false,
                _ => true,
            }
        {
            return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=terminal-seed");
        }
    }
    if let Some(proof) = &record.retirement_proof {
        if proof.schema_version != 3
            || proof.attempt_id != record.attempt_id
            || proof.nonce != record.nonce
            || proof.request_sha256 != record.request_sha256
            || proof.provider_generation != record.provider_generation
            || proof.launch_incarnation != record.launch_incarnation
            || proof.original_boot_id != record.boot_identity
            || proof.job_identity != record.job_identity_sha256
            || record
                .owner_manifest
                .as_ref()
                .and_then(|manifest| manifest.canonical_sha256().ok())
                .as_deref()
                != Some(proof.owner_manifest_sha256.as_str())
            || proof
                .capability_extinction
                .as_ref()
                .is_some_and(|extinction| {
                    record.job_closure_contract.as_ref() != Some(&extinction.contract)
                        || record.owner_manifest.as_ref() != Some(&extinction.owner_manifest)
                })
        {
            return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=retirement-proof");
        }
    }
    let has_complete_proof = record.terminal_seed.is_some() && record.retirement_proof.is_some();
    let proof_checkpoint_valid = match record.lifecycle {
        WindowsTerminalLifecycleV1::ProofReady => has_complete_proof,
        WindowsTerminalLifecycleV1::OutboxStaged
        | WindowsTerminalLifecycleV1::AckCommitted
        | WindowsTerminalLifecycleV1::RetirementComplete => {
            if record.terminal_disposition
                == Some(WindowsAttemptTerminalDispositionV1::PreauthorizationAbort)
            {
                record.terminal_seed.is_none() && record.retirement_proof.is_none()
            } else {
                has_complete_proof
            }
        }
        _ => true,
    };
    if !proof_checkpoint_valid {
        return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=proof-checkpoint");
    }
    if matches!(
        record.lifecycle,
        WindowsTerminalLifecycleV1::OutboxStaged
            | WindowsTerminalLifecycleV1::AckCommitted
            | WindowsTerminalLifecycleV1::RetirementComplete
    ) && record.terminal_response_json.is_none()
    {
        return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=outbox-checkpoint");
    }
    if let Some(json) = &record.terminal_response_json {
        let response: WindowsLauncherResponseV4 = serde_json::from_str(json)
            .map_err(|_| "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=outbox-json")?;
        if !windows_terminal_outbox_is_bound_v4(record, &response) {
            return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=outbox-binding");
        }
    }
    let integrity = std::mem::take(&mut record.integrity_sha256);
    let mut canonical = crate::bounded_json_bytes(record, WINDOWS_MAX_FRAME_BYTES, false)
        .map_err(|_| "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=canonicalization-failed")?;
    canonical.pop();
    let expected = windows_sha256(&canonical);
    record.integrity_sha256 = integrity;
    if record.integrity_sha256 != expected {
        return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=integrity-digest");
    }
    Ok(())
}

fn windows_durable_attempt_v5_state_error(
    record: &WindowsDurableAttemptRecordV5,
) -> Option<&'static str> {
    let premature_release = record
        .terminal_disposition
        .and_then(|value| value.premature_release_mutant())
        .is_some();
    if matches!(
        record.terminal_disposition,
        Some(WindowsAttemptTerminalDispositionV1::PrematureReleaseFailure { .. })
    ) && (!premature_release
        || record.authorization_unix_millis.is_some()
        || record.resume_attempted
        || record.owner_manifest.is_none()
        || !record.cleanup_state.termination_requested
        || !matches!(
            record.state,
            WindowsAttemptStateV1::Terminating | WindowsAttemptStateV1::Empty
        ))
    {
        return Some("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=premature-release-intent");
    }
    let guardian_required = matches!(
        record.state,
        WindowsAttemptStateV1::GuardianReady
            | WindowsAttemptStateV1::TargetCreatedSuspended
            | WindowsAttemptStateV1::Authorized
    );
    let preauthorization_abort = !record.resume_attempted
        && record.authorization_unix_millis.is_none()
        && record.terminal_disposition
            == Some(WindowsAttemptTerminalDispositionV1::PreauthorizationAbort)
        && matches!(
            record.state,
            WindowsAttemptStateV1::Terminating | WindowsAttemptStateV1::Empty
        )
        && record.cleanup_state.termination_requested;
    let target_required = matches!(
        record.state,
        WindowsAttemptStateV1::TargetCreatedSuspended | WindowsAttemptStateV1::Authorized
    ) || record.resume_attempted
        || record.target_released;
    if guardian_required && record.guardian_identity.is_none() {
        return Some("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=lifecycle-guardian-missing");
    }
    if target_required && record.target_identity.is_none() && !preauthorization_abort {
        return Some("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=lifecycle-target-missing");
    }
    if record.target_released
        && !record.resume_attempted
        && !preauthorization_abort
        && !premature_release
    {
        return Some(
            "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=lifecycle-release-without-intent",
        );
    }
    if record.resume_attempted && record.authorization_unix_millis.is_none() {
        return Some(
            "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=lifecycle-resume-without-authorization",
        );
    }
    if record.state == WindowsAttemptStateV1::Authorized
        && record.authorization_unix_millis.is_none()
    {
        return Some(
            "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=lifecycle-authorized-without-timestamp",
        );
    }
    if record.authorization_unix_millis.is_some()
        && !matches!(
            record.state,
            WindowsAttemptStateV1::Authorized
                | WindowsAttemptStateV1::Terminating
                | WindowsAttemptStateV1::Empty
        )
    {
        return Some(
            "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=lifecycle-authorization-before-state",
        );
    }
    if record.terminal_disposition
        == Some(WindowsAttemptTerminalDispositionV1::PreauthorizationAbort)
        && !matches!(
            record.state,
            WindowsAttemptStateV1::Terminating | WindowsAttemptStateV1::Empty
        )
    {
        return Some(
            "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=lifecycle-abort-before-termination",
        );
    }
    if record.cleanup_state.final_handles_closed
        && !(record.cleanup_state.termination_requested
            && record.cleanup_state.active_processes_zero
            && record.cleanup_state.guardian_reaped
            && record.state == WindowsAttemptStateV1::Empty)
    {
        return Some(
            "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=lifecycle-final-handles-before-empty",
        );
    }
    if !record.terminalization.is_consistent() {
        return Some("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=terminalization-status");
    }
    if record.terminal_response_json.is_some()
        != (record.terminalization.checkpoint == WindowsTerminalizationCheckpointV1::OutboxStaged)
    {
        return Some(
            "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=terminalization-outbox-checkpoint",
        );
    }
    if matches!(
        record.terminalization.checkpoint,
        WindowsTerminalizationCheckpointV1::CleanupProofReady
            | WindowsTerminalizationCheckpointV1::RejectionBuilding
            | WindowsTerminalizationCheckpointV1::OutboxStaging
            | WindowsTerminalizationCheckpointV1::OutboxStaged
            | WindowsTerminalizationCheckpointV1::AckRetiring
    ) && record.state != WindowsAttemptStateV1::Empty
    {
        return Some(
            "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=terminalization-checkpoint-before-empty",
        );
    }
    if record.terminal_response_json.is_some()
        && (record.state != WindowsAttemptStateV1::Empty || record.terminal_disposition.is_none())
    {
        return Some("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=terminal-outbox-before-empty");
    }
    None
}

pub fn windows_terminal_outbox_is_bound_v4(
    record: &WindowsDurableAttemptRecordV5,
    response: &WindowsLauncherResponseV4,
) -> bool {
    let receipt_bound = |receipt: &WindowsTerminalReceiptV3| {
        receipt.attempt_id == record.attempt_id
            && receipt.nonce == record.nonce
            && receipt.request_sha256 == record.request_sha256
            && record.retirement_proof.as_ref() == Some(&receipt.retirement_proof)
            && receipt.validate_for_attempt().is_ok()
    };
    match response {
        WindowsLauncherResponseV4::Terminal(receipt) => {
            record.terminal_disposition == Some(WindowsAttemptTerminalDispositionV1::Posttarget)
                && receipt_bound(receipt)
        }
        WindowsLauncherResponseV4::Reject {
            attempt_id,
            nonce,
            request_sha256,
            rejection,
            ..
        } => {
            attempt_id == &record.attempt_id
                && nonce == &record.nonce
                && request_sha256 == &record.request_sha256
                && rejection.is_consistent()
                && match (record.terminal_disposition, &rejection.disposition) {
                    (
                        Some(WindowsAttemptTerminalDispositionV1::PrematureReleaseFailure {
                            mutant,
                        }),
                        WindowsProviderRejectionDispositionV3::PrematureReleaseFailure { receipt },
                    ) => {
                        receipt_bound(receipt)
                            && record.authorization_unix_millis.is_none()
                            && !record.resume_attempted
                            && record.target_released
                            && record.target_identity == receipt.process_observation.root_identity
                            && record.terminal_seed.as_ref().is_some_and(|seed| {
                                seed.process_observation == receipt.process_observation
                            })
                            && matches!(&receipt.payload,
                            WindowsTerminalPayloadV3::PrematureReleaseFailure { witness, .. }
                                if witness.mutant == mutant
                                    && record.terminal_seed.as_ref()
                                        .and_then(|seed| seed.premature_release.as_ref()) == Some(witness))
                    }
                    (
                        Some(WindowsAttemptTerminalDispositionV1::PreauthorizationAbort),
                        WindowsProviderRejectionDispositionV3::Preauthorization { .. },
                    ) => true,
                    (
                        Some(WindowsAttemptTerminalDispositionV1::Posttarget),
                        WindowsProviderRejectionDispositionV3::PostauthorizationFailure { receipt },
                    ) => receipt_bound(receipt),
                    _ => false,
                }
        }
        _ => false,
    }
}

impl WindowsProviderResponseV4 {
    /// Report preparation failure without granting terminal or retirement authority.
    pub fn recovery_attempt_unavailable(
        attempt_id: &str,
        challenge: &str,
        detail: &str,
        native_detail_allowed: bool,
    ) -> Result<Self, String> {
        const DETAIL_LIMIT: usize = 1024;
        const TRUNCATED: &str = " [detail truncated]";
        let attempt_id = crate::BoundedText::<128>::new(attempt_id).map_err(str::to_owned)?;
        let challenge = crate::BoundedText::<128>::new(challenge).map_err(str::to_owned)?;
        if attempt_id.as_str().is_empty() || challenge.as_str().is_empty() {
            return Err("recovery unavailability context is empty".into());
        }
        let detail = if native_detail_allowed {
            if detail.is_empty() {
                return Err("recovery preparation error is empty".into());
            }
            detail
        } else {
            "recovery preparation unavailable"
        };
        let detail = if detail.len() > DETAIL_LIMIT {
            let mut end = DETAIL_LIMIT - TRUNCATED.len();
            while !detail.is_char_boundary(end) {
                end -= 1;
            }
            format!("{}{TRUNCATED}", &detail[..end])
        } else {
            detail.to_owned()
        };
        Ok(Self::RecoveryAttemptUnavailable {
            schema_version: WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION,
            challenge: challenge.as_str().to_owned(),
            attempt_id: attempt_id.as_str().to_owned(),
            detail,
        })
    }
}

#[derive(Debug)]
pub struct ValidatedWindowsCertificationTerminalV3<'a> {
    pub native: &'a WindowsSealedEvidenceV3,
}

/// Native observations before a terminal proof exists. This is deliberately not
/// a historical terminal wire document or a claim of validated retirement.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsNativeTerminalObservationV1 {
    pub attempt_id: String,
    pub nonce: String,
    pub request_sha256: String,
    pub child_pid: u32,
    pub duration_millis: u64,
    pub authorization_offset_millis: u64,
    pub job_total_processes: u32,
    pub job_process_identities: Vec<WindowsProcessIdentityV1>,
    pub cleanup_process_creation: Option<WindowsCleanupProcessCreationEvidenceV1>,
    pub outcome: crate::RunOutcome,
    pub restart_safety: crate::RestartSafetyProof,
    pub boundary_detail: crate::BoundaryMechanismEvidence,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsMutantNativeReceiptV2 {
    pub schema_version: u32,
    pub mutant: WindowsSealedMutant,
    pub attempt_id: String,
    pub nonce: String,
    pub request_sha256: String,
    pub hook_observation: WindowsMutantHookObservationV1,
    pub remote_observation_handle: Option<u64>,
    pub terminal_candidate: Option<Box<WindowsNativeTerminalObservationV1>>,
}
impl WindowsMutantNativeReceiptV2 {
    pub fn binding_matches(&self, attempt_id: &str, nonce: &str, request_sha256: &str) -> bool {
        self.schema_version == 2
            && !self.nonce.is_empty()
            && self.attempt_id == attempt_id
            && self.nonce == nonce
            && self.request_sha256 == request_sha256
    }
}
pub type WindowsProviderResponseV4 = WindowsProviderResponse<
    WindowsTerminalReceiptV3,
    WindowsProviderRejectionV3,
    WindowsMutantNativeReceiptV2,
>;
pub type WindowsLauncherResponseV4 = WindowsLauncherResponse<
    WindowsTerminalReceiptV3,
    WindowsProviderRejectionV3,
    WindowsMutantNativeReceiptV2,
>;

/// Native target and immutable owner-set commitment while the target is still
/// suspended. This is a current launch phase, never proof of target release.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsWorkloadPreparedV1 {
    pub format: String,
    pub revision: u32,
    pub attempt_id: String,
    pub nonce: String,
    pub request_sha256: String,
    pub target: WindowsProcessIdentityV1,
    pub owner_manifest_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsWorkloadAcceptedV1 {
    pub format: String,
    pub revision: u32,
    pub provider: crate::PublicProviderBindingV1,
    pub frontend: WindowsProcessIdentityV1,
    pub attempt_id: String,
    pub nonce: String,
    pub request_sha256: String,
    pub setup_deadline_millis: u64,
}

impl WindowsWorkloadAcceptedV1 {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.format != "memcordon.windows-workload-accepted"
            || self.revision != 1
            || !self.provider.is_consistent()
            || self.frontend.process_id == 0
            || self.nonce.is_empty()
            || self.nonce.len() > 128
            || self.setup_deadline_millis == 0
            || !windows_sha256_text_is_valid(&self.attempt_id)
            || !windows_sha256_text_is_valid(&self.request_sha256)
        {
            return Err("invalid native Windows preallocation binding");
        }
        Ok(())
    }
    pub fn canonical_sha256(&self) -> Result<String, String> {
        self.validate().map_err(str::to_owned)?;
        Ok(crate::hash_bytes(&serde_json::to_vec(self).map_err(|error| error.to_string())?).into())
    }
}

/// Emitted only before admission reservation or private native dispatch, after
/// closing the actual caller-token and caller-process handles captured by control.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsPreallocationCancellationV1 {
    pub format: String,
    pub revision: u32,
    pub accepted: WindowsWorkloadAcceptedV1,
    pub signal: i32,
    pub primary_token_closed: bool,
    pub frontend_process_handle_closed: bool,
}

impl WindowsPreallocationCancellationV1 {
    pub fn validate(&self) -> Result<(), &'static str> {
        self.accepted.validate()?;
        if self.format != "memcordon.windows-preallocation-cancellation"
            || self.revision != 1
            || !(1..=127).contains(&self.signal)
            || !self.primary_token_closed
            || !self.frontend_process_handle_closed
        {
            return Err("invalid native preallocation cancellation/handle closure");
        }
        Ok(())
    }
    pub fn exit_code(&self) -> i32 {
        128 + self.signal
    }
}

impl WindowsWorkloadPreparedV1 {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.format != "memcordon.windows-workload-prepared"
            || self.revision != 1
            || self.target.process_id == 0
            || self.nonce.is_empty()
            || [
                &self.attempt_id,
                &self.request_sha256,
                &self.owner_manifest_sha256,
            ]
            .into_iter()
            .any(|value| {
                value.len() != 64
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
        {
            return Err("invalid current Windows prepared binding");
        }
        Ok(())
    }

    pub fn canonical_sha256(&self) -> Result<String, String> {
        self.validate().map_err(str::to_owned)?;
        Ok(crate::hash_bytes(&serde_json::to_vec(self).map_err(|error| error.to_string())?).into())
    }
}

impl ExpirableRejectionDiagnostics for WindowsProviderRejectionV3 {
    fn clear_expirable_diagnostics(&mut self) {
        self.provider_failure = None;
        self.guardian_causal_receipt = None;
        if let Some(crate::WindowsLoaderQualificationOutcomeV2::Failed(failure)) =
            self.loader_qualification.as_mut()
        {
            failure.support_debug_observation = None;
        }
    }
}
terminal_authority_encoding!(WindowsProviderResponseV4);
terminal_authority_encoding!(WindowsLauncherResponseV4);
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "message", rename_all = "kebab-case", deny_unknown_fields)]
pub enum WindowsProviderRequestV4 {
    PreparationAcknowledged {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        accepted_sha256: String,
    },
    PreparedAcknowledged {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        prepared_sha256: String,
    },
    CertificationControlReleased {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        fault: WindowsSealedFault,
        target_pid: u32,
    },
    LoaderDiagnosticLaunch {
        schema_version: u32,
        attempt_id: String,
        request_sha256: String,
        caller_process_identity: WindowsProcessIdentityV1,
        launch: WindowsLaunchRequestV2,
    },
    Probe {
        schema_version: u32,
    },
    ObserveGuardianAttempt {
        schema_version: u32,
        challenge: String,
        guardian_identity: WindowsProcessIdentityV1,
    },
    RecoveryStatus {
        schema_version: u32,
        challenge: String,
    },
    RecoverAttempt {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        challenge: String,
    },
    ConvergeRecovery {
        schema_version: u32,
        challenge: String,
        deadline_millis: u64,
    },
    PackageCleanup {
        schema_version: u32,
        challenge: String,
        deadline_millis: u64,
    },
    CertificationFault {
        schema_version: u32,
        fault: WindowsSealedFault,
        attempt_id: String,
        request_sha256: String,
        caller_process_identity: WindowsProcessIdentityV1,
        launch: WindowsLaunchRequestV2,
    },
    CertificationMutant {
        schema_version: u32,
        mutant: WindowsSealedMutant,
        attempt_id: String,
        request_sha256: String,
        caller_process_identity: WindowsProcessIdentityV1,
        launch: WindowsLaunchRequestV2,
    },
    CertificationMachineRestart {
        schema_version: u32,
    },
    Launch(WindowsLaunchRequestV2),
    RelaysReady {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
    },
    Cancel {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        signal: i32,
    },
    RelaysRetired {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
    },
    TerminalAcknowledged {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        terminal_response_sha256: String,
    },
    ReplayTerminal {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        relay_phase: WindowsRelayPhaseV1,
    },
}

impl WindowsProviderRequestV4 {
    pub fn terminal_drain_control(
        &self,
        attempt: &str,
        nonce: &str,
        request: &str,
        terminal: &str,
    ) -> Option<WindowsTerminalDrainControl> {
        match self {
            Self::Cancel {
                schema_version: 4,
                attempt_id,
                nonce: actual_nonce,
                request_sha256,
                signal,
            } if attempt_id == attempt
                && actual_nonce == nonce
                && request_sha256 == request
                && (1..=127).contains(signal) =>
            {
                Some(WindowsTerminalDrainControl::Cancellation)
            }
            Self::TerminalAcknowledged {
                schema_version: 4,
                attempt_id,
                nonce: actual_nonce,
                request_sha256,
                terminal_response_sha256,
            } if attempt_id == attempt
                && actual_nonce == nonce
                && request_sha256 == request
                && terminal_response_sha256 == terminal =>
            {
                Some(WindowsTerminalDrainControl::Acknowledgment)
            }
            _ => None,
        }
    }
    pub fn control_release_binds(
        &self,
        expected_attempt: &str,
        expected_nonce: &str,
        expected_request: &str,
        expected_fault: WindowsSealedFault,
        expected_target: u32,
    ) -> bool {
        matches!(
            expected_fault,
            WindowsSealedFault::ControlWorkerKilledAfterAuthorization
                | WindowsSealedFault::ControlServiceKilledAfterAuthorization
        ) && !expected_attempt.is_empty()
            && !expected_nonce.is_empty()
            && !expected_request.is_empty()
            && expected_target != 0
            && matches!(self, Self::CertificationControlReleased {
                schema_version, attempt_id, nonce, request_sha256, fault, target_pid,
            } if *schema_version == WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION
                && attempt_id == expected_attempt && nonce == expected_nonce
                && request_sha256 == expected_request && *fault == expected_fault
                && *target_pid == expected_target)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsTerminalDrainControl {
    Cancellation,
    Acknowledgment,
}

/// Authenticated launcher evidence retained across both package cleanup boundaries.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
#[serde(tag = "message", rename_all = "kebab-case", deny_unknown_fields)]
pub enum WindowsLauncherRequestV4 {
    PreparedAcknowledged {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        prepared_sha256: String,
    },
    StartupAttestation {
        schema_version: u32,
        challenge: String,
    },
    Probe {
        schema_version: u32,
        challenge: String,
    },
    ObserveGuardianAttempt {
        schema_version: u32,
        challenge: crate::BoundedText<128>,
        guardian_identity: WindowsProcessIdentityV1,
    },
    CertificationMachineRestart {
        schema_version: u32,
    },
    PackageCleanup {
        schema_version: u32,
        deadline_millis: u64,
    },
    RecoverAttempt {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        challenge: String,
        caller: crate::WindowsRecoveryCallerEvidenceV1,
    },
    ConvergeRecovery {
        schema_version: u32,
        challenge: String,
        deadline_millis: u64,
    },
    Membership {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        remote_process_handle: u64,
    },
    Launch(WindowsLaunchBrokerRequestV2),
    RelaysReady {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
    },
    Cancel {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        signal: i32,
    },
    RelaysRetired {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
    },
    TerminalAcknowledged {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        terminal_response_sha256: String,
    },
    ReplayTerminal {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        relay_phase: WindowsRelayPhaseV1,
        caller_process_identity: WindowsProcessIdentityV1,
        caller_token_sha256: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        terminalization_error: Option<WindowsTerminalizationErrorV1>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsLaunchBrokerRequestV2 {
    pub schema_version: u32,
    pub setup_deadline_millis: u64,
    pub attempt_id: String,
    pub request_sha256: String,
    pub caller_process_identity: WindowsProcessIdentityV1,
    pub caller_token_envelope: WindowsCallerTokenEnvelopeV1,
    pub remote_primary_token_handle: u64,
    pub remote_frontend_process_handle: u64,
    /// Certification-only handles created by the authenticated frontend and
    /// duplicated into the launcher. They are absent from ordinary launches.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remote_frontend_canary_handles: Vec<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certification_fault: Option<WindowsSealedFault>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certification_mutant: Option<WindowsSealedMutant>,
    pub launch: WindowsLaunchRequestV2,
}
