//! Closed Linux provider rejection wire and its public evidence projection.

use serde::{Deserialize, Serialize};

use crate::{BoundarySetupPhase, ProviderRejectionEvidence, RestartSafetyProof};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RejectionPhaseV1 {
    RequestValidation,
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

impl From<RejectionPhaseV1> for BoundarySetupPhase {
    fn from(phase: RejectionPhaseV1) -> Self {
        match phase {
            RejectionPhaseV1::RequestValidation => Self::RequestValidation,
            RejectionPhaseV1::CallerEnvelopeCapture => Self::CallerEnvelopeCapture,
            RejectionPhaseV1::LauncherServiceAuthentication => Self::LauncherServiceAuthentication,
            RejectionPhaseV1::CallerMountNamespaceAdoption => Self::CallerMountNamespaceAdoption,
            RejectionPhaseV1::CallerCapabilityEnvelope => Self::CallerCapabilityEnvelope,
            RejectionPhaseV1::CredentialTransitionPolicy => Self::CredentialTransitionPolicy,
            RejectionPhaseV1::BoundaryCreation => Self::BoundaryCreation,
            RejectionPhaseV1::GuardianStartup => Self::GuardianStartup,
            RejectionPhaseV1::TargetCreation => Self::TargetCreation,
            RejectionPhaseV1::AssignmentVerification => Self::AssignmentVerification,
            RejectionPhaseV1::ResourceVerification => Self::ResourceVerification,
            RejectionPhaseV1::Authorization => Self::Authorization,
            RejectionPhaseV1::Monitoring => Self::Monitoring,
            RejectionPhaseV1::Retirement => Self::Retirement,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RejectionCleanupV1 {
    pub attempted: bool,
    pub direct_child_reaped: bool,
    pub workload_empty: Option<bool>,
    pub helpers_reaped: bool,
    pub containment_removed: bool,
    pub sealed_boundary_retired: bool,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RejectionWireV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_admission: Option<crate::workload_evidence::WorkloadAdmissionRejectionV1>,
    pub schema_version: u32,
    pub code: String,
    pub phase: RejectionPhaseV1,
    pub detail: String,
    pub os_code: Option<i32>,
    pub target_created: bool,
    pub target_released: bool,
    pub cleanup: RejectionCleanupV1,
}

impl RejectionWireV1 {
    pub fn parse(raw: &[u8]) -> Result<Self, String> {
        if raw.is_empty() || raw.len() > crate::workload_limits::PUBLIC_OBJECT_BYTES {
            return Err("provider rejection raw response is absent or oversized".into());
        }
        crate::workload_contract::reject_duplicate_json_keys(raw)?;
        let wire: Self = serde_json::from_slice(raw).map_err(|error| error.to_string())?;
        wire.validate()?;
        Ok(wire)
    }

    pub fn validate(&self) -> Result<(), String> {
        let valid_code = !self.code.is_empty()
            && self.code.len() <= 128
            && self
                .code
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-');
        if self.schema_version != 1
            || !valid_code
            || self.detail.is_empty()
            || self.detail.len() > 8 * 1024
            || self.detail.contains('\0')
            || self.target_released && !self.target_created
            || self.cleanup.errors.len() > 16
            || self
                .cleanup
                .errors
                .iter()
                .any(|error| error.len() > 1024 || error.contains('\0'))
        {
            return Err("typed rejection fields violate protocol bounds".into());
        }
        if !self.cleanup.attempted
            && (self.cleanup.direct_child_reaped
                || self.cleanup.workload_empty.is_some()
                || self.cleanup.helpers_reaped
                || self.cleanup.containment_removed
                || self.cleanup.sealed_boundary_retired
                || !self.cleanup.errors.is_empty())
        {
            return Err("typed rejection cleanup evidence is contradictory".into());
        }
        if self.cleanup.sealed_boundary_retired
            && (!self.cleanup.direct_child_reaped
                || self.cleanup.workload_empty != Some(true)
                || !self.cleanup.helpers_reaped
                || !self.cleanup.containment_removed
                || !self.cleanup.errors.is_empty())
        {
            return Err("typed rejection retirement evidence is incomplete".into());
        }
        Ok(())
    }

    pub fn into_evidence(self) -> Result<ProviderRejectionEvidence, String> {
        self.validate()?;
        let evidence = ProviderRejectionEvidence {
            workload_admission: self.workload_admission,
            provider_failure: None,
            schema_version: self.schema_version,
            code: self.code,
            phase: self.phase.into(),
            detail: self.detail,
            os_code: self.os_code,
            loader_qualification: None,
            target_created: self.target_created,
            target_released: self.target_released,
            cleanup_attempted: self.cleanup.attempted,
            restart_safety: RestartSafetyProof {
                direct_child_reaped: self.cleanup.direct_child_reaped,
                workload_empty: self.cleanup.workload_empty,
                helpers_reaped: self.cleanup.helpers_reaped,
                containment_removed: self.cleanup.containment_removed,
                containment_incapable_of_live_members: self.cleanup.workload_empty == Some(true),
                sealed_boundary_retired: self.cleanup.sealed_boundary_retired,
                errors: self.cleanup.errors,
            },
            terminal_ack_required: false,
            terminal_receipt: None,
        };
        if !evidence.is_consistent() {
            return Err("projected rejection evidence is inconsistent".into());
        }
        Ok(evidence)
    }

    pub fn parse_evidence(raw: &[u8]) -> Result<ProviderRejectionEvidence, String> {
        Self::parse(raw)?.into_evidence()
    }
}
