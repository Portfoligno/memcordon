//! Schema-11 private workload projection. This is not a native proof or the
//! current public report producer: callers must supply an independently
//! authenticated terminal receipt and installed authority to decode it.

use serde::{Deserialize, Serialize};

use crate::workload_admission_v2::AttemptBindingV2;
use crate::workload_evidence_v2::{
    PrivateTcpCheckpointV2, PrivateTcpRetiredV2, QualifiedNativeAbiV2,
};
use crate::{DiagnosticSha256, workload_contract, workload_limits};

/// Public failure-capable CLI envelope. Its bytes are historical output, not
/// admission authority. Only a live authenticated provider response may be
/// used by the platform to construct `Complete` with restart proof.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivatePublicResultV11 {
    pub schema_version: u32,
    pub result: PrivatePublicOutcomeV11,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PrivatePublicOutcomeV11 {
    Complete {
        terminal: Box<PrivateExecutionReportV11>,
        raw_response: Vec<u8>,
    },
    PreallocationRejected {
        rejection: Box<crate::ProviderRejectionEvidence>,
        raw_response: Vec<u8>,
    },
    AllocatedUnverified {
        rejection: Box<crate::ProviderRejectionEvidence>,
        raw_response: Vec<u8>,
    },
    Indeterminate {
        attempt_id: String,
        reason_code: String,
        raw_response: Vec<u8>,
    },
    BeforeSubmissionFailure {
        reason: String,
    },
    TransportUnverified {
        reason: String,
        raw_response: Option<Vec<u8>>,
    },
}

impl PrivatePublicResultV11 {
    pub fn validate_structure(&self) -> Result<(), String> {
        if self.schema_version != PRIVATE_EXECUTION_REPORT_SCHEMA_V11 {
            return Err("V11 public result schema differs".into());
        }
        let bounded =
            |bytes: &[u8]| !bytes.is_empty() && bytes.len() <= workload_limits::PUBLIC_OBJECT_BYTES;
        match &self.result {
            PrivatePublicOutcomeV11::Complete {
                terminal,
                raw_response,
            } => {
                if !bounded(raw_response) {
                    return Err("V11 complete raw response is absent or oversized".into());
                }
                workload_contract::reject_duplicate_json_keys(raw_response)?;
                let raw: PrivateExecutionReportV11 =
                    serde_json::from_slice(raw_response).map_err(|error| error.to_string())?;
                if raw != **terminal
                    || terminal.schema_version != self.schema_version
                    || terminal.checkpoint.native_abi != terminal.native_abi
                    || terminal.checkpoint.attempt_binding != terminal.attempt.canonical_digest()?
                    || !terminal.retirement.terminal_success(&terminal.checkpoint)
                {
                    return Err("V11 complete projection differs from raw response".into());
                }
            }
            PrivatePublicOutcomeV11::PreallocationRejected {
                rejection,
                raw_response,
            } => {
                if rejection.target_created || !rejection.is_consistent() || !bounded(raw_response)
                {
                    return Err(
                        "V11 preallocation rejection has allocated target or invalid raw evidence"
                            .into(),
                    );
                }
                if crate::provider_rejection_wire::RejectionWireV1::parse_evidence(raw_response)?
                    != **rejection
                {
                    return Err("V11 preallocation rejection differs from raw response".into());
                }
            }
            PrivatePublicOutcomeV11::AllocatedUnverified {
                rejection,
                raw_response,
            } => {
                if !rejection.target_created || !rejection.is_consistent() || !bounded(raw_response)
                {
                    return Err("V11 allocated failure lacks target or raw evidence".into());
                }
                if crate::provider_rejection_wire::RejectionWireV1::parse_evidence(raw_response)?
                    != **rejection
                {
                    return Err("V11 allocated rejection differs from raw response".into());
                }
            }
            PrivatePublicOutcomeV11::Indeterminate {
                attempt_id,
                reason_code,
                raw_response,
            } => {
                if attempt_id.is_empty() || reason_code.is_empty() || !bounded(raw_response) {
                    return Err("V11 indeterminate identity or raw evidence is absent".into());
                }
            }
            PrivatePublicOutcomeV11::BeforeSubmissionFailure { reason }
            | PrivatePublicOutcomeV11::TransportUnverified { reason, .. }
                if reason.is_empty() || reason.len() > workload_limits::PUBLIC_OBJECT_BYTES =>
            {
                return Err("V11 failure reason is absent or oversized".into());
            }
            PrivatePublicOutcomeV11::TransportUnverified { raw_response, .. }
                if raw_response.as_ref().is_some_and(|bytes| !bounded(bytes)) =>
            {
                return Err("V11 transport raw response is empty or oversized".into());
            }
            _ => {}
        }
        Ok(())
    }
}

pub const PRIVATE_EXECUTION_REPORT_SCHEMA_V11: u32 = 11;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PrivateTerminalOutcomeV11 {
    Exited { code: i32 },
    NativeFailure { phase: String, detail: String },
    Interrupted { reason: String },
}

impl PrivateTerminalOutcomeV11 {
    fn validate(&self) -> Result<(), String> {
        match self {
            Self::Exited { .. } => Ok(()),
            Self::NativeFailure { phase, detail } => {
                if phase.is_empty() || detail.is_empty() || phase.len() > 128 || detail.len() > 1024
                {
                    return Err("V11 native failure detail is empty or exceeds bound".into());
                }
                Ok(())
            }
            Self::Interrupted { reason } => {
                if reason.is_empty() || reason.len() > 128 {
                    return Err("V11 interruption reason is empty or exceeds bound".into());
                }
                Ok(())
            }
        }
    }
}

/// A report projection can be checked only against independent producer data.
/// In particular, a zero exit code and structurally valid JSON do not certify
/// acceptance, installed qualification, or terminal retirement on their own.
pub struct TrustedPrivateExecutionV11<'a> {
    pub source_commit: &'a str,
    pub native_abi: QualifiedNativeAbiV2,
    pub runtime_manifest_sha256: &'a DiagnosticSha256,
    pub installed_qualification_sha256: &'a DiagnosticSha256,
    pub attempt: &'a AttemptBindingV2,
    pub checkpoint_sha256: &'a DiagnosticSha256,
    pub retirement_sha256: &'a DiagnosticSha256,
    pub terminal_receipt_sha256: &'a DiagnosticSha256,
    pub outcome: &'a PrivateTerminalOutcomeV11,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateExecutionReportV11 {
    pub schema_version: u32,
    pub source_commit: String,
    pub native_abi: QualifiedNativeAbiV2,
    pub runtime_manifest_sha256: DiagnosticSha256,
    pub installed_qualification_sha256: DiagnosticSha256,
    pub attempt: AttemptBindingV2,
    pub checkpoint: PrivateTcpCheckpointV2,
    pub retirement: PrivateTcpRetiredV2,
    pub terminal_receipt_sha256: DiagnosticSha256,
    pub outcome: PrivateTerminalOutcomeV11,
}

impl PrivateExecutionReportV11 {
    /// Build a public projection only from the caller's authenticated native
    /// receipt and installed readback, then recheck every joined field. The
    /// trusted input must not be reconstructed from untrusted report bytes.
    pub fn from_trusted_native(
        checkpoint: PrivateTcpCheckpointV2,
        retirement: PrivateTcpRetiredV2,
        trusted: &TrustedPrivateExecutionV11<'_>,
    ) -> Result<Self, String> {
        let report = Self {
            schema_version: PRIVATE_EXECUTION_REPORT_SCHEMA_V11,
            source_commit: trusted.source_commit.to_owned(),
            native_abi: trusted.native_abi,
            runtime_manifest_sha256: trusted.runtime_manifest_sha256.clone(),
            installed_qualification_sha256: trusted.installed_qualification_sha256.clone(),
            attempt: trusted.attempt.clone(),
            checkpoint,
            retirement,
            terminal_receipt_sha256: trusted.terminal_receipt_sha256.clone(),
            outcome: trusted.outcome.clone(),
        };
        report.validate(trusted)?;
        Ok(report)
    }

    pub fn parse_and_validate(
        bytes: &[u8],
        expected_schema: u32,
        trusted: &TrustedPrivateExecutionV11<'_>,
    ) -> Result<Self, String> {
        if expected_schema != PRIVATE_EXECUTION_REPORT_SCHEMA_V11 {
            return Err("V11 report was not selected by trusted schema".into());
        }
        if bytes.len() > workload_limits::PUBLIC_OBJECT_BYTES {
            return Err("V11 report exceeds byte bound".into());
        }
        workload_contract::reject_duplicate_json_keys(bytes)?;
        let report: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        report.validate(trusted)?;
        Ok(report)
    }

    pub fn validate(&self, trusted: &TrustedPrivateExecutionV11<'_>) -> Result<(), String> {
        if self.schema_version != PRIVATE_EXECUTION_REPORT_SCHEMA_V11
            || self.source_commit != trusted.source_commit
            || self.source_commit.len() != 40
            || !self
                .source_commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || self.native_abi != trusted.native_abi
            || self.runtime_manifest_sha256 != *trusted.runtime_manifest_sha256
            || self.installed_qualification_sha256 != *trusted.installed_qualification_sha256
            || self.attempt != *trusted.attempt
            || self.terminal_receipt_sha256 != *trusted.terminal_receipt_sha256
            || self.outcome != *trusted.outcome
        {
            return Err(
                "V11 report differs from trusted source, install or native terminal".into(),
            );
        }
        self.outcome.validate()?;
        self.checkpoint.validate().map_err(str::to_owned)?;
        if self.checkpoint.native_abi != self.native_abi
            || self.checkpoint.attempt_binding != self.attempt.canonical_digest()?
            || !self.retirement.terminal_success(&self.checkpoint)
            || self.checkpoint.canonical_digest()? != *trusted.checkpoint_sha256
            || self.retirement.canonical_digest()? != *trusted.retirement_sha256
        {
            return Err("V11 report checkpoint or retirement differs from native proof".into());
        }
        Ok(())
    }
}
