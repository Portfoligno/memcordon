//! A separately scheduled diagnostic operation, never certification authority.
use crate::{CiError, Result};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

pub const PREPARATION: Duration = Duration::from_secs(180);
pub const BOOTSTRAP_WORK: Duration = Duration::from_secs(30);
pub const BOOTSTRAP_CLEANUP: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticDeadline {
    pub format: String,
    pub revision: u32,
    pub diagnostic_only: bool,
    pub source: crate::consumer_readiness_ledger::SourceIdentity,
    pub native_target: String,
    pub production_settlement_sha256: String,
    pub started_unix_millis: u64,
    pub work_deadline_unix_millis: u64,
    pub cleanup_deadline_unix_millis: u64,
}

impl DiagnosticDeadline {
    pub fn at(
        source: crate::consumer_readiness_ledger::SourceIdentity,
        target: String,
        settlement: String,
        now: u64,
    ) -> Result<Self> {
        if !matches!(
            target.as_str(),
            "x86_64-pc-windows-msvc" | "aarch64-pc-windows-msvc"
        ) || settlement.len() != crate::windows_causal_acceptance::sha256(&[]).len()
            || !settlement.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(CiError::Message(
                "diagnostic native producer binding differs".into(),
            ));
        }
        let work = now
            .checked_add(
                u64::try_from((PREPARATION + BOOTSTRAP_WORK).as_millis())
                    .map_err(|error| CiError::Message(error.to_string()))?,
            )
            .ok_or_else(|| CiError::Message("diagnostic work cutoff overflow".into()))?;
        let cleanup = work
            .checked_add(
                u64::try_from(BOOTSTRAP_CLEANUP.as_millis())
                    .map_err(|error| CiError::Message(error.to_string()))?,
            )
            .ok_or_else(|| CiError::Message("diagnostic cleanup cutoff overflow".into()))?;
        Ok(Self {
            format: "memcordon.support-loader-original-deadline".into(),
            revision: 1,
            diagnostic_only: true,
            source,
            native_target: target,
            production_settlement_sha256: settlement,
            started_unix_millis: now,
            work_deadline_unix_millis: work,
            cleanup_deadline_unix_millis: cleanup,
        })
    }

    /// Caller samples this monotonic origin before its Unix clock sample.
    pub fn remaining_at(&self, origin: Instant, unix: u64) -> Result<(Instant, Instant)> {
        self.remaining_for_phase_at(origin, unix, false)
    }

    pub fn remaining_cleanup_at(&self, origin: Instant, unix: u64) -> Result<(Instant, Instant)> {
        self.remaining_for_phase_at(origin, unix, true)
    }

    fn remaining_for_phase_at(
        &self,
        origin: Instant,
        unix: u64,
        cleanup_only: bool,
    ) -> Result<(Instant, Instant)> {
        if self.format != "memcordon.support-loader-original-deadline"
            || self.revision != 1
            || !self.diagnostic_only
            || unix < self.started_unix_millis
            || self
                .work_deadline_unix_millis
                .checked_sub(self.started_unix_millis)
                != Some((PREPARATION + BOOTSTRAP_WORK).as_millis() as u64)
            || self
                .cleanup_deadline_unix_millis
                .checked_sub(self.work_deadline_unix_millis)
                != Some(BOOTSTRAP_CLEANUP.as_millis() as u64)
            || unix >= self.cleanup_deadline_unix_millis
            || (!cleanup_only && unix >= self.work_deadline_unix_millis)
        {
            return Err(CiError::Message(
                "original diagnostic cutoff exhausted or invalid".into(),
            ));
        }
        let work = origin
            .checked_add(Duration::from_millis(
                self.work_deadline_unix_millis.saturating_sub(unix),
            ))
            .ok_or_else(|| CiError::Message("diagnostic monotonic cutoff overflow".into()))?;
        let cleanup = origin
            .checked_add(Duration::from_millis(
                self.cleanup_deadline_unix_millis - unix,
            ))
            .ok_or_else(|| CiError::Message("diagnostic cleanup cutoff overflow".into()))?;
        Ok((work, cleanup))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrontendObservation {
    pub selection: memcordon_core::WindowsLoaderDiagnosticSelectionV1,
    pub launch: Option<memcordon_core::WindowsLaunchRequestV1>,
    pub caller: Option<memcordon_core::WindowsProcessIdentityV1>,
    pub attempt_id: Option<String>,
    pub request_sha256: Option<String>,
    pub authenticated_provider_frames: Vec<Vec<u8>>,
    pub capture_failure: Option<String>,
}

/// Validate diagnostic association, not qualification or retirement authority.
pub fn validate_frontend(
    observation: &FrontendObservation,
    selected: &memcordon_core::WindowsLoaderDiagnosticSelectionV1,
    provider: &memcordon_core::PublicProviderBindingV1,
) -> Result<serde_json::Value> {
    use memcordon_core::WindowsProviderResponseV3;
    if &observation.selection != selected
        || observation.capture_failure.is_some()
        || observation.authenticated_provider_frames.len() > 16
        || observation
            .authenticated_provider_frames
            .iter()
            .try_fold(0_usize, |total, frame| total.checked_add(frame.len()))
            .is_none_or(|total| total > 1024 * 1024)
    {
        return Err(CiError::Message(
            "diagnostic frontend selection or capture differs".into(),
        ));
    }
    let launch = observation
        .launch
        .as_ref()
        .ok_or_else(|| CiError::Message("diagnostic launch unavailable".into()))?;
    let caller = observation
        .caller
        .as_ref()
        .ok_or_else(|| CiError::Message("diagnostic caller unavailable".into()))?;
    let request = crate::windows_causal_acceptance::sha256(&serde_json::to_vec(launch)?);
    let mut identity = sha2::Sha256::new();
    use sha2::Digest;
    identity.update(launch.nonce.as_bytes());
    identity.update(caller.process_id.to_le_bytes());
    identity.update(caller.creation_time_100ns.to_le_bytes());
    identity.update(request.as_bytes());
    let attempt = hex::encode(identity.finalize());
    if launch.loader_diagnostic.as_deref() != Some(selected)
        || &launch.expected_provider_binding != provider
        || launch.nonce.is_empty()
        || caller.process_id == 0
        || caller.creation_time_100ns == 0
        || observation.request_sha256.as_deref() != Some(&request)
        || observation.attempt_id.as_deref() != Some(&attempt)
    {
        return Err(CiError::Message(
            "diagnostic canonical request association differs".into(),
        ));
    }
    let mut retained = None;
    for bytes in &observation.authenticated_provider_frames {
        memcordon_core::canonical_json::reject_duplicate_json_keys(bytes)
            .map_err(CiError::Message)?;
        let response: WindowsProviderResponseV3 = serde_json::from_slice(bytes)?;
        match &response {
            WindowsProviderResponseV3::Reject {
                schema_version,
                attempt_id,
                nonce,
                request_sha256,
                rejection,
            } => {
                if *schema_version != memcordon_core::WINDOWS_PUBLIC_PROTOCOL_VERSION
                    || attempt_id != &attempt
                    || nonce != &launch.nonce
                    || request_sha256 != &request
                    || !rejection.is_consistent()
                    || retained.is_some()
                    || rejection.target_created
                    || rejection.target_released
                    || !matches!(
                        rejection.disposition,
                        memcordon_core::WindowsProviderRejectionDispositionV2::Preauthorization { .. }
                    )
                {
                    return Err(CiError::Message(
                        "diagnostic refusal crosses original request".into(),
                    ));
                }
                let trace = match &rejection.loader_qualification {
                    Some(memcordon_core::WindowsLoaderQualificationOutcomeV2::Failed(failure)) => {
                        failure.support_debug_observation.as_deref()
                    }
                    _ => None,
                }
                .ok_or_else(|| {
                    CiError::Message("original loader debug observation unavailable".into())
                })?;
                if trace.challenge != selected.challenge
                    || trace.executable_sha256 != selected.support_bootstrap_sha256
                {
                    return Err(CiError::Message(
                        "diagnostic original child measurement differs".into(),
                    ));
                }
                retained = Some(
                    serde_json::json!({"diagnostic_only":true,"certification_authority":false,
                    "attempt_id":attempt,"request_sha256":request,"original_refusal":rejection,
                    "terminal_receipt":rejection.terminal_receipt(),
                    "terminal_authority_sha256":crate::windows_causal_acceptance::sha256(response.terminal_authority_json()?.as_bytes())}),
                );
            }
            WindowsProviderResponseV3::TargetAuthorized { .. }
            | WindowsProviderResponseV3::Terminal(_) => {
                return Err(CiError::Message(
                    "diagnostic cannot authorize or complete a workload".into(),
                ));
            }
            WindowsProviderResponseV3::StreamsPrepared {
                schema_version,
                attempt_id,
                nonce,
                request_sha256,
                ..
            }
            | WindowsProviderResponseV3::RelaysAbort {
                schema_version,
                attempt_id,
                nonce,
                request_sha256,
            } => {
                if *schema_version != memcordon_core::WINDOWS_PUBLIC_PROTOCOL_VERSION
                    || attempt_id != &attempt
                    || nonce != &launch.nonce
                    || request_sha256 != &request
                {
                    return Err(CiError::Message(
                        "diagnostic transport frame crosses request".into(),
                    ));
                }
            }
            _ => {
                return Err(CiError::Message(
                    "unexpected diagnostic provider frame".into(),
                ));
            }
        }
    }
    retained.ok_or_else(|| CiError::Message("bound diagnostic refusal unavailable".into()))
}
