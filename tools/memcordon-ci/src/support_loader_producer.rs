//! A separately scheduled diagnostic operation, never certification authority.
use crate::{CiError, Result};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

pub const PREPARATION: Duration = Duration::from_secs(180);
pub const BOOTSTRAP_WORK: Duration = Duration::from_secs(30);
pub const BOOTSTRAP_CLEANUP: Duration = Duration::from_secs(60);

/// A separate installed diagnostic consumes the existing lease, never renews it.
pub fn installed_selection(
    challenge: &[u8],
    bootstrap_sha256: &str,
    producer_binding_sha256: &str,
    now: u64,
    original_work_cutoff: u64,
    original_cleanup_cutoff: u64,
) -> Result<memcordon_core::WindowsLoaderDiagnosticSelectionV1> {
    if original_cleanup_cutoff <= original_work_cutoff {
        return Err(CiError::Message(
            "installed diagnostic original cutoff order differs".into(),
        ));
    }
    let selected = memcordon_core::WindowsLoaderDiagnosticSelectionV1 {
        kind: memcordon_core::WindowsLoaderDiagnosticKindV1::OriginalRestrictedBootstrapConsoleComparison,
        challenge: hex::encode(challenge),
        support_bootstrap_sha256: bootstrap_sha256.into(),
        producer_deadline_sha256: producer_binding_sha256.into(),
        work_deadline_unix_ms: original_work_cutoff.min(
            now.checked_add(30_000)
                .ok_or_else(|| CiError::Message("installed diagnostic work overflow".into()))?,
        ),
        cleanup_deadline_unix_ms: original_cleanup_cutoff.min(
            now.checked_add(60_000)
                .ok_or_else(|| CiError::Message("installed diagnostic cleanup overflow".into()))?,
        ),
    };
    selected
        .validate_at(now)
        .map_err(|error| CiError::Message(error.into()))?;
    Ok(selected)
}

/// Admit only settled original loader refusals; this confers no launch authority.
pub fn installed_trigger(
    original: &memcordon_core::ResultV1,
    provider: &memcordon_core::PublicProviderBindingV1,
) -> Result<bool> {
    use memcordon_core::result_v1::{AuthorizationV1, CleanupStateV1, LaunchStateV1};
    use memcordon_core::{WindowsLoaderCleanupStatusV1, WindowsLoaderQualificationOutcomeV2};
    if original
        .provider_association
        .as_ref()
        .map(|association| &association.provider)
        != Some(provider)
    {
        return Err(CiError::Message(
            "installed diagnostic original provider differs".into(),
        ));
    }
    if original.authorization != AuthorizationV1::RejectedBeforeRelease
        || original.launch.state != LaunchStateV1::NotCreated
        || original.cleanup.state != CleanupStateV1::Complete
    {
        return Ok(false);
    }
    Ok(original.attempts.last().is_some_and(|attempt| {
        let Some(failure) = attempt.operational_failure.as_ref() else {
            return false;
        };
        if failure.provider_association != original.provider_association {
            return false;
        }
        let Some(rejection) = failure.windows_rejection.as_ref() else {
            return false;
        };
        let Some(WindowsLoaderQualificationOutcomeV2::Failed(loader)) =
            rejection.loader_qualification.as_ref()
        else {
            return false;
        };
        rejection.is_consistent()
            && !rejection.target_created
            && !rejection.target_released
            && rejection.code == "MCSPAWN-FAILED"
            && loader.cleanup.status == WindowsLoaderCleanupStatusV1::Complete
            && loader.stable_code == "loader-control-pipe-accept"
            && loader.detail.contains("bootstrap_role=loader-control")
            && attempt.error.as_ref().is_some_and(|error| {
                error.code == "MCSPAWN-FAILED"
                    && error.message.contains("bootstrap_role=loader-control")
            })
    }))
}

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
    let mut retained: Option<serde_json::Value> = None;
    let mut retired = false;
    for bytes in &observation.authenticated_provider_frames {
        if retired {
            return Err(CiError::Message(
                "diagnostic frame follows completed retirement".into(),
            ));
        }
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
                let reached_handshake = matches!(
                    &rejection.loader_qualification,
                    Some(memcordon_core::WindowsLoaderQualificationOutcomeV2::Failed(failure))
                        if failure.stage == memcordon_core::WindowsLoaderQualificationStageV2::LoaderReadyHandshake
                );
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
                let console_comparison = validate_console_comparison(
                    trace,
                    selected,
                    match &rejection.loader_qualification {
                        Some(memcordon_core::WindowsLoaderQualificationOutcomeV2::Failed(
                            failure,
                        )) => failure.launch_plan_json.as_deref(),
                        _ => None,
                    },
                )?;
                retained = Some(
                    serde_json::json!({"diagnostic_only":true,"certification_authority":false,
                    "debug_capture_complete":reached_handshake && trace.omitted_events == 0
                        && !trace.detached && trace.exit_event_continued
                        && trace.process.process_id != 0
                        && trace.process.creation_time_100ns != 0
                        && trace.creator_thread_id != 0
                        && trace.events.first().is_some_and(|event| event.code == 3)
                        && trace.events.last().is_some_and(|event| event.code == 5 && event.native_exit_code.is_some())
                        && trace.events.iter().all(|event| event.process_id == trace.process.process_id
                            && event.thread_id != 0
                            && (event.continuation == 0x0001_0002
                                || event.code == 1 && event.continuation == 0x8001_0001)
                            && event.continuation_error.is_none()),
                    "console_comparison":console_comparison,
                    "attempt_id":attempt,"request_sha256":request,"original_refusal":rejection,
                    "terminal_receipt":rejection.terminal_receipt(),
                    "terminal_authority_sha256":crate::windows_causal_acceptance::sha256(response.terminal_authority_json()?.as_bytes())}),
                );
            }
            WindowsProviderResponseV3::TerminalRetiredV2(receipt) => {
                let digest = retained
                    .as_ref()
                    .and_then(|value| value["terminal_authority_sha256"].as_str())
                    .ok_or_else(|| {
                        CiError::Message("diagnostic retirement precedes refusal".into())
                    })?;
                if receipt.provider_generation != provider.generation.as_str()
                    || receipt.disposition != memcordon_core::WindowsAttemptTerminalDispositionV1::PreauthorizationAbort
                    || !receipt.is_consistent_for(&attempt, &launch.nonce, &request, digest)
                {
                    return Err(CiError::Message("diagnostic refusal retirement differs".into()));
                }
                retained.as_mut().expect("bound refusal checked above")["refusal_retirement"] =
                    serde_json::to_value(receipt)?;
                retired = true;
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
                    || retained.is_some()
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
    if !retired {
        return Err(CiError::Message(
            "bound diagnostic refusal retirement unavailable".into(),
        ));
    }
    retained.ok_or_else(|| CiError::Message("bound diagnostic refusal unavailable".into()))
}

pub fn validate_console_comparison(
    baseline: &memcordon_core::WindowsLoaderDebugObservationV1,
    selected: &memcordon_core::WindowsLoaderDiagnosticSelectionV1,
    baseline_plan_json: Option<&str>,
) -> Result<serde_json::Value> {
    use memcordon_core::{
        WindowsLoaderConsoleComparisonOutcomeV1 as Outcome, WindowsLoaderDiagnosticKindV1 as Kind,
    };
    let Some(comparison) = baseline.console_comparison.as_ref() else {
        return if selected.kind == Kind::OriginalRestrictedBootstrap {
            Ok(serde_json::json!({"selected":false}))
        } else {
            Ok(
                serde_json::json!({"selected":true,"available":false,"reason":"comparison observation absent"}),
            )
        };
    };
    if selected.kind != Kind::OriginalRestrictedBootstrapConsoleComparison
        || !comparison.is_consistent_for(baseline)
    {
        return Err(CiError::Message(
            "console comparison selection or baseline binding differs".into(),
        ));
    }
    if let Some(json) = comparison.diagnostic_plan_json.as_ref() {
        let descriptor: memcordon_windows_launch_core::SupportDetachedConsolePlanV1 =
            serde_json::from_str(json)?;
        let original: memcordon_windows_launch_core::ProductionLoaderPlanV1 = serde_json::from_str(
            baseline_plan_json
                .ok_or_else(|| CiError::Message("comparison original plan absent".into()))?,
        )?;
        descriptor
            .validate_baseline(&original, &selected.challenge)
            .map_err(CiError::Message)?;
        if descriptor.actual_creation_flags() != comparison.actual_creation_flags
            || comparison.debug_observation.as_ref().is_some_and(|debug| {
                debug.launch_plan_sha256 != descriptor.diagnostic_plan_sha256()
            })
        {
            return Err(CiError::Message(
                "comparison actual flags or trace plan differs".into(),
            ));
        }
    }
    if matches!(
        comparison.outcome,
        Outcome::NotApplicable {
            baseline_schema_version: 2
        }
    ) {
        let plan: memcordon_windows_launch_core::ProductionLoaderPlanV2 = serde_json::from_str(
            baseline_plan_json
                .ok_or_else(|| CiError::Message("comparison original V2 plan absent".into()))?,
        )?;
        if plan.launch_plan_sha256() != baseline.launch_plan_sha256 {
            return Err(CiError::Message(
                "comparison V2 baseline binding differs".into(),
            ));
        }
        return Ok(
            serde_json::json!({"selected":true,"applicable":false,"reason":"consoleless-loader-control-v2", "diagnostic_only":true,"certification_authority":false,"observation":comparison}),
        );
    }
    let retired =
        comparison.cleanup.status == memcordon_core::WindowsLoaderCleanupStatusV1::Complete;
    let complete = comparison.debug_observation.as_ref().is_some_and(|debug| {
        debug.omitted_events == 0
            && !debug.detached
            && debug.exit_event_continued
            && debug.events.first().is_some_and(|event| event.code == 3)
            && debug
                .events
                .last()
                .is_some_and(|event| event.code == 5 && event.native_exit_code.is_some())
            && debug.events.iter().all(|event| {
                event.process_id == debug.process.process_id
                    && event.thread_id != 0
                    && event.continuation_error.is_none()
                    && (event.continuation == 0x10002
                        || event.code == 1 && event.continuation == 0x80010001)
            })
    });
    Ok(
        serde_json::json!({"selected":true,"diagnostic_only":true,"certification_authority":false,
        "available":retired && complete,
        "reached_handshake":retired && complete && matches!(comparison.outcome, Outcome::ReachedHandshake),
        "retirement_complete":retired,"capture_complete":complete,"observation":comparison}),
    )
}

/// A bound refusal is useful evidence even when the debugger never captured
/// the original child. Such a refusal must not be reported as capture success.
pub fn require_complete_debug_capture(refusal: &serde_json::Value) -> Result<()> {
    if refusal["debug_capture_complete"] != true {
        return Err(CiError::Message(
            "original loader debug capture incomplete or unavailable".into(),
        ));
    }
    Ok(())
}
