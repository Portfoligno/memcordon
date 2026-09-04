use memcordon_windows_launch_core::{
    ArtifactRefV1, CleanupOutcomeV1, HandshakeOutcomeV1, NativeCallOutcomeV1, NativeStatusV1,
    ProductionLoaderPlanV1, WindowsLoaderQualificationStageV2,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::path::PathBuf;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HarnessStatusV1 {
    Complete,
    Incomplete,
    CleanupFailed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LoaderLabStageV1 {
    AProductionReplica,
    BTargetBoundary,
    COneFactor,
    DObserver,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsBuildIdentityV1 {
    pub os: String,
    pub architecture: String,
    pub major_version: u32,
    pub minor_version: u32,
    pub build_number: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticTokenVariantV1 {
    ProductionTarget,
    CallerPrimary,
    PrivilegeDisabled,
    FullyRestrictedRestrictedCode,
    WriteRestrictedRestrictedCode,
    WriteRestrictedWriteRestrictedCode,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticDesktopVariantV1 {
    ProductionPrivate,
    ControlledTest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticEnvironmentVariantV1 {
    ProductionPrepared,
    TargetDerived,
    QualificationCaller,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticSecurityDescriptorVariantV1 {
    ProductionExact,
    ProcessAndThreadDefaults,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticProfileVariantV1 {
    ProductionUnloaded,
    LoadedForTarget,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticParentVariantV1 {
    ProductionLauncher,
    InteractiveShell,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticObserverV1 {
    None,
    DebugEventPump,
    FullDebugger,
    LoaderSnaps,
    PassiveEtw,
    ExternalProcmon,
    ExternalWpr,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverEvidenceV1 {
    pub kind: DiagnosticObserverV1,
    pub completed: bool,
    pub stable_code: Option<String>,
    pub event_count: u64,
    pub output_debug_string_count: u64,
    pub module_event_count: u64,
    pub exception_event_count: u64,
    pub event_codes: Vec<u32>,
    pub session_started: bool,
    pub provider_enabled: bool,
    pub cleanup_complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalCaptureSummaryV1 {
    pub schema_version: u32,
    pub run_id: String,
    pub side: String,
    pub source_scenario_id: String,
    pub source_result_sha256: String,
    pub production_plan_sha256: String,
    pub package_sha256: String,
    pub trace_sha256: String,
    pub target_process_id: u32,
    pub descendant_process_ids: Vec<u32>,
    pub capture_started_unix_millis: u64,
    pub capture_ended_unix_millis: u64,
    pub tool: ExternalCaptureToolV1,
    pub tool_build_sha256: String,
    pub symbol_identity_sha256: String,
    pub capture_profile: String,
    pub result_filter: String,
    pub first_divergence: ExternalFirstDivergenceV1,
    pub event_count: u64,
    pub collector_session_started: bool,
    pub provider_enabled: bool,
    pub collector_cleanup_complete: bool,
    pub raw_trace_restricted: bool,
    pub summary_redacted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExternalCaptureToolV1 {
    Procmon,
    Wpr,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalFirstDivergenceV1 {
    pub object_identity_sha256: String,
    pub operation: String,
    pub requested_rights: String,
    pub result: String,
    pub stack_module_sha256: Vec<String>,
}

pub struct ExternalCaptureBindingV1<'a> {
    pub run_id: &'a str,
    pub side: &'a str,
    pub source_scenario_id: &'a str,
    pub source_result_sha256: &'a str,
    pub production_plan_sha256: &'a str,
    pub package_sha256: &'a str,
    pub trace_sha256: &'a str,
    pub target_process_id: u32,
}

impl ExternalCaptureSummaryV1 {
    pub fn validate(&self, binding: ExternalCaptureBindingV1<'_>) -> Result<(), String> {
        if self.schema_version != 1
            || self.run_id != binding.run_id
            || self.side != binding.side
            || self.source_scenario_id != binding.source_scenario_id
            || self.source_result_sha256 != binding.source_result_sha256
            || self.production_plan_sha256 != binding.production_plan_sha256
            || self.package_sha256 != binding.package_sha256
            || self.trace_sha256 != binding.trace_sha256
            || self.target_process_id != binding.target_process_id
            || self.capture_started_unix_millis >= self.capture_ended_unix_millis
            || self.capture_profile.is_empty()
            || self.result_filter.is_empty()
            || self.first_divergence.operation.is_empty()
            || self.first_divergence.requested_rights.is_empty()
            || self.first_divergence.result.is_empty()
            || self.event_count == 0
            || !self.collector_session_started
            || !self.collector_cleanup_complete
            || !self.raw_trace_restricted
            || !self.summary_redacted
        {
            return Err(String::from(
                "external capture summary is not bound to the selected native scenario",
            ));
        }
        if self
            .descendant_process_ids
            .iter()
            .any(|process_id| *process_id == 0 || *process_id == self.target_process_id)
        {
            return Err(String::from(
                "external capture descendant identity is invalid",
            ));
        }
        for digest in [
            &self.production_plan_sha256,
            &self.package_sha256,
            &self.trace_sha256,
            &self.source_result_sha256,
            &self.tool_build_sha256,
            &self.symbol_identity_sha256,
            &self.first_divergence.object_identity_sha256,
        ]
        .into_iter()
        .chain(self.first_divergence.stack_module_sha256.iter())
        {
            if !is_digest(digest) {
                return Err(String::from(
                    "external capture summary contains an invalid digest",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TargetVariantV1 {
    MinimalSmoke,
    PackagedBootstrap,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoaderLabScenarioV1 {
    pub schema_version: u32,
    pub scenario_id: String,
    pub stage: LoaderLabStageV1,
    pub production_equivalent: bool,
    pub perturbed: bool,
    pub plan: ProductionLoaderPlanV1,
    pub target: TargetVariantV1,
    pub target_path: PathBuf,
    pub current_directory: PathBuf,
    pub token_variant: DiagnosticTokenVariantV1,
    pub desktop_variant: DiagnosticDesktopVariantV1,
    pub environment_variant: DiagnosticEnvironmentVariantV1,
    pub security_descriptor_variant: DiagnosticSecurityDescriptorVariantV1,
    pub profile_variant: DiagnosticProfileVariantV1,
    pub parent_variant: DiagnosticParentVariantV1,
    pub observer: DiagnosticObserverV1,
    pub namespace: String,
    pub production_plan_sha256: String,
}

impl LoaderLabScenarioV1 {
    pub fn validate(&self, production_plan_sha256: &str) -> Result<(), String> {
        if self.schema_version != 1
            || self.scenario_id.is_empty()
            || self.namespace.is_empty()
            || self.target_path.as_os_str().is_empty()
            || self.current_directory.as_os_str().is_empty()
        {
            return Err(String::from("lab scenario identity is invalid"));
        }
        if self.perturbed == self.production_equivalent {
            return Err(String::from(
                "only the production replica may be unperturbed",
            ));
        }
        if self.production_equivalent != (self.stage == LoaderLabStageV1::AProductionReplica) {
            return Err(String::from(
                "only stage A is production-equivalent and stage A must be production-equivalent",
            ));
        }
        if self.production_plan_sha256 != production_plan_sha256 {
            return Err(String::from(
                "scenario is not bound to the supplied production plan",
            ));
        }
        let production_factors = self.token_variant == DiagnosticTokenVariantV1::ProductionTarget
            && self.desktop_variant == DiagnosticDesktopVariantV1::ProductionPrivate
            && self.environment_variant == DiagnosticEnvironmentVariantV1::ProductionPrepared
            && self.security_descriptor_variant
                == DiagnosticSecurityDescriptorVariantV1::ProductionExact
            && self.profile_variant == DiagnosticProfileVariantV1::ProductionUnloaded
            && self.parent_variant == DiagnosticParentVariantV1::ProductionLauncher
            && self.observer == DiagnosticObserverV1::None;
        match self.stage {
            LoaderLabStageV1::AProductionReplica
                if self.target == TargetVariantV1::PackagedBootstrap
                    && production_factors
                    && self.plan.launch_plan_sha256() == production_plan_sha256 => {}
            LoaderLabStageV1::BTargetBoundary
                if self.target == TargetVariantV1::MinimalSmoke && production_factors => {}
            LoaderLabStageV1::COneFactor => {
                let changed = [
                    self.token_variant != DiagnosticTokenVariantV1::ProductionTarget,
                    self.desktop_variant != DiagnosticDesktopVariantV1::ProductionPrivate,
                    self.environment_variant != DiagnosticEnvironmentVariantV1::ProductionPrepared,
                    self.security_descriptor_variant
                        != DiagnosticSecurityDescriptorVariantV1::ProductionExact,
                    self.profile_variant != DiagnosticProfileVariantV1::ProductionUnloaded,
                    self.parent_variant != DiagnosticParentVariantV1::ProductionLauncher,
                ]
                .into_iter()
                .filter(|changed| *changed)
                .count();
                if self.target != TargetVariantV1::PackagedBootstrap
                    || self.observer != DiagnosticObserverV1::None
                    || changed != 1
                {
                    return Err(String::from(
                        "stage C must change exactly one non-observer production factor",
                    ));
                }
            }
            LoaderLabStageV1::DObserver if self.observer != DiagnosticObserverV1::None => {}
            _ => {
                return Err(String::from(
                    "lab stage and one-factor scenario inputs are inconsistent",
                ));
            }
        }
        if self.stage == LoaderLabStageV1::DObserver && !self.perturbed {
            return Err(String::from("stage-D observer scenario is not perturbed"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoaderLabScenarioResultV1 {
    pub scenario_id: String,
    pub production_equivalent: bool,
    pub perturbed: bool,
    pub launch_plan_sha256: Option<String>,
    pub token_variant: DiagnosticTokenVariantV1,
    pub desktop_variant: DiagnosticDesktopVariantV1,
    pub environment_variant: DiagnosticEnvironmentVariantV1,
    pub security_descriptor_variant: DiagnosticSecurityDescriptorVariantV1,
    pub profile_variant: DiagnosticProfileVariantV1,
    pub parent_variant: DiagnosticParentVariantV1,
    pub observer: DiagnosticObserverV1,
    pub observer_evidence: Option<ObserverEvidenceV1>,
    pub target_token_envelope_sha256: Option<String>,
    pub prepared_inputs: Option<PreparedInputEvidenceV1>,
    pub suspended_process: Option<SuspendedProcessEvidenceV1>,
    pub loader_ready_process_identity: Option<memcordon_core::WindowsProcessIdentityV1>,
    pub loader_ready_token_envelope_sha256: Option<String>,
    pub loader_ready_process_snapshot: Option<LoaderReadyTokenSnapshotEvidenceV1>,
    pub process_create: NativeCallOutcomeV1,
    pub failure_stage: Option<WindowsLoaderQualificationStageV2>,
    pub failure_status: Option<NativeStatusV1>,
    pub target_exit_code: Option<u32>,
    pub handshake: HandshakeOutcomeV1,
    pub cleanup: CleanupOutcomeV1,
    pub attachments: Vec<ArtifactRefV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedInputEvidenceV1 {
    pub command_line_sha256: String,
    pub command_line_units: u64,
    pub environment_sha256: String,
    pub environment_units: u64,
    pub current_directory_sha256: String,
    pub current_directory_units: u64,
}

impl LoaderLabScenarioResultV1 {
    pub fn validate_against(&self, scenario: &LoaderLabScenarioV1) -> Result<(), String> {
        if self.scenario_id != scenario.scenario_id
            || self.production_equivalent != scenario.production_equivalent
            || self.perturbed != scenario.perturbed
            || (scenario.production_equivalent
                && self
                    .launch_plan_sha256
                    .as_deref()
                    .is_some_and(|digest| digest != scenario.plan.launch_plan_sha256()))
            || self.token_variant != scenario.token_variant
            || self.desktop_variant != scenario.desktop_variant
            || self.environment_variant != scenario.environment_variant
            || self.security_descriptor_variant != scenario.security_descriptor_variant
            || self.profile_variant != scenario.profile_variant
            || self.parent_variant != scenario.parent_variant
            || self.observer != scenario.observer
            || self.observer_evidence.as_ref().is_some_and(|evidence| {
                evidence.kind != self.observer
                    || !evidence.cleanup_complete
                    || (evidence.completed == evidence.stable_code.is_some())
            })
        {
            return Err(String::from(
                "scenario result does not match its typed input",
            ));
        }
        if (self.observer == DiagnosticObserverV1::None && self.observer_evidence.is_some())
            || (self.observer != DiagnosticObserverV1::None
                && self.failure_stage.is_none()
                && self.observer_evidence.is_none())
        {
            return Err(String::from(
                "scenario observer evidence is inconsistent with execution",
            ));
        }
        if let Some(digest) = &self.launch_plan_sha256 {
            if !is_digest(digest) {
                return Err(String::from(
                    "scenario result launch-plan digest is invalid",
                ));
            }
        } else if self.process_create.completed
            || !matches!(
                self.failure_stage,
                Some(
                    WindowsLoaderQualificationStageV2::PlanValidation
                        | WindowsLoaderQualificationStageV2::DesktopPreflight
                )
            )
        {
            return Err(String::from(
                "scenario result without a plan digest is not an early typed failure",
            ));
        }
        if !self.process_create.completed && self.target_exit_code.is_some() {
            return Err(String::from(
                "a target exit code cannot exist when process creation did not complete",
            ));
        }
        if scenario.production_equivalent {
            if let Some(target_token_envelope_sha256) = &self.target_token_envelope_sha256 {
                if target_token_envelope_sha256 != &scenario.plan.target_token().envelope_sha256 {
                    return Err(String::from(
                        "production replica live token differs from the supplied plan",
                    ));
                }
            }
            if let Some(suspended) = self.suspended_process.as_ref() {
                if !suspended.image_matches_plan
                    || !suspended.job_membership_at_creation
                    || !suspended.empty_inherited_handle_list
                    || Some(&suspended.token_envelope_sha256)
                        != self.target_token_envelope_sha256.as_ref()
                {
                    return Err(String::from(
                        "production replica suspended-process evidence differs from the supplied plan",
                    ));
                }
            }
            if matches!(self.handshake, HandshakeOutcomeV1::Authenticated { .. }) {
                let suspended = self.suspended_process.as_ref().ok_or_else(|| {
                    String::from("authenticated production replica lacks suspended evidence")
                })?;
                let ready_identity =
                    self.loader_ready_process_identity.as_ref().ok_or_else(|| {
                        String::from("authenticated production replica lacks ready identity")
                    })?;
                let ready_envelope_sha256 = self
                    .loader_ready_token_envelope_sha256
                    .as_ref()
                    .ok_or_else(|| {
                        String::from("authenticated production replica lacks ready token envelope")
                    })?;
                let ready_snapshot =
                    self.loader_ready_process_snapshot.as_ref().ok_or_else(|| {
                        String::from("authenticated production replica lacks ready token snapshot")
                    })?;
                if suspended.process_identity != *ready_identity
                    || Some(ready_envelope_sha256) != self.target_token_envelope_sha256.as_ref()
                    || Some(&ready_snapshot.envelope_sha256)
                        != self.target_token_envelope_sha256.as_ref()
                {
                    return Err(String::from(
                        "production replica loader-ready evidence differs from suspended evidence",
                    ));
                }
            }
        }
        if self.failure_stage.is_none() && self.failure_status.is_some() {
            return Err(String::from("failure status has no typed failure stage"));
        }
        match (&self.handshake, &self.failure_stage) {
            (HandshakeOutcomeV1::Authenticated { .. }, None) => {}
            (
                HandshakeOutcomeV1::Authenticated { .. },
                Some(WindowsLoaderQualificationStageV2::ExitDrain),
            ) => {}
            (HandshakeOutcomeV1::Failed { .. }, Some(_)) => {}
            (
                HandshakeOutcomeV1::NotStarted,
                Some(
                    WindowsLoaderQualificationStageV2::PlanValidation
                    | WindowsLoaderQualificationStageV2::DesktopPreflight
                    | WindowsLoaderQualificationStageV2::ProcessCreate
                    | WindowsLoaderQualificationStageV2::SuspendedAttestation
                    | WindowsLoaderQualificationStageV2::Resume,
                ),
            ) => {}
            _ => {
                return Err(String::from(
                    "handshake and typed failure stage are contradictory",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuspendedProcessEvidenceV1 {
    pub process_identity: memcordon_core::WindowsProcessIdentityV1,
    pub parent_process_identity: memcordon_core::WindowsProcessIdentityV1,
    pub parent_token_envelope_sha256: String,
    pub token_envelope_sha256: String,
    pub image_path_sha256: String,
    pub image_matches_plan: bool,
    pub job_membership_at_creation: bool,
    pub empty_inherited_handle_list: bool,
    pub desktop_binding_name_sha256: String,
    pub window_station_descriptor_sha256: String,
    pub desktop_descriptor_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoaderReadyTokenSnapshotV1 {
    pub instance: LoaderReadyTokenInstanceV1,
    pub lineage: LoaderReadyTokenLineageV1,
    pub behavior: LoaderReadyTokenBehaviorV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoaderReadyTokenSnapshotEvidenceV1 {
    pub snapshot_sha256: String,
    pub envelope_sha256: String,
    pub token_id: u64,
    pub modified_id: u64,
    pub authentication_id: u64,
    pub originating_logon_session: u64,
    pub session_id: u32,
    pub group_count: u64,
    pub privilege_count: u64,
    pub restricting_sid_count: u64,
    pub token_is_restricted: bool,
    pub enabled_sensitive_privilege_count: u32,
    pub default_dacl_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoaderReadyTokenInstanceV1 {
    pub token_id: u64,
    pub modified_id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoaderReadyTokenLineageV1 {
    pub authentication_id: u64,
    pub originating_logon_session: u64,
    pub user_sid: String,
    pub session_id: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoaderReadyTokenBehaviorV1 {
    pub envelope: memcordon_core::WindowsCallerTokenEnvelopeV1,
    pub groups: Vec<String>,
    pub privileges: Vec<String>,
    pub restricting_sids: Vec<String>,
    pub token_is_restricted: bool,
    pub enabled_sensitive_privilege_count: u32,
    pub default_dacl_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoaderLabRunV1 {
    pub schema_version: u32,
    pub run_id: String,
    pub os: WindowsBuildIdentityV1,
    pub package_sha256: String,
    pub harness_status: HarnessStatusV1,
    pub scenarios: Vec<LoaderLabScenarioResultV1>,
    pub artifacts: Vec<ArtifactRefV1>,
}

impl LoaderLabRunV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 || self.run_id.is_empty() || self.scenarios.is_empty() {
            return Err(String::from("loader lab manifest is incomplete"));
        }
        if !is_digest(&self.package_sha256) {
            return Err(String::from("loader lab package digest is invalid"));
        }
        if self.harness_status != HarnessStatusV1::Complete {
            return Err(String::from("loader lab cleanup is incomplete"));
        }
        let production_count = self
            .scenarios
            .iter()
            .filter(|scenario| scenario.production_equivalent)
            .count();
        if production_count != 1 {
            return Err(String::from(
                "loader lab requires exactly one production-equivalent scenario",
            ));
        }
        if self.scenarios.iter().any(|scenario| {
            scenario.cleanup.status() != memcordon_windows_launch_core::CleanupStatusV1::Complete
                || scenario.production_equivalent == scenario.perturbed
        }) {
            return Err(String::from(
                "loader lab scenario cleanup or perturbation label is invalid",
            ));
        }
        let mut scenario_ids = std::collections::BTreeSet::new();
        if self
            .scenarios
            .iter()
            .any(|scenario| !scenario_ids.insert(&scenario.scenario_id))
        {
            return Err(String::from("loader lab scenario ids are not unique"));
        }
        if self.artifacts.is_empty() {
            return Err(String::from(
                "loader lab manifest has no artifact references",
            ));
        }
        let mut artifact_paths = std::collections::BTreeSet::new();
        if self
            .artifacts
            .iter()
            .any(|artifact| !artifact_paths.insert(artifact.relative_path()))
        {
            return Err(String::from("loader lab artifact paths are not unique"));
        }
        if self.scenarios.iter().any(|scenario| {
            scenario
                .launch_plan_sha256
                .as_deref()
                .is_some_and(|digest| !is_digest(digest))
                || scenario.attachments.is_empty()
                || scenario
                    .attachments
                    .iter()
                    .any(|attachment| !self.artifacts.contains(attachment))
                || (matches!(scenario.handshake, HandshakeOutcomeV1::Authenticated { .. })
                    && !matches!(
                        scenario.failure_stage,
                        None | Some(WindowsLoaderQualificationStageV2::ExitDrain)
                    ))
        }) {
            return Err(String::from(
                "loader lab scenario evidence or attachment manifest is incomplete",
            ));
        }
        Ok(())
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == sha2::Sha256::output_size() * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
