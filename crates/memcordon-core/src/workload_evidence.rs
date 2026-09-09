//! Workload declarations, authenticated admission and terminal enforcement remain distinct.
use crate::workload_contract::*;
use crate::workload_registry::{AdmissionRejectionV1, BaselineProfile};
use crate::{BoundedText, BoundedVec, DiagnosticSha256, PublicProviderBindingV1};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum WorkloadRequestReport {
    #[default]
    LegacyUnspecified,
    StrictV1 {
        contract: Box<WorkloadContractV1>,
    },
}
impl WorkloadRequestReport {
    pub fn from_contract(contract: Option<&WorkloadContractV1>) -> Self {
        match contract {
            Some(contract) => Self::StrictV1 {
                contract: Box::new(contract.clone()),
            },
            None => Self::LegacyUnspecified,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BaselineRestrictionObservationV1 {
    LinuxUnixOnlySocketSyscallFilterAlternatePathsUnknown,
    WindowsNetworkExternallyGoverned,
    UnmanagedStandardBackend,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestBindingV1 {
    pub request_digest: DiagnosticSha256,
    pub workload_plan_digest: DiagnosticSha256,
    pub profile: ProfileRef,
    pub authorization: AuthorizationRef,
    pub epoch: PolicyEpoch,
}
impl RequestBindingV1 {
    pub fn from_contract(contract: &WorkloadContractV1) -> Result<Self, String> {
        Ok(Self {
            request_digest: crate::workload_codec::contract_digest(contract)?,
            workload_plan_digest: contract.workload_plan_digest.clone(),
            profile: contract.authorized_profile.clone(),
            authorization: contract.authorization.clone(),
            epoch: contract.expected_epoch.clone(),
        })
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanBindingV1 {
    pub request: RequestBindingV1,
    pub registry_digest: DiagnosticSha256,
    pub qualification_digest: DiagnosticSha256,
    pub provider: PublicProviderBindingV1,
    pub boot_identity: BoundedText<128>,
    pub effective_policy_digest: DiagnosticSha256,
}
impl PlanBindingV1 {
    pub fn from_authorized(
        request: &WorkloadContractV1,
        registry_digest: DiagnosticSha256,
        qualification_digest: DiagnosticSha256,
        provider: PublicProviderBindingV1,
        boot_identity: BoundedText<128>,
    ) -> Result<Self, String> {
        if !provider.is_consistent() || boot_identity.as_str().is_empty() {
            return Err("provider/boot binding unavailable".into());
        }
        let profile = baseline_for(&request.authorized_profile)
            .ok_or("unknown qualified baseline profile")?;
        let ceiling = profile.ceiling();
        let request = RequestBindingV1::from_contract(request)?;
        let mut effective = crate::workload_codec::Encoder::new(
            b"effective-workload-policy-v1",
            crate::workload_limits::PUBLIC_OBJECT_BYTES,
        )?;
        effective.digest(&request.request_digest)?;
        effective.digest(&request.profile.semantic_digest)?;
        effective.digest(&registry_digest)?;
        crate::workload_codec::encode_ceiling(&mut effective, &ceiling)?;
        Ok(Self {
            request,
            registry_digest,
            qualification_digest,
            provider,
            boot_identity,
            effective_policy_digest: crate::workload_codec::hash_bytes(&effective.finish()),
        })
    }

    pub fn matches_contract(&self, contract: &WorkloadContractV1) -> bool {
        Self::from_authorized(
            contract,
            self.registry_digest.clone(),
            self.qualification_digest.clone(),
            self.provider.clone(),
            self.boot_identity.clone(),
        )
        .is_ok_and(|expected| expected == *self)
    }
}

fn baseline_for(reference: &ProfileRef) -> Option<BaselineProfile> {
    [
        BaselineProfile::LinuxUnixCreate,
        BaselineProfile::WindowsHostNetworkExternal,
    ]
    .into_iter()
    .find(|profile| profile.reference() == *reference)
}

pub fn baseline_observation(profile: BaselineProfile) -> BaselineRestrictionObservationV1 {
    match profile {
        BaselineProfile::LinuxUnixCreate => {
            BaselineRestrictionObservationV1::LinuxUnixOnlySocketSyscallFilterAlternatePathsUnknown
        }
        BaselineProfile::WindowsHostNetworkExternal => {
            BaselineRestrictionObservationV1::WindowsNetworkExternallyGoverned
        }
    }
}

pub const PENDING_PRELAUNCH_CHECKS: [PrelaunchCheck; 7] = [
    PrelaunchCheck::CallerIdentity,
    PrelaunchCheck::InvocationIdentity,
    PrelaunchCheck::DescriptorCustody,
    PrelaunchCheck::NativeControls,
    PrelaunchCheck::Guardian,
    PrelaunchCheck::CurrentEpoch,
    PrelaunchCheck::DurableCheckpoint,
];
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptBindingV1 {
    pub plan: PlanBindingV1,
    pub attempt_id: BoundedText<128>,
    pub restart_attempt: u64,
    pub admission_nonce: Nonce128,
    /// Opaque lookup reference to the provider's private authenticated caller and
    /// exact native invocation record; no environment/argument digest is public.
    pub caller_invocation_reference: Nonce128,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrelaunchCheck {
    CallerIdentity,
    InvocationIdentity,
    DescriptorCustody,
    NativeControls,
    Guardian,
    CurrentEpoch,
    DurableCheckpoint,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorizationKnowledge {
    NotAuthorized,
    Authorized,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdmissionAvailabilityFailure {
    ProviderUnavailable,
    TransportLost,
    UnqualifiedHost,
    BindingUnavailable,
    TerminalUnavailable,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveWorkloadPolicyV1 {
    pub profile: BaselineProfile,
    pub ceiling: NetworkCeilingV1,
    pub restriction: BaselineRestrictionObservationV1,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct False(bool);
impl<'de> Deserialize<'de> for False {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        if bool::deserialize(decoder)? {
            return Err(serde::de::Error::custom(
                "rejection cannot authorize a target",
            ));
        }
        Ok(Self::default())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum WorkloadResolutionReportV1 {
    LegacyUnspecified {
        restrictions: BaselineRestrictionObservationV1,
    },
    Planned {
        binding: PlanBindingV1,
        effective: EffectiveWorkloadPolicyV1,
        pending: BoundedVec<PrelaunchCheck, 32>,
    },
    Rejected {
        binding: RequestBindingV1,
        rejection: AdmissionRejectionV1,
        target_authorized: False,
    },
    Admitted {
        binding: AttemptBindingV1,
        effective: EffectiveWorkloadPolicyV1,
        preauthorization: DiagnosticSha256,
    },
    Unavailable {
        request: Option<RequestBindingV1>,
        reason: AdmissionAvailabilityFailure,
        authorization: AuthorizationKnowledge,
    },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadAdmissionRejectionV1 {
    pub request: RequestBindingV1,
    pub rejection: AdmissionRejectionV1,
}
impl WorkloadResolutionReportV1 {
    pub fn valid_plan_response(
        &self,
        contract: &WorkloadContractV1,
        profile: BaselineProfile,
    ) -> bool {
        if !self.matches_request(&WorkloadRequestReport::from_contract(Some(contract))) {
            return false;
        }
        match self {
            Self::Planned {
                binding,
                effective,
                pending,
            } => {
                binding.matches_contract(contract)
                    && contract.authorized_profile == profile.reference()
                    && effective.profile == profile
                    && effective.ceiling == profile.ceiling()
                    && effective.restriction == baseline_observation(profile)
                    && pending.as_slice() == PENDING_PRELAUNCH_CHECKS
            }
            Self::Rejected { .. } => true,
            Self::Unavailable { authorization, .. } => {
                *authorization == AuthorizationKnowledge::NotAuthorized
            }
            _ => false,
        }
    }
    pub fn matches_request(&self, request: &WorkloadRequestReport) -> bool {
        match request {
            WorkloadRequestReport::LegacyUnspecified => {
                matches!(self, Self::LegacyUnspecified { .. })
            }
            WorkloadRequestReport::StrictV1 { contract } => {
                let Ok(expected) = RequestBindingV1::from_contract(contract) else {
                    return false;
                };
                match self {
                    Self::LegacyUnspecified { .. } => false,
                    Self::Planned { binding, .. } => binding.request == expected,
                    Self::Rejected { binding, .. } => *binding == expected,
                    Self::Admitted { binding, .. } => binding.plan.request == expected,
                    Self::Unavailable { request, .. } => request.as_ref() == Some(&expected),
                }
            }
        }
    }

    pub fn unresolved(
        contract: Option<&WorkloadContractV1>,
        restriction: BaselineRestrictionObservationV1,
    ) -> Self {
        match contract {
            None => Self::LegacyUnspecified {
                restrictions: restriction,
            },
            Some(contract) => Self::Unavailable {
                request: Some(
                    RequestBindingV1::from_contract(contract).expect("validated workload request"),
                ),
                reason: AdmissionAvailabilityFailure::BindingUnavailable,
                authorization: AuthorizationKnowledge::NotAuthorized,
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PolicyTerminalEvidenceV1 {
    Retired {
        attempt_binding: DiagnosticSha256,
        checkpoint: DiagnosticSha256,
        controls_preserved: bool,
        provider_resources_closed: bool,
    },
    Unavailable {
        reason: AdmissionAvailabilityFailure,
    },
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum AttemptPolicyEnforcementV1 {
    #[default]
    LegacyUnspecified,
    NotAuthorized {
        request: RequestBindingV1,
        rejection: AdmissionRejectionV1,
    },
    Authorized {
        admission: Box<AttemptBindingV1>,
        before_authorization: VerifiedCheckpointV1,
        terminal: PolicyTerminalEvidenceV1,
    },
    AuthorizationUncertain {
        request: Option<RequestBindingV1>,
        failure: AdmissionAvailabilityFailure,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "CheckpointWire")]
pub struct VerifiedCheckpointV1 {
    attempt_binding: DiagnosticSha256,
    digest: DiagnosticSha256,
    controls: BaselineRestrictionObservationV1,
    target_gated: bool,
    caller_verified: bool,
    resources_verified: bool,
    guardian_verified: bool,
    epoch_verified: bool,
    durable: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointWire {
    attempt_binding: DiagnosticSha256,
    digest: DiagnosticSha256,
    controls: BaselineRestrictionObservationV1,
    target_gated: bool,
    caller_verified: bool,
    resources_verified: bool,
    guardian_verified: bool,
    epoch_verified: bool,
    durable: bool,
}
impl TryFrom<CheckpointWire> for VerifiedCheckpointV1 {
    type Error = String;
    fn try_from(wire: CheckpointWire) -> Result<Self, String> {
        if !(wire.target_gated
            && wire.caller_verified
            && wire.resources_verified
            && wire.guardian_verified
            && wire.epoch_verified
            && wire.durable)
            || wire.controls == BaselineRestrictionObservationV1::UnmanagedStandardBackend
        {
            return Err("incomplete workload preauthorization checkpoint".into());
        }
        if checkpoint_digest(&wire.attempt_binding, wire.controls)? != wire.digest {
            return Err("workload checkpoint digest differs".into());
        }
        Ok(Self {
            attempt_binding: wire.attempt_binding,
            digest: wire.digest,
            controls: wire.controls,
            target_gated: wire.target_gated,
            caller_verified: wire.caller_verified,
            resources_verified: wire.resources_verified,
            guardian_verified: wire.guardian_verified,
            epoch_verified: wire.epoch_verified,
            durable: wire.durable,
        })
    }
}

fn text(encoder: &mut crate::workload_codec::Encoder, value: &str) -> Result<(), String> {
    if !value.is_ascii() {
        return Err("canonical public binding text must be ASCII".into());
    }
    encoder.count(value.len())?;
    encoder.raw(value.as_bytes())
}
impl AttemptBindingV1 {
    pub fn matches_snapshot(
        &self,
        snapshot: &crate::workload_registry::ProviderAdmissionSnapshotV1,
    ) -> bool {
        snapshot.validate().is_ok()
            && self.admission_nonce == snapshot.admission_nonce
            && self.plan.matches_contract(&snapshot.request)
            && self.caller_invocation_reference == snapshot.caller_invocation_reference
            && self.plan.registry_digest == snapshot.registry_digest
            && self.plan.qualification_digest == snapshot.qualification_digest
            && RequestBindingV1::from_contract(&snapshot.request)
                .is_ok_and(|request| request == self.plan.request)
    }
    pub fn from_snapshot(
        snapshot: &crate::workload_registry::ProviderAdmissionSnapshotV1,
        provider: PublicProviderBindingV1,
        boot_identity: BoundedText<128>,
        attempt_id: BoundedText<128>,
        restart_attempt: u64,
    ) -> Result<Self, String> {
        snapshot.validate()?;
        if !provider.is_consistent()
            || boot_identity.as_str().is_empty()
            || attempt_id.as_str().is_empty()
        {
            return Err("provider/boot/attempt binding unavailable".into());
        }
        Ok(Self {
            plan: PlanBindingV1::from_authorized(
                &snapshot.request,
                snapshot.registry_digest.clone(),
                snapshot.qualification_digest.clone(),
                provider,
                boot_identity,
            )?,
            attempt_id,
            restart_attempt,
            admission_nonce: snapshot.admission_nonce,
            caller_invocation_reference: snapshot.caller_invocation_reference,
        })
    }
    pub fn canonical_digest(&self) -> Result<DiagnosticSha256, String> {
        let mut encoder = crate::workload_codec::Encoder::new(
            b"attempt-policy-binding-v1",
            crate::workload_limits::PUBLIC_OBJECT_BYTES,
        )?;
        let request = &self.plan.request;
        encoder.digest(&request.request_digest)?;
        encoder.digest(&request.workload_plan_digest)?;
        encoder.id(&request.profile.id)?;
        encoder.digest(&request.profile.semantic_digest)?;
        encoder.id(&request.authorization.grant_id)?;
        encoder.u64(request.authorization.grant_revision.get())?;
        encoder.digest(&request.authorization.approved_plan_digest)?;
        encoder.raw(&request.epoch.service_instance.0)?;
        encoder.u64(request.epoch.revision.get())?;
        encoder.digest(&self.plan.registry_digest)?;
        encoder.digest(&self.plan.qualification_digest)?;
        text(&mut encoder, self.plan.provider.generation.as_str())?;
        text(&mut encoder, self.plan.provider.source_commit.as_str())?;
        encoder.digest(&self.plan.provider.runtime_manifest_sha256)?;
        text(&mut encoder, self.plan.boot_identity.as_str())?;
        encoder.digest(&self.plan.effective_policy_digest)?;
        text(&mut encoder, self.attempt_id.as_str())?;
        encoder.u64(self.restart_attempt)?;
        encoder.raw(&self.admission_nonce.0)?;
        encoder.raw(&self.caller_invocation_reference.0)?;
        Ok(crate::workload_codec::hash_bytes(&encoder.finish()))
    }
}
fn checkpoint_digest(
    attempt: &DiagnosticSha256,
    controls: BaselineRestrictionObservationV1,
) -> Result<DiagnosticSha256, String> {
    let mut encoder = crate::workload_codec::Encoder::new(
        b"attempt-policy-enforcement-v1",
        crate::workload_limits::PUBLIC_OBJECT_BYTES,
    )?;
    encoder.digest(attempt)?;
    encoder.byte(match controls {
        BaselineRestrictionObservationV1::LinuxUnixOnlySocketSyscallFilterAlternatePathsUnknown => {
            1
        }
        BaselineRestrictionObservationV1::WindowsNetworkExternallyGoverned => 2,
        BaselineRestrictionObservationV1::UnmanagedStandardBackend => {
            return Err("unmanaged controls cannot make a verified checkpoint".into());
        }
    })?;
    encoder.raw(&[1, 1, 1, 1, 1, 1])?;
    Ok(crate::workload_codec::hash_bytes(&encoder.finish()))
}
impl VerifiedCheckpointV1 {
    pub fn matches_binding(&self, binding: &AttemptBindingV1) -> bool {
        baseline_for(&binding.plan.request.profile)
            .is_some_and(|profile| self.controls == baseline_observation(profile))
            && binding.canonical_digest().is_ok_and(|digest| {
                digest == self.attempt_binding
                    && checkpoint_digest(&digest, self.controls).as_ref() == Ok(&self.digest)
            })
    }
    // Each independently observed gate is required; none may default to verified.
    #[allow(clippy::too_many_arguments)]
    pub fn observed(
        binding: &AttemptBindingV1,
        controls: BaselineRestrictionObservationV1,
        target_gated: bool,
        caller_verified: bool,
        resources_verified: bool,
        guardian_verified: bool,
        epoch_verified: bool,
        durable: bool,
    ) -> Result<Self, String> {
        let attempt_binding = binding.canonical_digest()?;
        let digest = checkpoint_digest(&attempt_binding, controls)?;
        CheckpointWire {
            attempt_binding,
            digest,
            controls,
            target_gated,
            caller_verified,
            resources_verified,
            guardian_verified,
            epoch_verified,
            durable,
        }
        .try_into()
    }
    pub fn digest(&self) -> &DiagnosticSha256 {
        &self.digest
    }
}
impl AttemptPolicyEnforcementV1 {
    pub fn resolution(&self) -> Option<WorkloadResolutionReportV1> {
        if !self.is_consistent() {
            return None;
        }
        match self {
            Self::Authorized {
                admission,
                before_authorization,
                ..
            } => {
                let profile = baseline_for(&admission.plan.request.profile)?;
                Some(WorkloadResolutionReportV1::Admitted {
                    binding: admission.as_ref().clone(),
                    effective: EffectiveWorkloadPolicyV1 {
                        profile,
                        ceiling: profile.ceiling(),
                        restriction: baseline_observation(profile),
                    },
                    preauthorization: before_authorization.digest().clone(),
                })
            }
            Self::NotAuthorized { request, rejection } => {
                Some(WorkloadResolutionReportV1::Rejected {
                    binding: request.clone(),
                    rejection: rejection.clone(),
                    target_authorized: False::default(),
                })
            }
            Self::AuthorizationUncertain { request, failure } => {
                Some(WorkloadResolutionReportV1::Unavailable {
                    request: request.clone(),
                    reason: *failure,
                    authorization: AuthorizationKnowledge::Unknown,
                })
            }
            Self::LegacyUnspecified => None,
        }
    }

    pub fn valid_native_terminal(
        &self,
        contract: Option<&WorkloadContractV1>,
        profile: BaselineProfile,
        attempt_id: &str,
        restart_attempt: u64,
        boot: &str,
    ) -> bool {
        if !self.matches_terminal_request(contract) {
            return false;
        }
        match (self, contract) {
            (Self::LegacyUnspecified, None) => true,
            (
                Self::Authorized {
                    admission,
                    before_authorization,
                    ..
                },
                Some(contract),
            ) => {
                admission.plan.matches_contract(contract)
                    && contract.authorized_profile == profile.reference()
                    && admission.attempt_id.as_str() == attempt_id
                    && admission.restart_attempt == restart_attempt
                    && admission.plan.boot_identity.as_str() == boot
                    && before_authorization.controls == baseline_observation(profile)
            }
            _ => false,
        }
    }

    pub fn matches_terminal_request(&self, contract: Option<&WorkloadContractV1>) -> bool {
        match (self, contract) {
            (Self::LegacyUnspecified, None) => true,
            (Self::Authorized { admission, .. }, Some(contract)) => {
                self.terminal_success()
                    && RequestBindingV1::from_contract(contract)
                        .is_ok_and(|request| request == admission.plan.request)
            }
            _ => false,
        }
    }

    pub fn retired(
        binding: AttemptBindingV1,
        checkpoint: VerifiedCheckpointV1,
        controls_preserved: bool,
        provider_resources_closed: bool,
    ) -> Result<Self, String> {
        if !(controls_preserved && provider_resources_closed) {
            return Err("terminal workload enforcement is incomplete".into());
        }
        let digest = binding.canonical_digest()?;
        if checkpoint.attempt_binding != digest {
            return Err("checkpoint belongs to another attempt".into());
        }
        Ok(Self::Authorized {
            admission: Box::new(binding),
            terminal: PolicyTerminalEvidenceV1::Retired {
                attempt_binding: digest,
                checkpoint: checkpoint.digest.clone(),
                controls_preserved,
                provider_resources_closed,
            },
            before_authorization: checkpoint,
        })
    }
    pub fn is_consistent(&self) -> bool {
        match self {
            Self::LegacyUnspecified => true,
            Self::NotAuthorized { request, .. } => {
                request.authorization.approved_plan_digest == request.workload_plan_digest
            }
            Self::AuthorizationUncertain { .. } => true,
            Self::Authorized {
                admission,
                before_authorization,
                terminal,
            } => {
                let Ok(digest) = admission.canonical_digest() else {
                    return false;
                };
                if !before_authorization.matches_binding(admission) {
                    return false;
                }
                match terminal {
                    PolicyTerminalEvidenceV1::Retired {
                        attempt_binding,
                        checkpoint,
                        controls_preserved,
                        provider_resources_closed,
                    } => {
                        attempt_binding == &digest
                            && checkpoint == before_authorization.digest()
                            && *controls_preserved
                            && *provider_resources_closed
                    }
                    PolicyTerminalEvidenceV1::Unavailable { .. } => true,
                }
            }
        }
    }
    pub fn terminal_success(&self) -> bool {
        self.is_consistent()
            && matches!(
                self,
                Self::Authorized {
                    terminal: PolicyTerminalEvidenceV1::Retired { .. },
                    ..
                }
            )
    }
}
