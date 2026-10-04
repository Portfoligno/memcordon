//! Frozen historical workload-report decoding. No admission or native permission factories.
use crate::workload_contract::*;
use crate::workload_evidence::{
    AdmissionAvailabilityFailure, AuthorizationKnowledge, BaselineRestrictionObservationV1,
    EffectiveWorkloadPolicyV1, False, PENDING_PRELAUNCH_CHECKS, PolicyTerminalEvidenceV1,
    PrelaunchCheck, RequestBindingV1, WorkloadRequestReport, baseline_observation,
};
use crate::workload_registry::{AdmissionRejectionV1, BaselineProfile};
use crate::{BoundedText, BoundedVec, DiagnosticSha256, PublicProviderBindingV1};
use serde::{Deserialize, Serialize};

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
    pub fn matches_contract(&self, contract: &WorkloadContractV1) -> bool {
        crate::workload_evidence::RuntimePlanBinding::from_local_grant(
            contract,
            self.registry_digest.clone(),
            self.provider.clone(),
            self.boot_identity.clone(),
        )
        .is_ok_and(|expected| {
            expected.request == self.request
                && expected.registry_digest == self.registry_digest
                && expected.provider == self.provider
                && expected.boot_identity == self.boot_identity
                && expected.effective_policy_digest == self.effective_policy_digest
        })
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
