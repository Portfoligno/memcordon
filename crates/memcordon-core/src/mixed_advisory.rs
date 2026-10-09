//! Authenticated descriptions of the combined profile. None grants launch authority.
use crate::workload_contract_v3::WorkloadContractV3;
use crate::workload_registry_v3::AdmissionCodeV3;
use crate::{DiagnosticSha256, PublicProviderBindingV1};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MixedPlanV2 {
    pub format: String,
    pub revision: u32,
    pub provider_contract: u32,
    pub launch_wire: u32,
    pub provider: PublicProviderBindingV1,
    pub request: WorkloadContractV3,
    pub request_sha256: DiagnosticSha256,
    pub available_for_preparation: bool,
    pub conflict: Option<AdmissionCodeV3>,
    pub prerequisite_error: Option<crate::BoundedText<4096>>,
    pub pending: Vec<String>,
    pub authorizes_launch: bool,
}
impl MixedPlanV2 {
    pub fn validate(&self) -> Result<(), String> {
        self.request.validate()?;
        if self.format != "memcordon.plan"
            || self.revision != 2
            || self.provider_contract != 4
            || self.launch_wire != 4
            || self.request_sha256 != self.request.digest()?
            || self.authorizes_launch
            || self.pending != pending_obligations()
            || self.available_for_preparation
                != (self.conflict.is_none() && self.prerequisite_error.is_none())
        {
            return Err("mixed advisory plan format, association or authority differs".into());
        }
        Ok(())
    }
}

pub fn pending_obligations() -> Vec<String> {
    [
        "authenticate-live-caller",
        "reserve-exclusive-account",
        "pin-image-and-loader-closure",
        "materialize-readonly-root",
        "observe-native-namespaces",
        "check-target-credentials-and-filter",
        "recheck-local-epoch-at-release",
        "observe-exec-event",
        "observe-live-revocation",
        "drain-and-retire-aggregate",
        "export-selected-files",
        "retire-root-and-account",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MixedCapabilitiesV2 {
    pub format: String,
    pub revision: u32,
    pub provider_contract: u32,
    pub launch_wire: u32,
    pub provider: PublicProviderBindingV1,
    pub boot_identity: crate::BoundedText<64>,
    pub profile: crate::workload_contract::ProfileRef,
    pub request_versions: Vec<u32>,
    pub carrier_versions: Vec<u32>,
    pub supported: bool,
    pub installed_enabled: bool,
    pub exclusive_identity_eligible: bool,
    pub image_support: bool,
    pub plan: Option<MixedPlanV2>,
    pub authorizes_launch: bool,
}
impl MixedCapabilitiesV2 {
    pub fn validate(&self) -> Result<(), String> {
        if self.format != "memcordon.capabilities"
            || self.revision != 2
            || self.provider_contract != 4
            || self.launch_wire != 4
            || self.profile != crate::workload_registry_v3::profile_reference()
            || self.request_versions != [3]
            || self.carrier_versions != [2]
            || self.authorizes_launch
            || self.boot_identity.as_str().is_empty()
            || (self.installed_enabled && !self.supported)
            || (self.exclusive_identity_eligible && !self.installed_enabled)
            || (self.image_support && !self.installed_enabled)
        {
            return Err("mixed capabilities format, profile or authority differs".into());
        }
        if let Some(plan) = &self.plan {
            plan.validate()?;
            if plan.provider != self.provider {
                return Err("mixed capability plan provider differs".into());
            }
        }
        Ok(())
    }
}
