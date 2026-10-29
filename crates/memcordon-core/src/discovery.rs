//! Sole current capability and planning formats. These observations never authorize launch.
use crate::{BoundedText, BoundedVec, DiagnosticSha256};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileObservationV3 {
    pub profile: BoundedText<128>,
    pub supported: bool,
    pub installed: bool,
    pub currently_available: bool,
    pub limitations: BoundedVec<BoundedText<2048>, 16>,
    pub request: crate::runtime_manifest_v2::WireVersion,
    pub result: crate::runtime_manifest_v2::WireVersion,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitiesV3 {
    pub format: String,
    pub revision: u32,
    pub tool: crate::ToolReport,
    pub host: crate::HostReport,
    pub selected: Option<crate::BackendCapabilityReport>,
    pub available: Vec<crate::BackendCapabilityReport>,
    pub unavailable: Vec<crate::UnavailableCapabilityReport>,
    pub requirement: crate::RequirementReport,
    pub profiles: BoundedVec<ProfileObservationV3, 4>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanV3 {
    pub format: String,
    pub revision: u32,
    pub tool: crate::ToolReport,
    pub budget_tokens: Vec<crate::BudgetTokenReport>,
    pub resources: crate::RequestedPolicyReport,
    pub resolution: crate::PlanResolutionReport,
    pub request_sha256: Option<DiagnosticSha256>,
    pub compatible: bool,
    pub authorizes_launch: bool,
    pub remaining_live_checks: BoundedVec<BoundedText<2048>, 16>,
}

impl ProfileObservationV3 {
    pub fn validate(&self) -> Result<(), String> {
        if !matches!(
            self.profile.as_str(),
            "linux-private-workload-v1" | "windows-sealed-current-token-v1"
        ) || self.request.format != "memcordon.workload-request"
            || self.request.revision != 1
            || self.result.format != "memcordon.result"
            || self.result.revision != 3
            || self.currently_available && (!self.supported || !self.installed)
        {
            return Err("unsupported or inconsistent profile observation".into());
        }
        Ok(())
    }
}
impl CapabilitiesV3 {
    pub fn validate(&self) -> Result<(), String> {
        if self.format != "memcordon.capabilities"
            || self.revision != 3
            || self.available.len() > 16
            || self.unavailable.len() > 32
        {
            return Err("unsupported or oversized capabilities".into());
        }
        let mut profiles = std::collections::BTreeSet::new();
        for profile in self.profiles.as_slice() {
            profile.validate()?;
            if !profiles.insert(profile.profile.as_str()) {
                return Err("duplicate profile observation".into());
            }
        }
        Ok(())
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let value: Self = parse(bytes, "memcordon.capabilities")?;
        value.validate()?;
        Ok(value)
    }
}
impl PlanV3 {
    pub fn validate(&self) -> Result<(), String> {
        if self.format != "memcordon.plan"
            || self.revision != 3
            || self.authorizes_launch
            || self.resolution.launch_proof
            || self.budget_tokens.len() > 2
        {
            return Err("unsupported plan or local launch proof".into());
        }
        let invocation = crate::InvocationReport {
            syntax: "plus-budgets-v1".into(),
            budget_tokens: self.budget_tokens.clone(),
            memory_token: self
                .budget_tokens
                .iter()
                .find(|token| token.kind == crate::BudgetKindReport::Memory)
                .map(|token| token.token.clone()),
            deadline_token: self
                .budget_tokens
                .iter()
                .find(|token| token.kind == crate::BudgetKindReport::Time)
                .map(|token| token.token.clone()),
            argv: Vec::new(),
        };
        let policy = crate::PolicyEnvelopeReport {
            requested: self.resources.clone(),
            effective: self.resolution.effective.clone(),
            effects: self.resolution.effects.clone(),
        };
        policy.validate(&invocation).map_err(|e| e.to_string())?;
        Ok(())
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let value: Self = parse(bytes, "memcordon.plan")?;
        value.validate()?;
        Ok(value)
    }
}
fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8], format: &str) -> Result<T, String> {
    if bytes.len() > 1024 * 1024 {
        return Err("discovery exceeds byte bound".into());
    }
    crate::canonical_json::reject_duplicate_json_keys(bytes)?;
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if value.get("format").and_then(|v| v.as_str()) != Some(format)
        || value.get("revision").and_then(|v| v.as_u64()) != Some(3)
    {
        return Err("unsupported discovery format".into());
    }
    serde_json::from_value(value).map_err(|e| e.to_string())
}
