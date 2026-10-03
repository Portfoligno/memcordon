//! Frozen numeric public reports, readable only as historical diagnostics.
//! These readers never construct local grants, admissions, or operational bindings.
use crate::historical_workload_evidence::WorkloadResolutionReportV1;
use crate::workload_contract::{ContractVersionOne, NetworkCeilingV1, PolicyEpoch, ProfileRef};
use crate::workload_evidence::{BaselineRestrictionObservationV1, False, WorkloadRequestReport};
use crate::workload_registry::BaselineProfile;
use crate::{BoundedText, BoundedVec, DiagnosticSha256, PublicProviderBindingV1};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub struct HistoricalPlanReport {
    document: serde_json::Value,
}

#[derive(Clone, Debug)]
pub struct HistoricalDoctorReport {
    document: serde_json::Value,
}

fn document(bytes: &[u8], schema: u32) -> Result<serde_json::Value, String> {
    if bytes.len() > crate::result_v1::RESULT_MAX_BYTES {
        return Err("historical public report exceeds byte bound".into());
    }
    crate::workload_contract::reject_duplicate_json_keys(bytes)?;
    let document: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if document
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        != Some(u64::from(schema))
    {
        return Err("historical public report schema differs".into());
    }
    Ok(document)
}

impl HistoricalPlanReport {
    pub fn document(&self) -> &serde_json::Value {
        &self.document
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let document = document(bytes, crate::report::PLAN_REPORT_SCHEMA_VERSION)?;
        let request: WorkloadRequestReport =
            serde_json::from_value(document["request"]["workload"].clone())
                .map_err(|error| error.to_string())?;
        let resolution: WorkloadResolutionReportV1 =
            serde_json::from_value(document["resolution"]["effective"]["workload"].clone())
                .map_err(|error| error.to_string())?;
        if !resolution.matches_request(&request)
            || matches!(&request, WorkloadRequestReport::StrictV1 { contract }
                if ![BaselineProfile::LinuxUnixCreate, BaselineProfile::WindowsHostNetworkExternal]
                    .into_iter().any(|profile| resolution.valid_plan_response(contract, profile)))
        {
            return Err("historical plan binding differs from request".into());
        }
        let mut neutral = document.clone();
        neutral["request"]["workload"] = serde_json::json!({"state":"legacy-unspecified"});
        neutral["resolution"]["effective"]["workload"] = serde_json::to_value(
            crate::workload_evidence::RuntimeWorkloadResolution::LegacyUnspecified {
                restrictions: BaselineRestrictionObservationV1::UnmanagedStandardBackend,
            },
        )
        .map_err(|error| error.to_string())?;
        serde_json::from_value::<crate::PlanReport>(neutral).map_err(|error| error.to_string())?;
        Ok(Self { document })
    }
}

#[derive(Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
enum HistoricalDiscovery {
    Authenticated {
        discovery: Box<HistoricalCapabilities>,
    },
    Unavailable {
        reason: BoundedText<256>,
    },
    Unsupported,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalCapabilities {
    schema_version: ContractVersionOne,
    provider: PublicProviderBindingV1,
    boot_identity: BoundedText<128>,
    epoch: Option<PolicyEpoch>,
    registry_digest: Option<DiagnosticSha256>,
    catalog_digest: DiagnosticSha256,
    profile: ProfileRef,
    supported: bool,
    available: bool,
    qualification_digest: DiagnosticSha256,
    restriction: BaselineRestrictionObservationV1,
    ceiling: NetworkCeilingV1,
    grants: BoundedVec<crate::workload_discovery::DiscoverableGrantV1, 2048>,
    complete: bool,
    cache_ttl_seconds: u32,
    maximum_live_bindings: u32,
    maximum_snapshots: u32,
    target_authorized: False,
}

impl HistoricalCapabilities {
    fn validate(&self) -> bool {
        let Some(profile) = [
            BaselineProfile::LinuxUnixCreate,
            BaselineProfile::WindowsHostNetworkExternal,
        ]
        .into_iter()
        .find(|profile| profile.reference() == self.profile) else {
            return false;
        };
        let grants = self.grants.as_slice();
        !grants.iter().enumerate().any(|(index, grant)| {
            !crate::workload_registry::ceiling_contains(&grant.ceiling, &profile.ceiling())
                || grants[..index]
                    .iter()
                    .any(|previous| previous.authorization == grant.authorization)
        }) && serde_json::to_vec(self)
            .is_ok_and(|bytes| bytes.len() <= crate::workload_limits::PUBLIC_OBJECT_BYTES)
            && self.provider.is_consistent()
            && !self.boot_identity.as_str().is_empty()
            && self.ceiling == profile.ceiling()
            && self.restriction == crate::workload_evidence::baseline_observation(profile)
            && String::from(self.catalog_digest.clone())
                == crate::runtime_manifest::baseline_catalog_digest(
                    profile == BaselineProfile::WindowsHostNetworkExternal,
                )
            && self.epoch.is_some() == self.registry_digest.is_some()
            && self.supported
            && self.complete
            && self.cache_ttl_seconds <= 60
            && self.maximum_live_bindings == 256
            && self.maximum_snapshots == 16
            && (self.epoch.is_some() || (!self.available && grants.is_empty()))
    }
}

impl HistoricalDoctorReport {
    pub fn document(&self) -> &serde_json::Value {
        &self.document
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let document = document(bytes, crate::report::DOCTOR_REPORT_SCHEMA_VERSION)?;
        let discovery: HistoricalDiscovery =
            serde_json::from_value(document["workload_discovery"].clone())
                .map_err(|error| error.to_string())?;
        match discovery {
            HistoricalDiscovery::Authenticated { discovery } if !discovery.validate() => {
                return Err("historical discovery facts are inconsistent".into());
            }
            HistoricalDiscovery::Unavailable { reason } => {
                let _ = reason;
            }
            _ => {}
        }
        if let Some(value) = document["requirement"]
            .get("workload")
            .filter(|value| !value.is_null())
        {
            let _: WorkloadResolutionReportV1 =
                serde_json::from_value(value.clone()).map_err(|error| error.to_string())?;
        }
        let mut neutral = document.clone();
        neutral["workload_discovery"] = serde_json::json!({"state":"unsupported"});
        neutral["requirement"]["workload"] = serde_json::Value::Null;
        serde_json::from_value::<crate::DoctorReport>(neutral)
            .map_err(|error| error.to_string())?;
        Ok(Self { document })
    }
}
