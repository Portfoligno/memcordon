//! Public V4 private-plan projection. This data is not an admission or host
//! capability by itself: only an authenticated live provider response backed
//! by protected current installed qualification may use it for a launch.

use serde::{Deserialize, Serialize};

use crate::workload_codec::contract_digest_v2;
use crate::workload_contract::{WorkloadContractV2, reject_duplicate_json_keys};
use crate::workload_evidence_v2::QualifiedNativeAbiV2;
use crate::{DiagnosticSha256, workload_limits};

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivatePlanReceiptV2 {
    pub schema_version: u32,
    pub contract_digest: DiagnosticSha256,
    pub registry_digest: DiagnosticSha256,
    pub installed_qualification_sha256: DiagnosticSha256,
    pub runtime_manifest_sha256: DiagnosticSha256,
    pub generation_digest: DiagnosticSha256,
    pub source_commit: String,
    pub native_abi: QualifiedNativeAbiV2,
}

impl PrivatePlanReceiptV2 {
    pub fn parse_for_contract(bytes: &[u8], contract: &WorkloadContractV2) -> Result<Self, String> {
        if bytes.len() > workload_limits::PUBLIC_OBJECT_BYTES {
            return Err("private plan receipt exceeds byte bound".into());
        }
        reject_duplicate_json_keys(bytes)?;
        let receipt: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        receipt.validate_for_contract(contract)?;
        Ok(receipt)
    }

    pub fn validate_for_contract(&self, contract: &WorkloadContractV2) -> Result<(), String> {
        contract.validate()?;
        if self.schema_version != 2
            || self.contract_digest != contract_digest_v2(contract)?
            || self.source_commit.is_empty()
            || !self
                .source_commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("private plan receipt differs from exact V2 contract".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PrivatePlanAvailabilityV2 {
    Available { receipt: PrivatePlanReceiptV2 },
    Unavailable { reason: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivatePlanReportV10 {
    pub schema_version: u32,
    pub contract_digest: DiagnosticSha256,
    pub availability: PrivatePlanAvailabilityV2,
    /// Planning does not create or release a target.
    pub launch_proof: bool,
}

impl PrivatePlanReportV10 {
    pub fn validate_for_contract(&self, contract: &WorkloadContractV2) -> Result<(), String> {
        if self.schema_version != 10
            || self.launch_proof
            || self.contract_digest != contract_digest_v2(contract)?
        {
            return Err("V10 private plan identity or launch proof differs".into());
        }
        match &self.availability {
            PrivatePlanAvailabilityV2::Available { receipt } => {
                receipt.validate_for_contract(contract)
            }
            PrivatePlanAvailabilityV2::Unavailable { reason }
                if !reason.is_empty() && reason.len() <= workload_limits::PUBLIC_OBJECT_BYTES =>
            {
                Ok(())
            }
            _ => Err("V10 private plan unavailable reason is invalid".into()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateDoctorReportV7 {
    pub schema_version: u32,
    pub contract_digest: DiagnosticSha256,
    pub host_os: String,
    pub architecture: String,
    pub availability: PrivatePlanAvailabilityV2,
    /// A V2 plan is not an execution probe or a release test.
    pub execution_probe_performed: bool,
}

impl PrivateDoctorReportV7 {
    pub fn validate_for_contract(&self, contract: &WorkloadContractV2) -> Result<(), String> {
        if self.schema_version != 7
            || self.execution_probe_performed
            || self.contract_digest != contract_digest_v2(contract)?
            || self.host_os.is_empty()
            || self.architecture.is_empty()
        {
            return Err("V7 private doctor identity or probe proof differs".into());
        }
        PrivatePlanReportV10 {
            schema_version: 10,
            contract_digest: self.contract_digest.clone(),
            availability: self.availability.clone(),
            launch_proof: false,
        }
        .validate_for_contract(contract)
    }
}
