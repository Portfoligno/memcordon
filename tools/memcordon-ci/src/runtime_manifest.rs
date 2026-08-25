use serde::{Deserialize, Serialize};

use crate::config::RuntimeComponentRole;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeComponentRecord {
    pub id: String,
    pub path: String,
    pub role: RuntimeComponentRole,
    pub size: u64,
    pub mode: u32,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeManifestV1 {
    pub schema_version: u32,
    pub project: String,
    pub version: String,
    pub source_commit: String,
    pub target: String,
    pub components: Vec<RuntimeComponentRecord>,
    pub sealed: SealedRuntimeV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SealedRuntimeV1 {
    Included {
        agent_component: String,
        provider_protocol: u32,
        mechanism: String,
        execution_report_schema: u32,
        plan_report_schema: u32,
        doctor_report_schema: u32,
        qualification_schema: u32,
    },
    NotApplicable {
        reason: String,
    },
}

pub fn fuzz_runtime_manifest(data: &[u8]) {
    let _ = serde_json::from_slice::<RuntimeManifestV1>(data);
}
