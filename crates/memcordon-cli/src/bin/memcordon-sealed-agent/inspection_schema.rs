use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPackageInspectionV1 {
    pub schema_version: u32,
    pub version: String,
    pub source_commit: String,
    pub executable_sha256: String,
    pub provider_protocol: u32,
    pub mechanism: String,
    pub execution_report_schema: u32,
    pub plan_report_schema: u32,
    pub doctor_report_schema: u32,
    pub control_service_sha256: String,
    pub control_socket_sha256: String,
    pub launcher_service_sha256: String,
    pub launcher_socket_sha256: String,
    pub tmpfiles_sha256: String,
    pub compiled_metadata_valid: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledProviderInspectionV1 {
    pub schema_version: u32,
    pub agent: AgentPackageInspectionV1,
    pub installed_executable_sha256: String,
    pub installed_artifacts_valid: bool,
    pub provider_identity: Option<String>,
    pub provider_reachable: bool,
    pub qualification_complete: bool,
}
