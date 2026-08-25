use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPackageInspectionV2 {
    pub schema_version: u32,
    pub version: String,
    pub source_commit: String,
    pub executable_sha256: String,
    pub provider_protocol: u32,
    pub mechanism: String,
    pub execution_report_schema: u32,
    pub plan_report_schema: u32,
    pub doctor_report_schema: u32,
    #[serde(flatten)]
    pub platform: ProviderPackageMetadataV2,
    pub compiled_metadata_valid: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)] // Keep package inspection fields direct and schema-shaped.
#[serde(tag = "platform", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ProviderPackageMetadataV2 {
    LinuxSystemd {
        control_service_sha256: String,
        control_socket_sha256: String,
        launcher_service_sha256: String,
        launcher_socket_sha256: String,
        tmpfiles_sha256: String,
    },
    WindowsService {
        control_service_name: String,
        launcher_service_name: String,
        control_service_config_sha256: String,
        launcher_service_config_sha256: String,
        control_pipe: String,
        launcher_pipe: String,
        binary_install_path: String,
        state_root: String,
        control_service_sid_type: String,
        launcher_service_sid_type: String,
        control_required_privileges: Vec<String>,
        launcher_required_privileges: Vec<String>,
        control_pipe_security_sha256: String,
        launcher_pipe_security_sha256: String,
        install_directory_security_sha256: String,
        state_directory_security_sha256: String,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledProviderInspectionV2 {
    pub schema_version: u32,
    pub agent: AgentPackageInspectionV2,
    pub installed_executable_sha256: String,
    pub installed_artifacts_valid: bool,
    pub provider_identity: Option<String>,
    pub provider_reachable: bool,
    pub qualification_complete: bool,
}
