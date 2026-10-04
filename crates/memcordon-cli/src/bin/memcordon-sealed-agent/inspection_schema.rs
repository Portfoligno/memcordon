use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize)]
#[allow(dead_code)] // Preserve the stored historical V3 evidence schema.
pub struct AgentPackageInspectionV3 {
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
    pub platform: ProviderPackageMetadataV3,
    pub compiled_metadata_valid: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(dead_code)] // Preserve the stored historical V3 evidence schema.
#[allow(clippy::large_enum_variant)] // Keep package inspection fields direct and schema-shaped.
#[serde(tag = "platform", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ProviderPackageMetadataV3 {
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
        session_broker_service_name: String,
        guardian_slot_count: usize,
        control_service_config_sha256: String,
        launcher_service_config_sha256: String,
        session_broker_service_config_sha256: String,
        guardian_slot_config_sha256: String,
        control_pipe: String,
        launcher_pipe: String,
        session_broker_pipe: String,
        guardian_pipe_prefix: String,
        binary_install_path: String,
        target_desktop_bootstrap_install_path: String,
        target_desktop_bootstrap_sha256: String,
        target_desktop_bootstrap_crt_static: bool,
        target_desktop_bootstrap_normal_imports: Vec<String>,
        target_desktop_bootstrap_delayed_imports: Vec<String>,
        target_desktop_bootstrap_loader_contract_sha256: String,
        session_broker_install_path: String,
        session_broker_sha256: String,
        state_root: String,
        control_service_sid_type: String,
        launcher_service_sid_type: String,
        session_broker_service_sid_type: String,
        guardian_slot_service_sid_type: String,
        control_required_privileges: Vec<String>,
        launcher_required_privileges: Vec<String>,
        session_broker_required_privileges: Vec<String>,
        guardian_slot_required_privileges: Vec<String>,
        control_pipe_security_sha256: String,
        launcher_pipe_security_sha256: String,
        session_broker_service_security_sha256: String,
        session_broker_pipe_security_sha256: String,
        guardian_pipe_security_contract_sha256: String,
        install_directory_security_sha256: String,
        state_directory_security_sha256: String,
    },
}

#[derive(Clone, Debug, Serialize)]
pub struct AgentPackageInspectionV4 {
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
    pub platform: ProviderPackageMetadataV4,
    pub compiled_metadata_valid: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum TargetDesktopBootstrapRuntimeV4 {
    StaticVcRuntimeOsUcrt,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)] // Keep package inspection fields direct and schema-shaped.
#[serde(tag = "platform", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ProviderPackageMetadataV4 {
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
        session_broker_service_name: String,
        guardian_slot_count: usize,
        control_service_config_sha256: String,
        launcher_service_config_sha256: String,
        session_broker_service_config_sha256: String,
        guardian_slot_config_sha256: String,
        control_pipe: String,
        launcher_pipe: String,
        session_broker_pipe: String,
        guardian_pipe_prefix: String,
        binary_install_path: String,
        target_desktop_bootstrap_install_path: String,
        target_desktop_bootstrap_sha256: String,
        target_desktop_bootstrap_runtime: TargetDesktopBootstrapRuntimeV4,
        target_desktop_bootstrap_normal_imports: Vec<String>,
        target_desktop_bootstrap_delayed_imports: Vec<String>,
        target_desktop_bootstrap_loader_contract_sha256: String,
        session_broker_install_path: String,
        session_broker_sha256: String,
        state_root: String,
        control_service_sid_type: String,
        launcher_service_sid_type: String,
        session_broker_service_sid_type: String,
        guardian_slot_service_sid_type: String,
        control_required_privileges: Vec<String>,
        launcher_required_privileges: Vec<String>,
        session_broker_required_privileges: Vec<String>,
        guardian_slot_required_privileges: Vec<String>,
        control_pipe_security_sha256: String,
        launcher_pipe_security_sha256: String,
        session_broker_service_security_sha256: String,
        session_broker_pipe_security_sha256: String,
        guardian_pipe_security_contract_sha256: String,
        install_directory_security_sha256: String,
        state_directory_security_sha256: String,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(dead_code)] // Preserve the stored historical V3 evidence schema.
#[serde(deny_unknown_fields)]
pub struct InstalledProviderInspectionV3 {
    pub schema_version: u32,
    pub agent: AgentPackageInspectionV3,
    pub installed_executable_sha256: String,
    pub installed_artifacts_valid: bool,
    pub provider_identity: Option<String>,
    pub provider_reachable: bool,
    pub qualification_complete: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledProviderInspectionV4 {
    pub schema_version: u32,
    pub agent: AgentPackageInspectionV4,
    pub installed_executable_sha256: String,
    pub installed_artifacts_valid: bool,
    pub provider_identity: Option<String>,
    pub provider_reachable: bool,
    pub qualification_complete: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct AgentPackageInspection {
    pub format: AgentInspectionFormat,
    pub revision: InspectionRevision,
    pub version: String,
    pub source_commit: String,
    pub executable_sha256: String,
    pub provider_protocol: u32,
    pub native_protocols: memcordon_core::runtime_manifest::NativeProviderProtocols,
    pub runtime_manifest_schema: u32,
    pub workload_contract_schema: u32,
    pub profile_catalog_sha256: String,
    pub mechanism: String,
    pub execution_report_schema: u32,
    pub plan_report_schema: u32,
    pub doctor_report_schema: u32,
    #[serde(flatten)]
    pub platform: ProviderPackageMetadataV4,
    pub compiled_metadata_valid: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledProviderInspection {
    pub format: InstalledInspectionFormat,
    pub revision: InspectionRevision,
    pub agent: AgentPackageInspection,
    pub installed_executable_sha256: String,
    pub installed_artifacts_valid: bool,
    pub provider_identity: Option<String>,
    pub provider_reachable: bool,
    pub policy: memcordon_core::runtime_manifest::InstalledPolicyObservationV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum AgentInspectionFormat {
    #[serde(rename = "memcordon.agent-package-inspection")]
    Ordinary,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum InstalledInspectionFormat {
    #[serde(rename = "memcordon.installed-provider-inspection")]
    Ordinary,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct InspectionRevision;

impl TryFrom<u32> for InspectionRevision {
    type Error = &'static str;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value == 1 {
            Ok(Self)
        } else {
            Err("unsupported inspection revision")
        }
    }
}

impl From<InspectionRevision> for u32 {
    fn from(_: InspectionRevision) -> Self {
        1
    }
}

// Serde's strict outer derive cannot distinguish flattened enum fields from
// unknown fields. Decode common fields directly (including nested validation),
// then let the strict platform enum validate the remaining, unique fields.
macro_rules! deserialize_inspection {
    ($inspection:ident, $platform:ty, { $($field:ident: $ty:ty),+ $(,)? }) => {
        impl<'de> Deserialize<'de> for $inspection {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct InspectionVisitor;

                impl<'de> serde::de::Visitor<'de> for InspectionVisitor {
                    type Value = $inspection;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        formatter.write_str("a strict flattened provider inspection")
                    }

                    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                        $(let mut $field: Option<$ty> = None;)+
                        let mut platform_fields = serde_json::Map::new();
                        while let Some(key) = map.next_key::<String>()? {
                            match key.as_str() {
                                $(stringify!($field) => {
                                    if $field.is_some() {
                                        return Err(serde::de::Error::duplicate_field(stringify!($field)));
                                    }
                                    $field = Some(map.next_value::<$ty>()?);
                                })+
                                _ => {
                                    if platform_fields.contains_key(&key) {
                                        return Err(serde::de::Error::custom(format!("duplicate field `{key}`")));
                                    }
                                    platform_fields.insert(key, map.next_value::<serde_json::Value>()?);
                                }
                            }
                        }
                        let platform = serde_json::from_value::<$platform>(serde_json::Value::Object(platform_fields))
                            .map_err(serde::de::Error::custom)?;
                        Ok($inspection {
                            $($field: $field.ok_or_else(|| serde::de::Error::missing_field(stringify!($field)))?,)+
                            platform,
                        })
                    }
                }
                deserializer.deserialize_map(InspectionVisitor)
            }
        }
    };
}

deserialize_inspection!(AgentPackageInspectionV3, ProviderPackageMetadataV3, {
    schema_version: u32, version: String, source_commit: String,
    executable_sha256: String, provider_protocol: u32, mechanism: String,
    execution_report_schema: u32, plan_report_schema: u32,
    doctor_report_schema: u32, compiled_metadata_valid: bool,
});
deserialize_inspection!(AgentPackageInspectionV4, ProviderPackageMetadataV4, {
    schema_version: u32, version: String, source_commit: String,
    executable_sha256: String, provider_protocol: u32, mechanism: String,
    execution_report_schema: u32, plan_report_schema: u32,
    doctor_report_schema: u32, compiled_metadata_valid: bool,
});
deserialize_inspection!(AgentPackageInspection, ProviderPackageMetadataV4, {
    format: AgentInspectionFormat, revision: InspectionRevision,
    version: String, source_commit: String,
    executable_sha256: String, provider_protocol: u32,
    native_protocols: memcordon_core::runtime_manifest::NativeProviderProtocols,
    runtime_manifest_schema: u32, workload_contract_schema: u32,
    profile_catalog_sha256: String, mechanism: String,
    execution_report_schema: u32, plan_report_schema: u32,
    doctor_report_schema: u32, compiled_metadata_valid: bool,
});
