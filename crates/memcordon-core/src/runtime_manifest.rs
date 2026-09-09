//! Closed runtime inventory shared by packaging and authenticated clients.
use serde::{Deserialize, Serialize};

/// The baseline catalogue describes existing mechanism limits, not a grant.
pub fn baseline_catalog_digest(windows: bool) -> String {
    use crate::workload_registry::BaselineProfile;
    let profile = if windows {
        BaselineProfile::WindowsHostNetworkExternal
    } else {
        BaselineProfile::LinuxUnixCreate
    };
    let mut encoder = crate::workload_codec::Encoder::new(
        b"profile-catalog-v1",
        crate::workload_limits::CONTRACT_BYTES,
    )
    .expect("fixed catalog domain fits");
    encoder.count(1).expect("one profile fits");
    let reference = profile.reference();
    encoder.id(&reference.id).expect("fixed profile id fits");
    encoder
        .digest(&reference.semantic_digest)
        .expect("profile digest fits");
    crate::workload_codec::hash_bytes(&encoder.finish()).into()
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeComponentRole {
    PublicCli,
    SealedAgent,
    DesktopBootstrap,
    SessionBroker,
}

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
pub struct RuntimeManifestV2 {
    pub schema_version: u32,
    pub project: String,
    pub version: String,
    pub source_commit: String,
    pub target: String,
    pub components: Vec<RuntimeComponentRecord>,
    pub sealed: SealedRuntimeV2,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "platform", rename_all = "kebab-case", deny_unknown_fields)]
pub enum NativeProviderProtocols {
    Linux {
        provider_contract: u32,
        launch_wire: u32,
    },
    Windows {
        provider_contract: u32,
        public_wire: u32,
        private_wire: u32,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SealedRuntimeV2 {
    Included {
        agent_component: String,
        native_protocols: NativeProviderProtocols,
        mechanism: String,
        execution_report_schema: u32,
        plan_report_schema: u32,
        doctor_report_schema: u32,
        qualification_schema: u32,
        workload_contract_schema: u32,
        profile_catalog_sha256: String,
        profiles: Vec<String>,
        diagnostic_qualification: Option<QualificationArtifactReferenceV1>,
        profile_qualification: Box<QualificationArtifactReferenceV1>,
    },
    NotApplicable {
        reason: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationArtifactReferenceV1 {
    pub schema_version: u32,
    /// Release certification inventory binds the referenced artifact's actual bytes.
    pub artifact: String,
    /// Native target on which the referenced release qualification ran.
    pub qualified_target: String,
    /// False requires local native qualification before admission on this target.
    pub qualifies_package_target: bool,
}

/// A fresh administrative observation; never an authorization receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum InstalledPolicyObservationV1 {
    Unconfigured,
    Unavailable,
    Active {
        epoch: crate::workload_contract::PolicyEpoch,
        registry_digest: crate::DiagnosticSha256,
        enabled_profiles: crate::BoundedVec<crate::workload_contract::ProfileRef, 16>,
    },
}

impl InstalledPolicyObservationV1 {
    pub fn valid_for(&self, profile: crate::workload_registry::BaselineProfile) -> bool {
        match self {
            Self::Unavailable => false,
            Self::Unconfigured => true,
            Self::Active {
                enabled_profiles, ..
            } => {
                enabled_profiles.as_slice().len() <= 1
                    && enabled_profiles
                        .as_slice()
                        .iter()
                        .all(|reference| *reference == profile.reference())
            }
        }
    }
}

pub fn profile_qualification_reference(target: &str) -> QualificationArtifactReferenceV1 {
    let name = if target.contains("windows") {
        if target.starts_with("aarch64-") {
            "windows-arm64-profile-qualification.json"
        } else {
            "windows-x64-profile-qualification.json"
        }
    } else {
        "linux-profile-qualification.json"
    };
    let qualified_target = if target.contains("windows") {
        target
    } else {
        "x86_64-unknown-linux-gnu"
    };
    QualificationArtifactReferenceV1 {
        schema_version: 1,
        artifact: ["certification/workload/", name].concat(),
        qualified_target: qualified_target.to_owned(),
        qualifies_package_target: target == qualified_target,
    }
}

pub fn diagnostic_qualification_reference(
    target: &str,
) -> Option<QualificationArtifactReferenceV1> {
    target.contains("windows").then(|| {
        let name = if target.starts_with("aarch64-") {
            "windows-arm64-causal-diagnostics.json"
        } else {
            "windows-x64-causal-diagnostics.json"
        };
        QualificationArtifactReferenceV1 {
            schema_version: 1,
            artifact: ["certification/workload/", name].concat(),
            qualified_target: target.to_owned(),
            qualifies_package_target: true,
        }
    })
}

impl RuntimeManifestV2 {
    pub fn linux(
        version: String,
        source_commit: String,
        target: String,
        components: Vec<RuntimeComponentRecord>,
    ) -> Self {
        let profile_qualification = profile_qualification_reference(&target);
        Self {
            schema_version: 2,
            project: "memcordon".into(),
            version,
            source_commit,
            target,
            components,
            sealed: SealedRuntimeV2::Included {
                agent_component: "sealed-agent".into(),
                native_protocols: NativeProviderProtocols::Linux {
                    provider_contract: 3,
                    launch_wire: 3,
                },
                mechanism: "linux-pid-namespace-cgroup-v2".into(),
                execution_report_schema: crate::EXECUTION_REPORT_SCHEMA_VERSION,
                plan_report_schema: crate::PLAN_REPORT_SCHEMA_VERSION,
                doctor_report_schema: crate::DOCTOR_REPORT_SCHEMA_VERSION,
                qualification_schema: 3,
                workload_contract_schema: 1,
                profile_catalog_sha256: baseline_catalog_digest(false),
                profiles: vec!["linux-unix-create-v1".into()],
                diagnostic_qualification: None,
                profile_qualification: Box::new(profile_qualification),
            },
        }
    }

    pub fn windows(
        version: String,
        source_commit: String,
        target: String,
        components: Vec<RuntimeComponentRecord>,
    ) -> Self {
        let profile_qualification = profile_qualification_reference(&target);
        let diagnostic_qualification = diagnostic_qualification_reference(&target);
        Self {
            schema_version: 2,
            project: "memcordon".into(),
            version,
            source_commit,
            target,
            components,
            sealed: SealedRuntimeV2::Included {
                agent_component: "sealed-agent".into(),
                native_protocols: NativeProviderProtocols::Windows {
                    provider_contract: 3,
                    public_wire: 2,
                    private_wire: 2,
                },
                mechanism: "windows-job-object-v2".into(),
                execution_report_schema: crate::EXECUTION_REPORT_SCHEMA_VERSION,
                plan_report_schema: crate::PLAN_REPORT_SCHEMA_VERSION,
                doctor_report_schema: crate::DOCTOR_REPORT_SCHEMA_VERSION,
                qualification_schema: crate::WINDOWS_QUALIFICATION_SCHEMA_VERSION,
                workload_contract_schema: 1,
                profile_catalog_sha256: baseline_catalog_digest(true),
                profiles: vec!["windows-host-network-external-v1".into()],
                diagnostic_qualification,
                profile_qualification: Box::new(profile_qualification),
            },
        }
    }

    pub fn public_binding(&self, bytes: &[u8]) -> Result<crate::PublicProviderBindingV1, String> {
        use sha2::{Digest, Sha256};
        let binding = crate::PublicProviderBindingV1 {
            generation: crate::BoundedText::new(&format!(
                "{}:{}",
                self.version, self.source_commit
            ))
            .map_err(str::to_owned)?,
            source_commit: crate::BoundedText::new(&self.source_commit).map_err(str::to_owned)?,
            runtime_manifest_sha256: crate::DiagnosticSha256::from_bytes(
                Sha256::digest(bytes).into(),
            ),
        };
        if !binding.is_consistent() {
            return Err("invalid runtime provider identity".into());
        }
        Ok(binding)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > 128 * 1024 {
            return Err("runtime manifest exceeds bound".into());
        }
        crate::workload_contract::reject_duplicate_json_keys(bytes)?;
        let manifest: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        if manifest.schema_version != 2
            || manifest.project != "memcordon"
            || manifest.components.len() > 4
            || manifest.components.is_empty()
        {
            return Err("runtime manifest identity or inventory differs".into());
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut paths = std::collections::BTreeSet::new();
        for component in &manifest.components {
            if !ids.insert(&component.id)
                || !paths.insert(&component.path)
                || component.path.is_empty()
                || component
                    .path
                    .split('/')
                    .any(|part| part.is_empty() || matches!(part, "." | ".."))
                || component.path.contains('\\')
                || component.path.contains(':')
                || component.sha256.len() != std::mem::size_of::<[u8; 32]>() * 2
                || !component
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err("runtime component identity differs".into());
            }
        }
        Ok(manifest)
    }
}
