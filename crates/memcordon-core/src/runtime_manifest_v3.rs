//! Parse-only V3 runtime inventory. No producer currently claims private TCP.

use crate::runtime_manifest::{
    NativeProviderProtocols, RuntimeComponentRecord, RuntimeComponentRole, RuntimeManifestV2,
    SealedRuntimeV2, baseline_catalog_digest,
};
use crate::workload_contract::ProfileRef;
use crate::workload_discovery_v2::profile_catalog_digest_v2;
use crate::workload_limits as limits;
use crate::workload_qualification_v2::{
    QualificationArtifactV2, TrustedQualificationExpectationV2,
};
use crate::workload_registry::BaselineProfile;
use crate::workload_registry_v2::ProfileKindV2;
use crate::{BoundedVec, DiagnosticSha256};
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RuntimeManifestVersionThree(u32);
impl Default for RuntimeManifestVersionThree {
    fn default() -> Self {
        Self(3)
    }
}
impl<'de> Deserialize<'de> for RuntimeManifestVersionThree {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        if u32::deserialize(decoder)? != 3 {
            return Err(serde::de::Error::custom(
                "unsupported runtime manifest version",
            ));
        }
        Ok(Self::default())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct QualificationArtifactSchemaTwo(u32);
impl Default for QualificationArtifactSchemaTwo {
    fn default() -> Self {
        Self(2)
    }
}
impl<'de> Deserialize<'de> for QualificationArtifactSchemaTwo {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        if u32::deserialize(decoder)? != 2 {
            return Err(serde::de::Error::custom(
                "unsupported qualification artifact reference version",
            ));
        }
        Ok(Self::default())
    }
}

/// An artifact reference is an expected immutable byte identity, not evidence
/// that the referenced native suite actually ran or that its bytes were read.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationArtifactReferenceV2 {
    pub schema_version: QualificationArtifactSchemaTwo,
    pub artifact: String,
    pub artifact_sha256: DiagnosticSha256,
    pub qualified_target: String,
    pub source_commit: String,
    pub profile: ProfileRef,
}

/// A release reference joined to actual qualification bytes and an independent
/// native-run expectation. This proves a release artifact, not current host
/// qualification; installed admission must verify the host separately.
pub struct ValidatedQualificationReferenceV2(QualificationArtifactReferenceV2);

impl ValidatedQualificationReferenceV2 {
    pub fn from_verified_artifact(
        bytes: &[u8],
        reference: QualificationArtifactReferenceV2,
        expected: &TrustedQualificationExpectationV2<'_>,
    ) -> Result<Self, String> {
        QualificationArtifactV2::parse_and_validate(bytes, &reference, expected)?;
        reference.validate(expected.target, expected.source_commit, expected.profile)?;
        Ok(Self(reference))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RuntimeProfileAvailabilityV3 {
    Unsupported,
    Unqualified,
    Qualified {
        qualification: QualificationArtifactReferenceV2,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeProfileRecordV3 {
    pub profile: ProfileRef,
    pub availability: RuntimeProfileAvailabilityV3,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "policy_version", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SealedRuntimeV3 {
    /// Windows V1 authority remains V1; a V3 wrapper does not imply V2 policy.
    LegacyV1 {
        baseline: Box<SealedRuntimeV2>,
    },
    WorkloadV2 {
        agent_component: String,
        native_protocols: NativeProviderProtocols,
        broker_wire: u32,
        execution_report_schema: u32,
        plan_report_schema: u32,
        doctor_report_schema: u32,
        installed_qualification_schema: u32,
        supported_contract_versions: BoundedVec<u16, 2>,
        profile_catalog_sha256: DiagnosticSha256,
        profiles: BoundedVec<RuntimeProfileRecordV3, { limits::PROFILES }>,
    },
    NotApplicable {
        reason: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeManifestV3 {
    pub schema_version: RuntimeManifestVersionThree,
    pub project: String,
    pub version: String,
    pub source_commit: String,
    pub target: String,
    pub components: Vec<RuntimeComponentRecord>,
    pub sealed: SealedRuntimeV3,
}

pub enum VersionedRuntimeManifest {
    V2(RuntimeManifestV2),
    V3(RuntimeManifestV3),
}

impl VersionedRuntimeManifest {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > limits::PUBLIC_OBJECT_BYTES {
            return Err("runtime manifest exceeds bound".into());
        }
        crate::workload_contract::reject_duplicate_json_keys(bytes)?;
        #[derive(Deserialize)]
        struct VersionProbe {
            schema_version: u32,
        }
        let version: VersionProbe =
            serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        match version.schema_version {
            2 => RuntimeManifestV2::parse(bytes).map(Self::V2),
            3 => RuntimeManifestV3::parse(bytes).map(Self::V3),
            _ => Err("unsupported runtime manifest version".into()),
        }
    }
}

impl RuntimeManifestV3 {
    pub fn public_binding(&self, bytes: &[u8]) -> Result<crate::PublicProviderBindingV1, String> {
        if Self::parse(bytes)? != *self {
            return Err("V3 public binding differs from pinned manifest bytes".into());
        }
        let binding = crate::PublicProviderBindingV1 {
            generation: crate::BoundedText::new(&format!(
                "{}:{}",
                self.version, self.source_commit
            ))
            .map_err(str::to_owned)?,
            source_commit: crate::BoundedText::new(&self.source_commit).map_err(str::to_owned)?,
            runtime_manifest_sha256: crate::workload_codec::hash_bytes(bytes),
        };
        if !binding.is_consistent() {
            return Err("invalid V3 runtime provider identity".into());
        }
        Ok(binding)
    }

    /// Constructs a candidate Linux catalogue before native capability proof.
    pub fn linux_unqualified(
        version: String,
        source_commit: String,
        target: String,
        components: Vec<RuntimeComponentRecord>,
    ) -> Result<Self, String> {
        Self::linux_with_qualifications(version, source_commit, target, components, None)
    }

    /// Constructs a final Linux catalogue using release qualification checked
    /// against independent native completions. The installed host still needs
    /// a fresh qualification receipt before private execution is available.
    pub fn linux_with_qualifications(
        version: String,
        source_commit: String,
        target: String,
        components: Vec<RuntimeComponentRecord>,
        private: Option<ValidatedQualificationReferenceV2>,
    ) -> Result<Self, String> {
        let private_availability = private.map_or(RuntimeProfileAvailabilityV3::Unqualified, |q| {
            RuntimeProfileAvailabilityV3::Qualified { qualification: q.0 }
        });
        let mut profiles = BoundedVec::default();
        for profile in [
            ProfileKindV2::LinuxTcp4PrivateV1.reference(),
            ProfileKindV2::LinuxUnixCreateV1.reference(),
        ] {
            let is_private = profile == ProfileKindV2::LinuxTcp4PrivateV1.reference();
            profiles
                .try_push(RuntimeProfileRecordV3 {
                    profile,
                    availability: if is_private {
                        private_availability.clone()
                    } else {
                        RuntimeProfileAvailabilityV3::Unqualified
                    },
                })
                .map_err(|_| "Linux runtime profile catalogue exceeds bound")?;
        }
        let mut supported_contract_versions = BoundedVec::default();
        for version in [1, 2] {
            supported_contract_versions
                .try_push(version)
                .map_err(|_| "Linux runtime contract versions exceed bound")?;
        }
        let manifest = Self {
            schema_version: RuntimeManifestVersionThree::default(),
            project: "memcordon".into(),
            version,
            source_commit,
            target,
            components,
            sealed: SealedRuntimeV3::WorkloadV2 {
                agent_component: "sealed-agent".into(),
                native_protocols: NativeProviderProtocols::Linux {
                    provider_contract: 4,
                    launch_wire: 4,
                },
                broker_wire: 4,
                execution_report_schema: 11,
                plan_report_schema: 10,
                doctor_report_schema: 7,
                installed_qualification_schema: 4,
                supported_contract_versions,
                profile_catalog_sha256: profile_catalog_digest_v2(),
                profiles,
            },
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > limits::PUBLIC_OBJECT_BYTES {
            return Err("runtime manifest exceeds bound".into());
        }
        crate::workload_contract::reject_duplicate_json_keys(bytes)?;
        let manifest: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.project != "memcordon"
            || self.version.is_empty()
            || self.version.len() > 64
            || !valid_sha1(&self.source_commit)
            || self.target.is_empty()
            || self.target.len() > 128
            || !self.target.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
            })
            || self.components.is_empty()
            || self.components.len() > 4
            || serde_json::to_vec(self)
                .map_or(true, |bytes| bytes.len() > limits::PUBLIC_OBJECT_BYTES)
        {
            return Err("V3 runtime manifest identity or size differs".into());
        }
        for (index, component) in self.components.iter().enumerate() {
            if component.id.is_empty()
                || component.path.is_empty()
                || component.path.contains('\\')
                || component.path.contains(':')
                || component
                    .path
                    .split('/')
                    .any(|part| part.is_empty() || matches!(part, "." | ".."))
                || !valid_sha256(&component.sha256)
                || component.size == 0
                || component.mode != 0o755
                || self.components[..index]
                    .iter()
                    .any(|prior| prior.id == component.id || prior.path == component.path)
            {
                return Err("V3 runtime component identity differs".into());
            }
        }
        match &self.sealed {
            SealedRuntimeV3::LegacyV1 { baseline } => {
                if !matches!(
                    self.target.as_str(),
                    "x86_64-pc-windows-msvc" | "aarch64-pc-windows-msvc"
                ) || !self.has_exact_roles(&[
                    RuntimeComponentRole::PublicCli,
                    RuntimeComponentRole::SealedAgent,
                    RuntimeComponentRole::DesktopBootstrap,
                    RuntimeComponentRole::SessionBroker,
                ]) {
                    return Err("legacy V1 V3 wrapper requires Windows target".into());
                }
                let SealedRuntimeV2::Included {
                    agent_component,
                    native_protocols:
                        NativeProviderProtocols::Windows {
                            provider_contract: 3,
                            public_wire: 2,
                            private_wire: 2,
                        },
                    workload_contract_schema: 1,
                    profile_catalog_sha256,
                    profiles,
                    diagnostic_qualification,
                    profile_qualification,
                    ..
                } = baseline.as_ref()
                else {
                    return Err("Windows V3 wrapper cannot claim V2 provider authority".into());
                };
                if !self.has_agent_component(agent_component)
                    || profile_catalog_sha256 != &baseline_catalog_digest(true)
                    || profiles.as_slice()
                        != [BaselineProfile::WindowsHostNetworkExternal.id().as_str()]
                    || profile_qualification.qualified_target != self.target
                    || !profile_qualification.qualifies_package_target
                    || profile_qualification.schema_version != 1
                    || diagnostic_qualification.as_ref().is_none_or(|diagnostic| {
                        diagnostic.qualified_target != self.target
                            || !diagnostic.qualifies_package_target
                    })
                {
                    return Err("Windows legacy V1 runtime binding differs".into());
                }
            }
            SealedRuntimeV3::WorkloadV2 {
                agent_component,
                native_protocols:
                    NativeProviderProtocols::Linux {
                        provider_contract: 4,
                        launch_wire: 4,
                    },
                broker_wire: 4,
                execution_report_schema: 11,
                plan_report_schema: 10,
                doctor_report_schema: 7,
                installed_qualification_schema: 4,
                supported_contract_versions,
                profile_catalog_sha256,
                profiles,
            } => {
                if !matches!(
                    self.target.as_str(),
                    "x86_64-unknown-linux-gnu" | "aarch64-unknown-linux-gnu"
                ) || !(if self.target == "aarch64-unknown-linux-gnu" {
                    self.has_exact_roles(&[
                        RuntimeComponentRole::PublicCli,
                        RuntimeComponentRole::SealedAgent,
                        RuntimeComponentRole::Arm32AbiHelper,
                    ]) && self.components.iter().any(|component| {
                        component.role == RuntimeComponentRole::Arm32AbiHelper
                            && component.id == "arm32-abi-helper"
                            && component.path == "memcordon-arm32-abi-helper"
                    })
                } else {
                    self.has_exact_roles(&[
                        RuntimeComponentRole::PublicCli,
                        RuntimeComponentRole::SealedAgent,
                    ])
                }) || !self.has_agent_component(agent_component)
                    || supported_contract_versions.as_slice() != [1, 2]
                    || profile_catalog_sha256 != &profile_catalog_digest_v2()
                    || profiles.as_slice().len() != 2
                {
                    return Err("Linux V3 protocol or catalogue binding differs".into());
                }
                let expected = [
                    ProfileKindV2::LinuxTcp4PrivateV1.reference(),
                    ProfileKindV2::LinuxUnixCreateV1.reference(),
                ];
                for (record, reference) in profiles.as_slice().iter().zip(expected.iter()) {
                    if record.profile != *reference {
                        return Err("Linux V3 profile order or reference differs".into());
                    }
                    if let RuntimeProfileAvailabilityV3::Qualified { qualification } =
                        &record.availability
                    {
                        if record.profile != ProfileKindV2::LinuxTcp4PrivateV1.reference() {
                            return Err(
                                "Linux V3 has no qualified release source for this profile".into(),
                            );
                        }
                        qualification.validate(
                            &self.target,
                            &self.source_commit,
                            &record.profile,
                        )?;
                    }
                }
            }
            SealedRuntimeV3::NotApplicable { reason } => {
                if reason.is_empty()
                    || reason.len() > 256
                    || matches!(
                        self.target.as_str(),
                        "x86_64-unknown-linux-gnu"
                            | "aarch64-unknown-linux-gnu"
                            | "x86_64-pc-windows-msvc"
                            | "aarch64-pc-windows-msvc"
                    )
                {
                    return Err("invalid V3 not-applicable reason".into());
                }
            }
            _ => return Err("unsupported V3 provider protocol combination".into()),
        }
        Ok(())
    }

    fn has_agent_component(&self, id: &str) -> bool {
        self.components.iter().any(|component| {
            component.id == id && component.role == RuntimeComponentRole::SealedAgent
        })
    }

    fn has_exact_roles(&self, roles: &[RuntimeComponentRole]) -> bool {
        self.components.len() == roles.len()
            && roles.iter().all(|role| {
                self.components
                    .iter()
                    .filter(|component| component.role == *role)
                    .count()
                    == 1
            })
    }
}

impl QualificationArtifactReferenceV2 {
    fn validate(
        &self,
        target: &str,
        source_commit: &str,
        profile: &ProfileRef,
    ) -> Result<(), String> {
        let expected_artifact = match target {
            "x86_64-unknown-linux-gnu" => "certification/workload/linux-x64-private-v2.json",
            "aarch64-unknown-linux-gnu" => "certification/workload/linux-arm64-private-v2.json",
            _ => return Err("V2 qualification target is unsupported".into()),
        };
        if self.qualified_target != target
            || self.source_commit != source_commit
            || &self.profile != profile
            || self.artifact != expected_artifact
        {
            return Err("V2 qualification reference is not native, exact or complete".into());
        }
        Ok(())
    }
}

fn valid_sha1(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == std::mem::size_of::<[u8; 32]>() * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
