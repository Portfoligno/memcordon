//! Public descriptive compatibility and measured native package inventories.
use super::{
    artifacts::{self, FileRecord},
    distribution::{Distribution, TargetDistribution},
    source::BuildSourceIdentity,
    target,
};
use crate::{CiError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePackage {
    pub format: String,
    pub revision: u32,
    pub source: BuildSourceIdentity,
    pub target: String,
    pub features: Vec<String>,
    pub files: Vec<FileRecord>,
}
impl NativePackage {
    pub fn measured(
        source: &BuildSourceIdentity,
        distribution: &TargetDistribution,
        members: &BTreeMap<String, Vec<u8>>,
    ) -> Result<Self> {
        source.validate()?;
        distribution.validate()?;
        if members.contains_key("package.json") {
            return Err(CiError::Message(
                "native metadata must not hash itself".into(),
            ));
        }
        let files = members
            .iter()
            .map(|(name, bytes)| FileRecord {
                name: name.clone(),
                kind: if distribution
                    .binaries
                    .iter()
                    .any(|binary| target::binary_name(binary, &distribution.target) == *name)
                {
                    "binary"
                } else if distribution.units.contains(name) {
                    "unit"
                } else {
                    "runtime-metadata"
                }
                .into(),
                target: Some(distribution.target.clone()),
                package: None,
                byte_len: bytes.len() as u64,
                sha256: artifacts::checksum(bytes),
            })
            .collect();
        Ok(Self {
            format: "memcordon.native-package".into(),
            revision: 1,
            source: source.clone(),
            target: distribution.target.clone(),
            features: distribution.features.clone(),
            files,
        })
    }
    pub fn verify(
        bytes: &[u8],
        source: &BuildSourceIdentity,
        distribution: &TargetDistribution,
        members: &BTreeMap<String, Vec<u8>>,
    ) -> Result<()> {
        memcordon_core::canonical_json::reject_duplicate_json_keys(bytes)
            .map_err(CiError::Message)?;
        let supplied: Self = serde_json::from_slice(bytes)?;
        let actual: BTreeMap<_, _> = members
            .iter()
            .filter(|(name, _)| name.as_str() != "package.json")
            .map(|(name, bytes)| (name.clone(), bytes.clone()))
            .collect();
        if supplied != Self::measured(source, distribution, &actual)? {
            return Err(CiError::Message(
                "native package measured inventory/source/features differ".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetCompatibility {
    pub target: String,
    pub selected_features: Vec<String>,
    pub selected_binaries: Vec<String>,
    pub selected_units: Vec<String>,
    pub native_protocols: Option<memcordon_core::runtime_components::NativeProviderProtocols>,
    pub profiles: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityV2 {
    pub format: String,
    pub revision: u32,
    pub version: String,
    pub source_commit: String,
    pub public_packages: Vec<String>,
    pub default_executable: String,
    pub optional_features: Vec<String>,
    pub named_formats: BTreeMap<String, u32>,
    pub execution_schema: u32,
    pub clean_schema: u32,
    pub targets: Vec<TargetCompatibility>,
    pub behavior: Vec<String>,
}
impl CompatibilityV2 {
    pub fn selected(
        source: &BuildSourceIdentity,
        distribution: &Distribution,
        manifests: &BTreeMap<String, memcordon_core::runtime_manifest_v2::RuntimeManifestV2>,
    ) -> Result<Self> {
        use memcordon_core::runtime_manifest_v2::SealedRuntimeV2;
        source.validate()?;
        distribution.validate()?;
        if manifests.len() != distribution.targets.len() {
            return Err(CiError::Message(
                "current compatibility target inventory differs".into(),
            ));
        }
        let mut targets = Vec::new();
        for selection in &distribution.targets {
            let manifest = manifests
                .get(&selection.target)
                .ok_or_else(|| CiError::Message("current runtime inventory absent".into()))?;
            manifest.validate().map_err(CiError::Message)?;
            if manifest.version != source.version().to_string()
                || manifest.source_commit != source.commit()
                || manifest.target != selection.target
            {
                return Err(CiError::Message(
                    "current compatibility source association differs".into(),
                ));
            }
            let (native_protocols, profiles) = match &manifest.sealed {
                SealedRuntimeV2::NotIncluded => (None, Vec::new()),
                SealedRuntimeV2::CredentialPreservingLinux {
                    native_protocols, ..
                } => (
                    Some(native_protocols.clone()),
                    vec![
                        memcordon_core::workload_request::LINUX_CREDENTIAL_PRESERVING_PROFILE
                            .into(),
                    ],
                ),
                SealedRuntimeV2::Included {
                    native_protocols,
                    profile,
                    ..
                } => (Some(native_protocols.clone()), vec![profile.clone()]),
            };
            targets.push(TargetCompatibility {
                target: selection.target.clone(),
                selected_features: selection.features.clone(),
                selected_binaries: selection.binaries.clone(),
                selected_units: selection.units.clone(),
                native_protocols,
                profiles,
            });
        }
        Ok(Self {
            format: "memcordon.compatibility".into(),
            revision: 2,
            version: source.version().to_string(),
            source_commit: source.commit().into(),
            public_packages: distribution.packages.clone(),
            default_executable: "memcordon".into(),
            optional_features: vec![
                "sealed-runtime".into(),
                "private-tcp".into(),
                "windows-sealed-runtime".into(),
            ],
            named_formats: BTreeMap::from([
                ("memcordon.result".into(), 3),
                ("memcordon.plan".into(), 3),
                ("memcordon.capabilities".into(), 3),
                ("memcordon.workload-request".into(), 1),
                ("memcordon.runtime-manifest".into(), 2),
            ]),
            execution_schema: 10,
            clean_schema: 2,
            targets,
            behavior: [
                "default-installs-only-memcordon",
                "advisory-output-does-not-authorize-launch",
                "caller-owned-workload-snapshots",
                "memory-limit-124",
                "deadline-123",
                "provider-failure-125",
                "cleanup-uncertainty-blocks-clean-restart",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        })
    }
}
