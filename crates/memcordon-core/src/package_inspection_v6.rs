//! Proposed Linux V6 package-inspection validation, not an active producer.
//!
//! The caller supplies a pinned runtime manifest and independently read back
//! installed hashes/state. This parser cannot turn a package into a qualified
//! private-network provider; that native path remains unavailable.

use crate::runtime_manifest::{
    NativeProviderProtocols, QualificationArtifactReferenceV1, RuntimeComponentRecord,
    RuntimeComponentRole,
};
use crate::runtime_manifest_v3::{
    QualificationArtifactReferenceV2, RuntimeManifestV3, SealedRuntimeV3,
};
use crate::workload_codec::hash_bytes;
use crate::workload_contract::reject_duplicate_json_keys;
use crate::workload_discovery_v2::profile_catalog_digest_v2;
use crate::{BoundedText, DiagnosticSha256};
use serde::{Deserialize, Serialize};

const INSPECTION_MAX_BYTES: usize = 128 * 1024;
const MAX_COMPONENTS: usize = 8;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InspectionVersionSix;

impl Serialize for InspectionVersionSix {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u32(6)
    }
}

impl<'de> Deserialize<'de> for InspectionVersionSix {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if u32::deserialize(deserializer)? != 6 {
            return Err(serde::de::Error::custom(
                "unsupported package inspection version",
            ));
        }
        Ok(Self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxUnitHashesV6 {
    pub control_service: DiagnosticSha256,
    pub control_socket: DiagnosticSha256,
    pub launcher_service: DiagnosticSha256,
    pub launcher_socket: DiagnosticSha256,
    pub tmpfiles: DiagnosticSha256,
    pub network_launcher_service: DiagnosticSha256,
    pub network_launcher_socket: DiagnosticSha256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkLauncherStateV6 {
    InstalledDisabled,
    EnabledUnqualified,
    EnabledQualified,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxPackageInspectionV6 {
    pub schema_version: InspectionVersionSix,
    pub version: BoundedText<64>,
    pub source_commit: BoundedText<40>,
    pub target: BoundedText<128>,
    pub runtime_manifest_sha256: DiagnosticSha256,
    pub components: Vec<RuntimeComponentRecord>,
    pub native_protocols: NativeProviderProtocols,
    pub profile_catalog_sha256: DiagnosticSha256,
    pub private_filter_sha256: DiagnosticSha256,
    pub compiled_units: LinuxUnitHashesV6,
    pub compiled_metadata_valid: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxInstalledInspectionV6 {
    pub schema_version: InspectionVersionSix,
    pub package: LinuxPackageInspectionV6,
    pub installed_units: LinuxUnitHashesV6,
    pub installed_agent_sha256: DiagnosticSha256,
    pub installed_artifacts_valid: bool,
    pub provider_reachable: bool,
    pub network_launcher_state: NetworkLauncherStateV6,
    pub baseline_qualification: Option<QualificationArtifactReferenceV1>,
    pub private_qualification: Option<QualificationArtifactReferenceV2>,
}

/// These values must come from protected release inventory and fresh installed
/// file/service readback, not from the inspection document being verified.
pub struct TrustedLinuxInspectionV6<'a> {
    pub runtime_manifest_sha256: &'a DiagnosticSha256,
    pub filter_sha256: &'a DiagnosticSha256,
    pub unit_hashes: &'a LinuxUnitHashesV6,
    pub installed_agent_sha256: &'a DiagnosticSha256,
    pub provider_reachable: bool,
    pub network_launcher_state: NetworkLauncherStateV6,
    pub baseline_qualification: Option<&'a QualificationArtifactReferenceV1>,
}

impl LinuxInstalledInspectionV6 {
    pub fn parse_and_validate(
        inspection_bytes: &[u8],
        runtime_manifest_bytes: &[u8],
        trusted: &TrustedLinuxInspectionV6<'_>,
    ) -> Result<Self, String> {
        if inspection_bytes.len() > INSPECTION_MAX_BYTES {
            return Err("V6 inspection exceeds byte limit".into());
        }
        reject_duplicate_json_keys(inspection_bytes)?;
        let inspection: Self =
            serde_json::from_slice(inspection_bytes).map_err(|error| error.to_string())?;
        if hash_bytes(runtime_manifest_bytes) != *trusted.runtime_manifest_sha256
            || inspection.package.runtime_manifest_sha256 != *trusted.runtime_manifest_sha256
        {
            return Err("V6 inspection does not bind pinned runtime manifest bytes".into());
        }
        let manifest = RuntimeManifestV3::parse(runtime_manifest_bytes)?;
        inspection.validate(&manifest, trusted)?;
        Ok(inspection)
    }

    fn validate(
        &self,
        manifest: &RuntimeManifestV3,
        trusted: &TrustedLinuxInspectionV6<'_>,
    ) -> Result<(), String> {
        manifest.validate()?;
        let SealedRuntimeV3::WorkloadV2 {
            agent_component,
            native_protocols,
            profile_catalog_sha256,
            ..
        } = &manifest.sealed
        else {
            return Err("V6 Linux inspection requires workload-V2 manifest".into());
        };
        let agent = manifest
            .components
            .iter()
            .find(|component| {
                component.id == *agent_component
                    && component.role == RuntimeComponentRole::SealedAgent
            })
            .ok_or("V6 inspection has no sealed agent component")?;
        let agent_sha256 = DiagnosticSha256::try_from(
            BoundedText::<64>::new(&agent.sha256).map_err(str::to_owned)?,
        )
        .map_err(str::to_owned)?;
        if !matches!(native_protocols, NativeProviderProtocols::Linux { .. })
            || self.package.version.as_str() != manifest.version
            || self.package.source_commit.as_str() != manifest.source_commit
            || self.package.target.as_str() != manifest.target
            || self.package.components.len() > MAX_COMPONENTS
            || self.package.components != manifest.components
            || &self.package.native_protocols != native_protocols
            || self.package.profile_catalog_sha256 != *profile_catalog_sha256
            || self.package.profile_catalog_sha256 != profile_catalog_digest_v2()
            || self.package.private_filter_sha256 != *trusted.filter_sha256
            || self.package.compiled_units != *trusted.unit_hashes
            || self.installed_units != *trusted.unit_hashes
            || self.installed_agent_sha256 != agent_sha256
            || self.installed_agent_sha256 != *trusted.installed_agent_sha256
            || !self.package.compiled_metadata_valid
            || !self.installed_artifacts_valid
            || self.provider_reachable != trusted.provider_reachable
            || self.network_launcher_state != trusted.network_launcher_state
            || self.baseline_qualification.as_ref() != trusted.baseline_qualification
        {
            return Err("V6 package or installed-state binding differs".into());
        }
        if self.network_launcher_state == NetworkLauncherStateV6::EnabledQualified
            || self.private_qualification.is_some()
        {
            return Err("private profile cannot be qualified by parse-only V6 inspection".into());
        }
        Ok(())
    }
}
