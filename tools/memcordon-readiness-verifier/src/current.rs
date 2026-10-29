//! Current request-based readiness with one exact document profile.
use crate::{CaseKey, EvidenceClass, ManifestCase, VerificationResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

mod anchors;
pub mod assessment;
pub mod byte_effects;
pub mod linux;
mod linux_component_lifecycle;
pub mod linux_components;
pub mod linux_exports;
pub mod linux_images;
pub mod linux_isolation;
pub mod linux_owners;
pub mod linux_package;
pub mod linux_refusals;
pub mod linux_snapshots;
pub mod linux_status;
pub mod linux_wire;
pub mod parsers;
pub mod storage;
pub mod windows;
mod windows_actors;
pub mod windows_component;
mod windows_component_facts;
pub mod windows_diagnostics;
pub mod windows_facts;
mod windows_loss;
pub mod windows_proof;

pub const PROFILE: &str = "memcordon.consumer-readiness.v2";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProducerManifestV2 {
    pub format: String,
    pub revision: u32,
    pub job: String,
    pub run_id: String,
    pub run_attempt: u64,
    pub source_commit: String,
    pub source_tree_sha256: String,
    pub version: String,
    pub manifest_sha256: String,
    pub artifacts: Vec<crate::Artifact>,
    pub products: Vec<ProductObservationV2>,
    pub component_builds: Vec<crate::ComponentBuild>,
    pub records: Vec<crate::CaseRecord>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceIndexV2 {
    pub format: String,
    pub revision: u32,
    pub profile: String,
    pub run_id: String,
    pub source_commit: String,
    pub source_tree_sha256: String,
    pub version: String,
    pub manifest_sha256: String,
    pub repository: Option<String>,
    pub products: Vec<ProductObservationV2>,
    pub component_builds: Vec<crate::ComponentBuild>,
    pub workflow_cells: Vec<crate::ProductKey>,
    pub fixture_cases: Vec<CaseKey>,
    pub artifacts: Vec<crate::Artifact>,
    pub records: Vec<crate::CaseRecord>,
    pub producer_origins: Vec<crate::ProducerOrigin>,
    pub job_outcomes: Vec<crate::JobOutcome>,
    pub assessment_failures: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductObservationV2 {
    pub key: crate::ProductKey,
    pub source_commit: String,
    pub source_tree_sha256: String,
    pub version: String,
    pub host: crate::HostObservation,
    pub features: Vec<String>,
    pub components: Vec<crate::Component>,
    pub materialization: String,
    pub runtime_manifest: String,
    pub package_sha256: String,
    pub registry_graph_sha256: Option<String>,
    pub registry_graph: Option<String>,
    pub request: WireVersion,
    pub result: WireVersion,
    pub native_protocols: NativeProviderProtocolsV2,
    pub runtime_profile: String,
    pub lifecycle: LifecycleObservationV2,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "platform", rename_all = "kebab-case", deny_unknown_fields)]
pub enum NativeProviderProtocolsV2 {
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

pub fn validate_product_protocols(product: &ProductObservationV2) -> VerificationResult<()> {
    let (profile, protocols) = if product.key.target.ends_with("-unknown-linux-gnu") {
        (
            "linux-private-workload-v1",
            NativeProviderProtocolsV2::Linux {
                provider_contract: 3,
                launch_wire: 5,
            },
        )
    } else if product.key.target.ends_with("-pc-windows-msvc") {
        (
            "windows-sealed-current-token-v1",
            NativeProviderProtocolsV2::Windows {
                provider_contract: 4,
                public_wire: 4,
                private_wire: 4,
            },
        )
    } else {
        return Err("unknown current product target".into());
    };
    if product.runtime_profile != profile
        || product.native_protocols != protocols
        || product.request.format != "memcordon.workload-request"
        || product.request.revision != 1
        || product.result.format != "memcordon.result"
        || product.result.revision != 3
    {
        return Err("current product public/native protocol identity differs".into());
    }
    validate_native_inventory(&product.key.target, &product.lifecycle.native)
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum NativeResourceV2 {
    LinuxAggregate,
    LinuxTarget,
    LinuxNamespaceInit,
    LinuxGuardian,
    LinuxRelays,
    LinuxControlHandles,
    LinuxRootReferences,
    LinuxStaging,
    LinuxFootprint,
    WindowsJob,
    WindowsTarget,
    WindowsRelays,
    WindowsControlHandles,
    WindowsDesktop,
    WindowsProcessHandles,
}

/// A controller observation points to independently checked native evidence.
/// A producer's settled flag alone is never an acceptance predicate.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeResourceObservationV2 {
    pub resource: NativeResourceV2,
    pub settled: bool,
    pub evidence: String,
}

/// Structural completeness precedes platform-native evidence verification.
pub fn validate_native_inventory(
    target: &str,
    observations: &[NativeResourceObservationV2],
) -> VerificationResult<()> {
    use NativeResourceV2::*;
    let required: &[NativeResourceV2] = if target.ends_with("-unknown-linux-gnu") {
        &[
            LinuxAggregate,
            LinuxTarget,
            LinuxNamespaceInit,
            LinuxGuardian,
            LinuxRelays,
            LinuxControlHandles,
            LinuxRootReferences,
            LinuxStaging,
            LinuxFootprint,
        ]
    } else if target.ends_with("-pc-windows-msvc") {
        &[
            WindowsJob,
            WindowsTarget,
            WindowsRelays,
            WindowsControlHandles,
            WindowsDesktop,
            WindowsProcessHandles,
        ]
    } else {
        return Err("unsupported current native target".into());
    };
    let mut seen = BTreeSet::new();
    for observation in observations {
        if !required.contains(&observation.resource)
            || !seen.insert(observation.resource)
            || !observation.settled
            || observation.evidence.is_empty()
            || Path::new(&observation.evidence)
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err(
                "current native resource inventory unknown/duplicate/unsettled/unsafe".into(),
            );
        }
    }
    if seen.len() != required.len() {
        return Err("current native resource inventory incomplete".into());
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleObservationV2 {
    pub lease_id: String,
    pub journal: String,
    pub receipt: String,
    pub journal_before_mutation: bool,
    pub installed_verified: bool,
    pub all_cases_inside_lease: bool,
    pub explicit_finalization: bool,
    pub finalization_records: u32,
    pub package_absent: bool,
    pub native: Vec<NativeResourceObservationV2>,
    pub cleanup_failures: Vec<String>,
    pub outstanding: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledLifecycleReceiptV2 {
    pub format: String,
    pub revision: u32,
    pub run_id: String,
    pub lease_id: String,
    pub key: crate::ProductKey,
    pub journal_sha256: String,
    pub final_sequence: u64,
    pub explicit_finalization_count: u32,
    pub package_absent: bool,
    pub native: Vec<NativeResourceObservationV2>,
    pub cache_quiescent: bool,
    pub cleanup_failures: Vec<String>,
    pub outstanding: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseEvidenceV2 {
    pub format: String,
    pub revision: u32,
    pub key: CaseKey,
    pub run_id: String,
    pub source_commit: String,
    pub source_tree_sha256: String,
    pub lease_id: Option<String>,
    pub fixture: String,
    pub fixture_source: String,
    pub fixture_sha256: String,
    pub fixture_source_sha256: String,
    pub input: String,
    pub input_sha256: String,
    pub invocation: String,
    pub request: Option<String>,
    pub raw_result: Option<String>,
    pub attempt_observation: Option<String>,
    pub authenticated_terminal: Option<String>,
    pub recovery: Option<String>,
    pub stdout: String,
    pub stderr: String,
    pub outputs: Vec<String>,
    pub native_observation: String,
    pub retirement: String,
    pub semantic_observation: String,
    pub component_recipe_id: Option<String>,
}

pub fn current_readiness_manifest(root: &Path) -> PathBuf {
    root.join("ci").join("consumer-readiness-v2.toml")
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WireVersion {
    pub format: String,
    pub revision: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PlatformReadinessV2 {
    pub runtime_profile: String,
    pub request: WireVersion,
    pub result: WireVersion,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessManifestV2 {
    pub format: String,
    pub revision: u32,
    pub profile: String,
    pub targets: Vec<String>,
    pub channels: Vec<String>,
    pub requirements: Vec<String>,
    pub windows_churn_creations: u32,
    pub windows_churn_generations: u32,
    pub windows_churn_live_cohort: u32,
    pub windows_population_processes: u32,
    pub linux: PlatformReadinessV2,
    pub windows: PlatformReadinessV2,
    pub cases: Vec<ManifestCase>,
}

fn platform(value: &PlatformReadinessV2, profile: &str) -> VerificationResult<()> {
    if value.runtime_profile != profile
        || value.request.format != "memcordon.workload-request"
        || value.request.revision != 1
        || value.result.format != "memcordon.result"
        || value.result.revision != 3
    {
        return Err("current readiness wire/profile identity differs".into());
    }
    Ok(())
}

/// Validates the complete fixed inventory. This does not establish case execution.
pub fn validate_manifest(bytes: &[u8]) -> VerificationResult<BTreeSet<CaseKey>> {
    if bytes.len() > 1024 * 1024 {
        return Err("manifest exceeds bound".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
    let manifest: ReadinessManifestV2 = toml::from_str(text).map_err(|error| error.to_string())?;
    if manifest.format != "memcordon.consumer-readiness"
        || manifest.revision != 2
        || manifest.profile != PROFILE
        || manifest.windows_churn_creations != 4096
        || manifest.windows_churn_generations != 3
        || manifest.windows_churn_live_cohort != 64
        || manifest.windows_population_processes != 257
    {
        return Err("current readiness profile parameters differ".into());
    }
    platform(&manifest.linux, "linux-private-workload-v1")?;
    platform(&manifest.windows, "windows-sealed-current-token-v1")?;
    crate::exact_strings(&manifest.targets, crate::anchors::TARGETS)?;
    crate::exact_strings(&manifest.channels, crate::anchors::CHANNELS)?;
    crate::exact_strings(&manifest.requirements, crate::anchors::REQUIREMENTS)?;
    let mut groups = BTreeSet::new();
    for case in &manifest.cases {
        let class = match case.evidence_class {
            EvidenceClass::InstalledProduct => "installed_product",
            EvidenceClass::NativeComponentRegression => "native_component_regression",
        };
        if !groups.insert((case.family.as_str(), case.platform.as_str(), class)) {
            return Err("duplicate current manifest case group".into());
        }
        let anchor = anchors::CASES
            .iter()
            .find(|anchor| {
                anchor.0 == case.family && anchor.1 == case.platform && anchor.2 == class
            })
            .ok_or("unknown or reclassified current manifest case group")?;
        crate::exact_strings(&case.scenarios, anchor.3.split_whitespace())?;
        crate::exact_strings(&case.requirements, anchor.4.split_whitespace())?;
    }
    if groups.len() != anchors::CASES.len() {
        return Err("current manifest omits independently pinned semantic group".into());
    }
    let mut expected = BTreeSet::new();
    for (family, platform, class, scenarios, _) in anchors::CASES {
        for target in crate::anchors::TARGETS {
            if (*platform == "linux" && !target.ends_with("linux-gnu"))
                || (*platform == "windows" && !target.ends_with("windows-msvc"))
            {
                continue;
            }
            for scenario in scenarios.split_whitespace() {
                let evidence_class = if *class == "installed_product" {
                    EvidenceClass::InstalledProduct
                } else {
                    EvidenceClass::NativeComponentRegression
                };
                let channels = if evidence_class == EvidenceClass::InstalledProduct {
                    crate::anchors::CHANNELS
                        .into_iter()
                        .map(|channel| Some(channel.to_owned()))
                        .collect()
                } else {
                    vec![None]
                };
                for channel in channels {
                    expected.insert(CaseKey {
                        target: target.into(),
                        channel,
                        evidence_class,
                        family: (*family).into(),
                        scenario: scenario.into(),
                    });
                }
            }
        }
    }
    Ok(expected)
}
