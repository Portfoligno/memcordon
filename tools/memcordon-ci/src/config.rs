use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use cargo_metadata::{DependencyKind, Metadata};
use serde::{Deserialize, Serialize};

use crate::Result;

pub const RELEASE_SCHEMA_VERSION: u32 = 3;

/// Derive and validate the canonical dependency order for public workspace packages.
pub fn publish_order(metadata: &Metadata, configured: &[String]) -> Result<Vec<String>> {
    let configured_set: BTreeSet<&str> = configured.iter().map(String::as_str).collect();
    if configured_set.len() != configured.len() {
        return Err(crate::CiError::Message(
            "release publish package list contains duplicates".to_owned(),
        ));
    }
    let packages: BTreeMap<&str, &cargo_metadata::Package> = metadata
        .packages
        .iter()
        .map(|package| (package.name.as_str(), package))
        .collect();
    let mut remaining: BTreeSet<&str> = configured_set.clone();
    let mut order = Vec::new();
    while !remaining.is_empty() {
        let next = remaining.iter().copied().find(|name| {
            packages.get(name).is_some_and(|package| {
                package.dependencies.iter().all(|dependency| {
                    dependency.kind == DependencyKind::Development
                        || !configured_set.contains(dependency.name.as_str())
                        || order
                            .iter()
                            .any(|published| published == dependency.name.as_str())
                })
            })
        });
        let Some(next) = next else {
            return Err(crate::CiError::Message(
                "publishable workspace dependency graph contains a cycle".to_owned(),
            ));
        };
        let package = packages.get(next).ok_or_else(|| {
            crate::CiError::Message(format!("configured publish package is absent: {next}"))
        })?;
        if package.publish.as_ref().is_none_or(|registries| {
            registries.len() != 1
                || registries
                    .first()
                    .is_none_or(|registry| registry != "crates-io")
        }) {
            return Err(crate::CiError::Message(format!(
                "package is not crates.io-only: {next}"
            )));
        }
        for dependency in &package.dependencies {
            if dependency.kind != DependencyKind::Development
                && dependency.path.is_some()
                && !configured_set.contains(dependency.name.as_str())
            {
                return Err(crate::CiError::Message(format!(
                    "publishable package {next} depends on non-public workspace package {}",
                    dependency.name
                )));
            }
            if dependency.kind != DependencyKind::Development
                && configured_set.contains(dependency.name.as_str())
            {
                let requirement = dependency.req.to_string();
                let expected = format!("={}", package.version);
                if requirement != expected {
                    return Err(crate::CiError::Message(format!(
                        "internal dependency {} in {next} must be exact {expected}",
                        dependency.name
                    )));
                }
            }
        }
        remaining.remove(next);
        order.push(next.to_owned());
    }
    if order != configured {
        return Err(crate::CiError::Message(format!(
            "configured publish order {configured:?} does not match derived DAG {order:?}"
        )));
    }
    Ok(order)
}

#[derive(Clone, Debug, Deserialize)]
pub struct Toolchains {
    pub stable: String,
    pub msrv: String,
    pub miri: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Tools {
    pub cargo_audit: String,
    pub cargo_deny: String,
    pub cargo_fuzz: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Policy {
    pub workspace: WorkspacePolicy,
    pub workflow: WorkflowPolicy,
    pub test: TestPolicy,
}

#[derive(Clone, Debug, Deserialize)]
pub struct WorkspacePolicy {
    pub production_packages: Vec<String>,
    pub ci_packages: Vec<String>,
    pub ci_package_rust_versions: BTreeMap<String, semver::Version>,
    pub publish_packages: Vec<String>,
    pub non_publish_packages: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct WorkflowPolicy {
    pub required_public_matrix: Vec<String>,
    pub allowed_run_commands: Vec<String>,
    pub self_extracting_shell_allowlist: Vec<String>,
    pub environment_allowlist: Vec<EnvironmentAllowance>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct EnvironmentAllowance {
    pub file: String,
    pub variable: String,
    pub source: String,
    pub steps: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TestPolicy {
    pub fast_short_child_iterations: u32,
    pub deep_short_child_iterations: u32,
    pub release_short_child_iterations: u32,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ActionPins {
    pub action: Vec<ActionPin>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ActionPin {
    pub name: String,
    pub uses: String,
    pub release: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BinaryFiles {
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub extensions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    pub schema_version: u32,
    pub repository: String,
    pub workflow: String,
    pub registry: String,
    pub publish_packages: Vec<String>,
    pub github_api_version: String,
    pub maximum_package_bytes: u64,
    pub maximum_asset_bytes: u64,
    pub registry_credentials: RegistryCredentials,
    pub assets: Assets,
    pub registry_wait: RegistryWait,
    pub network_retry: RegistryWait,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum RegistryCredentialPolicy {
    OidcOnly,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryCredentials {
    pub policy: RegistryCredentialPolicy,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Assets {
    pub output_directory: String,
    pub manifest: String,
    pub publication_report: String,
    pub checksums: String,
    pub notes: String,
    pub target: Vec<AssetTarget>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetTarget {
    pub id: String,
    pub rust_target: String,
    pub archive: String,
    pub executable: Vec<AssetExecutable>,
    pub sealed: SealedAssetPolicy,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetExecutable {
    pub package: String,
    pub binary: String,
    pub archive_path: String,
    pub mode: u32,
    pub role: RuntimeComponentRole,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeComponentRole {
    PublicCli,
    SealedAgent,
    DesktopBootstrap,
    SessionBroker,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum SealedAssetPolicy {
    Included,
    NotApplicable,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RegistryWait {
    pub initial_milliseconds: u64,
    pub maximum_milliseconds: u64,
    pub total_seconds: u64,
}

fn read<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    parse_toml(&fs::read(path)?)
}

fn parse_toml<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    Ok(toml::from_str(text)?)
}

/// Parses untrusted repository policy bytes through the production deserializer.
pub fn parse_policy(bytes: &[u8]) -> Result<Policy> {
    parse_toml(bytes)
}

pub fn toolchains(root: &Path) -> Result<Toolchains> {
    read(&root.join("ci").join("toolchains.toml"))
}

pub fn tools(root: &Path) -> Result<Tools> {
    read(&root.join("ci").join("tools.toml"))
}

pub fn policy(root: &Path) -> Result<Policy> {
    parse_policy(&fs::read(root.join("ci").join("policy.toml"))?)
}

pub fn action_pins(root: &Path) -> Result<ActionPins> {
    read(&root.join(".github").join("action-pins.toml"))
}

pub fn binary_files(root: &Path) -> Result<BinaryFiles> {
    read(&root.join("ci").join("binary-files.toml"))
}

pub fn release(root: &Path) -> Result<Release> {
    read(&root.join("ci").join("release.toml"))
}

pub fn release_target_id_for_host(os: &str, arch: &str) -> Result<&'static str> {
    match (os, arch) {
        ("linux", "x86_64") => Ok("linux-x64"),
        ("linux", "aarch64") => Ok("linux-arm64"),
        ("macos", "aarch64") => Ok("macos-arm64"),
        ("macos", "x86_64") => Ok("macos-x64"),
        ("windows", "x86_64") => Ok("windows-x64"),
        ("windows", "aarch64") => Ok("windows-arm64"),
        _ => Err(crate::CiError::Message(
            "host is not a configured release target".to_owned(),
        )),
    }
}

pub fn validate_release_configuration_identity(release: &Release) -> Result<()> {
    let expected_targets = [
        ("linux-x64", "x86_64-unknown-linux-gnu", "tar-gz", true),
        ("linux-arm64", "aarch64-unknown-linux-gnu", "tar-gz", true),
        ("macos-arm64", "aarch64-apple-darwin", "tar-gz", false),
        ("macos-x64", "x86_64-apple-darwin", "tar-gz", false),
        ("windows-x64", "x86_64-pc-windows-msvc", "zip", true),
        ("windows-arm64", "aarch64-pc-windows-msvc", "zip", true),
    ];
    let targets_match = release.assets.target.len() == expected_targets.len()
        && release
            .assets
            .target
            .iter()
            .zip(expected_targets)
            .all(|(actual, expected)| {
                (
                    actual.id.as_str(),
                    actual.rust_target.as_str(),
                    actual.archive.as_str(),
                    actual.sealed == SealedAssetPolicy::Included,
                ) == expected
                    && validate_target_executables(actual, expected.3)
            });
    if release.schema_version != RELEASE_SCHEMA_VERSION
        || release.registry != "crates-io"
        || release.workflow != "release.yml"
        || release.github_api_version.is_empty()
        || release.maximum_package_bytes == 0
        || release.maximum_asset_bytes == 0
        || release.registry_wait.initial_milliseconds == 0
        || release.registry_wait.maximum_milliseconds < release.registry_wait.initial_milliseconds
        || release.network_retry.initial_milliseconds == 0
        || release.network_retry.maximum_milliseconds < release.network_retry.initial_milliseconds
        || !targets_match
    {
        return Err(crate::CiError::Message(
            "release configuration identity is invalid".to_owned(),
        ));
    }
    Ok(())
}

pub fn certify_windows_archive_omission_mutant(root: &Path) -> Result<bool> {
    let mut mutated = release(root)?;
    let target_id = release_target_id_for_host("windows", std::env::consts::ARCH)?;
    let target = mutated
        .assets
        .target
        .iter_mut()
        .find(|target| target.id == target_id)
        .ok_or_else(|| {
            crate::CiError::Message("host Windows release target is absent".to_owned())
        })?;
    let original_count = target.executable.len();
    target
        .executable
        .retain(|component| component.role != RuntimeComponentRole::SealedAgent);
    Ok(target.executable.len() + 1 == original_count
        && validate_release_configuration_identity(&mutated).is_err())
}

fn validate_target_executables(target: &AssetTarget, sealed: bool) -> bool {
    let expected_public_path = if target.archive == "zip" {
        "memcordon.exe"
    } else {
        "memcordon"
    };
    let windows_sealed = sealed && target.archive == "zip";
    let expected_count = usize::from(sealed) + usize::from(windows_sealed) * 2 + 1;
    if target.executable.len() != expected_count {
        return false;
    }
    let public = &target.executable[0];
    if public.package != "memcordon"
        || public.binary != "memcordon"
        || public.archive_path != expected_public_path
        || public.mode != 0o755
        || public.role != RuntimeComponentRole::PublicCli
    {
        return false;
    }
    if sealed {
        let agent = &target.executable[1];
        let expected_agent_path = if target.archive == "zip" {
            "memcordon-sealed-agent.exe"
        } else {
            "memcordon-sealed-agent"
        };
        if agent.package != "memcordon"
            || agent.binary != "memcordon-sealed-agent"
            || agent.archive_path != expected_agent_path
            || agent.mode != 0o755
            || agent.role != RuntimeComponentRole::SealedAgent
        {
            return false;
        }
    }
    if windows_sealed {
        let bootstrap = &target.executable[2];
        if bootstrap.package != "memcordon"
            || bootstrap.binary != "memcordon-target-desktop-bootstrap"
            || bootstrap.archive_path != "memcordon-target-desktop-bootstrap.exe"
            || bootstrap.mode != 0o755
            || bootstrap.role != RuntimeComponentRole::DesktopBootstrap
        {
            return false;
        }
        let broker = &target.executable[3];
        if broker.package != "memcordon"
            || broker.binary != "memcordon-session-broker"
            || broker.archive_path != "memcordon-session-broker.exe"
            || broker.mode != 0o755
            || broker.role != RuntimeComponentRole::SessionBroker
        {
            return false;
        }
    }
    let mut paths = std::collections::BTreeSet::new();
    let mut binaries = std::collections::BTreeSet::new();
    target.executable.iter().all(|component| {
        component.package == "memcordon"
            && paths.insert(component.archive_path.as_str())
            && binaries.insert(component.binary.as_str())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_configuration_is_closed_to_oidc_only() {
        toml::from_str::<RegistryCredentials>("policy = \"oidc-only\"\n")
            .expect("OIDC-only credentials should parse");
        for legacy in [
            "policy = \"arbitrary-provider\"\n",
            "policy = \"first-release-token-primary\"\nfirst_release_version = \"0.1.3\"\n",
            "policy = \"oidc-only\"\nfirst_release_version = \"0.1.3\"\n",
        ] {
            assert!(
                toml::from_str::<RegistryCredentials>(legacy).is_err(),
                "legacy credential configuration unexpectedly parsed"
            );
        }
    }

    #[test]
    fn release_configuration_rejects_removed_eligibility_fields() {
        let exact = include_str!("../../../ci/release.toml");
        toml::from_str::<Release>(exact)
            .expect("branch- and environment-independent release config should parse");
        let exact_table =
            toml::from_str::<toml::Table>(exact).expect("release config should be a TOML table");
        for (obsolete_field, obsolete_value) in [
            (
                "source_branches",
                toml::Value::Array(vec![toml::Value::String("release".to_owned())]),
            ),
            ("environment", toml::Value::String("release".to_owned())),
        ] {
            let mut obsolete_table = exact_table.clone();
            assert!(
                obsolete_table
                    .insert(obsolete_field.to_owned(), obsolete_value)
                    .is_none()
            );
            let obsolete =
                toml::to_string(&obsolete_table).expect("release config should serialize");
            assert!(toml::from_str::<Release>(&obsolete).is_err());
        }
    }
}
