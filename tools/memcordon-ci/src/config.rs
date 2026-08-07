use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::Result;

pub const RELEASE_SCHEMA_VERSION: u32 = 2;

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
pub struct AssetTarget {
    pub id: String,
    pub rust_target: String,
    pub archive: String,
    pub executable: String,
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
        (
            "linux-x64",
            "x86_64-unknown-linux-gnu",
            "tar-gz",
            "memcordon",
        ),
        (
            "linux-arm64",
            "aarch64-unknown-linux-gnu",
            "tar-gz",
            "memcordon",
        ),
        ("macos-arm64", "aarch64-apple-darwin", "tar-gz", "memcordon"),
        ("macos-x64", "x86_64-apple-darwin", "tar-gz", "memcordon"),
        (
            "windows-x64",
            "x86_64-pc-windows-msvc",
            "zip",
            "memcordon.exe",
        ),
        (
            "windows-arm64",
            "aarch64-pc-windows-msvc",
            "zip",
            "memcordon.exe",
        ),
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
                    actual.executable.as_str(),
                ) == expected
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
