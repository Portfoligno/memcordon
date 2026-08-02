use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::Result;

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
    FirstReleaseTokenPrimary,
    OidcOnly,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryCredentials {
    pub policy: RegistryCredentialPolicy,
    pub first_release_version: Option<semver::Version>,
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

pub fn validate_registry_credentials(
    credentials: &RegistryCredentials,
    workspace_version: &semver::Version,
) -> Result<()> {
    match (
        credentials.policy,
        credentials.first_release_version.as_ref(),
    ) {
        (RegistryCredentialPolicy::FirstReleaseTokenPrimary, Some(first))
            if first.pre.is_empty()
                && first.build.is_empty()
                && workspace_version.build.is_empty()
                && (workspace_version == first
                    || (workspace_version.major == first.major
                        && workspace_version.minor == first.minor
                        && workspace_version.patch == first.patch
                        && workspace_version.pre.as_str() == "dev")) =>
        {
            Ok(())
        }
        (RegistryCredentialPolicy::FirstReleaseTokenPrimary, Some(first))
            if first.pre.is_empty() && first.build.is_empty() =>
        {
            Err(crate::CiError::Message(format!(
                "first-release-token-primary permits only {first} and its corresponding -dev workspace version"
            )))
        }
        (RegistryCredentialPolicy::FirstReleaseTokenPrimary, _) => Err(crate::CiError::Message(
            "first-release-token-primary requires a stable first_release_version".to_owned(),
        )),
        (RegistryCredentialPolicy::OidcOnly, None) => Ok(()),
        (RegistryCredentialPolicy::OidcOnly, Some(_)) => Err(crate::CiError::Message(
            "oidc-only forbids first_release_version".to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use semver::Version;

    fn transition(first: Option<&str>) -> RegistryCredentials {
        RegistryCredentials {
            policy: RegistryCredentialPolicy::FirstReleaseTokenPrimary,
            first_release_version: first.map(|value| Version::parse(value).expect("valid version")),
        }
    }

    #[test]
    fn transition_version_policy_accepts_only_first_and_corresponding_dev() {
        let credentials = transition(Some("0.1.0"));
        for accepted in ["0.1.0", "0.1.0-dev"] {
            validate_registry_credentials(
                &credentials,
                &Version::parse(accepted).expect("valid accepted version"),
            )
            .expect("first release version shape should pass");
        }
        for rejected in ["0.1.0-alpha", "0.1.0+build", "0.1.1-dev", "0.2.0"] {
            assert!(
                validate_registry_credentials(
                    &credentials,
                    &Version::parse(rejected).expect("valid rejected version"),
                )
                .is_err(),
                "transition unexpectedly accepted {rejected}"
            );
        }
    }

    #[test]
    fn credential_configuration_is_closed_and_profile_consistent() {
        assert!(
            toml::from_str::<RegistryCredentials>(
                "policy = \"arbitrary-provider\"\nfirst_release_version = \"0.1.0\"\n"
            )
            .is_err()
        );
        assert!(
            validate_registry_credentials(
                &transition(None),
                &Version::parse("0.1.0-dev").expect("valid version")
            )
            .is_err()
        );
        let oidc = RegistryCredentials {
            policy: RegistryCredentialPolicy::OidcOnly,
            first_release_version: None,
        };
        validate_registry_credentials(
            &oidc,
            &Version::parse("9.0.0").expect("valid later version"),
        )
        .expect("oidc-only accepts later releases");
        let inconsistent = RegistryCredentials {
            first_release_version: Some(Version::parse("0.1.0").expect("valid version")),
            ..oidc
        };
        assert!(
            validate_registry_credentials(
                &inconsistent,
                &Version::parse("0.1.0").expect("valid version")
            )
            .is_err()
        );
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
