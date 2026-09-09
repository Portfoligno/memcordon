use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::num::NonZeroUsize;
use std::path::{Component, Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cargo_metadata::{Metadata, MetadataCommand};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use semver::Version;
use serde::de::Error as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use walkdir::WalkDir;

use memcordon_ci::capability;
use memcordon_ci::release_archive::{
    NATIVE_ARCHIVE_STATIC_PATHS, RUNTIME_MANIFEST, cargo_install_inventory,
    configured_default_cargo_binaries, validate_markdown_documents,
    validate_memcordon_crate_distribution as validate_reviewed_memcordon_distribution,
};
use memcordon_ci::release_evidence::{CertificationRecord, collect_certification};
use memcordon_ci::runtime_manifest::{RuntimeComponentRecord, RuntimeManifestV2, SealedRuntimeV2};
#[cfg(target_os = "linux")]
use memcordon_ci::sealed_identity::frontend_identity;
#[cfg(any(target_os = "linux", test))]
use memcordon_ci::sealed_identity::{FrontendIdentity, setpriv_sudo_arguments};
use memcordon_testkit::ObservedOutput;

use crate::command::{CommandSpec, git, rustup_cargo};
use crate::config::{self, AssetTarget, RuntimeComponentRole, SealedAssetPolicy};
use crate::{CiError, ReleaseCommand, Result};

const RELEASE_DEADLINE: Duration = Duration::from_secs(30 * 60);
const GITHUB_API_ROOT: &str = "https://api.github.com";
const GITHUB_UPLOADS_ROOT: &str = "https://uploads.github.com";
const CRATES_IO_API_ROOT: &str = "https://crates.io";
const CRATES_IO_INDEX_ROOT: &str = "https://index.crates.io";
const CRATES_IO_DOWNLOAD_ROOT: &str = "https://static.crates.io";
const REGISTRY_USER_AGENT: &str = "memcordon-ci (https://github.com/Portfoligno/memcordon)";
const GITHUB_RELEASES_PER_PAGE: usize = 100;
const CRATES_IO_TOKEN_VARIABLE: &str = "CARGO_REGISTRIES_CRATES_IO_TOKEN";
pub(crate) const TRUSTED_PUBLISHING_NEW_CRATE_MARKER: &str = "Trusted Publishing tokens do not support creating new crates. Publish the crate manually, first";
const ACCESS_TOKEN_CRATE_REJECTION_MARKER: &str =
    "The provided access token is not valid for crate `";
const PUBLICATION_EVIDENCE_SCHEMA_VERSION: u32 = 1;
const MAXIMUM_CARGO_DIAGNOSTIC_BYTES: usize = 65536;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialOrigin {
    Oidc,
    NewCrateToken,
}

impl CredentialOrigin {
    fn value(self) -> &'static str {
        match self {
            Self::Oidc => "oidc",
            Self::NewCrateToken => "new-crate-token",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "oidc" => Some(Self::Oidc),
            "new-crate-token" => Some(Self::NewCrateToken),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct CredentialRequest {
    v: u32,
    registry: CredentialRegistry,
    #[serde(default)]
    args: Vec<String>,
    #[serde(flatten)]
    action: CredentialAction,
}

#[derive(Clone, Copy, Debug)]
struct ProviderBinding<'a> {
    origin: CredentialOrigin,
    publication_slot: NonZeroUsize,
    name: &'a str,
    version: &'a str,
    archive_sha256: &'a str,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum CredentialAction {
    Get {
        #[serde(flatten)]
        operation: CredentialOperation,
    },
    Login {
        #[allow(dead_code)]
        #[serde(default)]
        token: Option<String>,
        #[allow(dead_code)]
        #[serde(rename = "login-url", default)]
        login_url: Option<String>,
    },
    Logout,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case")]
enum CredentialOperation {
    Read,
    Publish {
        name: String,
        vers: String,
        cksum: String,
    },
    #[serde(other)]
    Unsupported,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialRegistry {
    #[serde(rename = "index-url")]
    index_url: String,
    name: Option<String>,
    #[serde(rename = "headers", default)]
    _headers: Vec<String>,
}

#[derive(Serialize)]
struct CargoHomeConfig {
    registry: CargoRegistryConfig,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct CargoRegistryConfig {
    credential_provider: Vec<String>,
}

#[derive(Clone, Debug)]
struct HttpEndpoints {
    github_started: Instant,
    github_api: String,
    github_uploads: String,
    crates_io: String,
    crates_io_index: String,
    crates_io_download: String,
}

impl HttpEndpoints {
    fn production() -> Self {
        Self {
            github_started: Instant::now(),
            github_api: GITHUB_API_ROOT.to_owned(),
            github_uploads: GITHUB_UPLOADS_ROOT.to_owned(),
            crates_io: CRATES_IO_API_ROOT.to_owned(),
            crates_io_index: CRATES_IO_INDEX_ROOT.to_owned(),
            crates_io_download: CRATES_IO_DOWNLOAD_ROOT.to_owned(),
        }
    }

    #[cfg(test)]
    fn fixed_test_server(root: &str) -> Self {
        Self {
            github_started: Instant::now(),
            github_api: root.to_owned(),
            github_uploads: root.to_owned(),
            crates_io: root.to_owned(),
            crates_io_index: root.to_owned(),
            crates_io_download: root.to_owned(),
        }
    }
}
#[derive(Clone, Debug)]
pub struct ReleaseIdentity {
    tag: String,
    version: Version,
    commit: String,
    changelog_section: String,
    source_date: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct AssetRecord {
    name: String,
    target: String,
    size: u64,
    sha256: String,
    runtime_manifest_sha256: String,
    components: Vec<RuntimeComponentRecord>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct NativeAssetReport {
    schema_version: u32,
    tag: String,
    source_commit: String,
    asset: AssetRecord,
    archive_member_inventory_sha256: String,
    smoke: NativeSmokeReport,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct NativeSmokeReport {
    cli_version: bool,
    doctor: bool,
    agent_version: Option<bool>,
    agent_inspection: Option<bool>,
    provider_install: Option<bool>,
    provider_verify: Option<bool>,
    provider_qualification: Option<bool>,
    sealed_execution: Option<bool>,
    provider_uninstall: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct AgentPackageInspection {
    schema_version: u32,
    version: String,
    source_commit: String,
    executable_sha256: String,
    provider_protocol: u32,
    native_protocols: memcordon_core::runtime_manifest::NativeProviderProtocols,
    runtime_manifest_schema: u32,
    workload_contract_schema: u32,
    profile_catalog_sha256: String,
    mechanism: String,
    execution_report_schema: u32,
    plan_report_schema: u32,
    doctor_report_schema: u32,
    #[serde(flatten)]
    platform: AgentPackagePlatform,
    compiled_metadata_valid: bool,
}

#[derive(Debug, Deserialize)]
#[allow(clippy::large_enum_variant)] // Mirror the package schema without changing its field shape.
#[serde(tag = "platform", rename_all = "kebab-case", deny_unknown_fields)]
enum AgentPackagePlatform {
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
        target_desktop_bootstrap_runtime: TargetDesktopBootstrapRuntime,
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum TargetDesktopBootstrapRuntime {
    StaticVcRuntimeOsUcrt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct CrateRecord {
    name: String,
    version: String,
    archive_sha256: String,
    canonical_tree_sha256: String,
    canonical_identity_sha256: String,
    vcs_commit: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ReleaseManifest {
    schema_version: u32,
    project: String,
    tag: String,
    version: String,
    source_commit: String,
    workflow_commit: String,
    workflow_ref: String,
    workflow_sha256: String,
    action_revisions: BTreeMap<String, String>,
    prerelease: bool,
    rust_toolchain: String,
    assets: Vec<AssetRecord>,
    crates: Vec<CrateRecord>,
    certification: BTreeMap<String, CertificationRecord>,
    certification_contract: String,
    certification_origin: memcordon_ci::certification_context::ExpectedCertificationOrigin,
    source_date: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PublicationReport {
    schema_version: u32,
    manifest_sha256: String,
    github_release_id: u64,
    source_commit: String,
    workflow_commit: String,
    prerelease: bool,
    assets: Vec<PublicAssetRecord>,
    crates: Vec<PublicCrateRecord>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct PublicAssetRecord {
    id: u64,
    name: String,
    size: u64,
    sha256: String,
    runtime_manifest_sha256: Option<String>,
    components: Vec<RuntimeComponentRecord>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct PublicCrateRecord {
    name: String,
    version: String,
    state: String,
    registry_checksum: String,
    canonical_tree_sha256: String,
    canonical_identity_sha256: String,
    vcs_commit: String,
}

#[derive(Debug, Eq, PartialEq)]
struct CrateArchiveIdentity {
    sha256: String,
    package_name: String,
    package_version: String,
    vcs_commit: String,
    vcs_dirty: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RemoteReleaseState {
    Draft(u64),
    Published(u64),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DispatchInputs {
    tag: String,
}

#[derive(Debug, Deserialize)]
struct WorkflowEvent {
    #[serde(default)]
    inputs: Option<DispatchInputs>,
}

fn release_tag_version(tag: &str) -> Option<Version> {
    Version::parse(tag).ok()
}

fn validate_release_version(version: &Version) -> Result<()> {
    if !version.build.is_empty()
        || version
            .pre
            .as_str()
            .split('.')
            .any(|identifier| identifier == "dev")
    {
        return Err(failure(
            "release version may not contain build metadata or dev",
        ));
    }
    Ok(())
}

fn workspace_version(root: &Path) -> Result<Version> {
    let metadata = metadata(root)?;
    metadata
        .packages
        .iter()
        .find(|package| package.name.as_str() == "memcordon")
        .map(|package| package.version.clone())
        .ok_or_else(|| failure("workspace version is unavailable"))
}

fn validate_dynamic_release_identity(
    tag: &str,
    manifest_version: &str,
    workspace_version: &Version,
) -> Result<Version> {
    let tag_version = release_tag_version(tag)
        .ok_or_else(|| failure(format!("release tag is not canonical SemVer: {tag}")))?;
    let manifest_version = Version::parse(manifest_version)
        .map_err(|error| failure(format!("release manifest version is invalid: {error}")))?;
    validate_release_version(&tag_version)?;
    if manifest_version != tag_version {
        return Err(failure(format!(
            "release tag/version mismatch: tag={tag_version}, manifest={manifest_version}"
        )));
    }
    if *workspace_version != tag_version {
        return Err(failure(format!(
            "release tag/version mismatch: tag={tag_version}, workspace={workspace_version}"
        )));
    }
    Ok(tag_version)
}

fn required_platform_value(name: &str) -> Result<String> {
    std::env::var(name).map_err(|_| {
        failure(format!(
            "required GitHub release provenance is missing: {name}"
        ))
    })
}

fn workflow_event() -> Result<(String, WorkflowEvent)> {
    let event_name = required_platform_value("GITHUB_EVENT_NAME")?;
    let event_path = required_platform_value("GITHUB_EVENT_PATH")?;
    let event: WorkflowEvent = serde_json::from_slice(&fs::read(PathBuf::from(event_path))?)?;
    Ok((event_name, event))
}

fn validate_release_event_context(tag: &str) -> Result<()> {
    let (event_name, event) = workflow_event()?;
    match event_name.as_str() {
        "push" => {
            if event.inputs.is_some() {
                return Err(failure("push release event unexpectedly contains inputs"));
            }
        }
        "workflow_dispatch" => {
            let input_tag = &event
                .inputs
                .as_ref()
                .ok_or_else(|| failure("workflow_dispatch inputs are missing"))?
                .tag;
            if input_tag != tag {
                return Err(failure(
                    "workflow_dispatch tag input differs from the protected release tag",
                ));
            }
        }
        other => return Err(failure(format!("unsupported release event: {other}"))),
    }
    Ok(())
}

fn failure(message: impl Into<String>) -> CiError {
    CiError::Message(message.into())
}

fn utf8(bytes: impl AsRef<[u8]>, context: &str) -> Result<String> {
    String::from_utf8(bytes.as_ref().to_vec())
        .map_err(|error| failure(format!("{context} is not UTF-8: {error}")))
}

fn git_text(root: &Path, arguments: &[&str]) -> Result<String> {
    Ok(utf8(git(root, arguments)?, "Git output")?.trim().to_owned())
}

fn git_text_os(root: &Path, arguments: impl IntoIterator<Item = OsString>) -> Result<String> {
    Ok(utf8(
        CommandSpec::new("git", root, Duration::from_secs(120))
            .args(arguments)
            .run()?,
        "Git output",
    )?
    .trim()
    .to_owned())
}

fn metadata(root: &Path) -> Result<Metadata> {
    let mut command = MetadataCommand::new();
    command
        .current_dir(root)
        .env_remove("CARGO_REGISTRY_TOKEN")
        .env_remove(CRATES_IO_TOKEN_VARIABLE);
    Ok(command.exec()?)
}

fn parse_changelog(root: &Path, version: &Version) -> Result<(String, String)> {
    let markdown = fs::read_to_string(root.join("CHANGELOG.md"))?;
    let wanted = version.to_string();
    let mut section = Vec::new();
    let mut date = None;
    let mut collecting = false;
    let mut matches = 0_u32;
    for line in markdown.lines() {
        if let Some(header) = line.strip_prefix("## [") {
            if collecting {
                break;
            }
            let Some((candidate, suffix)) = header.split_once(']') else {
                return Err(failure("malformed changelog version heading"));
            };
            if candidate == wanted {
                matches += 1;
                collecting = true;
                let date_text = suffix
                    .strip_prefix(" - ")
                    .ok_or_else(|| failure("release changelog heading lacks an ISO date"))?;
                let fields: Vec<&str> = date_text.split('-').collect();
                if fields.len() != 3
                    || fields[0].parse::<u16>().is_err()
                    || fields[1]
                        .parse::<u8>()
                        .ok()
                        .is_none_or(|value| !(1..=12).contains(&value))
                    || fields[2]
                        .parse::<u8>()
                        .ok()
                        .is_none_or(|value| !(1..=31).contains(&value))
                {
                    return Err(failure("release changelog date is invalid"));
                }
                date = Some(date_text.to_owned());
                section.push(line.to_owned());
            }
        } else if collecting {
            section.push(line.to_owned());
        }
    }
    if matches != 1 || section.is_empty() {
        return Err(failure(format!(
            "CHANGELOG.md must contain exactly one section for {version}"
        )));
    }
    let body = section.join("\n");
    for placeholder in ["TBD", "TODO", "Unreleased"] {
        if body.contains(placeholder) {
            return Err(failure(format!(
                "release changelog section contains placeholder {placeholder}"
            )));
        }
    }
    Ok((
        format!("{body}\n"),
        date.expect("date set with matching section"),
    ))
}

fn validate_fallback_remote_tags(output: &[u8], release_version: &Version) -> Result<()> {
    let output = utf8(output, "remote release tag inventory")?;
    for reference in output
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1))
        .filter_map(|reference| reference.strip_prefix("refs/tags/"))
    {
        let Some(version) = release_tag_version(reference) else {
            continue;
        };
        if version > *release_version {
            return Err(failure(format!(
                "new-crate fallback policy survives a later release tag: release={release_version} observed={version}"
            )));
        }
    }
    Ok(())
}

pub fn preflight(root: &Path) -> Result<ReleaseIdentity> {
    let release = config::release(root)?;
    config::validate_release_configuration_identity(&release)?;
    let status = git(root, ["status", "--porcelain=v1", "-z"])?;
    if !status.is_empty() {
        return Err(failure("release worktree or index is dirty"));
    }
    let commit = git_text(root, &["rev-parse", "HEAD"])?;
    let tags = git_text(root, &["tag", "--points-at", "HEAD"])?;
    let exact_tags: Vec<(&str, Version)> = tags
        .lines()
        .filter_map(|tag| release_tag_version(tag).map(|version| (tag, version)))
        .collect();
    if exact_tags.len() != 1 {
        return Err(failure(
            "release HEAD must have exactly one SemVer release tag",
        ));
    }
    let (tag, version) = exact_tags
        .into_iter()
        .next()
        .expect("exactly one release tag checked");
    let tag = tag.to_owned();
    let mut tag_object = OsString::from(&tag);
    tag_object.push("^{}");
    let resolved_tag = git_text_os(root, [OsString::from("rev-parse"), tag_object])?;
    if resolved_tag != commit {
        return Err(failure("release tag does not resolve to HEAD"));
    }
    let mut remote_tag = OsString::from("refs/tags/");
    remote_tag.push(&tag);
    let mut remote_peeled_tag = remote_tag.clone();
    remote_peeled_tag.push("^{}");
    let remote_tag_output = utf8(
        git(
            root,
            [
                OsString::from("ls-remote"),
                OsString::from("--tags"),
                OsString::from("origin"),
                remote_tag,
                remote_peeled_tag,
            ],
        )?,
        "remote tag query",
    )?;
    if !remote_tag_output
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .any(|remote_commit| remote_commit == commit)
    {
        return Err(failure(
            "release tag is absent from origin or does not resolve to HEAD",
        ));
    }
    let metadata = metadata(root)?;
    let workspace_version = metadata
        .packages
        .iter()
        .find(|package| package.name.as_str() == "memcordon")
        .map(|package| package.version.clone())
        .ok_or_else(|| failure("workspace version is unavailable"))?;
    let version =
        validate_dynamic_release_identity(&tag, &version.to_string(), &workspace_version)?;
    config::validate_registry_credentials(&release, &workspace_version)?;
    if let config::RegistryCredentialPolicy::OidcFirstNewCrateFallback =
        release.registry_credentials.policy
    {
        let remote_tags = git_text(root, &["ls-remote", "--tags", "origin"])?;
        validate_fallback_remote_tags(remote_tags.as_bytes(), &version)?;
    }
    config::publish_order(&metadata, &release.publish_packages)?;
    let workflow_sha = required_platform_value("GITHUB_WORKFLOW_SHA")?;
    if workflow_sha != commit {
        return Err(failure(
            "workflow-definition commit differs from source tag commit",
        ));
    }
    let workflow_ref = required_platform_value("GITHUB_WORKFLOW_REF")?;
    let expected_suffix = format!("@refs/tags/{tag}");
    if !workflow_ref.ends_with(&expected_suffix) {
        return Err(failure(
            "workflow ref is not the exact protected release tag",
        ));
    }
    let github_ref = required_platform_value("GITHUB_REF")?;
    if github_ref != format!("refs/tags/{tag}") {
        return Err(failure(
            "release workflow did not execute at the exact tag ref",
        ));
    }
    validate_release_event_context(&tag)?;
    CommandSpec::new("git", root, Duration::from_secs(120))
        .args(["diff", "--quiet", "HEAD", "--", "Cargo.lock"])
        .run()
        .map_err(|_| failure("Cargo.lock differs from the tagged commit"))?;
    let (changelog_section, source_date) = parse_changelog(root, &version)?;
    Ok(ReleaseIdentity {
        tag,
        version,
        commit,
        changelog_section,
        source_date,
    })
}

pub fn validate_packages(root: &Path) -> Result<()> {
    let identity = preflight(root)?;
    let release = config::release(root)?;
    let default_cargo_binaries = configured_default_cargo_binaries(&release)?;
    let toolchains = config::toolchains(root)?;
    create_package_archives(root, &toolchains.stable, &release.publish_packages)?;
    for package in &release.publish_packages {
        let record = package_crate(
            root,
            &toolchains.stable,
            package,
            &identity.version,
            &identity.commit,
            release.maximum_package_bytes,
            &default_cargo_binaries,
        )?;
        if matches!(
            crate_version_state(&release, &record.name, &record.version)?,
            CrateVersionLookup::Present(_)
        ) {
            verify_public_crate(&release, &record)?;
        }
    }
    smoke_packaged_memcordon_install(
        root,
        &toolchains.stable,
        &identity.version,
        &identity.commit,
        &default_cargo_binaries,
    )?;
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(hex::encode(hash.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn normalized_member_path(path: &Path) -> Result<PathBuf> {
    let mut components = path.components();
    let package_root = components
        .next()
        .ok_or_else(|| failure("package archive contains an empty path"))?;
    if !matches!(package_root, Component::Normal(_)) {
        return Err(failure(
            "package archive root is not a normal relative path",
        ));
    }
    let mut normalized = PathBuf::new();
    for component in components {
        match component {
            Component::Normal(value) => normalized.push(value),
            _ => {
                return Err(failure(
                    "package archive contains a forbidden path component",
                ));
            }
        }
    }
    Ok(normalized)
}

fn archive_component(component: Component<'_>) -> Result<&str> {
    match component {
        Component::Normal(value) => value
            .to_str()
            .ok_or_else(|| failure("crate archive member path is not UTF-8")),
        _ => Err(failure(
            "crate archive member contains a forbidden path component",
        )),
    }
}

fn validated_archive_relative_path(path: &Path) -> Result<String> {
    let mut normalized = String::new();
    for component in path.components() {
        let component = archive_component(component)?;
        if !normalized.is_empty() {
            normalized.push('/');
        }
        normalized.push_str(component);
    }
    Ok(normalized)
}

fn archive_member_path(path: &Path) -> Result<String> {
    let mut components = path.components();
    let package_root = components
        .next()
        .ok_or_else(|| failure("package archive contains an empty path"))?;
    archive_component(package_root)?;
    let mut normalized = String::new();
    for component in components {
        let component = archive_component(component)?;
        if !normalized.is_empty() {
            normalized.push('/');
        }
        normalized.push_str(component);
    }
    Ok(normalized)
}

fn validate_crate_readme(path: &Path, package: &str) -> Result<()> {
    let decoder = GzDecoder::new(File::open(path)?);
    let mut archive = tar::Archive::new(decoder);
    let mut documents = BTreeMap::new();
    let mut readme = None;
    for entry in archive.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let normalized = normalized_member_path(&entry.path()?)?;
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        if normalized == Path::new("Cargo.toml") {
            let manifest: toml::Value = toml::from_str(
                std::str::from_utf8(&bytes)
                    .map_err(|_| failure("normalized Cargo.toml is not UTF-8"))?,
            )?;
            readme = manifest
                .get("package")
                .and_then(|value| value.get("readme"))
                .and_then(toml::Value::as_str)
                .map(PathBuf::from);
        }
        documents.insert(normalized, bytes);
    }
    let readme = readme.ok_or_else(|| failure(format!("{package} has no normalized README")))?;
    documents
        .get(&readme)
        .ok_or_else(|| failure(format!("{package} normalized README is absent")))?;
    validate_markdown_documents(&documents)
}

fn canonical_crate_tree(path: &Path) -> Result<String> {
    let decoder = GzDecoder::new(File::open(path)?);
    let mut archive = tar::Archive::new(decoder);
    let mut members = BTreeMap::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let kind = entry.header().entry_type();
        if !kind.is_file() && !kind.is_dir() {
            return Err(failure("package archive contains a non-file member"));
        }
        let normalized = archive_member_path(&entry.path()?)?;
        if normalized.is_empty() {
            continue;
        }
        if matches!(
            normalized.as_str(),
            "Cargo.toml" | "Cargo.lock" | ".cargo_vcs_info.json"
        ) {
            continue;
        }
        let mode = entry.header().mode()?;
        let mut bytes = Vec::new();
        if kind.is_file() {
            entry.read_to_end(&mut bytes)?;
        }
        members.insert(normalized, (mode, bytes));
    }
    let mut hash = Sha256::new();
    for (path, (mode, bytes)) in members {
        hash.update(path.as_bytes());
        hash.update([0]);
        hash.update(mode.to_le_bytes());
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    Ok(hex::encode(hash.finalize()))
}

fn canonical_crate_identity(path: &Path) -> Result<CrateArchiveIdentity> {
    let decoder = GzDecoder::new(File::open(path)?);
    let mut archive = tar::Archive::new(decoder);
    let mut members = BTreeMap::new();
    let mut package_name = None;
    let mut package_version = None;
    let mut vcs_commit = None;
    let mut vcs_dirty = None;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let kind = entry.header().entry_type();
        if !kind.is_file() && !kind.is_dir() {
            return Err(failure("package archive contains a non-file member"));
        }
        let normalized = archive_member_path(&entry.path()?)?;
        if normalized.is_empty() {
            continue;
        }
        let mode = entry.header().mode()?;
        let mut bytes = Vec::new();
        if kind.is_file() {
            entry.read_to_end(&mut bytes)?;
        }
        if normalized == "Cargo.toml" {
            let manifest: toml::Value = toml::from_str(
                std::str::from_utf8(&bytes)
                    .map_err(|_| failure("normalized Cargo.toml is not UTF-8"))?,
            )?;
            let package = manifest
                .get("package")
                .and_then(toml::Value::as_table)
                .ok_or_else(|| failure("normalized Cargo.toml lacks [package]"))?;
            package_name = package
                .get("name")
                .and_then(toml::Value::as_str)
                .map(str::to_owned);
            package_version = package
                .get("version")
                .and_then(toml::Value::as_str)
                .map(str::to_owned);
            bytes = toml::to_string(&manifest)
                .map_err(|error| failure(format!("normalized Cargo.toml is invalid: {error}")))?
                .into_bytes();
        } else if normalized == ".cargo_vcs_info.json" {
            let value: serde_json::Value = serde_json::from_slice(&bytes)?;
            vcs_commit = value
                .get("git")
                .and_then(|git| git.get("sha1"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned);
            vcs_dirty = Some(
                value
                    .get("dirty")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
            );
            bytes = serde_json::to_vec(&value)?;
        }
        if members.insert(normalized, (mode, bytes)).is_some() {
            return Err(failure(
                "package archive contains duplicate normalized paths",
            ));
        }
    }
    let mut hash = Sha256::new();
    for (path, (mode, bytes)) in members {
        hash.update(path.as_bytes());
        hash.update([0]);
        hash.update(mode.to_le_bytes());
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    Ok(CrateArchiveIdentity {
        sha256: hex::encode(hash.finalize()),
        package_name: package_name
            .ok_or_else(|| failure("package archive lacks normalized package name"))?,
        package_version: package_version
            .ok_or_else(|| failure("package archive lacks normalized package version"))?,
        vcs_commit: vcs_commit
            .ok_or_else(|| failure("package archive lacks Cargo VCS commit provenance"))?,
        vcs_dirty: vcs_dirty
            .ok_or_else(|| failure("package archive lacks Cargo VCS dirty provenance"))?,
    })
}

fn canonical_source_tree(root: &Path, package: &str, inventory: &str) -> Result<String> {
    let metadata = metadata(root)?;
    let package = metadata
        .packages
        .iter()
        .find(|candidate| candidate.name.as_str() == package)
        .ok_or_else(|| failure("package metadata is absent"))?;
    let package_root = package
        .manifest_path
        .parent()
        .ok_or_else(|| failure("package manifest has no parent"))?;
    let mut members = BTreeMap::new();
    for item in inventory.lines().filter(|line| !line.is_empty()) {
        if matches!(item, "Cargo.toml" | "Cargo.lock" | ".cargo_vcs_info.json") {
            continue;
        }
        let relative_path = PathBuf::from(item);
        let relative = validated_archive_relative_path(&relative_path)?;
        let package_path = package_root.as_std_path().join(&relative_path);
        let source = if relative == "Cargo.toml.orig" {
            package.manifest_path.as_std_path().to_path_buf()
        } else if package_path.is_file() {
            package_path
        } else if let Some(source) = relocated_manifest_source(
            package_root.as_std_path(),
            &relative_path,
            [
                (
                    "README",
                    package.readme.as_ref().map(|path| path.as_std_path()),
                ),
                (
                    "license file",
                    package.license_file.as_ref().map(|path| path.as_std_path()),
                ),
            ],
        )? {
            source
        } else {
            return Err(failure(format!(
                "Cargo package inventory source is missing: {relative:?}"
            )));
        };
        if !source.is_file() {
            return Err(failure(format!(
                "Cargo package inventory source is missing: {relative:?}"
            )));
        }
        members.insert(relative, fs::read(source)?);
    }
    let mut hash = Sha256::new();
    for (path, bytes) in members {
        hash.update(path.as_bytes());
        hash.update([0]);
        hash.update(0o644_u32.to_le_bytes());
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    Ok(hex::encode(hash.finalize()))
}

fn relocated_manifest_source<const N: usize>(
    package_root: &Path,
    inventory_path: &Path,
    declared_sources: [(&str, Option<&Path>); N],
) -> Result<Option<PathBuf>> {
    let mut resolved = None;
    for (description, declared_source) in declared_sources {
        let Some(declared_source) = declared_source else {
            continue;
        };
        let filename = declared_source.file_name().ok_or_else(|| {
            failure(format!(
                "package {description} path has no filename: {declared_source:?}"
            ))
        })?;
        if inventory_path != Path::new(filename) {
            continue;
        }
        let source = package_root.join(declared_source);
        if !source.is_file() {
            return Err(failure(format!(
                "package {description} source is missing: {declared_source:?}"
            )));
        }
        if resolved.replace(source).is_some() {
            return Err(failure(format!(
                "package metadata has ambiguous sources for {inventory_path:?}"
            )));
        }
    }
    Ok(resolved)
}

fn package_crate(
    root: &Path,
    stable: &str,
    package: &str,
    version: &Version,
    source_commit: &str,
    maximum_package_bytes: u64,
    default_cargo_binaries: &BTreeSet<String>,
) -> Result<CrateRecord> {
    let inventory_arguments = vec![
        OsString::from("package"),
        OsString::from("--locked"),
        OsString::from("--package"),
        OsString::from(package),
        OsString::from("--list"),
    ];
    let inventory = rustup_cargo(root, stable, inventory_arguments, RELEASE_DEADLINE).run()?;
    let inventory = utf8(inventory, "Cargo package inventory")?;
    let canonical_tree_sha256 = canonical_source_tree(root, package, &inventory)?;
    let filename = format!("{package}-{version}.crate");
    let archive = package_archive_directory(root).join(filename);
    if !archive.is_file() {
        return Err(failure(format!(
            "Cargo did not produce package archive for {package}"
        )));
    }
    if fs::metadata(&archive)?.len() > maximum_package_bytes {
        return Err(failure(format!(
            "package archive exceeds configured size policy: {package}"
        )));
    }
    let archive_tree = canonical_crate_tree(&archive)?;
    if archive_tree != canonical_tree_sha256 {
        return Err(failure(format!(
            "Cargo archive content differs from package inventory for {package}"
        )));
    }
    let archive_identity = canonical_crate_identity(&archive)?;
    if archive_identity.package_name != package
        || archive_identity.package_version != version.to_string()
        || archive_identity.vcs_commit != source_commit
        || archive_identity.vcs_dirty
    {
        return Err(failure(format!(
            "Cargo-normalized package identity/provenance differs for {package}"
        )));
    }
    validate_crate_readme(&archive, package)?;
    if package == "memcordon" {
        validate_reviewed_memcordon_distribution(&archive, default_cargo_binaries)?;
    }
    let archive_sha256 = sha256_file(&archive)?;
    Ok(CrateRecord {
        name: package.to_owned(),
        version: version.to_string(),
        archive_sha256,
        canonical_tree_sha256,
        canonical_identity_sha256: archive_identity.sha256,
        vcs_commit: archive_identity.vcs_commit,
    })
}

pub(crate) fn create_package_archives(
    root: &Path,
    stable: &str,
    packages: &[String],
) -> Result<()> {
    let mut arguments = vec![
        OsString::from("package"),
        OsString::from("--locked"),
        OsString::from("--no-verify"),
    ];
    for package in packages {
        arguments.push(OsString::from("--package"));
        arguments.push(OsString::from(package));
    }
    rustup_cargo(root, stable, arguments, RELEASE_DEADLINE).run()?;
    Ok(())
}

pub(crate) fn package_archive_directory(root: &Path) -> PathBuf {
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target"));
    if target.is_absolute() {
        target.join("package")
    } else {
        root.join(target).join("package")
    }
}

pub(crate) fn extract_crate_source(archive_path: &Path, destination: &Path) -> Result<()> {
    let decoder = GzDecoder::new(File::open(archive_path)?);
    let mut archive = tar::Archive::new(decoder);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let relative = normalized_member_path(&entry.path()?)?;
        let output = destination.join(relative);
        if entry.header().entry_type().is_dir() {
            fs::create_dir_all(&output)?;
        } else if entry.header().entry_type().is_file() {
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut file = File::create(output)?;
            std::io::copy(&mut entry, &mut file)?;
        } else {
            return Err(failure("crate archive contains a non-file member"));
        }
    }
    Ok(())
}

fn validate_agent_package_inspection(
    output: &[u8],
    expected_version: &str,
    expected_source_commit: &str,
) -> Result<()> {
    let inspection: AgentPackageInspection = serde_json::from_slice(output)?;
    let sha256_text_length = sha256_bytes(&[]).len();
    let valid_digest = |digest: &String| {
        digest.len() == sha256_text_length
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    let platform_valid = match &inspection.platform {
        AgentPackagePlatform::LinuxSystemd {
            control_service_sha256,
            control_socket_sha256,
            launcher_service_sha256,
            launcher_socket_sha256,
            tmpfiles_sha256,
        } => {
            inspection.provider_protocol == 2
                && inspection.mechanism == "linux-pid-namespace-cgroup-v2"
                && [
                    control_service_sha256,
                    control_socket_sha256,
                    launcher_service_sha256,
                    launcher_socket_sha256,
                    tmpfiles_sha256,
                ]
                .into_iter()
                .all(valid_digest)
        }
        AgentPackagePlatform::WindowsService {
            control_service_name,
            launcher_service_name,
            session_broker_service_name,
            guardian_slot_count,
            control_service_config_sha256,
            launcher_service_config_sha256,
            session_broker_service_config_sha256,
            guardian_slot_config_sha256,
            control_pipe,
            launcher_pipe,
            session_broker_pipe,
            guardian_pipe_prefix,
            binary_install_path,
            target_desktop_bootstrap_install_path,
            target_desktop_bootstrap_sha256,
            target_desktop_bootstrap_runtime,
            target_desktop_bootstrap_normal_imports,
            target_desktop_bootstrap_delayed_imports,
            target_desktop_bootstrap_loader_contract_sha256,
            session_broker_install_path,
            session_broker_sha256,
            state_root,
            control_service_sid_type,
            launcher_service_sid_type,
            session_broker_service_sid_type,
            guardian_slot_service_sid_type,
            control_required_privileges,
            launcher_required_privileges,
            session_broker_required_privileges,
            guardian_slot_required_privileges,
            control_pipe_security_sha256,
            launcher_pipe_security_sha256,
            session_broker_service_security_sha256,
            session_broker_pipe_security_sha256,
            guardian_pipe_security_contract_sha256,
            install_directory_security_sha256,
            state_directory_security_sha256,
        } => {
            let loader_imports = memcordon_core::WindowsPeImports {
                machine: 0,
                normal: target_desktop_bootstrap_normal_imports.clone(),
                delayed: target_desktop_bootstrap_delayed_imports.clone(),
            };
            inspection.provider_protocol == 1
                && inspection.mechanism == "windows-job-object-v2"
                && control_service_name == "MemCordonSealedControl"
                && launcher_service_name == "MemCordonSealedLauncher"
                && session_broker_service_name == "MemCordonSealedSessionBroker"
                && *guardian_slot_count == memcordon_core::WINDOWS_GUARDIAN_SLOT_COUNT
                && control_pipe == r"\\.\pipe\memcordon-sealed-agent-v1"
                && launcher_pipe == r"\\.\pipe\memcordon-sealed-launcher-v1"
                && session_broker_pipe == r"\\.\pipe\memcordon-sealed-session-broker-v1"
                && guardian_pipe_prefix == memcordon_core::WINDOWS_GUARDIAN_PIPE_PREFIX
                && !binary_install_path.is_empty()
                && !target_desktop_bootstrap_install_path.is_empty()
                && target_desktop_bootstrap_sha256.len() == Sha256::output_size() * 2
                && target_desktop_bootstrap_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
                && *target_desktop_bootstrap_runtime
                    == TargetDesktopBootstrapRuntime::StaticVcRuntimeOsUcrt
                && !target_desktop_bootstrap_normal_imports.is_empty()
                && target_desktop_bootstrap_normal_imports.is_sorted()
                && target_desktop_bootstrap_delayed_imports.is_sorted()
                && memcordon_core::verify_target_desktop_bootstrap_imports(&loader_imports).is_ok()
                && valid_digest(target_desktop_bootstrap_loader_contract_sha256)
                && !session_broker_install_path.is_empty()
                && valid_digest(session_broker_sha256)
                && !state_root.is_empty()
                && control_service_sid_type == "restricted"
                && launcher_service_sid_type == "restricted"
                && session_broker_service_sid_type == "unrestricted"
                && guardian_slot_service_sid_type == "restricted"
                && control_required_privileges
                    == memcordon_core::WINDOWS_CONTROL_REQUIRED_PRIVILEGES
                && launcher_required_privileges
                    == memcordon_core::WINDOWS_LAUNCHER_REQUIRED_PRIVILEGES
                && session_broker_required_privileges
                    == memcordon_core::WINDOWS_SESSION_BROKER_REQUIRED_PRIVILEGES
                && guardian_slot_required_privileges.is_empty()
                && [
                    control_service_config_sha256,
                    launcher_service_config_sha256,
                    session_broker_service_config_sha256,
                    guardian_slot_config_sha256,
                    control_pipe_security_sha256,
                    launcher_pipe_security_sha256,
                    session_broker_service_security_sha256,
                    session_broker_pipe_security_sha256,
                    guardian_pipe_security_contract_sha256,
                    install_directory_security_sha256,
                    state_directory_security_sha256,
                ]
                .into_iter()
                .all(valid_digest)
        }
    };
    let windows = matches!(
        &inspection.platform,
        AgentPackagePlatform::WindowsService { .. }
    );
    let expected_protocols = if windows {
        memcordon_core::runtime_manifest::NativeProviderProtocols::Windows {
            provider_contract: 3,
            public_wire: 2,
            private_wire: 2,
        }
    } else {
        memcordon_core::runtime_manifest::NativeProviderProtocols::Linux {
            provider_contract: 3,
            launch_wire: 3,
        }
    };
    if inspection.schema_version != 5
        || inspection.native_protocols != expected_protocols
        || inspection.runtime_manifest_schema != 2
        || inspection.workload_contract_schema != 1
        || inspection.profile_catalog_sha256
            != memcordon_core::runtime_manifest::baseline_catalog_digest(windows)
        || inspection.version != expected_version
        || inspection.source_commit != expected_source_commit
        || inspection.execution_report_schema != memcordon_core::EXECUTION_REPORT_SCHEMA_VERSION
        || inspection.plan_report_schema != memcordon_core::PLAN_REPORT_SCHEMA_VERSION
        || inspection.doctor_report_schema != memcordon_core::DOCTOR_REPORT_SCHEMA_VERSION
        || !inspection.compiled_metadata_valid
        || !valid_digest(&inspection.executable_sha256)
        || !platform_valid
    {
        return Err(failure(
            "sealed agent package inspection differs from the release identity",
        ));
    }
    Ok(())
}

fn verify_component_version(
    executable: &Path,
    component_name: &str,
    expected_version: &str,
    root: &Path,
) -> Result<()> {
    let output = CommandSpec::new(executable, root, Duration::from_secs(30))
        .arg("--version")
        .run()?;
    let expected = format!("{component_name} {expected_version}\n");
    if output != expected.as_bytes() {
        return Err(failure(format!(
            "{component_name} reports a version other than the release identity"
        )));
    }
    Ok(())
}

fn installed_binary_name(name: &str) -> OsString {
    let mut binary = OsString::from(name);
    if cfg!(windows) {
        binary.push(".exe");
    }
    binary
}

fn smoke_packaged_memcordon_install(
    root: &Path,
    stable: &str,
    version: &Version,
    source_commit: &str,
    default_cargo_binaries: &BTreeSet<String>,
) -> Result<()> {
    let temporary = TempDir::new()?;
    let sources = temporary.path().join("sources");
    let core = sources.join("memcordon-core");
    let platform = sources.join("memcordon-platform");
    let launch_core = sources.join("memcordon-windows-launch-core");
    let cli = sources.join("memcordon");
    for (package, destination) in [
        ("memcordon-core", &core),
        ("memcordon-platform", &platform),
        ("memcordon-windows-launch-core", &launch_core),
        ("memcordon", &cli),
    ] {
        let archive = package_archive_directory(root).join(format!("{package}-{version}.crate"));
        extract_crate_source(&archive, destination)?;
    }
    let cargo_configuration = temporary.path().join(".cargo");
    fs::create_dir_all(&cargo_configuration)?;
    let mut core_specification = toml::Table::new();
    core_specification.insert(
        "path".to_owned(),
        toml::Value::String(core.to_string_lossy().into_owned()),
    );
    let mut platform_specification = toml::Table::new();
    platform_specification.insert(
        "path".to_owned(),
        toml::Value::String(platform.to_string_lossy().into_owned()),
    );
    let mut launch_core_specification = toml::Table::new();
    launch_core_specification.insert(
        "path".to_owned(),
        toml::Value::String(launch_core.to_string_lossy().into_owned()),
    );
    let mut crates_io = toml::Table::new();
    crates_io.insert(
        "memcordon-core".to_owned(),
        toml::Value::Table(core_specification),
    );
    crates_io.insert(
        "memcordon-platform".to_owned(),
        toml::Value::Table(platform_specification),
    );
    crates_io.insert(
        "memcordon-windows-launch-core".to_owned(),
        toml::Value::Table(launch_core_specification),
    );
    let mut patch_table = toml::Table::new();
    patch_table.insert("crates-io".to_owned(), toml::Value::Table(crates_io));
    let mut configuration = toml::Table::new();
    configuration.insert("patch".to_owned(), toml::Value::Table(patch_table));
    fs::write(
        cargo_configuration.join("config.toml"),
        toml::to_string(&toml::Value::Table(configuration)).map_err(|error| {
            failure(format!(
                "packaged-source Cargo configuration serialization failed: {error}"
            ))
        })?,
    )?;
    let install_root = temporary.path().join("install");
    rustup_cargo(
        temporary.path(),
        stable,
        [
            OsString::from("install"),
            OsString::from("--locked"),
            OsString::from("--root"),
            install_root.clone().into_os_string(),
            OsString::from("--path"),
            cli.into_os_string(),
        ],
        RELEASE_DEADLINE,
    )
    .run()?;
    let binaries = install_root.join("bin");
    let cli_name = installed_binary_name("memcordon");
    let agent_name = installed_binary_name("memcordon-sealed-agent");
    let bootstrap_name = installed_binary_name("memcordon-target-desktop-bootstrap");
    let broker_name = installed_binary_name("memcordon-session-broker");
    let actual = fs::read_dir(&binaries)?
        .map(|entry| entry.map(|entry| entry.file_name()).map_err(CiError::from))
        .collect::<Result<BTreeSet<_>>>()?;
    let expected = cargo_install_inventory(default_cargo_binaries);
    if actual != expected {
        return Err(failure(format!(
            "packaged-source Cargo install binary inventory differs: expected={expected:?} actual={actual:?}"
        )));
    }
    let installed_cli = binaries.join(cli_name);
    let installed_agent = binaries.join(agent_name);
    let expected_version = version.to_string();
    verify_component_version(&installed_cli, "memcordon", &expected_version, root)?;
    verify_component_version(
        &installed_agent,
        "memcordon-sealed-agent",
        &expected_version,
        root,
    )?;
    let installed_bootstrap = binaries.join(bootstrap_name);
    verify_component_version(
        &installed_bootstrap,
        "memcordon-target-desktop-bootstrap",
        &expected_version,
        root,
    )?;
    let installed_broker = binaries.join(broker_name);
    verify_component_version(
        &installed_broker,
        "memcordon-session-broker",
        &expected_version,
        root,
    )?;
    let inspection = CommandSpec::new(&installed_agent, root, Duration::from_secs(30))
        .args(["package", "inspect", "--json"])
        .run()?;
    validate_agent_package_inspection(&inspection, &expected_version, source_commit)?;
    #[cfg(target_os = "linux")]
    {
        let mut smoke = NativeSmokeReport {
            cli_version: true,
            doctor: true,
            agent_version: Some(true),
            agent_inspection: Some(true),
            provider_install: None,
            provider_verify: None,
            provider_qualification: None,
            sealed_execution: None,
            provider_uninstall: None,
        };
        smoke_linux_provider(&installed_cli, &installed_agent, root, &mut smoke)?;
    }
    #[cfg(target_os = "windows")]
    {
        let mut smoke = NativeSmokeReport {
            cli_version: true,
            doctor: true,
            agent_version: Some(true),
            agent_inspection: Some(true),
            provider_install: None,
            provider_verify: None,
            provider_qualification: None,
            sealed_execution: None,
            provider_uninstall: None,
        };
        smoke_windows_provider(&installed_cli, &installed_agent, root, &mut smoke)?;
    }
    Ok(())
}

fn host_target(targets: &[AssetTarget]) -> Result<&AssetTarget> {
    let wanted = config::release_target_id_for_host(std::env::consts::OS, std::env::consts::ARCH)?;
    targets
        .iter()
        .find(|target| target.id == wanted)
        .ok_or_else(|| failure("host release target is absent from configuration"))
}

fn archive_name(version: &Version, target: &AssetTarget) -> String {
    let suffix = if target.archive == "zip" {
        "zip"
    } else {
        "tar.gz"
    };
    format!("memcordon-v{version}-{}.{suffix}", target.rust_target)
}

fn append_tar_file(
    builder: &mut tar::Builder<GzEncoder<File>>,
    source: &Path,
    archive_path: &Path,
    mode: u32,
) -> Result<()> {
    let bytes = fs::read(source)?;
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    builder.append_data(&mut header, archive_path, bytes.as_slice())?;
    Ok(())
}

struct BuiltArchive {
    path: PathBuf,
    runtime_manifest_sha256: String,
    components: Vec<RuntimeComponentRecord>,
}

fn built_executable_path(
    root: &Path,
    target: &AssetTarget,
    component: &config::AssetExecutable,
) -> PathBuf {
    let mut binary = PathBuf::from(&component.binary);
    if target.archive == "zip" {
        binary.set_extension("exe");
    }
    root.join("target")
        .join("ci")
        .join("release-native")
        .join(&target.rust_target)
        .join("release")
        .join(binary)
}

#[derive(Debug)]
struct BuiltExecutable<'a> {
    component: &'a config::AssetExecutable,
    path: PathBuf,
}

fn built_executable_inventory<'a>(
    root: &Path,
    target: &'a AssetTarget,
) -> Vec<BuiltExecutable<'a>> {
    target
        .executable
        .iter()
        .map(|component| BuiltExecutable {
            component,
            path: built_executable_path(root, target, component),
        })
        .collect()
}

fn require_built_executable_inventory<'a>(
    root: &Path,
    target: &'a AssetTarget,
) -> Result<Vec<BuiltExecutable<'a>>> {
    let inventory = built_executable_inventory(root, target);
    for artifact in &inventory {
        match fs::symlink_metadata(&artifact.path) {
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => {
                return Err(failure(format!(
                    "configured native executable is not a regular file: {} ({})",
                    artifact.component.binary,
                    artifact.path.display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(failure(format!(
                    "configured native executable was not built: {} ({})",
                    artifact.component.binary,
                    artifact.path.display()
                )));
            }
            Err(error) => {
                return Err(failure(format!(
                    "configured native executable state failed: {} ({}): {error}",
                    artifact.component.binary,
                    artifact.path.display()
                )));
            }
        }
    }
    Ok(inventory)
}

fn runtime_component_id(role: RuntimeComponentRole) -> &'static str {
    match role {
        RuntimeComponentRole::PublicCli => "public-cli",
        RuntimeComponentRole::SealedAgent => "sealed-agent",
        RuntimeComponentRole::DesktopBootstrap => "target-desktop-bootstrap",
        RuntimeComponentRole::SessionBroker => "session-broker",
    }
}

fn runtime_components(root: &Path, target: &AssetTarget) -> Result<Vec<RuntimeComponentRecord>> {
    target
        .executable
        .iter()
        .map(|component| {
            let source = built_executable_path(root, target, component);
            Ok(RuntimeComponentRecord {
                id: runtime_component_id(component.role).to_owned(),
                path: component.archive_path.clone(),
                role: component.role,
                size: fs::metadata(&source)?.len(),
                mode: component.mode,
                sha256: sha256_file(&source)?,
            })
        })
        .collect()
}

fn runtime_manifest(
    identity: &ReleaseIdentity,
    target: &AssetTarget,
    components: Vec<RuntimeComponentRecord>,
) -> RuntimeManifestV2 {
    let sealed = match (target.sealed, target.rust_target.contains("windows")) {
        (SealedAssetPolicy::Included, true) => SealedRuntimeV2::Included {
            diagnostic_qualification:
                memcordon_core::runtime_manifest::diagnostic_qualification_reference(
                    &target.rust_target,
                ),
            profile_qualification: Box::new(
                memcordon_core::runtime_manifest::profile_qualification_reference(
                    &target.rust_target,
                ),
            ),
            agent_component: "sealed-agent".to_owned(),
            native_protocols: memcordon_core::runtime_manifest::NativeProviderProtocols::Windows {
                provider_contract: 3,
                public_wire: 2,
                private_wire: 2,
            },
            workload_contract_schema: 1,
            profile_catalog_sha256: memcordon_core::runtime_manifest::baseline_catalog_digest(true),
            profiles: vec!["windows-host-network-external-v1".into()],
            mechanism: "windows-job-object-v2".to_owned(),
            execution_report_schema: memcordon_core::EXECUTION_REPORT_SCHEMA_VERSION,
            plan_report_schema: memcordon_core::PLAN_REPORT_SCHEMA_VERSION,
            doctor_report_schema: memcordon_core::DOCTOR_REPORT_SCHEMA_VERSION,
            qualification_schema: memcordon_core::WINDOWS_QUALIFICATION_SCHEMA_VERSION,
        },
        (SealedAssetPolicy::Included, false) => SealedRuntimeV2::Included {
            diagnostic_qualification: None,
            profile_qualification: Box::new(
                memcordon_core::runtime_manifest::profile_qualification_reference(
                    &target.rust_target,
                ),
            ),
            agent_component: "sealed-agent".to_owned(),
            native_protocols: memcordon_core::runtime_manifest::NativeProviderProtocols::Linux {
                provider_contract: 3,
                launch_wire: 3,
            },
            workload_contract_schema: 1,
            profile_catalog_sha256: memcordon_core::runtime_manifest::baseline_catalog_digest(
                false,
            ),
            profiles: vec!["linux-unix-create-v1".into()],
            mechanism: "linux-pid-namespace-cgroup-v2".to_owned(),
            execution_report_schema: memcordon_core::EXECUTION_REPORT_SCHEMA_VERSION,
            plan_report_schema: memcordon_core::PLAN_REPORT_SCHEMA_VERSION,
            doctor_report_schema: memcordon_core::DOCTOR_REPORT_SCHEMA_VERSION,
            qualification_schema: 3,
        },
        (SealedAssetPolicy::NotApplicable, _) => SealedRuntimeV2::NotApplicable {
            reason: "the platform has no qualified packaged sealed provider".to_owned(),
        },
    };
    RuntimeManifestV2 {
        schema_version: 2,
        project: "memcordon".to_owned(),
        version: identity.version.to_string(),
        source_commit: identity.commit.clone(),
        target: target.rust_target.clone(),
        components,
        sealed,
    }
}

fn build_archive(
    root: &Path,
    identity: &ReleaseIdentity,
    target: &AssetTarget,
) -> Result<BuiltArchive> {
    let output = root.join("target").join("ci").join("release-output");
    fs::create_dir_all(&output)?;
    let path = output.join(archive_name(&identity.version, target));
    let components = runtime_components(root, target)?;
    let manifest = runtime_manifest(identity, target, components.clone());
    let manifest_path = output.join(format!("runtime-manifest-{}.json", target.id));
    write_json(&manifest_path, &manifest)?;
    let runtime_manifest_sha256 = sha256_file(&manifest_path)?;
    let top = PathBuf::from(format!(
        "memcordon-v{}-{}",
        identity.version, target.rust_target
    ));
    let mut entries = target
        .executable
        .iter()
        .map(|component| {
            (
                built_executable_path(root, target, component),
                PathBuf::from(&component.archive_path),
                component.mode,
            )
        })
        .collect::<Vec<_>>();
    entries.push((manifest_path, PathBuf::from(RUNTIME_MANIFEST), 0o644));
    entries.extend(NATIVE_ARCHIVE_STATIC_PATHS.iter().map(|relative| {
        let relative = PathBuf::from(*relative);
        (root.join(&relative), relative, 0o644)
    }));
    entries.sort_by_key(|entry| top.join(&entry.1));
    if target.archive == "zip" {
        let file = File::create(&path)?;
        let mut writer = zip::ZipWriter::new(file);
        for (source, relative, mode) in entries {
            let name = top.join(relative).to_string_lossy().replace('\\', "/");
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated)
                .system(zip::System::Unix)
                .last_modified_time(zip::DateTime::default())
                .unix_permissions(mode);
            writer.start_file(name, options)?;
            writer.write_all(&fs::read(source)?)?;
        }
        writer.finish()?;
    } else {
        let encoder = GzEncoder::new(File::create(&path)?, Compression::best());
        let mut builder = tar::Builder::new(encoder);
        for (source, relative, mode) in entries {
            append_tar_file(&mut builder, &source, &top.join(relative), mode)?;
        }
        builder.finish()?;
        let encoder = builder.into_inner()?;
        encoder.finish()?;
    }
    Ok(BuiltArchive {
        path,
        runtime_manifest_sha256,
        components,
    })
}

fn safe_archive_path(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(failure("release archive contains an unsafe path"));
    }
    Ok(path.to_path_buf())
}

fn archive_member_inventory_name(path: &Path) -> Result<String> {
    let mut name = String::new();
    for component in path.components() {
        let Component::Normal(value) = component else {
            return Err(failure(
                "archive member inventory path is not a normal relative path",
            ));
        };
        let value = value
            .to_str()
            .ok_or_else(|| failure("archive member inventory path is not UTF-8"))?;
        if !name.is_empty() {
            name.push('/');
        }
        name.push_str(value);
    }
    if name.is_empty() {
        return Err(failure("archive member inventory path is empty"));
    }
    Ok(name)
}

fn read_archive_member(
    extraction_root: &Path,
    member: &str,
    relative: &Path,
    operation: &str,
) -> Result<Vec<u8>> {
    let path = extraction_root.join(relative);
    fs::read(&path).map_err(|error| {
        failure(format!(
            "release archive member read failed: operation={operation} member={member:?} path={path:?}: {error}"
        ))
    })
}

struct ArchiveInspection {
    runtime_manifest_sha256: String,
    components: Vec<RuntimeComponentRecord>,
    archive_member_inventory_sha256: String,
    smoke: NativeSmokeReport,
}

fn inspect_extract_and_smoke(
    root: &Path,
    archive_path: &Path,
    target: &AssetTarget,
    identity: &ReleaseIdentity,
    execute: bool,
) -> Result<ArchiveInspection> {
    let temporary = TempDir::new()?;
    let mut extracted_files = BTreeMap::<String, PathBuf>::new();
    let mut archive_modes = BTreeMap::<String, u32>::new();
    if target.archive == "zip" {
        let mut archive = zip::ZipArchive::new(File::open(archive_path)?)?;
        for index in 0..archive.len() {
            let mut entry = archive.by_index(index)?;
            let enclosed = entry
                .enclosed_name()
                .ok_or_else(|| failure("ZIP archive member escapes extraction root"))?;
            let relative = safe_archive_path(&enclosed)?;
            let member = archive_member_inventory_name(&relative)?;
            let destination = temporary.path().join(&relative);
            if entry.is_dir() {
                fs::create_dir_all(&destination)?;
            } else if entry.is_file() {
                if let Some(parent) = destination.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut output = File::create(&destination)?;
                std::io::copy(&mut entry, &mut output)?;
                archive_modes.insert(
                    member.clone(),
                    entry
                        .unix_mode()
                        .ok_or_else(|| failure("ZIP archive member has no Unix mode"))?
                        & 0o7777,
                );
                extracted_files.insert(member, relative);
            } else {
                return Err(failure("ZIP archive contains a non-file member"));
            }
        }
    } else {
        let decoder = GzDecoder::new(File::open(archive_path)?);
        let mut archive = tar::Archive::new(decoder);
        for entry in archive.entries()? {
            let mut entry = entry?;
            let relative = safe_archive_path(&entry.path()?)?;
            let member = archive_member_inventory_name(&relative)?;
            let destination = temporary.path().join(&relative);
            if entry.header().entry_type().is_dir() {
                fs::create_dir_all(&destination)?;
            } else if entry.header().entry_type().is_file() {
                if let Some(parent) = destination.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut output = File::create(&destination)?;
                std::io::copy(&mut entry, &mut output)?;
                archive_modes.insert(member.clone(), entry.header().mode()? & 0o7777);
                extracted_files.insert(member, relative);
            } else {
                return Err(failure("tar archive contains a non-file member"));
            }
        }
    }
    let top = PathBuf::from(format!(
        "memcordon-v{}-{}",
        identity.version, target.rust_target
    ));
    let mut expected = BTreeSet::<String>::new();
    for component in &target.executable {
        expected.insert(archive_member_inventory_name(
            &top.join(&component.archive_path),
        )?);
    }
    expected.insert(archive_member_inventory_name(&top.join(RUNTIME_MANIFEST))?);
    for relative in NATIVE_ARCHIVE_STATIC_PATHS {
        expected.insert(archive_member_inventory_name(&top.join(relative))?);
    }
    let actual_members = extracted_files.keys().cloned().collect::<BTreeSet<_>>();
    if actual_members != expected {
        return Err(failure(format!(
            "release archive member set differs: expected={expected:?} actual={actual_members:?}"
        )));
    }
    for component in &target.executable {
        let archive_path = archive_member_inventory_name(&top.join(&component.archive_path))?;
        if archive_modes.get(&archive_path) != Some(&component.mode) {
            return Err(failure(format!(
                "runtime component mode differs: {}",
                component.archive_path
            )));
        }
    }
    let manifest_path = temporary.path().join(&top).join(RUNTIME_MANIFEST);
    let manifest_member = archive_member_inventory_name(&top.join(RUNTIME_MANIFEST))?;
    if archive_modes.get(&manifest_member) != Some(&0o644) {
        return Err(failure("runtime manifest archive mode differs"));
    }
    let manifest_bytes = fs::read(&manifest_path)?;
    if !manifest_bytes.ends_with(b"\n") {
        return Err(failure("runtime manifest is not newline terminated"));
    }
    let manifest = RuntimeManifestV2::parse(&manifest_bytes).map_err(failure)?;
    let mut components = Vec::new();
    for configured in &target.executable {
        let path = temporary.path().join(&top).join(&configured.archive_path);
        components.push(RuntimeComponentRecord {
            id: runtime_component_id(configured.role).to_owned(),
            path: configured.archive_path.clone(),
            role: configured.role,
            size: fs::metadata(&path)?.len(),
            mode: configured.mode,
            sha256: sha256_file(&path)?,
        });
    }
    if manifest != runtime_manifest(identity, target, components.clone()) {
        return Err(failure(
            "runtime manifest identity or component inventory differs",
        ));
    }
    let mut documents = BTreeMap::new();
    for (member, relative) in &extracted_files {
        documents.insert(
            relative.clone(),
            read_archive_member(temporary.path(), member, relative, "document validation")?,
        );
    }
    validate_markdown_documents(&documents)?;
    if let Some(bootstrap) = target
        .executable
        .iter()
        .find(|component| component.role == RuntimeComponentRole::DesktopBootstrap)
    {
        let image = temporary.path().join(&top).join(&bootstrap.archive_path);
        memcordon_core::verify_target_desktop_bootstrap_pe(&fs::read(image)?).map_err(failure)?;
    }
    if let Some(broker) = target
        .executable
        .iter()
        .find(|component| component.role == RuntimeComponentRole::SessionBroker)
    {
        let image = temporary.path().join(&top).join(&broker.archive_path);
        memcordon_core::verify_session_broker_pe(&fs::read(image)?).map_err(failure)?;
    }
    let public = target
        .executable
        .iter()
        .find(|component| component.role == RuntimeComponentRole::PublicCli)
        .ok_or_else(|| failure("runtime archive has no public CLI component"))?;
    let executable = temporary.path().join(&top).join(&public.archive_path);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&executable)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&executable, permissions)?;
    }
    let mut smoke = NativeSmokeReport {
        cli_version: false,
        doctor: false,
        agent_version: None,
        agent_inspection: None,
        provider_install: None,
        provider_verify: None,
        provider_qualification: None,
        sealed_execution: None,
        provider_uninstall: None,
    };
    if execute {
        let expected_version = identity.version.to_string();
        verify_component_version(&executable, "memcordon", &expected_version, root)?;
        smoke.cli_version = true;
        CommandSpec::new(&executable, root, Duration::from_secs(30))
            .args(["doctor", "--json"])
            .run()?;
        smoke.doctor = true;
        if let Some(agent) = target
            .executable
            .iter()
            .find(|component| component.role == RuntimeComponentRole::SealedAgent)
        {
            let agent_executable = temporary.path().join(&top).join(&agent.archive_path);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut permissions = fs::metadata(&agent_executable)?.permissions();
                permissions.set_mode(agent.mode);
                fs::set_permissions(&agent_executable, permissions)?;
            }
            verify_component_version(
                &agent_executable,
                "memcordon-sealed-agent",
                &expected_version,
                root,
            )?;
            smoke.agent_version = Some(true);
            let output = CommandSpec::new(&agent_executable, root, Duration::from_secs(30))
                .args(["package", "inspect", "--json"])
                .run()?;
            validate_agent_package_inspection(&output, &expected_version, &identity.commit)?;
            smoke.agent_inspection = Some(true);
            #[cfg(target_os = "linux")]
            smoke_linux_provider(&executable, &agent_executable, root, &mut smoke)?;
            #[cfg(target_os = "windows")]
            smoke_windows_provider(&executable, &agent_executable, root, &mut smoke)?;
        }
    }
    let mut inventory = Sha256::new();
    for (member, relative) in &extracted_files {
        inventory.update(member.as_bytes());
        inventory.update([0]);
        inventory.update(
            archive_modes
                .get(member)
                .ok_or_else(|| failure("archive member mode is missing"))?
                .to_le_bytes(),
        );
        let bytes = read_archive_member(temporary.path(), member, relative, "inventory hashing")?;
        inventory.update(sha256_bytes(&bytes).as_bytes());
    }
    Ok(ArchiveInspection {
        runtime_manifest_sha256: sha256_bytes(&manifest_bytes),
        components,
        archive_member_inventory_sha256: hex::encode(inventory.finalize()),
        smoke,
    })
}

#[cfg(target_os = "windows")]
fn smoke_windows_provider(
    cli: &Path,
    agent: &Path,
    root: &Path,
    smoke: &mut NativeSmokeReport,
) -> Result<()> {
    let agent_command = |arguments: &[&str]| {
        CommandSpec::new(agent, root, RELEASE_DEADLINE)
            .args(arguments.iter().copied())
            .run()
            .map(|_| ())
    };
    let primary: Result<()> = (|| {
        agent_command(&["package", "install", "--ephemeral-ci"])?;
        smoke.provider_install = Some(true);
        agent_command(&["package", "verify", "--json"])?;
        smoke.provider_verify = Some(true);
        agent_command(&["qualify"])?;
        smoke.provider_qualification = Some(true);
        CommandSpec::new(cli, root, RELEASE_DEADLINE)
            .args(["doctor", "--require", "sealed"])
            .run()?;
        CommandSpec::new(cli, root, RELEASE_DEADLINE)
            .args([
                OsString::from("--sealed"),
                OsString::from("--"),
                agent.as_os_str().to_os_string(),
                OsString::from("--version"),
            ])
            .run()?;
        smoke.sealed_execution = Some(true);
        Ok(())
    })();
    let uninstall = agent_command(&["package", "uninstall", "--ephemeral-ci"])
        .and_then(|()| {
            let output = CommandSpec::new(agent, root, RELEASE_DEADLINE)
                .arg("windows-provider-state-absent")
                .run()?;
            if output
                .strip_suffix(b"\n")
                .and_then(|value| value.strip_suffix(b"\r").or(Some(value)))
                == Some(b"true")
            {
                Ok(())
            } else {
                Err(failure(format!(
                    "Windows native absence probe did not report true: {:?}",
                    String::from_utf8_lossy(&output)
                )))
            }
        })
        .and_then(|()| verify_windows_provider_absent());
    if uninstall.is_ok() {
        smoke.provider_uninstall = Some(true);
    }
    match (primary, uninstall) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(failure(format!(
            "Windows bundle provider smoke failed: primary={primary}; cleanup={cleanup}"
        ))),
    }
}

#[cfg(target_os = "windows")]
fn verify_windows_provider_absent() -> Result<()> {
    let program_files = std::env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"));
    let program_data = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    for path in [
        program_files.join("MemCordon"),
        program_data.join("MemCordon").join("sealed"),
    ] {
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(failure(format!(
                    "Windows provider uninstall left residual state at {}",
                    path.display()
                )));
            }
            Err(error) => {
                return Err(failure(format!(
                    "Windows provider uninstall state proof failed for {}: {error}",
                    path.display()
                )));
            }
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LinuxProviderFrontendStage {
    Doctor,
    SealedExecution,
}

#[cfg(any(target_os = "linux", test))]
fn linux_provider_frontend_arguments(
    identity: &FrontendIdentity,
    cli: &Path,
    stage: LinuxProviderFrontendStage,
) -> Result<Vec<OsString>> {
    let public_arguments = match stage {
        LinuxProviderFrontendStage::Doctor => vec![
            OsString::from("doctor"),
            OsString::from("--require"),
            OsString::from("sealed"),
        ],
        LinuxProviderFrontendStage::SealedExecution => vec![
            OsString::from("--sealed"),
            OsString::from("--"),
            OsString::from("/usr/bin/true"),
        ],
    };
    setpriv_sudo_arguments(identity, cli, &public_arguments)
}

#[cfg(target_os = "linux")]
fn smoke_linux_provider(
    cli: &Path,
    agent: &Path,
    root: &Path,
    smoke: &mut NativeSmokeReport,
) -> Result<()> {
    let privileged_agent = |arguments: &[&str]| {
        let mut command = vec![agent.as_os_str().to_os_string()];
        command.extend(arguments.iter().map(OsString::from));
        CommandSpec::new("sudo", root, RELEASE_DEADLINE)
            .args(command)
            .run()
            .map(|_| ())
    };
    let authorized_release_cli =
        |identity: &FrontendIdentity, stage: LinuxProviderFrontendStage, cli: &Path| {
            let sudo_arguments = linux_provider_frontend_arguments(identity, cli, stage)?;
            CommandSpec::new("/usr/bin/sudo", root, RELEASE_DEADLINE)
                .args(sudo_arguments)
                .run()
                .map(|_| ())
        };
    let primary: Result<()> = (|| {
        privileged_agent(&["package", "install", "--ephemeral-ci"])?;
        smoke.provider_install = Some(true);
        privileged_agent(&["package", "verify", "--json"])?;
        smoke.provider_verify = Some(true);
        privileged_agent(&["qualify"])?;
        smoke.provider_qualification = Some(true);
        let identity = frontend_identity(root, RELEASE_DEADLINE)?;
        authorized_release_cli(&identity, LinuxProviderFrontendStage::Doctor, cli)?;
        authorized_release_cli(&identity, LinuxProviderFrontendStage::SealedExecution, cli)?;
        smoke.sealed_execution = Some(true);
        Ok(())
    })();
    let uninstall = privileged_agent(&["package", "uninstall", "--ephemeral-ci"])
        .and_then(|()| verify_linux_provider_absent());
    if uninstall.is_ok() {
        smoke.provider_uninstall = Some(true);
    }
    match (primary, uninstall) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(failure(format!(
            "Linux bundle provider smoke failed: primary={primary}; cleanup={cleanup}"
        ))),
    }
}

#[cfg(target_os = "linux")]
fn verify_linux_provider_absent() -> Result<()> {
    verify_absent_paths(LINUX_PROVIDER_ABSENCE_PATHS.iter().map(Path::new))
}

#[cfg(any(target_os = "linux", test))]
const LINUX_PROVIDER_ABSENCE_PATHS: [&str; 12] = [
    "/usr/libexec/memcordon-sealed-agent",
    "/usr/lib/systemd/system/memcordon-sealed-agent.service",
    "/usr/lib/systemd/system/memcordon-sealed-agent.socket",
    "/usr/lib/systemd/system/memcordon-sealed-launcher.service",
    "/usr/lib/systemd/system/memcordon-sealed-launcher.socket",
    "/usr/lib/tmpfiles.d/memcordon.conf",
    "/run/memcordon/sealed-agent.sock",
    "/run/memcordon/sealed-launcher.sock",
    "/run/memcordon/sealed-package.lock",
    "/run/memcordon",
    "/var/lib/memcordon/sealed",
    "/sys/fs/cgroup/memcordon-sealed",
];

#[cfg(any(target_os = "linux", test))]
fn verify_absent_paths<'a>(paths: impl IntoIterator<Item = &'a Path>) -> Result<()> {
    for path in paths {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(failure(format!(
                    "Linux provider uninstall left residual state at {}",
                    path.display()
                )));
            }
            Err(error) => {
                return Err(failure(format!(
                    "Linux provider uninstall state proof failed for {}: {error}",
                    path.display()
                )));
            }
        }
    }
    Ok(())
}

pub fn native_asset(root: &Path) -> Result<()> {
    let identity = preflight(root)?;
    let release = config::release(root)?;
    let toolchains = config::toolchains(root)?;
    let target = host_target(&release.assets.target)?;
    rustup_cargo(
        root,
        &toolchains.stable,
        [
            "test",
            "--target-dir",
            "target/ci/release-native",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--release",
            "--locked",
        ],
        RELEASE_DEADLINE,
    )
    .run()?;
    let release_target = root.join("target").join("ci").join("release-native");
    let probe = capability::probe(root, &toolchains.stable, &release_target, RELEASE_DEADLINE)?;
    if capability::selected(&probe).is_some() {
        rustup_cargo(
            root,
            &toolchains.stable,
            [
                "test",
                "--target-dir",
                "target/ci/release-native",
                "--package",
                "memcordon",
                "--features",
                "test-fixtures",
                "--test",
                "stress",
                "--release",
                "--locked",
                "--",
                "release_short_children_are_bounded_reaped_and_observed",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ],
            RELEASE_DEADLINE,
        )
        .run()?;
    } else {
        eprintln!(
            "release-native backend-dependent stress is unavailable on this runner; required dedicated backend certification remains authoritative: {probe}"
        );
    }
    for component in &target.executable {
        let arguments = vec![
            OsString::from("build"),
            OsString::from("--target-dir"),
            release_target.clone().into_os_string(),
            OsString::from("--package"),
            OsString::from(&component.package),
            OsString::from("--bin"),
            OsString::from(&component.binary),
            OsString::from("--release"),
            OsString::from("--locked"),
            OsString::from("--target"),
            OsString::from(&target.rust_target),
        ];
        rustup_cargo(root, &toolchains.stable, arguments, RELEASE_DEADLINE).run()?;
    }

    let built_executables = require_built_executable_inventory(root, target)?;
    for built in &built_executables {
        let component = built.component;
        let executable = &built.path;
        verify_component_version(
            executable,
            &component.binary,
            &identity.version.to_string(),
            root,
        )?;
        match component.role {
            RuntimeComponentRole::PublicCli => {
                CommandSpec::new(executable, root, Duration::from_secs(30))
                    .args(["doctor", "--json"])
                    .run()?;
            }
            RuntimeComponentRole::SealedAgent => {
                CommandSpec::new(executable, root, Duration::from_secs(30))
                    .args(["package", "inspect", "--json"])
                    .run()?;
            }
            RuntimeComponentRole::DesktopBootstrap => {
                let bytes = fs::read(executable)?;
                memcordon_core::verify_target_desktop_bootstrap_pe(&bytes).map_err(failure)?;
            }
            RuntimeComponentRole::SessionBroker => {
                let bytes = fs::read(executable)?;
                memcordon_core::verify_session_broker_pe(&bytes).map_err(failure)?;
            }
        }
    }
    let built = build_archive(root, &identity, target)?;
    if fs::metadata(&built.path)?.len() > release.maximum_asset_bytes {
        return Err(failure(
            "native release archive exceeds configured size policy",
        ));
    }
    let inspection = inspect_extract_and_smoke(root, &built.path, target, &identity, true)?;
    if inspection.runtime_manifest_sha256 != built.runtime_manifest_sha256
        || inspection.components != built.components
    {
        return Err(failure("built archive runtime inventory differs"));
    }
    let asset = AssetRecord {
        name: built
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| failure("archive name is not UTF-8"))?
            .to_owned(),
        target: target.rust_target.clone(),
        size: fs::metadata(&built.path)?.len(),
        sha256: sha256_file(&built.path)?,
        runtime_manifest_sha256: inspection.runtime_manifest_sha256,
        components: inspection.components,
    };
    let report = NativeAssetReport {
        schema_version: 2,
        tag: identity.tag,
        source_commit: identity.commit,
        asset,
        archive_member_inventory_sha256: inspection.archive_member_inventory_sha256,
        smoke: inspection.smoke,
    };
    let report_name = format!(
        "{}.json",
        built
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| failure("archive name is not UTF-8"))?
    );
    write_json(&built.path.with_file_name(report_name), &report)?;
    Ok(())
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    fs::write(path, bytes)?;
    Ok(())
}

fn record_native_report_mismatch<T: std::fmt::Debug + Eq + ?Sized>(
    mismatches: &mut Vec<String>,
    field: &str,
    expected: &T,
    actual: &T,
) {
    if expected != actual {
        mismatches.push(format!(
            "field={field} expected={expected:?} actual={actual:?}"
        ));
    }
}

fn require_native_report_identity(
    target_id: &str,
    report: &NativeAssetReport,
    asset: &AssetRecord,
    identity: &ReleaseIdentity,
    archive_member_inventory_sha256: &str,
    expected_agent_smoke: Option<bool>,
) -> Result<()> {
    let expected_smoke = NativeSmokeReport {
        cli_version: true,
        doctor: true,
        agent_version: expected_agent_smoke,
        agent_inspection: expected_agent_smoke,
        provider_install: expected_agent_smoke,
        provider_verify: expected_agent_smoke,
        provider_qualification: expected_agent_smoke,
        sealed_execution: expected_agent_smoke,
        provider_uninstall: expected_agent_smoke,
    };
    let mut mismatches = Vec::new();
    record_native_report_mismatch(
        &mut mismatches,
        "schema_version",
        &2,
        &report.schema_version,
    );
    record_native_report_mismatch(&mut mismatches, "tag", &identity.tag, &report.tag);
    record_native_report_mismatch(
        &mut mismatches,
        "source_commit",
        &identity.commit,
        &report.source_commit,
    );
    record_native_report_mismatch(
        &mut mismatches,
        "asset.name",
        &asset.name,
        &report.asset.name,
    );
    record_native_report_mismatch(
        &mut mismatches,
        "asset.target",
        &asset.target,
        &report.asset.target,
    );
    record_native_report_mismatch(
        &mut mismatches,
        "asset.size",
        &asset.size,
        &report.asset.size,
    );
    record_native_report_mismatch(
        &mut mismatches,
        "asset.sha256",
        &asset.sha256,
        &report.asset.sha256,
    );
    record_native_report_mismatch(
        &mut mismatches,
        "asset.runtime_manifest_sha256",
        &asset.runtime_manifest_sha256,
        &report.asset.runtime_manifest_sha256,
    );
    if report.asset.components.len() == asset.components.len() {
        for (index, (expected, actual)) in asset
            .components
            .iter()
            .zip(report.asset.components.iter())
            .enumerate()
        {
            record_native_report_mismatch(
                &mut mismatches,
                &format!("asset.components[{index}].id"),
                &expected.id,
                &actual.id,
            );
            record_native_report_mismatch(
                &mut mismatches,
                &format!("asset.components[{index}].path"),
                &expected.path,
                &actual.path,
            );
            record_native_report_mismatch(
                &mut mismatches,
                &format!("asset.components[{index}].role"),
                &expected.role,
                &actual.role,
            );
            record_native_report_mismatch(
                &mut mismatches,
                &format!("asset.components[{index}].size"),
                &expected.size,
                &actual.size,
            );
            record_native_report_mismatch(
                &mut mismatches,
                &format!("asset.components[{index}].mode"),
                &expected.mode,
                &actual.mode,
            );
            record_native_report_mismatch(
                &mut mismatches,
                &format!("asset.components[{index}].sha256"),
                &expected.sha256,
                &actual.sha256,
            );
        }
    } else {
        record_native_report_mismatch(
            &mut mismatches,
            "asset.components",
            &asset.components,
            &report.asset.components,
        );
    }
    record_native_report_mismatch(
        &mut mismatches,
        "smoke.cli_version",
        &expected_smoke.cli_version,
        &report.smoke.cli_version,
    );
    record_native_report_mismatch(
        &mut mismatches,
        "smoke.doctor",
        &expected_smoke.doctor,
        &report.smoke.doctor,
    );
    record_native_report_mismatch(
        &mut mismatches,
        "smoke.agent_version",
        &expected_smoke.agent_version,
        &report.smoke.agent_version,
    );
    record_native_report_mismatch(
        &mut mismatches,
        "smoke.agent_inspection",
        &expected_smoke.agent_inspection,
        &report.smoke.agent_inspection,
    );
    record_native_report_mismatch(
        &mut mismatches,
        "smoke.provider_install",
        &expected_smoke.provider_install,
        &report.smoke.provider_install,
    );
    record_native_report_mismatch(
        &mut mismatches,
        "smoke.provider_verify",
        &expected_smoke.provider_verify,
        &report.smoke.provider_verify,
    );
    record_native_report_mismatch(
        &mut mismatches,
        "smoke.provider_qualification",
        &expected_smoke.provider_qualification,
        &report.smoke.provider_qualification,
    );
    record_native_report_mismatch(
        &mut mismatches,
        "smoke.sealed_execution",
        &expected_smoke.sealed_execution,
        &report.smoke.sealed_execution,
    );
    record_native_report_mismatch(
        &mut mismatches,
        "smoke.provider_uninstall",
        &expected_smoke.provider_uninstall,
        &report.smoke.provider_uninstall,
    );
    record_native_report_mismatch(
        &mut mismatches,
        "archive_member_inventory_sha256",
        archive_member_inventory_sha256,
        &report.archive_member_inventory_sha256,
    );
    if !mismatches.is_empty() {
        return Err(failure(format!(
            "native report identity differs for {target_id}: {}",
            mismatches.join("; ")
        )));
    }
    Ok(())
}

fn copy_release_inputs(
    root: &Path,
    output: &Path,
    targets: &[AssetTarget],
    identity: &ReleaseIdentity,
    maximum_asset_bytes: u64,
) -> Result<Vec<AssetRecord>> {
    let input = root.join("target").join("ci").join("release-inputs");
    let mut assets = Vec::new();
    for target in targets {
        let expected_name = archive_name(&identity.version, target);
        let mut matches = Vec::new();
        for entry in WalkDir::new(&input) {
            let entry = entry.map_err(|error| failure(error.to_string()))?;
            let name = entry.file_name().to_string_lossy();
            if entry.file_type().is_file() && name == expected_name {
                matches.push(entry.path().to_path_buf());
            }
        }
        if matches.len() != 1 {
            return Err(failure(format!(
                "expected exactly one release input for {}",
                target.id
            )));
        }
        let source = &matches[0];
        let name = source
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| failure("release asset name is not UTF-8"))?
            .to_owned();
        let destination = output.join(&name);
        fs::copy(source, &destination)?;
        if fs::metadata(&destination)?.len() > maximum_asset_bytes {
            return Err(failure(format!("release input is too large: {name}")));
        }
        let inspection = inspect_extract_and_smoke(root, &destination, target, identity, false)?;
        let asset = AssetRecord {
            name,
            target: target.rust_target.clone(),
            size: fs::metadata(&destination)?.len(),
            sha256: sha256_file(&destination)?,
            runtime_manifest_sha256: inspection.runtime_manifest_sha256,
            components: inspection.components,
        };
        let report_name = format!("{}.json", asset.name);
        let reports: Vec<PathBuf> = WalkDir::new(&input)
            .into_iter()
            .filter_map(std::result::Result::ok)
            .filter(|entry| {
                entry.file_type().is_file() && entry.file_name() == report_name.as_str()
            })
            .map(|entry| entry.path().to_path_buf())
            .collect();
        if reports.len() != 1 {
            return Err(failure(format!(
                "expected exactly one native report for {}",
                target.id
            )));
        }
        let report: NativeAssetReport = serde_json::from_slice(&fs::read(&reports[0])?)?;
        let expected_agent_smoke = (target.sealed == SealedAssetPolicy::Included).then_some(true);
        require_native_report_identity(
            target.id.as_str(),
            &report,
            &asset,
            identity,
            &inspection.archive_member_inventory_sha256,
            expected_agent_smoke,
        )?;
        assets.push(asset);
    }
    assets.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(assets)
}

fn workflow_provenance(
    root: &Path,
    identity: &ReleaseIdentity,
    release: &config::Release,
) -> Result<(String, String, String, BTreeMap<String, String>)> {
    let commit = std::env::var("GITHUB_WORKFLOW_SHA")
        .map_err(|_| failure("GITHUB_WORKFLOW_SHA is required for release provenance"))?;
    let workflow_ref = std::env::var("GITHUB_WORKFLOW_REF")
        .map_err(|_| failure("GITHUB_WORKFLOW_REF is required for release provenance"))?;
    if commit != identity.commit {
        return Err(failure(
            "workflow provenance commit differs from source commit",
        ));
    }
    workflow_provenance_at(
        root,
        identity,
        release,
        &HttpEndpoints::production(),
        &commit,
        &workflow_ref,
    )
}

fn workflow_provenance_at(
    root: &Path,
    identity: &ReleaseIdentity,
    release: &config::Release,
    endpoints: &HttpEndpoints,
    commit: &str,
    workflow_ref: &str,
) -> Result<(String, String, String, BTreeMap<String, String>)> {
    if commit != identity.commit {
        return Err(failure(
            "workflow provenance commit differs from source commit",
        ));
    }
    let workflow_relative = Path::new(".github")
        .join("workflows")
        .join(&release.workflow);
    let expected_ref = format!(
        "{}/.github/workflows/{}@refs/tags/{}",
        release.repository, release.workflow, identity.tag
    );
    if workflow_ref != expected_ref {
        return Err(failure("GITHUB_WORKFLOW_REF is not the exact release tag"));
    }
    let workflow_api_path = [".github", "workflows", release.workflow.as_str()].join("/");
    let url = format!(
        "{}/repos/{}/contents/{}?ref={commit}",
        endpoints.github_api, release.repository, workflow_api_path
    );
    let executed_bytes = github_raw_get(
        release,
        endpoints,
        &url,
        None,
        "application/vnd.github.raw+json",
        release.maximum_asset_bytes,
    )?;
    let policy = config::policy(root)?;
    crate::policy::validate_workflow_bytes(root, &workflow_relative, &executed_bytes, &policy)?;
    let workflow_sha256 = sha256_bytes(&executed_bytes);
    let action_revisions = config::action_pins(root)?
        .action
        .into_iter()
        .map(|pin| (pin.name, pin.uses))
        .collect();
    Ok((
        commit.to_owned(),
        workflow_ref.to_owned(),
        workflow_sha256,
        action_revisions,
    ))
}

fn assemble(root: &Path) -> Result<()> {
    let identity = preflight(root)?;
    let release = config::release(root)?;
    let default_cargo_binaries = configured_default_cargo_binaries(&release)?;
    let toolchains = config::toolchains(root)?;
    let output = root.join(&release.assets.output_directory);
    fs::create_dir_all(&output)?;
    let assets = copy_release_inputs(
        root,
        &output,
        &release.assets.target,
        &identity,
        release.maximum_asset_bytes,
    )?;
    let mut checksums = String::new();
    for asset in &assets {
        checksums.push_str(&asset.sha256);
        checksums.push_str("  ");
        checksums.push_str(&asset.name);
        checksums.push('\n');
    }
    fs::write(output.join(&release.assets.checksums), checksums)?;
    create_package_archives(root, &toolchains.stable, &release.publish_packages)?;
    let mut crates = Vec::new();
    for package in &release.publish_packages {
        crates.push(package_crate(
            root,
            &toolchains.stable,
            package,
            &identity.version,
            &identity.commit,
            release.maximum_package_bytes,
            &default_cargo_binaries,
        )?);
        let archive =
            package_archive_directory(root).join(format!("{package}-{}.crate", identity.version));
        let package_output = output.join("packages");
        fs::create_dir_all(&package_output)?;
        fs::copy(
            &archive,
            package_output.join(
                archive
                    .file_name()
                    .ok_or_else(|| failure("package archive has no filename"))?,
            ),
        )?;
    }
    let notes = format!(
        "{}\n---\n\nTag: \x60{}\x60  \nCommit: \x60{}\x60  \nRust: \x60{}\x60  \n",
        identity.changelog_section, identity.tag, identity.commit, toolchains.stable
    );
    fs::write(output.join(&release.assets.notes), notes)?;
    let (workflow_commit, workflow_ref, workflow_sha256, action_revisions) =
        workflow_provenance(root, &identity, &release)?;
    let certification_origin = memcordon_ci::certification_context::ExpectedCertificationOrigin {
        source_commit: identity.commit.clone(),
        repository: required_platform_value("GITHUB_REPOSITORY")?,
        run_id: required_platform_value("GITHUB_RUN_ID")?
            .parse()
            .map_err(|_| failure("invalid producer run id"))?,
        workflow_ref: workflow_ref.clone(),
        workflow_commit: workflow_commit.clone(),
    };
    let certification = collect_certification(
        &root.join("target").join("ci").join("release-inputs"),
        &output,
        &certification_origin,
    )?;
    verify_standard_producers(
        &release,
        &HttpEndpoints::production(),
        &certification_origin,
        |contract| memcordon_ci::release_evidence::read_report(&output.join(contract.bundle_path)),
    )?;
    let manifest = ReleaseManifest {
        schema_version: config::RELEASE_SCHEMA_VERSION,
        project: "memcordon".to_owned(),
        tag: identity.tag.clone(),
        version: identity.version.to_string(),
        source_commit: identity.commit.clone(),
        workflow_commit,
        workflow_ref,
        workflow_sha256,
        action_revisions,
        prerelease: !identity.version.pre.is_empty(),
        rust_toolchain: toolchains.stable,
        assets,
        crates,
        certification,
        certification_contract: "standard-and-sealed-v1".into(),
        certification_origin,
        source_date: identity.source_date,
    };
    write_json(&output.join(&release.assets.manifest), &manifest)?;
    Ok(())
}

fn bundle_manifest(root: &Path) -> Result<(config::Release, ReleaseManifest, PathBuf)> {
    let release = config::release(root)?;
    config::validate_release_configuration_identity(&release)?;
    let output = root.join(&release.assets.output_directory);
    let manifest: ReleaseManifest =
        serde_json::from_slice(&fs::read(output.join(&release.assets.manifest))?)?;
    if manifest.schema_version != config::RELEASE_SCHEMA_VERSION {
        return Err(failure("release manifest schema identity is invalid"));
    }
    validate_manifest_crates(&release, &manifest)?;
    if manifest.certification_contract != "standard-and-sealed-v1"
        || manifest.certification_origin.source_commit != manifest.source_commit
        || manifest.certification_origin.workflow_commit != manifest.workflow_commit
        || manifest.certification_origin.workflow_ref != manifest.workflow_ref
    {
        return Err(failure("release certification contract or origin mismatch"));
    }
    memcordon_ci::release_evidence::validate_required_certification_records(
        &manifest.certification,
        &manifest.certification_origin,
        |path| memcordon_ci::release_evidence::read_report(&output.join(path)),
    )?;
    Ok((release, manifest, output))
}

fn is_lowercase_hex_digest(value: &str) -> bool {
    let digest_length = "00".repeat(32).len();
    value.len() == digest_length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_manifest_crates(release: &config::Release, manifest: &ReleaseManifest) -> Result<()> {
    let names: Vec<&str> = manifest
        .crates
        .iter()
        .map(|record| record.name.as_str())
        .collect();
    let configured: Vec<&str> = release
        .publish_packages
        .iter()
        .map(String::as_str)
        .collect();
    if names != configured {
        return Err(failure(
            "release manifest crate inventory or order differs from configured publication order",
        ));
    }
    for record in &manifest.crates {
        if record.version != manifest.version
            || record.vcs_commit != manifest.source_commit
            || !is_lowercase_hex_digest(&record.archive_sha256)
            || !is_lowercase_hex_digest(&record.canonical_tree_sha256)
            || !is_lowercase_hex_digest(&record.canonical_identity_sha256)
        {
            return Err(failure(format!(
                "release manifest crate identity is invalid: {}",
                record.name
            )));
        }
    }
    Ok(())
}

fn github_token() -> Result<String> {
    std::env::var("GITHUB_TOKEN").map_err(|_| failure("GITHUB_TOKEN is required for this phase"))
}

fn retry_transient<T>(
    wait: &config::RegistryWait,
    mut operation: impl FnMut() -> Result<T>,
) -> Result<T> {
    let started = Instant::now();
    let total = Duration::from_secs(wait.total_seconds);
    let maximum = Duration::from_millis(wait.maximum_milliseconds);
    let mut delay = Duration::from_millis(wait.initial_milliseconds);
    loop {
        match operation() {
            Ok(value) => return Ok(value),
            Err(error) if transient_network_error(&error) && started.elapsed() < total => {
                thread::sleep(delay);
                delay = delay.saturating_mul(2).min(maximum);
            }
            Err(error) => return Err(error),
        }
    }
}

fn wait_for_remote_state<T>(
    wait: &config::RegistryWait,
    mut operation: impl FnMut() -> Result<Option<T>>,
) -> Result<Option<T>> {
    let started = Instant::now();
    let total = Duration::from_secs(wait.total_seconds);
    let maximum = Duration::from_millis(wait.maximum_milliseconds);
    let mut delay = Duration::from_millis(wait.initial_milliseconds);
    loop {
        match operation()? {
            Some(value) => return Ok(Some(value)),
            None if started.elapsed() < total => {
                thread::sleep(delay);
                delay = delay.saturating_mul(2).min(maximum);
            }
            None => return Ok(None),
        }
    }
}

#[cfg(test)]
fn existing_or_create<T>(existing: Option<T>, create: impl FnOnce() -> Result<T>) -> Result<T> {
    match existing {
        Some(value) => Ok(value),
        None => create(),
    }
}

fn classify_remote_release(
    remote: &serde_json::Value,
    tag: &str,
    source_commit: &str,
    prerelease: bool,
) -> Result<RemoteReleaseState> {
    if remote.get("tag_name").and_then(serde_json::Value::as_str) != Some(tag)
        || remote
            .get("target_commitish")
            .and_then(serde_json::Value::as_str)
            != Some(source_commit)
        || remote
            .get("prerelease")
            .and_then(serde_json::Value::as_bool)
            != Some(prerelease)
    {
        return Err(failure("existing GitHub release identity differs"));
    }
    let id = remote
        .get("id")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| failure("GitHub release lacks an id"))?;
    match remote.get("draft").and_then(serde_json::Value::as_bool) {
        Some(true) => Ok(RemoteReleaseState::Draft(id)),
        Some(false) => Ok(RemoteReleaseState::Published(id)),
        None => Err(failure("GitHub release lacks draft classification")),
    }
}

fn github_http_error(method: &str, url: &str, error: ureq::Error) -> CiError {
    CiError::GithubHttp {
        method: method.to_owned(),
        endpoint: url.to_owned(),
        source: Box::new(CiError::Http(Box::new(error))),
        details: String::new(),
        retry_after: None,
    }
}

fn http_status(error: &CiError) -> Option<u16> {
    match error {
        CiError::Http(error) => match error.as_ref() {
            ureq::Error::StatusCode(status) => Some(*status),
            _ => None,
        },
        CiError::GithubHttp { source, .. } => http_status(source),
        _ => None,
    }
}

fn github_rate_limit_delay(
    status: u16,
    retry_after: Option<&str>,
    remaining: Option<&str>,
    reset: Option<&str>,
    now: SystemTime,
) -> Option<Duration> {
    if !matches!(status, 403 | 429) {
        return None;
    }
    // GitHub documents Retry-After as seconds. An unsupported or malformed value
    // fails closed; never replace a server minimum with a shorter backoff.
    let retry = match retry_after {
        Some(value) => Some(Duration::from_secs(value.parse::<u64>().ok()?)),
        None => None,
    };
    let reset_delay = if remaining == Some("0") {
        let reset = UNIX_EPOCH.checked_add(Duration::from_secs(reset?.parse().ok()?))?;
        Some(
            reset
                .duration_since(now)
                .unwrap_or_default()
                .saturating_add(Duration::from_secs(1)),
        )
    } else {
        None
    };
    retry
        .max(reset_delay)
        .map(|delay| delay.max(Duration::from_secs(1)))
        .or_else(|| {
            // A 429 explicitly identifies throttling; an unqualified 403 does not.
            (status == 429).then_some(Duration::from_secs(60))
        })
}

fn github_response(
    method: &str,
    url: &str,
    response: std::result::Result<ureq::http::Response<ureq::Body>, ureq::Error>,
) -> Result<ureq::http::Response<ureq::Body>> {
    let response = response.map_err(|error| github_http_error(method, url, error))?;
    let status = response.status().as_u16();
    if response.status().is_success() {
        return Ok(response);
    }
    let header = |name| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
    };
    let retry_after = github_rate_limit_delay(
        status,
        header("retry-after"),
        header("x-ratelimit-remaining"),
        header("x-ratelimit-reset"),
        SystemTime::now(),
    );
    let mut details = String::new();
    // Do not print response bodies, arbitrary headers, redirect URLs or credentials.
    for name in [
        "x-github-request-id",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
        "retry-after",
    ] {
        if let Some(value) = header(name) {
            details.push_str(&format!("; {name}={value:?}"));
        }
    }
    Err(CiError::GithubHttp {
        method: method.to_owned(),
        endpoint: url.to_owned(),
        source: Box::new(CiError::Http(Box::new(ureq::Error::StatusCode(status)))),
        details,
        retry_after,
    })
}

fn github_retry_delay(
    release: &config::Release,
    error: &CiError,
    backoff: Duration,
    request_elapsed: Duration,
    operation_elapsed: Duration,
) -> Option<Duration> {
    let throttle = match error {
        CiError::GithubHttp { retry_after, .. } => *retry_after,
        _ => None,
    };
    let delay = if let Some(delay) = throttle {
        delay
    } else if transient_network_error(error)
        && request_elapsed.saturating_add(backoff)
            <= Duration::from_secs(release.network_retry.total_seconds)
    {
        backoff
    } else {
        return None;
    };
    (operation_elapsed.saturating_add(delay)
        <= Duration::from_secs(release.github_rate_limit_wait_seconds))
    .then_some(delay)
}

fn retry_github_read<T>(
    release: &config::Release,
    endpoints: &HttpEndpoints,
    mut operation: impl FnMut() -> Result<T>,
) -> Result<T> {
    let started = Instant::now();
    let mut backoff = Duration::from_millis(release.network_retry.initial_milliseconds);
    loop {
        match operation() {
            Ok(value) => return Ok(value),
            Err(error) => {
                let Some(delay) = github_retry_delay(
                    release,
                    &error,
                    backoff,
                    started.elapsed(),
                    endpoints.github_started.elapsed(),
                ) else {
                    if transient_network_error(&error) {
                        eprintln!(
                            "GitHub read retry budget exhausted or server delay exceeds remaining operation budget"
                        );
                    }
                    return Err(error);
                };
                eprintln!("{error}; retrying GitHub read after {delay:?}");
                thread::sleep(delay);
                backoff = backoff.saturating_mul(2).min(Duration::from_millis(
                    release.network_retry.maximum_milliseconds,
                ));
            }
        }
    }
}

fn verify_standard_producers(
    release: &config::Release,
    endpoints: &HttpEndpoints,
    origin: &memcordon_ci::certification_context::ExpectedCertificationOrigin,
    mut read: impl FnMut(memcordon_ci::standard_contract::StandardContract) -> Result<Vec<u8>>,
) -> Result<()> {
    for contract in [
        memcordon_ci::standard_contract::LINUX,
        memcordon_ci::standard_contract::WINDOWS,
    ] {
        let report: memcordon_ci::standard_contract::StandardCertificationReportV3 =
            serde_json::from_slice(&read(contract)?)?;
        memcordon_ci::standard_contract::validate_report(
            &report,
            contract,
            &origin.source_commit,
            Some(origin),
        )?;
        let provenance = report
            .provenance
            .as_ref()
            .ok_or_else(|| failure("hosted producer provenance absent"))?;
        let url = format!(
            "{}/repos/{}/actions/runs/{}/attempts/{}",
            endpoints.github_api, origin.repository, origin.run_id, provenance.run_attempt
        );
        let run = github_json_request(release, endpoints, "GET", &url, None, None)?;
        let jobs_url = format!("{url}/jobs?per_page=100");
        let jobs = github_json_request(release, endpoints, "GET", &jobs_url, None, None)?;
        let count = jobs
            .get("total_count")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| failure("producer job count absent"))?;
        if count > 100
            || jobs
                .get("jobs")
                .and_then(serde_json::Value::as_array)
                .is_none_or(|jobs| jobs.len() as u64 != count)
        {
            return Err(failure(
                "producer job metadata exceeds complete bounded inventory",
            ));
        }
        memcordon_ci::producer_metadata::validate(origin, provenance, contract, &run, &jobs)?;
    }
    Ok(())
}

fn github_json_request(
    release: &config::Release,
    endpoints: &HttpEndpoints,
    method: &str,
    url: &str,
    token: Option<&str>,
    body: Option<serde_json::Value>,
) -> Result<serde_json::Value> {
    if !url.starts_with(&format!("{}/", endpoints.github_api)) {
        return Err(failure("GitHub API destination is not allowlisted"));
    }
    let send = || {
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_connect(Some(Duration::from_secs(15)))
            .timeout_recv_response(Some(Duration::from_secs(60)))
            .timeout_recv_body(Some(Duration::from_secs(60)))
            .build()
            .new_agent();
        let authorization = token.map(|token| format!("Bearer {token}"));
        let response = match (method, &body) {
            ("GET", None) => {
                let mut request = agent
                    .get(url)
                    .header("Accept", "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", &release.github_api_version)
                    .header("User-Agent", "memcordon-ci");
                if let Some(authorization) = &authorization {
                    request = request.header("Authorization", authorization);
                }
                request.call()
            }
            ("POST", Some(value)) => {
                let mut request = agent
                    .post(url)
                    .header("Accept", "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", &release.github_api_version)
                    .header("User-Agent", "memcordon-ci");
                if let Some(authorization) = &authorization {
                    request = request.header("Authorization", authorization);
                }
                request.send_json(value)
            }
            ("PATCH", Some(value)) => {
                let mut request = agent
                    .patch(url)
                    .header("Accept", "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", &release.github_api_version)
                    .header("User-Agent", "memcordon-ci");
                if let Some(authorization) = &authorization {
                    request = request.header("Authorization", authorization);
                }
                request.send_json(value)
            }
            _ => return Err(failure("unsupported GitHub API request shape")),
        };
        github_response(method, url, response)
    };
    let mut response = if method == "GET" {
        retry_github_read(release, endpoints, send)?
    } else {
        // Mutations are attempted exactly once. A transport failure or transient response can
        // mean the server committed the operation before the response was lost; callers must
        // re-read canonical remote state before deciding whether a rerun is safe.
        send()?
    };
    response
        .body_mut()
        .read_json()
        .map_err(|error| github_http_error(method, url, error))
}

fn github_raw_get(
    release: &config::Release,
    endpoints: &HttpEndpoints,
    url: &str,
    token: Option<&str>,
    accept: &str,
    maximum_bytes: u64,
) -> Result<Vec<u8>> {
    if !url.starts_with(&format!("{}/", endpoints.github_api)) {
        return Err(failure("GitHub API destination is not allowlisted"));
    }
    retry_github_read(release, endpoints, || {
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_connect(Some(Duration::from_secs(15)))
            .timeout_recv_response(Some(Duration::from_secs(60)))
            .timeout_recv_body(Some(Duration::from_secs(60)))
            .build()
            .new_agent();
        let mut request = agent
            .get(url)
            .header("Accept", accept)
            .header("X-GitHub-Api-Version", &release.github_api_version)
            .header("User-Agent", "memcordon-ci");
        if let Some(token) = token {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
        let mut response = github_response("GET", url, request.call())?;
        let mut bytes = Vec::new();
        response
            .body_mut()
            .as_reader()
            .take(maximum_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| github_http_error("GET", url, ureq::Error::Io(error)))?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum_bytes {
            return Err(failure("GitHub response exceeds configured size policy"));
        }
        Ok(bytes)
    })
}

fn github_release_at(
    root: &Path,
    token: Option<&str>,
    endpoints: &HttpEndpoints,
) -> Result<Option<serde_json::Value>> {
    let (release, manifest, _) = bundle_manifest(root)?;
    if let Some(token) = token {
        let mut matched = None;
        let mut page = 1_usize;
        loop {
            let url = format!(
                "{}/repos/{}/releases?per_page={GITHUB_RELEASES_PER_PAGE}&page={page}",
                endpoints.github_api, release.repository
            );
            let response =
                github_json_request(&release, endpoints, "GET", &url, Some(token), None)?;
            let releases = response
                .as_array()
                .ok_or_else(|| failure("GitHub release listing is not an array"))?;
            for remote in releases.iter().filter(|remote| {
                remote.get("tag_name").and_then(serde_json::Value::as_str)
                    == Some(manifest.tag.as_str())
            }) {
                if matched.is_some() {
                    return Err(failure("multiple GitHub releases use the expected tag"));
                }
                matched = Some(remote.clone());
            }
            if releases.len() < GITHUB_RELEASES_PER_PAGE {
                return Ok(matched);
            }
            page = page
                .checked_add(1)
                .ok_or_else(|| failure("GitHub release listing page overflow"))?;
        }
    }
    let url = format!(
        "{}/repos/{}/releases/tags/{}",
        endpoints.github_api, release.repository, manifest.tag
    );
    match github_json_request(&release, endpoints, "GET", &url, token, None) {
        Ok(value) => Ok(Some(value)),
        Err(error) if http_status(&error) == Some(404) => Ok(None),
        Err(error) => Err(error),
    }
}

fn create_github_draft_at(
    root: &Path,
    token: &str,
    endpoints: &HttpEndpoints,
) -> Result<serde_json::Value> {
    let (release, manifest, output) = bundle_manifest(root)?;
    let notes = fs::read_to_string(output.join(&release.assets.notes))?;
    let url = format!(
        "{}/repos/{}/releases",
        endpoints.github_api, release.repository
    );
    github_json_request(
        &release,
        endpoints,
        "POST",
        &url,
        Some(token),
        Some(serde_json::json!({
            "tag_name": manifest.tag,
            "target_commitish": manifest.source_commit,
            "name": format!("MemCordon {}", manifest.version),
            "body": notes,
            "draft": true,
            "prerelease": manifest.prerelease,
            "make_latest": if manifest.prerelease { "false" } else { "true" },
        })),
    )
}

fn asset_matches(asset: &serde_json::Value, path: &Path) -> Result<bool> {
    let size = asset.get("size").and_then(serde_json::Value::as_u64);
    let digest = asset
        .get("digest")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| value.strip_prefix("sha256:"))
        .map(str::to_owned);
    Ok(size == Some(fs::metadata(path)?.len()) && digest == Some(sha256_file(path)?))
}

fn static_asset_paths(
    release: &config::Release,
    manifest: &ReleaseManifest,
    output: &Path,
) -> Result<Vec<PathBuf>> {
    let mut paths: Vec<PathBuf> = manifest
        .assets
        .iter()
        .map(|asset| output.join(&asset.name))
        .collect();
    paths.extend([
        output.join(&release.assets.checksums),
        output.join(&release.assets.manifest),
        output.join(&release.assets.notes),
    ]);
    paths.extend(
        manifest
            .certification
            .values()
            .map(|record| output.join(&record.evidence_path)),
    );
    paths.sort();
    let mut names = BTreeSet::new();
    for path in &paths {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| failure("static GitHub asset name is not UTF-8"))?;
        if !names.insert(name) {
            return Err(failure(format!(
                "static GitHub asset name is duplicated: {name}"
            )));
        }
    }
    Ok(paths)
}

fn public_asset_records(
    release: &config::Release,
    remote: &serde_json::Value,
    paths: &[PathBuf],
    manifest_assets: &[AssetRecord],
) -> Result<Vec<PublicAssetRecord>> {
    let assets = remote
        .get("assets")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| failure("GitHub release has no asset inventory"))?;
    let expected_names: BTreeSet<&str> = paths
        .iter()
        .filter_map(|path| path.file_name().and_then(|name| name.to_str()))
        .collect();
    let actual_names: BTreeSet<&str> = assets
        .iter()
        .filter_map(|asset| asset.get("name").and_then(serde_json::Value::as_str))
        .filter(|name| *name != release.assets.publication_report)
        .collect();
    if actual_names != expected_names {
        return Err(failure(format!(
            "GitHub static asset inventory differs: expected={expected_names:?} actual={actual_names:?}"
        )));
    }
    let mut records = Vec::new();
    for path in paths {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| failure("asset name is not UTF-8"))?;
        let matching: Vec<&serde_json::Value> = assets
            .iter()
            .filter(|asset| asset.get("name").and_then(serde_json::Value::as_str) == Some(name))
            .collect();
        if matching.len() != 1 || !asset_matches(matching[0], path)? {
            return Err(failure(format!(
                "GitHub asset identity differs or is duplicated: {name}"
            )));
        }
        let runtime = manifest_assets.iter().find(|asset| asset.name == name);
        records.push(PublicAssetRecord {
            id: matching[0]
                .get("id")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| failure("GitHub asset has no id"))?,
            name: name.to_owned(),
            size: fs::metadata(path)?.len(),
            sha256: sha256_file(path)?,
            runtime_manifest_sha256: runtime.map(|asset| asset.runtime_manifest_sha256.clone()),
            components: runtime
                .map(|asset| asset.components.clone())
                .unwrap_or_default(),
        });
    }
    records.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(records)
}

fn download_github_asset(
    release: &config::Release,
    asset: &serde_json::Value,
    token: Option<&str>,
    destination: &Path,
) -> Result<()> {
    download_github_asset_at(
        release,
        &HttpEndpoints::production(),
        asset,
        token,
        destination,
    )
}

fn download_github_asset_at(
    release: &config::Release,
    endpoints: &HttpEndpoints,
    asset: &serde_json::Value,
    token: Option<&str>,
    destination: &Path,
) -> Result<()> {
    let url = asset
        .get("url")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| failure("GitHub asset has no API URL"))?;
    if !url.starts_with(&format!("{}/", endpoints.github_api)) {
        return Err(failure("GitHub asset API URL is not allowlisted"));
    }
    let authorization = token.map(|token| format!("Bearer {token}"));
    let bytes = retry_github_read(release, endpoints, || {
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_connect(Some(Duration::from_secs(15)))
            .timeout_recv_response(Some(Duration::from_secs(60)))
            .timeout_recv_body(Some(Duration::from_secs(60)))
            .build()
            .new_agent();
        let mut request = agent
            .get(url)
            .header("Accept", "application/octet-stream")
            .header("X-GitHub-Api-Version", &release.github_api_version)
            .header("User-Agent", "memcordon-ci");
        if let Some(authorization) = &authorization {
            request = request.header("Authorization", authorization);
        }
        let mut response = github_response("GET", url, request.call())?;
        let mut bytes = Vec::new();
        response
            .body_mut()
            .as_reader()
            .take(release.maximum_asset_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| github_http_error("GET", url, ureq::Error::Io(error)))?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > release.maximum_asset_bytes {
            return Err(failure("GitHub asset exceeds configured size policy"));
        }
        Ok(bytes)
    })?;
    let temporary = destination.with_extension("download-part");
    fs::write(&temporary, bytes)?;
    fs::rename(temporary, destination)?;
    Ok(())
}

fn upload_github_asset_at(
    release: &config::Release,
    endpoints: &HttpEndpoints,
    release_id: u64,
    token: &str,
    path: &Path,
) -> Result<serde_json::Value> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| failure("asset name is not UTF-8"))?;
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err(failure("release asset name contains unsafe characters"));
    }
    let url = format!(
        "{}/repos/{}/releases/{release_id}/assets",
        endpoints.github_uploads, release.repository
    );
    let bytes = fs::read(path)?;
    // Upload is non-idempotent and therefore deliberately receives one network attempt.
    let agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_connect(Some(Duration::from_secs(15)))
        .timeout_recv_response(Some(Duration::from_secs(120)))
        .timeout_recv_body(Some(Duration::from_secs(120)))
        .build()
        .new_agent();
    let response = agent
        .post(&url)
        .query("name", name)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", &release.github_api_version)
        .header("User-Agent", "memcordon-ci")
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/octet-stream")
        .send(bytes.as_slice());
    let mut response = github_response("POST", &url, response)?;
    response
        .body_mut()
        .read_json()
        .map_err(|error| github_http_error("POST", &url, error))
}

fn ambiguous_mutation_error(error: &CiError) -> bool {
    // A rejected mutation stays rejected even when the same response would
    // permit a later GET retry. Preserve the existing reconciliation boundary.
    if http_status(error) == Some(403) {
        return false;
    }
    transient_network_error(error)
        || matches!(error, CiError::Io(_))
        || matches!(http_status(error), Some(409 | 422))
}

fn create_or_reconcile_github_draft_at(
    root: &Path,
    token: &str,
    endpoints: &HttpEndpoints,
) -> Result<serde_json::Value> {
    if let Some(remote) = github_release_at(root, Some(token), endpoints)? {
        return Ok(remote);
    }
    match create_github_draft_at(root, token, endpoints) {
        Ok(remote) => Ok(remote),
        Err(error) if ambiguous_mutation_error(&error) => {
            let (release, _, _) = bundle_manifest(root)?;
            wait_for_remote_state(&release.network_retry, || {
                github_release_at(root, Some(token), endpoints)
            })?
            .ok_or(error)
        }
        Err(error) => Err(error),
    }
}

fn upload_or_reconcile_github_asset_at(
    root: &Path,
    release: &config::Release,
    endpoints: &HttpEndpoints,
    release_id: u64,
    token: &str,
    path: &Path,
) -> Result<serde_json::Value> {
    match upload_github_asset_at(release, endpoints, release_id, token, path) {
        Ok(asset) => Ok(asset),
        Err(error) if ambiguous_mutation_error(&error) => {
            let (_, manifest, _) = bundle_manifest(root)?;
            let name = path
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or_else(|| failure("release asset name is not UTF-8"))?;
            wait_for_remote_state(&release.network_retry, || {
                let Some(remote) = github_release_at(root, Some(token), endpoints)? else {
                    return Ok(None);
                };
                match classify_remote_release(
                    &remote,
                    &manifest.tag,
                    &manifest.source_commit,
                    manifest.prerelease,
                )? {
                    RemoteReleaseState::Draft(id) | RemoteReleaseState::Published(id)
                        if id == release_id => {}
                    _ => {
                        return Err(failure(
                            "GitHub release identity changed after ambiguous upload",
                        ));
                    }
                }
                let assets = remote
                    .get("assets")
                    .and_then(serde_json::Value::as_array)
                    .ok_or_else(|| failure("GitHub release has no asset inventory"))?;
                let matching: Vec<&serde_json::Value> = assets
                    .iter()
                    .filter(|asset| {
                        asset.get("name").and_then(serde_json::Value::as_str) == Some(name)
                    })
                    .collect();
                match matching.as_slice() {
                    [] => Ok(None),
                    [asset] if asset_matches(asset, path)? => Ok(Some((*asset).clone())),
                    [..] => Err(failure(format!(
                        "GitHub release asset conflicts after ambiguous upload: {name}"
                    ))),
                }
            })?
            .ok_or(error)
        }
        Err(error) => Err(error),
    }
}

fn stage_github(root: &Path) -> Result<()> {
    let token = github_token()?;
    stage_github_at(root, &token, &HttpEndpoints::production())
}

fn stage_github_at(root: &Path, token: &str, endpoints: &HttpEndpoints) -> Result<()> {
    let (release, manifest, output) = bundle_manifest(root)?;
    let remote = create_or_reconcile_github_draft_at(root, token, endpoints)?;
    let state = classify_remote_release(
        &remote,
        &manifest.tag,
        &manifest.source_commit,
        manifest.prerelease,
    )?;
    let (draft, release_id) = match state {
        RemoteReleaseState::Draft(id) => (true, id),
        RemoteReleaseState::Published(id) => (false, id),
    };
    let existing = remote
        .get("assets")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .ok_or_else(|| failure("GitHub release has no asset inventory"))?;
    let static_paths = static_asset_paths(&release, &manifest, &output)?;
    for path in &static_paths {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| failure("static GitHub asset name is not UTF-8"))?;
        if let Some(asset) = existing
            .iter()
            .find(|asset| asset.get("name").and_then(serde_json::Value::as_str) == Some(name))
        {
            if !asset_matches(asset, path)? {
                return Err(failure(format!("GitHub release asset conflicts: {name}")));
            }
        } else {
            if !draft {
                return Err(failure(format!(
                    "published GitHub release lacks static asset: {name}"
                )));
            }
            let uploaded = upload_or_reconcile_github_asset_at(
                root, &release, endpoints, release_id, token, path,
            )?;
            if !asset_matches(&uploaded, path)? {
                return Err(failure(format!("GitHub rejected asset digest: {name}")));
            }
        }
    }
    let reconciled = github_release_at(root, Some(token), endpoints)?
        .ok_or_else(|| failure("GitHub release disappeared during staging"))?;
    if classify_remote_release(
        &reconciled,
        &manifest.tag,
        &manifest.source_commit,
        manifest.prerelease,
    )? != state
    {
        return Err(failure("GitHub release state changed during staging"));
    }
    public_asset_records(&release, &reconciled, &static_paths, &manifest.assets)?;
    if !draft {
        let publication_report = reconciled
            .get("assets")
            .and_then(serde_json::Value::as_array)
            .and_then(|assets| {
                assets.iter().find(|asset| {
                    asset.get("name").and_then(serde_json::Value::as_str)
                        == Some(release.assets.publication_report.as_str())
                })
            })
            .ok_or_else(|| failure("published GitHub release lacks publication report"))?;
        let report_path = output.join(&release.assets.publication_report);
        download_github_asset(&release, publication_report, Some(token), &report_path)?;
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct SparseCrateVersionRecord {
    name: String,
    vers: String,
    cksum: String,
    yanked: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CrateRegistryState {
    checksum: String,
    yanked: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CrateVersionLookup {
    Absent,
    Present(CrateRegistryState),
}

fn crate_name_exists(release: &config::Release, name: &str) -> Result<bool> {
    crate_name_exists_at(release, &HttpEndpoints::production(), name)
}

fn crate_name_exists_at(
    release: &config::Release,
    endpoints: &HttpEndpoints,
    name: &str,
) -> Result<bool> {
    let url = format!("{}/api/v1/crates/{name}", endpoints.crates_io);
    let result = retry_transient(&release.network_retry, || {
        ureq::get(&url)
            .header("User-Agent", REGISTRY_USER_AGENT)
            .call()
            .map_err(|error| CiError::Http(Box::new(error)))
    });
    match result {
        Ok(mut response) => {
            let value: serde_json::Value = response
                .body_mut()
                .read_json()
                .map_err(|error| CiError::Http(Box::new(error)))?;
            let observed = value
                .get("crate")
                .and_then(|crate_value| crate_value.get("id"))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| failure("crates.io crate-name response lacks a crate id"))?;
            if observed != name {
                return Err(failure(format!(
                    "crates.io crate-name response identity differs: expected={name} observed={observed}"
                )));
            }
            Ok(true)
        }
        Err(CiError::Http(error)) if matches!(*error, ureq::Error::StatusCode(404)) => Ok(false),
        Err(error) => Err(error),
    }
}

fn registry_http_error(operation: &str, url: &str, error: ureq::Error) -> CiError {
    if matches!(error, ureq::Error::StatusCode(403)) {
        return failure(format!(
            "{operation} was rejected with HTTP 403 at {url}: \
             crates.io 403 responses are endpoint-specific and are not treated as transient: {error}"
        ));
    }
    CiError::Http(Box::new(error))
}

fn sparse_index_path(name: &str) -> Result<String> {
    if name.is_empty() || !name.is_ascii() || name.contains('/') {
        return Err(failure("crate name is invalid for sparse-index lookup"));
    }
    let length = name.len();
    Ok(match length {
        1 => format!("1/{name}"),
        2 => format!("2/{name}"),
        3 => format!("3/{}/{}", &name[..1], name),
        _ => format!("{}/{}/{}", &name[..2], &name[2..4], name),
    })
}

fn sparse_crate_version_state(
    response: &str,
    name: &str,
    version: &str,
) -> Result<CrateVersionLookup> {
    let mut state = None;
    for line in response.lines().filter(|line| !line.is_empty()) {
        let record: SparseCrateVersionRecord = serde_json::from_str(line)
            .map_err(|error| failure(format!("sparse-index record is invalid: {error}")))?;
        if record.name != name {
            return Err(failure(format!(
                "sparse-index crate identity differs: expected={name} observed={}",
                record.name
            )));
        }
        if record.vers != version {
            continue;
        }
        let observed = CrateRegistryState {
            checksum: record.cksum,
            yanked: record.yanked,
        };
        if state.replace(observed).is_some() {
            return Err(failure("sparse-index contains duplicate target versions"));
        }
    }
    Ok(match state {
        Some(state) => CrateVersionLookup::Present(state),
        None => CrateVersionLookup::Absent,
    })
}

fn crate_version_state_at(
    release: &config::Release,
    endpoints: &HttpEndpoints,
    name: &str,
    version: &str,
) -> Result<CrateVersionLookup> {
    let record_path = sparse_index_path(name)?;
    let url = format!("{}/{record_path}", endpoints.crates_io_index);
    let result = retry_transient(&release.network_retry, || {
        ureq::get(&url)
            .header("User-Agent", REGISTRY_USER_AGENT)
            .call()
            .map_err(|error| registry_http_error("sparse-index version lookup", &url, error))
    });
    match result {
        Ok(mut response) => {
            let body = response
                .body_mut()
                .read_to_string()
                .map_err(|error| CiError::Http(Box::new(error)))?;
            sparse_crate_version_state(&body, name, version)
        }
        Err(CiError::Http(error)) if matches!(*error, ureq::Error::StatusCode(404)) => {
            Ok(CrateVersionLookup::Absent)
        }
        Err(error) => Err(error),
    }
}

fn crate_version_state(
    release: &config::Release,
    name: &str,
    version: &str,
) -> Result<CrateVersionLookup> {
    crate_version_state_at(release, &HttpEndpoints::production(), name, version)
}

fn public_crate_archive_at(
    release: &config::Release,
    endpoints: &HttpEndpoints,
    name: &str,
    version: &str,
    destination: &Path,
) -> Result<()> {
    let download_root = endpoints.crates_io_download.clone();
    let url = format!("{download_root}/crates/{name}/{name}-{version}.crate");
    let bytes = retry_transient(&release.network_retry, || {
        let mut response = ureq::get(&url)
            .header("User-Agent", REGISTRY_USER_AGENT)
            .call()
            .map_err(|error| registry_http_error("public crate archive download", &url, error))?;
        let mut bytes = Vec::new();
        response
            .body_mut()
            .as_reader()
            .take(release.maximum_package_bytes.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > release.maximum_package_bytes {
            return Err(failure("registry crate exceeds configured size policy"));
        }
        Ok(bytes)
    })?;
    fs::write(destination, bytes)?;
    Ok(())
}

fn verify_public_crate(
    release: &config::Release,
    record: &CrateRecord,
) -> Result<PublicCrateRecord> {
    verify_public_crate_at(release, &HttpEndpoints::production(), record)
}

fn verify_public_crate_at(
    release: &config::Release,
    endpoints: &HttpEndpoints,
    record: &CrateRecord,
) -> Result<PublicCrateRecord> {
    let state = match crate_version_state_at(release, endpoints, &record.name, &record.version)? {
        CrateVersionLookup::Present(state) => state,
        CrateVersionLookup::Absent => {
            return Err(failure(format!(
                "crate is not public: {} {}",
                record.name, record.version
            )));
        }
    };
    if state.yanked {
        return Err(failure(format!(
            "crate version is yanked: {} {}",
            record.name, record.version
        )));
    }
    if state.checksum != record.archive_sha256 {
        return Err(failure(format!(
            "published crate archive checksum conflict for {}: expected={} observed={}",
            record.name, record.archive_sha256, state.checksum
        )));
    }
    let checksum = state.checksum;
    let temporary = TempDir::new()?;
    let archive = temporary.path().join("package.crate");
    public_crate_archive_at(release, endpoints, &record.name, &record.version, &archive)?;
    if sha256_file(&archive)? != checksum {
        return Err(failure(format!(
            "registry checksum mismatch for {}",
            record.name
        )));
    }
    if canonical_crate_tree(&archive)? != record.canonical_tree_sha256 {
        return Err(failure(format!(
            "published crate content conflict for {}",
            record.name
        )));
    }
    let identity = canonical_crate_identity(&archive)?;
    if identity.sha256 != record.canonical_identity_sha256
        || identity.package_name != record.name
        || identity.package_version != record.version
        || identity.vcs_commit != record.vcs_commit
        || identity.vcs_dirty
    {
        return Err(failure(format!(
            "published crate normalized identity/provenance conflicts for {}",
            record.name
        )));
    }
    Ok(PublicCrateRecord {
        name: record.name.clone(),
        version: record.version.clone(),
        state: "VerifiedPublic".to_owned(),
        registry_checksum: checksum,
        canonical_tree_sha256: record.canonical_tree_sha256.clone(),
        canonical_identity_sha256: record.canonical_identity_sha256.clone(),
        vcs_commit: record.vcs_commit.clone(),
    })
}

fn transient_network_error(error: &CiError) -> bool {
    match error {
        CiError::GithubHttp {
            source,
            retry_after,
            ..
        } => {
            if matches!(http_status(source), Some(403 | 429)) {
                retry_after.is_some()
            } else {
                transient_network_error(source)
            }
        }
        CiError::Http(error) => match error.as_ref() {
            ureq::Error::StatusCode(status) => {
                matches!(*status, 408 | 425 | 429) || (500..=599).contains(status)
            }
            ureq::Error::Timeout(_) | ureq::Error::HostNotFound | ureq::Error::ConnectionFailed => {
                true
            }
            ureq::Error::Io(error) => matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::Interrupted
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::UnexpectedEof
            ),
            _ => false,
        },
        CiError::Io(error) => matches!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::Interrupted
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::UnexpectedEof
        ),
        _ => false,
    }
}

fn verify_crate_consumer(root: &Path, record: &CrateRecord) -> Result<()> {
    let temporary = TempDir::new()?;
    let source = temporary.path().join("src");
    fs::create_dir_all(&source)?;
    fs::write(source.join("main.rs"), b"fn main() {}\n")?;
    let manifest = format!(
        "[package]\nname = \"memcordon-release-consumer\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\n{} = \"={}\"\n",
        record.name, record.version
    );
    let manifest_path = temporary.path().join("Cargo.toml");
    fs::write(&manifest_path, manifest)?;
    let release = config::release(root)?;
    let default_cargo_binaries = configured_default_cargo_binaries(&release)?;
    let toolchains = config::toolchains(root)?;
    let manifest_argument = manifest_path.into_os_string();
    rustup_cargo(
        root,
        &toolchains.stable,
        [
            OsString::from("generate-lockfile"),
            OsString::from("--manifest-path"),
            manifest_argument.clone(),
        ],
        RELEASE_DEADLINE,
    )
    .run()?;
    rustup_cargo(
        root,
        &toolchains.stable,
        [
            OsString::from("check"),
            OsString::from("--locked"),
            OsString::from("--manifest-path"),
            manifest_argument,
        ],
        RELEASE_DEADLINE,
    )
    .run()?;
    if record.name == "memcordon" {
        let install_root = temporary.path().join("install");
        rustup_cargo(
            root,
            &toolchains.stable,
            [
                OsString::from("install"),
                OsString::from("memcordon"),
                OsString::from("--version"),
                OsString::from(&record.version),
                OsString::from("--locked"),
                OsString::from("--root"),
                install_root.clone().into_os_string(),
            ],
            RELEASE_DEADLINE,
        )
        .run()?;
        let binary_directory = install_root.join("bin");
        let cli_name = installed_binary_name("memcordon");
        let agent_name = installed_binary_name("memcordon-sealed-agent");
        let bootstrap_name = installed_binary_name("memcordon-target-desktop-bootstrap");
        let broker_name = installed_binary_name("memcordon-session-broker");
        let actual = fs::read_dir(&binary_directory)?
            .map(|entry| entry.map(|entry| entry.file_name()).map_err(CiError::from))
            .collect::<Result<BTreeSet<_>>>()?;
        let expected = cargo_install_inventory(&default_cargo_binaries);
        if actual != expected {
            return Err(failure(format!(
                "installed memcordon binary inventory differs: expected={expected:?} actual={actual:?}"
            )));
        }
        let executable = binary_directory.join(cli_name);
        verify_component_version(&executable, "memcordon", &record.version, root)?;
        let agent = binary_directory.join(agent_name);
        verify_component_version(&agent, "memcordon-sealed-agent", &record.version, root)?;
        let bootstrap = binary_directory.join(bootstrap_name);
        verify_component_version(
            &bootstrap,
            "memcordon-target-desktop-bootstrap",
            &record.version,
            root,
        )?;
        let broker = binary_directory.join(broker_name);
        verify_component_version(&broker, "memcordon-session-broker", &record.version, root)?;
        let output = CommandSpec::new(&agent, root, Duration::from_secs(30))
            .args(["package", "inspect", "--json"])
            .run()?;
        validate_agent_package_inspection(&output, &record.version, &record.vcs_commit)?;
        #[cfg(target_os = "linux")]
        {
            let mut smoke = NativeSmokeReport {
                cli_version: true,
                doctor: true,
                agent_version: Some(true),
                agent_inspection: Some(true),
                provider_install: None,
                provider_verify: None,
                provider_qualification: None,
                sealed_execution: None,
                provider_uninstall: None,
            };
            smoke_linux_provider(&executable, &agent, root, &mut smoke)?;
        }
        #[cfg(target_os = "windows")]
        {
            let mut smoke = NativeSmokeReport {
                cli_version: true,
                doctor: true,
                agent_version: Some(true),
                agent_inspection: Some(true),
                provider_install: None,
                provider_verify: None,
                provider_qualification: None,
                sealed_execution: None,
                provider_uninstall: None,
            };
            smoke_windows_provider(&executable, &agent, root, &mut smoke)?;
        }
    }
    Ok(())
}

fn wait_for_public_crate(
    root: &Path,
    release: &config::Release,
    record: &CrateRecord,
    wait: &config::RegistryWait,
) -> Result<PublicCrateRecord> {
    let started = Instant::now();
    let mut delay = Duration::from_millis(wait.initial_milliseconds);
    let maximum = Duration::from_millis(wait.maximum_milliseconds);
    let total = Duration::from_secs(wait.total_seconds);
    loop {
        match crate_version_state(release, &record.name, &record.version) {
            Ok(CrateVersionLookup::Absent) if started.elapsed() < total => {
                thread::sleep(delay);
                delay = delay.saturating_mul(2).min(maximum);
            }
            Ok(CrateVersionLookup::Absent) => {
                return Err(failure(format!(
                    "crate visibility retry budget expired: {} {}",
                    record.name, record.version
                )));
            }
            Ok(CrateVersionLookup::Present(_)) => {
                let verified = verify_public_crate(release, record)?;
                verify_crate_consumer(root, record)?;
                return Ok(verified);
            }
            Err(error) if transient_network_error(&error) && started.elapsed() < total => {
                thread::sleep(delay);
                delay = delay.saturating_mul(2).min(maximum);
            }
            Err(error) => return Err(error),
        }
    }
}

fn require_registry_token(token: Option<&OsStr>) -> Result<()> {
    if token.is_none_or(OsStr::is_empty) {
        return Err(failure(format!(
            "{CRATES_IO_TOKEN_VARIABLE} is absent or empty for the selected publication slot"
        )));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OidcFailureClass {
    TrustedPublishingNewCrate,
    TrustedPublishingExistingCrate,
    Other,
}

fn rejected_access_token_crate(line: &str) -> Option<&str> {
    let payload = line.split(ACCESS_TOKEN_CRATE_REJECTION_MARKER).nth(1)?;
    let mut delimited = payload.split('`');
    let name = delimited.next()?;
    delimited.next()?;
    if name.is_empty() { None } else { Some(name) }
}

fn classify_oidc_failure(stderr: &str, selected_crate: &str) -> OidcFailureClass {
    for line in stderr.lines() {
        if let Some(rejected_crate) = rejected_access_token_crate(line) {
            return if rejected_crate == selected_crate {
                OidcFailureClass::TrustedPublishingExistingCrate
            } else {
                OidcFailureClass::Other
            };
        }
    }
    if stderr
        .lines()
        .any(|line| line.contains(TRUSTED_PUBLISHING_NEW_CRATE_MARKER))
    {
        return OidcFailureClass::TrustedPublishingNewCrate;
    }
    OidcFailureClass::Other
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CrateBinding {
    name: String,
    version: String,
    archive_sha256: String,
}

impl CrateBinding {
    fn from_record(record: &CrateRecord) -> Self {
        Self {
            name: record.name.clone(),
            version: record.version.clone(),
            archive_sha256: record.archive_sha256.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseBinding {
    tag: String,
    source_commit: String,
    workflow_commit: String,
}

impl ReleaseBinding {
    fn from_manifest(manifest: &ReleaseManifest) -> Self {
        Self {
            tag: manifest.tag.clone(),
            source_commit: manifest.source_commit.clone(),
            workflow_commit: manifest.workflow_commit.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PublicationRunIdentity {
    run_id: String,
    run_attempt: String,
}

impl PublicationRunIdentity {
    fn from_environment() -> Result<Self> {
        Ok(Self {
            run_id: required_platform_value("GITHUB_RUN_ID")?,
            run_attempt: required_platform_value("GITHUB_RUN_ATTEMPT")?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PublicationOutcome {
    AlreadyPublic,
    OidcPubliclyAccepted,
    OidcRejectedNewCrate,
    OidcRejectedExistingCrate,
    OidcRejectedOther,
    NewCrateAuthorizationConflict,
    NewCrateAuthorized,
    TokenAttemptStarted,
    TokenPubliclyAccepted,
    TokenRejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PublicNameState {
    NotChecked,
    Absent,
    Present,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CargoDiagnostics {
    exit_code: Option<i32>,
    status: String,
    stdout: String,
    stderr: String,
    stdout_sha256: String,
    stderr_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PublicationAttemptRecord {
    schema_version: u32,
    credential_origin: CredentialOrigin,
    outcome: PublicationOutcome,
    public_name_state: PublicNameState,
    cargo: Option<CargoDiagnostics>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PublicationSlotEvidence {
    schema_version: u32,
    publication_slot: NonZeroUsize,
    release: ReleaseBinding,
    run: PublicationRunIdentity,
    crate_binding: CrateBinding,
    records: Vec<PublicationAttemptRecord>,
}

fn redact_exact(value: &str, credential: &str) -> String {
    if credential.is_empty() {
        return value.to_owned();
    }
    value
        .split(credential)
        .collect::<Vec<_>>()
        .join("[redacted]")
}

fn sha256_text(value: &str) -> String {
    sha256_bytes(value.as_bytes())
}

fn cargo_diagnostics(
    output: Option<&ObservedOutput>,
    process_error: Option<&str>,
    credential: &str,
) -> Result<CargoDiagnostics> {
    let decode = |bytes: &[u8], context: &str| -> Result<String> {
        if bytes.len() > MAXIMUM_CARGO_DIAGNOSTIC_BYTES {
            return Err(failure(format!(
                "{context} exceeds the credential-free diagnostic byte budget"
            )));
        }
        utf8(bytes, context)
    };
    let observed = output.map(|observed| {
        let stdout = redact_exact(&decode(&observed.stdout, "Cargo stdout")?, credential);
        let stderr = redact_exact(&decode(&observed.stderr, "Cargo stderr")?, credential);
        let stdout_sha256 = sha256_text(&stdout);
        let stderr_sha256 = sha256_text(&stderr);
        Ok(CargoDiagnostics {
            exit_code: observed.status.code(),
            status: observed.status.to_string(),
            stdout,
            stderr,
            stdout_sha256,
            stderr_sha256,
        })
    });
    match (observed, process_error) {
        (Some(diagnostics), _) => diagnostics,
        (None, Some(error)) => Ok(CargoDiagnostics {
            exit_code: None,
            status: redact_exact(error, credential),
            stdout: String::new(),
            stderr: String::new(),
            stdout_sha256: sha256_text(""),
            stderr_sha256: sha256_text(""),
        }),
        (None, None) => Err(failure("Cargo diagnostics are unavailable")),
    }
}

fn publication_record(
    origin: CredentialOrigin,
    outcome: PublicationOutcome,
    public_name_state: PublicNameState,
    cargo: Option<CargoDiagnostics>,
) -> PublicationAttemptRecord {
    PublicationAttemptRecord {
        schema_version: PUBLICATION_EVIDENCE_SCHEMA_VERSION,
        credential_origin: origin,
        outcome,
        public_name_state,
        cargo,
    }
}

fn publication_evidence_directory(root: &Path) -> PathBuf {
    root.join("target").join("ci").join("publication-evidence")
}

fn slot_evidence_path(root: &Path, slot: NonZeroUsize) -> PathBuf {
    publication_evidence_directory(root).join(format!("slot-{slot}.json"))
}

fn aggregate_evidence_path(root: &Path) -> PathBuf {
    publication_evidence_directory(root).join("publication-evidence.json")
}

fn clear_slot_evidence(root: &Path, slot: NonZeroUsize) -> Result<()> {
    match fs::remove_file(slot_evidence_path(root, slot)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn load_slot_evidence(root: &Path, slot: NonZeroUsize) -> Result<PublicationSlotEvidence> {
    let path = slot_evidence_path(root, slot);
    let bytes = fs::read(&path)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| failure(format!("publication evidence is malformed: {error}")))
}

fn write_slot_evidence(root: &Path, evidence: &PublicationSlotEvidence) -> Result<()> {
    let directory = publication_evidence_directory(root);
    fs::create_dir_all(&directory)?;
    write_json(
        &slot_evidence_path(root, evidence.publication_slot),
        evidence,
    )
}

fn append_publication_record(
    root: &Path,
    release: &config::Release,
    slot: NonZeroUsize,
    record: PublicationAttemptRecord,
) -> Result<()> {
    let mut evidence = load_slot_evidence(root, slot)?;
    evidence.records.push(record);
    write_slot_evidence(root, &evidence)?;

    let mut aggregate = Vec::new();
    for candidate in 1..=release.publish_packages.len() {
        let candidate = NonZeroUsize::new(candidate).expect("slot index is nonzero");
        let candidate_path = slot_evidence_path(root, candidate);
        if candidate_path.exists() {
            aggregate.push(load_slot_evidence(root, candidate)?);
        }
    }
    write_json(&aggregate_evidence_path(root), &aggregate)
}

fn establish_slot_evidence(
    root: &Path,
    slot: NonZeroUsize,
    release_binding: &ReleaseBinding,
    run: &PublicationRunIdentity,
    crate_binding: &CrateBinding,
) -> Result<()> {
    write_slot_evidence(
        root,
        &PublicationSlotEvidence {
            schema_version: PUBLICATION_EVIDENCE_SCHEMA_VERSION,
            publication_slot: slot,
            release: release_binding.clone(),
            run: run.clone(),
            crate_binding: crate_binding.clone(),
            records: Vec::new(),
        },
    )
}

fn validate_slot_evidence_identity(
    evidence: &PublicationSlotEvidence,
    slot: NonZeroUsize,
    release_binding: &ReleaseBinding,
    run: &PublicationRunIdentity,
    crate_binding: &CrateBinding,
) -> Result<()> {
    if evidence.schema_version != PUBLICATION_EVIDENCE_SCHEMA_VERSION
        || evidence.publication_slot != slot
        || evidence.release != *release_binding
        || evidence.run != *run
        || evidence.crate_binding != *crate_binding
    {
        return Err(failure(format!(
            "publication evidence identity differs for slot {slot}"
        )));
    }
    Ok(())
}

fn evidence_authorizes_token_provider(evidence: &PublicationSlotEvidence) -> bool {
    let mut rejection = false;
    for record in &evidence.records {
        match record.outcome {
            PublicationOutcome::OidcRejectedNewCrate => rejection = true,
            PublicationOutcome::OidcRejectedExistingCrate => return false,
            PublicationOutcome::NewCrateAuthorized if rejection => {
                return !evidence.records.iter().any(|record| {
                    matches!(
                        record.outcome,
                        PublicationOutcome::TokenPubliclyAccepted
                            | PublicationOutcome::TokenRejected
                    ) && record.credential_origin == CredentialOrigin::NewCrateToken
                });
            }
            _ => rejection = false,
        }
    }
    false
}

fn evidence_allows_new_token_attempt(evidence: &PublicationSlotEvidence) -> bool {
    !evidence
        .records
        .iter()
        .any(|record| record.credential_origin == CredentialOrigin::NewCrateToken)
}

fn cargo_publish_config(
    root: &Path,
    record: &CrateRecord,
    origin: CredentialOrigin,
    publication_slot: NonZeroUsize,
) -> Result<PathBuf> {
    let configuration_directory = root.join("target").join("ci").join("cargo-publish-config");
    fs::create_dir_all(&configuration_directory)?;
    let provider = std::env::current_exe()?
        .into_os_string()
        .into_string()
        .map_err(|_| failure("credential provider executable path is not UTF-8"))?;
    let configuration = CargoHomeConfig {
        registry: CargoRegistryConfig {
            credential_provider: vec![
                provider,
                origin.value().to_owned(),
                publication_slot.to_string(),
                record.name.clone(),
                record.version.clone(),
                record.archive_sha256.clone(),
            ],
        },
    };
    let configuration_path = configuration_directory.join(format!("slot-{publication_slot}.toml"));
    fs::write(
        &configuration_path,
        toml::to_string(&configuration)
            .map_err(|error| {
                failure(format!(
                    "Cargo provider config serialization failed: {error}"
                ))
            })?
            .as_bytes(),
    )?;
    Ok(configuration_path)
}

fn workflow_cargo_home() -> Result<PathBuf> {
    std::env::var_os("CARGO_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| failure("CARGO_HOME is absent for the selected publication slot"))
}

fn credential_request_error(message: impl Into<String>) -> serde_json::Value {
    serde_json::json!({
        "Err": {
            "kind": "other",
            "message": message.into(),
        }
    })
}

fn credential_operation_unsupported() -> serde_json::Value {
    serde_json::json!({
        "Err": {
            "kind": "operation-not-supported",
        }
    })
}

fn provider_binding_from_request(request: &CredentialRequest) -> Result<ProviderBinding<'_>> {
    let [origin, publication_slot, name, version, archive_sha256] = request.args.as_slice() else {
        return Err(failure(
            "Cargo credential provider configuration identity is invalid",
        ));
    };
    let origin = CredentialOrigin::parse(origin).ok_or_else(|| {
        failure(format!(
            "unknown credential-provider origin in Cargo request args: {origin}"
        ))
    })?;
    let publication_slot = publication_slot
        .parse::<NonZeroUsize>()
        .map_err(|error| failure(format!("invalid credential-provider slot: {error}")))?;
    Ok(ProviderBinding {
        origin,
        publication_slot,
        name,
        version,
        archive_sha256,
    })
}

fn credential_action_is_unsupported(action: &CredentialAction) -> bool {
    matches!(
        action,
        CredentialAction::Get {
            operation: CredentialOperation::Unsupported
        } | CredentialAction::Login { .. }
            | CredentialAction::Logout
    )
}

fn parse_credential_request(line: &str) -> serde_json::Result<CredentialRequest> {
    let value: serde_json::Value = serde_json::from_str(line)?;
    let object = value.as_object().ok_or_else(serde_error)?;
    let allowed_fields = [
        "v",
        "registry",
        "args",
        "kind",
        "operation",
        "name",
        "vers",
        "cksum",
        "token",
        "login-url",
    ];
    if object
        .keys()
        .any(|field| !allowed_fields.contains(&field.as_str()))
    {
        return Err(serde_error());
    }
    let kind = object
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(serde_error)?;
    match kind {
        "get" => {
            let operation = object
                .get("operation")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(serde_error)?;
            let artifact_fields = ["name", "vers", "cksum"];
            match operation {
                "read" => {
                    if artifact_fields
                        .iter()
                        .any(|field| object.contains_key(*field))
                    {
                        return Err(serde_error());
                    }
                }
                "publish" => {
                    for field in artifact_fields {
                        if !object.get(field).is_some_and(serde_json::Value::is_string) {
                            return Err(serde_error());
                        }
                    }
                }
                _ => {
                    if artifact_fields
                        .iter()
                        .any(|field| object.contains_key(*field))
                    {
                        return Err(serde_error());
                    }
                }
            }
        }
        "login" => {
            for field in ["operation", "name", "vers", "cksum"] {
                if object.contains_key(field) {
                    return Err(serde_error());
                }
            }
        }
        "logout" => {
            for field in ["operation", "name", "vers", "cksum", "token", "login-url"] {
                if object.contains_key(field) {
                    return Err(serde_error());
                }
            }
        }
        _ => return Err(serde_error()),
    }
    serde_json::from_value(value)
}

fn serde_error() -> serde_json::Error {
    serde_json::Error::custom("malformed credential action")
}

fn validate_credential_request<'a>(
    root: &Path,
    request: &'a CredentialRequest,
) -> Result<(ProviderBinding<'a>, CrateRecord)> {
    let expected = provider_binding_from_request(request)?;
    if request.v != 1
        || request.registry.name.as_deref() != Some("crates-io")
        || !matches!(
            request.registry.index_url.as_str(),
            "https://github.com/rust-lang/crates.io-index" | "sparse+https://index.crates.io/"
        )
    {
        return Err(failure("Cargo credential request identity is invalid"));
    }
    let (release, manifest, _) = bundle_manifest(root)?;
    let order = configured_publication_order(root, &release)?;
    let selected = configured_slot_record(&manifest, &order, expected.publication_slot)?;
    if selected.name != expected.name {
        return Err(failure(
            "Cargo credential request differs from the selected publication slot",
        ));
    }
    if selected.version != expected.version {
        return Err(failure(
            "Cargo credential request is absent from the release manifest",
        ));
    }
    let record = selected;
    if expected.archive_sha256 != record.archive_sha256.as_str() {
        return Err(failure(
            "Cargo credential request differs from the selected release artifact",
        ));
    }
    match &request.action {
        CredentialAction::Get {
            operation: CredentialOperation::Read,
        } => {}
        CredentialAction::Get {
            operation: CredentialOperation::Publish { name, vers, cksum },
        } if name == &record.name && vers == &record.version && cksum == &record.archive_sha256 => {
        }
        CredentialAction::Get {
            operation: CredentialOperation::Publish { .. },
        } => {
            return Err(failure(
                "Cargo credential request differs from the selected release artifact",
            ));
        }
        CredentialAction::Get {
            operation: CredentialOperation::Unsupported,
        }
        | CredentialAction::Login { .. }
        | CredentialAction::Logout => {
            return Err(failure("Cargo credential operation is unsupported"));
        }
    }
    Ok((expected, record))
}

fn authorize_token_credential_request(
    root: &Path,
    expected: &ProviderBinding<'_>,
    record: &CrateRecord,
    run: &PublicationRunIdentity,
    operation: &CredentialOperation,
) -> Result<()> {
    let (release, manifest, _) = bundle_manifest(root)?;
    let release_binding = ReleaseBinding::from_manifest(&manifest);
    let crate_binding = CrateBinding::from_record(record);
    let evidence = load_slot_evidence(root, expected.publication_slot)?;
    validate_slot_evidence_identity(
        &evidence,
        expected.publication_slot,
        &release_binding,
        run,
        &crate_binding,
    )?;
    if !evidence_authorizes_token_provider(&evidence) {
        return Err(failure(format!(
            "new-crate token evidence lacks a fresh OIDC rejection and authorization for slot {}",
            expected.publication_slot
        )));
    }
    if matches!(operation, CredentialOperation::Publish { .. }) {
        if !evidence_allows_new_token_attempt(&evidence) {
            return Err(failure(format!(
                "publication slot {} already used its one new-crate token attempt",
                expected.publication_slot
            )));
        }
        append_publication_record(
            root,
            &release,
            expected.publication_slot,
            publication_record(
                CredentialOrigin::NewCrateToken,
                PublicationOutcome::TokenAttemptStarted,
                PublicNameState::Absent,
                None,
            ),
        )?;
    }
    Ok(())
}

fn credential_response(
    root: &Path,
    request: serde_json::Result<CredentialRequest>,
    acquire_token: impl FnOnce() -> Option<String>,
    publication_run: impl FnOnce() -> Result<PublicationRunIdentity>,
) -> serde_json::Value {
    match request {
        Ok(request) if credential_action_is_unsupported(&request.action) => {
            credential_operation_unsupported()
        }
        Ok(request) => match validate_credential_request(root, &request) {
            Ok((expected, record)) => {
                if expected.origin == CredentialOrigin::NewCrateToken {
                    let operation = match &request.action {
                        CredentialAction::Get { operation } => operation,
                        CredentialAction::Login { .. } | CredentialAction::Logout => {
                            unreachable!("unsupported credential actions were already rejected")
                        }
                    };
                    let authorization = publication_run().and_then(|run| {
                        authorize_token_credential_request(
                            root, &expected, &record, &run, operation,
                        )
                    });
                    if let Err(error) = authorization {
                        return credential_request_error(error.to_string());
                    }
                }
                match acquire_token() {
                    Some(token) if !token.is_empty() => serde_json::json!({
                        "Ok": {
                            "kind": "get",
                            "token": token,
                            "cache": "never",
                            "operation_independent": false,
                        }
                    }),
                    _ => credential_request_error("registry capability is absent"),
                }
            }
            Err(error) => credential_request_error(error.to_string()),
        },
        Err(_) => credential_request_error("Cargo credential request is malformed"),
    }
}

fn cargo_credential_provider_io(
    root: &Path,
    input: impl BufRead,
    mut output: impl Write,
    acquire_token: impl FnOnce() -> Option<String>,
    publication_run: impl FnOnce() -> Result<PublicationRunIdentity>,
) -> Result<()> {
    serde_json::to_writer(&mut output, &serde_json::json!({ "v": [1] }))?;
    writeln!(output)?;
    output.flush()?;

    let mut input = input;
    let mut line = String::new();
    if input.read_line(&mut line)? == 0 {
        return Err(failure("Cargo credential provider received no request"));
    }
    let request = parse_credential_request(line.trim_end());
    let response = credential_response(root, request, acquire_token, publication_run);
    serde_json::to_writer(&mut output, &response)?;
    writeln!(output)?;
    output.flush()?;
    Ok(())
}

pub fn cargo_credential_provider(root: &Path) -> Result<()> {
    cargo_credential_provider_io(
        root,
        BufReader::new(std::io::stdin().lock()),
        std::io::stdout().lock(),
        || std::env::var(CRATES_IO_TOKEN_VARIABLE).ok(),
        PublicationRunIdentity::from_environment,
    )
}

#[derive(Debug)]
struct RegistryPublicationScan {
    public_names: Vec<String>,
    first_absent: Option<String>,
}

fn scan_registry_publication(
    release: &config::Release,
    endpoints: &HttpEndpoints,
    manifest: &ReleaseManifest,
    order: &[String],
) -> Result<RegistryPublicationScan> {
    let mut scan = RegistryPublicationScan {
        public_names: Vec::new(),
        first_absent: None,
    };
    for package in order {
        let record = manifest
            .crates
            .iter()
            .find(|record| record.name == *package)
            .ok_or_else(|| failure(format!("release manifest lacks crate {package}")))?;
        match crate_version_state_at(release, endpoints, &record.name, &record.version)? {
            CrateVersionLookup::Absent => {
                if scan.first_absent.is_none() {
                    scan.first_absent = Some(package.clone());
                }
            }
            CrateVersionLookup::Present(state) if state.yanked => {
                return Err(failure(format!(
                    "crate version is yanked and cannot be reconciled: {} {}",
                    record.name, record.version
                )));
            }
            CrateVersionLookup::Present(_) => {
                scan.public_names.push(package.clone());
            }
        }
    }
    Ok(scan)
}

fn manifest_record<'a>(manifest: &'a ReleaseManifest, package: &str) -> Result<&'a CrateRecord> {
    manifest
        .crates
        .iter()
        .find(|record| record.name == package)
        .ok_or_else(|| failure(format!("release manifest lacks crate {package}")))
}

struct CargoPublicationAttempt {
    observed: Option<ObservedOutput>,
    process_error: Option<String>,
}

fn redacted_console_output(observed: &ObservedOutput, credential: &str) -> (String, String) {
    (
        redact_exact(&String::from_utf8_lossy(&observed.stdout), credential),
        redact_exact(&String::from_utf8_lossy(&observed.stderr), credential),
    )
}

fn relay_observed_output(observed: &ObservedOutput, credential: &str) {
    let (stdout, stderr) = redacted_console_output(observed, credential);
    if !stdout.is_empty() {
        print!("{stdout}");
    }
    if !stderr.is_empty() {
        eprint!("{stderr}");
    }
}

fn run_cargo_publication(
    root: &Path,
    record: &CrateRecord,
    origin: CredentialOrigin,
    publication_slot: NonZeroUsize,
    credential: &str,
) -> Result<CargoPublicationAttempt> {
    let token = std::env::var_os(CRATES_IO_TOKEN_VARIABLE);
    require_registry_token(token.as_deref())?;
    let toolchains = config::toolchains(root)?;
    let cargo_config = cargo_publish_config(root, record, origin, publication_slot)?;
    let cargo_home = workflow_cargo_home()?;
    let publication = rustup_cargo(
        root,
        &toolchains.stable,
        [
            OsStr::new("--config"),
            cargo_config.as_os_str(),
            OsStr::new("publish"),
            OsStr::new("--locked"),
            OsStr::new("--no-verify"),
            OsStr::new("--registry"),
            OsStr::new("crates-io"),
            OsStr::new("--package"),
            OsStr::new(&record.name),
        ],
        RELEASE_DEADLINE,
    )
    .inherit_crates_io_registry_token()
    .output();
    for credentials in ["credentials", "credentials.toml"] {
        if cargo_home.join(credentials).exists() {
            return Err(failure(format!(
                "Cargo publication persisted forbidden {credentials}"
            )));
        }
    }
    match publication {
        Ok(observed) => {
            relay_observed_output(&observed, credential);
            Ok(CargoPublicationAttempt {
                observed: Some(observed),
                process_error: None,
            })
        }
        Err(error) => Ok(CargoPublicationAttempt {
            observed: None,
            process_error: Some(error.to_string()),
        }),
    }
}

fn publication_failure(attempt: &CargoPublicationAttempt, credential: &str) -> CiError {
    match (&attempt.observed, attempt.process_error.as_deref()) {
        (Some(observed), _) => {
            let stdout = String::from_utf8_lossy(&observed.stdout);
            let stderr = String::from_utf8_lossy(&observed.stderr);
            failure(format!(
                "cargo publish failed with {}; stdout={:?}; stderr={:?}",
                observed.status,
                redact_exact(&stdout, credential),
                redact_exact(&stderr, credential),
            ))
        }
        (None, Some(error)) => failure(redact_exact(error, credential)),
        (None, None) => failure("cargo publication attempt is unavailable"),
    }
}

fn attempt_stderr(attempt: &CargoPublicationAttempt) -> String {
    attempt
        .observed
        .as_ref()
        .map(|observed| String::from_utf8_lossy(&observed.stderr).into_owned())
        .or_else(|| attempt.process_error.as_deref().map(str::to_owned))
        .unwrap_or_default()
}

fn publication_context(root: &Path) -> Result<(config::Release, ReleaseManifest)> {
    let (release, manifest, _) = bundle_manifest(root)?;
    validate_release_event_context(&manifest.tag)?;
    Ok((release, manifest))
}

fn configured_publication_order(root: &Path, release: &config::Release) -> Result<Vec<String>> {
    let metadata = metadata(root)?;
    config::publish_order(&metadata, &release.publish_packages)
}

fn configured_slot_record(
    manifest: &ReleaseManifest,
    order: &[String],
    slot: NonZeroUsize,
) -> Result<CrateRecord> {
    let index = slot
        .get()
        .checked_sub(1)
        .filter(|index| *index < order.len())
        .ok_or_else(|| {
            failure(format!(
                "publication slot {slot} is outside the configured set"
            ))
        })?;
    Ok(manifest_record(manifest, &order[index])?.clone())
}

fn resolve_first_absent_slot(
    order: &[String],
    first_absent: Option<&str>,
    requested_slot: NonZeroUsize,
) -> Result<Option<usize>> {
    let Some(package) = first_absent else {
        return Ok(None);
    };
    let position = order
        .iter()
        .position(|name| name == package)
        .ok_or_else(|| failure(format!("release manifest lacks crate {package}")))?;
    let registry_slot = position + 1;
    if requested_slot.get() != registry_slot {
        return Err(failure(format!(
            "publication slot {requested_slot} does not select the first absent crate {package}; the registry selected slot {registry_slot}"
        )));
    }
    Ok(Some(position))
}

fn select_publication_slot(
    root: &Path,
    release: &config::Release,
    manifest: &ReleaseManifest,
    order: &[String],
    requested_slot: NonZeroUsize,
) -> Result<Option<CrateRecord>> {
    let scan = scan_registry_publication(release, &HttpEndpoints::production(), manifest, order)?;
    for package in &scan.public_names {
        let record = manifest_record(manifest, package)?;
        wait_for_public_crate(root, release, record, &release.registry_wait)?;
    }
    match resolve_first_absent_slot(order, scan.first_absent.as_deref(), requested_slot)? {
        None => Ok(None),
        Some(position) => Ok(Some(manifest_record(manifest, &order[position])?.clone())),
    }
}

fn require_fallback_profile(
    root: &Path,
    release: &config::Release,
    manifest: &ReleaseManifest,
) -> Result<()> {
    if release.registry_credentials.policy
        != config::RegistryCredentialPolicy::OidcFirstNewCrateFallback
    {
        return Err(failure(
            "new-crate fallback is unavailable under the current credential policy",
        ));
    }
    let workspace_version = workspace_version(root)?;
    config::validate_registry_credentials(release, &workspace_version)?;
    validate_dynamic_release_identity(&manifest.tag, &manifest.version, &workspace_version)?;
    Ok(())
}

fn slot_publication_identity(
    manifest: &ReleaseManifest,
    record: &CrateRecord,
) -> Result<(ReleaseBinding, PublicationRunIdentity, CrateBinding)> {
    Ok((
        ReleaseBinding::from_manifest(manifest),
        PublicationRunIdentity::from_environment()?,
        CrateBinding::from_record(record),
    ))
}

fn append_slot_record(
    root: &Path,
    release: &config::Release,
    slot: NonZeroUsize,
    record: PublicationAttemptRecord,
) -> Result<()> {
    append_publication_record(root, release, slot, record)
}

fn attempt_oidc_publication_at(root: &Path, publication_slot: NonZeroUsize) -> Result<()> {
    clear_slot_evidence(root, publication_slot)?;
    let (release, manifest) = publication_context(root)?;
    let order = configured_publication_order(root, &release)?;
    let record = configured_slot_record(&manifest, &order, publication_slot)?;
    let (release_binding, run, crate_binding) = slot_publication_identity(&manifest, &record)?;
    establish_slot_evidence(
        root,
        publication_slot,
        &release_binding,
        &run,
        &crate_binding,
    )?;
    let selected = select_publication_slot(root, &release, &manifest, &order, publication_slot)?;
    let Some(record) = selected else {
        append_slot_record(
            root,
            &release,
            publication_slot,
            publication_record(
                CredentialOrigin::Oidc,
                PublicationOutcome::AlreadyPublic,
                PublicNameState::NotChecked,
                None,
            ),
        )?;
        return Ok(());
    };

    let token = std::env::var_os(CRATES_IO_TOKEN_VARIABLE);
    require_registry_token(token.as_deref())?;
    let credential = token
        .clone()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| failure("registry capability is not valid Unicode"))?;
    let attempt = run_cargo_publication(
        root,
        &record,
        CredentialOrigin::Oidc,
        publication_slot,
        &credential,
    )?;
    let diagnostics = cargo_diagnostics(
        attempt.observed.as_ref(),
        attempt.process_error.as_deref(),
        &credential,
    )?;

    if attempt
        .observed
        .as_ref()
        .is_some_and(|observed| observed.status.success())
    {
        wait_for_public_crate(root, &release, &record, &release.registry_wait)?;
        append_slot_record(
            root,
            &release,
            publication_slot,
            publication_record(
                CredentialOrigin::Oidc,
                PublicationOutcome::OidcPubliclyAccepted,
                PublicNameState::NotChecked,
                Some(diagnostics),
            ),
        )?;
        return Ok(());
    }

    let state = crate_version_state(&release, &record.name, &record.version)?;
    match &state {
        CrateVersionLookup::Present(state)
            if !state.yanked && state.checksum == record.archive_sha256 =>
        {
            wait_for_public_crate(root, &release, &record, &release.registry_wait)?;
            append_slot_record(
                root,
                &release,
                publication_slot,
                publication_record(
                    CredentialOrigin::Oidc,
                    PublicationOutcome::OidcPubliclyAccepted,
                    PublicNameState::NotChecked,
                    Some(diagnostics),
                ),
            )?;
            return Ok(());
        }
        CrateVersionLookup::Present(state) => {
            append_slot_record(
                root,
                &release,
                publication_slot,
                publication_record(
                    CredentialOrigin::Oidc,
                    PublicationOutcome::OidcRejectedOther,
                    PublicNameState::NotChecked,
                    Some(diagnostics),
                ),
            )?;
            return Err(failure(format!(
                "public registry state conflicts with the failed OIDC publication: {} {} yanked={} checksum={}",
                record.name, record.version, state.yanked, state.checksum
            )));
        }
        CrateVersionLookup::Absent => {}
    }

    let failure_class = classify_oidc_failure(&attempt_stderr(&attempt), &record.name);
    let name_present = match failure_class {
        OidcFailureClass::Other => false,
        OidcFailureClass::TrustedPublishingNewCrate
        | OidcFailureClass::TrustedPublishingExistingCrate => {
            crate_name_exists(&release, &record.name)?
        }
    };
    match failure_class {
        OidcFailureClass::Other => {
            append_slot_record(
                root,
                &release,
                publication_slot,
                publication_record(
                    CredentialOrigin::Oidc,
                    PublicationOutcome::OidcRejectedOther,
                    PublicNameState::NotChecked,
                    Some(diagnostics),
                ),
            )?;
            Err(publication_failure(&attempt, &credential))
        }
        OidcFailureClass::TrustedPublishingNewCrate => {
            let (outcome, public_name_state) = if name_present {
                (
                    PublicationOutcome::NewCrateAuthorizationConflict,
                    PublicNameState::Present,
                )
            } else {
                (
                    PublicationOutcome::OidcRejectedNewCrate,
                    PublicNameState::Absent,
                )
            };
            append_slot_record(
                root,
                &release,
                publication_slot,
                publication_record(
                    CredentialOrigin::Oidc,
                    outcome,
                    public_name_state,
                    Some(diagnostics),
                ),
            )?;
            Err(publication_failure(&attempt, &credential))
        }
        OidcFailureClass::TrustedPublishingExistingCrate => {
            let (outcome, public_name_state) = if name_present {
                (
                    PublicationOutcome::OidcRejectedExistingCrate,
                    PublicNameState::Present,
                )
            } else {
                (
                    PublicationOutcome::OidcRejectedOther,
                    PublicNameState::NotChecked,
                )
            };
            append_slot_record(
                root,
                &release,
                publication_slot,
                publication_record(
                    CredentialOrigin::Oidc,
                    outcome,
                    public_name_state,
                    Some(diagnostics),
                ),
            )?;
            Err(publication_failure(&attempt, &credential))
        }
    }
}

fn authorize_new_crate_fallback_for_run(
    root: &Path,
    release: &config::Release,
    manifest: &ReleaseManifest,
    order: &[String],
    publication_slot: NonZeroUsize,
    run: &PublicationRunIdentity,
    github_output: Option<&Path>,
) -> Result<()> {
    let record = configured_slot_record(manifest, order, publication_slot)?;
    let release_binding = ReleaseBinding::from_manifest(manifest);
    let crate_binding = CrateBinding::from_record(&record);
    let evidence = load_slot_evidence(root, publication_slot)?;
    validate_slot_evidence_identity(
        &evidence,
        publication_slot,
        &release_binding,
        run,
        &crate_binding,
    )?;
    if evidence
        .records
        .iter()
        .any(|record| record.outcome == PublicationOutcome::OidcRejectedExistingCrate)
    {
        return Err(failure(format!(
            "publication slot {publication_slot} cannot use the new-crate fallback because crates.io rejected its OIDC access token for existing crate {}",
            record.name
        )));
    }
    if !evidence.records.iter().any(|record| {
        record.outcome == PublicationOutcome::OidcRejectedNewCrate
            && record.public_name_state == PublicNameState::Absent
    }) {
        return Err(failure(format!(
            "publication slot {publication_slot} lacks a new-crate-eligible OIDC rejection"
        )));
    }

    let conflict = |public_name_state| {
        publication_record(
            CredentialOrigin::Oidc,
            PublicationOutcome::NewCrateAuthorizationConflict,
            public_name_state,
            None,
        )
    };
    if crate_name_exists(release, &record.name)? {
        append_slot_record(
            root,
            release,
            publication_slot,
            conflict(PublicNameState::Present),
        )?;
        return Err(failure(format!(
            "crate name already exists, so slot {publication_slot} is not eligible for new-crate fallback: {}",
            record.name
        )));
    }
    if !matches!(
        crate_version_state(release, &record.name, &record.version)?,
        CrateVersionLookup::Absent
    ) {
        append_slot_record(
            root,
            release,
            publication_slot,
            conflict(PublicNameState::Absent),
        )?;
        return Err(failure(format!(
            "exact crate version appeared before fallback authorization: {} {}",
            record.name, record.version
        )));
    }

    append_slot_record(
        root,
        release,
        publication_slot,
        publication_record(
            CredentialOrigin::Oidc,
            PublicationOutcome::NewCrateAuthorized,
            PublicNameState::Absent,
            None,
        ),
    )?;
    if let Some(output) = github_output {
        let mut file = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(output)?;
        writeln!(file, "authorized=true")?;
    }
    Ok(())
}

fn authorize_new_crate_fallback_at(
    root: &Path,
    publication_slot: NonZeroUsize,
    github_output: Option<&Path>,
) -> Result<()> {
    let (release, manifest) = publication_context(root)?;
    require_fallback_profile(root, &release, &manifest)?;
    let order = configured_publication_order(root, &release)?;
    let run = PublicationRunIdentity::from_environment()?;
    authorize_new_crate_fallback_for_run(
        root,
        &release,
        &manifest,
        &order,
        publication_slot,
        &run,
        github_output,
    )
}

fn authorize_new_crate_fallback(root: &Path, publication_slot: NonZeroUsize) -> Result<()> {
    let output = std::env::var_os("GITHUB_OUTPUT")
        .map(PathBuf::from)
        .ok_or_else(|| failure("GITHUB_OUTPUT is absent for fallback authorization"))?;
    authorize_new_crate_fallback_at(root, publication_slot, Some(&output))
}

fn publish_token_fallback(root: &Path, publication_slot: NonZeroUsize) -> Result<()> {
    let (release, manifest) = publication_context(root)?;
    require_fallback_profile(root, &release, &manifest)?;
    let order = configured_publication_order(root, &release)?;
    let record = configured_slot_record(&manifest, &order, publication_slot)?;
    let (release_binding, run, crate_binding) = slot_publication_identity(&manifest, &record)?;
    let evidence = load_slot_evidence(root, publication_slot)?;
    validate_slot_evidence_identity(
        &evidence,
        publication_slot,
        &release_binding,
        &run,
        &crate_binding,
    )?;
    if !evidence_authorizes_token_provider(&evidence) {
        return Err(failure(format!(
            "publication slot {publication_slot} lacks fresh new-crate fallback authorization"
        )));
    }
    if !evidence_allows_new_token_attempt(&evidence) {
        return Err(failure(format!(
            "publication slot {publication_slot} already used its one new-crate token attempt"
        )));
    }

    let selected = select_publication_slot(root, &release, &manifest, &order, publication_slot)?;
    if selected.is_none() {
        append_slot_record(
            root,
            &release,
            publication_slot,
            publication_record(
                CredentialOrigin::NewCrateToken,
                PublicationOutcome::AlreadyPublic,
                PublicNameState::Absent,
                None,
            ),
        )?;
        return Ok(());
    }
    if crate_name_exists(&release, &record.name)? {
        append_slot_record(
            root,
            &release,
            publication_slot,
            publication_record(
                CredentialOrigin::NewCrateToken,
                PublicationOutcome::NewCrateAuthorizationConflict,
                PublicNameState::Present,
                None,
            ),
        )?;
        return Err(failure(format!(
            "crate name exists, so slot {publication_slot} can no longer create crate {}",
            record.name
        )));
    }

    let token = std::env::var_os(CRATES_IO_TOKEN_VARIABLE);
    require_registry_token(token.as_deref())?;
    let credential = token
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| failure("registry capability is not valid Unicode"))?;
    let attempt = run_cargo_publication(
        root,
        &record,
        CredentialOrigin::NewCrateToken,
        publication_slot,
        &credential,
    )?;
    let diagnostics = cargo_diagnostics(
        attempt.observed.as_ref(),
        attempt.process_error.as_deref(),
        &credential,
    );
    let diagnostics = match diagnostics {
        Ok(diagnostics) => Some(diagnostics),
        Err(error) => {
            append_slot_record(
                root,
                &release,
                publication_slot,
                publication_record(
                    CredentialOrigin::NewCrateToken,
                    PublicationOutcome::TokenRejected,
                    PublicNameState::Absent,
                    None,
                ),
            )?;
            return Err(error);
        }
    };

    let accepted = attempt
        .observed
        .as_ref()
        .is_some_and(|observed| observed.status.success())
        || matches!(
            crate_version_state(&release, &record.name, &record.version)?,
            CrateVersionLookup::Present(state)
                if !state.yanked && state.checksum == record.archive_sha256
        );
    if accepted {
        wait_for_public_crate(root, &release, &record, &release.registry_wait)?;
        append_slot_record(
            root,
            &release,
            publication_slot,
            publication_record(
                CredentialOrigin::NewCrateToken,
                PublicationOutcome::TokenPubliclyAccepted,
                PublicNameState::Absent,
                diagnostics,
            ),
        )?;
        return Ok(());
    }
    append_slot_record(
        root,
        &release,
        publication_slot,
        publication_record(
            CredentialOrigin::NewCrateToken,
            PublicationOutcome::TokenRejected,
            PublicNameState::Absent,
            diagnostics,
        ),
    )?;
    Err(publication_failure(&attempt, &credential))
}

fn verify_crates(root: &Path) -> Result<Vec<PublicCrateRecord>> {
    let (release, manifest, _) = bundle_manifest(root)?;
    let mut records = Vec::new();
    for record in &manifest.crates {
        records.push(wait_for_public_crate(
            root,
            &release,
            record,
            &release.registry_wait,
        )?);
    }
    records.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(records)
}

fn finalize_github(root: &Path) -> Result<()> {
    let token = github_token()?;
    let (release, manifest, output) = bundle_manifest(root)?;
    let endpoints = HttpEndpoints::production();
    let remote = github_release_at(root, Some(&token), &endpoints)?
        .ok_or_else(|| failure("GitHub draft is absent"))?;
    let state = classify_remote_release(
        &remote,
        &manifest.tag,
        &manifest.source_commit,
        manifest.prerelease,
    )?;
    if let RemoteReleaseState::Published(_) = state {
        let report_asset = remote
            .get("assets")
            .and_then(serde_json::Value::as_array)
            .and_then(|assets| {
                assets.iter().find(|asset| {
                    asset.get("name").and_then(serde_json::Value::as_str)
                        == Some(release.assets.publication_report.as_str())
                })
            })
            .ok_or_else(|| failure("published release lacks publication report"))?;
        let report_path = output.join(&release.assets.publication_report);
        download_github_asset(&release, report_asset, Some(&token), &report_path)?;
        return verify_public(root);
    }
    let RemoteReleaseState::Draft(release_id) = state else {
        unreachable!("published release returned above")
    };
    let static_paths = static_asset_paths(&release, &manifest, &output)?;
    let assets = public_asset_records(&release, &remote, &static_paths, &manifest.assets)?;
    let report = PublicationReport {
        schema_version: 2,
        manifest_sha256: sha256_file(&output.join(&release.assets.manifest))?,
        github_release_id: release_id,
        source_commit: manifest.source_commit.clone(),
        workflow_commit: manifest.workflow_commit.clone(),
        prerelease: manifest.prerelease,
        assets,
        crates: verify_crates(root)?,
    };
    let report_path = output.join(&release.assets.publication_report);
    write_json(&report_path, &report)?;
    let existing = remote
        .get("assets")
        .and_then(serde_json::Value::as_array)
        .and_then(|assets| {
            assets.iter().find(|asset| {
                asset.get("name").and_then(serde_json::Value::as_str)
                    == Some(release.assets.publication_report.as_str())
            })
        });
    if let Some(asset) = existing {
        if !asset_matches(asset, &report_path)? {
            return Err(failure("publication report conflicts with existing asset"));
        }
    } else {
        let uploaded = upload_or_reconcile_github_asset_at(
            root,
            &release,
            &endpoints,
            release_id,
            &token,
            &report_path,
        )?;
        if !asset_matches(&uploaded, &report_path)? {
            return Err(failure("publication report upload digest mismatch"));
        }
    }
    let refreshed = github_release_at(root, Some(&token), &endpoints)?
        .ok_or_else(|| failure("GitHub release disappeared during finalization"))?;
    if classify_remote_release(
        &refreshed,
        &manifest.tag,
        &manifest.source_commit,
        manifest.prerelease,
    )? != RemoteReleaseState::Draft(release_id)
    {
        return Err(failure("GitHub draft identity changed during finalization"));
    }
    let uploaded_report = refreshed
        .get("assets")
        .and_then(serde_json::Value::as_array)
        .and_then(|assets| {
            assets.iter().find(|asset| {
                asset.get("name").and_then(serde_json::Value::as_str)
                    == Some(release.assets.publication_report.as_str())
            })
        })
        .ok_or_else(|| failure("publication report asset is absent after upload"))?;
    if !asset_matches(uploaded_report, &report_path)? {
        return Err(failure("publication report public digest mismatch"));
    }
    let report_digest = sha256_file(&report_path)?;
    let notes = fs::read_to_string(output.join(&release.assets.notes))?;
    let body = format!("{notes}\nPublication report SHA-256: `{report_digest}`\n");
    let url = format!(
        "{}/repos/{}/releases/{release_id}",
        endpoints.github_api, release.repository
    );
    let publication = github_json_request(
        &release,
        &endpoints,
        "PATCH",
        &url,
        Some(&token),
        Some(serde_json::json!({
            "draft": false,
            "prerelease": manifest.prerelease,
            "make_latest": if manifest.prerelease { "false" } else { "true" },
            "body": body,
        })),
    );
    let mutation_error = match publication {
        Ok(_) => None,
        Err(error) if ambiguous_mutation_error(&error) => Some(error),
        Err(error) => return Err(error),
    };
    let published = wait_for_remote_state(&release.network_retry, || {
        let Some(remote) = github_release_at(root, Some(&token), &endpoints)? else {
            return Ok(None);
        };
        match classify_remote_release(
            &remote,
            &manifest.tag,
            &manifest.source_commit,
            manifest.prerelease,
        )? {
            RemoteReleaseState::Published(id) if id == release_id => Ok(Some(remote)),
            RemoteReleaseState::Draft(id) if id == release_id => Ok(None),
            _ => Err(failure("GitHub release identity changed after publication")),
        }
    })?;
    if published.is_none() {
        return Err(mutation_error
            .unwrap_or_else(|| failure("GitHub release publication classification differs")));
    }
    Ok(())
}

fn verify_public_workflow_provenance(
    root: &Path,
    release: &config::Release,
    manifest: &ReleaseManifest,
    identity: &ReleaseIdentity,
    endpoints: &HttpEndpoints,
) -> Result<()> {
    // The producer binds GitHub's exact-commit bytes. A checkout can have CRLF
    // conversion or other Git filters, so it is not the authoritative byte source.
    let (_, _, workflow_sha256, action_revisions) = workflow_provenance_at(
        root,
        identity,
        release,
        endpoints,
        &manifest.workflow_commit,
        &manifest.workflow_ref,
    )?;
    if manifest.workflow_sha256 != workflow_sha256 {
        return Err(failure(
            "release workflow digest differs from exact-commit bytes",
        ));
    }
    if manifest.action_revisions != action_revisions {
        return Err(failure("release action revisions differ"));
    }
    Ok(())
}

fn verify_public(root: &Path) -> Result<()> {
    // Every GitHub read shares this deadline, so sequential throttles cannot
    // each consume a fresh wait budget inside the 90-minute verification job.
    let endpoints = HttpEndpoints::production();
    let (release, manifest, output) = bundle_manifest(root)?;
    let remote = github_release_at(root, None, &endpoints)?
        .ok_or_else(|| failure("public GitHub release is absent"))?;
    if remote.get("draft").and_then(serde_json::Value::as_bool) != Some(false)
        || remote
            .get("target_commitish")
            .and_then(serde_json::Value::as_str)
            != Some(manifest.source_commit.as_str())
        || remote
            .get("prerelease")
            .and_then(serde_json::Value::as_bool)
            != Some(manifest.prerelease)
    {
        return Err(failure(
            "public GitHub release identity/classification mismatch",
        ));
    }
    let remote_assets = remote
        .get("assets")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| failure("public GitHub release has no asset array"))?;
    let report_asset = remote_assets
        .iter()
        .find(|asset| {
            asset.get("name").and_then(serde_json::Value::as_str)
                == Some(release.assets.publication_report.as_str())
        })
        .ok_or_else(|| failure("public publication report asset is missing"))?;
    let public_downloads = TempDir::new()?;
    let report_path = public_downloads
        .path()
        .join(&release.assets.publication_report);
    download_github_asset_at(&release, &endpoints, report_asset, None, &report_path)?;
    if !asset_matches(report_asset, &report_path)? {
        return Err(failure("public publication report digest differs"));
    }
    let report: PublicationReport = serde_json::from_slice(&fs::read(&report_path)?)?;
    let release_id = remote
        .get("id")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| failure("public release has no id"))?;
    let local_static_paths = static_asset_paths(&release, &manifest, &output)?;
    let mut static_paths = Vec::new();
    for local_path in local_static_paths {
        let name = local_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| failure("public asset name is not UTF-8"))?;
        let asset = remote_assets
            .iter()
            .find(|asset| asset.get("name").and_then(serde_json::Value::as_str) == Some(name))
            .ok_or_else(|| failure(format!("public asset is missing: {name}")))?;
        let destination = public_downloads.path().join(name);
        download_github_asset_at(&release, &endpoints, asset, None, &destination)?;
        if !asset_matches(asset, &destination)? {
            return Err(failure(format!("public asset digest differs: {name}")));
        }
        static_paths.push(destination);
    }
    memcordon_ci::release_evidence::validate_required_certification_records(
        &manifest.certification,
        &manifest.certification_origin,
        |path| {
            let name = Path::new(path)
                .file_name()
                .ok_or_else(|| failure("public certification has no filename"))?;
            memcordon_ci::release_evidence::read_report(&public_downloads.path().join(name))
        },
    )?;
    verify_standard_producers(
        &release,
        &endpoints,
        &manifest.certification_origin,
        |contract| {
            memcordon_ci::release_evidence::read_report(
                &public_downloads.path().join(contract.report_name),
            )
        },
    )?;
    let public_assets = public_asset_records(&release, &remote, &static_paths, &manifest.assets)?;
    let identity = ReleaseIdentity {
        tag: manifest.tag.clone(),
        version: Version::parse(&manifest.version)?,
        commit: manifest.source_commit.clone(),
        changelog_section: String::new(),
        source_date: manifest.source_date.clone(),
    };
    let host = config::release_target_id_for_host(std::env::consts::OS, std::env::consts::ARCH)?;
    for asset in &manifest.assets {
        let target = release
            .assets
            .target
            .iter()
            .find(|target| target.rust_target == asset.target)
            .ok_or_else(|| failure(format!("public asset target is unknown: {}", asset.target)))?;
        let archive = public_downloads.path().join(&asset.name);
        let inspection =
            inspect_extract_and_smoke(root, &archive, target, &identity, target.id == host)?;
        if inspection.runtime_manifest_sha256 != asset.runtime_manifest_sha256
            || inspection.components != asset.components
        {
            return Err(failure(format!(
                "public runtime inventory differs for {}",
                asset.name
            )));
        }
    }
    if report.schema_version != 2
        || report.manifest_sha256
            != sha256_file(&public_downloads.path().join(&release.assets.manifest))?
        || report.crates != verify_crates(root)?
        || report.github_release_id != release_id
        || report.source_commit != manifest.source_commit
        || report.workflow_commit != manifest.workflow_commit
        || report.prerelease != manifest.prerelease
        || report.assets != public_assets
    {
        return Err(failure("publication report does not match public state"));
    }
    let mut expected = static_paths;
    expected.push(report_path.clone());
    let expected_names: BTreeSet<&str> = expected
        .iter()
        .filter_map(|path| path.file_name().and_then(|name| name.to_str()))
        .collect();
    let actual_names: BTreeSet<&str> = remote_assets
        .iter()
        .filter_map(|asset| asset.get("name").and_then(serde_json::Value::as_str))
        .collect();
    if expected_names != actual_names {
        return Err(failure("public GitHub release asset set differs"));
    }
    for path in expected {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| failure("asset name is not UTF-8"))?;
        let asset = remote_assets
            .iter()
            .find(|asset| asset.get("name").and_then(serde_json::Value::as_str) == Some(name))
            .ok_or_else(|| failure(format!("public asset is missing: {name}")))?;
        if !asset_matches(asset, &path)? {
            return Err(failure(format!("public asset digest differs: {name}")));
        }
    }
    verify_public_workflow_provenance(root, &release, &manifest, &identity, &endpoints)?;
    let report_digest = sha256_file(&report_path)?;
    if !remote
        .get("body")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|body| body.contains(&report_digest))
    {
        return Err(failure("release notes do not bind the publication report"));
    }
    let checksum_text =
        fs::read_to_string(public_downloads.path().join(&release.assets.checksums))?;
    if !checksum_text.ends_with('\n') {
        return Err(failure("SHA256SUMS is not newline terminated"));
    }
    let expected_checksums: Vec<String> = manifest
        .assets
        .iter()
        .map(|asset| format!("{}  {}", asset.sha256, asset.name))
        .collect();
    let actual_checksums: Vec<&str> = checksum_text.lines().collect();
    if actual_checksums
        != expected_checksums
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    {
        return Err(failure("SHA256SUMS content/order differs"));
    }
    Ok(())
}

pub fn run(root: &Path, command: ReleaseCommand) -> Result<()> {
    match command {
        ReleaseCommand::Assemble => assemble(root),
        ReleaseCommand::StageGithub => stage_github(root),
        ReleaseCommand::AttemptOidc { publication_slot } => {
            attempt_oidc_publication_at(root, publication_slot)
        }
        ReleaseCommand::AuthorizeNewCrateFallback { publication_slot } => {
            authorize_new_crate_fallback(root, publication_slot)
        }
        ReleaseCommand::PublishTokenFallback { publication_slot } => {
            publish_token_fallback(root, publication_slot)
        }
        ReleaseCommand::VerifyCrates => verify_crates(root).map(|_| ()),
        ReleaseCommand::FinalizeGithub => finalize_github(root),
        ReleaseCommand::VerifyPublic => verify_public(root),
    }
}

#[cfg(test)]
#[path = "../tests/release/unit.rs"]
mod tests;
