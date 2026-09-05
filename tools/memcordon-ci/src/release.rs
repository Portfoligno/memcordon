use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use cargo_metadata::{Metadata, MetadataCommand};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use walkdir::WalkDir;

use memcordon_ci::capability;
use memcordon_ci::release_archive::{
    configured_default_cargo_binaries,
    validate_memcordon_crate_distribution as validate_reviewed_memcordon_distribution,
    validate_markdown_documents, NATIVE_ARCHIVE_STATIC_PATHS, RUNTIME_MANIFEST,
};
use memcordon_ci::release_evidence::{CertificationRecord, collect_certification};
use memcordon_ci::runtime_manifest::{RuntimeComponentRecord, RuntimeManifestV1, SealedRuntimeV1};

use crate::command::{CommandSpec, git, rustup_cargo};
use crate::config::{self, AssetTarget, RuntimeComponentRole, SealedAssetPolicy};
use crate::{CiError, ReleasePhase, Result};

const RELEASE_DEADLINE: Duration = Duration::from_secs(30 * 60);
const GITHUB_API_ROOT: &str = "https://api.github.com";
const GITHUB_UPLOADS_ROOT: &str = "https://uploads.github.com";
const CRATES_IO_API_ROOT: &str = "https://crates.io";
const GITHUB_RELEASES_PER_PAGE: usize = 100;
const CRATES_IO_TOKEN_VARIABLE: &str = "CARGO_REGISTRIES_CRATES_IO_TOKEN";

#[derive(Clone, Debug, Deserialize)]
struct CredentialRequest {
    v: u32,
    registry: CredentialRegistry,
    #[serde(default)]
    args: Vec<String>,
    #[serde(flatten)]
    action: CredentialAction,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum CredentialAction {
    Get {
        #[serde(flatten)]
        operation: CredentialOperation,
    },
    #[serde(other)]
    Unsupported,
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
    github_api: String,
    github_uploads: String,
    crates_io: String,
}

impl HttpEndpoints {
    fn production() -> Self {
        Self {
            github_api: GITHUB_API_ROOT.to_owned(),
            github_uploads: GITHUB_UPLOADS_ROOT.to_owned(),
            crates_io: CRATES_IO_API_ROOT.to_owned(),
        }
    }

    #[cfg(test)]
    fn fixed_test_server(root: &str) -> Self {
        Self {
            github_api: root.to_owned(),
            github_uploads: root.to_owned(),
            crates_io: root.to_owned(),
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

fn validate_registry_auth_context(tag: &str) -> Result<()> {
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

fn utf8(bytes: Vec<u8>, context: &str) -> Result<String> {
    String::from_utf8(bytes).map_err(|error| failure(format!("{context} is not UTF-8: {error}")))
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
    validate_release_version(&version)?;
    let metadata = metadata(root)?;
    let workspace_version = metadata
        .packages
        .iter()
        .find(|package| package.name.as_str() == "memcordon")
        .map(|package| package.version.clone())
        .ok_or_else(|| failure("workspace version is unavailable"))?;
    if workspace_version != version {
        return Err(failure(format!(
            "release tag/version mismatch: tag={version}, workspace={workspace_version}"
        )));
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
    validate_registry_auth_context(&tag)?;
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
        if crate_checksum(&release, &record.name, &record.version)?.is_some() {
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
        let normalized = normalized_member_path(&entry.path()?)?;
        if normalized.as_os_str().is_empty() {
            continue;
        }
        if matches!(
            normalized.to_str(),
            Some("Cargo.toml" | "Cargo.lock" | ".cargo_vcs_info.json")
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
        hash.update(path.to_string_lossy().as_bytes());
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
        let normalized = normalized_member_path(&entry.path()?)?;
        if normalized.as_os_str().is_empty() {
            continue;
        }
        let mode = entry.header().mode()?;
        let mut bytes = Vec::new();
        if kind.is_file() {
            entry.read_to_end(&mut bytes)?;
        }
        if normalized == Path::new("Cargo.toml") {
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
        } else if normalized == Path::new(".cargo_vcs_info.json") {
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
        hash.update(path.to_string_lossy().as_bytes());
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
        let relative = PathBuf::from(item);
        if relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(failure("Cargo package inventory contains an unsafe path"));
        }
        let package_path = package_root.as_std_path().join(&relative);
        let source = if relative == Path::new("Cargo.toml.orig") {
            package.manifest_path.as_std_path().to_path_buf()
        } else if package_path.is_file() {
            package_path
        } else if let Some(source) = relocated_manifest_source(
            package_root.as_std_path(),
            &relative,
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
        hash.update(path.to_string_lossy().as_bytes());
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
            target_desktop_bootstrap_crt_static,
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
                && *target_desktop_bootstrap_crt_static
                && !target_desktop_bootstrap_normal_imports.is_empty()
                && target_desktop_bootstrap_normal_imports.is_sorted()
                && target_desktop_bootstrap_delayed_imports.is_sorted()
                && valid_digest(target_desktop_bootstrap_loader_contract_sha256)
                && !session_broker_install_path.is_empty()
                && valid_digest(session_broker_sha256)
                && !state_root.is_empty()
                && control_service_sid_type == "restricted"
                && launcher_service_sid_type == "restricted"
                && session_broker_service_sid_type == "unrestricted"
                && guardian_slot_service_sid_type == "restricted"
                && !control_required_privileges.is_empty()
                && !launcher_required_privileges.is_empty()
                && session_broker_required_privileges
                    == &[
                        "SeAssignPrimaryTokenPrivilege",
                        "SeIncreaseQuotaPrivilege",
                        "SeTcbPrivilege",
                    ]
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
    if inspection.schema_version != 3
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

fn cargo_install_inventory(default_binaries: &BTreeSet<String>) -> BTreeSet<OsString> {
    default_binaries
        .iter()
        .map(|name| installed_binary_name(name))
        .collect()
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
    configuration.insert(
        "target".to_owned(),
        windows_static_crt_target_configuration(),
    );
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

fn windows_static_crt_target_configuration() -> toml::Value {
    let rustflags = || {
        toml::Value::Array(vec![
            toml::Value::String("-C".to_owned()),
            toml::Value::String("target-feature=+crt-static".to_owned()),
        ])
    };
    let mut targets = toml::Table::new();
    for target in ["x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"] {
        let mut specification = toml::Table::new();
        specification.insert("rustflags".to_owned(), rustflags());
        targets.insert(target.to_owned(), toml::Value::Table(specification));
    }
    toml::Value::Table(targets)
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
) -> RuntimeManifestV1 {
    let sealed = match (target.sealed, target.rust_target.contains("windows")) {
        (SealedAssetPolicy::Included, true) => SealedRuntimeV1::Included {
            agent_component: "sealed-agent".to_owned(),
            provider_protocol: 1,
            mechanism: "windows-job-object-v2".to_owned(),
            execution_report_schema: memcordon_core::EXECUTION_REPORT_SCHEMA_VERSION,
            plan_report_schema: memcordon_core::PLAN_REPORT_SCHEMA_VERSION,
            doctor_report_schema: memcordon_core::DOCTOR_REPORT_SCHEMA_VERSION,
            qualification_schema: memcordon_core::WINDOWS_QUALIFICATION_SCHEMA_VERSION,
        },
        (SealedAssetPolicy::Included, false) => SealedRuntimeV1::Included {
            agent_component: "sealed-agent".to_owned(),
            provider_protocol: 2,
            mechanism: "linux-pid-namespace-cgroup-v2".to_owned(),
            execution_report_schema: memcordon_core::EXECUTION_REPORT_SCHEMA_VERSION,
            plan_report_schema: memcordon_core::PLAN_REPORT_SCHEMA_VERSION,
            doctor_report_schema: memcordon_core::DOCTOR_REPORT_SCHEMA_VERSION,
            qualification_schema: 2,
        },
        (SealedAssetPolicy::NotApplicable, _) => SealedRuntimeV1::NotApplicable {
            reason: "the platform has no qualified packaged sealed provider".to_owned(),
        },
    };
    RuntimeManifestV1 {
        schema_version: 1,
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
    let mut extracted_files = BTreeSet::new();
    let mut archive_modes = BTreeMap::new();
    if target.archive == "zip" {
        let mut archive = zip::ZipArchive::new(File::open(archive_path)?)?;
        for index in 0..archive.len() {
            let mut entry = archive.by_index(index)?;
            let enclosed = entry
                .enclosed_name()
                .ok_or_else(|| failure("ZIP archive member escapes extraction root"))?;
            let relative = safe_archive_path(&enclosed)?;
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
                    relative.clone(),
                    entry
                        .unix_mode()
                        .ok_or_else(|| failure("ZIP archive member has no Unix mode"))?
                        & 0o7777,
                );
                extracted_files.insert(relative);
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
            let destination = temporary.path().join(&relative);
            if entry.header().entry_type().is_dir() {
                fs::create_dir_all(&destination)?;
            } else if entry.header().entry_type().is_file() {
                if let Some(parent) = destination.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut output = File::create(&destination)?;
                std::io::copy(&mut entry, &mut output)?;
                archive_modes.insert(relative.clone(), entry.header().mode()? & 0o7777);
                extracted_files.insert(relative);
            } else {
                return Err(failure("tar archive contains a non-file member"));
            }
        }
    }
    let top = PathBuf::from(format!(
        "memcordon-v{}-{}",
        identity.version, target.rust_target
    ));
    let mut expected = target
        .executable
        .iter()
        .map(|component| top.join(&component.archive_path))
        .collect::<BTreeSet<_>>();
    expected.insert(top.join(RUNTIME_MANIFEST));
    expected.extend(
        NATIVE_ARCHIVE_STATIC_PATHS
            .iter()
            .map(|relative| top.join(*relative)),
    );
    if extracted_files != expected {
        return Err(failure(format!(
            "release archive member set differs: expected={expected:?} actual={extracted_files:?}"
        )));
    }
    for component in &target.executable {
        let archive_path = top.join(&component.archive_path);
        if archive_modes.get(&archive_path) != Some(&component.mode) {
            return Err(failure(format!(
                "runtime component mode differs: {}",
                component.archive_path
            )));
        }
    }
    let manifest_path = temporary.path().join(&top).join(RUNTIME_MANIFEST);
    if archive_modes.get(&top.join(RUNTIME_MANIFEST)) != Some(&0o644) {
        return Err(failure("runtime manifest archive mode differs"));
    }
    let manifest_bytes = fs::read(&manifest_path)?;
    if !manifest_bytes.ends_with(b"\n") {
        return Err(failure("runtime manifest is not newline terminated"));
    }
    let manifest: RuntimeManifestV1 = serde_json::from_slice(&manifest_bytes)?;
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
    for path in &extracted_files {
        let relative = path
            .strip_prefix(&top)
            .map_err(|_| failure("release archive member is outside its top-level directory"))?;
        documents.insert(
            relative.to_path_buf(),
            fs::read(temporary.path().join(path))?,
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
    for path in &extracted_files {
        inventory.update(path.to_string_lossy().as_bytes());
        inventory.update([0]);
        inventory.update(
            archive_modes
                .get(path)
                .ok_or_else(|| failure("archive member mode is missing"))?
                .to_le_bytes(),
        );
        inventory.update(sha256_file(&temporary.path().join(path))?.as_bytes());
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
    let primary: Result<()> = (|| {
        privileged_agent(&["package", "install", "--ephemeral-ci"])?;
        smoke.provider_install = Some(true);
        privileged_agent(&["package", "verify", "--json"])?;
        smoke.provider_verify = Some(true);
        privileged_agent(&["qualify"])?;
        smoke.provider_qualification = Some(true);
        CommandSpec::new(cli, root, RELEASE_DEADLINE)
            .args(["doctor", "--require", "sealed"])
            .run()?;
        CommandSpec::new(cli, root, RELEASE_DEADLINE)
            .args(["--sealed", "--", "/usr/bin/true"])
            .run()?;
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
    verify_absent_paths([
        Path::new("/usr/libexec/memcordon-sealed-agent"),
        Path::new("/usr/lib/systemd/system/memcordon-sealed-agent.service"),
        Path::new("/usr/lib/systemd/system/memcordon-sealed-agent.socket"),
        Path::new("/usr/lib/systemd/system/memcordon-sealed-launcher.service"),
        Path::new("/usr/lib/systemd/system/memcordon-sealed-launcher.socket"),
        Path::new("/usr/lib/tmpfiles.d/memcordon.conf"),
        Path::new("/run/memcordon/sealed-agent.sock"),
        Path::new("/run/memcordon/sealed-launcher.sock"),
        Path::new("/run/memcordon/sealed-package.lock"),
        Path::new("/run/memcordon"),
        Path::new("/var/lib/memcordon/sealed"),
        Path::new("/sys/fs/cgroup/memcordon-sealed"),
    ])
}

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
        let executable = built_executable_path(root, target, component);
        verify_component_version(
            &executable,
            &component.binary,
            &identity.version.to_string(),
            root,
        )?;
        match component.role {
            RuntimeComponentRole::PublicCli => {
                CommandSpec::new(&executable, root, Duration::from_secs(30))
                    .args(["doctor", "--json"])
                    .run()?;
            }
            RuntimeComponentRole::SealedAgent => {
                CommandSpec::new(&executable, root, Duration::from_secs(30))
                    .args(["package", "inspect", "--json"])
                    .run()?;
            }
            RuntimeComponentRole::DesktopBootstrap => {
                let bytes = fs::read(&executable)?;
                memcordon_core::verify_target_desktop_bootstrap_pe(&bytes).map_err(failure)?;
            }
            RuntimeComponentRole::SessionBroker => {
                let bytes = fs::read(&executable)?;
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
        if report.schema_version != 2
            || report.tag != identity.tag
            || report.source_commit != identity.commit
            || report.asset != asset
            || !report.smoke.cli_version
            || !report.smoke.doctor
            || report.smoke.agent_version != expected_agent_smoke
            || report.smoke.agent_inspection != expected_agent_smoke
            || report.smoke.provider_install != expected_agent_smoke
            || report.smoke.provider_verify != expected_agent_smoke
            || report.smoke.provider_qualification != expected_agent_smoke
            || report.smoke.sealed_execution != expected_agent_smoke
            || report.smoke.provider_uninstall != expected_agent_smoke
            || report.archive_member_inventory_sha256 != inspection.archive_member_inventory_sha256
        {
            return Err(failure(format!(
                "native report identity differs for {}",
                target.id
            )));
        }
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
    let expected_ref_suffix = format!("@refs/tags/{}", identity.tag);
    if !workflow_ref.ends_with(&expected_ref_suffix) {
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
    let certification = collect_certification(
        &root.join("target").join("ci").join("release-inputs"),
        &output,
        &identity.commit,
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
    Ok((release, manifest, output))
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
        }
        .map_err(|error| CiError::Http(Box::new(error)))?;
        Ok(response)
    };
    let mut response = if method == "GET" {
        retry_transient(&release.network_retry, send)?
    } else {
        // Mutations are attempted exactly once. A transport failure or transient response can
        // mean the server committed the operation before the response was lost; callers must
        // re-read canonical remote state before deciding whether a rerun is safe.
        send()?
    };
    response
        .body_mut()
        .read_json()
        .map_err(|error| CiError::Http(Box::new(error)))
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
    retry_transient(&release.network_retry, || {
        let mut request = ureq::get(url)
            .header("Accept", accept)
            .header("X-GitHub-Api-Version", &release.github_api_version)
            .header("User-Agent", "memcordon-ci");
        if let Some(token) = token {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
        let mut response = request
            .call()
            .map_err(|error| CiError::Http(Box::new(error)))?;
        let mut bytes = Vec::new();
        response
            .body_mut()
            .as_reader()
            .take(maximum_bytes.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum_bytes {
            return Err(failure("GitHub response exceeds configured size policy"));
        }
        Ok(bytes)
    })
}

fn github_release(root: &Path, token: Option<&str>) -> Result<Option<serde_json::Value>> {
    github_release_at(root, token, &HttpEndpoints::production())
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
        Err(CiError::Http(error)) if matches!(*error, ureq::Error::StatusCode(404)) => Ok(None),
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
    let bytes = retry_transient(&release.network_retry, || {
        let mut request = ureq::get(url)
            .header("Accept", "application/octet-stream")
            .header("X-GitHub-Api-Version", &release.github_api_version)
            .header("User-Agent", "memcordon-ci");
        if let Some(authorization) = &authorization {
            request = request.header("Authorization", authorization);
        }
        let mut response = request
            .call()
            .map_err(|error| CiError::Http(Box::new(error)))?;
        let mut bytes = Vec::new();
        response
            .body_mut()
            .as_reader()
            .take(release.maximum_asset_bytes.saturating_add(1))
            .read_to_end(&mut bytes)?;
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
        .timeout_connect(Some(Duration::from_secs(15)))
        .timeout_recv_response(Some(Duration::from_secs(120)))
        .timeout_recv_body(Some(Duration::from_secs(120)))
        .build()
        .new_agent();
    let mut response = agent
        .post(&url)
        .query("name", name)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", &release.github_api_version)
        .header("User-Agent", "memcordon-ci")
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/octet-stream")
        .send(bytes.as_slice())
        .map_err(|error| CiError::Http(Box::new(error)))?;
    response
        .body_mut()
        .read_json()
        .map_err(|error| CiError::Http(Box::new(error)))
}

fn ambiguous_mutation_error(error: &CiError) -> bool {
    transient_network_error(error)
        || matches!(error, CiError::Io(_))
        || matches!(
            error,
            CiError::Http(inner)
                if matches!(inner.as_ref(), ureq::Error::StatusCode(409 | 422))
        )
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

fn crate_checksum(release: &config::Release, name: &str, version: &str) -> Result<Option<String>> {
    crate_checksum_at(release, &HttpEndpoints::production(), name, version)
}

#[cfg(test)]
fn crate_name_exists_at(
    release: &config::Release,
    endpoints: &HttpEndpoints,
    name: &str,
) -> Result<bool> {
    let url = format!("{}/api/v1/crates/{name}", endpoints.crates_io);
    let result = retry_transient(&release.network_retry, || {
        ureq::get(&url)
            .header("User-Agent", "memcordon-ci")
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

fn crate_checksum_at(
    release: &config::Release,
    endpoints: &HttpEndpoints,
    name: &str,
    version: &str,
) -> Result<Option<String>> {
    let url = format!("{}/api/v1/crates/{name}/{version}", endpoints.crates_io);
    let result = retry_transient(&release.network_retry, || {
        ureq::get(&url)
            .header("User-Agent", "memcordon-ci")
            .call()
            .map_err(|error| CiError::Http(Box::new(error)))
    });
    match result {
        Ok(mut response) => {
            let value: serde_json::Value = response
                .body_mut()
                .read_json()
                .map_err(|error| CiError::Http(Box::new(error)))?;
            Ok(value
                .get("version")
                .and_then(|version| version.get("checksum"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned))
        }
        Err(CiError::Http(error)) if matches!(*error, ureq::Error::StatusCode(404)) => Ok(None),
        Err(error) => Err(error),
    }
}

fn public_crate_archive(
    release: &config::Release,
    name: &str,
    version: &str,
    destination: &Path,
) -> Result<()> {
    public_crate_archive_at(
        release,
        &HttpEndpoints::production(),
        name,
        version,
        destination,
    )
}

fn public_crate_archive_at(
    release: &config::Release,
    endpoints: &HttpEndpoints,
    name: &str,
    version: &str,
    destination: &Path,
) -> Result<()> {
    let url = format!(
        "{}/api/v1/crates/{name}/{version}/download",
        endpoints.crates_io
    );
    let bytes = retry_transient(&release.network_retry, || {
        let mut response = ureq::get(&url)
            .header("User-Agent", "memcordon-ci")
            .call()
            .map_err(|error| CiError::Http(Box::new(error)))?;
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
    let checksum = crate_checksum(release, &record.name, &record.version)?.ok_or_else(|| {
        failure(format!(
            "crate is not public: {} {}",
            record.name, record.version
        ))
    })?;
    let temporary = TempDir::new()?;
    let archive = temporary.path().join("package.crate");
    public_crate_archive(release, &record.name, &record.version, &archive)?;
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
        match crate_checksum(release, &record.name, &record.version) {
            Ok(None) if started.elapsed() < total => {
                thread::sleep(delay);
                delay = delay.saturating_mul(2).min(maximum);
            }
            Ok(None) => {
                return Err(failure(format!(
                    "crate visibility retry budget expired: {} {}",
                    record.name, record.version
                )));
            }
            Ok(Some(_)) => {
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

fn require_registry_token(token: Option<&str>) -> Result<()> {
    if token.is_none_or(str::is_empty) {
        return Err(failure(format!(
            "{CRATES_IO_TOKEN_VARIABLE} is absent or empty for the selected publication slot"
        )));
    }
    Ok(())
}

fn cargo_publish_config(root: &Path, record: &CrateRecord) -> Result<PathBuf> {
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
                record.name.clone(),
                record.version.clone(),
                record.archive_sha256.clone(),
            ],
        },
    };
    let configuration_path =
        configuration_directory.join(PathBuf::from(&record.name).with_extension("toml"));
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

fn validate_credential_request(root: &Path, request: &CredentialRequest) -> Result<CrateRecord> {
    if request.v != 1
        || request.registry.name.as_deref() != Some("crates-io")
        || !matches!(
            request.registry.index_url.as_str(),
            "https://github.com/rust-lang/crates.io-index" | "sparse+https://index.crates.io/"
        )
    {
        return Err(failure("Cargo credential request identity is invalid"));
    }
    let [requested_name, requested_version, requested_archive_sha256] = request.args.as_slice()
    else {
        return Err(failure("Cargo credential request identity is invalid"));
    };
    let (_, manifest, _) = bundle_manifest(root)?;
    let record = manifest
        .crates
        .into_iter()
        .find(|record| {
            record.name == requested_name.as_str() && record.version == requested_version.as_str()
        })
        .ok_or_else(|| failure("Cargo credential request is absent from the release manifest"))?;
    if requested_archive_sha256.as_str() != record.archive_sha256 {
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
        | CredentialAction::Unsupported => {
            return Err(failure("Cargo credential operation is unsupported"));
        }
    }
    Ok(record)
}

fn credential_response(
    root: &Path,
    request: serde_json::Result<CredentialRequest>,
    token: Option<&str>,
) -> serde_json::Value {
    match request {
        Ok(request)
            if matches!(
                &request.action,
                CredentialAction::Get {
                    operation: CredentialOperation::Unsupported
                } | CredentialAction::Unsupported
            ) =>
        {
            credential_operation_unsupported()
        }
        Ok(request) => match validate_credential_request(root, &request) {
            Ok(_) => match token {
                Some(token) if !token.is_empty() => serde_json::json!({
                    "Ok": {
                        "kind": "get",
                        "token": token,
                        "cache": "never",
                        "operation_independent": false,
                    }
                }),
                _ => credential_request_error("trusted-publishing capability is absent"),
            },
            Err(error) => credential_request_error(error.to_string()),
        },
        Err(_) => credential_request_error("Cargo credential request is malformed"),
    }
}

fn cargo_credential_provider_io(
    root: &Path,
    input: impl BufRead,
    mut output: impl Write,
    token: Option<&str>,
) -> Result<()> {
    serde_json::to_writer(&mut output, &serde_json::json!({ "v": [1] }))?;
    writeln!(output)?;
    output.flush()?;

    let mut input = input;
    let mut line = String::new();
    if input.read_line(&mut line)? == 0 {
        return Err(failure("Cargo credential provider received no request"));
    }
    let request = serde_json::from_str::<CredentialRequest>(line.trim_end());
    let response = credential_response(root, request, token);
    serde_json::to_writer(&mut output, &response)?;
    writeln!(output)?;
    output.flush()?;
    Ok(())
}

pub fn cargo_credential_provider(root: &Path) -> Result<()> {
    let token = std::env::var(CRATES_IO_TOKEN_VARIABLE).ok();
    cargo_credential_provider_io(
        root,
        BufReader::new(std::io::stdin().lock()),
        std::io::stdout().lock(),
        token.as_deref(),
    )
}

fn reconcile_publication_result(
    publication: Result<Vec<u8>>,
    publicly_visible: bool,
) -> Result<()> {
    match publication {
        Ok(_) => Ok(()),
        Err(_) if publicly_visible => Ok(()),
        Err(error) => Err(error),
    }
}

fn publish_next(root: &Path) -> Result<()> {
    let token = std::env::var(CRATES_IO_TOKEN_VARIABLE).ok();
    require_registry_token(token.as_deref())?;
    let (release, manifest, _) = bundle_manifest(root)?;
    let metadata = metadata(root)?;
    let order = config::publish_order(&metadata, &release.publish_packages)?;
    let mut next_absent = None;
    for package in &order {
        let record = manifest
            .crates
            .iter()
            .find(|record| record.name == *package)
            .ok_or_else(|| failure(format!("release manifest lacks crate {package}")))?;
        if crate_checksum(&release, &record.name, &record.version)?.is_some() {
            wait_for_public_crate(root, &release, record, &release.registry_wait)?;
        } else if next_absent.is_none() {
            next_absent = Some(package.as_str());
        }
    }
    if let Some(package) = next_absent {
        let record = manifest
            .crates
            .iter()
            .find(|record| record.name == package)
            .ok_or_else(|| failure(format!("release manifest lacks crate {package}")))?;
        let toolchains = config::toolchains(root)?;
        let cargo_config = cargo_publish_config(root, record)?;
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
                OsStr::new(package),
            ],
            RELEASE_DEADLINE,
        )
        .inherit_workflow_registry_credentials()
        .run();
        for credentials in ["credentials", "credentials.toml"] {
            if cargo_home.join(credentials).exists() {
                return Err(failure(format!(
                    "Cargo publication persisted forbidden {credentials}"
                )));
            }
        }
        let publicly_visible = if publication.is_err() {
            crate_checksum(&release, &record.name, &record.version)?.is_some()
        } else {
            false
        };
        reconcile_publication_result(publication, publicly_visible)?;
        wait_for_public_crate(root, &release, record, &release.registry_wait)?;
    }
    Ok(())
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

fn verify_public(root: &Path) -> Result<()> {
    let (release, manifest, output) = bundle_manifest(root)?;
    let remote =
        github_release(root, None)?.ok_or_else(|| failure("public GitHub release is absent"))?;
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
    download_github_asset(&release, report_asset, None, &report_path)?;
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
        download_github_asset(&release, asset, None, &destination)?;
        if !asset_matches(asset, &destination)? {
            return Err(failure(format!("public asset digest differs: {name}")));
        }
        static_paths.push(destination);
    }
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
    let workflow_path = root
        .join(".github")
        .join("workflows")
        .join(&release.workflow);
    if manifest.workflow_sha256 != sha256_file(&workflow_path)?
        || manifest.action_revisions
            != config::action_pins(root)?
                .action
                .into_iter()
                .map(|pin| (pin.name, pin.uses))
                .collect()
    {
        return Err(failure("release workflow/action provenance differs"));
    }
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

pub fn run(root: &Path, phase: ReleasePhase) -> Result<()> {
    match phase {
        ReleasePhase::Assemble => assemble(root),
        ReleasePhase::StageGithub => stage_github(root),
        ReleasePhase::PublishNext => publish_next(root),
        ReleasePhase::VerifyCrates => verify_crates(root).map(|_| ()),
        ReleasePhase::FinalizeGithub => finalize_github(root),
        ReleasePhase::VerifyPublic => verify_public(root),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::io::{BufRead, BufReader, Cursor};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};

    fn package_inspection_fixture() -> serde_json::Value {
        let digest = sha256_bytes(b"package-inspection-fixture");
        serde_json::json!({
            "schema_version": 3,
            "version": "1.2.3",
            "source_commit": "source-commit",
            "executable_sha256": digest,
            "provider_protocol": 2,
            "mechanism": "linux-pid-namespace-cgroup-v2",
            "platform": "linux-systemd",
            "execution_report_schema": memcordon_core::EXECUTION_REPORT_SCHEMA_VERSION,
            "plan_report_schema": memcordon_core::PLAN_REPORT_SCHEMA_VERSION,
            "doctor_report_schema": memcordon_core::DOCTOR_REPORT_SCHEMA_VERSION,
            "control_service_sha256": digest,
            "control_socket_sha256": digest,
            "launcher_service_sha256": digest,
            "launcher_socket_sha256": digest,
            "tmpfiles_sha256": digest,
            "compiled_metadata_valid": true
        })
    }

    #[test]
    fn windows_runtime_manifest_uses_shared_qualification_schema() {
        let (_temporary, release) = release_fixture();
        let target = release
            .assets
            .target
            .iter()
            .find(|target| target.rust_target == "x86_64-pc-windows-msvc")
            .expect("release policy should contain the Windows x64 target");
        let identity = ReleaseIdentity {
            tag: "1.2.3".to_owned(),
            version: Version::parse("1.2.3").expect("version should parse"),
            commit: "0123456789abcdef".to_owned(),
            changelog_section: "notes".to_owned(),
            source_date: "2025-01-01T00:00:00Z".to_owned(),
        };
        let manifest = runtime_manifest(&identity, target, Vec::new());
        let SealedRuntimeV1::Included {
            qualification_schema,
            ..
        } = manifest.sealed
        else {
            panic!("Windows release target should include its sealed provider");
        };
        assert_eq!(
            qualification_schema,
            memcordon_core::WINDOWS_QUALIFICATION_SCHEMA_VERSION
        );
    }

    #[test]
    fn package_inspection_binds_version_source_commit_and_sha256_fields() {
        let canonical = package_inspection_fixture();
        validate_agent_package_inspection(
            &serde_json::to_vec(&canonical).unwrap(),
            "1.2.3",
            "source-commit",
        )
        .expect("canonical package inspection should validate");

        let mut wrong_commit = canonical.clone();
        wrong_commit["source_commit"] = serde_json::json!("different-commit");
        assert!(
            validate_agent_package_inspection(
                &serde_json::to_vec(&wrong_commit).unwrap(),
                "1.2.3",
                "source-commit",
            )
            .is_err()
        );

        let mut invalid_digest = canonical.clone();
        invalid_digest["executable_sha256"] = serde_json::json!("not-a-sha256");
        assert!(
            validate_agent_package_inspection(
                &serde_json::to_vec(&invalid_digest).unwrap(),
                "1.2.3",
                "source-commit",
            )
            .is_err()
        );

        let mut unknown_field = canonical;
        unknown_field["future_field"] = serde_json::json!(true);
        assert!(
            validate_agent_package_inspection(
                &serde_json::to_vec(&unknown_field).unwrap(),
                "1.2.3",
                "source-commit",
            )
            .is_err()
        );
    }

    #[test]
    fn provider_uninstall_proof_rejects_every_residual_path() {
        let temporary = TempDir::new().expect("temporary directory should exist");
        let artifact = temporary.path().join("installed-agent");
        let endpoint = temporary.path().join("sealed-agent.sock");
        let state = temporary.path().join("state");
        fs::write(&artifact, b"agent").expect("artifact should write");
        fs::write(&endpoint, b"endpoint").expect("endpoint should write");
        fs::create_dir(&state).expect("state directory should exist");
        for residual in [&artifact, &endpoint, &state] {
            assert!(verify_absent_paths([residual.as_path()]).is_err());
        }
        fs::remove_file(&artifact).unwrap();
        fs::remove_file(&endpoint).unwrap();
        fs::remove_dir(&state).unwrap();
        verify_absent_paths([artifact.as_path(), endpoint.as_path(), state.as_path()])
            .expect("complete uninstall inventory should be absent");
    }

    #[test]
    fn canonical_source_tree_resolves_relocated_manifest_readme() {
        let temporary = TempDir::new().expect("temporary workspace should exist");
        let root = temporary.path();
        let package_root = root.join("crates/example");
        let manifest = b"[package]\nname = \"example\"\nversion = \"0.1.0\"\nedition = \"2024\"\nreadme = \"../../docs/package-readme.md\"\n";
        let readme = b"# Example package\n";
        let source = b"pub fn example() {}\n";
        fs::create_dir_all(package_root.join("src"))
            .expect("package source directory should exist");
        fs::create_dir_all(root.join("docs")).expect("documentation directory should exist");
        fs::write(
            root.join("Cargo.toml"),
            b"[workspace]\nmembers = [\"crates/example\"]\nresolver = \"2\"\n",
        )
        .expect("workspace manifest should write");
        fs::write(package_root.join("Cargo.toml"), manifest)
            .expect("package manifest should write");
        fs::write(root.join("docs/package-readme.md"), readme)
            .expect("external package README should write");
        fs::write(package_root.join("src/lib.rs"), source).expect("package source should write");

        let inventory = "Cargo.toml\nCargo.toml.orig\npackage-readme.md\nsrc/lib.rs\n";
        let actual = canonical_source_tree(root, "example", inventory)
            .expect("relocated package README should resolve to its manifest source");
        let expected_members = BTreeMap::from([
            (PathBuf::from("Cargo.toml.orig"), manifest.as_slice()),
            (PathBuf::from("package-readme.md"), readme.as_slice()),
            (PathBuf::from("src/lib.rs"), source.as_slice()),
        ]);
        let mut expected = Sha256::new();
        for (path, bytes) in expected_members {
            expected.update(path.to_string_lossy().as_bytes());
            expected.update([0]);
            expected.update(0o644_u32.to_le_bytes());
            expected.update((bytes.len() as u64).to_le_bytes());
            expected.update(bytes);
        }
        assert_eq!(actual, hex::encode(expected.finalize()));

        let missing = canonical_source_tree(root, "example", "unrelated.md\n")
            .expect_err("unrelated inventory paths must not use workspace-root files");
        assert_eq!(
            missing.to_string(),
            "Cargo package inventory source is missing: \"unrelated.md\""
        );

        fs::remove_file(root.join("docs/package-readme.md"))
            .expect("external package README should be removable");
        let missing_readme = relocated_manifest_source(
            &package_root,
            Path::new("package-readme.md"),
            [("README", Some(Path::new("../../docs/package-readme.md")))],
        )
        .expect_err("missing declared README source must fail closed");
        assert_eq!(
            missing_readme.to_string(),
            "package README source is missing: \"../../docs/package-readme.md\""
        );
    }

    enum MockResponse {
        Json(u16, serde_json::Value),
        Bytes(u16, Vec<u8>),
        Truncated(Vec<u8>, usize),
        LoseResponse,
    }

    struct MockServer {
        root: String,
        requests: Arc<Mutex<Vec<String>>>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl MockServer {
        fn scripted(responses: Vec<MockResponse>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("mock listener should bind");
            let root = format!(
                "http://{}",
                listener
                    .local_addr()
                    .expect("mock listener should have an address")
            );
            let requests = Arc::new(Mutex::new(Vec::new()));
            let observed = Arc::clone(&requests);
            let thread = std::thread::spawn(move || {
                for response in responses {
                    let (mut stream, _) = listener.accept().expect("mock request should arrive");
                    let request = read_request(&mut stream);
                    observed.lock().expect("request log lock").push(request);
                    match response {
                        MockResponse::Json(status, value) => {
                            write_response(
                                &mut stream,
                                status,
                                "application/json",
                                &serde_json::to_vec(&value).expect("mock JSON should serialize"),
                            );
                        }
                        MockResponse::Bytes(status, bytes) => {
                            write_response(&mut stream, status, "application/octet-stream", &bytes);
                        }
                        MockResponse::Truncated(bytes, declared_length) => {
                            write!(
                                stream,
                                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {declared_length}\r\nConnection: close\r\n\r\n"
                            )
                            .expect("truncated mock headers should write");
                            stream
                                .write_all(&bytes)
                                .expect("truncated mock body should write");
                        }
                        MockResponse::LoseResponse => {}
                    }
                }
            });
            Self {
                root,
                requests,
                thread: Some(thread),
            }
        }

        fn finish(mut self) -> Vec<String> {
            self.thread
                .take()
                .expect("mock thread should exist")
                .join()
                .expect("mock thread should finish");
            Arc::try_unwrap(self.requests)
                .expect("request log should have one owner")
                .into_inner()
                .expect("request log lock")
        }
    }

    fn read_request(stream: &mut TcpStream) -> String {
        let mut reader = BufReader::new(stream);
        let mut first = String::new();
        reader
            .read_line(&mut first)
            .expect("request line should be readable");
        let mut request = first;
        let mut content_length = 0_usize;
        loop {
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("request header should be readable");
            if line == "\r\n" || line.is_empty() {
                break;
            }
            request.push_str(&line);
            if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                content_length = value.trim().parse().expect("content length should parse");
            }
        }
        let mut body = vec![0_u8; content_length];
        reader
            .read_exact(&mut body)
            .expect("request body should be readable");
        request.push_str(&String::from_utf8_lossy(&body));
        request
    }

    fn write_response(stream: &mut TcpStream, status: u16, content_type: &str, body: &[u8]) {
        let reason = match status {
            200 => "OK",
            201 => "Created",
            404 => "Not Found",
            409 => "Conflict",
            422 => "Unprocessable Entity",
            500 => "Internal Server Error",
            503 => "Service Unavailable",
            _ => "Mock",
        };
        write!(
            stream,
            "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .expect("mock headers should write");
        stream.write_all(body).expect("mock body should write");
    }

    fn request_json_body(request: &str) -> serde_json::Value {
        let start = request
            .find('{')
            .expect("JSON request should contain an object body");
        serde_json::from_str(&request[start..]).expect("request JSON should parse")
    }

    fn release_fixture() -> (TempDir, config::Release) {
        let temporary = TempDir::new().expect("temporary repository should exist");
        let root = temporary.path();
        fs::create_dir_all(root.join("ci")).expect("CI directory should exist");
        fs::write(
            root.join("ci/release.toml"),
            include_bytes!("../../../ci/release.toml"),
        )
        .expect("release config should be copied");
        let release = config::release(root).expect("release config should parse");
        let output = root.join(&release.assets.output_directory);
        fs::create_dir_all(&output).expect("release output should exist");
        let manifest = ReleaseManifest {
            schema_version: config::RELEASE_SCHEMA_VERSION,
            project: "memcordon".to_owned(),
            tag: "1.2.3".to_owned(),
            version: "1.2.3".to_owned(),
            source_commit: "0123456789abcdef".to_owned(),
            workflow_commit: "0123456789abcdef".to_owned(),
            workflow_ref: "Portfoligno/memcordon/.github/workflows/release.yml@refs/tags/1.2.3"
                .to_owned(),
            workflow_sha256: "00".repeat(32),
            action_revisions: BTreeMap::new(),
            prerelease: false,
            rust_toolchain: "1.85.0".to_owned(),
            assets: Vec::new(),
            crates: Vec::new(),
            certification: BTreeMap::new(),
            source_date: "2025-01-01T00:00:00Z".to_owned(),
        };
        write_json(&output.join(&release.assets.manifest), &manifest)
            .expect("manifest should write");
        fs::write(output.join(&release.assets.notes), "notes\n").expect("notes should write");
        (temporary, release)
    }

    fn provenance_fixture() -> (TempDir, config::Release, ReleaseIdentity) {
        let (temporary, release) = release_fixture();
        let root = temporary.path();
        fs::create_dir_all(root.join(".github/workflows"))
            .expect("workflow directory should exist");
        fs::write(
            root.join("ci/policy.toml"),
            include_bytes!("../../../ci/policy.toml"),
        )
        .expect("policy should be copied");
        fs::write(
            root.join("ci/toolchains.toml"),
            include_bytes!("../../../ci/toolchains.toml"),
        )
        .expect("toolchain policy should be copied");
        fs::write(
            root.join(".github/action-pins.toml"),
            include_bytes!("../../../.github/action-pins.toml"),
        )
        .expect("action pins should be copied");
        let identity = ReleaseIdentity {
            tag: "1.2.3".to_owned(),
            version: Version::parse("1.2.3").expect("version should parse"),
            commit: "0123456789abcdef".to_owned(),
            changelog_section: "notes".to_owned(),
            source_date: "2025-01-01T00:00:00Z".to_owned(),
        };
        (temporary, release, identity)
    }

    #[test]
    fn workflow_event_deserialization_rejects_retired_dispatch_inputs() {
        let steady: WorkflowEvent =
            serde_json::from_str(r#"{"inputs":{"tag":"0.2.0"},"repository":{"private":false}}"#)
                .expect("steady-state dispatch payload should parse");
        assert_eq!(steady.inputs.expect("dispatch inputs").tag, "0.2.0");
        assert!(
            serde_json::from_str::<WorkflowEvent>(
                r#"{"inputs":{"tag":"0.1.0","registry_auth":"unknown"}}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<WorkflowEvent>(
                r#"{"inputs":{"tag":"0.1.0","registry_auth":"stored-token","extra":"forbidden"}}"#
            )
            .is_err()
        );
    }

    #[test]
    fn publication_slot_requires_a_nonempty_source_agnostic_token() {
        assert!(require_registry_token(None).is_err());
        assert!(require_registry_token(Some("")).is_err());
        require_registry_token(Some("opaque-test-capability"))
            .expect("any nonempty credential source is accepted");
    }

    #[test]
    fn credential_provider_accepts_bound_read_and_publish_requests() {
        let (temporary, release) = release_fixture();
        let manifest_path = temporary
            .path()
            .join(&release.assets.output_directory)
            .join(&release.assets.manifest);
        let mut manifest: ReleaseManifest =
            serde_json::from_slice(&fs::read(&manifest_path).expect("manifest should read"))
                .expect("manifest should parse");
        let record = CrateRecord {
            name: "memcordon-core".to_owned(),
            version: "1.2.3".to_owned(),
            archive_sha256: "ab".repeat(32),
            canonical_tree_sha256: "cd".repeat(32),
            canonical_identity_sha256: "ef".repeat(32),
            vcs_commit: manifest.source_commit.clone(),
        };
        manifest.crates.push(record.clone());
        write_json(&manifest_path, &manifest).expect("manifest should update");
        let arguments = serde_json::json!([
            record.name.clone(),
            record.version.clone(),
            record.archive_sha256.clone(),
        ]);
        let read_message = serde_json::json!({
            "v": 1,
            "registry": {
                "index-url": "sparse+https://index.crates.io/",
                "name": "crates-io",
                "headers": ["WWW-Authenticate: Cargo login_url=https://crates.io/me"],
            },
            "kind": "get",
            "operation": "read",
            "args": arguments.clone(),
        });
        let read_request: CredentialRequest = serde_json::from_value(read_message.clone())
            .expect("Cargo read request without publish fields should parse");
        validate_credential_request(temporary.path(), &read_request)
            .expect("bound read request should pass");

        let mut read_output = Vec::new();
        let mut read_wire = serde_json::to_vec(&read_message).expect("read request should encode");
        read_wire.push(b'\n');
        cargo_credential_provider_io(
            temporary.path(),
            Cursor::new(read_wire),
            &mut read_output,
            Some("opaque-test-capability"),
        )
        .expect("Cargo read transcript should complete");
        let read_lines: Vec<serde_json::Value> = read_output
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).expect("provider output should be JSON"))
            .collect();
        assert_eq!(read_lines[0], serde_json::json!({ "v": [1] }));
        assert_eq!(read_lines[1]["Ok"]["kind"], "get");
        assert_eq!(read_lines[1]["Ok"]["cache"], "never");
        assert_eq!(read_lines[1]["Ok"]["operation_independent"], false);
        assert_eq!(read_lines[1]["Ok"]["token"], "opaque-test-capability");

        let publish_message = serde_json::json!({
            "v": 1,
            "registry": {
                "index-url": "sparse+https://index.crates.io/",
                "name": "crates-io",
            },
            "kind": "get",
            "operation": "publish",
            "name": record.name.clone(),
            "vers": record.version.clone(),
            "cksum": record.archive_sha256.clone(),
            "args": arguments.clone(),
        });
        let publish_request: CredentialRequest =
            serde_json::from_value(publish_message).expect("Cargo publish request should parse");
        validate_credential_request(temporary.path(), &publish_request)
            .expect("exact publish request should pass");
        let accepted = credential_response(
            temporary.path(),
            Ok(publish_request.clone()),
            Some("opaque-test-capability"),
        );
        assert_eq!(accepted["Ok"]["kind"], "get");
        assert_eq!(accepted["Ok"]["cache"], "never");
        assert_eq!(accepted["Ok"]["operation_independent"], false);
        assert_eq!(accepted["Ok"]["token"], "opaque-test-capability");
        let missing = credential_response(temporary.path(), Ok(publish_request.clone()), None);
        assert_eq!(missing["Err"]["kind"], "other");

        let mut missing_args = read_message;
        missing_args
            .as_object_mut()
            .expect("request should be an object")
            .remove("args");
        let missing_args = serde_json::from_value::<CredentialRequest>(missing_args)
            .expect("Cargo request may omit empty args");
        let missing_args = credential_response(
            temporary.path(),
            Ok(missing_args),
            Some("opaque-test-capability"),
        );
        assert_eq!(missing_args["Err"]["kind"], "other");
        assert_eq!(
            missing_args["Err"]["message"],
            "Cargo credential request identity is invalid"
        );

        let unsupported: CredentialRequest = serde_json::from_value(serde_json::json!({
            "v": 1,
            "registry": {
                "index-url": "sparse+https://index.crates.io/",
                "name": "crates-io",
            },
            "kind": "get",
            "operation": "yank",
            "args": arguments,
        }))
        .expect("unsupported Cargo operation should still parse");
        let unsupported = credential_response(
            temporary.path(),
            Ok(unsupported),
            Some("opaque-test-capability"),
        );
        assert_eq!(unsupported["Err"]["kind"], "operation-not-supported");

        let malformed = credential_response(
            temporary.path(),
            serde_json::from_str::<CredentialRequest>("not JSON"),
            Some("opaque-test-capability"),
        );
        assert_eq!(malformed["Err"]["kind"], "other");
        assert_eq!(
            malformed["Err"]["message"],
            "Cargo credential request is malformed"
        );

        let cargo_config = cargo_publish_config(temporary.path(), &record)
            .expect("isolated Cargo configuration should be prepared");
        let provider_config = fs::read_to_string(cargo_config).expect("config should read");
        assert!(!provider_config.contains("opaque-test-capability"));
        let provider_config: toml::Value =
            toml::from_str(&provider_config).expect("config should parse");
        let provider = provider_config["registry"]["credential-provider"]
            .as_array()
            .expect("provider should be an argv array");
        assert_eq!(provider.len(), 4);
        assert_eq!(provider[1].as_str(), Some(record.name.as_str()));
        assert_eq!(provider[2].as_str(), Some(record.version.as_str()));
        assert_eq!(provider[3].as_str(), Some(record.archive_sha256.as_str()));

        let mut wrong_checksum = publish_request;
        let CredentialAction::Get {
            operation: CredentialOperation::Publish { cksum, .. },
        } = &mut wrong_checksum.action
        else {
            panic!("publish request should retain its operation");
        };
        *cksum = "00".repeat(32);
        assert!(validate_credential_request(temporary.path(), &wrong_checksum).is_err());
    }

    #[test]
    fn ambiguous_publish_response_reconciles_public_acceptance_before_retry() {
        let lost_response = Err(failure("connection lost after acceptance"));
        reconcile_publication_result(lost_response, true)
            .expect("public acceptance should reconcile an ambiguous client failure");
        let rejected = Err(failure("publication rejected"));
        assert!(reconcile_publication_result(rejected, false).is_err());
        reconcile_publication_result(Ok(Vec::new()), false)
            .expect("acknowledged publication should succeed");
    }

    #[test]
    fn immutable_publication_report_has_no_credential_origin() {
        let report = PublicationReport {
            schema_version: 2,
            manifest_sha256: "digest".to_owned(),
            github_release_id: 7,
            source_commit: "commit".to_owned(),
            workflow_commit: "workflow".to_owned(),
            prerelease: false,
            assets: Vec::new(),
            crates: Vec::new(),
        };
        let bytes = serde_json::to_vec(&report).expect("report should serialize");
        let text = std::str::from_utf8(&bytes).expect("report should be UTF-8");
        for forbidden in ["token", "credential", "registry_auth"] {
            assert!(!text.contains(forbidden));
        }
    }

    fn remote(draft: bool) -> serde_json::Value {
        serde_json::json!({
            "id": 41,
            "tag_name": "1.2.3",
            "target_commitish": "0123456789abcdef",
            "prerelease": false,
            "draft": draft,
            "assets": [],
        })
    }

    fn remote_asset(path: &Path, id: u64) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "name": path
                .file_name()
                .and_then(|name| name.to_str())
                .expect("asset name should be UTF-8"),
            "size": fs::metadata(path).expect("asset metadata").len(),
            "digest": format!("sha256:{}", sha256_file(path).expect("asset digest")),
            "url": "unused",
        })
    }

    fn write_crate(path: &Path, manifest: &str, commit: &str, reverse: bool) {
        let file = File::create(path).expect("crate archive should be created");
        let encoder = GzEncoder::new(file, Compression::best());
        let mut archive = tar::Builder::new(encoder);
        let vcs = serde_json::to_vec(&serde_json::json!({
            "git": {"sha1": commit},
            "path_in_vcs": "crates/example",
            "dirty": false,
        }))
        .expect("VCS JSON should serialize");
        let mut entries = vec![
            ("example-1.2.3/Cargo.toml", manifest.as_bytes().to_vec()),
            ("example-1.2.3/.cargo_vcs_info.json", vcs),
            (
                "example-1.2.3/src/lib.rs",
                b"pub fn value() -> u8 { 1 }\n".to_vec(),
            ),
        ];
        if reverse {
            entries.reverse();
        }
        for (name, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_cksum();
            archive
                .append_data(&mut header, name, bytes.as_slice())
                .expect("archive member should append");
        }
        archive.finish().expect("archive should finish");
        archive
            .into_inner()
            .expect("encoder should be returned")
            .finish()
            .expect("gzip should finish");
    }

    #[test]
    fn mock_github_fresh_release_creates_one_draft() {
        let calls = Cell::new(0);
        let created = existing_or_create(None, || {
            calls.set(calls.get() + 1);
            Ok(remote(true))
        })
        .expect("fresh release should create");
        assert_eq!(calls.get(), 1);
        assert_eq!(
            classify_remote_release(&created, "1.2.3", "0123456789abcdef", false)
                .expect("created draft should classify"),
            RemoteReleaseState::Draft(41)
        );
    }

    #[test]
    fn mock_github_exact_existing_draft_is_not_created_again() {
        let calls = Cell::new(0);
        let existing = existing_or_create(Some(remote(true)), || {
            calls.set(calls.get() + 1);
            Ok(remote(true))
        })
        .expect("existing draft should reconcile");
        assert_eq!(calls.get(), 0);
        assert_eq!(
            classify_remote_release(&existing, "1.2.3", "0123456789abcdef", false)
                .expect("draft should classify"),
            RemoteReleaseState::Draft(41)
        );
    }

    #[test]
    fn mock_github_exact_published_release_is_immutable_and_reconciled() {
        let calls = Cell::new(0);
        let existing = existing_or_create(Some(remote(false)), || {
            calls.set(calls.get() + 1);
            Ok(remote(true))
        })
        .expect("published release should reconcile");
        assert_eq!(calls.get(), 0);
        assert_eq!(
            classify_remote_release(&existing, "1.2.3", "0123456789abcdef", false)
                .expect("published release should classify"),
            RemoteReleaseState::Published(41)
        );
    }

    #[test]
    fn mock_github_partial_rerun_reuses_existing_state() {
        let calls = Cell::new(0);
        let _ = existing_or_create(Some(remote(true)), || {
            calls.set(calls.get() + 1);
            Ok(remote(true))
        })
        .expect("partial rerun should resume");
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn mock_github_identity_conflict_hard_fails() {
        let mut conflicting = remote(true);
        conflicting["target_commitish"] = serde_json::json!("different");
        assert!(classify_remote_release(&conflicting, "1.2.3", "0123456789abcdef", false).is_err());
    }

    #[test]
    fn deterministic_crate_identity_ignores_archive_input_order() {
        let temporary = TempDir::new().expect("temporary directory should exist");
        let first = temporary.path().join("first.crate");
        let second = temporary.path().join("second.crate");
        let manifest =
            "[package]\nname = \"example\"\nversion = \"1.2.3\"\n\n[dependencies]\nserde = \"1\"\n";
        write_crate(&first, manifest, "0123456789abcdef", false);
        write_crate(&second, manifest, "0123456789abcdef", true);
        assert_eq!(
            canonical_crate_identity(&first).expect("first identity"),
            canonical_crate_identity(&second).expect("second identity")
        );
    }

    #[test]
    fn mock_registry_same_version_manifest_or_provenance_conflict_hard_fails() {
        let temporary = TempDir::new().expect("temporary directory should exist");
        let expected = temporary.path().join("expected.crate");
        let dependency_conflict = temporary.path().join("dependency-conflict.crate");
        let provenance_conflict = temporary.path().join("provenance-conflict.crate");
        write_crate(
            &expected,
            "[package]\nname = \"example\"\nversion = \"1.2.3\"\n\n[dependencies]\nserde = \"1\"\n",
            "0123456789abcdef",
            false,
        );
        write_crate(
            &dependency_conflict,
            "[package]\nname = \"example\"\nversion = \"1.2.3\"\n\n[dependencies]\nserde = \"2\"\n",
            "0123456789abcdef",
            false,
        );
        write_crate(
            &provenance_conflict,
            "[package]\nname = \"example\"\nversion = \"1.2.3\"\n\n[dependencies]\nserde = \"1\"\n",
            "fedcba9876543210",
            false,
        );
        let identity = canonical_crate_identity(&expected).expect("expected identity");
        assert_ne!(
            identity.sha256,
            canonical_crate_identity(&dependency_conflict)
                .expect("dependency identity")
                .sha256
        );
        assert_ne!(
            identity.sha256,
            canonical_crate_identity(&provenance_conflict)
                .expect("provenance identity")
                .sha256
        );
    }

    #[test]
    fn archive_inspection_rejects_traversal() {
        assert!(safe_archive_path(Path::new("../escape")).is_err());
        assert!(safe_archive_path(Path::new("/absolute")).is_err());
        assert_eq!(
            safe_archive_path(Path::new("root/bin")).expect("safe path"),
            PathBuf::from("root/bin")
        );
    }

    #[test]
    fn deterministic_conflict_is_not_retried() {
        let wait = config::RegistryWait {
            initial_milliseconds: 1,
            maximum_milliseconds: 1,
            total_seconds: 1,
        };
        let calls = Cell::new(0);
        let result: Result<()> = retry_transient(&wait, || {
            calls.set(calls.get() + 1);
            Err(failure("immutable conflict"))
        });
        assert!(result.is_err());
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn workflow_provenance_fetches_public_bytes_without_a_token() {
        let (temporary, release, identity) = provenance_fixture();
        let workflow = include_bytes!("../../../.github/workflows/release.yml");
        let server = MockServer::scripted(vec![MockResponse::Bytes(200, workflow.to_vec())]);
        let endpoints = HttpEndpoints::fixed_test_server(&server.root);
        let workflow_ref = "Portfoligno/memcordon/.github/workflows/release.yml@refs/tags/1.2.3";
        let (commit, observed_ref, digest, actions) = workflow_provenance_at(
            temporary.path(),
            &identity,
            &release,
            &endpoints,
            &identity.commit,
            workflow_ref,
        )
        .expect("public workflow provenance should not need credentials");
        assert_eq!(commit, identity.commit);
        assert_eq!(observed_ref, workflow_ref);
        assert_eq!(digest, sha256_bytes(workflow));
        assert_eq!(actions.len(), 6);
        let requests = server.finish();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].starts_with(
            "GET /repos/Portfoligno/memcordon/contents/.github/workflows/release.yml?ref=0123456789abcdef"
        ));
        assert!(
            !requests[0].to_ascii_lowercase().contains("authorization:"),
            "public workflow provenance must not send an authorization credential"
        );
    }

    #[test]
    fn workflow_provenance_rejects_fetched_bytes_that_fail_policy() {
        let (temporary, release, identity) = provenance_fixture();
        let server = MockServer::scripted(vec![MockResponse::Bytes(
            200,
            b"name: untrusted\non: push\njobs: {}\n".to_vec(),
        )]);
        let endpoints = HttpEndpoints::fixed_test_server(&server.root);
        let result = workflow_provenance_at(
            temporary.path(),
            &identity,
            &release,
            &endpoints,
            &identity.commit,
            "Portfoligno/memcordon/.github/workflows/release.yml@refs/tags/1.2.3",
        );
        assert!(
            result.is_err(),
            "untrusted fetched workflow must fail closed"
        );
        assert_eq!(server.finish().len(), 1);
    }

    #[test]
    fn http_mock_authenticated_github_lookup_finds_draft_in_release_listing() {
        let (temporary, _) = release_fixture();
        let server = MockServer::scripted(vec![MockResponse::Json(
            200,
            serde_json::json!([remote(true)]),
        )]);
        let endpoints = HttpEndpoints::fixed_test_server(&server.root);
        let found = github_release_at(temporary.path(), Some("token"), &endpoints)
            .expect("authenticated release listing should succeed")
            .expect("authenticated release listing should include the draft");
        assert_eq!(found, remote(true));
        let requests = server.finish();
        assert_eq!(requests.len(), 1);
        assert!(
            requests[0]
                .starts_with("GET /repos/Portfoligno/memcordon/releases?per_page=100&page=1 ")
        );
        assert!(
            requests[0]
                .to_ascii_lowercase()
                .contains("authorization: bearer token")
        );
        assert!(!requests[0].contains("/releases/tags/"));
    }

    #[test]
    fn http_mock_authenticated_github_lookup_rejects_duplicate_tag_releases() {
        let (temporary, _) = release_fixture();
        let mut first_page: Vec<serde_json::Value> = (0..GITHUB_RELEASES_PER_PAGE - 1)
            .map(|index| {
                let mut other = remote(false);
                other["id"] = serde_json::json!(index);
                other["tag_name"] = serde_json::json!(format!("other-{index}"));
                other
            })
            .collect();
        first_page.push(remote(true));
        let mut duplicate = remote(false);
        duplicate["id"] = serde_json::json!(42);
        let server = MockServer::scripted(vec![
            MockResponse::Json(200, serde_json::Value::Array(first_page)),
            MockResponse::Json(200, serde_json::json!([duplicate])),
        ]);
        let endpoints = HttpEndpoints::fixed_test_server(&server.root);
        let result = github_release_at(temporary.path(), Some("token"), &endpoints);
        assert!(result.is_err(), "duplicate tag ownership must fail closed");
        let requests = server.finish();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].contains("per_page=100&page=1"));
        assert!(requests[1].contains("per_page=100&page=2"));
    }

    #[test]
    fn http_mock_authenticated_github_lookup_paginates_until_draft() {
        let (temporary, _) = release_fixture();
        let first_page: Vec<serde_json::Value> = (0..GITHUB_RELEASES_PER_PAGE)
            .map(|index| {
                let mut other = remote(false);
                other["id"] = serde_json::json!(index);
                other["tag_name"] = serde_json::json!(format!("other-{index}"));
                other
            })
            .collect();
        let server = MockServer::scripted(vec![
            MockResponse::Json(200, serde_json::Value::Array(first_page)),
            MockResponse::Json(200, serde_json::json!([remote(true)])),
        ]);
        let endpoints = HttpEndpoints::fixed_test_server(&server.root);
        let found = github_release_at(temporary.path(), Some("token"), &endpoints)
            .expect("paginated release listing should succeed")
            .expect("second page should contain the draft");
        assert_eq!(found, remote(true));
        let requests = server.finish();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].contains("per_page=100&page=1"));
        assert!(requests[1].contains("per_page=100&page=2"));
    }

    #[test]
    fn http_mock_authenticated_github_lookup_rejects_malformed_listing() {
        let (temporary, _) = release_fixture();
        let server = MockServer::scripted(vec![MockResponse::Json(
            200,
            serde_json::json!({"unexpected": "object"}),
        )]);
        let endpoints = HttpEndpoints::fixed_test_server(&server.root);
        let result = github_release_at(temporary.path(), Some("token"), &endpoints);
        assert!(
            result.is_err(),
            "non-array release listing must fail closed"
        );
        assert_eq!(server.finish().len(), 1);
    }

    #[test]
    fn http_mock_public_github_lookup_uses_published_tag_endpoint() {
        let (temporary, _) = release_fixture();
        let server = MockServer::scripted(vec![MockResponse::Json(200, remote(false))]);
        let endpoints = HttpEndpoints::fixed_test_server(&server.root);
        let found = github_release_at(temporary.path(), None, &endpoints)
            .expect("public release lookup should succeed")
            .expect("published release should exist");
        assert_eq!(found, remote(false));
        let requests = server.finish();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].starts_with("GET /repos/Portfoligno/memcordon/releases/tags/1.2.3 "));
        assert!(!requests[0].to_ascii_lowercase().contains("authorization:"));
    }

    #[test]
    fn http_mock_github_response_loss_is_reconciled_and_rerun_is_idempotent() {
        let (temporary, _) = release_fixture();
        let server = MockServer::scripted(vec![
            MockResponse::Json(200, serde_json::json!([])),
            MockResponse::LoseResponse,
            MockResponse::Json(200, serde_json::json!([])),
            MockResponse::Json(200, serde_json::json!([remote(true)])),
            MockResponse::Json(200, serde_json::json!([remote(true)])),
        ]);
        let endpoints = HttpEndpoints::fixed_test_server(&server.root);
        let first = create_or_reconcile_github_draft_at(temporary.path(), "token", &endpoints)
            .expect("lost create response should reconcile by GET");
        let second = create_or_reconcile_github_draft_at(temporary.path(), "token", &endpoints)
            .expect("end-to-end rerun should reuse the draft");
        assert_eq!(first, second);
        let requests = server.finish();
        assert_eq!(requests.len(), 5);
        assert!(requests[0].starts_with("GET "));
        assert!(requests[1].starts_with("POST "));
        assert!(requests[2].starts_with("GET "));
        assert!(requests[3].starts_with("GET "));
        assert!(requests[4].starts_with("GET "));
        for request in [&requests[0], &requests[2], &requests[3], &requests[4]] {
            assert!(request.contains("/releases?per_page=100&page=1"));
            assert!(!request.contains("/releases/tags/"));
        }
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.starts_with("POST "))
                .count(),
            1,
            "an ambiguous create must never be blindly retried"
        );
    }

    #[test]
    fn http_mock_upload_conflict_reconciles_canonical_remote_asset_once() {
        let (temporary, release) = release_fixture();
        let path = temporary.path().join("asset.bin");
        fs::write(&path, b"canonical asset\n").expect("asset should write");
        let asset = serde_json::json!({
            "id": 9,
            "name": "asset.bin",
            "size": fs::metadata(&path).expect("asset metadata").len(),
            "digest": format!("sha256:{}", sha256_file(&path).expect("asset digest")),
            "url": "unused",
        });
        let mut release_state = remote(true);
        release_state["assets"] = serde_json::json!([asset.clone()]);
        let server = MockServer::scripted(vec![
            MockResponse::Json(422, serde_json::json!({"message": "already_exists"})),
            MockResponse::Json(200, serde_json::json!([remote(true)])),
            MockResponse::Json(200, serde_json::json!([release_state])),
        ]);
        let endpoints = HttpEndpoints::fixed_test_server(&server.root);
        let reconciled = upload_or_reconcile_github_asset_at(
            temporary.path(),
            &release,
            &endpoints,
            41,
            "token",
            &path,
        )
        .expect("upload collision should reconcile canonical asset");
        assert_eq!(reconciled, asset);
        let requests = server.finish();
        assert_eq!(requests.len(), 3);
        assert!(requests[0].starts_with("POST "));
        assert!(
            requests[1]
                .starts_with("GET /repos/Portfoligno/memcordon/releases?per_page=100&page=1 ")
        );
        assert!(
            requests[2]
                .starts_with("GET /repos/Portfoligno/memcordon/releases?per_page=100&page=1 ")
        );
    }

    #[test]
    fn http_mock_stage_uploads_complete_static_inventory_including_certification() {
        let (temporary, release) = release_fixture();
        let output = temporary.path().join(&release.assets.output_directory);
        let certification = [
            (
                "linux-cgroup-v2",
                "certification/backend-linux-cgroup-v2.json",
            ),
            (
                "windows-job-object-v2/x86_64-pc-windows-msvc",
                "certification/windows-sealed-v2/x64-windows-cleanup.json",
            ),
            (
                "windows-job-object-v2/aarch64-pc-windows-msvc",
                "certification/windows-sealed-v2/arm64-windows-cleanup.json",
            ),
            (
                "macos-watchdog",
                "certification/backend-macos-watchdog.json",
            ),
        ];
        fs::create_dir_all(output.join("certification"))
            .expect("certification directory should exist");
        fs::write(output.join(&release.assets.checksums), b"checksums\n")
            .expect("checksums should write");
        let native_path = output.join("memcordon-linux-x64.tar.gz");
        fs::write(&native_path, b"native archive\n").expect("native asset should write");
        let manifest_path = output.join(&release.assets.manifest);
        let mut manifest: ReleaseManifest =
            serde_json::from_slice(&fs::read(&manifest_path).expect("manifest should read"))
                .expect("manifest should parse");
        manifest.assets.push(AssetRecord {
            name: "memcordon-linux-x64.tar.gz".to_owned(),
            target: "linux-x64".to_owned(),
            size: fs::metadata(&native_path)
                .expect("native asset metadata")
                .len(),
            sha256: sha256_file(&native_path).expect("native asset digest"),
            runtime_manifest_sha256: "runtime-manifest-digest".to_owned(),
            components: Vec::new(),
        });
        for (backend, relative) in certification {
            let evidence_path = output.join(relative);
            fs::create_dir_all(
                evidence_path
                    .parent()
                    .expect("certification evidence should have a parent"),
            )
            .expect("certification evidence directory should exist");
            fs::write(&evidence_path, format!("{backend} certified\n"))
                .expect("certification evidence should write");
            manifest.certification.insert(
                backend.to_owned(),
                CertificationRecord {
                    evidence_path: relative.to_owned(),
                    sha256: sha256_file(&evidence_path).expect("evidence digest"),
                },
            );
        }
        write_json(&manifest_path, &manifest).expect("manifest should update");
        let static_paths = static_asset_paths(&release, &manifest, &output)
            .expect("static asset inventory should be valid");
        let assets: Vec<serde_json::Value> = static_paths
            .iter()
            .enumerate()
            .map(|(index, path)| remote_asset(path, 100 + index as u64))
            .collect();
        let mut final_remote = remote(true);
        final_remote["assets"] = serde_json::Value::Array(assets.clone());
        let mut responses = vec![
            MockResponse::Json(200, serde_json::json!([])),
            MockResponse::Json(201, remote(true)),
        ];
        responses.extend(
            assets
                .iter()
                .cloned()
                .map(|asset| MockResponse::Json(201, asset)),
        );
        responses.push(MockResponse::Json(200, serde_json::json!([final_remote])));
        let server = MockServer::scripted(responses);
        let endpoints = HttpEndpoints::fixed_test_server(&server.root);
        stage_github_at(temporary.path(), "token", &endpoints)
            .expect("complete static inventory should stage");
        let requests = server.finish();
        assert_eq!(requests.len(), static_paths.len() + 3);
        let create_body = request_json_body(&requests[1]);
        assert_eq!(create_body["draft"], true);
        assert_eq!(create_body["tag_name"], "1.2.3");
        assert_eq!(create_body["target_commitish"], "0123456789abcdef");
        assert!(
            requests
                .last()
                .expect("stage should perform a final reconciliation read")
                .starts_with("GET /repos/Portfoligno/memcordon/releases?per_page=100&page=1 ",)
        );
        assert_eq!(
            requests
                .iter()
                .filter(|request| {
                    request.starts_with("POST /repos/Portfoligno/memcordon/releases HTTP/")
                })
                .count(),
            1,
            "stage must create at most one draft"
        );
        for path in &static_paths {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .expect("asset name should be UTF-8");
            assert_eq!(
                requests
                    .iter()
                    .filter(|request| {
                        request.starts_with("POST /repos/Portfoligno/memcordon/releases/41/assets?")
                            && request.contains(&format!("name={name}"))
                    })
                    .count(),
                1,
                "each canonical static asset must upload exactly once"
            );
        }
    }

    #[test]
    fn http_mock_stage_rejects_missing_asset_inventory_before_mutation() {
        let (temporary, _) = release_fixture();
        let mut malformed = remote(true);
        malformed
            .as_object_mut()
            .expect("remote release should be an object")
            .remove("assets");
        let server = MockServer::scripted(vec![MockResponse::Json(
            200,
            serde_json::json!([malformed]),
        )]);
        let endpoints = HttpEndpoints::fixed_test_server(&server.root);
        let result = stage_github_at(temporary.path(), "token", &endpoints);
        assert!(result.is_err(), "missing asset inventory must fail closed");
        let requests = server.finish();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].starts_with("GET "));
        assert!(requests.iter().all(|request| !request.starts_with("POST ")));
    }

    #[test]
    fn http_mock_idempotent_github_and_registry_reads_retry_transient_statuses() {
        let (temporary, mut release) = release_fixture();
        release.network_retry = config::RegistryWait {
            initial_milliseconds: 1,
            maximum_milliseconds: 1,
            total_seconds: 2,
        };
        let server = MockServer::scripted(vec![
            MockResponse::Json(500, serde_json::json!({"message": "retry"})),
            MockResponse::Json(200, remote(true)),
            MockResponse::Json(503, serde_json::json!({"message": "retry"})),
            MockResponse::Json(
                200,
                serde_json::json!({"version": {"checksum": "registry-digest"}}),
            ),
            MockResponse::Bytes(503, b"retry".to_vec()),
            MockResponse::Truncated(b"partial".to_vec(), 20),
            MockResponse::Bytes(200, b"crate bytes".to_vec()),
        ]);
        let endpoints = HttpEndpoints::fixed_test_server(&server.root);
        let remote_url = format!(
            "{}/repos/{}/releases/tags/1.2.3",
            endpoints.github_api, release.repository
        );
        let github = github_json_request(&release, &endpoints, "GET", &remote_url, None, None)
            .expect("idempotent GitHub GET should retry");
        assert_eq!(github["id"], 41);
        assert_eq!(
            crate_checksum_at(&release, &endpoints, "example", "1.2.3")
                .expect("registry checksum should retry"),
            Some("registry-digest".to_owned())
        );
        let archive = temporary.path().join("download.crate");
        public_crate_archive_at(&release, &endpoints, "example", "1.2.3", &archive)
            .expect("registry download should retry");
        assert_eq!(
            fs::read(archive).expect("download should exist"),
            b"crate bytes"
        );
        let requests = server.finish();
        assert_eq!(requests.len(), 7);
        assert!(requests.iter().all(|request| request.starts_with("GET ")));
    }

    #[test]
    fn http_mock_partial_registry_publication_selects_only_missing_versions() {
        let (_, mut release) = release_fixture();
        release.network_retry = config::RegistryWait {
            initial_milliseconds: 1,
            maximum_milliseconds: 1,
            total_seconds: 1,
        };
        let server = MockServer::scripted(vec![
            MockResponse::Json(
                200,
                serde_json::json!({"version": {"checksum": "published"}}),
            ),
            MockResponse::Json(404, serde_json::json!({"message": "missing"})),
        ]);
        let endpoints = HttpEndpoints::fixed_test_server(&server.root);
        let states = ["memcordon-core", "memcordon-platform"]
            .into_iter()
            .map(|name| {
                crate_checksum_at(&release, &endpoints, name, "1.2.3")
                    .map(|checksum| (name, checksum))
            })
            .collect::<Result<Vec<_>>>()
            .expect("partial registry state should reconcile");
        assert_eq!(states[0].1.as_deref(), Some("published"));
        assert_eq!(states[1].1, None);
        assert_eq!(server.finish().len(), 2);
    }

    #[test]
    fn http_mock_distinguishes_existing_crate_name_from_absent_target_version() {
        let (_, mut release) = release_fixture();
        release.network_retry = config::RegistryWait {
            initial_milliseconds: 1,
            maximum_milliseconds: 1,
            total_seconds: 1,
        };
        let server = MockServer::scripted(vec![
            MockResponse::Json(200, serde_json::json!({"crate": {"id": "memcordon-core"}})),
            MockResponse::Json(404, serde_json::json!({"message": "missing version"})),
        ]);
        let endpoints = HttpEndpoints::fixed_test_server(&server.root);
        assert!(
            crate_name_exists_at(&release, &endpoints, "memcordon-core")
                .expect("existing name should be recognized")
        );
        assert_eq!(
            crate_checksum_at(&release, &endpoints, "memcordon-core", "0.1.0")
                .expect("absent target version should be recognized"),
            None
        );
        assert_eq!(server.finish().len(), 2);
    }

    #[test]
    fn http_mock_crate_name_check_fails_closed_on_malformed_or_wrong_identity() {
        let (_, release) = release_fixture();
        for response in [
            serde_json::json!({"crate": {}}),
            serde_json::json!({"crate": {"id": "different-name"}}),
        ] {
            let server = MockServer::scripted(vec![MockResponse::Json(200, response)]);
            let endpoints = HttpEndpoints::fixed_test_server(&server.root);
            assert!(crate_name_exists_at(&release, &endpoints, "memcordon-core").is_err());
            assert_eq!(server.finish().len(), 1);
        }
    }
}
