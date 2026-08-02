use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use cargo_metadata::{DependencyKind, Metadata, MetadataCommand};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use walkdir::WalkDir;

use memcordon_ci::capability;

use crate::command::{CommandSpec, git, rustup_cargo};
use crate::config::{self, AssetTarget, RegistryCredentialPolicy};
use crate::{CiError, ReleasePhase, Result};

const RELEASE_DEADLINE: Duration = Duration::from_secs(30 * 60);
const GITHUB_API_ROOT: &str = "https://api.github.com";
const GITHUB_UPLOADS_ROOT: &str = "https://uploads.github.com";
const CRATES_IO_API_ROOT: &str = "https://crates.io";

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
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct NativeAssetReport {
    schema_version: u32,
    tag: String,
    source_commit: String,
    asset: AssetRecord,
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
    certification: BTreeMap<String, String>,
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum DispatchRegistryAuth {
    StoredToken,
    OidcFallback,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DispatchInputs {
    tag: String,
    #[serde(default)]
    registry_auth: Option<DispatchRegistryAuth>,
}

#[derive(Debug, Deserialize)]
struct WorkflowEvent {
    #[serde(default)]
    inputs: Option<DispatchInputs>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RegistryAuthPath {
    StoredToken,
    OidcFallback,
    OidcOnly,
}

fn select_registry_auth_path(
    policy: RegistryCredentialPolicy,
    event_name: &str,
    event: &WorkflowEvent,
) -> Result<RegistryAuthPath> {
    match (policy, event_name) {
        (RegistryCredentialPolicy::FirstReleaseTokenPrimary, "push") => {
            Ok(RegistryAuthPath::StoredToken)
        }
        (RegistryCredentialPolicy::FirstReleaseTokenPrimary, "workflow_dispatch") => {
            let inputs = event
                .inputs
                .as_ref()
                .ok_or_else(|| failure("workflow_dispatch inputs are missing"))?;
            match inputs.registry_auth {
                Some(DispatchRegistryAuth::StoredToken) => Ok(RegistryAuthPath::StoredToken),
                Some(DispatchRegistryAuth::OidcFallback) => Ok(RegistryAuthPath::OidcFallback),
                None => Err(failure(
                    "transition workflow_dispatch registry_auth input is missing",
                )),
            }
        }
        (RegistryCredentialPolicy::OidcOnly, "push" | "workflow_dispatch") => {
            Ok(RegistryAuthPath::OidcOnly)
        }
        (_, other) => Err(failure(format!("unsupported release event: {other}"))),
    }
}

fn configured_first_release(release: &config::Release) -> Result<Option<&Version>> {
    match (
        release.registry_credentials.policy,
        release.registry_credentials.first_release_version.as_ref(),
    ) {
        (RegistryCredentialPolicy::FirstReleaseTokenPrimary, Some(version))
            if version.pre.is_empty() && version.build.is_empty() =>
        {
            Ok(Some(version))
        }
        (RegistryCredentialPolicy::OidcOnly, None) => Ok(None),
        (RegistryCredentialPolicy::FirstReleaseTokenPrimary, _) => Err(failure(
            "first-release-token-primary requires a stable first_release_version",
        )),
        (RegistryCredentialPolicy::OidcOnly, Some(_)) => Err(failure(
            "oidc-only forbids a first_release_version transition setting",
        )),
    }
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

fn validate_registry_auth_context(
    release: &config::Release,
    tag: &str,
) -> Result<RegistryAuthPath> {
    let (event_name, event) = workflow_event()?;
    let path = select_registry_auth_path(release.registry_credentials.policy, &event_name, &event)?;
    if event_name == "workflow_dispatch" {
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
    if path == RegistryAuthPath::OidcFallback {
        require_oidc_fallback_names(&release.publish_packages, |package| {
            crate_name_exists(release, package)
        })?;
    }
    Ok(path)
}

fn require_oidc_fallback_names(
    packages: &[String],
    mut exists: impl FnMut(&str) -> Result<bool>,
) -> Result<()> {
    for package in packages {
        if !exists(package)? {
            return Err(failure(format!(
                "OIDC fallback is forbidden while crates.io package name is absent: {package}"
            )));
        }
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
    Ok(MetadataCommand::new().current_dir(root).exec()?)
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

fn publish_order(metadata: &Metadata, configured: &[String]) -> Result<Vec<String>> {
    let configured_set: BTreeSet<&str> = configured.iter().map(String::as_str).collect();
    if configured_set.len() != configured.len() {
        return Err(failure("release publish package list contains duplicates"));
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
            return Err(failure(
                "publishable workspace dependency graph contains a cycle",
            ));
        };
        let package = packages
            .get(next)
            .ok_or_else(|| failure(format!("configured publish package is absent: {next}")))?;
        if package.publish.as_ref().is_none_or(|registries| {
            registries.len() != 1
                || registries
                    .first()
                    .is_none_or(|registry| registry != "crates-io")
        }) {
            return Err(failure(format!("package is not crates.io-only: {next}")));
        }
        for dependency in &package.dependencies {
            if dependency.kind != DependencyKind::Development
                && dependency.path.is_some()
                && !configured_set.contains(dependency.name.as_str())
            {
                return Err(failure(format!(
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
                    return Err(failure(format!(
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
        return Err(failure(format!(
            "configured publish order {configured:?} does not match derived DAG {order:?}"
        )));
    }
    Ok(order)
}

pub fn preflight(root: &Path) -> Result<ReleaseIdentity> {
    let release = config::release(root)?;
    if release.schema_version != 1
        || release.registry != "crates-io"
        || release.workflow != "release.yml"
        || release.github_api_version.is_empty()
        || release.maximum_package_bytes == 0
        || release.maximum_asset_bytes == 0
        || release.registry_wait.initial_milliseconds == 0
        || release.registry_wait.maximum_milliseconds < release.registry_wait.initial_milliseconds
        || release.network_retry.initial_milliseconds == 0
        || release.network_retry.maximum_milliseconds < release.network_retry.initial_milliseconds
    {
        return Err(failure("release configuration identity is invalid"));
    }
    let configured_first = configured_first_release(&release)?;
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
    if let Some(first) = configured_first {
        if version != *first {
            return Err(failure(format!(
                "transition credential policy is restricted to first release version {first}"
            )));
        }
        let remote_tags = utf8(
            git(root, ["ls-remote", "--tags", "origin"])?,
            "remote release tag inventory",
        )?;
        for candidate in remote_tags.lines().filter_map(|line| {
            let reference = line.split_whitespace().nth(1)?;
            let tag = reference
                .strip_prefix("refs/tags/")?
                .strip_suffix("^{}")
                .unwrap_or_else(|| {
                    reference
                        .strip_prefix("refs/tags/")
                        .expect("prefix checked")
                });
            release_tag_version(tag)
        }) {
            if candidate > *first {
                return Err(failure(format!(
                    "later release tag {candidate} exists while transition credential policy remains"
                )));
            }
        }
    }
    let metadata = metadata(root)?;
    let workspace_version = metadata
        .packages
        .iter()
        .find(|package| package.name == "memcordon")
        .map(|package| package.version.clone())
        .ok_or_else(|| failure("workspace version is unavailable"))?;
    if workspace_version != version {
        return Err(failure(format!(
            "release tag/version mismatch: tag={version}, workspace={workspace_version}"
        )));
    }
    publish_order(&metadata, &release.publish_packages)?;
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
    validate_registry_auth_context(&release, &tag)?;
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
        )?;
        if crate_checksum(&release, &record.name, &record.version)?.is_some() {
            verify_public_crate(&release, &record)?;
        }
    }
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
        .find(|candidate| candidate.name == package)
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
        } else {
            root.join(&relative)
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

fn package_crate(
    root: &Path,
    stable: &str,
    package: &str,
    version: &Version,
    source_commit: &str,
    maximum_package_bytes: u64,
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
    let archive = root.join("target").join("package").join(filename);
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

fn create_package_archives(root: &Path, stable: &str, packages: &[String]) -> Result<()> {
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

fn host_target(targets: &[AssetTarget]) -> Result<&AssetTarget> {
    let wanted = if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "linux-x64"
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        "linux-arm64"
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "macos-arm64"
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        "macos-x64"
    } else if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        "windows-x64"
    } else {
        return Err(failure("host is not a configured release target"));
    };
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

fn build_archive(root: &Path, identity: &ReleaseIdentity, target: &AssetTarget) -> Result<PathBuf> {
    let output = root.join("target").join("ci").join("release-output");
    fs::create_dir_all(&output)?;
    let path = output.join(archive_name(&identity.version, target));
    let executable = root
        .join("target")
        .join("ci")
        .join("release-native")
        .join(&target.rust_target)
        .join("release")
        .join(&target.executable);
    let top = PathBuf::from(format!(
        "memcordon-v{}-{}",
        identity.version, target.rust_target
    ));
    let mut entries = vec![
        (executable, PathBuf::from(&target.executable), 0o755),
        (root.join("README.md"), PathBuf::from("README.md"), 0o644),
        (root.join("LICENSE"), PathBuf::from("LICENSE"), 0o644),
    ];
    entries.sort_by_key(|entry| top.join(&entry.1));
    if target.archive == "zip" {
        let file = File::create(&path)?;
        let mut writer = zip::ZipWriter::new(file);
        for (source, relative, mode) in entries {
            let name = top.join(relative).to_string_lossy().replace('\\', "/");
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated)
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
    Ok(path)
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

fn inspect_extract_and_smoke(
    root: &Path,
    archive_path: &Path,
    target: &AssetTarget,
    version: &Version,
    execute: bool,
) -> Result<()> {
    let temporary = TempDir::new()?;
    let mut extracted_files = BTreeSet::new();
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
                extracted_files.insert(relative);
            } else {
                return Err(failure("tar archive contains a non-file member"));
            }
        }
    }
    let top = PathBuf::from(format!("memcordon-v{version}-{}", target.rust_target));
    let expected = BTreeSet::from([
        top.join(&target.executable),
        top.join("README.md"),
        top.join("LICENSE"),
    ]);
    if extracted_files != expected {
        return Err(failure(format!(
            "release archive member set differs: expected={expected:?} actual={extracted_files:?}"
        )));
    }
    let executable = temporary.path().join(top).join(&target.executable);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&executable)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&executable, permissions)?;
    }
    if execute {
        CommandSpec::new(&executable, root, Duration::from_secs(30))
            .arg("--version")
            .run()?;
        CommandSpec::new(&executable, root, Duration::from_secs(30))
            .args(["probe", "--json"])
            .run()?;
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
    let arguments = vec![
        OsString::from("build"),
        OsString::from("--target-dir"),
        release_target.into_os_string(),
        OsString::from("--package"),
        OsString::from("memcordon"),
        OsString::from("--release"),
        OsString::from("--locked"),
        OsString::from("--target"),
        OsString::from(&target.rust_target),
    ];
    rustup_cargo(root, &toolchains.stable, arguments, RELEASE_DEADLINE).run()?;
    let executable = root
        .join("target")
        .join("ci")
        .join("release-native")
        .join(&target.rust_target)
        .join("release")
        .join(&target.executable);
    CommandSpec::new(&executable, root, Duration::from_secs(30))
        .arg("--version")
        .run()?;
    CommandSpec::new(&executable, root, Duration::from_secs(30))
        .args(["probe", "--json"])
        .run()?;
    let archive = build_archive(root, &identity, target)?;
    if fs::metadata(&archive)?.len() > release.maximum_asset_bytes {
        return Err(failure(
            "native release archive exceeds configured size policy",
        ));
    }
    inspect_extract_and_smoke(root, &archive, target, &identity.version, true)?;
    let asset = AssetRecord {
        name: archive
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| failure("archive name is not UTF-8"))?
            .to_owned(),
        target: target.rust_target.clone(),
        size: fs::metadata(&archive)?.len(),
        sha256: sha256_file(&archive)?,
    };
    let report = NativeAssetReport {
        schema_version: 1,
        tag: identity.tag,
        source_commit: identity.commit,
        asset,
    };
    let report_name = format!(
        "{}.json",
        archive
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| failure("archive name is not UTF-8"))?
    );
    write_json(&archive.with_file_name(report_name), &report)?;
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
        inspect_extract_and_smoke(root, &destination, target, &identity.version, false)?;
        let asset = AssetRecord {
            name,
            target: target.rust_target.clone(),
            size: fs::metadata(&destination)?.len(),
            sha256: sha256_file(&destination)?,
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
        if report.schema_version != 1
            || report.tag != identity.tag
            || report.source_commit != identity.commit
            || report.asset != asset
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

fn collect_certification(
    root: &Path,
    identity: &ReleaseIdentity,
) -> Result<BTreeMap<String, String>> {
    let input = root.join("target").join("ci").join("release-inputs");
    let mut reports = BTreeMap::new();
    for required in ["linux-cgroup-v2", "windows-job-object", "macos-watchdog"] {
        let expected_runner_class = if required == "macos-watchdog" {
            "hosted-release-acceptance"
        } else {
            "ephemeral-certified"
        };
        let expected_tests = match required {
            "linux-cgroup-v2" | "windows-job-object" => 17,
            "macos-watchdog" => 8,
            _ => unreachable!("required backend inventory is static"),
        };
        let mut found = Vec::new();
        for entry in WalkDir::new(&input) {
            let entry = entry.map_err(|error| failure(error.to_string()))?;
            if entry.file_type().is_file() && entry.file_name().to_string_lossy().contains(required)
            {
                let value: serde_json::Value = serde_json::from_slice(&fs::read(entry.path())?)?;
                if value.get("schema").and_then(serde_json::Value::as_u64) != Some(1)
                    || value.get("backend").and_then(serde_json::Value::as_str) != Some(required)
                    || value.get("certified").and_then(serde_json::Value::as_bool) != Some(true)
                    || value.get("tests_run").and_then(serde_json::Value::as_u64)
                        != Some(expected_tests)
                    || value
                        .get("scenarios")
                        .and_then(serde_json::Value::as_array)
                        .map(|scenarios| scenarios.len())
                        != Some(expected_tests as usize)
                    || value
                        .get("tests_skipped")
                        .and_then(serde_json::Value::as_u64)
                        != Some(0)
                    || value.get("commit").and_then(serde_json::Value::as_str)
                        != Some(identity.commit.as_str())
                    || value
                        .get("runner_class")
                        .and_then(serde_json::Value::as_str)
                        != Some(expected_runner_class)
                {
                    return Err(failure(format!(
                        "required certification failed: {required}"
                    )));
                }
                found.push(sha256_file(entry.path())?);
            }
        }
        if found.len() != 1 {
            return Err(failure(format!(
                "expected exactly one certification report: {required}"
            )));
        }
        reports.insert(
            required.to_owned(),
            found.pop().expect("one certification report was checked"),
        );
    }
    Ok(reports)
}

fn assemble(root: &Path) -> Result<()> {
    let identity = preflight(root)?;
    let release = config::release(root)?;
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
        )?);
        let archive = root
            .join("target")
            .join("package")
            .join(format!("{package}-{}.crate", identity.version));
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
    let manifest = ReleaseManifest {
        schema_version: release.schema_version,
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
        certification: collect_certification(root, &identity)?,
        source_date: identity.source_date,
    };
    write_json(&output.join(&release.assets.manifest), &manifest)?;
    Ok(())
}

fn bundle_manifest(root: &Path) -> Result<(config::Release, ReleaseManifest, PathBuf)> {
    let release = config::release(root)?;
    let output = root.join(&release.assets.output_directory);
    let manifest: ReleaseManifest =
        serde_json::from_slice(&fs::read(output.join(&release.assets.manifest))?)?;
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
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(15))
            .timeout_read(Duration::from_secs(60))
            .build();
        let mut request = agent
            .request(method, url)
            .set("Accept", "application/vnd.github+json")
            .set("X-GitHub-Api-Version", &release.github_api_version)
            .set("User-Agent", "memcordon-ci");
        if let Some(token) = token {
            request = request.set("Authorization", &format!("Bearer {token}"));
        }
        match &body {
            Some(value) => request.send_json(value.clone()),
            None => request.call(),
        }
        .map_err(|error| CiError::Http(Box::new(error)))
    };
    let response = if method == "GET" {
        retry_transient(&release.network_retry, send)?
    } else {
        // Mutations are attempted exactly once. A transport failure or transient response can
        // mean the server committed the operation before the response was lost; callers must
        // re-read canonical remote state before deciding whether a rerun is safe.
        send()?
    };
    response
        .into_json()
        .map_err(|error| CiError::Io(std::io::Error::other(error)))
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
            .set("Accept", accept)
            .set("X-GitHub-Api-Version", &release.github_api_version)
            .set("User-Agent", "memcordon-ci");
        if let Some(token) = token {
            request = request.set("Authorization", &format!("Bearer {token}"));
        }
        let response = request
            .call()
            .map_err(|error| CiError::Http(Box::new(error)))?;
        let mut bytes = Vec::new();
        response
            .into_reader()
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
    let url = format!(
        "{}/repos/{}/releases/tags/{}",
        endpoints.github_api, release.repository, manifest.tag
    );
    match github_json_request(&release, endpoints, "GET", &url, token, None) {
        Ok(value) => Ok(Some(value)),
        Err(CiError::Http(error)) if matches!(*error, ureq::Error::Status(404, _)) => Ok(None),
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
) -> Vec<PathBuf> {
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
    paths.sort();
    paths
}

fn public_asset_records(
    release: &config::Release,
    remote: &serde_json::Value,
    paths: &[PathBuf],
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
        records.push(PublicAssetRecord {
            id: matching[0]
                .get("id")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| failure("GitHub asset has no id"))?,
            name: name.to_owned(),
            size: fs::metadata(path)?.len(),
            sha256: sha256_file(path)?,
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
    let mut request = ureq::get(url)
        .set("Accept", "application/octet-stream")
        .set("X-GitHub-Api-Version", &release.github_api_version)
        .set("User-Agent", "memcordon-ci");
    if let Some(token) = token {
        request = request.set("Authorization", &format!("Bearer {token}"));
    }
    let bytes = retry_transient(&release.network_retry, || {
        let response = request
            .clone()
            .call()
            .map_err(|error| CiError::Http(Box::new(error)))?;
        let mut bytes = Vec::new();
        response
            .into_reader()
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
    let response = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(15))
        .timeout_read(Duration::from_secs(120))
        .build()
        .post(&url)
        .query("name", name)
        .set("Accept", "application/vnd.github+json")
        .set("X-GitHub-Api-Version", &release.github_api_version)
        .set("User-Agent", "memcordon-ci")
        .set("Authorization", &format!("Bearer {token}"))
        .set("Content-Type", "application/octet-stream")
        .send_bytes(&bytes)
        .map_err(|error| CiError::Http(Box::new(error)))?;
    response
        .into_json()
        .map_err(|error| CiError::Io(std::io::Error::other(error)))
}

fn ambiguous_mutation_error(error: &CiError) -> bool {
    transient_network_error(error)
        || matches!(error, CiError::Io(_))
        || matches!(
            error,
            CiError::Http(inner)
                if matches!(inner.as_ref(), ureq::Error::Status(409 | 422, _))
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
            github_release_at(root, Some(token), endpoints)?.ok_or(error)
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
            let name = path
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or_else(|| failure("release asset name is not UTF-8"))?;
            let remote = github_release_at(root, Some(token), endpoints)?
                .ok_or_else(|| failure("GitHub release disappeared after ambiguous upload"))?;
            let asset = remote
                .get("assets")
                .and_then(serde_json::Value::as_array)
                .and_then(|assets| {
                    assets.iter().find(|asset| {
                        asset.get("name").and_then(serde_json::Value::as_str) == Some(name)
                    })
                })
                .ok_or(error)?;
            if !asset_matches(asset, path)? {
                return Err(failure(format!(
                    "GitHub release asset conflicts after ambiguous upload: {name}"
                )));
            }
            Ok(asset.clone())
        }
        Err(error) => Err(error),
    }
}

fn stage_github(root: &Path) -> Result<()> {
    let token = github_token()?;
    let (release, manifest, output) = bundle_manifest(root)?;
    let endpoints = HttpEndpoints::production();
    let remote = create_or_reconcile_github_draft_at(root, &token, &endpoints)?;
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
        .unwrap_or_default();
    let mut names: Vec<String> = manifest
        .assets
        .iter()
        .map(|asset| asset.name.clone())
        .collect();
    names.extend([
        release.assets.checksums.clone(),
        release.assets.manifest.clone(),
        release.assets.notes.clone(),
    ]);
    names.sort();
    for name in names {
        let path = output.join(&name);
        if let Some(asset) = existing.iter().find(|asset| {
            asset.get("name").and_then(serde_json::Value::as_str) == Some(name.as_str())
        }) {
            if !asset_matches(asset, &path)? {
                return Err(failure(format!("GitHub release asset conflicts: {name}")));
            }
        } else {
            let uploaded = upload_or_reconcile_github_asset_at(
                root, &release, &endpoints, release_id, &token, &path,
            )?;
            if !asset_matches(&uploaded, &path)? {
                return Err(failure(format!("GitHub rejected asset digest: {name}")));
            }
        }
    }
    let reconciled = github_release_at(root, Some(&token), &endpoints)?
        .ok_or_else(|| failure("GitHub release disappeared during staging"))?;
    let static_paths = static_asset_paths(&release, &manifest, &output);
    public_asset_records(&release, &reconciled, &static_paths)?;
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
        download_github_asset(&release, publication_report, Some(&token), &report_path)?;
    }
    Ok(())
}

fn crate_checksum(release: &config::Release, name: &str, version: &str) -> Result<Option<String>> {
    crate_checksum_at(release, &HttpEndpoints::production(), name, version)
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
            .set("User-Agent", "memcordon-ci")
            .call()
            .map_err(|error| CiError::Http(Box::new(error)))
    });
    match result {
        Ok(response) => {
            let value: serde_json::Value = response
                .into_json()
                .map_err(|error| CiError::Io(std::io::Error::other(error)))?;
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
        Err(CiError::Http(error)) if matches!(*error, ureq::Error::Status(404, _)) => Ok(false),
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
            .set("User-Agent", "memcordon-ci")
            .call()
            .map_err(|error| CiError::Http(Box::new(error)))
    });
    match result {
        Ok(response) => {
            let value: serde_json::Value = response
                .into_json()
                .map_err(|error| CiError::Io(std::io::Error::other(error)))?;
            Ok(value
                .get("version")
                .and_then(|version| version.get("checksum"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned))
        }
        Err(CiError::Http(error)) if matches!(*error, ureq::Error::Status(404, _)) => Ok(None),
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
        let response = ureq::get(&url)
            .set("User-Agent", "memcordon-ci")
            .call()
            .map_err(|error| CiError::Http(Box::new(error)))?;
        let mut bytes = Vec::new();
        response
            .into_reader()
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
            ureq::Error::Transport(_) => true,
            ureq::Error::Status(status, _) => {
                matches!(*status, 408 | 425 | 429) || (500..=599).contains(status)
            }
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
        let mut exact_version = OsString::from("=");
        exact_version.push(&record.version);
        rustup_cargo(
            root,
            &toolchains.stable,
            [
                OsString::from("install"),
                OsString::from("memcordon"),
                OsString::from("--version"),
                exact_version,
                OsString::from("--locked"),
                OsString::from("--root"),
                install_root.clone().into_os_string(),
            ],
            RELEASE_DEADLINE,
        )
        .run()?;
        let executable = install_root.join("bin").join(if cfg!(windows) {
            "memcordon.exe"
        } else {
            "memcordon"
        });
        let output = CommandSpec::new(executable, root, Duration::from_secs(30))
            .arg("--version")
            .run()?;
        if !String::from_utf8_lossy(&output).contains(&record.version) {
            return Err(failure("installed memcordon reports the wrong version"));
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

fn require_registry_token(token: Option<&std::ffi::OsStr>) -> Result<()> {
    if token.is_none_or(|token| token.is_empty()) {
        return Err(failure(
            "CARGO_REGISTRY_TOKEN is absent or empty for the selected publication slot",
        ));
    }
    Ok(())
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
    let token = std::env::var_os("CARGO_REGISTRY_TOKEN");
    require_registry_token(token.as_deref())?;
    let (release, manifest, _) = bundle_manifest(root)?;
    let metadata = metadata(root)?;
    let order = publish_order(&metadata, &release.publish_packages)?;
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
        let publication = rustup_cargo(
            root,
            &toolchains.stable,
            [
                "publish",
                "--locked",
                "--registry",
                "crates-io",
                "--package",
                package,
            ],
            RELEASE_DEADLINE,
        )
        .run();
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
    let is_draft = remote
        .get("draft")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| failure("GitHub release has no draft classification"))?;
    if !is_draft {
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
    let release_id = remote
        .get("id")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| failure("GitHub release lacks an id"))?;
    let static_paths = static_asset_paths(&release, &manifest, &output);
    let assets = public_asset_records(&release, &remote, &static_paths)?;
    let report = PublicationReport {
        schema_version: 1,
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
    let published = github_release_at(root, Some(&token), &endpoints)?
        .ok_or_else(|| failure("GitHub release disappeared after publication"))?;
    if published.get("draft").and_then(serde_json::Value::as_bool) != Some(false)
        || published
            .get("prerelease")
            .and_then(serde_json::Value::as_bool)
            != Some(manifest.prerelease)
    {
        if let Some(error) = mutation_error {
            return Err(error);
        }
        return Err(failure("GitHub release publication classification differs"));
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
    let report_path = output.join(&release.assets.publication_report);
    if !report_path.is_file() {
        download_github_asset(&release, report_asset, None, &report_path)?;
    }
    if !asset_matches(report_asset, &report_path)? {
        return Err(failure("public publication report digest differs"));
    }
    let report: PublicationReport = serde_json::from_slice(&fs::read(&report_path)?)?;
    let release_id = remote
        .get("id")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| failure("public release has no id"))?;
    let static_paths = static_asset_paths(&release, &manifest, &output);
    let public_assets = public_asset_records(&release, &remote, &static_paths)?;
    if report.manifest_sha256 != sha256_file(&output.join(&release.assets.manifest))?
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
    let checksum_text = fs::read_to_string(output.join(&release.assets.checksums))?;
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
    use std::io::{BufRead, BufReader};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};

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
            schema_version: 1,
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

    fn dispatch_event(auth: Option<DispatchRegistryAuth>) -> WorkflowEvent {
        WorkflowEvent {
            inputs: Some(DispatchInputs {
                tag: "0.1.0".to_owned(),
                registry_auth: auth,
            }),
        }
    }

    #[test]
    fn credential_selector_covers_profiles_events_and_dispatch_choices() {
        let push = WorkflowEvent { inputs: None };
        assert_eq!(
            select_registry_auth_path(
                RegistryCredentialPolicy::FirstReleaseTokenPrimary,
                "push",
                &push,
            )
            .expect("transition push should select stored token"),
            RegistryAuthPath::StoredToken
        );
        assert_eq!(
            select_registry_auth_path(
                RegistryCredentialPolicy::FirstReleaseTokenPrimary,
                "workflow_dispatch",
                &dispatch_event(Some(DispatchRegistryAuth::StoredToken)),
            )
            .expect("stored-token dispatch should select stored token"),
            RegistryAuthPath::StoredToken
        );
        assert_eq!(
            select_registry_auth_path(
                RegistryCredentialPolicy::FirstReleaseTokenPrimary,
                "workflow_dispatch",
                &dispatch_event(Some(DispatchRegistryAuth::OidcFallback)),
            )
            .expect("fallback dispatch should select OIDC fallback"),
            RegistryAuthPath::OidcFallback
        );
        for event_name in ["push", "workflow_dispatch"] {
            assert_eq!(
                select_registry_auth_path(
                    RegistryCredentialPolicy::OidcOnly,
                    event_name,
                    &dispatch_event(None),
                )
                .expect("steady-state event should select OIDC"),
                RegistryAuthPath::OidcOnly
            );
        }
        assert!(
            select_registry_auth_path(
                RegistryCredentialPolicy::FirstReleaseTokenPrimary,
                "workflow_dispatch",
                &dispatch_event(None),
            )
            .is_err()
        );
        for policy in [
            RegistryCredentialPolicy::FirstReleaseTokenPrimary,
            RegistryCredentialPolicy::OidcOnly,
        ] {
            for event_name in ["pull_request", "merge_group", "unknown"] {
                assert!(select_registry_auth_path(policy, event_name, &push).is_err());
            }
        }
    }

    #[test]
    fn workflow_event_deserialization_is_typed_and_steady_dispatch_compatible() {
        let steady: WorkflowEvent =
            serde_json::from_str(r#"{"inputs":{"tag":"0.2.0"},"repository":{"private":false}}"#)
                .expect("steady-state dispatch payload should parse");
        assert_eq!(
            select_registry_auth_path(
                RegistryCredentialPolicy::OidcOnly,
                "workflow_dispatch",
                &steady,
            )
            .expect("steady dispatch should select OIDC"),
            RegistryAuthPath::OidcOnly
        );
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
        assert!(require_registry_token(Some(std::ffi::OsStr::new(""))).is_err());
        require_registry_token(Some(std::ffi::OsStr::new("opaque-test-capability")))
            .expect("any nonempty credential source is accepted");
    }

    #[test]
    fn oidc_fallback_requires_every_configured_crate_name() {
        let packages = vec![
            "memcordon-core".to_owned(),
            "memcordon-platform".to_owned(),
            "memcordon".to_owned(),
        ];
        let mut checked = Vec::new();
        let partial = require_oidc_fallback_names(&packages, |package| {
            checked.push(package.to_owned());
            Ok(package != "memcordon-platform")
        });
        assert!(partial.is_err());
        assert_eq!(checked, ["memcordon-core", "memcordon-platform"]);
        require_oidc_fallback_names(&packages, |_| Ok(true))
            .expect("fallback should proceed only after all names exist");
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
            schema_version: 1,
            manifest_sha256: "digest".to_owned(),
            github_release_id: 7,
            source_commit: "commit".to_owned(),
            workflow_commit: "workflow".to_owned(),
            prerelease: false,
            assets: Vec::new(),
            crates: Vec::new(),
        };
        let cross_mode_bytes: Vec<Vec<u8>> = [
            RegistryAuthPath::StoredToken,
            RegistryAuthPath::OidcFallback,
            RegistryAuthPath::OidcOnly,
        ]
        .into_iter()
        .map(|_attempt_local_path| {
            serde_json::to_vec(&report).expect("report should serialize identically")
        })
        .collect();
        assert!(
            cross_mode_bytes.windows(2).all(|pair| pair[0] == pair[1]),
            "credential origin must not change final report bytes"
        );
        let bytes = &cross_mode_bytes[0];
        let text = std::str::from_utf8(bytes).expect("report should be UTF-8");
        for forbidden in ["StoredToken", "OidcFallback", "OidcOnly", "registry_auth"] {
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
    fn http_mock_github_response_loss_is_reconciled_and_rerun_is_idempotent() {
        let (temporary, _) = release_fixture();
        let server = MockServer::scripted(vec![
            MockResponse::Json(404, serde_json::json!({"message": "not found"})),
            MockResponse::LoseResponse,
            MockResponse::Json(200, remote(true)),
            MockResponse::Json(200, remote(true)),
        ]);
        let endpoints = HttpEndpoints::fixed_test_server(&server.root);
        let first = create_or_reconcile_github_draft_at(temporary.path(), "token", &endpoints)
            .expect("lost create response should reconcile by GET");
        let second = create_or_reconcile_github_draft_at(temporary.path(), "token", &endpoints)
            .expect("end-to-end rerun should reuse the draft");
        assert_eq!(first, second);
        let requests = server.finish();
        assert_eq!(requests.len(), 4);
        assert!(requests[0].starts_with("GET "));
        assert!(requests[1].starts_with("POST "));
        assert!(requests[2].starts_with("GET "));
        assert!(requests[3].starts_with("GET "));
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
            MockResponse::Json(200, release_state),
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
        assert_eq!(requests.len(), 2);
        assert!(requests[0].starts_with("POST "));
        assert!(requests[1].starts_with("GET "));
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
