//! Ordinary Git/tag/version selection. This module does not grant permissions.
use std::{collections::BTreeSet, fs, io::Read, path::Path};

use cargo_metadata::{DependencyKind, Metadata};
use semver::Version;
use serde::{Deserialize, Serialize};

use super::git::Git;
use crate::{CiError, Result};

pub const PUBLIC_PACKAGES: [&str; 4] = [
    "memcordon-core",
    "memcordon-windows-launch-core",
    "memcordon-platform",
    "memcordon",
];
const MAX_RECORD: u64 = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedSource {
    pub format: String,
    pub revision: u32,
    pub repository: String,
    pub tag_ref: String,
    pub commit: String,
    pub version: Version,
}

/// Actual build selection. A branch build has no release tag and cannot be
/// promoted into publication merely by serializing its descriptive identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum BuildSourceIdentity {
    Tagged { source: SelectedSource },
    Working { version: Version, commit: String },
}

impl BuildSourceIdentity {
    pub fn version(&self) -> &Version {
        match self {
            Self::Tagged { source } => &source.version,
            Self::Working { version, .. } => version,
        }
    }
    pub fn commit(&self) -> &str {
        match self {
            Self::Tagged { source } => &source.commit,
            Self::Working { commit, .. } => commit,
        }
    }
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Tagged { source } => source.validate(),
            Self::Working {
                version: selected,
                commit,
            } => {
                validate_oid(commit)?;
                version(&selected.to_string())?;
                Ok(())
            }
        }
    }
    pub fn require_tagged(&self) -> Result<&SelectedSource> {
        match self {
            Self::Tagged { source } => {
                source.validate()?;
                Ok(source)
            }
            Self::Working { .. } => Err(CiError::Message(
                "working build identity cannot select publication".into(),
            )),
        }
    }
    pub fn working(root: &Path) -> Result<Self> {
        let git = Git::new(root)?;
        git.require_clean()?;
        let commit = git.text(["rev-parse", "--verify", "HEAD"])?;
        let metadata = metadata(root)?;
        let selected = metadata
            .workspace_packages()
            .into_iter()
            .find(|package| package.name.as_str() == "memcordon-core")
            .ok_or_else(|| CiError::Message("working public core package absent".into()))?
            .version
            .clone();
        public_order(&metadata, &selected)?;
        let value = Self::Working {
            version: selected,
            commit,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn recheck(&self, root: &Path) -> Result<()> {
        self.validate()?;
        match self {
            Self::Tagged { source } => source.recheck(root),
            Self::Working { .. } => {
                if Self::working(root)? != *self {
                    return Err(CiError::Message("working source identity changed".into()));
                }
                Ok(())
            }
        }
    }
}

impl From<SelectedSource> for BuildSourceIdentity {
    fn from(source: SelectedSource) -> Self {
        Self::Tagged { source }
    }
}

pub fn version(text: &str) -> Result<Version> {
    let version = Version::parse(text)?;
    if version.to_string() != text || !version.build.is_empty() {
        return Err(CiError::Message(
            "tag must be canonical unprefixed SemVer without build metadata".into(),
        ));
    }
    Ok(version)
}

pub fn validate_repository(repository: &str) -> Result<()> {
    let components: Vec<_> = repository.split('/').collect();
    if components.len() != 2
        || components.iter().any(|part| {
            part.is_empty()
                || *part == "."
                || *part == ".."
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
    {
        return Err(CiError::Message("invalid GitHub owner/repository".into()));
    }
    Ok(())
}

pub fn validate_oid(oid: &str) -> Result<()> {
    // Git determines the object format. Do not assume SHA-1's width.
    if oid.is_empty() || !oid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CiError::Message("invalid full Git object ID".into()));
    }
    Ok(())
}

pub fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_RECORD + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RECORD {
        return Err(CiError::Message("release record exceeds byte bound".into()));
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes).map_err(CiError::Message)?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    use std::io::Write;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_RECORD {
        return Err(CiError::Message("release record exceeds byte bound".into()));
    }
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| CiError::Io(error.error))?;
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

pub fn public_order(metadata: &Metadata, expected_version: &Version) -> Result<Vec<String>> {
    let mut remaining: BTreeSet<_> = PUBLIC_PACKAGES.into_iter().collect();
    let mut order: Vec<String> = Vec::new();
    for name in PUBLIC_PACKAGES {
        let package = metadata
            .workspace_packages()
            .into_iter()
            .find(|package| package.name.as_str() == name)
            .ok_or_else(|| CiError::Message(format!("public package absent: {name}")))?;
        if &package.version != expected_version
            || package.publish.as_ref().is_some_and(|registries| {
                !registries.iter().any(|registry| registry == "crates-io")
            })
        {
            return Err(CiError::Message(format!(
                "public package version/registry differs: {name}"
            )));
        }
        for dependency in &package.dependencies {
            if dependency.kind == DependencyKind::Development {
                continue;
            }
            if dependency.path.is_some() && !PUBLIC_PACKAGES.contains(&dependency.name.as_str()) {
                return Err(CiError::Message(format!(
                    "unpublished runtime dependency: {}",
                    dependency.name
                )));
            }
            if PUBLIC_PACKAGES.contains(&dependency.name.as_str()) {
                let requirement = dependency.req.comparators.as_slice();
                if requirement.len() != 1
                    || requirement[0].op != semver::Op::Exact
                    || !dependency.req.matches(expected_version)
                {
                    return Err(CiError::Message(format!(
                        "internal dependency version differs: {}",
                        dependency.name
                    )));
                }
            }
        }
    }
    while !remaining.is_empty() {
        let next = remaining
            .iter()
            .copied()
            .find(|name| {
                let package = metadata
                    .workspace_packages()
                    .into_iter()
                    .find(|package| package.name.as_str() == *name)
                    .expect("validated package");
                package.dependencies.iter().all(|dependency| {
                    dependency.kind == DependencyKind::Development
                        || !remaining.contains(dependency.name.as_str())
                })
            })
            .ok_or_else(|| CiError::Message("public package dependency cycle".into()))?;
        remaining.remove(next);
        order.push(next.into());
    }
    Ok(order)
}

pub fn metadata(root: &Path) -> Result<Metadata> {
    let toolchain = crate::config::toolchains(root)?.stable;
    let bytes = crate::command::rustup_cargo(
        root,
        &toolchain,
        ["metadata", "--locked", "--format-version", "1", "--no-deps"],
        std::time::Duration::from_secs(120),
    )
    .output_quiet()?;
    if !bytes.status.success() {
        return Err(CiError::Message("Cargo metadata failed".into()));
    }
    Ok(serde_json::from_slice(&bytes.stdout)?)
}

pub fn select(root: &Path, repository: &str, full_ref: &str) -> Result<SelectedSource> {
    validate_repository(repository)?;
    let tag = full_ref
        .strip_prefix("refs/tags/")
        .ok_or_else(|| CiError::Message("publication requires an existing full tag ref".into()))?;
    let version = version(tag)?;
    let git = Git::new(root)?;
    git.require_clean()?;
    let selected = git.tag(full_ref)?;
    let head = git.text(["rev-parse", "--verify", "HEAD"])?;
    if selected.commit != head {
        return Err(CiError::Message(
            "tag does not select checked-out HEAD".into(),
        ));
    }
    public_order(&metadata(root)?, &version)?;
    Ok(SelectedSource {
        format: "memcordon.selected-source".into(),
        revision: 1,
        repository: repository.into(),
        tag_ref: selected.full_ref,
        commit: selected.commit,
        version,
    })
}

impl SelectedSource {
    pub fn validate(&self) -> Result<()> {
        if self.format != "memcordon.selected-source"
            || self.revision != 1
            || self.tag_ref.strip_prefix("refs/tags/") != Some(self.version.to_string().as_str())
        {
            return Err(CiError::Message(
                "unsupported selected-source record".into(),
            ));
        }
        validate_repository(&self.repository)?;
        validate_oid(&self.commit)?;
        version(&self.version.to_string())?;
        Ok(())
    }

    pub fn recheck(&self, root: &Path) -> Result<()> {
        self.validate()?;
        if select(root, &self.repository, &self.tag_ref)? != *self {
            return Err(CiError::Message("selected source changed".into()));
        }
        Ok(())
    }
}
