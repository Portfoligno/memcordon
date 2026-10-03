//! Prepared payloads contain actual bytes and ordinary source identities.
use super::{
    artifacts::{self, FileRecord},
    distribution::Distribution,
    packages::PackageBundle,
    source::{self, SelectedSource},
};
use crate::{CiError, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicManifest {
    pub schema: u32,
    pub version: semver::Version,
    pub tag: String,
    pub commit: String,
    pub files: Vec<FileRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedBundle {
    pub format: String,
    pub revision: u32,
    pub source: SelectedSource,
    pub distribution: Distribution,
    pub files: Vec<FileRecord>,
    pub notes: String,
}

pub struct LoadedBundle {
    pub metadata: PreparedBundle,
    pub payloads: Vec<Vec<u8>>,
}

impl PreparedBundle {
    pub fn load(directory: &Path) -> Result<LoadedBundle> {
        let metadata: Self = source::read_json(&directory.join("prepared.json"))?;
        metadata.validate()?;
        let mut payloads = Vec::new();
        let mut manifests = std::collections::BTreeMap::new();
        for file in &metadata.files {
            let bytes = artifacts::read_file(&directory.join(&file.name))?;
            artifacts::check_bytes(file, &bytes)?;
            if file.kind == "archive" {
                let target = metadata
                    .distribution
                    .targets
                    .iter()
                    .find(|target| Some(target.target.as_str()) == file.target.as_deref())
                    .ok_or_else(|| {
                        CiError::Message("prepared archive target is not selected".into())
                    })?;
                let members = super::target::decode_archive(&bytes, &target.target)?;
                let expected: BTreeSet<_> = target
                    .binaries
                    .iter()
                    .map(|name| super::target::binary_name(name, &target.target))
                    .chain(target.units.iter().cloned())
                    .chain(["runtime-manifest.json".into(), "package.json".into()])
                    .collect();
                if members.keys().cloned().collect::<BTreeSet<_>>() != expected {
                    return Err(CiError::Message(
                        "prepared archive native inventory differs".into(),
                    ));
                }
                let manifest = memcordon_core::runtime_manifest::RuntimeManifest::parse(
                    &members["runtime-manifest.json"],
                )
                .map_err(CiError::Message)?;
                super::compatibility::NativePackage::verify(
                    &members["package.json"],
                    &metadata.source.clone().into(),
                    target,
                    &members,
                )?;
                if manifest.version != metadata.source.version.to_string()
                    || manifest.source_commit != metadata.source.commit
                    || manifest.target != target.target
                    || manifest.components.len() != target.binaries.len()
                {
                    return Err(CiError::Message(
                        "prepared archive runtime source/selection differs".into(),
                    ));
                }
                for component in &manifest.components {
                    let bytes = members
                        .get(&component.path)
                        .ok_or_else(|| CiError::Message("prepared component absent".into()))?;
                    super::target::validate_executable(bytes, &target.target)?;
                    if component.size != bytes.len() as u64
                        || component.sha256 != artifacts::checksum(bytes)
                    {
                        return Err(CiError::Message(
                            "prepared component byte identity differs".into(),
                        ));
                    }
                }
                manifests.insert(target.target.clone(), manifest);
            }
            payloads.push(bytes);
        }
        let manifest = metadata
            .files
            .iter()
            .position(|file| file.kind == "manifest")
            .expect("validated manifest");
        let public: PublicManifest = serde_json::from_slice(&payloads[manifest])?;
        if public.schema != 1
            || public.version != metadata.source.version
            || public.tag != metadata.source.version.to_string()
            || public.commit != metadata.source.commit
            || public.files
                != metadata
                    .files
                    .iter()
                    .filter(|file| {
                        matches!(file.kind.as_str(), "crate" | "archive" | "compatibility")
                    })
                    .cloned()
                    .collect::<Vec<_>>()
        {
            return Err(CiError::Message(
                "public manifest differs from prepared bytes".into(),
            ));
        }
        let compatibility = metadata
            .files
            .iter()
            .position(|file| file.kind == "compatibility")
            .expect("validated compatibility inventory");
        memcordon_core::canonical_json::reject_duplicate_json_keys(&payloads[compatibility])
            .map_err(CiError::Message)?;
        let supplied: super::compatibility::Compatibility =
            serde_json::from_slice(&payloads[compatibility])?;
        if supplied
            != super::compatibility::Compatibility::selected(
                &metadata.source.clone().into(),
                &metadata.distribution,
                &manifests,
            )?
        {
            return Err(CiError::Message(
                "public compatibility metadata differs from measured selected runtimes".into(),
            ));
        }
        let checksums = metadata
            .files
            .iter()
            .position(|file| file.kind == "checksums")
            .expect("validated checksums");
        if payloads[checksums]
            != checksum_file(
                metadata
                    .files
                    .iter()
                    .filter(|file| file.kind != "checksums"),
            )
        {
            return Err(CiError::Message("prepared checksum listing differs".into()));
        }
        let package_files: Vec<_> = metadata
            .files
            .iter()
            .filter(|file| file.kind == "crate")
            .cloned()
            .collect();
        let package_bytes: Vec<_> = metadata
            .files
            .iter()
            .zip(&payloads)
            .filter(|(file, _)| file.kind == "crate")
            .map(|(_, bytes)| bytes.clone())
            .collect();
        let packages = PackageBundle {
            format: "memcordon.packages".into(),
            revision: 1,
            source: metadata.source.clone().into(),
            files: package_files,
        };
        let order = super::packages::archive_order(&packages, &package_bytes)?;
        if packages
            .files
            .iter()
            .filter_map(|file| file.package.as_ref())
            .ne(order.iter())
        {
            return Err(CiError::Message(
                "prepared registry order differs from normalized archives".into(),
            ));
        }
        Ok(LoadedBundle { metadata, payloads })
    }

    pub fn validate(&self) -> Result<()> {
        self.source.validate()?;
        self.distribution.validate()?;
        if self.format != "memcordon.prepared-release"
            || self.revision != 1
            || self.files.len() > 128
            || self.notes.is_empty()
            || self.notes.len() > 1024 * 1024
        {
            return Err(CiError::Message(
                "prepared release format/size differs".into(),
            ));
        }
        let mut names = BTreeSet::new();
        let mut packages = BTreeSet::new();
        let mut targets = BTreeSet::new();
        let mut kinds = BTreeSet::new();
        let mut aggregate = 0_u64;
        for file in &self.files {
            aggregate = aggregate
                .checked_add(file.byte_len)
                .ok_or_else(|| CiError::Message("prepared byte total overflow".into()))?;
            if aggregate > 1024 * 1024 * 1024 {
                return Err(CiError::Message(
                    "prepared aggregate byte bound exceeded".into(),
                ));
            }
            artifacts::safe_basename(&file.name)?;
            if !names.insert(file.name.to_ascii_lowercase())
                || file.byte_len == 0
                || file.byte_len > artifacts::MAX_FILE_BYTES
                || file.sha256.len() != hex::encode([0_u8; 32]).len()
                || !file
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            {
                return Err(CiError::Message(
                    "prepared file name/length/digest differs".into(),
                ));
            }
            match file.kind.as_str() {
                "crate" if file.target.is_none() => {
                    let package = file
                        .package
                        .as_ref()
                        .ok_or_else(|| CiError::Message("crate package absent".into()))?;
                    if !packages.insert(package.clone()) {
                        return Err(CiError::Message("duplicate prepared package".into()));
                    }
                }
                "archive" if file.package.is_none() => {
                    let target = file
                        .target
                        .as_ref()
                        .ok_or_else(|| CiError::Message("archive target absent".into()))?;
                    if !targets.insert(target.clone()) {
                        return Err(CiError::Message("duplicate prepared target".into()));
                    }
                }
                "manifest" | "checksums" | "compatibility"
                    if file.package.is_none() && file.target.is_none() =>
                {
                    if !kinds.insert(file.kind.clone()) {
                        return Err(CiError::Message("duplicate prepared metadata".into()));
                    }
                }
                _ => return Err(CiError::Message("unsupported prepared file kind".into())),
            }
        }
        if packages != self.distribution.packages.iter().cloned().collect()
            || targets
                != self
                    .distribution
                    .targets
                    .iter()
                    .map(|target| target.target.clone())
                    .collect()
            || kinds
                != BTreeSet::from([
                    "manifest".into(),
                    "checksums".into(),
                    "compatibility".into(),
                ])
        {
            return Err(CiError::Message(
                "incomplete selected release inventory".into(),
            ));
        }
        Ok(())
    }
}

fn checksum_file<'a>(files: impl Iterator<Item = &'a FileRecord>) -> Vec<u8> {
    let mut records: Vec<_> = files.collect();
    records.sort_by(|left, right| left.name.cmp(&right.name));
    let mut output = Vec::new();
    for file in records {
        writeln!(&mut output, "{}  {}", file.sha256, file.name).expect("Vec write");
    }
    output
}

pub fn changelog_notes(root: &Path, version: &semver::Version) -> Result<String> {
    let text = String::from_utf8(artifacts::read_file(&root.join("CHANGELOG.md"))?)
        .map_err(|_| CiError::Message("changelog is not UTF-8".into()))?;
    let mut selected = false;
    let mut notes = String::new();
    for line in text.lines() {
        if let Some(heading) = line.strip_prefix("## ") {
            if selected {
                break;
            }
            let token = heading
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .trim_matches(['[', ']']);
            selected = token == version.to_string();
            continue;
        }
        if selected {
            notes.push_str(line);
            notes.push('\n');
        }
    }
    if notes.trim().is_empty() {
        return Err(CiError::Message(
            "exact selected changelog section absent".into(),
        ));
    }
    Ok(notes)
}

pub fn assemble(
    root: &Path,
    source_path: &Path,
    packages: &Path,
    target_directories: &[PathBuf],
    destination: &Path,
) -> Result<()> {
    let source: SelectedSource = source::read_json(source_path)?;
    source.recheck(root)?;
    let distribution = Distribution::read(root)?;
    let (packages, package_bytes) = PackageBundle::load(packages)?;
    if packages.source.require_tagged()? != &source || destination.exists() {
        return Err(CiError::Message(
            "assembly source/destination differs".into(),
        ));
    }
    let mut files = packages.files;
    let mut bytes = package_bytes;
    let mut manifests = std::collections::BTreeMap::new();
    for directory in target_directories {
        let (target, archive) = super::target::TargetBundle::load(directory)?;
        if target.source.require_tagged()? != &source
            || !distribution.targets.contains(&target.distribution)
        {
            return Err(CiError::Message(
                "target artifact source/selection differs".into(),
            ));
        }
        files.push(target.archive);
        let members = super::target::decode_archive(&archive, &target.distribution.target)?;
        manifests.insert(
            target.distribution.target.clone(),
            memcordon_core::runtime_manifest::RuntimeManifest::parse(
                &members["runtime-manifest.json"],
            )
            .map_err(CiError::Message)?,
        );
        bytes.push(archive);
    }
    let compatibility = super::compatibility::Compatibility::selected(
        &source.clone().into(),
        &distribution,
        &manifests,
    )?;
    let mut compatibility_bytes = serde_json::to_vec_pretty(&compatibility)?;
    compatibility_bytes.push(b'\n');
    files.push(FileRecord {
        name: "compatibility.json".into(),
        kind: "compatibility".into(),
        target: None,
        package: None,
        byte_len: compatibility_bytes.len() as u64,
        sha256: artifacts::checksum(&compatibility_bytes),
    });
    bytes.push(compatibility_bytes);
    let manifest = PublicManifest {
        schema: 1,
        version: source.version.clone(),
        tag: source.version.to_string(),
        commit: source.commit.clone(),
        files: files.clone(),
    };
    let mut manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    manifest_bytes.push(b'\n');
    files.push(FileRecord {
        name: "release-manifest.json".into(),
        kind: "manifest".into(),
        package: None,
        target: None,
        byte_len: manifest_bytes.len() as u64,
        sha256: artifacts::checksum(&manifest_bytes),
    });
    bytes.push(manifest_bytes);
    let sums = checksum_file(files.iter());
    files.push(FileRecord {
        name: "SHA256SUMS".into(),
        kind: "checksums".into(),
        package: None,
        target: None,
        byte_len: sums.len() as u64,
        sha256: artifacts::checksum(&sums),
    });
    bytes.push(sums);
    let prepared = PreparedBundle {
        format: "memcordon.prepared-release".into(),
        revision: 1,
        source,
        distribution,
        files,
        notes: changelog_notes(root, &manifest.version)?,
    };
    prepared.validate()?;
    fs::create_dir_all(destination)?;
    for (file, bytes) in prepared.files.iter().zip(bytes) {
        fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(destination.join(&file.name))?
            .write_all(&bytes)?;
    }
    source::write_json(&destination.join("prepared.json"), &prepared)?;
    PreparedBundle::load(destination)?;
    Ok(())
}
