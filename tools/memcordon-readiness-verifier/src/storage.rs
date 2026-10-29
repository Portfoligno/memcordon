//! One-level physical storage for unchanged logical evidence records.
use crate::{
    Artifact, MAX_ARTIFACT_BYTES, MAX_INDEX_BYTES, MAX_PRODUCER_ARTIFACTS, MAX_PRODUCER_BYTES,
    VerificationResult,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactBinding {
    pub logical_path: String,
    pub object_path: String,
}

#[derive(Clone, Debug)]
pub struct StoragePlan {
    physical: BTreeMap<String, Artifact>,
    resolution: BTreeMap<String, String>,
    total: u64,
    packed: bool,
}

#[derive(Clone, Debug)]
pub struct ZipMember {
    pub name: String,
    pub length: u64,
    pub directory: bool,
}

pub fn object_path(digest: &str) -> VerificationResult<String> {
    crate::digest(digest)?;
    Ok(format!("objects/sha256/{digest}"))
}

fn tuple_equal(left: &Artifact, right: &Artifact) -> bool {
    left.length == right.length && left.sha256 == right.sha256
}

struct MetadataCounter {
    length: usize,
}

impl std::io::Write for MetadataCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.length = self
            .length
            .checked_add(bytes.len())
            .filter(|length| *length <= MAX_INDEX_BYTES)
            .ok_or_else(|| std::io::Error::other("storage tables exceed metadata byte bound"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn artifact(record: &Artifact, archive: bool) -> VerificationResult<()> {
    crate::custody::validate_path(&record.path)?;
    crate::digest(&record.sha256)?;
    if record.length
        > if archive {
            MAX_PRODUCER_BYTES
        } else {
            MAX_ARTIFACT_BYTES
        }
    {
        return Err("storage artifact exceeds per-file bound".into());
    }
    Ok(())
}

impl StoragePlan {
    /// Packed report roots contain exactly their declared physical files.
    pub fn validate_directory(&self, root: &std::path::Path) -> VerificationResult<()> {
        if !self.packed {
            return Ok(());
        }
        let mut pending = vec![root.to_path_buf()];
        let mut files = BTreeSet::new();
        let mut entries = 0usize;
        while let Some(directory) = pending.pop() {
            let metadata = std::fs::symlink_metadata(&directory).map_err(|e| e.to_string())?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err("packed storage directory is not ordinary".into());
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & 0x400 != 0 {
                    return Err("packed storage traverses a reparse point".into());
                }
            }
            for entry in std::fs::read_dir(&directory).map_err(|e| e.to_string())? {
                let path = entry.map_err(|e| e.to_string())?.path();
                entries = entries
                    .checked_add(1)
                    .ok_or("packed directory entry count overflow")?;
                if entries > MAX_PRODUCER_ARTIFACTS {
                    return Err("packed directory member count exceeds bound".into());
                }
                let metadata = std::fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
                if metadata.file_type().is_symlink() {
                    return Err("packed storage has a filesystem alias".into());
                }
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if metadata.file_attributes() & 0x400 != 0 {
                        return Err("packed storage member is a reparse point".into());
                    }
                }
                if metadata.is_dir() {
                    let relative = path.strip_prefix(root).map_err(|e| e.to_string())?;
                    if !self
                        .physical
                        .keys()
                        .any(|name| std::path::Path::new(name).starts_with(relative))
                    {
                        return Err("packed storage has undeclared directory".into());
                    }
                    pending.push(path);
                } else if metadata.is_file() {
                    let relative = path.strip_prefix(root).map_err(|e| e.to_string())?;
                    let name = relative
                        .components()
                        .map(|part| match part {
                            std::path::Component::Normal(name) => {
                                name.to_str().ok_or("packed storage member is not UTF-8")
                            }
                            _ => Err("packed storage member is not relative"),
                        })
                        .collect::<Result<Vec<_>, _>>()?
                        .join("/");
                    crate::custody::validate_path(&name)?;
                    if !self.physical.contains_key(&name) || !files.insert(name) {
                        return Err("packed storage has undeclared physical file".into());
                    }
                } else {
                    return Err("packed storage has special filesystem member".into());
                }
            }
        }
        if files.len() != self.physical.len() {
            return Err("packed storage physical member missing".into());
        }
        Ok(())
    }
    /// Validate the complete physical container before extracting any payload.
    pub fn validate_zip(
        &self,
        members: &[ZipMember],
        archive_bytes: u64,
    ) -> VerificationResult<()> {
        if members.len() > MAX_PRODUCER_ARTIFACTS {
            return Err("ZIP storage member count exceeds bound".into());
        }
        let mut files = BTreeMap::new();
        let mut directories = BTreeSet::new();
        let mut total = archive_bytes;
        for member in members {
            let name = if member.directory {
                member
                    .name
                    .strip_suffix('/')
                    .ok_or("ZIP directory lacks canonical suffix")?
            } else {
                member.name.as_str()
            };
            crate::custody::validate_path(name)?;
            if files.contains_key(name) || directories.contains(name) {
                return Err("ZIP storage member is duplicate or changes kind".into());
            }
            if member.directory {
                if member.length != 0 {
                    return Err("ZIP directory contains payload bytes".into());
                }
                directories.insert(name.to_owned());
            } else {
                if member.length > MAX_ARTIFACT_BYTES {
                    return Err("ZIP storage member exceeds per-file bound".into());
                }
                files.insert(name.to_owned(), member.length);
            }
            total = total
                .checked_add(member.length)
                .ok_or("ZIP physical total overflow")?;
            if total > MAX_PRODUCER_BYTES {
                return Err(
                    "producer archive and decoded physical members exceed total evidence budget"
                        .into(),
                );
            }
        }
        if self.packed {
            let mut expected = self.physical.keys().cloned().collect::<BTreeSet<_>>();
            expected.extend(["cell.json".to_owned(), "producer-manifest.json".to_owned()]);
            if files.keys().cloned().collect::<BTreeSet<_>>() != expected {
                return Err("packed ZIP has missing or undeclared physical members".into());
            }
            let expected_directories: BTreeSet<_> = expected
                .iter()
                .flat_map(|name| {
                    std::path::Path::new(name)
                        .ancestors()
                        .skip(1)
                        .filter(|p| !p.as_os_str().is_empty())
                        .map(|p| p.to_string_lossy().into_owned())
                })
                .collect();
            if directories
                .iter()
                .any(|name| !expected_directories.contains(name))
            {
                return Err("packed ZIP has undeclared directory".into());
            }
            for record in self.physical.values() {
                if files.get(&record.path) != Some(&record.length) {
                    return Err("packed ZIP physical member length differs".into());
                }
            }
            let metadata = ["cell.json", "producer-manifest.json"]
                .into_iter()
                .try_fold(0u64, |total, name| {
                    let length = *files.get(name).ok_or("packed ZIP metadata absent")?;
                    if length > MAX_INDEX_BYTES as u64 {
                        return Err("packed ZIP metadata exceeds bound");
                    }
                    total
                        .checked_add(length)
                        .ok_or("packed ZIP metadata overflow")
                })?;
            self.check_budget(
                metadata
                    .checked_add(archive_bytes)
                    .ok_or("ZIP container budget overflow")?,
            )?;
        }
        for name in files.keys().chain(directories.iter()) {
            if std::path::Path::new(name)
                .ancestors()
                .skip(1)
                .filter(|parent| !parent.as_os_str().is_empty())
                .any(|parent| files.contains_key(parent.to_string_lossy().as_ref()))
            {
                return Err("ZIP file/directory prefix collision".into());
            }
        }
        Ok(())
    }
    pub fn direct(records: &[Artifact]) -> VerificationResult<Self> {
        if records.len() > MAX_PRODUCER_ARTIFACTS {
            return Err("direct storage reference count exceeds bound".into());
        }
        let mut physical = BTreeMap::new();
        let mut resolution = BTreeMap::new();
        let mut total = 0u64;
        for record in records {
            // Archive roles are checked by the caller's origin inventory.
            artifact(record, true)?;
            if physical
                .insert(record.path.clone(), record.clone())
                .is_some()
            {
                return Err("duplicate logical storage path".into());
            }
            resolution.insert(record.path.clone(), record.path.clone());
            total = total
                .checked_add(record.length)
                .ok_or("storage total overflow")?;
        }
        let plan = Self {
            physical,
            resolution,
            total,
            packed: false,
        };
        plan.check_budget(0)?;
        Ok(plan)
    }

    pub fn packed(
        logical: &[Artifact],
        objects: &[Artifact],
        bindings: &[ArtifactBinding],
        archives: &BTreeSet<String>,
    ) -> VerificationResult<Self> {
        if logical.len() > MAX_PRODUCER_ARTIFACTS
            || objects.len() > MAX_PRODUCER_ARTIFACTS
            || bindings.len() > MAX_PRODUCER_ARTIFACTS
        {
            return Err("storage reference inventory exceeds bound".into());
        }
        let mut logical_table = BTreeMap::new();
        let mut physical = BTreeMap::new();
        let mut resolution = BTreeMap::new();
        for record in logical {
            artifact(record, archives.contains(&record.path))?;
            if matches!(
                record.path.split('/').next(),
                Some(
                    "objects"
                        | "producer"
                        | "cell.json"
                        | "producer-manifest.json"
                        | "evidence.json"
                )
            ) || logical_table.insert(record.path.clone(), record).is_some()
            {
                return Err("logical storage path is duplicate or reserved".into());
            }
            if archives.contains(&record.path) {
                physical.insert(record.path.clone(), record.clone());
                resolution.insert(record.path.clone(), record.path.clone());
            }
        }
        if archives
            .iter()
            .any(|path| !logical_table.contains_key(path))
        {
            return Err("storage archive role lacks logical artifact".into());
        }
        for record in objects {
            artifact(record, false)?;
            if record.path != object_path(&record.sha256)?
                || physical
                    .insert(record.path.clone(), record.clone())
                    .is_some()
            {
                return Err("physical object path is duplicate or differs from digest key".into());
            }
        }
        let mut used = BTreeSet::new();
        for binding in bindings {
            let logical = logical_table
                .get(&binding.logical_path)
                .ok_or("binding lacks logical artifact")?;
            if archives.contains(&binding.logical_path) {
                return Err("original producer archive cannot be an object alias".into());
            }
            let object = physical
                .get(&binding.object_path)
                .ok_or("binding lacks physical object")?;
            if !binding.object_path.starts_with("objects/sha256/")
                || !tuple_equal(logical, object)
                || resolution
                    .insert(binding.logical_path.clone(), binding.object_path.clone())
                    .is_some()
            {
                return Err(
                    "storage binding is duplicate, recursive or changes artifact tuple".into(),
                );
            }
            used.insert(binding.object_path.clone());
        }
        if resolution.len() != logical_table.len()
            || objects.iter().any(|object| !used.contains(&object.path))
        {
            return Err("storage graph has missing bindings or unreferenced objects".into());
        }
        // Bound cumulative alias metadata before publication, not only when the
        // final evidence document is persisted. The complete envelope is larger.
        serde_json::to_writer(
            &mut MetadataCounter { length: 0 },
            &(logical, objects, bindings, archives),
        )
        .map_err(|e| e.to_string())?;
        // Logical aliases create no directories. Inspect their ancestors without
        // materializing a potentially amplified tree of temporary path strings.
        if logical_table.keys().chain(physical.keys()).any(|path| {
            std::path::Path::new(path)
                .ancestors()
                .skip(1)
                .filter(|parent| !parent.as_os_str().is_empty())
                .any(|parent| {
                    let parent = parent.to_string_lossy();
                    logical_table.contains_key(parent.as_ref())
                        || physical.contains_key(parent.as_ref())
                })
        }) {
            return Err("storage file/directory prefix collision".into());
        }
        // Count physical entries and their directories, including the two metadata files.
        let physical_directories: BTreeSet<_> = physical
            .keys()
            .flat_map(|path| {
                std::path::Path::new(path)
                    .ancestors()
                    .skip(1)
                    .filter(|path| !path.as_os_str().is_empty())
                    .map(std::path::Path::to_path_buf)
            })
            .collect();
        if physical
            .len()
            .checked_add(physical_directories.len())
            .and_then(|n| n.checked_add(2))
            .is_none_or(|n| n > MAX_PRODUCER_ARTIFACTS)
        {
            return Err("physical storage member inventory exceeds bound".into());
        }
        let total = physical.values().try_fold(0u64, |total, record| {
            total
                .checked_add(record.length)
                .ok_or("physical storage total overflow")
        })?;
        let plan = Self {
            physical,
            resolution,
            total,
            packed: true,
        };
        plan.check_budget(0)?;
        Ok(plan)
    }

    pub fn is_packed(&self) -> bool {
        self.packed
    }
    pub fn physical_artifacts(&self) -> impl Iterator<Item = &Artifact> {
        self.physical.values()
    }
    pub fn resolve(&self, path: &str) -> VerificationResult<&Artifact> {
        let physical = self
            .resolution
            .get(path)
            .ok_or("logical artifact lacks storage binding")?;
        self.physical
            .get(physical)
            .ok_or_else(|| "physical artifact absent".into())
    }
    pub fn check_budget(&self, other_bytes: u64) -> VerificationResult<u64> {
        self.total
            .checked_add(other_bytes)
            .filter(|total| *total <= MAX_PRODUCER_BYTES)
            .ok_or_else(|| {
                "physical evidence including archives and metadata exceeds total budget".into()
            })
    }
}
