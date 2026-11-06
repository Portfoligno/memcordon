//! Authenticated declarations are data, never a native fixture capability.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};

pub const MAX_ANCESTORS: usize = 64;
pub const MAX_NATIVE_PATH_UNITS: usize = 2048;
pub const MAX_DIRECTORY_REFERENCES: usize = MAX_ANCESTORS * 2 + 1;
pub const DIRECTORY_QUERY_ACCESS: u32 = 0x80;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateFixtureAncestor {
    pub path: PathBuf,
    pub volume_serial: u32,
    pub file_index: u64,
    pub attributes: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateFixtureBinding {
    pub revision: u32,
    pub fixture: PathBuf,
    pub volume_serial: u32,
    pub file_index: u64,
    pub attributes: u32,
    pub links: u32,
    pub bytes: u64,
    pub sha256: String,
    pub native_path_utf16: Vec<u16>,
    /// The exact held chain, ordered from root through the fixture's parent.
    pub ancestors: Vec<PrivateFixtureAncestor>,
    pub local_directory: PrivateFixtureAncestor,
    /// Exact controller-held output chain, ordered root through output root.
    pub output_ancestors: Vec<PrivateFixtureAncestor>,
}

fn absolute(path: &Path) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
}

impl PrivateFixtureBinding {
    pub fn validate(&self, paths: &[PathBuf]) -> Result<(), String> {
        let parent = self
            .fixture
            .parent()
            .ok_or("private fixture parent absent")?;
        let leaf = self
            .fixture
            .file_name()
            .ok_or("private fixture leaf absent")?;
        let mut local = leaf.to_os_string();
        local.push(".local");
        let local = parent.join(local);
        if self.revision != 2
            || !(2..=9).contains(&paths.len())
            || paths.first() != Some(&self.fixture)
            || !absolute(&self.fixture)
            || self.attributes & (0x10 | 0x400) != 0
            || self.links != 1
            || self.bytes == 0
            || self.sha256.len() != 64
            || !self
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || self.native_path_utf16.is_empty()
            || self.native_path_utf16.len() > MAX_NATIVE_PATH_UNITS
            || self.native_path_utf16.first() != Some(&92)
            || self.native_path_utf16.contains(&0)
        {
            return Err("invalid private fixture declaration".into());
        }
        if paths.iter().any(|path| {
            !absolute(path) || (path != &self.fixture && path.parent() != Some(local.as_path()))
        }) || paths
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != paths.len()
        {
            return Err("private fixture target set differs".into());
        }
        let directory = |item: &PrivateFixtureAncestor| {
            absolute(&item.path) && item.attributes & 0x10 != 0 && item.attributes & 0x400 == 0
        };
        if self.ancestors.is_empty()
            || self.ancestors.len() > MAX_ANCESTORS
            || self.ancestors.iter().any(|item| !directory(item))
            || self.ancestors[0].path.parent().is_some()
            || self.ancestors.last().map(|item| item.path.as_path()) != Some(parent)
            || self
                .ancestors
                .windows(2)
                .any(|pair| pair[1].path.parent() != Some(pair[0].path.as_path()))
            || !directory(&self.local_directory)
            || self.local_directory.path != local
        {
            return Err("private fixture ancestry declaration differs".into());
        }
        Ok(())
    }

    pub fn validate_output(&self, output: &Path) -> Result<(), String> {
        let parent = self.ancestors.last().ok_or("private input parent absent")?;
        let chain = &self.output_ancestors;
        if !absolute(output)
            || chain.is_empty()
            || chain.len() > MAX_ANCESTORS
            || chain[0].path.parent().is_some()
            || chain.last().map(|item| item.path.as_path()) != Some(output)
            || chain
                .windows(2)
                .any(|pair| pair[1].path.parent() != Some(pair[0].path.as_path()))
            || chain.iter().any(|item| {
                !absolute(&item.path)
                    || item.attributes & 0x10 == 0
                    || item.attributes & 0x400 != 0
                    || [parent, &self.local_directory].iter().any(|input| {
                        (item.volume_serial, item.file_index)
                            == (input.volume_serial, input.file_index)
                    })
            })
        {
            return Err("private output ancestry declaration or separation differs".into());
        }
        Ok(())
    }

    pub fn directory_expectation(&self) -> Result<DirectoryExpectation, String> {
        if self.revision != 2 {
            return Err("private directory manifest revision differs".into());
        }
        let mut expected = DirectoryExpectation {
            manifest_sha256: [0; 32],
            input_count: u32::try_from(self.ancestors.len())
                .map_err(|_| "input ancestry count overflow")?,
            output_count: u32::try_from(self.output_ancestors.len())
                .map_err(|_| "output ancestry count overflow")?,
        };
        expected.validate()?;
        expected.manifest_sha256 =
            Sha256::digest(serde_json::to_vec(self).map_err(|error| error.to_string())?).into();
        Ok(expected)
    }
}

/// Transport data only. Native ownership is admitted privately after START.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[repr(u32)]
pub enum DirectoryRole {
    InputAncestor = 1,
    LocalDirectory = 2,
    OutputAncestor = 3,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryExpectation {
    pub manifest_sha256: [u8; 32],
    pub input_count: u32,
    pub output_count: u32,
}
impl DirectoryExpectation {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=MAX_ANCESTORS as u32).contains(&self.input_count)
            || !(1..=MAX_ANCESTORS as u32).contains(&self.output_count)
        {
            return Err("directory reference count exceeds finite chain bounds".into());
        }
        Ok(())
    }
    pub fn roles(&self) -> Result<Vec<(DirectoryRole, u32)>, String> {
        self.validate()?;
        Ok((0..self.input_count)
            .map(|index| (DirectoryRole::InputAncestor, index))
            .chain(std::iter::once((DirectoryRole::LocalDirectory, 0)))
            .chain((0..self.output_count).map(|index| (DirectoryRole::OutputAncestor, index)))
            .collect())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryReference {
    pub role: DirectoryRole,
    pub index: u32,
    pub handle: u64,
    pub access_mask: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryTransfer {
    pub version: u32,
    pub manifest_sha256: [u8; 32],
    pub references: Vec<DirectoryReference>,
}
impl DirectoryTransfer {
    pub fn validate(&self, expected: &DirectoryExpectation) -> Result<(), String> {
        let roles = expected.roles()?;
        if self.version != 1
            || self.manifest_sha256 != expected.manifest_sha256
            || self.references.len() != roles.len()
            || self.references.len() > MAX_DIRECTORY_REFERENCES
        {
            return Err("directory transfer version, manifest or extent differs".into());
        }
        let mut handles = std::collections::BTreeSet::new();
        for (reference, (role, index)) in self.references.iter().zip(roles) {
            if reference.role != role
                || reference.index != index
                || reference.access_mask != DIRECTORY_QUERY_ACCESS
                || reference.handle == 0
                || reference.handle > i64::MAX as u64
                || !handles.insert(reference.handle)
            {
                return Err(
                    "directory transfer role, order, query rights or distinct handle differs"
                        .into(),
                );
            }
        }
        Ok(())
    }
}

pub fn validate_declaration(
    experiment: bool,
    paths: &[PathBuf],
    binding: Option<&PrivateFixtureBinding>,
) -> Result<(), String> {
    match (experiment, binding) {
        (true, Some(binding)) => binding.validate(paths),
        (true, None) => Err("private fixture binding absent from experiment".into()),
        (false, Some(_)) => Err("private fixture binding requires explicit experiment".into()),
        (false, None) if paths.is_empty() => Ok(()),
        (false, None) => Err("provider input paths require explicit experiment".into()),
    }
}
