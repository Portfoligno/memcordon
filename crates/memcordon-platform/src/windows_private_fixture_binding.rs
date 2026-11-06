//! Authenticated declarations are data, never a native fixture capability.
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

pub const MAX_ANCESTORS: usize = 64;
pub const MAX_NATIVE_PATH_UNITS: usize = 2048;

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
        if self.revision != 1
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
