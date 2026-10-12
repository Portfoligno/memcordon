#[cfg(any(target_os = "linux", test))]
use std::{
    collections::BTreeMap,
    path::{Component, Path, PathBuf},
};

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub(crate) struct SourceState {
    pub device: u64,
    pub inode: u64,
    pub links: u64,
    pub length: u64,
    pub modified: (i64, i64),
    pub changed: (i64, i64),
}

#[cfg(any(target_os = "linux", test))]
pub(crate) struct ClosedInventory(BTreeMap<PathBuf, SourceState>);

#[cfg(any(target_os = "linux", test))]
impl ClosedInventory {
    pub fn acquire(entries: Vec<(PathBuf, SourceState)>) -> Result<Self, String> {
        if entries.len() > 8192 {
            return Err("native recovery alias inventory exceeds bound".into());
        }
        let mut paths = BTreeMap::new();
        let mut inodes: BTreeMap<(u64, u64), Vec<PathBuf>> = BTreeMap::new();
        for (path, state) in entries {
            if path.as_os_str().is_empty()
                || path
                    .components()
                    .any(|part| !matches!(part, Component::Normal(_)))
                || state.links == 0
                || paths.insert(path.clone(), state.clone()).is_some()
            {
                return Err("native recovery alias inventory path/identity malformed".into());
            }
            inodes
                .entry((state.device, state.inode))
                .or_default()
                .push(path);
        }
        let cargo = Path::new("component-package-admin/materialized/fixture-build");
        for group in inodes.values() {
            let state = &paths[&group[0]];
            if group.len() as u64 != state.links
                || group.iter().any(|path| paths[path] != *state)
                || state.links > 1 && group.iter().any(|path| !path.starts_with(cargo))
            {
                return Err(
                    "native recovery Cargo aliases are not a closed original source graph".into(),
                );
            }
        }
        Ok(Self(paths))
    }

    pub fn source(&self, path: &Path) -> Result<&SourceState, String> {
        self.0
            .get(path)
            .ok_or_else(|| "native recovery source absent from original alias inventory".into())
    }

    pub fn verify(&self, entries: Vec<(PathBuf, SourceState)>) -> Result<(), String> {
        let current = Self::acquire(entries)?;
        if self.0 != current.0 {
            return Err("native recovery original alias inventory changed during capture".into());
        }
        Ok(())
    }
}
