//! Finite link accounting for names acquired beneath one owned admin root.
use std::{
    collections::BTreeMap,
    fs::Metadata,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, PartialEq, Eq)]
struct Stamp {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
    links: u64,
}
impl Stamp {
    fn of(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            length: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
            links: metadata.nlink(),
        }
    }
}

#[derive(Default)]
pub struct Inventory {
    links: BTreeMap<(u64, u64), (Stamp, u64)>,
    names: BTreeMap<PathBuf, (u64, u64)>,
    directories: BTreeMap<PathBuf, Stamp>,
}

impl Inventory {
    pub fn directory(
        &mut self,
        name: &Path,
        metadata: &Metadata,
        census: bool,
    ) -> Result<(), String> {
        let stamp = Stamp::of(metadata);
        if census {
            if self.directories.insert(name.to_path_buf(), stamp).is_some() {
                return Err("admin source directory duplicated during census".into());
            }
        } else if self
            .directories
            .remove(name)
            .is_none_or(|original| original != stamp)
        {
            return Err("admin source original directory identity changed".into());
        }
        Ok(())
    }

    pub fn observe(&mut self, name: &Path, metadata: &Metadata) -> Result<(), String> {
        let stamp = Stamp::of(metadata);
        if stamp.links == 0 {
            return Err("admin source inode has no live link".into());
        }
        let key = (stamp.device, stamp.inode);
        if self.names.insert(name.to_path_buf(), key).is_some() {
            return Err("admin source original name duplicated".into());
        }
        let entry = self.links.entry(key).or_insert((stamp, 0));
        if entry.0 != stamp {
            return Err("admin source inode changed during census".into());
        }
        entry.1 = entry
            .1
            .checked_add(1)
            .ok_or("admin source link count overflow")?;
        Ok(())
    }

    pub fn verify_complete(&self) -> Result<(), String> {
        if self
            .links
            .values()
            .any(|(stamp, names)| stamp.links != *names)
        {
            return Err("admin source inode has an alias outside its owned tree".into());
        }
        Ok(())
    }

    pub fn before_unlink(&self, name: &Path, metadata: &Metadata) -> Result<(), String> {
        let stamp = Stamp::of(metadata);
        let key = (stamp.device, stamp.inode);
        if self.names.get(name) != Some(&key)
            || self
                .links
                .get(&key)
                .is_none_or(|(expected, _)| expected != &stamp || stamp.links == 0)
        {
            return Err("admin source original name/inode custody changed before unlink".into());
        }
        Ok(())
    }

    pub fn after_unlink(&mut self, name: &Path, metadata: &Metadata) -> Result<(), String> {
        let stamp = Stamp::of(metadata);
        let key = (stamp.device, stamp.inode);
        if self.names.get(name) != Some(&key) {
            return Err("admin source unlinked name differs from census".into());
        }
        let entry = self
            .links
            .get_mut(&key)
            .ok_or("admin source inode absent from census")?;
        let mut expected = entry.0;
        expected.links = expected
            .links
            .checked_sub(1)
            .ok_or("admin source unlink count exhausted")?;
        expected.changed = stamp.changed;
        if expected != stamp {
            return Err("admin source inode changed beyond owned unlink".into());
        }
        entry.0 = stamp;
        self.names.remove(name);
        Ok(())
    }

    pub fn verify_retired(&self) -> Result<(), String> {
        if !self.names.is_empty()
            || !self.directories.is_empty()
            || self.links.values().any(|(stamp, _)| stamp.links != 0)
        {
            return Err("admin source original names remain after retirement".into());
        }
        Ok(())
    }
}
