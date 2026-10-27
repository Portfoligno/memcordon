//! Share original image witnesses without duplicating their native descriptors.
#![cfg(unix)]

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Role {
    AdministrativeDirectory,
    EvidenceDirectory,
    AdministrativeFile,
}

impl Role {
    fn directory(self) -> bool {
        matches!(
            self,
            Self::AdministrativeDirectory | Self::EvidenceDirectory
        )
    }
}

#[derive(Default)]
pub struct CustodyPool {
    originals: BTreeMap<(Role, PathBuf), Arc<File>>,
}

impl CustodyPool {
    /// Caller must independently admit the candidate's current role policy,
    /// nofollow named-edge association and access mode on EVERY call. File
    /// witnesses must be read-only; partial writers never enter this pool.
    /// This table is neither a policy cache nor a cached size/hash observation.
    pub fn admit(&mut self, role: Role, path: &Path, candidate: File) -> io::Result<Arc<File>> {
        let normalized: PathBuf = path.components().collect();
        if !path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
            || normalized.as_os_str() != path.as_os_str()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "image custody requires an absolute normalized original path",
            ));
        }
        let candidate_metadata = candidate.metadata()?;
        if (role.directory() && !candidate_metadata.is_dir())
            || (!role.directory() && !candidate_metadata.is_file())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "image custody candidate type differs from its admitted role",
            ));
        }
        let key = (role, path.to_owned());
        if let Some(original) = self.originals.get(&key) {
            let original_metadata = original.metadata()?;
            if (original_metadata.dev(), original_metadata.ino())
                != (candidate_metadata.dev(), candidate_metadata.ino())
            {
                return Err(io::Error::other(format!(
                    "image custody original native association differs; role={role:?}; original=({},{}); candidate=({},{}); physical-owners={}",
                    original_metadata.dev(),
                    original_metadata.ino(),
                    candidate_metadata.dev(),
                    candidate_metadata.ino(),
                    self.owner_count()
                )));
            }
            // Drop this bounded transient descriptor; cloning the Arc below
            // keeps the SAME original File, not a File::try_clone duplicate.
            drop(candidate);
            return Ok(Arc::clone(original));
        }
        let original = Arc::new(candidate);
        self.originals.insert(key, Arc::clone(&original));
        Ok(original)
    }

    pub fn owner_count(&self) -> usize {
        self.originals.len()
    }
}

/// Each operation starts at offset zero on the same original read-only owner.
/// Separate readers never seek or advance that owner's shared file cursor.
pub struct PositionalReader<'a> {
    file: &'a File,
    offset: u64,
}

impl<'a> PositionalReader<'a> {
    pub fn new(file: &'a File) -> Self {
        Self { file, offset: 0 }
    }
}

impl Read for PositionalReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let count = self.file.read_at(bytes, self.offset)?;
        self.offset = self
            .offset
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::other("original image reader offset overflow"))?;
        Ok(count)
    }
}
