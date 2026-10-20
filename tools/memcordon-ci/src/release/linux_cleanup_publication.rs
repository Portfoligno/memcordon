//! Recovery-only receipts remain separate from original acquisition authority.
use rustix::fs::{Mode, OFlags, mkdirat, open, openat};
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub struct HeldPublication {
    path: PathBuf,
    parent: File,
    directory: File,
    owner: File,
    owner_stamp: (u64, u64, u64, i64, i64),
    uid: u32,
}

fn owner_stamp(metadata: &std::fs::Metadata) -> (u64, u64, u64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
    )
}

impl HeldPublication {
    pub fn open(parent_path: &Path, owner: &File, uid: u32) -> Result<Self, String> {
        let parent = File::from(
            open(
                parent_path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| error.to_string())?,
        );
        let parent_metadata = parent.metadata().map_err(|error| error.to_string())?;
        let named_owner = std::fs::symlink_metadata(parent_path.join("lease-owner.json"))
            .map_err(|error| error.to_string())?;
        let owner_metadata = owner.metadata().map_err(|error| error.to_string())?;
        if parent_metadata.uid() != uid
            || parent_metadata.mode() & 0o022 != 0
            || parent_metadata.nlink() == 0
            || !owner_metadata.is_file()
            || owner_metadata.uid() != uid
            || owner_metadata.nlink() != 1
            || owner_metadata.mode() & 0o022 != 0
            || named_owner.file_type().is_symlink()
            || owner_stamp(&named_owner) != owner_stamp(&owner_metadata)
        {
            return Err("recovery publication parent or lease owner custody differs".into());
        }
        match mkdirat(
            &parent,
            "interrupted-resource-retirement",
            Mode::from_bits_truncate(0o700),
        ) {
            Ok(()) => parent.sync_all().map_err(|error| error.to_string())?,
            Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(error.to_string()),
        }
        let directory = File::from(
            openat(
                &parent,
                "interrupted-resource-retirement",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| error.to_string())?,
        );
        let value = Self {
            path: parent_path.join("interrupted-resource-retirement"),
            parent,
            directory,
            owner: owner.try_clone().map_err(|error| error.to_string())?,
            owner_stamp: owner_stamp(&owner_metadata),
            uid,
        };
        value.verify()?;
        Ok(value)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn verify(&self) -> Result<(), String> {
        let parent_path = self.path.parent().ok_or("publication parent absent")?;
        let named_parent =
            std::fs::symlink_metadata(parent_path).map_err(|error| error.to_string())?;
        let parent = self.parent.metadata().map_err(|error| error.to_string())?;
        let named = std::fs::symlink_metadata(&self.path).map_err(|error| error.to_string())?;
        let held = self
            .directory
            .metadata()
            .map_err(|error| error.to_string())?;
        let named_owner = std::fs::symlink_metadata(parent_path.join("lease-owner.json"))
            .map_err(|error| error.to_string())?;
        let owner = self.owner.metadata().map_err(|error| error.to_string())?;
        if !named_parent.is_dir()
            || named_parent.file_type().is_symlink()
            || (named_parent.dev(), named_parent.ino()) != (parent.dev(), parent.ino())
            || parent.uid() != self.uid
            || parent.mode() & 0o022 != 0
            || parent.nlink() == 0
            || !named.is_dir()
            || named.file_type().is_symlink()
            || (named.dev(), named.ino()) != (held.dev(), held.ino())
            || held.uid() != self.uid
            || held.mode() & 0o7777 != 0o700
            || held.nlink() == 0
            || named_owner.file_type().is_symlink()
            || !named_owner.is_file()
            || owner_stamp(&named_owner) != self.owner_stamp
            || owner_stamp(&owner) != self.owner_stamp
            || owner.uid() != self.uid
            || owner.mode() & 0o022 != 0
            || owner.nlink() != 1
        {
            return Err("held recovery publication or original lease owner changed".into());
        }
        Ok(())
    }
}
