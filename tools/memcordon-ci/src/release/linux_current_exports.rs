//! Native observations of caller-declared outputs in an original private root.
use crate::{CiError, Result, linux_consumer_readiness::HeldLinuxProcess};
use memcordon_core::result_v3::LinuxNativeExecutionV3;
use std::{
    fs::File,
    io::Read,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::Path,
};

pub struct ExportRoot {
    root: File,
    work: File,
}
impl ExportRoot {
    pub fn hold(target: &HeldLinuxProcess, native: &LinuxNativeExecutionV3) -> Result<Self> {
        if target.process_id != native.target.pid
            || target.birth != native.target.birth
            || target.exited().map_err(CiError::Message)?
        {
            return Err(CiError::Message(
                "export observer original target identity differs".into(),
            ));
        }
        let root = File::open(
            Path::new("/proc")
                .join(target.process_id.to_string())
                .join("root"),
        )?;
        let metadata = root.metadata()?;
        if !metadata.is_dir()
            || (metadata.dev(), metadata.ino()) != (native.root_device, native.root_inode)
        {
            return Err(CiError::Message(
                "export observer is not in original private root".into(),
            ));
        }
        let work = File::from(
            rustix::fs::openat2(
                &root,
                "work",
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
                rustix::fs::ResolveFlags::BENEATH | rustix::fs::ResolveFlags::NO_SYMLINKS,
            )
            .map_err(std::io::Error::from)?,
        );
        let metadata = work.metadata()?;
        if metadata.uid() != native.target_uid
            || metadata.mode() & 0o077 != 0
            || target.exited().map_err(CiError::Message)?
        {
            return Err(CiError::Message(
                "original writable root custody differs".into(),
            ));
        }
        Ok(Self { root, work })
    }
    pub fn inject(&self, scenario: &str) -> Result<serde_json::Value> {
        let (kind, device) = match scenario {
            "export-fifo" => (rustix::fs::FileType::Fifo, 0),
            "export-device" => (
                rustix::fs::FileType::CharacterDevice,
                rustix::fs::makedev(1, 3),
            ),
            _ => {
                return Err(CiError::Message(
                    "unknown special export observation".into(),
                ));
            }
        };
        rustix::fs::mknodat(
            &self.work,
            "exported.bin",
            kind,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            device,
        )
        .map_err(std::io::Error::from)?;
        self.snapshot(scenario)
    }
    pub fn snapshot(&self, scenario: &str) -> Result<serde_json::Value> {
        let name = if scenario == "export-traversal" {
            "parent"
        } else {
            "exported.bin"
        };
        let metadata = rustix::fs::statat(&self.work, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(std::io::Error::from)?;
        let root = self.root.metadata()?;
        let link = if metadata.st_mode & libc::S_IFMT == libc::S_IFLNK {
            Some(
                rustix::fs::readlinkat(&self.work, name, Vec::new())
                    .map_err(std::io::Error::from)?
                    .to_bytes()
                    .to_vec(),
            )
        } else {
            None
        };
        Ok(
            serde_json::json!({"format":"memcordon.linux-current-export-node","revision":1,"scenario":scenario,"root":{"device":root.dev(),"inode":root.ino()},"component":format!("work/{name}"),"device":metadata.st_dev,"inode":metadata.st_ino,"mode":metadata.st_mode,"uid":metadata.st_uid,"gid":metadata.st_gid,"links":metadata.st_nlink,"size":metadata.st_size,"rdev":metadata.st_rdev,"symlink_target":link}),
        )
    }
    pub fn writer_sample(&self) -> Result<serde_json::Value> {
        let mut file = File::from(
            rustix::fs::openat2(
                &self.work,
                "exported.bin",
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
                rustix::fs::ResolveFlags::BENEATH | rustix::fs::ResolveFlags::NO_SYMLINKS,
            )
            .map_err(std::io::Error::from)?,
        );
        let before = file.metadata()?;
        if !before.is_file() || before.nlink() != 1 || before.len() > 65536 {
            return Err(CiError::Message(
                "export writer native file shape differs".into(),
            ));
        }
        let mut bytes = Vec::new();
        (&mut file).take(65537).read_to_end(&mut bytes)?;
        let after = file.metadata()?;
        Ok(
            serde_json::json!({"device":before.dev(),"inode":before.ino(),"before_length":before.len(),"after_length":after.len(),"before_mtime":[before.mtime(),before.mtime_nsec()],"after_mtime":[after.mtime(),after.mtime_nsec()],"bytes":bytes}),
        )
    }
}

pub fn output_empty(directory: &File) -> Result<bool> {
    Ok(
        std::fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))?
            .next()
            .is_none(),
    )
}
