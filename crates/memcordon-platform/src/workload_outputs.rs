//! Caller-right output materialization beneath one held destination directory.
//! No destination pathname or descriptor is supplied to the privileged provider.
use memcordon_core::result_v3::WorkloadOutputFileV1;
use memcordon_core::workload_request::PrivateRootLayoutV1;
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

struct Destination {
    parent: File,
    name: CString,
    file: File,
    committed: bool,
}

impl Destination {
    fn create(root: &File, path: &str) -> Result<Self, String> {
        let mut parent = root.try_clone().map_err(|error| error.to_string())?;
        let mut components = path.split('/').peekable();
        while let Some(component) = components.next() {
            let name = CString::new(component).map_err(|error| error.to_string())?;
            if components.peek().is_none() {
                // SAFETY: parent remains held; O_EXCL and O_NOFOLLOW prevent
                // replacing any existing leaf or following a substituted link.
                let raw = unsafe {
                    libc::openat(
                        parent.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_WRONLY
                            | libc::O_CREAT
                            | libc::O_EXCL
                            | libc::O_NOFOLLOW
                            | libc::O_CLOEXEC,
                        0o600,
                    )
                };
                if raw < 0 {
                    return Err(std::io::Error::last_os_error().to_string());
                }
                // SAFETY: successful openat returned a fresh owned descriptor.
                let file = unsafe { File::from_raw_fd(raw) };
                return Ok(Self {
                    parent,
                    name,
                    file,
                    committed: false,
                });
            }
            // SAFETY: this creates only a validated relative component beneath
            // the held caller directory; a preexisting object is checked below.
            if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } < 0
                && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
            {
                return Err(std::io::Error::last_os_error().to_string());
            }
            // SAFETY: no-follow directory-only open binds the next held parent.
            let raw = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if raw < 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            // SAFETY: successful openat returned a fresh owned descriptor.
            parent = unsafe { File::from_raw_fd(raw) };
        }
        Err("output relative path is empty".into())
    }

    fn abort(&mut self) -> Result<(), String> {
        if self.committed {
            return Ok(());
        }
        let held = self.file.metadata().map_err(|error| error.to_string())?;
        let mut named = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: parent/name are held; successful fstatat initializes named.
        if unsafe {
            libc::fstatat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                named.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        // SAFETY: the preceding successful fstatat initialized named.
        let named = unsafe { named.assume_init() };
        if (held.dev(), held.ino()) != (named.st_dev as u64, named.st_ino as u64) {
            return Err("partial output name no longer identifies its held object".into());
        }
        // SAFETY: only this exact newly created caller-owned leaf is removed.
        if unsafe { libc::unlinkat(self.parent.as_raw_fd(), self.name.as_ptr(), 0) } < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        self.committed = true;
        Ok(())
    }
}
impl Drop for Destination {
    fn drop(&mut self) {
        let _ = self.abort();
    }
}

pub struct WorkloadOutputReceiver {
    root: Option<File>,
    selected: Vec<memcordon_core::workload_request::RootRelativePath>,
    files: Option<Vec<WorkloadOutputFileV1>>,
    index: usize,
    offset: u64,
    digest: Sha256,
    destination: Option<Destination>,
    failure: Option<String>,
}

impl WorkloadOutputReceiver {
    pub fn new(layout: &PrivateRootLayoutV1, directory: Option<&Path>) -> Result<Self, String> {
        layout.validate().map_err(|error| error.to_string())?;
        if !layout.output_files.as_slice().is_empty() && directory.is_none() {
            return Err("selected outputs require --workload-output DIRECTORY".into());
        }
        let root = directory
            .map(|directory| {
                File::options()
                    .read(true)
                    .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(directory)
                    .map_err(|error| error.to_string())
            })
            .transpose()?;
        Ok(Self {
            root,
            selected: layout.output_files.as_slice().to_vec(),
            files: None,
            index: 0,
            offset: 0,
            digest: Sha256::new(),
            destination: None,
            failure: None,
        })
    }

    pub fn inventory(&mut self, bytes: &[u8]) -> Result<(), String> {
        if self.files.is_some() || bytes.len() > crate::workload_transport::INITIAL_FRAME_BYTES {
            return Err("duplicate or excessive output inventory".into());
        }
        memcordon_core::canonical_json::reject_duplicate_json_keys(bytes)?;
        let files: memcordon_core::BoundedVec<WorkloadOutputFileV1, 64> =
            serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        let mut paths = std::collections::BTreeSet::new();
        let mut total = 0_u64;
        for file in files.as_slice() {
            if !self.selected.contains(&file.path) || !paths.insert(&file.path) {
                return Err("undeclared or duplicate output path".into());
            }
            total = total
                .checked_add(file.size)
                .ok_or("output inventory size overflow")?;
            if total > memcordon_core::workload_bundle::IMAGE_BYTES {
                return Err("output inventory exceeds aggregate ceiling".into());
            }
        }
        if paths.len() != self.selected.len() {
            return Err("declared output is absent from inventory".into());
        }
        self.files = Some(files.as_slice().to_vec());
        self.begin_next()
    }

    fn begin_next(&mut self) -> Result<(), String> {
        loop {
            let Some(file) = self.files.as_ref().and_then(|files| files.get(self.index)) else {
                return Ok(());
            };
            self.offset = 0;
            self.digest = Sha256::new();
            if self.failure.is_none() {
                match self
                    .root
                    .as_ref()
                    .ok_or_else(|| "output directory absent".to_owned())
                    .and_then(|root| Destination::create(root, file.path.as_str()))
                {
                    Ok(destination) => self.destination = Some(destination),
                    Err(error) => self.failure = Some(error),
                }
            }
            if file.size != 0 {
                return Ok(());
            }
            self.complete_current()?;
        }
    }

    fn complete_current(&mut self) -> Result<(), String> {
        let file = self
            .files
            .as_ref()
            .and_then(|files| files.get(self.index))
            .ok_or("output member absent")?;
        if self.offset != file.size
            || memcordon_core::DiagnosticSha256::from_bytes(self.digest.clone().finalize().into())
                != file.sha256
        {
            return Err("output length or digest differs".into());
        }
        if let Some(mut destination) = self.destination.take() {
            if self.failure.is_none() {
                if let Err(error) = destination.file.sync_all() {
                    self.failure = Some(error.to_string());
                } else {
                    destination.committed = true;
                }
            }
            if !destination.committed
                && let Err(error) = destination.abort()
            {
                self.failure.get_or_insert(error);
            }
        }
        self.index += 1;
        Ok(())
    }

    pub fn chunk(&mut self, bytes: &[u8]) -> Result<(), String> {
        let chunk = memcordon_core::workload_chunks::WorkloadOutputChunkV1::decode(bytes)?;
        let file = self
            .files
            .as_ref()
            .and_then(|files| files.get(self.index))
            .ok_or("unexpected output chunk")?;
        if usize::try_from(chunk.file_index).map_err(|_| "output index overflow")? != self.index
            || chunk.total != file.size
            || chunk.offset != self.offset
            || self
                .offset
                .checked_add(chunk.bytes.len() as u64)
                .is_none_or(|end| end > file.size)
        {
            return Err("gapped, duplicate or foreign output chunk".into());
        }
        self.digest.update(chunk.bytes);
        self.offset = self
            .offset
            .checked_add(chunk.bytes.len() as u64)
            .ok_or("output offset overflow")?;
        if let Some(destination) = &mut self.destination
            && self.failure.is_none()
            && let Err(error) = destination.file.write_all(chunk.bytes)
        {
            self.failure = Some(error.to_string());
        }
        if self.offset == file.size {
            self.complete_current()?;
            self.begin_next()?;
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<(), String> {
        if self.selected.is_empty() && self.files.is_none() {
            return Ok(());
        }
        if self
            .files
            .as_ref()
            .is_none_or(|files| self.index != files.len())
        {
            return Err("output delivery is incomplete".into());
        }
        match self.failure.take() {
            Some(failure) => Err(failure),
            None => Ok(()),
        }
    }
}
