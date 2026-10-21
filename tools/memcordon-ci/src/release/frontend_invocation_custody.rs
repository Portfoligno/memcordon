//! Native invocation custody and an earned, nonserialized live-access proof.
use std::{
    fs::File,
    os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
    path::PathBuf,
};

pub struct Invocation {
    owner: File,
    path: PathBuf,
    bytes: Vec<u8>,
    sealed: Option<Vec<u8>>,
    uid: u32,
}

impl Invocation {
    pub fn new(owner: File, path: PathBuf, bytes: Vec<u8>, uid: u32) -> Self {
        Self {
            owner,
            path,
            bytes,
            sealed: None,
            uid,
        }
    }

    fn read(&self) -> Result<Vec<u8>, String> {
        let before = self.owner.metadata().map_err(|error| error.to_string())?;
        if before.len() != self.bytes.len() as u64 || before.len() > 65536 {
            return Err("retained frontend command length differs".into());
        }
        let mut bytes = vec![0; self.bytes.len()];
        self.owner
            .read_exact_at(&mut bytes, 0)
            .map_err(|error| error.to_string())?;
        let named = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.path)
            .map_err(|error| error.to_string())?;
        let named_metadata = named.metadata().map_err(|error| error.to_string())?;
        let after = self.owner.metadata().map_err(|error| error.to_string())?;
        let stamp = |value: &std::fs::Metadata| {
            (
                value.dev(),
                value.ino(),
                value.len(),
                value.ctime(),
                value.ctime_nsec(),
                value.nlink(),
                value.uid(),
                value.mode(),
            )
        };
        let mut named_bytes = vec![0; self.bytes.len()];
        named
            .read_exact_at(&mut named_bytes, 0)
            .map_err(|error| error.to_string())?;
        if stamp(&before) != stamp(&after)
            || stamp(&after) != stamp(&named_metadata)
            || after.nlink() != 1
            || after.uid() != self.uid
            || after.mode() & 0o022 != 0
            || bytes != self.bytes
            || named_bytes != bytes
            || stamp(&named_metadata)
                != stamp(&named.metadata().map_err(|error| error.to_string())?)
        {
            return Err("retained frontend command native identity/bytes changed".into());
        }
        Ok(bytes)
    }

    pub fn verified(
        &self,
        observe: impl FnOnce() -> Result<(serde_json::Value, serde_json::Value), String>,
    ) -> Result<Vec<u8>, String> {
        let bytes = self.read()?;
        if let Some(sealed) = &self.sealed {
            if sealed != &bytes {
                return Err("retained live-access proof differs from original invocation".into());
            }
        } else {
            let invocation: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            let (access, endpoint) = observe()?;
            if invocation["file_access"] != access || invocation["endpoint_access"] != endpoint {
                return Err(
                    "retained frontend file access differs from original held objects".into(),
                );
            }
            // Keep the live observation inside the held/named command identity checks.
            if self.read()? != bytes {
                return Err("frontend invocation changed during live-access observation".into());
            }
        }
        Ok(bytes)
    }

    pub fn seal(
        &mut self,
        observe: impl FnOnce() -> Result<(serde_json::Value, serde_json::Value), String>,
    ) -> Result<(), String> {
        let bytes = self.verified(observe)?;
        self.sealed = Some(bytes);
        Ok(())
    }
}
