//! A live owner for the exact installed descriptor inode used by negative tests.
use crate::{CiError, Result};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
};
const NAME: &str = "memcordon-runtime-manifest.json";

struct Fixture {
    parent: File,
    original: File,
    bad: File,
    backup: String,
    stage: String,
    original_bytes: Vec<u8>,
}
fn fail(message: &str) -> CiError {
    CiError::Message(message.into())
}
fn open(parent: &File, name: &str) -> Result<Option<File>> {
    match rustix::fs::openat(
        parent,
        name,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Ok(file) => Ok(Some(File::from(file))),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(error) => Err(std::io::Error::from(error).into()),
    }
}
fn same(left: &File, right: &File) -> Result<bool> {
    let left = left.metadata()?;
    let right = right.metadata()?;
    Ok((left.dev(), left.ino(), left.uid(), left.mode())
        == (right.dev(), right.ino(), right.uid(), right.mode()))
}
fn bytes(file: &File) -> Result<Vec<u8>> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.len() > 4 * 1024 * 1024
    {
        return Err(fail("installed descriptor native custody differs"));
    }
    let mut bytes = vec![
        0;
        usize::try_from(metadata.len())
            .map_err(|error| CiError::Message(error.to_string()))?
    ];
    file.read_exact_at(&mut bytes, 0)?;
    Ok(bytes)
}
impl Fixture {
    fn prepare(scenario: &str) -> Result<Self> {
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/usr/libexec")?;
        let metadata = parent.metadata()?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(fail("installed descriptor parent is not protected"));
        }
        let original =
            open(&parent, NAME)?.ok_or_else(|| fail("installed descriptor is absent"))?;
        let original_bytes = bytes(&original)?;
        memcordon_core::runtime_manifest_v2::RuntimeManifestV2::parse(&original_bytes)
            .map_err(CiError::Message)?;
        let mut malformed: serde_json::Value = serde_json::from_slice(&original_bytes)?;
        match scenario {
            "unsupported-provider-version" => malformed["revision"] = 255.into(),
            "corrupted-binding" => {
                let agent = malformed["components"]
                    .as_array_mut()
                    .ok_or_else(|| fail("installed component inventory absent"))?
                    .iter_mut()
                    .find(|component| component["role"] == "sealed-agent")
                    .ok_or_else(|| fail("installed sealed agent entry absent"))?;
                agent["sha256"] = "0".repeat(64).into();
            }
            _ => return Err(fail("unsupported installed descriptor mutation")),
        }
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).map_err(|error| CiError::Message(error.to_string()))?;
        let backup = format!(".memcordon-test-original-{}", hex::encode(nonce));
        let stage = format!(".memcordon-test-mutated-{}", hex::encode(nonce));
        let mut bad = File::from(
            rustix::fs::openat(
                &parent,
                ".",
                rustix::fs::OFlags::RDWR
                    | rustix::fs::OFlags::TMPFILE
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::from_raw_mode(0o444),
            )
            .map_err(std::io::Error::from)?,
        );
        bad.write_all(&serde_json::to_vec(&malformed)?)?;
        bad.sync_all()?;
        Ok(Self {
            parent,
            original,
            bad,
            backup,
            stage,
            original_bytes,
        })
    }
    fn publish(&self) -> Result<()> {
        let current =
            open(&self.parent, NAME)?.ok_or_else(|| fail("installed descriptor disappeared"))?;
        if !same(&current, &self.original)? {
            return Err(fail("installed descriptor changed before mutation"));
        }
        rustix::fs::linkat(
            &self.bad,
            "",
            &self.parent,
            self.stage.as_str(),
            rustix::fs::AtFlags::EMPTY_PATH,
        )
        .map_err(std::io::Error::from)?;
        rustix::fs::linkat(
            &self.parent,
            NAME,
            &self.parent,
            self.backup.as_str(),
            rustix::fs::AtFlags::empty(),
        )
        .map_err(std::io::Error::from)?;
        rustix::fs::renameat(&self.parent, self.stage.as_str(), &self.parent, NAME)
            .map_err(std::io::Error::from)?;
        self.parent.sync_all()?;
        Ok(())
    }
    fn restore(&self) -> Result<()> {
        let current = open(&self.parent, NAME)?;
        if let Some(current) = &current {
            if !same(current, &self.original)? && !same(current, &self.bad)? {
                return Err(fail(
                    "refusing to replace another descriptor inode during test cleanup",
                ));
            }
        }
        let original_named = current
            .as_ref()
            .map(|file| same(file, &self.original))
            .transpose()?
            .unwrap_or(false);
        if !original_named {
            let backup = open(&self.parent, &self.backup)?
                .ok_or_else(|| fail("owned original descriptor backup absent"))?;
            if !same(&backup, &self.original)? || bytes(&backup)? != self.original_bytes {
                return Err(fail("owned original descriptor bytes changed"));
            }
            rustix::fs::renameat(&self.parent, self.backup.as_str(), &self.parent, NAME)
                .map_err(std::io::Error::from)?;
        } else if let Some(backup) = open(&self.parent, &self.backup)? {
            if !same(&backup, &self.original)? {
                return Err(fail("owned descriptor backup name was replaced"));
            }
            rustix::fs::unlinkat(
                &self.parent,
                self.backup.as_str(),
                rustix::fs::AtFlags::empty(),
            )
            .map_err(std::io::Error::from)?;
        }
        if let Some(stage) = open(&self.parent, &self.stage)? {
            if !same(&stage, &self.bad)? {
                return Err(fail("owned descriptor staging name was replaced"));
            }
            rustix::fs::unlinkat(
                &self.parent,
                self.stage.as_str(),
                rustix::fs::AtFlags::empty(),
            )
            .map_err(std::io::Error::from)?;
        }
        self.parent.sync_all()?;
        let restored =
            open(&self.parent, NAME)?.ok_or_else(|| fail("restored descriptor absent"))?;
        if !same(&restored, &self.original)? || bytes(&restored)? != self.original_bytes {
            return Err(fail("installed descriptor restoration differs"));
        }
        Ok(())
    }
}

pub fn with<T>(scenario: &str, operation: impl FnOnce() -> Result<T>) -> Result<T> {
    let fixture = Fixture::prepare(scenario)?;
    let execution = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fixture.publish()?;
        operation()
    }));
    let restoration = fixture.restore();
    match execution {
        Ok(Ok(value)) => restoration.map(|()| value),
        Ok(Err(primary)) => match restoration {
            Ok(()) => Err(primary),
            Err(secondary) => Err(CiError::Message(format!(
                "{primary}; installed descriptor restoration: {secondary}"
            ))),
        },
        Err(panic) => {
            if let Err(error) = restoration {
                eprintln!("installed descriptor restoration after unwind: {error}");
            }
            std::panic::resume_unwind(panic)
        }
    }
}
