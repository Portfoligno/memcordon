//! A live owner for the exact installed descriptor inode used by negative tests.
use crate::{CiError, Result};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
};
const NAME: &str = "memcordon-runtime-manifest.json";
fn io_at(error: std::io::Error, operation: &str, name: &str) -> CiError {
    let path = std::path::Path::new("/usr/libexec").join(name);
    CiError::from(error).context(format!(
        "provider descriptor {operation} {}",
        path.display()
    ))
}

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
        Err(error) => Err(io_at(std::io::Error::from(error), "openat nofollow", name)),
    }
}
fn same(left: &File, right: &File) -> Result<bool> {
    let left = left
        .metadata()
        .map_err(|error| io_at(error, "held left descriptor metadata", ""))?;
    let right = right
        .metadata()
        .map_err(|error| io_at(error, "held right descriptor metadata", ""))?;
    Ok((left.dev(), left.ino(), left.uid(), left.mode())
        == (right.dev(), right.ino(), right.uid(), right.mode()))
}
fn bytes(file: &File) -> Result<Vec<u8>> {
    let metadata = file
        .metadata()
        .map_err(|error| io_at(error, "held bytes descriptor metadata", ""))?;
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
    file.read_exact_at(&mut bytes, 0)
        .map_err(|error| io_at(error, "held descriptor read_exact_at", ""))?;
    Ok(bytes)
}
impl Fixture {
    fn prepare(scenario: &str) -> Result<Self> {
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/usr/libexec")
            .map_err(|error| io_at(error, "open protected parent", ""))?;
        let metadata = parent
            .metadata()
            .map_err(|error| io_at(error, "held parent metadata", ""))?;
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
            .map_err(std::io::Error::from)
            .map_err(|error| io_at(error, "create malformed O_TMPFILE", "."))?,
        );
        bad.write_all(&serde_json::to_vec(&malformed)?)
            .map_err(|error| io_at(error, "write malformed held O_TMPFILE", "."))?;
        bad.sync_all()
            .map_err(|error| io_at(error, "sync malformed held O_TMPFILE", "."))?;
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
        .map_err(std::io::Error::from)
        .map_err(|error| io_at(error, "linkat malformed inode into stage", &self.stage))?;
        rustix::fs::linkat(
            &self.parent,
            NAME,
            &self.parent,
            self.backup.as_str(),
            rustix::fs::AtFlags::empty(),
        )
        .map_err(std::io::Error::from)
        .map_err(|error| io_at(error, "linkat original inode backup", &self.backup))?;
        rustix::fs::renameat(&self.parent, self.stage.as_str(), &self.parent, NAME)
            .map_err(std::io::Error::from)
            .map_err(|error| io_at(error, "renameat stage over installed name", &self.stage))?;
        self.parent
            .sync_all()
            .map_err(|error| io_at(error, "sync parent after publish", NAME))?;
        Ok(())
    }
    fn restore(&self) -> Result<()> {
        let current = open(&self.parent, NAME)?;
        if let Some(current) = &current
            && !same(current, &self.original)?
            && !same(current, &self.bad)?
        {
            return Err(fail(
                "refusing to replace another descriptor inode during test cleanup",
            ));
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
                .map_err(std::io::Error::from)
                .map_err(|error| {
                    io_at(error, "renameat original backup restoration", &self.backup)
                })?;
        } else if let Some(backup) = open(&self.parent, &self.backup)? {
            if !same(&backup, &self.original)? {
                return Err(fail("owned descriptor backup name was replaced"));
            }
            rustix::fs::unlinkat(
                &self.parent,
                self.backup.as_str(),
                rustix::fs::AtFlags::empty(),
            )
            .map_err(std::io::Error::from)
            .map_err(|error| io_at(error, "unlinkat owned original backup", &self.backup))?;
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
            .map_err(std::io::Error::from)
            .map_err(|error| io_at(error, "unlinkat owned malformed stage", &self.stage))?;
        }
        self.parent
            .sync_all()
            .map_err(|error| io_at(error, "sync parent after restoration", NAME))?;
        let restored =
            open(&self.parent, NAME)?.ok_or_else(|| fail("restored descriptor absent"))?;
        if !same(&restored, &self.original)? || bytes(&restored)? != self.original_bytes {
            return Err(fail("installed descriptor restoration differs"));
        }
        Ok(())
    }
}

pub fn with<T>(scenario: &str, operation: impl FnOnce() -> Result<T>) -> Result<T> {
    let fixture = Fixture::prepare(scenario).map_err(|error| {
        error.context(format!(
            "prepare provider descriptor scenario {scenario} installed-name={NAME}"
        ))
    })?;
    let execution = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fixture.publish().map_err(|error|error.context(format!("publish provider descriptor scenario {scenario} installed-name={NAME} stage={} backup={}",fixture.stage,fixture.backup)))?;
        operation().map_err(|error| {
            error.context(format!(
                "execute provider descriptor refusal scenario {scenario} installed-name={NAME}"
            ))
        })
    }));
    let restoration = fixture.restore().map_err(|error|error.context(format!("restore provider descriptor scenario {scenario} installed-name={NAME} stage={} backup={}",fixture.stage,fixture.backup)));
    match execution {
        Ok(Ok(value)) => restoration.map(|()| value),
        Ok(Err(primary)) => match restoration {
            Ok(()) => Err(primary),
            Err(secondary) => Err(CiError::LaneFailures {
                primary: Box::new(primary),
                secondary: Box::new(secondary),
            }),
        },
        Err(panic) => {
            if let Err(error) = restoration {
                eprintln!("installed descriptor restoration after unwind: {error}");
            }
            std::panic::resume_unwind(panic)
        }
    }
}
