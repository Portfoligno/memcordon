//! Ordinary-caller file effects for current snapshot qualification.
#![cfg(target_os = "linux")]
use crate::{CiError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{BufRead, Read, Write},
    os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeInput {
    pub format: String,
    pub revision: u32,
    pub operation: String,
    pub path: PathBuf,
    pub device: u64,
    pub inode: u64,
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub replacement: Option<PathBuf>,
    pub backup: Option<PathBuf>,
}

fn facts(file: &File) -> Result<serde_json::Value> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > 512 * 1024 * 1024 {
        return Err(CiError::Message(
            "snapshot probe file type/extent invalid".into(),
        ));
    }
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut offset = 0;
    loop {
        let count = file.read_at(&mut buffer, offset)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
        offset += count as u64;
        if offset > metadata.len() {
            return Err(CiError::Message(
                "snapshot source grew during observation".into(),
            ));
        }
    }
    if offset != metadata.len() {
        return Err(CiError::Message(
            "snapshot source changed during observation".into(),
        ));
    }
    Ok(
        serde_json::json!({"device":metadata.dev(),"inode":metadata.ino(),"uid":metadata.uid(),"gid":metadata.gid(),"mode":metadata.mode(),"links":metadata.nlink(),"length":metadata.len(),"sha256":hex::encode(hash.finalize()),"flags":rustix::fs::fcntl_getfl(file).map_err(std::io::Error::from)?.bits()}),
    )
}
fn emit(value: &serde_json::Value) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, value)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

pub fn run(input: &Path, output: &Path) -> Result<()> {
    if input != Path::new("-") {
        return Err(CiError::Message(
            "snapshot probe requires original stdin protocol".into(),
        ));
    }
    let uid = rustix::process::getuid().as_raw();
    let gid = rustix::process::getgid().as_raw();
    if uid == 0 || gid == 0 || rustix::process::geteuid().as_raw() != uid {
        return Err(CiError::Message(
            "snapshot file effects require actual ordinary OS caller".into(),
        ));
    }
    let stdin = std::io::stdin();
    let mut reader = std::io::BufReader::new(stdin.lock());
    let mut line = Vec::new();
    reader.by_ref().take(131073).read_until(b'\n', &mut line)?;
    if line.len() > 131072 || !line.ends_with(b"\n") {
        return Err(CiError::Message(
            "snapshot probe input line exceeds bound".into(),
        ));
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(&line).map_err(CiError::Message)?;
    let request: ProbeInput = serde_json::from_slice(&line)?;
    if request.format != "memcordon.current-snapshot-probe"
        || request.revision != 1
        || !request.path.is_absolute()
        || request.bytes.len() > 65536
        || ![
            "write",
            "hold-write",
            "replace",
            "hold-replace",
            "hold-substitute",
        ]
        .contains(&request.operation.as_str())
    {
        return Err(CiError::Message(
            "snapshot probe request fields invalid".into(),
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&request.path)?;
    let metadata = file.metadata()?;
    if metadata.uid() != uid
        || metadata.dev() != request.device
        || metadata.ino() != request.inode
        || metadata.nlink() != 1
        || !metadata.is_file()
    {
        return Err(CiError::Message(
            "snapshot probe source is not original caller-owned regular file".into(),
        ));
    }
    let pid = std::process::id();
    let birth = crate::linux_consumer_readiness::process_birth(pid).map_err(CiError::Message)?;
    let opened = facts(&file)?;
    emit(
        &serde_json::json!({"format":"memcordon.current-snapshot-probe-event","revision":1,"phase":"opened","uid":uid,"gid":gid,"pid":pid,"birth":birth,"file":opened}),
    )?;
    if request.operation.starts_with("hold-") {
        let mut gate = [0u8; 2];
        reader.read_exact(&mut gate)?;
        if gate != *b"W\n" {
            return Err(CiError::Message(
                "snapshot retained alias mutation gate differs".into(),
            ));
        }
    }
    if request.operation.ends_with("replace") || request.operation == "hold-substitute" {
        let replacement = request
            .replacement
            .as_ref()
            .filter(|path| path.is_absolute())
            .ok_or_else(|| CiError::Message("snapshot replacement source absent".into()))?;
        let other = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(replacement)?;
        let other_meta = other.metadata()?;
        if !other_meta.is_file()
            || other_meta.uid() != uid
            || other_meta.nlink() != 1
            || other_meta.dev() != metadata.dev()
            || other_meta.ino() == metadata.ino()
        {
            return Err(CiError::Message(
                "snapshot replacement is not a distinct original caller file".into(),
            ));
        }
        if request.operation == "hold-substitute" {
            let backup = request
                .backup
                .as_ref()
                .filter(|path| path.is_absolute())
                .ok_or_else(|| {
                    CiError::Message("original source substitution backup absent".into())
                })?;
            rustix::fs::renameat_with(
                rustix::fs::CWD,
                &request.path,
                rustix::fs::CWD,
                backup,
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .map_err(std::io::Error::from)?;
        } else if request.backup.is_some() {
            return Err(CiError::Message("unexpected source backup operand".into()));
        }
        if request.operation == "hold-substitute" {
            rustix::fs::renameat_with(
                rustix::fs::CWD,
                replacement,
                rustix::fs::CWD,
                &request.path,
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .map_err(std::io::Error::from)?;
        } else {
            std::fs::rename(replacement, &request.path)?;
        }
    } else {
        if request.replacement.is_some()
            || request.backup.is_some()
            || request
                .offset
                .checked_add(request.bytes.len() as u64)
                .is_none_or(|end| end > metadata.len())
        {
            return Err(CiError::Message(
                "snapshot write exceeds original source extent".into(),
            ));
        }
        file.write_all_at(&request.bytes, request.offset)?;
        file.sync_all()?;
    }
    let changed = facts(&file)?;
    let named = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&request.path)?;
    let named = facts(&named)?;
    emit(
        &serde_json::json!({"format":"memcordon.current-snapshot-probe-event","revision":1,"phase":"changed","uid":uid,"gid":gid,"pid":pid,"birth":birth,"file":changed,"named":named}),
    )?;
    if request.operation.starts_with("hold-") {
        let mut gate = [0u8; 2];
        reader.read_exact(&mut gate)?;
        if gate != *b"D\n" {
            return Err(CiError::Message(
                "snapshot retained alias retirement gate differs".into(),
            ));
        }
    }
    let restored = if request.operation == "hold-substitute" {
        let backup = request.backup.as_ref().expect("validated source backup");
        let replacement = request.replacement.as_ref().expect("validated replacement");
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            &request.path,
            rustix::fs::CWD,
            replacement,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(std::io::Error::from)?;
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            backup,
            rustix::fs::CWD,
            &request.path,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(std::io::Error::from)?;
        Some(facts(
            &OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&request.path)?,
        )?)
    } else {
        None
    };
    let receipt = serde_json::json!({"format":"memcordon.current-snapshot-probe-receipt","revision":1,"request":request,"uid":uid,"gid":gid,"pid":pid,"birth":birth,"opened":opened,"changed":changed,"named":named,"restored":restored});
    let mut target = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(output)?;
    serde_json::to_writer(&mut target, &receipt)?;
    target.write_all(b"\n")?;
    target.sync_all()?;
    Ok(())
}
