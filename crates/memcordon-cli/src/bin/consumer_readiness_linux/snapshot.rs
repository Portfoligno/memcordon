//! Current fixture byte observations for caller-input snapshot experiments.
use super::{Result, Transcript};
use std::{
    ffi::OsString,
    io::Read,
    os::unix::fs::{FileExt, MetadataExt},
};

pub(super) fn run(
    transcript: &mut Transcript,
    mode: &str,
    mut arguments: impl Iterator<Item = OsString>,
) -> Result<()> {
    let encoded = arguments
        .next()
        .ok_or("expected snapshot bytes absent")?
        .into_string()
        .map_err(|_| "snapshot bytes not UTF8")?;
    if encoded.len() > 131072 || arguments.next().is_some() {
        return Err("snapshot byte operands exceed bound".into());
    }
    if encoded.len() % 2 != 0 {
        return Err("snapshot hex bytes are truncated".into());
    }
    let expected = encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect::<Result<Vec<u8>>>()?;
    super::wait_release()?;
    let mut file = std::fs::File::open("/input/snapshot.bin")?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() > 65536 {
        return Err("snapshot input is not a bounded regular file".into());
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    if bytes != expected {
        return Err("actual target snapshot bytes differ from original request input".into());
    }
    let error = std::fs::OpenOptions::new()
        .write(true)
        .open("/input/snapshot.bin")
        .err()
        .ok_or("target could open immutable snapshot writable")?;
    let errno = error
        .raw_os_error()
        .ok_or("snapshot write refusal has no native errno")?;
    if ![libc::EACCES, libc::EPERM, libc::EROFS].contains(&errno) {
        return Err(error.into());
    }
    std::fs::write(
        "/work/snapshot-private-positive",
        transcript.challenge.as_bytes(),
    )?;
    let positive = std::fs::read("/work/snapshot-private-positive")?;
    if positive != transcript.challenge.as_bytes() {
        return Err("neighboring private file bytes differ".into());
    }
    transcript.record("snapshot-input-observed",serde_json::json!({"path":"/input/snapshot.bin","bytes":bytes,"device":before.dev(),"inode":before.ino(),"uid":before.uid(),"gid":before.gid(),"mode":before.mode(),"links":before.nlink(),"native_write_errno":errno,"private_bytes":positive}))?;
    if mode == "snapshot-read-held" {
        transcript.record(
            "snapshot-input-ready",
            serde_json::json!({"bytes":bytes,"device":before.dev(),"inode":before.ino()}),
        )?;
        super::wait_release()?;
        let mut after_bytes = vec![0; expected.len()];
        file.read_exact_at(&mut after_bytes, 0)?;
        let after = file.metadata()?;
        if after_bytes != expected
            || (after.dev(), after.ino(), after.len()) != (before.dev(), before.ino(), before.len())
        {
            return Err("original held snapshot changed during caller mutation".into());
        }
        transcript.record(
            "snapshot-input-after",
            serde_json::json!({"bytes":after_bytes,"device":after.dev(),"inode":after.ino()}),
        )?;
    } else if mode != "snapshot-read" {
        return Err("unknown snapshot fixture mode".into());
    }
    Ok(())
}
