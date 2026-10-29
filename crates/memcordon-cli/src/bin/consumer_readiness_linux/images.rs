use super::{Result, Transcript, wait_release};
use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::MetadataExt,
};
pub(super) fn run(
    transcript: &mut Transcript,
    mut arguments: impl Iterator<Item = OsString>,
) -> Result<()> {
    let scenario = arguments
        .next()
        .ok_or("image scenario absent")?
        .into_string()
        .map_err(|_| "image scenario not UTF-8")?;
    let path = arguments.next().ok_or("image object path absent")?;
    if arguments.next().is_some() || !std::path::Path::new(&path).is_absolute() {
        return Err("image object must be one absolute private path".into());
    }
    wait_release()?;
    let metadata = fs::metadata(&path)?;
    let mut held = OpenOptions::new().read(true).open(&path)?;
    let mut bytes = Vec::new();
    (&mut held)
        .take(512 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 512 * 1024 * 1024 {
        return Err("image object byte bound exceeded".into());
    }
    let error = OpenOptions::new()
        .write(true)
        .open(&path)
        .err()
        .ok_or("protected image writable alias opened")?;
    let errno = error
        .raw_os_error()
        .ok_or("image writable alias errno absent")?;
    if ![libc::EROFS, libc::EACCES, libc::ETXTBSY, libc::EPERM].contains(&errno) {
        return Err(error.into());
    }
    let mut positive = OpenOptions::new()
        .create_new(true)
        .write(true)
        .read(true)
        .open("/work/image-neighbor.bin")?;
    positive.write_all(transcript.challenge.as_bytes())?;
    positive.sync_all()?;
    drop(positive);
    let private = fs::read("/work/image-neighbor.bin")?;
    if private != transcript.challenge.as_bytes() {
        return Err("neighboring private file byte effects changed".into());
    }
    transcript.record("image-custody-ready",serde_json::json!({"scenario":scenario,"path":path,"device":metadata.dev(),"inode":metadata.ino(),"mode":metadata.mode(),"uid":metadata.uid(),"gid":metadata.gid(),"links":metadata.nlink(),"length":metadata.len(),"sha256":memcordon_core::hash_bytes(&bytes),"write_errno":errno,"private_positive":private,"maps":fs::read("/proc/self/maps")?,"library_path":std::env::var_os("LD_LIBRARY_PATH").map(|value|{use std::os::unix::ffi::OsStringExt;value.into_vec()})}))?;
    wait_release()?;
    transcript.record(
        "image-custody-complete",
        serde_json::json!({"scenario":scenario,"write_errno":errno}),
    )
}
