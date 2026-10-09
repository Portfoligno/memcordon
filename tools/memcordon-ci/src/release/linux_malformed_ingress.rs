//! A bounded native caller for the installed malformed-request refusal path.
use crate::{CiError, Result};
use clap::Args;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;

#[derive(Clone, Debug, Args)]
pub struct MalformedIngressArguments {
    #[arg(long)]
    pub request: PathBuf,
    #[arg(long)]
    pub output: PathBuf,
}

pub fn execute(arguments: &MalformedIngressArguments) -> Result<()> {
    if !arguments.output.is_absolute() {
        return Err(CiError::Message(
            "malformed ingress receipt must be an absolute fresh path".into(),
        ));
    }
    let request = crate::linux_consumer_readiness::measured(
        &arguments.request,
        memcordon_core::workload_limits::CONTRACT_ENVELOPE_BYTES as u64,
    )
    .map_err(CiError::Message)?;
    let transport = memcordon_platform::probe_malformed_mixed_ingress_with_evidence(&request)
        .map_err(CiError::Message)?;
    let caller = rustix::process::getpid().as_raw_nonzero().get();
    let birth =
        crate::linux_consumer_readiness::process_birth(caller as u32).map_err(CiError::Message)?;
    let executable_path = PathBuf::from(format!("/proc/{caller}/exe"));
    let executable = std::fs::File::open(&executable_path)?;
    let metadata = executable.metadata()?;
    let mut executable_bytes = Vec::new();
    executable
        .try_clone()?
        .take(512 * 1024 * 1024 + 1)
        .read_to_end(&mut executable_bytes)?;
    if executable_bytes.len() > 512 * 1024 * 1024 {
        return Err(CiError::Message(
            "malformed ingress executable exceeds bound".into(),
        ));
    }
    let after = executable.metadata()?;
    if (metadata.dev(), metadata.ino(), metadata.len()) != (after.dev(), after.ino(), after.len())
        || metadata.len() != executable_bytes.len() as u64
    {
        return Err(CiError::Message(
            "malformed ingress actual executable changed while retained".into(),
        ));
    }
    let receipt = serde_json::json!({
        "format":"memcordon.linux-malformed-ingress-observation","revision":2,
        "caller_pid":caller,"caller_uid":rustix::process::geteuid().as_raw(),"caller_gid":rustix::process::getegid().as_raw(),
        "caller_birth":birth,"native_image":{"device":metadata.dev(),"inode":metadata.ino(),"length":metadata.len(),
            "sha256":super::artifacts::checksum(&executable_bytes)},
        "provider":transport.provider,"wire_nonce":transport.nonce,"attempt":transport.attempt,
        "request":request,"response":transport.response,"transport":transport,
    });
    let bytes = serde_json::to_vec(&receipt)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&arguments.output)?;
    output.write_all(&bytes)?;
    output.sync_all()?;
    let parent = arguments
        .output
        .parent()
        .ok_or_else(|| CiError::Message("malformed ingress receipt parent absent".into()))?;
    let held_parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(parent)?;
    held_parent.sync_all()?;
    if crate::linux_consumer_readiness::measured(&arguments.output, 4 * 1024 * 1024)
        .map_err(CiError::Message)?
        != bytes
    {
        return Err(CiError::Message(
            "malformed ingress receipt named readback differs".into(),
        ));
    }
    Ok(())
}
