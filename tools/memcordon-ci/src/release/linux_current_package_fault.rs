//! Interrupt the original current installer at its actual journal publication.
use super::{
    artifacts,
    linux_current_phase_gate::{NativeReadGate, NativeTraceStop},
    source,
};
use crate::{CiError, Result, command::CommandSpec, linux_consumer_readiness::HeldLinuxProcess};
use std::{
    fs,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        process::ExitStatusExt,
    },
    path::Path,
    time::{Duration, Instant},
};
fn file_observation(path: &Path) -> Result<serde_json::Value> {
    if ![
        Path::new("/usr/libexec"),
        Path::new("/usr/lib/systemd/system"),
        Path::new("/usr/lib/tmpfiles.d"),
    ]
    .iter()
    .any(|parent| Some(*parent) == path.parent())
    {
        return Err(CiError::Message(
            "current transaction native observation path is outside finite package roots".into(),
        ));
    }
    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(serde_json::json!({"path":path,"absent":true}));
        }
        Err(error) => return Err(error.into()),
    };
    let before = file.metadata()?;
    if !before.is_file() || before.uid() != 0 || before.nlink() != 1 || before.mode() & 0o022 != 0 {
        return Err(CiError::Message(
            "current transaction native observation inode is not protected".into(),
        ));
    }
    let bytes = crate::linux_consumer_readiness::measured(path, 512 * 1024 * 1024)
        .map_err(CiError::Message)?;
    let after = fs::symlink_metadata(path)?;
    if (before.dev(), before.ino(), before.mode(), before.len())
        != (after.dev(), after.ino(), after.mode(), after.len())
    {
        return Err(CiError::Message(
            "current package inode changed during independent observation".into(),
        ));
    }
    Ok(
        serde_json::json!({"path":path,"device":before.dev(),"inode":before.ino(),"mode":before.mode()&0o7777,"uid":before.uid(),"links":before.nlink(),"length":before.len(),"sha256":artifacts::checksum(&bytes)}),
    )
}
fn file_inventory(publication: &serde_json::Value) -> Result<Vec<serde_json::Value>> {
    let bytes: Vec<u8> = serde_json::from_value(publication["record_bytes"].clone())?;
    let journal: serde_json::Value = serde_json::from_slice(&bytes)?;
    let entries = journal["entries"]
        .as_array()
        .ok_or_else(|| CiError::Message("current package journal entries absent".into()))?;
    if entries.len() > 32 {
        return Err(CiError::Message(
            "current package journal native inventory exceeds bound".into(),
        ));
    }
    let mut observations = Vec::new();
    for entry in entries {
        let path = entry["path"]
            .as_str()
            .ok_or_else(|| CiError::Message("current package target absent".into()))?;
        let query = |role: &str| -> Result<serde_json::Value> {
            match entry[role]["path"].as_str() {
                Some(path) => file_observation(Path::new(path)),
                None => Ok(serde_json::Value::Null),
            }
        };
        observations.push(serde_json::json!({"path":path,"target":file_observation(Path::new(path))?,"stage":query("stage")?,"placeholder":query("placeholder")?}));
    }
    Ok(observations)
}
pub fn interrupt(
    root: &Path,
    agent: &Path,
    lifetime: &Path,
    artifact_root: &Path,
    lease_id: &str,
    ordinal: u64,
    cutoff: Instant,
) -> Result<()> {
    let executable = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(agent)?;
    let executable_metadata = executable.metadata()?;
    let gate = NativeReadGate::on_current_executable(&executable, cutoff)?;
    let parent = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/usr/libexec")?;
    let before_manifest =
        artifacts::read_file(Path::new("/usr/libexec/memcordon-runtime-manifest.json"))?;
    let manifest = memcordon_core::runtime_manifest_v2::RuntimeManifestV2::parse(&before_manifest)
        .map_err(CiError::Message)?;
    let operation_path = lifetime.join(format!("root-operation-{ordinal}.json"));
    let intent = serde_json::json!({"format":"memcordon.current-root-operation","revision":1,"lease_id":lease_id,"program":agent,"executable_sha256":artifacts::checksum(&artifacts::read_file(agent)?),"arguments":["package","upgrade"],"process":null,"completed":null});
    source::write_json(&operation_path, &intent)?;
    let mut pin = None;
    let observation = lifetime.join("current-install-interruption.json");
    let output=CommandSpec::new(agent,root,Duration::from_secs(300)).bounded_until(cutoff).args(["package","upgrade"])
        .output_quiet_with_exec_observation(|child| {
            let birth=crate::linux_consumer_readiness::process_birth(child.id()).map_err(CiError::Message)?;
            let held=HeldLinuxProcess::acquire(child.id(),birth).map_err(CiError::Message)?;
            let mut operation=intent.clone();operation["process"]=serde_json::json!({"pid":child.id(),"birth":birth});source::write_json(&operation_path,&operation)?;
            let mut permission=gate.wait()?;
            if permission.process_id!=child.id() {return Err(CiError::Message("current installer permission event belongs to another process".into()));}
            let traced=HeldLinuxProcess::acquire(child.id(),birth).map_err(CiError::Message)?;
            let mut trace=NativeTraceStop::attach(traced,&mut permission,cutoff)?;
            let publication=trace.after_rename_prefix(&parent,".memcordon-journal-",".memcordon-current-package-transaction.json",|bytes|{
                serde_json::from_slice::<serde_json::Value>(bytes).is_ok_and(|value|value["format"]=="memcordon.current-package-transaction" && value["revision"]==1)
            })?;
            let detached=trace.detach_stopped()?;
            let file_inventory=file_inventory(&publication)?;
            let mut native=serde_json::json!({"format":"memcordon.linux-current-install-interruption","revision":1,"lease_id":lease_id,"operation":operation_path.strip_prefix(artifact_root).map_err(|error|CiError::Message(error.to_string()))?,"executable_identity":{"device":executable_metadata.dev(),"inode":executable_metadata.ino(),"length":executable_metadata.len(),"mode":executable_metadata.mode(),"uid":executable_metadata.uid(),"sha256":intent["executable_sha256"]},"manifest_before":manifest,"manifest_bytes_before":before_manifest,"permission":permission.observation(),"publication":publication,"detached":detached,"signal":9,"signal_result":null});
            native["file_inventory"]=serde_json::to_value(file_inventory)?;
            source::write_json(&observation,&native)?;
            held.signal_kill().map_err(CiError::Message)?.map_err(|code|CiError::Message(format!("original current installer kill failed: {code}")))?;
            native["signal_result"]=0.into();source::write_json(&observation,&native)?;
            pin=Some(held);Ok(())
        })?;
    let mut operation: serde_json::Value = source::read_json(&operation_path)?;
    operation["completed"] = serde_json::json!({"status":output.status.code(),"raw_wait_status":output.status.into_raw(),"stdout":output.stdout,"stderr":output.stderr});
    source::write_json(&operation_path, &operation)?;
    let pin =
        pin.ok_or_else(|| CiError::Message("original current installer handle absent".into()))?;
    if output.status.signal() != Some(9) || !pin.exited().map_err(CiError::Message)? {
        return Err(CiError::Message(
            "original current installer was not actually reaped after native interruption".into(),
        ));
    }
    let journal = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/usr/libexec/.memcordon-current-package-transaction.json")?;
    let metadata = journal.metadata()?;
    let mut native: serde_json::Value = source::read_json(&observation)?;
    if Some(metadata.dev()) != native["publication"]["device"].as_u64()
        || Some(metadata.ino()) != native["publication"]["inode"].as_u64()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(CiError::Message(
            "current installer journal replaced after original native kill".into(),
        ));
    }
    native["original_process_retired"] = serde_json::json!({"pid":pin.process_id,"birth":pin.birth,"pidfd_readable":true,"raw_wait_status":output.status.into_raw()});
    source::write_json(&observation, &native)
}
