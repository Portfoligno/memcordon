//! Interrupt the owned current installer at its real durable publication.
use super::linux_current_phase_gate::{NativeReadGate, NativeTraceStop};
use crate::{CiError, Result, command::CommandSpec, linux_consumer_readiness::HeldLinuxProcess};
use std::{
    fs::{self, File, OpenOptions},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        process::ExitStatusExt,
    },
    path::Path,
    time::{Duration, Instant},
};

pub fn interrupt(root: &Path, agent: &Path, cutoff: Instant) -> Result<()> {
    let executable = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(agent)?;
    let gate = NativeReadGate::on_current_executable(&executable, cutoff)?;
    let parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/usr/libexec")?;
    let mut owned = None;
    let output = CommandSpec::new(agent, root, Duration::from_secs(300))
        .bounded_until(cutoff)
        .args(["package", "upgrade"])
        .output_quiet_with_exec_observation(|child| {
            let birth = crate::linux_consumer_readiness::process_birth(child.id())
                .map_err(CiError::Message)?;
            let process = HeldLinuxProcess::acquire(child.id(), birth).map_err(CiError::Message)?;
            let mut permission = gate.wait()?;
            if permission.process_id != child.id() {
                return Err(CiError::Message(
                    "installer permission event belongs to another original child".into(),
                ));
            }
            let traced = HeldLinuxProcess::acquire(child.id(), birth).map_err(CiError::Message)?;
            let mut trace = NativeTraceStop::attach(traced, &mut permission, cutoff)?;
            let publication = trace.after_rename_prefix(
                &parent,
                ".memcordon-journal-",
                ".memcordon-current-package-transaction.json",
                |bytes| {
                    serde_json::from_slice::<serde_json::Value>(bytes).is_ok_and(|value| {
                        value["format"] == "memcordon.current-package-transaction"
                            && value["revision"] == 1
                    })
                },
            )?;
            trace.detach_stopped()?;
            let journal = File::from(
                rustix::fs::openat(
                    &parent,
                    ".memcordon-current-package-transaction.json",
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map_err(std::io::Error::from)?,
            );
            let metadata = journal.metadata()?;
            if metadata.uid() != 0
                || !metadata.is_file()
                || metadata.mode() & 0o777 != 0o600
                || Some(metadata.dev()) != publication["device"].as_u64()
                || Some(metadata.ino()) != publication["inode"].as_u64()
            {
                return Err(CiError::Message(
                    "installer did not publish its protected actual transaction inode".into(),
                ));
            }
            process
                .signal_kill()
                .map_err(CiError::Message)?
                .map_err(|code| {
                    CiError::Message(format!("owned installer interruption failed: {code}"))
                })?;
            owned = Some((process, journal, metadata));
            Ok(())
        })?;
    let (process, journal, before) = owned.ok_or_else(|| {
        CiError::Message("owned installer did not reach durable publication".into())
    })?;
    if output.status.signal() != Some(9) || !process.exited().map_err(CiError::Message)? {
        return Err(CiError::Message(
            "installer was not reaped after the exact owned interruption".into(),
        ));
    }
    let named = fs::symlink_metadata("/usr/libexec/.memcordon-current-package-transaction.json")?;
    let held = journal.metadata()?;
    if (before.dev(), before.ino(), before.uid(), before.mode())
        != (named.dev(), named.ino(), named.uid(), named.mode())
        || (before.dev(), before.ino()) != (held.dev(), held.ino())
    {
        return Err(CiError::Message(
            "current transaction was replaced after installer interruption".into(),
        ));
    }
    Ok(())
}
