//! Kernel observations of a full original relay pipe while its reader is stopped.
use crate::{CiError, Result, linux_consumer_readiness::HeldLinuxProcess};
use std::{
    fs::File,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    time::{Duration, Instant},
};

pub fn observe(
    frontend: &HeldLinuxProcess,
    target: &HeldLinuxProcess,
    cutoff: Instant,
    release: impl FnOnce() -> Result<()>,
) -> Result<serde_json::Value> {
    target
        .signal_stop()
        .map_err(CiError::Message)?
        .map_err(|code| CiError::Message(format!("original relay writer stop failed: {code}")))?;
    let mut target_stopped = true;
    let observed = (|| -> Result<serde_json::Value> {
        target
            .observe_stopped_until(cutoff)
            .map_err(CiError::Message)?;
        release()?;
        let input = File::options()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(format!("/proc/{}/fd/0", target.process_id))?;
        if input.metadata()?.mode() & libc::S_IFMT != libc::S_IFIFO {
            return Err(CiError::Message(
                "original target input gate is not a native pipe".into(),
            ));
        }
        loop {
            if Instant::now() >= cutoff
                || frontend.exited().map_err(CiError::Message)?
                || target.exited().map_err(CiError::Message)?
            {
                return Err(CiError::Message(
                    "original relay input gate cutoff/liveness exhausted".into(),
                ));
            }
            let queued = rustix::io::ioctl_fionread(&input).map_err(std::io::Error::from)?;
            if queued == 1 {
                break;
            }
            if queued > 1 {
                return Err(CiError::Message(
                    "original relay input gate has extra bytes".into(),
                ));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        drop(input);
        frontend
            .signal_stop()
            .map_err(CiError::Message)?
            .map_err(|code| {
                CiError::Message(format!("original relay reader stop failed: {code}"))
            })?;
        frontend
            .observe_stopped_until(cutoff)
            .map_err(CiError::Message)?;
        target
            .signal_continue()
            .map_err(CiError::Message)?
            .map_err(|code| {
                CiError::Message(format!("original relay writer resume failed: {code}"))
            })?;
        target_stopped = false;
        let mut pipes = Vec::new();
        for descriptor in [1, 2] {
            let path = format!("/proc/{}/fd/{descriptor}", target.process_id);
            let link = std::fs::read_link(&path)?;
            if !link.as_os_str().as_encoded_bytes().starts_with(b"pipe:[") {
                return Err(CiError::Message(
                    "original target stream is not a native pipe".into(),
                ));
            }
            let file = File::options()
                .read(true)
                .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(path)?;
            let metadata = file.metadata()?;
            if metadata.mode() & libc::S_IFMT != libc::S_IFIFO {
                return Err(CiError::Message(
                    "native relay descriptor changed type".into(),
                ));
            }
            let capacity = rustix::pipe::fcntl_getpipe_size(&file).map_err(std::io::Error::from)?;
            pipes.push((descriptor, file, metadata, capacity));
        }
        loop {
            if Instant::now() >= cutoff
                || target.exited().map_err(CiError::Message)?
                || frontend.exited().map_err(CiError::Message)?
            {
                return Err(CiError::Message(
                    "original relay pressure cutoff/liveness exhausted".into(),
                ));
            }
            for (descriptor, file, metadata, capacity) in &pipes {
                let available = rustix::io::ioctl_fionread(file).map_err(std::io::Error::from)?;
                let capacity = u64::try_from(*capacity)
                    .map_err(|error| CiError::Message(error.to_string()))?;
                let syscall =
                    std::fs::read_to_string(format!("/proc/{}/syscall", target.process_id))?;
                let fields: Vec<_> = syscall.split_whitespace().collect();
                let raw_number = fields.first().and_then(|value| value.parse::<i64>().ok());
                let hex_number = |index: usize| {
                    fields
                        .get(index)
                        .and_then(|value| value.strip_prefix("0x"))
                        .and_then(|value| u64::from_str_radix(value, 16).ok())
                };
                let wait_channel =
                    std::fs::read_to_string(format!("/proc/{}/wchan", target.process_id))?;
                if available > 0
                    && available <= capacity
                    && capacity - available < 4096
                    && raw_number == Some(libc::SYS_write)
                    && hex_number(1) == Some(*descriptor as u64)
                    && hex_number(3) == Some(256)
                    && wait_channel.trim() == "pipe_write"
                {
                    return Ok(
                        serde_json::json!({"format":"memcordon.linux-current-relay-pressure","revision":1,"frontend":{"pid":frontend.process_id,"birth":frontend.birth},"target":{"pid":target.process_id,"birth":target.birth},"reader_stopped":true,"target_alive":true,"descriptor":descriptor,"pipe":{"device":metadata.dev(),"inode":metadata.ino(),"capacity":capacity,"queued":available},"blocked_write":{"syscall":raw_number,"descriptor":hex_number(1),"length":hex_number(3),"wait_channel":wait_channel.trim()},"bytes_consumed_by_observer":0}),
                    );
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    })();
    let target_resumed = if target_stopped {
        target
            .signal_continue()
            .map_err(CiError::Message)
            .and_then(|result| {
                result.map_err(|code| {
                    CiError::Message(format!("original relay writer settlement failed: {code}"))
                })
            })
    } else {
        Ok(())
    };
    let resumed = frontend
        .signal_continue()
        .map_err(CiError::Message)
        .and_then(|result| {
            result.map_err(|code| {
                CiError::Message(format!("original relay reader resume failed: {code}"))
            })
        });
    let resumed = resumed.and(target_resumed);
    match (observed, resumed) {
        (Ok(mut value), Ok(())) => {
            value["reader_resumed"] = true.into();
            value["original_target_input_gated"] = true.into();
            value["release_byte_queued_before_reader_stop"] = 1.into();
            Ok(value)
        }
        (Err(primary), Ok(())) => Err(primary),
        (Ok(_), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(CiError::Message(format!(
            "{primary}; relay reader settlement: {cleanup}"
        ))),
    }
}
