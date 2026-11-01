//! Kernel observations of a full original relay pipe while its reader is stopped.
use crate::{CiError, Result, linux_consumer_readiness::HeldLinuxProcess};
use std::{
    fs::File,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    time::{Duration, Instant},
};

fn native_text(path: std::path::PathBuf) -> std::io::Result<String> {
    crate::linux_relay_sample::read_native_text(File::open(path)?)
}

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
    let started = Instant::now();
    let mut diagnostic = serde_json::json!({
        "diagnostic_only":true,"sequential_not_atomic":true,
        "frontend":{"pid":frontend.process_id,"birth":frontend.birth},
        "target":{"pid":target.process_id,"birth":target.birth},
        "original_remaining_micros":cutoff.saturating_duration_since(started).as_micros(),
        "stage":"target-stop-sent","release_byte_queued":false,
        "reader_stop_confirmed":false,"target_resume_confirmed":false,
        "pipes":{},"last_samples":{},"in_progress":null,"boundary":null
    });
    let observed = (|| -> Result<serde_json::Value> {
        target
            .observe_stopped_until(cutoff)
            .map_err(CiError::Message)?;
        diagnostic["stage"] = "target-stop-confirmed".into();
        release()?;
        diagnostic["stage"] = "release-sent-input-queue".into();
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
            let now = Instant::now();
            diagnostic["boundary"] = serde_json::json!({"elapsed_micros":now.duration_since(started).as_micros(),"cutoff_reached":now>=cutoff,"frontend_exited":null,"target_exited":null});
            if now >= cutoff {
                return Err(CiError::Message(
                    "original relay input gate cutoff exhausted".into(),
                ));
            }
            let frontend_exited = frontend.exited().map_err(|error| {
                diagnostic["boundary"]["query_error"] = "original-frontend".into();
                CiError::Message(error)
            })?;
            diagnostic["boundary"]["frontend_exited"] = frontend_exited.into();
            if frontend_exited {
                return Err(CiError::Message(
                    "original relay input gate frontend retired".into(),
                ));
            }
            let target_exited = target.exited().map_err(|error| {
                diagnostic["boundary"]["query_error"] = "original-target".into();
                CiError::Message(error)
            })?;
            diagnostic["boundary"]["target_exited"] = target_exited.into();
            if target_exited {
                return Err(CiError::Message(
                    "original relay input gate target retired".into(),
                ));
            }
            let queued = rustix::io::ioctl_fionread(&input).map_err(std::io::Error::from)?;
            diagnostic["input_queued"] = queued.into();
            if queued == 1 {
                diagnostic["release_byte_queued"] = true.into();
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
        diagnostic["stage"] = "reader-stop-sent".into();
        frontend
            .observe_stopped_until(cutoff)
            .map_err(CiError::Message)?;
        diagnostic["reader_stop_confirmed"] = true.into();
        target
            .signal_continue()
            .map_err(CiError::Message)?
            .map_err(|code| {
                CiError::Message(format!("original relay writer resume failed: {code}"))
            })?;
        target_stopped = false;
        diagnostic["target_resume_confirmed"] = true.into();
        diagnostic["stage"] = "acquire-stream-pipes".into();
        let mut pipes = Vec::new();
        for descriptor in [1, 2] {
            diagnostic["stream_acquisition"] =
                serde_json::json!({"descriptor":descriptor,"operation":"link-read"});
            let path = format!("/proc/{}/fd/{descriptor}", target.process_id);
            let link = std::fs::read_link(&path)?;
            if !link.as_os_str().as_encoded_bytes().starts_with(b"pipe:[") {
                return Err(CiError::Message(
                    "original target stream is not a native pipe".into(),
                ));
            }
            diagnostic["stream_acquisition"]["operation"] = "open-original-stream".into();
            let file = File::options()
                .read(true)
                .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(path)?;
            diagnostic["stream_acquisition"]["operation"] = "held-metadata".into();
            let metadata = file.metadata()?;
            if metadata.mode() & libc::S_IFMT != libc::S_IFIFO {
                return Err(CiError::Message(
                    "native relay descriptor changed type".into(),
                ));
            }
            diagnostic["stream_acquisition"]["operation"] = "capacity-read".into();
            let capacity = rustix::pipe::fcntl_getpipe_size(&file).map_err(std::io::Error::from)?;
            diagnostic["pipes"][descriptor.to_string()] = serde_json::json!({"device":metadata.dev(),"inode":metadata.ino(),"capacity":capacity});
            pipes.push((descriptor, file, metadata, capacity));
        }
        diagnostic["stage"] = "pressure-sampling".into();
        loop {
            let now = Instant::now();
            diagnostic["boundary"] = serde_json::json!({"elapsed_micros":now.duration_since(started).as_micros(),"cutoff_reached":now>=cutoff,"target_exited":null,"frontend_exited":null});
            if now >= cutoff {
                return Err(CiError::Message(
                    "original relay pressure original cutoff exhausted".into(),
                ));
            }
            let target_exited = target.exited().map_err(|error| {
                diagnostic["boundary"]["query_error"] = "original-target".into();
                CiError::Message(error)
            })?;
            diagnostic["boundary"]["target_exited"] = target_exited.into();
            if target_exited {
                return Err(CiError::Message(
                    "original relay pressure target retired".into(),
                ));
            }
            let frontend_exited = frontend.exited().map_err(|error| {
                diagnostic["boundary"]["query_error"] = "original-frontend".into();
                CiError::Message(error)
            })?;
            diagnostic["boundary"]["frontend_exited"] = frontend_exited.into();
            if frontend_exited {
                return Err(CiError::Message(
                    "original relay pressure frontend retired".into(),
                ));
            }
            for (descriptor, file, metadata, capacity) in &pipes {
                diagnostic["in_progress"] = serde_json::json!({"descriptor":descriptor,"elapsed_micros":now.duration_since(started).as_micros(),"operation":"queued-read","queued":null,"write":null,"complete":false});
                let available = rustix::io::ioctl_fionread(file).map_err(std::io::Error::from)?;
                diagnostic["in_progress"]["queued"] = available.into();
                let capacity = u64::try_from(*capacity)
                    .map_err(|error| CiError::Message(error.to_string()))?;
                diagnostic["in_progress"]["operation"] = "syscall-read".into();
                let syscall = native_text(std::path::PathBuf::from(format!(
                    "/proc/{}/syscall",
                    target.process_id
                )))?;
                diagnostic["in_progress"]["write"] = serde_json::to_value(
                    crate::linux_relay_sample::WriteSample::parse(&syscall, ""),
                )?;
                diagnostic["in_progress"]["operation"] = "wait-channel-read".into();
                let wait_channel = native_text(std::path::PathBuf::from(format!(
                    "/proc/{}/wchan",
                    target.process_id
                )))?;
                let sample = crate::linux_relay_sample::WriteSample::parse(&syscall, &wait_channel);
                diagnostic["last_samples"][descriptor.to_string()] = serde_json::json!({"elapsed_micros":now.duration_since(started).as_micros(),"pipe":{"device":metadata.dev(),"inode":metadata.ino(),"capacity":capacity,"queued":available},"write":&sample,"predicates":sample.predicates(*descriptor as u64,available,capacity,libc::SYS_write),"complete":true});
                diagnostic["in_progress"] = serde_json::Value::Null;
                if sample.matches(*descriptor as u64, available, capacity, libc::SYS_write) {
                    return Ok(
                        serde_json::json!({"format":"memcordon.linux-current-relay-pressure","revision":1,"frontend":{"pid":frontend.process_id,"birth":frontend.birth},"target":{"pid":target.process_id,"birth":target.birth},"reader_stopped":true,"target_alive":true,"descriptor":descriptor,"pipe":{"device":metadata.dev(),"inode":metadata.ino(),"capacity":capacity,"queued":available},"blocked_write":{"syscall":sample.number,"descriptor":sample.descriptor,"length":sample.length,"wait_channel":sample.wait_channel},"bytes_consumed_by_observer":0}),
                    );
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    })();
    // Freeze only already-collected observations before either resume changes
    // process state. This is sequential diagnostic context, not native proof.
    let observed = observed.map_err(|mut error| {
        for descriptor in [1, 2] {
            let sample = &diagnostic["last_samples"][descriptor.to_string()];
            error = error.context(format!(
                "last complete original relay pipe {descriptor} sample before cleanup (null means unavailable): {sample}"
            ));
        }
        let partial = diagnostic.as_object_mut().expect("local diagnostic object").remove("in_progress");
        error = error.context(format!("in-progress original relay sample before cleanup (null means unavailable): {}", partial.unwrap_or(serde_json::Value::Null)));
        diagnostic.as_object_mut().expect("local diagnostic object").remove("last_samples");
        error.context(format!("original relay sequential observations before cleanup: {diagnostic}"))
    });
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
    let resumed = crate::linux_relay_sample::combine(resumed, target_resumed);
    match (observed, resumed) {
        (Ok(mut value), Ok(())) => {
            value["reader_resumed"] = true.into();
            value["original_target_input_gated"] = true.into();
            value["release_byte_queued_before_reader_stop"] = 1.into();
            Ok(value)
        }
        (Err(primary), Ok(())) => Err(primary),
        (Ok(_), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(CiError::LaneFailures {
            primary: Box::new(primary),
            secondary: Box::new(cleanup),
        }),
    }
}
