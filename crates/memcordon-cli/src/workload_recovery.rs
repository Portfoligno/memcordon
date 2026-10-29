//! Explicit cleanup of an original workload locator, without a launch path.
use std::ffi::OsString;
use std::path::Path;

pub fn acknowledge(arguments: &[OsString]) -> Result<(), String> {
    let [flag, path] = arguments else {
        return Err("usage: memcordon workload acknowledge --observation PATH".into());
    };
    if flag != "--observation" {
        return Err("acknowledgment requires original observation path".into());
    }
    #[cfg(target_os = "linux")]
    {
        use std::io::Read;
        let file = std::fs::File::open(path).map_err(|error| error.to_string())?;
        if !file
            .metadata()
            .map_err(|error| error.to_string())?
            .is_file()
        {
            return Err("original locator must be a regular caller-readable file".into());
        }
        let limit = memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES;
        let mut bytes = Vec::new();
        file.take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        if bytes.len() > limit {
            return Err("original locator exceeds byte bound".into());
        }
        memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)?;
        let locator: memcordon_core::workload_request::WorkloadAttemptAssociationV1 =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        locator.validate().map_err(|error| error.to_string())?;
        let cutoff = std::time::Instant::now()
            .checked_add(std::time::Duration::from_secs(30))
            .ok_or("acknowledgment cutoff overflow")?;
        let acknowledgment = memcordon_platform::acknowledge_workload_attempt(&locator, cutoff)?;
        use std::io::Write;
        let mut bytes = serde_json::to_vec(&acknowledgment).map_err(|error| error.to_string())?;
        bytes.push(b'\n');
        std::io::stdout()
            .lock()
            .write_all(&bytes)
            .map_err(|error| error.to_string())?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Err("Linux workload acknowledgment requires the actual Linux provider".into())
    }
}

pub fn run(arguments: &[OsString]) -> Result<(), String> {
    let [observation, locator_path, report, report_path] = arguments else {
        return Err("usage: memcordon workload recover --observation PATH --report PATH".into());
    };
    if observation != "--observation"
        || report != "--report"
        || report_path == "-"
        || locator_path == report_path
    {
        return Err("recovery requires distinct locator and report file paths".into());
    }
    #[cfg(target_os = "linux")]
    {
        use std::io::Read;
        let file = std::fs::File::open(locator_path).map_err(|error| error.to_string())?;
        if !file
            .metadata()
            .map_err(|error| error.to_string())?
            .is_file()
        {
            return Err("original workload locator must be a regular caller-readable file".into());
        }
        let limit = memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES;
        let mut bytes = Vec::new();
        file.take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        if bytes.len() > limit {
            return Err("original workload locator exceeds byte bound".into());
        }
        memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)?;
        let locator: memcordon_core::workload_request::WorkloadAttemptAssociationV1 =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        locator.validate().map_err(|error| error.to_string())?;
        let cutoff = std::time::Instant::now()
            .checked_add(std::time::Duration::from_secs(30))
            .ok_or("recovery cutoff overflow")?;
        let terminal = memcordon_platform::recover_workload_attempt(&locator, cutoff)?;
        let mut bytes = serde_json::to_vec_pretty(&terminal).map_err(|error| error.to_string())?;
        bytes.push(b'\n');
        memcordon_core::write_report_bytes_atomic(Path::new(report_path), &bytes)
            .map_err(|error| error.to_string())?;
        if terminal.cleanup.state != memcordon_core::execution_facts::CleanupStateV1::Complete {
            return Err(
                "original workload still has native cleanup obligations; inspect recovery report"
                    .into(),
            );
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (Path::new(locator_path), Path::new(report_path));
        Err("Linux workload recovery requires the actual Linux provider".into())
    }
}
