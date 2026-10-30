//! Preserve the owned command capture before returning its original failure.
use memcordon_testkit::ProcessTestError;
use serde_json::{Value, json};
use std::{
    fs::OpenOptions,
    io::{self, Write},
    path::Path,
    process::ExitStatus,
};

fn status(status: ExitStatus) -> Value {
    #[cfg(unix)]
    let raw = {
        use std::os::unix::process::ExitStatusExt;
        json!({"domain":"unix-wait","value":status.into_raw()})
    };
    #[cfg(windows)]
    let raw = { json!({"domain":"windows-exit","value":status.code().map(|code|code as u32)}) };
    #[cfg(not(any(unix, windows)))]
    let raw = Value::Null;
    json!({"code":status.code(),"success":status.success(),"native":raw,"debug":format!("{status:?}")})
}
fn retain(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}
pub fn retain_failure(directory: &Path, error: &ProcessTestError, limit: usize) -> io::Result<()> {
    let (streams, observation) = match error {
        ProcessTestError::Callback {
            error,
            stdout,
            stderr,
            capture_complete,
            observed_status,
            termination,
            cleanup,
        } => (
            Some((stdout, stderr)),
            json!({"kind":"callback","error":error.to_string(),"error_kind":format!("{:?}",error.kind()),"raw_os_error":error.raw_os_error(),"capture_complete":capture_complete,"observed_status":observed_status.map(status),"termination":termination.map(status),"cleanup":cleanup}),
        ),
        ProcessTestError::Timeout {
            deadline,
            stdout,
            stderr,
            cleanup,
            observation,
        } => (
            Some((stdout, stderr)),
            json!({"kind":"timeout","deadline_ms":deadline.as_millis(),"cleanup":cleanup,"observed_status":observation.observed_status.map(status),"settlement_complete":observation.settlement_complete,"child_id":observation.child_id,"callback_completed":observation.callback_completed,"spawn_returned_ms":observation.spawn_returned.as_millis(),"boundary_admitted_ms":observation.boundary_admitted.as_millis(),"timeout_observed_ms":observation.timeout_observed.as_millis(),"stdout_reader_finished":observation.stdout_reader_finished,"stderr_reader_finished":observation.stderr_reader_finished}),
        ),
        ProcessTestError::Cancelled {
            stdout,
            stderr,
            cleanup,
            termination,
            observation,
        } => (
            Some((stdout, stderr)),
            json!({"kind":"cancelled","cleanup":cleanup,"termination":termination.map(status),"observed_status":observation.observed_status.map(status),"child_id":observation.child_id,"callback_completed":observation.callback_completed,"cancellation_observed_ms":observation.cancellation_observed.as_millis(),"external_interruption":observation.external_interruption,"stdout_reader_finished":observation.stdout_reader_finished,"stderr_reader_finished":observation.stderr_reader_finished}),
        ),
        ProcessTestError::OutputLimit {
            stdout,
            stderr,
            cleanup,
            termination,
        } => (
            Some((stdout, stderr)),
            json!({"kind":"output-limit","cleanup":cleanup,"termination":termination.map(status)}),
        ),
        ProcessTestError::Spawn(error) => (
            None,
            json!({"kind":"spawn","error":error.to_string(),"raw_os_error":error.raw_os_error()}),
        ),
        ProcessTestError::Wait(error) => (
            None,
            json!({"kind":"wait","error":error.to_string(),"raw_os_error":error.raw_os_error()}),
        ),
        ProcessTestError::Output(error) => (
            None,
            json!({"kind":"output","error":error.to_string(),"raw_os_error":error.raw_os_error()}),
        ),
    };
    let metadata = serde_json::to_vec(
        &json!({"format":"memcordon.current-command-failure","revision":1,"streams_available":streams.is_some(),"stream_bound":limit,"observation":observation}),
    )?;
    if metadata.len() > 64 * 1024 {
        return Err(io::Error::other("command failure metadata exceeds bound"));
    }
    if let Some((stdout, stderr)) = streams {
        if stdout.len() > limit || stderr.len() > limit {
            return Err(io::Error::other(
                "command failure streams exceed original bound",
            ));
        }
        retain(&directory.join("stdout.bin"), stdout)?;
        retain(&directory.join("stderr.bin"), stderr)?;
    }
    retain(&directory.join("command-failure.json"), &metadata)
}
pub fn into_ci_error(directory: &Path, error: ProcessTestError, limit: usize) -> crate::CiError {
    match retain_failure(directory, &error, limit) {
        Ok(()) => crate::CiError::Message(error.to_string()),
        Err(custody) => crate::CiError::Message(format!(
            "{error}; command failure evidence custody failed: {custody}"
        )),
    }
}
/// Retains returned native output even when a separate creation observer failed.
pub fn retain_output(
    directory: &Path,
    output: &memcordon_testkit::ObservedOutput,
    limit: usize,
) -> io::Result<()> {
    if output.stdout.len() > limit || output.stderr.len() > limit {
        return Err(io::Error::other(
            "command output streams exceed original bound",
        ));
    }
    let metadata = serde_json::to_vec(
        &json!({"format":"memcordon.current-command-output","revision":1,"status":status(output.status),"elapsed_ms":output.elapsed.as_millis(),"scope":"native output only; caller observer failure remains fatal"}),
    )?;
    retain(&directory.join("stdout.bin"), &output.stdout)?;
    retain(&directory.join("stderr.bin"), &output.stderr)?;
    retain(&directory.join("command-output.json"), &metadata)
}
/// Only WAIT_TIMEOUT means the original frontend is still pending. Expiry is
/// checked before the native wait; neither a wait nor progress renews it.
pub fn require_frontend_pending(
    stage: &str,
    expired: bool,
    wait: impl FnOnce() -> io::Result<u32>,
) -> io::Result<()> {
    if expired {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("original {stage} cutoff exhausted"),
        ));
    }
    match wait()? {
        258 => Ok(()),
        0 => Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            format!("original frontend exited before {stage}"),
        )),
        other => Err(io::Error::other(format!(
            "unexpected original frontend wait {other:#x} before {stage}"
        ))),
    }
}
