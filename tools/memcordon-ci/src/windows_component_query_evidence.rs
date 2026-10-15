//! Bounded evidence from the actual live-association query, including refusals.
use memcordon_testkit::{ObservedOutput, ProcessTestError};
use std::{
    fs::OpenOptions,
    io::{self, Write},
    path::Path,
};

fn retain(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

pub fn retain_invocation(directory: &Path, invocation: &[u8]) -> io::Result<()> {
    if invocation.len() > 256 * 1024 {
        return Err(io::Error::other("live query invocation exceeds bound"));
    }
    retain(
        &directory.join("live-association-query-invocation.json"),
        invocation,
    )
}

pub fn retain_not_started(directory: &Path) -> io::Result<()> {
    retain(&directory.join("live-association-query-result.json"),
        b"{\"format\":\"memcordon.windows-live-association-query-result\",\"revision\":1,\"streams_available\":false,\"observation\":{\"kind\":\"not-started\",\"reason\":\"original-work-cutoff-expired\"}}\n")
}

pub fn retain_result(
    directory: &Path,
    result: &Result<ObservedOutput, ProcessTestError>,
) -> io::Result<()> {
    use serde_json::json;
    let (streams, evidence) = match result {
        Ok(output) => (
            Some((&output.stdout, &output.stderr)),
            json!({
                "kind":"completed", "status":format!("{:?}",output.status),
                "elapsed_ms":output.elapsed.as_millis(),
            }),
        ),
        Err(ProcessTestError::Timeout {
            deadline,
            stdout,
            stderr,
            cleanup,
            observation,
        }) => (
            Some((stdout, stderr)),
            json!({
                "kind":"timeout", "deadline_ms":deadline.as_millis(), "cleanup":cleanup,
                "child_id":observation.child_id, "observed_status":observation.observed_status.map(|status| format!("{status:?}")),
                "callback_completed":observation.callback_completed,
                "spawn_returned_ms":observation.spawn_returned.as_millis(),
                "boundary_admitted_ms":observation.boundary_admitted.as_millis(),
                "timeout_observed_ms":observation.timeout_observed.as_millis(),
                "stdout_reader_finished":observation.stdout_reader_finished,
                "stderr_reader_finished":observation.stderr_reader_finished,
            }),
        ),
        Err(ProcessTestError::Cancelled {
            stdout,
            stderr,
            cleanup,
            termination,
            observation,
        }) => (
            Some((stdout, stderr)),
            json!({
                "kind":"cancelled", "cleanup":cleanup, "termination":termination.map(|status| format!("{status:?}")),
                "child_id":observation.child_id, "observed_status":observation.observed_status.map(|status| format!("{status:?}")),
                "callback_completed":observation.callback_completed,
                "cancellation_observed_ms":observation.cancellation_observed.as_millis(),
                "stdout_reader_finished":observation.stdout_reader_finished,
                "stderr_reader_finished":observation.stderr_reader_finished,
            }),
        ),
        Err(ProcessTestError::Callback {
            error,
            stdout,
            stderr,
            capture_complete,
            observed_status,
            termination,
            cleanup,
        }) => (
            Some((stdout, stderr)),
            json!({
                "kind":"callback", "error":error.to_string(), "capture_complete":capture_complete,
                "observed_status":observed_status.map(|status| format!("{status:?}")),
                "termination":termination.map(|status| format!("{status:?}")), "cleanup":cleanup,
            }),
        ),
        Err(ProcessTestError::OutputLimit {
            stdout,
            stderr,
            cleanup,
            termination,
        }) => (
            Some((stdout, stderr)),
            json!({
                "kind":"output-limit", "cleanup":cleanup,
                "termination":termination.map(|status| format!("{status:?}")),
            }),
        ),
        Err(ProcessTestError::Spawn(error)) => {
            (None, json!({"kind":"spawn", "error":error.to_string()}))
        }
        Err(ProcessTestError::Wait(error)) => {
            (None, json!({"kind":"wait", "error":error.to_string()}))
        }
        Err(ProcessTestError::Output(error)) => {
            (None, json!({"kind":"output", "error":error.to_string()}))
        }
    };
    if let Some((stdout, stderr)) = streams {
        let limit = memcordon_core::WindowsGuardianAttemptObservation::MAX_FRAME_BYTES;
        if stdout.len() > limit || stderr.len() > limit {
            return Err(io::Error::other(
                "live query captured stream exceeds original bound",
            ));
        }
        retain(&directory.join("live-association-query.stdout.bin"), stdout)?;
        retain(&directory.join("live-association-query.stderr.bin"), stderr)?;
    }
    let bytes = serde_json::to_vec(&json!({
        "format":"memcordon.windows-live-association-query-result", "revision":1,
        "streams_available":streams.is_some(), "observation":evidence,
    }))?;
    if bytes.len() > 256 * 1024 {
        return Err(io::Error::other("live query result metadata exceeds bound"));
    }
    retain(
        &directory.join("live-association-query-result.json"),
        &bytes,
    )
}
