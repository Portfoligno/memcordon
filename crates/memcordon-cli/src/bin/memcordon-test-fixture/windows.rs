//! Fixture windows handlers; invoked only through the command registry.
use super::*;

#[cfg(windows)]
pub(super) fn attempt_job_breakaway() {
    use std::os::windows::process::CommandExt;

    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
    let executable = std::env::current_exe().unwrap_or_else(|error| fail(error.to_string()));
    let result = Command::new(executable)
        .args(["exit", "--code", "0"])
        .creation_flags(CREATE_BREAKAWAY_FROM_JOB)
        .status();
    if let Ok(status) = result {
        fail(format!(
            "Job Object unexpectedly allowed breakaway child with status {status}"
        ));
    }
}

#[cfg(not(windows))]
pub(super) fn attempt_job_breakaway() {
    fail("Job Object breakaway fixture is only available on Windows");
}

pub(super) fn command_attempt_job_breakaway(_args: std::env::ArgsOs) -> i32 {
    {
        attempt_job_breakaway();
        0
    }
}
