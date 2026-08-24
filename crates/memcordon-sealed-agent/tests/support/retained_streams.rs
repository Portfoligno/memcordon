use std::io::Read;
use std::os::unix::net::UnixStream;

use memcordon_sealed_agent::linux::launch::TerminalFacts;
use memcordon_sealed_agent::request::LaunchRequestV1;

use crate::support;

pub struct CapturedExecution {
    pub facts: TerminalFacts,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub execution_millis: u64,
}

pub fn execute(request: LaunchRequestV1) -> Result<CapturedExecution, String> {
    let (mut stdout_reader, stdout_writer) =
        UnixStream::pair().map_err(|error| error.to_string())?;
    let (mut stderr_reader, stderr_writer) =
        UnixStream::pair().map_err(|error| error.to_string())?;
    // SAFETY: getpid has no pointer or ownership requirements and identifies this live frontend.
    let frontend_pid = unsafe { libc::getpid() };
    let (descriptors, attempt) =
        support::resources_with_outputs(frontend_pid, stdout_writer.into(), stderr_writer.into())?;
    let started = memcordon_sealed_agent::linux::clock::monotonic_millis()?;
    let facts = memcordon_sealed_agent::linux::launch::execute(
        request,
        descriptors,
        attempt,
        frontend_pid,
        65_534,
        65_534,
        Vec::new(),
    )?;
    let execution_millis =
        memcordon_sealed_agent::linux::clock::monotonic_millis()?.saturating_sub(started);
    let mut stdout = Vec::new();
    stdout_reader
        .read_to_end(&mut stdout)
        .map_err(|error| error.to_string())?;
    let mut stderr = Vec::new();
    stderr_reader
        .read_to_end(&mut stderr)
        .map_err(|error| error.to_string())?;
    Ok(CapturedExecution {
        facts,
        stdout,
        stderr,
        execution_millis,
    })
}
