#![forbid(unsafe_code)]

use std::fmt;
use std::io::{self, Read};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use memcordon_platform::test_support::OuterTestBoundary;

#[derive(Debug)]
pub struct ObservedOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub elapsed: Duration,
}

#[derive(Debug)]
pub enum ProcessTestError {
    Spawn(io::Error),
    Wait(io::Error),
    Output(io::Error),
    Timeout {
        deadline: Duration,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        cleanup: Result<(), String>,
    },
}

impl fmt::Display for ProcessTestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn(error) => write!(formatter, "test command failed to spawn: {error}"),
            Self::Wait(error) => write!(formatter, "test command wait failed: {error}"),
            Self::Output(error) => write!(formatter, "test output reader failed: {error}"),
            Self::Timeout {
                deadline,
                stdout,
                stderr,
                cleanup,
            } => write!(
                formatter,
                "test command exceeded {deadline:?}; cleanup={cleanup:?}; stdout={:?}; stderr={:?}",
                String::from_utf8_lossy(stdout),
                String::from_utf8_lossy(stderr)
            ),
        }
    }
}

impl std::error::Error for ProcessTestError {}

fn reader(mut stream: impl Read + Send + 'static) -> thread::JoinHandle<io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes)?;
        Ok(bytes)
    })
}

pub fn run_with_deadline(
    command: &mut Command,
    deadline: Duration,
) -> Result<ObservedOutput, ProcessTestError> {
    run_with_deadline_after(command, deadline, |_| Ok(()))
}

pub fn run_with_deadline_after(
    command: &mut Command,
    deadline: Duration,
    after_spawn: impl FnOnce(u32) -> io::Result<()> + Send + 'static,
) -> Result<ObservedOutput, ProcessTestError> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    OuterTestBoundary::configure(command).map_err(ProcessTestError::Spawn)?;
    let started = Instant::now();
    let mut child = command.spawn().map_err(ProcessTestError::Spawn)?;
    let boundary = match OuterTestBoundary::after_spawn(&child) {
        Ok(boundary) => boundary,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ProcessTestError::Spawn(error));
        }
    };
    let stdout_reader = reader(child.stdout.take().expect("stdout was configured as piped"));
    let stderr_reader = reader(child.stderr.take().expect("stderr was configured as piped"));
    let (callback_sender, callback_receiver) = mpsc::sync_channel(1);
    let child_id = child.id();
    let callback = thread::spawn(move || {
        let _ = callback_sender.send(after_spawn(child_id));
    });
    let mut callback_result = None;
    let mut observed_status = None;

    let status = loop {
        if callback_result.is_none() {
            match callback_receiver.try_recv() {
                Ok(result) => callback_result = Some(result),
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    callback_result = Some(Err(io::Error::other("after-spawn callback panicked")));
                }
            }
        }
        if callback_result.as_ref().is_some_and(Result::is_err) {
            let error = callback_result
                .take()
                .expect("callback result was present")
                .expect_err("callback result was checked as an error");
            let cleanup = boundary.terminate();
            if cleanup.is_err() {
                let _ = child.kill();
            }
            let _ = child.wait();
            if cleanup.is_ok() {
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
            }
            let _ = callback.join();
            return Err(ProcessTestError::Wait(error));
        }
        if observed_status.is_none() {
            match child.try_wait() {
                Ok(status) => observed_status = status,
                Err(error) => {
                    let cleanup = boundary.terminate();
                    if cleanup.is_err() {
                        let _ = child.kill();
                    }
                    let _ = child.wait();
                    if cleanup.is_ok() {
                        let _ = stdout_reader.join();
                        let _ = stderr_reader.join();
                    }
                    return Err(ProcessTestError::Wait(error));
                }
            }
        }
        if let (Some(status), Some(Ok(()))) = (observed_status, callback_result.as_ref()) {
            let _ = callback.join();
            break status;
        }
        if started.elapsed() >= deadline {
            let cleanup = boundary.terminate().map_err(|error| error.to_string());
            if cleanup.is_err() {
                let _ = child.kill();
            }
            let wait_result = observed_status.map_or_else(|| child.wait(), Ok);
            if let Err(error) = cleanup {
                return Err(ProcessTestError::Timeout {
                    deadline,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    cleanup: Err(error),
                });
            }
            let stdout = stdout_reader
                .join()
                .map_err(|_| ProcessTestError::Output(io::Error::other("stdout reader panicked")))?
                .map_err(ProcessTestError::Output)?;
            let stderr = stderr_reader
                .join()
                .map_err(|_| ProcessTestError::Output(io::Error::other("stderr reader panicked")))?
                .map_err(ProcessTestError::Output)?;
            let cleanup = wait_result.map(|_| ()).map_err(|error| error.to_string());
            return Err(ProcessTestError::Timeout {
                deadline,
                stdout,
                stderr,
                cleanup,
            });
        }
        thread::sleep(Duration::from_millis(5));
    };

    // A direct child may have exited while a descendant still owns inherited pipes. Empty the
    // independent outer boundary before joining readers so that such a defect cannot hang tests.
    if let Err(error) = boundary.terminate() {
        return Err(ProcessTestError::Wait(error));
    }
    let stdout = stdout_reader
        .join()
        .map_err(|_| ProcessTestError::Output(io::Error::other("stdout reader panicked")))?
        .map_err(ProcessTestError::Output)?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| ProcessTestError::Output(io::Error::other("stderr reader panicked")))?
        .map_err(ProcessTestError::Output)?;
    Ok(ObservedOutput {
        status,
        stdout,
        stderr,
        elapsed: started.elapsed(),
    })
}

pub fn assert_stdout_empty(output: &ObservedOutput) {
    assert!(
        output.stdout.is_empty(),
        "wrapper wrote unexpected stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}
