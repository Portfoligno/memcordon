//! Exact unbuffered START reads from the existing fixture stdin handle.
use super::descriptor::{Descriptor, controller_start};
use std::io::{self, Read};
use std::time::{Duration, Instant};
use windows_sys::Win32::{
    Foundation::{HANDLE, INVALID_HANDLE_VALUE},
    Storage::FileSystem::ReadFile,
    System::{
        Console::{GetStdHandle, STD_INPUT_HANDLE},
        Performance::{QueryPerformanceCounter, QueryPerformanceFrequency},
    },
};

struct OriginalInput(HANDLE);
impl Read for OriginalInput {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let length = u32::try_from(bytes.len()).map_err(io::Error::other)?;
        let mut received = 0;
        // SAFETY: original borrowed stdin remains owned by this process; only
        // the requested frame extent is read, with no buffering or read-ahead.
        if unsafe {
            ReadFile(
                self.0,
                bytes.as_mut_ptr(),
                length,
                &mut received,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(received as usize)
    }
}

#[derive(Debug)]
struct Failure {
    original: io::Error,
    deadline: String,
}
impl std::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "START read: {}; original-cutoff settlement: {}",
            self.original, self.deadline
        )
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}

pub(super) fn receive(descriptor: &Descriptor, digest: [u8; 32]) -> io::Result<()> {
    let input = descriptor
        .gate_precondition
        .as_ref()
        .ok_or_else(|| io::Error::other("controller stdin START lacks original clock input"))?;
    input.validate().map_err(io::Error::other)?;
    let sampled = Instant::now();
    let mut now = 0_i64;
    let mut frequency = 0_i64;
    // SAFETY: initialized scalar outputs for the unchanged native clock.
    if unsafe { QueryPerformanceCounter(&mut now) } == 0
        || unsafe { QueryPerformanceFrequency(&mut frequency) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if now < 0
        || frequency <= 0
        || frequency as u64 != input.qpc_frequency
        || now as u64 >= input.work_cutoff_qpc
    {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "original START work cutoff expired or clock differs",
        ));
    }
    let nanos = u128::from(input.work_cutoff_qpc - now as u64) * 1_000_000_000
        / u128::from(input.qpc_frequency);
    let deadline = sampled
        .checked_add(Duration::from_nanos(
            u64::try_from(nanos).map_err(io::Error::other)?,
        ))
        .ok_or_else(|| io::Error::other("original START cutoff cannot be represented"))?;
    let identity = super::native::current_identity()?;
    let binding = controller_start::Binding {
        challenge: descriptor.challenge.clone(),
        descriptor_sha256: digest,
        pid: identity.process_id,
        birth: identity.creation_time_100ns,
    };
    // SAFETY: borrowed standard handle is neither replaced nor closed here.
    let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::other(
            "original fixture stdin handle unavailable",
        ));
    }
    let timer = memcordon_platform::WindowsSynchronousIoDeadline::start(deadline)
        .map_err(io::Error::other)?;
    let result =
        controller_start::Receiver::default().receive(&mut OriginalInput(handle), &binding, || {
            if Instant::now() >= deadline {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "original START work cutoff exhausted",
                ))
            } else {
                Ok(())
            }
        });
    // The timer's exact-thread cancellation worker is joined before unrelated
    // application I/O. Preserve a native read failure as the primary source.
    match (result, timer.finish()) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(io::Error::other(error)),
        (Err(original), Err(deadline)) => Err(io::Error::new(
            original.kind(),
            Failure { original, deadline },
        )),
    }
}
