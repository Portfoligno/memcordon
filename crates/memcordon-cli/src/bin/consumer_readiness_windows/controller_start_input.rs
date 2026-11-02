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

pub(super) fn deadline_from_clock(input: &super::descriptor::ControlClock) -> io::Result<Instant> {
    input.validate().map_err(io::Error::other)?;
    let sampled = Instant::now();
    let mut now = 0_i64;
    let mut frequency = 0_i64;
    // SAFETY: initialized native scalar outputs for the original supplied clock.
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
    sampled
        .checked_add(Duration::from_nanos(
            u64::try_from(nanos).map_err(io::Error::other)?,
        ))
        .ok_or_else(|| io::Error::other("original START cutoff cannot be represented"))
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

pub(super) struct Session {
    binding: controller_start::Binding,
    receiver: controller_start::Receiver,
    handle: HANDLE,
    deadline: Instant,
}
impl Session {
    pub(super) fn original_binding(&self) -> &controller_start::Binding {
        &self.binding
    }
    pub(super) fn registry_capability(&self) -> Option<&controller_start::Capability> {
        self.receiver.registry_capability()
    }
    pub(super) fn original_deadline(&self) -> Instant {
        self.deadline
    }
    pub(super) fn new(descriptor: &Descriptor, digest: [u8; 32]) -> io::Result<Self> {
        let input = descriptor
            .control_clock
            .as_ref()
            .ok_or_else(|| io::Error::other("controller stdin START lacks original clock input"))?;
        let deadline = deadline_from_clock(input)?;
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
        Ok(Self {
            binding,
            receiver: if let Some(registry) = &descriptor.winsock_registry {
                controller_start::Receiver::with_registry(
                    registry.sha256,
                    matches!(
                        descriptor.case,
                        super::descriptor::Case::Joint | super::descriptor::Case::Churn
                    ),
                )
            } else if descriptor.case == super::descriptor::Case::Joint {
                controller_start::Receiver::joint()
            } else {
                controller_start::Receiver::default()
            },
            handle,
            deadline,
        })
    }
    pub(super) fn peer(
        clock: &super::descriptor::ControlClock,
        binding: controller_start::Binding,
        declaration: &super::descriptor::winsock_registry::Declaration,
    ) -> io::Result<Self> {
        declaration.validate().map_err(io::Error::other)?;
        let deadline = deadline_from_clock(clock)?;
        let actual = super::native::current_identity()?;
        if binding.pid != actual.process_id || binding.birth != actual.creation_time_100ns {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "registry peer original native identity differs",
            ));
        }
        // SAFETY: borrow only this admitted child's existing original stdin.
        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::other("original registry peer stdin unavailable"));
        }
        Ok(Self {
            binding,
            receiver: controller_start::Receiver::with_registry(declaration.sha256, false),
            handle,
            deadline,
        })
    }
    pub(super) fn receive(&mut self, phase: controller_start::Phase) -> io::Result<()> {
        let timer = memcordon_platform::WindowsSynchronousIoDeadline::start(self.deadline)
            .map_err(io::Error::other)?;
        let deadline = self.deadline;
        let check = || {
            if Instant::now() >= deadline {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "original START work cutoff exhausted",
                ))
            } else {
                Ok(())
            }
        };
        let result = match phase {
            controller_start::Phase::Start => {
                self.receiver
                    .receive(&mut OriginalInput(self.handle), &self.binding, check)
            }
            controller_start::Phase::ToolchainObserverRelease => self.receiver.receive_phase(
                &mut OriginalInput(self.handle),
                &self.binding,
                phase,
                check,
            ),
        };
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
}
