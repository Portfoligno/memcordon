//! Exact unbuffered START reads from the existing fixture stdin handle.
use super::descriptor::{Descriptor, controller_start};
use std::fs::File;
use std::io::{self, Read};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
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
    private_expected: bool,
    private_files: Vec<File>,
}

/// Issued only after the controller authenticated that it owns this exact peer.
pub(super) struct PeerHandoffPermit {
    recipient: controller_start::PeerRecipient,
    deadline: Instant,
    binding: controller_start::PeerAdmissionBinding,
}
impl PeerHandoffPermit {
    pub(super) fn validate(
        &self,
        peer: &std::process::Child,
        binding: &controller_start::Binding,
    ) -> io::Result<memcordon_core::WindowsProcessIdentityV1> {
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "peer handoff original cutoff exhausted",
            ));
        }
        if self.binding != controller_start::PeerAdmissionBinding::from_start(binding) {
            return Err(io::Error::other(
                "peer handoff permit belongs to a different original session",
            ));
        }
        let actual = super::native::child_identity(peer)?;
        if self.recipient.handle != peer.as_raw_handle() as usize as u64
            || self.recipient.pid != actual.process_id
            || self.recipient.birth != actual.creation_time_100ns
        {
            return Err(io::Error::other(
                "admitted peer process object differs before forwarding",
            ));
        }
        Ok(actual)
    }
}
impl Session {
    pub(super) fn private_directories(
        &self,
    ) -> io::Result<
        Option<
            memcordon_platform::test_support::windows_private_fixture::BorrowedPrivateDirectories<
                '_,
            >,
        >,
    > {
        if !self.private_expected {
            return Ok(None);
        }
        let transfer = self
            .receiver
            .directory_transfer()
            .ok_or_else(|| io::Error::other("private directory START was not admitted"))?;
        let input_count = transfer
            .references
            .iter()
            .take_while(|entry| entry.role == controller_start::DirectoryRole::InputAncestor)
            .count();
        if self.private_files.len() != transfer.references.len()
            || input_count == 0
            || input_count + 1 >= self.private_files.len()
            || !matches!(
                transfer.references[input_count].role,
                controller_start::DirectoryRole::LocalDirectory
                    | controller_start::DirectoryRole::LocalMarkerFile
            )
        {
            return Err(io::Error::other(
                "owned private directory set unavailable or already closed",
            ));
        }
        Ok(Some(
            memcordon_platform::test_support::windows_private_fixture::BorrowedPrivateDirectories {
                input: &self.private_files[..input_count],
                local: &self.private_files[input_count],
                output: &self.private_files[input_count + 1..],
            },
        ))
    }
    pub(super) fn close_private_directories(&mut self) {
        self.private_files.clear();
    }
    pub(super) fn take_private_directory_files(&mut self) -> Vec<File> {
        std::mem::take(&mut self.private_files)
    }
    fn adopt_private_directories(&mut self) -> io::Result<()> {
        if !self.private_expected {
            return Ok(());
        }
        if !self.private_files.is_empty() {
            return Err(io::Error::other("private references were already adopted"));
        }
        let transfer = self
            .receiver
            .directory_transfer()
            .ok_or_else(|| io::Error::other("complete authenticated private START absent"))?;
        let handles = transfer
            .references
            .iter()
            .map(|entry| usize::try_from(entry.handle).map_err(io::Error::other))
            .collect::<io::Result<Vec<_>>>()?;
        self.private_files = handles
            .into_iter()
            .map(|handle| {
                // SAFETY: only a complete, exact-bound authenticated START admits
                // distinct transferred local references; this private owner adopts
                // each once. Native type/rights/identity checks precede any use.
                unsafe { File::from_raw_handle(handle as *mut std::ffi::c_void) }
            })
            .collect();
        Ok(())
    }
    pub(super) fn peer_admission_binding(&self) -> controller_start::PeerAdmissionBinding {
        controller_start::PeerAdmissionBinding::from_start(&self.binding)
    }
    pub(super) fn pending_peer(
        &self,
        peer: &std::process::Child,
    ) -> io::Result<controller_start::PeerPendingAdmission> {
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original pending peer cutoff exhausted",
            ));
        }
        self.private_directories()?.ok_or_else(|| {
            io::Error::other("peer transfer requires admitted private references")
        })?;
        let identity = super::native::child_identity(peer)?;
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original pending peer identity returned after cutoff",
            ));
        }
        let pending = controller_start::PeerPendingAdmission {
            version: 1,
            binding: self.peer_admission_binding(),
            recipient: controller_start::PeerRecipient {
                handle: peer.as_raw_handle() as usize as u64,
                pid: identity.process_id,
                birth: identity.creation_time_100ns,
            },
        };
        pending.validate(&self.binding)?;
        Ok(pending)
    }
    pub(super) fn receive_peer_recipient(
        &mut self,
        pending: &controller_start::PeerPendingAdmission,
    ) -> io::Result<PeerHandoffPermit> {
        pending.validate(&self.binding)?;
        self.receive_bound(
            controller_start::Phase::PeerRecipientHeld,
            Some(&pending.recipient),
        )?;
        Ok(PeerHandoffPermit {
            recipient: pending.recipient,
            deadline: self.deadline,
            binding: self.peer_admission_binding(),
        })
    }
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
            receiver: if let Some(private) = &descriptor.provider_input_binding {
                let registry = descriptor
                    .winsock_registry
                    .as_ref()
                    .ok_or_else(|| io::Error::other("private input requires registry START"))?;
                if descriptor.matched_control.as_ref().is_some_and(|binding| {
                    binding.scope == super::descriptor::matched::Scope::ProviderListenerSelection
                }) {
                    controller_start::Receiver::provider_root(
                        registry.sha256,
                        private.directory_expectation().map_err(io::Error::other)?,
                    )?
                } else {
                    controller_start::Receiver::with_directories(
                        registry.sha256,
                        private.directory_expectation().map_err(io::Error::other)?,
                        true,
                    )?
                }
            } else if let Some(registry) = &descriptor.winsock_registry {
                controller_start::Receiver::with_registry(
                    registry.sha256,
                    matches!(
                        descriptor.case,
                        super::descriptor::Case::Joint | super::descriptor::Case::Churn
                    ) && !descriptor.matched_control.as_ref().is_some_and(|binding| {
                        binding.scope == super::descriptor::matched::Scope::JointListenerPrefix
                    }),
                )
            } else if descriptor.case == super::descriptor::Case::Joint {
                controller_start::Receiver::joint()
            } else {
                controller_start::Receiver::default()
            },
            handle,
            deadline,
            private_expected: descriptor.provider_input_experiment,
            private_files: Vec::new(),
        })
    }
    pub(super) fn peer(
        clock: &super::descriptor::ControlClock,
        binding: controller_start::Binding,
        descriptor: &Descriptor,
    ) -> io::Result<Self> {
        let declaration = descriptor
            .winsock_registry
            .as_ref()
            .ok_or_else(|| io::Error::other("peer registry declaration absent"))?;
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
            receiver: if let Some(private) = &descriptor.provider_input_binding {
                controller_start::Receiver::with_directories(
                    declaration.sha256,
                    private.directory_expectation().map_err(io::Error::other)?,
                    false,
                )?
            } else {
                controller_start::Receiver::with_registry(declaration.sha256, false)
            },
            handle,
            deadline,
            private_expected: descriptor.provider_input_experiment,
            private_files: Vec::new(),
        })
    }
    pub(super) fn receive(&mut self, phase: controller_start::Phase) -> io::Result<()> {
        self.receive_bound(phase, None)
    }
    fn receive_bound(
        &mut self,
        phase: controller_start::Phase,
        peer: Option<&controller_start::PeerRecipient>,
    ) -> io::Result<()> {
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
            controller_start::Phase::ToolchainObserverRelease
            | controller_start::Phase::ProviderPreludeRelease => self.receiver.receive_phase(
                &mut OriginalInput(self.handle),
                &self.binding,
                phase,
                check,
            ),
            controller_start::Phase::PeerRecipientHeld => match peer {
                Some(peer) => self.receiver.receive_peer_held(
                    &mut OriginalInput(self.handle),
                    &self.binding,
                    peer,
                    check,
                ),
                None => Err(io::Error::other(
                    "peer admission requires exact owned child echo",
                )),
            },
        };
        // The timer's exact-thread cancellation worker is joined before unrelated
        // application I/O. Preserve a native read failure as the primary source.
        let settled = timer.finish();
        // Once the complete START was admitted these are our references, even
        // if timer settlement fails. Adopt for RAII cleanup before propagating.
        let result = result.and_then(|()| {
            if phase == controller_start::Phase::Start {
                self.adopt_private_directories()
            } else {
                Ok(())
            }
        });
        match (result, settled) {
            (Ok(()), Ok(())) if Instant::now() >= self.deadline => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original START cutoff elapsed during deadline settlement",
            )),
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
