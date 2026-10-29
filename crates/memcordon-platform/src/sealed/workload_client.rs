//! Caller-owned workload streams over the authenticated native service socket.
use super::*;
use crate::workload_transport::{WorkloadConnectionBinding, WorkloadFrame, WorkloadFrameKind};
use memcordon_core::result_v3::{LinuxWorkloadTerminalV1, OutputDeliveryStateV3};
use memcordon_core::workload_bundle::{read_bundle_headers, stream_member};
use memcordon_core::workload_chunks::{CHUNK_DATA_BYTES, SnapshotRoleV1, WorkloadChunkV1};
use memcordon_core::workload_request::{
    RootRelativePath, RuntimeRequestV1, WorkloadAttemptAssociationV1, WorkloadStartV1,
};
use std::io::{Seek, SeekFrom};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Debug)]
pub struct WorkloadFrontendRequest {
    bundle: fs::File,
    pub output_directory: Option<PathBuf>,
    pub observation_path: Option<PathBuf>,
    observation_directory: Option<fs::File>,
    pub working_directory: Option<RootRelativePath>,
    /// Actual caller-selected target environment, never the provider's process environment.
    pub environment: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    association: Option<WorkloadAttemptAssociationV1>,
    expected_binding: Option<memcordon_core::result_v3::WorkloadRequestAssociationV1>,
    input_complete: bool,
    rejection: Option<memcordon_core::workload_request::WorkloadRejectionV1>,
}

impl WorkloadFrontendRequest {
    pub fn open(
        bundle: &Path,
        output_directory: Option<PathBuf>,
        observation_path: Option<PathBuf>,
        observation_directory: Option<PathBuf>,
        working_directory: Option<RootRelativePath>,
    ) -> Result<Self, String> {
        use std::os::unix::fs::OpenOptionsExt;
        let bundle = fs::File::options()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(bundle)
            .map_err(|error| error.to_string())?;
        if !bundle
            .metadata()
            .map_err(|error| error.to_string())?
            .is_file()
        {
            return Err("workload bundle must be a regular caller-readable file".into());
        }
        Ok(Self {
            bundle,
            output_directory,
            observation_path,
            observation_directory: observation_directory
                .as_deref()
                .map(super::workload_observer::open)
                .transpose()?,
            working_directory,
            environment: std::env::vars_os().collect(),
            association: None,
            expected_binding: None,
            input_complete: false,
            rejection: None,
        })
    }
}

fn build_start(
    policy: &memcordon_core::Policy,
    command: &memcordon_core::CommandSpec,
    request: &memcordon_core::workload_request::WorkloadRequestV1,
    io: &WorkloadFrontendRequest,
    absolute_deadline: Option<u64>,
    restart_attempt: u64,
    attempt_deadline_millis: Option<u64>,
) -> Result<WorkloadStartV1, String> {
    Ok(WorkloadStartV1 {
        format: "memcordon.workload-start".into(),
        revision: 1,
        request: request.clone(),
        native_launch: encode_launch_with_absolute_deadline(
            policy,
            command,
            absolute_deadline,
            restart_attempt,
            io.environment.clone(),
        )?,
        working_directory: io.working_directory.clone(),
        attempt_deadline_millis,
    })
}

#[cfg(feature = "test-support")]
pub(crate) fn encode_start_for_test(
    policy: &memcordon_core::Policy,
    command: &memcordon_core::CommandSpec,
    request: &memcordon_core::workload_request::WorkloadRequestV1,
    io: &WorkloadFrontendRequest,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&build_start(policy, command, request, io, None, 0, None)?)
        .map_err(|error| error.to_string())
}

fn binding(association: &WorkloadAttemptAssociationV1) -> WorkloadConnectionBinding {
    WorkloadConnectionBinding {
        challenge: association.challenge,
        attempt: association.attempt,
    }
}

fn connect_until(cutoff: Instant) -> Result<UnixStream, String> {
    if Instant::now() >= cutoff {
        return Err("original native connection cutoff already elapsed".into());
    }
    // SAFETY: socket creates a new Unix stream descriptor with native flags.
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: successful socket returned one new owned descriptor.
    let owner = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: zeroed sockaddr_un has an empty native path and initialized family.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let path = ENDPOINT.as_bytes();
    if path.len() >= address.sun_path.len() {
        return Err("native provider endpoint exceeds Unix address bound".into());
    }
    for (destination, source) in address.sun_path.iter_mut().zip(path) {
        *destination = *source as libc::c_char;
    }
    let length = std::mem::offset_of!(libc::sockaddr_un, sun_path) + path.len() + 1;
    // SAFETY: the native address and its computed initialized path length are valid.
    let connected = unsafe {
        libc::connect(
            owner.as_raw_fd(),
            (&raw const address).cast(),
            length as libc::socklen_t,
        )
    };
    if connected < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EAGAIN) {
            return Err("native connection capacity unavailable".into());
        }
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(error.to_string());
        }
        loop {
            if Instant::now() >= cutoff {
                return Err("original native connection cutoff elapsed".into());
            }
            let mut poll = libc::pollfd {
                fd: owner.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            let timeout = i32::try_from(
                cutoff
                    .saturating_duration_since(Instant::now())
                    .as_millis()
                    .min(20),
            )
            .map_err(|_| "connection poll range exceeded")?;
            // SAFETY: the owned descriptor and writable single pollfd stay live.
            let ready = unsafe { libc::poll(&raw mut poll, 1, timeout) };
            if ready < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error.to_string());
            }
            if ready == 0 {
                continue;
            }
            let mut status = 0_i32;
            let mut size = std::mem::size_of_val(&status) as libc::socklen_t;
            // SAFETY: getsockopt writes the native SO_ERROR integer and its size.
            if unsafe {
                libc::getsockopt(
                    owner.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    (&raw mut status).cast(),
                    &raw mut size,
                )
            } < 0
            {
                return Err(std::io::Error::last_os_error().to_string());
            }
            if status != 0 {
                return Err(std::io::Error::from_raw_os_error(status).to_string());
            }
            break;
        }
    }
    Ok(UnixStream::from(owner))
}

struct TimedStream {
    stream: UnixStream,
    cutoff: Instant,
}
impl TimedStream {
    fn remaining(&self) -> std::io::Result<Duration> {
        let remaining = self.cutoff.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "original recovery cutoff elapsed",
            ))
        } else {
            Ok(remaining)
        }
    }
}
impl Read for TimedStream {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(bytes)
    }
}
impl Write for TimedStream {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

fn persist_observation(
    path: &Path,
    association: &WorkloadAttemptAssociationV1,
    restart_attempt: u64,
) -> Result<(), String> {
    let path = if restart_attempt == 0 {
        path.to_path_buf()
    } else {
        path.with_extension(format!("attempt-{restart_attempt}"))
    };
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent).map_err(|error| error.to_string())?;
    serde_json::to_writer(file.as_file_mut(), association).map_err(|error| error.to_string())?;
    file.write_all(b"\n").map_err(|error| error.to_string())?;
    file.as_file()
        .sync_all()
        .map_err(|error| error.to_string())?;
    file.persist_noclobber(&path)
        .map_err(|error| error.to_string())?;
    fs::File::open(parent)
        .and_then(|parent| parent.sync_all())
        .map_err(|error| error.to_string())
}

struct Pump<'a> {
    stream: &'a UnixStream,
    relay: &'a mut super::private_relay::ByteRelay,
    signal: &'a crate::signal::SignalSource,
    assigned: Option<WorkloadConnectionBinding>,
    cutoff: Option<Instant>,
    return_cutoff: Option<Instant>,
    cleanup_cutoff: Option<Instant>,
    cleanup_allowance: Duration,
    work_cutoff: Option<Instant>,
    cancelled: bool,
    interruption: Option<i32>,
    relay_error: Option<String>,
}

impl Pump<'_> {
    fn tick(&mut self) -> std::io::Result<()> {
        if self.cutoff.is_some_and(|cutoff| Instant::now() >= cutoff) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "original workload return cutoff elapsed",
            ));
        }
        if self.relay_error.is_none()
            && let Err(error) = self.relay.step()
        {
            self.relay_error = Some(error.to_string());
            self.relay.close_input();
        }
        if self.interruption.is_none() {
            self.interruption = self.signal.take();
        }
        if !self.cancelled
            && (self.interruption.is_some()
                || self.relay_error.is_some()
                || self
                    .work_cutoff
                    .is_some_and(|cutoff| Instant::now() >= cutoff))
            && let Some(binding) = self.assigned
        {
            self.cancel(binding)?;
        }
        Ok(())
    }
    fn cancel(&mut self, binding: WorkloadConnectionBinding) -> std::io::Result<()> {
        if self.cancelled {
            return Ok(());
        }
        let deadline = Instant::now()
            .checked_add(self.cleanup_allowance)
            .ok_or_else(|| std::io::Error::other("original cleanup cutoff overflow"))?;
        let deadline = self
            .return_cutoff
            .map_or(deadline, |original| original.min(deadline));
        self.cleanup_cutoff = Some(deadline);
        self.cutoff = Some(deadline);
        self.send(WorkloadFrame {
            kind: WorkloadFrameKind::Cancel,
            binding,
            payload: Vec::new(),
        })?;
        self.cancelled = true;
        self.relay.close_input();
        Ok(())
    }
    fn send(&self, frame: WorkloadFrame) -> std::io::Result<()> {
        let mut bytes = Vec::new();
        frame.write(&mut bytes)?;
        super::native_transport::send_nonblocking(self.stream, &bytes, &[], self.cutoff)
            .map_err(std::io::Error::other)
    }
    fn object(
        &mut self,
        kind: WorkloadFrameKind,
        role: SnapshotRoleV1,
        index: u32,
        bytes: &[u8],
    ) -> Result<(), String> {
        let total = bytes.len() as u64;
        let mut offset = 0_u64;
        for chunk in bytes.chunks(CHUNK_DATA_BYTES) {
            self.tick().map_err(|error| error.to_string())?;
            if self.cancelled {
                return Err("workload cancelled during input transfer".into());
            }
            let payload = WorkloadChunkV1 {
                role,
                member_index: index,
                total,
                offset,
                bytes: chunk,
            }
            .encode()?;
            self.send(WorkloadFrame {
                kind,
                binding: self.assigned.ok_or("no original association")?,
                payload,
            })
            .map_err(|error| error.to_string())?;
            offset += chunk.len() as u64;
        }
        Ok(())
    }
}

impl Read for Pump<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        loop {
            self.tick()?;
            match (&*self.stream).read(buffer) {
                Ok(count) => return Ok(count),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    super::native_transport::poll(self.stream, self.relay, self.cutoff, true)
                        .map_err(std::io::Error::other)?;
                }
                Err(error) => return Err(error),
            }
        }
    }
}

struct MemberWriter<'a, 'b> {
    pump: &'a mut Pump<'b>,
    role: SnapshotRoleV1,
    index: u32,
    total: u64,
    offset: u64,
}
impl Write for MemberWriter<'_, '_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.pump.tick()?;
        if self.pump.cancelled {
            return Err(std::io::Error::other("input transfer cancelled"));
        }
        let count = bytes.len().min(CHUNK_DATA_BYTES);
        if count == 0 {
            return Ok(0);
        }
        let payload = WorkloadChunkV1 {
            role: self.role,
            member_index: self.index,
            total: self.total,
            offset: self.offset,
            bytes: &bytes[..count],
        }
        .encode()
        .map_err(std::io::Error::other)?;
        self.pump.send(WorkloadFrame {
            kind: WorkloadFrameKind::MemberChunk,
            binding: self
                .pump
                .assigned
                .ok_or_else(|| std::io::Error::other("original association absent"))?,
            payload,
        })?;
        self.offset += count as u64;
        Ok(count)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(crate) struct FrontendExecution {
    pub terminal: LinuxWorkloadTerminalV1,
    pub frontend: memcordon_core::WorkloadFrontendEvidenceV1,
    pub duration: Duration,
}

pub(crate) fn run_workload_attempt(
    io: &mut WorkloadFrontendRequest,
    policy: &memcordon_core::Policy,
    command: &memcordon_core::CommandSpec,
    context: crate::supervisor::AttemptContext,
    signal: &crate::signal::SignalSource,
    started: Instant,
    monotonic_origin: u64,
) -> Result<FrontendExecution, String> {
    io.association = None;
    io.expected_binding = None;
    io.input_complete = false;
    io.rejection = None;
    let request = policy
        .workload_request()
        .ok_or("current workload request absent")?;
    request.validate().map_err(|error| error.to_string())?;
    let RuntimeRequestV1::LinuxPrivate { inputs, layout, .. } = &request.runtime else {
        return Err("Linux provider cannot implement requested profile".into());
    };
    if command.program().to_str() != Some(inputs.entrypoint.as_str()) {
        return Err("request entrypoint and native invocation differ".into());
    }
    let mut outputs = Some(crate::workload_outputs::WorkloadOutputReceiver::new(
        layout,
        io.output_directory.as_deref(),
    )?);
    io.bundle
        .seek(SeekFrom::Start(0))
        .map_err(|error| error.to_string())?;
    let (runtime, input) = read_bundle_headers(&mut io.bundle)?;
    if runtime.digest()? != inputs.runtime_digest || input.digest()? != inputs.input_digest {
        return Err("request snapshot digests and caller bundle differ".into());
    }
    verify_endpoint()?;
    let provider = super::super::linux_runtime::installed_current_binding()?;
    let initial_connect_cutoff = started
        .checked_add(Duration::from_secs(30))
        .ok_or("connection cutoff overflow")?;
    let initial_connect_cutoff = if policy
        .deadline
        .is_some_and(|deadline| deadline.scope() == memcordon_core::DeadlineScope::Supervision)
    {
        started
            .checked_add(
                context
                    .supervision_deadline_remaining
                    .or(policy.deadline.map(|deadline| deadline.duration()))
                    .ok_or("deadline selection absent")?,
            )
            .ok_or("connection deadline overflow")?
            .min(initial_connect_cutoff)
    } else {
        initial_connect_cutoff
    };
    let stream = connect_until(initial_connect_cutoff)?;
    verify_peer(&stream)?;
    stream
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let deadline_budget = effective_deadline_duration(policy, context, started.elapsed());
    let attempt_scoped = policy
        .deadline
        .is_some_and(|deadline| deadline.scope() == memcordon_core::DeadlineScope::Attempt);
    let setup_cutoff = started
        .checked_add(Duration::from_secs(30))
        .ok_or("setup cutoff overflow")?;
    let work_duration = policy.deadline.map(|deadline| {
        if attempt_scoped {
            deadline.duration().saturating_add(Duration::from_secs(30))
        } else {
            context
                .supervision_deadline_remaining
                .unwrap_or(deadline.duration())
        }
    });
    let work_cutoff = work_duration
        .map(|duration| {
            started
                .checked_add(duration)
                .ok_or("workload cutoff overflow")
        })
        .transpose()?;
    let setup_cutoff = if attempt_scoped {
        setup_cutoff
    } else {
        work_cutoff.map_or(setup_cutoff, |work| setup_cutoff.min(work))
    };
    let cleanup_allowance = policy.limit_grace.max(Duration::from_secs(5));
    let return_cutoff = work_cutoff
        .map(|work| {
            work.checked_add(cleanup_allowance)
                .ok_or("cleanup cutoff overflow")
        })
        .transpose()?;
    let absolute_deadline = if attempt_scoped {
        None
    } else {
        work_duration
            .map(|duration| {
                monotonic_origin
                    .checked_add(
                        u64::try_from(duration.as_millis())
                            .map_err(|_| "native deadline range exceeded")?,
                    )
                    .ok_or("native deadline clock overflow")
            })
            .transpose()?
    };
    let attempt_deadline_millis = if attempt_scoped {
        deadline_budget
            .map(|duration| {
                u64::try_from(duration.as_millis()).map_err(|_| "attempt deadline overflow")
            })
            .transpose()?
    } else {
        None
    };
    let start = build_start(
        policy,
        command,
        request,
        io,
        absolute_deadline,
        context.restart_attempt,
        attempt_deadline_millis,
    )?;
    let payload = serde_json::to_vec(&start).map_err(|error| error.to_string())?;
    WorkloadStartV1::parse(&payload).map_err(|error| error.to_string())?;
    io.expected_binding = Some(memcordon_core::result_v3::WorkloadRequestAssociationV1 {
        request_sha256: request.digest().map_err(|error| error.to_string())?,
        invocation_sha256: memcordon_core::workload_request::invocation_digest(
            &start.native_launch,
            start.working_directory.as_ref(),
        )
        .map_err(|error| error.to_string())?,
        resource_policy_sha256: memcordon_core::workload_request::resource_policy_digest(
            &start.native_launch,
            start.attempt_deadline_millis,
        )
        .map_err(|error| error.to_string())?,
        runtime_sha256: Some(inputs.runtime_digest.clone()),
        input_sha256: Some(inputs.input_digest.clone()),
    });
    let frame = encoded_frame_for_version(5, 30, [0; 16], [0; 16], &payload)?;
    let cwd = fs::File::open(".").map_err(|error| error.to_string())?;
    let frontend_pidfd = pidfd_self()?;
    let (mut relay, channels) =
        super::private_relay::ByteRelay::new().map_err(|error| error.to_string())?;
    let descriptors = [
        cwd.as_raw_fd(),
        channels[0].as_raw_fd(),
        channels[1].as_raw_fd(),
        channels[2].as_raw_fd(),
        frontend_pidfd.as_raw_fd(),
    ];
    super::native_transport::send_nonblocking(&stream, &frame, &descriptors, Some(setup_cutoff))?;
    drop(channels);
    drop(cwd);
    let mut pump = Pump {
        stream: &stream,
        relay: &mut relay,
        signal,
        assigned: None,
        cutoff: Some(setup_cutoff),
        return_cutoff,
        cleanup_cutoff: None,
        cleanup_allowance,
        work_cutoff: None,
        cancelled: false,
        interruption: None,
        relay_error: None,
    };
    let first = WorkloadFrame::read_initial(&mut pump).map_err(|error| error.to_string())?;
    if first.kind == WorkloadFrameKind::Rejected {
        memcordon_core::canonical_json::reject_duplicate_json_keys(&first.payload)?;
        let rejection: memcordon_core::workload_request::WorkloadRejectionV1 =
            serde_json::from_slice(&first.payload).map_err(|error| error.to_string())?;
        if rejection.format != "memcordon.workload-rejection"
            || rejection.revision != 1
            || first.binding
                != (WorkloadConnectionBinding {
                    attempt: [0; 16],
                    challenge: [0; 16],
                })
        {
            return Err("invalid preallocation rejection binding".into());
        }
        let detail = rejection.detail.as_str().to_owned();
        io.rejection = Some(rejection);
        if let Some(directory) = &io.observation_directory {
            super::workload_observer::publish_observation(
                directory,
                "rejected-start.json",
                &payload,
            )
            .map_err(|secondary| {
                format!("{detail}; original rejected Start observation: {secondary}")
            })?;
        }
        return Err(detail);
    }
    if first.kind != WorkloadFrameKind::Progress {
        return Err("provider did not assign an original workload association".into());
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(&first.payload)?;
    let association: WorkloadAttemptAssociationV1 =
        serde_json::from_slice(&first.payload).map_err(|error| error.to_string())?;
    association.validate().map_err(|error| error.to_string())?;
    if binding(&association) != first.binding
        || association.provider != provider
        || association.request_sha256 != request.digest().map_err(|error| error.to_string())?
    {
        return Err("original provider/attempt/request association differs".into());
    }
    io.association = Some(association.clone());
    let control_owner = super::workload_control::ControlQueryOwner::capture(&association.control)?;
    if let Some(path) = &io.observation_path {
        persist_observation(path, &association, context.restart_attempt)?;
    }
    pump.assigned = Some(first.binding);
    let input_result = (|| -> Result<(), String> {
        if let Some(directory) = &io.observation_directory {
            pump.tick().map_err(|error| error.to_string())?;
            let attempt = association
                .attempt
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            super::workload_observer::publish_observation(
                directory,
                &format!("{attempt}.start.json"),
                &payload,
            )?;
            pump.tick().map_err(|error| error.to_string())?;
        }
        for (role, manifest) in [
            (SnapshotRoleV1::Runtime, &runtime),
            (SnapshotRoleV1::Input, &input),
        ] {
            pump.object(
                WorkloadFrameKind::ManifestChunk,
                role,
                0,
                &manifest.canonical_bytes()?,
            )?;
        }
        for (role, manifest) in [
            (SnapshotRoleV1::Runtime, &runtime),
            (SnapshotRoleV1::Input, &input),
        ] {
            for (index, member) in manifest.regular_members().into_iter().enumerate() {
                let memcordon_core::workload_bundle::ImageEntryV1::Regular { size, .. } = member
                else {
                    unreachable!()
                };
                let mut writer = MemberWriter {
                    pump: &mut pump,
                    role,
                    index: u32::try_from(index).map_err(|_| "member index overflow")?,
                    total: *size,
                    offset: 0,
                };
                stream_member(&mut io.bundle, &mut writer, member)?;
            }
        }
        let mut extra = [0; 1];
        if io
            .bundle
            .read(&mut extra)
            .map_err(|error| error.to_string())?
            != 0
        {
            return Err("caller bundle has trailing bytes".into());
        }
        Ok(())
    })();
    let mut input_error = input_result.err();
    if input_error.is_some() {
        if let Err(error) = pump.cancel(first.binding) {
            input_error = Some(format!(
                "{}; cancellation delivery failed: {error}",
                input_error.as_deref().expect("input error present")
            ));
        }
    } else {
        io.input_complete = true;
        if let Err(error) = pump.send(WorkloadFrame {
            kind: WorkloadFrameKind::InputComplete,
            binding: first.binding,
            payload: Vec::new(),
        }) {
            input_error = Some(format!("input completion delivery failed: {error}"));
        }
        pump.cutoff = Some(setup_cutoff);
    }
    let mut output_error = None;
    let mut prepared_native: Option<memcordon_core::result_v3::LinuxNativeExecutionV3> = None;
    let terminal = loop {
        let frame =
            WorkloadFrame::read(&mut pump, first.binding).map_err(|error| error.to_string())?;
        match frame.kind {
            WorkloadFrameKind::Progress => {}
            WorkloadFrameKind::Rejected => {
                memcordon_core::canonical_json::reject_duplicate_json_keys(&frame.payload)?;
                let rejection: memcordon_core::workload_request::WorkloadRejectionV1 =
                    serde_json::from_slice(&frame.payload).map_err(|error| error.to_string())?;
                if rejection.format != "memcordon.workload-rejection"
                    || rejection.revision != 1
                    || prepared_native.is_some()
                {
                    return Err("invalid native rejection header or post-preparation phase".into());
                }
                let detail = rejection.detail.as_str().to_owned();
                io.rejection = Some(rejection);
                return Err(match input_error {
                    Some(secondary) => {
                        format!("{detail}; caller input/transport observation: {secondary}")
                    }
                    None => detail,
                });
            }
            WorkloadFrameKind::Prepared => {
                if prepared_native.is_some() || !io.input_complete {
                    return Err("duplicate or premature native prepared observation".into());
                }
                let prepared =
                    memcordon_core::result_v3::LinuxWorkloadPreparedV1::parse(&frame.payload)?;
                if prepared.association != association
                    || Some(&prepared.request) != io.expected_binding.as_ref()
                {
                    return Err(
                        "native prepared observation changes original request/provider/attempt"
                            .into(),
                    );
                }
                let ack = memcordon_core::result_v3::WorkloadPreparedAckV1 {
                    format: "memcordon.workload-prepared-ack".into(),
                    revision: 1,
                    association: association.clone(),
                    prepared_sha256: memcordon_core::hash_bytes(&frame.payload),
                };
                let ack_bytes = serde_json::to_vec(&ack).map_err(|error| error.to_string())?;
                let observed = (|| -> Result<(), String> {
                    if let Some(directory) = &io.observation_directory {
                        let attempt = association
                            .attempt
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<String>();
                        super::workload_observer::publish_observation(
                            directory,
                            &format!("{attempt}.prepared.json"),
                            &frame.payload,
                        )?;
                        loop {
                            if Instant::now() >= setup_cutoff {
                                return Err(
                                    "original workload prepared observer cutoff elapsed".into()
                                );
                            }
                            pump.tick().map_err(|error| error.to_string())?;
                            if pump.cancelled {
                                return Err(
                                    "original workload cancelled while held before release".into(),
                                );
                            }
                            if super::workload_observer::acknowledgment(
                                directory,
                                &format!("{attempt}.prepared-ack.json"),
                                &ack_bytes,
                            )? {
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(10));
                        }
                    }
                    pump.tick().map_err(|error| error.to_string())?;
                    if pump.cancelled {
                        return Err(
                            "original workload cancelled before prepared acknowledgement".into(),
                        );
                    }
                    pump.send(WorkloadFrame {
                        kind: WorkloadFrameKind::PreparedAck,
                        binding: first.binding,
                        payload: ack_bytes,
                    })
                    .map_err(|error| error.to_string())
                })();
                prepared_native = Some(prepared.native);
                if let Err(error) = observed {
                    input_error.get_or_insert(error);
                    pump.cancel(first.binding)
                        .map_err(|error| error.to_string())?;
                } else {
                    pump.cutoff = return_cutoff;
                    pump.work_cutoff = work_cutoff;
                }
            }
            WorkloadFrameKind::OutputInventory => {
                if prepared_native.is_none() {
                    return Err("native output arrived without original prepared barrier".into());
                }
                if let Some(receiver) = &mut outputs
                    && let Err(error) = receiver.inventory(&frame.payload)
                {
                    output_error.get_or_insert(error);
                    outputs = None;
                }
            }
            WorkloadFrameKind::OutputChunk => {
                if prepared_native.is_none() {
                    return Err("native output arrived without original prepared barrier".into());
                }
                if let Some(receiver) = &mut outputs
                    && let Err(error) = receiver.chunk(&frame.payload)
                {
                    output_error.get_or_insert(error);
                    outputs = None;
                }
            }
            WorkloadFrameKind::Terminal => {
                let terminal = LinuxWorkloadTerminalV1::parse(&frame.payload)?;
                if terminal.association != association {
                    return Err("terminal belongs to another original native attempt".into());
                }
                if terminal.release != memcordon_core::result_v3::ReleaseKnowledgeV3::NotReleased
                    && prepared_native.is_none()
                {
                    return Err("released native workload omitted original prepared barrier".into());
                }
                if let (Some(prepared), Some(native)) = (&prepared_native, &terminal.native)
                    && (prepared.entrypoint_sha256 != native.entrypoint_sha256
                        || prepared.target != native.target
                        || prepared.namespace_init != native.namespace_init
                        || prepared.guardian != native.guardian
                        || prepared.root_inode != native.root_inode
                        || prepared.cgroup_inode != native.cgroup_inode
                        || prepared.target_uid != native.target_uid
                        || prepared.target_gid != native.target_gid
                        || prepared.caller_uid != native.caller_uid
                        || prepared.caller_namespaces != native.caller_namespaces)
                {
                    return Err(
                        "native terminal changed the exact held prepared attempt identities".into(),
                    );
                }
                if terminal.request.invocation_sha256
                    != memcordon_core::workload_request::invocation_digest(
                        &start.native_launch,
                        start.working_directory.as_ref(),
                    )
                    .map_err(|error| error.to_string())?
                    || terminal.request.resource_policy_sha256
                        != memcordon_core::workload_request::resource_policy_digest(
                            &start.native_launch,
                            start.attempt_deadline_millis,
                        )
                        .map_err(|error| error.to_string())?
                    || terminal.request.runtime_sha256.as_ref() != Some(&inputs.runtime_digest)
                    || terminal.request.input_sha256.as_ref() != Some(&inputs.input_digest)
                {
                    return Err(
                        "terminal invocation/resource/input bytes differ from original transfer"
                            .into(),
                    );
                }
                break terminal;
            }
            _ => return Err("unexpected provider workload frame".into()),
        }
    };
    if terminal.release != memcordon_core::result_v3::ReleaseKnowledgeV3::NotReleased
        && let Some(receiver) = outputs
        && let Err(error) = receiver.finish()
    {
        output_error.get_or_insert(error);
    }
    pump.relay.close_input();
    let drain_cutoff = pump.cleanup_cutoff.or(return_cutoff).unwrap_or(
        Instant::now()
            .checked_add(cleanup_allowance)
            .ok_or("relay cutoff overflow")?,
    );
    let mut control_error = stream
        .shutdown(std::net::Shutdown::Both)
        .err()
        .map(|error| error.to_string());
    if let Err(error) = control_owner.wait(drain_cutoff, || {
        pump.relay.step().map_err(|error| error.to_string())
    }) {
        control_error.get_or_insert(error);
    }
    let control_handles_retired = control_error.is_none();
    while pump.relay_error.is_none()
        && !pump.relay.outputs_drained()
        && Instant::now() < drain_cutoff
    {
        if let Err(error) = pump.relay.step() {
            pump.relay_error.get_or_insert(error.to_string());
        }
        if let Err(error) =
            super::native_transport::poll(&stream, pump.relay, Some(drain_cutoff), false)
        {
            pump.relay_error.get_or_insert(error);
        }
    }
    let relay_drained = pump.relay_error.is_none() && pump.relay.outputs_drained();
    if let Err(error) = pump.relay.finish() {
        pump.relay_error.get_or_insert(error.to_string());
    }
    let mut failures = memcordon_core::BoundedVec::default();
    for error in output_error
        .iter()
        .chain(pump.relay_error.iter())
        .chain(input_error.iter().filter(|_| pump.interruption.is_none()))
        .chain(control_error.iter())
    {
        failures
            .try_push(memcordon_core::BoundedText::new(error).map_err(str::to_owned)?)
            .map_err(|_| "frontend failure inventory full")?;
    }
    super::super::linux_runtime::verify(&provider)?;
    let output_delivery = if output_error.is_some() {
        OutputDeliveryStateV3::Incomplete
    } else if terminal.release == memcordon_core::result_v3::ReleaseKnowledgeV3::NotReleased {
        OutputDeliveryStateV3::Unknown
    } else {
        OutputDeliveryStateV3::Complete
    };
    Ok(FrontendExecution {
        terminal,
        frontend: memcordon_core::WorkloadFrontendEvidenceV1 {
            control_handles_retired,
            relay_drained,
            output_delivery,
            interruption: pump.interruption,
            failures,
        },
        duration: started.elapsed(),
    })
}

pub(crate) fn run_workload_backend(
    io: &mut WorkloadFrontendRequest,
    policy: &memcordon_core::Policy,
    command: &memcordon_core::CommandSpec,
    context: crate::supervisor::AttemptContext,
    signal: &crate::signal::SignalSource,
) -> Result<crate::backend::Execution, memcordon_core::Error> {
    use memcordon_core::result_v3::{
        CleanupResourceV3, NativeWorkloadOutcomeV1, ReleaseKnowledgeV3,
    };
    use memcordon_core::{
        BoundaryClass, BoundaryRequirement, ChildTermination, CleanupSummary, Error, ErrorCategory,
        LaunchEvidence, RestartSafetyProof, RunOutcome,
    };
    let started = Instant::now();
    let failure = |detail: String| {
        let mut error = Error::new(
            ErrorCategory::Monitor,
            "MCSEALED-WORKLOAD-TRANSACTION",
            detail,
        );
        error.workload_may_be_alive = true;
        error
    };
    let monotonic_origin = monotonic_millis().map_err(failure)?;
    let live = probe().map_err(failure)?;
    let receipt = run_workload_attempt(
        io,
        policy,
        command,
        context,
        signal,
        started,
        monotonic_origin,
    )
    .map_err(|detail| {
        let mut error = failure(detail);
        error.workload_may_be_alive = io.input_complete;
        error.workload_attempt = io.association.clone();
        error.workload_binding = io.expected_binding.clone();
        error.workload_input_complete = io.input_complete;
        error.workload_rejection = io.rejection.clone();
        if let Some(rejection) = &io.rejection {
            use memcordon_core::workload_request::WorkloadRejectionCodeV1::*;
            error.code = match rejection.code {
                MalformedRequest => "malformed-request",
                UnsupportedRequestVersion => "unsupported-request-version",
                UnsupportedRequirement => "unsupported-requirement",
                NativeUnavailable => "native-unavailable",
                CallerIdentityMismatch => "caller-identity-mismatch",
                InputCapacityUnavailable => "input-capacity-unavailable",
            };
        }
        error
    })?;
    let terminal = &receipt.terminal;
    let native = terminal.native.as_ref();
    let released = terminal.release == ReleaseKnowledgeV3::Released;
    let authorization_offset = if released {
        let released_at = native
            .and_then(|native| native.release_monotonic_millis)
            .ok_or_else(|| {
                failure("released target lacks actual native release timestamp".into())
            })?;
        Some(Duration::from_millis(
            released_at.checked_sub(monotonic_origin).ok_or_else(|| {
                failure("native release predates original frontend attempt".into())
            })?,
        ))
    } else {
        None
    };
    let settled = |resource| {
        terminal
            .cleanup
            .obligations
            .as_slice()
            .iter()
            .find(|obligation| obligation.resource == resource)
            .is_some_and(|obligation| obligation.settled)
    };
    let complete =
        terminal.cleanup.state == memcordon_core::execution_facts::CleanupStateV1::Complete;
    let child = native
        .and_then(|native| native.native_wait_status)
        .and_then(|status| {
            if libc::WIFEXITED(status) {
                Some(ChildTermination::ExitCode {
                    code: libc::WEXITSTATUS(status),
                })
            } else if libc::WIFSIGNALED(status) {
                Some(ChildTermination::UnixSignal {
                    signal: libc::WTERMSIG(status),
                })
            } else {
                None
            }
        });
    let errors = receipt
        .frontend
        .failures
        .as_slice()
        .iter()
        .map(|error| memcordon_core::CleanupErrorRecord {
            operation: "frontend workload delivery".into(),
            message: error.as_str().into(),
        })
        .collect();
    let cleanup = CleanupSummary {
        direct_child_reaped: child.is_some(),
        workload_empty: if settled(CleanupResourceV3::Aggregate) {
            Some(true)
        } else {
            None
        },
        errors,
        ..Default::default()
    };
    let outcome = if !receipt.frontend.failures.as_slice().is_empty()
        || !receipt.frontend.relay_drained
        || !receipt.frontend.control_handles_retired
    {
        RunOutcome::MonitorFailed {
            error: receipt
                .frontend
                .failures
                .as_slice()
                .first()
                .map_or("frontend relay did not drain".into(), |error| {
                    error.as_str().into()
                }),
            child_after_termination: child.clone(),
            cleanup,
        }
    } else {
        match terminal.outcome {
            NativeWorkloadOutcomeV1::Exited { .. } | NativeWorkloadOutcomeV1::Signaled { .. } => {
                RunOutcome::Exited {
                    child: child.clone().ok_or_else(|| {
                        failure("native completion has no direct target wait".into())
                    })?,
                    peak: None,
                    cleanup,
                }
            }
            NativeWorkloadOutcomeV1::MemoryLimit => RunOutcome::LimitExceeded {
                limit: policy
                    .memory
                    .ok_or_else(|| failure("provider reported absent memory limit".into()))?,
                observed: None,
                peak: None,
                evidence: memcordon_core::LimitEvidence {
                    backend: "linux-private-workload-v1".into(),
                    metric: "cgroup-memory".into(),
                    detail: "native provider observed the cgroup memory limit".into(),
                },
                child_after_termination: child.clone(),
                cleanup,
            },
            NativeWorkloadOutcomeV1::Deadline => {
                let deadline = policy.deadline.ok_or_else(|| {
                    failure("provider reported an absent workload deadline".into())
                })?;
                let duration_ms = u64::try_from(deadline.duration().as_millis())
                    .map_err(|_| failure("deadline duration exceeds range".into()))?;
                let elapsed = u64::try_from(started.elapsed().as_millis())
                    .map_err(|_| failure("deadline observation exceeds range".into()))?;
                let (expires, observed) = match deadline.scope() {
                    memcordon_core::DeadlineScope::Attempt => (
                        u64::try_from(
                            authorization_offset
                                .ok_or_else(|| {
                                    failure("attempt deadline lacks release timestamp".into())
                                })?
                                .as_millis(),
                        )
                        .map_err(|_| failure("release offset exceeds range".into()))?
                        .checked_add(duration_ms)
                        .ok_or_else(|| failure("deadline expiry overflow".into()))?,
                        elapsed,
                    ),
                    memcordon_core::DeadlineScope::Supervision => {
                        let origin = u64::try_from(context.supervision_offset.as_millis())
                            .map_err(|_| failure("supervision offset exceeds range".into()))?;
                        let remaining = u64::try_from(
                            context
                                .supervision_deadline_remaining
                                .unwrap_or(deadline.duration())
                                .as_millis(),
                        )
                        .map_err(|_| failure("remaining deadline exceeds range".into()))?;
                        (
                            origin
                                .checked_add(remaining)
                                .ok_or_else(|| failure("supervision expiry overflow".into()))?,
                            origin.checked_add(elapsed).ok_or_else(|| {
                                failure("supervision observation overflow".into())
                            })?,
                        )
                    }
                };
                let evidence = memcordon_core::DeadlineEvidence::new(
                    duration_ms,
                    deadline.scope(),
                    "original-provider-monotonic".into(),
                    expires,
                    observed,
                    0,
                    0,
                    None,
                    None,
                )
                .map_err(|error| failure(error.to_string()))?;
                RunOutcome::DeadlineExceeded {
                    deadline: evidence,
                    child_after_termination: child.clone(),
                    peak: None,
                    cleanup,
                }
            }
            NativeWorkloadOutcomeV1::ControlledCancellation
                if receipt.frontend.interruption.is_some() =>
            {
                RunOutcome::Interrupted {
                    signal: memcordon_core::Interruption {
                        signal: receipt.frontend.interruption.expect("checked interruption"),
                    },
                    child_after_termination: child.clone(),
                    cleanup,
                }
            }
            _ => RunOutcome::MonitorFailed {
                error: terminal.failures.as_slice().first().map_or(
                    "native workload did not produce a direct target outcome".into(),
                    |error| error.as_str().into(),
                ),
                child_after_termination: child.clone(),
                cleanup,
            },
        }
    };
    let restart_safety = RestartSafetyProof {
        direct_child_reaped: child.is_some(),
        workload_empty: cleanup_empty(&outcome),
        helpers_reaped: settled(CleanupResourceV3::Guardian)
            && settled(CleanupResourceV3::NamespaceInit),
        containment_removed: complete
            && settled(CleanupResourceV3::RootReferences)
            && settled(CleanupResourceV3::Staging)
            && settled(CleanupResourceV3::Record),
        containment_incapable_of_live_members: settled(CleanupResourceV3::Aggregate),
        sealed_boundary_retired: complete
            && receipt.frontend.control_handles_retired
            && receipt.frontend.relay_drained,
        errors: outcome
            .cleanup()
            .errors
            .iter()
            .map(|error| error.message.clone())
            .collect(),
    };
    let launch = LaunchEvidence {
        mechanism: "linux-private-workload-v1".into(),
        target_released: released,
        containment_verified_before_authorization: released,
        guardian_started_before_authorization: released,
        target_spawn_error_reported: true,
        boundary_requested: BoundaryRequirement::Sealed,
        boundary_effective: if released {
            BoundaryClass::Sealed
        } else {
            BoundaryClass::Unavailable
        },
        boundary_assignment_verified: released,
        boundary_reconfiguration_denied: released,
        inherited_resources_restricted: released,
        frontend_loss_cleanup_authority_verified: released,
    };
    let child_pid = native.and_then(|native| std::num::NonZeroU32::new(native.target.pid));
    Ok(crate::backend::Execution {
        outcome,
        backend: crate::linux_cgroup::sealed_info(live),
        child_pid,
        runtime: None,
        duration: receipt.duration,
        authorization_offset,
        launch,
        restart_safety,
        boundary_detail: memcordon_core::BoundaryMechanismEvidence::LinuxPrivateWorkloadV1 {
            terminal: Box::new(receipt.terminal),
            frontend: receipt.frontend,
        },
    })
}

fn cleanup_empty(outcome: &memcordon_core::RunOutcome) -> Option<bool> {
    outcome.cleanup().workload_empty
}

pub fn recover_workload_attempt(
    association: &WorkloadAttemptAssociationV1,
    cutoff: Instant,
) -> Result<LinuxWorkloadTerminalV1, String> {
    association.validate().map_err(|error| error.to_string())?;
    verify_endpoint()?;
    if super::super::linux_runtime::installed_current_binding()? != association.provider {
        return Err("recovery provider differs from original locator".into());
    }
    let stream = connect_until(cutoff)?;
    verify_peer(&stream)?;
    stream
        .set_nonblocking(false)
        .map_err(|error| error.to_string())?;
    let mut stream = TimedStream { stream, cutoff };
    WorkloadFrame {
        kind: WorkloadFrameKind::Recover,
        binding: binding(association),
        payload: serde_json::to_vec(association).map_err(|error| error.to_string())?,
    }
    .write(&mut stream)
    .map_err(|error| error.to_string())?;
    loop {
        if Instant::now() >= cutoff {
            return Err("original recovery cutoff elapsed".into());
        }
        let frame = WorkloadFrame::read(&mut stream, binding(association))
            .map_err(|error| error.to_string())?;
        match frame.kind {
            WorkloadFrameKind::Progress => {}
            WorkloadFrameKind::Recovery | WorkloadFrameKind::Terminal => {
                let terminal = LinuxWorkloadTerminalV1::parse(&frame.payload)?;
                if terminal.association != *association {
                    return Err("recovery terminal differs from original locator".into());
                }
                return Ok(terminal);
            }
            _ => return Err("unexpected native recovery frame".into()),
        }
    }
}

pub fn acknowledge_workload_attempt(
    association: &WorkloadAttemptAssociationV1,
    cutoff: Instant,
) -> Result<memcordon_core::workload_request::WorkloadAcknowledgmentV1, String> {
    association.validate().map_err(|error| error.to_string())?;
    verify_endpoint()?;
    if super::super::linux_runtime::installed_current_binding()? != association.provider {
        return Err("acknowledgment provider differs from original locator".into());
    }
    let stream = connect_until(cutoff)?;
    verify_peer(&stream)?;
    stream
        .set_nonblocking(false)
        .map_err(|error| error.to_string())?;
    let mut stream = TimedStream { stream, cutoff };
    WorkloadFrame {
        kind: WorkloadFrameKind::Acknowledge,
        binding: binding(association),
        payload: serde_json::to_vec(association).map_err(|error| error.to_string())?,
    }
    .write(&mut stream)
    .map_err(|error| error.to_string())?;
    let frame = WorkloadFrame::read(&mut stream, binding(association))
        .map_err(|error| error.to_string())?;
    if frame.kind == WorkloadFrameKind::Rejected {
        memcordon_core::canonical_json::reject_duplicate_json_keys(&frame.payload)?;
        let rejection: memcordon_core::workload_request::WorkloadRejectionV1 =
            serde_json::from_slice(&frame.payload).map_err(|error| error.to_string())?;
        return Err(format!(
            "native acknowledgment rejected: {:?}: {}",
            rejection.code,
            rejection.detail.as_str()
        ));
    }
    if frame.kind != WorkloadFrameKind::Acknowledgment {
        return Err("unexpected native acknowledgment frame".into());
    }
    let acknowledgment =
        memcordon_core::workload_request::WorkloadAcknowledgmentV1::parse(&frame.payload)
            .map_err(|error| error.to_string())?;
    if acknowledgment.association != *association {
        return Err("native acknowledgment differs from original locator".into());
    }
    Ok(acknowledgment)
}
