//! MemCordon-owned workload behavior; provider evidence remains independently checked.
mod controller_gate_access;
mod controller_gate_control_publication;
mod controller_gate_diagnostic;
mod controller_gate_error;
mod controller_gate_resolution;
mod controller_gate_thread_control;
mod controller_gate_token;
mod controller_start_input;
pub mod descriptor;
mod fixture_default_dacl;
mod fixture_environment;
mod gate_call_trace;
mod gate_call_trace_record;
mod gate_call_trace_self_check;
mod gate_directory_readback;
mod gate_directory_record;
mod gate_entry_route;
mod gate_precondition_child;
mod listener_trace;
mod listener_trace_record;
mod loader_security;
mod loader_security_record;
mod namespace_primary_root;
mod namespace_primary_worker;
mod native;
mod native_file_trace_record;
mod native_fixture_default_dacl;
mod native_gate_precondition;
mod operation_context;
mod own_thread_deadline_self_check;
mod peer_retirement;
mod provider_input_probes;
mod provider_input_target_record;
mod provider_loader_policy;
mod provider_loader_policy_native;
mod spawn_trace;
mod spawn_trace_record;
mod toolchain;
mod toolchain_debug;
mod toolchain_diagnostics;
mod winsock_registry;
mod winsock_startup;
mod winsock_trace;
mod winsock_trace_path;
mod winsock_trace_record;

use descriptor::{Case, Descriptor};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

pub(super) fn namespace_primary_experiment() -> io::Result<i32> {
    namespace_primary_worker::run()
}
pub(super) fn namespace_primary_replay(encoded: &str) -> io::Result<i32> {
    namespace_primary_worker::run_replay(encoded)
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub sequence: u32,
    pub stage: String,
    pub pid: u32,
    pub ordinal: Option<u32>,
    pub value: Vec<u8>,
}

struct Transcript {
    file: fs::File,
    sequence: u32,
}

impl Transcript {
    fn event(&mut self, stage: &str, ordinal: Option<u32>, value: &[u8]) -> io::Result<()> {
        let event = Event {
            sequence: self.sequence,
            stage: stage.into(),
            pid: std::process::id(),
            ordinal,
            value: value.to_vec(),
        };
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| io::Error::other("event sequence overflow"))?;
        let bytes = serde_json::to_vec(&event).map_err(io::Error::other)?;
        let length = u32::try_from(bytes.len()).map_err(io::Error::other)?;
        self.file.write_all(&length.to_le_bytes())?;
        self.file.write_all(&bytes)?;
        self.file.flush()
    }
}

fn read_descriptor(path: &Path) -> io::Result<Descriptor> {
    read_descriptor_with_digest(path).map(|(descriptor, _)| descriptor)
}

fn read_descriptor_with_digest(path: &Path) -> io::Result<(Descriptor, [u8; 32])> {
    let bytes = read_descriptor_bytes(path)?;
    let digest = descriptor::controller_start::descriptor_digest(&bytes);
    Descriptor::parse(&bytes)
        .map(|descriptor| (descriptor, digest))
        .map_err(io::Error::other)
}

fn read_descriptor_bytes(path: &Path) -> io::Result<Vec<u8>> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !metadata.is_file()
        || metadata.len() > descriptor::MAX_DESCRIPTOR_BYTES as u64
    {
        return Err(io::Error::other(
            "descriptor is not a bounded ordinary file",
        ));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((descriptor::MAX_DESCRIPTOR_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn child_command() -> io::Result<Command> {
    let mut command = Command::new(operation_context::context(
        operation_context::Operation::CurrentExecutable,
        std::env::current_exe(),
    )?);
    command.arg("consumer-readiness-windows");
    Ok(command)
}

fn frame_write(stream: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    stream.write_all(
        &u32::try_from(payload.len())
            .map_err(io::Error::other)?
            .to_le_bytes(),
    )?;
    stream.write_all(payload)?;
    stream.flush()
}

fn frame_read(stream: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_le_bytes(length) as usize;
    if length > 64 * 1024 {
        return Err(io::Error::other("application frame exceeds bound"));
    }
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload)?;
    Ok(payload)
}

fn read_http_header(stream: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        if bytes.len() >= 4096 {
            return Err(io::Error::other("HTTP header exceeds bound"));
        }
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        bytes.push(byte[0]);
    }
    Ok(bytes)
}

fn tcp_peer(
    port: u16,
    challenge: &[u8],
    output_root: &std::path::Path,
    deadline: Option<std::time::Instant>,
    trace: Option<&winsock_trace::Context<'_>>,
) -> io::Result<()> {
    let check = || {
        if deadline.is_some_and(|cutoff| std::time::Instant::now() >= cutoff) {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original registry TCP peer work cutoff exhausted",
            ))
        } else {
            Ok(())
        }
    };
    check()?;
    let _winsock = native::winsock_startup(trace.copied())?;
    check()?;
    let context = |stage, error| toolchain_diagnostics::socket_error(stage, port, error);
    let mut stream = match trace {
        Some(trace) => listener_trace::connect(
            trace,
            std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, port),
        ),
        None => TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)),
    }
    .map_err(|error| context("connect", error))?;
    // The retained peer awaits server half-close through compiler/churn work;
    // the independently owned public deadline bounds that whole operation.
    stream
        .set_read_timeout(Some(Duration::from_secs(600)))
        .map_err(|error| context("set-read-timeout", error))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(|error| context("set-write-timeout", error))?;
    stream
        .write_all(b"GET /readiness HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .map_err(|error| context("send-request", error))?;
    let header = read_http_header(&mut stream).map_err(|error| context("receive-header", error))?;
    if header != b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" {
        return Err(io::Error::other("HTTP response differs"));
    }
    let mut received = Vec::new();
    frame_write(&mut received, &header)?;
    for payload in [Vec::new(), vec![0, 255, 128, 10], challenge.to_vec()] {
        frame_write(&mut stream, &payload).map_err(|error| context("framed-send", error))?;
        let actual = frame_read(&mut stream).map_err(|error| context("framed-receive", error))?;
        if actual != payload {
            return Err(io::Error::other("TCP binary frame differs"));
        }
        frame_write(&mut received, &actual)?;
    }
    fs::write(output_root.join("tcp-peer-received.bin"), &received)?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|error| context("shutdown-write", error))?;
    let mut byte = [0];
    if stream
        .read(&mut byte)
        .map_err(|error| context("wait-server-eof", error))?
        != 0
    {
        return Err(io::Error::other("TCP half-close did not reach EOF"));
    }
    Ok(())
}

fn binary_files(descriptor: &Descriptor, transcript: &mut Transcript) -> io::Result<()> {
    let directory = descriptor.output_root.join("nested");
    fs::create_dir(&directory)?;
    fs::write(directory.join("empty.bin"), [])?;
    let bytes: Vec<u8> = (0..=255).collect();
    let temporary = directory.join("unrenamed.bin");
    fs::write(&temporary, &bytes)?;
    let renamed = directory.join("all-bytes.bin");
    fs::rename(temporary, &renamed)?;
    if fs::read(renamed)? != bytes {
        return Err(io::Error::other("binary file readback differs"));
    }
    fs::write(directory.join("challenge.bin"), &descriptor.challenge)?;
    transcript.event("binary-files", None, &descriptor.challenge)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerRegistryInput {
    descriptor_path: std::path::PathBuf,
    descriptor_sha256: [u8; 32],
    clock: descriptor::ControlClock,
}

fn read_peer_descriptor(
    input: &PeerRegistryInput,
    challenge: &[u8],
    output: &Path,
) -> io::Result<(Descriptor, [u8; 32])> {
    if !input.descriptor_path.is_absolute()
        || input.descriptor_path.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(io::Error::other(
            "peer original descriptor path is not absolute ordinary input",
        ));
    }
    let deadline = controller_start_input::deadline_from_clock(&input.clock)?;
    let timer = memcordon_platform::WindowsSynchronousIoDeadline::start(deadline)
        .map_err(io::Error::other)?;
    let read = (|| {
        listener_trace::live(&input.clock)?;
        let bytes = read_descriptor_bytes(&input.descriptor_path)?;
        listener_trace::live(&input.clock)?;
        let parsed = Descriptor::parse_authenticated_peer(
            &bytes,
            input.descriptor_sha256,
            challenge,
            output,
            &input.clock,
        )
        .map_err(io::Error::other)?;
        listener_trace::live(&input.clock)?;
        Ok(parsed)
    })();
    let stopped = timer.finish().map_err(io::Error::other);
    match (read, stopped) {
        (Err(primary), Err(secondary)) => Err(peer_failures(primary, secondary)),
        (Err(primary), _) => Err(primary),
        (Ok(_), Err(secondary)) => Err(secondary),
        (Ok(parsed), Ok(())) => {
            listener_trace::live(&input.clock)?;
            Ok(parsed)
        }
    }
}

#[derive(Debug)]
struct RegistryPeerFailure {
    primary: io::Error,
    secondary: io::Error,
}
impl std::fmt::Display for RegistryPeerFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}; independent registry peer cleanup: {}",
            self.primary, self.secondary
        )
    }
}
impl std::error::Error for RegistryPeerFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
fn peer_failures(primary: io::Error, secondary: io::Error) -> io::Error {
    io::Error::new(primary.kind(), RegistryPeerFailure { primary, secondary })
}

struct FailedPeerOwner {
    child: std::process::Child,
    _forwarding: Vec<File>,
}
struct UnsettledPeer {
    error: io::Error,
    // Quarantine for this root's remaining lifetime only. Controller holds an
    // independent admitted process owner, or conservatively keeps uncertainty.
    _owner: &'static FailedPeerOwner,
}
impl std::fmt::Debug for UnsettledPeer {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("UnsettledPeer")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
impl std::fmt::Display for UnsettledPeer {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            out,
            "{}; original peer owner retained for root lifetime; retirement unproved",
            self.error
        )
    }
}
impl std::error::Error for UnsettledPeer {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}
fn settle_peer_failure(
    peer: std::process::Child,
    forwarding: Vec<File>,
    primary: io::Error,
    cutoff: std::time::Instant,
) -> io::Error {
    use memcordon_platform::windows_registry_error::at;
    let mut owner = FailedPeerOwner {
        child: peer,
        _forwarding: forwarding,
    };
    owner.child.stdin.take();
    match peer_retirement::settle(
        owner,
        primary,
        cutoff,
        |owner| {
            at(
                owner.child.kill(),
                "peer/cleanup-kill",
                "Child::kill",
                "Win32",
                None,
            )
        },
        |owner| {
            at(
                owner.child.try_wait(),
                "peer/cleanup-wait",
                "Child::try_wait",
                "Win32",
                None,
            )
            .map(|status| status.is_some())
        },
    ) {
        peer_retirement::Outcome::Retired(error) => error,
        peer_retirement::Outcome::Unsettled { owner, error } => io::Error::new(
            error.kind(),
            UnsettledPeer {
                error,
                _owner: Box::leak(Box::new(owner)),
            },
        ),
    }
}

fn send_peer_registry(
    peer: &mut std::process::Child,
    registry: &winsock_registry::Mapping,
    descriptor: &Descriptor,
    session: &controller_start_input::Session,
    permit: Option<controller_start_input::PeerHandoffPermit>,
) -> io::Result<()> {
    use memcordon_platform::windows_registry_error::at;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::{
        Foundation::DuplicateHandle,
        System::{Registry::KEY_READ, Threading::GetCurrentProcess},
    };
    let deadline = session.original_deadline();
    let check = || {
        if std::time::Instant::now() >= deadline {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original registry peer handoff cutoff exhausted",
            ))
        } else {
            Ok(())
        }
    };
    check()?;
    // One watcher covers source metadata queries, every duplicate and START;
    // it is settled before later application I/O, never renewed per reference.
    let timer = memcordon_platform::WindowsSynchronousIoDeadline::start(deadline)
        .map_err(io::Error::other)?;
    let mut duplicated = 0u32;
    let mut registry_duplicated = false;
    let written = (|| -> io::Result<()> {
        if descriptor.provider_input_experiment != permit.is_some() {
            return Err(io::Error::other(
                "provider peer requires the exact admitted recipient permit",
            ));
        }
        if descriptor.provider_input_experiment {
            session.private_directories()?.ok_or_else(|| {
                io::Error::other("original private session is not admitted for forwarding")
            })?;
        }
        let identity = at(
            match &permit {
                Some(permit) => permit.validate(peer, session.original_binding()),
                None => native::child_identity(peer),
            },
            "peer/original-identity",
            "child_identity",
            "boundary",
            None,
        )?;
        check()?;
        let mut handle = std::ptr::null_mut();
        // SAFETY: source is the admitted read-only key; target is this exact owned
        // Child, never a reopened PID. Its numeric result is target-local only.
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                registry.raw(),
                peer.as_raw_handle(),
                &mut handle,
                KEY_READ,
                0,
                0,
            )
        } == 0
        {
            return at(
                Err(io::Error::last_os_error()),
                "peer/readonly-key-duplicate",
                "DuplicateHandle",
                "Win32",
                Some(KEY_READ),
            );
        }
        // A successful duplicate is already recipient debt before any cutoff check.
        registry_duplicated = true;
        check()?;
        let binding = descriptor::controller_start::Binding {
            challenge: descriptor.challenge.clone(),
            descriptor_sha256: session.original_binding().descriptor_sha256,
            pid: identity.process_id,
            birth: identity.creation_time_100ns,
        };
        let capability = descriptor::controller_start::Capability {
            version: 1,
            handle: handle as usize as u64,
            manifest_sha256: descriptor
                .winsock_registry
                .as_ref()
                .ok_or_else(|| io::Error::other("peer registry declaration absent"))?
                .sha256,
        };
        let mut sender = descriptor::controller_start::Sender::with_registry(capability, false);
        if descriptor.provider_input_experiment {
            let expected = descriptor
                .provider_input_binding
                .as_ref()
                .ok_or_else(|| io::Error::other("peer private binding absent"))?
                .directory_expectation()
                .map_err(io::Error::other)?;
            let directories = session
                .private_directories()?
                .ok_or_else(|| io::Error::other("root forwarding references absent"))?;
            let files = directories
                .input
                .iter()
                .chain(std::iter::once(directories.local))
                .chain(directories.output.iter())
                .collect::<Vec<_>>();
            let roles = expected.roles().map_err(io::Error::other)?;
            if roles.len() != files.len() {
                return Err(io::Error::other("root forwarding role extent differs"));
            }
            let mut references = Vec::with_capacity(roles.len());
            for ((role, index), file) in roles.into_iter().zip(files) {
                let handle = if role == descriptor::controller_start::DirectoryRole::LocalMarkerFile
                {
                    memcordon_platform::test_support::duplicate_marker_metadata_into_child(
                        peer,
                        file,
                        deadline,
                        &mut duplicated,
                    )?
                } else {
                    memcordon_platform::test_support::duplicate_directory_metadata_into_child(
                        peer,
                        file,
                        deadline,
                        &mut duplicated,
                    )?
                };
                references.push(descriptor::controller_start::DirectoryReference {
                    role,
                    index,
                    handle,
                    access_mask: 128,
                });
            }
            let transfer = descriptor::controller_start::DirectoryTransfer {
                version: expected.transfer_version(),
                manifest_sha256: expected.manifest_sha256,
                references,
            };
            sender = sender.with_directories(transfer, expected)?;
        }
        match peer.stdin.take() {
            Some(mut writer) => sender.send(
                &mut writer,
                &binding,
                descriptor::controller_start::Phase::Start,
                check,
            ),
            None => Err(io::Error::other("original registry peer stdin unavailable")),
        }
    })();
    let stopped = timer.finish().map_err(io::Error::other);
    let result = match (written, stopped) {
        (Err(primary), Err(secondary)) => Err(peer_failures(primary, secondary)),
        (Err(primary), _) => Err(primary),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => check(),
    };
    result.map_err(|primary| {
        io::Error::new(
            primary.kind(),
            PeerTransferFailure {
                primary,
                duplicated: duplicated.saturating_add(u32::from(registry_duplicated)),
                controller_recipient_admitted: permit.is_some(),
            },
        )
    })
}

#[derive(Debug)]
struct PeerTransferFailure {
    primary: io::Error,
    duplicated: u32,
    controller_recipient_admitted: bool,
}
impl std::fmt::Display for PeerTransferFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            out,
            "{}; peer transferred references={}; controller-recipient-admitted={}; native recipient retirement remains required",
            self.primary, self.duplicated, self.controller_recipient_admitted
        )
    }
}
impl std::error::Error for PeerTransferFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}

fn joint(
    descriptor: &Descriptor,
    transcript: &mut Transcript,
    churn: bool,
    control: Option<&mut controller_start_input::Session>,
    token_envelope: &[u8],
    descriptor_path: &Path,
) -> io::Result<()> {
    let registry = match (&descriptor.winsock_registry, control.as_deref()) {
        (Some(declaration), Some(session)) => {
            let capability = session.registry_capability().ok_or_else(|| {
                io::Error::other(
                    "declared registry input capability was not admitted by original START",
                )
            })?;
            if capability.manifest_sha256 != declaration.sha256 {
                return Err(io::Error::other(
                    "registry input capability and descriptor differ",
                ));
            }
            // The completed authenticated frame transfers this one reference;
            // native type/access/noninheritance and complete data are checked.
            let key = unsafe {
                winsock_registry::OwnedKey::from_transferred(
                    capability.handle,
                    session.original_deadline(),
                )
            }?;
            Some(winsock_registry::Mapping::install(
                key,
                declaration,
                session.original_deadline(),
            )?)
        }
        (None, _) => None,
        _ => {
            return Err(io::Error::other(
                "declared registry input lacks original control session",
            ));
        }
    };
    match registry {
        Some(mapping) => mapping.run(|mapping| {
            joint_mapped(
                descriptor,
                transcript,
                churn,
                control,
                token_envelope,
                Some(mapping),
                descriptor_path,
            )
        }),
        None => joint_mapped(
            descriptor,
            transcript,
            churn,
            control,
            token_envelope,
            None,
            descriptor_path,
        ),
    }
}

fn joint_mapped(
    descriptor: &Descriptor,
    transcript: &mut Transcript,
    churn: bool,
    mut control: Option<&mut controller_start_input::Session>,
    token_envelope: &[u8],
    registry: Option<&winsock_registry::Mapping>,
    descriptor_path: &Path,
) -> io::Result<()> {
    let trace_binding = control
        .as_deref()
        .map(|session| session.original_binding().clone());
    let trace = match (descriptor.control_clock.as_ref(), trace_binding.as_ref()) {
        (Some(clock), Some(binding)) => Some(winsock_trace::Context {
            clock,
            output_root: &descriptor.output_root,
            binding,
            token_envelope,
            provider_input_experiment: descriptor.provider_input_experiment,
            peer: false,
        }),
        _ => None,
    };
    if descriptor.provider_input_experiment {
        if registry.is_none() || trace.is_none() {
            return Err(io::Error::other(
                "provider experiment requires authenticated controller START and installed registry mapping",
            ));
        }
        let prepared = provider_input_probes::prepare(
            descriptor,
            false,
            control
                .as_deref()
                .expect("checked private session")
                .private_directories()?,
        )?;
        provider_input_probes::run(descriptor, false, prepared)?;
    }
    let _winsock = native::winsock_startup(trace)?;
    let listener = listener_trace::bind(trace.as_ref())?;
    use operation_context::{Operation, context};
    let address = context(Operation::ListenerLocalAddress, listener.local_addr())?;
    // The original socket stays held until every IPC/churn/descendant stage completes.
    let conflicting_bind = match TcpListener::bind(address) {
        Ok(_) => {
            return context(
                Operation::CompetingBind,
                Err(io::Error::other("competing bind acquired live endpoint")),
            );
        }
        Err(error) => error,
    };
    let conflicting_code = conflicting_bind.raw_os_error();
    if conflicting_code != Some(10048) {
        return context(Operation::CompetingBind, Err(conflicting_bind));
    }
    context(
        Operation::TranscriptConflictingBind,
        transcript.event(
            "tcp-conflicting-bind",
            None,
            &conflicting_code
                .expect("validated native bind code")
                .to_le_bytes(),
        ),
    )?;
    context(
        Operation::TranscriptListenerOwned,
        transcript.event("tcp-listener-owned", None, &address.port().to_le_bytes()),
    )?;
    if descriptor.case == Case::EndpointMismatch {
        let policy_endpoint = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let allowed = policy_endpoint.local_addr()?.port();
        let refusal = EndpointPolicy::ExactNumericPort(allowed)
            .check(address.port())
            .expect_err("two retained TCP listeners cannot own the same endpoint");
        transcript.event(
            "endpoint-policy-refused-before-readiness",
            None,
            &serde_json::to_vec(&refusal).map_err(io::Error::other)?,
        )?;
        let gate = descriptor
            .start_gate
            .as_ref()
            .ok_or_else(|| io::Error::other("endpoint refusal lacks owned observation barrier"))?;
        native::wait_controller_gate(
            std::ffi::OsStr::new(&format!("{gate}-endpoint-observed")),
            || Ok(()),
        )?;
        return Ok(());
    }
    let challenge_path = descriptor.output_root.join("tcp-challenge.bin");
    context(
        Operation::ChallengeWrite,
        fs::write(&challenge_path, &descriptor.challenge),
    )?;
    let mut peer_command = child_command()?;
    peer_command
        .arg("tcp-peer")
        .arg(address.port().to_string())
        .arg(challenge_path)
        .arg(&descriptor.output_root)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    if registry.is_some() {
        let session = control
            .as_deref()
            .ok_or_else(|| io::Error::other("original registry session absent"))?;
        let peer_input = PeerRegistryInput {
            descriptor_path: descriptor_path.to_owned(),
            descriptor_sha256: session.original_binding().descriptor_sha256,
            clock: descriptor
                .control_clock
                .clone()
                .ok_or_else(|| io::Error::other("original registry clock absent"))?,
        };
        let peer_input = serde_json::to_string(&peer_input).map_err(io::Error::other)?;
        if peer_input.len() > 4096 {
            return Err(io::Error::other(
                "peer original descriptor envelope exceeds argv bound",
            ));
        }
        peer_command.arg(peer_input).stdin(Stdio::piped());
    }
    if descriptor.provider_input_experiment {
        let binding = control
            .as_deref()
            .expect("checked private session")
            .peer_admission_binding();
        context(
            Operation::TranscriptSpawnIntent,
            transcript.event(
                "tcp-peer-spawn-intent",
                None,
                &serde_json::to_vec(&binding).map_err(io::Error::other)?,
            ),
        )?;
    }
    let mut peer = context(
        Operation::PeerCommandSpawn,
        spawn_trace::spawn(&mut peer_command, trace.as_ref()),
    )?;
    // Every error after spawn retains/settles this original Child. In a private
    // experiment the controller independently owns the peer before transfer,
    // or keeps the unresolved spawn interval quarantined.
    let worked = (|| -> io::Result<()> {
        let permit = if descriptor.provider_input_experiment {
            let session = control.as_deref_mut().expect("checked private session");
            let pending = context(Operation::PendingPeerIdentity, session.pending_peer(&peer))?;
            context(
                Operation::TranscriptPendingAdmission,
                transcript.event(
                    "tcp-peer-pending-admission",
                    None,
                    &serde_json::to_vec(&pending).map_err(io::Error::other)?,
                ),
            )?;
            Some(context(
                Operation::PeerRecipientAdmission,
                session.receive_peer_recipient(&pending),
            )?)
        } else {
            None
        };
        if let Some(registry) = registry {
            context(
                Operation::RegistryMetadataHandoff,
                send_peer_registry(
                    &mut peer,
                    registry,
                    descriptor,
                    control.as_deref().expect("checked registry control"),
                    permit,
                ),
            )?;
            control
                .as_deref_mut()
                .expect("checked registry control")
                .close_private_directories();
        }
        context(
            Operation::TranscriptPeerCreated,
            transcript.event(
                "tcp-peer-created",
                None,
                &serde_json::to_vec(&context(
                    Operation::PeerIdentity,
                    native::child_identity(&peer),
                )?)
                .map_err(io::Error::other)?,
            ),
        )?;
        let (mut stream, _) = listener.accept()?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        let header = read_http_header(&mut stream)?;
        if header != b"GET /readiness HTTP/1.1\r\nHost: localhost\r\n\r\n" {
            return Err(io::Error::other("HTTP request differs"));
        }
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")?;
        let mut received = Vec::new();
        frame_write(&mut received, &header)?;
        for payload in [
            Vec::new(),
            vec![0, 255, 128, 10],
            descriptor.challenge.clone(),
        ] {
            let actual = frame_read(&mut stream)?;
            if actual != payload {
                return Err(io::Error::other("TCP application frame differs"));
            }
            frame_write(&mut received, &actual)?;
            frame_write(&mut stream, &payload)?;
        }
        fs::write(
            descriptor.output_root.join("tcp-server-received.bin"),
            &received,
        )?;
        let pipe = native::named_pipe_exchange(&descriptor.challenge)?;
        fs::write(
            descriptor
                .output_root
                .join("named-pipe-server-received.bin"),
            &pipe.server_received,
        )?;
        fs::write(
            descriptor
                .output_root
                .join("named-pipe-client-received.bin"),
            &pipe.client_received,
        )?;
        transcript.event("named-pipe-while-tcp-owned", None, &descriptor.challenge)?;
        binary_files(descriptor, transcript)?;
        toolchain::execute(descriptor, transcript, control.as_deref_mut())?;
        protected_write_probes(descriptor, transcript)?;
        if churn {
            process_churn(descriptor, transcript)?;
        } else {
            generation_chain(3, &descriptor.challenge)?;
            transcript.event("descendants-complete", None, &descriptor.challenge)?;
        }
        if let Some(gate) = &descriptor.completion_gate {
            native::wait_controller_gate(std::ffi::OsStr::new(gate), || {
                transcript.event(
                    "capacity-live-before-natural-completion",
                    None,
                    &descriptor.challenge,
                )
            })?;
        }
        let mut byte = [0];
        if stream.read(&mut byte)? != 0 {
            return Err(io::Error::other("TCP peer did not half-close"));
        }
        stream.shutdown(Shutdown::Write)?;
        if !peer.wait()?.success() {
            return Err(io::Error::other("TCP child failed"));
        }
        transcript.event("tcp-peer-complete", None, &descriptor.challenge)
    })();
    match worked {
        Ok(()) => Ok(()),
        Err(primary) => match control.as_deref_mut() {
            Some(session) => {
                let cutoff = session.original_deadline();
                let forwarding = session.take_private_directory_files();
                Err(settle_peer_failure(peer, forwarding, primary, cutoff))
            }
            None => Err(primary),
        },
    }
}

fn protected_write_probes(descriptor: &Descriptor, transcript: &mut Transcript) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    for path in &descriptor.denied_write_paths {
        match OpenOptions::new().write(true).create_new(true).open(path) {
            Err(error)
                if error.kind() == io::ErrorKind::PermissionDenied
                    && error.raw_os_error() == Some(5) =>
            {
                let receipt = serde_json::to_vec(&serde_json::json!({
                    "path_utf16":path.as_os_str().encode_wide().collect::<Vec<_>>(),
                    "win32_code":error.raw_os_error(),
                }))
                .map_err(io::Error::other)?;
                transcript.event("protected-write-denied", None, &receipt)?;
            }
            Err(error) => {
                return Err(io::Error::other(format!(
                    "protected write had wrong error: {error}"
                )));
            }
            Ok(_) => {
                return Err(io::Error::other(
                    "protected driver/provider write succeeded",
                ));
            }
        }
    }
    Ok(())
}

enum EndpointPolicy {
    ExactNumericPort(u16),
}

#[derive(Debug, Serialize)]
struct EndpointRefusal {
    kind: &'static str,
    allowed_port: u16,
    observed_port: u16,
}

impl EndpointPolicy {
    fn check(self, observed_port: u16) -> Result<(), EndpointRefusal> {
        match self {
            Self::ExactNumericPort(allowed_port) if allowed_port == observed_port => Ok(()),
            Self::ExactNumericPort(allowed_port) => Err(EndpointRefusal {
                kind: "numeric-port-policy-mismatch",
                allowed_port,
                observed_port,
            }),
        }
    }
}

fn generation_chain(depth: u32, challenge: &[u8]) -> io::Result<()> {
    if depth == 0 {
        return Ok(());
    }
    let output = child_command()?
        .arg("generation")
        .arg((depth - 1).to_string())
        .arg(serde_json::to_string(challenge).map_err(io::Error::other)?)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    if !output.status.success() || output.stdout != challenge || !output.stderr.is_empty() {
        return Err(io::Error::other(
            "generated descendant output/status differs",
        ));
    }
    Ok(())
}

fn process_churn(descriptor: &Descriptor, transcript: &mut Transcript) -> io::Result<()> {
    let mut ordinal = 0u32;
    while ordinal < descriptor.churn_creations {
        let cohort = descriptor
            .churn_live
            .min(descriptor.churn_creations - ordinal);
        let mut children: Vec<(u32, Child)> = Vec::new();
        for _ in 0..cohort {
            // Each ordinal creates one process. Extra depth probes are explicit
            // supplemental creations, never counted in the frozen 4096 units.
            let child = child_command()?
                .arg("cohort-leaf")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            transcript.event(
                "child-created",
                Some(ordinal),
                &serde_json::to_vec(&native::child_identity(&child)?).map_err(io::Error::other)?,
            )?;
            children.push((ordinal, child));
            ordinal = ordinal
                .checked_add(1)
                .ok_or_else(|| io::Error::other("ordinal overflow"))?;
        }
        // Hold every child at its native stdio barrier; the driver can retain
        // process handles while the transcript publishes the complete cohort.
        for (_, child) in &mut children {
            let mut ready = [0; 1];
            child
                .stdout
                .as_mut()
                .ok_or_else(|| io::Error::other("missing child stdout"))?
                .read_exact(&mut ready)?;
            if ready != [0xA5] {
                return Err(io::Error::other("cohort readiness differs"));
            }
        }
        transcript.event("cohort-live", Some(ordinal), &cohort.to_le_bytes())?;
        native::wait_controller_gate_reset(std::ffi::OsStr::new(
            descriptor
                .cohort_gate
                .as_ref()
                .expect("validated cohort gate"),
        ))?;
        for (_, child) in &mut children {
            child
                .stdin
                .take()
                .ok_or_else(|| io::Error::other("missing child stdin"))?
                .write_all(&[0x5A])?;
        }
        for (unit, child) in children {
            let output = child.wait_with_output()?;
            if !output.status.success() || !output.stdout.is_empty() || !output.stderr.is_empty() {
                return Err(io::Error::other(
                    "churn child failed or emitted unexpected bytes",
                ));
            }
            transcript.event("child-completed", Some(unit), &[])?;
        }
        let gate = descriptor
            .generation_gate
            .as_ref()
            .expect("validated generation gate");
        let mut generation = child_command()?
            .arg("held-generation")
            .arg("2")
            .arg(gate)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut ready = [0];
        generation
            .stdout
            .as_mut()
            .expect("piped generation readiness")
            .read_exact(&mut ready)?;
        if ready != [0xA5] {
            return Err(io::Error::other("held generation did not become live"));
        }
        transcript.event("generation-live", Some(ordinal), &[])?;
        let output = generation.wait_with_output()?;
        if !output.status.success() || !output.stdout.is_empty() || !output.stderr.is_empty() {
            return Err(io::Error::other(
                "held three-generation branch did not complete",
            ));
        }
    }
    transcript.event("churn-complete", None, &ordinal.to_le_bytes())
}

pub fn run(mut args: impl Iterator<Item = OsString>) -> io::Result<i32> {
    let first = args
        .next()
        .ok_or_else(|| io::Error::other("missing Windows workload input"))?;
    match first.to_str() {
        Some("argv-nul-refusal") => {
            use std::os::windows::ffi::OsStringExt;
            let program = args
                .next()
                .ok_or_else(|| io::Error::other("NUL refusal target missing"))?;
            let contract_path = args
                .next()
                .ok_or_else(|| io::Error::other("NUL refusal contract missing"))?;
            let output = args
                .next()
                .ok_or_else(|| io::Error::other("NUL refusal output missing"))?;
            if args.next().is_some() {
                return Err(io::Error::other("unexpected NUL refusal arguments"));
            }
            let contract = memcordon_core::workload_request::WorkloadRequestV1::parse(&fs::read(
                contract_path,
            )?)
            .map_err(io::Error::other)?;
            let policy = memcordon::Policy::new(memcordon::ByteSize::gib(4))
                .sealed()
                .with_workload_request(contract)
                .map_err(io::Error::other)?;
            let native_argument = vec![b'a' as u16, 0, b'b' as u16];
            let command =
                memcordon::CommandSpec::new(program).args([OsString::from_wide(&native_argument)]);
            let result = memcordon::Limiter::new(policy).command(command).run();
            let error = result
                .err()
                .ok_or_else(|| io::Error::other("native NUL command unexpectedly authorized"))?;
            let evidence = serde_json::json!({"format":"memcordon.windows-native-argv-refusal", "revision":1,
                "argument_utf16":native_argument, "code":error.code, "category":format!("{:?}", error.category),
                "target_pid":error.target_pid, "target_released":error.target_released,
                "provider_association":error.provider_association, "detail":error.message});
            let bytes = serde_json::to_vec(&evidence).map_err(io::Error::other)?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            if fs::read(&output)? != bytes {
                return Err(io::Error::other(
                    "native NUL refusal named readback differs",
                ));
            }
            if error.code != "MCSEALED-WINDOWS-REQUEST"
                || !matches!(error.category, memcordon_core::ErrorCategory::Usage)
                || error.target_pid.is_some()
                || error.target_released
            {
                return Err(io::Error::other(
                    "native NUL argument did not fail before target authorization",
                ));
            }
            return Ok(0);
        }
        Some("token-snapshot") => {
            if args.next().is_some() {
                return Err(io::Error::other("extra token snapshot arguments"));
            }
            io::stdout().write_all(&native::token_observation()?)?;
            return Ok(0);
        }
        Some("owner-request-probe") => {
            let argument = args
                .next()
                .and_then(|value| value.into_string().ok())
                .ok_or_else(|| io::Error::other("current owner probe request absent"))?;
            if argument.len() > 4096 || args.next().is_some() {
                return Err(io::Error::other(
                    "current owner probe request exceeds bounds",
                ));
            }
            memcordon_core::canonical_json::reject_duplicate_json_keys(argument.as_bytes())
                .map_err(io::Error::other)?;
            let request: memcordon_core::WindowsProviderRequestV4 =
                serde_json::from_str(&argument).map_err(io::Error::other)?;
            if !matches!(
                request,
                memcordon_core::WindowsProviderRequestV4::RecoverAttempt { .. }
                    | memcordon_core::WindowsProviderRequestV4::ReplayTerminal { .. }
                    | memcordon_core::WindowsProviderRequestV4::Cancel { .. }
            ) {
                return Err(io::Error::other("unrelated current owner probe operation"));
            }
            let token: serde_json::Value =
                serde_json::from_slice(&native::token_observation()?).map_err(io::Error::other)?;
            let (response, error) =
                match memcordon_platform::observe_windows_owner_request(&request) {
                    Ok(raw) => (Some(raw), None),
                    Err(error) => (None, Some(error)),
                };
            serde_json::to_writer(io::stdout().lock(),&serde_json::json!({"format":"memcordon.windows-current-foreign-owner-probe","revision":1,"process_id":std::process::id(),"token":token,"request":request,"response_bytes":response,"exchange_error":error})).map_err(io::Error::other)?;
            return Ok(0);
        }
        Some("restricted-frontend") => return native::restricted_frontend(args),
        Some("system-frontend") => return native::system_frontend(args),
        Some("system-restricted-frontend") => return native::system_restricted_frontend(args),
        Some("system-restricted-gate-control-frontend") => {
            return native::system_restricted_gate_control_frontend(args);
        }
        Some("gate-call-trace-self-check") => {
            if args.next().is_some() {
                return Err(io::Error::other("trace self-check takes no operands"));
            }
            return gate_call_trace_self_check::run();
        }
        Some("winsock-call-trace-self-check") => {
            if args.next().is_some() {
                return Err(io::Error::other(
                    "Winsock forwarding self-check takes no operands",
                ));
            }
            winsock_trace::mock()?;
            return Ok(0);
        }
        Some("listener-call-trace-self-check") => {
            if args.next().is_some() {
                return Err(io::Error::other(
                    "listener trace self-check takes no operands",
                ));
            }
            return listener_trace::self_check();
        }
        Some("peer-spawn-call-trace-self-check") => {
            if args.next().is_some() {
                return Err(io::Error::other(
                    "peer spawn trace self-check takes no operands",
                ));
            }
            return spawn_trace::standalone_self_check();
        }
        Some("own-thread-deadline-self-check") => {
            if args.next().is_some() {
                return Err(io::Error::other(
                    "own-thread deadline self-check takes no operands",
                ));
            }
            return own_thread_deadline_self_check::run();
        }
        Some("gate-precondition-child") => {
            let path = args
                .next()
                .ok_or_else(|| io::Error::other("gate control descriptor missing"))?;
            let envelope = args
                .next()
                .ok_or_else(|| io::Error::other("gate control envelope missing"))?;
            if args.next().is_some() || envelope.len() > descriptor::gate_precondition::RECORD_BYTES
            {
                return Err(io::Error::other("gate control operands exceed bound"));
            }
            let envelope = serde_json::from_str(
                envelope
                    .to_str()
                    .ok_or_else(|| io::Error::other("gate control envelope is not JSON"))?,
            )
            .map_err(io::Error::other)?;
            return gate_precondition_child::run(Path::new(&path), &envelope);
        }
        Some("system-sentinel-frontend") => return native::system_sentinel_frontend(args),
        Some("sentinel-frontend") => return native::sentinel_frontend(args),
        Some("tcp-peer") => {
            let port = args
                .next()
                .and_then(|p| p.to_str().and_then(|s| s.parse::<u16>().ok()))
                .ok_or_else(|| io::Error::other("invalid TCP peer port"))?;
            let path = args
                .next()
                .ok_or_else(|| io::Error::other("missing peer challenge"))?;
            let output_root = args
                .next()
                .ok_or_else(|| io::Error::other("missing peer output root"))?;
            let registry = args.next();
            if args.next().is_some() {
                return Err(io::Error::other("extra peer arguments"));
            }
            let challenge = fs::read(path)?;
            let _registry = match registry {
                Some(input) => {
                    let input = input
                        .to_str()
                        .filter(|text| text.len() <= 4096)
                        .ok_or_else(|| {
                            io::Error::other("peer registry input is not bounded UTF8")
                        })?;
                    let input: PeerRegistryInput =
                        serde_json::from_str(input).map_err(io::Error::other)?;
                    let (parsed, fresh_digest) =
                        read_peer_descriptor(&input, &challenge, Path::new(&output_root))?;
                    let declaration = parsed.winsock_registry.as_ref().ok_or_else(|| {
                        io::Error::other("authenticated peer registry declaration absent")
                    })?;
                    let identity = native::current_identity()?;
                    let binding = descriptor::controller_start::Binding {
                        challenge: challenge.clone(),
                        descriptor_sha256: fresh_digest,
                        pid: identity.process_id,
                        birth: identity.creation_time_100ns,
                    };
                    let mut session =
                        controller_start_input::Session::peer(&input.clock, binding, &parsed)?;
                    let peer_token = if parsed.provider_input_experiment {
                        listener_trace::live(&input.clock)?;
                        let token = native::token_observation()?;
                        listener_trace::live(&input.clock)?;
                        Some(token)
                    } else {
                        None
                    };
                    // The root sender uses the digest admitted by its original
                    // controller START. Fresh local bytes alone grant nothing:
                    // this frame must match that digest and this exact peer.
                    session.receive(descriptor::controller_start::Phase::Start)?;
                    let capability = session
                        .registry_capability()
                        .ok_or_else(|| io::Error::other("peer registry capability absent"))?;
                    let key = unsafe {
                        winsock_registry::OwnedKey::from_transferred(
                            capability.handle,
                            session.original_deadline(),
                        )
                    }?;
                    Some((
                        winsock_registry::Mapping::install(
                            key,
                            declaration,
                            session.original_deadline(),
                        )?,
                        session.original_deadline(),
                        parsed,
                        session.original_binding().clone(),
                        peer_token,
                        session,
                    ))
                }
                None => None,
            };
            match _registry {
                Some((mapping, deadline, parsed, binding, token, mut session)) => {
                    mapping.run(|_| {
                        let clock = parsed
                            .control_clock
                            .as_ref()
                            .expect("authenticated peer clock checked");
                        let trace = token.as_ref().map(|token| winsock_trace::Context {
                            clock,
                            binding: &binding,
                            token_envelope: token,
                            output_root: &parsed.output_root,
                            provider_input_experiment: true,
                            peer: true,
                        });
                        if token.is_some() {
                            let prepared = provider_input_probes::prepare(
                                &parsed,
                                true,
                                session.private_directories()?,
                            )?;
                            session.close_private_directories();
                            provider_input_probes::run(&parsed, true, prepared)?;
                        }
                        tcp_peer(
                            port,
                            &parsed.challenge,
                            &parsed.output_root,
                            Some(deadline),
                            trace.as_ref(),
                        )
                    })?
                }
                None => tcp_peer(
                    port,
                    &challenge,
                    std::path::Path::new(&output_root),
                    None,
                    None,
                )?,
            }
            return Ok(0);
        }
        Some("winsock-registry-self-check") => {
            if args.next().is_some() {
                return Err(io::Error::other("extra registry selfcheck arguments"));
            }
            return winsock_registry::self_check();
        }
        Some("winsock-registry-uninherited-self-check") => {
            let clock = args
                .next()
                .ok_or_else(|| io::Error::other("registry selfcheck child lacks original clock"))?;
            let clock = clock
                .to_str()
                .filter(|value| value.len() <= 4096)
                .ok_or_else(|| io::Error::other("registry selfcheck clock is not bounded UTF8"))?;
            let clock: descriptor::ControlClock =
                serde_json::from_str(clock).map_err(io::Error::other)?;
            if args.next().is_some() {
                return Err(io::Error::other("extra registry child selfcheck arguments"));
            }
            return winsock_registry::uninherited_self_check(
                controller_start_input::deadline_from_clock(&clock)?,
            );
        }
        Some("generation") => {
            let depth = args
                .next()
                .and_then(|p| p.to_str().and_then(|s| s.parse::<u32>().ok()))
                .filter(|depth| *depth <= 3)
                .ok_or_else(|| io::Error::other("invalid generation depth"))?;
            let bytes: Vec<u8> = serde_json::from_str(
                &args
                    .next()
                    .and_then(|p| p.into_string().ok())
                    .ok_or_else(|| io::Error::other("missing generation challenge"))?,
            )
            .map_err(io::Error::other)?;
            if bytes.len() > 4096 || args.next().is_some() {
                return Err(io::Error::other("generation input exceeds bound"));
            }
            generation_chain(depth, &bytes)?;
            io::stdout().write_all(&bytes)?;
            return Ok(0);
        }
        Some("token-change-child") => {
            let output = args
                .next()
                .ok_or_else(|| io::Error::other("missing token-change output"))?;
            let challenge = args
                .next()
                .ok_or_else(|| io::Error::other("missing token-change challenge"))?;
            if args.next().is_some() {
                return Err(io::Error::other("extra token-change argv"));
            }
            let challenge: Vec<u8> = serde_json::from_str(
                challenge
                    .to_str()
                    .ok_or_else(|| io::Error::other("invalid challenge encoding"))?,
            )
            .map_err(io::Error::other)?;
            if challenge.len() > 4096 {
                return Err(io::Error::other("token-change challenge exceeds bound"));
            }
            native::assert_job_and_sentinels(&[])?;
            let token = native::token_observation()?;
            let observed: serde_json::Value =
                serde_json::from_slice(&token).map_err(io::Error::other)?;
            if observed
                .get("restricted")
                .and_then(serde_json::Value::as_bool)
                != Some(true)
            {
                return Err(io::Error::other(
                    "token-change child did not retain the restricted native envelope",
                ));
            }
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output)?
                .write_all(&challenge)?;
            io::stdout().write_all(&token)?;
            return Ok(0);
        }
        Some("intermediate-exit") => {
            let gate = args
                .next()
                .ok_or_else(|| io::Error::other("missing intermediate gate"))?;
            let output = args
                .next()
                .ok_or_else(|| io::Error::other("missing intermediate output"))?;
            let challenge = args
                .next()
                .ok_or_else(|| io::Error::other("missing intermediate challenge"))?;
            if args.next().is_some() {
                return Err(io::Error::other("extra intermediate argv"));
            }
            let mut child = child_command()?
                .arg("descendant-hold")
                .arg(gate)
                .arg(output)
                .arg(challenge)
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()?;
            let mut ready = [0];
            child
                .stdout
                .as_mut()
                .expect("piped readiness")
                .read_exact(&mut ready)?;
            if ready != [0xA5] || child.try_wait()?.is_some() {
                return Err(io::Error::other("grandchild was not held live"));
            }
            frame_write(
                &mut io::stdout(),
                &serde_json::to_vec(&native::child_identity(&child)?).map_err(io::Error::other)?,
            )?;
            let mut release = [0_u8];
            io::stdin().read_exact(&mut release)?;
            if release != [0xA5] {
                return Err(io::Error::other("intermediate controller release differs"));
            }
            return Ok(0);
        }
        Some("held-generation") => {
            let depth = args
                .next()
                .and_then(|p| p.to_str().and_then(|s| s.parse::<u32>().ok()))
                .filter(|depth| *depth <= 2)
                .ok_or_else(|| io::Error::other("invalid held generation depth"))?;
            let gate = args
                .next()
                .ok_or_else(|| io::Error::other("missing generation gate"))?;
            if args.next().is_some() {
                return Err(io::Error::other("extra generation args"));
            }
            if depth == 0 {
                io::stdout().write_all(&[0xA5])?;
                io::stdout().flush()?;
                native::wait_controller_gate_reset(&gate)?;
            } else {
                let mut child = child_command()?
                    .arg("held-generation")
                    .arg((depth - 1).to_string())
                    .arg(&gate)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()?;
                let mut ready = [0];
                child
                    .stdout
                    .as_mut()
                    .expect("piped readiness")
                    .read_exact(&mut ready)?;
                if ready != [0xA5] {
                    return Err(io::Error::other("nested generation readiness differs"));
                }
                io::stdout().write_all(&[0xA5])?;
                io::stdout().flush()?;
                let output = child.wait_with_output()?;
                if !output.status.success()
                    || !output.stdout.is_empty()
                    || !output.stderr.is_empty()
                {
                    return Err(io::Error::other("nested held generation failed"));
                }
            }
            return Ok(0);
        }
        Some("cohort-leaf") => {
            if args.next().is_some() {
                return Err(io::Error::other("extra leaf arguments"));
            }
            native::assert_job_and_sentinels(&[])?;
            io::stdout().write_all(&[0xA5])?;
            io::stdout().flush()?;
            let mut gate = [0];
            io::stdin().read_exact(&mut gate)?;
            if gate != [0x5A] {
                return Err(io::Error::other("cohort release differs"));
            }
            return Ok(0);
        }
        Some("descendant-hold") => {
            let gate = args
                .next()
                .ok_or_else(|| io::Error::other("missing descendant gate"))?;
            let output = args
                .next()
                .ok_or_else(|| io::Error::other("missing descendant product"))?;
            let bytes: Vec<u8> = serde_json::from_str(
                &args
                    .next()
                    .and_then(|p| p.into_string().ok())
                    .ok_or_else(|| io::Error::other("missing descendant challenge"))?,
            )
            .map_err(io::Error::other)?;
            if bytes.len() > 4096 || args.next().is_some() {
                return Err(io::Error::other("descendant input exceeds bound"));
            }
            native::wait_controller_gate(&gate, || {
                io::stdout().write_all(&[0xA5])?;
                io::stdout().flush()
            })?;
            fs::write(output, bytes)?;
            return Ok(0);
        }
        _ => {}
    }
    let (descriptor, descriptor_digest) = read_descriptor_with_digest(Path::new(&first))?;
    let actual_arguments: Vec<OsString> = args.collect();
    if actual_arguments
        != descriptor
            .arguments
            .iter()
            .map(OsString::from)
            .collect::<Vec<_>>()
    {
        return Err(io::Error::other(
            "native argv differs from independently supplied descriptor",
        ));
    }
    use std::os::windows::ffi::OsStrExt;
    let actual_argv = serde_json::to_vec(&serde_json::json!({
        "encoding":"windows_utf16", "values":actual_arguments.iter().map(|argument|argument.encode_wide().collect::<Vec<_>>()).collect::<Vec<_>>(),
    })).map_err(io::Error::other)?;
    fs::write(
        descriptor.output_root.join("native-argv.json"),
        &actual_argv,
    )?;
    let mut transcript = Transcript {
        file: OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&descriptor.transcript)?,
        sequence: 0,
    };
    transcript.event("started", None, &descriptor.challenge)?;
    transcript.event("native-argv-observed", None, &actual_argv)?;
    native::assert_job_and_sentinels(&descriptor.sentinel_handles)?;
    transcript.event(
        "sentinel-handles-excluded",
        None,
        &u32::try_from(descriptor.sentinel_handles.len())
            .map_err(io::Error::other)?
            .to_le_bytes(),
    )?;
    let envelope = native::token_observation()?;
    transcript.event("token-envelope", None, &envelope)?;
    let mut control = match descriptor.start_transport {
        descriptor::StartTransport::ControllerStdin { .. } => Some(
            controller_start_input::Session::new(&descriptor, descriptor_digest)?,
        ),
        descriptor::StartTransport::NamedEvent => None,
    };
    let released = match descriptor.start_transport {
        descriptor::StartTransport::ControllerStdin { .. } => {
            control
                .as_mut()
                .expect("selected stdin session")
                .receive(descriptor::controller_start::Phase::Start)?;
            true
        }
        descriptor::StartTransport::NamedEvent => {
            if let Some(gate) = &descriptor.start_gate {
                native::wait_controller_gate_for_fixture(
                    std::ffi::OsStr::new(gate),
                    &descriptor,
                    transcript.sequence,
                )?;
                true
            } else {
                false
            }
        }
    };
    if released {
        transcript
            .event("controller-released", None, &descriptor.challenge)
            .map_err(|error| {
                controller_gate_error::context(
                    controller_gate_error::Stage::PublishRelease,
                    None,
                    error,
                )
            })?;
    }
    match descriptor.case {
        Case::Joint | Case::EndpointMismatch => joint(
            &descriptor,
            &mut transcript,
            false,
            control.as_mut(),
            &envelope,
            Path::new(&first),
        )?,
        Case::Churn => joint(
            &descriptor,
            &mut transcript,
            true,
            control.as_mut(),
            &envelope,
            Path::new(&first),
        )?,
        Case::Toolchain => toolchain::execute(&descriptor, &mut transcript, None)?,
        Case::BinaryFiles => binary_files(&descriptor, &mut transcript)?,
        Case::EmptyInput => {
            let mut actual = Vec::new();
            io::stdin().take(1).read_to_end(&mut actual)?;
            if !actual.is_empty() {
                return Err(io::Error::other(
                    "empty-input fixture received unexpected stdin bytes",
                ));
            }
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(descriptor.output_root.join("stdin.bin"))?;
            file.write_all(&actual)?;
            file.sync_all()?;
            transcript.event("stdin-read-to-eof", None, &actual)?;
        }
        Case::BinaryStreams => {
            let stdout = descriptor.stdout.clone();
            let stderr = descriptor.stderr.clone();
            let out = thread::spawn(move || -> io::Result<()> {
                for _ in 0..128 {
                    io::stdout().write_all(&stdout)?;
                }
                io::stdout().flush()
            });
            for _ in 0..128 {
                io::stderr().write_all(&stderr)?;
            }
            io::stderr().flush()?;
            out.join()
                .map_err(|_| io::Error::other("stdout writer panicked"))??;
        }
        Case::Envelope => {
            if !descriptor.denied_write_paths.is_empty() {
                binary_files(&descriptor, &mut transcript)?;
                protected_write_probes(&descriptor, &mut transcript)?;
            }
        }
        Case::EmptyStreams | Case::NativeArgv | Case::ApplicationExit => {}
        Case::DeadlineDemand | Case::HeldDemand => {
            let mut child = child_command()?
                .arg("cohort-leaf")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            let mut ready = [0u8];
            child
                .stdout
                .as_mut()
                .ok_or_else(|| io::Error::other("demand child readiness pipe absent"))?
                .read_exact(&mut ready)?;
            if ready != [0xA5] {
                return Err(io::Error::other(
                    "demand child did not enter native held barrier",
                ));
            }
            transcript.event(
                "child-created",
                Some(0),
                &serde_json::to_vec(&native::child_identity(&child)?).map_err(io::Error::other)?,
            )?;
            transcript.event("policy-demand-started", None, &descriptor.challenge)?;
            loop {
                std::hint::black_box(&child);
                thread::sleep(Duration::from_millis(5));
            }
        }
        Case::MemoryDemand => {
            transcript.event("policy-demand-started", None, &descriptor.challenge)?;
            let mut committed = Vec::<Vec<u8>>::new();
            loop {
                let mut allocation = Vec::new();
                if allocation.try_reserve_exact(8 * 1024 * 1024).is_err() {
                    loop {
                        thread::sleep(Duration::from_millis(5));
                    }
                }
                allocation.resize(8 * 1024 * 1024, 0xA5);
                std::hint::black_box(&allocation);
                committed.push(allocation);
                std::hint::black_box(&committed);
            }
        }
        Case::NestedJob => native::nested_job()?,
        Case::BreakawayDenied => native::breakaway_denied()?,
        Case::AllowedTokenChange => {
            let executable = std::env::current_exe()?;
            let output = child_command()?
                .arg("restricted-frontend")
                .arg(&executable)
                .arg("consumer-readiness-windows")
                .arg("token-change-child")
                .arg(descriptor.output_root.join("token-change-output.bin"))
                .arg(serde_json::to_string(&descriptor.challenge).map_err(io::Error::other)?)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()?;
            if !output.status.success() || !output.stderr.is_empty() {
                return Err(io::Error::other("allowed token-change descendant failed"));
            }
            transcript.event("allowed-token-change-retained-job", None, &output.stdout)?;
        }
        Case::RootFirst | Case::IntermediateFirst => {
            let gate = descriptor
                .descendant_gate
                .as_ref()
                .expect("validated descendant gate");
            let owned_gate = native::create_controller_gate(gate)?;
            if descriptor.case == Case::IntermediateFirst {
                let intermediate_gate = format!("{gate}-intermediate-live");
                let intermediate_owner = native::create_controller_gate(&intermediate_gate)?;
                let mut intermediate = child_command()?
                    .arg("intermediate-exit")
                    .arg(gate)
                    .arg(descriptor.output_root.join("descendant-output.bin"))
                    .arg(serde_json::to_string(&descriptor.challenge).map_err(io::Error::other)?)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit())
                    .spawn()?;
                let identity: memcordon_core::WindowsProcessIdentityV1 = serde_json::from_slice(
                    &frame_read(intermediate.stdout.as_mut().expect("piped intermediate"))?,
                )
                .map_err(io::Error::other)?;
                let parent = native::child_identity(&intermediate)?;
                transcript.event(
                    "intermediate-live-with-descendant",
                    None,
                    &serde_json::to_vec(&serde_json::json!({"parent":parent,"child":identity}))
                        .map_err(io::Error::other)?,
                )?;
                native::wait_controller_gate(std::ffi::OsStr::new(&intermediate_gate), || Ok(()))?;
                intermediate
                    .stdin
                    .take()
                    .expect("piped intermediate release")
                    .write_all(&[0xA5])?;
                if !intermediate.wait()?.success() {
                    return Err(io::Error::other("intermediate did not exit naturally"));
                }
                drop(intermediate_owner);
                transcript.event(
                    "intermediate-exits-with-live-descendant",
                    None,
                    &serde_json::to_vec(&identity).map_err(io::Error::other)?,
                )?;
                native::wait_controller_gate(std::ffi::OsStr::new(gate), || Ok(()))?;
                drop(owned_gate);
            } else {
                let mut child = child_command()?
                    .arg("descendant-hold")
                    .arg(gate)
                    .arg(descriptor.output_root.join("descendant-output.bin"))
                    .arg(serde_json::to_string(&descriptor.challenge).map_err(io::Error::other)?)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit())
                    .spawn()?;
                let mut ready = [0];
                child
                    .stdout
                    .as_mut()
                    .expect("piped stdout")
                    .read_exact(&mut ready)?;
                if ready != [0xA5] || child.try_wait()?.is_some() {
                    return Err(io::Error::other("descendant was not held live"));
                }
                let identity = native::child_identity(&child)?;
                transcript.event(
                    "root-exits-with-live-descendant",
                    None,
                    &serde_json::to_vec(&identity).map_err(io::Error::other)?,
                )?;
                drop(owned_gate);
            }
            // Intentionally relinquish only the root's wait; Job ownership must
            // continue after this process exits. Collection drains descendant I/O.
        }
    }
    transcript.event("finished", None, &descriptor.challenge)?;
    transcript.file.sync_all()?;
    if descriptor.case == Case::EndpointMismatch {
        Ok(42)
    } else {
        Ok(i32::try_from(descriptor.application_status).map_err(io::Error::other)?)
    }
}
