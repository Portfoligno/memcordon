use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{UnixListener, UnixStream};

use crate::protocol::{Frame, MessageKind, read_frame, write_frame};
use crate::rejection::RejectionV1;
use crate::request::{
    DescriptorPurpose, LaunchBrokerRequestV2, decode_launch_broker_request,
    encode_launch_broker_request,
};

pub const SOCKET_PATH: &str = "/run/memcordon/sealed-launcher.sock";
pub const NETWORK_SOCKET_PATH: &str = "/run/memcordon/sealed-network-launcher.sock";
const NETWORK_LAUNCHER_UNIT: &str = "memcordon-sealed-network-launcher.service";
const CONTROL_UNIT: &str = "memcordon-sealed-agent.service";
const LAUNCHER_UNIT: &str = "memcordon-sealed-launcher.service";
const INSTALLED_BINARY: &str = "/usr/libexec/memcordon-sealed-agent";

struct AllocatedRecordGuard(Option<super::attempt::AttemptRecord>);

impl AllocatedRecordGuard {
    fn take(&mut self) -> super::attempt::AttemptRecord {
        self.0
            .take()
            .expect("allocated broker record remains owned before bootstrap")
    }
}

impl Drop for AllocatedRecordGuard {
    fn drop(&mut self) {
        if let Some(record) = self.0.take() {
            let _ = record.retire();
        }
    }
}

pub fn serve() -> Result<(), String> {
    serve_selected(ListenerMode::Legacy(Box::new(
        super::qualification::observe_readiness()?,
    )))
}

#[cfg(feature = "private-tcp")]
pub fn serve_network() -> Result<(), String> {
    // Current requests authenticate their actual installed runtime and account;
    // no sacrificial qualification report authorizes this transport.
    // SAFETY: geteuid has no pointer or handle preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Err("MCSEALED-PROVIDER-IDENTITY: provider must run as root".into());
    }
    super::runtime_manifest::installed_binding()?;
    super::workload_account::verify()?;
    super::attempt::secure_state_root()?;
    super::cgroup::prepare_private_root()?;
    let unresolved = super::recovery::recover()?;
    super::qualification::require_unambiguous_recovery(&unresolved)?;
    serve_selected(ListenerMode::Current)
}

enum ListenerMode {
    Legacy(Box<super::qualification::ReadinessObservation>),
    #[cfg(feature = "private-tcp")]
    Current,
}

fn serve_selected(mode: ListenerMode) -> Result<(), String> {
    let listener = activated_listener()?;
    loop {
        let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
        // SAFETY: launcher is single-threaded at this bounded per-connection fork point.
        let worker = unsafe { libc::fork() };
        if worker == -1 {
            return Err(format!(
                "MCSEALED-LAUNCHER-WORKER: {}",
                io::Error::last_os_error()
            ));
        }
        if worker == 0 {
            drop(listener);
            let code = match handle(&mut stream, &mode) {
                Ok(()) => 0,
                Err(error) => {
                    eprintln!("sealed launcher rejected request: {error}");
                    125
                }
            };
            // SAFETY: worker owns no Rust runtime state that may be unwound after fork.
            unsafe { libc::_exit(code) };
        }
        drop(stream);
        reap_workers();
    }
}

pub fn probe() -> Result<super::qualification::ReadinessObservation, String> {
    let request = Frame {
        kind: MessageKind::BrokerProbe,
        nonce: nonce()?,
        attempt_id: [0; 16],
        payload: Vec::new(),
    };
    let mut stream = connect_authenticated(request.nonce, request.attempt_id)?;
    write_frame(&mut stream, &request).map_err(|error| error.to_string())?;
    let response = read_frame(&mut stream).map_err(|error| error.to_string())?;
    if response.kind != MessageKind::ProbeReceipt
        || response.nonce != request.nonce
        || response.attempt_id != request.attempt_id
    {
        return Err("MCSEALED-LAUNCHER-SERVICE-AUTHENTICATION: invalid probe response".to_owned());
    }
    let qualification = super::qualification::ReadinessObservation::parse(&response.payload)?;
    if qualification.complete() {
        Ok(qualification)
    } else {
        Err("MCSEALED-LAUNCHER-SERVICE-AUTHENTICATION: incomplete qualification".to_owned())
    }
}

pub fn launch(
    request: &Frame,
    broker_request: &LaunchBrokerRequestV2,
    descriptors: &[RawFd],
) -> Result<Frame, String> {
    if descriptors.len() != 7 {
        return Err(
            "MCSEALED-LAUNCHER-DESCRIPTOR-SET: exact descriptor inventory required".to_owned(),
        );
    }
    let mut stream = connect_authenticated(request.nonce, request.attempt_id)?;
    let broker_frame = Frame {
        kind: MessageKind::BrokerLaunch,
        nonce: request.nonce,
        attempt_id: request.attempt_id,
        payload: encode_launch_broker_request(broker_request)
            .map_err(|error| format!("MCSEALED-LAUNCHER-ENCODE: {error:?}"))?,
    };
    let mut encoded = Vec::new();
    write_frame(&mut encoded, &broker_frame).map_err(|error| error.to_string())?;
    super::transport::send(&stream, &encoded, descriptors)?;
    let response = read_frame(&mut stream).map_err(|error| error.to_string())?;
    if response.nonce != request.nonce
        || response.attempt_id != request.attempt_id
        || !matches!(response.kind, MessageKind::Terminal | MessageKind::Rejected)
    {
        return Err("MCSEALED-LAUNCHER-SERVICE-AUTHENTICATION: invalid launch response".to_owned());
    }
    Ok(response)
}

fn handle(stream: &mut UnixStream, mode: &ListenerMode) -> Result<(), String> {
    let network = !matches!(mode, ListenerMode::Legacy(_));
    let peer = authenticate_peer(stream, CONTROL_UNIT)?;
    // The listener belongs to systemd, so the client authenticates this accepted-stream worker
    // from kernel-supplied message credentials before it sends the broker request.
    let (authentication, authentication_descriptors) = super::transport::receive(stream)?;
    if authentication.kind != MessageKind::BrokerAuthenticate
        || !authentication.payload.is_empty()
        || !authentication_descriptors.is_empty()
    {
        let response = rejected(
            &authentication,
            &RejectionV1::request_error(
                "MCSEALED-LAUNCHER-SERVICE-AUTHENTICATION",
                "launcher authentication request is invalid",
            ),
        )?;
        return write_authentication_response(stream, &response);
    }
    let authenticated = Frame {
        kind: MessageKind::BrokerAuthenticated,
        nonce: authentication.nonce,
        attempt_id: authentication.attempt_id,
        payload: Vec::new(),
    };
    write_authentication_response(stream, &authenticated)?;
    let (request, descriptors, _) = super::transport::receive_public(stream)?;
    let response = if request.nonce != authentication.nonce
        || request.attempt_id != authentication.attempt_id
    {
        rejected(
            &request,
            &RejectionV1::request_error(
                "MCSEALED-LAUNCHER-REQUEST-BINDING",
                "broker request does not match authenticated launcher exchange",
            ),
        )?
    } else {
        match request.kind {
            MessageKind::WorkloadBrokerStart if network && cfg!(feature = "private-tcp") => {
                super::workload_runtime::execute_brokered(
                    stream,
                    &request,
                    descriptors,
                    peer.pid,
                    peer.process_start_time,
                )?
            }
            MessageKind::WorkloadBrokerRecover if network && cfg!(feature = "private-tcp") => {
                super::workload_recovery::recover_brokered(
                    stream,
                    &request,
                    descriptors,
                    peer.pid,
                    peer.process_start_time,
                )?
            }
            MessageKind::WorkloadBrokerAcknowledge if network && cfg!(feature = "private-tcp") => {
                super::workload_recovery::acknowledge_brokered(
                    stream,
                    &request,
                    descriptors,
                    peer.pid,
                    peer.process_start_time,
                )?
            }
            MessageKind::BrokerProbe
                if !network && descriptors.is_empty() && request.payload.is_empty() =>
            {
                Frame {
                    kind: MessageKind::ProbeReceipt,
                    nonce: request.nonce,
                    attempt_id: request.attempt_id,
                    payload: match mode {
                        ListenerMode::Legacy(qualification) => qualification.render().into_bytes(),
                        #[cfg(feature = "private-tcp")]
                        ListenerMode::Current => {
                            unreachable!("current listener rejects legacy probe")
                        }
                    },
                }
            }
            MessageKind::BrokerLaunch if !network => launch_response(&request, descriptors, peer)?,
            _ => rejected(
                &request,
                &RejectionV1::request_error(
                    "MCSEALED-LAUNCHER-AUTHORIZATION",
                    "private launcher accepts only bounded broker protocol v2 requests",
                ),
            )?,
        }
    };
    super::workload_runtime::write_frame_until(
        stream,
        &response,
        std::time::Instant::now() + std::time::Duration::from_secs(1),
    )
}

fn launch_response(
    request: &Frame,
    descriptors: Vec<OwnedFd>,
    peer: AuthenticatedPeer,
) -> Result<Frame, String> {
    let broker = match decode_launch_broker_request(&request.payload) {
        Ok(broker) => broker,
        Err(error) => {
            return rejected(
                request,
                &RejectionV1::request_error(
                    "MCSEALED-LAUNCHER-DECODE",
                    &format!("invalid broker request: {error:?}"),
                ),
            );
        }
    };
    if broker.attempt_id != request.attempt_id
        || broker.control_process_id != peer.pid
        || broker.control_process_start_time != peer.process_start_time
    {
        return rejected(
            request,
            &RejectionV1::request_error(
                "MCSEALED-LAUNCHER-REQUEST-BINDING",
                "broker request does not match authenticated control peer or frame",
            ),
        );
    }
    let record_identity = broker
        .record_identity
        .attempt_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let record_digest = broker
        .record_identity
        .caller_envelope_digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let mut record = AllocatedRecordGuard(Some(super::attempt::AttemptRecord::adopt_v2(
        record_identity,
        broker.caller.pid,
        record_digest,
    )?));
    if descriptors.len() != broker.descriptor_manifest.len() || descriptors.len() != 7 {
        return rejected(
            request,
            &RejectionV1::request_error(
                "MCSEALED-LAUNCHER-DESCRIPTOR-SET",
                "broker descriptor manifest does not match transferred descriptors",
            ),
        );
    }
    super::envelope::verify_live(&broker.caller)?;
    if !super::envelope::descriptor_matches(
        descriptors[0].as_fd(),
        broker.caller.current_directory_identity,
    )? || !super::envelope::namespace_descriptor_matches(
        descriptors[5].as_fd(),
        broker.caller.mount_namespace_identity,
    )? || !super::envelope::descriptor_matches(
        descriptors[6].as_fd(),
        broker.caller.root_identity,
    )? {
        return rejected(
            request,
            &RejectionV1::request_error(
                "MCSEALED-LAUNCHER-DESCRIPTOR-IDENTITY",
                "caller descriptor identity changed before launch",
            ),
        );
    }
    let mut descriptors = descriptors.into_iter();
    let workload = descriptors.by_ref().take(5).collect::<Vec<_>>();
    let mount_namespace = descriptors
        .next()
        .ok_or_else(|| "launcher mount namespace descriptor missing".to_owned())?;
    let root = descriptors
        .next()
        .ok_or_else(|| "launcher root descriptor missing".to_owned())?;
    if descriptors.next().is_some() {
        return Err("launcher descriptor inventory exceeded manifest".to_owned());
    }
    match super::launch::execute_brokered_typed(
        broker.launch,
        workload,
        request.attempt_id,
        broker.caller,
        mount_namespace,
        root,
        record.take(),
    ) {
        Ok(facts) => Ok(Frame {
            kind: MessageKind::Terminal,
            nonce: request.nonce,
            attempt_id: request.attempt_id,
            payload: super::service::terminal_payload(&facts),
        }),
        Err(rejection) => rejected(request, &rejection),
    }
}

fn rejected(request: &Frame, rejection: &RejectionV1) -> Result<Frame, String> {
    Ok(Frame {
        kind: MessageKind::Rejected,
        nonce: request.nonce,
        attempt_id: request.attempt_id,
        payload: rejection.encode()?,
    })
}

fn connect_authenticated(nonce: [u8; 16], attempt_id: [u8; 16]) -> Result<UnixStream, String> {
    connect_selected(SOCKET_PATH, LAUNCHER_UNIT, nonce, attempt_id)
}

pub(super) fn connect_workload(
    attempt: [u8; 16],
    challenge: [u8; 16],
) -> Result<UnixStream, String> {
    connect_workload_until(
        attempt,
        challenge,
        std::time::Instant::now() + std::time::Duration::from_secs(30),
    )
}
pub(super) fn connect_workload_until(
    attempt: [u8; 16],
    challenge: [u8; 16],
    cutoff: std::time::Instant,
) -> Result<UnixStream, String> {
    use std::time::{Duration, Instant};
    let mut stream = loop {
        if Instant::now() >= cutoff {
            return Err("original native broker connection cutoff expired".into());
        }
        // SAFETY: scalar socket arguments request a newly owned nonblocking Unix stream.
        let raw = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        // SAFETY: the successful socket result transfers unique ownership.
        let stream = unsafe { UnixStream::from_raw_fd(raw) };
        // SAFETY: zero is a valid initial representation of sockaddr_un before fields are set.
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let path = std::ffi::CString::new(NETWORK_SOCKET_PATH).expect("fixed native socket path");
        if path.as_bytes_with_nul().len() > address.sun_path.len() {
            return Err("fixed native socket path exceeds ABI bound".into());
        }
        for (target, byte) in address.sun_path.iter_mut().zip(path.as_bytes_with_nul()) {
            *target = *byte as libc::c_char;
        }
        // SAFETY: initialized sockaddr_un and its exact ABI length remain live through connect.
        let connected = unsafe {
            libc::connect(
                stream.as_raw_fd(),
                (&address as *const libc::sockaddr_un).cast(),
                std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
            )
        };
        if connected == 0 {
            break stream;
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EAGAIN) {
            std::thread::sleep(
                cutoff
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(10)),
            );
            continue;
        }
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(error.to_string());
        }
        loop {
            let remaining = cutoff.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("original native broker connect cutoff expired".into());
            }
            let mut poll = libc::pollfd {
                fd: stream.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            // SAFETY: one initialized poll record borrows the original live socket for a bounded wait.
            let result = unsafe {
                libc::poll(
                    &mut poll,
                    1,
                    i32::try_from(remaining.as_millis())
                        .unwrap_or(i32::MAX)
                        .min(100),
                )
            };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error.to_string());
            }
            if result == 0 {
                continue;
            }
            let mut native_error = 0_i32;
            let mut length = std::mem::size_of::<i32>() as libc::socklen_t;
            // SAFETY: exact initialized SO_ERROR output word and length are writable for the call.
            if unsafe {
                libc::getsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    (&mut native_error as *mut i32).cast(),
                    &mut length,
                )
            } != 0
            {
                return Err(io::Error::last_os_error().to_string());
            }
            if native_error != 0 {
                return Err(io::Error::from_raw_os_error(native_error).to_string());
            }
            break;
        }
        break stream;
    };
    stream.set_nonblocking(false).map_err(|e| e.to_string())?;
    let remaining = cutoff.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err("original broker authentication cutoff expired".into());
    }
    stream
        .set_read_timeout(Some(remaining))
        .and_then(|_| stream.set_write_timeout(Some(remaining)))
        .map_err(|e| e.to_string())?;
    set_receive_credentials(&stream, true)?;
    let authentication = Frame {
        kind: MessageKind::BrokerAuthenticate,
        nonce: challenge,
        attempt_id: attempt,
        payload: Vec::new(),
    };
    super::workload_runtime::write_frame_until(&mut stream, &authentication, cutoff)?;
    let (response, descriptors, credentials) =
        super::transport::receive_authentication_until(&stream, cutoff)?;
    if response.kind != MessageKind::BrokerAuthenticated
        || response.nonce != challenge
        || response.attempt_id != attempt
        || !response.payload.is_empty()
        || !descriptors.is_empty()
    {
        return Err("invalid bounded native broker authentication response".into());
    }
    let credentials = credentials.ok_or("native broker authentication credentials missing")?;
    let _ = authenticate_credentials(credentials, NETWORK_LAUNCHER_UNIT)?;
    if Instant::now() >= cutoff {
        return Err(
            "original broker authentication cutoff expired after native identity verification"
                .into(),
        );
    }
    set_receive_credentials(&stream, false)?;
    Ok(stream)
}

fn connect_selected(
    path: &str,
    unit: &str,
    nonce: [u8; 16],
    attempt_id: [u8; 16],
) -> Result<UnixStream, String> {
    let mut stream = UnixStream::connect(path)
        .map_err(|error| format!("MCSEALED-LAUNCHER-CONNECTION: {error}"))?;
    // SO_PEERCRED identifies systemd for an activation-owned listener. SCM_CREDENTIALS on the
    // response instead identifies the launcher worker that holds this accepted connection.
    set_receive_credentials(&stream, true)?;
    let authentication = Frame {
        kind: MessageKind::BrokerAuthenticate,
        nonce,
        attempt_id,
        payload: Vec::new(),
    };
    write_frame(&mut stream, &authentication).map_err(|error| error.to_string())?;
    let credentials = receive_authentication_response(&stream, &authentication)?;
    let _ = authenticate_credentials(credentials, unit)?;
    set_receive_credentials(&stream, false)?;
    Ok(stream)
}

pub(super) fn check_network_endpoint() -> Result<(), String> {
    let stream = connect_selected(
        NETWORK_SOCKET_PATH,
        NETWORK_LAUNCHER_UNIT,
        nonce()?,
        [0; 16],
    )?;
    drop(stream);
    Ok(())
}

fn write_authentication_response(stream: &UnixStream, response: &Frame) -> Result<(), String> {
    let mut encoded = Vec::new();
    write_frame(&mut encoded, response).map_err(|error| error.to_string())?;
    // One sendmsg transaction keeps the kernel credential record aligned with the complete frame.
    super::transport::send(stream, &encoded, &[])
}

fn receive_authentication_response(
    stream: &UnixStream,
    request: &Frame,
) -> Result<libc::ucred, String> {
    let (response, descriptors, credentials) = super::transport::receive_with_credentials(stream)?;
    if response.kind != MessageKind::BrokerAuthenticated
        || response.nonce != request.nonce
        || response.attempt_id != request.attempt_id
        || !response.payload.is_empty()
        || !descriptors.is_empty()
    {
        return Err(
            "MCSEALED-LAUNCHER-SERVICE-AUTHENTICATION: invalid authentication response".to_owned(),
        );
    }
    credentials.ok_or_else(|| {
        "MCSEALED-LAUNCHER-SERVICE-AUTHENTICATION: authenticated credentials missing".to_owned()
    })
}

fn set_receive_credentials(stream: &UnixStream, enabled: bool) -> Result<(), String> {
    let value: libc::c_int = i32::from(enabled);
    // SAFETY: setsockopt reads one initialized integer through a live socket descriptor.
    let status = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            (&raw const value).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if status == -1 {
        return Err(format!(
            "MCSEALED-LAUNCHER-SERVICE-AUTHENTICATION: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct AuthenticatedPeer {
    pid: libc::pid_t,
    process_start_time: u64,
}

fn authenticate_peer(
    stream: &UnixStream,
    expected_unit: &str,
) -> Result<AuthenticatedPeer, String> {
    let credentials = peer_credentials(stream)?;
    authenticate_credentials(credentials, expected_unit)
}

pub(crate) fn authenticate_control_service(stream: &UnixStream) -> Result<(), String> {
    authenticate_peer(stream, CONTROL_UNIT).map(|_| ())
}

fn authenticate_credentials(
    credentials: libc::ucred,
    expected_unit: &str,
) -> Result<AuthenticatedPeer, String> {
    if credentials.uid != 0 || credentials.pid <= 0 {
        return Err("MCSEALED-LAUNCHER-SERVICE-AUTHENTICATION: peer uid is not root".to_owned());
    }
    let process = std::path::Path::new("/proc").join(credentials.pid.to_string());
    let executable = std::fs::metadata(process.join("exe"))
        .map_err(|error| format!("MCSEALED-LAUNCHER-SERVICE-AUTHENTICATION: {error}"))?;
    let installed = std::fs::metadata(INSTALLED_BINARY)
        .map_err(|error| format!("MCSEALED-LAUNCHER-SERVICE-AUTHENTICATION: {error}"))?;
    if executable.dev() != installed.dev() || executable.ino() != installed.ino() {
        return Err(
            "MCSEALED-LAUNCHER-SERVICE-AUTHENTICATION: executable identity mismatch".to_owned(),
        );
    }
    let cgroup = std::fs::read_to_string(process.join("cgroup"))
        .map_err(|error| format!("MCSEALED-LAUNCHER-SERVICE-AUTHENTICATION: {error}"))?;
    let expected_unit = std::ffi::OsStr::new(expected_unit);
    let matches_unit = cgroup.lines().any(|line| {
        line.split_once("::").is_some_and(|(_, path)| {
            std::path::Path::new(path)
                .components()
                .any(|component| component.as_os_str() == expected_unit)
        })
    });
    if !matches_unit {
        return Err("MCSEALED-LAUNCHER-SERVICE-AUTHENTICATION: unit identity mismatch".to_owned());
    }
    let process_start_time = super::envelope::process_start_time(credentials.pid)?;
    Ok(AuthenticatedPeer {
        pid: credentials.pid,
        process_start_time,
    })
}

#[cfg(feature = "test-support")]
pub fn set_receive_credentials_for_test(stream: &UnixStream, enabled: bool) -> Result<(), String> {
    set_receive_credentials(stream, enabled)
}

#[cfg(feature = "test-support")]
pub fn write_authentication_response_for_test(
    stream: &UnixStream,
    response: &Frame,
) -> Result<(), String> {
    write_authentication_response(stream, response)
}

#[cfg(feature = "test-support")]
pub fn receive_authentication_response_for_test(
    stream: &UnixStream,
    request: &Frame,
) -> Result<libc::pid_t, String> {
    receive_authentication_response(stream, request).map(|credentials| credentials.pid)
}

#[cfg(feature = "test-support")]
pub fn socket_peer_pid_for_test(stream: &UnixStream) -> Result<libc::pid_t, String> {
    peer_credentials(stream).map(|credentials| credentials.pid)
}

fn peer_credentials(stream: &UnixStream) -> Result<libc::ucred, String> {
    let mut value = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut length = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>())
        .map_err(|_| "credential size overflow".to_owned())?;
    // SAFETY: SO_PEERCRED writes a libc::ucred into live initialized storage.
    let status = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut value).cast(),
            &raw mut length,
        )
    };
    if status == -1 || length as usize != std::mem::size_of::<libc::ucred>() {
        return Err(format!(
            "MCSEALED-LAUNCHER-SERVICE-AUTHENTICATION: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(value)
}

fn activated_listener() -> Result<UnixListener, String> {
    const SYSTEMD_LISTEN_FD: RawFd = 3;
    // SAFETY: systemd socket activation transfers ownership of descriptor 3 to this process.
    Ok(unsafe { UnixListener::from_raw_fd(SYSTEMD_LISTEN_FD) })
}

fn reap_workers() {
    loop {
        // SAFETY: WNOHANG reaps any completed direct launcher worker without blocking.
        if unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) } <= 0 {
            break;
        }
    }
}

pub(crate) fn nonce() -> Result<[u8; 16], String> {
    let mut nonce = [0_u8; 16];
    std::io::Read::read_exact(
        &mut std::fs::File::open("/dev/urandom").map_err(|error| error.to_string())?,
        &mut nonce,
    )
    .map_err(|error| error.to_string())?;
    Ok(nonce)
}

pub fn broker_descriptor_manifest() -> Vec<DescriptorPurpose> {
    vec![
        DescriptorPurpose::CurrentDirectory,
        DescriptorPurpose::Stdin,
        DescriptorPurpose::Stdout,
        DescriptorPurpose::Stderr,
        DescriptorPurpose::FrontendLiveness,
        DescriptorPurpose::CallerMountNamespace,
        DescriptorPurpose::CallerRoot,
    ]
}
