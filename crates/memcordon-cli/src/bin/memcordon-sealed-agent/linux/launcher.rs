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
    let qualification = super::qualification::qualify()?;
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
            let code = match handle(&mut stream, &qualification) {
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

pub fn probe() -> Result<super::qualification::QualificationReceipt, String> {
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
    let qualification: super::qualification::QualificationReceipt =
        serde_json::from_slice(&response.payload).map_err(|error| error.to_string())?;
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

fn handle(
    stream: &mut UnixStream,
    qualification: &super::qualification::QualificationReceipt,
) -> Result<(), String> {
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
    let (request, descriptors) = super::transport::receive(stream)?;
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
            MessageKind::BrokerProbe if descriptors.is_empty() && request.payload.is_empty() => {
                Frame {
                    kind: MessageKind::ProbeReceipt,
                    nonce: request.nonce,
                    attempt_id: request.attempt_id,
                    payload: qualification.render().into_bytes(),
                }
            }
            MessageKind::BrokerLaunch => launch_response(&request, descriptors, peer)?,
            _ => rejected(
                &request,
                &RejectionV1::request_error(
                    "MCSEALED-LAUNCHER-AUTHORIZATION",
                    "private launcher accepts only bounded broker protocol v2 requests",
                ),
            )?,
        }
    };
    write_frame(stream, &response).map_err(|error| error.to_string())
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
    let mut stream = UnixStream::connect(SOCKET_PATH)
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
    let _ = authenticate_credentials(credentials, LAUNCHER_UNIT)?;
    set_receive_credentials(&stream, false)?;
    Ok(stream)
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

fn nonce() -> Result<[u8; 16], String> {
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
