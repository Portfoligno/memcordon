use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::{UnixListener, UnixStream};

use crate::protocol::{Frame, MessageKind, write_frame};
use crate::rejection::RejectionV1;

pub fn serve() -> Result<(), String> {
    super::startup::clear()?;
    configure_subreaper()?;
    let qualification = super::qualification::qualify().map_err(|error| {
        record_startup_failure(super::startup::StartupPhase::Qualification, &error)
    })?;
    let listener = activated_listener().map_err(|error| {
        let error = format!("MCSEALED-SOCKET-ACTIVATION: {error}");
        record_startup_failure(super::startup::StartupPhase::SocketActivation, &error)
    })?;
    super::startup::clear()?;
    loop {
        let (mut stream, _) = match listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                reap_workers();
                wait_for_connection(&listener)?;
                continue;
            }
            Err(error) => return Err(error.to_string()),
        };
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        let worker = unsafe { libc::fork() };
        if worker == -1 {
            return Err(format!(
                "MCSEALED-PROVIDER-WORKER: {}",
                io::Error::last_os_error()
            ));
        }
        if worker == 0 {
            drop(listener);
            if let Err(error) = stream.set_nonblocking(false) {
                eprintln!("sealed provider worker could not configure stream: {error}");
                // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
                unsafe { libc::_exit(125) };
            }
            let code = match handle(&mut stream, &qualification) {
                Ok(()) => 0,
                Err(error) => {
                    eprintln!("sealed provider rejected request: {error}");
                    125
                }
            };
            // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
            unsafe { libc::_exit(code) };
        }
        drop(stream);
        reap_workers();
    }
}

fn configure_subreaper() -> Result<(), String> {
    // SAFETY: prctl receives the documented scalar PR_SET_CHILD_SUBREAPER arguments.
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } == -1 {
        return Err(format!(
            "MCSEALED-PROVIDER-SUBREAPER: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn record_startup_failure(phase: super::startup::StartupPhase, error: &str) -> String {
    match super::startup::record(phase, error) {
        Ok(()) => error.to_owned(),
        Err(record_error) => format!("{error}; {record_error}"),
    }
}

fn reap_workers() {
    loop {
        // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
        let result = unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) };
        if result <= 0 {
            break;
        }
    }
}

fn wait_for_connection(listener: &UnixListener) -> Result<(), String> {
    let mut pollfd = libc::pollfd {
        fd: listener.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let status = unsafe { libc::poll(&raw mut pollfd, 1, 1_000) };
    if status == -1 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error.to_string());
        }
    }
    Ok(())
}

fn activated_listener() -> Result<UnixListener, String> {
    const SYSTEMD_LISTEN_FD: RawFd = 3;
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let listener = unsafe { UnixListener::from_raw_fd(SYSTEMD_LISTEN_FD) };
    listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    Ok(listener)
}

fn handle(
    stream: &mut UnixStream,
    qualification: &super::qualification::QualificationReceipt,
) -> Result<(), String> {
    let credentials = peer_credentials(stream)?;
    if credentials.uid == u32::MAX {
        return Err("MCSEALED-PIPE-AUTH: invalid peer credentials".to_owned());
    }
    let groups = peer_groups(credentials.pid)?;
    authorize_peer(credentials, &groups)?;
    let (request, descriptors) = super::transport::receive(stream)?;
    let response = match request.kind {
        MessageKind::Probe => probe_response(&request, descriptors.len(), qualification)?,
        MessageKind::Launch => {
            match launch_response(request.clone(), descriptors, credentials, groups) {
                Ok(response) => response,
                Err(rejection) => {
                    journal_rejection(request.attempt_id, &rejection);
                    rejected(&request, &rejection)?
                }
            }
        }
        _ => rejected_text(
            &request,
            "MCSEALED-AUTHORIZATION",
            "MCSEALED-AUTHORIZATION: launch protocol requires the native descriptor transaction",
        )?,
    };
    write_frame(stream, &response).map_err(|error| error.to_string())
}

fn probe_response(
    request: &Frame,
    descriptor_count: usize,
    qualification: &super::qualification::QualificationReceipt,
) -> Result<Frame, String> {
    if descriptor_count != 0 {
        return rejected_text(
            request,
            "MCSEALED-PROVIDER-REJECTION",
            "MCSEALED-PROVIDER-REJECTION: probe must not carry descriptors",
        );
    }
    Ok(Frame {
        kind: MessageKind::ProbeReceipt,
        nonce: request.nonce,
        attempt_id: request.attempt_id,
        payload: qualification.render().into_bytes(),
    })
}

#[cfg(feature = "test-support")]
pub fn cached_probe_response_for_test(
    request: &Frame,
    descriptor_count: usize,
    qualification: &super::qualification::QualificationReceipt,
) -> Frame {
    probe_response(request, descriptor_count, qualification)
        .expect("fixed probe rejection must fit the bounded protocol")
}

fn launch_response(
    request: Frame,
    descriptors: Vec<std::os::fd::OwnedFd>,
    credentials: PeerCredentials,
    groups: Vec<libc::gid_t>,
) -> Result<Frame, RejectionV1> {
    let _launch_lease = acquire_lease(libc::LOCK_SH | libc::LOCK_NB)
        .map_err(|error| RejectionV1::request_error("MCSEALED-PACKAGE-LEASE", &error))?;
    let launch = crate::request::decode_launch_request(&request.payload).map_err(|error| {
        RejectionV1::request_error(
            "MCSEALED-LAUNCH-DECODE",
            &format!("invalid launch request: {error:?}"),
        )
    })?;
    let facts = super::launch::execute_typed(
        launch,
        descriptors,
        request.attempt_id,
        credentials.pid,
        credentials.uid,
        credentials.gid,
        groups,
    )?;
    if matches!(
        facts.exec_status,
        super::launch::TargetExecStatus::Failed { .. }
    ) {
        journal_exec_failure(request.attempt_id, &facts);
    }
    Ok(Frame {
        kind: MessageKind::Terminal,
        nonce: request.nonce,
        attempt_id: request.attempt_id,
        payload: terminal_payload(&facts),
    })
}

fn journal_exec_failure(attempt_id: [u8; 16], facts: &super::launch::TerminalFacts) {
    let super::launch::TargetExecStatus::Failed { class, os_code } = facts.exec_status else {
        return;
    };
    let attempt = attempt_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let diagnostic = serde_json::json!({
        "schema_version": 1,
        "event": "sealed-target-exec-failed",
        "attempt_id": attempt,
        "phase": "target-exec",
        "class": class.receipt_name(),
        "os_code": os_code,
        "target_pid": facts.target_pid,
        "target_released": true,
        "spawn_error_reported": facts.spawn_error_reported,
        "workload_empty": facts.cgroup_empty,
        "helpers_reaped": facts.init_reaped && facts.guardian_reaped,
        "boundary_retired": facts.boundary_retired,
    });
    eprintln!("sealed provider target exec failure: {diagnostic}");
}

fn terminal_payload(facts: &super::launch::TerminalFacts) -> Vec<u8> {
    let (exec_status, exec_os_code) = match facts.exec_status {
        super::launch::TargetExecStatus::Succeeded => ("success", "none".to_owned()),
        super::launch::TargetExecStatus::Failed { class, os_code } => {
            (class.receipt_name(), os_code.to_string())
        }
    };
    format!(
        "status={}\nexec-status={}\nexec-os-code={}\nspawn-error-reported={}\ntarget-pid={}\nauthorization-offset-millis={}\nmemory-limit-exceeded={}\ndeadline-exceeded={}\nassignment-verified={}\nnamespaces-verified={}\ncredentials-verified={}\ncapabilities-empty={}\ndescriptors-verified={}\ncgroup-view-denied={}\nguardian-ready-before-authorization={}\nfrontend-loss-authority-verified={}\ncgroup-kill-invoked={}\ncgroup-empty={}\ninit-reaped={}\nguardian-reaped={}\nboundary-retired={}\n",
        facts.child_status,
        exec_status,
        exec_os_code,
        facts.spawn_error_reported,
        facts.target_pid,
        facts.authorization_offset_millis,
        facts.memory_limit_exceeded,
        facts.deadline_exceeded,
        facts.assignment_verified,
        facts.namespaces_verified,
        facts.credentials_verified,
        facts.capabilities_empty,
        facts.descriptors_verified,
        facts.cgroup_view_denied,
        facts.guardian_ready_before_authorization,
        facts.frontend_loss_authority_verified,
        facts.cgroup_kill_invoked,
        facts.cgroup_empty,
        facts.init_reaped,
        facts.guardian_reaped,
        facts.boundary_retired
    )
    .into_bytes()
}

#[cfg(feature = "test-support")]
pub fn terminal_payload_for_test(facts: &super::launch::TerminalFacts) -> Vec<u8> {
    terminal_payload(facts)
}

fn rejected(request: &Frame, rejection: &RejectionV1) -> Result<Frame, String> {
    Ok(Frame {
        kind: MessageKind::Rejected,
        nonce: request.nonce,
        attempt_id: request.attempt_id,
        payload: rejection.encode()?,
    })
}

fn rejected_text(request: &Frame, code: &str, detail: &str) -> Result<Frame, String> {
    rejected(request, &RejectionV1::request_error(code, detail))
}

fn journal_rejection(attempt_id: [u8; 16], rejection: &RejectionV1) {
    let attempt = attempt_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let diagnostic = serde_json::json!({
        "schema_version": 1,
        "event": "sealed-launch-rejected",
        "attempt_id": attempt,
        "code": rejection.code,
        "phase": rejection.phase,
        "target_created": rejection.target_created,
        "target_released": rejection.target_released,
        "cleanup_attempted": rejection.cleanup.attempted,
        "workload_empty": rejection.cleanup.workload_empty,
        "helpers_reaped": rejection.cleanup.helpers_reaped,
        "boundary_retired": rejection.cleanup.sealed_boundary_retired,
    });
    eprintln!("sealed provider launch rejection: {diagnostic}");
}

pub fn acquire_package_lease() -> Result<std::fs::File, String> {
    acquire_lease(libc::LOCK_EX | libc::LOCK_NB)
}

pub fn acquire_qualification_lease() -> Result<std::fs::File, String> {
    acquire_lease(libc::LOCK_EX | libc::LOCK_NB).map_err(|error| {
        format!("MCSEALED-QUALIFICATION-LEASE: provider attempt is active: {error}")
    })
}

fn acquire_lease(operation: libc::c_int) -> Result<std::fs::File, String> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open("/run/memcordon/sealed-package.lock")
        .map_err(|error| format!("MCSEALED-PACKAGE-LEASE: {error}"))?;
    // SAFETY: `file` owns a live descriptor for the duration of the advisory lock; flock has no
    // pointer arguments and reports contention/error without changing Rust ownership.
    if unsafe { libc::flock(file.as_raw_fd(), operation) } == -1 {
        return Err(format!(
            "MCSEALED-PACKAGE-LEASE: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(file)
}

#[derive(Clone, Copy)]
struct PeerCredentials {
    pid: libc::pid_t,
    uid: libc::uid_t,
    gid: libc::gid_t,
}

fn peer_credentials(stream: &UnixStream) -> Result<PeerCredentials, String> {
    let mut value = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = libc::socklen_t::try_from(size_of::<libc::ucred>())
        .map_err(|_| "credential size overflow".to_owned())?;
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let status = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut value).cast(),
            &raw mut length,
        )
    };
    if status == -1 {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok(PeerCredentials {
        pid: value.pid,
        uid: value.uid,
        gid: value.gid,
    })
}

fn peer_groups(pid: libc::pid_t) -> Result<Vec<libc::gid_t>, String> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|error| error.to_string())?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Groups:\t"))
        .ok_or_else(|| "peer groups unavailable".to_owned())?
        .split_ascii_whitespace()
        .map(|value| value.parse().map_err(|_| "invalid peer group".to_owned()))
        .collect()
}

fn authorize_peer(credentials: PeerCredentials, groups: &[libc::gid_t]) -> Result<(), String> {
    let endpoint = std::fs::symlink_metadata(crate::linux::SOCKET_PATH)
        .map_err(|error| format!("MCSEALED-PIPE-AUTH: endpoint metadata unavailable: {error}"))?;
    if !endpoint.file_type().is_socket()
        || endpoint.uid() != 0
        || endpoint.gid() == 0
        || endpoint.mode() & 0o007 != 0
    {
        return Err("MCSEALED-PIPE-AUTH: endpoint authorization identity is unsafe".to_owned());
    }
    if peer_is_authorized(credentials.uid, credentials.gid, groups, endpoint.gid()) {
        Ok(())
    } else {
        Err("MCSEALED-PIPE-AUTH: caller is not in the provider access group".to_owned())
    }
}

fn peer_is_authorized(
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: &[libc::gid_t],
    allowed_gid: libc::gid_t,
) -> bool {
    uid == 0 || gid == allowed_gid || groups.contains(&allowed_gid)
}

#[cfg(feature = "test-support")]
pub fn peer_is_authorized_for_test(
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: &[libc::gid_t],
    allowed_gid: libc::gid_t,
) -> bool {
    peer_is_authorized(uid, gid, groups, allowed_gid)
}
