use std::io;
use std::mem::size_of;
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};

use crate::protocol::{Frame, MessageKind, write_frame};

pub fn serve() -> Result<(), String> {
    super::qualification::qualify()?;
    let listener = activated_listener()?;
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
            let code = match handle(&mut stream) {
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

fn handle(stream: &mut UnixStream) -> Result<(), String> {
    let credentials = peer_credentials(stream)?;
    if credentials.uid == u32::MAX {
        return Err("MCSEALED-PIPE-AUTH: invalid peer credentials".to_owned());
    }
    let (request, descriptors) = super::transport::receive(stream)?;
    let response = match request.kind {
        MessageKind::Probe if descriptors.is_empty() => Frame { kind: MessageKind::ProbeReceipt, nonce: request.nonce, attempt_id: request.attempt_id, payload: super::qualification::qualify()?.render().into_bytes() },
        MessageKind::Launch => {
            let launch = crate::request::decode_launch_request(&request.payload).map_err(|error| format!("invalid launch request: {error:?}"))?;
            let facts = super::launch::execute(launch, descriptors, request.attempt_id, credentials.pid, credentials.uid, credentials.gid, peer_groups(credentials.pid)?)?;
            Frame { kind: MessageKind::Terminal, nonce: request.nonce, attempt_id: request.attempt_id, payload: format!("status={}\ntarget-pid={}\nauthorization-offset-millis={}\nmemory-limit-exceeded={}\ndeadline-exceeded={}\nassignment-verified={}\nnamespaces-verified={}\ncredentials-verified={}\ncapabilities-empty={}\ndescriptors-verified={}\ncgroup-view-denied={}\nguardian-ready-before-authorization={}\nfrontend-loss-authority-verified={}\ncgroup-kill-invoked={}\ncgroup-empty={}\ninit-reaped={}\nguardian-reaped={}\nboundary-retired={}\n", facts.child_status, facts.target_pid, facts.authorization_offset_millis, facts.memory_limit_exceeded, facts.deadline_exceeded, facts.assignment_verified, facts.namespaces_verified, facts.credentials_verified, facts.capabilities_empty, facts.descriptors_verified, facts.cgroup_view_denied, facts.guardian_ready_before_authorization, facts.frontend_loss_authority_verified, facts.cgroup_kill_invoked, facts.cgroup_empty, facts.init_reaped, facts.guardian_reaped, facts.boundary_retired).into_bytes() }
        }
        _ => Frame { kind: MessageKind::Rejected, nonce: request.nonce, attempt_id: request.attempt_id, payload: b"MCSEALED-AUTHORIZATION: launch protocol requires the native descriptor transaction".to_vec() },
    };
    write_frame(stream, &response).map_err(|error| error.to_string())
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

use std::os::fd::AsRawFd;
