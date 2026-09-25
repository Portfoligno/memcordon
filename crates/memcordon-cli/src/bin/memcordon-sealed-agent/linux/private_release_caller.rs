//! Closed physical caller-authentication subwitness for the release matrix.
//! The distinct stale-installation-epoch half is not implemented, so this
//! module cannot publish a case result or qualification by itself.

use std::ffi::CString;
use std::fs;
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_codec::hash_bytes;

use crate::protocol::{Frame, MessageKind, read_network_frame, write_network_frame};
use crate::rejection::{RejectionPhaseV1, RejectionV1};

use super::private_attempt::ProcessIdentityV4;
use super::private_release_case::{ReleaseCaseRequestV1, ReleaseStageV1};
use super::private_release_run::ReleaseCandidateRunAuthorityV1;

pub(crate) const SELECTOR: &str = "private_tcp::caller_identity_and_epoch_bound";
const REJECTION_CODE: &str = "MCSEALED-PRIVATE-RELEASE-AUTHORIZATION";
const READY: u8 = 0x71;
const PROCEED: u8 = 0x72;
const SEND_REQUEST: u8 = 0x73;
const SOCKET_HANDOFF: &[u8] = b"connected-public-service-v1";

pub(crate) struct NonrootCallerRejectionV1 {
    pub(crate) caller: ProcessIdentityV4,
    pub(crate) caller_uid: u32,
    pub(crate) caller_gid: u32,
    pub(crate) control_group_gid: u32,
    pub(crate) spoof_result_key: DiagnosticSha256,
    pub(crate) rejection_sha256: DiagnosticSha256,
}

struct ForkedCallerGuard {
    pid: libc::pid_t,
    pidfd: Option<OwnedFd>,
    reaped: bool,
}

impl Drop for ForkedCallerGuard {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        if let Some(pidfd) = &self.pidfd {
            // SAFETY: signal addresses the retained exact child pidfd.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
        } else {
            // SAFETY: before any waitpid this forked child retains its PID,
            // including while zombie, so the number cannot be reused.
            unsafe { libc::kill(self.pid, libc::SIGKILL) };
        }
        let mut status = 0;
        // SAFETY: waitpid targets only this forked child.
        unsafe { libc::waitpid(self.pid, &raw mut status, 0) };
    }
}

/// Real socket admission with kernel SCM credentials. The child has no
/// privileged inherited descriptors and no root UID/GID/capability set; the
/// service must reject before allocating the alternate protected result key.
/// No caller-authored credential field is accepted as the observation.
#[allow(dead_code)] // The full selector awaits a physical stale-epoch replay.
pub(crate) fn observe_nonroot_caller_rejection(
    case: &ReleaseCandidateRunAuthorityV1,
) -> Result<NonrootCallerRejectionV1, String> {
    if unsafe { libc::geteuid() } != 0 || case.selector() != SELECTOR {
        return Err("MCSEALED-PRIVATE-RELEASE: caller witness authority differs".into());
    }
    case.revalidate()?;
    let (uid, gid) = case.target_ids()?;
    if uid == 0 || gid == 0 {
        return Err("MCSEALED-PRIVATE-RELEASE: caller witness needs nonroot identity".into());
    }
    let control_gid = service_group_gid()?;
    let spoof = ReleaseCaseRequestV1 {
        stage: ReleaseStageV1::CandidateCapability,
        selector: SELECTOR,
        challenge: spoof_challenge(&case.challenge_bytes()),
    };
    let key = spoof.result_key();
    case.require_unallocated_result_key(&key)?;
    let nonce = super::launcher::nonce()?;
    let attempt_id = super::launcher::nonce()?;
    if nonce == [0; 16] || attempt_id == [0; 16] {
        return Err("MCSEALED-PRIVATE-RELEASE: caller witness nonce absent".into());
    }
    let request = Frame {
        kind: MessageKind::ReleaseCase,
        nonce,
        attempt_id,
        payload: super::private_release_run::encode_control_request(&spoof)?,
    };
    let (mut parent, child) = UnixStream::pair().map_err(|error| error.to_string())?;
    parent
        .set_read_timeout(Some(Duration::from_secs(10)))
        .and_then(|()| parent.set_write_timeout(Some(Duration::from_secs(10))))
        .map_err(|error| error.to_string())?;
    // SAFETY: the release worker is single-threaded here. The child closes
    // inherited descriptors before dropping identity or opening the socket.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: caller witness fork: {}",
            std::io::Error::last_os_error()
        ));
    }
    if pid == 0 {
        let status = child_exchange(parent, child, uid, gid, control_gid, request);
        // SAFETY: child must not unwind through inherited parent authority.
        unsafe { libc::_exit(if status.is_ok() { 0 } else { 125 }) };
    }
    drop(child);
    let mut child_guard = ForkedCallerGuard {
        pid,
        pidfd: None,
        reaped: false,
    };
    let child_pidfd = pidfd_open(pid)?;
    child_guard.pidfd = Some(child_pidfd);
    let caller = ProcessIdentityV4::observe(
        pid,
        child_guard
            .pidfd
            .as_ref()
            .expect("pidfd was retained before identity observation")
            .as_fd(),
    )?;
    let exchange = (|| -> Result<_, String> {
        let mut marker = [0_u8; 1];
        parent
            .read_exact(&mut marker)
            .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: caller ready: {error}"))?;
        if marker != [READY] {
            return Err("MCSEALED-PRIVATE-RELEASE: caller ready marker differs".into());
        }
        require_nonroot_proc_identity(pid, uid, gid, control_gid)?;
        parent
            .write_all(&[PROCEED])
            .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: caller proceed: {error}"))?;
        let (handoff, mut descriptors) = super::transport::receive_network(&parent)?;
        if handoff.kind != MessageKind::ReleaseCase
            || handoff.nonce != nonce
            || handoff.attempt_id != attempt_id
            || handoff.payload != SOCKET_HANDOFF
            || descriptors.len() != 1
        {
            return Err("MCSEALED-PRIVATE-RELEASE: caller service socket handoff differs".into());
        }
        let mut service: UnixStream = descriptors.pop().expect("exactly one service fd").into();
        service
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|error| error.to_string())?;
        super::launcher::authenticate_control_service(&service)?;
        parent
            .write_all(&[SEND_REQUEST])
            .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: caller send: {error}"))?;
        // The parent reads directly from the authenticated provider socket.
        // Child-authored bytes on the control channel cannot forge denial.
        let response = read_network_frame(&mut service).map_err(|error| error.to_string())?;
        if response.kind != MessageKind::Rejected
            || response.nonce != nonce
            || response.attempt_id != attempt_id
        {
            return Err("MCSEALED-PRIVATE-RELEASE: caller service response differs".into());
        }
        memcordon_core::workload_contract::reject_duplicate_json_keys(&response.payload)?;
        let rejection: RejectionV1 =
            serde_json::from_slice(&response.payload).map_err(|error| error.to_string())?;
        validate_spoof_rejection(&rejection)?;
        Ok(hash_bytes(&response.payload))
    })();
    if exchange.is_err() {
        // SAFETY: pidfd_send_signal addresses only the retained child identity.
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                child_guard
                    .pidfd
                    .as_ref()
                    .expect("pidfd was retained before exchange")
                    .as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
    }
    let mut status = 0;
    // SAFETY: waitpid reaps only this exact forked child.
    let waited = unsafe { libc::waitpid(pid, &raw mut status, 0) };
    if waited == pid {
        child_guard.reaped = true;
    }
    let rejection_sha256 = exchange?;
    if waited != pid || !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        return Err("MCSEALED-PRIVATE-RELEASE: caller child not cleanly reaped".into());
    }
    case.require_unallocated_result_key(&key)?;
    case.revalidate()?;
    Ok(NonrootCallerRejectionV1 {
        caller,
        caller_uid: uid,
        caller_gid: gid,
        control_group_gid: control_gid,
        spoof_result_key: key,
        rejection_sha256,
    })
}

fn validate_spoof_rejection(rejection: &RejectionV1) -> Result<(), String> {
    rejection.validate()?;
    if rejection.code != REJECTION_CODE
        || rejection.phase != RejectionPhaseV1::RequestValidation
        || rejection.target_created
        || rejection.target_released
        || rejection.cleanup.attempted
    {
        return Err("MCSEALED-PRIVATE-RELEASE: caller denial reason differs".into());
    }
    Ok(())
}

fn child_exchange(
    parent: UnixStream,
    child: UnixStream,
    uid: u32,
    gid: u32,
    control_gid: u32,
    request: Frame,
) -> Result<(), String> {
    let child_fd = child.as_raw_fd();
    // SAFETY: dup2 installs the one child control socket in fd 3.
    if unsafe { libc::dup2(child_fd, 3) } != 3 {
        return Err("MCSEALED-PRIVATE-RELEASE: caller control fd differs".into());
    }
    std::mem::forget(parent);
    std::mem::forget(child);
    // SAFETY: all inherited package, pidfd and service descriptors above fd 3
    // are closed before credentials are changed or the public socket opens.
    if unsafe { libc::syscall(libc::SYS_close_range, 4_u32, u32::MAX, 0_u32) } != 0 {
        return Err("MCSEALED-PRIVATE-RELEASE: caller inherited fd closure failed".into());
    }
    // SAFETY: fd 3 now uniquely owns the child side of the control socket.
    let mut control = unsafe { UnixStream::from_raw_fd(3) };
    let groups = [control_gid];
    // SAFETY: the child changes only its own supplementary and real/effective/
    // saved IDs. The fixed group permits connection to the public socket.
    if unsafe { libc::setgroups(groups.len(), groups.as_ptr()) } != 0
        || unsafe { libc::setresgid(gid, gid, gid) } != 0
        || unsafe { libc::setresuid(uid, uid, uid) } != 0
        || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE: caller identity drop failed".into());
    }
    let (mut real_uid, mut effective_uid, mut saved_uid) = (0, 0, 0);
    let (mut real_gid, mut effective_gid, mut saved_gid) = (0, 0, 0);
    // SAFETY: getresuid/getresgid write only initialized scalar slots.
    if unsafe {
        libc::getresuid(
            &raw mut real_uid,
            &raw mut effective_uid,
            &raw mut saved_uid,
        )
    } != 0
        || unsafe {
            libc::getresgid(
                &raw mut real_gid,
                &raw mut effective_gid,
                &raw mut saved_gid,
            )
        } != 0
        || (real_uid, effective_uid, saved_uid) != (uid, uid, uid)
        || (real_gid, effective_gid, saved_gid) != (gid, gid, gid)
    {
        return Err("MCSEALED-PRIVATE-RELEASE: caller dropped identity differs".into());
    }
    control
        .write_all(&[READY])
        .map_err(|error| error.to_string())?;
    let mut proceed = [0_u8; 1];
    control
        .read_exact(&mut proceed)
        .map_err(|error| error.to_string())?;
    if proceed != [PROCEED] {
        return Err("MCSEALED-PRIVATE-RELEASE: caller proceed marker differs".into());
    }
    let service = UnixStream::connect(super::SOCKET_PATH)
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: nonroot socket: {error}"))?;
    super::launcher::authenticate_control_service(&service)?;
    let handoff = Frame {
        kind: MessageKind::ReleaseCase,
        nonce: request.nonce,
        attempt_id: request.attempt_id,
        payload: SOCKET_HANDOFF.to_vec(),
    };
    let mut handoff_bytes = Vec::new();
    write_network_frame(&mut handoff_bytes, &handoff).map_err(|error| error.to_string())?;
    super::transport::send(&control, &handoff_bytes, &[service.as_raw_fd()])?;
    let mut send_request = [0_u8; 1];
    control
        .read_exact(&mut send_request)
        .map_err(|error| error.to_string())?;
    if send_request != [SEND_REQUEST] {
        return Err("MCSEALED-PRIVATE-RELEASE: caller send marker differs".into());
    }
    let mut bytes = Vec::new();
    write_network_frame(&mut bytes, &request).map_err(|error| error.to_string())?;
    super::transport::send(&service, &bytes, &[])
}

fn require_nonroot_proc_identity(
    pid: libc::pid_t,
    uid: u32,
    gid: u32,
    control_gid: u32,
) -> Result<(), String> {
    let status = fs::read_to_string(
        std::path::Path::new("/proc")
            .join(pid.to_string())
            .join("status"),
    )
    .map_err(|error| error.to_string())?;
    validate_proc_identity(&status, uid, gid, control_gid)
}

fn validate_proc_identity(
    status: &str,
    uid: u32,
    gid: u32,
    control_gid: u32,
) -> Result<(), String> {
    let values = |prefix: &str| -> Result<Vec<u32>, String> {
        let line = status
            .lines()
            .find(|line| line.starts_with(prefix))
            .ok_or("MCSEALED-PRIVATE-RELEASE: caller proc field absent")?;
        line.strip_prefix(prefix)
            .ok_or("MCSEALED-PRIVATE-RELEASE: caller proc prefix differs")?
            .split_ascii_whitespace()
            .map(|value| value.parse::<u32>().map_err(|error| error.to_string()))
            .collect()
    };
    let cap_zero = |prefix: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(prefix))
            .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
            == Some(0)
    };
    if values("Uid:")? != [uid; 4]
        || values("Gid:")? != [gid; 4]
        || values("Groups:")? != [control_gid]
        || !cap_zero("CapEff:")
        || !cap_zero("CapPrm:")
        || !cap_zero("CapAmb:")
        || values("NoNewPrivs:")? != [1]
    {
        return Err("MCSEALED-PRIVATE-RELEASE: caller kernel identity differs".into());
    }
    Ok(())
}

fn service_group_gid() -> Result<u32, String> {
    let name = CString::new("memcordon").expect("fixed service group has no NUL");
    // SAFETY: the single-threaded coordinator reads the NSS result before
    // forking, and copies only the scalar group id.
    let group = unsafe { libc::getgrnam(name.as_ptr()) };
    if group.is_null() {
        return Err("MCSEALED-PRIVATE-RELEASE: service group absent".into());
    }
    // SAFETY: nonnull NSS entry remains live until another group lookup.
    let gid = unsafe { (*group).gr_gid };
    if gid == 0 {
        return Err("MCSEALED-PRIVATE-RELEASE: service group is root".into());
    }
    Ok(gid)
}

fn pidfd_open(pid: libc::pid_t) -> Result<OwnedFd, String> {
    // SAFETY: pidfd_open takes one positive forked child PID.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if fd < 0 {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: caller pidfd: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful pidfd_open transfers one descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn spoof_challenge(challenge: &[u8; 32]) -> [u8; 32] {
    let mut bytes =
        Vec::with_capacity(b"memcordon-private-caller-spoof-v1\0".len() + challenge.len());
    bytes.extend_from_slice(b"memcordon-private-caller-spoof-v1\0");
    bytes.extend_from_slice(challenge);
    *hash_bytes(&bytes).bytes()
}

#[cfg(test)]
pub(crate) fn spoof_challenge_for_test(challenge: &[u8; 32]) -> [u8; 32] {
    spoof_challenge(challenge)
}

#[cfg(test)]
pub(crate) fn validate_proc_identity_for_test(
    status: &str,
    uid: u32,
    gid: u32,
    control_gid: u32,
) -> Result<(), String> {
    validate_proc_identity(status, uid, gid, control_gid)
}

#[cfg(test)]
pub(crate) fn validate_spoof_rejection_for_test(rejection: &RejectionV1) -> Result<(), String> {
    validate_spoof_rejection(rejection)
}
