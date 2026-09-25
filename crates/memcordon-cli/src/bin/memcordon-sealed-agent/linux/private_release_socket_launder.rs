//! Fixed release-only pre-filter socket laundering probe. It is deliberately
//! unavailable to production grants and remains unrouted until owner/raw
//! and detached evidence join the native denial and retirement.

use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use memcordon_core::DiagnosticSha256;
use serde::{Deserialize, Serialize};

use super::private_attempt::ProcessIdentityV4;

pub(crate) const SELECTOR: &str = "private_tcp::scm_rights_and_precreated_socket_denied";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrecreatedSocketGatedWitnessV1 {
    pub(crate) schema_version: u8,
    pub(crate) target: ProcessIdentityV4,
    pub(crate) network_namespace_inode: u64,
    pub(crate) first_socket_device: u64,
    pub(crate) first_socket_inode: u64,
    pub(crate) second_socket_device: u64,
    pub(crate) second_socket_inode: u64,
    pub(crate) filter_sha256: DiagnosticSha256,
    pub(crate) sendmsg_errno: i32,
}

pub(crate) fn expected_target_suffix() -> [u8; 4] {
    super::private_release_descriptors::expected_projection()
}

/// The pinned image independently confirms no exceptional socket survived
/// exec, then performs the same real TCP listener/client/competitor workload.
pub(crate) fn run_target(challenge: &[u8; 32]) -> Result<[u8; 4], String> {
    let projection = super::private_release_descriptors::observe_target_projection()?;
    if projection != expected_target_suffix() {
        return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: precreated socket leaked".into());
    }
    super::private_qualification::tcp_listener_client_competitor(challenge)?;
    Ok(projection)
}

pub(crate) fn precreate_pair() -> Result<[OwnedFd; 2], String> {
    let mut descriptors = [-1_i32; 2];
    // SAFETY: socketpair writes exactly two descriptors on success. This runs
    // only in the sacrificial target after fd0–4 sealing and before seccomp.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
            descriptors.as_mut_ptr(),
        )
    } != 0
    {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: pre-filter socketpair: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful socketpair transferred two unique descriptors.
    let pair = unsafe {
        [
            OwnedFd::from_raw_fd(descriptors[0]),
            OwnedFd::from_raw_fd(descriptors[1]),
        ]
    };
    if pair[0].as_raw_fd() != 5 || pair[1].as_raw_fd() != 6 {
        return Err("MCSEALED-PRIVATE-RELEASE: pre-filter socket slots differ".into());
    }
    Ok(pair)
}

pub(crate) fn observe_scm_rights_denied(pair: &[OwnedFd; 2]) -> Result<i32, String> {
    let mut byte = [0x51_u8; 1];
    let mut iovec = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: byte.len(),
    };
    // SAFETY: CMSG_SPACE is computed from one native descriptor value.
    let control_len = unsafe { libc::CMSG_SPACE(size_of::<libc::c_int>() as u32) } as usize;
    let mut control = vec![0_u8; control_len];
    // SAFETY: zero initialization is valid for msghdr; all used pointers and
    // lengths are set to live owned storage before the syscall.
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &raw mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();
    // SAFETY: control is sized for one SCM_RIGHTS descriptor and remains live.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        if header.is_null() {
            return Err("MCSEALED-PRIVATE-RELEASE: precreated ancillary header absent".into());
        }
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(size_of::<libc::c_int>() as u32) as usize;
        *libc::CMSG_DATA(header).cast::<libc::c_int>() = 0;
    }
    // SAFETY: sendmsg borrows a valid precreated socket endpoint, iovec, and
    // ancillary descriptor. Successful laundering is rejected immediately.
    let result =
        unsafe { libc::sendmsg(pair[0].as_raw_fd(), &raw const message, libc::MSG_NOSIGNAL) };
    let errno = std::io::Error::last_os_error().raw_os_error();
    if result != -1 || errno != Some(libc::EPERM) {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: precreated SCM_RIGHTS sendmsg result {result} errno {errno:?} differs"
        ));
    }
    Ok(libc::EPERM)
}
