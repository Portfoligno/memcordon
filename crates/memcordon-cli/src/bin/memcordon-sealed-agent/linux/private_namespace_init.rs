//! Unrouted V2 namespace-init startup channel for the private TCP profile.
//!
//! A startup record is evidence from the exact cloned init, not permission to
//! release the gated target. The provider must also pin/read back the NEWNET
//! object and complete its checkpoint and lifecycle obligations.

use std::fs::File;
use std::io::Write;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Instant;

use crate::request::NamespaceIdentity;

use super::network_profile::{PrivateNetworkSetup, PrivatePortPolicy};
use super::private_target::{
    MAX_FAILURE_DETAIL_BYTES, PrivateGatedTarget, PrivateNetworkNamespaceOwner,
    pin_private_network_namespace, prepare_private_namespace_before_target_fork,
};

const VERSION: u8 = 2;
const READY: u8 = 1;
const FAILURE: u8 = 2;
const READY_LENGTH: usize = 33;
const FAILURE_HEADER_LENGTH: usize = 6;
const MAX_PACKET_LENGTH: usize = FAILURE_HEADER_LENGTH + MAX_FAILURE_DETAIL_BYTES;

#[repr(align(16))]
struct AlignedAncillary<const N: usize>([u8; N]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivateNamespaceStartupPhase {
    NamespaceSetup,
    TargetFork,
}

impl PrivateNamespaceStartupPhase {
    const fn code(self) -> u8 {
        match self {
            Self::NamespaceSetup => 1,
            Self::TargetFork => 2,
        }
    }

    fn from_code(code: u8) -> Result<Self, String> {
        match code {
            1 => Ok(Self::NamespaceSetup),
            2 => Ok(Self::TargetFork),
            _ => Err("MCSEALED-PRIVATE-INIT: unknown failure phase".into()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrivateNamespaceStartupObservation {
    TargetForked {
        namespace: NamespaceIdentity,
        network: PrivateNetworkSetup,
    },
    Failed {
        phase: PrivateNamespaceStartupPhase,
        detail: String,
    },
}

/// A pidfd received with the authenticated init packet is the only accepted
/// target handle. The numeric PID is read from the kernel's pidfd metadata in
/// the provider namespace; an init-supplied PID is never executable authority.
#[derive(Debug)]
pub struct AuthenticatedPrivateNamespaceStartup {
    pub observation: PrivateNamespaceStartupObservation,
    pub target_pidfd: Option<OwnedFd>,
}

impl AuthenticatedPrivateNamespaceStartup {
    pub fn target_host_pid(&self) -> Result<libc::pid_t, String> {
        let pidfd = self
            .target_pidfd
            .as_ref()
            .ok_or("MCSEALED-PRIVATE-INIT: target pidfd absent")?;
        let path = std::path::Path::new("/proc/self/fdinfo").join(pidfd.as_raw_fd().to_string());
        let contents = std::fs::read_to_string(path)
            .map_err(|error| format!("MCSEALED-PRIVATE-INIT: pidfd readback: {error}"))?;
        let mut pid = contents
            .lines()
            .filter_map(|line| line.strip_prefix("Pid:"))
            .map(str::trim);
        let value = pid
            .next()
            .ok_or("MCSEALED-PRIVATE-INIT: pidfd has no target PID")?;
        if pid.next().is_some() {
            return Err("MCSEALED-PRIVATE-INIT: ambiguous pidfd target PID".into());
        }
        let parsed = value
            .parse::<libc::pid_t>()
            .map_err(|_| "MCSEALED-PRIVATE-INIT: invalid pidfd target PID")?;
        if parsed <= 0 {
            return Err("MCSEALED-PRIVATE-INIT: pidfd target not visible to provider".into());
        }
        let mut pollfd = libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll borrows one initialized pidfd record without waiting.
        if unsafe { libc::poll(&raw mut pollfd, 1, 0) } != 0 || pollfd.revents != 0 {
            return Err("MCSEALED-PRIVATE-INIT: target exited before readback".into());
        }
        Ok(parsed)
    }
}

pub struct PrivateNamespaceStartupReadback {
    pub network: PrivateNetworkSetup,
    pub namespace_owner: PrivateNetworkNamespaceOwner,
    pub target_pid: libc::pid_t,
    pub target_pidfd: OwnedFd,
}

/// Provider-side readback after a private clone but before any authorization.
/// The original native failure detail is returned on setup failure; success
/// requires the exact init sender, a live init pidfd, a live transferred target
/// pidfd, and matching pinned init/target network namespace objects.
#[allow(clippy::too_many_arguments)]
pub fn observe_private_namespace_startup(
    provider: &PrivateNamespaceStartupProvider,
    init_pid: libc::pid_t,
    init_pidfd: BorrowedFd<'_>,
    caller_namespace: NamespaceIdentity,
    provider_namespace: NamespaceIdentity,
    deadline: Instant,
) -> Result<PrivateNamespaceStartupReadback, String> {
    let received = provider.receive(init_pid, deadline)?;
    if let PrivateNamespaceStartupObservation::Failed { phase, detail } = &received.observation {
        return Err(format!("MCSEALED-PRIVATE-INIT: {phase:?} failed: {detail}"));
    }
    let owner =
        pin_private_network_namespace(init_pid, init_pidfd, caller_namespace, provider_namespace)?;
    received.observation.validate_ready(&owner)?;
    let target_pid = received.target_host_pid()?;
    let target_process = Path::new("/proc").join(target_pid.to_string());
    let target_namespace_path = target_process.join("ns/net");
    let metadata = std::fs::metadata(target_namespace_path)
        .map_err(|error| format!("MCSEALED-PRIVATE-INIT: target NEWNET readback: {error}"))?;
    let target_namespace = NamespaceIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    if target_namespace != owner.identity() {
        return Err("MCSEALED-PRIVATE-INIT: target NEWNET differs from pinned init".into());
    }
    let status = std::fs::read_to_string(target_process.join("status"))
        .map_err(|error| format!("MCSEALED-PRIVATE-INIT: target parent readback: {error}"))?;
    if parse_target_parent_pid(&status)? != init_pid {
        return Err("MCSEALED-PRIVATE-INIT: target is not child of cloned init".into());
    }
    if received.target_host_pid()? != target_pid {
        return Err("MCSEALED-PRIVATE-INIT: target pidfd changed during readback".into());
    }
    let target_pidfd = received
        .target_pidfd
        .ok_or("MCSEALED-PRIVATE-INIT: target pidfd absent")?;
    let network = match received.observation {
        PrivateNamespaceStartupObservation::TargetForked { network, .. } => network,
        PrivateNamespaceStartupObservation::Failed { .. } => unreachable!("failure returned above"),
    };
    Ok(PrivateNamespaceStartupReadback {
        network,
        namespace_owner: owner,
        target_pid,
        target_pidfd,
    })
}

pub fn parse_target_parent_pid(status: &str) -> Result<libc::pid_t, String> {
    let mut parent = status
        .lines()
        .filter_map(|line| line.strip_prefix("PPid:"))
        .map(str::trim);
    let parent_pid = parent
        .next()
        .ok_or("MCSEALED-PRIVATE-INIT: target parent absent")?
        .parse::<libc::pid_t>()
        .map_err(|_| "MCSEALED-PRIVATE-INIT: invalid target parent")?;
    if parent.next().is_some() || parent_pid <= 0 {
        return Err("MCSEALED-PRIVATE-INIT: ambiguous or invalid target parent".into());
    }
    Ok(parent_pid)
}

impl PrivateNamespaceStartupObservation {
    /// The init's topology report must agree with the separately pinned
    /// namespace object. This check does not replace provider-native topology
    /// inspection or constitute a release checkpoint.
    pub fn validate_ready(&self, owner: &PrivateNetworkNamespaceOwner) -> Result<(), String> {
        let Self::TargetForked { namespace, network } = self else {
            return Err("MCSEALED-PRIVATE-INIT: startup did not fork a target".into());
        };
        if *namespace != owner.identity()
            || network.port_policy != PrivatePortPolicy::REQUIRED
            || network.loopback_index <= 0
            || network.address_count != 1
            || !(1..=32).contains(&network.route_count)
        {
            return Err("MCSEALED-PRIVATE-INIT: namespace or topology readback mismatch".into());
        }
        Ok(())
    }
}

pub fn encode_private_namespace_startup(
    observation: &PrivateNamespaceStartupObservation,
) -> Result<Vec<u8>, String> {
    match observation {
        PrivateNamespaceStartupObservation::TargetForked { namespace, network } => {
            if network.port_policy != PrivatePortPolicy::REQUIRED
                || network.loopback_index <= 0
                || network.address_count != 1
                || !(1..=32).contains(&network.route_count)
            {
                return Err("MCSEALED-PRIVATE-INIT: invalid native topology report".into());
            }
            let mut packet = Vec::with_capacity(READY_LENGTH);
            packet.extend_from_slice(&[VERSION, READY, 0, 0]);
            packet.extend_from_slice(&namespace.device.to_be_bytes());
            packet.extend_from_slice(&namespace.inode.to_be_bytes());
            packet.extend_from_slice(&network.loopback_index.to_be_bytes());
            packet.push(u8::try_from(network.address_count).expect("bounded address count"));
            packet.push(u8::try_from(network.route_count).expect("bounded route count"));
            packet.extend_from_slice(&network.port_policy.unprivileged_port_start.to_be_bytes());
            packet.extend_from_slice(&network.port_policy.local_port_range.0.to_be_bytes());
            packet.extend_from_slice(&network.port_policy.local_port_range.1.to_be_bytes());
            packet.push(u8::from(network.port_policy.reserved_ports_empty));
            Ok(packet)
        }
        PrivateNamespaceStartupObservation::Failed { phase, detail } => {
            let detail = if detail.is_empty() {
                "native namespace-init failure detail unavailable"
            } else if detail.len() > MAX_FAILURE_DETAIL_BYTES {
                "native namespace-init failure detail exceeded protocol bound"
            } else {
                detail
            };
            let mut packet = Vec::with_capacity(FAILURE_HEADER_LENGTH + detail.len());
            packet.extend_from_slice(&[VERSION, FAILURE, phase.code(), 0]);
            packet.extend_from_slice(
                &u16::try_from(detail.len())
                    .expect("bounded detail fits u16")
                    .to_be_bytes(),
            );
            packet.extend_from_slice(detail.as_bytes());
            Ok(packet)
        }
    }
}

pub fn decode_private_namespace_startup(
    packet: &[u8],
) -> Result<PrivateNamespaceStartupObservation, String> {
    if packet.len() < 4 || packet[0] != VERSION || packet[3] != 0 {
        return Err("MCSEALED-PRIVATE-INIT: invalid record header".into());
    }
    match packet[1] {
        READY if packet.len() == READY_LENGTH && packet[2] == 0 => {
            let namespace = NamespaceIdentity {
                device: u64::from_be_bytes(packet[4..12].try_into().expect("fixed packet")),
                inode: u64::from_be_bytes(packet[12..20].try_into().expect("fixed packet")),
            };
            let network = PrivateNetworkSetup {
                loopback_index: i32::from_be_bytes(
                    packet[20..24].try_into().expect("fixed packet"),
                ),
                address_count: packet[24] as usize,
                route_count: packet[25] as usize,
                port_policy: PrivatePortPolicy {
                    unprivileged_port_start: u16::from_be_bytes([packet[26], packet[27]]),
                    local_port_range: (
                        u16::from_be_bytes([packet[28], packet[29]]),
                        u16::from_be_bytes([packet[30], packet[31]]),
                    ),
                    reserved_ports_empty: packet[32] == 1,
                },
            };
            if packet[32] > 1
                || network.port_policy != PrivatePortPolicy::REQUIRED
                || network.loopback_index <= 0
                || network.address_count != 1
                || !(1..=32).contains(&network.route_count)
            {
                return Err("MCSEALED-PRIVATE-INIT: invalid network readback".into());
            }
            Ok(PrivateNamespaceStartupObservation::TargetForked { namespace, network })
        }
        FAILURE if packet.len() >= FAILURE_HEADER_LENGTH => {
            let phase = PrivateNamespaceStartupPhase::from_code(packet[2])?;
            let length = u16::from_be_bytes([packet[4], packet[5]]) as usize;
            if length == 0
                || length > MAX_FAILURE_DETAIL_BYTES
                || packet.len() != FAILURE_HEADER_LENGTH + length
            {
                return Err("MCSEALED-PRIVATE-INIT: invalid failure length".into());
            }
            let detail = std::str::from_utf8(&packet[FAILURE_HEADER_LENGTH..])
                .map_err(|_| "MCSEALED-PRIVATE-INIT: invalid failure encoding")?;
            Ok(PrivateNamespaceStartupObservation::Failed {
                phase,
                detail: detail.to_owned(),
            })
        }
        _ => Err("MCSEALED-PRIVATE-INIT: invalid record kind or length".into()),
    }
}

pub struct PrivateNamespaceStartupProvider(File);
pub struct PrivateNamespaceStartupInit(File);

pub fn private_namespace_startup_channel()
-> Result<(PrivateNamespaceStartupProvider, PrivateNamespaceStartupInit), String> {
    let mut fds = [-1_i32; 2];
    // SAFETY: socketpair initializes exactly two descriptors on success.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    } == -1
    {
        return Err(format!(
            "MCSEALED-PRIVATE-INIT: socketpair: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful socketpair transferred unique owned descriptors.
    let provider = unsafe { File::from_raw_fd(fds[0]) };
    // SAFETY: successful socketpair transferred unique owned descriptors.
    let init = unsafe { File::from_raw_fd(fds[1]) };
    let enabled: libc::c_int = 1;
    // SAFETY: setsockopt reads one initialized integer from a live socket.
    if unsafe {
        libc::setsockopt(
            provider.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            (&raw const enabled).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    } == -1
    {
        return Err(format!(
            "MCSEALED-PRIVATE-INIT: SO_PASSCRED: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok((
        PrivateNamespaceStartupProvider(provider),
        PrivateNamespaceStartupInit(init),
    ))
}

impl PrivateNamespaceStartupProvider {
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }

    /// Only a packet whose SCM_CREDENTIALS PID matches the exact clone result
    /// can be accepted. MSG_TRUNC/MSG_CTRUNC and deadline are fail-closed.
    pub fn receive(
        &self,
        expected_init_pid: libc::pid_t,
        deadline: Instant,
    ) -> Result<AuthenticatedPrivateNamespaceStartup, String> {
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err("MCSEALED-PRIVATE-INIT: startup deadline expired".into());
            }
            let timeout = deadline
                .saturating_duration_since(now)
                .as_millis()
                .min(i32::MAX as u128) as i32;
            let mut pollfd = libc::pollfd {
                fd: self.0.as_raw_fd(),
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            };
            // SAFETY: poll borrows one initialized descriptor record.
            let ready = unsafe { libc::poll(&raw mut pollfd, 1, timeout) };
            if ready == -1 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(format!(
                    "MCSEALED-PRIVATE-INIT: poll: {}",
                    std::io::Error::last_os_error()
                ));
            }
            if ready == 0 {
                continue;
            }
            if pollfd.revents & libc::POLLIN == 0 {
                return Err("MCSEALED-PRIVATE-INIT: startup channel closed".into());
            }
            let mut packet = [0_u8; MAX_PACKET_LENGTH];
            // SAFETY: CMSG_SPACE computes a constant buffer size for one ucred.
            let mut control = AlignedAncillary(
                [0_u8; unsafe {
                    libc::CMSG_SPACE(size_of::<libc::ucred>() as u32)
                        + libc::CMSG_SPACE(size_of::<libc::c_int>() as u32)
                } as usize],
            );
            let mut iov = libc::iovec {
                iov_base: packet.as_mut_ptr().cast(),
                iov_len: packet.len(),
            };
            // SAFETY: zero is the documented default for unused msghdr fields.
            let mut message: libc::msghdr = unsafe { zeroed() };
            message.msg_iov = &raw mut iov;
            message.msg_iovlen = 1;
            message.msg_control = control.0.as_mut_ptr().cast();
            message.msg_controllen = control.0.len();
            // SAFETY: recvmsg writes only into the live packet/ancillary buffers.
            let count = unsafe {
                libc::recvmsg(
                    self.0.as_raw_fd(),
                    &raw mut message,
                    libc::MSG_DONTWAIT | libc::MSG_TRUNC | libc::MSG_CMSG_CLOEXEC,
                )
            };
            if count == -1 {
                if matches!(
                    std::io::Error::last_os_error().kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) {
                    continue;
                }
                return Err(format!(
                    "MCSEALED-PRIVATE-INIT: recvmsg: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let (credentials, target_pidfd) = receive_startup_ancillary(&message)?;
            if count == 0
                || count as usize > packet.len()
                || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
            {
                return Err("MCSEALED-PRIVATE-INIT: empty or truncated record".into());
            }
            if expected_init_pid <= 0 || credentials.pid != expected_init_pid {
                return Err("MCSEALED-PRIVATE-INIT: sender is not cloned namespace init".into());
            }
            let observation = decode_private_namespace_startup(&packet[..count as usize])?;
            if matches!(
                observation,
                PrivateNamespaceStartupObservation::TargetForked { .. }
            ) != target_pidfd.is_some()
            {
                return Err("MCSEALED-PRIVATE-INIT: target pidfd and record kind disagree".into());
            }
            return Ok(AuthenticatedPrivateNamespaceStartup {
                observation,
                target_pidfd,
            });
        }
    }
}

fn receive_startup_ancillary(
    message: &libc::msghdr,
) -> Result<(libc::ucred, Option<OwnedFd>), String> {
    let mut credentials = None;
    let mut descriptors = Vec::new();
    let mut invalid = false;
    // SAFETY: recvmsg set msg_controllen to the initialized ancillary extent;
    // CMSG_FIRSTHDR/NXTHDR walk only complete headers inside that extent.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(message);
        while !header.is_null() {
            let length = (*header).cmsg_len as usize;
            if (*header).cmsg_level == libc::SOL_SOCKET
                && (*header).cmsg_type == libc::SCM_CREDENTIALS
                && length == libc::CMSG_LEN(size_of::<libc::ucred>() as u32) as usize
                && credentials.is_none()
            {
                credentials = Some(std::ptr::read_unaligned(
                    libc::CMSG_DATA(header).cast::<libc::ucred>(),
                ));
            } else if (*header).cmsg_level == libc::SOL_SOCKET
                && (*header).cmsg_type == libc::SCM_RIGHTS
                && length >= libc::CMSG_LEN(0) as usize
            {
                let bytes = length - libc::CMSG_LEN(0) as usize;
                if bytes % size_of::<libc::c_int>() != 0 {
                    invalid = true;
                } else {
                    for index in 0..bytes / size_of::<libc::c_int>() {
                        let fd = std::ptr::read_unaligned(
                            libc::CMSG_DATA(header).cast::<libc::c_int>().add(index),
                        );
                        if fd < 0 {
                            invalid = true;
                        } else {
                            // SAFETY: SCM_RIGHTS installed a new process-local
                            // descriptor, now owned exactly once by this vector.
                            descriptors.push(OwnedFd::from_raw_fd(fd));
                        }
                    }
                }
            } else {
                invalid = true;
            }
            header = libc::CMSG_NXTHDR(message, header);
        }
    }
    if invalid || descriptors.len() > 1 {
        return Err("MCSEALED-PRIVATE-INIT: invalid ancillary descriptor set".into());
    }
    let credentials = credentials.ok_or("MCSEALED-PRIVATE-INIT: sender credentials absent")?;
    Ok((credentials, descriptors.pop()))
}

impl PrivateNamespaceStartupInit {
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }

    pub fn report(
        &self,
        observation: &PrivateNamespaceStartupObservation,
        target_pidfd: Option<BorrowedFd<'_>>,
    ) -> Result<(), String> {
        if matches!(
            observation,
            PrivateNamespaceStartupObservation::TargetForked { .. }
        ) != target_pidfd.is_some()
        {
            return Err("MCSEALED-PRIVATE-INIT: target pidfd and record kind disagree".into());
        }
        let packet = encode_private_namespace_startup(observation)?;
        let mut iov = libc::iovec {
            iov_base: packet.as_ptr().cast_mut().cast(),
            iov_len: packet.len(),
        };
        // SAFETY: zero is the documented default for unused msghdr fields.
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_iov = &raw mut iov;
        message.msg_iovlen = 1;
        // SAFETY: CMSG_SPACE computes a constant buffer size for one int.
        let mut control = AlignedAncillary(
            [0_u8; unsafe { libc::CMSG_SPACE(size_of::<libc::c_int>() as u32) } as usize],
        );
        if let Some(pidfd) = target_pidfd {
            message.msg_control = control.0.as_mut_ptr().cast();
            message.msg_controllen = control.0.len();
            // SAFETY: the allocated control buffer fits exactly one SCM_RIGHTS
            // int; sendmsg only borrows the pidfd and the encoded packet.
            unsafe {
                let header = libc::CMSG_FIRSTHDR(&raw const message);
                (*header).cmsg_level = libc::SOL_SOCKET;
                (*header).cmsg_type = libc::SCM_RIGHTS;
                (*header).cmsg_len = libc::CMSG_LEN(size_of::<libc::c_int>() as u32) as usize;
                std::ptr::write_unaligned(
                    libc::CMSG_DATA(header).cast::<libc::c_int>(),
                    pidfd.as_raw_fd(),
                );
            }
        }
        // SAFETY: sendmsg borrows the initialized iovec and optional single
        // SCM_RIGHTS record from an owned seqpacket endpoint.
        let count =
            unsafe { libc::sendmsg(self.0.as_raw_fd(), &raw const message, libc::MSG_NOSIGNAL) };
        if count != packet.len() as isize {
            return Err(format!(
                "MCSEALED-PRIVATE-INIT: startup send: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }
}

/// Run only as the `NamespaceMode::PrivateTcp4` clone child. This helper is
/// intentionally not called by the V4 broker while checkpoint and guardian
/// ownership are incomplete. The provider endpoints are closed before setup.
#[allow(clippy::too_many_arguments)]
pub fn run_private_namespace_init(
    target: PrivateGatedTarget,
    startup: PrivateNamespaceStartupInit,
    provider_startup_fd: BorrowedFd<'_>,
    provider_control_fd: BorrowedFd<'_>,
    mut status: File,
    caller_namespace: NamespaceIdentity,
    provider_namespace: NamespaceIdentity,
    wait_for_descendants: bool,
) -> i32 {
    // SAFETY: clone gave this init local copies of provider-owned endpoints;
    // closing those copies ensures only the provider can hold its side open.
    unsafe {
        libc::close(provider_startup_fd.as_raw_fd());
        libc::close(provider_control_fd.as_raw_fd());
    }
    let network =
        match prepare_private_namespace_before_target_fork(caller_namespace, provider_namespace) {
            Ok(network) => network,
            Err(detail) => {
                let _ = startup.report(
                    &PrivateNamespaceStartupObservation::Failed {
                        phase: PrivateNamespaceStartupPhase::NamespaceSetup,
                        detail,
                    },
                    None,
                );
                return 125;
            }
        };
    let namespace = match super::network_profile::current_network_namespace() {
        Ok(namespace) => namespace,
        Err(detail) => {
            let _ = startup.report(
                &PrivateNamespaceStartupObservation::Failed {
                    phase: PrivateNamespaceStartupPhase::NamespaceSetup,
                    detail,
                },
                None,
            );
            return 125;
        }
    };
    // SAFETY: fork has no borrowed pointers; only the target child runs the
    // single-threaded gated setup and never returns to this init.
    let child = unsafe { libc::fork() };
    if child == -1 {
        let _ = startup.report(
            &PrivateNamespaceStartupObservation::Failed {
                phase: PrivateNamespaceStartupPhase::TargetFork,
                detail: format!("target fork: {}", std::io::Error::last_os_error()),
            },
            None,
        );
        return 125;
    }
    if child == 0 {
        drop(startup);
        drop(status);
        target.run();
    }
    drop(target);
    // SAFETY: pidfd_open binds a new descriptor to the exact fork result, not
    // to a provider-guessed numeric PID. The child is still gated on fd 3.
    let raw_pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, child, 0) } as i32;
    if raw_pidfd == -1 {
        let detail = format!("target pidfd_open: {}", std::io::Error::last_os_error());
        // SAFETY: child is the exact fork result and has not been released.
        unsafe {
            libc::kill(child, libc::SIGKILL);
            libc::waitpid(child, std::ptr::null_mut(), 0);
        }
        let _ = startup.report(
            &PrivateNamespaceStartupObservation::Failed {
                phase: PrivateNamespaceStartupPhase::TargetFork,
                detail,
            },
            None,
        );
        return 125;
    }
    // SAFETY: successful pidfd_open returned a fresh owned descriptor.
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw_pidfd) };
    if startup
        .report(
            &PrivateNamespaceStartupObservation::TargetForked { namespace, network },
            Some(pidfd.as_fd()),
        )
        .is_err()
    {
        // SAFETY: child is the exact fork result, and no release byte has been
        // sent. Kill/reap it before returning a startup failure.
        unsafe {
            libc::kill(child, libc::SIGKILL);
            libc::waitpid(child, std::ptr::null_mut(), 0);
        }
        return 125;
    }
    drop(startup);
    let mut raw = 0_i32;
    // SAFETY: waitpid observes only this init's exact direct child.
    if unsafe { libc::waitpid(child, &raw mut raw, 0) } == -1 {
        return 125;
    }
    if wait_for_descendants {
        // SAFETY: all remaining children are scoped to this namespace init.
        while unsafe { libc::waitpid(-1, std::ptr::null_mut(), 0) } > 0 {}
    } else {
        // SAFETY: nonblocking reap observes only this init's children.
        while unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) } > 0 {}
    }
    let code = if libc::WIFEXITED(raw) {
        libc::WEXITSTATUS(raw)
    } else {
        128 + libc::WTERMSIG(raw)
    };
    let _ = status.write_all(&code.to_be_bytes());
    0
}
