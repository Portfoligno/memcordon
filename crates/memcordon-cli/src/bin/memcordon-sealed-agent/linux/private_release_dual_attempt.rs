//! Two separately journaled release-domain attempts for the isolation case.
//! This only allocates protected custody; it does not prove two live targets.

use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::time::Duration;

use memcordon_core::DiagnosticSha256;
use sha2::{Digest, Sha256};

use super::private_attempt::ProcessIdentityV4;
use super::private_lifecycle::PrivateAttemptOwner;
use super::private_release_attempt::DurableReleaseCandidateAttemptV1;

pub(crate) const SELECTOR: &str = "private_tcp::dual_attempt_namespace_isolation";
const TARGET_ACK: u8 = 0xa7;

/// Each target holds an identical loopback port until both are independently
/// observed live. A target report alone cannot prove namespace separation.
pub(crate) fn run_target(challenge: &[u8; 32]) -> Result<(), String> {
    let port = fixed_port(challenge);
    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    let listener = TcpListener::bind(address)
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE-FIXTURE: dual TCP bind: {error}"))?;
    match TcpListener::bind(address) {
        Err(error) if error.raw_os_error() == Some(libc::EADDRINUSE) => {}
        _ => return Err("dual same-namespace competitor did not return EADDRINUSE".into()),
    }
    let free = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .map_err(|error| error.to_string())?;
    if free.local_addr().map_err(|error| error.to_string())?.port() == port {
        return Err("dual free-bind control reused live port".into());
    }
    let mut client = TcpStream::connect(address)
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE-FIXTURE: dual connect: {error}"))?;
    let (mut accepted, peer) = listener
        .accept()
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE-FIXTURE: dual accept: {error}"))?;
    if !peer.ip().is_loopback() {
        return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: dual peer differs".into());
    }
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .and_then(|()| client.set_write_timeout(Some(Duration::from_secs(2))))
        .and_then(|()| accepted.set_read_timeout(Some(Duration::from_secs(2))))
        .and_then(|()| accepted.set_write_timeout(Some(Duration::from_secs(2))))
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE-FIXTURE: dual timeout: {error}"))?;
    client
        .write_all(challenge)
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE-FIXTURE: dual TCP send: {error}"))?;
    let mut received = [0_u8; 32];
    accepted
        .read_exact(&mut received)
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE-FIXTURE: dual TCP receive: {error}"))?;
    if received != *challenge {
        return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: dual TCP challenge differs".into());
    }
    accepted
        .write_all(&received)
        .and_then(|()| client.read_exact(&mut received))
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE-FIXTURE: dual TCP echo: {error}"))?;
    if received != *challenge {
        return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: dual TCP echo differs".into());
    }
    let inode = std::fs::metadata("/proc/self/ns/net")
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE-FIXTURE: dual netns: {error}"))?
        .ino();
    if inode == 0 {
        return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: dual netns is zero".into());
    }
    let ready = ready_frame(challenge, port, inode);
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(&ready)
        .and_then(|()| stdout.flush())
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE-FIXTURE: dual ready: {error}"))?;
    let mut waiting = libc::pollfd {
        fd: libc::STDIN_FILENO,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll observes only the fixed stdin descriptor. An abandoned
    // owner cannot leave this target waiting without a bound.
    if unsafe { libc::poll(&raw mut waiting, 1, 45_000) } != 1
        || waiting.revents & libc::POLLIN == 0
        || waiting.revents & (libc::POLLERR | libc::POLLNVAL | libc::POLLHUP) != 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: dual ack timed out".into());
    }
    let mut ack = [0_u8; 1];
    std::io::stdin()
        .read_exact(&mut ack)
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE-FIXTURE: dual ack: {error}"))?;
    if ack == [2] {
        let mut next = Sha256::new();
        next.update(b"memcordon/private-dual-second-exchange/v1\0");
        next.update(challenge);
        let next: [u8; 32] = next.finalize().into();
        client
            .write_all(&next)
            .and_then(|()| accepted.read_exact(&mut received))
            .map_err(|error| format!("dual second exchange send/receive: {error}"))?;
        if received != next {
            return Err("dual second exchange challenge differs".into());
        }
        accepted
            .write_all(&received)
            .and_then(|()| client.read_exact(&mut received))
            .map_err(|error| format!("dual second exchange echo: {error}"))?;
        if received != next {
            return Err("dual second exchange echo differs".into());
        }
        let response = post_retirement_frame(challenge, &received, port, inode);
        stdout
            .write_all(&response)
            .and_then(|()| stdout.flush())
            .map_err(|error| error.to_string())?;
        waiting.revents = 0;
        // SAFETY: fixed stdin remains the same one-shot observer ACK channel.
        if unsafe { libc::poll(&raw mut waiting, 1, 45_000) } != 1
            || waiting.revents & libc::POLLIN == 0
            || waiting.revents & (libc::POLLERR | libc::POLLNVAL | libc::POLLHUP) != 0
        {
            return Err("dual final ACK timed out".into());
        }
        std::io::stdin()
            .read_exact(&mut ack)
            .map_err(|error| error.to_string())?;
    }
    if ack[0] != TARGET_ACK {
        return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: dual ack differs".into());
    }
    drop(listener);
    Ok(())
}

pub(crate) fn post_retirement_frame(
    challenge: &[u8; 32],
    received: &[u8; 32],
    port: u16,
    inode: u64,
) -> [u8; 82] {
    let mut frame = [0_u8; 82];
    frame[..8].copy_from_slice(b"MCDR\x01\0\0\0");
    frame[8..40].copy_from_slice(challenge);
    frame[40..72].copy_from_slice(received);
    frame[72..74].copy_from_slice(&port.to_le_bytes());
    frame[74..].copy_from_slice(&inode.to_le_bytes());
    frame
}

pub(crate) fn fixed_port(challenge: &[u8; 32]) -> u16 {
    memcordon_core::private_release_case_v1::candidate_fixture_port_v1(challenge)
}

pub(crate) fn ready_frame(challenge: &[u8; 32], port: u16, inode: u64) -> [u8; 42] {
    assert_eq!(port, fixed_port(challenge), "reviewed dual fixture port");
    memcordon_core::private_release_case_v1::candidate_fixture_expected_response_v1(
        if cfg!(target_arch = "x86_64") {
            "x86_64-unknown-linux-gnu"
        } else {
            "aarch64-unknown-linux-gnu"
        },
        SELECTOR,
        challenge,
        Some(inode),
        None,
    )
    .expect("reviewed dual operands")
    .try_into()
    .expect("reviewed dual ready frame")
}

pub(crate) fn target_ack() -> [u8; 1] {
    [TARGET_ACK]
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DualAttemptRoleV1 {
    First,
    Second,
}

impl DualAttemptRoleV1 {
    fn leaf(self) -> &'static str {
        match self {
            Self::First => "dual-first",
            Self::Second => "dual-second",
        }
    }

    fn tag(self) -> u8 {
        match self {
            Self::First => 1,
            Self::Second => 2,
        }
    }
}

pub(crate) fn subattempt_key(
    parent: &DiagnosticSha256,
    role: DualAttemptRoleV1,
) -> DiagnosticSha256 {
    let mut digest = Sha256::new();
    digest.update(b"memcordon-private-release-dual-subattempt-v1\0");
    digest.update(parent.bytes());
    digest.update([role.tag()]);
    DiagnosticSha256::from_bytes(digest.finalize().into())
}

pub(crate) struct DualCandidateJournalPairV1 {
    pub(crate) first_key: DiagnosticSha256,
    pub(crate) first: PrivateAttemptOwner<DurableReleaseCandidateAttemptV1>,
    pub(crate) second_key: DiagnosticSha256,
    pub(crate) second: PrivateAttemptOwner<DurableReleaseCandidateAttemptV1>,
}

pub(crate) struct DualCandidateJournalBindingsV1<'a> {
    pub(crate) parent_directory: &'a File,
    pub(crate) parent_key: &'a DiagnosticSha256,
    pub(crate) challenge: &'a [u8; 32],
    pub(crate) installation_epoch: &'a DiagnosticSha256,
    pub(crate) candidate_manifest_sha256: &'a DiagnosticSha256,
    pub(crate) service_generation_sha256: &'a DiagnosticSha256,
    pub(crate) coordinator: &'a ProcessIdentityV4,
}

pub(crate) fn allocate_pair(
    binding: DualCandidateJournalBindingsV1<'_>,
) -> Result<DualCandidateJournalPairV1, String> {
    require_protected_directory(binding.parent_directory)?;
    let first_key = subattempt_key(binding.parent_key, DualAttemptRoleV1::First);
    let second_key = subattempt_key(binding.parent_key, DualAttemptRoleV1::Second);
    if first_key == second_key
        || first_key == *binding.parent_key
        || second_key == *binding.parent_key
    {
        return Err("MCSEALED-PRIVATE-RELEASE: dual subattempt key collision".into());
    }
    // Each child is no-replace and pinned before its attempt.json is created.
    // Failure after the first allocation leaves a blocking protected journal.
    let first_directory = create_child(binding.parent_directory, DualAttemptRoleV1::First)?;
    let mut first = DurableReleaseCandidateAttemptV1::allocate(
        first_directory,
        first_key.clone(),
        SELECTOR,
        binding.challenge,
        binding.installation_epoch.clone(),
        binding.candidate_manifest_sha256.clone(),
        binding.service_generation_sha256.clone(),
        binding.coordinator.clone(),
    )?;
    first.freeze()?;
    let second_directory = create_child(binding.parent_directory, DualAttemptRoleV1::Second)?;
    let mut second = DurableReleaseCandidateAttemptV1::allocate(
        second_directory,
        second_key.clone(),
        SELECTOR,
        binding.challenge,
        binding.installation_epoch.clone(),
        binding.candidate_manifest_sha256.clone(),
        binding.service_generation_sha256.clone(),
        binding.coordinator.clone(),
    )?;
    second.freeze()?;
    Ok(DualCandidateJournalPairV1 {
        first_key,
        first: PrivateAttemptOwner::new(first)?,
        second_key,
        second: PrivateAttemptOwner::new(second)?,
    })
}

fn require_protected_directory(directory: &File) -> Result<(), String> {
    let metadata = directory.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o777 != 0o700 {
        return Err("MCSEALED-PRIVATE-RELEASE: dual directory protection differs".into());
    }
    Ok(())
}

fn create_child(parent: &File, role: DualAttemptRoleV1) -> Result<File, String> {
    let leaf = CString::new(role.leaf()).expect("fixed dual subattempt leaf");
    // SAFETY: fixed single-component leaf, pinned parent, no-replace creation.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), leaf.as_ptr(), 0o700) } != 0 {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: dual subattempt directory: {}",
            std::io::Error::last_os_error()
        ));
    }
    parent.sync_all().map_err(|error| error.to_string())?;
    open_child(parent, role)
}

pub(crate) fn open_child(parent: &File, role: DualAttemptRoleV1) -> Result<File, String> {
    require_protected_directory(parent)?;
    let leaf = CString::new(role.leaf()).expect("fixed dual subattempt leaf");
    // SAFETY: fixed child below pinned parent, directory-only and no-follow.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: openat returned a uniquely owned descriptor.
    let directory = unsafe { File::from_raw_fd(fd) };
    require_protected_directory(&directory)?;
    Ok(directory)
}

#[cfg(feature = "test-support")]
pub(crate) fn child_leaf_for_test(role: DualAttemptRoleV1) -> &'static str {
    role.leaf()
}
