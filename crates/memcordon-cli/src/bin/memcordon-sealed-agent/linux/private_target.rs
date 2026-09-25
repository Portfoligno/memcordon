//! Non-routed trusted child setup for the optional private IPv4 TCP profile.
//!
//! This module does not authorize or launch a V2 workload by itself. The
//! provider must prove an exact gated target, freeze a durable checkpoint,
//! revalidate its policy lease, and own retirement before releasing fd 3.

use std::ffi::CString;
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Instant;

use crate::request::{NamespaceIdentity, NetworkLaunchRequestV4};

use super::descriptor_custody::{
    ExpectedGatedDescriptorInventory, GatedDescriptorProof, TargetPipeStdio,
    verify_private_gated_descriptor_inventory,
};
use super::entrypoint::VerifiedEntrypoint;
use super::execution_identity::{ResolvedTargetIdentity, apply_target_identity};
use super::network_filter::{NativeAbi, install_gated_private_filter};
use super::network_profile::{PrivateNetworkSetup, prepare_private_ipv4_network};

const CONTROL_VERSION: u8 = 2;
const CONTROL_READY: u8 = 3;
const CONTROL_FAILURE: u8 = 2;
const CONTROL_ARMED: u8 = 1;
const FAILURE_ENTRYPOINT: u8 = 1;
const FAILURE_IDENTITY: u8 = 2;
const FAILURE_FILTER: u8 = 3;
const FAILURE_AUTHORIZATION: u8 = 4;
const FAILURE_EXEC: u8 = 5;
pub(crate) const MAX_FAILURE_DETAIL_BYTES: usize = 512;

pub const PRIVATE_EXEC_ARMED_PACKET: [u8; 4] = [CONTROL_VERSION, CONTROL_ARMED, 1, 0];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivateGateEvent {
    FilterInstalled,
    ReadyReported,
    AuthorizationReceived,
    ExecArmed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivateGateProgress {
    next: u8,
}

impl PrivateGateProgress {
    pub const fn gated() -> Self {
        Self { next: 0 }
    }

    /// The trusted stub advances only after each native operation succeeds.
    /// Any attempted release transition out of order fails closed.
    pub fn advance(&mut self, event: PrivateGateEvent) -> Result<(), &'static str> {
        let expected = match self.next {
            0 => PrivateGateEvent::FilterInstalled,
            1 => PrivateGateEvent::ReadyReported,
            2 => PrivateGateEvent::AuthorizationReceived,
            3 => PrivateGateEvent::ExecArmed,
            _ => return Err("MCSEALED-PRIVATE-GATE: sequence already complete"),
        };
        if event != expected {
            return Err("MCSEALED-PRIVATE-GATE: release sequence out of order");
        }
        self.next += 1;
        Ok(())
    }
}

pub fn exact_private_authorization_packet(packet: &[u8]) -> bool {
    packet == [1]
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivateReadyObservation {
    pub native_abi: NativeAbi,
    pub instruction_count: u16,
    pub filter_digest: [u8; 32],
    /// Present only for the fixed release-domain precreated-socket probe.
    pub(crate) precreated_sendmsg_errno: Option<i32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrivateControlObservation {
    Ready(PrivateReadyObservation),
    Failed { phase: u8, detail: String },
}

fn encode_private_failure_packet(phase: u8, detail: &str) -> Vec<u8> {
    let detail = if detail.is_empty() {
        "native failure detail unavailable"
    } else if detail.len() > MAX_FAILURE_DETAIL_BYTES {
        "native failure detail exceeded protocol bound"
    } else {
        detail
    };
    let length = u16::try_from(detail.len()).expect("bounded failure detail fits u16");
    let mut packet = Vec::with_capacity(6 + detail.len());
    packet.extend_from_slice(&[CONTROL_VERSION, CONTROL_FAILURE, phase, 0]);
    packet.extend_from_slice(&length.to_be_bytes());
    packet.extend_from_slice(detail.as_bytes());
    packet
}

#[cfg(feature = "test-support")]
pub fn encode_private_failure_packet_for_test(phase: u8, detail: &str) -> Vec<u8> {
    encode_private_failure_packet(phase, detail)
}

pub fn decode_private_control_packet(bytes: &[u8]) -> Result<PrivateControlObservation, String> {
    if bytes.len() >= 6
        && bytes[0] == CONTROL_VERSION
        && bytes[1] == CONTROL_FAILURE
        && bytes[3] == 0
        && (FAILURE_ENTRYPOINT..=FAILURE_EXEC).contains(&bytes[2])
    {
        let length = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
        if length == 0 || length > MAX_FAILURE_DETAIL_BYTES || bytes.len() != 6 + length {
            return Err("MCSEALED-PRIVATE-CONTROL: invalid failure detail length".into());
        }
        let detail = std::str::from_utf8(&bytes[6..])
            .map_err(|_| "MCSEALED-PRIVATE-CONTROL: invalid failure detail encoding")?;
        return Ok(PrivateControlObservation::Failed {
            phase: bytes[2],
            detail: detail.to_owned(),
        });
    }
    let probe = bytes.len() == 43 && bytes[..4] == [CONTROL_VERSION, CONTROL_READY, 1, 1];
    if !probe && (bytes.len() != 39 || bytes[..4] != [CONTROL_VERSION, CONTROL_READY, 1, 0]) {
        return Err("MCSEALED-PRIVATE-CONTROL: invalid ready record".into());
    }
    let native_abi = match bytes[4] {
        1 => NativeAbi::X86_64,
        2 => NativeAbi::Aarch64,
        _ => return Err("MCSEALED-PRIVATE-CONTROL: unknown native ABI".into()),
    };
    let instruction_count = u16::from_be_bytes([bytes[5], bytes[6]]);
    if instruction_count == 0 {
        return Err("MCSEALED-PRIVATE-CONTROL: empty filter program".into());
    }
    let mut filter_digest = [0_u8; 32];
    filter_digest.copy_from_slice(&bytes[7..39]);
    let precreated_sendmsg_errno = if probe {
        let errno = i32::from_le_bytes(bytes[39..43].try_into().expect("fixed probe errno bytes"));
        if errno != libc::EPERM {
            return Err("MCSEALED-PRIVATE-CONTROL: precreated sendmsg was not denied".into());
        }
        Some(errno)
    } else {
        None
    };
    Ok(PrivateControlObservation::Ready(PrivateReadyObservation {
        native_abi,
        instruction_count,
        filter_digest,
        precreated_sendmsg_errno,
    }))
}

/// Provider readback before any authorization byte is sent. The pidfd is an
/// attempt-owned reference: checking it both before and after `/proc` reads
/// prevents a raced PID reuse from being accepted as the gated target.
pub struct PrivateGatedReadback {
    pub ready: PrivateReadyObservation,
    pub descriptors: GatedDescriptorProof,
    pub network_namespace: NamespaceIdentity,
}

/// The provider's attempt-local reference to the NEWNET object. This is a
/// kernel namespace descriptor, never a persistent `/run/netns` bind mount.
/// It must be held by the lifecycle owner until the target and all helpers
/// have retired, then explicitly dropped and accounted for in terminal facts.
pub struct PrivateNetworkNamespaceOwner {
    descriptor: OwnedFd,
    identity: NamespaceIdentity,
}

impl PrivateNetworkNamespaceOwner {
    pub fn identity(&self) -> NamespaceIdentity {
        self.identity
    }

    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.descriptor.as_fd()
    }
}

#[cfg(feature = "test-support")]
pub fn private_network_owner_for_test(
    descriptor: OwnedFd,
    identity: NamespaceIdentity,
) -> PrivateNetworkNamespaceOwner {
    PrivateNetworkNamespaceOwner {
        descriptor,
        identity,
    }
}

/// Pin the fresh network namespace while its init remains live. The caller
/// supplies the pidfd obtained from the exact clone result, not a guessed PID.
pub fn pin_private_network_namespace(
    namespace_init_pid: libc::pid_t,
    namespace_init_pidfd: BorrowedFd<'_>,
    caller_namespace: NamespaceIdentity,
    provider_namespace: NamespaceIdentity,
) -> Result<PrivateNetworkNamespaceOwner, String> {
    require_live_pidfd(namespace_init_pidfd)?;
    let path = Path::new("/proc")
        .join(namespace_init_pid.to_string())
        .join("ns/net");
    let file = File::open(&path)
        .map_err(|error| format!("MCSEALED-PRIVATE-NETWORK: pin namespace: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("MCSEALED-PRIVATE-NETWORK: pinned metadata: {error}"))?;
    let identity = NamespaceIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    if identity == caller_namespace || identity == provider_namespace {
        return Err("MCSEALED-PRIVATE-NETWORK: clone did not create fresh NEWNET".into());
    }
    // SAFETY: F_GETFD queries only the live namespace descriptor.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
    if flags < 0 || flags & libc::FD_CLOEXEC == 0 {
        return Err("MCSEALED-PRIVATE-NETWORK: namespace descriptor not CLOEXEC".into());
    }
    require_live_pidfd(namespace_init_pidfd)?;
    Ok(PrivateNetworkNamespaceOwner {
        descriptor: file.into(),
        identity,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn observe_private_gated_target(
    pid: libc::pid_t,
    pidfd: BorrowedFd<'_>,
    namespace_init_pid: libc::pid_t,
    expected_descriptors: ExpectedGatedDescriptorInventory,
    provider_control: BorrowedFd<'_>,
    target_identity: &ResolvedTargetIdentity,
    caller_namespace: NamespaceIdentity,
    provider_namespace: NamespaceIdentity,
    namespace_owner: &PrivateNetworkNamespaceOwner,
    expected_abi: NativeAbi,
    expected_filter_digest: [u8; 32],
    deadline: Instant,
) -> Result<PrivateGatedReadback, String> {
    require_live_pidfd(pidfd)?;
    let packet = receive_private_control_packet(provider_control, deadline)?;
    let ready = match decode_private_control_packet(&packet)? {
        PrivateControlObservation::Ready(ready) => ready,
        PrivateControlObservation::Failed { phase, detail } => {
            return Err(format!(
                "MCSEALED-PRIVATE-TARGET-SETUP: child phase {phase} failed: {detail}"
            ));
        }
    };
    if ready.native_abi != expected_abi
        || ready.filter_digest != expected_filter_digest
        || ready.precreated_sendmsg_errno.is_some()
            != expected_descriptors.expects_precreated_probe_pair()
    {
        return Err("MCSEALED-PRIVATE-FILTER: ready digest or ABI mismatch".into());
    }
    require_live_pidfd(pidfd)?;
    let descriptors = verify_private_gated_descriptor_inventory(pid, expected_descriptors)
        .map_err(|error| format!("MCSEALED-PRIVATE-DESCRIPTOR-READBACK: {error}"))?;
    let process = Path::new("/proc").join(pid.to_string());
    let status = std::fs::read_to_string(process.join("status"))
        .map_err(|error| format!("MCSEALED-PRIVATE-IDENTITY-READBACK: {error}"))?;
    let parsed = super::envelope::parse_proc_status(&status)
        .map_err(|error| format!("MCSEALED-PRIVATE-IDENTITY-READBACK: {error}"))?;
    let mut actual_groups = parsed.supplementary_groups;
    actual_groups.sort_unstable();
    if parsed.uids != [target_identity.uid(); 4]
        || parsed.gids != [target_identity.gid(); 4]
        || actual_groups != target_identity.groups()
        || !parsed.no_new_privs
        || parsed.capability_inheritable_set != 0
        || parsed.capability_permitted_set != 0
        || parsed.capability_effective_set != 0
        || parsed.capability_bounding_set != 0
        || parsed.capability_ambient_set != 0
    {
        return Err("MCSEALED-PRIVATE-IDENTITY: gated target credential mismatch".into());
    }
    if status
        .lines()
        .find_map(|line| line.strip_prefix("Seccomp:"))
        .map(str::trim)
        != Some("2")
    {
        return Err("MCSEALED-PRIVATE-FILTER: gated target seccomp readback mismatch".into());
    }
    let network_namespace = namespace_identity(&process)?;
    let init_namespace =
        namespace_identity(&Path::new("/proc").join(namespace_init_pid.to_string()))?;
    if network_namespace != init_namespace
        || network_namespace != namespace_owner.identity()
        || network_namespace == caller_namespace
        || network_namespace == provider_namespace
    {
        return Err("MCSEALED-PRIVATE-NETWORK: gated target namespace mismatch".into());
    }
    require_live_pidfd(pidfd)?;
    Ok(PrivateGatedReadback {
        ready,
        descriptors,
        network_namespace,
    })
}

fn namespace_identity(process: &Path) -> Result<NamespaceIdentity, String> {
    let metadata = std::fs::metadata(process.join("ns/net"))
        .map_err(|error| format!("MCSEALED-PRIVATE-NETWORK: namespace readback: {error}"))?;
    Ok(NamespaceIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn require_live_pidfd(pidfd: BorrowedFd<'_>) -> Result<(), String> {
    let mut descriptor = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll borrows one initialized pollfd for a zero-timeout query.
    let result = unsafe { libc::poll(&raw mut descriptor, 1, 0) };
    if result != 0 || descriptor.revents != 0 {
        return Err("MCSEALED-PRIVATE-TARGET: pidfd exited or became invalid".into());
    }
    Ok(())
}

fn receive_private_control_packet(
    control: BorrowedFd<'_>,
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err("MCSEALED-PRIVATE-CONTROL: ready deadline expired".into());
        }
        let timeout = deadline
            .saturating_duration_since(now)
            .as_millis()
            .min(i32::MAX as u128) as i32;
        let mut descriptor = libc::pollfd {
            fd: control.as_raw_fd(),
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        // SAFETY: poll borrows one initialized pollfd for the bounded wait.
        let result = unsafe { libc::poll(&raw mut descriptor, 1, timeout) };
        if result == -1 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!(
                "MCSEALED-PRIVATE-CONTROL: poll: {}",
                std::io::Error::last_os_error()
            ));
        }
        if result == 0 {
            continue;
        }
        if descriptor.revents & libc::POLLIN == 0 {
            return Err("MCSEALED-PRIVATE-CONTROL: closed before ready".into());
        }
        let mut packet = [0_u8; 6 + MAX_FAILURE_DETAIL_BYTES];
        // SAFETY: recv borrows the exact control endpoint. MSG_TRUNC exposes
        // oversized seqpackets instead of silently accepting a valid prefix.
        let received = unsafe {
            libc::recv(
                control.as_raw_fd(),
                packet.as_mut_ptr().cast(),
                packet.len(),
                libc::MSG_DONTWAIT | libc::MSG_TRUNC,
            )
        };
        if received == -1 {
            if matches!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(format!(
                "MCSEALED-PRIVATE-CONTROL: recv: {}",
                std::io::Error::last_os_error()
            ));
        }
        let count = usize::try_from(received)
            .map_err(|_| "MCSEALED-PRIVATE-CONTROL: invalid packet length")?;
        if count == 0 || count > packet.len() {
            return Err("MCSEALED-PRIVATE-CONTROL: closed or oversized packet".into());
        }
        return Ok(packet[..count].to_vec());
    }
}

/// Call only in the fresh `NamespaceMode::PrivateTcp4` namespace init, before
/// it forks the candidate stub. A setup failure must abort that init; a
/// successful return is not a release or provider-side topology observation.
pub fn prepare_private_namespace_before_target_fork(
    caller_namespace: NamespaceIdentity,
    provider_namespace: NamespaceIdentity,
) -> Result<PrivateNetworkSetup, String> {
    super::namespace::prepare_namespace_init().map_err(|error| error.to_string())?;
    prepare_private_ipv4_network(caller_namespace, provider_namespace)
}

/// Exec ABI values are prepared from the same V4 launch whose contract and
/// program were checked by `pin_private_prelaunch_authority`. No shell or
/// pathname re-resolution participates in target execution.
#[derive(Debug)]
pub struct PrivateExecArguments {
    argv: Vec<CString>,
    environment: Vec<CString>,
    mode: PrivateExecMode,
}

#[derive(Debug)]
enum PrivateExecMode {
    Pinned,
    ProbeRejectEmptyPath,
    ProbePrecreatedSocket,
}

impl PrivateExecArguments {
    /// Pinned ELF target entry for the closed AF_UNIX socket-stage witness.
    /// This is intentionally distinct from the candidate fixture eligibility
    /// gate and cannot make the release selector publishable.
    pub(crate) fn for_closed_unix_intent() -> Self {
        Self {
            argv: vec![
                CString::new("/usr/libexec/memcordon-sealed-agent")
                    .expect("fixed installed image path has no NUL"),
                CString::new("private-release-unix-intent")
                    .expect("fixed release subwitness command has no NUL"),
            ],
            environment: Vec::new(),
            mode: PrivateExecMode::Pinned,
        }
    }

    pub(crate) fn for_release_candidate_fixture(selector: &str) -> Result<Self, String> {
        if !super::private_release_case::candidate_physical_selector_supported(selector) {
            return Err("MCSEALED-PRIVATE-RELEASE-ARGV: candidate fixture unavailable".into());
        }
        Ok(Self {
            argv: vec![
                CString::new("/usr/libexec/memcordon-sealed-agent")
                    .expect("fixed installed image path has no NUL"),
                CString::new("private-release-fixture")
                    .expect("fixed release fixture subcommand has no NUL"),
                CString::new(selector).expect("fixed release selector has no NUL"),
            ],
            environment: Vec::new(),
            mode: if selector == super::private_release_socket_launder::SELECTOR {
                PrivateExecMode::ProbePrecreatedSocket
            } else {
                PrivateExecMode::Pinned
            },
        })
    }

    pub(crate) fn for_probe_fixture(
        kind: super::private_qualification::ProbeFixtureKindV1,
    ) -> Result<Self, String> {
        let index = (0..super::qualification::HOST_PROBE_CATALOG_V1.len())
            .find(|index| {
                super::private_qualification::ProbeFixtureKindV1::at(*index) == Some(kind)
            })
            .ok_or("MCSEALED-PRIVATE-PROBE-ARGV: unknown case")?;
        let name = super::qualification::HOST_PROBE_CATALOG_V1[index].1;
        Ok(Self {
            argv: vec![
                CString::new("/usr/libexec/memcordon-sealed-agent")
                    .expect("fixed installed image path has no NUL"),
                CString::new("private-probe-fixture").expect("fixed fixture subcommand has no NUL"),
                CString::new(name).expect("closed fixture name has no NUL"),
            ],
            environment: Vec::new(),
            mode: if kind
                == super::private_qualification::ProbeFixtureKindV1::TargetExecFailureRetirement
            {
                PrivateExecMode::ProbeRejectEmptyPath
            } else {
                PrivateExecMode::Pinned
            },
        })
    }

    pub fn from_request(request: &NetworkLaunchRequestV4) -> Result<Self, String> {
        if request.launch.program.is_empty() {
            return Err("MCSEALED-PRIVATE-ARGV: empty executable name".into());
        }
        let mut argv = Vec::with_capacity(request.launch.arguments.len() + 1);
        argv.push(
            CString::new(request.launch.program.clone())
                .map_err(|_| "MCSEALED-PRIVATE-ARGV: NUL in executable name")?,
        );
        for argument in &request.launch.arguments {
            argv.push(
                CString::new(argument.as_slice())
                    .map_err(|_| "MCSEALED-PRIVATE-ARGV: NUL in argument")?,
            );
        }
        let mut environment = Vec::with_capacity(request.launch.environment.len());
        for (name, value) in &request.launch.environment {
            if name.is_empty() || name.contains(&b'=') || name.contains(&0) || value.contains(&0) {
                return Err("MCSEALED-PRIVATE-ENV: invalid environment field".into());
            }
            let mut entry = Vec::with_capacity(name.len() + 1 + value.len());
            entry.extend_from_slice(name);
            entry.push(b'=');
            entry.extend_from_slice(value);
            environment
                .push(CString::new(entry).map_err(|_| "MCSEALED-PRIVATE-ENV: NUL in environment")?);
        }
        Ok(Self {
            argv,
            environment,
            mode: PrivateExecMode::Pinned,
        })
    }

    pub fn argv(&self) -> &[CString] {
        &self.argv
    }

    pub fn environment(&self) -> &[CString] {
        &self.environment
    }

    pub(crate) fn probes_precreated_socket(&self) -> bool {
        matches!(self.mode, PrivateExecMode::ProbePrecreatedSocket)
    }
}

/// All fields are provider-produced and moved into one single-threaded child.
/// The provider must retain its own independent copies of the control, ELF
/// identity, and expected descriptor inventory for gated readback.
pub struct PrivateGatedTarget {
    pub entrypoint: VerifiedEntrypoint,
    pub identity: ResolvedTargetIdentity,
    pub stdio: TargetPipeStdio,
    pub target_control: OwnedFd,
    pub command: PrivateExecArguments,
    pub native_abi: NativeAbi,
    pub expected_filter_digest: [u8; 32],
}

impl PrivateGatedTarget {
    /// Never call in the provider process. The caller must already have
    /// forked this child inside a freshly prepared private network namespace;
    /// all failures terminate the child before candidate code can execute.
    pub fn run(self) -> ! {
        let (elf_fd, seal_ticket) = self.entrypoint.into_sealing_parts();
        let sealed_elf = match self.stdio.seal_gated_table(self.target_control, elf_fd) {
            Ok(fd) => fd,
            Err(_) => child_exit(125),
        };
        // SAFETY: descriptor custody installed the exact owned AF_UNIX control
        // endpoint at fd 3 and the child now takes sole ownership of that slot.
        let mut control = unsafe { File::from_raw_fd(3) };
        let entrypoint = match VerifiedEntrypoint::from_sealed_slot(sealed_elf, seal_ticket) {
            Ok(entrypoint) => entrypoint,
            Err(error) => fail(&mut control, FAILURE_ENTRYPOINT, &error),
        };
        let mut gate = PrivateGateProgress::gated();
        if let Err(error) = apply_target_identity(&self.identity) {
            fail(&mut control, FAILURE_IDENTITY, &error);
        }
        let probe_pair = if matches!(self.command.mode, PrivateExecMode::ProbePrecreatedSocket) {
            match super::private_release_socket_launder::precreate_pair() {
                Ok(pair) => Some(pair),
                Err(error) => fail(&mut control, FAILURE_FILTER, &error),
            }
        } else {
            None
        };
        let filter =
            match install_gated_private_filter(self.native_abi, self.expected_filter_digest) {
                Ok(filter) => filter,
                Err(error) => fail(&mut control, FAILURE_FILTER, &error),
            };
        if gate.advance(PrivateGateEvent::FilterInstalled).is_err() {
            fail(
                &mut control,
                FAILURE_FILTER,
                "filter gate transition failed",
            );
        }
        let probe_errno = match probe_pair.as_ref() {
            Some(pair) => {
                match super::private_release_socket_launder::observe_scm_rights_denied(pair) {
                    Ok(errno) => Some(errno),
                    Err(error) => fail(&mut control, FAILURE_FILTER, &error),
                }
            }
            None => None,
        };
        let mut ready = [0_u8; 43];
        ready[..4].copy_from_slice(&[CONTROL_VERSION, CONTROL_READY, 1, 0]);
        if probe_errno.is_some() {
            ready[3] = 1;
        }
        ready[4] = match filter.abi {
            NativeAbi::X86_64 => 1,
            NativeAbi::Aarch64 => 2,
        };
        ready[5..7].copy_from_slice(&filter.instruction_count.to_be_bytes());
        ready[7..39].copy_from_slice(&filter.instruction_digest);
        if let Some(errno) = probe_errno {
            ready[39..43].copy_from_slice(&errno.to_le_bytes());
        }
        let ready_length = if probe_errno.is_some() { 43 } else { 39 };
        if control.write_all(&ready[..ready_length]).is_err() {
            child_exit(125);
        }
        if gate.advance(PrivateGateEvent::ReadyReported).is_err() {
            fail(
                &mut control,
                FAILURE_AUTHORIZATION,
                "ready gate transition failed",
            );
        }
        if !read_exact_authorization(&control) {
            fail(
                &mut control,
                FAILURE_AUTHORIZATION,
                "authorization packet invalid",
            );
        }
        if gate
            .advance(PrivateGateEvent::AuthorizationReceived)
            .is_err()
        {
            fail(
                &mut control,
                FAILURE_AUTHORIZATION,
                "authorization gate transition failed",
            );
        }
        // The exceptional probe pair is never inherited by the pinned image.
        drop(probe_pair);
        if control.write_all(&PRIVATE_EXEC_ARMED_PACKET).is_err() {
            child_exit(125);
        }
        if gate.advance(PrivateGateEvent::ExecArmed).is_err() {
            fail(&mut control, FAILURE_EXEC, "exec gate transition failed");
        }
        let execution = match self.command.mode {
            PrivateExecMode::Pinned => {
                entrypoint.execveat(self.command.argv(), self.command.environment())
            }
            PrivateExecMode::ProbeRejectEmptyPath => {
                entrypoint.execveat_probe_rejected(self.command.argv(), self.command.environment())
            }
            PrivateExecMode::ProbePrecreatedSocket => {
                entrypoint.execveat(self.command.argv(), self.command.environment())
            }
        };
        if let Err(error) = execution {
            fail(&mut control, FAILURE_EXEC, &error);
        }
        // `execveat` must either replace this process or return an error.
        child_exit(125)
    }
}

fn read_exact_authorization(control: &File) -> bool {
    let mut packet = [0_u8; 2];
    // SAFETY: recv borrows the exact live control socket and writes no more
    // than the two-byte buffer. A longer seqpacket is truncated and rejected.
    let received = unsafe {
        libc::recv(
            control.as_raw_fd(),
            packet.as_mut_ptr().cast(),
            packet.len(),
            0,
        )
    };
    received == 1 && exact_private_authorization_packet(&packet[..1])
}

fn fail(control: &mut File, phase: u8, detail: &str) -> ! {
    let record = encode_private_failure_packet(phase, detail);
    let _ = control.write_all(&record);
    child_exit(125)
}

fn child_exit(code: i32) -> ! {
    // SAFETY: this is the trusted fork child. Unwinding or returning into
    // provider control flow after partial native setup is forbidden.
    unsafe { libc::_exit(code) }
}
