//! Candidate-only host probe authority and its separate durable record domain.
//! Allocating a probe does not create a production grant, a V4 checkpoint, or
//! a qualified host receipt. Only native lifecycle completion can advance it.

use std::collections::BTreeSet;
use std::ffi::CString;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::Instant;

use memcordon_core::workload_contract::ProfileRef;
use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::private_attempt::{PrivateAttemptPhase, ProcessIdentityV4, ReleaseKnowledge};
use super::private_lifecycle::PrivateNativeJournal;
use super::private_probe_loss::{ProbeLossPhysicalProofV1, ProbeLossSubattemptObservationV1};
use super::qualification::HOST_PROBE_CATALOG_V1;

pub(crate) const PROBE_DIRECTORY_NAME: &str = "private-qualification";
pub(crate) const PROBE_ROOT: &str = "/var/lib/memcordon/sealed/private-qualification";
pub(crate) const PROBE_WORKING_DIRECTORY: &str = "/var/lib/memcordon/qualification-empty";
const PROBE_IDENTITY: &str = "memcordon-qualify";
const PROBE_RUN_LOCK: &str = "/run/memcordon/private-qualification.lock";
const MAX_PROBE_RECORD_BYTES: usize = 16 * 1024;

/// A package-generation lock and a live coordinator pidfd stay owned for the
/// entire run. No deserializer or conversion into production authority exists.
pub(crate) struct ProbeRunAuthority {
    package: crate::package::VerifiedProbePackageLease,
    _run_lock: File,
    _work_directory: File,
    coordinator_pidfd: OwnedFd,
    coordinator: ProcessIdentityV4,
    nonce: [u8; 32],
    run_directory: File,
    boot_id: String,
    target_uid: u32,
    target_gid: u32,
    service_generation_digest: DiagnosticSha256,
    host_prerequisites_digest: DiagnosticSha256,
    installation_epoch: DiagnosticSha256,
    deadline: Instant,
}

/// Only the exact protected eight-case catalogue can construct this run.
/// It is still not an installed H1 receipt or a production lease.
pub(crate) struct VerifiedHostRunV1 {
    native_run_digest: DiagnosticSha256,
    host_prerequisites_digest: DiagnosticSha256,
    installation_epoch: DiagnosticSha256,
    coordinator: ProcessIdentityV4,
    probes: Vec<super::qualification::NativeQualificationProbeV4>,
}

impl VerifiedHostRunV1 {
    pub(crate) fn native_run_digest(&self) -> &DiagnosticSha256 {
        &self.native_run_digest
    }

    pub(crate) fn host_prerequisites_digest(&self) -> &DiagnosticSha256 {
        &self.host_prerequisites_digest
    }

    pub(crate) fn installation_epoch(&self) -> &DiagnosticSha256 {
        &self.installation_epoch
    }

    pub(crate) fn coordinator(&self) -> &ProcessIdentityV4 {
        &self.coordinator
    }

    pub(crate) fn probes(&self) -> &[super::qualification::NativeQualificationProbeV4] {
        &self.probes
    }
}

pub(crate) struct ProbeCaseAuthority<'a> {
    run: &'a ProbeRunAuthority,
    index: usize,
    loss_kind: Option<ProbeLossKindV1>,
    frontend: Option<ProcessIdentityV4>,
}

/// The two loss observations are distinct native attempts under one fixed
/// catalogue case. Neither branch alone can complete case 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ProbeLossKindV1 {
    Frontend,
    Guardian,
}

pub(crate) struct ProbeLossCaseAuthority<'a> {
    case: ProbeCaseAuthority<'a>,
    frontend_pidfd: OwnedFd,
}

/// Created by the authenticated root control service and transferred as one
/// descriptor to the network launcher. The nonce is bound to this exact
/// protected directory before a worker may allocate a native attempt.
pub(crate) struct PreparedProbeRunV1 {
    pub(crate) nonce: [u8; 32],
    pub(crate) directory: File,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProbeBrokerRequestV1 {
    schema_version: u8,
    catalogue_version: u8,
    run_nonce: [u8; 32],
    catalogue_sha256: DiagnosticSha256,
}

impl PreparedProbeRunV1 {
    pub(crate) fn encode_broker_request(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&ProbeBrokerRequestV1 {
            schema_version: 1,
            catalogue_version: 1,
            run_nonce: self.nonce,
            catalogue_sha256: catalogue_digest(),
        })
        .map_err(|error| error.to_string())
    }
}

pub(crate) fn decode_broker_request(bytes: &[u8]) -> Result<[u8; 32], String> {
    if bytes.len() > 1024 {
        return Err("MCSEALED-PRIVATE-PROBE: broker request exceeds byte bound".into());
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)?;
    let request: ProbeBrokerRequestV1 =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if request.schema_version != 1
        || request.catalogue_version != 1
        || request.run_nonce == [0; 32]
        || request.catalogue_sha256 != catalogue_digest()
    {
        return Err("MCSEALED-PRIVATE-PROBE: broker catalogue or nonce differs".into());
    }
    Ok(request.run_nonce)
}

pub(crate) fn prepare_control_run() -> Result<PreparedProbeRunV1, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("MCSEALED-PRIVATE-PROBE: root control service required".into());
    }
    verify_service_context("memcordon-sealed-agent.service")?;
    let ambiguous = super::recovery::recover()?;
    if !ambiguous.is_empty() {
        return Err("MCSEALED-PRIVATE-PROBE: unresolved prior native state".into());
    }
    let mut nonce = [0_u8; 32];
    let mut filled = 0;
    while filled < nonce.len() {
        // SAFETY: getrandom writes at most the remaining live buffer length.
        let count = unsafe {
            libc::syscall(
                libc::SYS_getrandom,
                nonce[filled..].as_mut_ptr(),
                nonce.len() - filled,
                0,
            )
        };
        if count <= 0 {
            return Err(format!(
                "MCSEALED-PRIVATE-PROBE: run nonce: {}",
                std::io::Error::last_os_error()
            ));
        }
        filled += count as usize;
    }
    let directory = create_run_directory(&nonce)?;
    Ok(PreparedProbeRunV1 { nonce, directory })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[repr(u8)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ProbeFixtureKindV1 {
    DescriptorIdentityFilterNamespace,
    FrontendGuardianLossRetirement,
    NamespacePortSysctlIsolation,
    TargetExecFailureRetirement,
    TcpListenerClientCompetitor,
    UnixCreationSocketpairDenial,
    WrongFamilyProtocolDenial,
    BaselineUnixSuccessRetirement,
}

impl ProbeFixtureKindV1 {
    pub(crate) fn at(index: usize) -> Option<Self> {
        Some(match index {
            0 => Self::DescriptorIdentityFilterNamespace,
            1 => Self::FrontendGuardianLossRetirement,
            2 => Self::NamespacePortSysctlIsolation,
            3 => Self::TargetExecFailureRetirement,
            4 => Self::TcpListenerClientCompetitor,
            5 => Self::UnixCreationSocketpairDenial,
            6 => Self::WrongFamilyProtocolDenial,
            7 => Self::BaselineUnixSuccessRetirement,
            _ => return None,
        })
    }

    pub(crate) fn named(name: &OsStr) -> Option<Self> {
        let name = name.to_str()?;
        HOST_PROBE_CATALOG_V1
            .iter()
            .position(|(_, expected)| *expected == name)
            .and_then(Self::at)
    }
}

/// A directly invoked fixture has no qualification authority. Only the root
/// coordinator's protected ledger and independently observed V4 lifecycle may
/// turn its bounded challenge response into native completion evidence.
pub(crate) fn run_fixture(name: &OsStr) -> Result<(), String> {
    let kind = ProbeFixtureKindV1::named(name)
        .ok_or("MCSEALED-PRIVATE-PROBE-FIXTURE: case is not in the closed catalogue")?;
    // The coordinator independently pins the dedicated numeric account before
    // release. A chrooted target cannot safely consult the host account DB.
    // Local readback still rejects root or mismatched real/effective/saved IDs.
    let (mut real_uid, mut effective_uid, mut saved_uid) = (0, 0, 0);
    let (mut real_gid, mut effective_gid, mut saved_gid) = (0, 0, 0);
    // SAFETY: getresuid/getresgid write three live scalar output slots each.
    if unsafe { libc::getresuid(&raw mut real_uid, &raw mut effective_uid, &raw mut saved_uid) }
        != 0
        || unsafe { libc::getresgid(&raw mut real_gid, &raw mut effective_gid, &raw mut saved_gid) }
            != 0
        || real_uid == 0
        || real_gid == 0
        || real_uid != effective_uid
        || real_uid != saved_uid
        || real_gid != effective_gid
        || real_gid != saved_gid
        // SAFETY: a null getgroups buffer with size zero only queries count.
        || unsafe { libc::getgroups(0, std::ptr::null_mut()) } != 0
    {
        return Err("MCSEALED-PRIVATE-PROBE-FIXTURE: target credentials differ".into());
    }
    let mut challenge = [0_u8; 32];
    std::io::stdin()
        .read_exact(&mut challenge)
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE-FIXTURE: challenge: {error}"))?;
    match kind {
        ProbeFixtureKindV1::FrontendGuardianLossRetirement => {
            super::private_probe_loss::run_loss_fixture(&challenge)?
        }
        ProbeFixtureKindV1::DescriptorIdentityFilterNamespace => {
            descriptor_identity_filter_namespace()?
        }
        ProbeFixtureKindV1::NamespacePortSysctlIsolation => namespace_port_sysctl_isolation()?,
        ProbeFixtureKindV1::TcpListenerClientCompetitor => {
            tcp_listener_client_competitor(&challenge)?
        }
        ProbeFixtureKindV1::UnixCreationSocketpairDenial => unix_creation_socketpair_denial()?,
        ProbeFixtureKindV1::WrongFamilyProtocolDenial => wrong_family_protocol_denial()?,
        ProbeFixtureKindV1::BaselineUnixSuccessRetirement => baseline_unix_success(&challenge)?,
        _ => {
            return Err(
                "MCSEALED-PRIVATE-PROBE-FIXTURE: coordinator fault scenario is not routed".into(),
            );
        }
    }
    let mut digest = Sha256::new();
    digest.update(b"memcordon-private-probe-fixture-v1\0");
    digest.update([kind as u8]);
    digest.update(challenge);
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(&digest.finalize())
        .and_then(|()| stdout.flush())
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE-FIXTURE: response: {error}"))
}

fn descriptor_identity_filter_namespace() -> Result<(), String> {
    // SAFETY: PR_GET_NO_NEW_PRIVS takes only scalar arguments and does not
    // mutate process state. The native owner separately verifies this gate.
    if unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } != 1 {
        return Err("MCSEALED-PRIVATE-PROBE-FIXTURE: no-new-privileges absent".into());
    }
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE-FIXTURE: status: {error}"))?;
    // The bounding set is intentionally inherited from the authenticated
    // coordinator policy; the native owner compares it with that policy.
    // The target itself must have no usable capabilities.
    for field in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"] {
        let value = status
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .ok_or("MCSEALED-PRIVATE-PROBE-FIXTURE: capability field absent")?;
        if u64::from_str_radix(value.trim(), 16).map_err(|error| error.to_string())? != 0 {
            return Err("MCSEALED-PRIVATE-PROBE-FIXTURE: capability set not empty".into());
        }
    }
    let network = fs::metadata("/proc/self/ns/net")
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE-FIXTURE: network namespace: {error}"))?;
    if network.ino() == 0 {
        return Err("MCSEALED-PRIVATE-PROBE-FIXTURE: network namespace inode zero".into());
    }
    Ok(())
}

fn namespace_port_sysctl_isolation() -> Result<(), String> {
    let unprivileged = fs::read_to_string("/proc/sys/net/ipv4/ip_unprivileged_port_start")
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE-FIXTURE: port start: {error}"))?;
    let range = fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE-FIXTURE: port range: {error}"))?;
    let reserved = fs::read_to_string("/proc/sys/net/ipv4/ip_local_reserved_ports")
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE-FIXTURE: reserved ports: {error}"))?;
    let mut bounds = range.split_whitespace();
    if unprivileged.trim() != "0"
        || bounds.next() != Some("32768")
        || bounds.next() != Some("60999")
        || bounds.next().is_some()
        || !reserved.trim().is_empty()
    {
        return Err("MCSEALED-PRIVATE-PROBE-FIXTURE: private port policy differs".into());
    }
    Ok(())
}

pub(crate) fn tcp_listener_client_competitor(challenge: &[u8; 32]) -> Result<(), String> {
    tcp_listener_client_competitor_observed(challenge).map(|_| ())
}

pub(crate) fn tcp_listener_client_competitor_observed(challenge: &[u8; 32]) -> Result<i32, String> {
    use std::time::Duration;

    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE-FIXTURE: TCP bind: {error}"))?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE-FIXTURE: TCP address: {error}"))?;
    let collision_errno = match TcpListener::bind(address) {
        Ok(_) => return Err("MCSEALED-PRIVATE-PROBE-FIXTURE: competing listener succeeded".into()),
        Err(error) => {
            let errno = error.raw_os_error().ok_or_else(|| {
                format!("MCSEALED-PRIVATE-PROBE-FIXTURE: competing listener errno: {error}")
            })?;
            if errno != libc::EADDRINUSE {
                return Err(format!(
                    "MCSEALED-PRIVATE-PROBE-FIXTURE: competing listener errno: {error}"
                ));
            }
            errno
        }
    };
    let mut client = TcpStream::connect_timeout(&address, Duration::from_secs(2))
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE-FIXTURE: TCP connect: {error}"))?;
    let (mut accepted, peer) = listener
        .accept()
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE-FIXTURE: TCP accept: {error}"))?;
    if peer.ip() != address.ip() {
        return Err("MCSEALED-PRIVATE-PROBE-FIXTURE: TCP peer is not loopback".into());
    }
    client
        .set_write_timeout(Some(Duration::from_secs(2)))
        .and_then(|()| accepted.set_read_timeout(Some(Duration::from_secs(2))))
        .and_then(|()| accepted.set_write_timeout(Some(Duration::from_secs(2))))
        .and_then(|()| client.set_read_timeout(Some(Duration::from_secs(2))))
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE-FIXTURE: TCP timeout: {error}"))?;
    client
        .write_all(challenge)
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE-FIXTURE: TCP send: {error}"))?;
    let mut observed = [0_u8; 32];
    accepted
        .read_exact(&mut observed)
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE-FIXTURE: TCP receive: {error}"))?;
    if observed != *challenge {
        return Err("MCSEALED-PRIVATE-PROBE-FIXTURE: TCP challenge differs".into());
    }
    accepted
        .write_all(&observed)
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE-FIXTURE: TCP echo: {error}"))?;
    client
        .read_exact(&mut observed)
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE-FIXTURE: TCP echo receive: {error}"))?;
    if observed != *challenge {
        return Err("MCSEALED-PRIVATE-PROBE-FIXTURE: TCP echo differs".into());
    }
    Ok(collision_errno)
}

fn denied_socket(
    family: libc::c_int,
    kind: libc::c_int,
    expected_errno: i32,
) -> Result<(), String> {
    // SAFETY: socket takes only scalar arguments; any unexpected successful fd
    // is closed before returning an error.
    let fd = unsafe { libc::socket(family, kind | libc::SOCK_CLOEXEC, 0) };
    let errno = std::io::Error::last_os_error().raw_os_error();
    if fd >= 0 {
        // SAFETY: socket returned one owned descriptor.
        unsafe { libc::close(fd) };
        return Err("MCSEALED-PRIVATE-PROBE-FIXTURE: denied socket succeeded".into());
    }
    if errno != Some(expected_errno) {
        return Err(format!(
            "MCSEALED-PRIVATE-PROBE-FIXTURE: denied socket errno {errno:?} differs"
        ));
    }
    Ok(())
}

fn unix_creation_socketpair_denial() -> Result<(), String> {
    denied_socket(libc::AF_UNIX, libc::SOCK_STREAM, libc::EAFNOSUPPORT)?;
    let mut pair = [-1; 2];
    // SAFETY: socketpair receives two writable descriptor slots; any
    // unexpected successful descriptors are closed before rejection.
    let status = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            pair.as_mut_ptr(),
        )
    };
    let errno = std::io::Error::last_os_error().raw_os_error();
    if status == 0 {
        for fd in pair {
            // SAFETY: successful socketpair initialized each unique fd.
            unsafe { libc::close(fd) };
        }
        return Err("MCSEALED-PRIVATE-PROBE-FIXTURE: denied socketpair succeeded".into());
    }
    if errno != Some(libc::EPERM) {
        return Err(format!(
            "MCSEALED-PRIVATE-PROBE-FIXTURE: socketpair errno {errno:?} differs"
        ));
    }
    Ok(())
}

fn wrong_family_protocol_denial() -> Result<(), String> {
    denied_socket(libc::AF_INET6, libc::SOCK_STREAM, libc::EAFNOSUPPORT)?;
    denied_socket(libc::AF_INET, libc::SOCK_DGRAM, libc::EPROTONOSUPPORT)
}

fn baseline_unix_success(challenge: &[u8; 32]) -> Result<(), String> {
    use std::os::unix::net::UnixStream;

    let (mut sender, mut receiver) = UnixStream::pair()
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE-FIXTURE: UNIX pair: {error}"))?;
    sender
        .write_all(challenge)
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE-FIXTURE: UNIX send: {error}"))?;
    let mut observed = [0_u8; 32];
    receiver
        .read_exact(&mut observed)
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE-FIXTURE: UNIX receive: {error}"))?;
    if observed != *challenge {
        return Err("MCSEALED-PRIVATE-PROBE-FIXTURE: UNIX challenge differs".into());
    }
    Ok(())
}

impl ProbeRunAuthority {
    /// The caller must already have authenticated the protected launcher
    /// service operation. Kernel and account facts are obtained independently
    /// here; no public frame supplies a UID, fixture, argv, or case name.
    pub(crate) fn begin(
        package: crate::package::VerifiedProbePackageLease,
        coordinator_pid: libc::pid_t,
        coordinator_pidfd: OwnedFd,
        deadline: Instant,
        nonce: [u8; 32],
        run_directory: File,
    ) -> Result<Self, String> {
        // SAFETY: scalar credential and PID observations have no pointer arguments.
        let uid = unsafe { libc::geteuid() };
        if uid != 0 || deadline <= Instant::now() {
            return Err("MCSEALED-PRIVATE-PROBE: root and a future deadline required".into());
        }
        verify_qualification_service_context()?;
        let run_lock = acquire_run_lock()?;
        let ambiguous = super::recovery::recover()?;
        if !ambiguous.is_empty() {
            return Err(format!(
                "MCSEALED-PRIVATE-PROBE: unresolved prior state: {}",
                ambiguous.join(",")
            ));
        }
        let coordinator = ProcessIdentityV4::observe(coordinator_pid, coordinator_pidfd.as_fd())?;
        let (target_uid, target_gid) = fixed_probe_account()?;
        let work_directory = verify_probe_working_directory()?;
        if target_uid == 0 || target_gid == 0 || target_uid == uid {
            return Err("MCSEALED-PRIVATE-PROBE: dedicated nonroot identity absent".into());
        }
        let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|error| error.to_string())?
            .trim()
            .to_owned();
        if boot_id.is_empty() {
            return Err("MCSEALED-PRIVATE-PROBE: boot identity absent".into());
        }
        let prerequisites =
            super::private_host_prerequisites::observe_host_prerequisites(&package)?;
        if prerequisites.boot_id() != boot_id
            || prerequisites.target_ids() != (target_uid, target_gid)
        {
            return Err("MCSEALED-PRIVATE-PROBE: host prerequisite identity differs".into());
        }
        let service = prerequisites.service_generation();
        if service.main().pid != unsafe { libc::getppid() } as u32 {
            return Err("MCSEALED-PRIVATE-PROBE: worker is not owned by launcher service".into());
        }
        super::private_host_prerequisites::require_current_worker_cgroup(service)?;
        let service_generation_digest = service.digest()?;
        let host_prerequisites_digest = prerequisites.digest()?;
        let installation_epoch = prerequisites.installation_epoch().clone();
        verify_transferred_run_directory(&nonce, &run_directory)?;
        Ok(Self {
            package,
            _run_lock: run_lock,
            _work_directory: work_directory,
            coordinator_pidfd,
            coordinator,
            nonce,
            run_directory,
            boot_id,
            target_uid,
            target_gid,
            service_generation_digest,
            host_prerequisites_digest,
            installation_epoch,
            deadline,
        })
    }

    pub(crate) fn case(&self, index: usize) -> Result<ProbeCaseAuthority<'_>, String> {
        if ProbeFixtureKindV1::at(index).is_none()
            || index >= HOST_PROBE_CATALOG_V1.len()
            || Instant::now() >= self.deadline
            || fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .map_err(|error| error.to_string())?
                .trim()
                != self.boot_id
            || super::private_host_prerequisites::observe_host_prerequisites(&self.package)?
                .digest()?
                != self.host_prerequisites_digest
        {
            return Err("MCSEALED-PRIVATE-PROBE: case or live run differs".into());
        }
        // SAFETY: poll only observes the retained coordinator pidfd.
        let mut pollfd = libc::pollfd {
            fd: self.coordinator_pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&raw mut pollfd, 1, 0) } != 0 || pollfd.revents != 0 {
            return Err("MCSEALED-PRIVATE-PROBE: coordinator exited".into());
        }
        Ok(ProbeCaseAuthority {
            run: self,
            index,
            loss_kind: None,
            frontend: None,
        })
    }

    pub(crate) fn verify_complete_run(&self) -> Result<VerifiedHostRunV1, String> {
        verify_complete_run_inventory(&self.run_directory, &self.nonce)?;
        let mut probes = Vec::with_capacity(HOST_PROBE_CATALOG_V1.len());
        for index in 0..HOST_PROBE_CATALOG_V1.len() {
            let probe = self
                .case(index)?
                .verify_persisted_completion()?
                .into_native_probe();
            probes.push(probe);
        }
        Ok(VerifiedHostRunV1 {
            native_run_digest: verified_host_run_digest(
                &self.nonce,
                &self.boot_id,
                &self.package,
                &self.coordinator,
                &self.service_generation_digest,
                &self.host_prerequisites_digest,
                &self.installation_epoch,
                &probes,
            )?,
            host_prerequisites_digest: self.host_prerequisites_digest.clone(),
            installation_epoch: self.installation_epoch.clone(),
            coordinator: self.coordinator.clone(),
            probes,
        })
    }

    pub(crate) fn verify_independent_readback(&self) -> Result<VerifiedHostRunV1, String> {
        verify_completed_run_after_exit(&self.nonce, &self.run_directory, &self.package)
    }
}

pub(crate) fn verify_complete_run_inventory(
    directory: &File,
    nonce: &[u8; 32],
) -> Result<(), String> {
    let expected: BTreeSet<String> = (0..HOST_PROBE_CATALOG_V1.len())
        .map(|index| format!("case-{index}.completion.json"))
        .chain(
            [0, 2, 3, 4, 5, 6]
                .into_iter()
                .map(|index| format!("case-{index}.json")),
        )
        .chain([
            "case-1-frontend.json".to_owned(),
            "case-1-guardian.json".to_owned(),
            format!("{}.retired", probe_attempt_id(nonce, 7)),
        ])
        .collect();
    let observed: BTreeSet<String> = pinned_directory_items(directory)?
        .into_iter()
        .map(|(name, inode)| {
            if inode == 0 {
                return Err("MCSEALED-PRIVATE-PROBE: zero run entry inode".into());
            }
            name.into_string()
                .map_err(|_| "MCSEALED-PRIVATE-PROBE: non-UTF8 run entry".into())
        })
        .collect::<Result<_, String>>()?;
    if observed != expected {
        return Err("MCSEALED-PRIVATE-PROBE: complete run inventory differs".into());
    }
    Ok(())
}

// Each binding is independently sampled or derived from a distinct protected
// source; keeping explicit arguments makes accidental omission visible.
#[allow(clippy::too_many_arguments)]
fn verified_host_run_digest(
    nonce: &[u8; 32],
    boot_id: &str,
    package: &crate::package::VerifiedProbePackageLease,
    coordinator: &ProcessIdentityV4,
    service_generation_digest: &DiagnosticSha256,
    host_prerequisites_digest: &DiagnosticSha256,
    installation_epoch: &DiagnosticSha256,
    probes: &[super::qualification::NativeQualificationProbeV4],
) -> Result<DiagnosticSha256, String> {
    let mut digest = Sha256::new();
    digest.update(b"memcordon-private-verified-host-run-v1\0");
    digest.update(nonce);
    hash_length_prefixed(&mut digest, boot_id.as_bytes());
    digest.update(package.runtime_manifest_sha256.bytes());
    digest.update(package.release_qualification_sha256.bytes());
    digest.update(service_generation_digest.bytes());
    digest.update(host_prerequisites_digest.bytes());
    digest.update(installation_epoch.bytes());
    digest.update(package.agent_sha256.bytes());
    digest.update(package.filter_sha256.bytes());
    digest.update(catalogue_digest().bytes());
    hash_length_prefixed(&mut digest, package.source_commit.as_bytes());
    hash_length_prefixed(&mut digest, package.target.as_bytes());
    let units = serde_json::to_vec(&package.units).map_err(|error| error.to_string())?;
    hash_length_prefixed(&mut digest, &units);
    let coordinator = serde_json::to_vec(coordinator).map_err(|error| error.to_string())?;
    hash_length_prefixed(&mut digest, &coordinator);
    for (index, probe) in probes.iter().enumerate() {
        digest.update((index as u64).to_be_bytes());
        digest.update(probe.completion_digest.bytes());
    }
    Ok(DiagnosticSha256::from_bytes(digest.finalize().into()))
}

/// Reopens a finished protected run without retaining or resurrecting its
/// coordinator capability. This is deliberately separate from the live
/// producer's `verify_complete_run`: a dead coordinator cannot authorize new
/// fixture work, but its exact retired records remain verifiable evidence.
pub(crate) fn verify_completed_run_after_exit(
    nonce: &[u8; 32],
    directory: &File,
    package: &crate::package::VerifiedProbePackageLease,
) -> Result<VerifiedHostRunV1, String> {
    verify_existing_run_directory(nonce, directory)?;
    verify_complete_run_inventory(directory, nonce)?;
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|error| error.to_string())?
        .trim()
        .to_owned();
    if boot_id.is_empty() {
        return Err("MCSEALED-PRIVATE-PROBE: current boot identity absent".into());
    }
    let (target_uid, target_gid) = fixed_probe_account()?;
    let prerequisites = super::private_host_prerequisites::observe_host_prerequisites(package)?;
    if prerequisites.boot_id() != boot_id || prerequisites.target_ids() != (target_uid, target_gid)
    {
        return Err("MCSEALED-PRIVATE-PROBE: readback prerequisite identity differs".into());
    }
    let service_generation_digest = prerequisites.service_generation().digest()?;
    let host_prerequisites_digest = prerequisites.digest()?;
    let installation_epoch = prerequisites.installation_epoch().clone();
    let first_name = CString::new("case-0.json").expect("fixed case name");
    let first_bytes = read_protected_probe_file(directory, &first_name)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&first_bytes)?;
    let first: ProbeCaseRecordV1 =
        serde_json::from_slice(&first_bytes).map_err(|error| error.to_string())?;
    if first.coordinator.pid <= 1 || first.coordinator.start_time == 0 {
        return Err("MCSEALED-PRIVATE-PROBE: recorded coordinator identity differs".into());
    }
    let coordinator = first.coordinator;
    let mut probes = Vec::with_capacity(HOST_PROBE_CATALOG_V1.len());
    for (index, (profile, name)) in HOST_PROBE_CATALOG_V1.iter().enumerate() {
        let completion_name =
            CString::new(format!("case-{index}.completion.json")).expect("numeric completion name");
        let bytes = read_protected_probe_file(directory, &completion_name)?;
        let completion_digest = match ProbeFixtureKindV1::at(index).expect("closed catalogue") {
            ProbeFixtureKindV1::FrontendGuardianLossRetirement => {
                let completion = ProbeLossCompletionV1::parse_verified(&bytes)?;
                if completion.run_nonce != hex(nonce) || completion.case_index != index {
                    return Err("MCSEALED-PRIVATE-PROBE: stored loss run differs".into());
                }
                for (kind, branch) in [ProbeLossKindV1::Frontend, ProbeLossKindV1::Guardian]
                    .into_iter()
                    .zip(&completion.branches)
                {
                    let expected = initial_probe_record(
                        nonce,
                        index,
                        Some(kind),
                        &branch.frontend,
                        &coordinator,
                        &boot_id,
                        target_uid,
                        target_gid,
                        &service_generation_digest,
                        &host_prerequisites_digest,
                        &installation_epoch,
                        package,
                    )?;
                    let name = CString::new(match kind {
                        ProbeLossKindV1::Frontend => "case-1-frontend.json",
                        ProbeLossKindV1::Guardian => "case-1-guardian.json",
                    })
                    .expect("fixed loss record name");
                    let retired = verify_retired_probe_record(
                        directory,
                        &name,
                        &expected,
                        &branch.attempt_id,
                        &branch.checkpoint_digest,
                        &branch.retired_record_digest,
                    )?;
                    verify_stored_loss_branch(nonce, kind, branch, &retired, &coordinator)?;
                }
                if completion.branches[0].frontend == completion.branches[1].frontend {
                    return Err("MCSEALED-PRIVATE-PROBE: stored loss frontend reused".into());
                }
                completion.completion_digest
            }
            ProbeFixtureKindV1::TargetExecFailureRetirement => {
                let completion = ProbeFailedExecCompletionV1::parse_verified(&bytes)?;
                let retired = verify_stored_retirement(
                    nonce,
                    directory,
                    package,
                    &coordinator,
                    &boot_id,
                    target_uid,
                    target_gid,
                    &service_generation_digest,
                    &host_prerequisites_digest,
                    &installation_epoch,
                    index,
                    &completion.attempt_id,
                    &completion.checkpoint_digest,
                    &completion.retired_record_digest,
                )?;
                if completion.run_nonce != hex(nonce)
                    || completion.attempt_id != probe_attempt_id(nonce, index)
                    || retired.release_knowledge != ReleaseKnowledge::PossiblyReleased
                    || retired.candidate_exit_code != Some(125)
                    || completion.challenge_sha256
                        != hash_bytes(&probe_challenge_bytes(nonce, index, None))
                {
                    return Err("MCSEALED-PRIVATE-PROBE: stored failed exec differs".into());
                }
                completion.completion_digest
            }
            ProbeFixtureKindV1::BaselineUnixSuccessRetirement => {
                let completion = ProbeBaselineCompletionV1::parse_verified(&bytes)?;
                let expected = initial_probe_record(
                    nonce,
                    index,
                    None,
                    &coordinator,
                    &coordinator,
                    &boot_id,
                    target_uid,
                    target_gid,
                    &service_generation_digest,
                    &host_prerequisites_digest,
                    &installation_epoch,
                    package,
                )?;
                let retired = super::attempt::verify_probe_retired_in(
                    directory,
                    &probe_attempt_id(nonce, index),
                    &String::from(expected.record_digest),
                )?;
                if completion.run_nonce != hex(nonce)
                    || completion.attempt_id != probe_attempt_id(nonce, index)
                    || completion.retired_record_digest != retired
                    || completion.challenge_sha256
                        != hash_bytes(&probe_challenge_bytes(nonce, index, None))
                    || completion.response_sha256
                        != hash_bytes(&expected_probe_fixture_response(nonce, index))
                    || completion.terminal_projection.attempt != probe_attempt_bytes(nonce, index)
                    || completion.terminal_projection.validate_and_digest()?
                        != completion.terminal_facts_sha256
                {
                    return Err("MCSEALED-PRIVATE-PROBE: stored baseline differs".into());
                }
                completion.completion_digest
            }
            _ => {
                let completion = ProbeSuccessfulCompletionV1::parse_verified(&bytes)?;
                let retired = verify_stored_retirement(
                    nonce,
                    directory,
                    package,
                    &coordinator,
                    &boot_id,
                    target_uid,
                    target_gid,
                    &service_generation_digest,
                    &host_prerequisites_digest,
                    &installation_epoch,
                    index,
                    &completion.attempt_id,
                    &completion.checkpoint_digest,
                    &completion.retired_record_digest,
                )?;
                if completion.run_nonce != hex(nonce)
                    || completion.case_index != index
                    || completion.attempt_id != probe_attempt_id(nonce, index)
                    || retired.release_knowledge != ReleaseKnowledge::ExecObserved
                    || retired.candidate_exit_code != Some(0)
                    || completion.challenge_sha256
                        != hash_bytes(&probe_challenge_bytes(nonce, index, None))
                    || completion.response_sha256
                        != hash_bytes(&expected_probe_fixture_response(nonce, index))
                {
                    return Err("MCSEALED-PRIVATE-PROBE: stored successful case differs".into());
                }
                completion.completion_digest
            }
        };
        probes.push(super::qualification::NativeQualificationProbeV4 {
            profile: profile.reference(),
            name: (*name).into(),
            native_executed: true,
            passed: true,
            completion_digest,
        });
    }
    if super::private_host_prerequisites::observe_host_prerequisites(package)?.digest()?
        != host_prerequisites_digest
    {
        return Err("MCSEALED-PRIVATE-PROBE: service generation changed during readback".into());
    }
    Ok(VerifiedHostRunV1 {
        native_run_digest: verified_host_run_digest(
            nonce,
            &boot_id,
            package,
            &coordinator,
            &service_generation_digest,
            &host_prerequisites_digest,
            &installation_epoch,
            &probes,
        )?,
        host_prerequisites_digest,
        installation_epoch,
        coordinator,
        probes,
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_stored_retirement(
    nonce: &[u8; 32],
    directory: &File,
    package: &crate::package::VerifiedProbePackageLease,
    coordinator: &ProcessIdentityV4,
    boot_id: &str,
    target_uid: u32,
    target_gid: u32,
    service_generation_digest: &DiagnosticSha256,
    host_prerequisites_digest: &DiagnosticSha256,
    installation_epoch: &DiagnosticSha256,
    index: usize,
    attempt_id: &str,
    checkpoint_digest: &DiagnosticSha256,
    record_digest: &DiagnosticSha256,
) -> Result<ProbeCaseRecordV1, String> {
    let expected = initial_probe_record(
        nonce,
        index,
        None,
        coordinator,
        coordinator,
        boot_id,
        target_uid,
        target_gid,
        service_generation_digest,
        host_prerequisites_digest,
        installation_epoch,
        package,
    )?;
    let name = CString::new(format!("case-{index}.json")).expect("numeric record name");
    verify_retired_probe_record(
        directory,
        &name,
        &expected,
        attempt_id,
        checkpoint_digest,
        record_digest,
    )
}

fn verify_stored_loss_branch(
    nonce: &[u8; 32],
    kind: ProbeLossKindV1,
    branch: &ProbeLossBranchCompletionV1,
    retired: &ProbeCaseRecordV1,
    coordinator: &ProcessIdentityV4,
) -> Result<(), String> {
    if branch.kind != kind
        || branch.attempt_id != probe_loss_attempt_id(nonce, kind)
        || branch.challenge_sha256 != hash_bytes(&probe_loss_challenge_bytes(nonce, kind))
        || branch.armed_response_sha256 != hash_bytes(&probe_loss_armed_response(nonce, kind))
        || branch.frontend == *coordinator
        || branch.candidate_exit_code == Some(0)
        || retired.release_knowledge != ReleaseKnowledge::ExecObserved
        || retired.candidate_exit_code != branch.candidate_exit_code
        || retired.cleanup_error.is_some()
    {
        return Err("MCSEALED-PRIVATE-PROBE: stored loss branch differs".into());
    }
    match (&branch.physical, kind) {
        (
            ProbeLossProofRecordV1::Frontend {
                proxy_wait_signal,
                guardian_terminal,
            },
            ProbeLossKindV1::Frontend,
        ) => {
            let terminal = super::private_guardian::GuardianTerminalV4::decode(
                *guardian_terminal,
                probe_loss_attempt_bytes(nonce, kind),
            )?;
            if *proxy_wait_signal != libc::SIGKILL
                || terminal.trigger != super::private_guardian::GuardianTriggerV4::FrontendLost
                || !terminal.boundary_retired
            {
                return Err("MCSEALED-PRIVATE-PROBE: stored frontend loss differs".into());
            }
        }
        (
            ProbeLossProofRecordV1::Guardian {
                guardian,
                guardian_signal,
                proxy_exit_code,
            },
            ProbeLossKindV1::Guardian,
        ) => {
            if retired.guardian.as_ref() != Some(guardian)
                || *guardian_signal != libc::SIGKILL
                || *proxy_exit_code != 0
            {
                return Err("MCSEALED-PRIVATE-PROBE: stored guardian loss differs".into());
            }
        }
        _ => return Err("MCSEALED-PRIVATE-PROBE: stored loss proof kind differs".into()),
    }
    Ok(())
}

impl ProbeCaseAuthority<'_> {
    pub(crate) fn attempt_bytes(&self) -> [u8; 16] {
        match self.loss_kind {
            Some(kind) => probe_loss_attempt_bytes(&self.run.nonce, kind),
            None => probe_attempt_bytes(&self.run.nonce, self.index),
        }
    }

    pub(crate) fn challenge_bytes(&self) -> [u8; 32] {
        probe_challenge_bytes(&self.run.nonce, self.index, self.loss_kind)
    }

    pub(crate) fn loss_subcase(
        &self,
        kind: ProbeLossKindV1,
        proxy_pid: libc::pid_t,
        proxy_pidfd: OwnedFd,
    ) -> Result<ProbeLossCaseAuthority<'_>, String> {
        if self.kind() != ProbeFixtureKindV1::FrontendGuardianLossRetirement
            || self.loss_kind.is_some()
            || proxy_pid <= 1
            || proxy_pid == self.run.coordinator.pid as libc::pid_t
            || proxy_pid == unsafe { libc::getpid() }
        {
            return Err("MCSEALED-PRIVATE-PROBE: loss proxy identity differs".into());
        }
        self.revalidate()?;
        let frontend = ProcessIdentityV4::observe(proxy_pid, proxy_pidfd.as_fd())?;
        let case = ProbeCaseAuthority {
            run: self.run,
            index: self.index,
            loss_kind: Some(kind),
            frontend: Some(frontend),
        };
        Ok(ProbeLossCaseAuthority {
            case,
            frontend_pidfd: proxy_pidfd,
        })
    }

    fn record_leaf(&self) -> CString {
        let name = match self.loss_kind {
            Some(ProbeLossKindV1::Frontend) => "case-1-frontend.json".to_owned(),
            Some(ProbeLossKindV1::Guardian) => "case-1-guardian.json".to_owned(),
            None => format!("case-{}.json", self.index),
        };
        CString::new(name).expect("fixed probe record name has no NUL")
    }

    pub(crate) fn expected_fixture_response(&self) -> [u8; 32] {
        expected_probe_fixture_response(&self.run.nonce, self.index)
    }

    pub(crate) fn work_directory(&self) -> Result<File, String> {
        self.run.case(self.index)?;
        self.run
            ._work_directory
            .try_clone()
            .map_err(|error| error.to_string())
    }

    pub(crate) fn kind(&self) -> ProbeFixtureKindV1 {
        ProbeFixtureKindV1::at(self.index).expect("run selected a closed catalogue case")
    }

    pub(crate) fn name(&self) -> &'static str {
        HOST_PROBE_CATALOG_V1[self.index].1
    }

    pub(crate) fn profile(&self) -> ProfileRef {
        HOST_PROBE_CATALOG_V1[self.index].0.reference()
    }

    pub(crate) fn target_ids(&self) -> (u32, u32) {
        (self.run.target_uid, self.run.target_gid)
    }

    pub(crate) fn fixture_digest(&self) -> &DiagnosticSha256 {
        &self.run.package.agent_sha256
    }

    pub(crate) fn pinned_fixture_entrypoint(
        &self,
    ) -> Result<super::entrypoint::VerifiedEntrypoint, String> {
        self.revalidate()?;
        self.run.package.pinned_fixture_entrypoint()
    }

    pub(crate) fn allocate_baseline_probe_record(
        &self,
    ) -> Result<super::attempt::AttemptRecord, String> {
        if self.kind() != ProbeFixtureKindV1::BaselineUnixSuccessRetirement {
            return Err("MCSEALED-PRIVATE-PROBE: baseline record requested for wrong case".into());
        }
        self.revalidate()?;
        super::attempt::AttemptRecord::create_probe_in(
            self.run
                .run_directory
                .try_clone()
                .map_err(|error| error.to_string())?,
            probe_attempt_id(&self.run.nonce, self.index),
            self.run.coordinator.pid as libc::pid_t,
            String::from(self.initial_record()?.record_digest),
        )
    }

    pub(crate) fn baseline_retired_record_digest(&self) -> Result<DiagnosticSha256, String> {
        if self.kind() != ProbeFixtureKindV1::BaselineUnixSuccessRetirement {
            return Err(
                "MCSEALED-PRIVATE-PROBE: baseline readback requested for wrong case".into(),
            );
        }
        self.revalidate()?;
        super::attempt::verify_probe_retired_in(
            &self.run.run_directory,
            &probe_attempt_id(&self.run.nonce, self.index),
            &String::from(self.initial_record()?.record_digest),
        )
    }

    pub(crate) fn native_abi(&self) -> Result<super::network_filter::NativeAbi, String> {
        if self.run.package.target != super::runtime_manifest::target()? {
            return Err("MCSEALED-PRIVATE-PROBE: installed target differs from coordinator".into());
        }
        match self.run.package.target.as_str() {
            "x86_64-unknown-linux-gnu" => Ok(super::network_filter::NativeAbi::X86_64),
            "aarch64-unknown-linux-gnu" => Ok(super::network_filter::NativeAbi::Aarch64),
            _ => Err("MCSEALED-PRIVATE-PROBE: installed target ABI differs".into()),
        }
    }

    pub(crate) fn filter_digest(&self) -> &DiagnosticSha256 {
        &self.run.package.filter_sha256
    }

    pub(crate) fn coordinator_pidfd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.run.coordinator_pidfd.as_fd()
    }

    pub(crate) fn coordinator_pid(&self) -> libc::pid_t {
        self.run.coordinator.pid as libc::pid_t
    }

    pub(crate) fn duplicate_coordinator_pidfd(&self) -> Result<OwnedFd, String> {
        self.revalidate()?;
        self.run
            .coordinator_pidfd
            .try_clone()
            .map_err(|error| error.to_string())
    }

    pub(crate) fn deadline(&self) -> Instant {
        self.run.deadline
    }

    pub(crate) fn revoked(&self) -> bool {
        self.run.case(self.index).is_err()
    }

    pub(crate) fn revalidate(&self) -> Result<(), String> {
        self.run.case(self.index).map(|_| ())
    }

    /// A probe enters the exact V4 physical owner only after its separate
    /// case record is durably frozen. There is no production admission or
    /// qualification digest in this transition.
    pub(crate) fn begin_native_owner(
        &self,
    ) -> Result<super::private_lifecycle::PrivateAttemptOwner<DurableProbeAttempt>, String> {
        if self.kind() == ProbeFixtureKindV1::FrontendGuardianLossRetirement
            && self.loss_kind.is_none()
        {
            return Err("MCSEALED-PRIVATE-PROBE: loss branch absent".into());
        }
        let mut journal = DurableProbeAttempt::allocate(self)?;
        journal.freeze_case(self)?;
        super::private_lifecycle::PrivateAttemptOwner::new(journal)
    }

    /// Prepare a fixed installed-image fixture without passing through a
    /// caller program path or the qualified production admission constructor.
    pub(crate) fn prepare_native_prelaunch(
        &self,
    ) -> Result<super::launch::PrivateGatedPrelaunch, String> {
        self.run.case(self.index)?;
        let abi = self.native_abi()?;
        let identity = super::execution_identity::ResolvedTargetIdentity::for_probe_account(
            self.run.target_uid,
            self.run.target_gid,
        )?;
        let entrypoint = self.run.package.pinned_fixture_entrypoint()?;
        let command = super::private_target::PrivateExecArguments::for_probe_fixture(self.kind())?;
        super::launch::prepare_probe_gated_prelaunch(
            identity,
            entrypoint,
            self.run.package.agent_sha256.clone(),
            command,
            abi,
            *self.run.package.filter_sha256.bytes(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn bind_native_checkpoint(
        &self,
        guardian: ProcessIdentityV4,
        namespace_init: ProcessIdentityV4,
        target: ProcessIdentityV4,
        network_namespace_inode: u64,
        target_uid: u32,
        target_gid: u32,
        observed_filter: [u8; 32],
        topology_sha256: DiagnosticSha256,
        native_readback_sha256: DiagnosticSha256,
    ) -> Result<ProbeCheckpointBindingV1, String> {
        self.run.case(self.index)?;
        if target_uid != self.run.target_uid
            || target_gid != self.run.target_gid
            || observed_filter != *self.run.package.filter_sha256.bytes()
            || network_namespace_inode == 0
        {
            return Err("MCSEALED-PRIVATE-PROBE: native checkpoint differs from fixed case".into());
        }
        Ok(ProbeCheckpointBindingV1 {
            schema_version: 1,
            run_nonce: hex(&self.run.nonce),
            case_index: self.index,
            attempt_id: hex(&self.attempt_bytes()),
            boot_id: self.run.boot_id.clone(),
            runtime_manifest_sha256: self.run.package.runtime_manifest_sha256.clone(),
            fixture_sha256: self.run.package.agent_sha256.clone(),
            catalogue_sha256: catalogue_digest(),
            filter_sha256: self.run.package.filter_sha256.clone(),
            target_uid,
            target_gid,
            guardian,
            namespace_init,
            target,
            network_namespace_inode,
            topology_sha256,
            native_readback_sha256,
        })
    }

    pub(crate) fn persist_successful_completion(
        &self,
        observation: &super::private_probe_execution::ProbeSuccessfulFixtureV1,
    ) -> Result<DiagnosticSha256, String> {
        let retired = self.retired_record_for_case(
            &observation.attempt_id,
            &observation.checkpoint_digest,
            &observation.terminal_record_digest,
        )?;
        if retired.release_knowledge != ReleaseKnowledge::ExecObserved
            || retired.candidate_exit_code != Some(0)
            || observation.challenge_sha256 != hash_bytes(&self.challenge_bytes())
            || observation.response_sha256 != hash_bytes(&self.expected_fixture_response())
        {
            return Err("MCSEALED-PRIVATE-PROBE: successful native observation differs".into());
        }
        let mut completion = ProbeSuccessfulCompletionV1 {
            schema_version: 1,
            run_nonce: hex(&self.run.nonce),
            case_index: self.index,
            attempt_id: observation.attempt_id.clone(),
            retired_record_digest: retired.record_digest,
            checkpoint_digest: observation.checkpoint_digest.clone(),
            challenge_sha256: observation.challenge_sha256.clone(),
            response_sha256: observation.response_sha256.clone(),
            candidate_exit_code: 0,
            completion_digest: DiagnosticSha256::from_bytes([0; 32]),
        };
        completion.completion_digest = completion.canonical_digest()?;
        let bytes = serde_json::to_vec(&completion).map_err(|error| error.to_string())?;
        let readback = self.persist_completion_bytes(&bytes)?;
        if readback != bytes
            || ProbeSuccessfulCompletionV1::parse_verified(&readback)? != completion
        {
            return Err("MCSEALED-PRIVATE-PROBE: completion readback differs".into());
        }
        Ok(completion.completion_digest)
    }

    pub(crate) fn persist_failed_exec_completion(
        &self,
        observed: &ProbeFailedExecObservationV1,
    ) -> Result<DiagnosticSha256, String> {
        if self.kind() != ProbeFixtureKindV1::TargetExecFailureRetirement
            || observed.phase != 5
            || observed.detail != "MCSEALED-PROBE-EXECVEAT-ENOENT"
        {
            return Err("MCSEALED-PRIVATE-PROBE: wrong failed-exec case or stage".into());
        }
        let retired = self.retired_record_for_case(
            &observed.attempt_id,
            &observed.checkpoint_digest,
            &observed.terminal_record_digest,
        )?;
        if retired.release_knowledge != ReleaseKnowledge::PossiblyReleased
            || retired.candidate_exit_code != Some(125)
        {
            return Err("MCSEALED-PRIVATE-PROBE: failed-exec retirement differs".into());
        }
        let mut completion = ProbeFailedExecCompletionV1 {
            schema_version: 1,
            run_nonce: hex(&self.run.nonce),
            case_index: self.index,
            attempt_id: observed.attempt_id.clone(),
            retired_record_digest: retired.record_digest,
            checkpoint_digest: observed.checkpoint_digest.clone(),
            challenge_sha256: hash_bytes(&self.challenge_bytes()),
            phase: observed.phase,
            detail: observed.detail.clone(),
            candidate_exit_code: 125,
            completion_digest: DiagnosticSha256::from_bytes([0; 32]),
        };
        completion.completion_digest = completion.canonical_digest()?;
        let bytes = serde_json::to_vec(&completion).map_err(|error| error.to_string())?;
        let readback = self.persist_completion_bytes(&bytes)?;
        if readback != bytes
            || ProbeFailedExecCompletionV1::parse_verified(&readback)? != completion
        {
            return Err("MCSEALED-PRIVATE-PROBE: failed-exec readback differs".into());
        }
        Ok(completion.completion_digest)
    }

    pub(crate) fn persist_baseline_completion(
        &self,
        observed: &BaselineProbeObservationV1,
    ) -> Result<DiagnosticSha256, String> {
        if self.kind() != ProbeFixtureKindV1::BaselineUnixSuccessRetirement
            || observed.attempt_id != probe_attempt_id(&self.run.nonce, self.index)
            || observed.retired_record_digest != self.baseline_retired_record_digest()?
            || observed.challenge_sha256 != hash_bytes(&self.challenge_bytes())
            || observed.response_sha256 != hash_bytes(&self.expected_fixture_response())
            || observed.terminal_projection.attempt != self.attempt_bytes()
            || observed.terminal_projection.validate_and_digest()? != observed.terminal_facts_sha256
        {
            return Err("MCSEALED-PRIVATE-PROBE: baseline native observation differs".into());
        }
        let mut completion = ProbeBaselineCompletionV1 {
            schema_version: 1,
            run_nonce: hex(&self.run.nonce),
            case_index: self.index,
            attempt_id: observed.attempt_id.clone(),
            retired_record_digest: observed.retired_record_digest.clone(),
            challenge_sha256: observed.challenge_sha256.clone(),
            response_sha256: observed.response_sha256.clone(),
            terminal_facts_sha256: observed.terminal_facts_sha256.clone(),
            terminal_projection: observed.terminal_projection.clone(),
            completion_digest: DiagnosticSha256::from_bytes([0; 32]),
        };
        completion.completion_digest = completion.canonical_digest()?;
        let bytes = serde_json::to_vec(&completion).map_err(|error| error.to_string())?;
        let readback = self.persist_completion_bytes(&bytes)?;
        if readback != bytes || ProbeBaselineCompletionV1::parse_verified(&readback)? != completion
        {
            return Err("MCSEALED-PRIVATE-PROBE: baseline readback differs".into());
        }
        Ok(completion.completion_digest)
    }

    pub(crate) fn persist_loss_completion(
        &self,
        observations: &[ProbeLossSubattemptObservationV1; 2],
    ) -> Result<DiagnosticSha256, String> {
        if self.kind() != ProbeFixtureKindV1::FrontendGuardianLossRetirement
            || self.loss_kind.is_some()
        {
            return Err("MCSEALED-PRIVATE-PROBE: dual loss requires base case".into());
        }
        let branches = [ProbeLossKindV1::Frontend, ProbeLossKindV1::Guardian]
            .into_iter()
            .zip(observations)
            .map(|(kind, observed)| self.loss_branch_from_observation(kind, observed))
            .collect::<Result<Vec<_>, _>>()?;
        let mut completion = ProbeLossCompletionV1 {
            schema_version: 1,
            run_nonce: hex(&self.run.nonce),
            case_index: self.index,
            branches: branches.try_into().expect("exactly two loss branches"),
            completion_digest: DiagnosticSha256::from_bytes([0; 32]),
        };
        completion.completion_digest = completion.canonical_digest()?;
        self.verify_loss_completion(&completion)?;
        let bytes = serde_json::to_vec(&completion).map_err(|error| error.to_string())?;
        let readback = self.persist_completion_bytes(&bytes)?;
        let parsed = ProbeLossCompletionV1::parse_verified(&readback)?;
        if readback != bytes || parsed != completion {
            return Err("MCSEALED-PRIVATE-PROBE: dual loss readback differs".into());
        }
        self.verify_loss_completion(&parsed)?;
        Ok(completion.completion_digest)
    }

    fn loss_branch_from_observation(
        &self,
        kind: ProbeLossKindV1,
        observed: &ProbeLossSubattemptObservationV1,
    ) -> Result<ProbeLossBranchCompletionV1, String> {
        if observed.kind != kind {
            return Err("MCSEALED-PRIVATE-PROBE: loss branch order differs".into());
        }
        let physical = match (&observed.physical, kind) {
            (
                ProbeLossPhysicalProofV1::Frontend {
                    proxy_wait_signal,
                    guardian_terminal,
                },
                ProbeLossKindV1::Frontend,
            ) => ProbeLossProofRecordV1::Frontend {
                proxy_wait_signal: *proxy_wait_signal,
                guardian_terminal: guardian_terminal.encode(),
            },
            (
                ProbeLossPhysicalProofV1::Guardian {
                    guardian_killed,
                    proxy_exit_code,
                },
                ProbeLossKindV1::Guardian,
            ) => ProbeLossProofRecordV1::Guardian {
                guardian: guardian_killed.identity.clone(),
                guardian_signal: guardian_killed.signal,
                proxy_exit_code: *proxy_exit_code,
            },
            _ => return Err("MCSEALED-PRIVATE-PROBE: loss physical proof kind differs".into()),
        };
        Ok(ProbeLossBranchCompletionV1 {
            kind,
            attempt_id: observed.attempt_id.clone(),
            checkpoint_digest: observed.checkpoint_digest.clone(),
            retired_record_digest: observed.terminal_record_digest.clone(),
            challenge_sha256: observed.challenge_sha256.clone(),
            armed_response_sha256: observed.armed_response_sha256.clone(),
            frontend: observed.frontend.clone(),
            candidate_exit_code: observed.candidate_exit_code,
            physical,
        })
    }

    fn verify_loss_completion(&self, completion: &ProbeLossCompletionV1) -> Result<(), String> {
        if completion.run_nonce != hex(&self.run.nonce)
            || completion.case_index != 1
            || self.index != 1
            || self.loss_kind.is_some()
        {
            return Err("MCSEALED-PRIVATE-PROBE: loss completion case differs".into());
        }
        for (kind, branch) in [ProbeLossKindV1::Frontend, ProbeLossKindV1::Guardian]
            .into_iter()
            .zip(&completion.branches)
        {
            if branch.kind != kind
                || branch.attempt_id != probe_loss_attempt_id(&self.run.nonce, kind)
                || branch.challenge_sha256
                    != hash_bytes(&probe_loss_challenge_bytes(&self.run.nonce, kind))
                || branch.armed_response_sha256
                    != hash_bytes(&probe_loss_armed_response(&self.run.nonce, kind))
                || branch.frontend == self.run.coordinator
                || branch.candidate_exit_code == Some(0)
            {
                return Err("MCSEALED-PRIVATE-PROBE: loss branch binding differs".into());
            }
            let branch_case = ProbeCaseAuthority {
                run: self.run,
                index: 1,
                loss_kind: Some(kind),
                frontend: Some(branch.frontend.clone()),
            };
            let retired = branch_case.retired_record_for_case(
                &branch.attempt_id,
                &branch.checkpoint_digest,
                &branch.retired_record_digest,
            )?;
            if retired.release_knowledge != ReleaseKnowledge::ExecObserved
                || retired.candidate_exit_code != branch.candidate_exit_code
                || retired.cleanup_error.is_some()
                || retired.frontend != branch.frontend
            {
                return Err("MCSEALED-PRIVATE-PROBE: loss native retirement differs".into());
            }
            match (&branch.physical, kind) {
                (
                    ProbeLossProofRecordV1::Frontend {
                        proxy_wait_signal,
                        guardian_terminal,
                    },
                    ProbeLossKindV1::Frontend,
                ) => {
                    let terminal = super::private_guardian::GuardianTerminalV4::decode(
                        *guardian_terminal,
                        probe_loss_attempt_bytes(&self.run.nonce, kind),
                    )?;
                    if *proxy_wait_signal != libc::SIGKILL
                        || terminal.trigger
                            != super::private_guardian::GuardianTriggerV4::FrontendLost
                        || !terminal.boundary_retired
                    {
                        return Err("MCSEALED-PRIVATE-PROBE: frontend loss proof differs".into());
                    }
                }
                (
                    ProbeLossProofRecordV1::Guardian {
                        guardian,
                        guardian_signal,
                        proxy_exit_code,
                    },
                    ProbeLossKindV1::Guardian,
                ) => {
                    if retired.guardian.as_ref() != Some(guardian)
                        || *guardian_signal != libc::SIGKILL
                        || *proxy_exit_code != 0
                    {
                        return Err("MCSEALED-PRIVATE-PROBE: guardian loss proof differs".into());
                    }
                }
                _ => return Err("MCSEALED-PRIVATE-PROBE: loss proof branch differs".into()),
            }
        }
        if completion.branches[0].frontend == completion.branches[1].frontend {
            return Err("MCSEALED-PRIVATE-PROBE: loss frontends were reused".into());
        }
        Ok(())
    }

    /// Re-read the protected completion and native journal from pinned run
    /// storage. The producer's returned digest is never accepted as a
    /// substitute for these bytes. A full host run must additionally require
    /// every catalogue case and current independent host prerequisites.
    pub(crate) fn verify_persisted_completion(&self) -> Result<VerifiedProbeCompletionV1, String> {
        self.revalidate()?;
        let name = CString::new(format!("case-{}.completion.json", self.index))
            .expect("numeric completion name has no NUL");
        let bytes = read_protected_probe_file(&self.run.run_directory, &name)?;
        let completion_digest = match self.kind() {
            ProbeFixtureKindV1::DescriptorIdentityFilterNamespace
            | ProbeFixtureKindV1::NamespacePortSysctlIsolation
            | ProbeFixtureKindV1::TcpListenerClientCompetitor
            | ProbeFixtureKindV1::UnixCreationSocketpairDenial
            | ProbeFixtureKindV1::WrongFamilyProtocolDenial => {
                let completion = ProbeSuccessfulCompletionV1::parse_verified(&bytes)?;
                let retired = self.retired_record_for_case(
                    &completion.attempt_id,
                    &completion.checkpoint_digest,
                    &completion.retired_record_digest,
                )?;
                if completion.run_nonce != hex(&self.run.nonce)
                    || completion.case_index != self.index
                    || retired.release_knowledge != ReleaseKnowledge::ExecObserved
                    || retired.candidate_exit_code != Some(0)
                    || completion.challenge_sha256 != hash_bytes(&self.challenge_bytes())
                    || completion.response_sha256 != hash_bytes(&self.expected_fixture_response())
                {
                    return Err("MCSEALED-PRIVATE-PROBE: successful completion join differs".into());
                }
                completion.completion_digest
            }
            ProbeFixtureKindV1::TargetExecFailureRetirement => {
                let completion = ProbeFailedExecCompletionV1::parse_verified(&bytes)?;
                let retired = self.retired_record_for_case(
                    &completion.attempt_id,
                    &completion.checkpoint_digest,
                    &completion.retired_record_digest,
                )?;
                if completion.run_nonce != hex(&self.run.nonce)
                    || completion.attempt_id != probe_attempt_id(&self.run.nonce, self.index)
                    || retired.release_knowledge != ReleaseKnowledge::PossiblyReleased
                    || retired.candidate_exit_code != Some(125)
                    || completion.challenge_sha256 != hash_bytes(&self.challenge_bytes())
                {
                    return Err(
                        "MCSEALED-PRIVATE-PROBE: failed-exec completion join differs".into(),
                    );
                }
                completion.completion_digest
            }
            ProbeFixtureKindV1::BaselineUnixSuccessRetirement => {
                let completion = ProbeBaselineCompletionV1::parse_verified(&bytes)?;
                if completion.run_nonce != hex(&self.run.nonce)
                    || completion.attempt_id != probe_attempt_id(&self.run.nonce, self.index)
                    || completion.retired_record_digest != self.baseline_retired_record_digest()?
                    || completion.challenge_sha256 != hash_bytes(&self.challenge_bytes())
                    || completion.response_sha256 != hash_bytes(&self.expected_fixture_response())
                    || completion.terminal_projection.attempt != self.attempt_bytes()
                    || completion.terminal_projection.validate_and_digest()?
                        != completion.terminal_facts_sha256
                {
                    return Err("MCSEALED-PRIVATE-PROBE: baseline completion join differs".into());
                }
                completion.completion_digest
            }
            ProbeFixtureKindV1::FrontendGuardianLossRetirement => {
                let completion = ProbeLossCompletionV1::parse_verified(&bytes)?;
                self.verify_loss_completion(&completion)?;
                completion.completion_digest
            }
        };
        Ok(VerifiedProbeCompletionV1 {
            profile: self.profile(),
            name: self.name(),
            completion_digest,
        })
    }

    fn retired_record_for_case(
        &self,
        attempt_id: &str,
        checkpoint_digest: &DiagnosticSha256,
        record_digest: &DiagnosticSha256,
    ) -> Result<ProbeCaseRecordV1, String> {
        self.revalidate()?;
        let name = self.record_leaf();
        verify_retired_probe_record(
            &self.run.run_directory,
            &name,
            &self.initial_record()?,
            attempt_id,
            checkpoint_digest,
            record_digest,
        )
    }

    fn persist_completion_bytes(&self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        if bytes.len() > MAX_PROBE_RECORD_BYTES {
            return Err("MCSEALED-PRIVATE-PROBE: completion exceeds byte bound".into());
        }
        let name = CString::new(format!("case-{}.completion.json", self.index))
            .expect("numeric completion name has no NUL");
        let temporary = CString::new(format!("case-{}.completion.json.new", self.index))
            .expect("numeric temporary completion name has no NUL");
        let directory = &self.run.run_directory;
        // SAFETY: both fixed names are rooted at the retained protected run
        // descriptor; O_EXCL and RENAME_NOREPLACE prevent replay/overwrite.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                temporary.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd == -1 {
            return Err(format!(
                "MCSEALED-PRIVATE-PROBE: completion creation: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: successful openat returned one owned file descriptor.
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| error.to_string())?;
        // SAFETY: renameat2 uses live fixed names relative to one pinned root.
        let status = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                directory.as_raw_fd(),
                temporary.as_ptr(),
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if status == -1 {
            return Err(format!(
                "MCSEALED-PRIVATE-PROBE: completion rename: {}",
                std::io::Error::last_os_error()
            ));
        }
        directory.sync_all().map_err(|error| error.to_string())?;
        read_protected_probe_file(directory, &name)
    }

    fn initial_record(&self) -> Result<ProbeCaseRecordV1, String> {
        initial_probe_record(
            &self.run.nonce,
            self.index,
            self.loss_kind,
            self.frontend.as_ref().unwrap_or(&self.run.coordinator),
            &self.run.coordinator,
            &self.run.boot_id,
            self.run.target_uid,
            self.run.target_gid,
            &self.run.service_generation_digest,
            &self.run.host_prerequisites_digest,
            &self.run.installation_epoch,
            &self.run.package,
        )
    }
}

fn verify_retired_probe_record(
    directory: &File,
    name: &CString,
    expected_initial: &ProbeCaseRecordV1,
    attempt_id: &str,
    checkpoint_digest: &DiagnosticSha256,
    record_digest: &DiagnosticSha256,
) -> Result<ProbeCaseRecordV1, String> {
    let bytes = read_protected_probe_file(directory, name)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)?;
    let retired: ProbeCaseRecordV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    retired.validate_phase()?;
    if retired.record_digest != retired.canonical_digest()?
        || retired.phase != ProbePhaseV1::Retired
        || &retired.record_digest != record_digest
        || retired.checkpoint_digest.as_ref() != Some(checkpoint_digest)
        || retired.attempt_id != attempt_id
    {
        return Err("MCSEALED-PRIVATE-PROBE: retired native record differs".into());
    }
    let mut static_readback = retired.clone();
    static_readback.phase = ProbePhaseV1::Allocated;
    static_readback.guardian = None;
    static_readback.namespace_init = None;
    static_readback.target_process = None;
    static_readback.network_namespace_inode = None;
    static_readback.checkpoint_digest = None;
    static_readback.checkpoint_binding = None;
    static_readback.release_knowledge = ReleaseKnowledge::NotReleased;
    static_readback.cleanup_error = None;
    static_readback.candidate_exit_code = None;
    static_readback.record_digest = expected_initial.record_digest.clone();
    if static_readback != *expected_initial {
        return Err("MCSEALED-PRIVATE-PROBE: retired case authority differs".into());
    }
    Ok(retired)
}

#[allow(clippy::too_many_arguments)]
fn initial_probe_record(
    nonce: &[u8; 32],
    index: usize,
    loss_kind: Option<ProbeLossKindV1>,
    frontend: &ProcessIdentityV4,
    coordinator: &ProcessIdentityV4,
    boot_id: &str,
    target_uid: u32,
    target_gid: u32,
    service_generation_digest: &DiagnosticSha256,
    host_prerequisites_digest: &DiagnosticSha256,
    installation_epoch: &DiagnosticSha256,
    package: &crate::package::VerifiedProbePackageLease,
) -> Result<ProbeCaseRecordV1, String> {
    let kind =
        ProbeFixtureKindV1::at(index).ok_or("MCSEALED-PRIVATE-PROBE: unknown initial case")?;
    let attempt = loss_kind.map_or_else(
        || probe_attempt_bytes(nonce, index),
        |kind| probe_loss_attempt_bytes(nonce, kind),
    );
    let mut record = ProbeCaseRecordV1 {
        schema_version: 1,
        run_nonce: hex(nonce),
        attempt_id: hex(&attempt),
        case_index: index,
        fixture_kind: kind,
        case_name: HOST_PROBE_CATALOG_V1[index].1.into(),
        profile: HOST_PROBE_CATALOG_V1[index].0.reference(),
        boot_id: boot_id.into(),
        service_generation_digest: service_generation_digest.clone(),
        host_prerequisites_digest: host_prerequisites_digest.clone(),
        installation_epoch: installation_epoch.clone(),
        coordinator: coordinator.clone(),
        frontend: frontend.clone(),
        loss_kind,
        source_commit: package.source_commit.clone(),
        target: package.target.clone(),
        runtime_manifest_sha256: package.runtime_manifest_sha256.clone(),
        fixture_sha256: package.agent_sha256.clone(),
        unit_hashes: package.units.clone(),
        filter_sha256: package.filter_sha256.clone(),
        catalogue_sha256: catalogue_digest(),
        target_uid,
        target_gid,
        phase: ProbePhaseV1::Allocated,
        guardian: None,
        namespace_init: None,
        target_process: None,
        network_namespace_inode: None,
        checkpoint_digest: None,
        checkpoint_binding: None,
        release_knowledge: ReleaseKnowledge::NotReleased,
        cleanup_error: None,
        candidate_exit_code: None,
        record_digest: DiagnosticSha256::from_bytes([0; 32]),
    };
    record.record_digest = record.canonical_digest()?;
    Ok(record)
}

impl ProbeLossCaseAuthority<'_> {
    pub(crate) fn kind(&self) -> ProbeLossKindV1 {
        self.case.loss_kind.expect("loss subcase has a branch")
    }

    /// This is the branch-bound case, not the catalogue's unbranched case 1.
    pub(crate) fn as_case(&self) -> &ProbeCaseAuthority<'_> {
        &self.case
    }

    pub(crate) fn revalidate(&self) -> Result<(), String> {
        self.case.revalidate()
    }

    pub(crate) fn verify_proxy_live(&self) -> Result<(), String> {
        self.revalidate()?;
        let expected = self
            .case
            .frontend
            .as_ref()
            .expect("loss subcase pins frontend identity");
        if ProcessIdentityV4::observe(expected.pid as libc::pid_t, self.frontend_pidfd.as_fd())?
            != *expected
        {
            return Err("MCSEALED-PRIVATE-PROBE: loss proxy identity changed".into());
        }
        Ok(())
    }

    pub(crate) fn frontend_pidfd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.frontend_pidfd.as_fd()
    }

    pub(crate) fn frontend_identity(&self) -> &ProcessIdentityV4 {
        self.case
            .frontend
            .as_ref()
            .expect("loss subcase pins frontend identity")
    }

    pub(crate) fn attempt_bytes(&self) -> [u8; 16] {
        self.case.attempt_bytes()
    }

    pub(crate) fn challenge_bytes(&self) -> [u8; 32] {
        self.case.challenge_bytes()
    }

    pub(crate) fn expected_armed_response(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"memcordon-private-probe-loss-armed-v1\0");
        digest.update(self.challenge_bytes());
        digest.finalize().into()
    }

    pub(crate) fn begin_native_owner(
        &self,
    ) -> Result<super::private_lifecycle::PrivateAttemptOwner<DurableProbeAttempt>, String> {
        self.verify_proxy_live()?;
        self.case.begin_native_owner()
    }

    pub(crate) fn prepare_native_prelaunch(
        &self,
    ) -> Result<super::launch::PrivateGatedPrelaunch, String> {
        self.verify_proxy_live()?;
        self.case.prepare_native_prelaunch()
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn bind_native_checkpoint(
        &self,
        guardian: ProcessIdentityV4,
        namespace_init: ProcessIdentityV4,
        target: ProcessIdentityV4,
        network_namespace_inode: u64,
        target_uid: u32,
        target_gid: u32,
        observed_filter: [u8; 32],
        topology_sha256: DiagnosticSha256,
        native_readback_sha256: DiagnosticSha256,
    ) -> Result<ProbeCheckpointBindingV1, String> {
        self.verify_proxy_live()?;
        self.case.bind_native_checkpoint(
            guardian,
            namespace_init,
            target,
            network_namespace_inode,
            target_uid,
            target_gid,
            observed_filter,
            topology_sha256,
            native_readback_sha256,
        )
    }

    pub(crate) fn deadline(&self) -> Instant {
        self.case.deadline()
    }

    pub(crate) fn target_ids(&self) -> (u32, u32) {
        self.case.target_ids()
    }

    pub(crate) fn native_abi(&self) -> Result<super::network_filter::NativeAbi, String> {
        self.case.native_abi()
    }

    pub(crate) fn filter_digest(&self) -> &DiagnosticSha256 {
        self.case.filter_digest()
    }

    pub(crate) fn fixture_digest(&self) -> &DiagnosticSha256 {
        self.case.fixture_digest()
    }

    pub(crate) fn work_directory(&self) -> Result<File, String> {
        self.case.work_directory()
    }

    pub(crate) fn coordinator_pidfd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.case.coordinator_pidfd()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ProbePhaseV1 {
    Allocated,
    AuthorityFrozen,
    BoundaryCreated,
    GuardianReady,
    TargetGated,
    CheckpointCommitted,
    ReleaseIntent,
    ExecutionObserved,
    Retiring,
    Retired,
    CleanupIncomplete,
}

/// Native checkpoint data is probe-domain-only; it cannot deserialize as a
/// production `AttemptBindingV2` or authorize a public V11 result.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProbeCheckpointBindingV1 {
    schema_version: u8,
    run_nonce: String,
    case_index: usize,
    attempt_id: String,
    boot_id: String,
    runtime_manifest_sha256: DiagnosticSha256,
    fixture_sha256: DiagnosticSha256,
    catalogue_sha256: DiagnosticSha256,
    filter_sha256: DiagnosticSha256,
    target_uid: u32,
    target_gid: u32,
    guardian: ProcessIdentityV4,
    namespace_init: ProcessIdentityV4,
    target: ProcessIdentityV4,
    network_namespace_inode: u64,
    topology_sha256: DiagnosticSha256,
    native_readback_sha256: DiagnosticSha256,
}

impl ProbeCheckpointBindingV1 {
    fn digest(&self) -> Result<DiagnosticSha256, String> {
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        let mut digest = Sha256::new();
        digest.update(b"memcordon-private-probe-checkpoint-v1\0");
        digest.update(bytes);
        Ok(DiagnosticSha256::from_bytes(digest.finalize().into()))
    }
}

/// Probe records cannot parse as production V4 records and never contain a
/// `ProviderAdmissionSnapshotV2` or production `AttemptBindingV2`.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProbeCaseRecordV1 {
    schema_version: u8,
    run_nonce: String,
    attempt_id: String,
    case_index: usize,
    fixture_kind: ProbeFixtureKindV1,
    case_name: String,
    profile: ProfileRef,
    boot_id: String,
    service_generation_digest: DiagnosticSha256,
    host_prerequisites_digest: DiagnosticSha256,
    installation_epoch: DiagnosticSha256,
    coordinator: ProcessIdentityV4,
    frontend: ProcessIdentityV4,
    loss_kind: Option<ProbeLossKindV1>,
    source_commit: String,
    target: String,
    runtime_manifest_sha256: DiagnosticSha256,
    fixture_sha256: DiagnosticSha256,
    unit_hashes: memcordon_core::package_inspection_v6::LinuxUnitHashesV6,
    filter_sha256: DiagnosticSha256,
    catalogue_sha256: DiagnosticSha256,
    target_uid: u32,
    target_gid: u32,
    phase: ProbePhaseV1,
    guardian: Option<ProcessIdentityV4>,
    namespace_init: Option<ProcessIdentityV4>,
    target_process: Option<ProcessIdentityV4>,
    network_namespace_inode: Option<u64>,
    checkpoint_digest: Option<DiagnosticSha256>,
    checkpoint_binding: Option<ProbeCheckpointBindingV1>,
    release_knowledge: ReleaseKnowledge,
    cleanup_error: Option<String>,
    candidate_exit_code: Option<i32>,
    record_digest: DiagnosticSha256,
}

impl ProbeCaseRecordV1 {
    fn canonical_digest(&self) -> Result<DiagnosticSha256, String> {
        let mut canonical = self.clone();
        canonical.record_digest = DiagnosticSha256::from_bytes([0; 32]);
        Ok(hash_bytes(
            &serde_json::to_vec(&canonical).map_err(|error| error.to_string())?,
        ))
    }

    fn encode(&self) -> Result<Vec<u8>, String> {
        if self.schema_version != 1 || self.record_digest != self.canonical_digest()? {
            return Err("MCSEALED-PRIVATE-PROBE: record digest differs".into());
        }
        self.validate_phase()?;
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if bytes.len() > MAX_PROBE_RECORD_BYTES {
            return Err("MCSEALED-PRIVATE-PROBE: record exceeds byte bound".into());
        }
        Ok(bytes)
    }

    fn parse_for_case(bytes: &[u8], case: &ProbeCaseAuthority<'_>) -> Result<Self, String> {
        if bytes.len() > MAX_PROBE_RECORD_BYTES {
            return Err("MCSEALED-PRIVATE-PROBE: record exceeds byte bound".into());
        }
        memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)?;
        let record: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        record.validate_phase()?;
        if record != case.initial_record()? || record.phase != ProbePhaseV1::Allocated {
            return Err("MCSEALED-PRIVATE-PROBE: protected case binding differs".into());
        }
        Ok(record)
    }

    fn validate_phase(&self) -> Result<(), String> {
        if (self.case_index == 1) != self.loss_kind.is_some()
            || (self.loss_kind.is_some() && self.frontend == self.coordinator)
            || (self.loss_kind.is_none() && self.frontend != self.coordinator)
        {
            return Err("MCSEALED-PRIVATE-PROBE: frontend or loss branch differs".into());
        }
        let guardian = self.guardian.is_some();
        let target = self.target_process.is_some()
            && self.namespace_init.is_some()
            && self.network_namespace_inode.is_some_and(|inode| inode != 0);
        let no_target = self.target_process.is_none()
            && self.namespace_init.is_none()
            && self.network_namespace_inode.is_none();
        let checkpoint = self.checkpoint_digest.is_some()
            && self.checkpoint_binding.as_ref().is_some_and(|binding| {
                binding.digest().ok().as_ref() == self.checkpoint_digest.as_ref()
                    && binding.schema_version == 1
                    && binding.run_nonce == self.run_nonce
                    && binding.case_index == self.case_index
                    && binding.attempt_id == self.attempt_id
                    && binding.boot_id == self.boot_id
                    && binding.runtime_manifest_sha256 == self.runtime_manifest_sha256
                    && binding.fixture_sha256 == self.fixture_sha256
                    && binding.catalogue_sha256 == self.catalogue_sha256
                    && binding.filter_sha256 == self.filter_sha256
                    && binding.target_uid == self.target_uid
                    && binding.target_gid == self.target_gid
                    && Some(&binding.guardian) == self.guardian.as_ref()
                    && Some(&binding.namespace_init) == self.namespace_init.as_ref()
                    && Some(&binding.target) == self.target_process.as_ref()
                    && Some(binding.network_namespace_inode) == self.network_namespace_inode
            });
        let no_checkpoint = self.checkpoint_digest.is_none() && self.checkpoint_binding.is_none();
        let valid = match self.phase {
            ProbePhaseV1::Allocated
            | ProbePhaseV1::AuthorityFrozen
            | ProbePhaseV1::BoundaryCreated => {
                !guardian
                    && no_target
                    && no_checkpoint
                    && self.candidate_exit_code.is_none()
                    && self.release_knowledge == ReleaseKnowledge::NotReleased
            }
            ProbePhaseV1::GuardianReady => {
                guardian
                    && no_target
                    && no_checkpoint
                    && self.candidate_exit_code.is_none()
                    && self.release_knowledge == ReleaseKnowledge::NotReleased
            }
            ProbePhaseV1::TargetGated => {
                guardian
                    && target
                    && no_checkpoint
                    && self.candidate_exit_code.is_none()
                    && self.release_knowledge == ReleaseKnowledge::NotReleased
            }
            ProbePhaseV1::CheckpointCommitted => {
                guardian
                    && target
                    && checkpoint
                    && self.candidate_exit_code.is_none()
                    && self.release_knowledge == ReleaseKnowledge::NotReleased
            }
            ProbePhaseV1::ReleaseIntent => {
                guardian
                    && target
                    && checkpoint
                    && self.candidate_exit_code.is_none()
                    && self.release_knowledge == ReleaseKnowledge::PossiblyReleased
            }
            ProbePhaseV1::ExecutionObserved => {
                guardian
                    && target
                    && checkpoint
                    && self.candidate_exit_code.is_none()
                    && self.release_knowledge == ReleaseKnowledge::ExecObserved
            }
            ProbePhaseV1::Retiring | ProbePhaseV1::Retired | ProbePhaseV1::CleanupIncomplete => {
                (target || no_target)
                    && (no_checkpoint || (checkpoint && target))
                    && (!target || guardian)
                    && (self.phase == ProbePhaseV1::Retired || self.candidate_exit_code.is_none())
                    && (self.release_knowledge == ReleaseKnowledge::NotReleased || checkpoint)
            }
        };
        if !valid
            || (self.phase == ProbePhaseV1::CleanupIncomplete) != self.cleanup_error.is_some()
            || self
                .cleanup_error
                .as_ref()
                .is_some_and(|detail| detail.is_empty() || detail.len() > 1024)
        {
            return Err("MCSEALED-PRIVATE-PROBE: phase or native resource shape differs".into());
        }
        Ok(())
    }
}

pub(crate) struct DurableProbeAttempt {
    name: CString,
    directory: File,
    record: ProbeCaseRecordV1,
}

pub(crate) struct ProbeReleasePermitV1 {
    attempt_id: String,
    checkpoint_digest: DiagnosticSha256,
}

/// Constructed only after the move-only owner has observed native settlement.
/// It is evidence input, never by itself a completed/qualified host case.
pub(crate) struct ProbeRetirementObservationV1 {
    pub(crate) attempt_id: String,
    pub(crate) checkpoint_digest: Option<DiagnosticSha256>,
    pub(crate) terminal_record_digest: DiagnosticSha256,
    pub(crate) candidate_exit_code: Option<i32>,
}

/// Native exec-failure facts are returned by the probe owner, not the fixture.
pub(crate) struct ProbeFailedExecObservationV1 {
    pub(crate) attempt_id: String,
    pub(crate) checkpoint_digest: DiagnosticSha256,
    pub(crate) terminal_record_digest: DiagnosticSha256,
    pub(crate) phase: u8,
    pub(crate) detail: String,
}

/// Produced only by the separate pinned baseline V1 physical owner.
pub(crate) struct BaselineProbeObservationV1 {
    pub(crate) attempt_id: String,
    pub(crate) retired_record_digest: DiagnosticSha256,
    pub(crate) challenge_sha256: DiagnosticSha256,
    pub(crate) response_sha256: DiagnosticSha256,
    pub(crate) terminal_facts_sha256: DiagnosticSha256,
    pub(crate) terminal_projection: super::private_probe_baseline::BaselineTerminalProjectionV1,
}

/// Constructible only by joining pinned protected completion and native
/// retirement bytes with the fixed live case authority.
pub(crate) struct VerifiedProbeCompletionV1 {
    profile: ProfileRef,
    name: &'static str,
    completion_digest: DiagnosticSha256,
}

impl VerifiedProbeCompletionV1 {
    pub(crate) fn into_native_probe(self) -> super::qualification::NativeQualificationProbeV4 {
        super::qualification::NativeQualificationProbeV4 {
            profile: self.profile,
            name: self.name.to_owned(),
            native_executed: true,
            passed: true,
            completion_digest: self.completion_digest,
        }
    }
}

/// A separately persisted observation joins the fixture pipe with the
/// already-retired native journal. It is not a qualification receipt: an
/// independent protected reader must still verify the complete case set.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProbeSuccessfulCompletionV1 {
    schema_version: u8,
    run_nonce: String,
    case_index: usize,
    attempt_id: String,
    retired_record_digest: DiagnosticSha256,
    checkpoint_digest: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    response_sha256: DiagnosticSha256,
    candidate_exit_code: i32,
    completion_digest: DiagnosticSha256,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProbeFailedExecCompletionV1 {
    schema_version: u8,
    run_nonce: String,
    case_index: usize,
    attempt_id: String,
    retired_record_digest: DiagnosticSha256,
    checkpoint_digest: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    phase: u8,
    detail: String,
    candidate_exit_code: i32,
    completion_digest: DiagnosticSha256,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProbeBaselineCompletionV1 {
    schema_version: u8,
    run_nonce: String,
    case_index: usize,
    attempt_id: String,
    retired_record_digest: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    response_sha256: DiagnosticSha256,
    terminal_facts_sha256: DiagnosticSha256,
    terminal_projection: super::private_probe_baseline::BaselineTerminalProjectionV1,
    completion_digest: DiagnosticSha256,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProbeLossCompletionV1 {
    schema_version: u8,
    run_nonce: String,
    case_index: usize,
    branches: [ProbeLossBranchCompletionV1; 2],
    completion_digest: DiagnosticSha256,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProbeLossBranchCompletionV1 {
    kind: ProbeLossKindV1,
    attempt_id: String,
    checkpoint_digest: DiagnosticSha256,
    retired_record_digest: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    armed_response_sha256: DiagnosticSha256,
    frontend: ProcessIdentityV4,
    candidate_exit_code: Option<i32>,
    physical: ProbeLossProofRecordV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum ProbeLossProofRecordV1 {
    Frontend {
        proxy_wait_signal: i32,
        guardian_terminal: [u8; 20],
    },
    Guardian {
        guardian: ProcessIdentityV4,
        guardian_signal: i32,
        proxy_exit_code: i32,
    },
}

impl ProbeLossCompletionV1 {
    fn canonical_digest(&self) -> Result<DiagnosticSha256, String> {
        let mut canonical = self.clone();
        canonical.completion_digest = DiagnosticSha256::from_bytes([0; 32]);
        Ok(hash_bytes(
            &serde_json::to_vec(&canonical).map_err(|error| error.to_string())?,
        ))
    }

    pub(crate) fn parse_verified(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_PROBE_RECORD_BYTES {
            return Err("MCSEALED-PRIVATE-PROBE: loss completion exceeds byte bound".into());
        }
        memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)?;
        let completion: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        if completion.schema_version != 1
            || completion.case_index != 1
            || completion.run_nonce.len() != hex(&[0_u8; 32]).len()
            || !completion
                .run_nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || completion.branches[0].kind != ProbeLossKindV1::Frontend
            || completion.branches[1].kind != ProbeLossKindV1::Guardian
            || completion.completion_digest != completion.canonical_digest()?
        {
            return Err("MCSEALED-PRIVATE-PROBE: loss completion differs".into());
        }
        Ok(completion)
    }
}

impl ProbeBaselineCompletionV1 {
    fn canonical_digest(&self) -> Result<DiagnosticSha256, String> {
        let mut canonical = self.clone();
        canonical.completion_digest = DiagnosticSha256::from_bytes([0; 32]);
        Ok(hash_bytes(
            &serde_json::to_vec(&canonical).map_err(|error| error.to_string())?,
        ))
    }

    pub(crate) fn parse_verified(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_PROBE_RECORD_BYTES {
            return Err("MCSEALED-PRIVATE-PROBE: baseline completion exceeds byte bound".into());
        }
        memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)?;
        let completion: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        if completion.schema_version != 1
            || completion.case_index != 7
            || completion.run_nonce.len() != hex(&[0_u8; 32]).len()
            || !completion
                .run_nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || completion.attempt_id.len() != hex(&[0_u8; 16]).len()
            || !completion
                .attempt_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || completion.terminal_facts_sha256 == DiagnosticSha256::from_bytes([0; 32])
            || completion.terminal_projection.validate_and_digest()?
                != completion.terminal_facts_sha256
            || completion.completion_digest != completion.canonical_digest()?
        {
            return Err("MCSEALED-PRIVATE-PROBE: baseline completion differs".into());
        }
        Ok(completion)
    }
}

impl ProbeFailedExecCompletionV1 {
    fn canonical_digest(&self) -> Result<DiagnosticSha256, String> {
        let mut canonical = self.clone();
        canonical.completion_digest = DiagnosticSha256::from_bytes([0; 32]);
        Ok(hash_bytes(
            &serde_json::to_vec(&canonical).map_err(|error| error.to_string())?,
        ))
    }

    pub(crate) fn parse_verified(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_PROBE_RECORD_BYTES {
            return Err("MCSEALED-PRIVATE-PROBE: failed-exec completion exceeds byte bound".into());
        }
        memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)?;
        let completion: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        if completion.schema_version != 1
            || completion.case_index != 3
            || completion.phase != 5
            || completion.detail != "MCSEALED-PROBE-EXECVEAT-ENOENT"
            || completion.candidate_exit_code != 125
            || completion.run_nonce.len() != hex(&[0_u8; 32]).len()
            || !completion
                .run_nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || completion.attempt_id.len() != hex(&[0_u8; 16]).len()
            || !completion
                .attempt_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || completion.completion_digest != completion.canonical_digest()?
        {
            return Err("MCSEALED-PRIVATE-PROBE: failed-exec completion differs".into());
        }
        Ok(completion)
    }
}

impl ProbeSuccessfulCompletionV1 {
    fn canonical_digest(&self) -> Result<DiagnosticSha256, String> {
        let mut canonical = self.clone();
        canonical.completion_digest = DiagnosticSha256::from_bytes([0; 32]);
        Ok(hash_bytes(
            &serde_json::to_vec(&canonical).map_err(|error| error.to_string())?,
        ))
    }

    /// Structural parsing alone grants nothing. The installed verifier must
    /// separately join this object to the pinned retired journal and current
    /// host/package facts before admitting it as native evidence.
    pub(crate) fn parse_verified(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_PROBE_RECORD_BYTES {
            return Err("MCSEALED-PRIVATE-PROBE: completion exceeds byte bound".into());
        }
        memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)?;
        let completion: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        if completion.schema_version != 1
            || completion.case_index >= HOST_PROBE_CATALOG_V1.len()
            || completion.run_nonce.len() != hex(&[0_u8; 32]).len()
            || !completion
                .run_nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || completion.attempt_id.len() != hex(&[0_u8; 16]).len()
            || !completion
                .attempt_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || completion.candidate_exit_code != 0
            || completion.completion_digest != completion.canonical_digest()?
        {
            return Err("MCSEALED-PRIVATE-PROBE: completion structure differs".into());
        }
        Ok(completion)
    }
}

impl ProbeReleasePermitV1 {
    pub(crate) fn send(
        self,
        control: &mut File,
        attempt_id: &str,
        checkpoint_digest: &DiagnosticSha256,
    ) -> Result<(), String> {
        if self.attempt_id != attempt_id || &self.checkpoint_digest != checkpoint_digest {
            return Err("MCSEALED-PRIVATE-PROBE: release permit binding differs".into());
        }
        super::private_attempt::send_private_release_byte(control)
    }
}

/// Until probe-specific physical recovery is implemented, any persisted case
/// remains blocking evidence. An empty protected directory is not an attempt.
pub(crate) fn pending_records(directory: &Path) -> Result<Vec<String>, String> {
    let metadata = match fs::symlink_metadata(directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("MCSEALED-PRIVATE-PROBE-RECOVERY: {error}")),
    };
    if !metadata.file_type().is_dir() || metadata.uid() != 0 || metadata.mode() & 0o777 != 0o700 {
        return Err("MCSEALED-PRIVATE-PROBE-RECOVERY: directory protection differs".into());
    }
    let directory_fd = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory)
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE-RECOVERY: {error}"))?;
    let opened = directory_fd
        .metadata()
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE-RECOVERY: {error}"))?;
    if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
        return Err("MCSEALED-PRIVATE-PROBE-RECOVERY: directory changed during open".into());
    }
    // Enumerate the already authenticated directory object. An empty run
    // directory has no allocated native case and is not a pending attempt;
    // every nonempty or unknown entry remains blocking evidence.
    let mut pending = Vec::new();
    for (leaf_name, observed_ino) in pinned_directory_items(&directory_fd)? {
        let entry = format!("{PROBE_DIRECTORY_NAME}/{}", leaf_name.to_string_lossy());
        let Some(name) = leaf_name.to_str() else {
            pending.push(entry);
            continue;
        };
        if name.len() != hex(&[0_u8; 32]).len()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            pending.push(entry);
            continue;
        }
        let leaf = CString::new(name).expect("validated hex run name has no NUL");
        // SAFETY: the run is opened relative to the retained root; no path
        // component or symlink can redirect it outside the protected store.
        let fd = unsafe {
            libc::openat(
                directory_fd.as_raw_fd(),
                leaf.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd == -1 {
            return Err(format!(
                "MCSEALED-PRIVATE-PROBE-RECOVERY: run open: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: successful openat returned one owned directory descriptor.
        let run = unsafe { File::from_raw_fd(fd) };
        let metadata = run.metadata().map_err(|error| error.to_string())?;
        if observed_ino == 0
            || metadata.ino() != observed_ino
            || !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.mode() & 0o777 != 0o700
        {
            return Err("MCSEALED-PRIVATE-PROBE-RECOVERY: run protection differs".into());
        }
        for case in pinned_directory_entries(&run)? {
            let case = case
                .strip_prefix("private-qualification/")
                .ok_or("MCSEALED-PRIVATE-PROBE-RECOVERY: unexpected case name")?;
            pending.push(format!("{entry}/{case}"));
        }
    }
    Ok(pending)
}

pub(crate) fn pinned_directory_entries(directory: &File) -> Result<Vec<String>, String> {
    Ok(pinned_directory_items(directory)?
        .into_iter()
        .map(|(name, _)| format!("{PROBE_DIRECTORY_NAME}/{}", name.to_string_lossy()))
        .collect())
}

fn pinned_directory_items(directory: &File) -> Result<Vec<(std::ffi::OsString, u64)>, String> {
    // A dup would share the original directory's seek offset, causing a later
    // independent inventory pass to observe false EOF. Open "." relative to
    // the pinned directory instead: this is a new file description without a
    // mutable pathname lookup or shared enumeration offset.
    let dot = CString::new(".").expect("fixed dot path has no NUL");
    // SAFETY: openat resolves only "." under the retained protected directory.
    let cloned = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            dot.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if cloned == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-PROBE-RECOVERY: open pinned directory: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: cloned is a live descriptor for the same pinned inode.
    let mut opened = std::mem::MaybeUninit::<libc::stat>::uninit();
    let mut original = std::mem::MaybeUninit::<libc::stat>::uninit();
    let same = unsafe {
        libc::fstat(cloned, opened.as_mut_ptr()) == 0
            && libc::fstat(directory.as_raw_fd(), original.as_mut_ptr()) == 0
            && {
                let opened = opened.assume_init();
                let original = original.assume_init();
                opened.st_dev == original.st_dev && opened.st_ino == original.st_ino
            }
    };
    if !same {
        // SAFETY: fdopendir has not yet consumed the opened descriptor.
        unsafe { libc::close(cloned) };
        return Err("MCSEALED-PRIVATE-PROBE-RECOVERY: pinned directory changed".into());
    }
    // SAFETY: cloned is a live directory descriptor. On failure fdopendir
    // does not consume it; on success closedir owns and closes it.
    let stream = unsafe { libc::fdopendir(cloned) };
    if stream.is_null() {
        let error = std::io::Error::last_os_error();
        // SAFETY: failed fdopendir did not take ownership of cloned.
        unsafe { libc::close(cloned) };
        return Err(format!(
            "MCSEALED-PRIVATE-PROBE-RECOVERY: fdopendir: {error}"
        ));
    }
    let mut pending = Vec::new();
    let mut read_error = None;
    loop {
        // SAFETY: Linux readdir returns a pointer valid until the next call
        // on this live DIR stream. errno zero distinguishes EOF from failure.
        unsafe { *libc::__errno_location() = 0 };
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let code = unsafe { *libc::__errno_location() };
            if code != 0 {
                read_error = Some(std::io::Error::from_raw_os_error(code));
            }
            break;
        }
        // SAFETY: d_name is NUL-terminated within this live dirent, and the
        // bytes are copied before readdir invalidates the entry pointer.
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            pending.push((std::ffi::OsStr::from_bytes(name).to_owned(), unsafe {
                (*entry).d_ino
            }));
        }
    }
    // SAFETY: fdopendir transferred the duplicated descriptor to this DIR.
    let close_result = unsafe { libc::closedir(stream) };
    if let Some(error) = read_error {
        return Err(format!("MCSEALED-PRIVATE-PROBE-RECOVERY: readdir: {error}"));
    }
    if close_result == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-PROBE-RECOVERY: closedir: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(pending)
}

fn read_protected_probe_file(directory: &File, name: &CString) -> Result<Vec<u8>, String> {
    // SAFETY: openat is rooted at the pinned protected directory and will not
    // follow a leaf symlink.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-PROBE: protected readback: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful openat returned one owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    let root = directory.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || !root.is_dir()
        || root.uid() != 0
        || root.mode() & 0o777 != 0o700
    {
        return Err("MCSEALED-PRIVATE-PROBE: protected readback mode differs".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_PROBE_RECORD_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > MAX_PROBE_RECORD_BYTES {
        return Err("MCSEALED-PRIVATE-PROBE: protected readback exceeds byte bound".into());
    }
    Ok(bytes)
}

impl DurableProbeAttempt {
    pub(crate) fn retired_after_native_cleanup(
        &mut self,
        candidate_exit_code: Option<i32>,
    ) -> Result<ProbeRetirementObservationV1, String> {
        if self.record.phase != ProbePhaseV1::Retiring {
            return Err("MCSEALED-PRIVATE-PROBE: retirement phase differs".into());
        }
        let mut next = self.record.clone();
        next.phase = ProbePhaseV1::Retired;
        next.candidate_exit_code = candidate_exit_code;
        self.replace(next)?;
        Ok(ProbeRetirementObservationV1 {
            attempt_id: self.record.attempt_id.clone(),
            checkpoint_digest: self.record.checkpoint_digest.clone(),
            terminal_record_digest: self.record.record_digest.clone(),
            candidate_exit_code,
        })
    }

    pub(crate) fn commit_checkpoint(
        &mut self,
        binding: ProbeCheckpointBindingV1,
    ) -> Result<DiagnosticSha256, String> {
        if self.record.phase != ProbePhaseV1::TargetGated
            || binding.attempt_id != self.record.attempt_id
            || Some(&binding.guardian) != self.record.guardian.as_ref()
            || Some(&binding.namespace_init) != self.record.namespace_init.as_ref()
            || Some(&binding.target) != self.record.target_process.as_ref()
            || Some(binding.network_namespace_inode) != self.record.network_namespace_inode
        {
            return Err("MCSEALED-PRIVATE-PROBE: checkpoint native ownership differs".into());
        }
        let digest = binding.digest()?;
        let mut next = self.record.clone();
        next.checkpoint_binding = Some(binding);
        next.checkpoint_digest = Some(digest.clone());
        next.phase = ProbePhaseV1::CheckpointCommitted;
        self.replace(next)?;
        Ok(digest)
    }

    pub(crate) fn release_intent(
        &mut self,
        case: &ProbeCaseAuthority<'_>,
        checkpoint_digest: &DiagnosticSha256,
    ) -> Result<ProbeReleasePermitV1, String> {
        case.run.case(case.index)?;
        if self.record.phase != ProbePhaseV1::CheckpointCommitted
            || self.record.case_index != case.index
            || self.record.run_nonce != hex(&case.run.nonce)
            || self.record.checkpoint_digest.as_ref() != Some(checkpoint_digest)
        {
            return Err("MCSEALED-PRIVATE-PROBE: release intent differs from live case".into());
        }
        let mut next = self.record.clone();
        next.phase = ProbePhaseV1::ReleaseIntent;
        next.release_knowledge = ReleaseKnowledge::PossiblyReleased;
        self.replace(next)?;
        Ok(ProbeReleasePermitV1 {
            attempt_id: self.record.attempt_id.clone(),
            checkpoint_digest: checkpoint_digest.clone(),
        })
    }

    pub(crate) fn allocate(case: &ProbeCaseAuthority<'_>) -> Result<Self, String> {
        let directory = case
            .run
            .run_directory
            .try_clone()
            .map_err(|error| error.to_string())?;
        let metadata = directory.metadata().map_err(|error| error.to_string())?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o777 != 0o700 {
            return Err("MCSEALED-PRIVATE-PROBE: state directory is not protected".into());
        }
        let record = case.initial_record()?;
        let name = case.record_leaf();
        let temporary = CString::new(format!(
            "{}.new",
            name.to_str().expect("fixed probe record name is UTF-8")
        ))
        .expect("fixed temporary name has no NUL");
        // SAFETY: openat receives a retained protected directory and a live
        // fixed case name. O_EXCL prevents replacing any interrupted write.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                temporary.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd == -1 {
            return Err(format!(
                "MCSEALED-PRIVATE-PROBE: temporary record creation: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: successful openat returned one owned descriptor.
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(&record.encode()?)
            .and_then(|()| file.sync_all())
            .map_err(|error| error.to_string())?;
        // SAFETY: both NUL-terminated names and the retained directory remain
        // live; RENAME_NOREPLACE leaves prior case records untouched.
        let status = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                directory.as_raw_fd(),
                temporary.as_ptr(),
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if status == -1 {
            return Err(format!(
                "MCSEALED-PRIVATE-PROBE: case record rename: {}",
                std::io::Error::last_os_error()
            ));
        }
        directory.sync_all().map_err(|error| error.to_string())?;
        Ok(Self {
            name,
            directory,
            record,
        })
    }

    pub(crate) fn read_back(&self, case: &ProbeCaseAuthority<'_>) -> Result<(), String> {
        let bytes = self.read_back_bytes()?;
        if ProbeCaseRecordV1::parse_for_case(&bytes, case)? != self.record {
            return Err("MCSEALED-PRIVATE-PROBE: record changed after allocation".into());
        }
        Ok(())
    }

    pub(crate) fn freeze_case(&mut self, case: &ProbeCaseAuthority<'_>) -> Result<(), String> {
        if self.record.phase != ProbePhaseV1::Allocated {
            return Err("MCSEALED-PRIVATE-PROBE: case already frozen".into());
        }
        self.read_back(case)?;
        let mut next = self.record.clone();
        next.phase = ProbePhaseV1::AuthorityFrozen;
        self.replace(next)
    }

    fn read_back_owned(&self) -> Result<(), String> {
        let bytes = self.read_back_bytes()?;
        memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)?;
        let observed: ProbeCaseRecordV1 =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        observed.validate_phase()?;
        if observed.record_digest != observed.canonical_digest()? || observed != self.record {
            return Err("MCSEALED-PRIVATE-PROBE: owned record readback differs".into());
        }
        Ok(())
    }

    fn read_back_bytes(&self) -> Result<Vec<u8>, String> {
        read_protected_probe_file(&self.directory, &self.name)
    }

    fn replace(&mut self, mut next: ProbeCaseRecordV1) -> Result<(), String> {
        self.read_back_owned()?;
        next.record_digest = next.canonical_digest()?;
        let bytes = next.encode()?;
        let temporary = CString::new(format!(
            "{}.new",
            self.name.to_str().expect("numeric case name is UTF-8")
        ))
        .expect("numeric temporary name has no NUL");
        // SAFETY: the temporary leaf is fixed from this owned case name and
        // created exclusively under the retained protected run directory.
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                temporary.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd == -1 {
            return Err(format!(
                "MCSEALED-PRIVATE-PROBE: transition creation: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: successful openat returned one owned descriptor.
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| error.to_string())?;
        // SAFETY: both names are NUL-terminated and rooted at the retained
        // directory. Replacement is atomic; an interrupted `.new` remains
        // blocking evidence to startup recovery.
        if unsafe {
            libc::renameat(
                self.directory.as_raw_fd(),
                temporary.as_ptr(),
                self.directory.as_raw_fd(),
                self.name.as_ptr(),
            )
        } == -1
        {
            return Err(format!(
                "MCSEALED-PRIVATE-PROBE: transition rename: {}",
                std::io::Error::last_os_error()
            ));
        }
        self.directory
            .sync_all()
            .map_err(|error| error.to_string())?;
        self.record = next;
        Ok(())
    }
}

impl PrivateNativeJournal for DurableProbeAttempt {
    fn phase(&self) -> PrivateAttemptPhase {
        match self.record.phase {
            ProbePhaseV1::Allocated => PrivateAttemptPhase::Allocated,
            ProbePhaseV1::AuthorityFrozen => PrivateAttemptPhase::AuthorityFrozen,
            ProbePhaseV1::BoundaryCreated => PrivateAttemptPhase::BoundaryCreated,
            ProbePhaseV1::GuardianReady => PrivateAttemptPhase::GuardianReady,
            ProbePhaseV1::TargetGated => PrivateAttemptPhase::TargetGated,
            ProbePhaseV1::CheckpointCommitted => PrivateAttemptPhase::CheckpointCommitted,
            ProbePhaseV1::ReleaseIntent => PrivateAttemptPhase::ReleaseIntent,
            ProbePhaseV1::ExecutionObserved => PrivateAttemptPhase::ExecutionObserved,
            ProbePhaseV1::Retiring => PrivateAttemptPhase::Retiring,
            ProbePhaseV1::Retired => PrivateAttemptPhase::Retired,
            ProbePhaseV1::CleanupIncomplete => PrivateAttemptPhase::CleanupIncomplete,
        }
    }

    fn read_back_native(&self) -> Result<(), String> {
        self.read_back_owned()
    }

    fn attempt_id(&self) -> &str {
        &self.record.attempt_id
    }

    fn frontend(&self) -> &ProcessIdentityV4 {
        &self.record.frontend
    }

    fn target(&self) -> Option<&ProcessIdentityV4> {
        self.record.target_process.as_ref()
    }

    fn namespace_init(&self) -> Option<&ProcessIdentityV4> {
        self.record.namespace_init.as_ref()
    }

    fn network_namespace_inode(&self) -> Option<u64> {
        self.record.network_namespace_inode
    }

    fn possibly_released(&self) -> bool {
        self.record.release_knowledge != ReleaseKnowledge::NotReleased
    }

    fn boundary_created(&mut self) -> Result<(), String> {
        if self.record.phase != ProbePhaseV1::AuthorityFrozen {
            return Err("MCSEALED-PRIVATE-PROBE: boundary requires frozen case".into());
        }
        let mut next = self.record.clone();
        next.phase = ProbePhaseV1::BoundaryCreated;
        self.replace(next)
    }

    fn guardian_ready(&mut self, guardian: ProcessIdentityV4) -> Result<(), String> {
        if self.record.phase != ProbePhaseV1::BoundaryCreated {
            return Err("MCSEALED-PRIVATE-PROBE: guardian requires boundary".into());
        }
        let mut next = self.record.clone();
        next.guardian = Some(guardian);
        next.phase = ProbePhaseV1::GuardianReady;
        self.replace(next)
    }

    fn target_gated(
        &mut self,
        namespace_init: ProcessIdentityV4,
        target: ProcessIdentityV4,
        network_namespace_inode: u64,
    ) -> Result<(), String> {
        if self.record.phase != ProbePhaseV1::GuardianReady || network_namespace_inode == 0 {
            return Err("MCSEALED-PRIVATE-PROBE: target requires live guardian".into());
        }
        let mut next = self.record.clone();
        next.namespace_init = Some(namespace_init);
        next.target_process = Some(target);
        next.network_namespace_inode = Some(network_namespace_inode);
        next.phase = ProbePhaseV1::TargetGated;
        self.replace(next)
    }

    fn execution_observed(&mut self) -> Result<(), String> {
        if self.record.phase != ProbePhaseV1::ReleaseIntent {
            return Err("MCSEALED-PRIVATE-PROBE: exec requires release intent".into());
        }
        let mut next = self.record.clone();
        next.phase = ProbePhaseV1::ExecutionObserved;
        next.release_knowledge = ReleaseKnowledge::ExecObserved;
        self.replace(next)
    }

    fn retiring(&mut self) -> Result<(), String> {
        if matches!(
            self.record.phase,
            ProbePhaseV1::Retired | ProbePhaseV1::CleanupIncomplete
        ) {
            return Err("MCSEALED-PRIVATE-PROBE: case is already terminal".into());
        }
        let mut next = self.record.clone();
        next.phase = ProbePhaseV1::Retiring;
        self.replace(next)
    }

    fn cleanup_incomplete(&mut self, detail: &str) -> Result<(), String> {
        if self.record.phase == ProbePhaseV1::Retired {
            return Err("MCSEALED-PRIVATE-PROBE: retired case cannot become incomplete".into());
        }
        let mut next = self.record.clone();
        next.phase = ProbePhaseV1::CleanupIncomplete;
        next.cleanup_error = Some(detail.to_owned());
        self.replace(next)
    }
}

pub(crate) fn catalogue_digest() -> DiagnosticSha256 {
    let mut digest = Sha256::new();
    digest.update(b"memcordon-installed-private-host-catalogue-v1\0");
    for (kind, name) in HOST_PROBE_CATALOG_V1 {
        let id = kind.id();
        digest.update((id.as_str().len() as u64).to_be_bytes());
        digest.update(id.as_str().as_bytes());
        digest.update((name.len() as u64).to_be_bytes());
        digest.update(name.as_bytes());
    }
    DiagnosticSha256::from_bytes(digest.finalize().into())
}

fn hash_length_prefixed(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}

pub(crate) fn probe_attempt_id(nonce: &[u8; 32], index: usize) -> String {
    hex(&probe_attempt_bytes(nonce, index))
}

pub(crate) fn probe_loss_attempt_id(nonce: &[u8; 32], kind: ProbeLossKindV1) -> String {
    hex(&probe_loss_attempt_bytes(nonce, kind))
}

fn probe_attempt_bytes(nonce: &[u8; 32], index: usize) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(b"memcordon-private-probe-attempt-v1\0");
    digest.update(nonce);
    digest.update((index as u64).to_be_bytes());
    let hash = digest.finalize();
    let mut attempt = [0_u8; 16];
    let length = attempt.len();
    attempt.copy_from_slice(&hash[..length]);
    attempt
}

fn probe_loss_attempt_bytes(nonce: &[u8; 32], kind: ProbeLossKindV1) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(b"memcordon-private-probe-loss-attempt-v1\0");
    digest.update(nonce);
    digest.update([kind as u8]);
    let hash = digest.finalize();
    let mut attempt = [0_u8; 16];
    let length = attempt.len();
    attempt.copy_from_slice(&hash[..length]);
    attempt
}

fn probe_challenge_bytes(
    nonce: &[u8; 32],
    index: usize,
    loss_kind: Option<ProbeLossKindV1>,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"memcordon-private-probe-challenge-v1\0");
    digest.update(nonce);
    digest.update((index as u64).to_be_bytes());
    if let Some(kind) = loss_kind {
        digest.update([kind as u8]);
    }
    digest.finalize().into()
}

fn probe_loss_challenge_bytes(nonce: &[u8; 32], kind: ProbeLossKindV1) -> [u8; 32] {
    probe_challenge_bytes(nonce, 1, Some(kind))
}

fn probe_loss_armed_response(nonce: &[u8; 32], kind: ProbeLossKindV1) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"memcordon-private-probe-loss-armed-v1\0");
    digest.update(probe_loss_challenge_bytes(nonce, kind));
    digest.finalize().into()
}

fn expected_probe_fixture_response(nonce: &[u8; 32], index: usize) -> [u8; 32] {
    let kind = ProbeFixtureKindV1::at(index).expect("closed probe case index");
    let mut digest = Sha256::new();
    digest.update(b"memcordon-private-probe-fixture-v1\0");
    digest.update([kind as u8]);
    digest.update(probe_challenge_bytes(nonce, index, None));
    digest.finalize().into()
}

fn create_run_directory(nonce: &[u8; 32]) -> Result<File, String> {
    super::attempt::secure_state_root()?;
    let root = Path::new(PROBE_ROOT);
    match fs::create_dir(root) {
        Ok(()) => {
            fs::set_permissions(root, fs::Permissions::from_mode(0o700))
                .map_err(|error| error.to_string())?;
            File::open(super::STATE_ROOT)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| error.to_string())?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(format!("MCSEALED-PRIVATE-PROBE: state root: {error}")),
    }
    let root_directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE: state root open: {error}"))?;
    let root_metadata = root_directory
        .metadata()
        .map_err(|error| error.to_string())?;
    if !root_metadata.is_dir() || root_metadata.uid() != 0 || root_metadata.mode() & 0o777 != 0o700
    {
        return Err("MCSEALED-PRIVATE-PROBE: state root protection differs".into());
    }
    let name = CString::new(hex(nonce)).expect("hex nonce has no NUL");
    // SAFETY: mkdirat creates one random run name under the retained protected
    // probe root. An existing run cannot be reused.
    if unsafe { libc::mkdirat(root_directory.as_raw_fd(), name.as_ptr(), 0o700) } == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-PROBE: run directory creation: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: openat follows no link and returns a distinct owned run handle.
    let fd = unsafe {
        libc::openat(
            root_directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-PROBE: run directory open: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful openat returned one owned descriptor.
    let directory = unsafe { File::from_raw_fd(fd) };
    let metadata = directory.metadata().map_err(|error| error.to_string())?;
    if metadata.uid() != 0 || metadata.mode() & 0o777 != 0o700 {
        return Err("MCSEALED-PRIVATE-PROBE: run directory protection differs".into());
    }
    directory.sync_all().map_err(|error| error.to_string())?;
    root_directory
        .sync_all()
        .map_err(|error| error.to_string())?;
    Ok(directory)
}

fn verify_transferred_run_directory(nonce: &[u8; 32], transferred: &File) -> Result<(), String> {
    verify_existing_run_directory(nonce, transferred)?;
    if !pinned_directory_entries(transferred)?.is_empty() {
        return Err("MCSEALED-PRIVATE-PROBE: transferred run is not empty".into());
    }
    Ok(())
}

fn verify_existing_run_directory(nonce: &[u8; 32], transferred: &File) -> Result<(), String> {
    if *nonce == [0; 32] {
        return Err("MCSEALED-PRIVATE-PROBE: zero run nonce".into());
    }
    super::attempt::secure_state_root()?;
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(PROBE_ROOT)
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE: root readback: {error}"))?;
    let root_metadata = root.metadata().map_err(|error| error.to_string())?;
    if !root_metadata.is_dir() || root_metadata.uid() != 0 || root_metadata.mode() & 0o777 != 0o700
    {
        return Err("MCSEALED-PRIVATE-PROBE: run root protection differs".into());
    }
    let name = CString::new(hex(nonce)).expect("hex nonce has no NUL");
    // SAFETY: fixed hex leaf is opened relative to a verified protected root;
    // no symlink is followed at this final component.
    let fd = unsafe {
        libc::openat(
            root.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-PROBE: run handle readback: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful openat returned one owned directory descriptor.
    let expected = unsafe { File::from_raw_fd(fd) };
    let expected_metadata = expected.metadata().map_err(|error| error.to_string())?;
    let transferred_metadata = transferred.metadata().map_err(|error| error.to_string())?;
    if expected_metadata.dev() != transferred_metadata.dev()
        || expected_metadata.ino() != transferred_metadata.ino()
        || transferred_metadata.uid() != 0
        || transferred_metadata.mode() & 0o777 != 0o700
    {
        return Err("MCSEALED-PRIVATE-PROBE: protected run handle differs".into());
    }
    Ok(())
}

fn acquire_run_lock() -> Result<File, String> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(PROBE_RUN_LOCK)
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE: run lock open: {error}"))?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err("MCSEALED-PRIVATE-PROBE: run lock protection differs".into());
    }
    // SAFETY: flock applies one nonblocking exclusive lock to this owned fd.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-PROBE: another qualification run is active: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(file)
}

fn verify_qualification_service_context() -> Result<(), String> {
    verify_service_context("memcordon-sealed-network-launcher.service")
}

fn verify_service_context(unit: &str) -> Result<(), String> {
    let membership = fs::read_to_string("/proc/self/cgroup")
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE: service membership: {error}"))?;
    let in_unit = membership.lines().any(|line| {
        line.split_once("::").is_some_and(|(_, path)| {
            Path::new(path)
                .components()
                .any(|component| component.as_os_str() == unit)
        })
    });
    if !in_unit {
        return Err("MCSEALED-PRIVATE-PROBE: coordinator is not in protected launcher unit".into());
    }
    let current = fs::metadata("/proc/self/exe")
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE: coordinator image: {error}"))?;
    let installed = fs::symlink_metadata("/usr/libexec/memcordon-sealed-agent")
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE: installed image: {error}"))?;
    if !installed.is_file() || current.dev() != installed.dev() || current.ino() != installed.ino()
    {
        return Err("MCSEALED-PRIVATE-PROBE: coordinator image differs from install".into());
    }
    Ok(())
}

fn verify_probe_working_directory() -> Result<File, String> {
    let path = Path::new(PROBE_WORKING_DIRECTORY);
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE: workdir open: {error}"))?;
    let metadata = directory.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o555
        || !pinned_directory_entries(&directory)?.is_empty()
    {
        return Err("MCSEALED-PRIVATE-PROBE: workdir protection or emptiness differs".into());
    }
    Ok(directory)
}

pub(crate) fn fixed_probe_account() -> Result<(u32, u32), String> {
    let name = CString::new(PROBE_IDENTITY).expect("fixed account has no NUL");
    let mut entry = unsafe { std::mem::zeroed::<libc::passwd>() };
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0_u8; 4096];
    // SAFETY: getpwnam_r receives live output pointers and a bounded buffer.
    let status = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            &raw mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &raw mut result,
        )
    };
    if status != 0
        || result.is_null()
        || entry.pw_uid == 0
        || entry.pw_gid == 0
        || entry.pw_dir.is_null()
        || entry.pw_shell.is_null()
    {
        return Err("MCSEALED-PRIVATE-PROBE: dedicated account readback failed".into());
    }
    // SAFETY: successful getpwnam_r returned pointers into the still-live
    // caller-owned buffer; neither field is nullable for an account entry.
    let (home, shell) = unsafe {
        (
            std::ffi::CStr::from_ptr(entry.pw_dir),
            std::ffi::CStr::from_ptr(entry.pw_shell),
        )
    };
    if home.to_bytes() != b"/nonexistent" || shell.to_bytes() != b"/usr/sbin/nologin" {
        return Err("MCSEALED-PRIVATE-PROBE: account home or shell differs".into());
    }
    let mut group_entry = unsafe { std::mem::zeroed::<libc::group>() };
    let mut group_result = std::ptr::null_mut();
    let mut group_buffer = vec![0_u8; 4096];
    // SAFETY: getgrgid_r receives live output pointers and a bounded buffer.
    let group_status = unsafe {
        libc::getgrgid_r(
            entry.pw_gid,
            &raw mut group_entry,
            group_buffer.as_mut_ptr().cast(),
            group_buffer.len(),
            &raw mut group_result,
        )
    };
    if group_status != 0
        || group_result.is_null()
        || group_entry.gr_name.is_null()
        || unsafe { std::ffi::CStr::from_ptr(group_entry.gr_name) }.to_bytes()
            != PROBE_IDENTITY.as_bytes()
    {
        return Err("MCSEALED-PRIVATE-PROBE: dedicated primary group differs".into());
    }
    let mut count = 0;
    // SAFETY: the first call only obtains the required supplementary-group count.
    unsafe {
        libc::getgrouplist(
            name.as_ptr(),
            entry.pw_gid,
            std::ptr::null_mut(),
            &raw mut count,
        )
    };
    if !(1..=32).contains(&count) {
        return Err("MCSEALED-PRIVATE-PROBE: account group inventory differs".into());
    }
    let mut groups = vec![0 as libc::gid_t; count as usize];
    // SAFETY: getgrouplist receives a live buffer of the probed size.
    let status = unsafe {
        libc::getgrouplist(
            name.as_ptr(),
            entry.pw_gid,
            groups.as_mut_ptr(),
            &raw mut count,
        )
    };
    if status < 0 || count != 1 || groups[0] != entry.pw_gid {
        return Err("MCSEALED-PRIVATE-PROBE: account has supplementary groups".into());
    }
    Ok((entry.pw_uid, entry.pw_gid))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut value, "{byte:02x}").expect("hex writing to String cannot fail");
    }
    value
}
