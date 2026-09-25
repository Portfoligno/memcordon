//! Fixed successful host-canary cases through the same V4 physical owner.
//! This is not a host qualification producer: fault cases, baseline and the
//! independent protected completion reader are still required.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_codec::hash_bytes;

use super::namespace::CallerMountContext;
use super::network_profile::current_network_namespace;
use super::private_lifecycle::{PrivateExecObservation, PrivateMonitorOutcome};
use super::private_qualification::{
    ProbeCaseAuthority, ProbeFailedExecObservationV1, ProbeFixtureKindV1,
};
use crate::request::{FileIdentity, NamespaceIdentity, SwapLimit};

pub(crate) struct ProbeSuccessfulFixtureV1 {
    pub(crate) attempt_id: String,
    pub(crate) checkpoint_digest: DiagnosticSha256,
    pub(crate) terminal_record_digest: DiagnosticSha256,
    pub(crate) challenge_sha256: DiagnosticSha256,
    pub(crate) response_sha256: DiagnosticSha256,
    pub(crate) completion_digest: DiagnosticSha256,
}

/// Run only the positive private fixture cases whose target behavior is
/// currently implemented. The caller must already be the protected launcher
/// worker and hold a live `ProbeCaseAuthority`; this function cannot mint a
/// host receipt or production lease.
pub(crate) fn execute_success_fixture(
    case: &ProbeCaseAuthority<'_>,
) -> Result<ProbeSuccessfulFixtureV1, String> {
    if !matches!(
        case.kind(),
        ProbeFixtureKindV1::DescriptorIdentityFilterNamespace
            | ProbeFixtureKindV1::NamespacePortSysctlIsolation
            | ProbeFixtureKindV1::TcpListenerClientCompetitor
            | ProbeFixtureKindV1::UnixCreationSocketpairDenial
            | ProbeFixtureKindV1::WrongFamilyProtocolDenial
    ) {
        return Err("MCSEALED-PRIVATE-PROBE: case has no native outcome adapter".into());
    }
    case.revalidate()?;
    let prelaunch = case.prepare_native_prelaunch()?;
    let (uid, gid) = case.target_ids();
    let identity = super::execution_identity::ResolvedTargetIdentity::for_probe_account(uid, gid)?;
    let abi = case.native_abi()?;
    let mount = File::open("/proc/self/ns/mnt")
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE: mount namespace: {error}"))?;
    let root = File::open("/")
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE: root descriptor: {error}"))?;
    let mount_metadata = mount.metadata().map_err(|error| error.to_string())?;
    let root_metadata = root.metadata().map_err(|error| error.to_string())?;
    let mount_context = CallerMountContext {
        mount_namespace: mount.into(),
        root: root.into(),
        mount_namespace_identity: NamespaceIdentity {
            device: mount_metadata.dev(),
            inode: mount_metadata.ino(),
        },
        root_identity: FileIdentity {
            device: root_metadata.dev(),
            inode: root_metadata.ino(),
        },
    };
    let work_directory = case.work_directory()?;
    let provider_namespace = current_network_namespace()?;
    let host_port_policy_before = (case.kind() == ProbeFixtureKindV1::NamespacePortSysctlIsolation)
        .then(host_port_policy_snapshot)
        .transpose()?;
    let worker_pidfd = super::private_execution::pidfd_for_self()?;
    let (stdin_read, stdin_write) = nonblocking_pipe()?;
    let (stdout_read, stdout_write) = nonblocking_pipe()?;
    let (stderr_read, stderr_write) = nonblocking_pipe()?;
    let challenge = case.challenge_bytes();
    let mut stdin_write = File::from(stdin_write);
    stdin_write
        .write_all(&challenge)
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE: challenge pipe: {error}"))?;
    drop(stdin_write);
    let mut owner = case.begin_native_owner()?;
    let startup_deadline = (Instant::now() + Duration::from_secs(5)).min(case.deadline());
    if startup_deadline <= Instant::now() {
        return Err("MCSEALED-PRIVATE-PROBE: startup deadline expired".into());
    }
    let run = (|| -> Result<_, String> {
        owner.create_boundary(None, SwapLimit::Host)?;
        owner.spawn_namespace(
            prelaunch,
            mount_context,
            work_directory.into(),
            provider_namespace,
            provider_namespace,
        )?;
        owner.start_guardian(
            case.attempt_bytes(),
            case.coordinator_pidfd(),
            worker_pidfd.as_fd(),
            startup_deadline,
        )?;
        let observed = owner.observe_gated_target(
            provider_namespace,
            provider_namespace,
            &identity,
            abi,
            *case.filter_digest().bytes(),
            startup_deadline,
        )?;
        owner.prepare_relay([stdin_read, stdout_write, stderr_write])?;
        let checkpoint = owner.commit_probe_and_release(observed, case)?;
        if !matches!(
            owner.observe_exec(startup_deadline)?,
            PrivateExecObservation::ArmedAndControlClosed
        ) {
            return Err("MCSEALED-PRIVATE-PROBE: fixture failed native exec".into());
        }
        if owner.monitor_probe(case)? != PrivateMonitorOutcome::Completed {
            return Err("MCSEALED-PRIVATE-PROBE: fixture did not complete".into());
        }
        let response = read_bounded_pipe(stdout_read, challenge.len() + 1)?;
        let stderr = read_bounded_pipe(stderr_read, 1025)?;
        if response.as_slice() != case.expected_fixture_response() || !stderr.is_empty() {
            return Err("MCSEALED-PRIVATE-PROBE: fixture response or stderr differs".into());
        }
        Ok((checkpoint, response))
    })();
    let retirement_deadline = Instant::now() + Duration::from_secs(30);
    let retirement = owner.retire_probe(retirement_deadline);
    let (checkpoint, response) = run?;
    let retirement = retirement?;
    if current_network_namespace()? != provider_namespace {
        return Err("MCSEALED-PRIVATE-PROBE: provider network namespace changed".into());
    }
    if let Some(before) = host_port_policy_before {
        if host_port_policy_snapshot()? != before {
            return Err("MCSEALED-PRIVATE-PROBE: host port policy changed".into());
        }
    }
    if retirement.checkpoint_digest.as_ref() != Some(&checkpoint)
        || retirement.candidate_exit_code != Some(0)
    {
        return Err("MCSEALED-PRIVATE-PROBE: target exit or retirement differs".into());
    }
    case.revalidate()?;
    let mut observation = ProbeSuccessfulFixtureV1 {
        attempt_id: retirement.attempt_id,
        checkpoint_digest: checkpoint,
        terminal_record_digest: retirement.terminal_record_digest,
        challenge_sha256: hash_bytes(&challenge),
        response_sha256: hash_bytes(&response),
        completion_digest: DiagnosticSha256::from_bytes([0; 32]),
    };
    observation.completion_digest = case.persist_successful_completion(&observation)?;
    Ok(observation)
}

/// Case 3 deliberately reaches the native target-side execveat syscall with
/// a pinned verified image, then omits AT_EMPTY_PATH. Only the exact ENOENT
/// failure packet and a retired exit-125 probe journal count as this fault.
pub(crate) fn execute_failed_exec_fixture(
    case: &ProbeCaseAuthority<'_>,
) -> Result<ProbeFailedExecObservationV1, String> {
    if case.kind() != ProbeFixtureKindV1::TargetExecFailureRetirement {
        return Err("MCSEALED-PRIVATE-PROBE: wrong fixed exec-failure case".into());
    }
    case.revalidate()?;
    let prelaunch = case.prepare_native_prelaunch()?;
    let (uid, gid) = case.target_ids();
    let identity = super::execution_identity::ResolvedTargetIdentity::for_probe_account(uid, gid)?;
    let abi = case.native_abi()?;
    let mount = File::open("/proc/self/ns/mnt")
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE: mount namespace: {error}"))?;
    let root = File::open("/")
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE: root descriptor: {error}"))?;
    let mount_metadata = mount.metadata().map_err(|error| error.to_string())?;
    let root_metadata = root.metadata().map_err(|error| error.to_string())?;
    let mount_context = CallerMountContext {
        mount_namespace: mount.into(),
        root: root.into(),
        mount_namespace_identity: NamespaceIdentity {
            device: mount_metadata.dev(),
            inode: mount_metadata.ino(),
        },
        root_identity: FileIdentity {
            device: root_metadata.dev(),
            inode: root_metadata.ino(),
        },
    };
    let work_directory = case.work_directory()?;
    let provider_namespace = current_network_namespace()?;
    let worker_pidfd = super::private_execution::pidfd_for_self()?;
    let (stdin_read, stdin_write) = nonblocking_pipe()?;
    let (stdout_read, stdout_write) = nonblocking_pipe()?;
    let (stderr_read, stderr_write) = nonblocking_pipe()?;
    let mut stdin_write = File::from(stdin_write);
    stdin_write
        .write_all(&case.challenge_bytes())
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE: challenge pipe: {error}"))?;
    drop(stdin_write);
    let mut owner = case.begin_native_owner()?;
    let startup_deadline = (Instant::now() + Duration::from_secs(5)).min(case.deadline());
    if startup_deadline <= Instant::now() {
        return Err("MCSEALED-PRIVATE-PROBE: startup deadline expired".into());
    }
    let run = (|| -> Result<_, String> {
        owner.create_boundary(None, SwapLimit::Host)?;
        owner.spawn_namespace(
            prelaunch,
            mount_context,
            work_directory.into(),
            provider_namespace,
            provider_namespace,
        )?;
        owner.start_guardian(
            case.attempt_bytes(),
            case.coordinator_pidfd(),
            worker_pidfd.as_fd(),
            startup_deadline,
        )?;
        let observed = owner.observe_gated_target(
            provider_namespace,
            provider_namespace,
            &identity,
            abi,
            *case.filter_digest().bytes(),
            startup_deadline,
        )?;
        owner.prepare_relay([stdin_read, stdout_write, stderr_write])?;
        let checkpoint = owner.commit_probe_and_release(observed, case)?;
        let exec = owner.observe_exec(startup_deadline)?;
        let (phase, detail) = match exec {
            PrivateExecObservation::Failed { phase, detail }
                if phase == 5 && detail == "MCSEALED-PROBE-EXECVEAT-ENOENT" =>
            {
                (phase, detail)
            }
            _ => {
                return Err(
                    "MCSEALED-PRIVATE-PROBE: fixed target exec did not fail at execveat".into(),
                );
            }
        };
        owner.wait_failed_probe_target_exit(startup_deadline)?;
        Ok((checkpoint, phase, detail))
    })();
    let retirement = owner.retire_probe(Instant::now() + Duration::from_secs(30));
    let (checkpoint, phase, detail) = run?;
    let retirement = retirement?;
    if retirement.checkpoint_digest.as_ref() != Some(&checkpoint)
        || retirement.candidate_exit_code != Some(125)
        || current_network_namespace()? != provider_namespace
        || !read_bounded_pipe(stdout_read, 1)?.is_empty()
        || !read_bounded_pipe(stderr_read, 1025)?.is_empty()
    {
        return Err("MCSEALED-PRIVATE-PROBE: failed-exec terminal or retirement differs".into());
    }
    case.revalidate()?;
    let observed = ProbeFailedExecObservationV1 {
        attempt_id: retirement.attempt_id,
        checkpoint_digest: checkpoint,
        terminal_record_digest: retirement.terminal_record_digest,
        phase,
        detail,
    };
    case.persist_failed_exec_completion(&observed)?;
    Ok(observed)
}

fn host_port_policy_snapshot() -> Result<[Vec<u8>; 3], String> {
    const PATHS: [&str; 3] = [
        "/proc/sys/net/ipv4/ip_unprivileged_port_start",
        "/proc/sys/net/ipv4/ip_local_port_range",
        "/proc/sys/net/ipv4/ip_local_reserved_ports",
    ];
    PATHS
        .map(|path| {
            let mut bytes = Vec::new();
            File::open(path)
                .and_then(|file| file.take(65).read_to_end(&mut bytes))
                .map_err(|error| format!("MCSEALED-PRIVATE-PROBE: host sysctl {path}: {error}"))?;
            if bytes.len() > 64 {
                return Err(format!(
                    "MCSEALED-PRIVATE-PROBE: host sysctl overlong {path}"
                ));
            }
            Ok(bytes)
        })
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| "MCSEALED-PRIVATE-PROBE: host sysctl count differs".into())
}

pub(crate) fn nonblocking_pipe() -> Result<(OwnedFd, OwnedFd), String> {
    let mut fds = [-1; 2];
    // SAFETY: pipe2 initializes two unique descriptor slots on success.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-PROBE: pipe: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful pipe2 returned two unique owned descriptors.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

pub(crate) fn read_bounded_pipe(fd: OwnedFd, limit: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    File::from(fd)
        .take(limit as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE: fixture pipe: {error}"))?;
    Ok(bytes)
}
