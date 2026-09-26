//! Fixed release-domain guardian-loss target. Producing its armed response is
//! never a completed case: the target stays live until the candidate owner
//! proves an exact guardian SIGKILL, reap, and bounded native retirement.

use std::fs::File;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_codec::hash_bytes;

use super::namespace::CallerMountContext;
use super::network_profile::current_network_namespace;
use super::private_lifecycle::PrivateExecObservation;
use super::private_release_run::ReleaseCandidateRunAuthorityV1;
use crate::request::{FileIdentity, NamespaceIdentity, SwapLimit};

pub(crate) const SELECTOR: &str = "private_tcp::guardian_loss_retired";

pub(crate) fn armed_response(challenge: &[u8; 32]) -> [u8; 32] {
    super::private_release_case::candidate_fixture_response(SELECTOR, challenge)
}

pub(crate) fn run_target(challenge: &[u8; 32]) -> Result<(), String> {
    run_target_with_response(challenge, &armed_response(challenge))
}

pub(crate) fn run_target_with_response(
    challenge: &[u8; 32],
    response: &[u8; 32],
) -> Result<(), String> {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE-GUARDIAN-LOSS: TCP bind: {error}"))?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE-GUARDIAN-LOSS: TCP address: {error}"))?;
    let mut client = TcpStream::connect_timeout(&address, Duration::from_secs(2))
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE-GUARDIAN-LOSS: TCP connect: {error}"))?;
    let (mut accepted, peer) = listener
        .accept()
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE-GUARDIAN-LOSS: TCP accept: {error}"))?;
    if peer.ip() != address.ip() {
        return Err("MCSEALED-PRIVATE-RELEASE-GUARDIAN-LOSS: TCP peer differs".into());
    }
    let collision = TcpListener::bind(address);
    if collision
        .as_ref()
        .err()
        .and_then(std::io::Error::raw_os_error)
        != Some(libc::EADDRINUSE)
    {
        return Err("MCSEALED-PRIVATE-RELEASE-GUARDIAN-LOSS: TCP competitor differed".into());
    }
    client
        .set_write_timeout(Some(Duration::from_secs(2)))
        .and_then(|()| accepted.set_read_timeout(Some(Duration::from_secs(2))))
        .and_then(|()| accepted.set_write_timeout(Some(Duration::from_secs(2))))
        .and_then(|()| client.set_read_timeout(Some(Duration::from_secs(2))))
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE-GUARDIAN-LOSS: TCP timeout: {error}"))?;
    client
        .write_all(challenge)
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE-GUARDIAN-LOSS: TCP send: {error}"))?;
    let mut observed = [0_u8; 32];
    accepted
        .read_exact(&mut observed)
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE-GUARDIAN-LOSS: TCP receive: {error}"))?;
    if observed != *challenge {
        return Err("MCSEALED-PRIVATE-RELEASE-GUARDIAN-LOSS: TCP challenge differs".into());
    }
    accepted
        .write_all(&observed)
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE-GUARDIAN-LOSS: TCP echo: {error}"))?;
    client.read_exact(&mut observed).map_err(|error| {
        format!("MCSEALED-PRIVATE-RELEASE-GUARDIAN-LOSS: TCP echo receive: {error}")
    })?;
    if observed != *challenge {
        return Err("MCSEALED-PRIVATE-RELEASE-GUARDIAN-LOSS: TCP echo differs".into());
    }
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(response)
        .and_then(|()| stdout.flush())
        .map_err(|error| {
            format!("MCSEALED-PRIVATE-RELEASE-GUARDIAN-LOSS: armed output: {error}")
        })?;
    loop {
        std::hint::black_box((&listener, &client, &accepted));
        std::thread::park();
    }
}

/// This comes only from a distinct release-domain V4 owner after real TCP
/// arming, exact guardian pidfd SIGKILL/reap, and durable native retirement.
/// Raw attachment and detached service/CI joins remain separate prerequisites.
pub(crate) struct GuardianLossCandidateNativeObservationV1 {
    pub(crate) attempt_id: String,
    pub(crate) checkpoint_digest: DiagnosticSha256,
    pub(crate) terminal_record_digest: DiagnosticSha256,
    pub(crate) challenge_sha256: DiagnosticSha256,
    pub(crate) armed_response_sha256: DiagnosticSha256,
    pub(crate) network_namespace_inode: u64,
    pub(crate) terminal_bytes: Vec<u8>,
    pub(crate) settlement: super::private_release_attempt::GuardianLossCandidateSettlementFactsV1,
}

pub(crate) fn execute_guardian_loss_candidate_case(
    case: &ReleaseCandidateRunAuthorityV1,
) -> Result<GuardianLossCandidateNativeObservationV1, String> {
    if case.selector() != SELECTOR {
        return Err("MCSEALED-PRIVATE-RELEASE: guardian-loss selector differs".into());
    }
    case.revalidate()?;
    let prelaunch = case.prepare_native_prelaunch()?;
    let (uid, gid) = case.target_ids()?;
    let identity = super::execution_identity::ResolvedTargetIdentity::for_probe_account(uid, gid)?;
    let abi = case.native_abi()?;
    let mount = File::open("/proc/self/ns/mnt")
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: mount namespace: {error}"))?;
    let root = File::open("/")
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: root descriptor: {error}"))?;
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
    let (stdin_read, stdin_write) = super::private_probe_execution::nonblocking_pipe()?;
    let (stdout_read, stdout_write) = super::private_probe_execution::nonblocking_pipe()?;
    let (stderr_read, stderr_write) = super::private_probe_execution::nonblocking_pipe()?;
    let challenge = case.challenge_bytes();
    let mut baseline_input = File::from(stdin_write);
    baseline_input
        .write_all(&challenge)
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: guardian-loss challenge: {error}"))?;
    let mut owner = case.begin_native_owner()?;
    let startup_deadline = (Instant::now() + Duration::from_secs(5)).min(case.deadline());
    if startup_deadline <= Instant::now() {
        return Err("MCSEALED-PRIVATE-RELEASE: guardian-loss startup deadline expired".into());
    }
    let setup = (|| -> Result<(DiagnosticSha256, u64), String> {
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
        let namespace_inode = observed.network_namespace_inode();
        owner.prepare_relay([stdin_read, stdout_write, stderr_write])?;
        super::private_release_live_gate::wait_pre_for_candidate(
            case,
            &mut owner,
            observed.target_identity(),
        )?;
        let checkpoint = owner.commit_release_candidate_and_release(observed, case)?;
        if !matches!(
            owner.observe_exec(startup_deadline)?,
            PrivateExecObservation::ArmedAndControlClosed
        ) {
            return Err("MCSEALED-PRIVATE-RELEASE: guardian-loss target did not exec".into());
        }
        super::private_release_live_gate::wait_baseline_for_candidate(
            case,
            &mut owner,
            stdout_read.as_fd(),
            baseline_input.as_fd(),
            None,
        )?;
        owner.await_release_guardian_loss_armed(
            case,
            stdout_read.as_fd(),
            &armed_response(&challenge),
            startup_deadline,
        )?;
        Ok((checkpoint, namespace_inode))
    })();
    let (checkpoint, network_namespace_inode) = match setup {
        Ok(facts) => facts,
        Err(error) => {
            let cleanup = owner.abort_release_candidate_guardian_loss_setup(
                Instant::now() + Duration::from_secs(30),
            );
            return Err(match cleanup {
                Ok(_) => error,
                Err(cleanup) => format!("{error}; native cleanup: {cleanup}"),
            });
        }
    };
    if let Err(error) = case.revalidate() {
        let cleanup = owner
            .abort_release_candidate_guardian_loss_setup(Instant::now() + Duration::from_secs(30));
        return Err(match cleanup {
            Ok(()) => error,
            Err(cleanup) => format!("{error}; native cleanup: {cleanup}"),
        });
    }
    let retirement = owner
        .retire_release_candidate_after_guardian_loss(Instant::now() + Duration::from_secs(30))?;
    let extra_stdout = super::private_probe_execution::read_bounded_pipe(stdout_read, 1)?;
    let stderr = super::private_probe_execution::read_bounded_pipe(stderr_read, 1)?;
    if !extra_stdout.is_empty()
        || !stderr.is_empty()
        || retirement.checkpoint_digest != checkpoint
        || retirement.settlement.candidate_exit_code == Some(0)
        || current_network_namespace()? != provider_namespace
    {
        return Err("MCSEALED-PRIVATE-RELEASE: guardian-loss terminal differs".into());
    }
    case.revalidate()?;
    Ok(GuardianLossCandidateNativeObservationV1 {
        attempt_id: retirement.attempt_id,
        checkpoint_digest: checkpoint,
        terminal_record_digest: retirement.terminal_record_digest,
        challenge_sha256: hash_bytes(&challenge),
        armed_response_sha256: hash_bytes(&armed_response(&challenge)),
        network_namespace_inode,
        terminal_bytes: retirement.terminal_bytes,
        settlement: retirement.settlement,
    })
}
