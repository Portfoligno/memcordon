//! Physical owner path for the sealed precreated-socket laundering case.
//! This is unrouted until protected raw, detached and CI joins exist.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

use memcordon_core::workload_codec::hash_bytes;

use super::namespace::CallerMountContext;
use super::network_profile::current_network_namespace;
use super::private_lifecycle::{PrivateExecObservation, PrivateMonitorOutcome};
use super::private_release_execution::CandidateNativeObservationV1;
use super::private_release_run::ReleaseCandidateRunAuthorityV1;
use crate::request::{FileIdentity, NamespaceIdentity, SwapLimit};

pub(crate) struct SocketLaunderNativeObservationV1 {
    pub(crate) candidate: CandidateNativeObservationV1,
    pub(crate) gated_witness: super::private_release_socket_launder::PrecreatedSocketGatedWitnessV1,
    pub(crate) socket_gate_sha256: memcordon_core::DiagnosticSha256,
}

#[allow(dead_code)] // The selector is closed until protected evidence joins.
pub(crate) fn execute_socket_launder_candidate_case(
    case: &ReleaseCandidateRunAuthorityV1,
) -> Result<SocketLaunderNativeObservationV1, String> {
    if case.selector() != super::private_release_socket_launder::SELECTOR {
        return Err("MCSEALED-PRIVATE-RELEASE: socket laundering selector differs".into());
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
    let mut stdout_pipe = File::from(stdout_read);
    let (stderr_read, stderr_write) = super::private_probe_execution::nonblocking_pipe()?;
    let challenge = case.challenge_bytes();
    let mut baseline_input = File::from(stdin_write);
    baseline_input
        .write_all(&challenge)
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: socket challenge pipe: {error}"))?;
    let mut owner = case.begin_native_owner()?;
    let startup_deadline = (Instant::now() + Duration::from_secs(5)).min(case.deadline());
    if startup_deadline <= Instant::now() {
        return Err("MCSEALED-PRIVATE-RELEASE: socket startup deadline expired".into());
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
        if observed.precreated_sendmsg_errno() != Some(libc::EPERM) {
            return Err("MCSEALED-PRIVATE-RELEASE: gated SCM_RIGHTS denial absent".into());
        }
        let network_namespace_inode = observed.network_namespace_inode();
        let sampled_target = observed.target_identity().clone();
        let witness = observed.precreated_socket_witness()?;
        let gate_sha256 = case.persist_socket_gate(&witness)?;
        case.wait_socket_ack(&gate_sha256, Instant::now() + Duration::from_secs(15))?;
        owner.revalidate_precreated_socket_before_release(&observed)?;
        owner.prepare_relay([stdin_read, stdout_write, stderr_write])?;
        super::private_release_live_gate::wait_pre_for_candidate(
            case,
            &mut owner,
            observed.target_identity(),
        )?;
        let checkpoint = owner.commit_release_candidate_and_release(observed, case)?;
        let exec_deadline = (Instant::now() + Duration::from_secs(5)).min(case.deadline());
        if !matches!(
            owner.observe_exec(exec_deadline)?,
            PrivateExecObservation::ArmedAndControlClosed
        ) {
            return Err("MCSEALED-PRIVATE-RELEASE: socket target failed pinned exec".into());
        }
        super::private_release_live_gate::wait_baseline_for_candidate(
            case,
            &mut owner,
            stdout_pipe.as_fd(),
            baseline_input.as_fd(),
            None,
        )?;
        let expected = case.expected_fixture_output(network_namespace_inode)?;
        let mut response = vec![0u8; expected.len()];
        let mut offset = 0;
        while offset < response.len() {
            owner.tick_relay_for_unix_observer()?;
            match stdout_pipe.read(&mut response[offset..]) {
                Ok(0) => return Err("held SCM fixture output EOF".into()),
                Ok(count) => offset += count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= case.deadline() {
                        return Err("held SCM fixture output deadline".into());
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(error) => return Err(error.to_string()),
            }
        }
        super::private_release_live_gate::wait_for_sample(
            case.protected_case_directory()?,
            case.selector(),
            case.protected_result_key()?,
            &case.challenge_bytes(),
            &sampled_target,
            true,
            &response,
            case.deadline(),
            || owner.require_live_target_identity(&sampled_target),
        )?;
        baseline_input
            .write_all(
                super::private_release_unix_intent::observer_ack_digest(&case.challenge_bytes())
                    .bytes(),
            )
            .map_err(|error| error.to_string())?;
        if owner.monitor_release_candidate(case)? != PrivateMonitorOutcome::Completed {
            return Err("MCSEALED-PRIVATE-RELEASE: socket monitor incomplete".into());
        }
        let extra = super::private_probe_execution::read_bounded_pipe(stdout_pipe.into(), 1)?;
        let stderr = super::private_probe_execution::read_bounded_pipe(stderr_read, 1025)?;
        if response != expected || !extra.is_empty() || !stderr.is_empty() {
            return Err("MCSEALED-PRIVATE-RELEASE: socket target response differs".into());
        }
        Ok((
            checkpoint,
            response,
            network_namespace_inode,
            witness,
            gate_sha256,
        ))
    })();
    let retirement = owner.retire_release_candidate(Instant::now() + Duration::from_secs(30));
    let (checkpoint, response, network_namespace_inode, witness, gate_sha256) = run?;
    let retirement = retirement?;
    if current_network_namespace()? != provider_namespace
        || retirement.checkpoint_digest.as_ref() != Some(&checkpoint)
        || retirement.candidate_exit_code != Some(0)
    {
        return Err("MCSEALED-PRIVATE-RELEASE: socket retirement differs".into());
    }
    case.revalidate()?;
    Ok(SocketLaunderNativeObservationV1 {
        candidate: CandidateNativeObservationV1 {
            attempt_id: retirement.attempt_id,
            checkpoint_digest: checkpoint,
            terminal_record_digest: retirement.terminal_record_digest,
            challenge_sha256: hash_bytes(&challenge),
            response_sha256: hash_bytes(&response),
            candidate_exit_code: 0,
            response_bytes: response,
            network_namespace_inode,
            terminal_bytes: retirement.terminal_bytes,
            settlement: retirement.settlement,
            host_network_preservation: None,
            agent_path_preservation: None,
            unix_absence: None,
        },
        gated_witness: witness,
        socket_gate_sha256: gate_sha256,
    })
}
