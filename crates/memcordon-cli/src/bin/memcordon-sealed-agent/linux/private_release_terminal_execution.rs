//! Physical post-release midpoint owner. A target cannot reach its final
//! response until protected ExecObserved readback and CI live ACK both finish.

use std::fs::File;
use std::io::Write;
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, Instant};

use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_codec::hash_bytes;

use super::namespace::CallerMountContext;
use super::network_profile::current_network_namespace;
use super::private_lifecycle::{PrivateExecObservation, PrivateMonitorOutcome};
use super::private_release_execution::CandidateNativeObservationV1;
use super::private_release_run::ReleaseCandidateRunAuthorityV1;
use super::private_release_terminal_join::{LIVE_BYTES, SELECTOR, TerminalJoinLiveFrameV1};
use crate::request::{FileIdentity, NamespaceIdentity, SwapLimit};

pub(crate) struct TerminalJoinNativeObservationV1 {
    pub(crate) candidate: CandidateNativeObservationV1,
    pub(crate) live_frame: [u8; LIVE_BYTES],
    pub(crate) target_namespace_pid: u32,
    pub(crate) target_pid_chain: Vec<u32>,
    pub(crate) midflight_record_digest: DiagnosticSha256,
    pub(crate) terminal_join_gate_sha256: DiagnosticSha256,
}

/// No result is published here: worker raw, coordinator exit and detached
/// terminal joins remain mandatory after this physical run.
#[allow(dead_code)] // Selector remains closed until raw/detached joins land.
pub(crate) fn execute_terminal_join_candidate_case(
    case: &ReleaseCandidateRunAuthorityV1,
) -> Result<TerminalJoinNativeObservationV1, String> {
    if case.selector() != SELECTOR {
        return Err("MCSEALED-PRIVATE-RELEASE: terminal-join selector differs".into());
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
    let mut target_stdin = File::from(stdin_write);
    target_stdin.write_all(&challenge).map_err(|error| {
        format!("MCSEALED-PRIVATE-RELEASE: terminal-join challenge pipe: {error}")
    })?;
    let mut owner = case.begin_native_owner()?;
    let startup_deadline = (Instant::now() + Duration::from_secs(5)).min(case.deadline());
    if startup_deadline <= Instant::now() {
        return Err("MCSEALED-PRIVATE-RELEASE: terminal-join startup expired".into());
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
        let network_namespace_inode = observed.network_namespace_inode();
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
            return Err("MCSEALED-PRIVATE-RELEASE: terminal-join target exec failed".into());
        }
        super::private_release_live_gate::wait_baseline_for_candidate(
            case,
            &mut owner,
            stdout_read.as_fd(),
            target_stdin.as_fd(),
            None,
        )?;
        let live_deadline = (Instant::now() + Duration::from_secs(5)).min(case.deadline());
        let live_frame = super::private_release_terminal_join::read_live_frame(
            stdout_read.as_fd(),
            live_deadline,
        )?;
        let decoded = TerminalJoinLiveFrameV1::decode(&live_frame, &challenge)?;
        let target = owner.observe_live_terminal_join_target()?;
        let chain = super::private_release_child_owner::read_namespace_chain(
            &Path::new("/proc")
                .join(target.pid.to_string())
                .join("status"),
        )?;
        if !super::private_release_child_owner::chain_matches(
            &chain,
            target.pid,
            decoded.target_pid,
        ) || owner.observe_live_terminal_join_target()? != target
        {
            return Err("MCSEALED-PRIVATE-RELEASE: terminal-join target PID differs".into());
        }
        let midflight = case.read_terminal_join_midflight()?;
        if midflight.target != target || midflight.checkpoint_digest != checkpoint {
            return Err("MCSEALED-PRIVATE-RELEASE: terminal-join midflight differs".into());
        }
        let gate_sha256 = case.persist_terminal_join_gate(&midflight, &target)?;
        case.wait_terminal_join_ack(&gate_sha256, Instant::now() + Duration::from_secs(15))?;
        if owner.observe_live_terminal_join_target()? != target
            || case.read_terminal_join_midflight()?.execution_record_bytes
                != midflight.execution_record_bytes
        {
            return Err("MCSEALED-PRIVATE-RELEASE: terminal-join target or journal changed".into());
        }
        target_stdin.write_all(&[1]).map_err(|error| {
            format!("MCSEALED-PRIVATE-RELEASE: terminal-join target ack: {error}")
        })?;
        if owner.monitor_release_candidate(case)? != PrivateMonitorOutcome::Completed {
            return Err("MCSEALED-PRIVATE-RELEASE: terminal-join monitor incomplete".into());
        }
        let final_response =
            super::private_release_case::candidate_fixture_response(SELECTOR, &challenge);
        let output = super::private_probe_execution::read_bounded_pipe(
            stdout_read,
            final_response.len() + 1,
        )?;
        let stderr = super::private_probe_execution::read_bounded_pipe(stderr_read, 1025)?;
        if output != final_response || !stderr.is_empty() {
            return Err("MCSEALED-PRIVATE-RELEASE: terminal-join final response differs".into());
        }
        Ok((
            checkpoint,
            network_namespace_inode,
            live_frame,
            decoded.target_pid,
            chain,
            midflight.execution_record_digest,
            gate_sha256,
            final_response,
        ))
    })();
    let retirement = owner.retire_release_candidate(Instant::now() + Duration::from_secs(30));
    let (
        checkpoint,
        network_namespace_inode,
        live_frame,
        target_namespace_pid,
        target_pid_chain,
        midflight_record_digest,
        terminal_join_gate_sha256,
        final_response,
    ) = run?;
    let retirement = retirement?;
    if current_network_namespace()? != provider_namespace
        || retirement.checkpoint_digest.as_ref() != Some(&checkpoint)
        || retirement.candidate_exit_code != Some(0)
    {
        return Err("MCSEALED-PRIVATE-RELEASE: terminal-join retirement differs".into());
    }
    case.revalidate()?;
    let mut response = Vec::with_capacity(LIVE_BYTES + final_response.len());
    response.extend_from_slice(&live_frame);
    response.extend_from_slice(&final_response);
    Ok(TerminalJoinNativeObservationV1 {
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
        live_frame,
        target_namespace_pid,
        target_pid_chain,
        midflight_record_digest,
        terminal_join_gate_sha256,
    })
}
