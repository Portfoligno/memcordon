//! Physical release-domain child/thread fixture owner. The target's early
//! frame is only an ID selector; the owner independently observes live kernel
//! identities and cgroup membership before acknowledging it.

use std::fs::File;
use std::io::Write;
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

use memcordon_core::workload_codec::hash_bytes;

use super::namespace::CallerMountContext;
use super::network_profile::current_network_namespace;
use super::private_lifecycle::{PrivateExecObservation, PrivateMonitorOutcome};
use super::private_release_child_owner::LiveDescendantWitnessV1;
use super::private_release_execution::CandidateNativeObservationV1;
use super::private_release_run::ReleaseCandidateRunAuthorityV1;
use crate::request::{FileIdentity, NamespaceIdentity, SwapLimit};

pub(crate) struct ChildCandidateNativeObservationV1 {
    pub(crate) candidate: CandidateNativeObservationV1,
    pub(crate) live: LiveDescendantWitnessV1,
}

/// No result or Q token is produced here. The worker must still persist raw
/// bytes, the coordinator must observe worker exit, and detached service/CI
/// must independently verify retirement before a case can complete.
#[allow(dead_code)] // Selector stays closed until raw/detached joins land.
pub(crate) fn execute_child_candidate_case(
    case: &ReleaseCandidateRunAuthorityV1,
) -> Result<ChildCandidateNativeObservationV1, String> {
    if case.selector() != super::private_release_children::SELECTOR {
        return Err("MCSEALED-PRIVATE-RELEASE: child selector differs".into());
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
    target_stdin
        .write_all(&challenge)
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: child challenge pipe: {error}"))?;
    let mut owner = case.begin_native_owner()?;
    let startup_deadline = (Instant::now() + Duration::from_secs(5)).min(case.deadline());
    if startup_deadline <= Instant::now() {
        return Err("MCSEALED-PRIVATE-RELEASE: child startup deadline expired".into());
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
        let checkpoint = owner.commit_release_candidate_and_release(observed, case)?;
        if !matches!(
            owner.observe_exec(startup_deadline)?,
            PrivateExecObservation::ArmedAndControlClosed
        ) {
            return Err("MCSEALED-PRIVATE-RELEASE: child target exec failed".into());
        }
        let custody = owner.observe_release_live_descendants(
            &challenge,
            stdout_read.as_fd(),
            startup_deadline,
        )?;
        let live_gate_sha256 = case.persist_child_live_gate(&custody.witness)?;
        case.wait_child_live_ack(&live_gate_sha256, Instant::now() + Duration::from_secs(15))?;
        owner.revalidate_release_live_descendants(&custody)?;
        target_stdin
            .write_all(&[1])
            .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: child owner ack: {error}"))?;
        if owner.monitor_release_candidate(case)? != PrivateMonitorOutcome::Completed {
            return Err("MCSEALED-PRIVATE-RELEASE: child monitor did not complete".into());
        }
        let final_response = super::private_release_case::candidate_fixture_response(
            super::private_release_children::SELECTOR,
            &challenge,
        );
        let output = super::private_probe_execution::read_bounded_pipe(
            stdout_read,
            final_response.len() + 1,
        )?;
        let stderr = super::private_probe_execution::read_bounded_pipe(stderr_read, 1025)?;
        if output != final_response || !stderr.is_empty() {
            return Err("MCSEALED-PRIVATE-RELEASE: child completion response differs".into());
        }
        Ok((checkpoint, network_namespace_inode, custody, final_response))
    })();
    let retirement = owner.retire_release_candidate(Instant::now() + Duration::from_secs(30));
    let (checkpoint, network_namespace_inode, custody, final_response) = run?;
    let retirement = retirement?;
    if current_network_namespace()? != provider_namespace
        || retirement.checkpoint_digest.as_ref() != Some(&checkpoint)
        || retirement.candidate_exit_code != Some(0)
    {
        return Err("MCSEALED-PRIVATE-RELEASE: child native retirement differs".into());
    }
    let live = custody.verify_retired(&retirement.attempt_id)?;
    case.revalidate()?;
    let mut response =
        Vec::with_capacity(super::private_release_children::LIVE_BYTES + final_response.len());
    response.extend_from_slice(&live.live_frame());
    response.extend_from_slice(&final_response);
    Ok(ChildCandidateNativeObservationV1 {
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
        },
        live,
    })
}
