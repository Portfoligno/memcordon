//! Physically implemented candidate release selectors through the V4
//! owner. Returning an observation is not a release-case result or Q proof.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_codec::hash_bytes;

use super::namespace::CallerMountContext;
use super::network_profile::current_network_namespace;
use super::private_lifecycle::{PrivateExecObservation, PrivateMonitorOutcome};
use super::private_release_run::ReleaseCandidateRunAuthorityV1;
use crate::request::{FileIdentity, NamespaceIdentity, SwapLimit};

pub(crate) struct CandidateNativeObservationV1 {
    pub(crate) attempt_id: String,
    pub(crate) checkpoint_digest: DiagnosticSha256,
    pub(crate) terminal_record_digest: DiagnosticSha256,
    pub(crate) challenge_sha256: DiagnosticSha256,
    pub(crate) response_sha256: DiagnosticSha256,
    pub(crate) candidate_exit_code: i32,
    pub(crate) response_bytes: Vec<u8>,
    pub(crate) network_namespace_inode: u64,
    pub(crate) terminal_bytes: Vec<u8>,
    pub(crate) settlement: super::private_lifecycle::ReleaseCandidateSettlementFactsV1,
    pub(crate) host_network_preservation:
        Option<super::private_release_host_state::HostNetworkPreservationV1>,
    pub(crate) agent_path_preservation:
        Option<super::private_release_ancestor::AgentPathPreservationV1>,
    pub(crate) unix_absence:
        Option<super::private_release_unix_intent::UnixIntentSupervisorAbsenceV1>,
}

pub(crate) struct UncertainCandidateNativeObservationV1 {
    pub(crate) attempt_id: String,
    pub(crate) checkpoint_digest: DiagnosticSha256,
    pub(crate) terminal_record_digest: DiagnosticSha256,
    pub(crate) challenge_sha256: DiagnosticSha256,
    pub(crate) authorization_failure_phase: u8,
    pub(crate) authorization_failure_detail: String,
    pub(crate) terminal_bytes: Vec<u8>,
    pub(crate) settlement: super::private_release_attempt::UncertainCandidateSettlementFactsV1,
}

pub(crate) struct BlockedCandidateNativeObservationV1 {
    pub(crate) attempt_id: String,
    pub(crate) checkpoint_digest: DiagnosticSha256,
    pub(crate) terminal_record_digest: DiagnosticSha256,
    pub(crate) challenge_sha256: DiagnosticSha256,
    pub(crate) response_sha256: DiagnosticSha256,
    pub(crate) response_bytes: Vec<u8>,
    pub(crate) network_namespace_inode: u64,
    pub(crate) terminal_bytes: Vec<u8>,
    pub(crate) fault_marker_bytes: Vec<u8>,
    pub(crate) transition_error: String,
    pub(crate) reuse_error: String,
    pub(crate) settlement: super::private_lifecycle::ReleaseCandidateSettlementFactsV1,
}

/// Executes the fixed TCP target through the real V4 owner, proves ordinary
/// physical resource settlement, then injects only the durable Retired write
/// conflict. The returned observation is a failure, never TargetCompleted.
#[allow(dead_code)] // Detached fault verifier and result are not connected yet.
pub(crate) fn execute_blocked_retirement_candidate_case(
    case: &ReleaseCandidateRunAuthorityV1,
) -> Result<BlockedCandidateNativeObservationV1, String> {
    if case.selector() != super::private_release_case::RETIREMENT_FAULT_SELECTOR {
        return Err("MCSEALED-PRIVATE-RELEASE: retirement fault selector differs".into());
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
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: fault challenge pipe: {error}"))?;
    let mut owner = case.begin_native_owner()?;
    let startup_deadline = (Instant::now() + Duration::from_secs(5)).min(case.deadline());
    if startup_deadline <= Instant::now() {
        return Err("MCSEALED-PRIVATE-RELEASE: fault startup deadline expired".into());
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
            return Err("MCSEALED-PRIVATE-RELEASE: fault target failed exec".into());
        }
        super::private_release_live_gate::wait_baseline_for_candidate(
            case,
            &mut owner,
            stdout_read.as_fd(),
            baseline_input.as_fd(),
            None,
        )?;
        if owner.monitor_release_candidate(case)? != PrivateMonitorOutcome::Completed {
            return Err("MCSEALED-PRIVATE-RELEASE: fault target monitor incomplete".into());
        }
        let expected = case.expected_fixture_output(network_namespace_inode)?;
        let response =
            super::private_probe_execution::read_bounded_pipe(stdout_read, expected.len() + 1)?;
        let stderr = super::private_probe_execution::read_bounded_pipe(stderr_read, 1025)?;
        if response != expected || !stderr.is_empty() {
            return Err("MCSEALED-PRIVATE-RELEASE: fault fixture response differs".into());
        }
        Ok((checkpoint, response, network_namespace_inode))
    })();
    let retirement = owner.retire_release_candidate_with_durable_fault(
        &challenge,
        Instant::now() + Duration::from_secs(30),
    );
    let (checkpoint, response, network_namespace_inode) = run?;
    let retirement = retirement?;
    if current_network_namespace()? != provider_namespace
        || retirement.checkpoint_digest != checkpoint
        || retirement.settlement.candidate_exit_code != Some(0)
        || retirement.transition_error.is_empty()
        || retirement.reuse_error.is_empty()
    {
        return Err("MCSEALED-PRIVATE-RELEASE: fault native settlement differs".into());
    }
    case.revalidate()?;
    Ok(BlockedCandidateNativeObservationV1 {
        attempt_id: retirement.attempt_id,
        checkpoint_digest: checkpoint,
        terminal_record_digest: retirement.terminal_record_digest,
        challenge_sha256: hash_bytes(&challenge),
        response_sha256: hash_bytes(&response),
        response_bytes: response,
        network_namespace_inode,
        terminal_bytes: retirement.terminal_bytes,
        fault_marker_bytes: retirement.fault_marker_bytes,
        transition_error: retirement.transition_error,
        reuse_error: retirement.reuse_error,
        settlement: retirement.settlement,
    })
}

/// Deliberately loses the control transport after a durable release intent.
/// This never proves target execution or a successful candidate result.
#[allow(dead_code)] // The protected detached verifier is not connected yet.
pub(crate) fn execute_uncertain_candidate_case(
    case: &ReleaseCandidateRunAuthorityV1,
) -> Result<UncertainCandidateNativeObservationV1, String> {
    if case.selector() != super::private_release_case::AUTHORIZATION_UNCERTAIN_SELECTOR {
        return Err("MCSEALED-PRIVATE-RELEASE: uncertainty selector differs".into());
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
    File::from(stdin_write)
        .write_all(&case.challenge_bytes())
        .map_err(|error| {
            format!("MCSEALED-PRIVATE-RELEASE: uncertainty challenge pipe: {error}")
        })?;
    let mut owner = case.begin_native_owner()?;
    let startup_deadline = (Instant::now() + Duration::from_secs(5)).min(case.deadline());
    if startup_deadline <= Instant::now() {
        return Err("MCSEALED-PRIVATE-RELEASE: uncertainty startup deadline expired".into());
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
        super::private_release_live_gate::wait_pre_for_candidate(
            case,
            &mut owner,
            observed.target_identity(),
        )?;
        owner.commit_uncertain_candidate_transport_loss(observed, case)
    })();
    let (checkpoint, transport_errno) = run?;
    // Even if the control observation fails, the owner still attempts
    // bounded physical retirement; a failed observation cannot be promoted.
    let authorization = owner.observe_exec(startup_deadline);
    let retirement = owner.retire_uncertain_release_candidate(
        transport_errno,
        Instant::now() + Duration::from_secs(30),
    )?;
    let (authorization_failure_phase, authorization_failure_detail) = match authorization? {
        PrivateExecObservation::Failed { phase, detail }
            if phase == 4 && detail == "authorization packet invalid" =>
        {
            (phase, detail)
        }
        _ => {
            return Err("MCSEALED-PRIVATE-RELEASE: uncertainty gate failure differs".into());
        }
    };
    let stdout_fd = stdout_read.as_raw_fd();
    let stderr_fd = stderr_read.as_raw_fd();
    let stdout_identity =
        std::fs::metadata(std::path::Path::new("/proc/self/fd").join(stdout_fd.to_string()))
            .map_err(|error| error.to_string())?;
    let stderr_identity =
        std::fs::metadata(std::path::Path::new("/proc/self/fd").join(stderr_fd.to_string()))
            .map_err(|error| error.to_string())?;
    let drain_begin = super::clock::monotonic_nanos()?;
    let stdout = super::private_probe_execution::read_bounded_pipe(stdout_read, 1)?;
    let stderr = super::private_probe_execution::read_bounded_pipe(stderr_read, 1)?;
    let drain_end = super::clock::monotonic_nanos()?;
    if retirement.checkpoint_digest != checkpoint
        || retirement.settlement.transport_errno != libc::EPIPE
        || retirement.settlement.candidate_exit_code == Some(0)
        || current_network_namespace()? != provider_namespace
        || !stdout.is_empty()
        || !stderr.is_empty()
    {
        return Err("MCSEALED-PRIVATE-RELEASE: uncertainty physical observation differs".into());
    }
    let encode_stream = |bytes: &[u8]| {
        let mut framed = (bytes.len() as u64).to_be_bytes().to_vec();
        framed.extend_from_slice(bytes);
        framed
    };
    let directory = case.protected_case_directory()?;
    let stdout = encode_stream(&stdout);
    let stderr = encode_stream(&stderr);
    super::private_release_child_gate::persist_atomic(
        directory,
        "uncertain-stdout-v1.pending",
        "uncertain-stdout-v1.bin",
        &stdout,
    )?;
    super::private_release_child_gate::persist_atomic(
        directory,
        "uncertain-stderr-v1.pending",
        "uncertain-stderr-v1.bin",
        &stderr,
    )?;
    let reader = super::private_attempt::ProcessIdentityV4::observe(
        std::process::id() as libc::pid_t,
        worker_pidfd.as_fd(),
    )?;
    let bytes=serde_json::to_vec(&serde_json::json!({"schema_version":1,"reader":reader,"stdout_fd":stdout_fd,"stderr_fd":stderr_fd,"stdout_inode":stdout_identity.ino(),"stderr_inode":stderr_identity.ino(),"stdout_dev":stdout_identity.dev(),"stderr_dev":stderr_identity.dev(),"stdout_sha256":hash_bytes(&stdout),"stderr_sha256":hash_bytes(&stderr),"begin_monotonic_ns":drain_begin,"end_monotonic_ns":drain_end})).map_err(|error|error.to_string())?;
    super::private_release_child_gate::persist_atomic(
        directory,
        "uncertain-streams-v1.pending",
        "uncertain-streams-v1.json",
        &bytes,
    )?;
    case.revalidate()?;
    Ok(UncertainCandidateNativeObservationV1 {
        attempt_id: retirement.attempt_id,
        checkpoint_digest: checkpoint,
        terminal_record_digest: retirement.terminal_record_digest,
        challenge_sha256: hash_bytes(&case.challenge_bytes()),
        authorization_failure_phase,
        authorization_failure_detail,
        terminal_bytes: retirement.terminal_bytes,
        settlement: retirement.settlement,
    })
}

/// This proves only one selected native target behavior. The fixed 25-case
/// release matrix, raw attachments, independent CI supervisor and Q gate
/// remain separate and must reject any missing selector.
pub(crate) fn execute_candidate_fixture_case(
    case: &ReleaseCandidateRunAuthorityV1,
) -> Result<CandidateNativeObservationV1, String> {
    if !super::private_release_case::candidate_fixture_supported(case.selector()) {
        return Err("MCSEALED-PRIVATE-RELEASE: candidate fixture unavailable".into());
    }
    execute_fixture_case_with_mode(case, FixtureExecutionModeV1::Ordinary)
}

/// Runs the AF_UNIX socket-stage target under the ordinary V4 lifecycle while
/// retaining a held-target observer handshake for independent absence checks.
pub(crate) fn execute_closed_unix_intent_case(
    case: &ReleaseCandidateRunAuthorityV1,
) -> Result<CandidateNativeObservationV1, String> {
    if case.selector() != super::private_release_unix_intent::SELECTOR {
        return Err("MCSEALED-PRIVATE-RELEASE: Unix intent selector differs".into());
    }
    execute_fixture_case_with_mode(case, FixtureExecutionModeV1::ClosedUnixIntent)
}

#[derive(Clone, Copy)]
enum FixtureExecutionModeV1 {
    Ordinary,
    ClosedUnixIntent,
}

fn execute_fixture_case_with_mode(
    case: &ReleaseCandidateRunAuthorityV1,
    mode: FixtureExecutionModeV1,
) -> Result<CandidateNativeObservationV1, String> {
    case.revalidate()?;
    let prelaunch = match mode {
        FixtureExecutionModeV1::Ordinary => case.prepare_native_prelaunch()?,
        FixtureExecutionModeV1::ClosedUnixIntent => case.prepare_closed_unix_intent_prelaunch()?,
    };
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
    let host_before = if case.selector() == super::private_release_host_state::SELECTOR {
        Some(super::private_release_host_state::HostNetworkStateV1::capture()?)
    } else {
        None
    };
    let agent_path_before = if case.selector() == super::private_release_ancestor::SELECTOR {
        Some(case.protected_agent_path_snapshot()?)
    } else {
        None
    };
    let worker_pidfd = super::private_execution::pidfd_for_self()?;
    let (stdin_read, stdin_write) = super::private_probe_execution::nonblocking_pipe()?;
    let (stdout_read, stdout_write) = super::private_probe_execution::nonblocking_pipe()?;
    let (stderr_read, stderr_write) = super::private_probe_execution::nonblocking_pipe()?;
    let challenge = case.challenge_bytes();
    let mut challenge_writer = File::from(stdin_write);
    challenge_writer
        .write_all(&challenge)
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: challenge pipe: {error}"))?;
    let mut observer_input = Some(challenge_writer);
    let mut stdout_pipe = File::from(stdout_read);
    let mut owner = case.begin_native_owner()?;
    let startup_deadline = (Instant::now() + Duration::from_secs(5)).min(case.deadline());
    if startup_deadline <= Instant::now() {
        return Err("MCSEALED-PRIVATE-RELEASE: startup deadline expired".into());
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
        let sampled_target = observed.target_identity().clone();
        let unix_target = (matches!(mode, FixtureExecutionModeV1::ClosedUnixIntent))
            .then(|| observed.target_identity().clone());
        let unix_before = unix_target
            .as_ref()
            .map(|target| {
                owner.require_live_target_identity(target)?;
                super::private_release_unix_intent::observe_target_absence(
                    target,
                    &challenge,
                    network_namespace_inode,
                )
            })
            .transpose()?;
        owner.prepare_relay([stdin_read, stdout_write, stderr_write])?;
        super::private_release_live_gate::wait_for_sample(
            case.protected_case_directory()?,
            case.selector(),
            case.protected_result_key()?,
            &challenge,
            &sampled_target,
            false,
            &[],
            case.deadline(),
            || owner.require_live_target_identity(&sampled_target),
        )?;
        let checkpoint = owner.commit_release_candidate_and_release(observed, case)?;
        if !matches!(
            owner.observe_exec(startup_deadline)?,
            PrivateExecObservation::ArmedAndControlClosed
        ) {
            return Err("MCSEALED-PRIVATE-RELEASE: target failed native exec".into());
        }
        super::private_release_live_gate::wait_baseline_for_candidate(
            case,
            &mut owner,
            stdout_pipe.as_fd(),
            observer_input
                .as_ref()
                .ok_or("baseline stdin missing")?
                .as_fd(),
            None,
        )?;
        let expected = match mode {
            FixtureExecutionModeV1::Ordinary => {
                case.expected_fixture_output(network_namespace_inode)?
            }
            FixtureExecutionModeV1::ClosedUnixIntent => {
                case.expected_closed_unix_intent_output()?
            }
        };
        let (response, unix_absence) = if let Some(target) = unix_target {
            let response = super::private_release_unix_intent::read_held_target_response(
                &mut stdout_pipe,
                &challenge,
                case.deadline(),
                || owner.tick_relay_for_unix_observer(),
            )?;
            owner.require_live_target_identity(&target)?;
            let after = super::private_release_unix_intent::observe_target_absence(
                &target,
                &challenge,
                network_namespace_inode,
            )?;
            owner.require_live_target_identity(&target)?;
            let witness = super::private_release_unix_intent::UnixIntentSupervisorAbsenceV1 {
                target,
                challenge_sha256: hash_bytes(&challenge),
                before_release: unix_before
                    .ok_or("MCSEALED-PRIVATE-RELEASE: Unix before-release observation absent")?,
                after_denials_before_ack: after,
                ack_sha256: super::private_release_unix_intent::observer_ack_digest(&challenge),
            };
            witness.verify_binding(&challenge, &witness.target, network_namespace_inode)?;
            let directory = case.protected_case_directory()?;
            let result_key = case.protected_result_key()?;
            let gate_sha256 = super::private_release_unix_gate::persist_gate(
                directory, result_key, &challenge, &witness,
            )?;
            super::private_release_unix_gate::wait_for_ci_ack(
                directory,
                result_key,
                &challenge,
                &witness,
                &gate_sha256,
                case.deadline(),
            )?;
            owner.require_live_target_identity(&witness.target)?;
            let input = observer_input
                .as_mut()
                .ok_or("MCSEALED-PRIVATE-RELEASE: Unix observer input absent")?;
            input
                .write_all(witness.ack_sha256.bytes())
                .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: Unix observer ACK: {error}"))?;
            drop(observer_input.take());
            (response, Some(witness))
        } else {
            let mut response = vec![0; expected.len()];
            let mut offset = 0;
            while offset < response.len() {
                owner.tick_relay_for_unix_observer()?;
                match stdout_pipe.read(&mut response[offset..]) {
                    Ok(0) => return Err("MCSEALED-PRIVATE-RELEASE: held fixture EOF".into()),
                    Ok(count) => offset += count,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= case.deadline() {
                            return Err(
                                "MCSEALED-PRIVATE-RELEASE: held fixture output deadline".into()
                            );
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
                &challenge,
                &sampled_target,
                true,
                &response,
                case.deadline(),
                || owner.require_live_target_identity(&sampled_target),
            )?;
            observer_input
                .as_mut()
                .ok_or("candidate observer input absent")?
                .write_all(
                    super::private_release_unix_intent::observer_ack_digest(&challenge).bytes(),
                )
                .map_err(|error| error.to_string())?;
            drop(observer_input.take());
            (response, None)
        };
        if owner.monitor_release_candidate(case)? != PrivateMonitorOutcome::Completed {
            return Err("MCSEALED-PRIVATE-RELEASE: native monitor did not complete".into());
        }
        let response = {
            let mut extra = Vec::new();
            (&mut stdout_pipe)
                .take(1)
                .read_to_end(&mut extra)
                .map_err(|error| {
                    format!("MCSEALED-PRIVATE-RELEASE: Unix trailing output: {error}")
                })?;
            if !extra.is_empty() {
                return Err("MCSEALED-PRIVATE-RELEASE: Unix target emitted trailing output".into());
            }
            response
        };
        let stderr = super::private_probe_execution::read_bounded_pipe(stderr_read, 1025)?;
        if response != expected || !stderr.is_empty() {
            return Err("MCSEALED-PRIVATE-RELEASE: fixture response or stderr differs".into());
        }
        Ok((checkpoint, response, network_namespace_inode, unix_absence))
    })();
    let retirement = owner.retire_release_candidate(Instant::now() + Duration::from_secs(30));
    let (checkpoint, response, network_namespace_inode, unix_absence) = run?;
    let retirement = retirement?;
    if current_network_namespace()? != provider_namespace
        || retirement.checkpoint_digest.as_ref() != Some(&checkpoint)
        || retirement.candidate_exit_code != Some(0)
    {
        return Err("MCSEALED-PRIVATE-RELEASE: native retirement differs".into());
    }
    case.revalidate()?;
    let host_network_preservation = host_before
        .map(|before| {
            super::private_release_host_state::HostNetworkPreservationV1::complete(
                before,
                super::private_release_host_state::HostNetworkStateV1::capture()?,
            )
        })
        .transpose()?;
    let agent_path_preservation = agent_path_before
        .map(|before| {
            super::private_release_ancestor::AgentPathPreservationV1::complete(
                before,
                case.protected_agent_path_snapshot()?,
            )
        })
        .transpose()?;
    Ok(CandidateNativeObservationV1 {
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
        host_network_preservation,
        agent_path_preservation,
        unix_absence,
    })
}
