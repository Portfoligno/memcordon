//! Physical dual-attempt owner. This returns only a native diagnostic until
//! protected raw, detached and independent CI joins are implemented.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use memcordon_core::DiagnosticSha256;

use super::namespace::CallerMountContext;
use super::network_profile::current_network_namespace;
use super::private_lifecycle::{
    PrivateExecObservation, PrivateMonitorOutcome, PrivateObservedTarget,
};
use super::private_release_dual_attempt::{self, DualAttemptRoleV1, DualCandidateJournalPairV1};
use super::private_release_run::ReleaseCandidateRunAuthorityV1;
use crate::request::{FileIdentity, NamespaceIdentity, SwapLimit};

pub(crate) struct DualCandidateNativeObservationV1 {
    pub(crate) first: super::private_release_attempt::ReleaseCandidateRetirementObservationV1,
    pub(crate) second: super::private_release_attempt::ReleaseCandidateRetirementObservationV1,
    pub(crate) first_namespace_inode: u64,
    pub(crate) second_namespace_inode: u64,
    pub(crate) port: u16,
    pub(crate) first_listener_inode: u64,
    pub(crate) second_listener_inode: u64,
    pub(crate) gate_sha256: DiagnosticSha256,
    pub(crate) first_frame: [u8; 42],
    pub(crate) second_frame: [u8; 42],
}

struct PreparedTargetV1 {
    observed: PrivateObservedTarget,
    stdin_writer: File,
    stdout_reader: OwnedFd,
    stderr_reader: OwnedFd,
}

/// Both targets complete the V4 gated release lifecycle but remain alive on
/// the same TCP port until their distinct host-observed namespace identities
/// are read in one overlapping window. Any failure still attempts retirement
/// of both independently journaled owners.
pub(crate) fn execute_dual_candidate_case(
    case: &ReleaseCandidateRunAuthorityV1,
) -> Result<DualCandidateNativeObservationV1, String> {
    if case.selector() != private_release_dual_attempt::SELECTOR {
        return Err("MCSEALED-PRIVATE-RELEASE: dual physical selector differs".into());
    }
    case.revalidate()?;
    let provider_namespace = current_network_namespace()?;
    let DualCandidateJournalPairV1 {
        first_key,
        mut first,
        second_key,
        mut second,
    } = case.begin_dual_native_owners()?;
    let mut first_readback = None;
    let mut second_readback = None;
    let mut gate_readback = None;
    let mut first_retired_early = None;
    let mut first_slot = Some(first);
    let run = (|| -> Result<(), String> {
        let mut first = first_slot.as_mut().ok_or("dual first owner absent")?;
        let first_target = prepare_target(case, &mut first, &first_key, provider_namespace)?;
        let first_inode = first_target.observed.network_namespace_inode();
        let first_checkpoint = first.commit_dual_candidate_and_release(
            first_target.observed,
            case,
            DualAttemptRoleV1::First,
        )?;
        require_exec(&mut first, case)?;
        super::private_release_live_gate::wait_baseline_for_candidate(
            case,
            &mut first,
            first_target.stdout_reader.as_fd(),
            first_target.stdin_writer.as_fd(),
            Some(0),
        )?;
        let first_live = first.observe_live_terminal_join_target()?;
        let first_frame =
            read_fixed_frame::<42>(first_target.stdout_reader.as_fd(), case.deadline(), || {
                first.tick_relay_for_unix_observer()
            })?;
        let first_listener_inode =
            require_live_frame(case, &first, &first_live, first_inode, &first_frame)?;

        let second_target = prepare_target(case, &mut second, &second_key, provider_namespace)?;
        let second_inode = second_target.observed.network_namespace_inode();
        let second_checkpoint = second.commit_dual_candidate_and_release(
            second_target.observed,
            case,
            DualAttemptRoleV1::Second,
        )?;
        require_exec(&mut second, case)?;
        super::private_release_live_gate::wait_baseline_for_candidate(
            case,
            &mut second,
            second_target.stdout_reader.as_fd(),
            second_target.stdin_writer.as_fd(),
            Some(1),
        )?;
        let second_live = second.observe_live_terminal_join_target()?;
        let second_frame =
            read_fixed_frame::<42>(second_target.stdout_reader.as_fd(), case.deadline(), || {
                second.tick_relay_for_unix_observer()
            })?;
        let second_listener_inode =
            require_live_frame(case, &second, &second_live, second_inode, &second_frame)?;
        if first_inode == second_inode
            || first_inode == provider_namespace.inode
            || second_inode == provider_namespace.inode
            || first_live == second_live
        {
            return Err("MCSEALED-PRIVATE-RELEASE: dual live namespaces differ".into());
        }
        // Re-observe the first pidfd and host nsfs inode only after the second
        // target has reached its live frame. This is the overlapping window.
        if require_live_frame(case, &first, &first_live, first_inode, &first_frame)?
            != first_listener_inode
            || require_live_frame(case, &second, &second_live, second_inode, &second_frame)?
                != second_listener_inode
        {
            return Err("MCSEALED-PRIVATE-RELEASE: dual listener changed".into());
        }
        let gate_sha256 = case.persist_dual_live_gate(
            &super::private_release_dual_gate::DualLiveHostObservationV1 {
                target: first_live.clone(),
                network_namespace_inode: first_inode,
                listener_socket_inode: first_listener_inode,
            },
            &super::private_release_dual_gate::DualLiveHostObservationV1 {
                target: second_live.clone(),
                network_namespace_inode: second_inode,
                listener_socket_inode: second_listener_inode,
            },
        )?;
        let ack_deadline = (Instant::now() + Duration::from_secs(15)).min(case.deadline());
        case.wait_dual_live_ack(&gate_sha256, ack_deadline)?;
        if require_live_frame(case, &first, &first_live, first_inode, &first_frame)?
            != first_listener_inode
            || require_live_frame(case, &second, &second_live, second_inode, &second_frame)?
                != second_listener_inode
        {
            return Err("MCSEALED-PRIVATE-RELEASE: dual live ACK state changed".into());
        }
        case.revalidate()?;
        let mut first_writer = first_target.stdin_writer;
        let mut second_writer = second_target.stdin_writer;
        first_writer
            .write_all(&private_release_dual_attempt::target_ack())
            .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: dual target ACK: {error}"))?;
        if first.monitor_release_candidate(case)? != PrivateMonitorOutcome::Completed {
            return Err("MCSEALED-PRIVATE-RELEASE: dual native monitor differs".into());
        }
        let retired = first_slot
            .take()
            .ok_or("dual first retirement owner absent")?
            .retire_release_candidate(Instant::now() + Duration::from_secs(30))?;
        let retired_ns = super::clock::monotonic_nanos()?;
        first_retired_early = Some(retired);
        second.require_live_target_identity(&second_live)?;
        second_writer
            .write_all(&[2])
            .map_err(|error| error.to_string())?;
        let response =
            read_fixed_frame::<82>(second_target.stdout_reader.as_fd(), case.deadline(), || {
                second.tick_relay_for_unix_observer()
            })?;
        let response_ns = super::clock::monotonic_nanos()?;
        let mut next = sha2::Sha256::new();
        use sha2::Digest;
        next.update(b"memcordon/private-dual-second-exchange/v1\0");
        next.update(case.challenge_bytes());
        let next: [u8; 32] = next.finalize().into();
        if response
            != private_release_dual_attempt::post_retirement_frame(
                &case.challenge_bytes(),
                &next,
                private_release_dual_attempt::fixed_port(&case.challenge_bytes()),
                second_inode,
            )
            || response_ns <= retired_ns
        {
            return Err("dual genuine second post-retirement response differs".into());
        }
        let first_retired = first_retired_early
            .as_ref()
            .expect("actual retirement retained");
        let record = serde_json::to_vec(&serde_json::json!({"schema_version":1,"protocol":"candidate-dual-second-exchange-v1","first_attempt_id":first_retired.attempt_id,"first_terminal_sha256":memcordon_core::workload_codec::hash_bytes(&first_retired.terminal_bytes),"first_retirement_monotonic_ns":retired_ns,"second_response_monotonic_ns":response_ns,"second_target":second_live,"frame":response.to_vec()})).map_err(|error|error.to_string())?;
        super::private_release_child_gate::persist_atomic(
            case.protected_case_directory()?,
            "dual-second-post-retirement.pending",
            "dual-second-post-retirement.json",
            &record,
        )?;
        super::private_release_live_gate::wait_for_sample_with_role(
            case.protected_case_directory()?,
            case.selector(),
            case.protected_result_key()?,
            &case.challenge_bytes(),
            &second_live,
            true,
            &response,
            case.deadline(),
            || second.require_live_target_identity(&second_live),
            Some(1),
        )?;
        second_writer
            .write_all(&private_release_dual_attempt::target_ack())
            .map_err(|error| error.to_string())?;
        if second.monitor_release_candidate(case)? != PrivateMonitorOutcome::Completed {
            return Err("dual second native monitor differs".into());
        }
        let first_stdout =
            super::private_probe_execution::read_bounded_pipe(first_target.stdout_reader, 1)?;
        let second_stdout =
            super::private_probe_execution::read_bounded_pipe(second_target.stdout_reader, 1)?;
        let first_stderr =
            super::private_probe_execution::read_bounded_pipe(first_target.stderr_reader, 1)?;
        let second_stderr =
            super::private_probe_execution::read_bounded_pipe(second_target.stderr_reader, 1)?;
        if !first_stdout.is_empty()
            || !second_stdout.is_empty()
            || !first_stderr.is_empty()
            || !second_stderr.is_empty()
        {
            return Err("MCSEALED-PRIVATE-RELEASE: dual target trailing output differs".into());
        }
        first_readback = Some((
            first_checkpoint,
            first_inode,
            first_listener_inode,
            first_frame,
        ));
        second_readback = Some((
            second_checkpoint,
            second_inode,
            second_listener_inode,
            second_frame,
        ));
        gate_readback = Some(gate_sha256);
        Ok(())
    })();
    let retire_deadline = Instant::now() + Duration::from_secs(30);
    let first_retired = match first_retired_early {
        Some(retired) => Ok(retired),
        None => first_slot
            .take()
            .ok_or_else(|| "dual first retirement failed".to_owned())
            .and_then(|owner| owner.retire_release_candidate(retire_deadline)),
    };
    let second_retired = second.retire_release_candidate(retire_deadline);
    run?;
    let first_retired = first_retired?;
    let second_retired = second_retired?;
    let (first_checkpoint, first_inode, first_listener_inode, first_frame) =
        first_readback.ok_or("MCSEALED-PRIVATE-RELEASE: first dual readback absent")?;
    let (second_checkpoint, second_inode, second_listener_inode, second_frame) =
        second_readback.ok_or("MCSEALED-PRIVATE-RELEASE: second dual readback absent")?;
    let gate_sha256 = gate_readback.ok_or("MCSEALED-PRIVATE-RELEASE: dual gate absent")?;
    if first_retired.checkpoint_digest.as_ref() != Some(&first_checkpoint)
        || second_retired.checkpoint_digest.as_ref() != Some(&second_checkpoint)
        || first_retired.candidate_exit_code != Some(0)
        || second_retired.candidate_exit_code != Some(0)
        || current_network_namespace()? != provider_namespace
    {
        return Err("MCSEALED-PRIVATE-RELEASE: dual retirement differs".into());
    }
    case.revalidate()?;
    Ok(DualCandidateNativeObservationV1 {
        first: first_retired,
        second: second_retired,
        first_namespace_inode: first_inode,
        second_namespace_inode: second_inode,
        port: private_release_dual_attempt::fixed_port(&case.challenge_bytes()),
        first_listener_inode,
        second_listener_inode,
        gate_sha256,
        first_frame,
        second_frame,
    })
}

fn prepare_target(
    case: &ReleaseCandidateRunAuthorityV1,
    owner: &mut super::private_lifecycle::PrivateAttemptOwner<
        super::private_release_attempt::DurableReleaseCandidateAttemptV1,
    >,
    subkey: &DiagnosticSha256,
    provider_namespace: NamespaceIdentity,
) -> Result<PreparedTargetV1, String> {
    let prelaunch = case.prepare_native_prelaunch()?;
    let (uid, gid) = case.target_ids()?;
    let identity = super::execution_identity::ResolvedTargetIdentity::for_probe_account(uid, gid)?;
    let mount = File::open("/proc/self/ns/mnt").map_err(|error| error.to_string())?;
    let root = File::open("/").map_err(|error| error.to_string())?;
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
    let (stdin_read, stdin_write) = super::private_probe_execution::nonblocking_pipe()?;
    let (stdout_read, stdout_write) = super::private_probe_execution::nonblocking_pipe()?;
    let (stderr_read, stderr_write) = super::private_probe_execution::nonblocking_pipe()?;
    let mut stdin_writer = File::from(stdin_write);
    stdin_writer
        .write_all(&case.challenge_bytes())
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: dual challenge pipe: {error}"))?;
    let startup_deadline = (Instant::now() + Duration::from_secs(5)).min(case.deadline());
    owner.create_boundary(None, SwapLimit::Host)?;
    owner.spawn_namespace(
        prelaunch,
        mount_context,
        case.work_directory()?.into(),
        provider_namespace,
        provider_namespace,
    )?;
    let worker_pidfd = super::private_execution::pidfd_for_self()?;
    owner.start_guardian(
        super::private_release_attempt::candidate_attempt_bytes(subkey),
        case.coordinator_pidfd(),
        worker_pidfd.as_fd(),
        startup_deadline,
    )?;
    let observed = owner.observe_gated_target(
        provider_namespace,
        provider_namespace,
        &identity,
        case.native_abi()?,
        *case.filter_digest().bytes(),
        startup_deadline,
    )?;
    owner.prepare_relay([stdin_read, stdout_write, stderr_write])?;
    let role = if *subkey
        == super::private_release_dual_attempt::subattempt_key(
            case.protected_result_key()?,
            super::private_release_dual_attempt::DualAttemptRoleV1::First,
        ) {
        0
    } else {
        1
    };
    super::private_release_live_gate::wait_for_sample_with_role(
        case.protected_case_directory()?,
        case.selector(),
        case.protected_result_key()?,
        &case.challenge_bytes(),
        observed.target_identity(),
        false,
        &[],
        case.deadline(),
        || owner.require_live_target_identity(observed.target_identity()),
        Some(role),
    )?;
    Ok(PreparedTargetV1 {
        observed,
        stdin_writer,
        stdout_reader: stdout_read,
        stderr_reader: stderr_read,
    })
}

fn require_exec(
    owner: &mut super::private_lifecycle::PrivateAttemptOwner<
        super::private_release_attempt::DurableReleaseCandidateAttemptV1,
    >,
    case: &ReleaseCandidateRunAuthorityV1,
) -> Result<(), String> {
    if !matches!(
        owner.observe_exec(case.deadline())?,
        PrivateExecObservation::ArmedAndControlClosed
    ) {
        return Err("MCSEALED-PRIVATE-RELEASE: dual target exec differs".into());
    }
    Ok(())
}

fn require_live_frame(
    case: &ReleaseCandidateRunAuthorityV1,
    owner: &super::private_lifecycle::PrivateAttemptOwner<
        super::private_release_attempt::DurableReleaseCandidateAttemptV1,
    >,
    target: &super::private_attempt::ProcessIdentityV4,
    inode: u64,
    frame: &[u8; 42],
) -> Result<u64, String> {
    if owner.observe_live_terminal_join_target()? != *target
        || *frame
            != private_release_dual_attempt::ready_frame(
                &case.challenge_bytes(),
                private_release_dual_attempt::fixed_port(&case.challenge_bytes()),
                inode,
            )
    {
        return Err("MCSEALED-PRIVATE-RELEASE: dual target frame differs".into());
    }
    let path = PathBuf::from("/proc")
        .join(target.pid.to_string())
        .join("ns/net");
    let observed = std::fs::metadata(path).map_err(|error| error.to_string())?;
    if observed.ino() != inode
        || observed.dev() == 0
        || owner.observe_live_terminal_join_target()? != *target
    {
        return Err("MCSEALED-PRIVATE-RELEASE: dual host namespace differs".into());
    }
    let listener_inode = require_live_listener(
        target.pid,
        private_release_dual_attempt::fixed_port(&case.challenge_bytes()),
    )?;
    if owner.observe_live_terminal_join_target()? != *target {
        return Err("MCSEALED-PRIVATE-RELEASE: dual listener target changed".into());
    }
    Ok(listener_inode)
}

fn require_live_listener(pid: u32, port: u16) -> Result<u64, String> {
    let root = PathBuf::from("/proc").join(pid.to_string());
    let tcp = File::open(root.join("net/tcp"))
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: dual TCP table: {error}"))?;
    let mut bytes = Vec::new();
    tcp.take(65_537)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > 65_536 {
        return Err("MCSEALED-PRIVATE-RELEASE: dual TCP table exceeds bound".into());
    }
    let table = std::str::from_utf8(&bytes)
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE: dual TCP table encoding differs")?;
    let listener_inode = parse_loopback_listener_inode(table, port)?;
    let expected = format!("socket:[{listener_inode}]");
    let mut matched = false;
    for entry in std::fs::read_dir(root.join("fd")).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let link = std::fs::read_link(entry.path()).map_err(|error| error.to_string())?;
        if link.to_str() == Some(expected.as_str()) {
            matched = true;
        }
    }
    if !matched {
        return Err("MCSEALED-PRIVATE-RELEASE: dual target listener fd absent".into());
    }
    Ok(listener_inode)
}

pub(crate) fn parse_loopback_listener_inode(table: &str, port: u16) -> Result<u64, String> {
    let expected_port = format!("{port:04X}");
    let mut found = None;
    for line in table.lines().skip(1) {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        let Some(local) = fields.get(1) else {
            return Err("MCSEALED-PRIVATE-RELEASE: dual TCP row truncated".into());
        };
        let Some(state) = fields.get(3) else {
            return Err("MCSEALED-PRIVATE-RELEASE: dual TCP state absent".into());
        };
        let Some(inode_text) = fields.get(9) else {
            return Err("MCSEALED-PRIVATE-RELEASE: dual TCP inode absent".into());
        };
        let Some((address, row_port)) = local.split_once(':') else {
            return Err("MCSEALED-PRIVATE-RELEASE: dual TCP local address differs".into());
        };
        if address == "0100007F" && row_port == expected_port && *state == "0A" {
            let inode = inode_text
                .parse::<u64>()
                .map_err(|_| "MCSEALED-PRIVATE-RELEASE: dual TCP inode differs")?;
            if inode == 0 || found.replace(inode).is_some() {
                return Err("MCSEALED-PRIVATE-RELEASE: dual TCP listener ambiguous".into());
            }
        }
    }
    found.ok_or_else(|| "MCSEALED-PRIVATE-RELEASE: dual TCP listener absent".into())
}

fn read_fixed_frame<const N: usize>(
    fd: BorrowedFd<'_>,
    deadline: Instant,
    mut tick: impl FnMut() -> Result<(), String>,
) -> Result<[u8; N], String> {
    let mut frame = [0_u8; N];
    let mut offset = 0;
    while offset < frame.len() {
        tick()?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or("MCSEALED-PRIVATE-RELEASE: dual frame deadline expired")?;
        let timeout = i32::try_from(remaining.as_millis().min(10))
            .map_err(|_| "MCSEALED-PRIVATE-RELEASE: dual frame deadline differs")?;
        let mut poll = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll borrows only the fixed target stdout descriptor.
        let ready = unsafe { libc::poll(&raw mut poll, 1, timeout) };
        if ready == 0 {
            continue;
        }
        if ready != 1
            || poll.revents & libc::POLLIN == 0
            || poll.revents & (libc::POLLERR | libc::POLLNVAL) != 0
        {
            return Err("MCSEALED-PRIVATE-RELEASE: dual frame unavailable".into());
        }
        // SAFETY: read writes only the unfilled suffix of the fixed frame.
        let count = unsafe {
            libc::read(
                fd.as_raw_fd(),
                frame[offset..].as_mut_ptr().cast(),
                frame.len() - offset,
            )
        };
        if count <= 0 {
            return Err("MCSEALED-PRIVATE-RELEASE: dual frame truncated".into());
        }
        offset += usize::try_from(count)
            .map_err(|_| "MCSEALED-PRIVATE-RELEASE: dual frame size differs")?;
    }
    Ok(frame)
}
