//! Original-source causal joins for public faults and concurrent attempts.
//! The provider's phase decoder supplies durable knowledge, not kernel facts.
use crate::private_candidate_replay::ReplayTaskV1;
use crate::private_kernel_observer::{KernelTaskIdentityV1, VerifiedKernelIntervalV1};
use crate::private_kernel_replay::{CaptureStageV2, KernelEventRecordV2};
use crate::private_process_clock::VerifiedProcClockCalibrationV1;
use crate::private_public_dispatch::{
    ObservedInstalledPublicCaseV3, StructuralProviderFrameReadbackV2,
};
use crate::private_public_live::HeldPublicTargetSamplesV1;
use crate::{CiError, Result};
use memcordon_core::private_release_case_v1::{
    PrivateReleaseAllocatedOutcomeV1 as Outcome, PrivateReleaseObservationV1 as Observation,
};
use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};
use serde::Deserialize;
use std::collections::BTreeSet;

fn fail<T>(message: &str) -> Result<T> {
    Err(CiError::Message(message.into()))
}
fn sample_leaf<'a>(observed: &'a ObservedInstalledPublicCaseV3, name: &str) -> Result<&'a [u8]> {
    observed
        .live_samples
        .get(name)
        .map(Vec::as_slice)
        .ok_or_else(|| CiError::Message("public causal original sample absent".into()))
}
fn same(task: &ReplayTaskV1, event: &KernelEventRecordV2) -> bool {
    (
        task.tid,
        task.tgid,
        task.start_boottime_ns,
        task.cgroup_inode,
        task.time_ns_inode,
    ) == (
        event.task.tid,
        event.task.tgid,
        event.task.start_boottime_ns,
        event.task.cgroup_inode,
        event.task.time_ns_inode,
    )
}
pub(crate) fn task(
    events: &[KernelEventRecordV2],
    clock: &VerifiedProcClockCalibrationV1,
    pid: u32,
    ticks: u64,
) -> Result<ReplayTaskV1> {
    let identities = events
        .iter()
        .filter(|e| {
            e.task.tid == pid
                && clock.matches(
                    KernelTaskIdentityV1 {
                        pid: e.task.tid,
                        start_time: e.task.start_boottime_ns,
                        cgroup_inode: e.task.cgroup_inode,
                        time_ns_inode: e.task.time_ns_inode,
                    },
                    ticks,
                )
        })
        .map(|e| {
            (
                e.task.tid,
                e.task.tgid,
                e.task.start_boottime_ns,
                e.task.cgroup_inode,
                e.task.time_ns_inode,
            )
        })
        .collect::<BTreeSet<_>>();
    let identities = identities.into_iter().collect::<Vec<_>>();
    let [(tid, tgid, start, cgroup, time_ns)] = identities.as_slice() else {
        return fail("public causal exact original-clock task absent or ambiguous");
    };
    Ok(ReplayTaskV1 {
        tid: *tid,
        tgid: *tgid,
        start_boottime_ns: *start,
        cgroup_inode: *cgroup,
        time_ns_inode: *time_ns,
    })
}
fn paired<'a>(
    events: &'a [KernelEventRecordV2],
    ret: &KernelEventRecordV2,
    entry_kind: u32,
) -> Result<&'a KernelEventRecordV2> {
    let entries = events
        .iter()
        .filter(|e| {
            e.kind == entry_kind
                && e.task == ret.task
                && e.syscall_occurrence == ret.syscall_occurrence
                && e.syscall_arch == ret.syscall_arch
                && e.syscall_nr == ret.syscall_nr
                && e.args == ret.args
                && e.sequence < ret.sequence
        })
        .collect::<Vec<_>>();
    match entries.as_slice() {
        [entry] => Ok(*entry),
        _ => fail("public causal paired entry/return absent or ambiguous"),
    }
}
fn retired(events: &[KernelEventRecordV2], task: &ReplayTaskV1) -> Result<(u64, u64)> {
    let exits = events
        .iter()
        .filter(|e| e.kind == 8 && same(task, e))
        .collect::<Vec<_>>();
    let [exit] = exits.as_slice() else {
        return fail("public causal unique target exit absent");
    };
    let reaps = events
        .iter()
        .filter(|e| {
            e.kind == 9
                && e.other_tid == task.tid
                && u64::try_from(e.syscall_result).ok() == Some(task.start_boottime_ns)
                && e.sequence > exit.sequence
        })
        .collect::<Vec<_>>();
    let [reap] = reaps.as_slice() else {
        return fail("public causal exact target reap absent");
    };
    Ok((exit.monotonic_ns, reap.monotonic_ns))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReopenV1 {
    schema_version: u8,
    file_dev: u64,
    file_inode: u64,
    directory_dev: u64,
    directory_inode: u64,
    bytes_sha256: DiagnosticSha256,
    observed_monotonic_ns: u64,
}

/// Exact actual durable fsync/reopen/release chain; a helper copy cannot be
/// substituted for the reopened native attempt file's dev/inode.
fn checkpoint(
    events: &[KernelEventRecordV2],
    target: &ReplayTaskV1,
    original: &[u8],
    metadata: &[u8],
    uncertain: bool,
) -> Result<()> {
    let read: ReopenV1 = crate::private_observer_session::strict_json(metadata, 4096)?;
    if read.schema_version != 1
        || read.bytes_sha256 != hash_bytes(original)
        || [
            read.file_dev,
            read.file_inode,
            read.directory_dev,
            read.directory_inode,
            read.observed_monotonic_ns,
        ]
        .contains(&0)
    {
        return fail("public causal actual durable reopen object differs");
    }
    let syncs = events
        .iter()
        .filter(|e| {
            e.kind == 5
                && matches!(
                    (e.syscall_arch, e.syscall_nr),
                    (0xc000003e, 74) | (0xc00000b7, 82)
                )
                && e.syscall_result == 0
                && e.monotonic_ns < read.observed_monotonic_ns
                && paired(events, e, 11).is_ok_and(|entry| {
                    entry.image_dev == read.file_dev && entry.image_inode == read.file_inode
                })
        })
        .collect::<Vec<_>>();
    let [sync] = syncs.as_slice() else {
        return fail("public causal durable file fsync absent/ambiguous");
    };
    let directories = events
        .iter()
        .filter(|e| {
            e.kind == 5
                && e.task == sync.task
                && e.syscall_nr == sync.syscall_nr
                && e.syscall_result == 0
                && e.sequence > sync.sequence
                && e.monotonic_ns < read.observed_monotonic_ns
                && paired(events, e, 11).is_ok_and(|entry| {
                    entry.image_dev == read.directory_dev
                        && entry.image_inode == read.directory_inode
                })
        })
        .collect::<Vec<_>>();
    if directories.len() != 1 {
        return fail("public causal durable parent directory fsync absent/ambiguous");
    }
    if uncertain {
        let lost = events
            .iter()
            .filter(|e| {
                e.kind == 5
                    && e.task == sync.task
                    && matches!(
                        (e.syscall_arch, e.syscall_nr),
                        (0xc000003e, 44) | (0xc00000b7, 206)
                    )
                    && e.args[2] == 1
                    && e.args[3] == 0x4000
                    && e.syscall_result == -32
                    && e.monotonic_ns > read.observed_monotonic_ns
            })
            .collect::<Vec<_>>();
        let [lost] = lost.as_slice() else {
            return fail("public authorization actual EPIPE occurrence absent/ambiguous");
        };
        paired(events, lost, 11)?;
        let eof = events
            .iter()
            .filter(|e| {
                e.kind == 5
                    && same(target, e)
                    && matches!(
                        (e.syscall_arch, e.syscall_nr),
                        (0xc000003e, 45) | (0xc00000b7, 207)
                    )
                    && e.args[0] == 3
                    && e.args[2] == 2
                    && e.args[3] == 0
                    && e.syscall_result == 0
                    && e.sequence > lost.sequence
            })
            .collect::<Vec<_>>();
        let [eof] = eof.as_slice() else {
            return fail("public authorization actual pre-exec gate EOF absent/ambiguous");
        };
        paired(events, eof, 4)?;
        if events.iter().any(|e| {
            e.kind == 6 && same(target, e)
                || e.kind == 5
                    && e.task == lost.task
                    && matches!(
                        (e.syscall_arch, e.syscall_nr),
                        (0xc000003e, 1) | (0xc00000b7, 64)
                    )
                    && e.args[0] == lost.args[0]
                    && e.args[2] == 1
                    && e.syscall_result == 1
                    && e.sequence > sync.sequence
        }) {
            return fail("public authorization has observed GO/exec");
        }
    } else {
        let execs = events
            .iter()
            .filter(|e| e.kind == 6 && same(target, e))
            .collect::<Vec<_>>();
        let [exec] = execs.as_slice() else {
            return fail("public causal unique actual target exec absent");
        };
        let go = events
            .iter()
            .filter(|e| {
                e.kind == 5
                    && e.task == sync.task
                    && matches!(
                        (e.syscall_arch, e.syscall_nr),
                        (0xc000003e, 1) | (0xc00000b7, 64)
                    )
                    && e.args[2] == 1
                    && e.syscall_result == 1
                    && e.monotonic_ns > read.observed_monotonic_ns
                    && e.sequence < exec.sequence
            })
            .collect::<Vec<_>>();
        let [go] = go.as_slice() else {
            return fail("public causal actual post-reopen GO write absent/ambiguous");
        };
        paired(events, go, 11)?;
        let received = events
            .iter()
            .filter(|e| {
                e.kind == 5
                    && same(target, e)
                    && matches!(
                        (e.syscall_arch, e.syscall_nr),
                        (0xc000003e, 45) | (0xc00000b7, 207)
                    )
                    && e.args[0] == 3
                    && e.args[2] == 2
                    && e.args[3] == 0
                    && e.syscall_result == 1
                    && e.sequence > go.sequence
                    && e.sequence < exec.sequence
            })
            .collect::<Vec<_>>();
        let [received] = received.as_slice() else {
            return fail("public causal target actual one-byte gate receive absent/ambiguous");
        };
        paired(events, received, 4)?;
    }
    Ok(())
}

/// Bounded diagnostic parser/predicate, never an observer or P capability.
/// The completed adapter supplies these bytes through authenticated custody.
pub fn validate_public_checkpoint_capture(
    bytes: &[u8],
    key: &DiagnosticSha256,
    target: &ReplayTaskV1,
    original: &[u8],
    metadata: &[u8],
    uncertain: bool,
) -> Result<()> {
    let parsed = crate::private_kernel_replay::parse_capture_v2_with_budget(
        bytes,
        key,
        CaptureStageV2::FinalPublic,
    )?;
    checkpoint(parsed.events(), target, original, metadata, uncertain)
}

fn decode_sample(
    observed: &ObservedInstalledPublicCaseV3,
    name: &str,
    image_leaf: &impl Fn(&str) -> Result<Vec<u8>>,
) -> Result<HeldPublicTargetSamplesV1> {
    crate::private_source_carrier::decode_held_source(sample_leaf(observed, name)?, image_leaf)
}
fn check_held(
    sample: &HeldPublicTargetSamplesV1,
    task: &ReplayTaskV1,
    events: &[KernelEventRecordV2],
    end: u64,
) -> Result<()> {
    if sample.pid != task.tid
        || sample.begin_monotonic_ns == 0
        || sample.begin_monotonic_ns > sample.end_monotonic_ns
        || sample.end_monotonic_ns >= end
        || events
            .iter()
            .any(|e| e.kind == 8 && same(task, e) && e.monotonic_ns <= sample.end_monotonic_ns)
    {
        return fail("public causal held sample target/time differs");
    }
    Ok(())
}
fn protected_sample(
    sample: &HeldPublicTargetSamplesV1,
    identity: &crate::private_public_dispatch::ProviderTargetIdentityV1,
) -> Result<()> {
    if sample.schema_version != 1
        || sample.pid != identity.target.pid
        || sample.start_time_ticks != identity.target.start_time
        || sample.executable_sha256 != identity.entrypoint_sha256
        || sample.executable_device != identity.entrypoint_device
        || sample.executable_inode != identity.entrypoint_inode
        || !sample.tasks.iter().any(|task| {
            task.tid == sample.pid
                && task.namespace_inodes.get("net") == Some(&identity.network_namespace_inode)
        })
    {
        return fail(
            "public causal held original executable/start/namespace differs from protected target",
        );
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TcpV2 {
    schema_version: u8,
    network_namespace_inode: u64,
    listener_port: u16,
    client_port: u16,
    challenge_sha256: DiagnosticSha256,
    response_sha256: DiagnosticSha256,
    observed_response_bytes: [u8; 32],
}
fn tcp_frames(
    bytes: &[u8],
    challenge: &[u8; 32],
    port: u16,
    netns: u64,
    count: usize,
) -> Result<()> {
    let mut bytes = bytes;
    for _ in 0..count {
        let raw = bytes
            .strip_prefix(b"MCPH\x01\0\0\0")
            .ok_or_else(|| CiError::Message("public dual actual response frame absent".into()))?;
        let width = std::mem::size_of::<u32>();
        let len = u32::from_le_bytes(
            raw.get(..width)
                .ok_or_else(|| CiError::Message("public dual frame length absent".into()))?
                .try_into()
                .expect("bounded u32"),
        ) as usize;
        if len == 0 || len > 64 * 1024 {
            return fail("public dual response frame budget differs");
        }
        let payload = raw
            .get(width..width + len)
            .ok_or_else(|| CiError::Message("public dual response frame truncated".into()))?;
        let response: TcpV2 = crate::private_observer_session::strict_json(payload, 64 * 1024)?;
        let expected =
            memcordon_core::private_release_case_v1::public_fixture_expected_response_v1(
                "private_tcp::native_tcp_bind_listen_connect",
                challenge,
                port,
            )
            .map_err(|e| CiError::Message(e.into()))?;
        if response.schema_version != 2
            || response.network_namespace_inode != netns
            || response.listener_port != port
            || response.client_port == 0
            || response.client_port == port
            || response.challenge_sha256 != hash_bytes(challenge)
            || response.response_sha256.bytes() != &response.observed_response_bytes
            || response.observed_response_bytes != expected
        {
            return fail("public dual actual read bytes/namespace/recipe differ");
        }
        bytes = &raw[width + len..];
    }
    if !bytes.is_empty() {
        return fail("public dual unexpected response frame inventory");
    }
    Ok(())
}

/// Shared live/detached adapter. A successful source join is still not a P
/// capability: completed replay also requires protected recipe/host/admission,
/// retirement, and all other closed selector families.
#[cfg(unix)]
pub(crate) fn compose_public_fault_dual_sources(
    selector: &str,
    provider: &StructuralProviderFrameReadbackV2,
    observed: &ObservedInstalledPublicCaseV3,
    interval: &VerifiedKernelIntervalV1,
    clock: &VerifiedProcClockCalibrationV1,
    challenge: &[u8; 32],
    port: u16,
    target_triple: &str,
    image_leaf: impl Fn(&str) -> Result<Vec<u8>>,
) -> Result<Observation> {
    if !matches!(
        selector,
        "private_tcp::authorization_uncertainty_retired"
            | "private_tcp::frontend_loss_retired"
            | "private_tcp::guardian_loss_retired"
            | "private_tcp::dual_attempt_namespace_isolation"
    ) {
        return fail("public causal source selector is outside reviewed fault/dual inventory");
    }
    let parsed = crate::private_kernel_replay::parse_capture_v2_with_budget(
        interval.capture_bytes()?,
        &provider.result_key,
        CaptureStageV2::FinalPublic,
    )?;
    let events = parsed.events();
    if parsed.digest() != interval.trace_sha256() || provider.phase != "launch-exchanges-complete" {
        return fail("public causal exact raw capture/provider phase differs");
    }
    let dual = selector == "private_tcp::dual_attempt_namespace_isolation";
    if provider.attempts.len() != if dual { 2 } else { 1 } {
        return fail("public causal exact attempt inventory differs");
    }
    let mut targets = Vec::new();
    let mut preexec = BTreeSet::new();
    let mut tasks = Vec::new();
    for (ordinal, attempt) in provider.attempts.iter().enumerate() {
        let identity = attempt
            .target_identity
            .as_ref()
            .ok_or_else(|| CiError::Message("public causal protected target absent".into()))?;
        let selected = task(
            events,
            clock,
            identity.target.pid,
            identity.target.start_time,
        )?;
        let uncertain = attempt
            .fault
            .as_ref()
            .is_some_and(|fault| fault.outcome == Outcome::AuthorizationUncertain);
        if uncertain {
            preexec.insert(attempt.attempt_id.clone());
        }
        let phase = if ordinal == 0 {
            "release-intent"
        } else {
            "dual-second/release-intent"
        };
        let original = sample_leaf(
            observed,
            &std::path::Path::new(phase)
                .join("release-intent-v4.bin")
                .to_string_lossy(),
        )?;
        let metadata = sample_leaf(
            observed,
            &std::path::Path::new(phase)
                .join("release-intent-v4.bin.metadata.json")
                .to_string_lossy(),
        )?;
        if attempt
            .phase_leaves
            .get("release-intent-v4.bin")
            .map(Vec::as_slice)
            != Some(original)
        {
            return fail("public causal original durable source differs from provider inventory");
        }
        checkpoint(events, &selected, original, metadata, uncertain)?;
        retired(events, &selected)?;
        targets.push(
            crate::private_public_kernel_join::ProtectedPublicTargetExpectationV1 {
                attempt_id: attempt.attempt_id.clone(),
                pid: identity.target.pid,
                start_ticks: identity.target.start_time,
                network_namespace_inode: identity.network_namespace_inode,
                entrypoint_sha256: identity.entrypoint_sha256.clone(),
                entrypoint_device: identity.entrypoint_device,
                entrypoint_inode: identity.entrypoint_inode,
                entrypoint_path: identity.entrypoint_path.clone(),
            },
        );
        tasks.push(selected);
    }
    let joined = crate::private_public_kernel_join::join_public_case_kernel_targets_v2(
        interval,
        clock,
        &provider.result_key,
        &targets,
        &preexec,
    )?;
    if dual {
        let first = decode_sample(
            observed,
            "dual-first-overlap/target-live-sample-v1.json",
            &image_leaf,
        )?;
        let second = decode_sample(
            observed,
            "dual-second-overlap/target-live-sample-v1.json",
            &image_leaf,
        )?;
        let post = decode_sample(
            observed,
            "dual-second-after-first-retirement/target-live-sample-v1.json",
            &image_leaf,
        )?;
        protected_sample(
            &first,
            provider.attempts[0]
                .target_identity
                .as_ref()
                .expect("checked"),
        )?;
        protected_sample(
            &second,
            provider.attempts[1]
                .target_identity
                .as_ref()
                .expect("checked"),
        )?;
        protected_sample(
            &post,
            provider.attempts[1]
                .target_identity
                .as_ref()
                .expect("checked"),
        )?;
        let (exit, reap) = retired(events, &tasks[0])?;
        let cg: crate::private_live_fact_recording::CgroupRetirementSourceV1 =
            crate::private_observer_session::strict_json(
                provider.attempts[0]
                    .phase_leaves
                    .get("cgroup-retirement-v1.json")
                    .ok_or_else(|| {
                        CiError::Message("public dual original R1 cgroup source absent".into())
                    })?,
                64 * 1024,
            )?;
        if tasks[0].tgid == tasks[1].tgid
            || tasks[0].cgroup_inode == tasks[1].cgroup_inode
            || targets[0].network_namespace_inode == targets[1].network_namespace_inode
            || cg.schema_version != 1
            || cg.inode != tasks[0].cgroup_inode
            || !cg.last_members.is_empty()
            || cg.empty_monotonic_ns < exit
            || cg.removed_monotonic_ns < cg.empty_monotonic_ns
            || cg.removed_monotonic_ns >= post.begin_monotonic_ns
            || reap >= post.begin_monotonic_ns
        {
            return fail("public dual distinct allocation/R1 before second sample differs");
        }
        check_held(&first, &tasks[0], events, exit)?;
        check_held(&second, &tasks[1], events, exit)?;
        let second_exit = retired(events, &tasks[1])?.0;
        check_held(&post, &tasks[1], events, second_exit)?;
        let endpoints = crate::private_candidate_network_facts::validate_held_tcp_endpoints;
        let (a, _) = endpoints(&first, &tasks[0], events, target_triple, port)?;
        let (b, c) = endpoints(&second, &tasks[1], events, target_triple, port)?;
        let (b_post, c_post) = endpoints(&post, &tasks[1], events, target_triple, port)?;
        if a.netns_inode != targets[0].network_namespace_inode
            || b.netns_inode != targets[1].network_namespace_inode
            || a.socket_inode == b.socket_inode
            || b != b_post
            || c != c_post
        {
            return fail("public dual actual endpoint/inode continuity differs");
        }
        crate::private_candidate_network_facts::validate_held_tcp_exchange_after(
            &post,
            &tasks[1],
            events,
            target_triple,
            c.socket_inode,
            reap.max(cg.removed_monotonic_ns),
            post.begin_monotonic_ns,
        )?;
        for (ordinal, name, count) in [
            (0, "dual-first-overlap", 1),
            (1, "dual-second-overlap", 1),
            (1, "dual-second-after-first-retirement", 2),
        ] {
            let branch = memcordon_core::private_release_case_v1::public_dual_challenge_v1(
                challenge, ordinal,
            )
            .map_err(|e| CiError::Message(e.into()))?;
            tcp_frames(
                sample_leaf(
                    observed,
                    &std::path::Path::new(name)
                        .join("target-response-at-held-gate.bin")
                        .to_string_lossy(),
                )?,
                &branch,
                port,
                targets[ordinal as usize].network_namespace_inode,
                count,
            )?;
        }
        if sample_leaf(observed, "dual-first-authenticated-terminal.bin")?
            != provider.attempts[0]
                .terminal_bytes
                .as_deref()
                .ok_or_else(|| {
                    CiError::Message("public dual first original terminal absent".into())
                })?
        {
            return fail("public dual R1 terminal was not independently retained");
        }
        Ok(
            crate::private_public_dispatch::compose_public_case_observation(
                selector, provider, observed, interval, &joined, None,
            )?
            .0,
        )
    } else {
        let fault = provider.attempts[0]
            .fault
            .as_ref()
            .ok_or_else(|| CiError::Message("public causal actual fault absent".into()))?;
        match fault.outcome {
            Outcome::AuthorizationUncertain => {
                let pre =
                    decode_sample(observed, "pre-exec/target-live-sample-v1.json", &image_leaf)?;
                protected_sample(
                    &pre,
                    provider.attempts[0]
                        .target_identity
                        .as_ref()
                        .expect("checked"),
                )?;
                let exit = retired(events, &tasks[0])?.0;
                check_held(&pre, &tasks[0], events, exit)?;
                if hash_bytes(pre.leaves.get("image.raw").ok_or_else(|| {
                    CiError::Message("public authorization original held image absent".into())
                })?) != pre.executable_sha256
                {
                    return fail("public authorization original held image bytes differ");
                }
            }
            Outcome::FrontendLost | Outcome::GuardianLost => {
                let held = decode_sample(observed, "target-live-sample-v1.json", &image_leaf)?;
                protected_sample(
                    &held,
                    provider.attempts[0]
                        .target_identity
                        .as_ref()
                        .expect("checked"),
                )?;
                let exit = retired(events, &tasks[0])?.0;
                check_held(&held, &tasks[0], events, exit)?;
                let (listener, connector) =
                    crate::private_candidate_network_facts::validate_held_tcp_endpoints(
                        &held,
                        &tasks[0],
                        events,
                        target_triple,
                        port,
                    )?;
                let trigger_rows = crate::private_candidate_network_facts::parse_held_tcp_table(
                    &fault.target_tcp_bytes,
                )?;
                let owned = fault
                    .target_socket_inodes
                    .iter()
                    .copied()
                    .collect::<BTreeSet<_>>();
                if owned.len() != fault.target_socket_inodes.len()
                    || !owned.contains(&listener.socket_inode)
                    || !owned.contains(&connector.socket_inode)
                    || !trigger_rows.iter().any(|row| {
                        row.inode == listener.socket_inode
                            && row.state == 10
                            && row.local_address == 0x0100007f
                            && row.local_port == port
                    })
                    || !trigger_rows.iter().any(|row| {
                        row.inode == connector.socket_inode
                            && row.state == 1
                            && row.remote_address == 0x0100007f
                            && row.remote_port == port
                    })
                {
                    return fail(
                        "public fault trigger actual socket operands differ from held endpoints",
                    );
                }
                tcp_frames(
                    sample_leaf(observed, "target-response-at-held-gate.bin")?,
                    challenge,
                    port,
                    targets[0].network_namespace_inode,
                    1,
                )?;
                if fault.outcome == Outcome::GuardianLost {
                    let victim = task(events, clock, fault.victim.pid, fault.victim.start_time)?;
                    let victim_exits = events
                        .iter()
                        .filter(|e| {
                            e.kind == 8
                                && same(&victim, e)
                                && e.syscall_result == 9
                                && e.monotonic_ns > held.end_monotonic_ns
                                && e.monotonic_ns < exit
                        })
                        .collect::<Vec<_>>();
                    if victim_exits.len() != 1 {
                        return fail(
                            "public guardian exact kill after live target absent/ambiguous",
                        );
                    }
                    retired(events, &victim)?;
                } else {
                    #[derive(Deserialize)]
                    #[serde(deny_unknown_fields)]
                    struct Wait {
                        schema_version: u8,
                        pid: u32,
                        start_time_ticks: u64,
                        raw_wait_status: i32,
                        signal: i32,
                        stdout_sha256: DiagnosticSha256,
                        stderr_sha256: DiagnosticSha256,
                        wait_observed_monotonic_ns: u64,
                    }
                    use std::os::unix::process::ExitStatusExt;
                    let wait: Wait = crate::private_observer_session::strict_json(
                        sample_leaf(observed, "supervisor/wait-v1.json")?,
                        4096,
                    )?;
                    let timing = interval.observation_timing().ok_or_else(|| {
                        CiError::Message("public original observation timing absent".into())
                    })?;
                    if wait.schema_version != 1
                        || wait.pid != fault.victim.pid
                        || wait.start_time_ticks != fault.victim.start_time
                        || wait.signal != 9
                        || wait.raw_wait_status != observed.process.status.into_raw()
                        || wait.stdout_sha256 != hash_bytes(&observed.process.stdout)
                        || wait.stderr_sha256 != hash_bytes(&observed.process.stderr)
                        || sample_leaf(observed, "supervisor/stdout.raw")?
                            != observed.process.stdout
                        || sample_leaf(observed, "supervisor/stderr.raw")?
                            != observed.process.stderr
                        || wait.wait_observed_monotonic_ns <= held.end_monotonic_ns
                        || wait.wait_observed_monotonic_ns > timing.operation_end_monotonic_ns
                    {
                        return fail(
                            "public frontend original supervisor wait/live target join differs",
                        );
                    }
                }
            }
            _ => return fail("public causal non-fault outcome cannot satisfy fault family"),
        }
        crate::private_public_dispatch::compose_public_fault_observation_v2(
            selector, provider, observed, interval, &joined, clock,
        )
    }
}

#[cfg(unix)]
pub(crate) fn replay_completed_public_fault_dual(
    intent: &crate::private_public_plan::StaticPublicSuiteIntentV1,
    completed: &crate::private_public_completion::AuthenticatedCompletedPublicEvidenceV2,
    ordinal: usize,
) -> Result<()> {
    replay_public_fault_dual_origin(intent, completed.origin(), ordinal)
}

pub(crate) fn replay_public_fault_dual_origin(
    intent: &crate::private_public_plan::StaticPublicSuiteIntentV1,
    origin: &impl crate::private_observer_session::ObserverEvidenceV1,
    ordinal: usize,
) -> Result<()> {
    let scenario = intent
        .scenarios
        .get(ordinal)
        .ok_or_else(|| CiError::Message("public causal case ordinal absent".into()))?;
    if !matches!(
        scenario.selector.as_str(),
        "private_tcp::authorization_uncertainty_retired"
            | "private_tcp::frontend_loss_retired"
            | "private_tcp::guardian_loss_retired"
            | "private_tcp::dual_attempt_namespace_isolation"
    ) {
        return fail("public causal adapter selector is not a fault/dual family");
    }
    let prefix = std::path::Path::new("cases").join(ordinal.to_string());
    let path = |name: &str| prefix.join(name).to_string_lossy().into_owned();
    let record: crate::private_observer_session::ObserverIntervalRecordV1 =
        crate::private_observer_session::strict_json(
            origin.leaf(&path("interval.json"))?,
            64 * 1024,
        )?;
    let purpose = if scenario.selector == "private_tcp::dual_attempt_namespace_isolation" {
        "dual-continuous"
    } else {
        "ordinary"
    };
    let (kernel, clock) =
        crate::private_public_specialist_replay::interval(origin, &path("interval.json"), purpose)?;
    let provider = crate::private_public_specialist_replay::provider(origin, &path("provider"))?;
    let challenge = crate::private_public_specialist_replay::bind_provider(
        intent,
        origin,
        &provider,
        &scenario.selector,
        record.generation,
    )?;
    let host = crate::private_public_specialist_replay::host(
        origin,
        intent,
        &path("host.json"),
        record.generation,
    )?;
    let case = memcordon_core::private_public_case_v2::FinalPublicCaseEvidenceV3::parse(
        origin.leaf(&path("result.json"))?,
    )
    .map_err(CiError::Message)?
    .0;
    let process = crate::private_public_ordinary_replay::process(
        origin.leaf(&path("cli/stdio.bin"))?,
        &case.child,
    )?;
    if case.child.uid != intent.public_uid
        || case.child.gid != intent.public_gid
        || !case.child.supplementary_groups_empty
        || case.child.executable_sha256 != intent.public_cli_sha256
        || case.selector != scenario.selector
        || record.logical_case_key != provider.result_key
        || record.ordinal != ordinal as u32
    {
        return fail("public causal independently approved child/case/physical role differs");
    }
    let report = match &case.report {
        memcordon_core::private_public_report_v2::PublicCliReportEvidenceV2::Present { .. } => {
            Some(origin.leaf(&path("cli/report.json"))?.to_vec())
        }
        _ => None,
    };
    let mut samples = std::collections::BTreeMap::new();
    let sample_prefix = path("samples");
    for name in &record.sample_paths {
        if let Some(relative) = name
            .strip_prefix(&sample_prefix)
            .and_then(|s| s.strip_prefix('/'))
        {
            samples.insert(relative.to_owned(), origin.leaf(name)?.to_vec());
        }
    }
    let mut observed = ObservedInstalledPublicCaseV3 {
        process,
        report: None,
        dual_report: None,
        report_bytes: report,
        stdio_bytes: origin.leaf(&path("cli/stdio.bin"))?.to_vec(),
        cli_sha256: intent.public_cli_sha256.clone(),
        argv_sha256: case.child.argv_sha256.clone(),
        working_directory_sha256: case.child.working_directory_sha256.clone(),
        live_samples: samples,
    };
    if scenario.selector == "private_tcp::authorization_uncertainty_retired" {
        let expected = &scenario.recipe;
        let pre = decode_sample(&observed, "pre-exec/target-live-sample-v1.json", &|name| {
            Ok(origin.leaf(name)?.to_vec())
        })?;
        let status = std::str::from_utf8(pre.leaves.get("status.raw").ok_or_else(|| {
            CiError::Message("public authorization original status absent".into())
        })?)
        .map_err(|_| CiError::Message("public authorization original status malformed".into()))?;
        let numbers = |name: &str| -> Result<Vec<u64>> {
            let values = status
                .lines()
                .filter_map(|line| line.strip_prefix(name))
                .collect::<Vec<_>>();
            let [value] = values.as_slice() else {
                return fail("public authorization status field ambiguous");
            };
            value
                .split_whitespace()
                .map(|v| {
                    v.parse().map_err(|_| {
                        CiError::Message("public authorization status scalar malformed".into())
                    })
                })
                .collect()
        };
        if numbers("Tgid:")? != vec![u64::from(pre.pid)]
            || numbers("Uid:")? != vec![u64::from(expected.target_uid); 4]
            || numbers("Gid:")? != vec![u64::from(expected.target_gid); 4]
            || numbers("Groups:")?
                != expected
                    .supplementary_groups
                    .iter()
                    .map(|g| u64::from(*g))
                    .collect::<Vec<_>>()
            || numbers("NoNewPrivs:")? != vec![1]
            || numbers("Seccomp:")? != vec![2]
            || pre.executable_sha256 != scenario.fixture_sha256
        {
            return fail(
                "public authorization held original target credentials/filter/image differ",
            );
        }
        for name in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
            let values = status
                .lines()
                .filter_map(|line| line.strip_prefix(name))
                .collect::<Vec<_>>();
            let [value] = values.as_slice() else {
                return fail("public authorization capability field ambiguous");
            };
            if u64::from_str_radix(value.trim(), 16).ok() != Some(0) {
                return fail("public authorization original capabilities are not empty");
            }
        }
    }
    if purpose == "dual-continuous" {
        let abi = match intent.observer_subject.target.as_str() {
            "x86_64-unknown-linux-gnu" => {
                memcordon_core::workload_evidence_v2::QualifiedNativeAbiV2::X86_64LinuxGnu
            }
            "aarch64-unknown-linux-gnu" => {
                memcordon_core::workload_evidence_v2::QualifiedNativeAbiV2::Aarch64LinuxGnu
            }
            _ => return fail("public causal ABI differs"),
        };
        observed.dual_report = Some(
            crate::private_public_v2::validate_structural_public_dual_v12_readback(
                &observed.process,
                observed
                    .report_bytes
                    .as_deref()
                    .ok_or_else(|| CiError::Message("public dual original report absent".into()))?,
                &crate::private_public_v2::ExpectedPublicV2Readback {
                    source_commit: &intent.observer_subject.source_commit,
                    native_abi: abi,
                    archive_sha256: &intent.archive_sha256,
                    runtime_manifest_sha256: &intent.manifest_sha256,
                    qualification_sha256: &intent.qualification_sha256,
                    host_receipt_sha256: host.active_h1_receipt_sha256(),
                    report_owner_uid: intent.public_uid,
                    outcome: crate::private_public_v2::ExpectedPublicV2Outcome::Exited(0),
                },
            )?,
        );
    }
    let actual = compose_public_fault_dual_sources(
        &scenario.selector,
        &provider,
        &observed,
        &kernel,
        &clock,
        &challenge,
        scenario.recipe.port,
        &intent.observer_subject.target,
        |name| Ok(origin.leaf(name)?.to_vec()),
    )?;
    if actual != case.observation {
        return fail("public causal result replaced original fault/dual observation");
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn verify_public_fault_dual_family_sources(
    origin: &impl crate::private_observer_session::ObserverEvidenceV1,
    expected: &crate::private_candidate_replay::ExpectedCaseSubjectV1<'_>,
    facts: &crate::private_candidate_replay::CaseReplayFactsV1,
    case_prefix: &str,
    family: crate::private_case_semantics::CaseFactKindV1,
) -> Result<()> {
    use crate::private_case_semantics::CaseFactKindV1 as F;
    if origin.descriptor().subject.stage != crate::private_observer_session::ObserverStageV1::Public
    {
        return fail("public causal family used outside final public stage");
    }
    let required = match expected.selector {
        "private_tcp::authorization_uncertainty_retired" => F::AuthorizationLoss,
        "private_tcp::frontend_loss_retired" => F::FrontendLoss,
        "private_tcp::guardian_loss_retired" => F::GuardianLoss,
        "private_tcp::dual_attempt_namespace_isolation" => F::Dual,
        _ => return fail("public causal family selector is not reviewed"),
    };
    if family != required
        && !(family == F::Checkpoint
            && matches!(
                required,
                F::AuthorizationLoss | F::FrontendLoss | F::GuardianLoss
            ))
    {
        return fail("public causal source family differs from exact selector");
    }
    let records = origin
        .descriptor()
        .intervals
        .iter()
        .filter(|record| record.interval_id == facts.interval_id)
        .collect::<Vec<_>>();
    let [record] = records.as_slice() else {
        return fail("public causal fact interval is ambiguous");
    };
    let prefix = std::path::Path::new("cases").join(record.ordinal.to_string());
    if prefix != std::path::Path::new(case_prefix)
        || record.generation != facts.generation
        || record.logical_case_key != facts.result_key
        || record.purpose
            != if required == F::Dual {
                "dual-continuous"
            } else {
                "ordinary"
            }
    {
        return fail("public causal fact source path/key/physical role differs");
    }
    let path = |name: &str| prefix.join(name).to_string_lossy().into_owned();
    let case = memcordon_core::private_public_case_v2::FinalPublicCaseEvidenceV3::parse(
        origin.leaf(&path("result.json"))?,
    )
    .map_err(CiError::Message)?
    .0;
    let challenge: [u8; 32] = expected
        .challenge
        .try_into()
        .map_err(|_| CiError::Message("public causal expected challenge length differs".into()))?;
    if case.selector != expected.selector
        || case.challenge != challenge
        || case.source_commit != origin.descriptor().subject.source_commit
        || case.target != origin.descriptor().subject.target
        || case.build_context_sha256 != origin.descriptor().subject.build_sha256
        || case.release_catalogue_sha256 != origin.descriptor().subject.catalogue_sha256
    {
        return fail("public causal original V3 subject differs");
    }
    let bytes = origin.leaf(&path("provider/record.json"))?;
    let mut leaves = std::collections::BTreeMap::new();
    for name in crate::private_public_dispatch::public_provider_source_leaf_names(bytes)? {
        leaves.insert(
            name.clone(),
            origin
                .leaf(
                    &prefix
                        .join("provider")
                        .join("raw")
                        .join(&name)
                        .to_string_lossy(),
                )?
                .to_vec(),
        );
    }
    let provider =
        crate::private_public_dispatch::parse_structural_provider_case_from_leaves(bytes, &leaves)?;
    if provider.result_key != facts.result_key {
        return fail("public causal protected provider key differs");
    }
    let kernel =
        crate::private_origin_replay::replay_origin_kernel_interval(origin, &record.capture_path)?;
    let clock_path = std::path::Path::new(&record.capture_path)
        .parent()
        .ok_or_else(|| CiError::Message("public causal capture parent absent".into()))?
        .join("clock.json")
        .to_string_lossy()
        .into_owned();
    if facts.clock_path != clock_path {
        return fail("public causal original clock path differs");
    }
    let clock = crate::private_origin_replay::replay_origin_clock(origin, record, &clock_path)?;
    let process = crate::private_public_ordinary_replay::process(
        origin.leaf(&path("cli/stdio.bin"))?,
        &case.child,
    )?;
    let mut samples = std::collections::BTreeMap::new();
    let sample_prefix = path("samples");
    for name in &record.sample_paths {
        if let Some(relative) = name
            .strip_prefix(&sample_prefix)
            .and_then(|p| p.strip_prefix('/'))
        {
            samples.insert(relative.to_owned(), origin.leaf(name)?.to_vec());
        }
    }
    let report_bytes = match case.report {
        memcordon_core::private_public_report_v2::PublicCliReportEvidenceV2::Present { .. } => {
            Some(origin.leaf(&path("cli/report.json"))?.to_vec())
        }
        _ => None,
    };
    let mut observed = ObservedInstalledPublicCaseV3 {
        process,
        report: None,
        dual_report: None,
        report_bytes,
        stdio_bytes: origin.leaf(&path("cli/stdio.bin"))?.to_vec(),
        cli_sha256: case.child.executable_sha256.clone(),
        argv_sha256: case.child.argv_sha256.clone(),
        working_directory_sha256: case.child.working_directory_sha256.clone(),
        live_samples: samples,
    };
    if required == F::AuthorizationLoss {
        let pre = decode_sample(&observed, "pre-exec/target-live-sample-v1.json", &|name| {
            Ok(origin.leaf(name)?.to_vec())
        })?;
        validate_public_pre_exec_status(
            &pre,
            expected.uid,
            expected.gid,
            expected.groups,
            expected.fixture_sha256,
        )?;
    }
    if required == F::Dual {
        let abi = match origin.descriptor().subject.target.as_str() {
            "x86_64-unknown-linux-gnu" => {
                memcordon_core::workload_evidence_v2::QualifiedNativeAbiV2::X86_64LinuxGnu
            }
            "aarch64-unknown-linux-gnu" => {
                memcordon_core::workload_evidence_v2::QualifiedNativeAbiV2::Aarch64LinuxGnu
            }
            _ => return fail("public dual native ABI is outside reviewed targets"),
        };
        observed.dual_report = Some(
            crate::private_public_v2::validate_structural_public_dual_v12_readback(
                &observed.process,
                observed
                    .report_bytes
                    .as_deref()
                    .ok_or_else(|| CiError::Message("public dual original report absent".into()))?,
                &crate::private_public_v2::ExpectedPublicV2Readback {
                    source_commit: &origin.descriptor().subject.source_commit,
                    native_abi: abi,
                    archive_sha256: &case.installed.archive_sha256,
                    runtime_manifest_sha256: &case.installed.qualified_manifest_sha256,
                    qualification_sha256: &case.installed.release_qualification_sha256,
                    host_receipt_sha256: &case.installed.active_host_receipt_sha256,
                    report_owner_uid: case.child.uid,
                    outcome: crate::private_public_v2::ExpectedPublicV2Outcome::Exited(0),
                },
            )?,
        );
    }
    let observation = compose_public_fault_dual_sources(
        expected.selector,
        &provider,
        &observed,
        &kernel,
        &clock,
        &challenge,
        expected.port,
        &origin.descriptor().subject.target,
        |name| Ok(origin.leaf(name)?.to_vec()),
    )?;
    if observation != case.observation {
        return fail("public causal family differs from authentic V3 outcome");
    }
    Ok(())
}

fn validate_public_pre_exec_status(
    sample: &HeldPublicTargetSamplesV1,
    uid: u32,
    gid: u32,
    groups: &[u32],
    image: &DiagnosticSha256,
) -> Result<()> {
    let status = std::str::from_utf8(
        sample
            .leaves
            .get("status.raw")
            .ok_or_else(|| CiError::Message("public preexec original status absent".into()))?,
    )
    .map_err(|_| CiError::Message("public preexec status malformed".into()))?;
    let field = |name: &str| -> Result<&str> {
        let values = status
            .lines()
            .filter_map(|line| line.strip_prefix(name))
            .collect::<Vec<_>>();
        let [value] = values.as_slice() else {
            return fail("public preexec status field ambiguous");
        };
        Ok(value.trim())
    };
    let numbers = |name: &str| -> Result<Vec<u64>> {
        field(name)?
            .split_whitespace()
            .map(|v| {
                v.parse()
                    .map_err(|_| CiError::Message("public preexec status scalar malformed".into()))
            })
            .collect()
    };
    if numbers("Tgid:")? != vec![u64::from(sample.pid)]
        || numbers("Uid:")? != vec![u64::from(uid); 4]
        || numbers("Gid:")? != vec![u64::from(gid); 4]
        || numbers("Groups:")? != groups.iter().map(|g| u64::from(*g)).collect::<Vec<_>>()
        || numbers("NoNewPrivs:")? != vec![1]
        || numbers("Seccomp:")? != vec![2]
        || sample.executable_sha256 != *image
    {
        return fail("public preexec held status/image differs from protected recipe");
    }
    for name in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
        if u64::from_str_radix(field(name)?, 16).ok() != Some(0) {
            return fail("public preexec capabilities are not empty");
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn verify_public_fault_dual_family_sources(
    _origin: &impl crate::private_observer_session::ObserverEvidenceV1,
    _expected: &crate::private_candidate_replay::ExpectedCaseSubjectV1<'_>,
    _facts: &crate::private_candidate_replay::CaseReplayFactsV1,
    _case_prefix: &str,
    _family: crate::private_case_semantics::CaseFactKindV1,
) -> Result<()> {
    fail("public original Unix supervisor wire replay requires a Unix collector")
}
