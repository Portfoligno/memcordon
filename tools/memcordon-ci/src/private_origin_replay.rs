//! Origin-authenticated archived interval and original-reader clock replay.
//! Kept separate from source-only diagnostic modules used by external tests.
use crate::private_kernel_observer::{
    AllocationBoundaryKindV1, KernelEventV1, KernelIntervalReplayMetadataV1, KernelTaskIdentityV1,
    SeccompActionV1, VerifiedKernelIntervalV1,
};
use crate::private_process_clock::{
    ParsedProcClockCalibrationV1, ProcClockInputsV1, VerifiedProcClockCalibrationV1,
};
use crate::{CiError, Result};
use memcordon_core::DiagnosticSha256;
fn fail(message: &'static str) -> CiError {
    CiError::Message(message.into())
}

pub(crate) fn replay_origin_kernel_interval(
    origin: &impl crate::private_observer_session::ObserverEvidenceV1,
    capture_path: &str,
) -> Result<VerifiedKernelIntervalV1> {
    let bound = crate::private_candidate_replay::replay_observer_interval(origin, capture_path)?;
    let records = origin
        .descriptor()
        .intervals
        .iter()
        .filter(|record| record.capture_path == capture_path)
        .collect::<Vec<_>>();
    let [record] = records.as_slice() else {
        return Err(fail("specialist physical interval absent or ambiguous"));
    };
    let prefix = std::path::Path::new(capture_path)
        .parent()
        .ok_or_else(|| fail("specialist capture parent absent"))?;
    let metadata_path = prefix
        .join("kernel-metadata.json")
        .to_string_lossy()
        .into_owned();
    if !record.sample_paths.contains(&metadata_path) {
        return Err(fail("specialist kernel metadata not enrolled"));
    }
    let metadata: KernelIntervalReplayMetadataV1 =
        crate::private_observer_session::strict_json(origin.leaf(&metadata_path)?, 4096)?;
    if metadata.schema_version != 1
        || metadata.kernel_release.is_empty()
        || metadata.kernel_release.len() > 128
        || metadata.probe_map_sha256 == DiagnosticSha256::from_bytes([0; 32])
        || metadata.coordinator_pid == 0
        || metadata.coordinator_start_time == 0
        || metadata.cgroup_inode == 0
    {
        return Err(fail("specialist enrolled kernel metadata differs"));
    }
    let timing = metadata
        .observation_timing
        .as_ref()
        .ok_or_else(|| fail("specialist original observation timing absent"))?;
    if timing.armed_monotonic_ns != record.arm_monotonic_ns
        || timing.operation_begin_monotonic_ns != record.begin_monotonic_ns
        || timing.operation_end_monotonic_ns != record.end_monotonic_ns
        || timing.detached_monotonic_ns != record.detach_monotonic_ns
        || timing.armed_monotonic_ns == 0
        || timing.armed_monotonic_ns > timing.operation_begin_monotonic_ns
        || timing.operation_begin_monotonic_ns >= timing.operation_end_monotonic_ns
        || timing.operation_end_monotonic_ns > timing.detached_monotonic_ns
        || timing.detached_monotonic_ns > timing.drained_monotonic_ns
    {
        return Err(fail(
            "specialist original timing differs from custody enrollment",
        ));
    }
    let task = |raw: crate::private_kernel_replay::KernelTaskIdentityV2| KernelTaskIdentityV1 {
        pid: raw.tid,
        start_time: raw.start_boottime_ns,
        cgroup_inode: raw.cgroup_inode,
        time_ns_inode: raw.time_ns_inode,
    };
    let mut events = Vec::new();
    for raw in bound.events() {
        if matches!(raw.kind, 11..=19)
            || (raw.kind == 5
                && bound.events().iter().any(|entry| {
                    matches!(entry.kind, 11 | 17)
                        && entry.syscall_occurrence == raw.syscall_occurrence
                }))
        {
            continue; // Explicit diagnostic V1 projection, not a seccomp claim.
        }
        let subject = task(raw.task);
        let event = match raw.kind {
            1 | 2 | 3 => KernelEventV1::AllocationBoundary {
                task: subject,
                request_key: record.logical_case_key.clone(),
                kind: match raw.kind {
                    1 => AllocationBoundaryKindV1::Enter,
                    2 => AllocationBoundaryKindV1::Exit,
                    _ => AllocationBoundaryKindV1::Allocate,
                },
            },
            4 => KernelEventV1::SeccompDecision {
                task: subject,
                arch: raw.syscall_arch,
                syscall: raw.syscall_nr,
                action: match raw.seccomp_action {
                    0x7fff0000 => SeccompActionV1::Allow,
                    0x00050000 => SeccompActionV1::Errno,
                    0x80000000 => SeccompActionV1::KillProcess,
                    _ => return Err(fail("specialist seccomp action differs")),
                },
                errno: raw
                    .syscall_result
                    .try_into()
                    .map_err(|_| fail("specialist errno overflow"))?,
            },
            5 => KernelEventV1::SyscallReturn {
                task: subject,
                arch: raw.syscall_arch,
                syscall: raw.syscall_nr,
                value: raw.syscall_result,
            },
            6 => KernelEventV1::Exec {
                task: subject,
                image_dev: raw.image_dev,
                image_inode: raw.image_inode,
                abi: raw.syscall_arch,
            },
            7 => {
                let child_start = u64::try_from(raw.syscall_result)
                    .map_err(|_| fail("specialist fork start differs"))?;
                let child = bound
                    .events()
                    .iter()
                    .find(|event| {
                        event.task.tid == raw.other_tid
                            && event.task.start_boottime_ns == child_start
                    })
                    .ok_or_else(|| fail("specialist fork child has no actual task observation"))?;
                KernelEventV1::Fork {
                    parent: subject,
                    child: task(child.task),
                }
            }
            8 => KernelEventV1::Exit {
                task: subject,
                signal: raw
                    .syscall_result
                    .try_into()
                    .map_err(|_| fail("specialist exit status differs"))?,
            },
            9 => {
                let matches = bound
                    .events()
                    .iter()
                    .filter(|event| {
                        event.kind == 8
                            && event.sequence < raw.sequence
                            && event.task.tid == raw.other_tid
                            && i64::try_from(event.task.start_boottime_ns).ok()
                                == Some(raw.syscall_result)
                    })
                    .collect::<Vec<_>>();
                let [exited] = matches.as_slice() else {
                    return Err(fail("specialist reap exact exit absent or ambiguous"));
                };
                KernelEventV1::Reap {
                    task: task(exited.task),
                }
            }
            10 => KernelEventV1::NamespaceFdClosed {
                task: subject,
                namespace_inode: raw.image_inode,
            },
            _ => return Err(fail("specialist event kind differs")),
        };
        events.push(event);
    }
    if !bound.events().iter().any(|event| {
        event.task.tid == metadata.coordinator_pid
            && event.task.start_boottime_ns == metadata.coordinator_start_time
            && event.task.cgroup_inode == metadata.cgroup_inode
    }) {
        return Err(fail("specialist metadata lacks exact raw coordinator join"));
    }
    let clock_path = prefix.join("clock.json").to_string_lossy().into_owned();
    let clock = replay_origin_clock(origin, record, &clock_path)?;
    use crate::private_kernel_replay::{IntervalIdV1, IntervalPurposeV1};
    let physical_interval_id = IntervalIdV1 {
        session_nonce: hex::decode(&origin.descriptor().session_nonce)
            .map_err(|_| fail("specialist session nonce encoding differs"))?
            .try_into()
            .map_err(|_| fail("specialist session nonce width differs"))?,
        generation: record.generation,
        logical_case_key: record.logical_case_key.clone(),
        purpose: match record.purpose.as_str() {
            "controls" => IntervalPurposeV1::KnownControls,
            "ordinary" => IntervalPurposeV1::Ordinary,
            "abi-outer" => IntervalPurposeV1::AbiOuter,
            "abi-filtered" => IntervalPurposeV1::AbiFiltered,
            "historical" => IntervalPurposeV1::Historical,
            "caller-spoof" => IntervalPurposeV1::CallerSpoof,
            "policy" => IntervalPurposeV1::Policy,
            "reuse-first" => IntervalPurposeV1::ReuseFirst,
            "reuse-blocked" => IntervalPurposeV1::ReuseBlocked,
            "recovery" => IntervalPurposeV1::Recovery,
            "dual-continuous" => IntervalPurposeV1::DualContinuous,
            _ => return Err(fail("specialist physical purpose differs")),
        },
        ordinal: record.ordinal,
    };
    if physical_interval_id.storage_sha256() != record.interval_id {
        return Err(fail(
            "specialist physical identity differs from custody enrollment",
        ));
    }
    Ok(VerifiedKernelIntervalV1 {
        boot_id: origin.descriptor().boot_id.clone(),
        kernel_release: metadata.kernel_release,
        btf_sha256: origin.descriptor().kernel_btf_sha256.clone(),
        probe_map_sha256: metadata.probe_map_sha256,
        trace_sha256: bound.capture_sha256().clone(),
        coordinator_pid: metadata.coordinator_pid,
        coordinator_start_time: metadata.coordinator_start_time,
        cgroup_inode: metadata.cgroup_inode,
        result_key: record.logical_case_key.clone(),
        events,
        capture_bytes: Some(origin.leaf(capture_path)?.to_vec()),
        physical_interval_id: Some(physical_interval_id),
        raw_candidate_only: false,
        clock_inputs: clock.inputs().cloned(),
        original_clock: Some(clock.clone()),
        loader_stderr: None,
        observation_timing: metadata.observation_timing,
    })
}

pub(crate) fn replay_origin_clock(
    origin: &impl crate::private_observer_session::ObserverEvidenceV1,
    interval: &crate::private_observer_session::ObserverIntervalRecordV1,
    path: &str,
) -> Result<VerifiedProcClockCalibrationV1> {
    if !interval.sample_paths.iter().any(|sample| sample == path) {
        return Err(fail("archived clock is not in enrolled interval"));
    }
    let inputs: ProcClockInputsV1 =
        crate::private_observer_session::strict_json(origin.leaf(path)?, 128 * 1024)?;
    let parsed = ParsedProcClockCalibrationV1::parse(&inputs)?;
    Ok(VerifiedProcClockCalibrationV1 {
        reader_pid: parsed.reader_pid,
        reader_start_ticks: parsed.reader_start_ticks,
        time_ns_inode: parsed.time_ns_inode,
        boottime_offset_ns: parsed.boottime_offset_ns,
        clock_ticks_per_second: parsed.clock_ticks_per_second,
        inputs: Some(inputs),
    })
}
