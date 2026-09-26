//! Versioned installed-program sources shared by candidate and final-public.
//! No local proc reads and no submitted-buffer-as-installed proof.
use crate::private_candidate_replay::{CaseFactV1, ReplayTaskV1};
use crate::private_kernel_replay::{KernelEventRecordV2, installed_kernel_filters};
use crate::private_process_clock::{ParsedProcClockCalibrationV1, ProcClockInputsV1};
use crate::private_public_live::HeldPublicTargetSamplesV1;
use crate::{CiError, Result};
use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeFilterSourcesV1 {
    pub schema_version: u8,
    /// Held after the actual filter READY but before GO/exec, not before install.
    pub pre_path: String,
    pub baseline_path: String,
    /// Actual kernel-retained original instructions emitted by feature16.
    pub instruction_path: String,
}

pub fn filter_install_source_revision_sha256() -> DiagnosticSha256 {
    hash_bytes(b"memcordon/installed-kernel-filter-source/v1\0feature16;native-checked-fprog;kernel-orig-program-4096;paired-success;actual-count-plus-one;head-prev-identity-exec-fork-decision;all-held-thread-status;nnp1;exact-reviewed-instructions\0")
}
fn fail<T>(message: &str) -> Result<T> {
    Err(CiError::Message(message.into()))
}
fn status(sample: &HeldPublicTargetSamplesV1, path: &str, field: &str) -> Result<u64> {
    let raw = sample
        .leaves
        .get(path)
        .ok_or_else(|| CiError::Message(format!("filter status source absent: {path}")))?;
    if raw.len() > 128 * 1024 {
        return fail("filter status exceeds bound");
    }
    let text = std::str::from_utf8(raw)
        .map_err(|_| CiError::Message("filter status is not text".into()))?;
    let rows = text
        .lines()
        .filter_map(|line| line.strip_prefix(field))
        .collect::<Vec<_>>();
    if rows.len() != 1 {
        return fail("filter status field absent or duplicated");
    }
    let fields = rows[0].split_whitespace().collect::<Vec<_>>();
    if fields.len() != 1 {
        return fail("filter status scalar differs");
    }
    fields[0]
        .parse()
        .map_err(|_| CiError::Message("filter status scalar invalid".into()))
}
pub(crate) fn check_sample(
    sample: &HeldPublicTargetSamplesV1,
    target: &ReplayTaskV1,
    clock: &ProcClockInputsV1,
    count: u32,
) -> Result<()> {
    if sample.schema_version != 1
        || sample.pid != target.tid
        || sample.tasks.is_empty()
        || sample.begin_monotonic_ns == 0
        || sample.end_monotonic_ns < sample.begin_monotonic_ns
    {
        return fail("filter held sample identity/time differs");
    }
    let clock = ParsedProcClockCalibrationV1::parse(clock)?;
    if !clock.matches(
        crate::private_kernel_observer::KernelTaskIdentityV1 {
            pid: target.tid,
            start_time: target.start_boottime_ns,
            cgroup_inode: target.cgroup_inode,
            time_ns_inode: target.time_ns_inode,
        },
        sample.start_time_ticks,
    ) {
        return fail("filter original clock/task differs");
    }
    for task in &sample.tasks {
        let prefix = std::path::Path::new("tasks").join(task.tid.to_string());
        let path = prefix.join("status.raw");
        let path = path
            .to_str()
            .ok_or_else(|| CiError::Message("filter status path is not UTF-8".into()))?;
        if task.tgid != target.tgid
            || task.start_time_ticks == 0
            || status(sample, path, "NoNewPrivs:")? != 1
            || status(sample, path, "Seccomp:")? != 2
            || status(sample, path, "Seccomp_filters:")? != u64::from(count)
        {
            return fail("filter all-thread installed count/mode/NNP differs");
        }
        for name in ["stat.raw", "stat-after.raw"] {
            let path = prefix.join(name);
            let raw = sample
                .leaves
                .get(path.to_str().expect("numeric proc task path"))
                .ok_or_else(|| CiError::Message("filter raw task stat absent".into()))?;
            if raw.len() > 64 * 1024 {
                return fail("filter task stat exceeds bound");
            }
            let text = std::str::from_utf8(raw)
                .map_err(|_| CiError::Message("filter task stat is not text".into()))?;
            let (pid, tail) = text
                .split_once(' ')
                .ok_or_else(|| CiError::Message("filter task stat PID absent".into()))?;
            let (_, fields) = tail
                .rsplit_once(") ")
                .ok_or_else(|| CiError::Message("filter task stat fields absent".into()))?;
            if pid.parse::<u32>().ok() != Some(task.tid)
                || fields
                    .split_whitespace()
                    .nth(19)
                    .and_then(|v| v.parse::<u64>().ok())
                    != Some(task.start_time_ticks)
            {
                return fail("filter raw held thread PID/start differs");
            }
        }
    }
    Ok(())
}

/// Portable diagnostic helper; it returns no observer-origin capability.
pub fn validate_capture_filter_source(
    capture: &[u8],
    key: &DiagnosticSha256,
    clock_bytes: &[u8],
    target: &ReplayTaskV1,
    pre: &HeldPublicTargetSamplesV1,
    baseline: &HeldPublicTargetSamplesV1,
    instructions: &[u8],
    reviewed_filter: &DiagnosticSha256,
) -> Result<()> {
    let parsed = crate::private_kernel_replay::parse_capture_v2(capture, key)?;
    let clock = crate::private_observer_session::strict_json(clock_bytes, 128 * 1024)?;
    validate_filter_source(
        parsed.events(),
        &clock,
        target,
        pre,
        baseline,
        instructions,
        reviewed_filter,
    )
}

/// Source conversion returns actual dumped bytes for immutable retention. The
/// caller must place these bytes at sources.instruction_path before sealing.
pub(crate) fn record_filter_source_facts(
    events: &[KernelEventRecordV2],
    clock: &ProcClockInputsV1,
    target: &ReplayTaskV1,
    pre: &HeldPublicTargetSamplesV1,
    baseline: &HeldPublicTargetSamplesV1,
    sources: NativeFilterSourcesV1,
    reviewed_filter: &DiagnosticSha256,
) -> Result<(Vec<CaseFactV1>, Vec<u8>)> {
    let installed = installed_kernel_filters(events)?;
    let matches = installed
        .iter()
        .filter(|f| {
            f.task.tid == target.tid && f.task.start_boottime_ns == target.start_boottime_ns
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return fail("filter target exact install absent or duplicated");
    }
    let bytes = matches[0].instructions.clone();
    validate_filter_source(
        events,
        clock,
        target,
        pre,
        baseline,
        &bytes,
        reviewed_filter,
    )?;
    Ok((vec![CaseFactV1::NativeFilterV1 { sources }], bytes))
}

pub(crate) fn verify_native_filter_source(
    sources: &NativeFilterSourcesV1,
    target: &ReplayTaskV1,
    events: &[KernelEventRecordV2],
    clock: &ProcClockInputsV1,
    reviewed_filter: &DiagnosticSha256,
    approved_revision: Option<&DiagnosticSha256>,
    leaf: impl Fn(&str) -> Result<Vec<u8>>,
) -> Result<()> {
    if sources.schema_version != 1
        || approved_revision != Some(&filter_install_source_revision_sha256())
        || sources.pre_path == sources.baseline_path
        || sources.instruction_path == sources.pre_path
        || sources.instruction_path == sources.baseline_path
    {
        return fail("filter source version/independent reviewed opt-in differs");
    }
    let decode = |path: &str| {
        crate::private_source_carrier::decode_held_source(&leaf(path)?, |image| leaf(image))
    };
    let pre = decode(&sources.pre_path)?;
    let baseline = decode(&sources.baseline_path)?;
    validate_filter_source(
        events,
        clock,
        target,
        &pre,
        &baseline,
        &leaf(&sources.instruction_path)?,
        reviewed_filter,
    )
}

pub(crate) fn validate_filter_source(
    events: &[KernelEventRecordV2],
    clock: &ProcClockInputsV1,
    target: &ReplayTaskV1,
    pre: &HeldPublicTargetSamplesV1,
    baseline: &HeldPublicTargetSamplesV1,
    instructions: &[u8],
    reviewed_filter: &DiagnosticSha256,
) -> Result<()> {
    let all = installed_kernel_filters(events)?;
    let selected = all
        .iter()
        .filter(|f| {
            f.task.tid == target.tid && f.task.start_boottime_ns == target.start_boottime_ns
        })
        .collect::<Vec<_>>();
    if selected.len() != 1 {
        return fail("filter target exact install absent or duplicated");
    }
    let filter = selected[0];
    if filter.task.tgid != target.tgid
        || filter.task.cgroup_inode != target.cgroup_inode
        || filter.task.time_ns_inode != target.time_ns_inode
        || filter.instructions != instructions
        || filter.instructions_sha256 != *reviewed_filter
        || hash_bytes(instructions) != *reviewed_filter
        || filter.count_before.checked_add(1) != Some(filter.count_after)
    {
        return fail("filter actual installed instruction object/count differs");
    }
    check_sample(pre, target, clock, filter.count_after)?;
    check_sample(baseline, target, clock, filter.count_after)?;
    let installed_event = events
        .iter()
        .find(|e| e.sequence == filter.installed_sequence)
        .expect("parsed installed filter sequence");
    let exec = events
        .iter()
        .filter(|e| {
            e.kind == 6
                && e.task == filter.task
                && e.sequence > filter.installed_sequence
                && e.monotonic_ns > pre.end_monotonic_ns
                && e.monotonic_ns < baseline.begin_monotonic_ns
        })
        .collect::<Vec<_>>();
    if installed_event.monotonic_ns >= pre.begin_monotonic_ns
        || pre.end_monotonic_ns >= baseline.begin_monotonic_ns
        || exec.len() != 1
    {
        return fail("filter genuine install/pre/exec/baseline order differs");
    }
    let mut lineage = BTreeMap::from([(
        (target.tid, target.start_boottime_ns),
        (filter.filter_identity, filter.previous_filter_identity),
    )]);
    for event in events
        .iter()
        .filter(|e| e.sequence > filter.installed_sequence)
    {
        let Some(&(head, previous)) = lineage.get(&(event.task.tid, event.task.start_boottime_ns))
        else {
            continue;
        };
        if event.kind == 13 {
            if event.image_dev != head
                || event.image_inode != previous
                || event.syscall_result != 2
                || event.seccomp_action == 1
            {
                return fail("filter lineage identity changed after install");
            }
            if event.seccomp_action == 4 {
                let fork = events
                    .iter()
                    .rev()
                    .find(|f| {
                        f.kind == 7
                            && f.task == event.task
                            && f.other_tid == event.other_tid
                            && f.sequence < event.sequence
                    })
                    .ok_or_else(|| CiError::Message("filter child actual fork absent".into()))?;
                let start = u64::try_from(fork.syscall_result)
                    .map_err(|_| CiError::Message("filter child start invalid".into()))?;
                if start == 0
                    || lineage
                        .insert((event.other_tid, start), (head, previous))
                        .is_some()
                {
                    return fail("filter child lineage duplicated");
                }
            }
        } else if matches!(event.kind, 4 | 6 | 7) {
            let role = match event.kind {
                4 => 2,
                6 => 3,
                _ => 4,
            };
            let identities = events
                .iter()
                .filter(|f| {
                    f.kind == 13
                        && f.task == event.task
                        && f.seccomp_action == role
                        && (role != 2 || f.syscall_occurrence == event.syscall_occurrence)
                        && (role != 4 || f.other_tid == event.other_tid)
                        && if role == 2 {
                            f.sequence < event.sequence
                        } else {
                            f.sequence > event.sequence
                        }
                })
                .collect::<Vec<_>>();
            if identities.is_empty() {
                return fail("filter exec/fork/decision kernel identity absent");
            }
        }
    }
    let calibration = ParsedProcClockCalibrationV1::parse(clock)?;
    for task in &baseline.tasks {
        if !lineage.iter().any(|(&(tid, start), _)| {
            tid == task.tid
                && calibration.matches(
                    crate::private_kernel_observer::KernelTaskIdentityV1 {
                        pid: tid,
                        start_time: start,
                        cgroup_inode: target.cgroup_inode,
                        time_ns_inode: target.time_ns_inode,
                    },
                    task.start_time_ticks,
                )
        }) {
            return fail("filter held thread lacks actual inherited kernel identity");
        }
    }
    Ok(())
}
