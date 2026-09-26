//! Source-only conversion of supervisor measurements into replay carriers.
//!
//! These functions do not produce verification capabilities. They deliberately
//! accept no selector: a label cannot supply a missing process, descriptor,
//! syscall result, namespace close, or cgroup-removal observation.
use crate::private_candidate_replay::{
    CaseFactV1, CgroupRetirementV1, DescriptorV1, NamespaceRetirementV1, ReplayTaskV1,
    TaskRetirementV1,
};
use crate::private_kernel_replay::{CaptureStageV2, KernelEventRecordV2};
use crate::private_public_live::{HeldPublicTargetSamplesV1, PublicNamespaceCloseV1};
use crate::{CiError, Result};
use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CgroupRetirementSourceV1 {
    pub schema_version: u8,
    pub path: String,
    pub inode: u64,
    pub last_members: Vec<u32>,
    pub empty_monotonic_ns: u64,
    pub removed_monotonic_ns: u64,
}

pub(crate) struct CommonSourceFactsV1 {
    pub(crate) target: ReplayTaskV1,
    pub(crate) facts: Vec<CaseFactV1>,
}

pub(crate) fn record_elf_source_fact(
    sample: &HeldPublicTargetSamplesV1,
    image_path: String,
    before_metadata_path: String,
    after_metadata_path: String,
) -> Result<CaseFactV1> {
    let before: Vec<crate::private_public_live::ProtectedAncestorSourceV1> =
        crate::private_observer_session::strict_json(
            sample_leaf(sample, "ancestors-before.json")?,
            64 * 1024,
        )?;
    let after: Vec<crate::private_public_live::ProtectedAncestorSourceV1> =
        crate::private_observer_session::strict_json(
            sample_leaf(sample, "ancestors-after.json")?,
            64 * 1024,
        )?;
    if before.is_empty()
        || before != after
        || before.iter().any(|entry| {
            entry.uid != 0
                || entry.mode & 0o022 != 0
                || entry.kind != "directory"
                || entry.dev == 0
                || entry.inode == 0
        })
        || hash_bytes(sample_leaf(sample, "image.raw")?) != sample.executable_sha256
    {
        return fail("source actual protected ELF ancestors/image differ");
    }
    Ok(CaseFactV1::ElfAncestors {
        dev: sample.executable_device,
        inode: sample.executable_inode,
        image_path,
        before_metadata_path,
        after_metadata_path,
    })
}

/// Both samples are the original held measurements, not caller-supplied
/// semantic projections. `before` is after relay sealing and before exec;
/// `after` is the immediate post-exec baseline before fixture operations.
pub(crate) fn record_common_source_facts(
    capture: &[u8],
    result_key: &DiagnosticSha256,
    stage: CaptureStageV2,
    target_triple: &str,
    clock_bytes: &[u8],
    before: &HeldPublicTargetSamplesV1,
    after: &HeldPublicTargetSamplesV1,
    response_path: String,
) -> Result<CommonSourceFactsV1> {
    let parsed =
        crate::private_kernel_replay::parse_capture_v2_with_budget(capture, result_key, stage)?;
    let clock_inputs = crate::private_observer_session::strict_json(clock_bytes, 128 * 1024)?;
    let clock = crate::private_process_clock::ParsedProcClockCalibrationV1::parse(&clock_inputs)?;
    if before.schema_version != 1
        || after.schema_version != 1
        || before.pid != after.pid
        || before.start_time_ticks != after.start_time_ticks
        || before.begin_monotonic_ns > before.end_monotonic_ns
        || after.begin_monotonic_ns > after.end_monotonic_ns
    {
        return fail("source pre/post held process identity differs");
    }
    let execs = parsed
        .events()
        .iter()
        .filter(|event| {
            event.kind == 6
                && event.task.tgid == after.pid
                && event.image_dev == after.executable_device
                && event.image_inode == after.executable_inode
                && event.monotonic_ns > before.end_monotonic_ns
                && event.monotonic_ns < after.begin_monotonic_ns
        })
        .collect::<Vec<_>>();
    if execs.len() != 1 {
        return fail("source exact pre/post exec is absent or duplicated");
    }
    let exec = execs[0];
    if !clock.matches(
        crate::private_kernel_observer::KernelTaskIdentityV1 {
            pid: exec.task.tid,
            start_time: exec.task.start_boottime_ns,
            cgroup_inode: exec.task.cgroup_inode,
            time_ns_inode: exec.task.time_ns_inode,
        },
        after.start_time_ticks,
    ) {
        return fail("source original-reader clock/process identity differs");
    }
    let target = task(exec);
    let argv_bytes = sample_leaf(after, "cmdline.raw")?;
    if !argv_bytes.ends_with(&[0]) {
        return fail("source cmdline terminator absent");
    }
    let argv = argv_bytes
        .strip_suffix(&[0])
        .expect("checked")
        .split(|byte| *byte == 0)
        .map(|argument| {
            std::str::from_utf8(argument)
                .map(str::to_owned)
                .map_err(|_| CiError::Message("source argv is not UTF-8".into()))
        })
        .collect::<Result<Vec<_>>>()?;
    if hash_bytes(sample_leaf(after, "image.raw")?) != after.executable_sha256 {
        return fail("source held image bytes/hash differ");
    }
    let before_fds = descriptors(before)?;
    let after_fds = descriptors(after)?;
    if before_fds.iter().map(|fd| fd.fd).collect::<Vec<_>>() != [0, 1, 2, 3, 4]
        || after_fds.iter().map(|fd| fd.fd).collect::<Vec<_>>() != [0, 1, 2]
        || before_fds[..3] != after_fds[..]
        || before_fds[..3].iter().any(|fd| fd.kind != "pipe")
        || before_fds[3].kind != "unix-seqpacket"
        || before_fds[4].kind != "regular-pinned-image"
        || before_fds[3..].iter().any(|fd| fd.flags & 0x80000 == 0)
    {
        return fail("source immediate pre/post exec descriptor inventory differs");
    }
    let status = text(sample_leaf(after, "status.raw")?)?;
    let uids = fixed_numbers::<4>(status, "Uid:")?;
    let gids = fixed_numbers::<4>(status, "Gid:")?;
    let groups = numbers(status, "Groups:")?
        .into_iter()
        .map(|value| {
            u32::try_from(value).map_err(|_| CiError::Message("source group exceeds u32".into()))
        })
        .collect::<Result<Vec<_>>>()?;
    let capabilities = ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"]
        .map(|key| {
            u64::from_str_radix(field(status, key)?, 16)
                .map_err(|_| CiError::Message("source capability field differs".into()))
        })
        .into_iter()
        .collect::<Result<Vec<_>>>()?
        .try_into()
        .map_err(|_| CiError::Message("source capabilities inventory differs".into()))?;
    let no_new_privs = fixed_numbers::<1>(status, "NoNewPrivs:")?[0];
    let (audit_arch, prctl_nr) = match target_triple {
        "x86_64-unknown-linux-gnu" => (0xc000003e, 157),
        "aarch64-unknown-linux-gnu" => (0xc00000b7, 167),
        _ => return fail("source credential syscall target is not native GNU"),
    };
    // /proc/status does not expose securebits. Only the same-task native
    // PR_GET_SECUREBITS syscall return can provide this value.
    let securebit_returns = parsed
        .events()
        .iter()
        .filter(|event| {
            event.kind == 5
                && same(&target, event)
                && event.syscall_arch == audit_arch
                && event.syscall_nr == prctl_nr
                && event.args[0] == 27
                && event.monotonic_ns > exec.monotonic_ns
                && event.monotonic_ns < after.begin_monotonic_ns
                && event.syscall_result >= 0
        })
        .collect::<Vec<_>>();
    if securebit_returns.len() != 1 {
        return fail("source actual PR_GET_SECUREBITS return absent or duplicated");
    }
    let securebits = u32::try_from(securebit_returns[0].syscall_result)
        .map_err(|_| CiError::Message("source securebits return exceeds u32".into()))?;
    let userns_inode = after
        .tasks
        .iter()
        .find(|entry| entry.tid == target.tid)
        .and_then(|entry| entry.namespace_inodes.get("user"))
        .copied()
        .filter(|inode| *inode != 0)
        .ok_or_else(|| CiError::Message("source target user namespace absent".into()))?;
    Ok(CommonSourceFactsV1 {
        target: target.clone(),
        facts: vec![
            CaseFactV1::ExecImage {
                task: target.clone(),
                dev: exec.image_dev,
                inode: exec.image_inode,
                sha256: after.executable_sha256.clone(),
                argv,
                response_path,
            },
            CaseFactV1::Descriptors {
                task: target.clone(),
                before: before_fds,
                after: after_fds,
                before_monotonic_ns: before.end_monotonic_ns,
                after_monotonic_ns: after.begin_monotonic_ns,
            },
            CaseFactV1::Credentials {
                task: target,
                uids,
                gids,
                groups,
                capabilities,
                no_new_privs,
                securebits,
                userns_inode,
            },
        ],
    })
}

/// Roles must come from actually held subject samples, not the selector.
pub(crate) fn record_retirement_source_fact(
    events: &[KernelEventRecordV2],
    clock_inputs: &crate::private_process_clock::ProcClockInputsV1,
    held: &[(&str, &HeldPublicTargetSamplesV1)],
    cgroup_bytes: &[Vec<u8>],
    close_bytes: &[u8],
    terminal_path: String,
) -> Result<CaseFactV1> {
    let clock = crate::private_process_clock::ParsedProcClockCalibrationV1::parse(clock_inputs)?;
    let mut tasks = BTreeMap::new();
    let mut namespaces = BTreeMap::<u64, BTreeSet<u32>>::new();
    for (role, sample) in held {
        let reader_before: BTreeMap<String, u64> = crate::private_observer_session::strict_json(
            sample_leaf(sample, "reader-namespaces-before.json")?,
            4096,
        )?;
        let reader_after: BTreeMap<String, u64> = crate::private_observer_session::strict_json(
            sample_leaf(sample, "reader-namespaces-after.json")?,
            4096,
        )?;
        if reader_before != reader_after
            || reader_before.len() != 3
            || ["pid", "net", "mnt"]
                .iter()
                .any(|name| reader_before.get(*name).is_none_or(|inode| *inode == 0))
        {
            return fail("source original reader private namespace inventory changed");
        }
        if !matches!(
            *role,
            "target" | "child" | "thread" | "guardian" | "frontend" | "namespace-init" | "helper"
        ) {
            return fail("source retirement role is not closed");
        }
        for sampled in &sample.tasks {
            let exits = events
                .iter()
                .filter(|event| {
                    event.kind == 8
                        && event.task.tid == sampled.tid
                        && event.task.tgid == sampled.tgid
                        && clock.matches(
                            crate::private_kernel_observer::KernelTaskIdentityV1 {
                                pid: event.task.tid,
                                start_time: event.task.start_boottime_ns,
                                cgroup_inode: event.task.cgroup_inode,
                                time_ns_inode: event.task.time_ns_inode,
                            },
                            sampled.start_time_ticks,
                        )
                })
                .collect::<Vec<_>>();
            if exits.len() != 1 {
                return fail("source sampled task exact exit absent or duplicated");
            }
            let exit = exits[0];
            let reap = events
                .iter()
                .find(|event| {
                    event.kind == 9
                        && event.other_tid == exit.task.tid
                        && event.syscall_result > 0
                        && event.syscall_result as u64 == exit.task.start_boottime_ns
                        && event.sequence > exit.sequence
                })
                .ok_or_else(|| CiError::Message("source exact victim reap absent".into()))?;
            if tasks
                .insert(
                    sampled.tid,
                    TaskRetirementV1 {
                        task: task(exit),
                        role: (*role).into(),
                        live_monotonic_ns: sample.end_monotonic_ns,
                        exit_sequence: exit.sequence,
                        reap_sequence: reap.sequence,
                        terminal_source_path: None,
                    },
                )
                .is_some()
            {
                return fail("source retirement task is duplicated across roles");
            }
            for name in ["pid", "net", "mnt"] {
                let inode = sampled
                    .namespace_inodes
                    .get(name)
                    .copied()
                    .filter(|inode| *inode != 0)
                    .ok_or_else(|| {
                        CiError::Message("source owned private namespace role absent".into())
                    })?;
                if reader_before.get(name) == Some(&inode) {
                    continue;
                }
                namespaces.entry(inode).or_default().insert(sampled.tid);
            }
        }
    }
    let closes: Vec<PublicNamespaceCloseV1> =
        crate::private_observer_session::strict_json(close_bytes, 1024 * 1024)?;
    let namespace_facts = namespaces
        .into_iter()
        .map(|(inode, owners)| {
            let matching = closes
                .iter()
                .filter(|close| close.inode == inode)
                .collect::<Vec<_>>();
            if matching.is_empty() {
                return fail("source held namespace actual close record absent");
            }
            let mut sequences = Vec::new();
            let mut last = 0;
            let mut descriptors = BTreeSet::new();
            for close in matching {
                if close.before_close_monotonic_ns > close.after_close_monotonic_ns
                    || close.fd < 0
                    || !descriptors.insert((close.observer_pid, close.fd))
                    || close.observer_pid != clock_inputs.reader_pid
                {
                    return fail("source namespace close clock order differs");
                }
                let matched = events
                    .iter()
                    .filter(|event| {
                        event.kind == 10
                            && event.task.tgid == close.observer_pid
                            && event.image_inode == inode
                            && event.syscall_result == 0
                            && event.monotonic_ns >= close.before_close_monotonic_ns
                            && event.monotonic_ns <= close.after_close_monotonic_ns
                    })
                    .collect::<Vec<_>>();
                let [event] = matched.as_slice() else {
                    return fail("source observer successful namespace close absent or ambiguous");
                };
                let entries = events
                    .iter()
                    .filter(|entry| {
                        entry.kind == 11
                            && entry.task == event.task
                            && matches!(
                                (entry.syscall_arch, entry.syscall_nr),
                                (0xc000003e, 3) | (0xc00000b7, 57)
                            )
                            && entry.args[0] == close.fd as u64
                            && entry.sequence < event.sequence
                            && entry.monotonic_ns >= close.before_close_monotonic_ns
                            && entry.monotonic_ns <= close.after_close_monotonic_ns
                    })
                    .collect::<Vec<_>>();
                let [entry] = entries.as_slice() else {
                    return fail("source namespace close lacks exact typed observer FD entry");
                };
                let returns = events
                    .iter()
                    .filter(|ret| {
                        ret.kind == 5
                            && ret.task == entry.task
                            && ret.syscall_arch == entry.syscall_arch
                            && ret.syscall_nr == entry.syscall_nr
                            && ret.syscall_occurrence == entry.syscall_occurrence
                            && ret.args == entry.args
                            && ret.syscall_result == 0
                            && ret.sequence > event.sequence
                            && ret.monotonic_ns <= close.after_close_monotonic_ns
                    })
                    .collect::<Vec<_>>();
                if returns.len() != 1 {
                    return fail("source namespace close lacks exact successful close return");
                }
                sequences.push(event.sequence);
                last = last.max(close.after_close_monotonic_ns);
            }
            sequences.sort_unstable();
            sequences.dedup();
            Ok(NamespaceRetirementV1 {
                inode,
                owning_tids: owners.into_iter().collect(),
                observer_close_sequences: sequences,
                last_holder_close_monotonic_ns: last,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let cgroups = cgroup_bytes
        .iter()
        .map(|bytes| {
            let raw: CgroupRetirementSourceV1 =
                crate::private_observer_session::strict_json(bytes, 64 * 1024)?;
            if raw.schema_version != 1
                || !std::path::Path::new(&raw.path).is_absolute()
                || raw.inode == 0
                || !raw.last_members.is_empty()
                || raw.empty_monotonic_ns == 0
                || raw.removed_monotonic_ns < raw.empty_monotonic_ns
            {
                return fail("source actual cgroup removal observation differs");
            }
            Ok(CgroupRetirementV1 {
                inode: raw.inode,
                last_members: raw.last_members,
                empty_monotonic_ns: raw.empty_monotonic_ns,
                removed_monotonic_ns: raw.removed_monotonic_ns,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if tasks.is_empty()
        || cgroups.is_empty()
        || namespace_facts.is_empty()
        || tasks
            .values()
            .filter(|task| !matches!(task.role.as_str(), "guardian" | "frontend"))
            .any(|task| {
                !cgroups
                    .iter()
                    .any(|group| group.inode == task.task.cgroup_inode)
            })
    {
        return fail("source complete retirement inventory is missing a task/cgroup/namespace");
    }
    Ok(CaseFactV1::Retirement {
        tasks: tasks.into_values().collect(),
        cgroups,
        namespaces: namespace_facts,
        terminal_path,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFdV1 {
    fd: u32,
    link: String,
    device: u64,
    inode: u64,
    mode: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSocketTypeV1 {
    inode: u64,
    socket_type: i32,
    domain: i32,
}
fn descriptors(sample: &HeldPublicTargetSamplesV1) -> Result<Vec<DescriptorV1>> {
    let prefix = std::path::Path::new("tasks")
        .join(sample.pid.to_string())
        .join("fds");
    let prefix = prefix.to_string_lossy().into_owned();
    let mut result = BTreeMap::new();
    for (path, bytes) in &sample.leaves {
        let Some(rest) = path
            .strip_prefix(&prefix)
            .and_then(|rest| rest.strip_prefix('/'))
        else {
            continue;
        };
        let Some((number, "identity.json")) = rest.split_once('/') else {
            continue;
        };
        let number: u32 = number
            .parse()
            .map_err(|_| CiError::Message("source fd path number differs".into()))?;
        let raw: RawFdV1 = crate::private_observer_session::strict_json(bytes, 4096)?;
        let info_path = std::path::Path::new(path)
            .parent()
            .expect("fd identity has parent")
            .join("fdinfo.raw");
        let info = text(sample_leaf(sample, &info_path.to_string_lossy())?)?;
        let flags = u64::from_str_radix(field(info, "flags:")?, 8)
            .map_err(|_| CiError::Message("source fd flags differ".into()))?;
        if raw.fd != number || raw.inode == 0 || numbers(info, "ino:")? != [raw.inode] {
            return fail("source descriptor raw inode/path identity differs");
        }
        let kind = match raw.mode & 0o170000 {
            0o010000 if raw.link.starts_with("pipe:[") => "pipe",
            0o140000 if raw.link.starts_with("socket:[") && number == 3 => {
                let source_path = std::path::Path::new(path)
                    .parent()
                    .expect("fd identity has parent")
                    .join("socket-type.json");
                let source: RawSocketTypeV1 = crate::private_observer_session::strict_json(
                    sample_leaf(sample, &source_path.to_string_lossy())?,
                    4096,
                )?;
                if source.inode != raw.inode || source.socket_type != 5 || source.domain != 1 {
                    return fail("source fd3 actual SO_TYPE/SO_DOMAIN differs");
                }
                "unix-seqpacket"
            }
            0o100000
                if number == 4
                    && raw.device == sample.executable_device
                    && raw.inode == sample.executable_inode =>
            {
                "regular-pinned-image"
            }
            _ => return fail("source descriptor role/object type differs"),
        };
        let access = match flags & 3 {
            0 => "read",
            1 => "write",
            2 => "read-write",
            _ => return fail("source fd access flags invalid"),
        };
        if result
            .insert(
                number,
                DescriptorV1 {
                    fd: number,
                    kind: kind.into(),
                    object_inode: raw.inode,
                    flags,
                    access: access.into(),
                },
            )
            .is_some()
        {
            return fail("source descriptor duplicated");
        }
    }
    Ok(result.into_values().collect())
}
fn sample_leaf<'a>(sample: &'a HeldPublicTargetSamplesV1, path: &str) -> Result<&'a [u8]> {
    sample
        .leaves
        .get(path)
        .map(Vec::as_slice)
        .ok_or_else(|| CiError::Message("source sample required raw leaf absent".into()))
}
fn task(event: &KernelEventRecordV2) -> ReplayTaskV1 {
    ReplayTaskV1 {
        tid: event.task.tid,
        tgid: event.task.tgid,
        start_boottime_ns: event.task.start_boottime_ns,
        cgroup_inode: event.task.cgroup_inode,
        time_ns_inode: event.task.time_ns_inode,
    }
}
fn same(task: &ReplayTaskV1, event: &KernelEventRecordV2) -> bool {
    task == &self::task(event)
}
fn text(bytes: &[u8]) -> Result<&str> {
    std::str::from_utf8(bytes).map_err(|_| CiError::Message("source proc bytes not UTF-8".into()))
}
fn field<'a>(text: &'a str, key: &str) -> Result<&'a str> {
    let fields = text
        .lines()
        .filter_map(|line| line.strip_prefix(key))
        .collect::<Vec<_>>();
    if fields.len() != 1 {
        return fail("source proc field absent or duplicated");
    }
    Ok(fields[0].trim())
}
fn numbers(text: &str, key: &str) -> Result<Vec<u64>> {
    field(text, key)?
        .split_whitespace()
        .map(|value| {
            value
                .parse()
                .map_err(|_| CiError::Message("source proc numeric field differs".into()))
        })
        .collect()
}
fn fixed_numbers<const N: usize>(text: &str, key: &str) -> Result<[u32; N]> {
    numbers(text, key)?
        .into_iter()
        .map(|value| {
            u32::try_from(value)
                .map_err(|_| CiError::Message("source proc value exceeds u32".into()))
        })
        .collect::<Result<Vec<_>>>()?
        .try_into()
        .map_err(|_| CiError::Message("source proc field arity differs".into()))
}
fn fail<T>(message: &str) -> Result<T> {
    Err(CiError::Message(message.into()))
}
