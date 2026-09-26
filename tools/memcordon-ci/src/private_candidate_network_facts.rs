//! Exact held endpoint and target-network sources. These parsers never open
//! the verifier's /proc and never derive a successful action from a selector.
use crate::private_candidate_replay::{CaseFactV1, ReplayTaskV1, SocketV1};
use crate::private_case_semantics::{CaseFactKindV1, NativeOperationV1, native_syscall_number};
use crate::private_kernel_replay::KernelEventRecordV2;
use crate::private_process_clock::{ParsedProcClockCalibrationV1, ProcClockInputsV1};
use crate::private_protected_readback::StructuralProtectedNativeCaseV1;
use crate::private_public_live::HeldPublicTargetSamplesV1;
use crate::{CiError, Result};
use memcordon_core::private_release_case_v1::PrivateReleaseCaseResultV1;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) struct CandidateNetworkPathsV1 {
    pub(crate) raw_leaves: BTreeMap<String, Vec<u8>>,
    /// Original protected native request.json, not a manufactured 32-byte leaf.
    pub(crate) request_path: String,
    pub(crate) response_path: String,
    pub(crate) held_sample_path: String,
    pub(crate) host_sample_path: String,
    pub(crate) init_sample_path: Option<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeNetworkSourcesV1 {
    pub(crate) result_path: String,
    pub(crate) request_path: String,
    pub(crate) response_path: String,
    pub(crate) held_sample_path: String,
    pub(crate) host_sample_path: String,
    pub(crate) init_sample_path: Option<String>,
}
fn fail<T>(message: &str) -> Result<T> {
    Err(CiError::Message(message.into()))
}
fn raw<'a>(sample: &'a HeldPublicTargetSamplesV1, path: &str) -> Result<&'a [u8]> {
    sample
        .leaves
        .get(path)
        .map(Vec::as_slice)
        .ok_or_else(|| CiError::Message(format!("held network source absent: {path}")))
}
pub(crate) fn matches(task: &ReplayTaskV1, event: &KernelEventRecordV2) -> bool {
    task.tid == event.task.tid
        && task.tgid == event.task.tgid
        && task.start_boottime_ns == event.task.start_boottime_ns
        && task.cgroup_inode == event.task.cgroup_inode
        && task.time_ns_inode == event.task.time_ns_inode
}
fn held_matches(
    sample: &HeldPublicTargetSamplesV1,
    task: &ReplayTaskV1,
    clock: &ProcClockInputsV1,
) -> Result<()> {
    if sample.schema_version != 1
        || sample.pid != task.tid
        || sample.begin_monotonic_ns == 0
        || sample.end_monotonic_ns < sample.begin_monotonic_ns
        || !ParsedProcClockCalibrationV1::parse(clock)?.matches(
            crate::private_kernel_observer::KernelTaskIdentityV1 {
                pid: task.tid,
                start_time: task.start_boottime_ns,
                cgroup_inode: task.cgroup_inode,
                time_ns_inode: task.time_ns_inode,
            },
            sample.start_time_ticks,
        )
    {
        return fail("held network original task/clock differs");
    }
    validate_held_proc_identity(sample)
}
pub(crate) fn validate_held_proc_identity(sample: &HeldPublicTargetSamplesV1) -> Result<()> {
    for path in ["stat-before.raw", "stat-after.raw"] {
        let text = std::str::from_utf8(raw(sample, path)?)
            .map_err(|_| CiError::Message("held network stat not text".into()))?;
        let (pid, tail) = text
            .split_once(' ')
            .ok_or_else(|| CiError::Message("held network stat PID absent".into()))?;
        let (_, fields) = tail
            .rsplit_once(") ")
            .ok_or_else(|| CiError::Message("held network stat fields absent".into()))?;
        if pid.parse::<u32>().ok() != Some(sample.pid)
            || fields
                .split_whitespace()
                .nth(19)
                .and_then(|word| word.parse::<u64>().ok())
                != Some(sample.start_time_ticks)
        {
            return fail("held network original proc PID/start differs");
        }
    }
    Ok(())
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedTcpRowV1 {
    pub local_address: u32,
    pub local_port: u16,
    pub remote_address: u32,
    pub remote_port: u16,
    pub state: u8,
    pub inode: u64,
}
/// Diagnostic parser only. A row cannot qualify an endpoint without actual
/// held FD, task/namespace and syscall occurrence joins below.
pub fn parse_held_tcp_table(bytes: &[u8]) -> Result<Vec<ParsedTcpRowV1>> {
    if bytes.len() > 1024 * 1024 {
        return fail("TCP table exceeds reviewed bound");
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| CiError::Message("TCP table is not text".into()))?;
    let mut lines = text.lines();
    let header = lines
        .next()
        .ok_or_else(|| CiError::Message("TCP table header absent".into()))?;
    if !header.split_whitespace().eq([
        "sl",
        "local_address",
        "rem_address",
        "st",
        "tx_queue",
        "rx_queue",
        "tr",
        "tm->when",
        "retrnsmt",
        "uid",
        "timeout",
        "inode",
    ]) {
        return fail("TCP table header differs");
    }
    let mut rows = Vec::new();
    let mut inodes = BTreeSet::new();
    for line in lines {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 10 || rows.len() >= 1024 {
            return fail("TCP row shape/count differs");
        }
        let endpoint = |word: &str| -> Result<(u32, u16)> {
            let (address, port) = word
                .split_once(':')
                .ok_or_else(|| CiError::Message("TCP endpoint separator absent".into()))?;
            if address.len() != 8 || port.len() != 4 {
                return fail("TCP endpoint width differs");
            }
            Ok((
                u32::from_str_radix(address, 16)
                    .map_err(|_| CiError::Message("TCP address differs".into()))?,
                u16::from_str_radix(port, 16)
                    .map_err(|_| CiError::Message("TCP port differs".into()))?,
            ))
        };
        let (local_address, local_port) = endpoint(fields[1])?;
        let (remote_address, remote_port) = endpoint(fields[2])?;
        let state = u8::from_str_radix(fields[3], 16)
            .map_err(|_| CiError::Message("TCP state differs".into()))?;
        let inode = fields[9]
            .parse()
            .map_err(|_| CiError::Message("TCP inode differs".into()))?;
        // TIME_WAIT legitimately has inode0; it cannot be an owned endpoint.
        if inode != 0 && !inodes.insert(inode) {
            return fail("TCP socket inode duplicated");
        }
        rows.push(ParsedTcpRowV1 {
            local_address,
            local_port,
            remote_address,
            remote_port,
            state,
            inode,
        });
    }
    Ok(rows)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fd {
    fd: u32,
    link: String,
    device: u64,
    inode: u64,
    mode: u32,
}
pub(crate) fn socket_fds(sample: &HeldPublicTargetSamplesV1) -> Result<BTreeMap<u64, u32>> {
    let prefix = std::path::Path::new("tasks")
        .join(sample.pid.to_string())
        .join("fds");
    let mut result = BTreeMap::new();
    for (path, bytes) in &sample.leaves {
        let path = std::path::Path::new(path);
        if path.file_name().and_then(|s| s.to_str()) != Some("identity.json")
            || !path.starts_with(&prefix)
        {
            continue;
        }
        let fd: Fd = crate::private_observer_session::strict_json(bytes, 4096)?;
        if fd.mode & 0o170000 != 0o140000 {
            continue;
        }
        let inode = fd
            .link
            .strip_prefix("socket:[")
            .and_then(|s| s.strip_suffix(']'))
            .ok_or_else(|| CiError::Message("held socket FD link differs".into()))?
            .parse::<u64>()
            .map_err(|_| CiError::Message("held socket inode link differs".into()))?;
        if inode == 0
            || inode != fd.inode
            || fd.device == 0
            || path
                .parent()
                .and_then(std::path::Path::file_name)
                .and_then(|s| s.to_str())
                .and_then(|s| s.parse::<u32>().ok())
                != Some(fd.fd)
            || result.insert(inode, fd.fd).is_some()
        {
            return fail("held socket FD object/number differs");
        }
    }
    Ok(result)
}
pub(crate) fn returned<'a>(
    events: &'a [KernelEventRecordV2],
    entry: &KernelEventRecordV2,
) -> Result<&'a KernelEventRecordV2> {
    let found = events
        .iter()
        .filter(|event| {
            event.kind == 5
                && event.task == entry.task
                && event.syscall_occurrence == entry.syscall_occurrence
                && event.syscall_nr == entry.syscall_nr
                && event.syscall_arch == entry.syscall_arch
                && event.args == entry.args
                && event.sequence > entry.sequence
        })
        .collect::<Vec<_>>();
    match found.as_slice() {
        [event] => Ok(*event),
        _ => fail("network syscall lacks exact entry/return occurrence"),
    }
}
fn successful<'a>(
    events: &'a [KernelEventRecordV2],
    task: &ReplayTaskV1,
    nr: i64,
    fd: u32,
    before: u64,
) -> Result<&'a KernelEventRecordV2> {
    let found = events
        .iter()
        .filter(|event| {
            event.kind == 4
                && matches(task, event)
                && event.syscall_nr == nr
                && event.args[0] == fd as u64
                && event.seccomp_action == 0x7fff0000
                && event.monotonic_ns < before
        })
        .filter_map(|entry| {
            returned(events, entry)
                .ok()
                .filter(|ret| ret.syscall_result == 0)
                .map(|_| entry)
        })
        .collect::<Vec<_>>();
    match found.as_slice() {
        [event] => Ok(*event),
        _ => fail("network actual successful FD operation absent/ambiguous"),
    }
}
pub(crate) fn checked_loopback_operand(event: &KernelEventRecordV2, port: u16) -> bool {
    event.network_address.as_ref().is_some_and(|address| {
        address.family == 2
            && address.length == 16
            && address.address == [127, 0, 0, 1]
            && address.port == port
    })
}

pub(crate) fn validate_socket_lifetime(
    events: &[KernelEventRecordV2],
    task: &ReplayTaskV1,
    operation: &KernelEventRecordV2,
    held_end: u64,
) -> Result<()> {
    let creation = events
        .iter()
        .rev()
        .find(|entry| {
            entry.kind == 4
                && matches(task, entry)
                && matches!(
                    (entry.syscall_arch, entry.syscall_nr),
                    (0xc000003e, 41) | (0xc00000b7, 198)
                )
                && entry.sequence < operation.sequence
                && returned(events, entry)
                    .is_ok_and(|ret| ret.syscall_result == operation.args[0] as i64)
        })
        .ok_or_else(|| CiError::Message("actual socket creation for held FD absent".into()))?;
    if creation.seccomp_action != 0x7fff0000
        || creation.args[0] != 2
        || creation.args[1] & !(0x80000 | 0x800) != 1
        || !matches!(creation.args[2], 0 | 6)
        || events.iter().any(|event| {
            event.kind == 5
                && matches(task, event)
                && matches!(event.syscall_nr, 3 | 57)
                && event.args[0] == operation.args[0]
                && event.syscall_result == 0
                && event.sequence > creation.sequence
                && event.monotonic_ns <= held_end
        })
    {
        return fail("socket creation operands/FD lifetime differ");
    }
    Ok(())
}

pub(crate) fn validate_held_tcp_endpoints(
    sample: &HeldPublicTargetSamplesV1,
    task: &ReplayTaskV1,
    events: &[KernelEventRecordV2],
    target: &str,
    port: u16,
) -> Result<(SocketV1, SocketV1)> {
    validate_held_proc_identity(sample)?;
    let own = sample
        .tasks
        .iter()
        .find(|candidate| candidate.tid == task.tid)
        .ok_or_else(|| CiError::Message("network target task namespace source absent".into()))?;
    let netns = *own
        .namespace_inodes
        .get("net")
        .ok_or_else(|| CiError::Message("network namespace absent".into()))?;
    let rows = parse_held_tcp_table(raw(sample, "net-tcp.raw")?)?;
    let fds = socket_fds(sample)?;
    let find = |predicate: &dyn Fn(&ParsedTcpRowV1) -> bool| -> Result<&ParsedTcpRowV1> {
        let found = rows
            .iter()
            .filter(|row| row.inode != 0 && fds.contains_key(&row.inode) && predicate(row))
            .collect::<Vec<_>>();
        match found.as_slice() {
            [row] => Ok(*row),
            _ => fail("held TCP endpoint absent/ambiguous"),
        }
    };
    let listener = find(&|row| {
        row.state == 10
            && row.local_address == 0x0100007f
            && row.local_port == port
            && row.remote_address == 0
            && row.remote_port == 0
    })?;
    let connector = find(&|row| {
        row.state == 1
            && row.local_address == 0x0100007f
            && row.remote_address == 0x0100007f
            && row.remote_port == port
            && row.local_port != port
    })?;
    let listen_fd = fds[&listener.inode];
    let connect_fd = fds[&connector.inode];
    let bind = successful(
        events,
        task,
        native_syscall_number(target, NativeOperationV1::Bind)?,
        listen_fd,
        sample.begin_monotonic_ns,
    )?;
    let listen = successful(
        events,
        task,
        native_syscall_number(target, NativeOperationV1::Listen)?,
        listen_fd,
        sample.begin_monotonic_ns,
    )?;
    let connect = successful(
        events,
        task,
        native_syscall_number(target, NativeOperationV1::Connect)?,
        connect_fd,
        sample.begin_monotonic_ns,
    )?;
    if !checked_loopback_operand(bind, port) || !checked_loopback_operand(connect, port) {
        return fail("reviewed checked bind/connect sockaddr evidence absent or differs");
    }
    validate_socket_lifetime(events, task, bind, sample.end_monotonic_ns)?;
    validate_socket_lifetime(events, task, connect, sample.end_monotonic_ns)?;
    if bind.sequence >= listen.sequence
        || listen.sequence >= connect.sequence
        || netns == 0
        || listener.inode == connector.inode
    {
        return fail("actual TCP lifecycle order/object differs");
    }
    for (fd, begin) in [
        (listen_fd, bind.monotonic_ns),
        (connect_fd, connect.monotonic_ns),
    ] {
        if events.iter().any(|event| {
            matches(task, event)
                && event.kind == 5
                && matches!(event.syscall_nr, 3 | 57)
                && event.args[0] == fd as u64
                && event.syscall_result == 0
                && event.monotonic_ns > begin
                && event.monotonic_ns <= sample.end_monotonic_ns
        }) {
            return fail("held TCP FD closed before sampled object join");
        }
    }
    // The connector must actually send and receive the fresh32-byte payload
    // before the held response, not merely have an ESTABLISHED table row.
    for nr in if target == "x86_64-unknown-linux-gnu" {
        [44, 45]
    } else {
        [206, 207]
    } {
        if !events.iter().any(|entry| {
            entry.kind == 4
                && matches(task, entry)
                && entry.syscall_nr == nr
                && entry.args[0] == connect_fd as u64
                && entry.args[2] == 32
                && entry.seccomp_action == 0x7fff0000
                && entry.sequence > connect.sequence
                && entry.monotonic_ns < sample.begin_monotonic_ns
                && returned(events, entry).is_ok_and(|ret| ret.syscall_result == 32)
        }) {
            return fail("actual held TCP fresh send/receive occurrence absent");
        }
    }
    let socket = |row: &ParsedTcpRowV1, state: &str| SocketV1 {
        task: task.clone(),
        socket_inode: row.inode,
        netns_inode: netns,
        address: "127.0.0.1".into(),
        port,
        state: state.into(),
    };
    Ok((socket(listener, "listen"), socket(connector, "established")))
}

pub(crate) fn validate_held_tcp_exchange_after(
    sample: &HeldPublicTargetSamplesV1,
    task: &ReplayTaskV1,
    events: &[KernelEventRecordV2],
    target: &str,
    inode: u64,
    begin: u64,
    end: u64,
) -> Result<()> {
    let fds = socket_fds(sample)?;
    let fd = fds
        .get(&inode)
        .ok_or_else(|| CiError::Message("post-R1 connector FD absent".into()))?;
    let numbers = if target == "x86_64-unknown-linux-gnu" {
        [44, 45]
    } else {
        [206, 207]
    };
    let mut previous = 0;
    for nr in numbers {
        let occurrences = events
            .iter()
            .filter(|entry| {
                entry.kind == 4
                    && matches(task, entry)
                    && entry.syscall_nr == nr
                    && entry.seccomp_action == 0x7fff0000
                    && entry.args[0] == *fd as u64
                    && entry.args[2] == 32
                    && entry.monotonic_ns > begin
                    && entry.monotonic_ns < end
                    && entry.sequence > previous
                    && returned(events, entry)
                        .is_ok_and(|ret| ret.syscall_result == 32 && ret.monotonic_ns < end)
            })
            .collect::<Vec<_>>();
        let [entry] = occurrences.as_slice() else {
            return fail("post-R1 actual second TCP exchange absent/ambiguous");
        };
        previous = entry.sequence;
    }
    Ok(())
}

pub(crate) fn record_candidate_network_facts(
    raw_case: &StructuralProtectedNativeCaseV1,
    events: &[KernelEventRecordV2],
    clock: &ProcClockInputsV1,
    target: &ReplayTaskV1,
    held: &[(&str, &HeldPublicTargetSamplesV1)],
    paths: &CandidateNetworkPathsV1,
) -> Result<Vec<CaseFactV1>> {
    let target_triple = raw_case.result.target.as_str();
    let spec = crate::private_case_semantics::closed_candidate_case_spec(
        &raw_case.result.selector,
        target_triple,
    )?;
    let families = spec
        .facts
        .iter()
        .copied()
        .filter(|kind| {
            matches!(
                kind,
                CaseFactKindV1::Tcp | CaseFactKindV1::Collision | CaseFactKindV1::Topology
            )
        })
        .collect::<Vec<_>>();
    if families.is_empty() {
        return Ok(Vec::new());
    }
    let sources = NativeNetworkSourcesV1 {
        result_path: std::path::Path::new(&paths.request_path)
            .with_file_name("result.json")
            .to_string_lossy()
            .into_owned(),
        request_path: paths.request_path.clone(),
        response_path: paths.response_path.clone(),
        held_sample_path: paths.held_sample_path.clone(),
        host_sample_path: paths.host_sample_path.clone(),
        init_sample_path: paths.init_sample_path.clone(),
    };
    let (_, sample) = held
        .iter()
        .find(|(path, _)| *path == sources.held_sample_path)
        .ok_or_else(|| CiError::Message("network exact held source path absent".into()))?;
    held_matches(sample, target, clock)?;
    let leaf = |path: &str| {
        paths
            .raw_leaves
            .get(path)
            .map(Vec::as_slice)
            .ok_or_else(|| {
                CiError::Message(format!("original candidate network leaf absent: {path}"))
            })
    };
    for family in &families {
        verify_native_network_sources(&sources, *family, target, events, clock, leaf)?;
    }
    Ok(families
        .into_iter()
        .map(|family| CaseFactV1::NativeNetworkV1 {
            family,
            sources: sources.clone(),
        })
        .collect())
}

pub(crate) fn verify_native_network_sources<'a>(
    sources: &NativeNetworkSourcesV1,
    family: CaseFactKindV1,
    target: &ReplayTaskV1,
    events: &[KernelEventRecordV2],
    clock: &ProcClockInputsV1,
    leaf: impl Fn(&str) -> Result<&'a [u8]>,
) -> Result<PrivateReleaseCaseResultV1> {
    let result =
        PrivateReleaseCaseResultV1::parse(leaf(&sources.result_path)?).map_err(CiError::Message)?;
    let key = result.result_key().map_err(CiError::Message)?;
    let challenge = result.challenge_bytes().map_err(CiError::Message)?;
    crate::private_protected_readback::parse_protected_candidate_request(
        leaf(&sources.request_path)?,
        &result.selector,
        challenge,
        &key,
    )?;
    if !matches!(result.installed,memcordon_core::private_release_case_v1::PrivateReleaseInstalledBindingV1::CandidateCapability{..}){return fail("network source stage differs");}
    let triple = result.target.as_str();
    let sample = crate::private_source_carrier::decode_held_source(
        leaf(&sources.held_sample_path)?,
        |path| leaf(path).map(ToOwned::to_owned),
    )?;
    held_matches(&sample, target, clock)?;
    let namespace = sample
        .tasks
        .iter()
        .find(|task| task.tid == target.tid)
        .and_then(|task| task.namespace_inodes.get("net"))
        .copied()
        .ok_or_else(|| CiError::Message("held target network namespace absent".into()))?;
    let expected = memcordon_core::private_release_case_v1::candidate_fixture_expected_response_v1(
        triple,
        &result.selector,
        &challenge,
        Some(namespace),
        Some((sample.executable_device, sample.executable_inode)),
    )
    .map_err(|message| CiError::Message(message.into()))?;
    if leaf(&sources.response_path)? != expected {
        return fail("actual held response differs from protected fresh fixture codec");
    }
    match family {
        CaseFactKindV1::Tcp => {
            validate_held_tcp_endpoints(
                &sample,
                target,
                events,
                triple,
                memcordon_core::private_release_case_v1::candidate_fixture_port_v1(&challenge),
            )?;
        }
        CaseFactKindV1::Collision => {
            let (listener, _) = validate_held_tcp_endpoints(
                &sample,
                target,
                events,
                triple,
                memcordon_core::private_release_case_v1::candidate_fixture_port_v1(&challenge),
            )?;
            let nr = native_syscall_number(triple, NativeOperationV1::Bind)?;
            let denied = events
                .iter()
                .filter(|event| {
                    event.kind == 4
                        && matches(target, event)
                        && event.syscall_nr == nr
                        && event.seccomp_action == 0x7fff0000
                        && event.monotonic_ns < sample.begin_monotonic_ns
                        && returned(events, event).is_ok_and(|ret| ret.syscall_result == -98)
                })
                .collect::<Vec<_>>();
            let [denied] = denied.as_slice() else {
                return fail("actual same-namespace collision occurrence absent/ambiguous");
            };
            let fds = socket_fds(&sample)?;
            let listener_fd = fds[&listener.socket_inode];
            if denied.args[0] == listener_fd as u64
                || !checked_loopback_operand(denied, listener.port)
            {
                return fail("collision substituted live listener fd");
            }
            let free = events
                .iter()
                .filter(|entry| {
                    entry.kind == 4
                        && matches(target, entry)
                        && entry.syscall_nr == nr
                        && entry.seccomp_action == 0x7fff0000
                        && entry.sequence > denied.sequence
                        && entry.args[0] != listener_fd as u64
                        && checked_loopback_operand(entry, 0)
                        && entry.monotonic_ns < sample.begin_monotonic_ns
                        && returned(events, entry).is_ok_and(|ret| ret.syscall_result == 0)
                })
                .collect::<Vec<_>>();
            let [free] = free.as_slice() else {
                return fail("actual collision free-bind control absent/ambiguous");
            };
            validate_socket_lifetime(events, target, free, sample.end_monotonic_ns)?;
            let rows = parse_held_tcp_table(raw(&sample, "net-tcp.raw")?)?;
            if !rows.iter().any(|row| {
                row.state == 10
                    && row.local_address == 0x0100007f
                    && row.local_port != listener.port
                    && fds
                        .get(&row.inode)
                        .is_some_and(|fd| *fd as u64 == free.args[0])
            }) {
                return fail("actual free-bind endpoint object absent");
            }
        }
        CaseFactKindV1::Topology => {
            verify_topology_sources(&sample, target, events, clock, sources, &result, &leaf)?
        }
        _ => return fail("native network wrapper family is not closed"),
    }
    Ok(result)
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TopologyInitIdentityV1 {
    pub pid: u32,
    pub start_time_ticks: u64,
}

fn verify_topology_sources<'a>(
    sample: &HeldPublicTargetSamplesV1,
    target: &ReplayTaskV1,
    events: &[KernelEventRecordV2],
    clock: &ProcClockInputsV1,
    sources: &NativeNetworkSourcesV1,
    result: &PrivateReleaseCaseResultV1,
    leaf: &impl Fn(&str) -> Result<&'a [u8]>,
) -> Result<()> {
    let host = crate::private_source_carrier::decode_held_source(
        leaf(&sources.host_sample_path)?,
        |path| leaf(path).map(ToOwned::to_owned),
    )?;
    let init_path = sources
        .init_sample_path
        .as_ref()
        .ok_or_else(|| CiError::Message("independent held namespace-init source absent".into()))?;
    let init = crate::private_source_carrier::decode_held_source(leaf(init_path)?, |path| {
        leaf(path).map(ToOwned::to_owned)
    })?;
    let request = crate::private_protected_readback::parse_protected_candidate_request(
        leaf(&sources.request_path)?,
        &result.selector,
        result.challenge_bytes().map_err(CiError::Message)?,
        &result.result_key().map_err(CiError::Message)?,
    )?;
    let attempt_path = std::path::Path::new(&sources.result_path).with_file_name("attempt.json");
    let attempt = crate::private_protected_readback::parse_protected_candidate_attempt(
        leaf(
            attempt_path
                .to_str()
                .ok_or_else(|| CiError::Message("topology attempt path not UTF8".into()))?,
        )?,
        &request,
        &result.observation,
        result.challenge_bytes().map_err(CiError::Message)?,
    )?;
    let roles = attempt
        .terminal_processes()
        .ok_or_else(|| CiError::Message("topology durable process roles absent".into()))?;
    validate_held_topology_sources(
        sample,
        target,
        events,
        clock,
        &host,
        &init,
        &TopologyInitIdentityV1 {
            pid: roles[1].pid,
            start_time_ticks: roles[1].start_time,
        },
    )
}

/// Stage-neutral original source predicate. The caller must separately bind
/// expected_init to the original authenticated durable process role; this pure
/// function cannot create that role or an observer-origin capability.
pub(crate) fn validate_held_topology_sources(
    sample: &HeldPublicTargetSamplesV1,
    target: &ReplayTaskV1,
    events: &[KernelEventRecordV2],
    clock: &ProcClockInputsV1,
    host: &HeldPublicTargetSamplesV1,
    init: &HeldPublicTargetSamplesV1,
    expected_init: &TopologyInitIdentityV1,
) -> Result<()> {
    held_matches(sample, target, clock)?;
    validate_held_proc_identity(init)?;
    let network: BTreeMap<String, Vec<u8>> = crate::private_observer_session::strict_json(
        raw(sample, "network-source-v1.bin")?,
        8 * 1024 * 1024,
    )?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Identity {
        schema_version: u8,
        target_pid: u32,
        target_start_ticks: u64,
        host_netns_inode: u64,
        target_netns_inode: u64,
        begin_monotonic_ns: u64,
        end_monotonic_ns: u64,
    }
    let get = |name: &str| {
        network
            .get(name)
            .map(Vec::as_slice)
            .ok_or_else(|| CiError::Message(format!("target network source absent: {name}")))
    };
    let identity: Identity =
        crate::private_observer_session::strict_json(get("identity.json")?, 4096)?;
    let own = sample
        .tasks
        .iter()
        .find(|task| task.tid == target.tid)
        .ok_or_else(|| CiError::Message("topology target source absent".into()))?;
    let host_ns: BTreeMap<String, u64> = crate::private_observer_session::strict_json(
        raw(&host, "reader-namespaces-before.json")?,
        4096,
    )?;
    if raw(&host, "reader-namespaces-before.json")? != raw(&host, "reader-namespaces-after.json")?
        || identity.schema_version != 1
        || identity.target_pid != target.tid
        || identity.target_start_ticks != sample.start_time_ticks
        || identity.host_netns_inode == 0
        || identity.host_netns_inode == identity.target_netns_inode
        || host_ns.get("net") != Some(&identity.host_netns_inode)
        || own.namespace_inodes.get("net") != Some(&identity.target_netns_inode)
        || identity.begin_monotonic_ns < sample.begin_monotonic_ns
        || identity.end_monotonic_ns > sample.end_monotonic_ns
        || identity.end_monotonic_ns < identity.begin_monotonic_ns
    {
        return fail("target-network physical context/time differs");
    }
    let stat = |bytes: &[u8]| -> Result<(u32, u64)> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| CiError::Message("topology stat not text".into()))?;
        let (pid, tail) = text
            .split_once(' ')
            .ok_or_else(|| CiError::Message("topology stat PID absent".into()))?;
        let (_, fields) = tail
            .rsplit_once(") ")
            .ok_or_else(|| CiError::Message("topology stat fields absent".into()))?;
        Ok((
            pid.parse()
                .map_err(|_| CiError::Message("topology stat PID malformed".into()))?,
            fields
                .split_whitespace()
                .nth(19)
                .ok_or_else(|| CiError::Message("topology stat start absent".into()))?
                .parse()
                .map_err(|_| CiError::Message("topology stat start malformed".into()))?,
        ))
    };
    if stat(get("target-stat-before.raw")?)? != (sample.pid, sample.start_time_ticks)
        || stat(get("target-stat-after.raw")?)? != (sample.pid, sample.start_time_ticks)
        || stat(get("reader-stat.raw")?)? != stat(get("reader-stat-after.raw")?)?
    {
        return fail("actual network reader/target stable proc identity differs");
    }
    for (name, expected) in [
        ("ip_unprivileged_port_start", "0"),
        ("ip_forward", "0"),
        ("ip_local_port_range", "32768 60999"),
        ("ip_local_reserved_ports", ""),
    ] {
        let value = std::str::from_utf8(get(name)?)
            .map_err(|_| CiError::Message("network sysctl not text".into()))?
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if value != expected {
            return fail("actual target-network sysctl differs");
        }
    }
    validate_private_loopback_dump_v1(&network)?;
    let init_task = init
        .tasks
        .iter()
        .find(|task| task.tid == init.pid)
        .ok_or_else(|| CiError::Message("topology init source task absent".into()))?;
    if init.pid == target.tid
        || init.start_time_ticks == 0
        || ["pid", "net", "mnt"].into_iter().any(|name| {
            own.namespace_inodes.get(name).is_none()
                || own.namespace_inodes.get(name) != init_task.namespace_inodes.get(name)
        })
    {
        return fail("independent topology init/target namespaces differ");
    }
    let nspid = |bytes: &[u8]| -> Result<Vec<u32>> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| CiError::Message("topology status not text".into()))?;
        let fields = text
            .lines()
            .filter_map(|line| line.strip_prefix("NSpid:"))
            .collect::<Vec<_>>();
        let [field] = fields.as_slice() else {
            return fail("topology NSpid field absent/ambiguous");
        };
        field
            .split_whitespace()
            .map(|word| {
                word.parse()
                    .map_err(|_| CiError::Message("topology NSpid differs".into()))
            })
            .collect()
    };
    if nspid(raw(&init, "status.raw")?)?.last() != Some(&1)
        || nspid(raw(sample, "status.raw")?)?
            .last()
            .is_none_or(|pid| *pid == 1)
        || nspid(get("proc1-status.raw")?)? != [1]
    {
        return fail("actual namespace init/private proc PID1 projection differs");
    }
    let proc_mount = |bytes: &[u8]| -> Result<Vec<String>> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| CiError::Message("topology mountinfo not text".into()))?;
        let mut proc = None;
        for line in text.lines() {
            let (before, after) = line
                .split_once(" - ")
                .ok_or_else(|| CiError::Message("topology mountinfo separator absent".into()))?;
            let before = before.split_whitespace().collect::<Vec<_>>();
            let after = after.split_whitespace().collect::<Vec<_>>();
            if before.len() < 6 || after.len() != 3 {
                return fail("topology mountinfo fields differ");
            }
            if before[6..]
                .iter()
                .any(|field| field.starts_with("shared:") || field.starts_with("master:"))
                || after[0] == "cgroup"
                || after[0] == "cgroup2"
            {
                return fail("target mount namespace propagated/cgroup-visible");
            }
            if before[4] == "/proc" {
                if proc.is_some()
                    || before[3] != "/"
                    || after[0] != "proc"
                    || after[1] != "proc"
                    || ["nosuid", "nodev", "noexec"]
                        .iter()
                        .any(|option| !before[5].split(',').any(|value| value == *option))
                {
                    return fail("target private proc mount flags/root/source differ");
                }
                proc = Some(
                    before[..6]
                        .iter()
                        .chain(after.iter())
                        .map(|word| (*word).to_owned())
                        .collect(),
                );
            }
        }
        proc.ok_or_else(|| CiError::Message("target private proc mount absent".into()))
    };
    if proc_mount(raw(sample, "mountinfo.raw")?)? != proc_mount(raw(&init, "mountinfo.raw")?)? {
        return fail("target/init private proc mount identity differs");
    }
    if expected_init.pid != init.pid || expected_init.start_time_ticks != init.start_time_ticks {
        return fail("namespace-init raw role differs from actual durable ownership");
    }
    let calibration = ParsedProcClockCalibrationV1::parse(clock)?;
    let starts = events
        .iter()
        .filter(|event| {
            event.task.tid == init.pid
                && calibration.matches(
                    crate::private_kernel_observer::KernelTaskIdentityV1 {
                        pid: event.task.tid,
                        start_time: event.task.start_boottime_ns,
                        cgroup_inode: event.task.cgroup_inode,
                        time_ns_inode: event.task.time_ns_inode,
                    },
                    init.start_time_ticks,
                )
        })
        .map(|event| {
            (
                event.task.start_boottime_ns,
                event.task.cgroup_inode,
                event.task.time_ns_inode,
            )
        })
        .collect::<BTreeSet<_>>();
    if starts.len() != 1
        || init.begin_monotonic_ns == 0
        || init.end_monotonic_ns < init.begin_monotonic_ns
        || events.iter().any(|event| {
            event.kind == 8
                && event.task.tid == init.pid
                && starts.contains(&(
                    event.task.start_boottime_ns,
                    event.task.cgroup_inode,
                    event.task.time_ns_inode,
                ))
                && event.monotonic_ns <= sample.end_monotonic_ns
        })
    {
        return fail("namespace-init original clock/liveness source differs");
    }
    Ok(())
}

/// Pure diagnostic validation only; custody, task, durable ownership and
/// target-held timing joins remain mandatory for a Topology capability.
pub fn validate_private_loopback_dump_v1(network: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    if network.len() > 256
        || network
            .values()
            .try_fold(0usize, |sum, bytes| sum.checked_add(bytes.len()))
            .is_none_or(|sum| sum > 8 * 1024 * 1024)
    {
        return fail("target network dump exceeds reviewed bound");
    }
    let links = dump_objects(network, "links", 18, 16, 16)?;
    let addresses = dump_objects(network, "addresses", 22, 20, 8)?;
    let routes = dump_objects(network, "routes", 26, 24, 12)?;
    verify_loopback(&links, &addresses, &routes)
}

pub(crate) fn dump_objects(
    network: &BTreeMap<String, Vec<u8>>,
    label: &str,
    request_type: u16,
    response_type: u16,
    body: usize,
) -> Result<Vec<Vec<u8>>> {
    let request = network
        .get(&format!("{label}/request.raw"))
        .ok_or_else(|| CiError::Message("original netlink request absent".into()))?;
    if request.len() != 16 + body
        || u32::from_le_bytes(request[..4].try_into().expect("request header")) as usize
            != request.len()
        || u16::from_le_bytes(request[4..6].try_into().expect("request header")) != request_type
        || u16::from_le_bytes(request[6..8].try_into().expect("request header")) != 0x301
        || request[16..].iter().any(|byte| *byte != 0)
    {
        return fail("original netlink dump request differs");
    }
    let sequence = u32::from_le_bytes(request[8..12].try_into().expect("request header"));
    let port = u32::from_le_bytes(request[12..16].try_into().expect("request header"));
    if sequence == 0 || port == 0 {
        return fail("netlink sequence/port absent");
    }
    let mut objects = Vec::new();
    let mut done = false;
    let mut packets = 0usize;
    for ordinal in 0..64 {
        let Some(packet) = network.get(&format!("{label}/{ordinal}.raw")) else {
            break;
        };
        packets += 1;
        if packet.is_empty() || packet.len() > 8192 || done {
            return fail("netlink packet bounds/trailing data differ");
        }
        let mut cursor = 0;
        while cursor < packet.len() {
            if packet.len() - cursor < 16 {
                return fail("netlink partial header");
            }
            let header = &packet[cursor..cursor + 16];
            let length =
                u32::from_le_bytes(header[..4].try_into().expect("netlink header")) as usize;
            let kind = u16::from_le_bytes(header[4..6].try_into().expect("netlink header"));
            let flags = u16::from_le_bytes(header[6..8].try_into().expect("netlink header"));
            if done
                || length < 16
                || length > packet.len() - cursor
                || u32::from_le_bytes(header[8..12].try_into().expect("netlink header")) != sequence
                || u32::from_le_bytes(header[12..16].try_into().expect("netlink header")) != port
                || flags & 0x10 != 0
            {
                return fail("netlink interrupted/unmatched/trailing message");
            }
            if kind == 3 {
                if length < 20 || packet[cursor + 16..cursor + 20] != [0; 4] {
                    return fail("netlink DONE status differs");
                }
                done = true;
            } else {
                if kind != response_type || flags & 2 == 0 || objects.len() >= 64 {
                    return fail("netlink response type/multipart bound differs");
                }
                objects.push(packet[cursor + 16..cursor + length].to_vec());
            }
            cursor += (length + 3) & !3;
            if cursor > packet.len() {
                return fail("netlink message alignment differs");
            }
        }
    }
    let actual = network
        .keys()
        .filter(|key| key.starts_with(&format!("{label}/")) && !key.ends_with("/request.raw"))
        .count();
    if !done || actual != packets {
        return fail("netlink source inventory lacks exact DONE or ordinal continuity");
    }
    Ok(objects)
}
fn attrs(bytes: &[u8]) -> Result<Vec<(u16, &[u8])>> {
    let mut cursor = 0;
    let mut result = Vec::new();
    while cursor < bytes.len() {
        if bytes.len() - cursor < 4 {
            return fail("netlink attribute partial header");
        }
        let len = u16::from_le_bytes(
            bytes[cursor..cursor + 2]
                .try_into()
                .expect("attribute header"),
        ) as usize;
        let kind = u16::from_le_bytes(
            bytes[cursor + 2..cursor + 4]
                .try_into()
                .expect("attribute header"),
        );
        if len < 4 || len > bytes.len() - cursor {
            return fail("netlink attribute length differs");
        }
        result.push((kind, &bytes[cursor + 4..cursor + len]));
        cursor += (len + 3) & !3;
        if cursor > bytes.len() {
            return fail("netlink attribute alignment differs");
        }
    }
    Ok(result)
}
fn verify_loopback(links: &[Vec<u8>], addresses: &[Vec<u8>], routes: &[Vec<u8>]) -> Result<()> {
    let [link] = links else {
        return fail("target network has additional/missing links");
    };
    if link.len() < 16
        || link[0] != 0
        || u16::from_le_bytes(link[2..4].try_into().expect("link header")) != 772
    {
        return fail("target link not native loopback");
    }
    let index = u32::from_le_bytes(link[4..8].try_into().expect("link header"));
    let flags = u32::from_le_bytes(link[8..12].try_into().expect("link header"));
    if index == 0
        || flags & 9 != 9
        || attrs(&link[16..])?
            .iter()
            .filter(|(kind, _)| *kind == 3)
            .map(|(_, value)| *value)
            .collect::<Vec<_>>()
            != [b"lo\0".as_slice()]
    {
        return fail("target loopback index/name/up differs");
    }
    let [address] = addresses else {
        return fail("target address inventory not exactIPv4 loopback");
    };
    if address.len() < 8
        || address[0] != 2
        || address[1] != 8
        || address[3] != 254
        || u32::from_le_bytes(address[4..8].try_into().expect("address header")) != index
    {
        return fail("target address scope/index differs");
    }
    let attributes = attrs(&address[8..])?;
    for kind in [1, 2] {
        if attributes
            .iter()
            .filter(|(number, _)| *number == kind)
            .map(|(_, value)| *value)
            .collect::<Vec<_>>()
            != [[127, 0, 0, 1].as_slice()]
        {
            return fail("target loopback address/local attributes differ");
        }
    }
    if routes.is_empty() || routes.len() > 32 {
        return fail("target route inventory bound differs");
    }
    let mut observed = BTreeSet::new();
    for route in routes {
        if route.len() < 12
            || route[0] != 2
            || !(8..=32).contains(&route[1])
            || route[2] != 0
            || route[4] != 255
            || route[5] != 2
            || !matches!(route[7], 2 | 3)
            || route[6] != if route[7] == 2 { 254 } else { 253 }
        {
            return fail("target route family/scope/table differs");
        }
        let mut destination = None;
        let mut output = None;
        for (kind, value) in attrs(&route[12..])? {
            match kind {
                1 => {
                    if destination.replace(value).is_some() {
                        return fail("route destination duplicated");
                    }
                }
                4 => {
                    if value.len() != 4
                        || output
                            .replace(u32::from_le_bytes(
                                value.try_into().expect("route interface"),
                            ))
                            .is_some()
                    {
                        return fail("route interface duplicated/invalid");
                    }
                }
                7 => {
                    if value != [127, 0, 0, 1] {
                        return fail("route preferred source escapes loopback");
                    }
                }
                15 => {
                    if value.len() != 4
                        || u32::from_le_bytes(value.try_into().expect("route table"))
                            != route[4] as u32
                    {
                        return fail("route table attribute differs");
                    }
                }
                6 | 12 => {}
                _ => return fail("target route has gateway/unreviewed attribute"),
            }
        }
        let Some(destination) = destination else {
            return fail("target route destination absent");
        };
        if destination.len() != 4 || destination[0] != 127 || output != Some(index) {
            return fail("target route escapes loopback");
        }
        if !observed.insert((
            route[1],
            route[7],
            <[u8; 4]>::try_from(destination).expect("checked route address"),
        )) {
            return fail("target automatic loopback route duplicated");
        }
    }
    if observed
        != BTreeSet::from([
            (8, 2, [127, 0, 0, 0]),
            (32, 2, [127, 0, 0, 1]),
            (32, 3, [127, 255, 255, 255]),
        ])
    {
        return fail("target exact Linux automatic loopback route inventory differs");
    }
    Ok(())
}
