//! Exact Unix endpoint inventories and isolated planted detector sources.
//! These portable parsers never consult the verifier's process or namespaces.
use crate::private_public_live::HeldPublicTargetSamplesV1;
use crate::{CiError, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const MAX_UNIX_BYTES: usize = 1024 * 1024;
fn fail<T>(message: &str) -> Result<T> {
    Err(CiError::Message(message.into()))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnixSocketRowV1 {
    pub socket_type: u32,
    pub state: u32,
    pub flags: u32,
    pub inode: u64,
    pub path: String,
}

/// Diagnostic raw parser. Rows alone confer no origin or semantic authority.
pub fn parse_unix_proc_table_v1(bytes: &[u8]) -> Result<Vec<UnixSocketRowV1>> {
    if bytes.is_empty() || bytes.len() > MAX_UNIX_BYTES {
        return fail("Unix proc table byte bound differs");
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| CiError::Message("Unix proc table is not UTF-8".into()))?;
    if !text.ends_with('\n') {
        return fail("Unix proc table is truncated");
    }
    let mut lines = text.lines();
    if !lines.next().is_some_and(|line| {
        line.split_ascii_whitespace().eq([
            "Num", "RefCount", "Protocol", "Flags", "Type", "St", "Inode", "Path",
        ])
    }) {
        return fail("Unix proc table header differs");
    }
    let mut rows = Vec::new();
    let mut inodes = BTreeSet::new();
    for line in lines {
        let mut remainder = line;
        let mut fields = Vec::new();
        for _ in 0..7 {
            remainder = remainder.trim_ascii_start();
            let end = remainder
                .find(char::is_whitespace)
                .unwrap_or(remainder.len());
            if end == 0 {
                return fail("Unix proc table column is absent");
            }
            fields.push(&remainder[..end]);
            remainder = &remainder[end..];
        }
        let number = fields[0]
            .strip_suffix(':')
            .ok_or_else(|| CiError::Message("Unix proc row number differs".into()))?;
        if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return fail("Unix proc row number differs");
        }
        let hex = |field: &str| {
            if field.is_empty() || !field.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return fail("Unix proc hexadecimal spelling differs");
            }
            u32::from_str_radix(field, 16)
                .map_err(|_| CiError::Message("Unix proc hexadecimal column differs".into()))
        };
        let _refs = hex(fields[1])?;
        if hex(fields[2])? != 0 {
            return fail("Unix proc protocol differs");
        }
        if fields[6].is_empty() || !fields[6].bytes().all(|byte| byte.is_ascii_digit()) {
            return fail("Unix proc inode spelling differs");
        }
        let inode = fields[6]
            .parse::<u64>()
            .map_err(|_| CiError::Message("Unix proc inode differs".into()))?;
        // Linux unix_seq_show can retain an orphan with sock_i_ino()==0.
        // It cannot prove a held FD, but its pathname must still be inspected.
        if inode != 0 && !inodes.insert(inode) {
            return fail("Unix proc live inode is duplicated");
        }
        let path = if remainder.is_empty() {
            ""
        } else {
            remainder
                .strip_prefix(' ')
                .ok_or_else(|| CiError::Message("Unix proc pathname delimiter differs".into()))?
        };
        if path.contains('\0') || path.contains('\r') {
            return fail("Unix proc pathname is ambiguous");
        }
        rows.push(UnixSocketRowV1 {
            socket_type: hex(fields[4])?,
            state: hex(fields[5])?,
            flags: hex(fields[3])?,
            inode,
            path: path.into(),
        });
    }
    Ok(rows)
}

pub fn unix_intent_names_v1(challenge: &[u8; 32]) -> (String, String) {
    let prefix = format!("memcordon-private-unix-{}", hex::encode(challenge));
    (format!("/tmp/{prefix}-path"), format!("@{prefix}-abstract"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlantedIdentityV1 {
    schema_version: u8,
    protocol: String,
    pathname: String,
    abstract_name: String,
    reader_netns_inode: u64,
    reader_mountns_inode: u64,
    control_netns_inode: u64,
    control_mountns_inode: u64,
    pathname_fd: i32,
    pathname_socket_inode: u64,
    abstract_fd: i32,
    abstract_socket_inode: u64,
    pathname_device: u64,
    pathname_inode: u64,
    pathname_mode: u32,
    pathname_uid: u32,
    begin_monotonic_ns: u64,
    held_monotonic_ns: u64,
}

fn source<'a>(sources: &'a BTreeMap<String, Vec<u8>>, name: &str) -> Result<&'a [u8]> {
    sources
        .get(name)
        .map(Vec::as_slice)
        .ok_or_else(|| CiError::Message(format!("Unix exact source absent: {name}")))
}

fn stat_identity(bytes: &[u8]) -> Result<(u32, u64)> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| CiError::Message("Unix stat source is not text".into()))?;
    let (pid, tail) = text
        .split_once(' ')
        .ok_or_else(|| CiError::Message("Unix stat PID absent".into()))?;
    let (_, fields) = tail
        .rsplit_once(") ")
        .ok_or_else(|| CiError::Message("Unix stat fields absent".into()))?;
    let pid = pid
        .parse()
        .map_err(|_| CiError::Message("Unix stat PID differs".into()))?;
    let ticks = fields
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| CiError::Message("Unix stat start absent".into()))?
        .parse()
        .map_err(|_| CiError::Message("Unix stat start differs".into()))?;
    if pid == 0 || ticks == 0 {
        return fail("Unix stat identity is zero");
    }
    Ok((pid, ticks))
}

fn fdinfo_inode(bytes: &[u8]) -> Result<u64> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| CiError::Message("Unix fdinfo is not text".into()))?;
    let mut values = text
        .lines()
        .filter_map(|line| line.strip_prefix("ino:").map(str::trim));
    let inode = values
        .next()
        .ok_or_else(|| CiError::Message("Unix fdinfo inode absent".into()))?
        .parse()
        .map_err(|_| CiError::Message("Unix fdinfo inode differs".into()))?;
    if inode == 0 || values.next().is_some() {
        return fail("Unix fdinfo inode is zero or duplicated");
    }
    Ok(inode)
}

/// Source-only validation, reusable by candidate/public custody replay. A
/// caller must separately bind these exact bytes to an enrolled raw origin.
pub fn validate_planted_unix_sources_v1(
    sources: &BTreeMap<String, Vec<u8>>,
    challenge: &[u8; 32],
) -> Result<(u64, u64)> {
    let expected: BTreeSet<&str> = [
        "identity.json",
        "stat-before.raw",
        "stat-after.raw",
        "status.raw",
        "unix-before.raw",
        "unix-held.raw",
        "unix-after.raw",
        "pathname-fdinfo.raw",
        "abstract-fdinfo.raw",
        "end-monotonic.raw",
    ]
    .into_iter()
    .collect();
    if sources.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected {
        return fail("Unix planted control exact inventory differs");
    }
    let identity: PlantedIdentityV1 =
        crate::private_observer_session::strict_json(source(sources, "identity.json")?, 8192)?;
    let (pathname, abstract_name) = unix_intent_names_v1(challenge);
    let end = u64::from_le_bytes(
        source(sources, "end-monotonic.raw")?
            .try_into()
            .map_err(|_| CiError::Message("Unix detector end clock width differs".into()))?,
    );
    if identity.schema_version != 1
        || identity.protocol != "private-unix-planted-detector-v1"
        || identity.pathname != pathname
        || identity.abstract_name != abstract_name.strip_prefix('@').expect("derived abstract")
        || identity.reader_netns_inode == 0
        || identity.reader_mountns_inode == 0
        || identity.control_netns_inode == 0
        || identity.control_mountns_inode == 0
        || identity.control_netns_inode == identity.reader_netns_inode
        || identity.control_mountns_inode == identity.reader_mountns_inode
        || identity.pathname_fd < 0
        || identity.abstract_fd < 0
        || identity.pathname_fd == identity.abstract_fd
        || identity.pathname_socket_inode == identity.abstract_socket_inode
        || identity.pathname_device == 0
        || identity.pathname_inode == 0
        || identity.pathname_uid != 0
        || identity.pathname_mode & 0o170000 != 0o140000
        || identity.begin_monotonic_ns == 0
        || identity.held_monotonic_ns < identity.begin_monotonic_ns
        || end < identity.held_monotonic_ns
        || stat_identity(source(sources, "stat-before.raw")?)?
            != stat_identity(source(sources, "stat-after.raw")?)?
        || fdinfo_inode(source(sources, "pathname-fdinfo.raw")?)? != identity.pathname_socket_inode
        || fdinfo_inode(source(sources, "abstract-fdinfo.raw")?)? != identity.abstract_socket_inode
    {
        return fail("Unix planted control actual identity/timing/object differs");
    }
    let status = std::str::from_utf8(source(sources, "status.raw")?)
        .map_err(|_| CiError::Message("Unix detector status is not text".into()))?;
    let uid = status
        .lines()
        .filter_map(|line| line.strip_prefix("Uid:"))
        .collect::<Vec<_>>();
    if uid.len() != 1 || !uid[0].split_whitespace().eq(["0", "0", "0", "0"]) {
        return fail("Unix detector actual root identity differs");
    }
    for path in ["unix-before.raw", "unix-after.raw"] {
        let rows = parse_unix_proc_table_v1(source(sources, path)?)?;
        if rows
            .iter()
            .any(|row| row.path.contains(&pathname) || row.path.contains(&abstract_name))
        {
            return fail("Unix planted endpoint existed before or survived close");
        }
    }
    let rows = parse_unix_proc_table_v1(source(sources, "unix-held.raw")?)?;
    for (name, inode) in [
        (&pathname, identity.pathname_socket_inode),
        (&abstract_name, identity.abstract_socket_inode),
    ] {
        let selected = rows
            .iter()
            .filter(|row| row.path == *name)
            .collect::<Vec<_>>();
        if !matches!(selected.as_slice(),[row] if row.inode == inode && row.socket_type == 1 && row.state == 1 && row.flags & 0x10000 != 0)
        {
            return fail("Unix positive detector exact live listening endpoint absent");
        }
        if rows
            .iter()
            .any(|row| row.path != *name && row.path.contains(name))
        {
            return fail("Unix detector pathname is ambiguous");
        }
    }
    Ok((identity.begin_monotonic_ns, end))
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UnixDirectorySourceV1 {
    schema_version: u8,
    device: u64,
    inode: u64,
    mode: u32,
    network_namespace_inode: u64,
    mount_namespace_inode: u64,
    target_root_inode: u64,
    entries: Vec<Vec<u8>>,
}

/// Actual late held endpoint sample; call before the target acknowledgement.
#[cfg(target_os = "linux")]
pub(crate) fn sample_held_unix_source(
    sample: &mut HeldPublicTargetSamplesV1,
    challenge: [u8; 32],
) -> Result<()> {
    use std::os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
    };
    let root = std::path::Path::new("/proc").join(sample.pid.to_string());
    if stat_identity(&std::fs::read(root.join("stat"))?)? != (sample.pid, sample.start_time_ticks) {
        return fail("held Unix target changed before sampling");
    }
    let directory = root.join("root/tmp");
    let held = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(&directory)?;
    let before = held.metadata()?;
    let net = std::fs::metadata(root.join("ns/net"))?.ino();
    let mount = std::fs::metadata(root.join("ns/mnt"))?.ino();
    let root_inode = std::fs::metadata(root.join("root"))?.ino();
    let mut entries = Vec::new();
    let mut entry_bytes = 0usize;
    for entry in std::fs::read_dir(&directory)? {
        let name = entry?.file_name().as_bytes().to_vec();
        entry_bytes = entry_bytes
            .checked_add(name.len())
            .ok_or_else(|| CiError::Message("Unix directory source size overflow".into()))?;
        if entries.len() >= 4096 || entry_bytes > 128 * 1024 {
            return fail("held Unix directory exceeds reviewed bound");
        }
        entries.push(name);
    }
    entries.sort();
    if entries.len() > 4096 || entries.iter().map(Vec::len).sum::<usize>() > 128 * 1024 {
        return fail("held Unix directory exceeds reviewed bound");
    }
    let (pathname, abstract_name) = unix_intent_names_v1(&challenge);
    let filename = std::path::Path::new(&pathname)
        .file_name()
        .expect("derived path")
        .as_bytes();
    if entries.iter().any(|entry| entry == filename) {
        return fail("Unix pathname exists in actual target root");
    }
    use std::io::Read;
    let mut table = Vec::new();
    std::fs::File::open(root.join("net/unix"))?
        .take((MAX_UNIX_BYTES + 1) as u64)
        .read_to_end(&mut table)?;
    crate::private_unix_live::verify_proc_unix_endpoints_absent(&table, &pathname, &abstract_name)?;
    let after = held.metadata()?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || std::fs::metadata(&directory)?.ino() != before.ino()
        || stat_identity(&std::fs::read(root.join("stat"))?)?
            != (sample.pid, sample.start_time_ticks)
    {
        return fail("held Unix directory/task changed during observation");
    }
    let planted = memcordon_platform::test_support::private_sample_unix_detector(challenge)?;
    validate_planted_unix_sources_v1(&planted, &challenge)?;
    for (name, bytes) in [
        ("unix-target-table.raw", table),
        (
            "unix-target-directory.json",
            serde_json::to_vec(&UnixDirectorySourceV1 {
                schema_version: 1,
                device: before.dev(),
                inode: before.ino(),
                mode: before.mode(),
                network_namespace_inode: net,
                mount_namespace_inode: mount,
                target_root_inode: root_inode,
                entries,
            })?,
        ),
        (
            "unix-planted-control.v1.bin",
            crate::private_source_carrier::encode_source_carrier(&planted)?,
        ),
    ] {
        if sample.leaves.insert(name.into(), bytes).is_some() {
            return fail("held Unix source repeated");
        }
    }
    if std::fs::metadata(root.join("ns/net"))?.ino() != net
        || std::fs::metadata(root.join("ns/mnt"))?.ino() != mount
        || std::fs::metadata(root.join("root"))?.ino() != root_inode
        || stat_identity(&std::fs::read(root.join("stat"))?)?
            != (sample.pid, sample.start_time_ticks)
    {
        return fail("held Unix task/namespace changed around detector control");
    }
    sample.end_monotonic_ns = memcordon_platform::test_support::private_observer_monotonic_ns()?;
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeUnixSourcesV1 {
    pub(crate) result_path: String,
    pub(crate) request_path: String,
    pub(crate) gate_path: String,
    pub(crate) ack_path: String,
    pub(crate) held_sample_path: String,
    pub(crate) response_path: String,
}

/// Shared physical source conjunction. Public callers bind their own original
/// provider/result tuple first; this function does not convert candidate tokens.
pub(crate) fn verify_held_unix_sources(
    sample: &HeldPublicTargetSamplesV1,
    events: &[crate::private_kernel_replay::KernelEventRecordV2],
    clock: &crate::private_process_clock::ProcClockInputsV1,
    target: &crate::private_candidate_replay::ReplayTaskV1,
    triple: &str,
    challenge: &[u8; 32],
) -> Result<()> {
    let calibration = crate::private_process_clock::ParsedProcClockCalibrationV1::parse(clock)?;
    if sample.pid != target.tid
        || sample.schema_version != 1
        || sample.begin_monotonic_ns == 0
        || sample.end_monotonic_ns < sample.begin_monotonic_ns
        || !calibration.matches(
            crate::private_kernel_observer::KernelTaskIdentityV1 {
                pid: target.tid,
                start_time: target.start_boottime_ns,
                cgroup_inode: target.cgroup_inode,
                time_ns_inode: target.time_ns_inode,
            },
            sample.start_time_ticks,
        )
        || stat_identity(source(&sample.leaves, "stat-before.raw")?)?
            != (sample.pid, sample.start_time_ticks)
        || stat_identity(source(&sample.leaves, "stat-after.raw")?)?
            != (sample.pid, sample.start_time_ticks)
    {
        return fail("held Unix exact task/original clock differs");
    }
    let namespaces = sample
        .tasks
        .iter()
        .find(|task| task.tid == target.tid)
        .ok_or_else(|| CiError::Message("held Unix task namespaces absent".into()))?;
    let directory: UnixDirectorySourceV1 = crate::private_observer_session::strict_json(
        source(&sample.leaves, "unix-target-directory.json")?,
        256 * 1024,
    )?;
    let (pathname, abstract_name) = unix_intent_names_v1(challenge);
    let filename = std::path::Path::new(&pathname)
        .file_name()
        .expect("derived path")
        .to_string_lossy();
    let mut entries = directory.entries.clone();
    entries.sort();
    entries.dedup();
    if directory.schema_version != 1
        || directory.device == 0
        || directory.inode == 0
        || directory.mode & 0o170000 != 0o040000
        || directory.target_root_inode == 0
        || directory.network_namespace_inode == 0
        || directory.mount_namespace_inode == 0
        || namespaces.namespace_inodes.get("net") != Some(&directory.network_namespace_inode)
        || namespaces.namespace_inodes.get("mnt") != Some(&directory.mount_namespace_inode)
        || entries != directory.entries
        || entries.len() > 4096
        || entries.iter().any(|entry| {
            entry == filename.as_bytes()
                || entry.is_empty()
                || entry.contains(&b'/')
                || entry.contains(&0)
        })
    {
        return fail("held Unix exact namespace/root directory differs");
    }
    crate::private_unix_live::verify_proc_unix_endpoints_absent(
        source(&sample.leaves, "unix-target-table.raw")?,
        &pathname,
        &abstract_name,
    )?;
    verify_unix_creation_denials(events, target, triple, sample.begin_monotonic_ns)?;
    let control = crate::private_source_carrier::parse_source_carrier(source(
        &sample.leaves,
        "unix-planted-control.v1.bin",
    )?)?;
    let (begin, end) = validate_planted_unix_sources_v1(&control, challenge)?;
    let identity: PlantedIdentityV1 =
        crate::private_observer_session::strict_json(source(&control, "identity.json")?, 8192)?;
    let reader_before: BTreeMap<String, u64> = crate::private_observer_session::strict_json(
        source(&sample.leaves, "reader-namespaces-before.json")?,
        8192,
    )?;
    let reader_after: BTreeMap<String, u64> = crate::private_observer_session::strict_json(
        source(&sample.leaves, "reader-namespaces-after.json")?,
        8192,
    )?;
    let (tid, ticks) = stat_identity(source(&control, "stat-before.raw")?)?;
    if reader_before != reader_after
        || reader_before.get("net") != Some(&identity.reader_netns_inode)
        || reader_before.get("mnt") != Some(&identity.reader_mountns_inode)
        || identity.control_netns_inode == directory.network_namespace_inode
        || identity.control_mountns_inode == directory.mount_namespace_inode
        || begin < sample.begin_monotonic_ns
        || end > sample.end_monotonic_ns
        || !events.iter().any(|event| {
            event.kind == 11
                && event.task.tid == tid
                && event.task.tgid == clock.reader_pid
                && event.monotonic_ns >= begin
                && event.monotonic_ns <= end
                && calibration.matches(
                    crate::private_kernel_observer::KernelTaskIdentityV1 {
                        pid: tid,
                        start_time: event.task.start_boottime_ns,
                        cgroup_inode: event.task.cgroup_inode,
                        time_ns_inode: event.task.time_ns_inode,
                    },
                    ticks,
                )
        })
    {
        return fail("planted Unix control independent reader/task/interval join differs");
    }
    Ok(())
}

fn verify_unix_creation_denials(
    events: &[crate::private_kernel_replay::KernelEventRecordV2],
    target: &crate::private_candidate_replay::ReplayTaskV1,
    triple: &str,
    before: u64,
) -> Result<()> {
    use crate::private_candidate_network_facts::{matches, returned};
    use crate::private_case_semantics::{NativeOperationV1, native_syscall_number};
    let nr = native_syscall_number(triple, NativeOperationV1::Socket)?;
    let denied = events
        .iter()
        .filter(|event| {
            event.kind == 4
                && matches(target, event)
                && event.syscall_nr == nr
                && event.args[0] == 1
        })
        .collect::<Vec<_>>();
    if denied.len() != 2
        || denied.iter().any(|entry| {
            entry.args[1] != (1 | 0x80000)
                || entry.args[2] != 0
                || entry.seccomp_action != 0x50000
                || entry.syscall_result != 97
                || entry.monotonic_ns >= before
                || !returned(events, entry)
                    .is_ok_and(|ret| ret.syscall_result == -97 && ret.monotonic_ns < before)
        })
    {
        return fail("two actual AF_UNIX stream/CLOEXEC creation denials differ");
    }
    let bind = native_syscall_number(triple, NativeOperationV1::Bind)?;
    if events
        .iter()
        .any(|event| event.kind == 4 && matches(target, event) && event.syscall_nr == bind)
    {
        return fail("Unix intent target attempted bind");
    }
    Ok(())
}

/// Diagnostic only: no completed origin, gate, namespace, approval or token.
pub fn diagnostic_unix_creation_denials_v1(
    bytes: &[u8],
    key: &memcordon_core::DiagnosticSha256,
    tid: u32,
    triple: &str,
    before: u64,
) -> Result<()> {
    let parsed = crate::private_kernel_replay::parse_capture_v2(bytes, key)?;
    let task = parsed
        .events()
        .iter()
        .find(|event| event.kind == 4 && event.task.tid == tid)
        .ok_or_else(|| CiError::Message("diagnostic Unix target absent".into()))?
        .task;
    verify_unix_creation_denials(
        parsed.events(),
        &crate::private_candidate_replay::ReplayTaskV1 {
            tid: task.tid,
            tgid: task.tgid,
            start_boottime_ns: task.start_boottime_ns,
            cgroup_inode: task.cgroup_inode,
            time_ns_inode: task.time_ns_inode,
        },
        triple,
        before,
    )
}

pub(crate) fn verify_native_unix_sources<'a>(
    sources: &NativeUnixSourcesV1,
    target: &crate::private_candidate_replay::ReplayTaskV1,
    events: &[crate::private_kernel_replay::KernelEventRecordV2],
    clock: &crate::private_process_clock::ProcClockInputsV1,
    leaf: impl Fn(&str) -> Result<&'a [u8]>,
) -> Result<memcordon_core::private_release_case_v1::PrivateReleaseCaseResultV1> {
    use memcordon_core::private_release_case_v1::PrivateReleaseCaseResultV1;
    let result =
        PrivateReleaseCaseResultV1::parse(leaf(&sources.result_path)?).map_err(CiError::Message)?;
    let key = result.result_key().map_err(CiError::Message)?;
    let challenge = result.challenge_bytes().map_err(CiError::Message)?;
    if result.selector != crate::private_unix_live::UNIX_INTENT_SELECTOR {
        return fail("native Unix source selector differs");
    }
    crate::private_protected_readback::parse_protected_candidate_request(
        leaf(&sources.request_path)?,
        &result.selector,
        challenge,
        &key,
    )?;
    let gate = crate::private_unix_live::parse_gate(leaf(&sources.gate_path)?, &key, challenge)?;
    let ack: crate::private_unix_live::UnixIntentAckV1 =
        crate::private_observer_session::strict_json(leaf(&sources.ack_path)?, 8192)?;
    let sample = crate::private_source_carrier::decode_held_source(
        leaf(&sources.held_sample_path)?,
        |path| leaf(path).map(ToOwned::to_owned),
    )?;
    verify_held_unix_sources(&sample, events, clock, target, &result.target, &challenge)?;
    let directory: UnixDirectorySourceV1 = crate::private_observer_session::strict_json(
        source(&sample.leaves, "unix-target-directory.json")?,
        256 * 1024,
    )?;
    let observed = crate::private_protected_readback::UnixAbsenceSnapshotV1 {
        network_namespace_inode: directory.network_namespace_inode,
        mount_namespace_inode: directory.mount_namespace_inode,
        target_root_inode: directory.target_root_inode,
        proc_unix_sha256: memcordon_core::workload_codec::hash_bytes(source(
            &sample.leaves,
            "unix-target-table.raw",
        )?),
        pathname_absent: true,
        abstract_absent: true,
    };
    if gate.witness.target.pid != sample.pid
        || gate.witness.target.start_time != sample.start_time_ticks
        || gate.witness.after_denials_before_ack != observed
        || ack.schema_version != 1
        || ack.selector != result.selector
        || ack.result_key != key
        || ack.challenge_sha256 != memcordon_core::workload_codec::hash_bytes(&challenge)
        || ack.gate_sha256 != memcordon_core::workload_codec::hash_bytes(leaf(&sources.gate_path)?)
        || ack.observed != observed
        || serde_json::to_vec(&ack)? != leaf(&sources.ack_path)?
        || leaf(&sources.response_path)?
            != memcordon_core::private_release_case_v1::candidate_fixture_expected_response_v1(
                &result.target,
                &result.selector,
                &challenge,
                None,
                None,
            )
            .map_err(|message| CiError::Message(message.into()))?
    {
        return fail("original Unix gate/ack/intents/exact response differs");
    }
    Ok(result)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn sample_held_unix_source(
    _sample: &mut HeldPublicTargetSamplesV1,
    _challenge: [u8; 32],
) -> Result<()> {
    fail("held Unix source sampling requires native Linux")
}
