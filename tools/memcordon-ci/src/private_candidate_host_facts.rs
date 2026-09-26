//! Actual host continuity source replay. No before/after-only success path.
use crate::private_kernel_replay::KernelEventRecordV2;
use crate::{CiError, Result};
use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};
use std::collections::{BTreeMap, BTreeSet};

pub fn host_preservation_source_revision_sha256() -> DiagnosticSha256 {
    hash_bytes(b"memcordon/host-preservation-source/v1/feature32/all-successful-sysctl-writers/root-rtnetlink-continuity\0")
}
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeHostSourcesV1 {
    pub schema_version: u8,
    pub source_path: String,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostIdentityV1 {
    schema_version: u8,
    protocol: String,
    reader_pid: u32,
    host_netns_inode: u64,
    begin_monotonic_ns: u64,
    end_monotonic_ns: u64,
    object_pins: [(u64, u64); 4],
    socket_inode: u64,
    queue_overflow: u32,
    truncated: bool,
}
fn fail(message: &str) -> CiError {
    CiError::Message(message.into())
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or_else(|| fail("host source truncated"))?
            .try_into()
            .map_err(|_| fail("host source word differs"))?,
    ))
}
fn u16_at(bytes: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or_else(|| fail("host source truncated"))?
            .try_into()
            .map_err(|_| fail("host source word differs"))?,
    ))
}
fn u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or_else(|| fail("host source truncated"))?
            .try_into()
            .map_err(|_| fail("host source word differs"))?,
    ))
}
fn leaf<'a>(map: &'a BTreeMap<String, Vec<u8>>, path: &str) -> Result<&'a [u8]> {
    map.get(path)
        .map(Vec::as_slice)
        .ok_or_else(|| fail("host original source leaf absent"))
}
fn stat_identity(text: &str) -> Result<(u32, u64)> {
    let pid = text
        .split_once(' ')
        .ok_or_else(|| fail("host reader stat absent"))?
        .0
        .parse()
        .map_err(|_| fail("host reader PID differs"))?;
    let ticks = text
        .rsplit_once(") ")
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .and_then(|value| value.parse().ok())
        .filter(|ticks| *ticks > 0)
        .ok_or_else(|| fail("host reader stat start differs"))?;
    Ok((pid, ticks))
}
fn phase_objects(
    map: &BTreeMap<String, Vec<u8>>,
    phase: &str,
    label: &str,
    request: u16,
    response: u16,
    body: usize,
) -> Result<BTreeSet<Vec<u8>>> {
    let packet = leaf(map, &format!("{phase}/{label}-dump.raw"))?;
    if packet.get(..8) != Some(b"MCHD\x01\0\0\0") {
        return Err(fail("host dump envelope differs"));
    }
    let count = u32_at(packet, 8)? as usize;
    if count == 0 || count > 64 {
        return Err(fail("host dump packet bound differs"));
    }
    let mut cursor = 12usize;
    let mut unpacked = BTreeMap::new();
    unpacked.insert(
        format!("{label}/request.raw"),
        leaf(map, &format!("{phase}/{label}-request.raw"))?.to_vec(),
    );
    for ordinal in 0..count {
        let length = u32_at(packet, cursor)? as usize;
        cursor += 4;
        let end = cursor
            .checked_add(length)
            .ok_or_else(|| fail("host dump overflow"))?;
        unpacked.insert(
            format!("{label}/{ordinal}.raw"),
            packet
                .get(cursor..end)
                .ok_or_else(|| fail("host dump truncated"))?
                .to_vec(),
        );
        cursor = end;
    }
    if cursor != packet.len() {
        return Err(fail("host dump trailing data"));
    }
    let raw = crate::private_candidate_network_facts::dump_objects(
        &unpacked, label, request, response, body,
    )?;
    let mut objects = BTreeSet::new();
    for object in raw {
        if !objects.insert(configuration(response, &object)?) {
            return Err(fail("host duplicate configuration object"));
        }
    }
    Ok(objects)
}
fn configuration(kind: u16, bytes: &[u8]) -> Result<Vec<u8>> {
    let body = match kind {
        16 => 16,
        20 => 8,
        24 => 12,
        _ => return Err(fail("host netlink configuration kind differs")),
    };
    if bytes.len() < body {
        return Err(fail("host netlink body truncated"));
    }
    let mut output = bytes[..body].to_vec();
    // ifi_change is a notification mask, not retained link configuration.
    if kind == 16 {
        output[12..16].fill(0);
    }
    let mut cursor = body;
    let mut attributes = BTreeMap::new();
    while cursor < bytes.len() {
        let length = u16_at(bytes, cursor)? as usize;
        let attribute = u16_at(bytes, cursor + 2)?;
        if length < 4 || length > bytes.len() - cursor {
            return Err(fail("host configuration attribute length differs"));
        }
        let skip = kind == 16 && matches!(attribute, 7 | 23) || kind == 24 && attribute == 12;
        if !skip
            && attributes
                .insert(attribute, bytes[cursor + 4..cursor + length].to_vec())
                .is_some()
        {
            return Err(fail("host duplicate configuration attribute"));
        }
        cursor = cursor
            .checked_add((length + 3) & !3)
            .ok_or_else(|| fail("host attribute overflow"))?;
        if cursor > bytes.len() {
            return Err(fail("host configuration attribute alignment differs"));
        }
    }
    for (attribute, value) in attributes {
        output.extend_from_slice(&attribute.to_le_bytes());
        output.extend_from_slice(&(value.len() as u32).to_le_bytes());
        output.extend_from_slice(&value);
    }
    Ok(output)
}
/// Structural diagnostics only. Origin custody, independent approved source
/// revision and kernel writer observations are separate prerequisites.
pub fn validate_host_network_sources_v1(
    map: &BTreeMap<String, Vec<u8>>,
    arm: u64,
    detach: u64,
) -> Result<()> {
    if map.len() != 26
        || map
            .values()
            .try_fold(0usize, |n, v| n.checked_add(v.len()))
            .is_none_or(|n| n > 8 * 1024 * 1024)
    {
        return Err(fail("host source inventory/bound differs"));
    }
    let identity: HostIdentityV1 = serde_json::from_slice(leaf(map, "identity.json")?)?;
    if identity.schema_version != 1
        || identity.protocol != "private-host-continuity-v1"
        || identity.reader_pid == 0
        || identity.host_netns_inode == 0
        || identity.begin_monotonic_ns == 0
        || identity.begin_monotonic_ns > arm
        || arm >= detach
        || detach > identity.end_monotonic_ns
        || identity.queue_overflow != 0
        || identity.truncated
    {
        return Err(fail("host continuous observer endpoints/loss differ"));
    }
    for slot in 0..4 {
        if identity.object_pins[slot].0 == 0
            || identity.object_pins[slot].1 == 0
            || identity.object_pins[..slot].contains(&identity.object_pins[slot])
            || leaf(map, &format!("before/sysctl-{slot}.raw"))?
                != leaf(map, &format!("after/sysctl-{slot}.raw"))?
        {
            return Err(fail(
                "host independently held sysctl identity/value differs",
            ));
        }
    }
    for path in ["netlink-queue-before.raw", "netlink-queue-after.raw"] {
        let bytes = leaf(map, path)?;
        if bytes.len() > 128 * 1024 || identity.socket_inode == 0 {
            return Err(fail("host netlink queue source bound/identity differs"));
        }
        let mut rows = std::str::from_utf8(bytes)
            .map_err(|_| fail("host queue UTF8 differs"))?
            .lines();
        if rows
            .next()
            .map(|line| line.split_whitespace().collect::<Vec<_>>())
            != Some(vec![
                "sk", "Eth", "Pid", "Groups", "Rmem", "Wmem", "Dump", "Locks", "Drops", "Inode",
            ])
        {
            return Err(fail("host netlink queue header differs"));
        }
        let mut matched = 0;
        for row in rows {
            let fields = row.split_whitespace().collect::<Vec<_>>();
            if fields.len() != 10 {
                return Err(fail("host queue row differs"));
            }
            if fields[9]
                .parse::<u64>()
                .map_err(|_| fail("host queue inode differs"))?
                == identity.socket_inode
            {
                matched += 1;
                if fields[1]
                    .parse::<u32>()
                    .map_err(|_| fail("host queue protocol differs"))?
                    != 0
                    || fields[2]
                        .parse::<u32>()
                        .map_err(|_| fail("host queue port differs"))?
                        == 0
                    || u32::from_str_radix(fields[3], 16)
                        .map_err(|_| fail("host queue groups differ"))?
                        != 0x551
                    || fields[8]
                        .parse::<u64>()
                        .map_err(|_| fail("host queue drops differs"))?
                        != 0
                {
                    return Err(fail("host continuity queue loss observed"));
                }
            }
        }
        if matched != 1 {
            return Err(fail("host retained notification socket absent/duplicated"));
        }
    }
    let mut before = BTreeMap::new();
    for (label, request, response, body) in [
        ("links", 18, 16, 16),
        ("addresses", 22, 20, 8),
        ("routes", 26, 24, 12),
    ] {
        let objects = phase_objects(map, "before", label, request, response, body)?;
        if objects != phase_objects(map, "after", label, request, response, body)? {
            return Err(fail("host network configuration changed"));
        }
        before.insert(response, objects);
    }
    // Original thread stat identities must remain identical across monitor.
    let stat = |path| -> Result<(u32, u64)> {
        let text = std::str::from_utf8(leaf(map, path)?)
            .map_err(|_| fail("host reader stat UTF8 differs"))?;
        stat_identity(text)
    };
    if stat("reader-stat-before.raw")? != stat("reader-stat-after.raw")? {
        return Err(fail("host monitor reader task changed"));
    }
    let notifications = leaf(map, "notifications.raw")?;
    if notifications.get(..8) != Some(b"MCHN\x01\0\0\0") {
        return Err(fail("host continuity notification envelope differs"));
    }
    let mut cursor = 8usize;
    let mut previous = identity.begin_monotonic_ns;
    while cursor < notifications.len() {
        let time = u64_at(notifications, cursor)?;
        let length = u32_at(notifications, cursor + 8)? as usize;
        cursor += 12;
        if time < previous || time > identity.end_monotonic_ns || length == 0 || length > 65536 {
            return Err(fail("host notification clock/bound differs"));
        }
        previous = time;
        let end = cursor
            .checked_add(length)
            .ok_or_else(|| fail("host notification overflow"))?;
        let packet = notifications
            .get(cursor..end)
            .ok_or_else(|| fail("host notification truncated"))?;
        cursor = end;
        let mut offset = 0usize;
        while offset < packet.len() {
            let length = u32_at(packet, offset)? as usize;
            let kind = u16_at(packet, offset + 4)?;
            if length < 16
                || length > packet.len() - offset
                || u32_at(packet, offset + 8)? != 0
                || u32_at(packet, offset + 12)? != 0
                || !matches!(kind, 16 | 20 | 24)
                || u16_at(packet, offset + 6)? & 0x10 != 0
            {
                return Err(fail("host mutation/deletion/loss notification observed"));
            }
            if !before.get(&kind).is_some_and(|objects| {
                configuration(kind, &packet[offset + 16..offset + length])
                    .is_ok_and(|object| objects.contains(&object))
            }) {
                return Err(fail(
                    "transient host network configuration mutation observed",
                ));
            }
            offset += (length + 3) & !3;
            if offset > packet.len() {
                return Err(fail("host notification alignment differs"));
            }
        }
    }
    Ok(())
}
pub(crate) fn verify_host_sources(
    map: &BTreeMap<String, Vec<u8>>,
    events: &[KernelEventRecordV2],
    arm: u64,
    detach: u64,
) -> Result<()> {
    validate_host_network_sources_v1(map, arm, detach)?;
    crate::private_kernel_replay::validate_host_records(events)?;
    let identity: HostIdentityV1 = serde_json::from_slice(leaf(map, "identity.json")?)?;
    for event in events.iter().filter(|event| event.kind == 15) {
        let slot = event.other_tid as usize - 1;
        if (event.image_dev, event.image_inode) != identity.object_pins[slot]
            || event.args[3] != identity.host_netns_inode
            || event.args[2] > arm
            || event.monotonic_ns < arm
            || event.monotonic_ns > detach
        {
            return Err(fail("host independent observer objects/kernel pins differ"));
        }
    }
    if events
        .iter()
        .any(|event| event.kind == 16 && event.monotonic_ns >= arm && event.monotonic_ns <= detach)
    {
        return Err(fail("successful host sysctl mutation observed"));
    }
    Ok(())
}
pub(crate) fn verify_host_reader_clock(
    map: &BTreeMap<String, Vec<u8>>,
    events: &[KernelEventRecordV2],
    inputs: &crate::private_process_clock::ProcClockInputsV1,
) -> Result<()> {
    let identity: HostIdentityV1 = serde_json::from_slice(leaf(map, "identity.json")?)?;
    let clock = crate::private_process_clock::ParsedProcClockCalibrationV1::parse(inputs)?;
    let (pid, ticks) = stat_identity(
        std::str::from_utf8(leaf(map, "reader-stat-before.raw")?)
            .map_err(|_| fail("host reader stat UTF8 differs"))?,
    )?;
    if identity.reader_pid != clock.reader_identity().0
        || !events.iter().any(|event| {
            event.kind == 11
                && event.task.tid == pid
                && event.task.tgid == identity.reader_pid
                && clock.matches(
                    crate::private_kernel_observer::KernelTaskIdentityV1 {
                        pid: event.task.tid,
                        start_time: event.task.start_boottime_ns,
                        cgroup_inode: event.task.cgroup_inode,
                        time_ns_inode: event.task.time_ns_inode,
                    },
                    ticks,
                )
        })
    {
        return Err(fail("host monitor original reader task/clock differs"));
    }
    Ok(())
}
/// Diagnostic raw protocol entry point; never creates an observer capability.
pub fn diagnostic_host_kernel_sources_v1(
    map: &BTreeMap<String, Vec<u8>>,
    bytes: &[u8],
    key: &DiagnosticSha256,
    arm: u64,
    detach: u64,
) -> Result<()> {
    let parsed = crate::private_kernel_replay::parse_capture_v2(bytes, key)?;
    verify_host_sources(map, parsed.events(), arm, detach)
}
