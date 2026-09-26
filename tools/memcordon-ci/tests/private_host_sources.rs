use memcordon_ci::private_candidate_host_facts::{
    diagnostic_host_kernel_sources_v1, validate_host_network_sources_v1,
};
use memcordon_core::DiagnosticSha256;
use std::collections::BTreeMap;
fn message(kind: u16, body: &[u8], sequence: u32, port: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&((body.len() + 16) as u32).to_le_bytes());
    bytes.extend_from_slice(&kind.to_le_bytes());
    bytes.extend_from_slice(&(if kind == 3 { 0u16 } else { 2 }).to_le_bytes());
    bytes.extend_from_slice(&sequence.to_le_bytes());
    bytes.extend_from_slice(&port.to_le_bytes());
    bytes.extend_from_slice(body);
    while bytes.len() % 4 != 0 {
        bytes.push(0);
    }
    bytes
}
fn fixture() -> BTreeMap<String, Vec<u8>> {
    let mut leaves = BTreeMap::new();
    for phase in ["before", "after"] {
        for slot in 0..4 {
            leaves.insert(format!("{phase}/sysctl-{slot}.raw"), b"1\n".to_vec());
        }
        for (label, request, response, body) in [
            ("links", 18u16, 16u16, 16usize),
            ("addresses", 22, 20, 8),
            ("routes", 26, 24, 12),
        ] {
            let mut sent = message(request, &vec![0; body], 1, 999);
            sent[6..8].copy_from_slice(&0x301u16.to_le_bytes());
            leaves.insert(format!("{phase}/{label}-request.raw"), sent);
            let mut packet = Vec::new();
            if label == "links" {
                let mut link = vec![0; 16];
                link[2..4].copy_from_slice(&772u16.to_le_bytes());
                link[4..8].copy_from_slice(&1u32.to_le_bytes());
                link[8..12].copy_from_slice(&73u32.to_le_bytes());
                packet.extend(message(response, &link, 1, 999));
            }
            packet.extend(message(3, &[0; 4], 1, 999));
            let mut framed = b"MCHD\x01\0\0\0".to_vec();
            framed.extend_from_slice(&1u32.to_le_bytes());
            framed.extend_from_slice(&(packet.len() as u32).to_le_bytes());
            framed.extend(packet);
            leaves.insert(format!("{phase}/{label}-dump.raw"), framed);
        }
    }
    let mut fields = vec!["0"; 20];
    fields[0] = "S";
    fields[19] = "123";
    let stat = format!("101 (host monitor) {}\n", fields.join(" ")).into_bytes();
    leaves.insert("reader-stat-before.raw".into(), stat.clone());
    leaves.insert("reader-stat-after.raw".into(), stat);
    leaves.insert("notifications.raw".into(), b"MCHN\x01\0\0\0".to_vec());
    for phase in ["before", "after"] {
        leaves.insert(
            format!("netlink-queue-{phase}.raw"),
            b"sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode\n0000 0 100 551 0 0 0 2 0 9999\n"
                .to_vec(),
        );
    }
    leaves.insert("identity.json".into(),serde_json::to_vec(&serde_json::json!({"schema_version":1,"protocol":"private-host-continuity-v1","reader_pid":100,"host_netns_inode":40,"begin_monotonic_ns":10,"end_monotonic_ns":70,"object_pins":[[2,100],[2,101],[2,102],[2,103]],"socket_inode":9999,"queue_overflow":0,"truncated":false})).unwrap());
    leaves
}
fn capture(key: &DiagnosticSha256, write: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    for value in [0x4d434b31u32, 2] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend_from_slice(&(if write { 5u64 } else { 4 }).to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    for value in [192u32, 47, 16, 0x01020304] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    for ordinal in 0..if write { 5 } else { 4 } {
        let slot = ordinal % 4;
        let mut record = vec![0u8; 192];
        for (offset, value) in [
            (0, ordinal as u64 + 1),
            (8, 40 + ordinal as u64),
            (16, 3),
            (24, 1000),
            (32, 2),
            (40, 100 + slot as u64),
            (56, 2),
            (120, 4),
            (136, 1000 + slot as u64),
            (144, 2000 + slot as u64),
            (152, 20),
            (160, 40),
            (168, 40),
            (176, 35),
        ] {
            record[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [
            (64, 7u32),
            (68, slot as u32 + 1),
            (80, if ordinal == 4 { 16 } else { 15 }),
            (184, 7),
        ] {
            record[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        record[84..116].copy_from_slice(key.bytes());
        bytes.extend(record);
    }
    bytes
}
#[test]
fn host_requires_continuous_exact_original_inventory() {
    let map = fixture();
    validate_host_network_sources_v1(&map, 30, 50).unwrap();
    let mut missing = map.clone();
    missing.remove("notifications.raw");
    assert!(validate_host_network_sources_v1(&missing, 30, 50).is_err());
    let mut changed = map.clone();
    changed.insert("after/sysctl-1.raw".into(), b"0\n".to_vec());
    assert!(validate_host_network_sources_v1(&changed, 30, 50).is_err());
    let mut lost = map.clone();
    lost.insert(
        "netlink-queue-after.raw".into(),
        b"sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode\n0000 0 100 000 0 0 0 2 0 9999\n"
            .to_vec(),
    );
    assert!(validate_host_network_sources_v1(&lost, 30, 50).is_err());
    lost.insert(
        "netlink-queue-after.raw".into(),
        b"sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode\n0000 0 100 551 0 0 0 2 1 9999\n"
            .to_vec(),
    );
    assert!(validate_host_network_sources_v1(&lost, 30, 50).is_err());
    assert!(validate_host_network_sources_v1(&map, 5, 50).is_err());
    assert!(validate_host_network_sources_v1(&map, 30, 80).is_err());
}
#[test]
fn restored_transient_route_or_link_mutation_is_not_preservation() {
    let mut map = fixture();
    let mut notification = b"MCHN\x01\0\0\0".to_vec();
    let packet = message(17, &[0; 16], 0, 0);
    notification.extend_from_slice(&45u64.to_le_bytes());
    notification.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    notification.extend(packet);
    map.insert("notifications.raw".into(), notification);
    assert!(validate_host_network_sources_v1(&map, 30, 50).is_err());
    let mut map = fixture();
    let mut packet = map["after/links-dump.raw"].clone();
    packet[16 + 16 + 8] = 74;
    map.insert("after/links-dump.raw".into(), packet);
    assert!(validate_host_network_sources_v1(&map, 30, 50).is_err());
}
#[test]
fn real_kernel_writer_event_rejects_even_equal_before_after() {
    let map = fixture();
    let key = DiagnosticSha256::from_bytes([9; 32]);
    diagnostic_host_kernel_sources_v1(&map, &capture(&key, false), &key, 30, 50).unwrap();
    assert!(diagnostic_host_kernel_sources_v1(&map, &capture(&key, true), &key, 30, 50).is_err());
    let mut bytes = capture(&key, false);
    bytes[28..32].copy_from_slice(&15u32.to_le_bytes());
    assert!(diagnostic_host_kernel_sources_v1(&map, &bytes, &key, 30, 50).is_err());
    let mut bytes = capture(&key, false);
    bytes[40 + 144..40 + 152].fill(0);
    assert!(diagnostic_host_kernel_sources_v1(&map, &bytes, &key, 30, 50).is_err());
}
