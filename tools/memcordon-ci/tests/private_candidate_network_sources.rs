use memcordon_ci::private_candidate_replay::parse_held_tcp_table;
use memcordon_ci::private_candidate_replay::validate_private_loopback_dump_v1;
use std::collections::BTreeMap;

const HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n";
#[test]
fn original_tcp_table_retains_endpoints_state_and_owned_inode() {
    let bytes=[HEADER," 0: 0100007F:7530 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 901 1 0000000000000000\n"," 1: 0100007F:C350 0100007F:7530 01 00000000:00000000 00:00000000 00000000 1000 0 902 1 0000000000000000\n"].concat();
    let rows = parse_held_tcp_table(bytes.as_bytes()).unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].state, 10);
    assert_eq!(rows[0].local_port, 30000);
    assert_eq!(rows[0].inode, 901);
    assert_eq!(rows[1].remote_port, 30000);
    assert_eq!(rows[1].inode, 902);
}
#[test]
fn malformed_endpoint_duplicate_inode_and_owner_summary_header_reject() {
    let row =
        " 0: 0100007F:7530 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 901\n";
    assert!(parse_held_tcp_table([HEADER, row, row].concat().as_bytes()).is_err());
    assert!(
        parse_held_tcp_table(
            [HEADER, "0: 7F:7530 00000000:0000 0A 0 0 0 1000 0 901\n"]
                .concat()
                .as_bytes()
        )
        .is_err()
    );
    assert!(parse_held_tcp_table(b"listener socket inode=901\n").is_err());
}

fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
    let length = 4 + value.len();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(length as u16).to_le_bytes());
    bytes.extend_from_slice(&kind.to_le_bytes());
    bytes.extend_from_slice(value);
    bytes.resize((length + 3) & !3, 0);
    bytes
}
fn message(kind: u16, flags: u16, body: &[u8]) -> Vec<u8> {
    let length = 16 + body.len();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(length as u32).to_le_bytes());
    bytes.extend_from_slice(&kind.to_le_bytes());
    bytes.extend_from_slice(&flags.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&701u32.to_le_bytes());
    bytes.extend_from_slice(body);
    bytes.resize((length + 3) & !3, 0);
    bytes
}
fn original_loopback_dump() -> BTreeMap<String, Vec<u8>> {
    let mut link = vec![0u8; 16];
    link[2..4].copy_from_slice(&772u16.to_le_bytes());
    link[4..8].copy_from_slice(&1u32.to_le_bytes());
    link[8..12].copy_from_slice(&9u32.to_le_bytes());
    link.extend(attribute(3, b"lo\0"));
    let mut address = vec![2, 8, 0, 254, 1, 0, 0, 0];
    for kind in [1, 2] {
        address.extend(attribute(kind, &[127, 0, 0, 1]));
    }
    let mut map = BTreeMap::new();
    for (label, request, response, size, body) in [
        ("links", 18, 16, 16, link),
        ("addresses", 22, 20, 8, address),
    ] {
        map.insert(
            format!("{label}/request.raw"),
            message(request, 0x301, &vec![0; size]),
        );
        map.insert(format!("{label}/0.raw"), message(response, 2, &body));
        map.insert(format!("{label}/1.raw"), message(3, 2, &0i32.to_le_bytes()));
    }
    map.insert("routes/request.raw".into(), message(26, 0x301, &[0; 12]));
    let mut packet = Vec::new();
    for (prefix, scope, kind, destination) in [
        (8, 254, 2, [127, 0, 0, 0]),
        (32, 254, 2, [127, 0, 0, 1]),
        (32, 253, 3, [127, 255, 255, 255]),
    ] {
        let mut route = vec![2, prefix, 0, 0, 255, 2, scope, kind, 0, 0, 0, 0];
        route.extend(attribute(1, &destination));
        route.extend(attribute(4, &1u32.to_le_bytes()));
        route.extend(attribute(7, &[127, 0, 0, 1]));
        packet.extend(message(24, 2, &route));
    }
    map.insert("routes/0.raw".into(), packet);
    map.insert("routes/1.raw".into(), message(3, 2, &0i32.to_le_bytes()));
    map
}
#[test]
fn original_kernel_loopback_dump_checks_requests_objects_and_done() {
    validate_private_loopback_dump_v1(&original_loopback_dump()).unwrap();
}
#[test]
fn netlink_wrong_peer_sequence_interruption_extra_link_and_missing_done_reject() {
    for (field, value) in [(8, 2u32), (12, 0), (6, 0x12)] {
        let mut map = original_loopback_dump();
        let bytes = map.get_mut("links/0.raw").unwrap();
        if field == 6 {
            bytes[field..field + 2].copy_from_slice(&(value as u16).to_le_bytes());
        } else {
            bytes[field..field + 4].copy_from_slice(&value.to_le_bytes());
        }
        assert!(validate_private_loopback_dump_v1(&map).is_err());
    }
    let mut missing = original_loopback_dump();
    missing.remove("routes/1.raw");
    assert!(validate_private_loopback_dump_v1(&missing).is_err());
    let mut extra = original_loopback_dump();
    let second = extra["links/0.raw"].clone();
    extra.get_mut("links/0.raw").unwrap().extend(second);
    assert!(validate_private_loopback_dump_v1(&extra).is_err());
    let mut gateway = original_loopback_dump();
    let route = gateway.get_mut("routes/0.raw").unwrap();
    let length = u32::from_le_bytes(route[..4].try_into().unwrap()) as usize;
    let gateway_attr = attribute(5, &[10, 0, 0, 1]);
    route.splice(length..length, gateway_attr.iter().copied());
    route[..4].copy_from_slice(&((length + gateway_attr.len()) as u32).to_le_bytes());
    assert!(validate_private_loopback_dump_v1(&gateway).is_err());
}

#[test]
fn wrong_main_unicast_prefix_does_not_replace_automatic_local_route() {
    let mut map = original_loopback_dump();
    let packet = map.get_mut("routes/0.raw").unwrap();
    packet[16 + 4] = 254;
    packet[16 + 6] = 253;
    packet[16 + 7] = 1;
    assert!(validate_private_loopback_dump_v1(&map).is_err());
}
