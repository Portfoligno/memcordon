use memcordon_ci::release::linux_installed_consumer::host_network_configuration_unchanged;
use serde_json::{Value, json};

const LOOPBACK_ROUTE: &str = "00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000005 00000000 80200001 lo\n";

fn snapshot(route: &str) -> Value {
    json!({
        "namespace_device": 4,
        "namespace_inode": 4026531992_u64,
        "facts": {
            "/proc/net/ipv6_route": route.as_bytes(),
            "/proc/net/route": b"unchanged IPv4 routes\n".as_slice(),
            "/proc/sys/net/ipv4/ip_nonlocal_bind": b"0\n".as_slice(),
        },
        "links": {"lo": {"ifindex": b"1\n".as_slice(), "flags": b"0x9\n".as_slice()}},
    })
}

#[test]
fn observed_ipv6_reference_churn_does_not_change_configuration_or_raw_capture() {
    let before = snapshot(LOOPBACK_ROUTE);
    let after = snapshot(&LOOPBACK_ROUTE.replace("00000005", "00000006"));
    let original_before = before.clone();
    let original_after = after.clone();
    assert!(host_network_configuration_unchanged(&before, &after).unwrap());
    assert_eq!(before, original_before);
    assert_eq!(after, original_after);
    assert_ne!(before, after);
}

#[test]
fn route_configuration_and_every_other_snapshot_field_remain_guarded() {
    let before = snapshot(LOOPBACK_ROUTE);
    let fields: Vec<_> = LOOPBACK_ROUTE.split_ascii_whitespace().collect();
    for (index, changed) in [
        (0, "00000000000000000000000000000002"),
        (1, "7f"),
        (2, "00000000000000000000000000000001"),
        (3, "01"),
        (4, "00000000000000000000000000000001"),
        (5, "00000001"),
        (7, "00000001"),
        (8, "80200000"),
        (9, "eth0"),
    ] {
        let mut changed_fields = fields.clone();
        changed_fields[index] = changed;
        assert!(
            !host_network_configuration_unchanged(&before, &snapshot(&changed_fields.join(" ")))
                .unwrap(),
            "configuration field {index} must remain guarded"
        );
    }
    for path in [
        "/namespace_inode",
        "/namespace_device",
        "/facts/~1proc~1net~1route",
        "/facts/~1proc~1sys~1net~1ipv4~1ip_nonlocal_bind",
        "/links/lo/ifindex",
        "/links/lo/flags",
    ] {
        let mut after = before.clone();
        *after.pointer_mut(path).unwrap() = json!("actual changed observation");
        assert!(!host_network_configuration_unchanged(&before, &after).unwrap());
    }
}

#[test]
fn malformed_route_observations_fail_closed_even_when_both_snapshots_match() {
    let fields: Vec<_> = LOOPBACK_ROUTE.split_ascii_whitespace().collect();
    for (index, malformed) in [
        (0, "not-an-address"),
        (1, "81"),
        (3, "ff"),
        (5, "100000000"),
        (6, "not-a-reference-count"),
        (6, "100000000"),
        (7, "-0000001"),
        (8, "z0200001"),
    ] {
        let mut changed = fields.clone();
        changed[index] = malformed;
        let invalid = snapshot(&changed.join(" "));
        assert!(host_network_configuration_unchanged(&invalid, &invalid).is_err());
    }
    for route in ["missing fields", "\n", "invalid\u{fffd}bytes"] {
        let invalid = snapshot(route);
        assert!(host_network_configuration_unchanged(&invalid, &invalid).is_err());
    }
    let mut missing = snapshot(LOOPBACK_ROUTE);
    missing["facts"]
        .as_object_mut()
        .unwrap()
        .remove("/proc/net/ipv6_route");
    assert!(host_network_configuration_unchanged(&missing, &missing).is_err());
    let mut non_byte = snapshot(LOOPBACK_ROUTE);
    non_byte["facts"]["/proc/net/ipv6_route"] = json!([256]);
    assert!(host_network_configuration_unchanged(&non_byte, &non_byte).is_err());
}
