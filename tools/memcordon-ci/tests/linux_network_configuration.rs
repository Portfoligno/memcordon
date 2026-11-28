use memcordon_ci::release::linux_current_network::{
    host_network_comparison, host_network_configuration_unchanged,
};
use serde_json::{Value, json};

#[test]
fn captured_same_mac_slave_addition_stays_strict_without_native_provenance() {
    let before: Value =
        serde_json::from_slice(include_bytes!("fixtures/linux_host_network_before.json")).unwrap();
    let after: Value =
        serde_json::from_slice(include_bytes!("fixtures/linux_host_network_after.json")).unwrap();
    let original_before = before.clone();
    let original_after = after.clone();
    let comparison =
        memcordon_ci::release::linux_current_network::host_network_comparison(&before, &after)
            .unwrap();
    assert_eq!(comparison["unchanged"], false);
    assert!(
        comparison["acceleration_churn"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let changes = comparison["changes"].as_array().unwrap();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0]["path"], json!(["links", "enP29613s1"]));
    assert_eq!(changes[0]["before"]["present"], false);
    assert_eq!(before, original_before);
    assert_eq!(after, original_after);
}

#[test]
fn malformed_link_population_has_an_explicit_structural_delta() {
    let before = snapshot(LOOPBACK_ROUTE);
    let mut after = before.clone();
    after["links"] = json!("not a native link map");
    let comparison =
        memcordon_ci::release::linux_current_network::host_network_comparison(&before, &after)
            .unwrap();
    assert_eq!(comparison["unchanged"], false);
    assert_eq!(comparison["changes"][0]["path"], json!(["links"]));
}

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

fn link_identity(name: &str, ifindex: u32) -> Value {
    json!({
        "path": format!("/sys/devices/example/net/{name}"),
        "device": 4,
        "inode": 500 + ifindex,
        "ifindex": ifindex,
    })
}

fn observed_link(name: &str, ifindex: u32, subsystem: &str, driver: &str) -> Value {
    json!({
        "ifindex": format!("{ifindex}\n").as_bytes(),
        "address": b"00:0d:3a:ff:ee:dd\n".as_slice(),
        "flags": b"0x1003\n".as_slice(),
        "operstate": b"up\n".as_slice(),
        "provenance": {
            "revision": 1,
            "state": "observed",
            "identity": link_identity(name, ifindex),
            "device": {
                "path": "/sys/devices/example",
                "subsystem": format!("/sys/bus/{subsystem}"),
                "driver": format!("/sys/bus/{subsystem}/drivers/{driver}"),
                "physfn": null,
            },
            "master": null,
            "uppers": {},
            "lowers": {},
        },
    })
}

fn add_vf(snapshot: &mut Value, name: &str, ifindex: u32) {
    let mut vf = observed_link(name, ifindex, "pci", "mlx5_core");
    let master_identity = &snapshot["links"]["eth0"]["provenance"]["identity"];
    vf["provenance"]["master"] = json!({"name": "eth0", "identity": master_identity});
    vf["provenance"]["uppers"]["eth0"] = master_identity.clone();
    snapshot["links"]["eth0"]["provenance"]["lowers"][name] = link_identity(name, ifindex);
    snapshot["links"][name] = vf;
}

fn acceleration_snapshots() -> (Value, Value) {
    let mut without = snapshot(LOOPBACK_ROUTE);
    without["links"]["eth0"] = observed_link("eth0", 2, "vmbus", "hv_netvsc");
    let mut with = without.clone();
    add_vf(&mut with, "vf0", 3);
    (without, with)
}

fn assert_proven_acceleration(kind: &str, before: &Value, after: &Value) {
    let original_before = before.clone();
    let original_after = after.clone();
    let comparison = host_network_comparison(before, after).unwrap();
    assert_eq!(comparison["unchanged"], true);
    assert_eq!(comparison["changes"], json!([]));
    assert_eq!(comparison["omitted_changes"], 0);
    assert_eq!(
        comparison["acceleration_churn"],
        json!([{
            "kind": kind,
            "link": "vf0",
            "master": "eth0",
            "vf_identity": link_identity("vf0", 3),
            "master_identity": link_identity("eth0", 2),
        }]),
    );
    assert_eq!(*before, original_before);
    assert_eq!(*after, original_after);
}

#[test]
fn proven_azure_vf_hot_add_is_reported_as_acceleration_churn() {
    let (without, with) = acceleration_snapshots();
    assert_proven_acceleration("added", &without, &with);
}

#[test]
fn proven_azure_vf_hot_remove_is_reported_as_acceleration_churn() {
    let (without, with) = acceleration_snapshots();
    assert_proven_acceleration("removed", &with, &without);
}

fn assert_strict_acceleration(before: &Value, after: &Value, reason: &str) {
    for (left, right) in [(before, after), (after, before)] {
        let comparison = host_network_comparison(left, right).unwrap();
        assert_eq!(comparison["unchanged"], false, "{reason}");
        assert_eq!(comparison["acceleration_churn"], json!([]), "{reason}");
        for link in ["eth0", "vf0"] {
            assert!(
                comparison["changes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|change| change["path"] == json!(["links", link])),
                "{reason}: missing strict delta for {link}",
            );
        }
    }
}

#[test]
fn non_azure_or_unobserved_master_keeps_both_link_deltas_strict() {
    for (path, value) in [
        ("device/subsystem", json!("/sys/bus/pci")),
        ("device/driver", json!("/sys/bus/vmbus/drivers/other")),
        ("state", json!("unavailable")),
    ] {
        let (mut before, mut after) = acceleration_snapshots();
        let pointer = format!("/links/eth0/provenance/{path}");
        for snapshot in [&mut before, &mut after] {
            *snapshot.pointer_mut(&pointer).unwrap() = value.clone();
        }
        assert_strict_acceleration(&before, &after, path);
    }
}

#[test]
fn missing_or_mismatched_vf_proof_keeps_both_link_deltas_strict() {
    for (path, value) in [
        ("/address", json!(b"aa:bb:cc:dd:ee:ff\n".as_slice())),
        ("/provenance/state", json!("unavailable")),
        ("/provenance/device/subsystem", json!("/sys/bus/vmbus")),
        ("/provenance/master", Value::Null),
        ("/provenance/master/name", json!("missing")),
        ("/provenance/master/identity", link_identity("other", 4)),
        ("/provenance/uppers/eth0", link_identity("other", 4)),
        (
            "/provenance/uppers",
            json!({"eth0": link_identity("eth0", 2), "other": link_identity("other", 4)}),
        ),
        (
            "/provenance/lowers",
            json!({"other": link_identity("other", 4)}),
        ),
        ("/provenance/identity", link_identity("other", 4)),
    ] {
        let (before, mut after) = acceleration_snapshots();
        *after.pointer_mut(&format!("/links/vf0{path}")).unwrap() = value;
        assert_strict_acceleration(&before, &after, path);
    }
    let (mut before, mut after) = acceleration_snapshots();
    before["links"]["eth0"]["address"] = json!([]);
    after["links"]["eth0"]["address"] = json!([]);
    after["links"]["vf0"]["address"] = json!([]);
    assert_strict_acceleration(&before, &after, "empty matching addresses");
}

#[test]
fn any_other_master_delta_invalidates_acceleration_churn() {
    for (path, value) in [
        ("/ifindex", json!(b"9\n".as_slice())),
        ("/flags", json!(b"0x1002\n".as_slice())),
        ("/operstate", json!(b"down\n".as_slice())),
        ("/address", json!(b"aa:bb:cc:dd:ee:ff\n".as_slice())),
        ("/provenance/identity/inode", json!(99)),
        ("/provenance/device/physfn", json!("/sys/devices/physfn")),
        (
            "/provenance/master",
            json!({"name": "other", "identity": link_identity("other", 4)}),
        ),
        (
            "/provenance/uppers",
            json!({"other": link_identity("other", 4)}),
        ),
    ] {
        let (mut before, after) = acceleration_snapshots();
        *before.pointer_mut(&format!("/links/eth0{path}")).unwrap() = value;
        assert_strict_acceleration(&before, &after, path);
    }

    let (mut before, mut after) = acceleration_snapshots();
    before["links"]["eth0"]["provenance"]["lowers"]["existing"] = link_identity("existing", 4);
    after["links"]["eth0"]["provenance"]["lowers"]["existing"] = link_identity("existing", 4);
    assert_proven_acceleration("added", &before, &after);
    after["links"]["eth0"]["provenance"]["lowers"]["existing"] = link_identity("replacement", 5);
    assert_strict_acceleration(&before, &after, "another lower changed identity");

    let (mut before, after) = acceleration_snapshots();
    before["links"]["eth0"]["provenance"]["lowers"]["vf0"] = link_identity("stale", 4);
    assert_strict_acceleration(&before, &after, "stale lower was already present");
}

#[test]
fn master_delta_is_suppressed_only_when_every_changed_lower_is_proven() {
    let (before, mut after) = acceleration_snapshots();
    add_vf(&mut after, "vf1", 4);
    let comparison = host_network_comparison(&before, &after).unwrap();
    assert_eq!(comparison["unchanged"], true);
    assert_eq!(comparison["changes"], json!([]));
    let churn = comparison["acceleration_churn"].as_array().unwrap();
    assert_eq!(churn.len(), 2);
    assert_eq!(churn[0]["link"], "vf0");
    assert_eq!(churn[1]["link"], "vf1");

    after["links"]["vf1"]["provenance"]["state"] = json!("unavailable");
    assert_strict_acceleration(&before, &after, "unproven second VF");
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
