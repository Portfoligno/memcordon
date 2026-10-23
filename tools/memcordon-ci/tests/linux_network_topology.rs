use memcordon_ci::release::linux_network_topology::project_acceleration_churn;
use serde_json::{Value, json};

fn identity(name: &str, index: u64) -> Value {
    json!({"path":format!("/sys/devices/native/{name}/net/{name}"),"device":4,"inode":index + 100,"ifindex":index})
}

fn link(name: &str, index: u64, bus: &str, driver: &str) -> Value {
    json!({"ifindex":format!("{index}\n").as_bytes(),"address":b"60:45:bd:07:46:e8\n".as_slice(),
        "flags":b"0x1003\n".as_slice(),"operstate":b"up\n".as_slice(),
        "provenance":{"revision":1,"state":"observed","identity":identity(name,index),
            "device":{"path":format!("/sys/devices/native/{name}"),"subsystem":bus,"driver":driver,"physfn":null},
            "master":null,"uppers":{},"lowers":{}}})
}

fn pair() -> (Value, Value) {
    let master = link(
        "eth0",
        2,
        "/sys/bus/vmbus",
        "/sys/bus/vmbus/drivers/hv_netvsc",
    );
    let before = json!({"namespace_device":5,"namespace_inode":123,"facts":{"routes":"same","sysctl":"same"},"links":{"eth0":master}});
    let mut after = before.clone();
    let mut slave = link("vf0", 4, "/sys/bus/pci", "/sys/bus/pci/drivers/mlx5_core");
    slave["flags"] = json!(b"0x1803\n".as_slice());
    slave["provenance"]["master"] = json!({"name":"eth0","identity":identity("eth0",2)});
    slave["provenance"]["uppers"]["eth0"] = identity("eth0", 2);
    after["links"]["vf0"] = slave;
    after["links"]["eth0"]["provenance"]["lowers"]["vf0"] = identity("vf0", 4);
    (before, after)
}

#[test]
fn only_complete_single_edge_addition_or_removal_is_projected() {
    for removal in [false, true] {
        let (mut before, mut after) = pair();
        if removal {
            std::mem::swap(&mut before, &mut after);
        }
        let decisions = project_acceleration_churn(&mut before, &mut after);
        assert_eq!(decisions.len(), 1);
        assert_eq!(before, after);
        assert_eq!(
            decisions[0]["change"],
            if removal { "removed" } else { "added" }
        );
    }
}

#[test]
fn incomplete_ambiguous_and_changed_provenance_stays_strict() {
    for (path, value) in [
        ("/links/vf0/provenance", Value::Null),
        ("/links/vf0/provenance/state", json!("unavailable")),
        ("/links/vf0/provenance/revision", json!(2)),
        ("/links/vf0/provenance/identity/ifindex", json!(99)),
        (
            "/links/vf0/provenance/identity/path",
            json!("/sys/devices/../net/vf0"),
        ),
        ("/links/vf0/provenance/identity/inode", json!(0)),
        (
            "/links/vf0/provenance/device/subsystem",
            json!("/sys/bus/virtual"),
        ),
        (
            "/links/vf0/provenance/device/path",
            json!("/sys/devices/foreign"),
        ),
        ("/links/vf0/provenance/device/driver", Value::Null),
        (
            "/links/vf0/provenance/device/driver",
            json!("/sys/bus/pci/drivers/a/other"),
        ),
        ("/links/vf0/provenance/master/identity/ifindex", json!(99)),
        ("/links/vf0/provenance/master", Value::Null),
        ("/links/vf0/provenance/uppers", json!({})),
        (
            "/links/vf0/provenance/lowers",
            json!({"unknown":identity("unknown",8)}),
        ),
        ("/links/vf0/flags", json!(b"0x1003\n".as_slice())),
        ("/links/vf0/address", json!(b"different\n".as_slice())),
        (
            "/links/eth0/provenance/device/driver",
            json!("/sys/bus/vmbus/drivers/other"),
        ),
        ("/links/eth0/provenance/identity/inode", json!(999)),
        ("/links/eth0/provenance/lowers/vf0/ifindex", json!(99)),
        ("/links/eth0/operstate", json!(b"down\n".as_slice())),
    ] {
        let (mut before, mut after) = pair();
        *after.pointer_mut(path).unwrap() = value;
        let original_before = before.clone();
        let original_after = after.clone();
        assert!(
            project_acceleration_churn(&mut before, &mut after).is_empty(),
            "{path}"
        );
        assert_eq!(before, original_before);
        assert_eq!(after, original_after);
    }
    let (mut before, mut after) = pair();
    after["links"]["vf0"]["unknown"] = json!(true);
    assert!(project_acceleration_churn(&mut before, &mut after).is_empty());
    let (mut before, mut after) = pair();
    after["links"]["vf0"]["provenance"]["unknown"] = json!(true);
    assert!(project_acceleration_churn(&mut before, &mut after).is_empty());
    let (mut before, mut after) = pair();
    after["links"]["vf0"]["provenance"]["device"]["unknown"] = json!(true);
    assert!(project_acceleration_churn(&mut before, &mut after).is_empty());
}

#[test]
fn unchanged_namespace_facts_and_existing_links_are_not_projected_away() {
    for path in [
        "/namespace_inode",
        "/namespace_device",
        "/facts/routes",
        "/facts/sysctl",
    ] {
        let (mut before, mut after) = pair();
        *after.pointer_mut(path).unwrap() = json!("changed");
        project_acceleration_churn(&mut before, &mut after);
        assert_ne!(before, after, "{path}");
    }
    let (_, mut before) = pair();
    let mut after = before.clone();
    after["links"]["vf0"]["operstate"] = json!(b"down\n".as_slice());
    assert!(project_acceleration_churn(&mut before, &mut after).is_empty());
    assert_ne!(before, after);
}

#[test]
fn multiple_new_edges_cannot_jointly_hide_master_changes() {
    let (mut before, mut after) = pair();
    let mut second = after["links"]["vf0"].clone();
    second["provenance"]["identity"] = identity("vf1", 5);
    second["ifindex"] = json!(b"5\n".as_slice());
    after["links"]["vf1"] = second;
    after["links"]["eth0"]["provenance"]["lowers"]["vf1"] = identity("vf1", 5);
    assert!(project_acceleration_churn(&mut before, &mut after).is_empty());
}

#[test]
fn captured_same_mac_slave_without_native_provenance_never_qualifies() {
    let (mut before, mut after) = pair();
    for snapshot in [&mut before, &mut after] {
        for value in snapshot["links"].as_object_mut().unwrap().values_mut() {
            value.as_object_mut().unwrap().remove("provenance");
        }
    }
    assert!(project_acceleration_churn(&mut before, &mut after).is_empty());
    assert_ne!(before, after);
}

#[test]
fn kernel_integer_bounds_and_optional_physical_function_stay_strict() {
    for (path, value) in [
        (
            "/links/vf0/provenance/identity/ifindex",
            json!(u64::from(u32::MAX) + 1),
        ),
        ("/links/vf0/ifindex", json!(b"4294967296\n".as_slice())),
        ("/links/vf0/flags", json!(b"0x100001803\n".as_slice())),
        ("/links/vf0/provenance/device/physfn", json!("/sys/bus/pci")),
        (
            "/links/vf0/provenance/device/physfn",
            json!("/sys/devices/../foreign"),
        ),
    ] {
        let (mut before, mut after) = pair();
        *after.pointer_mut(path).unwrap() = value;
        assert!(
            project_acceleration_churn(&mut before, &mut after).is_empty(),
            "{path}"
        );
    }
    let (mut before, mut after) = pair();
    after["links"]["vf0"]["provenance"]["identity"]["ifindex"] = json!(u64::from(u32::MAX) + 1);
    after["links"]["vf0"]["ifindex"] = json!(b"4294967296\n".as_slice());
    after["links"]["eth0"]["provenance"]["lowers"]["vf0"] =
        after["links"]["vf0"]["provenance"]["identity"].clone();
    assert!(project_acceleration_churn(&mut before, &mut after).is_empty());
    let (mut before, mut after) = pair();
    after["links"]["vf0"]["provenance"]["device"]["physfn"] =
        json!("/sys/devices/pci-native/function");
    assert_eq!(project_acceleration_churn(&mut before, &mut after).len(), 1);
    assert_eq!(before, after);
}
