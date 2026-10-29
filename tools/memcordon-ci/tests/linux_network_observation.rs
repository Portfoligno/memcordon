#![cfg(unix)]

use memcordon_ci::release::linux_current_network::observe_link;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

fn link(base: &Path, name: &str, index: u32) -> PathBuf {
    let device = base.join("devices").join(name);
    let path = device.join("net").join(name);
    fs::create_dir_all(&path).unwrap();
    for (leaf, bytes) in [
        ("ifindex", format!("{index}\n")),
        ("address", "60:45:bd:07:46:e8\n".into()),
        ("flags", "0x1803\n".into()),
        ("operstate", "up\n".into()),
    ] {
        fs::write(path.join(leaf), bytes).unwrap();
    }
    symlink(&device, path.join("device")).unwrap();
    symlink(&path, base.join("class/net").join(name)).unwrap();
    path
}

#[test]
fn native_filesystem_observation_joins_exact_named_relations_and_device_paths() {
    let temporary = tempfile::tempdir().unwrap();
    let base = temporary.path();
    let root = base.join("class/net");
    fs::create_dir_all(&root).unwrap();
    let master = link(base, "eth0", 2);
    let slave = link(base, "vf0", 4);
    let bus = base.join("bus/pci");
    let driver = bus.join("drivers/native-vf");
    fs::create_dir_all(&driver).unwrap();
    symlink(&bus, base.join("devices/vf0/subsystem")).unwrap();
    symlink(&driver, base.join("devices/vf0/driver")).unwrap();
    symlink(&master, slave.join("master")).unwrap();
    symlink(&master, slave.join("upper_eth0")).unwrap();
    symlink(&slave, master.join("lower_vf0")).unwrap();
    let observed_master = observe_link(&root, "eth0").unwrap();
    let observed_slave = observe_link(&root, "vf0").unwrap();
    assert_eq!(observed_slave["provenance"]["state"], "observed");
    assert_eq!(
        observed_slave["provenance"]["device"]["subsystem"],
        fs::canonicalize(bus).unwrap().to_str().unwrap()
    );
    assert_eq!(
        observed_slave["provenance"]["device"]["driver"],
        fs::canonicalize(driver).unwrap().to_str().unwrap()
    );
    assert!(observed_slave["provenance"]["device"]["physfn"].is_null());
    assert_eq!(
        observed_slave["provenance"]["master"]["identity"],
        observed_master["provenance"]["identity"]
    );
    assert_eq!(
        observed_slave["provenance"]["uppers"]["eth0"],
        observed_master["provenance"]["identity"]
    );
    assert_eq!(
        observed_master["provenance"]["lowers"]["vf0"],
        observed_slave["provenance"]["identity"]
    );
    assert_eq!(observed_slave["provenance"]["identity"]["ifindex"], 4);
}

#[test]
fn contradictory_or_non_symlink_relations_keep_raw_capture_but_no_proof() {
    let temporary = tempfile::tempdir().unwrap();
    let base = temporary.path();
    let root = base.join("class/net");
    fs::create_dir_all(&root).unwrap();
    let master = link(base, "eth0", 2);
    let slave = link(base, "vf0", 4);
    symlink(&master, slave.join("upper_other")).unwrap();
    let observed = observe_link(&root, "vf0").unwrap();
    assert_eq!(observed["provenance"]["state"], "unavailable");
    assert_eq!(
        observed["address"],
        serde_json::json!(b"60:45:bd:07:46:e8\n".as_slice())
    );
    fs::write(master.join("lower_bad"), b"not a kernel relation").unwrap();
    let observed = observe_link(&root, "eth0").unwrap();
    assert_eq!(observed["provenance"]["state"], "unavailable");
    assert!(
        observed["provenance"]["error"]
            .as_str()
            .unwrap()
            .contains("not a kernel symlink")
    );
}

#[test]
fn oversized_native_leaf_fails_without_qualifying_a_snapshot() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("class/net");
    fs::create_dir_all(&root).unwrap();
    let path = link(temporary.path(), "eth0", 2);
    fs::write(path.join("address"), vec![b'x'; 1025]).unwrap();
    assert!(
        observe_link(&root, "eth0")
            .unwrap_err()
            .to_string()
            .contains("exceeds bound")
    );
}
