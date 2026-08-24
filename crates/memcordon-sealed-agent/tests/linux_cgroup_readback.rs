#![cfg(all(target_os = "linux", feature = "test-support"))]

use std::path::Path;

use tempfile::TempDir;

const PRIVATE_CONTROLS: &[(&str, &str)] = &[
    ("cgroup.controllers", "memory pids\n"),
    ("cgroup.events", "populated 0\n"),
    ("cgroup.kill", ""),
    ("cgroup.procs", ""),
    ("cgroup.subtree_control", "memory\n"),
];

const ATTEMPT_CONTROLS: &[&str] = &[
    "cgroup.events",
    "cgroup.kill",
    "cgroup.procs",
    "memory.events",
    "memory.max",
    "memory.swap.max",
];

fn create_controls(root: &Path, controls: &[(&str, &str)]) {
    for (name, contents) in controls {
        std::fs::write(root.join(name), contents).unwrap();
    }
}

#[test]
fn private_receipt_uses_non_root_cgroup_controls_and_memory_readback() {
    let temporary = TempDir::new().unwrap();
    create_controls(temporary.path(), PRIVATE_CONTROLS);

    memcordon_sealed_agent::linux::cgroup::prepare_private_root_for_test(temporary.path()).unwrap();
}

#[test]
fn private_root_without_non_root_kill_or_memory_controller_fails_closed() {
    let temporary = TempDir::new().unwrap();
    create_controls(temporary.path(), PRIVATE_CONTROLS);
    std::fs::remove_file(temporary.path().join("cgroup.kill")).unwrap();
    let error =
        memcordon_sealed_agent::linux::cgroup::prepare_private_root_for_test(temporary.path())
            .unwrap_err();
    assert!(error.contains("omitted cgroup.kill"));

    std::fs::write(temporary.path().join("cgroup.kill"), "").unwrap();
    std::fs::write(temporary.path().join("cgroup.controllers"), "pids\n").unwrap();
    let error =
        memcordon_sealed_agent::linux::cgroup::prepare_private_root_for_test(temporary.path())
            .unwrap_err();
    assert!(error.contains("memory is unavailable"));
}

#[test]
fn attempt_control_inventory_requires_memory_and_retirement_interfaces() {
    let temporary = TempDir::new().unwrap();
    for control in ATTEMPT_CONTROLS {
        std::fs::write(temporary.path().join(control), "").unwrap();
    }
    memcordon_sealed_agent::linux::cgroup::verify_attempt_controls_for_test(temporary.path())
        .unwrap();

    std::fs::remove_file(temporary.path().join("memory.swap.max")).unwrap();
    let error =
        memcordon_sealed_agent::linux::cgroup::verify_attempt_controls_for_test(temporary.path())
            .unwrap_err();
    assert!(error.contains("memory.swap.max"));
}
