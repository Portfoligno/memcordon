#![cfg(target_os = "linux")]

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::process::Command;

const AGENT: &str = "/usr/libexec/memcordon-sealed-agent";

#[test]
fn sealed_package_identity_rejects_tampered_provider() {
    let metadata = std::fs::symlink_metadata(AGENT).expect("installed provider must exist");
    assert!(!metadata.file_type().is_symlink());
    assert_eq!(metadata.uid(), 0);
    assert_eq!(metadata.permissions().mode() & 0o022, 0);
    let status = Command::new(AGENT)
        .args(["package", "verify"])
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn sealed_package_upgrade_recovers_before_advertising() {
    let status = Command::new(AGENT)
        .args(["package", "upgrade", "--ephemeral-ci"])
        .status()
        .unwrap();
    assert!(status.success());
    let socket = Command::new("/usr/bin/systemctl")
        .args(["is-active", "memcordon-sealed-agent.socket"])
        .status()
        .unwrap();
    assert!(socket.success());
    let qualification = Command::new(AGENT).arg("qualify").output().unwrap();
    assert!(qualification.status.success());
    let receipt: serde_json::Value = serde_json::from_slice(&qualification.stdout).unwrap();
    assert_eq!(receipt["boundary_retired"], true);

    let execution = memcordon_platform::supervise(memcordon_platform::SupervisorRequest {
        policy: memcordon_core::Policy::unbounded().sealed(),
        restart: memcordon_core::RestartPolicy::Never,
        command: memcordon_core::CommandSpec::new(env!(
            "CARGO_BIN_EXE_memcordon-sealed-test-fixture"
        ))
        .args(["exit"]),
        memcordon_executable: None,
    })
    .expect("installed socket-activated provider must supervise end to end");
    assert_eq!(execution.wrapper_exit_code(), 0);
    assert_eq!(execution.targets_authorized(), 1);
    assert_eq!(execution.attempts().total, 1);
    let attempt = execution.attempts().records().next().unwrap();
    assert!(attempt.launch.target_released);
    assert!(attempt.launch.boundary_assignment_verified);
    assert!(attempt.launch.inherited_resources_restricted);
    assert!(attempt.restart_safety.sealed_boundary_retired);
    assert!(matches!(
        &attempt.boundary_detail,
        memcordon_core::BoundaryMechanismEvidence::LinuxPidNamespaceCgroupV1(evidence)
            if evidence.schema_version == 1
                && evidence.cgroup_empty_verified
                && evidence.namespace_init_reaped
                && evidence.guardian_reaped
                && evidence.cgroup_removed
    ));
    let wire = serde_json::to_value(&execution).unwrap();
    assert_eq!(wire["wrapper_exit_code"], 0);
    assert_eq!(wire["targets_authorized"], 1);
    assert_eq!(wire["attempts"]["total"], 1);

    let service = Command::new("/usr/bin/systemctl")
        .args(["is-active", "memcordon-sealed-agent.service"])
        .status()
        .unwrap();
    assert!(service.success());
}

#[test]
fn sealed_package_uninstall_refuses_live_authenticated_attempt() {
    let identity = "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1".to_owned();
    let record = memcordon_sealed_agent::linux::attempt::AttemptRecord::create(identity, unsafe {
        libc::getpid()
    })
    .unwrap();
    let status = Command::new(AGENT)
        .args(["package", "uninstall", "--ephemeral-ci"])
        .status()
        .unwrap();
    assert!(!status.success());
    record.retire().unwrap();
    assert!(std::path::Path::new(AGENT).exists());
}
