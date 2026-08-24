#![cfg(target_os = "linux")]

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::process::Command;

const AGENT: &str = "/usr/libexec/memcordon-sealed-agent";

struct PermissionRestore {
    path: &'static str,
    permissions: Option<std::fs::Permissions>,
}

impl PermissionRestore {
    fn restore(&mut self) -> std::io::Result<()> {
        if let Some(permissions) = &self.permissions {
            std::fs::set_permissions(self.path, permissions.clone())?;
            self.permissions = None;
        }
        Ok(())
    }
}

impl Drop for PermissionRestore {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

struct AttemptRecordCleanup {
    record: Option<memcordon_sealed_agent::linux::attempt::AttemptRecord>,
}

impl AttemptRecordCleanup {
    fn disarm(&mut self) {
        self.record = None;
    }
}

impl Drop for AttemptRecordCleanup {
    fn drop(&mut self) {
        if let Some(record) = self.record.take() {
            let _ = record.retire();
        }
    }
}

fn assert_successful_public_execution(execution: &memcordon_core::SupervisionExecution) {
    let terminal = serde_json::to_string(execution.terminal())
        .expect("typed supervision terminal must be serializable");
    let typed_failure = match execution.terminal() {
        memcordon_core::SupervisionTerminal::Error {
            attempt_number,
            error,
        } => format!(
            "attempt={attempt_number:?}; category={}; code={}; spawn-class={:?}; os-code={:?}; supervision-phase={:?}; launch-phase={:?}; target-released={}; workload-may-be-alive={}; provider-rejection={:?}",
            error.category,
            error.code,
            error.initial_spawn_failure,
            error.os_code,
            error.supervision_phase,
            error.launch_phase,
            error.target_released,
            error.workload_may_be_alive,
            error.provider_rejection
        ),
        _ => "no typed spawn failure".to_owned(),
    };
    assert_eq!(
        execution.wrapper_exit_code(),
        0,
        "post-upgrade public launch failed: wrapper-status={}; typed-failure={typed_failure}; typed-terminal={terminal}",
        execution.wrapper_exit_code()
    );
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_package_identity_rejects_tampered_provider() {
    let metadata = std::fs::symlink_metadata(AGENT).expect("installed provider must exist");
    assert!(!metadata.file_type().is_symlink());
    assert!(metadata.file_type().is_file());
    assert_eq!(metadata.uid(), 0);
    assert_eq!(metadata.gid(), 0);
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o755);
    let mut restore = PermissionRestore {
        path: AGENT,
        permissions: Some(metadata.permissions()),
    };
    let mut tampered = metadata.permissions();
    tampered.set_mode(0o775);
    std::fs::set_permissions(AGENT, tampered).unwrap();
    let rejected = Command::new(AGENT)
        .args(["package", "verify"])
        .output()
        .unwrap();
    restore.restore().unwrap();
    assert_eq!(rejected.status.code(), Some(125));
    let rejection = String::from_utf8(rejected.stderr).unwrap();
    assert!(rejection.starts_with("MCSEALED-PACKAGE-VERIFY:"));
    assert!(rejection.contains("mode is not 0755"));
    let restored = Command::new(AGENT)
        .args(["package", "verify"])
        .status()
        .unwrap();
    assert!(restored.success());
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_package_upgrade_recovers_before_advertising() {
    let identity = "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2".to_owned();
    let record_path =
        std::path::Path::new(memcordon_sealed_agent::linux::STATE_ROOT).join(&identity);
    let cgroup_path =
        std::path::Path::new(memcordon_sealed_agent::linux::CGROUP_ROOT).join(&identity);
    let record =
        memcordon_sealed_agent::linux::attempt::AttemptRecord::create(identity, libc::pid_t::MAX)
            .unwrap();
    record.transition("boundary-created").unwrap();
    let mut stale_record = AttemptRecordCleanup {
        record: Some(record),
    };
    assert!(record_path.is_file());
    assert!(
        !cgroup_path.exists(),
        "record-only stale recovery fixture must not stage an attempt cgroup"
    );
    assert!(
        std::fs::read_to_string(&record_path)
            .unwrap()
            .lines()
            .any(|line| line == "state=boundary-created")
    );
    let status = Command::new(AGENT)
        .args(["package", "upgrade", "--ephemeral-ci"])
        .status()
        .unwrap();
    assert!(status.success());
    assert!(
        !record_path.exists(),
        "upgrade advertised before retiring the authenticated stale record"
    );
    assert!(
        !cgroup_path.exists(),
        "record-only upgrade recovery created or retained an attempt cgroup"
    );
    stale_record.disarm();
    let socket = Command::new("/usr/bin/systemctl")
        .args(["is-active", "memcordon-sealed-agent.socket"])
        .status()
        .unwrap();
    assert!(socket.success());
    let qualification = Command::new(AGENT).arg("probe").output().unwrap();
    assert!(qualification.status.success());
    let receipt: serde_json::Value = serde_json::from_slice(&qualification.stdout).unwrap();
    assert_eq!(receipt["boundary_retired"], true);

    let policy = memcordon_core::Policy::unbounded().sealed();
    let backend = memcordon_platform::probe()
        .selected_for(memcordon_core::BoundaryRequirement::Sealed)
        .cloned()
        .expect("installed provider must resolve");
    let backend_capabilities =
        memcordon_platform::capabilities_for(&backend, memcordon_core::BoundaryRequirement::Sealed);
    let active_qualification = backend_capabilities
        .boundary_qualification
        .as_ref()
        .expect("installed provider must expose its active qualification");
    assert_eq!(
        receipt["provider_identity"],
        active_qualification.provider_identity
    );
    assert_eq!(
        receipt["receipt_digest"],
        active_qualification.receipt_digest
    );
    let execution = memcordon_platform::supervise(memcordon_platform::SupervisorRequest {
        policy,
        restart: memcordon_core::RestartPolicy::Never,
        command: memcordon_core::CommandSpec::new("/usr/bin/true"),
        memcordon_executable: None,
        resolved_backend: Some(backend_capabilities),
    })
    .expect("installed socket-activated provider must supervise end to end");
    assert_successful_public_execution(&execution);
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
                && receipt["provider_identity"].as_str()
                    == Some(evidence.provider_identity.as_str())
                && receipt["receipt_digest"].as_str()
                    == Some(evidence.cgroup_identity_digest.as_str())
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
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_package_uninstall_refuses_live_authenticated_attempt() {
    let identity = "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1".to_owned();
    let record_path =
        std::path::Path::new(memcordon_sealed_agent::linux::STATE_ROOT).join(&identity);
    let cgroup_path =
        std::path::Path::new(memcordon_sealed_agent::linux::CGROUP_ROOT).join(&identity);
    // SAFETY: getpid has no pointer arguments and returns this live test frontend's pid.
    let frontend_pid = unsafe { libc::getpid() };
    // SAFETY: signal zero performs a liveness/permission probe without delivering a signal.
    assert_eq!(unsafe { libc::kill(frontend_pid, 0) }, 0);
    let record = memcordon_sealed_agent::linux::attempt::AttemptRecord::create(
        identity.clone(),
        frontend_pid,
    )
    .unwrap();
    let mut live_record = AttemptRecordCleanup {
        record: Some(record),
    };
    let authenticated_before = std::fs::read(&record_path).unwrap();
    let authenticated_text = std::str::from_utf8(&authenticated_before).unwrap();
    assert!(
        authenticated_text
            .lines()
            .any(|line| line == format!("frontend-pid={frontend_pid}")),
        "live authenticated record omitted the current frontend pid"
    );
    assert!(
        authenticated_text
            .lines()
            .any(|line| line == "state=allocated"),
        "live authenticated record omitted its allocated state"
    );
    let output = Command::new(AGENT)
        .args(["package", "uninstall", "--ephemeral-ci"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(125));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        format!("refusing to uninstall while sealed recovery is ambiguous: {identity}\n")
    );
    // SAFETY: signal zero confirms the refused mutation did not terminate the live frontend.
    assert_eq!(unsafe { libc::kill(frontend_pid, 0) }, 0);
    assert_eq!(std::fs::read(&record_path).unwrap(), authenticated_before);
    assert!(
        !cgroup_path.exists(),
        "record-only live-attempt fixture must not fabricate a cgroup"
    );
    assert!(std::path::Path::new(AGENT).exists());
    let retained = Command::new(AGENT)
        .args(["package", "verify"])
        .output()
        .unwrap();
    assert!(
        retained.status.success(),
        "refused uninstall damaged the installed provider: status={}; stdout={}; stderr={}",
        retained.status,
        String::from_utf8_lossy(&retained.stdout),
        String::from_utf8_lossy(&retained.stderr)
    );
    assert!(retained.stdout.is_empty());
    assert!(retained.stderr.is_empty());
    live_record.record.take().unwrap().retire().unwrap();
    assert!(!record_path.exists());
}
