#![cfg(target_os = "linux")]

use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
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
    record: Option<crate::linux::attempt::AttemptRecord>,
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

fn load_legacy_runtime_directory_units() {
    for path in [
        "/usr/lib/systemd/system/memcordon-sealed-agent.service",
        "/usr/lib/systemd/system/memcordon-sealed-launcher.service",
    ] {
        let current = std::fs::read_to_string(path).unwrap();
        assert!(!current.contains("RuntimeDirectory="));
        let legacy = current.replacen(
            "KillMode=process\n",
            "KillMode=process\nRuntimeDirectory=memcordon\nRuntimeDirectoryMode=0750\n",
            1,
        );
        assert_ne!(legacy, current);
        std::fs::write(path, legacy).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let reload = Command::new("/usr/bin/systemctl")
        .arg("daemon-reload")
        .status()
        .unwrap();
    assert!(reload.success());
    for service in [
        "memcordon-sealed-launcher.service",
        "memcordon-sealed-agent.service",
    ] {
        let restart = Command::new("/usr/bin/systemctl")
            .args(["restart", service])
            .status()
            .unwrap();
        assert!(restart.success());
    }
}

fn assert_runtime_directory_contract() {
    let directory = std::fs::symlink_metadata("/run/memcordon").unwrap();
    assert!(directory.file_type().is_dir());
    assert_eq!(directory.uid(), 0);
    assert_eq!(directory.mode() & 0o7777, 0o750);

    let public_socket = std::fs::symlink_metadata("/run/memcordon/sealed-agent.sock").unwrap();
    assert!(public_socket.file_type().is_socket());
    assert_eq!(public_socket.uid(), 0);
    assert_eq!(public_socket.gid(), directory.gid());
    assert_eq!(public_socket.mode() & 0o7777, 0o660);

    let launcher_socket = std::fs::symlink_metadata("/run/memcordon/sealed-launcher.sock").unwrap();
    assert!(launcher_socket.file_type().is_socket());
    assert_eq!(launcher_socket.uid(), 0);
    assert_eq!(launcher_socket.gid(), 0);
    assert_eq!(launcher_socket.mode() & 0o7777, 0o600);

    let stable_lease = std::fs::symlink_metadata("/run/memcordon-sealed-package.lock").unwrap();
    assert!(stable_lease.file_type().is_file());
    assert_eq!(stable_lease.uid(), 0);
    assert_eq!(stable_lease.gid(), 0);
    assert_eq!(stable_lease.mode() & 0o7777, 0o600);
}

fn assert_active_capability_caller_rejected(execution: &memcordon_core::SupervisionExecution) {
    assert_eq!(execution.wrapper_exit_code(), 125);
    assert_eq!(execution.targets_authorized(), 0);
    assert_eq!(execution.attempts().total, 1);
    match execution.terminal() {
        memcordon_core::SupervisionTerminal::Error {
            attempt_number,
            error,
        } => {
            assert_eq!(*attempt_number, Some(1));
            assert_eq!(error.attempt_number, Some(1));
            assert_eq!(error.category, "setup");
            assert_eq!(error.code, "MCSEALED-PROVIDER-REJECTION");
            assert_eq!(
                error.supervision_phase,
                memcordon_core::SupervisionPhase::AttemptSetup
            );
            assert_eq!(error.launch_phase.as_deref(), Some("request-validation"));
            assert!(!error.target_released);
            assert!(!error.workload_may_be_alive);
            assert!(error.initial_spawn_failure.is_none());
            let rejection = error
                .provider_rejection
                .as_ref()
                .expect("active-capability rejection must retain typed provider evidence");
            assert_eq!(rejection.schema_version, 1);
            assert_eq!(rejection.code, "MCSEALED-CALLER-ENVELOPE-CAPTURE");
            assert_eq!(
                rejection.phase,
                memcordon_core::BoundarySetupPhase::RequestValidation
            );
            assert_eq!(
                rejection.detail,
                "MCSEALED-CREDENTIAL-TRANSITION-POLICY: callers with active capability sets are unsupported"
            );
            assert!(!rejection.target_created);
            assert!(!rejection.target_released);
            assert!(!rejection.cleanup_attempted);
            assert_eq!(
                rejection.restart_safety,
                memcordon_core::RestartSafetyProof::default()
            );
        }
        terminal => panic!("active-capability caller produced unexpected terminal: {terminal:?}"),
    }
}

fn active_provider_unit_states() -> Vec<(&'static str, Vec<u8>)> {
    [
        "memcordon-sealed-agent.service",
        "memcordon-sealed-launcher.service",
        "memcordon-sealed-agent.socket",
        "memcordon-sealed-launcher.socket",
    ]
    .into_iter()
    .map(|unit| {
        let output = Command::new("/usr/bin/systemctl")
            .args(["is-active", unit])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "provider unit is not active: unit={unit}; status={}; stdout={}; stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"active\n");
        assert!(output.stderr.is_empty());
        (unit, output.stdout)
    })
    .collect()
}

fn installed_package_bytes() -> Vec<(&'static str, Vec<u8>)> {
    [
        AGENT,
        "/usr/lib/systemd/system/memcordon-sealed-agent.service",
        "/usr/lib/systemd/system/memcordon-sealed-agent.socket",
        "/usr/lib/systemd/system/memcordon-sealed-launcher.service",
        "/usr/lib/systemd/system/memcordon-sealed-launcher.socket",
        "/usr/lib/tmpfiles.d/memcordon.conf",
    ]
    .into_iter()
    .map(|path| (path, std::fs::read(path).unwrap()))
    .collect()
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
fn sealed_package_stable_lease_survives_legacy_inode_replacement() {
    let stable = crate::linux::service::acquire_package_lease().unwrap();
    let legacy = crate::linux::service::acquire_legacy_package_lease().unwrap();
    std::fs::remove_file("/run/memcordon/sealed-package.lock").unwrap();
    let replacement = crate::linux::service::acquire_legacy_package_lease().unwrap();

    assert!(crate::linux::service::acquire_package_lease().is_err());
    assert!(crate::linux::service::acquire_qualification_lease().is_err());
    assert!(crate::linux::service::acquire_shared_package_lease().is_err());

    drop(replacement);
    drop(legacy);
    drop(stable);
    let shared = crate::linux::service::acquire_shared_package_lease().unwrap();
    assert!(crate::linux::service::acquire_package_lease().is_err());
    assert!(crate::linux::service::acquire_qualification_lease().is_err());
    drop(shared);
    assert!(crate::linux::service::acquire_package_lease().is_ok());
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_package_upgrade_recovers_before_advertising() {
    load_legacy_runtime_directory_units();
    let identity = "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2".to_owned();
    let record_path = std::path::Path::new(crate::linux::STATE_ROOT).join(&identity);
    let cgroup_path = std::path::Path::new(crate::linux::CGROUP_ROOT).join(&identity);
    let record = crate::linux::attempt::AttemptRecord::create(identity, libc::pid_t::MAX).unwrap();
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
    assert_runtime_directory_contract();
    let verification = Command::new(AGENT)
        .args(["package", "verify"])
        .status()
        .unwrap();
    assert!(verification.success());
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
    let launcher_socket = Command::new("/usr/bin/systemctl")
        .args(["is-active", "memcordon-sealed-launcher.socket"])
        .status()
        .unwrap();
    assert!(launcher_socket.success());
    let qualification = Command::new(AGENT).arg("probe").output().unwrap();
    assert!(qualification.status.success());
    let receipt: serde_json::Value = serde_json::from_slice(&qualification.stdout).unwrap();
    assert_eq!(receipt["boundary_retired"], true);
    assert_eq!(receipt["schema_version"], 2);
    assert_eq!(receipt["mechanism"], "linux-pid-namespace-cgroup-v2");
    assert_eq!(receipt["provider_identity"], "memcordon-sealed-agent-v2");
    for field in [
        "receipt_digest",
        "setid_transition_certification_digest",
        "sudo_transition_certification_digest",
    ] {
        let digest = receipt[field]
            .as_str()
            .expect("qualification SHA-256 field");
        assert_eq!(digest.len(), 64);
        assert!(
            digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
    }

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
    .expect("typed provider rejection must remain a supervision result");
    assert_active_capability_caller_rejected(&execution);
    let wire = serde_json::to_value(&execution).unwrap();
    assert_eq!(wire["wrapper_exit_code"], 125);
    assert_eq!(wire["targets_authorized"], 0);
    assert_eq!(wire["attempts"]["total"], 1);

    let service = Command::new("/usr/bin/systemctl")
        .args(["is-active", "memcordon-sealed-agent.service"])
        .status()
        .unwrap();
    assert!(service.success());
    let launcher_service = Command::new("/usr/bin/systemctl")
        .args(["is-active", "memcordon-sealed-launcher.service"])
        .status()
        .unwrap();
    assert!(launcher_service.success());
}

#[test]
#[ignore = "requires privileged Linux sealed certification"]
fn sealed_package_uninstall_refuses_live_authenticated_attempt() {
    let unit_states_before = active_provider_unit_states();
    let package_before = installed_package_bytes();
    let identity = "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1".to_owned();
    let record_path = std::path::Path::new(crate::linux::STATE_ROOT).join(&identity);
    let cgroup_path = std::path::Path::new(crate::linux::CGROUP_ROOT).join(&identity);
    // SAFETY: getpid has no pointer arguments and returns this live test frontend's pid.
    let frontend_pid = unsafe { libc::getpid() };
    // SAFETY: signal zero performs a liveness/permission probe without delivering a signal.
    assert_eq!(unsafe { libc::kill(frontend_pid, 0) }, 0);
    let record =
        crate::linux::attempt::AttemptRecord::create(identity.clone(), frontend_pid).unwrap();
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
    assert_eq!(active_provider_unit_states(), unit_states_before);
    assert_eq!(installed_package_bytes(), package_before);
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
    let probe = Command::new(AGENT).arg("probe").output().unwrap();
    assert!(
        probe.status.success(),
        "refused uninstall left the provider unusable: status={}; stdout={}; stderr={}",
        probe.status,
        String::from_utf8_lossy(&probe.stdout),
        String::from_utf8_lossy(&probe.stderr)
    );
    assert!(!probe.stdout.is_empty());
    assert!(probe.stderr.is_empty());
}
