#![cfg(target_os = "linux")]

use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::process::Command;

const AGENT: &str = "/usr/libexec/memcordon-sealed-agent";

#[test]
fn unit_export_publishes_only_selected_templates_with_exact_regular_file_modes() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    crate::package::export_unit_files(directory.path()).unwrap();
    let mut names: Vec<_> = std::fs::read_dir(directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    let mut expected = vec![
        "memcordon-sealed-agent.service",
        "memcordon-sealed-agent.socket",
        "memcordon-sealed-launcher.service",
        "memcordon-sealed-launcher.socket",
        "memcordon.conf",
    ];
    if cfg!(feature = "private-tcp") {
        expected.extend([
            "memcordon-sealed-network-launcher.service",
            "memcordon-sealed-network-launcher.socket",
        ]);
    }
    expected.sort();
    assert_eq!(names, expected);
    for name in names {
        let path = directory.path().join(name);
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.mode() & 0o7777, 0o644);
        assert!(!std::fs::read(path).unwrap().is_empty());
    }
    assert_eq!(
        std::fs::read_to_string(directory.path().join("memcordon.conf")).unwrap(),
        "d /run/memcordon 0750 root memcordon -\nf /run/memcordon-sealed-package.lock 0600 root root -\n"
    );
    assert!(crate::package::export_unit_files(directory.path()).is_err());
}

#[test]
fn unit_export_rejects_symlink_parents_unprotected_and_nonempty_directories() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("output");
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let alias = root.path().join("alias");
    std::os::unix::fs::symlink(&directory, &alias).unwrap();
    assert!(crate::package::export_unit_files(&alias).is_err());
    let nested = directory.join("nested");
    std::fs::create_dir(&nested).unwrap();
    assert!(crate::package::export_unit_files(&alias.join("nested")).is_err());
    std::fs::remove_dir(nested).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(crate::package::export_unit_files(&directory).is_err());
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let input = directory.join("existing");
    std::fs::write(&input, b"preserved input").unwrap();
    assert!(crate::package::export_unit_files(&directory).is_err());
    assert_eq!(std::fs::read(input).unwrap(), b"preserved input");
}

#[cfg(target_env = "gnu")]
const ARM32_HELPER: &[u8] = b"exact package ARM32 helper";

#[cfg(target_env = "gnu")]
fn helper_bytes() -> Option<&'static [u8]> {
    cfg!(target_arch = "aarch64").then_some(ARM32_HELPER)
}

#[cfg(target_env = "gnu")]
fn with_helper(
    mut components: Vec<memcordon_core::runtime_manifest::RuntimeComponentRecord>,
) -> Vec<memcordon_core::runtime_manifest::RuntimeComponentRecord> {
    if let Some(bytes) = helper_bytes() {
        components.push(memcordon_core::runtime_manifest::RuntimeComponentRecord {
            id: "arm32-abi-helper".into(),
            path: "memcordon-arm32-abi-helper".into(),
            role: memcordon_core::runtime_manifest::RuntimeComponentRole::Arm32AbiHelper,
            size: bytes.len() as u64,
            mode: 0o755,
            sha256: String::from(memcordon_core::workload_codec::hash_bytes(bytes)),
        });
    }
    components
}

#[cfg(target_env = "gnu")]
fn write_helper(root: &std::path::Path) {
    if let Some(bytes) = helper_bytes() {
        let path = root.join("memcordon-arm32-abi-helper");
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

#[test]
fn install_cannot_replace_a_live_generation_without_upgrade_quiescence() {
    assert!(crate::package::ensure_install_is_new(std::ffi::OsStr::new("install"), false).is_ok());
    assert!(crate::package::ensure_install_is_new(std::ffi::OsStr::new("install"), true).is_err());
    assert!(crate::package::ensure_install_is_new(std::ffi::OsStr::new("upgrade"), true).is_ok());
}

#[test]
fn redundant_install_is_rejected_before_epoch_change() {
    let install = std::ffi::OsStr::new("install");
    let upgrade = std::ffi::OsStr::new("upgrade");
    let uninstall = std::ffi::OsStr::new("uninstall");
    assert!(crate::package::ensure_install_preflight(install, false, false).is_ok());
    assert!(crate::package::ensure_install_preflight(install, false, true).is_err());
    assert!(crate::package::ensure_install_preflight(install, true, false).is_err());
    assert!(crate::package::ensure_install_preflight(install, true, true).is_err());
    assert!(crate::package::ensure_install_preflight(upgrade, true, true).is_ok());
    assert!(crate::package::ensure_install_preflight(uninstall, true, true).is_ok());
}

#[test]
fn package_crash_journal_accepts_only_fixed_artifact_and_backup_inventory() {
    use crate::package::{PackageJournal, PackageJournalEntry, validate_package_journal};
    use memcordon_core::DiagnosticSha256;
    let target = std::path::PathBuf::from("/usr/libexec/memcordon-runtime-manifest.json");
    let entry = PackageJournalEntry {
        path: target.clone(),
        backup: Some(std::path::PathBuf::from(
            "/usr/libexec/.memcordon-backup-example",
        )),
        old_sha256: Some(DiagnosticSha256::from_bytes([1; 32])),
        old_device: Some(1),
        old_inode: Some(2),
    };
    let journal = PackageJournal {
        schema_version: 1,
        entries: vec![entry.clone()],
    };
    assert!(validate_package_journal(&journal).is_ok());
    for proof in [
        "/usr/libexec/memcordon/certification/workload/x64-private-build-v1.json",
        "/usr/libexec/memcordon/certification/workload/arm64-native-q-grant-v1.json",
    ] {
        let mut proof_entry = entry.clone();
        proof_entry.path = proof.into();
        proof_entry.backup = None;
        proof_entry.old_sha256 = None;
        proof_entry.old_device = None;
        proof_entry.old_inode = None;
        assert!(
            validate_package_journal(&PackageJournal {
                schema_version: 1,
                entries: vec![proof_entry],
            })
            .is_err()
        );
    }
    let mut duplicate = journal;
    duplicate.entries.push(entry.clone());
    assert!(validate_package_journal(&duplicate).is_err());
    let mut wrong_target = entry.clone();
    wrong_target.path = "/etc/passwd".into();
    assert!(
        validate_package_journal(&PackageJournal {
            schema_version: 1,
            entries: vec![wrong_target],
        })
        .is_err()
    );
    let mut wrong_backup = entry.clone();
    wrong_backup.backup = Some("/tmp/.memcordon-backup-example".into());
    assert!(
        validate_package_journal(&PackageJournal {
            schema_version: 1,
            entries: vec![wrong_backup],
        })
        .is_err()
    );
    let mut missing_identity = entry;
    missing_identity.old_inode = None;
    assert!(
        validate_package_journal(&PackageJournal {
            schema_version: 1,
            entries: vec![missing_identity],
        })
        .is_err()
    );
}

#[test]
fn package_publication_precedes_activation_and_retains_generation_for_finalization() {
    let phases = std::cell::RefCell::new(Vec::new());
    let generation = crate::package::activate_published_package(
        || {
            phases.borrow_mut().push("publish");
            Ok(7_u8)
        },
        || {
            phases.borrow_mut().push("activate");
            Ok(())
        },
        |_| panic!("successful activation must not compensate"),
    )
    .unwrap();
    assert_eq!(generation, 7);
    assert_eq!(*phases.borrow(), ["publish", "activate"]);
}

#[test]
fn package_failed_publication_never_activates_or_compensates() {
    let error = crate::package::activate_published_package::<()>(
        || Err("publication was not durable".into()),
        || panic!("an unpublished generation must not activate"),
        |_| panic!("publication failure must retain its original recovery path"),
    )
    .unwrap_err();
    assert_eq!(error, "publication was not durable");
}

#[test]
fn package_failed_activation_compensates_the_exact_published_generation() {
    let phases = std::cell::RefCell::new(Vec::new());
    let error = crate::package::activate_published_package(
        || {
            phases.borrow_mut().push("publish");
            Ok(7_u8)
        },
        || {
            phases.borrow_mut().push("activate");
            Err("launcher rejected startup".into())
        },
        |generation| {
            assert_eq!(generation, 7);
            phases.borrow_mut().push("compensate");
            Ok(())
        },
    )
    .unwrap_err();
    assert_eq!(*phases.borrow(), ["publish", "activate", "compensate"]);
    assert_eq!(
        error,
        "package activation failed: launcher rejected startup; compensation: Ok(())"
    );
}

#[test]
fn package_failed_compensation_never_claims_successful_restoration() {
    let error = crate::package::activate_published_package(
        || Ok(7_u8),
        || Err("launcher rejected startup".into()),
        |generation| {
            assert_eq!(generation, 7);
            Err("postimage identity changed; backups retained".into())
        },
    )
    .unwrap_err();
    assert_eq!(
        error,
        "package activation failed: launcher rejected startup; compensation: Err(\"postimage identity changed; backups retained\")"
    );
}

#[test]
fn installation_epoch_advances_even_for_byte_identical_package_replacement() {
    let first = crate::package::next_installation_epoch(None, [1; 32]).unwrap();
    let second = crate::package::next_installation_epoch(Some(&first), [2; 32]).unwrap();
    assert_eq!(first.counter, 1);
    assert_eq!(second.counter, 2);
    assert_ne!(first.nonce_digest, second.nonce_digest);
    let same_nonce = crate::package::next_installation_epoch(Some(&first), [1; 32]).unwrap();
    assert_eq!(same_nonce.counter, 2);
    assert_ne!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&same_nonce).unwrap()
    );
    let exhausted = crate::package::PackageInstallationEpochV1 {
        counter: u64::MAX,
        ..first
    };
    assert!(crate::package::next_installation_epoch(Some(&exhausted), [3; 32]).is_err());
}

#[test]
#[cfg(target_env = "gnu")]
fn ordinary_source_inventory_binds_actual_images_and_helper_bytes() {
    use memcordon_core::runtime_manifest::{
        RuntimeComponentRecord, RuntimeComponentRole, RuntimeManifest,
    };
    let directory = tempfile::tempdir().unwrap();
    let agent = b"exact provider image";
    let public = b"exact public image";
    let source = directory.path().join("memcordon-sealed-agent");
    let public_path = directory.path().join("memcordon");
    let manifest_path = directory.path().join("runtime-manifest.json");
    write_helper(directory.path());
    for (path, bytes) in [
        (&source, agent.as_slice()),
        (&public_path, public.as_slice()),
    ] {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let component = |id: &str, path: &str, role, bytes: &[u8]| RuntimeComponentRecord {
        id: id.into(),
        path: path.into(),
        role,
        size: bytes.len() as u64,
        mode: 0o755,
        sha256: crate::package::sha256_bytes(bytes),
    };
    let manifest = RuntimeManifest::linux_selected(
        env!("CARGO_PKG_VERSION").into(),
        crate::SOURCE_COMMIT.into(),
        crate::linux::runtime_manifest::target().unwrap().into(),
        with_helper(vec![
            component(
                "public-cli",
                "memcordon",
                RuntimeComponentRole::PublicCli,
                public,
            ),
            component(
                "sealed-agent",
                "memcordon-sealed-agent",
                RuntimeComponentRole::SealedAgent,
                agent,
            ),
        ]),
        cfg!(feature = "private-tcp"),
    )
    .unwrap();
    let bytes = serde_json::to_vec(&manifest).unwrap();
    std::fs::write(&manifest_path, &bytes).unwrap();
    let snapshot = crate::package::linux_source_snapshot(&source).unwrap();
    assert_eq!(snapshot.agent_bytes, agent);
    assert_eq!(snapshot.manifest_bytes, bytes);
    assert_eq!(snapshot.arm32_helper_bytes.as_deref(), helper_bytes());
    for (path, original) in [
        (&source, agent.as_slice()),
        (&public_path, public.as_slice()),
    ] {
        std::fs::write(path, b"changed actual image").unwrap();
        assert!(crate::package::linux_source_snapshot(&source).is_err());
        std::fs::write(path, original).unwrap();
    }
    std::fs::set_permissions(&public_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(crate::package::linux_source_snapshot(&source).is_err());
    std::fs::set_permissions(&public_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    if helper_bytes().is_some() {
        let helper = directory.path().join("memcordon-arm32-abi-helper");
        std::fs::write(&helper, b"changed helper").unwrap();
        assert!(crate::package::linux_source_snapshot(&source).is_err());
        write_helper(directory.path());
    }
    std::fs::remove_file(&manifest_path).unwrap();
    std::os::unix::fs::symlink("missing-manifest", &manifest_path).unwrap();
    assert!(crate::package::linux_source_snapshot(&source).is_err());
    std::fs::remove_file(&manifest_path).unwrap();
    let generated = crate::package::linux_source_snapshot(&source).unwrap();
    assert_eq!(
        RuntimeManifest::parse(&generated.manifest_bytes).unwrap(),
        manifest
    );
}

#[test]
fn installed_upgrade_requires_exact_image_and_preserves_runtime_generation() {
    use memcordon_core::runtime_manifest::{
        RuntimeComponentRecord, RuntimeComponentRole, RuntimeManifest,
    };
    let agent = b"exact installed provider image";
    let public = b"exact public image";
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("memcordon-sealed-agent");
    let manifest_path = directory.path().join("runtime-manifest.json");
    let public_path = directory.path().join("memcordon");
    std::fs::write(&public_path, public).unwrap();
    std::fs::set_permissions(&public_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let manifest = RuntimeManifest::linux_selected(
        env!("CARGO_PKG_VERSION").into(),
        crate::SOURCE_COMMIT.into(),
        crate::linux::runtime_manifest::target().unwrap().into(),
        vec![
            RuntimeComponentRecord {
                id: "public-cli".into(),
                path: "memcordon".into(),
                role: RuntimeComponentRole::PublicCli,
                size: public.len() as u64,
                mode: 0o755,
                sha256: memcordon_core::workload_codec::hash_bytes(public).into(),
            },
            RuntimeComponentRecord {
                id: "sealed-agent".into(),
                path: "memcordon-sealed-agent".into(),
                role: RuntimeComponentRole::SealedAgent,
                size: agent.len() as u64,
                mode: 0o755,
                sha256: memcordon_core::workload_codec::hash_bytes(agent).into(),
            },
        ],
        cfg!(feature = "private-tcp"),
    )
    .unwrap();
    let validate = |manifest: &RuntimeManifest, image: &[u8]| {
        std::fs::write(&source, image).unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(&manifest_path, serde_json::to_vec(manifest).unwrap()).unwrap();
        crate::package::linux_source_snapshot(&source)
    };
    validate(&manifest, agent).unwrap();
    assert!(validate(&manifest, b"different installed image").is_err());
    let mut same_size_image = agent.to_vec();
    same_size_image[0] ^= 1;
    assert!(validate(&manifest, &same_size_image).is_err());
    for mutation in 0..6 {
        let mut changed = manifest.clone();
        match mutation {
            0 => changed.components[1].size += 1,
            1 => changed.components[1].sha256 = "cd".repeat(32),
            2 => changed.components[1].path = "other-agent".into(),
            3 => changed.components[0].role = RuntimeComponentRole::SealedAgent,
            4 => changed.components[0].mode = 0o777,
            5 => changed.components.push(changed.components[0].clone()),
            _ => unreachable!(),
        }
        assert!(
            validate(&changed, agent).is_err(),
            "accepted mutation {mutation}"
        );
    }
    let mut wrong_generation = serde_json::to_value(&manifest).unwrap();
    let other_target = if manifest.target == "x86_64-unknown-linux-gnu" {
        "aarch64-unknown-linux-gnu"
    } else {
        "x86_64-unknown-linux-gnu"
    };
    for (field, replacement) in [
        ("version", "9.9.9"),
        ("source_commit", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ("target", other_target),
    ] {
        let original = wrong_generation[field].clone();
        assert!(!original.is_null(), "missing manifest field {field}");
        assert_ne!(original, replacement);
        wrong_generation[field] = serde_json::Value::String(replacement.into());
        std::fs::write(
            &manifest_path,
            serde_json::to_vec(&wrong_generation).unwrap(),
        )
        .unwrap();
        assert!(crate::package::linux_source_snapshot(&source).is_err());
        wrong_generation[field] = original;
    }
}

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
    // Restarting would run package verification against the deliberately legacy
    // on-disk units and turn both services into delayed startup failures. The
    // reload alone installs those definitions in the running manager, while the
    // still-active processes keep the currently verified executable running.
    for service in [
        "memcordon-sealed-launcher.service",
        "memcordon-sealed-agent.service",
    ] {
        let active = Command::new("/usr/bin/systemctl")
            .args(["is-active", service])
            .status()
            .unwrap();
        assert!(active.success());
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
    assert!(crate::linux::service::acquire_shared_package_lease().is_err());

    drop(replacement);
    drop(legacy);
    drop(stable);
    let shared = crate::linux::service::acquire_shared_package_lease().unwrap();
    assert!(crate::linux::service::acquire_package_lease().is_err());
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
    let typed_receipt =
        crate::linux::qualification::ReadinessObservation::parse(&qualification.stdout)
            .expect("strict live readiness observation");
    assert!(typed_receipt.complete(), "{typed_receipt:#?}");
    let receipt: serde_json::Value = serde_json::from_slice(&qualification.stdout).unwrap();
    assert_eq!(receipt["boundary_retired"], true);
    assert_eq!(receipt["format"], "memcordon.runtime-readiness");
    assert_eq!(receipt["revision"], 1);
    assert_eq!(receipt["mechanism"], "linux-pid-namespace-cgroup-v2");
    assert_eq!(receipt["provider_identity"], "memcordon-sealed-agent-v2");
    let digest = receipt["observation_digest"]
        .as_str()
        .expect("actual observation SHA-256 field");
    assert_eq!(digest.len(), 64);
    assert!(
        digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    );

    let policy = memcordon_core::Policy::unbounded().sealed();
    let backend = memcordon_platform::probe()
        .selected_for(memcordon_core::BoundaryRequirement::Sealed)
        .cloned()
        .expect("installed provider must resolve");
    let backend_capabilities =
        memcordon_platform::capabilities_for(&backend, memcordon_core::BoundaryRequirement::Sealed);
    assert!(
        backend_capabilities.boundary_qualification.is_none(),
        "ordinary readiness must not publish legacy qualification authority"
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
        .args(["package", "verify", "--json"])
        .output()
        .unwrap();
    assert!(
        retained.status.success(),
        "refused uninstall damaged the installed provider: status={}; stdout={}; stderr={}",
        retained.status,
        String::from_utf8_lossy(&retained.stdout),
        String::from_utf8_lossy(&retained.stderr)
    );
    assert!(retained.stderr.is_empty());
    let typed: crate::inspection_schema::InstalledProviderInspection =
        serde_json::from_slice(&retained.stdout).expect("strict current installed inspection");
    assert_eq!(u32::from(typed.revision), 1);
    assert_eq!(u32::from(typed.agent.revision), 1);
    assert_eq!(typed.agent.runtime_manifest_schema, 1);
    assert_eq!(typed.agent.workload_contract_schema, 1);
    assert_eq!(
        typed.agent.profile_catalog_sha256,
        memcordon_core::runtime_manifest::baseline_catalog_digest(false)
    );
    let inspection: serde_json::Value = serde_json::from_slice(&retained.stdout)
        .expect("retained installed-provider inspection should be JSON");
    assert_eq!(
        inspection["format"],
        "memcordon.installed-provider-inspection"
    );
    assert_eq!(inspection["revision"], 1);
    assert_eq!(inspection["installed_artifacts_valid"], true);
    assert_eq!(inspection["provider_reachable"], true);
    assert_eq!(
        inspection["installed_executable_sha256"],
        inspection["agent"]["executable_sha256"]
    );
    let provider_identity = inspection["provider_identity"]
        .as_str()
        .expect("retained provider identity should be present");
    assert!(!provider_identity.is_empty());
    assert_eq!(inspection["agent"]["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(
        inspection["agent"]["mechanism"],
        "linux-pid-namespace-cgroup-v2"
    );
    assert_eq!(inspection["agent"]["platform"], "linux-systemd");
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
