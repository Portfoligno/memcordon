use super::*;

#[test]
#[ignore = "requires an installed ephemeral Windows provider and administrative package access"]
fn legacy_manifest_absence_survives_failed_upgrade_qualification() {
    assert!(
        certification_faults_enabled(),
        "protected ephemeral marker is mandatory"
    );
    let lease = PackageLease::acquire().unwrap();
    let before = validate_existing_installed_artifacts().unwrap();
    let bytes = captured_installed_manifest(&before)
        .unwrap()
        .expect("current manifest before legacy fixture");
    let restore = RestoreManifest {
        path: install_root().join("runtime-manifest.json"),
        bytes,
    };
    let policy = super::super::policy_registry::Lease::acquire()
        .unwrap()
        .read()
        .unwrap()
        .unwrap()
        .registry;
    std::fs::remove_file(&restore.path).unwrap();
    let installation = upgrade_from(
        true,
        Path::new(
            option_env!("CARGO_BIN_EXE_memcordon-sealed-agent")
                .expect("run native package qualification through --test sealed_agent"),
        ),
    )
    .unwrap();
    std::fs::write(
        state_root()
            .join("package")
            .join(QUALIFICATION_ROLLBACK_FAULT),
        b"fixture\n",
    )
    .unwrap();
    let error =
        qualify_outside_package_lease(lease, QualificationRollback::Upgrade(installation), None)
            .unwrap_err();
    assert!(
        error.contains("MCSEALED-WINDOWS-UPGRADE-ROLLED-BACK"),
        "{error}"
    );
    let restored = validate_existing_installed_artifacts().unwrap();
    assert_eq!(restored.agent_bytes, before.agent_bytes);
    assert_eq!(
        restored.target_desktop_bootstrap_bytes,
        before.target_desktop_bootstrap_bytes
    );
    assert_eq!(restored.session_broker_bytes, before.session_broker_bytes);
    assert!(
        captured_installed_manifest(&restored).unwrap().is_none(),
        "legacy rollback must preserve actual absence"
    );
    assert_eq!(
        super::super::policy_registry::Lease::acquire()
            .unwrap()
            .read()
            .unwrap()
            .unwrap()
            .registry,
        policy
    );
    drop(restore);
    verify_installed().unwrap();
}

struct RestoreManifest {
    path: PathBuf,
    bytes: Vec<u8>,
}
impl Drop for RestoreManifest {
    fn drop(&mut self) {
        if let Err(error) = copy_atomically_bytes(&self.bytes, &self.path) {
            if std::thread::panicking() {
                eprintln!("manifest restoration failed: {error}");
            } else {
                panic!("manifest restoration failed: {error}");
            }
        }
    }
}

#[test]
#[ignore = "requires an installed ephemeral Windows provider and administrative package access"]
fn mixed_runtime_component_is_rejected_before_execution() {
    assert!(
        certification_faults_enabled(),
        "protected ephemeral marker is mandatory"
    );
    let _package = PackageLease::acquire().unwrap();
    let captured = validate_existing_installed_artifacts().unwrap();
    let bytes = captured_installed_manifest(&captured)
        .unwrap()
        .expect("current installed manifest");
    let restore = RestoreManifest {
        path: install_root().join("runtime-manifest.json"),
        bytes,
    };
    let mut manifest: memcordon_core::runtime_manifest::RuntimeManifestV2 =
        serde_json::from_slice(&restore.bytes).unwrap();
    let bootstrap = manifest
        .components
        .iter_mut()
        .find(|component| {
            component.role
                == memcordon_core::runtime_manifest::RuntimeComponentRole::DesktopBootstrap
        })
        .unwrap();
    bootstrap.sha256 = "00".repeat(32);
    copy_atomically_bytes(&serde_json::to_vec(&manifest).unwrap(), &restore.path).unwrap();
    assert!(installed_public_provider_binding().is_err());
    let directory = tempfile::TempDir::new().unwrap();
    let marker = directory.path().join("must-not-execute");
    let status = std::process::Command::new(
        option_env!("CARGO_BIN_EXE_memcordon")
            .expect("run native package qualification through --test sealed_agent"),
    )
    .args(["--sealed", "--"])
    .arg(
        option_env!("CARGO_BIN_EXE_memcordon-test-fixture")
            .expect("run native package qualification through --test sealed_agent"),
    )
    .arg("gate-marker")
    .arg(&marker)
    .status()
    .unwrap();
    assert!(!status.success() && !marker.exists());
    drop(restore);
    installed_public_provider_binding().unwrap();
}

#[test]
#[ignore = "requires an installed ephemeral Windows provider and administrative package access"]
fn partial_uninstall_restores_captured_images_manifest_and_policy() {
    assert!(
        certification_faults_enabled(),
        "protected ephemeral marker is mandatory"
    );
    let _package = PackageLease::acquire().unwrap();
    let before = validate_existing_installed_artifacts().unwrap();
    let manifest_path = install_root().join("runtime-manifest.json");
    let manifest = captured_installed_manifest(&before)
        .unwrap()
        .expect("current installed manifest");
    let manifest_restore = RestoreManifest {
        path: manifest_path.clone(),
        bytes: manifest.clone(),
    };
    let policy_before = super::super::policy_registry::Lease::acquire()
        .unwrap()
        .read()
        .unwrap()
        .unwrap();
    for legacy_absence in [false, true] {
        if legacy_absence {
            std::fs::remove_file(&manifest_path).unwrap();
        }
        let failure = uninstall_with_removal(true, |_context| {
            if manifest_path.exists() {
                std::fs::remove_file(&manifest_path).map_err(|error| error.to_string())?;
            }
            std::fs::remove_file(installed_target_desktop_bootstrap())
                .map_err(|error| error.to_string())?;
            Err("fixture: removal interrupted after manifest and bootstrap deletion".into())
        })
        .expect_err("injected partial removal must fail");
        assert!(
            failure.contains("MCSEALED-WINDOWS-UNINSTALL-ROLLED-BACK"),
            "{failure}"
        );
        let restored = validate_existing_installed_artifacts().unwrap();
        assert_eq!(restored.agent_bytes, before.agent_bytes);
        assert_eq!(
            restored.target_desktop_bootstrap_bytes,
            before.target_desktop_bootstrap_bytes
        );
        assert_eq!(restored.session_broker_bytes, before.session_broker_bytes);
        assert_eq!(
            captured_installed_manifest(&restored).unwrap(),
            (!legacy_absence).then(|| manifest.clone())
        );
        let policy_after = super::super::policy_registry::Lease::acquire()
            .unwrap()
            .read()
            .unwrap()
            .unwrap();
        assert_eq!(policy_after.registry_digest, policy_before.registry_digest);
        assert_eq!(policy_after.registry, policy_before.registry);
        if legacy_absence {
            copy_atomically_bytes(&manifest, &manifest_path).unwrap();
        }
        verify_installed().unwrap();
    }
    drop(manifest_restore);
}
