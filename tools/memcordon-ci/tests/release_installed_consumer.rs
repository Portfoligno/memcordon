use memcordon_ci::release::{
    artifacts,
    distribution::TargetDistribution,
    installed_consumer::{
        binary_path, cli_case_command, create_fresh_destination, measured_manifest,
    },
    source::{BuildSourceIdentity, SelectedSource},
    target::unit_export_directory,
};
use memcordon_core::runtime_manifest::{
    RuntimeComponentRecord, RuntimeComponentRole, RuntimeManifest, SealedRuntime,
};

fn directory() -> tempfile::TempDir {
    if cfg!(unix) {
        tempfile::tempdir_in("/tmp").unwrap()
    } else {
        tempfile::tempdir().unwrap()
    }
}

#[test]
fn installed_case_selection_preserves_and_checks_auxiliary_capture_evidence() {
    use memcordon_ci::{
        release::installed_consumer::installed_case_artifacts,
        windows_installed_cases::SelectedArtifact,
    };
    let owner = directory();
    let mut records = Vec::new();
    // Four original crate artifacts and the complete four-bin auxiliary bound.
    for index in 0..29 {
        let path = owner.path().join(format!("artifact-{index}"));
        let bytes = format!("actual retained artifact {index}").into_bytes();
        std::fs::write(&path, &bytes).unwrap();
        records.push(SelectedArtifact {
            path,
            sha256: artifacts::checksum(&bytes),
        });
    }
    let selected = installed_case_artifacts(&records, 4, 4).unwrap();
    assert_eq!(selected.len(), 4);
    assert_eq!(selected[3].path, records[3].path);
    assert_eq!(records.len(), 29);
    assert!(installed_case_artifacts(&records, 0, 4).is_err());
    assert!(installed_case_artifacts(&records, 17, 4).is_err());
    assert!(installed_case_artifacts(&records, 4, 3).is_err());
    let mut duplicate = records.clone();
    duplicate[28] = duplicate[0].clone();
    assert!(installed_case_artifacts(&duplicate, 4, 4).is_err());
    std::fs::write(&records[28].path, b"changed auxiliary capture").unwrap();
    assert!(installed_case_artifacts(&records, 4, 4).is_err());
    std::fs::write(&records[0].path, b"changed selected crate").unwrap();
    assert!(installed_case_artifacts(&records[..4], 4, 4).is_err());
}

#[cfg(unix)]
#[test]
fn selected_cli_paths_reach_actual_fixture_and_report_after_child_changes_directory() {
    use memcordon_ci::{command::CommandSpec, config};
    use std::{path::PathBuf, time::Duration};

    let owner = directory();
    let payload = owner.path().join("payload");
    let reports = owner.path().join("cases");
    std::fs::create_dir(&payload).unwrap();
    std::fs::create_dir(&reports).unwrap();
    let fixture = owner.path().join("selected-fixture-input");
    let bytes = b"selected fixture bytes, distinct from the child directory";
    std::fs::write(&fixture, bytes).unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let compiler = CommandSpec::toolchain_program(
        "rustup",
        owner.path(),
        &config::toolchains(root).unwrap().stable,
        "rustc",
        Duration::from_secs(30),
    )
    .arg(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/support/installed_path_child.rs"),
    )
    .args(["--edition", "2024", "-o"])
    .arg(payload.join("memcordon"))
    .output_quiet()
    .unwrap();
    assert!(compiler.status.success(), "{compiler:?}");

    // Supply driver-relative paths without changing this multithreaded test's cwd.
    let current = std::env::current_dir().unwrap();
    let common = current
        .ancestors()
        .find(|ancestor| owner.path().starts_with(ancestor))
        .unwrap();
    let mut relative = PathBuf::new();
    for _ in current.strip_prefix(common).unwrap().components() {
        relative.push("..");
    }
    relative.push(owner.path().strip_prefix(common).unwrap());
    let (command, report) = cli_case_command(
        &relative.join("payload"),
        "native-test",
        &relative.join("selected-fixture-input"),
        &relative.join("cases"),
        "path-observation",
        &[],
        &[],
    )
    .unwrap();
    let output = command.output_quiet().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(std::fs::read(report).unwrap(), bytes);
    assert_eq!(
        std::fs::read(reports.join("path-observation.json")).unwrap(),
        bytes
    );
    assert!(!payload.join("cases/path-observation.json").exists());
}

#[cfg(unix)]
#[test]
fn unit_export_creation_satisfies_held_producer_contract_without_reusing_existing_evidence() {
    use std::os::unix::fs::MetadataExt;

    let owner = directory();
    let existing = owner.path().join("units");
    std::fs::create_dir(&existing).unwrap();
    let evidence = existing.join("failure.json");
    std::fs::write(&evidence, b"existing operation diagnostics").unwrap();
    // A separately created file provides the actual creating process's owner,
    // independent of the directory helper's requested metadata.
    let creating_owner = std::fs::metadata(&evidence).unwrap().uid();
    let first = unit_export_directory(owner.path()).unwrap();
    let second = unit_export_directory(owner.path()).unwrap();
    for directory in [&first, &second] {
        let held = std::fs::File::open(directory.path()).unwrap();
        let metadata = held.metadata().unwrap();
        assert!(metadata.is_dir());
        assert_eq!(metadata.uid(), creating_owner);
        assert_eq!(metadata.mode() & 0o777, 0o700);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        assert_ne!(directory.path(), existing);
    }
    let first_path = first.path().to_owned();
    assert_ne!(first_path, second.path());
    let first_metadata = std::fs::metadata(&first_path).unwrap();
    let second_metadata = std::fs::metadata(second.path()).unwrap();
    assert_ne!(
        (first_metadata.dev(), first_metadata.ino()),
        (second_metadata.dev(), second_metadata.ino())
    );
    drop(first);
    assert!(!first_path.exists());
    assert!(second.path().is_dir());
    assert_eq!(
        std::fs::read(evidence).unwrap(),
        b"existing operation diagnostics"
    );
    assert!(unit_export_directory(&owner.path().join("absent-parent")).is_err());
}

fn source() -> BuildSourceIdentity {
    BuildSourceIdentity::Tagged {
        source: SelectedSource {
            format: "memcordon.selected-source".into(),
            revision: 1,
            repository: "example/repository".into(),
            tag_ref: "refs/tags/1.2.3".into(),
            commit: hex::encode([1; 20]),
            version: "1.2.3".parse().unwrap(),
        },
    }
}

#[test]
fn fresh_consumer_destination_provisions_missing_parent_but_preserves_existing_evidence() {
    let root = directory();
    let destination = root.path().join("windows-installed/cargo");
    create_fresh_destination(&destination).unwrap();
    let evidence = destination.join("failure.json");
    std::fs::write(&evidence, b"original diagnostics").unwrap();
    assert!(create_fresh_destination(&destination).is_err());
    assert_eq!(std::fs::read(&evidence).unwrap(), b"original diagnostics");
    create_fresh_destination(&root.path().join("windows-installed/native")).unwrap();
}

// Architecture-header fixtures test inventory and byte correlation only. They
// are never executed or counted as native consumer acceptance.
fn pe(marker: u8) -> Vec<u8> {
    let mut bytes = vec![marker; 128];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[60..64].copy_from_slice(&64_u32.to_le_bytes());
    bytes[64..70].copy_from_slice(b"PE\0\0\x64\x86");
    bytes
}

fn windows() -> TargetDistribution {
    TargetDistribution {
        target: "x86_64-pc-windows-msvc".into(),
        features: vec!["windows-sealed-runtime".into()],
        binaries: [
            "memcordon",
            "memcordon-sealed-agent",
            "memcordon-target-desktop-bootstrap",
            "memcordon-session-broker",
        ]
        .map(str::to_owned)
        .to_vec(),
        units: Vec::new(),
    }
}

#[test]
fn cargo_inventory_measures_own_graph_and_does_not_copy_native_binary_hashes() {
    let root = directory();
    let selected = windows();
    for (index, binary) in selected.binaries.iter().enumerate() {
        std::fs::write(
            binary_path(root.path(), binary, &selected.target),
            pe(index as u8),
        )
        .unwrap();
    }
    let first = measured_manifest(&source(), &selected, root.path()).unwrap();
    assert_eq!(first.components.len(), 4);
    for component in &first.components {
        assert_eq!(
            component.sha256,
            artifacts::checksum(&std::fs::read(root.path().join(&component.path)).unwrap())
        );
    }
    let replacement = pe(99);
    std::fs::write(
        binary_path(root.path(), "memcordon", &selected.target),
        &replacement,
    )
    .unwrap();
    let second = measured_manifest(&source(), &selected, root.path()).unwrap();
    assert_ne!(first.components[0].sha256, second.components[0].sha256);
    assert_eq!(
        second.components[0].sha256,
        artifacts::checksum(&replacement)
    );
    assert_eq!(first.components[1..], second.components[1..]);
    assert_eq!(first.source_commit, second.source_commit);
}

#[test]
fn selected_graph_rejects_wrong_native_architecture_missing_companion_and_fixture_member() {
    let root = directory();
    let selected = windows();
    for binary in &selected.binaries {
        std::fs::write(binary_path(root.path(), binary, &selected.target), pe(1)).unwrap();
    }
    let mut wrong = selected.clone();
    wrong.target = "aarch64-pc-windows-msvc".into();
    assert!(measured_manifest(&source(), &wrong, root.path()).is_err());
    let missing = binary_path(root.path(), "memcordon-session-broker", &selected.target);
    std::fs::remove_file(missing).unwrap();
    assert!(measured_manifest(&source(), &selected, root.path()).is_err());
    let mut fixture = selected;
    fixture.binaries.push("memcordon-test-fixture".into());
    assert!(measured_manifest(&source(), &fixture, root.path()).is_err());
}

#[test]
fn linux_inventory_selects_private_profile_only_with_actual_private_feature_graph() {
    let root = directory();
    let mut elf = vec![0; 64];
    elf[..6].copy_from_slice(b"\x7fELF\x02\x01");
    elf[18..20].copy_from_slice(&62_u16.to_le_bytes());
    let mut selected = TargetDistribution {
        target: "x86_64-unknown-linux-gnu".into(),
        features: vec!["sealed-runtime".into()],
        binaries: vec!["memcordon".into(), "memcordon-sealed-agent".into()],
        units: [
            "memcordon-sealed-agent.service",
            "memcordon-sealed-agent.socket",
            "memcordon-sealed-launcher.service",
            "memcordon-sealed-launcher.socket",
            "memcordon.conf",
        ]
        .map(str::to_owned)
        .to_vec(),
    };
    for binary in &selected.binaries {
        std::fs::write(root.path().join(binary), &elf).unwrap();
    }
    let ordinary = measured_manifest(&source(), &selected, root.path()).unwrap();
    let SealedRuntime::Included { profiles, .. } = ordinary.sealed else {
        panic!("selected runtime missing");
    };
    assert_eq!(profiles, ["linux-unix-create-v1"]);
    selected.features.push("private-tcp".into());
    assert!(measured_manifest(&source(), &selected, root.path()).is_err());
    selected.units.extend(
        [
            "memcordon-sealed-network-launcher.service",
            "memcordon-sealed-network-launcher.socket",
        ]
        .map(str::to_owned),
    );
    let private = measured_manifest(&source(), &selected, root.path()).unwrap();
    let SealedRuntime::Included { profiles, .. } = private.sealed else {
        panic!("selected runtime missing");
    };
    assert_eq!(
        profiles,
        [
            "linux-unix-create-v1",
            "linux-tcp4-private-v1",
            "linux-tcp4-unix-private-v1"
        ]
    );
}

fn retained_component(
    directory: &std::path::Path,
    role: RuntimeComponentRole,
    id: &str,
    path: &str,
) -> RuntimeComponentRecord {
    let bytes = std::fs::read(directory.join(path)).unwrap();
    RuntimeComponentRecord {
        id: id.into(),
        path: path.into(),
        role,
        size: bytes.len() as u64,
        mode: 0o755,
        sha256: artifacts::checksum(&bytes),
    }
}

#[test]
fn runtime_inventory_matches_retained_linux_source_contract_in_both_channels() {
    use memcordon_ci::release::target::runtime_component;
    for (target, machine) in [
        ("x86_64-unknown-linux-gnu", 62_u16),
        ("aarch64-unknown-linux-gnu", 183_u16),
    ] {
        for private in [false, true] {
            let owner = directory();
            let mut selected = TargetDistribution {
                target: target.into(),
                features: vec!["sealed-runtime".into()],
                binaries: vec!["memcordon".into(), "memcordon-sealed-agent".into()],
                units: [
                    "memcordon-sealed-agent.service",
                    "memcordon-sealed-agent.socket",
                    "memcordon-sealed-launcher.service",
                    "memcordon-sealed-launcher.socket",
                    "memcordon.conf",
                ]
                .map(str::to_owned)
                .to_vec(),
            };
            if private {
                selected.features.push("private-tcp".into());
                selected.units.extend(
                    [
                        "memcordon-sealed-network-launcher.service",
                        "memcordon-sealed-network-launcher.socket",
                    ]
                    .map(str::to_owned),
                );
            }
            let mut native = Vec::new();
            let mut retained = Vec::new();
            // Match the retained source reader's independent semantic tuple,
            // not the producer's mapping or the executable basename.
            for (index, (role, id, path)) in [
                (RuntimeComponentRole::PublicCli, "public-cli", "memcordon"),
                (
                    RuntimeComponentRole::SealedAgent,
                    "sealed-agent",
                    "memcordon-sealed-agent",
                ),
            ]
            .into_iter()
            .enumerate()
            {
                let mut bytes = vec![index as u8; 64];
                bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
                bytes[18..20].copy_from_slice(&machine.to_le_bytes());
                std::fs::write(owner.path().join(path), &bytes).unwrap();
                native.push(runtime_component(role, path.into(), &bytes));
                retained.push(retained_component(owner.path(), role, id, path));
            }
            let expected = if private {
                RuntimeManifest::linux_combined(
                    "1.2.3".into(),
                    source().commit().into(),
                    target.into(),
                    retained,
                )
            } else {
                RuntimeManifest::linux_selected(
                    "1.2.3".into(),
                    source().commit().into(),
                    target.into(),
                    retained,
                    private,
                )
            }
            .unwrap();
            let produced = if private {
                RuntimeManifest::linux_combined(
                    "1.2.3".into(),
                    source().commit().into(),
                    target.into(),
                    native,
                )
            } else {
                RuntimeManifest::linux_selected(
                    "1.2.3".into(),
                    source().commit().into(),
                    target.into(),
                    native,
                    private,
                )
            }
            .unwrap();
            assert_eq!(
                RuntimeManifest::parse(&serde_json::to_vec(&produced).unwrap()).unwrap(),
                expected
            );
            assert_eq!(
                measured_manifest(&source(), &selected, owner.path()).unwrap(),
                expected
            );
            let mut old = expected.clone();
            old.components[0].id = "memcordon".into();
            old.validate().unwrap(); // Generic validity did not catch the source mismatch.
            assert_ne!(old, expected);
        }
    }
    let helper = runtime_component(
        RuntimeComponentRole::Arm32AbiHelper,
        "memcordon-arm32-abi-helper".into(),
        b"selected helper bytes",
    );
    assert_eq!(helper.id, "arm32-abi-helper");
    assert_eq!(helper.path, "memcordon-arm32-abi-helper");
}

#[test]
fn runtime_inventory_matches_retained_windows_source_contract_in_both_channels() {
    use memcordon_ci::release::target::runtime_component;
    for target in ["x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"] {
        let owner = directory();
        let mut selected = windows();
        selected.target = target.into();
        let mut native = Vec::new();
        let mut retained = Vec::new();
        for (index, (role, id, path)) in [
            (
                RuntimeComponentRole::PublicCli,
                "public-cli",
                "memcordon.exe",
            ),
            (
                RuntimeComponentRole::SealedAgent,
                "sealed-agent",
                "memcordon-sealed-agent.exe",
            ),
            (
                RuntimeComponentRole::DesktopBootstrap,
                "target-desktop-bootstrap",
                "memcordon-target-desktop-bootstrap.exe",
            ),
            (
                RuntimeComponentRole::SessionBroker,
                "session-broker",
                "memcordon-session-broker.exe",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let mut bytes = pe(index as u8);
            if target.starts_with("aarch64-") {
                bytes[68..70].copy_from_slice(&[0x64, 0xaa]);
            }
            std::fs::write(owner.path().join(path), &bytes).unwrap();
            native.push(runtime_component(role, path.into(), &bytes));
            retained.push(retained_component(owner.path(), role, id, path));
        }
        let expected = RuntimeManifest::windows(
            "1.2.3".into(),
            source().commit().into(),
            target.into(),
            retained,
        )
        .unwrap();
        let produced = RuntimeManifest::windows(
            "1.2.3".into(),
            source().commit().into(),
            target.into(),
            native,
        )
        .unwrap();
        assert_eq!(
            RuntimeManifest::parse(&serde_json::to_vec(&produced).unwrap()).unwrap(),
            expected
        );
        assert_eq!(
            measured_manifest(&source(), &selected, owner.path()).unwrap(),
            expected
        );
    }
}
