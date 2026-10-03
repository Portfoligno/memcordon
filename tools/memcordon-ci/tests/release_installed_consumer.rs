use memcordon_ci::release::{
    artifacts,
    distribution::TargetDistribution,
    installed_consumer::{binary_path, measured_manifest},
    source::{BuildSourceIdentity, SelectedSource},
};
use memcordon_core::runtime_manifest::SealedRuntime;

fn directory() -> tempfile::TempDir {
    if cfg!(unix) {
        tempfile::tempdir_in("/tmp").unwrap()
    } else {
        tempfile::tempdir().unwrap()
    }
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
    assert_eq!(profiles, ["linux-unix-create-v1", "linux-tcp4-private-v1"]);
}
