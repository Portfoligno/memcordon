use memcordon_core::runtime_manifest::{
    NativeProviderProtocols, RuntimeComponentRecord, RuntimeComponentRole, RuntimeManifest,
    SealedRuntime,
};

fn components(windows: bool) -> Vec<RuntimeComponentRecord> {
    use RuntimeComponentRole::*;
    let members = if windows {
        vec![
            ("public-cli", "memcordon.exe", PublicCli),
            ("sealed-agent", "memcordon-sealed-agent.exe", SealedAgent),
            (
                "desktop-bootstrap",
                "memcordon-target-desktop-bootstrap.exe",
                DesktopBootstrap,
            ),
            (
                "session-broker",
                "memcordon-session-broker.exe",
                SessionBroker,
            ),
        ]
    } else {
        vec![
            ("public-cli", "memcordon", PublicCli),
            ("sealed-agent", "memcordon-sealed-agent", SealedAgent),
        ]
    };
    members
        .into_iter()
        .map(|(id, path, role)| RuntimeComponentRecord {
            id: id.into(),
            path: path.into(),
            role,
            size: 4096,
            mode: 0o755,
            sha256: String::from(memcordon_core::DiagnosticSha256::from_bytes([7; 32])),
        })
        .collect()
}

fn linux() -> RuntimeManifest {
    RuntimeManifest::linux(
        "0.5.7-dev".into(),
        "a".repeat(std::mem::size_of::<[u8; 20]>() * 2),
        "x86_64-unknown-linux-gnu".into(),
        components(false),
    )
    .unwrap()
}

#[test]
fn selected_components_round_trip_on_each_native_target_without_approval_fields() {
    for target in ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"] {
        let manifest = RuntimeManifest::linux(
            linux().version,
            linux().source_commit,
            target.into(),
            components(false),
        )
        .unwrap();
        let bytes = serde_json::to_vec(&manifest).unwrap();
        assert_eq!(RuntimeManifest::parse(&bytes).unwrap(), manifest);
        assert!(
            !std::str::from_utf8(&bytes)
                .unwrap()
                .contains("qualification")
        );
    }
    for target in ["x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"] {
        let manifest = RuntimeManifest::windows(
            linux().version,
            linux().source_commit,
            target.into(),
            components(true),
        )
        .unwrap();
        assert_eq!(
            RuntimeManifest::parse(&serde_json::to_vec(&manifest).unwrap()).unwrap(),
            manifest
        );
    }
    for target in ["x86_64-apple-darwin", "aarch64-apple-darwin"] {
        let manifest = RuntimeManifest::cli_only(
            linux().version,
            linux().source_commit,
            target.into(),
            vec![components(false).remove(0)],
        )
        .unwrap();
        assert_eq!(
            RuntimeManifest::parse(&serde_json::to_vec(&manifest).unwrap()).unwrap(),
            manifest
        );
    }
}

#[test]
fn component_alias_role_size_mode_and_hash_substitution_are_rejected() {
    for path in [
        "./memcordon",
        "bin/../memcordon",
        "memcordon/",
        "MEMCORDON",
        "C:memcordon",
        "memcordon\\",
    ] {
        let mut manifest = linux();
        manifest.components[0].path = path.into();
        assert!(manifest.validate().is_err(), "accepted member alias {path}");
    }
    let mut manifest = linux();
    manifest.components[1].role = RuntimeComponentRole::PublicCli;
    assert!(manifest.validate().is_err());
    let mut manifest = linux();
    manifest.components[1].id = manifest.components[0].id.clone();
    assert!(manifest.validate().is_err());
    let mut manifest = linux();
    manifest.components[1].size = 0;
    assert!(manifest.validate().is_err());
    manifest.components[1].size = 4096;
    manifest.components[1].mode = 0o777;
    assert!(manifest.validate().is_err());
    manifest.components[1].mode = 0o755;
    manifest.components[1].sha256.pop();
    assert!(manifest.validate().is_err());
    let mut manifest = linux();
    manifest.components[1].sha256 = "0".repeat(manifest.components[1].sha256.len());
    assert!(manifest.validate().is_err());
    let mut manifest = linux();
    manifest.source_commit = "0".repeat(manifest.source_commit.len());
    assert!(manifest.validate().is_err());
}

#[test]
fn target_protocol_and_selected_companion_inventory_must_agree() {
    let mut manifest = linux();
    manifest.target = "aarch64-pc-windows-msvc".into();
    assert!(manifest.validate().is_err());
    let mut manifest = linux();
    let SealedRuntime::Included {
        native_protocols, ..
    } = &mut manifest.sealed
    else {
        unreachable!()
    };
    *native_protocols = NativeProviderProtocols::Linux {
        provider_contract: 3,
        launch_wire: 4,
    };
    assert!(manifest.validate().is_err());
    let mut manifest = linux();
    manifest.components.pop();
    assert!(manifest.validate().is_err());
    let mut manifest = linux();
    manifest.sealed = SealedRuntime::NotIncluded;
    assert!(manifest.validate().is_err());
}

#[test]
fn parsed_manifest_cannot_bind_different_source_version_or_exact_bytes() {
    let manifest = linux();
    let bytes = serde_json::to_vec(&manifest).unwrap();
    let binding = manifest.public_binding(&bytes).unwrap();
    assert_eq!(
        binding.runtime_manifest_sha256,
        memcordon_core::workload_codec::hash_bytes(&bytes)
    );
    let mut changed = manifest.clone();
    changed.version = "0.5.8-dev".into();
    assert!(changed.public_binding(&bytes).is_err());
    changed = manifest.clone();
    changed.source_commit = "b".repeat(manifest.source_commit.len());
    assert!(changed.public_binding(&bytes).is_err());
    let mut differently_encoded = bytes.clone();
    differently_encoded.push(b' ');
    assert_ne!(
        manifest.public_binding(&differently_encoded).unwrap(),
        binding
    );
}

#[test]
fn parser_rejects_old_envelopes_duplicate_unknown_fields_and_oversized_input() {
    let manifest = linux();
    for (field, value) in [
        (
            "format",
            serde_json::json!("memcordon.runtime-manifest-old"),
        ),
        ("revision", serde_json::json!(2)),
        ("schema_version", serde_json::json!(3)),
        ("qualification", serde_json::json!({"state": "qualified"})),
    ] {
        let mut object = serde_json::to_value(&manifest).unwrap();
        object[field] = value;
        assert!(RuntimeManifest::parse(&serde_json::to_vec(&object).unwrap()).is_err());
    }
    let mut object = serde_json::to_value(&manifest).unwrap();
    object.as_object_mut().unwrap().remove("format");
    object.as_object_mut().unwrap().remove("revision");
    object["schema_version"] = serde_json::json!(2);
    assert!(RuntimeManifest::parse(&serde_json::to_vec(&object).unwrap()).is_err());
    assert!(
        RuntimeManifest::parse(
            br#"{"format":"memcordon.runtime-manifest","format":"memcordon.runtime-manifest"}"#
        )
        .is_err()
    );
    assert!(
        RuntimeManifest::parse(&vec![
            b' ';
            memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES
                + 1
        ])
        .is_err()
    );
}
