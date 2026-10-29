use memcordon_ci::release::{
    compatibility::{CompatibilityV2, NativePackage},
    distribution::{Distribution, TargetDistribution},
    source::{BuildSourceIdentity, SelectedSource},
};
use memcordon_core::runtime_components::{RuntimeComponentRecord, RuntimeComponentRole};
use memcordon_core::runtime_manifest_v2::RuntimeManifestV2;
use std::collections::BTreeMap;

fn source() -> BuildSourceIdentity {
    SelectedSource {
        format: "memcordon.selected-source".into(),
        revision: 1,
        repository: "example/project".into(),
        tag_ref: "refs/tags/1.2.3".into(),
        commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        version: "1.2.3".parse().unwrap(),
    }
    .into()
}
fn selection() -> TargetDistribution {
    TargetDistribution {
        target: "x86_64-unknown-linux-gnu".into(),
        features: vec![],
        binaries: vec!["memcordon".into()],
        units: vec![],
    }
}
#[test]
fn measured_package_metadata_excludes_self_and_binds_actual_source_features_bytes() {
    let source = source();
    let selected = selection();
    let mut members = BTreeMap::from([
        ("memcordon".into(), b"actual selected image".to_vec()),
        (
            "runtime-manifest.json".into(),
            b"actual runtime metadata".to_vec(),
        ),
    ]);
    let package = NativePackage::measured(&source, &selected, &members).unwrap();
    assert_eq!(package.files.len(), 2);
    let bytes = serde_json::to_vec(&package).unwrap();
    members.insert("package.json".into(), bytes.clone());
    NativePackage::verify(&bytes, &source, &selected, &members).unwrap();
    assert!(NativePackage::measured(&source, &selected, &members).is_err());
    members.get_mut("memcordon").unwrap().push(0);
    assert!(NativePackage::verify(&bytes, &source, &selected, &members).is_err());
    let mut wrong = serde_json::to_value(package).unwrap();
    wrong["features"] = serde_json::json!(["sealed-runtime"]);
    assert!(
        NativePackage::verify(
            &serde_json::to_vec(&wrong).unwrap(),
            &source,
            &selected,
            &members
        )
        .is_err()
    );
}
#[test]
fn compatibility_uses_selected_inventory_and_exact_runtime_protocol_profiles() {
    let source = source();
    let selected = selection();
    let distribution = Distribution {
        format: "memcordon.distribution".into(),
        revision: 1,
        public_consumer: false,
        packages: memcordon_ci::release::source::PUBLIC_PACKAGES
            .into_iter()
            .map(str::to_owned)
            .collect(),
        targets: vec![selected.clone()],
    };
    let manifest = RuntimeManifestV2::cli_only(
        "1.2.3".into(),
        source.commit().into(),
        selected.target.clone(),
        vec![RuntimeComponentRecord {
            id: "memcordon".into(),
            role: RuntimeComponentRole::PublicCli,
            path: "memcordon".into(),
            size: 1,
            mode: 0o755,
            sha256: hex::encode([1; 32]),
        }],
    )
    .unwrap();
    let mut manifests = BTreeMap::from([(selected.target.clone(), manifest)]);
    let compatibility = CompatibilityV2::selected(&source, &distribution, &manifests).unwrap();
    assert_eq!(compatibility.targets[0].selected_binaries, ["memcordon"]);
    assert!(compatibility.targets[0].native_protocols.is_none());
    assert_eq!(compatibility.named_formats["memcordon.result"], 3);
    assert_eq!(compatibility.execution_schema, 10);
    assert_eq!(compatibility.clean_schema, 2);
    manifests.get_mut(&selected.target).unwrap().source_commit =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into();
    assert!(CompatibilityV2::selected(&source, &distribution, &manifests).is_err());
}
