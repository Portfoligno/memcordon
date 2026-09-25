use std::collections::BTreeMap;
use std::fs;

use memcordon_ci::private_suite::read_downloaded_candidate;
use memcordon_ci::release_private::{PrivateCandidateInputs, prepare_private_candidate};
use memcordon_core::package_inspection_v6::{
    InspectionVersionSix, LinuxPackageInspectionV6, LinuxUnitHashesV6,
};
use memcordon_core::runtime_manifest::{RuntimeComponentRecord, RuntimeComponentRole};
use memcordon_core::runtime_manifest_v3::SealedRuntimeV3;
use memcordon_core::workload_codec::hash_bytes;
use memcordon_core::{BoundedText, DiagnosticSha256};

const TARGET: &str = "x86_64-unknown-linux-gnu";
const SOURCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn units() -> LinuxUnitHashesV6 {
    let digest = DiagnosticSha256::from_bytes([8; 32]);
    LinuxUnitHashesV6 {
        control_service: digest.clone(),
        control_socket: digest.clone(),
        launcher_service: digest.clone(),
        launcher_socket: digest.clone(),
        tmpfiles: digest.clone(),
        network_launcher_service: digest.clone(),
        network_launcher_socket: digest,
    }
}

#[test]
fn downloaded_candidate_requires_exact_native_target_inventory_and_b_m0() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp
        .path()
        .join("target/ci/release-inputs/release-native-linux-x64/private-candidate-linux-x64");
    fs::create_dir_all(&directory).unwrap();
    let bytes = vec![7; 4096];
    let components = [
        ("public-cli", "memcordon", RuntimeComponentRole::PublicCli),
        (
            "sealed-agent",
            "memcordon-sealed-agent",
            RuntimeComponentRole::SealedAgent,
        ),
    ]
    .map(|(id, path, role)| RuntimeComponentRecord {
        id: id.into(),
        path: path.into(),
        role,
        size: bytes.len() as u64,
        mode: 0o755,
        sha256: String::from(hash_bytes(&bytes)),
    });
    let mut component_bytes = BTreeMap::new();
    for component in &components {
        component_bytes.insert(component.path.clone(), bytes.clone());
        fs::write(directory.join(&component.path), &bytes).unwrap();
    }
    let filter = DiagnosticSha256::from_bytes([9; 32]);
    let hashes = units();
    let prepared = prepare_private_candidate(PrivateCandidateInputs {
        version: env!("CARGO_PKG_VERSION"),
        source_commit: SOURCE,
        target: TARGET,
        components: &components,
        component_bytes: &component_bytes,
        compiled_units: &hashes,
        filter_sha256: &filter,
    })
    .unwrap();
    let SealedRuntimeV3::WorkloadV2 {
        native_protocols,
        profile_catalog_sha256,
        ..
    } = &prepared.manifest.sealed
    else {
        panic!("candidate fixture must be workload V2");
    };
    let inspection = LinuxPackageInspectionV6 {
        schema_version: InspectionVersionSix,
        version: BoundedText::new(env!("CARGO_PKG_VERSION")).unwrap(),
        source_commit: BoundedText::new(SOURCE).unwrap(),
        target: BoundedText::new(TARGET).unwrap(),
        runtime_manifest_sha256: prepared.manifest_sha256.clone(),
        components: components.to_vec(),
        native_protocols: native_protocols.clone(),
        profile_catalog_sha256: profile_catalog_sha256.clone(),
        private_filter_sha256: filter,
        compiled_units: hashes,
        compiled_metadata_valid: true,
    };
    fs::write(
        directory.join("runtime-manifest.json"),
        &prepared.manifest_bytes,
    )
    .unwrap();
    fs::write(
        directory.join("package-inspection-v6.json"),
        serde_json::to_vec(&inspection).unwrap(),
    )
    .unwrap();
    fs::write(
        directory.join("candidate-build-v2.json"),
        serde_json::to_vec(&prepared.record()).unwrap(),
    )
    .unwrap();
    let loaded = read_downloaded_candidate(temp.path(), TARGET, SOURCE).unwrap();
    assert_eq!(loaded.prepared.manifest_sha256, prepared.manifest_sha256);

    fs::write(directory.join("surplus.json"), b"{}").unwrap();
    assert!(read_downloaded_candidate(temp.path(), TARGET, SOURCE).is_err());
    fs::remove_file(directory.join("surplus.json")).unwrap();
    assert!(read_downloaded_candidate(temp.path(), TARGET, &"b".repeat(40)).is_err());
    fs::write(directory.join("memcordon-sealed-agent"), vec![8; 4096]).unwrap();
    assert!(read_downloaded_candidate(temp.path(), TARGET, SOURCE).is_err());
}
