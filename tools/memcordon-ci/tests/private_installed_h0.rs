use std::collections::BTreeMap;

use memcordon_ci::private_installed_h0::{
    InstalledH0StaticBytes, join_installed_epoch_to_candidate_request,
    validate_installation_epoch_bytes, validate_installed_h0_static,
};
use memcordon_ci::private_protected_readback::{
    ProtectedCandidateReleaseRequestV1, ProtectedCoordinatorIdentityV1,
};
use memcordon_ci::release_private::{PrivateCandidateInputs, prepare_private_candidate};
use memcordon_core::package_inspection_v6::{
    InspectionVersionSix, LinuxInstalledInspectionV6, LinuxPackageInspectionV6, LinuxUnitHashesV6,
    NetworkLauncherStateV6,
};
use memcordon_core::runtime_manifest::{RuntimeComponentRecord, RuntimeComponentRole};
use memcordon_core::runtime_manifest_v3::SealedRuntimeV3;
use memcordon_core::workload_codec::hash_bytes;
use memcordon_core::{BoundedText, DiagnosticSha256};

fn unit_bytes() -> [Vec<u8>; 7] {
    std::array::from_fn(|index| vec![u8::try_from(index + 1).unwrap(); 16])
}

fn unit_hashes(bytes: &[Vec<u8>; 7]) -> LinuxUnitHashesV6 {
    LinuxUnitHashesV6 {
        control_service: hash_bytes(&bytes[0]),
        control_socket: hash_bytes(&bytes[1]),
        launcher_service: hash_bytes(&bytes[2]),
        launcher_socket: hash_bytes(&bytes[3]),
        tmpfiles: hash_bytes(&bytes[4]),
        network_launcher_service: hash_bytes(&bytes[5]),
        network_launcher_socket: hash_bytes(&bytes[6]),
    }
}

#[test]
fn h0_static_readback_binds_independently_measured_files() {
    let agent = vec![7; 4096];
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
        size: 4096,
        mode: 0o755,
        sha256: String::from(hash_bytes(&agent)),
    });
    let mut component_bytes = BTreeMap::new();
    for component in &components {
        component_bytes.insert(component.path.clone(), agent.clone());
    }
    let units = unit_bytes();
    let hashes = unit_hashes(&units);
    let filter = DiagnosticSha256::from_bytes([9; 32]);
    let candidate = prepare_private_candidate(PrivateCandidateInputs {
        version: "0.5.7-dev",
        source_commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        target: "x86_64-unknown-linux-gnu",
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
    } = &candidate.manifest.sealed
    else {
        panic!("candidate fixture must be workload V2");
    };
    let mut inspection = LinuxInstalledInspectionV6 {
        schema_version: InspectionVersionSix,
        package: LinuxPackageInspectionV6 {
            schema_version: InspectionVersionSix,
            version: BoundedText::new("0.5.7-dev").unwrap(),
            source_commit: BoundedText::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            target: BoundedText::new("x86_64-unknown-linux-gnu").unwrap(),
            runtime_manifest_sha256: candidate.manifest_sha256.clone(),
            components: components.to_vec(),
            native_protocols: native_protocols.clone(),
            profile_catalog_sha256: profile_catalog_sha256.clone(),
            private_filter_sha256: filter,
            compiled_units: hashes.clone(),
            compiled_metadata_valid: true,
        },
        installed_units: hashes.clone(),
        installed_agent_sha256: hash_bytes(&agent),
        installed_artifacts_valid: true,
        provider_reachable: false,
        network_launcher_state: NetworkLauncherStateV6::InstalledDisabled,
        baseline_qualification: None,
        private_qualification: None,
        installed_qualification_sha256: None,
    };
    let mut installed = InstalledH0StaticBytes {
        manifest: candidate.manifest_bytes.clone(),
        agent,
        units,
    };
    let bytes = serde_json::to_vec(&inspection).unwrap();
    assert_eq!(
        validate_installed_h0_static(&candidate, &hashes, &installed, &bytes).unwrap(),
        hash_bytes(&bytes)
    );

    installed.units[6][0] ^= 1;
    assert!(validate_installed_h0_static(&candidate, &hashes, &installed, &bytes).is_err());
    installed.units[6][0] ^= 1;
    inspection.installed_agent_sha256 = DiagnosticSha256::from_bytes([3; 32]);
    assert!(
        validate_installed_h0_static(
            &candidate,
            &hashes,
            &installed,
            &serde_json::to_vec(&inspection).unwrap()
        )
        .is_err()
    );
    inspection.installed_agent_sha256 = hash_bytes(&installed.agent);
    inspection.network_launcher_state = NetworkLauncherStateV6::EnabledUnqualified;
    assert!(
        validate_installed_h0_static(
            &candidate,
            &hashes,
            &installed,
            &serde_json::to_vec(&inspection).unwrap()
        )
        .is_err()
    );
}

#[test]
fn canonical_epoch_binds_protected_candidate_request() {
    #[derive(serde::Serialize)]
    struct CanonicalEpoch {
        schema_version: u8,
        counter: u64,
        nonce_digest: DiagnosticSha256,
    }
    let bytes = serde_json::to_vec(&CanonicalEpoch {
        schema_version: 1,
        counter: 42,
        nonce_digest: DiagnosticSha256::from_bytes([7; 32]),
    })
    .unwrap();
    let epoch = validate_installation_epoch_bytes(&bytes).unwrap();
    let mut request = ProtectedCandidateReleaseRequestV1 {
        schema_version: 1,
        stage: "candidate-capability".into(),
        selector: "private_tcp::native_tcp_bind_listen_connect".into(),
        challenge: "ab".repeat(32),
        result_key: DiagnosticSha256::from_bytes([1; 32]),
        installation_epoch: epoch.clone(),
        candidate_manifest_sha256: DiagnosticSha256::from_bytes([2; 32]),
        service_generation_sha256: DiagnosticSha256::from_bytes([3; 32]),
        coordinator: ProtectedCoordinatorIdentityV1 {
            pid: 123,
            start_time: 456,
        },
    };
    join_installed_epoch_to_candidate_request(&request, &epoch).unwrap();
    request.installation_epoch = DiagnosticSha256::from_bytes([8; 32]);
    assert!(join_installed_epoch_to_candidate_request(&request, &epoch).is_err());
    assert!(validate_installation_epoch_bytes(b"{\"schema_version\":1,\"counter\":0,\"nonce_digest\":\"7777777777777777777777777777777777777777777777777777777777777777\"}").is_err());
    assert!(
        validate_installation_epoch_bytes(b"{\"schema_version\":1,\"schema_version\":1}").is_err()
    );
    let mut noncanonical = bytes.clone();
    noncanonical.push(b' ');
    assert!(validate_installation_epoch_bytes(&noncanonical).is_err());
}
