use memcordon_core::runtime_manifest::{
    NativeProviderProtocols, RuntimeComponentRecord, RuntimeComponentRole, RuntimeManifestV2,
};
use memcordon_core::runtime_manifest_v3::*;
use memcordon_core::workload_discovery_v2::profile_catalog_digest_v2;
use memcordon_core::workload_registry_v2::ProfileKindV2;
use memcordon_core::{BoundedVec, DiagnosticSha256};

const SOURCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TARGET: &str = "x86_64-unknown-linux-gnu";

fn components() -> Vec<RuntimeComponentRecord> {
    [
        (
            "memcordon",
            "bin/memcordon",
            RuntimeComponentRole::PublicCli,
        ),
        (
            "sealed-agent",
            "bin/memcordon-sealed-agent",
            RuntimeComponentRole::SealedAgent,
        ),
    ]
    .into_iter()
    .map(|(id, path, role)| RuntimeComponentRecord {
        id: id.into(),
        path: path.into(),
        role,
        size: 4096,
        mode: 0o755,
        sha256: "7".repeat(64),
    })
    .collect()
}

fn manifest() -> RuntimeManifestV3 {
    let mut contracts = BoundedVec::default();
    contracts.try_push(1).unwrap();
    contracts.try_push(2).unwrap();
    let mut profiles = BoundedVec::default();
    profiles
        .try_push(RuntimeProfileRecordV3 {
            profile: ProfileKindV2::LinuxTcp4PrivateV1.reference(),
            availability: RuntimeProfileAvailabilityV3::Unsupported,
        })
        .unwrap();
    profiles
        .try_push(RuntimeProfileRecordV3 {
            profile: ProfileKindV2::LinuxUnixCreateV1.reference(),
            availability: RuntimeProfileAvailabilityV3::Unqualified,
        })
        .unwrap();
    RuntimeManifestV3 {
        schema_version: RuntimeManifestVersionThree::default(),
        project: "memcordon".into(),
        version: "0.5.7-dev".into(),
        source_commit: SOURCE.into(),
        target: TARGET.into(),
        components: components(),
        sealed: SealedRuntimeV3::WorkloadV2 {
            agent_component: "sealed-agent".into(),
            native_protocols: NativeProviderProtocols::Linux {
                provider_contract: 4,
                launch_wire: 4,
            },
            broker_wire: 4,
            execution_report_schema: 11,
            plan_report_schema: 10,
            doctor_report_schema: 7,
            installed_qualification_schema: 4,
            supported_contract_versions: contracts,
            profile_catalog_sha256: profile_catalog_digest_v2(),
            profiles,
        },
    }
}

fn qualification(profile: ProfileKindV2) -> QualificationArtifactReferenceV2 {
    QualificationArtifactReferenceV2 {
        schema_version: QualificationArtifactSchemaTwo::default(),
        artifact: "certification/workload/linux-profile-qualification.json".into(),
        artifact_sha256: DiagnosticSha256::from_bytes([7; 32]),
        qualified_target: TARGET.into(),
        source_commit: SOURCE.into(),
        profile: profile.reference(),
    }
}

#[test]
fn linux_constructor_emits_exact_unqualified_catalogue() {
    for target in ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"] {
        let generated = RuntimeManifestV3::linux_unqualified(
            "0.5.7-dev".into(),
            SOURCE.into(),
            target.into(),
            components(),
        )
        .unwrap();
        let parsed = RuntimeManifestV3::parse(&serde_json::to_vec(&generated).unwrap()).unwrap();
        assert_eq!(parsed, generated);
        let SealedRuntimeV3::WorkloadV2 { profiles, .. } = parsed.sealed else {
            panic!("Linux constructor emitted another provider policy");
        };
        assert_eq!(profiles.as_slice().len(), 2);
        assert!(profiles.as_slice().iter().all(|record| matches!(
            record.availability,
            RuntimeProfileAvailabilityV3::Unqualified
        )));
    }
    assert!(
        RuntimeManifestV3::linux_unqualified(
            "0.5.7-dev".into(),
            SOURCE.into(),
            "x86_64-unknown-linux-musl".into(),
            components(),
        )
        .is_err()
    );
}

#[test]
fn v3_public_binding_requires_exact_manifest_bytes() {
    let manifest = RuntimeManifestV3::linux_unqualified(
        "0.5.7-dev".into(),
        SOURCE.into(),
        TARGET.into(),
        components(),
    )
    .unwrap();
    let bytes = serde_json::to_vec(&manifest).unwrap();
    let binding = manifest.public_binding(&bytes).unwrap();
    assert_eq!(
        binding.runtime_manifest_sha256,
        memcordon_core::workload_codec::hash_bytes(&bytes)
    );
    let mut changed = manifest.clone();
    changed.version = "0.5.8-dev".into();
    assert!(changed.public_binding(&bytes).is_err());
}

#[test]
fn v3_parser_is_closed_and_versioned_without_rewriting_v2() {
    let v3 = manifest();
    let bytes = serde_json::to_vec(&v3).unwrap();
    assert_eq!(RuntimeManifestV3::parse(&bytes).unwrap(), v3);
    assert!(matches!(
        VersionedRuntimeManifest::parse(&bytes).unwrap(),
        VersionedRuntimeManifest::V3(_)
    ));
    let v2 = RuntimeManifestV2::linux(
        "0.5.7-dev".into(),
        SOURCE.into(),
        TARGET.into(),
        components(),
    );
    assert!(matches!(
        VersionedRuntimeManifest::parse(&serde_json::to_vec(&v2).unwrap()).unwrap(),
        VersionedRuntimeManifest::V2(_)
    ));
    let mut wrong: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    wrong["schema_version"] = serde_json::json!(2);
    assert!(VersionedRuntimeManifest::parse(&serde_json::to_vec(&wrong).unwrap()).is_err());
    wrong["schema_version"] = serde_json::json!(3);
    wrong["unknown"] = serde_json::json!(true);
    assert!(RuntimeManifestV3::parse(&serde_json::to_vec(&wrong).unwrap()).is_err());
}

#[test]
fn v3_rejects_private_claims_and_cross_target_native_references() {
    let mut v3 = manifest();
    if let SealedRuntimeV3::WorkloadV2 { profiles, .. } = &mut v3.sealed {
        let mut records = BoundedVec::default();
        records
            .try_push(RuntimeProfileRecordV3 {
                profile: ProfileKindV2::LinuxTcp4PrivateV1.reference(),
                availability: RuntimeProfileAvailabilityV3::Qualified {
                    qualification: qualification(ProfileKindV2::LinuxTcp4PrivateV1),
                },
            })
            .unwrap();
        records.try_push(profiles.as_slice()[1].clone()).unwrap();
        *profiles = records;
    }
    assert!(v3.validate().is_err());
    let mut v3 = manifest();
    if let SealedRuntimeV3::WorkloadV2 { profiles, .. } = &mut v3.sealed {
        let mut records = BoundedVec::default();
        records.try_push(profiles.as_slice()[0].clone()).unwrap();
        let mut wrong = qualification(ProfileKindV2::LinuxUnixCreateV1);
        wrong.qualified_target = "aarch64-unknown-linux-gnu".into();
        records
            .try_push(RuntimeProfileRecordV3 {
                profile: ProfileKindV2::LinuxUnixCreateV1.reference(),
                availability: RuntimeProfileAvailabilityV3::Qualified {
                    qualification: wrong,
                },
            })
            .unwrap();
        *profiles = records;
    }
    assert!(v3.validate().is_err());
}

#[test]
fn v3_rejects_component_and_protocol_substitution() {
    let mut v3 = manifest();
    v3.components[1].role = RuntimeComponentRole::PublicCli;
    assert!(v3.validate().is_err());
    let mut v3 = manifest();
    v3.components[1].sha256 = "7".repeat(63);
    assert!(v3.validate().is_err());
    let mut v3 = manifest();
    if let SealedRuntimeV3::WorkloadV2 { broker_wire, .. } = &mut v3.sealed {
        *broker_wire = 3;
    }
    assert!(v3.validate().is_err());
    let mut v3 = manifest();
    if let SealedRuntimeV3::WorkloadV2 {
        supported_contract_versions,
        ..
    } = &mut v3.sealed
    {
        let mut versions = BoundedVec::default();
        versions.try_push(2).unwrap();
        versions.try_push(1).unwrap();
        *supported_contract_versions = versions;
    }
    assert!(v3.validate().is_err());
}
