#![cfg(all(target_os = "linux", target_env = "gnu"))]

use crate::linux::installed_release_qualification::{
    fixed_q_reference_path, from_exact_bytes, read_protected_absolute,
};
use memcordon_core::runtime_manifest::{RuntimeComponentRecord, RuntimeComponentRole};
use memcordon_core::runtime_manifest_v3::{
    QualificationArtifactReferenceV2, RuntimeManifestV3, RuntimeProfileAvailabilityV3,
    SealedRuntimeV3,
};
use memcordon_core::workload_discovery_v2::profile_catalog_digest_v2;
use memcordon_core::workload_qualification_v2::QualificationArtifactV2;
use memcordon_core::workload_registry_v2::ProfileKindV2;
use memcordon_core::{BoundedText, BoundedVec, DiagnosticSha256, workload_codec::hash_bytes};

const AGENT: &[u8] = b"installed provider image";
const PUBLIC: &[u8] = b"installed public image";

fn m0() -> RuntimeManifestV3 {
    let component = |id: &str, path: &str, role, bytes: &[u8]| RuntimeComponentRecord {
        id: id.into(),
        path: path.into(),
        role,
        size: bytes.len() as u64,
        mode: 0o755,
        sha256: String::from(hash_bytes(bytes)),
    };
    RuntimeManifestV3::linux_unqualified(
        env!("CARGO_PKG_VERSION").into(),
        crate::SOURCE_COMMIT.into(),
        crate::linux::runtime_manifest::target().unwrap().into(),
        vec![
            component(
                "public-cli",
                "memcordon",
                RuntimeComponentRole::PublicCli,
                PUBLIC,
            ),
            component(
                "sealed-agent",
                "memcordon-sealed-agent",
                RuntimeComponentRole::SealedAgent,
                AGENT,
            ),
        ],
    )
    .unwrap()
}

fn q_bytes(target: &str) -> Vec<u8> {
    let zero = DiagnosticSha256::from_bytes([0; 32]);
    serde_json::to_vec(&QualificationArtifactV2 {
        schema_version: Default::default(),
        source_commit: BoundedText::new(crate::SOURCE_COMMIT).unwrap(),
        target: BoundedText::new(target).unwrap(),
        profile: ProfileKindV2::LinuxTcp4PrivateV1.reference(),
        profile_catalog_digest: profile_catalog_digest_v2(),
        filter_digest: zero.clone(),
        unit_digest: zero.clone(),
        component_digest: zero.clone(),
        test_inventory_digest: zero.clone(),
        runner_run_digest: zero.clone(),
        host_prerequisites_digest: zero,
        observed_results: BoundedVec::default(),
        tests_skipped: 0,
    })
    .unwrap()
}

fn m1(q: &[u8]) -> RuntimeManifestV3 {
    let mut manifest = m0();
    let SealedRuntimeV3::WorkloadV2 { profiles, .. } = &mut manifest.sealed else {
        panic!("Linux M0 constructor changed protocol");
    };
    let mut records = BoundedVec::default();
    for (index, record) in profiles.as_slice().iter().enumerate() {
        let mut record = record.clone();
        if index == 0 {
            record.availability = RuntimeProfileAvailabilityV3::Qualified {
                qualification: QualificationArtifactReferenceV2 {
                    schema_version: Default::default(),
                    artifact: fixed_q_reference_path(&manifest.target).unwrap().into(),
                    artifact_sha256: hash_bytes(q),
                    qualified_target: manifest.target.clone(),
                    source_commit: manifest.source_commit.clone(),
                    profile: ProfileKindV2::LinuxTcp4PrivateV1.reference(),
                },
            };
        }
        records.try_push(record).unwrap();
    }
    *profiles = records;
    manifest.validate().unwrap();
    manifest
}

#[test]
fn candidate_m0_and_m1_have_distinct_non_authoritative_readbacks() {
    let unqualified = m0();
    let m0_bytes = serde_json::to_vec(&unqualified).unwrap();
    let readback = from_exact_bytes(m0_bytes.clone(), AGENT, PUBLIC, None).unwrap();
    assert_eq!(readback.manifest, unqualified);
    assert_eq!(readback.manifest_bytes, m0_bytes);
    assert_eq!(readback.qualification_sha256, None);
    assert_eq!(readback.qualification_bytes(), None);

    let q = q_bytes(&unqualified.target);
    let qualified = m1(&q);
    let m1_bytes = serde_json::to_vec(&qualified).unwrap();
    let readback = from_exact_bytes(m1_bytes.clone(), AGENT, PUBLIC, Some(q.clone())).unwrap();
    assert_eq!(readback.manifest, qualified);
    assert_eq!(readback.manifest_bytes, m1_bytes);
    assert_eq!(readback.qualification_sha256, Some(hash_bytes(&q)));
    assert_eq!(readback.qualification_bytes(), Some(q.as_slice()));
    let baseline_binding = crate::linux::runtime_manifest::candidate_public_binding(&readback)
        .expect("M1 must preserve a valid public baseline generation identity");
    assert_eq!(
        baseline_binding.runtime_manifest_sha256,
        hash_bytes(&m1_bytes)
    );
    assert_ne!(
        baseline_binding.runtime_manifest_sha256,
        hash_bytes(&m0_bytes)
    );
}

#[test]
fn candidate_m1_rejects_missing_substituted_or_other_target_q() {
    let target = crate::linux::runtime_manifest::target().unwrap();
    let q = q_bytes(target);
    let bytes = serde_json::to_vec(&m1(&q)).unwrap();
    assert!(from_exact_bytes(bytes.clone(), AGENT, PUBLIC, None).is_err());
    assert!(from_exact_bytes(bytes.clone(), AGENT, PUBLIC, Some(b"other Q".to_vec())).is_err());
    assert!(from_exact_bytes(bytes.clone(), AGENT, b"changed public", Some(q.clone())).is_err());
    let other = if target == "x86_64-unknown-linux-gnu" {
        "aarch64-unknown-linux-gnu"
    } else {
        "x86_64-unknown-linux-gnu"
    };
    assert!(from_exact_bytes(bytes, AGENT, PUBLIC, Some(q_bytes(other))).is_err());
}

#[test]
fn q_member_names_are_fixed_for_both_gnu_targets() {
    assert_eq!(
        fixed_q_reference_path("x86_64-unknown-linux-gnu").unwrap(),
        "certification/workload/linux-x64-private-v2.json"
    );
    assert_eq!(
        fixed_q_reference_path("aarch64-unknown-linux-gnu").unwrap(),
        "certification/workload/linux-arm64-private-v2.json"
    );
    assert!(fixed_q_reference_path("x86_64-unknown-linux-musl").is_err());
}

#[test]
fn protected_reader_rejects_relative_and_world_writable_ancestors() {
    assert!(read_protected_absolute(std::path::Path::new("relative"), 100, None).is_err());
    assert!(read_protected_absolute(std::path::Path::new("/tmp/not-a-q"), 100, None).is_err());
}
