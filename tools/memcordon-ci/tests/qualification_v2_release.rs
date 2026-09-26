use memcordon_ci::release_private::{
    OfflinePrivateQualifiedInputs, PrivateArchiveFormat, PrivateCandidateInputs,
    QualifiedArchiveExpectation, QualifiedLinuxReadbackInputs, prepare_private_candidate,
    prepare_private_final_manifest, prepare_private_qualified_offline, seal_qualified_archive,
    validate_private_candidate_record, validate_qualified_archive,
    validate_qualified_linux_readback,
};
use memcordon_ci::workload_qualification::{
    ARTIFACTS, PRIVATE_V2_ARTIFACTS, QualificationArtifactV1, QualificationKind,
    private_component_digest_v2, private_unit_digest_v2, reject_proposed_private_qualification_v2,
    validate_private_v2_against_build, validate_private_v2_against_trusted_native_completions,
};
use memcordon_core::package_inspection_v6::{
    InspectionVersionSix, LinuxInstalledInspectionV6, LinuxPackageInspectionV6, LinuxUnitHashesV6,
    NetworkLauncherStateV6, TrustedLinuxInspectionV6,
};
use memcordon_core::release_trust::{
    NativeQualificationCertificateV1, SignedNativeQualificationCertificateV1,
};
use memcordon_core::runtime_manifest::{RuntimeComponentRecord, RuntimeComponentRole};
use memcordon_core::runtime_manifest_v3::{
    QualificationArtifactReferenceV2, QualificationArtifactSchemaTwo, RuntimeProfileAvailabilityV3,
    SealedRuntimeV3,
};
use memcordon_core::workload_codec::hash_bytes;
use memcordon_core::workload_discovery_v2::profile_catalog_digest_v2;
use memcordon_core::workload_qualification_v2::{
    NativeTestOutcomeV2, ObservedNativeTestV2, QualificationArtifactV2, TrustedNativeCompletionV2,
    TrustedQualificationExpectationV2, inventory_digest,
};
use memcordon_core::workload_registry_v2::ProfileKindV2;
use memcordon_core::{BoundedText, BoundedVec, DiagnosticSha256};
use std::collections::BTreeMap;
use std::io::{Cursor, Write};

const SOURCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const X64: &str = "x86_64-unknown-linux-gnu";
const ARM64: &str = "aarch64-unknown-linux-gnu";
const NATIVE_TEST: &str = "native_private_tcp::namespace_isolation";

fn components() -> Vec<RuntimeComponentRecord> {
    [
        ("public-cli", "memcordon", RuntimeComponentRole::PublicCli),
        (
            "sealed-agent",
            "memcordon-sealed-agent",
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
        sha256: String::from(hash_bytes(&vec![7; 4096])),
    })
    .collect()
}

fn units() -> LinuxUnitHashesV6 {
    LinuxUnitHashesV6 {
        control_service: digest(11),
        control_socket: digest(12),
        launcher_service: digest(13),
        launcher_socket: digest(14),
        tmpfiles: digest(15),
        network_launcher_service: digest(16),
        network_launcher_socket: digest(17),
    }
}

fn digest(byte: u8) -> DiagnosticSha256 {
    DiagnosticSha256::from_bytes([byte; 32])
}

fn member_mode(path: &str) -> u32 {
    if matches!(path, "memcordon" | "memcordon-sealed-agent") {
        0o755
    } else {
        0o644
    }
}

#[test]
fn candidate_build_binds_actual_bytes_and_has_no_private_qualification() {
    let mut binaries = BTreeMap::new();
    for component in components() {
        binaries.insert(component.path, vec![7; 4096]);
    }
    let candidate = prepare_private_candidate(PrivateCandidateInputs {
        version: "0.5.7-dev",
        source_commit: SOURCE,
        target: X64,
        components: &components(),
        component_bytes: &binaries,
        compiled_units: &units(),
        filter_sha256: &digest(6),
    })
    .unwrap();
    assert_eq!(
        candidate.manifest_sha256,
        hash_bytes(&candidate.manifest_bytes)
    );
    assert_eq!(candidate.unit_sha256, private_unit_digest_v2(&units()));
    let record_bytes = serde_json::to_vec(&candidate.record()).unwrap();
    assert!(validate_private_candidate_record(&record_bytes, &candidate).is_ok());
    let mut changed_record = candidate.record();
    changed_record.filter_sha256 = digest(9);
    assert!(
        validate_private_candidate_record(
            &serde_json::to_vec(&changed_record).unwrap(),
            &candidate
        )
        .is_err()
    );
    assert!(
        validate_private_candidate_record(
            b"{\"schema_version\":2,\"schema_version\":2}",
            &candidate,
        )
        .is_err()
    );
    assert!(matches!(
        &candidate.manifest.sealed,
        SealedRuntimeV3::WorkloadV2 { profiles, .. }
            if profiles.as_slice().iter().all(|profile|
                !matches!(profile.availability, RuntimeProfileAvailabilityV3::Qualified { .. }))
    ));
    let mut changed = binaries.clone();
    changed.get_mut("memcordon-sealed-agent").unwrap()[0] ^= 1;
    assert!(
        prepare_private_candidate(PrivateCandidateInputs {
            version: "0.5.7-dev",
            source_commit: SOURCE,
            target: X64,
            components: &components(),
            component_bytes: &changed,
            compiled_units: &units(),
            filter_sha256: &digest(6),
        })
        .is_err()
    );
    assert!(
        prepare_private_candidate(PrivateCandidateInputs {
            version: "0.5.7-dev",
            source_commit: SOURCE,
            target: "aarch64-unknown-linux-musl",
            components: &components(),
            component_bytes: &binaries,
            compiled_units: &units(),
            filter_sha256: &digest(6),
        })
        .is_err()
    );
}

struct Fixture {
    artifact: QualificationArtifactV2,
    completion: DiagnosticSha256,
    filter: DiagnosticSha256,
    unit: DiagnosticSha256,
    component: DiagnosticSha256,
    runner: DiagnosticSha256,
    host: DiagnosticSha256,
}

impl Fixture {
    fn new() -> Self {
        let completion = digest(1);
        let trusted = [TrustedNativeCompletionV2 {
            name: NATIVE_TEST,
            target: X64,
            native_executed: true,
            completion_digest: &completion,
        }];
        let mut observed_results = BoundedVec::default();
        observed_results
            .try_push(ObservedNativeTestV2 {
                name: BoundedText::new(NATIVE_TEST).unwrap(),
                target: BoundedText::new(X64).unwrap(),
                outcome: NativeTestOutcomeV2::Passed,
                runner_completion_digest: completion.clone(),
            })
            .unwrap();
        let filter = digest(2);
        let unit = private_unit_digest_v2(&units());
        let component =
            private_component_digest_v2(X64, SOURCE, "0.5.7-dev", &components()).unwrap();
        let runner = digest(5);
        let host = digest(6);
        Self {
            artifact: QualificationArtifactV2 {
                schema_version: QualificationArtifactSchemaTwo::default(),
                source_commit: BoundedText::new(SOURCE).unwrap(),
                target: BoundedText::new(X64).unwrap(),
                profile: ProfileKindV2::LinuxTcp4PrivateV1.reference(),
                profile_catalog_digest: profile_catalog_digest_v2(),
                filter_digest: filter.clone(),
                unit_digest: unit.clone(),
                component_digest: component.clone(),
                test_inventory_digest: inventory_digest(&trusted).unwrap(),
                runner_run_digest: runner.clone(),
                host_prerequisites_digest: host.clone(),
                observed_results,
                tests_skipped: 0,
            },
            completion,
            filter,
            unit,
            component,
            runner,
            host,
        }
    }

    fn completions(&self) -> [TrustedNativeCompletionV2<'_>; 1] {
        [TrustedNativeCompletionV2 {
            name: NATIVE_TEST,
            target: X64,
            native_executed: true,
            completion_digest: &self.completion,
        }]
    }

    fn expected<'a>(
        &'a self,
        completions: &'a [TrustedNativeCompletionV2<'a>],
    ) -> TrustedQualificationExpectationV2<'a> {
        TrustedQualificationExpectationV2 {
            source_commit: SOURCE,
            target: X64,
            profile: &self.artifact.profile,
            filter_digest: &self.filter,
            unit_digest: &self.unit,
            component_digest: &self.component,
            runner_run_digest: &self.runner,
            host_prerequisites_digest: &self.host,
            completions,
        }
    }
}

fn reference(bytes: &[u8]) -> QualificationArtifactReferenceV2 {
    QualificationArtifactReferenceV2 {
        schema_version: QualificationArtifactSchemaTwo::default(),
        artifact: "certification/workload/linux-private-profile-qualification.json".into(),
        artifact_sha256: hash_bytes(bytes),
        qualified_target: X64.into(),
        source_commit: SOURCE.into(),
        profile: ProfileKindV2::LinuxTcp4PrivateV1.reference(),
    }
}

#[test]
fn even_structurally_valid_proposed_private_qualification_is_not_release_authority() {
    assert!(
        ARTIFACTS
            .iter()
            .all(|(_, name, _, _)| !name.contains("private"))
    );
    let fixture = Fixture::new();
    let completions = fixture.completions();
    let expected = fixture.expected(&completions);
    let bytes = serde_json::to_vec(&fixture.artifact).unwrap();
    let error = reject_proposed_private_qualification_v2(&bytes, &reference(&bytes), &expected)
        .unwrap_err();
    assert!(error.to_string().contains("not accepted"));
}

#[test]
fn private_v2_acceptance_requires_every_checked_in_native_completion() {
    let mut fixture = Fixture::new();
    let inventory: toml::Value =
        toml::from_str(include_str!("../../../ci/private-native-v2.toml")).unwrap();
    let names: Vec<&str> = inventory["tests"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    let digests: Vec<DiagnosticSha256> = names
        .iter()
        .map(|name| hash_bytes(name.as_bytes()))
        .collect();
    let completions: Vec<TrustedNativeCompletionV2<'_>> = names
        .iter()
        .zip(&digests)
        .map(|(name, digest)| TrustedNativeCompletionV2 {
            name,
            target: X64,
            native_executed: true,
            completion_digest: digest,
        })
        .collect();
    let mut observed = BoundedVec::default();
    for completion in &completions {
        observed
            .try_push(ObservedNativeTestV2 {
                name: BoundedText::new(completion.name).unwrap(),
                target: BoundedText::new(X64).unwrap(),
                outcome: NativeTestOutcomeV2::Passed,
                runner_completion_digest: completion.completion_digest.clone(),
            })
            .unwrap();
    }
    fixture.artifact.observed_results = observed;
    fixture.artifact.test_inventory_digest = inventory_digest(&completions).unwrap();
    let bytes = serde_json::to_vec(&fixture.artifact).unwrap();
    let mut reference = reference(&bytes);
    reference.artifact = PRIVATE_V2_ARTIFACTS[1].1.into();
    let expected = fixture.expected(&completions);
    assert!(
        validate_private_v2_against_trusted_native_completions(&bytes, &reference, &expected)
            .is_ok()
    );
    assert!(
        validate_private_v2_against_build(
            &bytes,
            &reference,
            &expected,
            "0.5.7-dev",
            &components(),
        )
        .is_ok()
    );
    let mut binaries = BTreeMap::new();
    for component in components() {
        binaries.insert(component.path, vec![7; 4096]);
    }
    let candidate = prepare_private_candidate(PrivateCandidateInputs {
        version: "0.5.7-dev",
        source_commit: SOURCE,
        target: X64,
        components: &components(),
        component_bytes: &binaries,
        compiled_units: &units(),
        filter_sha256: &fixture.filter,
    })
    .unwrap();
    let mut wrong_candidate = candidate;
    wrong_candidate.filter_sha256 = digest(99);
    assert!(
        prepare_private_final_manifest(&wrong_candidate, &bytes, reference.clone(), &expected)
            .is_err()
    );
    wrong_candidate.filter_sha256 = fixture.filter.clone();
    assert!(
        prepare_private_final_manifest(&wrong_candidate, b"{}", reference.clone(), &expected)
            .is_err()
    );
    let final_manifest =
        prepare_private_final_manifest(&wrong_candidate, &bytes, reference.clone(), &expected)
            .unwrap();
    let candidate_record_bytes = serde_json::to_vec(&wrong_candidate.record()).unwrap();
    let certificate_bytes = serde_json::to_vec(&SignedNativeQualificationCertificateV1 {
        payload: NativeQualificationCertificateV1 {
            schema_version: 1,
            policy_version: 1,
            key_id: "fixture-q".into(),
            release_sequence: 1,
            build_sha256: String::from(hash_bytes(&candidate_record_bytes)),
            build_context_sha256: String::from(digest(1)),
            target: X64.into(),
            native_machine: "x86_64".into(),
            source_commit: SOURCE.into(),
            release_version: "0.5.7-dev".into(),
            qualification_sha256: String::from(hash_bytes(&bytes)),
            qualification_size: bytes.len() as u64,
            raw_index_sha256: String::from(digest(2)),
            completed_provenance_sha256: String::from(digest(3)),
            repository_id: 1,
            repository: "fixture/repo".into(),
            workflow_path: ".github/workflows/release.yml".into(),
            workflow_revision: SOURCE.into(),
            run_id: 1,
            run_attempt: 1,
            producer_job_id: 1,
            artifact_id: 1,
            verifier_sha256: String::from(digest(4)),
            verifier_source_commit: SOURCE.into(),
            verifier_policy_sha256: String::from(digest(5)),
            catalogue_sha256: String::from(digest(6)),
            accepted_case_set_sha256: String::from(digest(7)),
            issued_at_unix: 1,
            expires_at_unix: 2,
            decision: "Complete".into(),
        },
        signature_hex: "00".repeat(64),
    })
    .unwrap();
    let manifest = final_manifest.manifest().clone();
    let manifest_bytes = final_manifest.manifest_bytes().to_vec();
    let manifest_digest = final_manifest.manifest_sha256().clone();
    let unit_hashes = units();
    let installed_receipt_digest = digest(18);
    let agent_digest = hash_bytes(&vec![7; 4096]);
    let inspection = LinuxInstalledInspectionV6 {
        schema_version: InspectionVersionSix,
        package: LinuxPackageInspectionV6 {
            schema_version: InspectionVersionSix,
            version: BoundedText::new("0.5.7-dev").unwrap(),
            source_commit: BoundedText::new(SOURCE).unwrap(),
            target: BoundedText::new(X64).unwrap(),
            runtime_manifest_sha256: manifest_digest.clone(),
            components: components(),
            native_protocols: memcordon_core::runtime_manifest::NativeProviderProtocols::Linux {
                provider_contract: 4,
                launch_wire: 4,
            },
            profile_catalog_sha256: profile_catalog_digest_v2(),
            private_filter_sha256: fixture.filter.clone(),
            compiled_units: unit_hashes.clone(),
            compiled_metadata_valid: true,
        },
        installed_units: unit_hashes.clone(),
        installed_agent_sha256: agent_digest.clone(),
        installed_artifacts_valid: true,
        provider_reachable: true,
        network_launcher_state: NetworkLauncherStateV6::EnabledQualified,
        baseline_qualification: None,
        private_qualification: Some(reference.clone()),
        installed_qualification_sha256: Some(installed_receipt_digest.clone()),
    };
    let trusted = TrustedLinuxInspectionV6 {
        runtime_manifest_sha256: &manifest_digest,
        filter_sha256: &fixture.filter,
        unit_hashes: &unit_hashes,
        installed_agent_sha256: &agent_digest,
        provider_reachable: true,
        network_launcher_state: NetworkLauncherStateV6::EnabledQualified,
        baseline_qualification: None,
        private_qualification: Some(&reference),
        installed_qualification_sha256: Some(&installed_receipt_digest),
    };
    let inspection_bytes = serde_json::to_vec(&inspection).unwrap();
    let verified = validate_qualified_linux_readback(QualifiedLinuxReadbackInputs {
        qualification_bytes: &bytes,
        qualification_reference: &reference,
        expected_qualification: &expected,
        version: "0.5.7-dev",
        components: &components(),
        runtime_manifest_bytes: &manifest_bytes,
        installed_inspection_bytes: &inspection_bytes,
        trusted_installed: &trusted,
    })
    .unwrap();
    assert_eq!(verified.runtime_manifest, manifest);
    let mut static_bytes = BTreeMap::new();
    for path in memcordon_ci::release_archive::NATIVE_ARCHIVE_STATIC_PATHS {
        static_bytes.insert((*path).into(), b"reviewed static member".to_vec());
    }
    let offline_inputs = OfflinePrivateQualifiedInputs {
        candidate: &wrong_candidate,
        qualification_bytes: &bytes,
        candidate_record_bytes: &candidate_record_bytes,
        certificate_bytes: &certificate_bytes,
        qualification_reference: reference.clone(),
        expected_qualification: &expected,
        component_bytes: &binaries,
        static_bytes: &static_bytes,
        archive_format: PrivateArchiveFormat::TarGz,
        installed_inspection_bytes: &inspection_bytes,
        trusted_installed: &trusted,
    };
    let offline = prepare_private_qualified_offline(offline_inputs.clone()).unwrap();
    assert_eq!(offline.final_manifest().manifest(), &manifest);
    assert_eq!(
        offline.archive_sha256(),
        &hash_bytes(offline.archive_bytes())
    );
    assert_eq!(offline.installed_readback().runtime_manifest, manifest);
    let public_binding = offline.expected_final_public_binding().unwrap();
    assert_eq!(public_binding.archive_sha256, *offline.archive_sha256());
    assert_eq!(public_binding.runtime_manifest_sha256, manifest_digest);
    assert_eq!(
        public_binding.installed_receipt_sha256,
        installed_receipt_digest
    );
    let mut changed_inspection = inspection.clone();
    changed_inspection.package.runtime_manifest_sha256 = digest(99);
    let changed_inspection_bytes = serde_json::to_vec(&changed_inspection).unwrap();
    let mut wrong_h1 = offline_inputs.clone();
    wrong_h1.installed_inspection_bytes = &changed_inspection_bytes;
    assert!(prepare_private_qualified_offline(wrong_h1).is_err());
    let mut wrong_q = offline_inputs.clone();
    wrong_q.qualification_bytes = b"{}";
    assert!(prepare_private_qualified_offline(wrong_q).is_err());
    let mut members = BTreeMap::new();
    members.insert("runtime-manifest.json".into(), manifest_bytes.clone());
    members.insert(reference.artifact.clone(), bytes.clone());
    for component in components() {
        members.insert(component.path, vec![7; 4096]);
    }
    for path in memcordon_ci::release_archive::NATIVE_ARCHIVE_STATIC_PATHS {
        members.insert((*path).into(), b"reviewed static member".to_vec());
    }
    members.insert(
        "certification/workload/x64-private-build-v1.json".into(),
        candidate_record_bytes.clone(),
    );
    members.insert(
        "certification/workload/x64-private-cq-v1.json".into(),
        certificate_bytes.clone(),
    );
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::default(),
    ));
    for (path, member_bytes) in &members {
        let mut header = tar::Header::new_gnu();
        header.set_size(member_bytes.len() as u64);
        header.set_mode(member_mode(path));
        header.set_cksum();
        builder
            .append_data(
                &mut header,
                format!("memcordon-v0.5.7-dev-{X64}/{path}"),
                member_bytes.as_slice(),
            )
            .unwrap();
    }
    let archive = builder.into_inner().unwrap().finish().unwrap();
    assert!(
        validate_qualified_archive(
            &archive,
            &QualifiedArchiveExpectation {
                format: PrivateArchiveFormat::TarGz,
                members: &members,
                final_manifest: &final_manifest,
                qualification_bytes: &bytes,
                candidate_record_bytes: &candidate_record_bytes,
                certificate_bytes: &certificate_bytes,
            },
        )
        .is_ok()
    );
    let (sealed_tar, sealed_tar_digest) = seal_qualified_archive(&QualifiedArchiveExpectation {
        format: PrivateArchiveFormat::TarGz,
        members: &members,
        final_manifest: &final_manifest,
        qualification_bytes: &bytes,
        candidate_record_bytes: &candidate_record_bytes,
        certificate_bytes: &certificate_bytes,
    })
    .unwrap();
    assert_eq!(sealed_tar_digest, hash_bytes(&sealed_tar));
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (path, member_bytes) in &members {
        let mode = member_mode(path);
        let options = zip::write::SimpleFileOptions::default()
            .system(zip::System::Unix)
            .unix_permissions(mode);
        zip.start_file(format!("memcordon-v0.5.7-dev-{X64}/{path}"), options)
            .unwrap();
        zip.write_all(member_bytes).unwrap();
    }
    let zip_archive = zip.finish().unwrap().into_inner();
    assert!(
        validate_qualified_archive(
            &zip_archive,
            &QualifiedArchiveExpectation {
                format: PrivateArchiveFormat::Zip,
                members: &members,
                final_manifest: &final_manifest,
                qualification_bytes: &bytes,
                candidate_record_bytes: &candidate_record_bytes,
                certificate_bytes: &certificate_bytes,
            },
        )
        .is_ok()
    );
    let (sealed_zip, sealed_zip_digest) = seal_qualified_archive(&QualifiedArchiveExpectation {
        format: PrivateArchiveFormat::Zip,
        members: &members,
        final_manifest: &final_manifest,
        qualification_bytes: &bytes,
        candidate_record_bytes: &candidate_record_bytes,
        certificate_bytes: &certificate_bytes,
    })
    .unwrap();
    assert_eq!(sealed_zip_digest, hash_bytes(&sealed_zip));
    members.insert("surplus.bin".into(), b"unexpected".to_vec());
    assert!(
        seal_qualified_archive(&QualifiedArchiveExpectation {
            format: PrivateArchiveFormat::TarGz,
            members: &members,
            final_manifest: &final_manifest,
            qualification_bytes: &bytes,
            candidate_record_bytes: &candidate_record_bytes,
            certificate_bytes: &certificate_bytes,
        })
        .is_err()
    );
    let mut surplus_builder = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::default(),
    ));
    for (path, member_bytes) in &members {
        let mut header = tar::Header::new_gnu();
        header.set_size(member_bytes.len() as u64);
        header.set_mode(member_mode(path));
        header.set_cksum();
        surplus_builder
            .append_data(
                &mut header,
                format!("memcordon-v0.5.7-dev-{X64}/{path}"),
                member_bytes.as_slice(),
            )
            .unwrap();
    }
    let surplus_archive = surplus_builder.into_inner().unwrap().finish().unwrap();
    assert!(
        validate_qualified_archive(
            &surplus_archive,
            &QualifiedArchiveExpectation {
                format: PrivateArchiveFormat::TarGz,
                members: &members,
                final_manifest: &final_manifest,
                qualification_bytes: &bytes,
                candidate_record_bytes: &candidate_record_bytes,
                certificate_bytes: &certificate_bytes,
            },
        )
        .is_err()
    );
    let mut changed_manifest = manifest.clone();
    changed_manifest.version = "0.5.8-dev".into();
    assert!(
        validate_qualified_linux_readback(QualifiedLinuxReadbackInputs {
            qualification_bytes: &bytes,
            qualification_reference: &reference,
            expected_qualification: &expected,
            version: "0.5.7-dev",
            components: &components(),
            runtime_manifest_bytes: &serde_json::to_vec(&changed_manifest).unwrap(),
            installed_inspection_bytes: &inspection_bytes,
            trusted_installed: &trusted,
        })
        .is_err()
    );
    let mut substituted_units = unit_hashes.clone();
    substituted_units.network_launcher_socket = digest(20);
    let mut substituted_inspection = inspection.clone();
    substituted_inspection.package.compiled_units = substituted_units.clone();
    substituted_inspection.installed_units = substituted_units.clone();
    let substituted_trusted = TrustedLinuxInspectionV6 {
        runtime_manifest_sha256: &manifest_digest,
        filter_sha256: &fixture.filter,
        unit_hashes: &substituted_units,
        installed_agent_sha256: &agent_digest,
        provider_reachable: true,
        network_launcher_state: NetworkLauncherStateV6::EnabledQualified,
        baseline_qualification: None,
        private_qualification: Some(&reference),
        installed_qualification_sha256: Some(&installed_receipt_digest),
    };
    assert!(
        validate_qualified_linux_readback(QualifiedLinuxReadbackInputs {
            qualification_bytes: &bytes,
            qualification_reference: &reference,
            expected_qualification: &expected,
            version: "0.5.7-dev",
            components: &components(),
            runtime_manifest_bytes: &manifest_bytes,
            installed_inspection_bytes: &serde_json::to_vec(&substituted_inspection).unwrap(),
            trusted_installed: &substituted_trusted,
        })
        .is_err()
    );
    let mut replaced = components();
    replaced[1].sha256 = "8".repeat(64);
    assert!(
        validate_private_v2_against_build(&bytes, &reference, &expected, "0.5.7-dev", &replaced,)
            .is_err()
    );
    let mut wrong_target = reference.clone();
    wrong_target.qualified_target = ARM64.into();
    assert!(
        validate_private_v2_against_trusted_native_completions(&bytes, &wrong_target, &expected)
            .is_err()
    );
    let missing = fixture.expected(&completions[1..]);
    assert!(
        validate_private_v2_against_trusted_native_completions(&bytes, &reference, &missing)
            .is_err()
    );
}

#[test]
fn target_source_profile_and_native_completion_substitutions_fail_structurally() {
    let fixture = Fixture::new();
    let completions = fixture.completions();
    let expected = fixture.expected(&completions);
    let bytes = serde_json::to_vec(&fixture.artifact).unwrap();

    let mut wrong_target = reference(&bytes);
    wrong_target.qualified_target = ARM64.into();
    let error =
        reject_proposed_private_qualification_v2(&bytes, &wrong_target, &expected).unwrap_err();
    assert!(error.to_string().contains("differs"));

    let mut wrong_native_target = fixture.expected(&completions);
    wrong_native_target.target = ARM64;
    let error =
        reject_proposed_private_qualification_v2(&bytes, &reference(&bytes), &wrong_native_target)
            .unwrap_err();
    assert!(error.to_string().contains("differs"));

    let mut wrong_source = reference(&bytes);
    wrong_source.source_commit = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into();
    let error =
        reject_proposed_private_qualification_v2(&bytes, &wrong_source, &expected).unwrap_err();
    assert!(error.to_string().contains("differs"));

    let mut wrong_profile = reference(&bytes);
    wrong_profile.profile = ProfileKindV2::LinuxUnixCreateV1.reference();
    let error =
        reject_proposed_private_qualification_v2(&bytes, &wrong_profile, &expected).unwrap_err();
    assert!(error.to_string().contains("differs"));

    let mut wrong_catalog = fixture.artifact.clone();
    wrong_catalog.profile_catalog_digest = digest(10);
    let wrong_catalog_bytes = serde_json::to_vec(&wrong_catalog).unwrap();
    let error = reject_proposed_private_qualification_v2(
        &wrong_catalog_bytes,
        &reference(&wrong_catalog_bytes),
        &expected,
    )
    .unwrap_err();
    assert!(error.to_string().contains("differs"));

    let unobserved = [TrustedNativeCompletionV2 {
        name: NATIVE_TEST,
        target: X64,
        native_executed: false,
        completion_digest: &fixture.completion,
    }];
    let error = reject_proposed_private_qualification_v2(
        &bytes,
        &reference(&bytes),
        &fixture.expected(&unobserved),
    )
    .unwrap_err();
    assert!(error.to_string().contains("differs"));
}

#[test]
fn baseline_v1_artifact_cannot_substitute_for_private_v2_evidence() {
    let fixture = Fixture::new();
    let completions = fixture.completions();
    let expected = fixture.expected(&completions);
    let legacy =
        QualificationArtifactV1::after_observed_tests(QualificationKind::Profile, X64, SOURCE);
    let bytes = serde_json::to_vec(&legacy).unwrap();
    let error = reject_proposed_private_qualification_v2(&bytes, &reference(&bytes), &expected)
        .unwrap_err();
    assert!(error.to_string().contains("differs"));
}
