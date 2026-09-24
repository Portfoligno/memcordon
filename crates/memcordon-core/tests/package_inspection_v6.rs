use memcordon_core::package_inspection_v6::{
    InspectionVersionSix, LinuxInstalledInspectionV6, LinuxPackageInspectionV6, LinuxUnitHashesV6,
    NetworkLauncherStateV6, TrustedLinuxInspectionV6,
};
use memcordon_core::runtime_manifest::{
    NativeProviderProtocols, RuntimeComponentRecord, RuntimeComponentRole,
};
use memcordon_core::runtime_manifest_v3::{
    QualificationArtifactReferenceV2, QualificationArtifactSchemaTwo, RuntimeManifestV3,
    RuntimeManifestVersionThree, RuntimeProfileAvailabilityV3, RuntimeProfileRecordV3,
    SealedRuntimeV3,
};
use memcordon_core::workload_codec::hash_bytes;
use memcordon_core::workload_discovery_v2::profile_catalog_digest_v2;
use memcordon_core::workload_registry_v2::ProfileKindV2;
use memcordon_core::{BoundedText, BoundedVec, DiagnosticSha256};

const SOURCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TARGET: &str = "x86_64-unknown-linux-gnu";

struct Fixture {
    manifest: RuntimeManifestV3,
    manifest_bytes: Vec<u8>,
    inspection: LinuxInstalledInspectionV6,
    manifest_digest: DiagnosticSha256,
    unit_hashes: LinuxUnitHashesV6,
    filter_digest: DiagnosticSha256,
    agent_digest: DiagnosticSha256,
}

impl Fixture {
    fn new() -> Self {
        let agent_digest = digest(7);
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
        let components = vec![
            RuntimeComponentRecord {
                id: "memcordon".into(),
                path: "bin/memcordon".into(),
                role: RuntimeComponentRole::PublicCli,
                size: 4096,
                mode: 0o755,
                sha256: String::from(digest(6)),
            },
            RuntimeComponentRecord {
                id: "sealed-agent".into(),
                path: "bin/memcordon-sealed-agent".into(),
                role: RuntimeComponentRole::SealedAgent,
                size: 4096,
                mode: 0o755,
                sha256: String::from(agent_digest.clone()),
            },
        ];
        let protocols = NativeProviderProtocols::Linux {
            provider_contract: 4,
            launch_wire: 4,
        };
        let manifest = RuntimeManifestV3 {
            schema_version: RuntimeManifestVersionThree::default(),
            project: "memcordon".into(),
            version: "0.5.7-dev".into(),
            source_commit: SOURCE.into(),
            target: TARGET.into(),
            components: components.clone(),
            sealed: SealedRuntimeV3::WorkloadV2 {
                agent_component: "sealed-agent".into(),
                native_protocols: protocols.clone(),
                broker_wire: 4,
                execution_report_schema: 11,
                plan_report_schema: 10,
                doctor_report_schema: 7,
                installed_qualification_schema: 4,
                supported_contract_versions: contracts,
                profile_catalog_sha256: profile_catalog_digest_v2(),
                profiles,
            },
        };
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let unit_hashes = LinuxUnitHashesV6 {
            control_service: digest(1),
            control_socket: digest(2),
            launcher_service: digest(3),
            launcher_socket: digest(4),
            tmpfiles: digest(5),
            network_launcher_service: digest(8),
            network_launcher_socket: digest(9),
        };
        let filter_digest = digest(10);
        let manifest_digest = hash_bytes(&manifest_bytes);
        let inspection = LinuxInstalledInspectionV6 {
            schema_version: InspectionVersionSix,
            package: LinuxPackageInspectionV6 {
                schema_version: InspectionVersionSix,
                version: BoundedText::new("0.5.7-dev").unwrap(),
                source_commit: BoundedText::new(SOURCE).unwrap(),
                target: BoundedText::new(TARGET).unwrap(),
                runtime_manifest_sha256: manifest_digest.clone(),
                components,
                native_protocols: protocols,
                profile_catalog_sha256: profile_catalog_digest_v2(),
                private_filter_sha256: filter_digest.clone(),
                compiled_units: unit_hashes.clone(),
                compiled_metadata_valid: true,
            },
            installed_units: unit_hashes.clone(),
            installed_agent_sha256: agent_digest.clone(),
            installed_artifacts_valid: true,
            provider_reachable: true,
            network_launcher_state: NetworkLauncherStateV6::InstalledDisabled,
            baseline_qualification: None,
            private_qualification: None,
            installed_qualification_sha256: None,
        };
        Self {
            manifest,
            manifest_bytes,
            inspection,
            manifest_digest,
            unit_hashes,
            filter_digest,
            agent_digest,
        }
    }

    fn trusted(&self) -> TrustedLinuxInspectionV6<'_> {
        TrustedLinuxInspectionV6 {
            runtime_manifest_sha256: &self.manifest_digest,
            filter_sha256: &self.filter_digest,
            unit_hashes: &self.unit_hashes,
            installed_agent_sha256: &self.agent_digest,
            provider_reachable: true,
            network_launcher_state: NetworkLauncherStateV6::InstalledDisabled,
            baseline_qualification: None,
            private_qualification: None,
            installed_qualification_sha256: None,
        }
    }

    fn validate(&self) -> Result<LinuxInstalledInspectionV6, String> {
        LinuxInstalledInspectionV6::parse_and_validate(
            &serde_json::to_vec(&self.inspection).unwrap(),
            &self.manifest_bytes,
            &self.trusted(),
        )
    }
}

fn digest(byte: u8) -> DiagnosticSha256 {
    DiagnosticSha256::from_bytes([byte; 32])
}

#[test]
fn disabled_v6_inspection_binds_pinned_manifest_and_all_units() {
    let fixture = Fixture::new();
    let bytes = serde_json::to_vec(&fixture.inspection).unwrap();
    assert_eq!(
        LinuxInstalledInspectionV6::parse_and_validate(
            &bytes,
            &fixture.manifest_bytes,
            &fixture.trusted()
        )
        .unwrap(),
        fixture.inspection
    );
    let mut other_manifest = fixture.manifest_bytes.clone();
    other_manifest.push(b' ');
    assert!(
        LinuxInstalledInspectionV6::parse_and_validate(&bytes, &other_manifest, &fixture.trusted())
            .is_err()
    );
}

#[test]
fn unit_component_filter_or_metadata_substitution_rejects() {
    let mut fixture = Fixture::new();
    fixture.inspection.installed_units.network_launcher_socket = digest(11);
    assert!(fixture.validate().is_err());
    fixture.inspection.installed_units = fixture.unit_hashes.clone();
    fixture.inspection.package.runtime_manifest_sha256 = digest(15);
    assert!(fixture.validate().is_err());
    fixture.inspection.package.runtime_manifest_sha256 = fixture.manifest_digest.clone();
    fixture.inspection.package.components[1].sha256 = String::from(digest(12));
    assert!(fixture.validate().is_err());
    fixture.inspection.package.components = fixture.manifest.components.clone();
    fixture.inspection.package.private_filter_sha256 = digest(13);
    assert!(fixture.validate().is_err());
    fixture.inspection.package.private_filter_sha256 = fixture.filter_digest.clone();
    fixture.inspection.installed_artifacts_valid = false;
    assert!(fixture.validate().is_err());
}

#[test]
fn private_qualified_claims_reject_until_native_qualification_is_integrated() {
    let mut fixture = Fixture::new();
    fixture.inspection.network_launcher_state = NetworkLauncherStateV6::EnabledQualified;
    assert!(fixture.validate().is_err());
    fixture.inspection.network_launcher_state = NetworkLauncherStateV6::InstalledDisabled;
    fixture.inspection.private_qualification = Some(QualificationArtifactReferenceV2 {
        schema_version: QualificationArtifactSchemaTwo::default(),
        artifact: "certification/workload/linux-private-qualification.json".into(),
        artifact_sha256: digest(14),
        qualified_target: TARGET.into(),
        source_commit: SOURCE.into(),
        profile: ProfileKindV2::LinuxTcp4PrivateV1.reference(),
    });
    assert!(fixture.validate().is_err());
    fixture.inspection.private_qualification = None;
    fixture.inspection.installed_qualification_sha256 = Some(digest(16));
    assert!(fixture.validate().is_err());
}

#[test]
fn cross_target_and_unobserved_launcher_state_reject() {
    let mut fixture = Fixture::new();
    fixture.inspection.package.target = BoundedText::new("aarch64-unknown-linux-gnu").unwrap();
    assert!(fixture.validate().is_err());
    fixture.inspection.package.target = BoundedText::new(TARGET).unwrap();
    fixture.inspection.network_launcher_state = NetworkLauncherStateV6::EnabledUnqualified;
    assert!(fixture.validate().is_err());
}

#[test]
fn unavailable_state_requires_unreachable_provider() {
    let mut fixture = Fixture::new();
    fixture.inspection.network_launcher_state = NetworkLauncherStateV6::Unavailable;
    {
        let mut trusted = fixture.trusted();
        trusted.network_launcher_state = NetworkLauncherStateV6::Unavailable;
        assert!(
            LinuxInstalledInspectionV6::parse_and_validate(
                &serde_json::to_vec(&fixture.inspection).unwrap(),
                &fixture.manifest_bytes,
                &trusted,
            )
            .is_err()
        );
    }
    fixture.inspection.provider_reachable = false;
    let mut trusted = fixture.trusted();
    trusted.network_launcher_state = NetworkLauncherStateV6::Unavailable;
    trusted.provider_reachable = false;
    assert!(
        LinuxInstalledInspectionV6::parse_and_validate(
            &serde_json::to_vec(&fixture.inspection).unwrap(),
            &fixture.manifest_bytes,
            &trusted,
        )
        .is_ok()
    );
}

#[test]
fn parser_is_closed_and_bounded() {
    let fixture = Fixture::new();
    let mut value = serde_json::to_value(&fixture.inspection).unwrap();
    value["unknown"] = serde_json::json!(true);
    let bytes = serde_json::to_vec(&value).unwrap();
    assert!(
        LinuxInstalledInspectionV6::parse_and_validate(
            &bytes,
            &fixture.manifest_bytes,
            &fixture.trusted()
        )
        .is_err()
    );
    let mut value = serde_json::to_value(&fixture.inspection).unwrap();
    value["schema_version"] = serde_json::json!(5);
    let bytes = serde_json::to_vec(&value).unwrap();
    assert!(
        LinuxInstalledInspectionV6::parse_and_validate(
            &bytes,
            &fixture.manifest_bytes,
            &fixture.trusted()
        )
        .is_err()
    );
    let duplicate = br#"{"schema_version":6,"schema_version":6}"#;
    assert!(
        LinuxInstalledInspectionV6::parse_and_validate(
            duplicate,
            &fixture.manifest_bytes,
            &fixture.trusted()
        )
        .is_err()
    );
    let oversized = vec![b' '; 128 * 1024 + 1];
    assert!(
        LinuxInstalledInspectionV6::parse_and_validate(
            &oversized,
            &fixture.manifest_bytes,
            &fixture.trusted()
        )
        .is_err()
    );
}
