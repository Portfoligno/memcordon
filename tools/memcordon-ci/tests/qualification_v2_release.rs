use memcordon_ci::workload_qualification::{
    ARTIFACTS, QualificationArtifactV1, QualificationKind, reject_proposed_private_qualification_v2,
};
use memcordon_core::runtime_manifest_v3::{
    QualificationArtifactReferenceV2, QualificationArtifactSchemaTwo,
};
use memcordon_core::workload_codec::hash_bytes;
use memcordon_core::workload_discovery_v2::profile_catalog_digest_v2;
use memcordon_core::workload_qualification_v2::{
    NativeTestOutcomeV2, ObservedNativeTestV2, QualificationArtifactV2, TrustedNativeCompletionV2,
    TrustedQualificationExpectationV2, inventory_digest,
};
use memcordon_core::workload_registry_v2::ProfileKindV2;
use memcordon_core::{BoundedText, BoundedVec, DiagnosticSha256};

const SOURCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const X64: &str = "x86_64-unknown-linux-gnu";
const ARM64: &str = "aarch64-unknown-linux-gnu";
const NATIVE_TEST: &str = "native_private_tcp::namespace_isolation";

fn digest(byte: u8) -> DiagnosticSha256 {
    DiagnosticSha256::from_bytes([byte; 32])
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
        let unit = digest(3);
        let component = digest(4);
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
