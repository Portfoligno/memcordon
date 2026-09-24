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
const TARGET: &str = "x86_64-unknown-linux-gnu";
const NAMES: [&str; 2] = [
    "native_private_tcp::namespace_isolation",
    "native_private_tcp::tcp_roundtrip",
];

struct Fixture {
    artifact: QualificationArtifactV2,
    completions: [DiagnosticSha256; 2],
    expected_bindings: [DiagnosticSha256; 5],
}

impl Fixture {
    fn new() -> Self {
        let completions = [digest(1), digest(2)];
        let trusted = trusted_completions(&completions);
        let mut observed_results = BoundedVec::default();
        for (name, completion_digest) in NAMES.into_iter().zip(&completions) {
            observed_results
                .try_push(ObservedNativeTestV2 {
                    name: BoundedText::new(name).unwrap(),
                    target: BoundedText::new(TARGET).unwrap(),
                    outcome: NativeTestOutcomeV2::Passed,
                    runner_completion_digest: completion_digest.clone(),
                })
                .unwrap();
        }
        Self {
            artifact: QualificationArtifactV2 {
                schema_version: QualificationArtifactSchemaTwo::default(),
                source_commit: BoundedText::new(SOURCE).unwrap(),
                target: BoundedText::new(TARGET).unwrap(),
                profile: ProfileKindV2::LinuxTcp4PrivateV1.reference(),
                profile_catalog_digest: profile_catalog_digest_v2(),
                filter_digest: digest(3),
                unit_digest: digest(4),
                component_digest: digest(5),
                test_inventory_digest: inventory_digest(&trusted).unwrap(),
                runner_run_digest: digest(6),
                host_prerequisites_digest: digest(7),
                observed_results,
                tests_skipped: 0,
            },
            completions,
            expected_bindings: [digest(3), digest(4), digest(5), digest(6), digest(7)],
        }
    }

    fn expectation<'a>(
        &'a self,
        completions: &'a [TrustedNativeCompletionV2<'a>],
    ) -> TrustedQualificationExpectationV2<'a> {
        TrustedQualificationExpectationV2 {
            source_commit: SOURCE,
            target: TARGET,
            profile: &self.artifact.profile,
            filter_digest: &self.expected_bindings[0],
            unit_digest: &self.expected_bindings[1],
            component_digest: &self.expected_bindings[2],
            runner_run_digest: &self.expected_bindings[3],
            host_prerequisites_digest: &self.expected_bindings[4],
            completions,
        }
    }
}

fn digest(byte: u8) -> DiagnosticSha256 {
    DiagnosticSha256::from_bytes([byte; 32])
}

fn trusted_completions(digests: &[DiagnosticSha256; 2]) -> [TrustedNativeCompletionV2<'_>; 2] {
    [
        TrustedNativeCompletionV2 {
            name: NAMES[0],
            target: TARGET,
            native_executed: true,
            completion_digest: &digests[0],
        },
        TrustedNativeCompletionV2 {
            name: NAMES[1],
            target: TARGET,
            native_executed: true,
            completion_digest: &digests[1],
        },
    ]
}

fn reference(bytes: &[u8]) -> QualificationArtifactReferenceV2 {
    QualificationArtifactReferenceV2 {
        schema_version: QualificationArtifactSchemaTwo::default(),
        artifact: "certification/workload/linux-private-profile-qualification.json".into(),
        artifact_sha256: hash_bytes(bytes),
        qualified_target: TARGET.into(),
        source_commit: SOURCE.into(),
        profile: ProfileKindV2::LinuxTcp4PrivateV1.reference(),
    }
}

#[test]
fn exact_observed_native_completions_validate_with_byte_binding() {
    let fixture = Fixture::new();
    let trusted = trusted_completions(&fixture.completions);
    let expectation = fixture.expectation(&trusted);
    let bytes = serde_json::to_vec(&fixture.artifact).unwrap();
    assert_eq!(
        QualificationArtifactV2::parse_and_validate(&bytes, &reference(&bytes), &expectation)
            .unwrap(),
        fixture.artifact
    );

    let mut wrong_reference = reference(&bytes);
    wrong_reference.artifact_sha256 = digest(8);
    assert!(
        QualificationArtifactV2::parse_and_validate(&bytes, &wrong_reference, &expectation)
            .is_err()
    );

    let mut wrong_reference = reference(&bytes);
    wrong_reference.qualified_target = "aarch64-unknown-linux-gnu".into();
    assert!(
        QualificationArtifactV2::parse_and_validate(&bytes, &wrong_reference, &expectation)
            .is_err()
    );
}

#[test]
fn unsupported_or_unobserved_results_never_qualify() {
    let mut fixture = Fixture::new();
    let trusted = trusted_completions(&fixture.completions);
    fixture.artifact.tests_skipped = 1;
    assert!(
        fixture
            .artifact
            .validate(&fixture.expectation(&trusted))
            .is_err()
    );
    fixture.artifact.tests_skipped = 0;
    let mut observed = fixture.artifact.observed_results.as_slice().to_vec();
    observed[0].outcome = NativeTestOutcomeV2::Skipped;
    fixture.artifact.observed_results = bounded(observed);
    assert!(
        fixture
            .artifact
            .validate(&fixture.expectation(&trusted))
            .is_err()
    );
    let mut observed = fixture.artifact.observed_results.as_slice().to_vec();
    observed[0].outcome = NativeTestOutcomeV2::Passed;
    observed[0].runner_completion_digest = digest(9);
    fixture.artifact.observed_results = bounded(observed);
    assert!(
        fixture
            .artifact
            .validate(&fixture.expectation(&trusted))
            .is_err()
    );
    let mut observed = fixture.artifact.observed_results.as_slice().to_vec();
    observed.pop();
    fixture.artifact.observed_results = bounded(observed);
    assert!(
        fixture
            .artifact
            .validate(&fixture.expectation(&trusted))
            .is_err()
    );
}

#[test]
fn target_source_and_inputs_are_exact() {
    let mut fixture = Fixture::new();
    let trusted = trusted_completions(&fixture.completions);
    fixture.artifact.target = BoundedText::new("aarch64-unknown-linux-gnu").unwrap();
    assert!(
        fixture
            .artifact
            .validate(&fixture.expectation(&trusted))
            .is_err()
    );
    fixture.artifact.target = BoundedText::new(TARGET).unwrap();
    fixture.artifact.source_commit =
        BoundedText::new("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
    assert!(
        fixture
            .artifact
            .validate(&fixture.expectation(&trusted))
            .is_err()
    );
    fixture.artifact.source_commit = BoundedText::new(SOURCE).unwrap();
    fixture.artifact.filter_digest = digest(10);
    assert!(
        fixture
            .artifact
            .validate(&fixture.expectation(&trusted))
            .is_err()
    );
    fixture.artifact.filter_digest = digest(3);
    fixture.artifact.profile_catalog_digest = digest(11);
    assert!(
        fixture
            .artifact
            .validate(&fixture.expectation(&trusted))
            .is_err()
    );
    fixture.artifact.profile_catalog_digest = profile_catalog_digest_v2();
    fixture.artifact.host_prerequisites_digest = digest(12);
    assert!(
        fixture
            .artifact
            .validate(&fixture.expectation(&trusted))
            .is_err()
    );
}

#[test]
fn trusted_records_must_confirm_native_execution_on_exact_target() {
    let fixture = Fixture::new();
    let mut trusted = trusted_completions(&fixture.completions);
    trusted[0].native_executed = false;
    assert!(
        fixture
            .artifact
            .validate(&fixture.expectation(&trusted))
            .is_err()
    );
    trusted[0].native_executed = true;
    trusted[0].target = "aarch64-unknown-linux-gnu";
    assert!(
        fixture
            .artifact
            .validate(&fixture.expectation(&trusted))
            .is_err()
    );
}

#[test]
fn inventory_is_sorted_unique_and_closed() {
    let digests = [digest(1), digest(2)];
    let sorted = trusted_completions(&digests);
    assert!(inventory_digest(&sorted).is_ok());
    let reversed = [
        TrustedNativeCompletionV2 {
            name: NAMES[1],
            target: TARGET,
            native_executed: true,
            completion_digest: &digests[1],
        },
        TrustedNativeCompletionV2 {
            name: NAMES[0],
            target: TARGET,
            native_executed: true,
            completion_digest: &digests[0],
        },
    ];
    assert!(inventory_digest(&reversed).is_err());
    let duplicate = [
        TrustedNativeCompletionV2 {
            name: NAMES[0],
            target: TARGET,
            native_executed: true,
            completion_digest: &digests[0],
        },
        TrustedNativeCompletionV2 {
            name: NAMES[0],
            target: TARGET,
            native_executed: true,
            completion_digest: &digests[1],
        },
    ];
    assert!(inventory_digest(&duplicate).is_err());
    assert!(inventory_digest(&[]).is_err());
}

#[test]
fn parser_rejects_unknown_and_duplicate_fields() {
    let fixture = Fixture::new();
    let trusted = trusted_completions(&fixture.completions);
    let expectation = fixture.expectation(&trusted);
    let mut value = serde_json::to_value(&fixture.artifact).unwrap();
    value["unknown"] = serde_json::json!(true);
    let bytes = serde_json::to_vec(&value).unwrap();
    assert!(
        QualificationArtifactV2::parse_and_validate(&bytes, &reference(&bytes), &expectation)
            .is_err()
    );
    let duplicate = br#"{"schema_version":2,"schema_version":2}"#;
    assert!(
        QualificationArtifactV2::parse_and_validate(duplicate, &reference(duplicate), &expectation)
            .is_err()
    );
}

fn bounded(observed: Vec<ObservedNativeTestV2>) -> BoundedVec<ObservedNativeTestV2, 256> {
    let mut result = BoundedVec::default();
    for record in observed {
        result.try_push(record).unwrap();
    }
    result
}
