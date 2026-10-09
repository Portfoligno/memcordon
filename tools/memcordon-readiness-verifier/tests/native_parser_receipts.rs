//! Independent decoder mutation vectors, not native harness execution proof.
use memcordon_readiness_verifier::*;
use sha2::{Digest, Sha256};
const MANIFEST: &str = include_str!("../../../ci/consumer-readiness-v1.toml");
fn base() -> EvidenceIndex {
    let cases = validate_manifest(MANIFEST.as_bytes()).unwrap();
    EvidenceIndex {
        format: "memcordon.consumer-readiness.evidence".into(),
        revision: 1,
        profile: PROFILE.into(),
        run_id: "vector-run".into(),
        source_commit: "1".repeat(40),
        source_tree_sha256: "2".repeat(64),
        version: "0.5.8-dev".into(),
        manifest_sha256: hex::encode(Sha256::digest(MANIFEST.as_bytes())),
        repository: None,
        products: Vec::new(),
        component_builds: Vec::new(),
        producer_origins: Vec::new(),
        job_outcomes: Vec::new(),
        assessment_failures: Vec::new(),
        workflow_cells: Vec::new(),
        fixture_cases: cases.iter().cloned().collect(),
        artifacts: Vec::new(),
        records: cases
            .into_iter()
            .map(|key| CaseRecord {
                key,
                run_id: "vector-run".into(),
                state: CaseState::NotRun,
                reason: None,
                evidence: None,
            })
            .collect(),
    }
}
fn assess(
    mutator: impl FnOnce(&mut NativeParserMutationReceipt, &mut EvidenceIndex, &mut Vec<EvidenceIndex>),
) -> VerificationResult<()> {
    let directory = tempfile::tempdir().unwrap();
    let mut baseline = base();
    let mut changed = Vec::new();
    let mut observations = Vec::new();
    for scenario in ["omitted-case", "duplicate-case", "wrong-product"] {
        let mut input = baseline.clone();
        match scenario {
            "omitted-case" => {
                input.records.pop();
            }
            "duplicate-case" => input.records.push(input.records[0].clone()),
            _ => {
                input
                    .records
                    .iter_mut()
                    .find(|record| record.key.evidence_class == EvidenceClass::InstalledProduct)
                    .unwrap()
                    .key
                    .channel = Some("unselected-product".into())
            }
        }
        changed.push(input);
        observations.push(ParserMutationObservation {
            scenario: scenario.into(),
            base_input: "base.json".into(),
            mutated_input: format!("{scenario}.json"),
            operation: "independent-evidence-index-frozen-inventory".into(),
            actual_refusal: "missing/duplicate/unexpected/reclassified evidence rows".into(),
            baseline_profile_ready: false,
        });
    }
    let mut receipt = NativeParserMutationReceipt {
        format: "memcordon.native-parser-mutation-receipt".into(),
        revision: 1,
        run_id: "native-run".into(),
        recipe_id: "native-recipe".into(),
        test_name: "native_index_mutations_emit_actual_parser_receipts".into(),
        native_target: "x86_64-unknown-linux-gnu".into(),
        executable_sha256: "3".repeat(64),
        challenge_sha256: "4".repeat(64),
        manifest: "manifest.toml".into(),
        observations,
    };
    mutator(&mut receipt, &mut baseline, &mut changed);
    let mut files = vec![
        ("manifest.toml".into(), MANIFEST.as_bytes().to_vec()),
        ("base.json".into(), serde_json::to_vec(&baseline).unwrap()),
    ];
    for (scenario, input) in ["omitted-case", "duplicate-case", "wrong-product"]
        .into_iter()
        .zip(changed)
    {
        files.push((
            format!("{scenario}.json"),
            serde_json::to_vec(&input).unwrap(),
        ));
    }
    let mut artifacts = Vec::new();
    for (path, bytes) in files {
        std::fs::write(directory.path().join(&path), &bytes).unwrap();
        artifacts.push(Artifact {
            path,
            length: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(bytes)),
        });
    }
    let key = CaseKey {
        target: "x86_64-unknown-linux-gnu".into(),
        channel: None,
        evidence_class: EvidenceClass::NativeComponentRegression,
        family: "C-PARSER".into(),
        scenario: "omitted-case".into(),
    };
    validate_native_parser_mutations(&receipt, &key, &artifacts, directory.path())
}
#[test]
fn raw_parser_mutations_cannot_be_relabelled_or_narrowed_together() {
    assert!(assess(|_, _, _| {}).is_ok());
    assert!(
        assess(|receipt, _, _| {
            receipt.observations.pop();
        })
        .is_err()
    );
    assert!(
        assess(|receipt, _, _| receipt.observations[0].actual_refusal =
            "some unrelated failure".into())
        .is_err()
    );
    assert!(assess(|_, _, changed| changed[0].run_id = "substituted-run".into()).is_err());
    assert!(assess(|receipt, _, _| receipt.observations[0].baseline_profile_ready = true).is_err());
    assert!(assess(|_, baseline, _| baseline.records[0].state = CaseState::Passed).is_err());
    assert!(
        assess(|_, baseline, changed| {
            baseline
                .records
                .retain(|record| record.key.family != "L-MIX-01");
            baseline
                .fixture_cases
                .retain(|key| key.family != "L-MIX-01");
            for input in changed {
                input
                    .records
                    .retain(|record| record.key.family != "L-MIX-01");
                input.fixture_cases.retain(|key| key.family != "L-MIX-01");
            }
        })
        .is_err()
    );
}
