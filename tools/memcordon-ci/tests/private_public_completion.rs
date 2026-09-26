use memcordon_ci::private_observer_session::{ObserverStageV1, ObserverSubjectV1};
use memcordon_ci::private_public_completion::{
    ProtectedPublicCollectorIntentV1, validate_completed_public_metadata,
};
use memcordon_ci::private_public_plan::{
    PublicStageSemanticsPolicyV1, ReviewedPublicCaseRecipeV1, ReviewedPublicPolicyBranchV1,
    ReviewedPublicPolicyRecipeV1, StaticPublicScenarioV1, StaticPublicSuiteIntentV1,
    prepared_public_case_recipe_v1,
};
use memcordon_core::{
    DiagnosticSha256, private_release_case_v1::REQUIRED_PRIVATE_RELEASE_SELECTORS_V1,
};
use serde_json::{Value, json};

fn digest(byte: u8) -> DiagnosticSha256 {
    DiagnosticSha256::from_bytes([byte; 32])
}
fn suite() -> StaticPublicSuiteIntentV1 {
    let mut suite = StaticPublicSuiteIntentV1 {
        schema_version: 1,
        observer_subject: ObserverSubjectV1 {
            stage: ObserverStageV1::Public,
            repository_id: 11,
            run_id: 21,
            run_attempt: 2,
            job_id: 31,
            runner_id: 41,
            target: "x86_64-unknown-linux-gnu".into(),
            source_commit: "ab".repeat(20),
            release_version: "0.5.6-rc.1".into(),
            build_sha256: digest(1),
            intent_sha256: digest(2),
            catalogue_sha256: digest(3),
            host_profile_sha256: digest(4),
        },
        archive_sha256: digest(5),
        archive_size: 1024,
        manifest_sha256: digest(6),
        qualification_sha256: digest(7),
        qualification_certificate_file_sha256: digest(8),
        qualification_certificate_payload_sha256: digest(9),
        public_cli_sha256: digest(10),
        public_uid: 1001,
        public_gid: 1001,
        historical_spoof_uid: 1003,
        historical_spoof_gid: 1003,
        historical_spoof_challenge_seed: hex::encode(digest(99).bytes()),
        policy_recipe: ReviewedPublicPolicyRecipeV1 {
            registry_sha256: digest(20),
            fixture_template_sha256: digest(21),
            branches: memcordon_core::private_release_branch_v1::PolicyOperationBranchV1::ALL
                .into_iter()
                .map(|branch| ReviewedPublicPolicyBranchV1 {
                    branch,
                    contract_template_sha256: digest(22),
                })
                .collect(),
        },
        semantics_policy: PublicStageSemanticsPolicyV1 {
            schema_version: 1,
            final_stage_semantics_version: 3,
            approved_semantics_sha256:
                memcordon_ci::private_case_semantics::semantics_revision_sha256(),
            auxiliary_conjunction_approved: true,
        },
        scenarios: REQUIRED_PRIVATE_RELEASE_SELECTORS_V1
            .iter()
            .enumerate()
            .map(|(ordinal, selector)| {
                let challenge = hex::encode(digest(u8::try_from(ordinal + 1).unwrap()).bytes());
                StaticPublicScenarioV1 {
                    selector: (*selector).into(),
                    challenge: challenge.clone(),
                    fixture_sha256: digest(13),
                    contract_template_sha256: digest(14),
                    recipe: ReviewedPublicCaseRecipeV1 {
                        filter_install_source_sha256: None,
                        facility_source_sha256: None,
                        host_preservation_source_sha256: None,
                        filter_sha256: digest(15),
                        fixture_argv: if ordinal == 0 {
                            vec![
                                "/usr/libexec/memcordon-sealed-agent".into(),
                                "public-abi-filtered-target".into(),
                                "--challenge".into(),
                                challenge,
                            ]
                        } else {
                            vec![
                                "/usr/libexec/memcordon-sealed-agent".into(),
                                "public-release-fixture".into(),
                                (*selector).into(),
                                "--challenge".into(),
                                challenge,
                            ]
                        },
                        target_uid: 1002,
                        target_gid: 1002,
                        supplementary_groups: vec![],
                        port: 23456,
                    },
                }
            })
            .collect(),
    };
    suite.observer_subject.intent_sha256 = suite.identity_sha256().unwrap();
    suite
}
fn intent() -> ProtectedPublicCollectorIntentV1 {
    ProtectedPublicCollectorIntentV1 {
        schema_version: 1,
        suite: suite(),
        repository: "example/memcordon".into(),
        workflow_path: ".github/workflows/release.yml".into(),
        workflow_revision: "cd".repeat(20),
        event: "workflow_dispatch".into(),
        producer_job_name: "Release / Linux private final / x64".into(),
        artifact_name: "release-private-final-x64".into(),
        artifact_id: 51,
        runner_name: "runner-approved".into(),
        runner_labels: vec!["Linux".into(), "X64".into()],
        custody_policy: "/etc/memcordon/observer-policy.json".into(),
    }
}
fn metadata(intent: &ProtectedPublicCollectorIntentV1) -> (Value, Value, Value) {
    let s = &intent.suite.observer_subject;
    (
        json!({"id":s.run_id,"run_attempt":s.run_attempt,"head_sha":s.source_commit,"event":intent.event,
        "path":intent.workflow_path,"repository":{"id":s.repository_id,"full_name":intent.repository},
        "status":"in_progress"}),
        json!({"total_count":1,"jobs":[{"id":s.job_id,"name":intent.producer_job_name,"run_id":s.run_id,
        "run_attempt":s.run_attempt,"head_sha":s.source_commit,"status":"completed","conclusion":"success",
        "runner_id":s.runner_id,"runner_name":intent.runner_name,"labels":intent.runner_labels}]}),
        json!({"total_count":1,"artifacts":[{"id":intent.artifact_id,"name":intent.artifact_name,"expired":false,
        "size_in_bytes":1024,"workflow_run":{"id":s.run_id,"head_sha":s.source_commit}}]}),
    )
}

#[test]
fn prepared_challenge_binds_controller_nonce_generation_and_exact_argv_slot() {
    let suite = suite();
    suite.validate().unwrap();
    let selector = REQUIRED_PRIVATE_RELEASE_SELECTORS_V1[16];
    let nonce = hex::encode([42; 32]);
    let (challenge, argv) = prepared_public_case_recipe_v1(&suite, &nonce, 1, selector).unwrap();
    assert_ne!(hex::encode(challenge), suite.scenarios[16].challenge);
    let slot = argv.iter().position(|arg| arg == "--challenge").unwrap();
    assert_eq!(argv[slot + 1], hex::encode(challenge));
    assert_eq!(
        argv[..=slot],
        suite.scenarios[16].recipe.fixture_argv[..=slot]
    );
    assert_ne!(
        challenge,
        prepared_public_case_recipe_v1(&suite, &hex::encode([43; 32]), 1, selector)
            .unwrap()
            .0
    );
    assert_ne!(
        challenge,
        prepared_public_case_recipe_v1(&suite, &nonce, 0, selector)
            .unwrap()
            .0
    );
    assert!(prepared_public_case_recipe_v1(&suite, &hex::encode([0; 32]), 1, selector).is_err());
    let mut changed = suite.clone();
    changed.scenarios[16].recipe.port += 1;
    assert!(
        changed.validate().is_err(),
        "altered static operand must not retain admission identity"
    );
}

#[test]
fn metadata_requires_exact_completed_producer_not_whole_workflow_completion() {
    let intent = intent();
    let (run, jobs, artifacts) = metadata(&intent);
    validate_completed_public_metadata(&intent, &run, &jobs, &artifacts).unwrap();
    for field in ["run_attempt", "runner_id", "run_id", "id"] {
        let mut changed = jobs.clone();
        changed["jobs"][0][field] = json!(999);
        assert!(
            validate_completed_public_metadata(&intent, &run, &changed, &artifacts).is_err(),
            "accepted mutated {field}"
        );
    }
    let mut changed = jobs.clone();
    changed["jobs"][0]["conclusion"] = json!("failure");
    assert!(validate_completed_public_metadata(&intent, &run, &changed, &artifacts).is_err());
    let mut changed = artifacts.clone();
    changed["artifacts"]
        .as_array_mut()
        .unwrap()
        .push(artifacts["artifacts"][0].clone());
    changed["total_count"] = json!(2);
    assert!(validate_completed_public_metadata(&intent, &run, &jobs, &changed).is_err());
    let mut changed = artifacts.clone();
    changed["total_count"] = json!(2);
    assert!(validate_completed_public_metadata(&intent, &run, &jobs, &changed).is_err());
    let mut changed = intent.clone();
    changed
        .suite
        .semantics_policy
        .auxiliary_conjunction_approved = false;
    changed.suite.observer_subject.intent_sha256 = changed.suite.identity_sha256().unwrap();
    assert!(
        validate_completed_public_metadata(&changed, &run, &jobs, &artifacts).is_err(),
        "metadata cannot grant auxiliary policy approval"
    );
}
