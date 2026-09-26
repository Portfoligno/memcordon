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

fn completion_p() -> Vec<u8> {
    let mut index = json!({
        "schema_version":3,"target":"x86_64-unknown-linux-gnu","native_machine":"x86_64",
        "source_commit":"a".repeat(40),"release_version":"0.5.7-dev","archive_size":1024,
        "boot_identity":"fixture-boot",
        "cases": REQUIRED_PRIVATE_RELEASE_SELECTORS_V1.iter().map(|selector| {
            let format = match *selector {
                "private_tcp::abi_alternate_entry_denied" => "abi-composite-v1",
                "private_tcp::retirement_failure_blocks_reuse" => "reuse-composite-v1",
                "private_tcp::wrong_grant_profile_and_port_rejected" => "policy-composite-v1",
                _ => "single-case-v3",
            };
            json!({"selector":selector,"evidence_format":format,"case_sha256":hex::encode([1;32]),
                "result_key":hex::encode([2;32]),"generation_ref":0,"raw_case_commitment_sha256":hex::encode([3;32])})
        }).collect::<Vec<_>>()
    });
    index["build_sha256"] = json!(hex::encode([4; 32]));
    index["archive_sha256"] = json!(hex::encode([7; 32]));
    index["manifest_sha256"] = json!(hex::encode([10; 32]));
    index["qualification_sha256"] = json!(hex::encode([5; 32]));
    index["qualification_certificate_file_sha256"] = json!(hex::encode([1; 32]));
    index["qualification_certificate_payload_sha256"] = json!(hex::encode([6; 32]));
    index["host_receipt_sha256"] = json!(hex::encode([11; 32]));
    index["installation_epoch"] = json!(hex::encode([1; 32]));
    index["generation_timeline_sha256"] = json!(hex::encode([1; 32]));
    index["origin_commitment_sha256"] = json!(hex::encode([1; 32]));
    index["custody_receipt_sha256"] = json!(hex::encode([1; 32]));
    index["payload_index_sha256"] = json!(hex::encode([1; 32]));
    index["raw_index_sha256"] = json!(hex::encode([12; 32]));
    index["completed_provenance_sha256"] = json!(hex::encode([13; 32]));
    index["catalogue_sha256"] = json!(hex::encode([3; 32]));
    index["semantics_sha256"] = json!(hex::encode([1; 32]));
    index["historical_transition_sha256"] = json!(hex::encode([1; 32]));
    let index: memcordon_ci::private_public_completion::PublicEvidenceIndexV3 =
        serde_json::from_value(index).unwrap();
    memcordon_ci::private_public_raw::canonical_json(&index).unwrap()
}

#[test]
fn completion_adapter_requires_independent_subject_policy_and_actual_p_bytes() {
    use ed25519_dalek::{Signer, SigningKey};
    use memcordon_ci::private_public_completion::validate_private_completion_bytes;
    use memcordon_core::public_release_trust::{
        PublicQualificationCertificateV1, PublicQualificationCertificateV2,
        SignedPublicQualificationCertificateV1, SignedPublicQualificationCertificateV2,
    };
    use memcordon_core::release_trust::{
        DelegatedReleaseKeyV1, ReleaseSigningRoleV1, ReleaseTrustAnchorV1, ReleaseTrustPolicyV1,
        SignedReleaseTrustPolicyV1, TrustHighWaterV1,
    };
    use memcordon_core::workload_codec::hash_bytes;
    let hex = |bytes: &[u8]| hex::encode(bytes);
    let digest = |byte: u8| hex::encode([byte; 32]);
    let root = SigningKey::from_bytes(&[3; 32]);
    let delegated = SigningKey::from_bytes(&[9; 32]);
    let p_bytes = completion_p();
    let p = p_bytes.as_slice();
    let policy = ReleaseTrustPolicyV1 {
        schema_version: 1,
        policy_version: 4,
        root_key_id: "offline-root-1".into(),
        repository_id: 101,
        repository: "Portfoligno/memcordon".into(),
        workflow_path: ".github/workflows/release.yml".into(),
        workflow_revision: digest(1),
        verifier_sha256: digest(8),
        verifier_policy_sha256: digest(2),
        catalogue_sha256: digest(3),
        minimum_release_sequence: 10,
        not_before_unix: 100,
        expires_at_unix: 1000,
        delegated_keys: vec![DelegatedReleaseKeyV1 {
            key_id: "ci-p-1".into(),
            public_key_hex: hex(delegated.verifying_key().as_bytes()),
            roles: vec![ReleaseSigningRoleV1::PublicP],
            not_before_unix: 100,
            expires_at_unix: 1000,
        }],
        revoked_key_ids: vec![],
        revoked_certificate_sha256: vec![],
        revoked_qualification_sha256: vec![],
        revoked_build_sha256: vec![],
    };
    let signed_policy = SignedReleaseTrustPolicyV1 {
        signature_hex: hex(&root.sign(&policy.canonical_bytes().unwrap()).to_bytes()),
        payload: policy,
    };
    let high_water = TrustHighWaterV1 {
        policy_version: 4,
        release_sequence: 9,
        last_accepted_wall_unix: 200,
    };
    let _verified_policy = signed_policy
        .verify(
            &ReleaseTrustAnchorV1 {
                root_key_id: "offline-root-1".into(),
                public_key_hex: hex(root.verifying_key().as_bytes()),
            },
            &high_water,
            300,
        )
        .unwrap();
    let payload = PublicQualificationCertificateV1 {
        schema_version: 1,
        policy_version: 4,
        key_id: "ci-p-1".into(),
        release_sequence: 10,
        build_sha256: digest(4),
        qualification_sha256: digest(5),
        qualification_certificate_sha256: digest(6),
        archive_sha256: digest(7),
        manifest_sha256: digest(10),
        host_receipt_sha256: digest(11),
        public_evidence_sha256: String::from(hash_bytes(p)),
        public_evidence_size: p.len() as u64,
        raw_index_sha256: digest(12),
        completed_provenance_sha256: digest(13),
        target: "x86_64-unknown-linux-gnu".into(),
        native_machine: "x86_64".into(),
        source_commit: "a".repeat(40),
        release_version: "0.5.7-dev".into(),
        repository_id: 101,
        repository: "Portfoligno/memcordon".into(),
        workflow_path: ".github/workflows/release.yml".into(),
        workflow_revision: digest(1),
        run_id: 11,
        run_attempt: 1,
        producer_job_id: 12,
        artifact_id: 13,
        verifier_sha256: digest(8),
        verifier_source_commit: "a".repeat(40),
        verifier_policy_sha256: digest(2),
        catalogue_sha256: digest(3),
        accepted_case_set_sha256: digest(14),
        issued_at_unix: 200,
        expires_at_unix: 900,
        decision: "Complete".into(),
    };
    let certificate = SignedPublicQualificationCertificateV1 {
        signature_hex: hex(&delegated
            .sign(&payload.canonical_bytes().unwrap())
            .to_bytes()),
        payload,
    };
    let expected = PublicQualificationCertificateV2 {
        schema_version: 2,
        subject: certificate.payload,
        payload_index_sha256: digest(1),
        origin_commitment_sha256: digest(1),
        custody_receipt_sha256: digest(1),
        generation_timeline_sha256: digest(1),
        qualification_certificate_file_sha256: digest(1),
        semantics_sha256: digest(1),
    };
    let cp = SignedPublicQualificationCertificateV2 {
        signature_hex: hex(&delegated
            .sign(&expected.canonical_bytes().unwrap())
            .to_bytes()),
        payload: expected.clone(),
    };
    let protected = json!({
        "schema_version":1,"root_key_id":"offline-root-1",
        "root_public_key_hex":hex(root.verifying_key().as_bytes()),"signed_policy":signed_policy,
        "high_water_policy_version":4,"high_water_release_sequence":9,"high_water_wall_unix":200,
        "expected":expected
    });
    let cp_bytes = serde_json::to_vec(&cp).unwrap();
    let verify = |intent: &Value, public: &[u8], cert: &[u8], now| {
        validate_private_completion_bytes(&serde_json::to_vec(intent).unwrap(), public, cert, now)
    };
    verify(&protected, p, &cp_bytes, 300).unwrap();
    for field in ["host_receipt_sha256", "target", "archive_sha256"] {
        let mut changed = protected.clone();
        changed["expected"]["subject"][field] = if field == "target" {
            json!("aarch64-unknown-linux-gnu")
        } else {
            json!(digest(99))
        };
        assert!(
            verify(&changed, p, &cp_bytes, 300).is_err(),
            "accepted stale or different {field}"
        );
    }
    let mut wrong_root = protected.clone();
    wrong_root["root_public_key_hex"] = json!(hex(SigningKey::from_bytes(&[7; 32])
        .verifying_key()
        .as_bytes()));
    assert!(verify(&wrong_root, p, &cp_bytes, 300).is_err());
    let mut wrong_role = protected.clone();
    let mut policy = signed_policy.clone();
    policy.payload.delegated_keys[0].roles = vec![ReleaseSigningRoleV1::NativeQ];
    policy.signature_hex = hex(&root
        .sign(&policy.payload.canonical_bytes().unwrap())
        .to_bytes());
    wrong_role["signed_policy"] = serde_json::to_value(policy).unwrap();
    assert!(verify(&wrong_role, p, &cp_bytes, 300).is_err());
    let mut altered: Value = serde_json::from_slice(p).unwrap();
    altered["archive_size"] = json!(2048);
    let altered: memcordon_ci::private_public_completion::PublicEvidenceIndexV3 =
        serde_json::from_value(altered).unwrap();
    let altered = memcordon_ci::private_public_raw::canonical_json(&altered).unwrap();
    assert!(verify(&protected, &altered, &cp_bytes, 300).is_err());
    assert!(verify(&protected, p, &cp_bytes, 900).is_err());
    let mut forged = cp;
    forged.signature_hex = hex(&[0; 64]);
    assert!(verify(&protected, p, &serde_json::to_vec(&forged).unwrap(), 300).is_err());
}

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
        schema_version: 2,
        suite: suite(),
        repository: "example/memcordon".into(),
        workflow_path: ".github/workflows/release.yml".into(),
        workflow_revision: "cd".repeat(20),
        event: "workflow_dispatch".into(),
        producer_job_name: "Release / Linux private final / x64".into(),
        artifact_name: "release-private-public-raw-x64".into(),
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

#[test]
fn raw_collector_rejects_legacy_schema_and_final_envelope_artifact() {
    let current = intent();
    current.validate().unwrap();
    let mut legacy = current.clone();
    legacy.schema_version = 1;
    assert!(legacy.validate().is_err());
    let mut envelope = current.clone();
    envelope.artifact_name = "release-private-final-x64".into();
    assert!(envelope.validate().is_err());
    let mut foreign = current;
    foreign.artifact_name = "release-private-public-raw-arm64".into();
    assert!(foreign.validate().is_err());
}
