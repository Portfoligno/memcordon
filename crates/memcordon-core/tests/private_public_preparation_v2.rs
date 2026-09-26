use memcordon_core::private_public_preparation_v2::*;
use memcordon_core::private_release_branch_v1::PolicyOperationBranchV1;
use memcordon_core::private_release_case_v1::{
    PrivateReleaseStageV1, REQUIRED_PRIVATE_RELEASE_SELECTORS_V1, private_release_case_key_v1,
};
use memcordon_core::{DiagnosticSha256, workload_contract::*};
fn digest(byte: u8) -> DiagnosticSha256 {
    DiagnosticSha256::from_bytes([byte; 32])
}
fn contract() -> WorkloadContractV2 {
    WorkloadContractV2::parse(include_bytes!(
        "../../../fuzz/corpus/workload-request/baseline-v2.json"
    ))
    .unwrap()
}
fn approval(contract: &WorkloadContractV2) -> ApprovedPublicPreparationPolicyV2 {
    let template = public_contract_template_sha256_v2(contract).unwrap();
    ApprovedPublicPreparationPolicyV2 {
        schema_version: 2,
        stage_semantics_version: 3,
        preparation_approved: true,
        static_suite_sha256: digest(1),
        preparer_image_sha256: digest(2),
        source_commit: "ab".repeat(20),
        target: "x86_64-unknown-linux-gnu".into(),
        manifest_sha256: digest(3),
        qualification_sha256: digest(4),
        public_cli_sha256: digest(5),
        public_uid: 1001,
        public_gid: 1001,
        historical_spoof_uid: 1002,
        historical_spoof_gid: 1002,
        historical_spoof_challenge_seed: [99; 32],
        policy_registry_sha256: digest(6),
        policy_fixture_template_sha256: digest(7),
        cases: REQUIRED_PRIVATE_RELEASE_SELECTORS_V1
            .iter()
            .enumerate()
            .map(|(ordinal, selector)| ApprovedPublicCaseTemplateV2 {
                selector: (*selector).into(),
                challenge_seed: [u8::try_from(ordinal + 1).unwrap(); 32],
                contract_template_sha256: template.clone(),
                fixture_sha256: digest(8),
                facility_source_sha256: None,
                fixture_argv_template: if ordinal == 0 {
                    vec![
                        "/usr/libexec/memcordon/memcordon-sealed-agent".into(),
                        "public-abi-filtered-target".into(),
                        "--challenge".into(),
                        String::from(DiagnosticSha256::from_bytes([1; 32])),
                    ]
                } else {
                    vec![
                        "/usr/libexec/memcordon/memcordon-sealed-agent".into(),
                        "public-release-fixture".into(),
                        (*selector).into(),
                        "--challenge".into(),
                        String::from(DiagnosticSha256::from_bytes(
                            [u8::try_from(ordinal + 1).unwrap(); 32],
                        )),
                    ]
                },
            })
            .collect(),
        policy_branches: PolicyOperationBranchV1::ALL
            .into_iter()
            .map(|branch| ApprovedPublicPolicyBranchTemplateV2 {
                branch,
                contract_template_sha256: template.clone(),
            })
            .collect(),
    }
}
#[test]
fn preparation_normalizes_only_epoch_and_never_grants_approval() {
    let mut contract = contract();
    let approved = approval(&contract);
    let original = public_contract_template_sha256_v2(&contract).unwrap();
    contract.expected_epoch.service_instance = Nonce128([44; 16]);
    assert_eq!(
        public_contract_template_sha256_v2(&contract).unwrap(),
        original
    );
    let selector = REQUIRED_PRIVATE_RELEASE_SELECTORS_V1[16];
    let role = PublicPreparedRoleV2::Ordinary;
    let challenge = approved.challenge([11; 32], 1, selector, role).unwrap();
    let mut record = PreparedPublicDispatchRecordV2 {
        schema_version: 2,
        static_suite_sha256: approved.static_suite_sha256.clone(),
        session_nonce: [11; 32],
        generation: 1,
        selector: selector.into(),
        role,
        challenge,
        result_key: private_release_case_key_v1(
            PrivateReleaseStageV1::FinalPublic,
            selector,
            &challenge,
        )
        .unwrap(),
        installation_epoch: digest(21),
        active_h1_receipt_sha256: digest(22),
        policy_epoch: contract.expected_epoch.clone(),
        contract_path: "/run/memcordon-final-public/prepared-v2/case/contract.json".into(),
        contract_file_sha256: digest(23),
        dispatch_bytes: b"{}".to_vec(),
    };
    record.validate(&approved, &contract).unwrap();
    let mut disabled = approved.clone();
    disabled.preparation_approved = false;
    assert!(record.validate(&disabled, &contract).is_err());
    record.session_nonce = [12; 32];
    assert!(record.validate(&approved, &contract).is_err());
    record.session_nonce = [11; 32];
    contract.authorization.grant_id = LogicalId::new("different-reviewed-grant".into()).unwrap();
    assert_ne!(
        public_contract_template_sha256_v2(&contract).unwrap(),
        original
    );
    assert!(record.validate(&approved, &contract).is_err());
}
#[test]
fn historical_spoof_and_policy_branches_have_independent_keys() {
    let approved = approval(&contract());
    let selector = "private_tcp::caller_identity_and_epoch_bound";
    let ordinary = approved
        .challenge([11; 32], 1, selector, PublicPreparedRoleV2::Ordinary)
        .unwrap();
    let spoof = approved
        .challenge([11; 32], 1, selector, PublicPreparedRoleV2::CallerSpoof)
        .unwrap();
    assert_ne!(ordinary, spoof);
    assert!(
        approved
            .challenge([11; 32], 0, selector, PublicPreparedRoleV2::CallerSpoof)
            .is_err()
    );
    let keys = PolicyOperationBranchV1::ALL
        .into_iter()
        .map(|branch| {
            approved
                .challenge(
                    [11; 32],
                    1,
                    "private_tcp::wrong_grant_profile_and_port_rejected",
                    PublicPreparedRoleV2::Policy { branch },
                )
                .unwrap()
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(keys.len(), 5);
}

#[test]
fn dual_argv_changes_only_the_independently_approved_challenge_slot() {
    let approved = approval(&contract());
    let selector = "private_tcp::dual_attempt_namespace_isolation";
    let parent = approved
        .challenge([11; 32], 1, selector, PublicPreparedRoleV2::Ordinary)
        .unwrap();
    let template = &approved
        .cases
        .iter()
        .find(|case| case.selector == selector)
        .unwrap()
        .fixture_argv_template;
    let mut branches = Vec::new();
    for ordinal in [0, 1] {
        let argv = approved
            .fixture_argv(
                [11; 32],
                1,
                selector,
                PublicPreparedRoleV2::Ordinary,
                ordinal,
            )
            .unwrap();
        assert_eq!(&argv[..4], &template[..4]);
        assert_eq!(argv.len(), template.len());
        assert_eq!(
            argv[4],
            String::from(DiagnosticSha256::from_bytes(
                memcordon_core::private_release_case_v1::public_dual_challenge_v1(&parent, ordinal)
                    .unwrap()
            ))
        );
        branches.push(argv);
    }
    assert_ne!(branches[0][4], branches[1][4]);
    assert!(
        approved
            .fixture_argv([11; 32], 1, selector, PublicPreparedRoleV2::Ordinary, 2)
            .is_err()
    );
    assert!(
        approved
            .fixture_argv([11; 32], 1, selector, PublicPreparedRoleV2::HistoricalE0, 0)
            .is_err()
    );
}

#[test]
fn preparation_rejects_missing_or_ambiguous_argv_approval() {
    let approved = approval(&contract());
    for mutation in [0, 1, 2, 3] {
        let mut changed = approved.clone();
        let case = &mut changed.cases[8];
        match mutation {
            0 => case.fixture_argv_template.clear(),
            1 => case.fixture_argv_template[2] = "different-selector".into(),
            2 => case.fixture_argv_template[4] = String::from(digest(99)),
            3 => case
                .fixture_argv_template
                .extend(["--challenge".into(), String::from(digest(99))]),
            _ => unreachable!(),
        }
        assert!(changed.validate().is_err());
    }
}

#[test]
fn abi_entrypoint_is_exact_and_not_an_ordinary_argv_substitution() {
    let approved = approval(&contract());
    assert!(approved.validate().is_ok());
    let mut ordinary = approved.clone();
    ordinary.cases[1].fixture_argv_template = approved.cases[0].fixture_argv_template.clone();
    assert!(ordinary.validate().is_err());
    let mut generic_abi = approved.clone();
    generic_abi.cases[0].fixture_argv_template = vec![
        "/usr/libexec/memcordon/memcordon-sealed-agent".into(),
        "public-release-fixture".into(),
        generic_abi.cases[0].selector.clone(),
        "--challenge".into(),
        String::from(digest(1)),
    ];
    assert!(generic_abi.validate().is_err());
}
