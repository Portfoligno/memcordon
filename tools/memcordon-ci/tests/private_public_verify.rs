use memcordon_ci::private_public_verify::{
    PublicCaseDigestV1, PublicCaseDigestV2, PublicCaseEvidenceFormatV2, PublicEvidenceIndexV1,
    PublicEvidenceIndexV2,
};
use memcordon_core::private_release_case_v1::REQUIRED_PRIVATE_RELEASE_SELECTORS_V1;
use memcordon_core::workload_codec::hash_bytes;

#[test]
fn public_index_rejects_missing_extra_or_reordered_cases() {
    let cases = REQUIRED_PRIVATE_RELEASE_SELECTORS_V1
        .iter()
        .map(|selector| PublicCaseDigestV1 {
            selector: (*selector).into(),
            case_sha256: hash_bytes(selector.as_bytes()),
            result_key: hash_bytes(format!("key:{selector}").as_bytes()),
        })
        .collect();
    let index = PublicEvidenceIndexV1 {
        schema_version: 1,
        target: "x86_64-unknown-linux-gnu".into(),
        native_machine: "x86_64".into(),
        source_commit: "a".repeat(40),
        release_version: "0.5.7-dev".into(),
        archive_sha256: hash_bytes(b"A"),
        manifest_sha256: hash_bytes(b"M1"),
        qualification_sha256: hash_bytes(b"Q"),
        host_receipt_sha256: hash_bytes(b"H1"),
        installation_epoch: hash_bytes(b"E1"),
        boot_identity: "boot-a".into(),
        historical_epoch_sha256: hash_bytes(b"E0-E1 protected replay"),
        cases,
    };
    assert!(PublicEvidenceIndexV1::parse(&serde_json::to_vec(&index).unwrap()).is_ok());
    let mut missing = index.clone();
    missing.cases.pop();
    assert!(PublicEvidenceIndexV1::parse(&serde_json::to_vec(&missing).unwrap()).is_err());
    let mut extra = index.clone();
    extra.cases.push(extra.cases[0].clone());
    assert!(PublicEvidenceIndexV1::parse(&serde_json::to_vec(&extra).unwrap()).is_err());
    let mut reordered = index;
    reordered.cases.swap(0, 1);
    assert!(PublicEvidenceIndexV1::parse(&serde_json::to_vec(&reordered).unwrap()).is_err());
}

#[test]
fn public_v2_index_requires_one_five_actor_policy_composite() {
    let cases = REQUIRED_PRIVATE_RELEASE_SELECTORS_V1
        .iter()
        .map(|selector| PublicCaseDigestV2 {
            selector: (*selector).into(),
            evidence_format: if *selector
                == memcordon_core::private_public_policy_composite_v1::PUBLIC_POLICY_SELECTOR_V1
            {
                PublicCaseEvidenceFormatV2::PolicyCompositeV1
            } else if *selector
                == memcordon_core::private_public_abi_composite_v1::PUBLIC_ABI_SELECTOR_V1
            {
                PublicCaseEvidenceFormatV2::AbiCompositeV1
            } else if *selector
                == memcordon_core::private_public_reuse_composite_v1::PUBLIC_REUSE_SELECTOR_V1
            {
                PublicCaseEvidenceFormatV2::ReuseCompositeV1
            } else {
                PublicCaseEvidenceFormatV2::SingleCaseV2
            },
            case_sha256: hash_bytes(selector.as_bytes()),
            result_key: hash_bytes(format!("key:{selector}").as_bytes()),
        })
        .collect();
    let index = PublicEvidenceIndexV2 {
        schema_version: 2,
        target: "x86_64-unknown-linux-gnu".into(),
        native_machine: "x86_64".into(),
        source_commit: "a".repeat(40),
        release_version: "0.5.7-dev".into(),
        archive_sha256: hash_bytes(b"A"),
        manifest_sha256: hash_bytes(b"M1"),
        qualification_sha256: hash_bytes(b"Q"),
        host_receipt_sha256: hash_bytes(b"H1"),
        installation_epoch: hash_bytes(b"E1"),
        boot_identity: "boot-a".into(),
        historical_epoch_sha256: hash_bytes(b"E0-E1"),
        cases,
    };
    assert!(PublicEvidenceIndexV2::parse(&serde_json::to_vec(&index).unwrap()).is_ok());
    let policy = index
        .cases
        .iter()
        .position(|case| case.evidence_format == PublicCaseEvidenceFormatV2::PolicyCompositeV1)
        .unwrap();
    let mut wrong = index.clone();
    wrong.cases[policy].evidence_format = PublicCaseEvidenceFormatV2::SingleCaseV2;
    assert!(PublicEvidenceIndexV2::parse(&serde_json::to_vec(&wrong).unwrap()).is_err());
    let abi = index
        .cases
        .iter()
        .position(|case| case.evidence_format == PublicCaseEvidenceFormatV2::AbiCompositeV1)
        .unwrap();
    let mut wrong_abi = index.clone();
    wrong_abi.cases[abi].evidence_format = PublicCaseEvidenceFormatV2::SingleCaseV2;
    assert!(PublicEvidenceIndexV2::parse(&serde_json::to_vec(&wrong_abi).unwrap()).is_err());
    let reuse = index
        .cases
        .iter()
        .position(|case| case.evidence_format == PublicCaseEvidenceFormatV2::ReuseCompositeV1)
        .unwrap();
    let mut wrong_reuse = index.clone();
    wrong_reuse.cases[reuse].evidence_format = PublicCaseEvidenceFormatV2::SingleCaseV2;
    assert!(PublicEvidenceIndexV2::parse(&serde_json::to_vec(&wrong_reuse).unwrap()).is_err());
    let mut duplicate = index.clone();
    duplicate.cases[policy].case_sha256 = duplicate.cases[0].case_sha256.clone();
    assert!(PublicEvidenceIndexV2::parse(&serde_json::to_vec(&duplicate).unwrap()).is_err());
    let mut missing = index.clone();
    missing.cases.remove(policy);
    assert!(PublicEvidenceIndexV2::parse(&serde_json::to_vec(&missing).unwrap()).is_err());
    let mut old = index;
    old.schema_version = 1;
    assert!(PublicEvidenceIndexV2::parse(&serde_json::to_vec(&old).unwrap()).is_err());
}
