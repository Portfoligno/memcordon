use std::collections::BTreeMap;
use std::io::{Cursor, Write};

use memcordon_ci::private_observer_session::{ObserverStageV1, ObserverSubjectV1};
use memcordon_ci::private_public_raw::*;
use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::REQUIRED_PRIVATE_RELEASE_SELECTORS_V1;

fn subject() -> ObserverSubjectV1 {
    ObserverSubjectV1 {
        stage: ObserverStageV1::Public,
        repository_id: 1,
        run_id: 2,
        run_attempt: 1,
        job_id: 3,
        runner_id: 4,
        target: "x86_64-unknown-linux-gnu".into(),
        source_commit: "a".repeat(40),
        release_version: "0.5.7-dev".into(),
        build_sha256: DiagnosticSha256::from_bytes([1; 32]),
        intent_sha256: DiagnosticSha256::from_bytes([2; 32]),
        catalogue_sha256: DiagnosticSha256::from_bytes([3; 32]),
        host_profile_sha256: DiagnosticSha256::from_bytes([4; 32]),
    }
}

fn layers() -> (RawPublicEvidenceIndexV1, BTreeMap<String, Vec<u8>>) {
    let payload = BTreeMap::from([(
        "origin/session-v1.json".into(),
        (PublicLeafKindV1::Session, b"{\"session\":1}\n".to_vec()),
    )]);
    let i = make_payload_index(&subject(), &payload).unwrap();
    let i_bytes = canonical_json(&i).unwrap();
    let k = b"{\"commitment\":1}\n".to_vec();
    let r = b"{\"receipt\":1}\n".to_vec();
    let w = make_transport_index(&i, &payload, &i_bytes, &k, &r).unwrap();
    let mut leaves = payload
        .into_iter()
        .map(|(path, (_, bytes))| (path, bytes))
        .collect::<BTreeMap<_, _>>();
    leaves.insert(PAYLOAD_INDEX.into(), i_bytes);
    leaves.insert(ORIGIN_COMMITMENT.into(), k);
    leaves.insert(ORIGIN_RECEIPT.into(), r);
    (w, leaves)
}

#[test]
fn acyclic_exact_transport_roundtrips_without_semantic_authority() {
    let (index, leaves) = layers();
    let cursor = write_public_archive(Cursor::new(Vec::new()), &index, &leaves).unwrap();
    let mut visited = Vec::new();
    let (parsed, _) = visit_public_archive(
        Cursor::new(cursor.into_inner()),
        PublicRawBudgetV1::REVIEWED,
        |leaf, bytes| {
            assert_eq!(&leaves[&leaf.path], bytes);
            visited.push(leaf.path.clone());
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(parsed, index);
    assert_eq!(visited.len(), leaves.len());
    assert!(
        !parsed
            .leaves
            .iter()
            .any(|leaf| leaf.path == TRANSPORT_INDEX)
    );
}

#[test]
fn every_transport_leaf_mutation_and_omission_fails() {
    let (index, leaves) = layers();
    for path in leaves.keys() {
        let mut changed = leaves.clone();
        changed.get_mut(path).unwrap().push(0);
        assert!(
            write_public_archive(Cursor::new(Vec::new()), &index, &changed).is_err(),
            "mutated {path}"
        );
        let mut missing = leaves.clone();
        missing.remove(path);
        assert!(
            write_public_archive(Cursor::new(Vec::new()), &index, &missing).is_err(),
            "omitted {path}"
        );
    }
}

#[test]
fn paths_cannot_alias_or_escape() {
    for path in [
        "",
        "/absolute",
        "a//b",
        "./a",
        "a/../b",
        "a/",
        "a\\b",
        "a\0b",
        "C:drive",
    ] {
        assert!(
            validate_relative_evidence_path(path).is_err(),
            "accepted {path:?}"
        );
    }
    assert!(validate_relative_evidence_path("cases/16/attempts/0/checkpoint-v4.bin").is_ok());
}

#[test]
fn all25_have_closed_branch_and_outcome_inventory() {
    for (ordinal, selector) in REQUIRED_PRIVATE_RELEASE_SELECTORS_V1
        .into_iter()
        .enumerate()
    {
        let (branch, outcome) = match ordinal {
            0 => (PublicRawBranchV1::AbiFiltered, PublicRawOutcomeV1::Terminal),
            20 => (
                PublicRawBranchV1::Reuse,
                PublicRawOutcomeV1::AllocatedRejectedThenRecovered,
            ),
            24 => (
                PublicRawBranchV1::PolicyAccepted,
                PublicRawOutcomeV1::Terminal,
            ),
            3 | 11 => (
                PublicRawBranchV1::Ordinary,
                PublicRawOutcomeV1::AllocatedRejectedThenRecovered,
            ),
            10 => (
                PublicRawBranchV1::Ordinary,
                PublicRawOutcomeV1::TransportLostThenRecovered,
            ),
            _ => (PublicRawBranchV1::Ordinary, PublicRawOutcomeV1::Terminal),
        };
        let leaves =
            required_public_leaves(selector, branch, outcome, "x86_64-unknown-linux-gnu").unwrap();
        assert!(!leaves.is_empty());
        assert!(
            required_public_leaves(
                selector,
                branch,
                PublicRawOutcomeV1::PreallocationRejected,
                "x86_64-unknown-linux-gnu"
            )
            .is_err()
        );
        if ordinal != 24 {
            assert!(
                required_public_leaves(
                    selector,
                    PublicRawBranchV1::PolicyWrongGrant,
                    PublicRawOutcomeV1::PreallocationRejected,
                    "x86_64-unknown-linux-gnu"
                )
                .is_err()
            );
        }
    }
}

#[test]
fn conditional_frontend_and_fault_leaves_are_distinct() {
    let frontend = required_public_leaves(
        REQUIRED_PRIVATE_RELEASE_SELECTORS_V1[10],
        PublicRawBranchV1::Ordinary,
        PublicRawOutcomeV1::TransportLostThenRecovered,
        "aarch64-unknown-linux-gnu",
    )
    .unwrap();
    assert!(!frontend.keys().any(|path| path.ends_with("/report.json")));
    assert!(
        frontend
            .keys()
            .any(|path| path.ends_with("/transport-loss.json"))
    );
    assert!(
        !frontend
            .keys()
            .any(|path| path.ends_with("/original-rejection.bin"))
    );
    let uncertain = required_public_leaves(
        REQUIRED_PRIVATE_RELEASE_SELECTORS_V1[3],
        PublicRawBranchV1::Ordinary,
        PublicRawOutcomeV1::AllocatedRejectedThenRecovered,
        "aarch64-unknown-linux-gnu",
    )
    .unwrap();
    assert!(
        uncertain
            .keys()
            .any(|path| path.ends_with("/original-rejection.bin"))
    );
    assert!(!uncertain.keys().any(|path| path.ends_with("/terminal.bin")));
}

#[test]
fn stage_budgets_cannot_be_raised_by_artifact_input() {
    assert_eq!(
        PublicRawBudgetV1::REVIEWED.capture_limit(40, 192).unwrap(),
        19_200_040
    );
    assert!(
        PublicRawBudgetV1::REVIEWED
            .capture_limit(u64::MAX, 192)
            .is_err()
    );
    assert!(
        PublicRawBudgetV1::REVIEWED
            .capture_limit(40, u64::MAX)
            .is_err()
    );
    let mut unreviewed = PublicRawBudgetV1::REVIEWED;
    unreviewed.capture_events += 1;
    assert!(unreviewed.capture_limit(40, 192).is_err());
}

#[test]
fn zip_unknown_member_and_duplicate_json_keys_fail() {
    let (index, leaves) = layers();
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default();
    for (path, bytes) in &leaves {
        zip.start_file(path, options).unwrap();
        zip.write_all(bytes).unwrap();
    }
    zip.start_file(TRANSPORT_INDEX, options).unwrap();
    zip.write_all(&canonical_json(&index).unwrap()).unwrap();
    zip.start_file("undeclared.bin", options).unwrap();
    zip.write_all(b"extra").unwrap();
    assert!(
        visit_public_archive(
            Cursor::new(zip.finish().unwrap().into_inner()),
            PublicRawBudgetV1::REVIEWED,
            |_, _| Ok(())
        )
        .is_err()
    );
    let payload = BTreeMap::from([(
        "origin/session-v1.json".into(),
        (PublicLeafKindV1::Session, b"{}".to_vec()),
    )]);
    let i = make_payload_index(&subject(), &payload).unwrap();
    assert!(
        make_transport_index(
            &i,
            &payload,
            &canonical_json(&i).unwrap(),
            b"{\"x\":1,\"x\":2}",
            b"{}"
        )
        .is_err()
    );
}
