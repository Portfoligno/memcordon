use std::collections::BTreeMap;

use memcordon_ci::private_candidate_replay::{
    ReplayLeafRoleV1, ReplayLeafV1, encode_replay_bundle, parse_replay_bundle,
};
use memcordon_ci::private_case_semantics::{ExecRequirementV1, closed_case_spec};
use memcordon_ci::private_observer_session::*;
use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_codec::hash_bytes;

fn digest(value: u8) -> DiagnosticSha256 {
    DiagnosticSha256::from_bytes([value; 32])
}

fn descriptor() -> ObserverSessionDescriptorV1 {
    ObserverSessionDescriptorV1 {
        schema_version: 1,
        session_nonce: "01".repeat(32),
        enrolled_host: "test-enrollment".into(),
        boot_id: "test-boot".into(),
        kernel_btf_sha256: digest(1),
        observer_executable_sha256: digest(2),
        intervals: Vec::new(),
        subject: ObserverSubjectV1 {
            stage: ObserverStageV1::Candidate,
            repository_id: 1,
            run_id: 2,
            run_attempt: 1,
            job_id: 3,
            runner_id: 4,
            target: "x86_64-unknown-linux-gnu".into(),
            source_commit: "a".repeat(40),
            release_version: "0.5.6-rc.1".into(),
            build_sha256: digest(3),
            intent_sha256: digest(4),
            catalogue_sha256: digest(5),
            host_profile_sha256: digest(6),
        },
        generations: vec![ObservedGenerationV1 {
            generation: 0,
            installation_epoch: digest(7),
            installed_manifest_sha256: digest(8),
            installed_receipt_sha256: digest(9),
            service_identity_sha256: digest(10),
            broker_identity_sha256: digest(11),
            transaction_sha256: digest(12),
            observer_bundle_sha256: digest(13),
            begin_monotonic_ns: 10,
            end_monotonic_ns: 100,
        }],
    }
}

#[test]
fn journal_enforces_exact_append_chain_and_no_reused_interval() {
    let descriptor = descriptor();
    let initial = hash_bytes(&canonical_bytes(&descriptor).unwrap());
    let mut journal = CustodyJournalV1::begin(descriptor).unwrap();
    journal.begin_interval(digest(14)).unwrap();
    journal
        .append(0, &initial, "case/raw.bin", b"literal raw data")
        .unwrap();
    assert!(
        journal
            .append(1, &initial, "case/next.bin", b"next")
            .is_err()
    );
    assert!(
        journal.seal(digest(15), 101).is_err(),
        "a poisoned session cannot be sealed"
    );
}

#[test]
fn disconnect_cannot_be_repaired_into_completed_custody() {
    let mut journal = CustodyJournalV1::begin(descriptor()).unwrap();
    journal.disconnect();
    assert!(journal.begin_interval(digest(14)).is_err());
    assert!(journal.seal(digest(15), 101).is_err());
}

fn closed_source_journal() -> CustodyJournalV1 {
    closed_source_journal_for_stage(ObserverStageV1::Candidate)
}

fn closed_source_journal_for_stage(stage: ObserverStageV1) -> CustodyJournalV1 {
    let mut session = descriptor();
    session.subject.stage = stage;
    let initial = hash_bytes(&canonical_bytes(&session).unwrap());
    let mut journal = CustodyJournalV1::begin(session).unwrap();
    let id = digest(14);
    journal.begin_interval(id.clone()).unwrap();
    journal
        .append(0, &initial, "case/capture.bin", b"original capture")
        .unwrap();
    let chain = journal.chain().clone();
    journal
        .append(1, &chain, "case/sample.json", b"original sample")
        .unwrap();
    journal
        .close_interval(ObserverIntervalRecordV1 {
            interval_id: id,
            logical_case_key: digest(15),
            generation: 0,
            purpose: "controls".into(),
            ordinal: 0,
            capture_path: "case/capture.bin".into(),
            capture_sha256: hash_bytes(b"original capture"),
            controls_paths: vec!["case/capture.bin".into()],
            sample_paths: vec!["case/sample.json".into()],
            arm_monotonic_ns: 11,
            begin_monotonic_ns: 12,
            end_monotonic_ns: 20,
            detach_monotonic_ns: 21,
            loss_count: 0,
            first_sequence: 1,
            last_sequence: 2,
        })
        .unwrap();
    journal
}

#[test]
fn public_representation_phase_cannot_admit_raw_sources_or_noncanonical_case_names() {
    for path in [
        "historical/epoch-transition.json",
        "cases/0/facts.json",
        "cases/24/result.json",
        "composites/abi/composite.json",
        "composites/reuse/composite.json",
        "composites/policy/composite.json",
    ] {
        let mut journal = closed_source_journal_for_stage(ObserverStageV1::Public);
        let previous = journal.chain().clone();
        journal
            .append_representation(2, &previous, path, b"derived representation")
            .unwrap();
        assert_eq!(journal.descriptor().intervals.len(), 1);
        assert_eq!(journal.leaves()[path], b"derived representation");
    }
    for path in [
        "cases/25/facts.json",
        "cases/04/facts.json",
        "cases/4/capture.bin",
        "historical/spoof/request.bin",
        "origin/receipt.json",
        "composites/abi/outer/interval.json",
        "composites/reuse/holder-clock.json",
    ] {
        let mut journal = closed_source_journal_for_stage(ObserverStageV1::Public);
        let previous = journal.chain().clone();
        assert!(
            journal
                .append_representation(2, &previous, path, b"not raw authority")
                .is_err()
        );
    }
}

#[test]
fn source_repacking_preserves_custody_subleaf_mapping_before_seal() {
    let mut journal = closed_source_journal();
    let previous = journal.chain().clone();
    journal
        .repack_sources(
            2,
            &previous,
            "case/source-carrier.v1.bin",
            &["case/capture.bin".into(), "case/sample.json".into()],
        )
        .unwrap();
    assert_eq!(journal.leaves().len(), 1);
    let views =
        memcordon_ci::private_candidate_replay::expand_replay_payload(journal.leaves()).unwrap();
    assert_eq!(views["case/capture.bin"], b"original capture");
    assert_eq!(views["case/sample.json"], b"original sample");
    journal.seal(digest(16), 101).unwrap();
}

#[test]
fn representation_append_requires_closed_original_observation_and_exact_case_path() {
    let mut journal = closed_source_journal();
    let previous = journal.chain().clone();
    let path = format!(
        "candidate-c-v3/cases/{}/family/replay-bundle.v1.bin",
        "ab".repeat(32)
    );
    journal
        .append_representation(2, &previous, &path, b"derived transport bytes")
        .unwrap();
    assert_eq!(journal.leaves()[&path], b"derived transport bytes");
    assert_eq!(journal.descriptor().intervals.len(), 1);
    journal.seal(digest(16), 101).unwrap();

    let mut empty = CustodyJournalV1::begin(descriptor()).unwrap();
    let previous = empty.chain().clone();
    assert!(
        empty
            .append_representation(0, &previous, &path, b"unobserved")
            .is_err()
    );

    for invalid in [
        "qualification.json",
        "candidate-c-v3/cases/bad/result.json",
        "candidate-c-v3/cases/abababababababababababababababababababababababababababababababab/family/source-carrier.v1.bin",
    ] {
        let mut journal = closed_source_journal();
        let previous = journal.chain().clone();
        assert!(
            journal
                .append_representation(2, &previous, invalid, b"invalid")
                .is_err()
        );
    }
}

#[test]
fn source_repacking_rejects_omission_duplicate_and_cycle_without_qualification() {
    for sources in [
        vec!["case/absent".into()],
        vec!["case/capture.bin".into(), "case/capture.bin".into()],
    ] {
        let mut journal = closed_source_journal();
        let previous = journal.chain().clone();
        assert!(
            journal
                .repack_sources(2, &previous, "case/source-carrier.v1.bin", &sources)
                .is_err()
        );
        assert!(journal.seal(digest(16), 101).is_err());
    }
    let mut journal = closed_source_journal();
    let previous = journal.chain().clone();
    journal
        .repack_sources(
            2,
            &previous,
            "case/source-carrier.v1.bin",
            &["case/capture.bin".into(), "case/sample.json".into()],
        )
        .unwrap();
    let previous = journal.chain().clone();
    assert!(
        journal
            .repack_sources(
                3,
                &previous,
                "other/source-carrier.v1.bin",
                &["case/source-carrier.v1.bin".into()]
            )
            .is_err()
    );
}

#[test]
fn generation_reuse_and_overlap_fail() {
    let mut descriptor = descriptor();
    let mut next = descriptor.generations[0].clone();
    next.generation = 1;
    next.begin_monotonic_ns = 101;
    next.end_monotonic_ns = 110;
    descriptor.generations.push(next);
    assert!(
        descriptor.validate().is_err(),
        "installation epoch cannot be reused"
    );
    descriptor.generations[1].installation_epoch = digest(16);
    descriptor.validate().unwrap();
    descriptor.generations[1].begin_monotonic_ns = 99;
    assert!(
        descriptor.validate().is_err(),
        "generations may not overlap"
    );
}

#[test]
fn payload_index_excludes_future_carriers_and_retains_installed_q() {
    let subject = descriptor().subject;
    let mut payload = BTreeMap::from([(
        "installed/qualification.json".into(),
        b"installed Q".to_vec(),
    )]);
    let index = canonical_payload_index(&subject, &payload).unwrap();
    assert_eq!(index.leaves.len(), 1);
    payload.insert(
        ORIGIN_COMMITMENT_LEAF.into(),
        b"must not self-commit".to_vec(),
    );
    assert!(canonical_payload_index(&subject, &payload).is_err());
    payload.remove(ORIGIN_COMMITMENT_LEAF);
    payload.insert("../escape".into(), b"raw".to_vec());
    assert!(canonical_payload_index(&subject, &payload).is_err());
}

#[test]
fn bounded_replay_bundle_preserves_exact_bytes_and_rejects_tampering() {
    let leaves = vec![
        ReplayLeafV1 {
            role: ReplayLeafRoleV1::Facts,
            ordinal: 0,
            bytes: b"facts".to_vec(),
        },
        ReplayLeafV1 {
            role: ReplayLeafRoleV1::Clock,
            ordinal: 0,
            bytes: b"clock".to_vec(),
        },
    ];
    let bytes = encode_replay_bundle(&leaves).unwrap();
    let parsed = parse_replay_bundle(&bytes).unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].bytes, b"facts");
    let mut changed = bytes.clone();
    let last = changed.last_mut().unwrap();
    *last ^= 1;
    assert!(parse_replay_bundle(&changed).is_err());
    let mut trailing = bytes;
    trailing.push(0);
    assert!(parse_replay_bundle(&trailing).is_err());
    assert!(
        encode_replay_bundle(&[ReplayLeafV1 {
            role: ReplayLeafRoleV1::Facts,
            ordinal: 0,
            bytes: Vec::new()
        }])
        .is_err()
    );
}

#[test]
fn custody_retains_genuinely_empty_streams_but_not_empty_evidence() {
    let session = descriptor();
    let initial = hash_bytes(&canonical_bytes(&session).unwrap());
    let payload = BTreeMap::from([
        ("supervisor/stdout.raw".into(), Vec::new()),
        ("supervisor/stderr.raw".into(), Vec::new()),
    ]);
    let index = canonical_payload_index(&session.subject, &payload).unwrap();
    assert_eq!(index.leaves.len(), 2);
    assert!(index.leaves.iter().all(|leaf| leaf.size == 0));
    let mut journal = CustodyJournalV1::begin(session).unwrap();
    journal.begin_interval(digest(14)).unwrap();
    journal
        .append(0, &initial, "supervisor/stdout.raw", b"")
        .unwrap();
    let invalid = BTreeMap::from([("supervisor/wait-v1.json".into(), Vec::new())]);
    assert!(canonical_payload_index(&descriptor().subject, &invalid).is_err());
}

#[test]
fn closed_family_table_covers_exact_all25_and_uncertainty_is_pre_exec() {
    for target in ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"] {
        for selector in
            memcordon_core::private_release_case_v1::REQUIRED_PRIVATE_RELEASE_SELECTORS_V1
        {
            let spec = closed_case_spec(selector, target).unwrap();
            assert!(!spec.facts.is_empty());
            assert!(spec.facts.windows(2).all(|pair| pair[0] < pair[1]));
        }
        let uncertainty =
            closed_case_spec("private_tcp::authorization_uncertainty_retired", target).unwrap();
        assert_eq!(
            uncertainty.exec,
            ExecRequirementV1::PreExecAuthorizationRejected
        );
    }
    assert!(closed_case_spec("private_tcp::made-up", "x86_64-unknown-linux-gnu").is_err());
}

#[test]
fn frame_decoder_bounds_before_allocating_and_canonical_json_rejects_duplicates() {
    assert!(read_controller_frame(&mut &u32::MAX.to_be_bytes()[..]).is_err());
    assert!(read_controller_frame(&mut &[0_u8; 4][..]).is_err());
    let mut frame = Vec::new();
    write_controller_frame(&mut frame, b"literal").unwrap();
    assert_eq!(
        read_controller_frame(&mut frame.as_slice()).unwrap(),
        b"literal"
    );
    assert!(strict_json::<serde_json::Value>(br#"{"a":1,"a":2}"#, 128).is_err());
}

#[test]
fn partial_leaf_never_enters_committed_inventory_and_gap_poisons_session() {
    let descriptor = descriptor();
    let previous = hash_bytes(&canonical_bytes(&descriptor).unwrap());
    let mut journal = CustodyJournalV1::begin(descriptor).unwrap();
    journal.begin_interval(digest(14)).unwrap();
    let whole = b"complete original bytes";
    let sha = hash_bytes(whole);
    assert_eq!(
        journal
            .append_leaf_part(
                0,
                &previous,
                "case/raw.bin",
                whole.len() as u64,
                &sha,
                0,
                &whole[..4]
            )
            .unwrap(),
        previous
    );
    assert!(
        journal
            .append_leaf_part(
                0,
                &previous,
                "case/raw.bin",
                whole.len() as u64,
                &sha,
                5,
                &whole[5..]
            )
            .is_err()
    );
    assert!(journal.seal(digest(15), 101).is_err());
}

#[test]
fn exact_completed_partial_leaf_advances_only_once() {
    let descriptor = descriptor();
    let previous = hash_bytes(&canonical_bytes(&descriptor).unwrap());
    let mut journal = CustodyJournalV1::begin(descriptor).unwrap();
    journal.begin_interval(digest(14)).unwrap();
    let whole = b"complete original bytes";
    let sha = hash_bytes(whole);
    journal
        .append_leaf_part(
            0,
            &previous,
            "case/raw.bin",
            whole.len() as u64,
            &sha,
            0,
            &whole[..4],
        )
        .unwrap();
    let complete = journal
        .append_leaf_part(
            0,
            &previous,
            "case/raw.bin",
            whole.len() as u64,
            &sha,
            4,
            &whole[4..],
        )
        .unwrap();
    assert_ne!(complete, previous);
    assert!(
        journal
            .append_leaf_part(
                1,
                &complete,
                "case/raw.bin",
                whole.len() as u64,
                &sha,
                0,
                whole
            )
            .is_err()
    );
}

#[test]
fn structural_origin_layer_roundtrip_and_exact_payload_tamper_rejection() {
    use ed25519_dalek::{Signer, SigningKey};
    let mut descriptor = descriptor();
    let initial = hash_bytes(&canonical_bytes(&descriptor).unwrap());
    let mut journal = CustodyJournalV1::begin(descriptor.clone()).unwrap();
    journal.begin_interval(digest(14)).unwrap();
    let capture = b"structural capture carrier, not a semantic proof".to_vec();
    journal
        .append(0, &initial, "control/capture.bin", &capture)
        .unwrap();
    let record = ObserverIntervalRecordV1 {
        interval_id: digest(14),
        logical_case_key: digest(15),
        generation: 0,
        purpose: "controls".into(),
        ordinal: 0,
        capture_path: "control/capture.bin".into(),
        capture_sha256: hash_bytes(&capture),
        controls_paths: vec!["control/capture.bin".into()],
        sample_paths: Vec::new(),
        arm_monotonic_ns: 20,
        begin_monotonic_ns: 21,
        end_monotonic_ns: 30,
        detach_monotonic_ns: 31,
        loss_count: 0,
        first_sequence: 1,
        last_sequence: 2,
    };
    journal.close_interval(record.clone()).unwrap();
    descriptor.intervals.push(record);
    let (index, commitment) = journal.seal(digest(16), 101).unwrap();
    let key = SigningKey::from_bytes(&[17; 32]);
    let mut receipt = OriginReceiptV1 {
        schema_version: 1,
        custodian_id: "diagnostic-test-key".into(),
        storage_revision: 1,
        origin_commitment_sha256: hash_bytes(&commitment),
        signature: String::new(),
    };
    receipt.signature = hex::encode(
        key.sign(&origin_receipt_message(&receipt).unwrap())
            .to_bytes(),
    );
    let receipt = canonical_bytes(&receipt).unwrap();
    let mut payload = BTreeMap::from([("control/capture.bin".into(), capture)]);
    verify_origin_layers(
        &descriptor,
        &payload,
        &index,
        &commitment,
        &receipt,
        key.verifying_key().as_bytes(),
    )
    .unwrap();
    payload.get_mut("control/capture.bin").unwrap().push(0);
    assert!(
        verify_origin_layers(
            &descriptor,
            &payload,
            &index,
            &commitment,
            &receipt,
            key.verifying_key().as_bytes()
        )
        .is_err()
    );
    // This public structural API intentionally cannot manufacture an
    // AuthenticatedObserverSessionV1 or any NativeQ capability.
}
