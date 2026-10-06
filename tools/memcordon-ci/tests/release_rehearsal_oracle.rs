use memcordon_ci::{
    rehearsal_support::{coordinator::assert_evidence, protocol::*},
    release::publish::PublicationSummary,
};
use std::collections::BTreeSet;

#[test]
fn interruption_receipt_requires_exact_current_committed_boundary() {
    use memcordon_ci::rehearsal_support::{cases::Case, coordinator::expected_boundary};
    let case = Case {
        group: "R04",
        variant: "asset-two".into(),
        fault: Fault::Barrier {
            boundary: Boundary::Asset(2),
        },
        seed: false,
        recover: true,
        positive: true,
    };
    let actual = Snapshot {
        fault_reached: true,
        fault_boundary: Some(Boundary::Asset(2)),
        effects: vec![EffectObservation {
            boundary: Boundary::Asset(2),
            id: 7,
            name: "asset-two".into(),
        }],
        ..Snapshot::default()
    };
    assert!(expected_boundary(&case, &actual).is_ok());
    let mut wrong = actual.clone();
    wrong.fault_boundary = Some(Boundary::Asset(1));
    assert!(expected_boundary(&case, &wrong).is_err());
    let mut absent = actual.clone();
    absent.effects.clear();
    assert!(expected_boundary(&case, &absent).is_err());
    let mut stale = actual;
    stale.fault_boundary = None;
    stale.fault_reached = false;
    assert!(expected_boundary(&case, &stale).is_err());
}

#[test]
fn false_completion_skipped_body_and_missing_retirement_cannot_pass() {
    let selection = FixtureSelection {
        version: "1.2.3".into(),
        commit: "1111111111111111111111111111111111111111".into(),
        repository: "fixture/repository".into(),
        notes: "notes".into(),
        prerelease: false,
        files: vec![ExpectedFile {
            name: "asset".into(),
            size: 3,
            sha256: "digest".into(),
            package: None,
        }],
    };
    let summary:PublicationSummary=serde_json::from_value(serde_json::json!({"source_commit":selection.commit,"objects":[],"complete":true,"public":true})).unwrap();
    let received = Snapshot {
        assets: vec![AssetState {
            id: 7,
            name: "asset".into(),
            size: 3,
            sha256: "digest".into(),
            path: "received".into(),
            state: "uploaded".into(),
        }],
        ..Snapshot::default()
    };
    let compared = BTreeSet::from([("github".into(), "asset".into())]);
    assert!(assert_evidence(&selection, &received, &summary, &compared, true, true).is_ok());
    assert!(
        assert_evidence(
            &selection,
            &Snapshot::default(),
            &summary,
            &compared,
            true,
            true
        )
        .is_err()
    );
    assert!(
        assert_evidence(
            &selection,
            &received,
            &summary,
            &BTreeSet::new(),
            true,
            true
        )
        .is_err()
    );
    assert!(assert_evidence(&selection, &received, &summary, &compared, true, false).is_err());
    assert!(assert_evidence(&selection, &received, &summary, &compared, false, true).is_err());
}
