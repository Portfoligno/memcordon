use memcordon_core::BoundedText;
use memcordon_core::mixed_observation::*;
use memcordon_core::workload_contract::Nonce128;

fn result() -> MixedRetirementObserverResultV1 {
    MixedRetirementObserverResultV1 {
        format: "memcordon.mixed-retirement-observer-result".into(),
        revision: 1,
        binding: MixedRetirementBindingV1 {
            attempt_id: BoundedText::new("original-attempt").unwrap(),
            admission_nonce: Nonce128([7; 16]),
            prepared_sha256: retirement_digest(b"original prepared bytes"),
        },
        enrollment_sha256: retirement_digest(b"original enrollment bytes"),
        witness_sha256: Some(retirement_digest(b"original witness bytes")),
        outcome: MixedRetirementOutcomeV1::Acknowledged,
    }
}

#[test]
fn observer_result_requires_witness_for_acknowledgement_and_post_witness_failures() {
    let mut value = result();
    value.validate().unwrap();
    value.witness_sha256 = None;
    assert!(value.validate().is_err());
    for stage in [
        MixedRetirementFailureStageV1::AcknowledgementRead,
        MixedRetirementFailureStageV1::AcknowledgementAssociation,
        MixedRetirementFailureStageV1::ObserverAborted,
        MixedRetirementFailureStageV1::PeerLost,
    ] {
        value.outcome = MixedRetirementOutcomeV1::Failed {
            stage,
            detail: BoundedText::new("failure retained independently of native cleanup").unwrap(),
        };
        assert!(value.validate().is_err());
    }
    for stage in [
        MixedRetirementFailureStageV1::IneligiblePhase,
        MixedRetirementFailureStageV1::JournalSnapshot,
        MixedRetirementFailureStageV1::WitnessWrite,
        MixedRetirementFailureStageV1::ObservationDeadline,
    ] {
        value.outcome = MixedRetirementOutcomeV1::Failed {
            stage,
            detail: BoundedText::new("failure before witness").unwrap(),
        };
        value.validate().unwrap();
    }
}

#[test]
fn retirement_payload_is_closed_bounded_and_byte_bound() {
    let value = result();
    let bytes = encode_retirement(&value).unwrap();
    assert_eq!(
        parse_retirement::<MixedRetirementObserverResultV1>(&bytes).unwrap(),
        value
    );
    assert_ne!(
        retirement_digest(&bytes),
        retirement_digest(b"substituted bytes")
    );
    let mut json = serde_json::to_value(&value).unwrap();
    json["extra"] = true.into();
    assert!(
        parse_retirement::<MixedRetirementObserverResultV1>(&serde_json::to_vec(&json).unwrap())
            .is_err()
    );
    let duplicate = br#"{"format":"first","format":"second"}"#;
    assert!(parse_retirement::<serde_json::Value>(duplicate).is_err());
    let oversized = vec![b' '; RETIREMENT_OBSERVATION_BYTES + 1];
    assert!(parse_retirement::<serde_json::Value>(&oversized).is_err());
    assert!(encode_retirement(&String::from_utf8(oversized).unwrap()).is_err());
}
