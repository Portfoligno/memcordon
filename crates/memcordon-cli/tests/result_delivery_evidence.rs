#![cfg(all(target_os = "macos", feature = "test-fixtures"))]
#[path = "../src/commands/result_delivery_evidence.rs"]
mod model;
use memcordon_platform::{DeliveryObservation, DeliveryStage, ObservationProvenance};
use model::{EVIDENCE_BYTES, EvidenceOutcome, encode};
#[test]
fn provenance_outcome_and_outstanding_are_independent_facts() {
    for (provenance, cleanup, label) in [
        (
            ObservationProvenance::CallerDeadlineSnapshot,
            true,
            "caller_deadline_snapshot",
        ),
        (ObservationProvenance::OwnerResult, false, "owner_result"),
        (ObservationProvenance::OwnerResult, true, "owner_result"),
        (
            ObservationProvenance::PreOwnerRejection,
            false,
            "pre_owner_rejection",
        ),
    ] {
        let observation = DeliveryObservation {
            provenance,
            cleanup_outstanding: cleanup,
            frame_transferred: provenance == ObservationProvenance::OwnerResult,
            writer_phases: [1, 2, 3, 4, 0, 0, 0, 0],
            writer_phase_count: if provenance == ObservationProvenance::OwnerResult {
                4
            } else {
                0
            },
            ..Default::default()
        };
        let bytes = encode(
            if provenance == ObservationProvenance::OwnerResult {
                EvidenceOutcome::Uncertain
            } else {
                EvidenceOutcome::Failed
            },
            if provenance == ObservationProvenance::PreOwnerRejection {
                DeliveryStage::Deadline
            } else {
                DeliveryStage::WriterDeadline
            },
            None,
            Some(observation),
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            value["outcome"],
            if provenance == ObservationProvenance::OwnerResult {
                "uncertain"
            } else {
                "failed"
            }
        );
        assert_eq!(value["writer"]["provenance"], label);
        assert_eq!(value["writer"]["cleanup_outstanding"], cleanup);
        assert_eq!(
            value["writer"]["phases"],
            if provenance == ObservationProvenance::OwnerResult {
                serde_json::json!(["entered", "payload_read", "payload_decoded", "before_write"])
            } else {
                serde_json::json!([])
            }
        );
    }
    for outcome in [
        EvidenceOutcome::Failed,
        EvidenceOutcome::Busy,
        EvidenceOutcome::InitializationFailed,
    ] {
        let bytes = encode(outcome, DeliveryStage::OwnerThread, Some(5), None).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(value["writer"].is_null());
    }
}
#[test]
fn actual_maximum_envelope_including_newline_fits_existing_collector() {
    let observation = DeliveryObservation {
        provenance: ObservationProvenance::OwnerResult,
        writer_pid: std::num::NonZeroU32::new(u32::MAX),
        exit_code: Some(i32::MIN),
        frame_transferred: true,
        cleanup_outstanding: true,
        writer_phases: [1, 2, 3, 4, 5, 6, 7, 8],
        writer_phase_count: 8,
        writer_phase_error: Some(i32::MIN),
        writer_phase_malformed: true,
        writer_phase_truncated: true,
    };
    let bytes = encode(
        EvidenceOutcome::Uncertain,
        DeliveryStage::ExecutableResolution,
        Some(i32::MIN),
        Some(observation),
    )
    .unwrap();
    assert!(bytes.len() <= EVIDENCE_BYTES);
    assert_eq!(bytes.last(), Some(&b'\n'));
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["writer"]["writer_pid"], u32::MAX);
    assert_eq!(value["writer_exit_code"], i32::MIN);
    assert_eq!(value["writer"]["phases"].as_array().unwrap().len(), 8);
    assert!(
        encode(
            EvidenceOutcome::Failed,
            DeliveryStage::WriterDeadline,
            None,
            Some(DeliveryObservation {
                writer_phase_count: 9,
                ..observation
            })
        )
        .is_err()
    );
}
