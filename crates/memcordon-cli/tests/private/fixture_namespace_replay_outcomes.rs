use super::{protocol, replay_wire as replay};
use memcordon_windows_launch_core::ObservationUnavailable;
use protocol::*;
use replay::*;
use serde_json::json;

fn envelope() -> ReplayEnvelope {
    let request: Request = serde_json::from_value(json!({
        "revision": REVISION, "nonce": "a".repeat(32), "cell": "Private",
        "alias": "owned-alias", "boundary": "owned-boundary", "event": "original-event",
        "user_sid": "S-1-5-21-1-2-3-1001", "deadline_qpc": 1000, "qpc_frequency": 10000000,
        "expected_default_acl_sha256": "a".repeat(64),
        "expected_token": {
            "user_sid": "S-1-5-21-1-2-3-1001", "owner_sid": "S-1-5-32-544",
            "primary_group_sid": "S-1-5-21-1-2-3-513", "groups_sha256": "1".repeat(64),
            "privileges_sha256": "2".repeat(64), "restricted_sids_sha256": "3".repeat(64),
            "integrity_level": "S-1-16-12288", "mandatory_policy": 1, "session_id": 2,
            "elevation_type": 2, "elevated": true, "virtualization_allowed": false,
            "virtualization_enabled": false, "ui_access": false, "appcontainer": false,
            "authentication_id": 1, "token_type": 1, "impersonation_level": 0
        }
    }))
    .unwrap();
    ReplayEnvelope {
        format: "memcordon.namespace-debug-replay".into(),
        revision: 2,
        original_nonce: request.nonce.clone(),
        replay_nonce: "b".repeat(32),
        request_sha256: replay_digest(&request).unwrap(),
        diagnostic_stop_qpc: 500,
        request,
        source_commit: None,
        run: None,
        attempt: None,
    }
}
fn result(envelope: &ReplayEnvelope, outcome: ReplayOutcome) -> ReplayResult {
    ReplayResult {
        format: "memcordon.namespace-debug-replay-result".into(),
        revision: 2,
        original_nonce: envelope.original_nonce.clone(),
        replay_nonce: envelope.replay_nonce.clone(),
        diagnostic_stop_qpc: envelope.diagnostic_stop_qpc,
        request_sha256: envelope.request_sha256.clone(),
        outcome,
        cleanup: ReplayCleanup::Closed,
        diagnostic_only: true,
        acceptance_authority: false,
    }
}
fn unavailable() -> SourceCapture {
    Err(ObservationUnavailable::NotRequested)
}

#[test]
fn envelope_stop_is_canonical_and_does_not_rewrite_original_request() {
    let envelope = envelope();
    let original = encode_request(&envelope.request).unwrap();
    assert_eq!(
        decode_replay(&encode_replay(&envelope).unwrap()).unwrap(),
        envelope
    );
    assert_eq!(encode_request(&envelope.request).unwrap(), original);
    for stop in [0, envelope.request.deadline_qpc, u64::MAX] {
        let mut bad = envelope.clone();
        bad.diagnostic_stop_qpc = stop;
        assert!(encode_replay(&bad).is_err());
    }
    let mut old = envelope.clone();
    old.revision = 1;
    assert!(encode_replay(&old).is_err());
    check_replay_command_line(&[65, 0]).unwrap();
    assert!(!event_name(&envelope.request).unwrap().is_empty());
}

#[test]
fn not_attempted_is_a_distinct_witness_without_fabricated_event_fields() {
    let envelope = envelope();
    for (reason, before) in [
        (NotAttemptedReason::DiagnosticStopBeforePre, None),
        (
            NotAttemptedReason::DiagnosticStopAfterPre,
            Some(unavailable()),
        ),
    ] {
        let value = result(
            &envelope,
            ReplayOutcome::CallNotAttempted {
                reason,
                observed_qpc: 500,
                before,
            },
        );
        let frame = encode_replay_result(&value, &envelope).unwrap();
        decode_replay_result(&frame, &envelope).unwrap();
        let mut json: serde_json::Value = serde_json::from_slice(&frame).unwrap();
        for field in ["event_open", "raw_error", "after"] {
            json["outcome"][field] = json!(false);
            let mut bad = serde_json::to_vec(&json).unwrap();
            bad.push(b'\n');
            assert!(decode_replay_result(&bad, &envelope).is_err());
            json["outcome"].as_object_mut().unwrap().remove(field);
        }
    }
    for (observed_qpc, before) in [(499, Some(unavailable())), (500, None)] {
        assert!(
            encode_replay_result(
                &result(
                    &envelope,
                    ReplayOutcome::CallNotAttempted {
                        reason: NotAttemptedReason::DiagnosticStopAfterPre,
                        observed_qpc,
                        before,
                    }
                ),
                &envelope
            )
            .is_err()
        );
    }
}

#[test]
fn returned_results_preserve_error_and_skipped_after_without_fake_observation() {
    let envelope = envelope();
    for (opened, error) in [(false, Some(5)), (true, None)] {
        let value = result(
            &envelope,
            ReplayOutcome::EventReturned {
                event_open: opened,
                raw_error: error,
                before: unavailable(),
                after: ReplayAfter::SkippedDiagnosticStop,
            },
        );
        let frame = encode_replay_result(&value, &envelope).unwrap();
        assert!(frame.len() <= 65536 && frame.last() == Some(&b'\n'));
        let decoded = decode_replay_result(&frame, &envelope).unwrap();
        assert!(matches!(
            decoded.outcome,
            ReplayOutcome::EventReturned {
                after: ReplayAfter::SkippedDiagnosticStop,
                ..
            }
        ));
        let mut json: serde_json::Value = serde_json::from_slice(&frame).unwrap();
        json["outcome"]["after"]["observation"] = json!({});
        let mut bad = serde_json::to_vec(&json).unwrap();
        bad.push(b'\n');
        assert!(decode_replay_result(&bad, &envelope).is_err());
    }
    for (opened, error) in [(true, Some(5)), (false, None)] {
        assert!(
            encode_replay_result(
                &result(
                    &envelope,
                    ReplayOutcome::EventReturned {
                        event_open: opened,
                        raw_error: error,
                        before: unavailable(),
                        after: ReplayAfter::Unavailable {
                            reason: ObservationUnavailable::NotRequested
                        }
                    }
                ),
                &envelope
            )
            .is_err()
        );
    }
}

#[test]
fn result_binding_and_canonical_frame_remain_strict() {
    let envelope = envelope();
    let value = result(
        &envelope,
        ReplayOutcome::NamespaceFailed {
            raw_error: 5,
            before: unavailable(),
        },
    );
    let frame = encode_replay_result(&value, &envelope).unwrap();
    for field in [
        "revision",
        "original_nonce",
        "replay_nonce",
        "request_sha256",
        "diagnostic_stop_qpc",
        "acceptance_authority",
    ] {
        let mut bad = serde_json::to_value(&value).unwrap();
        bad[field] = match field {
            "revision" => json!(1),
            "diagnostic_stop_qpc" => json!(501),
            "acceptance_authority" => json!(true),
            _ => json!("c".repeat(64)),
        };
        let mut bytes = serde_json::to_vec(&bad).unwrap();
        bytes.push(b'\n');
        assert!(decode_replay_result(&bytes, &envelope).is_err());
    }
    assert!(decode_replay_result(&[], &envelope).is_err());
    assert!(decode_replay_result(&frame[..frame.len() - 1], &envelope).is_err());
    assert!(decode_replay_result(&vec![b' '; 65537], &envelope).is_err());
    let duplicate = String::from_utf8(frame).unwrap().replacen(
        "\"revision\":2",
        "\"revision\":2,\"revision\":2",
        1,
    );
    assert!(decode_replay_result(duplicate.as_bytes(), &envelope).is_err());
}

#[test]
fn source_samples_must_finish_before_the_exact_diagnostic_stop() {
    let (request, diagnostics) = super::diagnostic_fixture(2);
    let mut envelope = super::replay_envelope(request);
    envelope.diagnostic_stop_qpc = 50;
    let DiagnosticState::Present { before, mut after } = diagnostics else {
        unreachable!()
    };
    after.role = SourceRole::ReplayAfter;
    let valid = result(
        &envelope,
        ReplayOutcome::EventReturned {
            event_open: false,
            raw_error: Some(5),
            before: Ok(*before.clone()),
            after: ReplayAfter::Observed {
                observation: after.clone(),
            },
        },
    );
    encode_replay_result(&valid, &envelope).unwrap();
    for change in 0..4 {
        let mut value = valid.clone();
        let ReplayOutcome::EventReturned {
            before: Ok(before),
            after: ReplayAfter::Observed { observation: after },
            ..
        } = &mut value.outcome
        else {
            unreachable!()
        };
        match change {
            0 => before.finished_qpc = 50,
            1 => after.finished_qpc = 50,
            2 => after.started_qpc = 19,
            _ => before.token.envelope.session_id += 1,
        }
        assert!(encode_replay_result(&value, &envelope).is_err());
    }
}
