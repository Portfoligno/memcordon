use crate::protocol::{
    Frame, MessageKind, PROTOCOL_VERSION, ProtocolError, read_frame, write_frame,
};
use crate::state::{AttemptState, AttemptStateMachine};

fn unsupported_vectors() -> Vec<serde_json::Value> {
    let frame = Frame {
        kind: MessageKind::WorkloadStart,
        nonce: [7; 16],
        attempt_id: [9; 16],
        payload: vec![],
    };
    let mut current = Vec::new();
    write_frame(&mut current, &frame).unwrap();
    assert_eq!(
        crate::protocol::read_frame_version(
            &mut current.as_slice(),
            crate::protocol::WORKLOAD_PROTOCOL_VERSION
        )
        .unwrap(),
        frame
    );
    [0_u16, 1, 255]
        .into_iter()
        .map(|version| {
            let mut bytes = current.clone();
            bytes[..size_of::<u16>()].copy_from_slice(&version.to_be_bytes());
            let error = crate::protocol::read_frame_version(
                &mut bytes.as_slice(),
                crate::protocol::WORKLOAD_PROTOCOL_VERSION,
            )
            .unwrap_err();
            assert_eq!(error, ProtocolError::UnsupportedVersion(version));
            serde_json::json!({"version":version,"frame_bytes":bytes,"error":error.to_string()})
        })
        .collect()
}

#[test]
fn current_unsupported_versions_reject_before_payload_allocation() {
    assert_eq!(unsupported_vectors().len(), 3);
}

#[test]
fn frame_round_trips_native_counted_payload() {
    let expected = Frame {
        kind: MessageKind::Launch,
        nonce: [7; 16],
        attempt_id: [9; 16],
        payload: vec![0, 1, 2, 255],
    };
    let mut bytes = Vec::new();
    write_frame(&mut bytes, &expected).unwrap();
    assert_eq!(read_frame(&mut bytes.as_slice()).unwrap(), expected);
}

#[test]
fn unknown_version_is_rejected_before_payload_allocation() {
    let mut bytes = vec![0, PROTOCOL_VERSION as u8 + 1];
    bytes.extend_from_slice(&[0; 70]);
    assert!(matches!(
        read_frame(&mut bytes.as_slice()),
        Err(ProtocolError::UnsupportedVersion(_))
    ));
}

#[test]
fn payload_corruption_is_rejected() {
    let frame = Frame {
        kind: MessageKind::Probe,
        nonce: [1; 16],
        attempt_id: [0; 16],
        payload: vec![1, 2, 3],
    };
    let mut bytes = Vec::new();
    write_frame(&mut bytes, &frame).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    assert_eq!(
        read_frame(&mut bytes.as_slice()),
        Err(ProtocolError::PayloadDigestMismatch)
    );
}

#[test]
fn retirement_cannot_skip_empty_proof() {
    let mut machine = AttemptStateMachine::default();
    assert!(machine.transition(AttemptState::Retired).is_err());
}

#[test]
fn every_resource_owning_preauthorization_state_can_enter_cleanup() {
    let setup_path = [
        AttemptState::BoundaryCreated,
        AttemptState::GuardianReady,
        AttemptState::TargetCreatedGated,
        AttemptState::AssignmentVerified,
        AttemptState::ResourceInheritanceVerified,
        AttemptState::Authorized,
    ];
    for failure_state in setup_path {
        let mut machine = AttemptStateMachine::default();
        for state in setup_path {
            machine.transition(state).unwrap();
            if state == failure_state {
                break;
            }
        }
        machine.transition(AttemptState::Terminating).unwrap();
        machine.transition(AttemptState::Empty).unwrap();
        machine.transition(AttemptState::Retired).unwrap();
    }
}
