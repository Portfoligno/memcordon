use crate::protocol::{
    Frame, MessageKind, PROTOCOL_VERSION, ProtocolError, read_frame, write_frame,
};
use crate::state::{AttemptState, AttemptStateMachine};

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
fn combined_envelope_has_independent_revision_and_rejects_cross_version_kinds() {
    use crate::protocol::{MIXED_PROTOCOL_VERSION, read_frame_version};
    for kind in [
        MessageKind::MixedLaunch,
        MessageKind::MixedBrokerLaunch,
        MessageKind::MixedPlan,
        MessageKind::MixedDiscovery,
        MessageKind::MixedPreparedAck,
        MessageKind::MixedTerminal,
        MessageKind::MixedRejected,
        MessageKind::MixedPlanReceipt,
        MessageKind::MixedDiscoveryReceipt,
        MessageKind::MixedPreparedObservation,
    ] {
        let frame = Frame {
            kind,
            nonce: [7; 16],
            attempt_id: [9; 16],
            payload: vec![],
        };
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &frame).unwrap();
        assert_eq!(&bytes[..2], &[0, 4], "new closed domain freezes envelope4");
        assert_eq!(
            read_frame_version(&mut bytes.as_slice(), MIXED_PROTOCOL_VERSION).unwrap(),
            frame
        );
        assert!(matches!(
            read_frame(&mut bytes.as_slice()),
            Err(ProtocolError::UnsupportedVersion(4))
        ));
        bytes[..2].copy_from_slice(&[0, 3]);
        assert!(
            read_frame(&mut bytes.as_slice()).is_err(),
            "mixed kind must not enter legacy envelope"
        );
    }
    let legacy = Frame {
        kind: MessageKind::Launch,
        nonce: [7; 16],
        attempt_id: [9; 16],
        payload: vec![],
    };
    let mut bytes = Vec::new();
    write_frame(&mut bytes, &legacy).unwrap();
    bytes[..2].copy_from_slice(&[0, 4]);
    assert!(
        read_frame_version(&mut bytes.as_slice(), MIXED_PROTOCOL_VERSION).is_err(),
        "legacy kind must not enter combined envelope"
    );
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
fn deleted_private_wire_four_is_rejected_before_payload_allocation() {
    let frame = Frame {
        kind: MessageKind::Launch,
        nonce: [4; 16],
        attempt_id: [5; 16],
        payload: vec![1, 2, 3],
    };
    let mut wire = Vec::new();
    write_frame(&mut wire, &frame).unwrap();
    let deleted_version = 4_u16;
    wire[..std::mem::size_of::<u16>()].copy_from_slice(&deleted_version.to_be_bytes());
    assert_eq!(
        read_frame(&mut wire.as_slice()),
        Err(ProtocolError::UnsupportedVersion(deleted_version))
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
