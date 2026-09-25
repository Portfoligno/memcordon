use crate::protocol::{
    Frame, MessageKind, NETWORK_PROTOCOL_VERSION, PROTOCOL_VERSION, ProtocolError, read_frame,
    read_network_frame, write_frame, write_network_frame,
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
fn network_wire_four_is_not_accepted_on_legacy_wire_three() {
    let frame = Frame {
        kind: MessageKind::BrokerLaunch,
        nonce: [4; 16],
        attempt_id: [5; 16],
        payload: vec![1, 2, 3],
    };
    let mut network = Vec::new();
    write_network_frame(&mut network, &frame).unwrap();
    assert_eq!(network[1], NETWORK_PROTOCOL_VERSION as u8);
    assert_eq!(read_network_frame(&mut network.as_slice()).unwrap(), frame);
    assert_eq!(
        read_frame(&mut network.as_slice()),
        Err(ProtocolError::UnsupportedVersion(NETWORK_PROTOCOL_VERSION))
    );

    let mut legacy = Vec::new();
    write_frame(&mut legacy, &frame).unwrap();
    assert_eq!(
        read_network_frame(&mut legacy.as_slice()),
        Err(ProtocolError::UnsupportedVersion(PROTOCOL_VERSION))
    );
}

#[test]
fn private_indeterminate_has_distinct_network_discriminant() {
    let frame = Frame {
        kind: MessageKind::PrivateIndeterminate,
        nonce: [4; 16],
        attempt_id: [5; 16],
        payload: b"possibly-released".to_vec(),
    };
    let mut wire = Vec::new();
    write_network_frame(&mut wire, &frame).unwrap();
    assert_eq!(u16::from_be_bytes([wire[2], wire[3]]), 110);
    assert_eq!(read_network_frame(&mut wire.as_slice()).unwrap(), frame);
    assert_eq!(
        read_frame(&mut wire.as_slice()),
        Err(ProtocolError::UnsupportedVersion(NETWORK_PROTOCOL_VERSION))
    );
}

#[test]
fn private_plan_uses_the_platforms_exact_v4_discriminants() {
    for (kind, discriminant) in [
        (MessageKind::PrivatePlan, 13_u16),
        (MessageKind::PrivatePlanReceipt, 111_u16),
    ] {
        let frame = Frame {
            kind,
            nonce: [3; 16],
            attempt_id: [0; 16],
            payload: vec![1, 2, 3],
        };
        let mut wire = Vec::new();
        write_network_frame(&mut wire, &frame).unwrap();
        assert_eq!(u16::from_be_bytes([wire[2], wire[3]]), discriminant);
        assert_eq!(read_network_frame(&mut wire.as_slice()).unwrap(), frame);
        assert_eq!(
            read_frame(&mut wire.as_slice()),
            Err(ProtocolError::UnsupportedVersion(NETWORK_PROTOCOL_VERSION))
        );
    }
}

#[test]
fn candidate_release_route_has_distinct_v4_kinds() {
    for (kind, discriminant) in [
        (MessageKind::ReleaseCase, 15_u16),
        (MessageKind::BrokerReleaseCase, 16_u16),
        (MessageKind::FinalizeReleaseCase, 17_u16),
        (MessageKind::ReleaseCaseIncomplete, 114_u16),
        (MessageKind::ReleaseCaseCompleted, 115_u16),
    ] {
        let frame = Frame {
            kind,
            nonce: [4; 16],
            attempt_id: [5; 16],
            payload: Vec::new(),
        };
        let mut wire = Vec::new();
        write_network_frame(&mut wire, &frame).unwrap();
        assert_eq!(u16::from_be_bytes([wire[2], wire[3]]), discriminant);
        assert_eq!(read_network_frame(&mut wire.as_slice()).unwrap(), frame);
    }
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
