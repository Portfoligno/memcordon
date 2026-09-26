#[allow(dead_code)]
#[path = "../src/bin/memcordon-sealed-agent/protocol.rs"]
mod protocol;

use protocol::{Frame, MessageKind, read_network_frame, write_network_frame};

#[test]
fn policy_decision_has_distinct_request_and_receipt_kinds() {
    for kind in [
        MessageKind::PolicyDecision,
        MessageKind::PolicyDecisionRecorded,
    ] {
        assert_ne!(kind, MessageKind::ReleaseCase);
        assert_ne!(kind, MessageKind::ReleaseCaseCompleted);
        let frame = Frame {
            kind,
            nonce: [1; 16],
            attempt_id: [2; 16],
            payload: vec![3; 32],
        };
        let mut bytes = Vec::new();
        write_network_frame(&mut bytes, &frame).unwrap();
        let decoded = read_network_frame(&mut bytes.as_slice()).unwrap();
        assert_eq!(decoded, frame);
    }
}
