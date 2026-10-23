use super::*;

#[test]
fn original_cutoff_applies_to_partial_frames_and_disconnected_peers() {
    let (mut sender, receiver) = UnixStream::pair().unwrap();
    let frame = Frame {
        kind: MessageKind::MixedRetirementEnrolled,
        nonce: [1; 16],
        attempt_id: [2; 16],
        payload: vec![3],
    };
    let mut bytes = Vec::new();
    crate::protocol::write_frame(&mut bytes, &frame).unwrap();
    sender.write_all(&bytes[..bytes.len() - 1]).unwrap();
    let deadline = Instant::now() + Duration::from_millis(30);
    assert!(receive_until(&receiver, deadline).is_err());
    assert!(Instant::now() >= deadline);
    drop(sender);
    assert!(receive_until(&receiver, Instant::now() + Duration::from_secs(1)).is_err());
}

#[test]
fn expired_cutoff_cannot_send_even_to_ready_socket() {
    let (sender, _receiver) = UnixStream::pair().unwrap();
    let frame = Frame {
        kind: MessageKind::MixedRetirementAck,
        nonce: [1; 16],
        attempt_id: [2; 16],
        payload: Vec::new(),
    };
    assert!(send_until(&sender, &frame, Instant::now()).is_err());
}
