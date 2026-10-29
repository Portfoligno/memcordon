use memcordon_platform::workload_transport::{
    OrderedByteStream, STREAM_CHUNK_BYTES, WorkloadConnectionBinding, WorkloadFrame,
    WorkloadFrameKind,
};
use std::io::{self, Write};

#[allow(dead_code)]
#[path = "../../memcordon-cli/src/bin/memcordon-sealed-agent/protocol.rs"]
mod native_protocol;

#[test]
fn native_provider_and_frontend_share_exact_frame_encoding() {
    let frame = WorkloadFrame {
        kind: WorkloadFrameKind::MemberChunk,
        binding: binding(),
        payload: b"exact native payload".to_vec(),
    };
    let mut bytes = Vec::new();
    frame.write(&mut bytes).unwrap();
    let native = native_protocol::read_frame_version(&mut bytes.as_slice(), 5).unwrap();
    assert_eq!(
        native.kind,
        native_protocol::MessageKind::WorkloadMemberChunk
    );
    assert_eq!(native.nonce, frame.binding.challenge);
    assert_eq!(native.attempt_id, frame.binding.attempt);
    assert_eq!(native.payload, frame.payload);
    let mut reverse = Vec::new();
    native_protocol::write_frame(&mut reverse, &native).unwrap();
    assert_eq!(reverse, bytes);
    assert_eq!(
        WorkloadFrame::read(&mut reverse.as_slice(), binding()).unwrap(),
        frame
    );
    let last = bytes.last_mut().unwrap();
    *last ^= 1;
    assert!(WorkloadFrame::read(&mut bytes.as_slice(), binding()).is_err());
}

fn binding() -> WorkloadConnectionBinding {
    WorkloadConnectionBinding {
        challenge: [3; 16],
        attempt: [7; 16],
    }
}

#[test]
fn stream_rejects_cross_connection_before_allocating_payload() {
    let frame = WorkloadFrame {
        kind: WorkloadFrameKind::ManifestChunk,
        binding: binding(),
        payload: vec![42; STREAM_CHUNK_BYTES],
    };
    let mut wire = Vec::new();
    frame.write(&mut wire).unwrap();
    assert_eq!(
        WorkloadFrame::read(&mut wire.as_slice(), binding()).unwrap(),
        frame
    );
    let mut wrong = binding();
    wrong.challenge[0] ^= 1;
    assert!(WorkloadFrame::read(&mut wire.as_slice(), wrong).is_err());
    wrong = binding();
    wrong.attempt[0] ^= 1;
    assert!(WorkloadFrame::read(&mut wire.as_slice(), wrong).is_err());
    wire.truncate(wire.len() - 1);
    assert!(WorkloadFrame::read(&mut wire.as_slice(), binding()).is_err());
}

#[test]
fn duplicate_gap_and_overflow_never_write_extra_bytes() {
    let mut stream = OrderedByteStream::new(6, 6).unwrap();
    let mut bytes = Vec::new();
    stream.append(0, b"abc", &mut bytes).unwrap();
    assert!(stream.append(0, b"abc", &mut bytes).is_err());
    assert!(stream.append(4, b"d", &mut bytes).is_err());
    assert!(stream.append(u64::MAX, b"d", &mut bytes).is_err());
    assert_eq!(bytes, b"abc");
    stream.append(3, b"def", &mut bytes).unwrap();
    stream.finish().unwrap();
    assert_eq!(bytes, b"abcdef");
    assert!(OrderedByteStream::new(7, 6).is_err());
    assert!(OrderedByteStream::new(6, 6).unwrap().finish().is_err());
}

struct PartialFailure(bool);
impl Write for PartialFailure {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.0 {
            return Err(io::Error::other("destination failed"));
        }
        self.0 = true;
        Ok(bytes.len().min(1))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn partial_destination_failure_cannot_be_retried_or_completed() {
    let mut stream = OrderedByteStream::new(3, 3).unwrap();
    assert!(
        stream
            .append(0, b"abc", &mut PartialFailure(false))
            .is_err()
    );
    let mut replacement = Vec::new();
    assert!(stream.append(0, b"abc", &mut replacement).is_err());
    assert!(replacement.is_empty());
    assert!(stream.finish().is_err());
}
