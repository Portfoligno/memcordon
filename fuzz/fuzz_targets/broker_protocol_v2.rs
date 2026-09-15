#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;

#[path = "../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/protocol.rs"]
mod protocol;
#[path = "../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/request.rs"]
mod request;
fuzz_target!(|data: &[u8]| {
    if let Ok(frame) = protocol::read_frame(&mut Cursor::new(data)) {
        let mut encoded = Vec::new();
        protocol::write_frame(&mut encoded, &frame).expect("decoded frame is encodable");
        // Decoding one frame must preserve the following frame in the stream.
        let mut sequence = encoded.clone();
        sequence.extend_from_slice(&encoded);
        let mut sequence = Cursor::new(sequence);
        assert_eq!(protocol::read_frame(&mut sequence).unwrap(), frame);
        assert_eq!(protocol::read_frame(&mut sequence).unwrap(), frame);
        assert_eq!(sequence.position() as usize, sequence.get_ref().len());
    }
    if let Ok(decoded) = request::decode_launch_broker_request(data) {
        let encoded = request::encode_launch_broker_request(&decoded)
            .expect("validated broker request is encodable");
        assert_eq!(request::decode_launch_broker_request(&encoded).unwrap(), decoded);
        let mut altered = decoded.clone();
        altered.request_authentication_binding[0] ^= 1;
        assert!(request::encode_launch_broker_request(&altered).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(request::decode_launch_broker_request(&trailing).is_err());
    }
});
