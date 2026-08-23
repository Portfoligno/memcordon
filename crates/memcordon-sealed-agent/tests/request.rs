use memcordon_sealed_agent::request::{
    DeadlineScope, DescriptorPurpose, LaunchPolicyV1, LaunchRequestV1, Lifetime, RequestCodecError,
    SwapLimit, decode_launch_request, encode_launch_request,
};

fn request() -> LaunchRequestV1 {
    LaunchRequestV1 {
        program: b"/usr/bin/printf".to_vec(),
        arguments: vec![b"%s".to_vec(), b"native argument".to_vec()],
        environment: vec![(b"LANG".to_vec(), b"C".to_vec())],
        policy: LaunchPolicyV1 {
            memory_limit_bytes: Some(1024),
            swap_limit: SwapLimit::Bytes(0),
            absolute_deadline_millis: Some(50_000),
            deadline_scope: DeadlineScope::Supervision,
            lifetime: Lifetime::Workload,
            poll_interval_millis: 10,
            signal_grace_millis: 1_000,
            command_exit_grace_millis: 2_000,
            limit_grace_millis: 3_000,
        },
        descriptors: vec![
            DescriptorPurpose::CurrentDirectory,
            DescriptorPurpose::Stdin,
            DescriptorPurpose::Stdout,
            DescriptorPurpose::Stderr,
            DescriptorPurpose::FrontendLiveness,
        ],
    }
}

#[test]
fn launch_request_round_trips_native_counted_values() {
    let request = request();
    let encoded = encode_launch_request(&request).unwrap();
    assert_eq!(decode_launch_request(&encoded).unwrap(), request);
}

#[test]
fn descriptor_inventory_is_exact_and_ordered() {
    let mut request = request();
    request.descriptors.swap(1, 2);
    assert_eq!(
        encode_launch_request(&request),
        Err(RequestCodecError::InvalidValue)
    );
}

#[test]
fn truncated_and_trailing_payloads_fail_closed() {
    let encoded = encode_launch_request(&request()).unwrap();
    assert_eq!(
        decode_launch_request(&encoded[..encoded.len() - 1]),
        Err(RequestCodecError::Truncated)
    );
    let mut trailing = encoded;
    trailing.push(0);
    assert_eq!(
        decode_launch_request(&trailing),
        Err(RequestCodecError::TrailingBytes)
    );
}
