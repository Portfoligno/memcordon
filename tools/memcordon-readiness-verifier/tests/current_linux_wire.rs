use memcordon_readiness_verifier::{NativeArguments, current::linux_wire::verify_start};
use serde_json::{Value, json};

fn vector() -> (Vec<u8>, Value, Value, usize) {
    let mut wire = vec![0, 3];
    wire.extend(0_u64.to_be_bytes());
    let value = |wire: &mut Vec<u8>, bytes: &[u8]| {
        wire.extend(u32::try_from(bytes.len()).unwrap().to_be_bytes());
        wire.extend(bytes);
    };
    value(&mut wire, b"owned-readiness");
    let arguments = vec![b"deadline-demand".to_vec(), vec![b'a'; 64]];
    wire.extend(2_u32.to_be_bytes());
    for argument in &arguments {
        value(&mut wire, argument);
    }
    wire.extend(0_u32.to_be_bytes());
    wire.push(1);
    wire.extend((128_u64 * 1024 * 1024).to_be_bytes());
    wire.extend([3, 0, 1]);
    let lifetime = wire.len();
    wire.push(1);
    for duration in [20_u64, 100, 1000, 1000] {
        wire.extend(duration.to_be_bytes());
    }
    wire.extend(5_u32.to_be_bytes());
    wire.extend([1, 2, 3, 4, 5, 0]);
    let request = json!({"format":"memcordon.workload-request","revision":1,"runtime":{"kind":"linux-private","profile":"linux-private-workload-v1","inputs":{"runtime_digest":"a".repeat(64),"input_digest":"b".repeat(64),"entrypoint":"owned-readiness"},"layout":{"writable_roots":[{"id":"work","path":"work","byte_limit":1048576,"generated_execution":true}],"output_files":[]}},"requirements":[]});
    let input = json!({"target_argv":NativeArguments::UnixBytes(arguments),"memory_bytes":128*1024*1024,"deadline_millis":2000,"lifetime":"command"});
    (wire, request, input, lifetime)
}
fn document(wire: Vec<u8>, request: &Value) -> (Vec<u8>, Value) {
    let binding = json!({"invocation_sha256":memcordon_core::workload_request::invocation_digest(&wire,None).unwrap(),"resource_policy_sha256":memcordon_core::workload_request::resource_policy_digest(&wire,Some(2000)).unwrap()});
    (serde_json::to_vec(&json!({"format":"memcordon.workload-start","revision":1,"request":request,"native_launch":wire,"working_directory":null,"attempt_deadline_millis":2000})).unwrap(),binding)
}

#[test]
fn original_native_wire_matches_independent_resource_and_argv_decode() {
    let (wire, request, input, _) = vector();
    let (start, binding) = document(wire, &request);
    verify_start(&start, &request, &binding, &input).unwrap();
}

#[test]
fn rehashed_lifetime_substitution_cannot_change_original_caller_selection() {
    let (mut wire, request, input, lifetime) = vector();
    wire[lifetime] = 2;
    let (start, binding) = document(wire, &request);
    assert!(
        verify_start(&start, &request, &binding, &input)
            .unwrap_err()
            .contains("lifetime")
    );
}

#[test]
fn rehashed_descriptor_and_host_destination_substitutions_are_rejected() {
    let (mut wire, request, input, _) = vector();
    let last = wire.len();
    wire[last - 2] = 6;
    let (start, binding) = document(wire, &request);
    assert!(verify_start(&start, &request, &binding, &input).is_err());
    let (wire, request, input, _) = vector();
    let (start, binding) = document(wire, &request);
    let mut altered: Value = serde_json::from_slice(&start).unwrap();
    altered["output_directory"] = json!("/tmp/caller-output");
    assert!(
        verify_start(
            &serde_json::to_vec(&altered).unwrap(),
            &request,
            &binding,
            &input
        )
        .is_err()
    );
}

#[test]
fn original_cwd_changes_commitment_without_changing_native_argv() {
    let (wire, request, mut input, _) = vector();
    let (start, mut binding) = document(wire.clone(), &request);
    let work = memcordon_core::workload_files::RootRelativePath::new("work".into()).unwrap();
    let digest = memcordon_core::workload_request::invocation_digest(&wire, Some(&work)).unwrap();
    assert_ne!(
        serde_json::to_value(&digest).unwrap(),
        binding["invocation_sha256"]
    );
    binding["invocation_sha256"] = serde_json::to_value(digest).unwrap();
    let mut start: Value = serde_json::from_slice(&start).unwrap();
    start["working_directory"] = json!("work");
    input["working_directory"] = json!("work");
    verify_start(
        &serde_json::to_vec(&start).unwrap(),
        &request,
        &binding,
        &input,
    )
    .unwrap();
    let other = memcordon_core::workload_files::RootRelativePath::new("other".into()).unwrap();
    start["working_directory"] = json!("other");
    binding["invocation_sha256"] = serde_json::to_value(
        memcordon_core::workload_request::invocation_digest(&wire, Some(&other)).unwrap(),
    )
    .unwrap();
    assert!(
        verify_start(
            &serde_json::to_vec(&start).unwrap(),
            &request,
            &binding,
            &input
        )
        .is_err()
    );
}
