#![cfg(all(target_os = "linux", feature = "test-support"))]

use memcordon_core::workload_request::{
    WorkloadRequestV1, WorkloadStartV1, invocation_digest, resource_policy_digest,
};
use memcordon_core::{ByteSize, CommandSpec, DiagnosticSha256, Policy};
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;

fn take<const N: usize>(bytes: &mut &[u8]) -> [u8; N] {
    let (head, tail) = bytes.split_at(N);
    *bytes = tail;
    head.try_into().unwrap()
}
fn word(bytes: &mut &[u8]) -> u32 {
    u32::from_be_bytes(take(bytes))
}
fn value(bytes: &mut &[u8]) -> Vec<u8> {
    let length = word(bytes) as usize;
    let (value, tail) = bytes.split_at(length);
    *bytes = tail;
    value.to_vec()
}
fn actual_environment(native: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut bytes = native;
    assert_eq!(u16::from_be_bytes(take(&mut bytes)), 3);
    let _restart = u64::from_be_bytes(take(&mut bytes));
    assert_eq!(value(&mut bytes), b"tool");
    let count = word(&mut bytes);
    for _ in 0..count {
        value(&mut bytes);
    }
    let count = word(&mut bytes);
    (0..count)
        .map(|_| (value(&mut bytes), value(&mut bytes)))
        .collect()
}

#[test]
fn actual_target_environment_is_in_original_start_and_invocation_commitment_only() {
    let bundle = tempfile::NamedTempFile::new().unwrap();
    let mut frontend =
        memcordon_platform::WorkloadFrontendRequest::open(bundle.path(), None, None, None, None)
            .unwrap();
    let parent = std::env::var_os("CURRENT_TARGET_MARKER");
    frontend.environment = vec![(
        OsString::from("CURRENT_TARGET_MARKER"),
        OsString::from_vec(vec![b'a', 0xff, b'z']),
    )];
    let request=WorkloadRequestV1::parse(&serde_json::to_vec(&serde_json::json!({
        "format":"memcordon.workload-request","revision":1,"requirements":[],
        "runtime":{"kind":"linux-private","profile":"linux-private-workload-v1",
          "inputs":{"runtime_digest":DiagnosticSha256::from_bytes([1;32]),"input_digest":DiagnosticSha256::from_bytes([2;32]),"entrypoint":"tool"},
          "layout":{"writable_roots":[],"output_files":[]}}
    })).unwrap()).unwrap();
    let policy = Policy::new(ByteSize::from_bytes(128 * 1024 * 1024));
    let command = CommandSpec::new("tool");
    let raw = memcordon_platform::test_support::workload_start_bytes(
        &policy, &command, &request, &frontend,
    )
    .unwrap();
    let start = WorkloadStartV1::parse(&raw).unwrap();
    assert_eq!(
        actual_environment(&start.native_launch),
        vec![(b"CURRENT_TARGET_MARKER".to_vec(), vec![b'a', 0xff, b'z'])]
    );
    assert_eq!(start.request, request);
    frontend.environment = vec![(
        OsString::from("LD_LIBRARY_PATH"),
        OsString::from("/work/untrusted"),
    )];
    let changed = WorkloadStartV1::parse(
        &memcordon_platform::test_support::workload_start_bytes(
            &policy, &command, &request, &frontend,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        actual_environment(&changed.native_launch),
        vec![(b"LD_LIBRARY_PATH".to_vec(), b"/work/untrusted".to_vec())],
        "actual unsupported loader operand must reach native refusal, never be silently dropped"
    );
    assert_ne!(
        invocation_digest(&start.native_launch, None).unwrap(),
        invocation_digest(&changed.native_launch, None).unwrap()
    );
    assert_eq!(
        resource_policy_digest(&start.native_launch, None).unwrap(),
        resource_policy_digest(&changed.native_launch, None).unwrap()
    );
    assert_eq!(
        std::env::var_os("CURRENT_TARGET_MARKER"),
        parent,
        "target vector must not mutate the frontend/provider process environment"
    );
}
