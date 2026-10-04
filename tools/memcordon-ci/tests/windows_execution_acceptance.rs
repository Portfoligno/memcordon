use memcordon_ci::windows_execution_acceptance::{
    WindowsExecutionCaseV2, validate_identity_stream,
};

#[test]
fn identity_stream_requires_exact_unique_ordinals_and_bounded_count() {
    let mut bytes = Vec::new();
    for ordinal in std::iter::once(None).chain((0..256).map(Some)) {
        let identity = memcordon_ci::windows_causal_acceptance::FixtureProcessIdentityV1 {
            ordinal,
            pid: u32::try_from(ordinal.unwrap_or(0) + 1).expect("ordinal fits PID"),
            birth: u128::try_from(ordinal.unwrap_or(0) + 1).expect("ordinal fits birth"),
        };
        bytes.extend(serde_json::to_vec(&identity).expect("identity serializes"));
        bytes.push(b'\n');
    }
    // Root and ordinal zero deliberately collide: ordinal coverage alone is insufficient.
    assert!(validate_identity_stream(WindowsExecutionCaseV2::Concurrent257, &bytes).is_err());
    let mut fixed = Vec::new();
    for (index, ordinal) in std::iter::once(None).chain((0..256).map(Some)).enumerate() {
        let identity = memcordon_ci::windows_causal_acceptance::FixtureProcessIdentityV1 {
            ordinal,
            pid: u32::try_from(index + 1).expect("index fits PID"),
            birth: u128::try_from(index + 1).expect("index fits birth"),
        };
        fixed.extend(serde_json::to_vec(&identity).expect("identity serializes"));
        fixed.push(b'\n');
    }
    validate_identity_stream(WindowsExecutionCaseV2::Concurrent257, &fixed)
        .expect("complete independent identity stream validates");
    fixed.extend(
        serde_json::to_vec(
            &memcordon_ci::windows_causal_acceptance::FixtureProcessIdentityV1 {
                ordinal: Some(256),
                pid: 258,
                birth: 258,
            },
        )
        .expect("identity serializes"),
    );
    fixed.push(b'\n');
    assert!(validate_identity_stream(WindowsExecutionCaseV2::Concurrent257, &fixed).is_err());
}
