use memcordon_readiness_verifier::validate_memory_event_transition;

#[test]
fn large_native_streams_require_every_byte_on_both_captured_streams() {
    use memcordon_readiness_verifier::validate_bounded_large_streams;
    let actual = (0..256 * 8192)
        .map(|index| (index % 256) as u8)
        .collect::<Vec<_>>();
    validate_bounded_large_streams(&actual, &actual).unwrap();
    let mut modified = actual.clone();
    modified[1024 * 1024] ^= 1;
    let mut extended = actual.clone();
    extended.push(b'\n');
    for stdout in [
        &actual[..actual.len() - 1],
        modified.as_slice(),
        extended.as_slice(),
    ] {
        assert!(validate_bounded_large_streams(stdout, &actual).is_err());
        assert!(validate_bounded_large_streams(&actual, stdout).is_err());
    }
    assert!(validate_bounded_large_streams(&actual, b"native-exit-0").is_err());
}

const BEFORE: &[u8] = b"low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n";
const AFTER: &[u8] = b"low 0\nhigh 0\nmax 7\noom 2\noom_kill 1\noom_group_kill 0\n";

#[test]
fn actual_counter_transition_rejects_status_substitutes_and_counter_reassociation() {
    validate_memory_event_transition(BEFORE, AFTER).unwrap();
    for after in [
        BEFORE.to_vec(),
        String::from_utf8(AFTER.to_vec())
            .unwrap()
            .replace("oom 2", "oom 0")
            .into_bytes(),
        String::from_utf8(AFTER.to_vec())
            .unwrap()
            .replace("oom_kill 1", "oom_kill 0")
            .into_bytes(),
        String::from_utf8(AFTER.to_vec())
            .unwrap()
            .replace("oom_kill 1", "oom_kill 01")
            .into_bytes(),
        [AFTER, b"target_status 137\n"].concat(),
        [AFTER, b"oom_kill 1\n"].concat(),
        String::from_utf8(AFTER.to_vec())
            .unwrap()
            .replace("oom_group_kill 0\n", "")
            .into_bytes(),
        String::from_utf8(AFTER.to_vec())
            .unwrap()
            .replace("oom 2", "oom 18446744073709551616")
            .into_bytes(),
    ] {
        assert!(validate_memory_event_transition(BEFORE, &after).is_err());
    }
    let reused = String::from_utf8(BEFORE.to_vec())
        .unwrap()
        .replace("oom_kill 0", "oom_kill 1");
    assert!(validate_memory_event_transition(reused.as_bytes(), AFTER).is_err());
    let backwards = String::from_utf8(BEFORE.to_vec())
        .unwrap()
        .replace("high 0", "high 4");
    assert!(validate_memory_event_transition(backwards.as_bytes(), AFTER).is_err());
}
