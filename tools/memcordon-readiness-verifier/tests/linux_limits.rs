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

#[test]
fn documented_socket_counter_preserves_six_and_seven_field_transitions() {
    validate_memory_event_transition(BEFORE, AFTER).unwrap();
    let before = [BEFORE, b"sock_throttled 3\n"].concat();
    let after = [AFTER, b"sock_throttled 4\n"].concat();
    validate_memory_event_transition(&before, &after).unwrap();
    let reordered =
        b"sock_throttled 4\noom_kill 1\nlow 0\noom_group_kill 0\nhigh 0\noom 2\nmax 7\n";
    validate_memory_event_transition(&before, reordered).unwrap();
    validate_memory_event_transition(&before, &[AFTER, b"sock_throttled 3\n"].concat()).unwrap();
}

#[test]
fn socket_counter_does_not_admit_missing_or_malformed_native_inventory() {
    let before = [BEFORE, b"sock_throttled 0\n"].concat();
    let after = [AFTER, b"sock_throttled 1\n"].concat();
    let text = std::str::from_utf8(&after).unwrap();
    for required in [
        "low 0\n",
        "high 0\n",
        "max 7\n",
        "oom 2\n",
        "oom_kill 1\n",
        "oom_group_kill 0\n",
    ] {
        let missing = text.replace(required, "");
        assert!(validate_memory_event_transition(&before, missing.as_bytes()).is_err());
        let name = required.split_whitespace().next().unwrap();
        let missing_before = std::str::from_utf8(&before)
            .unwrap()
            .replace(&format!("{name} 0\n"), "");
        assert!(validate_memory_event_transition(missing_before.as_bytes(), &after).is_err());
    }
    for optional in [
        "sock_throttled 01\n",
        "sock_throttled -1\n",
        "sock_throttled 18446744073709551616\n",
        "sock_throttled 1 extra\n",
        "sock_throttled\n",
        "sock_throttled 1\nsock_throttled 1\n",
        "sock_throttled 1\nunknown_counter 0\n",
    ] {
        let malformed = [AFTER, optional.as_bytes()].concat();
        assert!(validate_memory_event_transition(&before, &malformed).is_err());
        let malformed_before = [BEFORE, optional.as_bytes()].concat();
        assert!(validate_memory_event_transition(&malformed_before, &after).is_err());
    }
}

#[test]
fn socket_counter_requires_stable_inventory_monotonicity_and_fresh_oom() {
    let before = [BEFORE, b"sock_throttled 3\n"].concat();
    let after = [AFTER, b"sock_throttled 4\n"].concat();
    assert!(validate_memory_event_transition(BEFORE, &after).is_err());
    assert!(validate_memory_event_transition(&before, AFTER).is_err());
    let backwards = [AFTER, b"sock_throttled 2\n"].concat();
    assert!(validate_memory_event_transition(&before, &backwards).is_err());
    let no_oom = [BEFORE, b"sock_throttled 4\n"].concat();
    assert!(validate_memory_event_transition(&before, &no_oom).is_err());
    for required in ["oom 2", "oom_kill 1"] {
        let missing_increment = std::str::from_utf8(&after).unwrap().replace(
            required,
            &format!("{} 0", required.split_whitespace().next().unwrap()),
        );
        assert!(validate_memory_event_transition(&before, missing_increment.as_bytes()).is_err());
    }
    let reused = std::str::from_utf8(&before)
        .unwrap()
        .replace("oom_kill 0", "oom_kill 1");
    assert!(validate_memory_event_transition(reused.as_bytes(), &after).is_err());
}
