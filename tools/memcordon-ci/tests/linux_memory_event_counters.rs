#[path = "../src/release/linux_memory_event_counters.rs"]
mod counters;

const SIX: &[u8] = b"low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n";

#[test]
fn parses_native_required_and_documented_optional_inventory() {
    let six = counters::parse(SIX).unwrap();
    assert_eq!(six.len(), 6);
    let seven = counters::parse(&[b"sock_throttled 3\n".as_slice(), SIX].concat()).unwrap();
    assert_eq!(seven.len(), 7);
    assert_eq!(seven["sock_throttled"], 3);
    assert_eq!(seven["oom"], 0);
    assert_eq!(seven["oom_kill"], 0);
}

#[test]
fn rejects_missing_unknown_duplicate_and_noncanonical_counters() {
    for extension in [
        b"future_counter 0\n".as_slice(),
        b"sock_throttled 01\n",
        b"sock_throttled -1\n",
        b"sock_throttled 18446744073709551616\n",
        b"sock_throttled 1 extra\n",
        b"oom 0\n",
        b"sock_throttled 0\nsock_throttled 0\n",
    ] {
        assert!(counters::parse(&[SIX, extension].concat()).is_err());
    }
    for name in ["low", "high", "max", "oom", "oom_kill", "oom_group_kill"] {
        let bytes = String::from_utf8(SIX.to_vec())
            .unwrap()
            .replace(&format!("{name} 0\n"), "");
        assert!(counters::parse(bytes.as_bytes()).is_err());
    }
    assert!(counters::parse(b"\xff").is_err());
}

#[test]
fn interval_preserves_inventory_and_every_cumulative_counter() {
    let six = counters::parse(SIX).unwrap();
    let seven = counters::parse(&[SIX, b"sock_throttled 4\n"].concat()).unwrap();
    assert!(counters::require_monotonic(&six, &seven).is_err());
    assert!(counters::require_monotonic(&seven, &six).is_err());
    let mut later = seven.clone();
    later.insert("oom".into(), 1);
    later.insert("oom_kill".into(), 1);
    counters::require_monotonic(&seven, &later).unwrap();
    later.insert("sock_throttled".into(), 3);
    assert!(counters::require_monotonic(&seven, &later).is_err());
}
