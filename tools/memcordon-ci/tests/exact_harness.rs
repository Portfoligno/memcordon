use memcordon_ci::exact_harness::{
    require_listed_exactly_once, require_selected_watchdog, resolve_binary, resolve_executable,
};

#[test]
fn listing_requires_one_exact_name_without_regex_or_prefix_matches() {
    assert!(require_listed_exactly_once(b"case: test\ncase_extra: test\n", "case").is_ok());
    for output in [
        b"case_extra: test\n".as_slice(),
        b"case: test\ncase: test\n",
        b"case: benchmark\n",
    ] {
        assert!(require_listed_exactly_once(output, "case").is_err());
    }
}

#[test]
fn selected_backend_probe_fails_closed_and_binary_identity_is_cargo_selected() {
    let artifact = serde_json::json!({"reason":"compiler-artifact", "target":{"name":"memcordon","kind":["bin"]},"profile":{"test":false},"executable":"/actual/frontend"});
    assert_eq!(
        resolve_binary(&serde_json::to_vec(&artifact).unwrap(), "memcordon").unwrap(),
        std::path::Path::new("/actual/frontend")
    );
    let available = serde_json::json!({"selected":{"name":"macos-watchdog", "containment":{"supported":true}, "deadline":{"supported":true}}});
    require_selected_watchdog(&serde_json::to_vec(&available).unwrap()).unwrap();
    for unavailable in [
        serde_json::json!({"selected":null}),
        serde_json::json!({"selected":{"name":"other"}}),
    ] {
        assert!(require_selected_watchdog(&serde_json::to_vec(&unavailable).unwrap()).is_err());
    }
}

#[test]
fn machine_readable_cargo_output_rejects_missing_or_ambiguous_harnesses() {
    let artifact = serde_json::json!({"reason":"compiler-artifact", "target":{"name":"lifecycle","kind":["test"]},"profile":{"test":true},"executable":"/actual/hashed-harness"});
    let mut bytes = serde_json::to_vec(&artifact).unwrap();
    bytes.push(b'\n');
    assert_eq!(
        resolve_executable(&bytes, "lifecycle").unwrap(),
        std::path::Path::new("/actual/hashed-harness")
    );
    assert!(resolve_executable(&bytes, "other").is_err());
    let duplicate = [bytes.as_slice(), bytes.as_slice()].concat();
    assert!(resolve_executable(&duplicate, "lifecycle").is_err());
}
