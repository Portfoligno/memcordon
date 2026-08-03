use memcordon_ci::capability;
use serde_json::json;

#[test]
fn backend_selection_distinguishes_available_and_unavailable_probes() {
    let unavailable = json!({
        "selected": null,
        "available": [],
        "unavailable": [{
            "name": "linux-cgroup-v2",
            "reason": "delegated cgroup v2 is unavailable"
        }]
    });
    assert!(capability::selected(&unavailable).is_none());
    assert!(capability::require_selected(&unavailable).is_err());

    let available = json!({
        "selected": {
            "name": "macos-watchdog",
            "hard_limit": false
        }
    });
    assert_eq!(
        capability::require_selected(&available)
            .ok()
            .and_then(|selected| selected.get("name"))
            .and_then(serde_json::Value::as_str),
        Some("macos-watchdog")
    );
}

#[test]
fn exact_test_success_requires_one_executed_test() {
    assert!(
        capability::require_single_test_success(
            b"running 1 test\ntest example ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.01s\n",
            "example",
        )
        .is_ok()
    );
    for output in [
        b"running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out; finished in 0.00s\n"
            .as_slice(),
        b"test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.01s\n"
            .as_slice(),
    ] {
        assert!(capability::require_single_test_success(output, "example").is_err());
    }
}
