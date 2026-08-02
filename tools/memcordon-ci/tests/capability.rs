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
