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
            "memory": {
                "supported": true,
                "class": "watchdog"
            }
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

#[test]
fn certification_consumes_typed_doctor_schema() {
    let mut probe = json!({
        "schema_version": memcordon_core::DOCTOR_REPORT_SCHEMA_VERSION,
        "tool": { "name": "memcordon", "version": "0.3.0" },
        "host": { "os": "linux", "architecture": "x86_64" },
        "selected": backend_capability("linux-cgroup-v2", true, "hard"),
        "available": [backend_capability("linux-cgroup-v2", true, "hard")],
        "unavailable": [],
        "requirement": { "kind": null, "met": true, "reason": null }
    });
    assert!(capability::require_certified_hard_backend(&probe, "linux-cgroup-v2").is_ok());

    probe["selected"]["memory"]["supported"] = json!(false);
    assert!(capability::require_certified_hard_backend(&probe, "linux-cgroup-v2").is_err());

    probe["selected"] = backend_capability("linux-cgroup-v2", true, "watchdog");
    assert!(capability::require_certified_hard_backend(&probe, "linux-cgroup-v2").is_err());

    probe["selected"] = backend_capability("unsupported-backend", true, "hard");
    assert!(capability::require_certified_hard_backend(&probe, "linux-cgroup-v2").is_err());

    probe["selected"] = backend_capability("linux-cgroup-v2", true, "hard");
    probe["selected"]["containment"]["supported"] = json!(false);
    assert!(capability::require_certified_hard_backend(&probe, "linux-cgroup-v2").is_err());

    probe["selected"] = backend_capability("linux-cgroup-v2", true, "hard");
    probe["schema_version"] = json!(1);
    assert!(capability::require_certified_hard_backend(&probe, "linux-cgroup-v2").is_err());
}

fn backend_capability(name: &str, memory_supported: bool, memory_class: &str) -> serde_json::Value {
    json!({
        "name": name,
        "containment": { "supported": true, "reason": null },
        "boundary": {
            "class": "standard",
            "mechanism": "fixture",
            "target_gated": true,
            "boundary_verified_before_authorization": true,
            "target_can_reconfigure_boundary": true,
            "frontend_loss_cleanup_authority": false,
            "workload_empty_proof": true,
            "limitations": []
        },
        "memory": {
            "supported": memory_supported,
            "class": memory_class,
            "metric": "linux-cgroup-memory",
            "reason": null
        },
        "deadline": { "supported": true, "reason": null },
        "restart": { "supported": true, "reason": null },
        "deadline_scopes": ["attempt", "supervision"],
        "deadline_origin": "installed-cli-release-byte",
        "restart_conditions": ["memory-limit", "deadline"],
        "persistent_restart_state": false,
        "startup_containment": "gated launcher assigned before exec",
        "restart_cleanup_condition": "workload empty",
        "limitations": []
    })
}
