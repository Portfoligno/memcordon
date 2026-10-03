#![cfg(feature = "test-fixtures")]

use memcordon_testkit::run_with_deadline_output_limit;
use serde_json::Value;
use std::{process::Command, time::Duration};

fn observe(mode: &str) -> (i32, Vec<Value>) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_memcordon-test-fixture"));
    command.arg(mode);
    let output =
        run_with_deadline_output_limit(&mut command, Duration::from_secs(10), 64 * 1024).unwrap();
    assert!(output.stderr.is_empty(), "{output:?}");
    let rows = std::str::from_utf8(&output.stdout)
        .unwrap()
        .lines()
        .map(|line| {
            memcordon_core::workload_contract::reject_duplicate_json_keys(line.as_bytes()).unwrap();
            let value: Value = serde_json::from_str(line).unwrap();
            assert_eq!(value["format"], "memcordon.prebound-listener");
            assert_eq!(value["revision"], 1);
            value
        })
        .collect();
    (output.status.code().unwrap(), rows)
}

#[test]
fn prebound_listener_remains_owned_through_exact_readiness() {
    let (status, rows) = observe("prebound-listener-owned");
    assert_eq!(status, 0);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["state"], "ready");
    assert_eq!(rows[0]["competitor"], "address-in-use");
    let port = rows[0]["bound_port"].as_u64().unwrap();
    assert!((1..=u16::MAX as u64).contains(&port));
    assert_eq!(rows[1]["bound_port"].as_u64(), Some(port));
    assert_eq!(rows[1]["state"], "completed");
    assert_eq!(rows[1]["http_body"], "owned");
    assert_eq!(rows[1]["server_joined"], true);
}

#[test]
fn prebound_listener_policy_failure_is_typed_before_readiness() {
    let (status, rows) = observe("prebound-listener-policy-failure");
    assert_eq!(status, 42);
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row["state"], "listener-policy-failure");
    assert_eq!(row["readiness_emitted"], false);
    assert_eq!(row["dispatch_started"], false);
    let bound = row["bound_port"].as_u64().unwrap();
    let requested = row["requested_port"].as_u64().unwrap();
    assert!((1..=u16::MAX as u64).contains(&bound));
    assert!((1..=u16::MAX as u64).contains(&requested));
    assert_ne!(bound, requested);
}
