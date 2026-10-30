#![cfg(unix)]
use memcordon_ci::release::linux_snapshot_budget::memory_budget;
use memcordon_core::workload_bundle::SnapshotManifestV1;
use serde_json::json;

fn snapshot(sizes: &[u64]) -> SnapshotManifestV1 {
    SnapshotManifestV1::parse(&serde_json::to_vec(&json!({"format":"memcordon.workload-snapshot","revision":1,"target":"aarch64-unknown-linux-gnu","entries":sizes.iter().enumerate().map(|(index,size)|json!({"kind":"regular","path":format!("member-{index}"),"size":size,"sha256":"01".repeat(32),"executable":false})).collect::<Vec<_>>(),"entrypoints":[],"library_directories":[]})).unwrap()).unwrap()
}

#[test]
fn actual_snapshot_pages_preserve_scenario_headroom_and_match_independent_budget() {
    let runtime = snapshot(&[4097, 0, 1024 * 1024 * 1024]);
    let input = snapshot(&[1]);
    let (token, simple) = memory_budget(&runtime, &input, 128 * 1024 * 1024).unwrap();
    let (_, compiler) = memory_budget(&runtime, &input, 2 * 1024 * 1024 * 1024).unwrap();
    assert_eq!(
        compiler - simple,
        2 * 1024 * 1024 * 1024 - 128 * 1024 * 1024
    );
    assert!(simple > 1024 * 1024 * 1024 + 256 * 1024 * 1024);
    assert_eq!(
        token.to_str().unwrap(),
        format!("+{}MiB", simple / (1024 * 1024))
    );
    assert_eq!(simple, 1281 * 1024 * 1024);
}

#[test]
fn snapshot_budget_rejects_zero_headroom_overflow_and_invalid_current_metadata() {
    let runtime = snapshot(&[1]);
    let input = snapshot(&[]);
    assert!(memory_budget(&runtime, &input, 0).is_err());
    assert!(memory_budget(&runtime, &input, u64::MAX).is_err());
    let mut invalid = runtime;
    invalid.revision = 99;
    assert!(memory_budget(&invalid, &input, 128 * 1024 * 1024).is_err());
}
