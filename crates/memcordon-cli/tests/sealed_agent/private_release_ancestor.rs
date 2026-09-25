#![cfg(target_os = "linux")]

use crate::linux::private_release_ancestor::{AgentPathPreservationV1, SELECTOR};
use crate::linux::private_release_case::{
    candidate_fixture_output_with_native, candidate_fixture_supported,
};

#[test]
fn ancestor_case_requires_pinned_image_identity() {
    assert!(candidate_fixture_supported(SELECTOR));
    assert!(
        crate::linux::private_target::PrivateExecArguments::for_release_candidate_fixture(SELECTOR)
            .is_ok()
    );
    let challenge = [0x4d; 32];
    assert!(candidate_fixture_output_with_native(SELECTOR, &challenge, 7, (0, 9)).is_err());
    let output = candidate_fixture_output_with_native(SELECTOR, &challenge, 7, (8, 9))
        .expect("retained package image");
    assert_eq!(output.len(), challenge.len() + 20);
}

#[test]
fn ancestor_record_cannot_mask_a_changed_component() {
    let node = |component: &str, inode: u64| {
        serde_json::json!({
            "component": component,
            "device": 1,
            "inode": inode,
            "owner_uid": 0,
            "mode": 0o40755,
        })
    };
    let chain = serde_json::json!({
        "schema_version": 1,
        "nodes": [node("/", 1), node("usr", 2), node("libexec", 3), node("memcordon-sealed-agent", 4)],
    });
    let mut record = serde_json::json!({
        "schema_version": 1,
        "before": chain,
        "after": chain,
    });
    let same: AgentPathPreservationV1 = serde_json::from_value(record.clone()).unwrap();
    same.validate().unwrap();
    record["after"]["nodes"][1]["inode"] = serde_json::json!(99);
    let changed: AgentPathPreservationV1 = serde_json::from_value(record).unwrap();
    assert!(changed.validate().is_err());
}
