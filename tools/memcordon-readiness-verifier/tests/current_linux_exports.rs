use memcordon_readiness_verifier::{
    CaseKey, EvidenceClass,
    current::{CaseEvidenceV2, linux_exports},
};
use serde_json::{Value, json};

fn evidence() -> CaseEvidenceV2 {
    CaseEvidenceV2 {
        format: "memcordon.consumer-readiness.case".into(),
        revision: 2,
        key: CaseKey {
            target: "x86_64-unknown-linux-gnu".into(),
            channel: Some("native".into()),
            family: "L-IMG-04".into(),
            scenario: "export-symlink".into(),
            evidence_class: EvidenceClass::InstalledProduct,
        },
        run_id: "run".into(),
        source_commit: "a".repeat(40),
        source_tree_sha256: "b".repeat(64),
        lease_id: Some("lease".into()),
        fixture: "fixture".into(),
        fixture_source: "source".into(),
        fixture_sha256: "c".repeat(64),
        fixture_source_sha256: "b".repeat(64),
        input: "input".into(),
        input_sha256: "d".repeat(64),
        invocation: "invocation".into(),
        request: Some("request".into()),
        raw_result: Some("result".into()),
        attempt_observation: Some("locator".into()),
        authenticated_terminal: None,
        recovery: None,
        stdout: "stdout".into(),
        stderr: "stderr".into(),
        outputs: vec![],
        native_observation: "native".into(),
        retirement: "retirement".into(),
        semantic_observation: "semantic".into(),
        component_recipe_id: None,
    }
}

#[test]
fn unsafe_export_requires_original_native_object_and_zero_materialized_outputs() {
    let mut evidence = evidence();
    let result = json!({"outcome":{"native_termination":{"kind":"exit-code","code":0},"wrapper_status":125},"output_delivery":"incomplete"});
    let native = json!({"root_device":1,"root_inode":2,"target_uid":1000,"native_wait_status":0});
    let rows = vec![
        json!({"operation":"export-object-ready","observation":{"kind":"symlink"}}),
        json!({"operation":"export-object-controller-release","observation":{}}),
    ];
    let controller = json!({"export_candidate":{"format":"memcordon.linux-current-export-node","revision":1,
        "scenario":"export-symlink","root":{"device":1,"inode":2},"component":"work/exported.bin",
        "mode":0o120777,"inode":3,"links":1,"uid":1000,"output_empty_before_release":true,
        "symlink_target":b"/owned-source/Cargo.toml"},"rejected_export_output_empty":true});
    let check = |evidence: &CaseEvidenceV2, controller: &Value| {
        linux_exports::verify(evidence, &result, &native, &rows, controller, &|_| {
            Err("unexpected output read".into())
        })
    };
    check(&evidence, &controller).unwrap();
    let mut altered = controller.clone();
    altered["export_candidate"]["root"]["inode"] = 9.into();
    assert!(check(&evidence, &altered).is_err());
    altered = controller.clone();
    altered["rejected_export_output_empty"] = false.into();
    assert!(check(&evidence, &altered).is_err());
    altered = controller.clone();
    altered["export_candidate"]["mode"] = 0o100600.into();
    assert!(check(&evidence, &altered).is_err());
    evidence.outputs.push("outputs/unsafe".into());
    assert!(check(&evidence, &controller).is_err());
}
