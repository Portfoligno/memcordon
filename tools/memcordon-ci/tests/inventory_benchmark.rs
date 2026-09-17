use memcordon_ci::inventory_benchmark::{ScanRequest, scan};
#[test]
fn report_inside_input_is_rejected_before_creating_it() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("inputs");
    std::fs::create_dir(&root).unwrap();
    let request = ScanRequest {
        schema: 1,
        profile: "full-tree-v1".into(),
        corpus_identity: "fixture".into(),
        roots: vec![root.canonicalize().unwrap()],
        audits: 0,
    };
    let path = temp.path().join("request.json");
    std::fs::write(&path, serde_json::to_vec(&request).unwrap()).unwrap();
    let output = root.join("forbidden");
    assert!(scan(&path, &output).is_err());
    assert!(!output.exists());
}
#[test]
fn scan_report_keeps_initial_and_audit_phases_and_full_manifest() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("inputs");
    let output = temp.path().join("reports");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("empty"), b"").unwrap();
    std::fs::write(root.join("file"), b"inventory bytes").unwrap();
    let request = ScanRequest {
        schema: 1,
        profile: "full-tree-v1".into(),
        corpus_identity: "fixture".into(),
        roots: vec![root.canonicalize().unwrap()],
        audits: 1,
    };
    let path = temp.path().join("request.json");
    std::fs::write(&path, serde_json::to_vec(&request).unwrap()).unwrap();
    scan(&path, &output).unwrap();
    let result: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output.join("outcome.json")).unwrap()).unwrap();
    assert_eq!(result["inventory_complete"], true);
    assert_eq!(result["cache_eligible"], false);
    let phases = std::fs::read_to_string(output.join("phases.jsonl")).unwrap();
    let phases: Vec<serde_json::Value> = phases
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(phases.len(), 2);
    assert_eq!(phases[0]["phase"], "initial");
    assert_eq!(phases[1]["phase"], "audit");
    assert!(output.join("0.manifest.json").exists());
}
#[test]
fn finite_runner_executes_exact_schedule_and_compares_complete_identities() {
    use memcordon_ci::inventory_benchmark::{Plan, Variant, benchmark, file_sha256};
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("inputs");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("file"), b"same bytes").unwrap();
    let binary = std::path::PathBuf::from(env!("CARGO_BIN_EXE_memcordon-ci"));
    let plan = Plan {
        schema: 1,
        request: ScanRequest {
            schema: 1,
            profile: "full-tree-v1".into(),
            corpus_identity: "immutable-test-fixture".into(),
            roots: vec![root.canonicalize().unwrap()],
            audits: 1,
        },
        variants: vec![Variant {
            name: "current".into(),
            sha256: file_sha256(&binary).unwrap(),
            binary,
        }],
        order: vec![0, 0],
        child_budget_seconds: 30,
        instance_provenance: "same-test-process-planned-order".into(),
    };
    let plan_path = temp.path().join("plan.json");
    std::fs::write(&plan_path, serde_json::to_vec(&plan).unwrap()).unwrap();
    let output = temp.path().join("comparison");
    benchmark(&plan_path, &output).unwrap();
    let result: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output.join("comparison.json")).unwrap()).unwrap();
    assert_eq!(result["complete"], true);
    assert_eq!(result["qualified"], true);
    assert_eq!(result["observations"].as_array().unwrap().len(), 2);
    assert_eq!(result["cache_equivalence"], "not_established");
}
