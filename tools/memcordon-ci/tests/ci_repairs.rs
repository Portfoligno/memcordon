use memcordon_ci::workflow_definitions;
use serde_yaml::Value;

#[test]
fn narrow_checks_remain_independent_with_required_formatting() {
    let baseline = workflow_definitions::definition("ci.yml").unwrap();
    let mut blocked = baseline.clone();
    blocked["jobs"]["policy"]["needs"] = Value::String("source-seed".into());
    assert!(workflow_definitions::validate_semantics(&blocked).is_err());
    let mut missing_format = baseline.clone();
    let steps = missing_format["jobs"]["format"]["steps"]
        .as_sequence_mut()
        .unwrap();
    let index = steps
        .iter()
        .position(|step| {
            step["run"]
                .as_str()
                .is_some_and(|run| run.ends_with("cargo fmt --all -- --check"))
        })
        .unwrap();
    steps.remove(index);
    assert!(workflow_definitions::validate_semantics(&missing_format).is_err());
}
