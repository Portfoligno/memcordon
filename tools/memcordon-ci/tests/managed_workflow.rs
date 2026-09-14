use memcordon_ci::managed_workflow::validate_and_project;
use serde_yaml::Value;

fn release() -> Value {
    serde_yaml::from_str(include_str!("../../../.github/workflows/release.yml")).unwrap()
}

#[test]
fn every_workflow_enrolls_compiled_caches_in_fresh_contexts() {
    for source in [
        include_str!("../../../.github/workflows/ci.yml"),
        include_str!("../../../.github/workflows/deep-ci.yml"),
        include_str!("../../../.github/workflows/backend-certification.yml"),
        include_str!("../../../.github/workflows/release.yml"),
    ] {
        let mut document = serde_yaml::from_str(source).unwrap();
        validate_and_project(&mut document).unwrap();
    }
}

#[test]
fn release_fuzz_cache_cannot_escape_context_order_or_identity() {
    for mutation in [
        "old-key",
        "missing-context",
        "restore-before-plan",
        "unguarded-save",
    ] {
        let mut document = release();
        let steps = document["jobs"]["fuzz"]["steps"].as_sequence_mut().unwrap();
        let restore = steps
            .iter()
            .position(|step| step["id"] == "fuzz-target")
            .unwrap();
        match mutation {
            "old-key" => {
                let key = steps[restore]["with"]["key"]
                    .as_str()
                    .unwrap()
                    .strip_prefix("managed-v2-")
                    .unwrap()
                    .to_owned();
                steps[restore]["with"]["key"] = Value::from(key);
            }
            "missing-context" => {
                let key = steps[restore]["with"]["key"]
                    .as_str()
                    .unwrap()
                    .replace("'target/ci/native-inputs.bin', ", "");
                steps[restore]["with"]["key"] = Value::from(key);
            }
            "restore-before-plan" => {
                let restore = steps.remove(restore);
                steps.insert(0, restore);
            }
            "unguarded-save" => {
                let save = steps
                    .iter_mut()
                    .find(|step| {
                        step["uses"]
                            .as_str()
                            .is_some_and(|action| action.starts_with("actions/cache/save@"))
                    })
                    .unwrap();
                save["if"] = Value::from("always()");
            }
            _ => unreachable!(),
        }
        assert!(
            validate_and_project(&mut document).is_err(),
            "{mutation} must not authorize compiled cache reuse"
        );
    }
}

#[test]
fn bootstrap_binary_and_context_cannot_be_restored_from_broad_targets() {
    let mut document: Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/ci.yml")).unwrap();
    let steps = document["jobs"]["quality"]["steps"]
        .as_sequence_mut()
        .unwrap();
    let restore = steps
        .iter_mut()
        .find(|step| step["id"] == "quality-target")
        .unwrap();
    restore["with"]["path"] = Value::from("target/ci");
    assert!(validate_and_project(&mut document).is_err());
}
