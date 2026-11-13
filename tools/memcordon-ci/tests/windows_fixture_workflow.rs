use memcordon_ci::workflow_definitions::{definition, validate_semantics};
use serde_yaml::Value;

fn document() -> Value {
    let document = definition("ci.yml").unwrap();
    validate_semantics(&document).unwrap();
    document
}

#[test]
fn targeted_native_fixture_executes_independently_of_workspace_build_and_fetch() {
    let document = document();
    let lane = &document["jobs"]["windows-fixture-native"];
    assert!(lane["needs"].is_null());
    let rows = lane["strategy"]["matrix"]["include"].as_sequence().unwrap();
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .any(|row| row["id"] == "windows-x64" && row["runner"] == "windows-2025")
    );
    assert!(
        rows.iter()
            .any(|row| row["id"] == "windows-arm64" && row["runner"] == "windows-11-arm")
    );
    let steps = lane["steps"].as_sequence().unwrap();
    assert!(
        steps
            .iter()
            .any(|step| step["id"] == "windows-fixture-native")
    );
    assert!(!steps.iter().any(|step| {
        step["run"].as_str().is_some_and(|run| {
            run.ends_with(" ci segment workspace-fetch") || run.contains(" ci segment native-")
        })
    }));
    assert!(
        document["jobs"]["native"]["steps"]
            .as_sequence()
            .unwrap()
            .iter()
            .any(|step| step["id"] == "native-compile")
    );
}

#[test]
fn required_fixture_work_cannot_be_gated_skipped_softened_or_replaced() {
    let baseline = document();
    for (field, value) in [
        ("if", Value::Bool(false)),
        ("continue-on-error", Value::Bool(true)),
        ("timeout-minutes", Value::Number(1.into())),
    ] {
        let mut changed = baseline.clone();
        let step = changed["jobs"]["windows-fixture-native"]["steps"]
            .as_sequence_mut()
            .unwrap()
            .iter_mut()
            .find(|step| step["id"] == "windows-fixture-native")
            .unwrap();
        step[field] = value;
        assert_ne!(changed, baseline);
        assert!(validate_semantics(&changed).is_err());
    }
    let mut gated = baseline.clone();
    gated["jobs"]["windows-fixture-native"]["needs"] =
        Value::Sequence(vec![Value::String("native".into())]);
    assert_ne!(gated, baseline);
    assert!(validate_semantics(&gated).is_err());
    let mut missing = baseline.clone();
    missing["jobs"]["windows-fixture-native"]["steps"]
        .as_sequence_mut()
        .unwrap()
        .retain(|step| step["id"] != "windows-fixture-native");
    assert_ne!(missing, baseline);
    assert!(validate_semantics(&missing).is_err());
    let mut wrong_host = baseline.clone();
    wrong_host["jobs"]["windows-fixture-native"]["strategy"]["matrix"]["include"][0]["runner"] =
        Value::String("ubuntu-24.04".into());
    assert_ne!(wrong_host, baseline);
    assert!(validate_semantics(&wrong_host).is_err());
}

#[test]
fn fixture_host_identity_and_narrow_work_do_not_replace_workspace_native_phases() {
    let baseline = document();
    let work = baseline["jobs"]["windows-fixture-native"]["steps"]
        .as_sequence()
        .unwrap()
        .iter()
        .position(|step| step["id"] == "windows-fixture-native")
        .unwrap();
    for mutation in 0..10 {
        let mut changed = baseline.clone();
        let lane = &mut changed["jobs"]["windows-fixture-native"];
        match mutation {
            0 => lane["if"] = false.into(),
            1 => lane["continue-on-error"] = true.into(),
            2 => lane["runs-on"] = "windows-2025".into(),
            3 => {
                let row = lane["strategy"]["matrix"]["include"][0].clone();
                lane["strategy"]["matrix"]["include"][1] = row;
            }
            4 => {
                lane["strategy"]["matrix"]["include"]
                    .as_sequence_mut()
                    .unwrap()
                    .pop();
            }
            5 => lane["steps"][work]["id"] = "unrelated".into(),
            6 => {
                let duplicate = lane["steps"][work].clone();
                lane["steps"].as_sequence_mut().unwrap().push(duplicate);
            }
            7 => lane["steps"][work]["continue-on-error"] = "${{ always() }}".into(),
            8 => {
                let mut extra = lane["steps"][work].clone();
                extra["id"] = "unrelated-work".into();
                extra["run"] =
                    "./target/ci-runtime/current/memcordon-ci.exe ci segment workspace-fetch"
                        .into();
                lane["steps"].as_sequence_mut().unwrap().push(extra);
            }
            _ => changed["jobs"]["native"]["steps"]
                .as_sequence_mut()
                .unwrap()
                .retain(|step| step["id"] != "native-compile"),
        }
        assert_ne!(
            changed, baseline,
            "fixture mutation {mutation} must change the graph"
        );
        assert!(
            validate_semantics(&changed).is_err(),
            "fixture mutation {mutation}"
        );
    }
}
