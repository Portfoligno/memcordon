use memcordon_ci::workflow_definitions;
use serde_yaml::Value;
use std::path::{Path, PathBuf};

fn workflow() -> Value {
    workflow_definitions::definition("release.yml").unwrap()
}
#[track_caller]
fn rejects(value: Value, change: impl FnOnce(&mut Value)) {
    rejects_named(value, &std::panic::Location::caller().to_string(), change);
}
fn rejects_named(mut value: Value, context: &str, change: impl FnOnce(&mut Value)) {
    change(&mut value);
    assert!(
        workflow_definitions::validate_semantics(&value).is_err(),
        "accepted hostile workflow mutation: {context}"
    );
}
fn step(workflow: &Value, job: &str, needle: &str) -> usize {
    workflow["jobs"][job]["steps"]
        .as_sequence()
        .unwrap()
        .iter()
        .position(|step| step["run"].as_str().is_some_and(|run| run.contains(needle)))
        .unwrap()
}

#[test]
fn aggregate_requires_all_source_bound_independent_owners() {
    let original = workflow();
    workflow_definitions::validate_semantics(&original).unwrap();
    for dependency in [
        "native-macos-x64-plan",
        "native-macos-x64-product",
        "native-macos-x64-shard-0",
        "native-macos-x64-shard-1",
        "native-macos-x64-shard-2",
        "native-macos-x64-shard-3",
    ] {
        rejects(original.clone(), |value| {
            value["jobs"]["native-macos-x64"]["needs"]
                .as_sequence_mut()
                .unwrap()
                .retain(|item| item.as_str() != Some(dependency));
        });
        rejects(original.clone(), |value| {
            value["jobs"]
                .as_mapping_mut()
                .unwrap()
                .remove(Value::String(dependency.into()));
        });
    }
    rejects(original.clone(), |value| {
        value["jobs"]["native-macos-x64-shard-0"]["strategy"]["matrix"]["include"]
            .as_sequence_mut()
            .unwrap()
            .pop();
    });
    rejects(original.clone(), |value| {
        value["jobs"]["native-macos-x64-shard-1"]["strategy"]["matrix"]["include"][0]["shard"] =
            Value::Number(1.into());
    });
    rejects(original.clone(), |value| {
        value["jobs"]["native-macos-x64-shard-2"]["outputs"] =
            serde_yaml::from_str("artifact-id: '${{ steps.payload.outputs.artifact-id }}'")
                .unwrap();
    });
    rejects(original.clone(), |value| {
        value["jobs"]["native-macos-x64-product"]["strategy"]["matrix"]["include"][0]["target"] =
            Value::String("aarch64-apple-darwin".into());
    });
    rejects(original, |value| {
        value["jobs"]["native-macos-x64"]["if"] = Value::String("always()".into());
    });
}

#[test]
fn exact_recipes_and_plan_transport_cannot_be_substituted_or_soft_failed() {
    let original = workflow();
    for (job, recipe) in [
        ("native-macos-x64-plan", " release native-coverage-plan "),
        ("native-macos-x64-product", " release compile-target "),
        (
            "native-macos-x64-shard-0",
            " release native-coverage-shard ",
        ),
        (
            "native-macos-x64-shard-1",
            " release native-coverage-shard ",
        ),
        (
            "native-macos-x64-shard-2",
            " release native-coverage-shard ",
        ),
        (
            "native-macos-x64-shard-3",
            " release native-coverage-shard ",
        ),
        ("native-macos-x64", " release validate-package "),
    ] {
        let index = step(&original, job, recipe);
        rejects(original.clone(), |value| {
            value["jobs"][job]["steps"][index]["continue-on-error"] = Value::Bool(true);
        });
        rejects(original.clone(), |value| {
            value["jobs"][job]["steps"][index]["continue-on-error"] =
                Value::String("${{ true }}".into());
        });
        rejects(original.clone(), |value| {
            value["jobs"][job]["continue-on-error"] = Value::String("${{ true }}".into());
        });
        let steps = original["jobs"][job]["steps"].as_sequence().unwrap();
        for (witness, item) in steps.iter().enumerate() {
            let action = item["uses"].as_str().unwrap_or("");
            let bound_download = action.starts_with("actions/download-artifact@")
                && (item["with"]["artifact-ids"].as_str().is_some_and(|ids| {
                    ids.contains("needs.select.outputs.selection-artifact-id")
                        || ids.contains("needs.native-macos-x64-")
                }) || item["with"]["name"]
                    .as_str()
                    .is_some_and(|name| name.starts_with("native-coverage-")));
            let bound_upload = action.starts_with("actions/upload-artifact@")
                && item["id"].as_str() == Some("payload");
            if action.starts_with("actions/checkout@") || bound_download || bound_upload {
                rejects_named(
                    original.clone(),
                    &format!("{job}: step {witness} {action} expression soft failure"),
                    |value| {
                        value["jobs"][job]["steps"][witness]["continue-on-error"] =
                            Value::String("${{ true }}".into());
                    },
                );
            }
            if action.starts_with("actions/checkout@") {
                rejects(original.clone(), |value| {
                    value["jobs"][job]["steps"][witness]["if"] = Value::String("false".into());
                });
            }
        }
        rejects(original.clone(), |value| {
            let run = value["jobs"][job]["steps"][index]["run"]
                .as_str()
                .unwrap()
                .replace(".release/build-source.json", ".release/foreign-source.json");
            value["jobs"][job]["steps"][index]["run"] = Value::String(run);
        });
        if job != "native-macos-x64-plan" {
            let download = original["jobs"][job]["steps"]
                .as_sequence()
                .unwrap()
                .iter()
                .position(|step| {
                    step["with"]["artifact-ids"].as_str()
                        == Some("${{ needs.native-macos-x64-plan.outputs.artifact-id }}")
                })
                .unwrap();
            rejects(original.clone(), |value| {
                value["jobs"][job]["steps"][download]["with"]["artifact-ids"] =
                    Value::String("foreign-plan".into());
            });
        }
    }
    let product = step(
        &original,
        "native-macos-x64-product",
        " release compile-target ",
    );
    let shard = step(
        &original,
        "native-macos-x64-shard-1",
        " release native-coverage-shard ",
    );
    rejects(original.clone(), |value| {
        let run = value["jobs"]["native-macos-x64-shard-1"]["steps"][shard]["run"]
            .as_str()
            .unwrap()
            .replace("--shard 1", "--shard 0");
        value["jobs"]["native-macos-x64-shard-1"]["steps"][shard]["run"] = Value::String(run);
    });
    rejects(original.clone(), |value| {
        let run = value["jobs"]["native-macos-x64-product"]["steps"][product]["run"]
            .as_str()
            .unwrap()
            .replace(" --product-only", "");
        value["jobs"]["native-macos-x64-product"]["steps"][product]["run"] = Value::String(run);
    });
    let download = original["jobs"]["native-macos-x64"]["steps"]
        .as_sequence()
        .unwrap()
        .iter()
        .position(|step| step["with"]["path"].as_str() == Some(".release/native-coverage/3"))
        .unwrap();
    rejects(original, |value| {
        value["jobs"]["native-macos-x64"]["steps"][download]["with"]["name"] =
            Value::String("native-coverage-old-run".into());
    });
}

#[test]
fn legacy_projection_requires_each_exact_authored_owner() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let configuration = memcordon_ci::config::policy(&root).unwrap();
    let source = workflow_definitions::render("release.yml").unwrap();
    for owner in [
        "native-macos-x64-plan",
        "native-macos-x64-product",
        "native-macos-x64-shard-0",
        "native-macos-x64-shard-1",
        "native-macos-x64-shard-2",
        "native-macos-x64-shard-3",
        "native-macos-x64",
    ] {
        let heading = format!("  {owner}:\n");
        assert_eq!(source.matches(&heading).count(), 1);
        let changed = source.replacen(
            &heading,
            &format!("{heading}    name: Unreviewed owner\n"),
            1,
        );
        let value: Value = serde_yaml::from_str(&changed).unwrap();
        workflow_definitions::validate_semantics(&value).unwrap();
        let error = memcordon_ci::policy::validate_workflow_bytes(
            &root,
            Path::new(".github/workflows/release.yml"),
            changed.as_bytes(),
            &configuration,
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("distributed native owner differs from reviewed source")
                || (owner == "native-macos-x64"
                    && message.contains("readiness preparation graph differs: native-macos-x64")),
            "{owner}: {error}"
        );
    }
}
