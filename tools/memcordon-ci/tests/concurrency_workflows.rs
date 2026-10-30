use memcordon_ci::workflow_definitions;
use serde_yaml::Value;

#[test]
fn readiness_download_retry_is_terminal_and_stays_within_six_minutes() {
    let workflow = workflow_definitions::definition("release.yml").unwrap();
    let steps = workflow["jobs"]["native-macos-x64"]["steps"]
        .as_sequence()
        .unwrap();
    let first = steps
        .iter()
        .position(|step| step["id"].as_str() == Some("test-tools-download"))
        .unwrap();
    let initial = &steps[first];
    let retry = &steps[first + 1];
    let extract = &steps[first + 2];
    assert_eq!(initial["timeout-minutes"].as_u64(), Some(3));
    assert_eq!(retry["timeout-minutes"].as_u64(), Some(3));
    assert_eq!(initial["with"], retry["with"]);
    assert_eq!(initial["continue-on-error"], Value::Bool(true));
    assert!(retry["continue-on-error"].is_null());
    assert_eq!(
        retry["if"].as_str(),
        Some("!cancelled() && steps.test-tools-download.outcome == 'failure'")
    );
    assert_eq!(extract["id"].as_str(), Some("test-tools-extract"));
    assert!(extract["if"].is_null());
    // Model the emitted outcome guard and default success gate, including the
    // first step's masked conclusion. A log line or existing file is no input.
    for (first_outcome, retry_outcome, cancelled, want_retry, want_extract) in [
        ("failure", "success", false, true, true),
        ("failure", "failure", false, true, false),
        ("success", "skipped", false, false, true),
        ("failure", "skipped", true, false, false),
        ("skipped", "skipped", false, false, false),
    ] {
        let selected = !cancelled && first_outcome == "failure";
        let required_success = if selected {
            retry_outcome == "success"
        } else {
            first_outcome == "success"
        };
        assert_eq!(selected, want_retry);
        assert_eq!(!cancelled && required_success, want_extract);
    }
    for mutation in 0..12 {
        rejects(workflow.clone(), |value| {
            let steps = value["jobs"]["native-macos-x64"]["steps"]
                .as_sequence_mut()
                .unwrap();
            match mutation {
                0 => steps[first]["continue-on-error"] = Value::Bool(false),
                1 => steps[first + 1]["continue-on-error"] = Value::Bool(true),
                2 => steps[first]["timeout-minutes"] = Value::from(4),
                3 => steps[first + 1]["timeout-minutes"] = Value::from(4),
                4 => {
                    steps[first + 1]["if"] = Value::String(
                        "!cancelled() && steps.test-tools-download.conclusion == 'failure'".into(),
                    )
                }
                5 => steps[first + 1]["with"]["artifact-ids"] = Value::String("other".into()),
                6 => steps[first + 1]["with"]["path"] = Value::String("other".into()),
                7 => steps[first + 1]["with"]["digest-mismatch"] = Value::String("ignore".into()),
                8 => steps[first + 1]["with"]["merge-multiple"] = Value::Bool(true),
                9 => steps[first + 2]["if"] = Value::String("always()".into()),
                10 => steps.swap(first + 1, first + 2),
                _ => {
                    let duplicate = steps[first].clone();
                    steps.insert(first, duplicate);
                }
            }
        });
    }
}

#[track_caller]
fn rejects(mut workflow: Value, mutation: impl FnOnce(&mut Value)) {
    let original = workflow.clone();
    mutation(&mut workflow);
    assert_ne!(
        workflow, original,
        "workflow mutation must change its input"
    );
    assert!(workflow_definitions::validate_semantics(&workflow).is_err());
}

#[test]
fn quality_and_security_leaves_are_independent_and_required() {
    for file in ["ci.yml", "release.yml"] {
        let workflow = workflow_definitions::definition(file).unwrap();
        let docs = if file == "ci.yml" {
            "quality-docs"
        } else {
            "source-docs"
        };
        rejects(workflow.clone(), |v| {
            v["jobs"][docs]["needs"] = Value::String("quality".into())
        });
        rejects(workflow.clone(), |v| {
            v["jobs"]["supply-chain-deny"]["needs"] = Value::String("supply-chain-audit".into())
        });
        rejects(workflow.clone(), |v| {
            let job = v["jobs"]["supply-chain-audit"].clone();
            v["jobs"]
                .as_mapping_mut()
                .unwrap()
                .insert(Value::String("supply-chain".into()), job);
        });
        rejects(workflow.clone(), |v| {
            v["jobs"]
                .as_mapping_mut()
                .unwrap()
                .remove(Value::String(docs.into()));
        });
        if file == "release.yml" {
            rejects(workflow, |v| {
                v["jobs"]["assemble"]["needs"]
                    .as_sequence_mut()
                    .unwrap()
                    .retain(|n| n.as_str() != Some("source-docs"))
            });
        }
    }
}

#[test]
fn matrices_preserve_peer_retention_and_native_validation_requires_success() {
    for file in workflow_definitions::FILES {
        let workflow = workflow_definitions::definition(file).unwrap();
        for (id, job) in workflow["jobs"].as_mapping().unwrap() {
            if job["strategy"]["matrix"].is_mapping() {
                rejects(workflow.clone(), |v| {
                    v["jobs"][id]["strategy"]["fail-fast"] = Value::Bool(true)
                });
            }
            let Some(steps) = job["steps"].as_sequence() else {
                continue;
            };
            for (index, step) in steps.iter().enumerate() {
                if step["run"]
                    .as_str()
                    .is_some_and(|run| run.contains(" release compile-target "))
                {
                    rejects(workflow.clone(), |v| {
                        v["jobs"][id]["steps"][index]["continue-on-error"] = Value::Bool(true)
                    });
                    rejects(workflow.clone(), |v| {
                        v["jobs"][id]["steps"]
                            .as_sequence_mut()
                            .unwrap()
                            .remove(index);
                    });
                }
                if step["run"]
                    .as_str()
                    .is_some_and(|run| run.contains(" release validate-package "))
                {
                    rejects(workflow.clone(), |v| {
                        v["jobs"][id]["steps"][index]["if"] = Value::String("always()".into())
                    });
                }
            }
        }
    }
}

#[test]
fn actual_release_yaml_requires_same_host_helper_and_native_success() {
    let workflow: Value =
        serde_yaml::from_str(&workflow_definitions::render("release.yml").unwrap()).unwrap();
    for host in [
        "linux-x64",
        "linux-arm64",
        "macos-x64",
        "macos-arm64",
        "windows-x64",
        "windows-arm64",
    ] {
        let prep = format!("test-tools-{host}");
        let native = format!("native-{host}");
        rejects(workflow.clone(), |v| {
            v["jobs"]
                .as_mapping_mut()
                .unwrap()
                .remove(Value::String(prep.clone()));
        });
        rejects(workflow.clone(), |v| {
            v["jobs"][&native]["needs"]
                .as_sequence_mut()
                .unwrap()
                .retain(|need| need.as_str() != Some(&prep));
        });
        let steps = workflow["jobs"][&native]["steps"].as_sequence().unwrap();
        let download = steps
            .iter()
            .position(|step| step["id"].as_str() == Some("test-tools-download"))
            .unwrap();
        rejects(workflow.clone(), |v| {
            v["jobs"][&native]["steps"][download]["with"]["artifact-ids"] =
                Value::String("unrelated-id".into());
        });
        let check = steps
            .iter()
            .position(|step| step["id"].as_str() == Some("test-tools-check"))
            .unwrap();
        rejects(workflow.clone(), |v| {
            v["jobs"][&native]["steps"][check]["continue-on-error"] = Value::Bool(true);
        });
        rejects(workflow.clone(), |v| {
            v["jobs"][&native]["steps"][check]["if"] = Value::String("always()".into());
        });
        for (name, job) in workflow["jobs"].as_mapping().unwrap() {
            let name = name.as_str().unwrap();
            if !name.starts_with(&format!("candidate-{host}-"))
                && !name.starts_with(&format!("installed-{host}-"))
            {
                continue;
            }
            assert!(
                job["needs"]
                    .as_sequence()
                    .unwrap()
                    .iter()
                    .any(|need| need.as_str() == Some(&native))
            );
            rejects(workflow.clone(), |v| {
                v["jobs"][name]["needs"]
                    .as_sequence_mut()
                    .unwrap()
                    .retain(|need| need.as_str() != Some(&native));
            });
        }
    }
}
