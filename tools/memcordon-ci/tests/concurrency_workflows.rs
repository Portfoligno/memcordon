use memcordon_ci::workflow_definitions;
use serde_yaml::Value;

fn rejects(mut workflow: Value, mutation: impl FnOnce(&mut Value)) {
    mutation(&mut workflow);
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
                }
                if step["run"]
                    .as_str()
                    .is_some_and(|run| run.contains(" release validate-package "))
                {
                    rejects(workflow.clone(), |v| {
                        v["jobs"][id]["steps"][index]["if"] = Value::String("always()".into())
                    });
                    rejects(workflow.clone(), |v| {
                        v["jobs"][id]["steps"]
                            .as_sequence_mut()
                            .unwrap()
                            .retain(|s| {
                                !s["run"]
                                    .as_str()
                                    .is_some_and(|run| run.contains(" release compile-target "))
                            });
                    });
                }
            }
        }
    }
}

#[test]
fn split_quality_cache_roots_cannot_import_mixed_archives() {
    use memcordon_ci::cache_restore::roots;
    assert_eq!(
        roots("quality-compiler-v1", "complete").unwrap(),
        [std::path::PathBuf::from("target/ci/quality")]
    );
    assert_eq!(
        roots("quality-documentation-v1", "complete").unwrap(),
        [std::path::PathBuf::from("target/ci/quality-doc")]
    );
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
        let prep = format!("readiness-tools-{host}");
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
            .position(|step| step["id"].as_str() == Some("readiness-tools-download"))
            .unwrap();
        rejects(workflow.clone(), |v| {
            v["jobs"][&native]["steps"][download]["with"]["artifact-ids"] =
                Value::String("unrelated-id".into());
        });
        let check = steps
            .iter()
            .position(|step| step["id"].as_str() == Some("readiness-tools-check"))
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
