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
fn trace_opt_in_cannot_expand_architectures_or_upload_unbounded_working_volume() {
    for mutation in ["x64", "arm64", "upload"] {
        let mut document: Value = serde_yaml::from_str(include_str!(
            "../../../.github/workflows/backend-certification.yml"
        ))
        .unwrap();
        let job = &mut document["jobs"][if mutation == "x64" {
            "windows-loader-production-x64"
        } else {
            "windows-loader-production-arm64"
        }];
        match mutation {
            "x64" | "arm64" => {
                let preparation = job["steps"]
                    .as_sequence_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|step| step["id"] == "build-context-prepare")
                    .unwrap();
                preparation["run"] = if mutation == "x64" { "./ci-native-fingerprint.exe --profile stable --output target/ci/native-inputs.bin --trace-inventory true" } else { "./ci-native-fingerprint.exe --profile stable --output target/ci/native-inputs.bin --trace-inventory false" }.into();
            }
            "upload" => {
                let observation = job["steps"]
                    .as_sequence_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|step| step["id"] == "inventory-observation")
                    .unwrap();
                observation["with"]["path"] =
                    "target/ci/reports/inventory-observation/v1/**\n".into();
            }
            _ => unreachable!(),
        }
        assert!(validate_and_project(&mut document).is_err(), "{mutation}");
    }
}

#[test]
fn trace_volume_qualification_is_required_before_prepare_and_cannot_ignore_failure() {
    for mutation in ["missing", "late", "early", "condition", "ignore"] {
        let mut document: Value = serde_yaml::from_str(include_str!(
            "../../../.github/workflows/backend-certification.yml"
        ))
        .unwrap();
        let steps = document["jobs"]["windows-loader-production-arm64"]["steps"]
            .as_sequence_mut()
            .unwrap();
        let index = steps
            .iter()
            .position(|step| step["id"] == "trace-volume-qualification")
            .unwrap();
        match mutation {
            "missing" => {
                steps.remove(index);
            }
            "late" => steps.swap(index, index + 1),
            "early" => steps.swap(index, index - 1),
            "condition" => steps[index]["if"] = "always()".into(),
            "ignore" => steps[index]["continue-on-error"] = true.into(),
            _ => unreachable!(),
        }
        assert!(validate_and_project(&mut document).is_err(), "{mutation}");
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

#[test]
fn extensionless_bootstrap_cannot_authorize_windows_compiled_cache() {
    for mutation in ["compile", "invoke", "both"] {
        let mut document: Value =
            serde_yaml::from_str(include_str!("../../../.github/workflows/ci.yml")).unwrap();
        let steps = document["jobs"]["native"]["steps"]
            .as_sequence_mut()
            .unwrap();
        for step in steps {
            let Some(run) = step.get_mut("run") else {
                continue;
            };
            let Some(command) = run.as_str() else {
                continue;
            };
            if (mutation != "invoke" && command.contains(" -o ci-native-fingerprint.exe"))
                || (mutation != "compile" && command.starts_with("./ci-native-fingerprint.exe "))
            {
                *run = Value::from(
                    command.replace("ci-native-fingerprint.exe", "ci-native-fingerprint"),
                );
            }
        }
        assert!(
            validate_and_project(&mut document).is_err(),
            "{mutation} must not authorize reuse before Windows executes the bootstrap"
        );
    }
}

#[test]
fn parent_admission_cannot_be_restored_or_bypassed_after_failed_preparation() {
    for mutation in [
        "restore-guard",
        "audit-guard",
        "admission-exclusion",
        "admission-only",
    ] {
        let mut document: Value =
            serde_yaml::from_str(include_str!("../../../.github/workflows/ci.yml")).unwrap();
        let steps = document["jobs"]["quality"]["steps"]
            .as_sequence_mut()
            .unwrap();
        let restore = steps
            .iter()
            .position(|step| step["id"] == "quality-target")
            .unwrap();
        match mutation {
            "restore-guard" => steps[restore]["if"] = Value::from("always()"),
            "audit-guard" => {
                let audit = steps
                    .iter_mut()
                    .find(|step| step["id"] == "build-context-audit")
                    .unwrap();
                audit["if"] = Value::from("always()");
            }
            "admission-exclusion" => {
                steps[restore]["with"]["path"] = Value::from(
                    steps[restore]["with"]["path"]
                        .as_str()
                        .unwrap()
                        .replace("!target/ci/native-inputs.admission.json\n", ""),
                )
            }
            _ => {
                steps[restore]["with"]["path"] =
                    Value::from("target/ci/native-inputs.admission.json")
            }
        }
        assert!(validate_and_project(&mut document).is_err(), "{mutation}");
    }
}
