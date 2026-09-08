use memcordon_ci::{config, policy};
use serde_yaml::Value;
use std::path::{Path, PathBuf};

const BACKEND: &str = ".github/workflows/backend-certification.yml";
const RELEASE: &str = ".github/workflows/release.yml";
const JOBS: [(&str, &str); 4] = [
    (BACKEND, "standard-linux"),
    (BACKEND, "standard-windows"),
    (RELEASE, "linux-standard-certification"),
    (RELEASE, "windows-standard-certification"),
];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn validate(path: &str, workflow: &Value) -> Result<(), memcordon_ci::CiError> {
    let root = root();
    let policy = config::policy(&root).unwrap();
    policy::validate_workflow_bytes(
        &root,
        Path::new(path),
        serde_yaml::to_string(workflow).unwrap().as_bytes(),
        &policy,
    )
}

fn fixture(path: &str) -> Value {
    let source = std::fs::read(root().join(path)).unwrap();
    let workflow: Value = serde_yaml::from_slice(&source).unwrap();
    validate(path, &workflow).expect("the actual parsed workflow must pass before mutation");
    workflow
}

fn steps<'a>(workflow: &'a mut Value, job: &str) -> &'a mut Vec<Value> {
    workflow["jobs"][job]["steps"].as_sequence_mut().unwrap()
}

fn action_index(steps: &[Value], action: &str) -> usize {
    steps
        .iter()
        .position(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|uses| uses.starts_with(action))
        })
        .unwrap()
}

fn suite_index(steps: &[Value]) -> usize {
    steps
        .iter()
        .position(|step| {
            step["run"]
                .as_str()
                .is_some_and(|run| run.split_whitespace().any(|part| part == "suite"))
        })
        .unwrap()
}

fn rejected(path: &str, workflow: &Value, mutation: &str) {
    assert!(
        validate(path, workflow).is_err(),
        "policy accepted {mutation} in {path}"
    );
}

#[test]
fn deleting_each_standard_job_rejects_with_sealed_jobs_intact() {
    for (path, job) in JOBS {
        let original = fixture(path);
        let mut changed = original.clone();
        assert!(
            changed["jobs"]
                .as_mapping_mut()
                .unwrap()
                .remove(Value::String(job.into()))
                .is_some()
        );
        for sealed in if path == RELEASE {
            ["linux-certification", "windows-package-channel"]
        } else {
            ["linux", "windows-package-channel"]
        } {
            assert!(!original["jobs"][sealed].is_null());
            assert_eq!(changed["jobs"][sealed], original["jobs"][sealed]);
        }
        rejected(path, &changed, job);
    }
}

#[test]
fn release_requires_each_standard_assembly_dependency() {
    for required in [
        "linux-standard-certification",
        "windows-standard-certification",
    ] {
        let mut workflow = fixture(RELEASE);
        let needs = workflow["jobs"]["assemble"]["needs"]
            .as_sequence_mut()
            .unwrap();
        let index = needs
            .iter()
            .position(|value| value.as_str() == Some(required))
            .unwrap();
        needs.remove(index);
        assert!(
            needs
                .iter()
                .any(|value| value.as_str() == Some("linux-certification"))
        );
        assert!(
            needs
                .iter()
                .any(|value| value.as_str() == Some("windows-package-channel"))
        );
        rejected(RELEASE, &workflow, required);
    }
}

#[test]
fn standard_certificate_uploads_are_required_and_strict() {
    for (path, job) in JOBS {
        let original = fixture(path);
        for mutation in [
            "delete",
            "missing-file-warning",
            "wrong-artifact",
            "wrong-path",
            "conditional",
            "continue-on-error",
        ] {
            let mut changed = original.clone();
            let steps = steps(&mut changed, job);
            let index = action_index(steps, "actions/upload-artifact@");
            match mutation {
                "delete" => {
                    steps.remove(index);
                }
                "missing-file-warning" => {
                    steps[index]["with"]["if-no-files-found"] = Value::String("warn".into())
                }
                "wrong-artifact" => {
                    steps[index]["with"]["name"] =
                        Value::String("release-certification-linux".into())
                }
                "wrong-path" => {
                    steps[index]["with"]["path"] = Value::String("target/ci/reports/sealed".into())
                }
                "conditional" => steps[index]["if"] = Value::String("always()".into()),
                "continue-on-error" => steps[index]["continue-on-error"] = Value::Bool(true),
                _ => unreachable!(),
            }
            rejected(path, &changed, mutation);
        }
    }
}

#[test]
fn standard_suite_cannot_be_removed_substituted_skipped_or_published_before_running() {
    for (path, job) in JOBS {
        let original = fixture(path);
        for mutation in [
            "delete",
            "sealed-substitution",
            "cache-skip",
            "continue-on-error",
            "upload-before-suite",
        ] {
            let mut changed = original.clone();
            let steps = steps(&mut changed, job);
            let suite = suite_index(steps);
            match mutation {
                "delete" => { steps.remove(suite); }
                "sealed-substitution" => steps[suite]["run"] = Value::String("rustup run 1.97.1 cargo run --locked --target-dir target/ci/bootstrap --package memcordon-ci -- suite linux-sealed".into()),
                "cache-skip" => steps[suite]["if"] = Value::String("steps.standard-target.outputs.cache-hit != 'true'".into()),
                "continue-on-error" => steps[suite]["continue-on-error"] = Value::Bool(true),
                "upload-before-suite" => {
                    let upload = action_index(steps, "actions/upload-artifact@");
                    steps.swap(suite, upload);
                }
                _ => unreachable!(),
            }
            rejected(path, &changed, mutation);
        }
    }
}

#[test]
fn assembly_download_cannot_be_deleted_or_exclude_standard_evidence() {
    for mutation in [
        "delete",
        "sealed-only-pattern",
        "merged-artifacts",
        "wrong-path",
    ] {
        let mut workflow = fixture(RELEASE);
        let steps = steps(&mut workflow, "assemble");
        let download = action_index(steps, "actions/download-artifact@");
        match mutation {
            "delete" => {
                steps.remove(download);
            }
            "sealed-only-pattern" => {
                steps[download]["with"]["pattern"] =
                    Value::String("release-certification-linux".into())
            }
            "merged-artifacts" => steps[download]["with"]["merge-multiple"] = Value::Bool(true),
            "wrong-path" => {
                steps[download]["with"]["path"] = Value::String("target/ci/other-inputs".into())
            }
            _ => unreachable!(),
        }
        rejected(RELEASE, &workflow, mutation);
    }
}

#[test]
fn assembly_download_precedes_assembly_and_bundle_upload_follows_it() {
    for swap_download in [true, false] {
        let mut workflow = fixture(RELEASE);
        let steps = steps(&mut workflow, "assemble");
        let assemble = steps
            .iter()
            .position(|step| {
                step["run"]
                    .as_str()
                    .is_some_and(|run| run.ends_with("release assemble"))
            })
            .unwrap();
        let other = action_index(
            steps,
            if swap_download {
                "actions/download-artifact@"
            } else {
                "actions/upload-artifact@"
            },
        );
        steps.swap(assemble, other);
        rejected(
            RELEASE,
            &workflow,
            if swap_download {
                "assemble-before-download"
            } else {
                "bundle-upload-before-assemble"
            },
        );
    }
}
