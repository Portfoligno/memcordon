use memcordon_ci::{config, policy};
use serde_yaml::Value;
use std::path::{Path, PathBuf};

const BACKEND: &str = ".github/workflows/backend-certification.yml";
const JOBS: [(&str, &str); 3] = [
    (BACKEND, "standard-linux"),
    (BACKEND, "standard-windows"),
    (BACKEND, "standard-windows-arm64"),
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
fn selected_macos_forms_and_windows_channels_fail_closed_on_missing_work() {
    let original = fixture(BACKEND);
    for job in [
        "macos-combined",
        "macos-native",
        "macos-acceptance",
        "macos-assessment",
        "windows-payload-x64",
        "windows-payload-arm64",
        "windows-installed-x64",
        "windows-installed-arm64",
    ] {
        let mut changed = original.clone();
        changed["jobs"]
            .as_mapping_mut()
            .unwrap()
            .remove(Value::String(job.into()));
        rejected(
            BACKEND,
            &changed,
            "omitted selected native phase or channel",
        );
    }
    let mut changed = original.clone();
    changed["jobs"]["macos-native"]["if"] =
        Value::String("needs.macos-performance-plan.outputs.split == 'false'".into());
    rejected(BACKEND, &changed, "noncomplementary Mac selection");
    let mut changed = original.clone();
    changed["jobs"]["macos-acceptance"]["strategy"]["matrix"]["include"]
        .as_sequence_mut()
        .unwrap()
        .pop();
    rejected(BACKEND, &changed, "missing Mac architecture");
    let mut changed = original.clone();
    changed["jobs"]["macos-assessment"]["if"] = Value::String("success()".into());
    rejected(BACKEND, &changed, "skipped failed Mac phase assessment");
    let mut changed = original.clone();
    changed["jobs"]["windows-installed-arm64"]["strategy"]["matrix"]["include"][1]["channel"] =
        Value::String("native".into());
    rejected(BACKEND, &changed, "duplicate channel replacing Cargo");
    let mut changed = original.clone();
    changed["jobs"]["windows-installed-x64"]["needs"] =
        Value::String("windows-payload-arm64".into());
    rejected(BACKEND, &changed, "wrong architecture producer");
}

#[test]
fn deleting_each_standard_job_rejects_with_other_native_jobs_intact() {
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
        for (_, other) in JOBS {
            if other != job {
                assert_eq!(changed["jobs"][other], original["jobs"][other]);
            }
        }
        rejected(path, &changed, job);
    }
}

#[test]
fn standard_suite_cannot_be_removed_substituted_skipped_or_ignore_failure() {
    for (path, job) in JOBS {
        let original = fixture(path);
        for mutation in [
            "delete",
            "sealed-substitution",
            "cache-skip",
            "continue-on-error",
        ] {
            let mut changed = original.clone();
            let steps = steps(&mut changed, job);
            let suite = suite_index(steps);
            match mutation {
                "delete" => {
                    steps.remove(suite);
                }
                "sealed-substitution" => {
                    steps[suite]["run"] = Value::String(
                        "./target/ci/release/memcordon-ci suite backend-linux-sealed-v2".into(),
                    )
                }
                "cache-skip" => {
                    steps[suite]["if"] =
                        Value::String("steps.standard-deps.outputs.cache-hit != 'true'".into())
                }
                "continue-on-error" => steps[suite]["continue-on-error"] = Value::Bool(true),
                _ => unreachable!(),
            }
            rejected(path, &changed, mutation);
        }
    }
}

#[test]
fn actual_driver_build_must_precede_the_native_suite() {
    for (path, job) in JOBS {
        let mut changed = fixture(path);
        let steps = steps(&mut changed, job);
        let suite = suite_index(steps);
        let build = steps
            .iter()
            .position(|step| step["name"] == "Build ordinary CI driver")
            .unwrap();
        steps.swap(build, suite);
        rejected(path, &changed, "suite-before-driver-build");
    }
}
