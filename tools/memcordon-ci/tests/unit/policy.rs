use super::*;

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

#[test]
fn ordinary_workflows_do_not_restore_retired_self_hosted_runner_exceptions() {
    let root = repository_root();
    let policy = config::policy(&root).unwrap();
    for (job_name, runner) in [
        ("linux-private-q-x64", "[self-hosted, linux]"),
        (
            "windows-prior-boot",
            "[self-hosted, Windows, prior-boot-controller, '${{ matrix.id }}']",
        ),
    ] {
        let mut document: Value =
            serde_yaml::from_slice(include_bytes!("../../../../.github/workflows/ci.yml"))
                .expect("actual ordinary workflow parses");
        let job: Value = serde_yaml::from_str(&format!("runs-on: {runner}\nsteps: []\n")).unwrap();
        document["jobs"][job_name] = job;
        let bytes = serde_yaml::to_string(&document).unwrap();
        let error = validate_workflow_bytes(
            &root,
            Path::new(".github/workflows/ci.yml"),
            bytes.as_bytes(),
            &policy,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("workflow may not select self-hosted runners"),
            "unexpected rejection for {job_name}: {error}"
        );
    }
}

#[test]
fn malformed_policy_fixture_is_rejected() {
    let malformed = "[workspace]\nproduction_packages = \"not-a-list\"\n";
    assert!(toml::from_str::<config::Policy>(malformed).is_err());
}

#[test]
fn malformed_workflow_fixture_non_scalar_run_is_rejected() {
    let document: Value = serde_yaml::from_str(
        "jobs:\n  check:\n    steps:\n      - run:\n          command: cargo check\n",
    )
    .expect("fixture YAML should parse");
    let jobs = mapping(
        mapping(&document, "workflow")
            .expect("workflow mapping")
            .get(key("jobs"))
            .expect("jobs"),
        "jobs",
    )
    .expect("jobs mapping");
    let step = jobs
        .get(key("check"))
        .and_then(Value::as_mapping)
        .and_then(|job| job.get(key("steps")))
        .and_then(Value::as_sequence)
        .and_then(|steps| steps.first())
        .and_then(Value::as_mapping)
        .expect("step mapping");
    assert!(step.get(key("run")).is_some());
    assert!(scalar(step, "run").is_none());
}

#[test]
fn workflow_shell_operator_fixtures_are_rejected() {
    for command in [
        "cargo check && cargo test",
        "cargo check | tee out",
        "cargo &",
    ] {
        assert!(!static_run_command(command));
    }
    assert!(static_run_command("cargo check --locked"));
}

#[test]
fn workflow_event_fixture_requires_exact_keys() {
    let mapping: Mapping =
        serde_yaml::from_str("push: {}\npull_request_target: {}\n").expect("mapping should parse");
    assert!(exact_mapping_keys(&mapping, &["push", "pull_request"], "events").is_err());
}
