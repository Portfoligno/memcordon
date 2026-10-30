use super::*;

#[test]
fn rehearsal_legacy_credentials_are_allowed_only_as_reviewed_removals() {
    let coordinator = Path::new("tools/memcordon-ci/src/rehearsal_support/coordinator.rs");
    let removal = r#"fn sanitize_child(command: &mut Command) {
        for name in ["GITHUB_TOKEN", "CARGO_REGISTRY_TOKEN"] {
            command.env_remove(name);
        }
    }"#;
    let secret_source = ["${{ secrets.", "CARGO_REGISTRY_TOKEN", " }}"].concat();
    validate_legacy_registry_token_source(coordinator, removal).unwrap();
    validate_legacy_registry_token_source(
        coordinator,
        include_str!("../../src/rehearsal_support/coordinator.rs"),
    )
    .unwrap();
    validate_legacy_registry_token_source(
        Path::new("tools/memcordon-ci/tests/release_rehearsal_http.rs"),
        include_str!("../release_rehearsal_http.rs"),
    )
    .unwrap();
    for source in [
        removal.replace("env_remove", "env"),
        removal.replace("command.env_remove(name)", "other.env_remove(name)"),
        removal.replace("sanitize_child", "configure_child"),
        removal.replace("&mut Command", "&mut Other"),
        removal.replace("\"GITHUB_TOKEN\"", "acquire()"),
        removal.replace("command.env_remove(name);", "command.env_remove(name); acquire();"),
        [removal, "fn acquire() { std::env::var(\"CARGO_REGISTRY_TOKEN\"); }"].join("\n"),
        "fn sanitize_child(command: &mut Command) { command.env(\"CARGO_REGISTRY_TOKEN\", \"secret\"); }".into(),
        secret_source.clone(),
    ] {
        assert!(validate_legacy_registry_token_source(coordinator, &source).is_err(), "accepted credential configuration: {source}");
    }
    assert!(
        validate_legacy_registry_token_source(
            Path::new("tools/memcordon-ci/src/release/other.rs"),
            removal,
        )
        .is_err()
    );
    assert!(
        validate_legacy_registry_token_source(Path::new("RELEASING.md"), &secret_source,).is_err()
    );
    assert!(
        validate_rust_policy_bytes(
            Path::new("tools/memcordon-ci/tests/release_rehearsal_transport.rs"),
            br#"fn proxy(command: &mut Command) {
            command.env("HTTP_PROXY", "http://127.0.0.1:1");
            command.env("CUSTOM_PROXY", "unexpected");
        }"#,
        )
        .is_err()
    );
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

#[test]
fn authored_workflow_tokens_require_only_trusted_publishing_bindings() {
    let path = Path::new("tools/memcordon-ci/src/workflow_definitions/release.rs");
    let source = include_str!("../../src/workflow_definitions/release.rs");
    validate_legacy_registry_token_source(path, source).unwrap();
    let secret = ["${{ secrets.", "CARGO_REGISTRY_TOKEN", " }}"].concat();
    for changed in [
        source.replace("${{ steps.registry-auth.outputs.token }}", &secret),
        source.replace("${{ steps.registry-auth.outputs.token }}", "untrusted"),
        [
            source,
            r#"fn token() { std::env::var("CARGO_REGISTRY_TOKEN"); }"#,
        ]
        .join("\n"),
        [
            source,
            r#"fn token(command: &mut Command) { command.env("CARGO_REGISTRY_TOKEN", "secret"); }"#,
        ]
        .join("\n"),
    ] {
        assert!(validate_legacy_registry_token_source(path, &changed).is_err());
    }
    assert!(validate_legacy_registry_token_source(Path::new("tools/other.rs"), source).is_err());
}

#[test]
fn ordinary_workflows_do_not_restore_retired_self_hosted_runner_exceptions() {
    let root = repository_root();
    let policy = config::policy(&root).unwrap();
    let generated: Value =
        serde_yaml::from_slice(include_bytes!("../../../../.github/workflows/ci.yml")).unwrap();
    let checkout = generated["jobs"]
        .as_mapping()
        .unwrap()
        .values()
        .flat_map(|job| job["steps"].as_sequence().unwrap())
        .find_map(|step| {
            step["uses"]
                .as_str()
                .filter(|uses| uses.starts_with("actions/checkout@"))
        })
        .expect("generated workflow pins checkout");
    let mut ordinary: Value = serde_yaml::from_str(
        "name: Policy fixture\non: [push]\npermissions:\n  contents: read\njobs:\n  check:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 10\n    steps:\n      - uses: checkout\n        with:\n          persist-credentials: false\n",
    )
    .unwrap();
    ordinary["jobs"]["check"]["steps"][0]["uses"] = Value::String(checkout.into());
    let ordinary_path = Path::new(".github/workflows/policy-fixture.yml");
    validate_workflow_bytes(
        &root,
        ordinary_path,
        serde_yaml::to_string(&ordinary).unwrap().as_bytes(),
        &policy,
    )
    .expect("ordinary policy baseline must pass");
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
        // Generated workflows reject any drift before generic runner checks.
        let mut job = document["jobs"]
            .as_mapping()
            .unwrap()
            .values()
            .next()
            .unwrap()
            .clone();
        job["runs-on"] = serde_yaml::from_str(runner).unwrap();
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
                .contains("workflow differs from current Rust authoring graph"),
            "unexpected rejection for {job_name}: {error}"
        );
        let mut changed = ordinary.clone();
        let mut job = changed["jobs"]
            .as_mapping_mut()
            .unwrap()
            .remove(Value::String("check".into()))
            .unwrap();
        job["runs-on"] = serde_yaml::from_str(runner).unwrap();
        changed["jobs"][job_name] = job;
        let error = validate_workflow_bytes(
            &root,
            ordinary_path,
            serde_yaml::to_string(&changed).unwrap().as_bytes(),
            &policy,
        )
        .expect_err("ordinary workflows must reject retired self-hosted runners");
        assert!(
            error
                .to_string()
                .contains("workflow may not select self-hosted runners"),
            "unexpected ordinary rejection for {job_name}: {error}"
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
