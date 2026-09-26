use super::*;

const AUTH_ACTION: &str =
    "rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn steady_workflow_fixture() -> &'static str {
    r#"name: Release
on:
  push:
    tags:
      - "[0-9]+.[0-9]+.[0-9]+*"
  workflow_dispatch:
    inputs:
      tag:
        description: Existing protected SemVer tag to publish or reconcile
        required: true
        type: string
      private_native:
        description: Run fail-closed private native qualification diagnostics
        required: false
        type: boolean
        default: false
      collector_intent_sha256_x64:
        description: Digest only of the verifier host's protected candidate collector intent
        required: false
        type: string
      collector_intent_sha256_arm64:
        description: Static protected ARM64 collector intent
        required: false
        type: string
      policy_intent_sha256_x64:
        description: Digest only of the independently provisioned protected private-policy release intent
        required: false
        type: string
      policy_intent_sha256_arm64:
        description: Static protected ARM64 policy recipe
        required: false
        type: string
      observer_intent_sha256_x64:
        description: Static protected x64 observer intent
        required: false
        type: string
      observer_intent_sha256_arm64:
        description: Static protected ARM64 observer intent
        required: false
        type: string
      public_observer_intent_sha256_x64:
        description: Static protected x64 installed public observer intent
        required: false
        type: string
      public_observer_intent_sha256_arm64:
        description: Static protected ARM64 installed public observer intent
        required: false
        type: string
permissions:
  contents: read
concurrency:
  group: memcordon-release
  cancel-in-progress: false
jobs:
  publish:
    needs:
      - assemble
      - rehearse-public
    permissions:
      actions: read
      contents: write
      id-token: write
    steps:
      - name: Stage GitHub draft and assets
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: rustup run 1.97.1 cargo run --locked --target-dir target/ci/publish-bootstrap --package memcordon-ci -- release stage-github
      - name: Acquire crates.io token for publication slot 1
        id: crates_auth_1
        uses: rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18
      - name: Attempt crates.io OIDC publication in slot 1
        id: publish_oidc_1
        env:
          CARGO_HOME: target/ci/cargo-publish-home/slot-1
          CARGO_REGISTRIES_CRATES_IO_TOKEN: ${{ steps.crates_auth_1.outputs.token }}
        run: target/ci/publish-bootstrap/debug/memcordon-ci release attempt-oidc --publication-slot 1
      - name: Acquire crates.io token for publication slot 2
        id: crates_auth_2
        uses: rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18
      - name: Attempt crates.io OIDC publication in slot 2
        id: publish_oidc_2
        env:
          CARGO_HOME: target/ci/cargo-publish-home/slot-2
          CARGO_REGISTRIES_CRATES_IO_TOKEN: ${{ steps.crates_auth_2.outputs.token }}
        run: target/ci/publish-bootstrap/debug/memcordon-ci release attempt-oidc --publication-slot 2
      - name: Acquire crates.io token for publication slot 3
        id: crates_auth_3
        uses: rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18
      - name: Attempt crates.io OIDC publication in slot 3
        id: publish_oidc_3
        env:
          CARGO_HOME: target/ci/cargo-publish-home/slot-3
          CARGO_REGISTRIES_CRATES_IO_TOKEN: ${{ steps.crates_auth_3.outputs.token }}
        run: target/ci/publish-bootstrap/debug/memcordon-ci release attempt-oidc --publication-slot 3
      - name: Acquire crates.io token for publication slot 4
        id: crates_auth_4
        uses: rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18
      - name: Attempt crates.io OIDC publication in slot 4
        id: publish_oidc_4
        env:
          CARGO_HOME: target/ci/cargo-publish-home/slot-4
          CARGO_REGISTRIES_CRATES_IO_TOKEN: ${{ steps.crates_auth_4.outputs.token }}
        run: target/ci/publish-bootstrap/debug/memcordon-ci release attempt-oidc --publication-slot 4
      - name: Finalize GitHub release
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: rustup run 1.97.1 cargo run --locked --target-dir target/ci/publish-bootstrap --package memcordon-ci -- release finalize-github
  verify-public:
    needs: publish
"#
}

fn check_steady_fixture(text: &str) -> Result<()> {
    let root = repository_root();
    let fixture: Value = serde_yaml::from_str(text)?;
    let fixture_workflow = mapping(&fixture, "steady workflow")?;
    let fixture_jobs = mapping(
        fixture_workflow
            .get(key("jobs"))
            .ok_or_else(|| failure("steady fixture jobs are absent"))?,
        "steady jobs",
    )?;
    let mut document: Value =
        serde_yaml::from_slice(include_bytes!("../../../../.github/workflows/release.yml"))?;
    {
        let workflow = document
            .as_mapping_mut()
            .ok_or_else(|| failure("release workflow must be a mapping"))?;
        workflow.insert(
            key("on"),
            fixture_workflow
                .get(key("on"))
                .ok_or_else(|| failure("steady fixture events are absent"))?
                .clone(),
        );
        let jobs = workflow
            .get_mut(key("jobs"))
            .and_then(Value::as_mapping_mut)
            .ok_or_else(|| failure("release jobs are absent"))?;
        let job_name = "publish";
        jobs.insert(
            key(job_name),
            fixture_jobs
                .get(key(job_name))
                .ok_or_else(|| failure(format!("steady {job_name} job is absent")))?
                .clone(),
        );
    }
    crate::managed_workflow::validate_and_project(&mut document)?;
    let workflow = mapping(&document, "release workflow")?;
    let jobs = mapping(
        workflow
            .get(key("jobs"))
            .ok_or_else(|| failure("release jobs are absent"))?,
        "release jobs",
    )?;
    let mut release = config::release(&root)?;
    release.registry_credentials.policy = config::RegistryCredentialPolicy::OidcOnly;
    release.registry_credentials.fallback_token_secret = None;
    let toolchains = config::toolchains(&root)?;
    check_release_structure(workflow, jobs, &release, &toolchains, AUTH_ACTION)
}

fn steady_cleanup_configuration() -> Result<(String, config::Release)> {
    let root = repository_root();
    let fixture: Value = serde_yaml::from_str(steady_workflow_fixture())?;
    let fixture_workflow = mapping(&fixture, "steady workflow")?;
    let fixture_jobs = mapping(
        fixture_workflow
            .get(key("jobs"))
            .ok_or_else(|| failure("steady fixture jobs are absent"))?,
        "steady jobs",
    )?;
    let mut document: Value =
        serde_yaml::from_slice(include_bytes!("../../../../.github/workflows/release.yml"))?;
    let workflow = document
        .as_mapping_mut()
        .ok_or_else(|| failure("release workflow must be a mapping"))?;
    workflow.insert(
        key("on"),
        fixture_workflow
            .get(key("on"))
            .ok_or_else(|| failure("steady fixture events are absent"))?
            .clone(),
    );
    let jobs = workflow
        .get_mut(key("jobs"))
        .and_then(Value::as_mapping_mut)
        .ok_or_else(|| failure("release jobs are absent"))?;
    jobs.insert(
        key("publish"),
        fixture_jobs
            .get(key("publish"))
            .ok_or_else(|| failure("steady publish job is absent"))?
            .clone(),
    );
    let text = serde_yaml::to_string(&document)?;
    let mut release = config::release(&root)?;
    release.registry_credentials.policy = config::RegistryCredentialPolicy::OidcOnly;
    release.registry_credentials.fallback_token_secret = None;
    Ok((text, release))
}

fn legacy_token_source() -> String {
    ["${{ secrets.", "CARGO_REGISTRY_TOKEN", " }}"].concat()
}

fn fallback_token_source() -> String {
    [
        "${{ secrets.",
        "MEMCORDON_CRATES_IO_NEW_CRATE_FALLBACK",
        " }}",
    ]
    .concat()
}

#[test]
fn exact_fallback_and_cleanup_workflow_profiles_are_accepted() {
    let root = repository_root();
    let policy = config::policy(&root).expect("repository policy should parse");
    validate_workflow_bytes(
        &root,
        Path::new(".github/workflows/release.yml"),
        include_bytes!("../../../../.github/workflows/release.yml"),
        &policy,
    )
    .expect("generic OIDC-first fallback workflow should satisfy production policy");
    check_steady_fixture(steady_workflow_fixture())
        .expect("cleanup steady-state workflow should satisfy structure policy");
}

#[test]
fn steady_profile_rejects_noncanonical_oidc_slots_and_token_reintroduction() {
    let with_input = steady_workflow_fixture().replacen(
        "        uses: rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18
",
        "        uses: rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18
        with:
          url: https://example.invalid
",
        1,
    );
    assert!(check_steady_fixture(&with_input).is_err());

    let wrong_output = steady_workflow_fixture().replacen(
        "steps.crates_auth_1.outputs.token",
        "steps.crates_auth_2.outputs.token",
        1,
    );
    assert!(check_steady_fixture(&wrong_output).is_err());

    let separated_pair = steady_workflow_fixture().replacen(
        "        uses: rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18
      - name: Attempt crates.io OIDC publication in slot 1
",
        "        uses: rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18
      - run: rustup toolchain install 1.97.1 --profile minimal
      - name: Attempt crates.io OIDC publication in slot 1
",
        1,
    );
    assert!(check_steady_fixture(&separated_pair).is_err());

    let stored = steady_workflow_fixture().replacen(
        "${{ steps.crates_auth_1.outputs.token }}",
        &fallback_token_source(),
        1,
    );
    assert!(check_steady_fixture(&stored).is_err());

    let missing_github_mapping = steady_workflow_fixture().replacen(
        "      - name: Stage GitHub draft and assets
",
        "      - name: Stage mapping removed
",
        1,
    );
    assert!(check_steady_fixture(&missing_github_mapping).is_err());
}

#[test]
fn fallback_profile_rejects_unbounded_or_cross_wired_credentials() {
    let root = repository_root();
    let policy = config::policy(&root).expect("repository policy should parse");
    let exact = std::str::from_utf8(include_bytes!("../../../../.github/workflows/release.yml"))
        .expect("workflow should be UTF-8")
        .replace("\r\n", "\n");
    let without_continue = exact.replacen("        continue-on-error: true\n", "", 1);
    let authorizer_step = "      - name: Authorize new-crate token fallback in slot 3\n";
    let continued_authorizer = exact.replacen(
        authorizer_step,
        format!("{authorizer_step}        continue-on-error: true\n").as_str(),
        1,
    );
    let token_step = "      - name: Publish new crate with fallback credential in slot 3\n";
    let continued_token = exact.replacen(
        token_step,
        format!("{token_step}        continue-on-error: true\n").as_str(),
        1,
    );
    let broadened_condition = exact.replacen(
            "steps.authorize_fallback_3.outcome == 'success' && steps.authorize_fallback_3.outputs.authorized == 'true'",
            "steps.authorize_fallback_3.outcome == 'success'",
            1,
        );
    let cross_wired_source = exact.replacen(
        fallback_token_source().as_str(),
        "${{ steps.crates_auth_3.outputs.token }}",
        1,
    );
    let package_named_step = exact.replacen(
        "Publish new crate with fallback credential in slot 3",
        "Publish new memcordon-windows-launch-core in slot 3",
        1,
    );
    let authorizer_environment = exact.replacen(
            "      - name: Authorize new-crate token fallback in slot 3\n        id: authorize_fallback_3\n",
            "      - name: Authorize new-crate token fallback in slot 3\n        id: authorize_fallback_3\n        env:\n          CARGO_REGISTRIES_CRATES_IO_TOKEN: ${{ steps.crates_auth_3.outputs.token }}\n",
            1,
        );
    let transition_input = "      registry_auth:\n        required: true\n        type: choice\n        options:\n          - stored-token\n";
    let with_transition_input = exact.replacen(
        "  workflow_dispatch:\n    inputs:\n",
        format!("  workflow_dispatch:\n    inputs:\n{transition_input}").as_str(),
        1,
    );
    let legacy_variable = exact.replacen(
            format!(
                "          CARGO_HOME: target/ci/cargo-publish-home/slot-3\n          CARGO_REGISTRIES_CRATES_IO_TOKEN: {}",
                fallback_token_source()
            )
            .as_str(),
            format!(
                "          CARGO_HOME: target/ci/cargo-publish-home/slot-3\n          CARGO_REGISTRIES_CRATES_IO_TOKEN: {}",
                legacy_token_source()
            )
            .as_str(),
            1,
        );
    let cases = [
        ("OIDC attempt loses continue-on-error", without_continue),
        ("continued authorizer", continued_authorizer),
        ("continued token publication", continued_token),
        ("broadened token condition", broadened_condition),
        ("cross-wired token source", cross_wired_source),
        ("package-named credential step", package_named_step),
        ("authorizer gains credentials", authorizer_environment),
        ("transition dispatch input", with_transition_input),
        ("legacy singular-token variable", legacy_variable),
    ];
    for (case, invalid) in cases {
        assert_ne!(invalid, exact, "{case} fixture mutation must apply");
        assert!(
            validate_workflow_bytes(
                &root,
                Path::new(".github/workflows/release.yml"),
                invalid.as_bytes(),
                &policy,
            )
            .is_err(),
            "{case} fixture must be rejected"
        );
    }
}

#[test]
fn cleanup_profile_rejects_transition_inputs_and_stored_tokens() {
    let transition_input = "      registry_auth:\n        required: true\n        type: choice\n        options:\n          - stored-token\n          - oidc-fallback\n";
    let with_transition_input = steady_workflow_fixture().replacen(
        "  workflow_dispatch:\n    inputs:\n",
        format!("  workflow_dispatch:\n    inputs:\n{transition_input}").as_str(),
        1,
    );
    assert!(check_steady_fixture(&with_transition_input).is_err());

    let with_stored_token = steady_workflow_fixture().replacen(
        "${{ steps.crates_auth_1.outputs.token }}",
        fallback_token_source().as_str(),
        1,
    );
    assert!(check_steady_fixture(&with_stored_token).is_err());
}

#[test]
fn cleanup_policy_text_rejects_stale_transition_commands_and_sources() {
    let (clean_text, release) = steady_cleanup_configuration()
        .expect("steady cleanup configuration should be constructible");
    check_release_workflow_text(&clean_text, &release)
        .expect("the cleaned workflow should satisfy the OIDC-only text policy");

    let stale_command = format!(
        "{clean_text}# stale target/ci/publish-bootstrap/debug/memcordon-ci release publish-token-fallback --publication-slot 1 command\n"
    );
    let stale_authorizer = format!(
        "{clean_text}# stale target/ci/publish-bootstrap/debug/memcordon-ci release authorize-new-crate-fallback --publication-slot 1 command\n"
    );
    let stale_secret = format!(
        "{clean_text}# stale ${{{{ secrets.MEMCORDON_CRATES_IO_NEW_CRATE_FALLBACK }}}} mapping\n"
    );
    let stale_variable = format!("{clean_text}# stale CARGO_REGISTRIES_CRATES_IO_TOKEN mapping\n");
    let stale_literal = format!("{clean_text}# stale stored-token literal\n");
    for (case, invalid) in [
        ("token-fallback command", stale_command),
        ("fallback authorizer command", stale_authorizer),
        ("fallback secret source", stale_secret),
        ("extra credential variable", stale_variable),
        ("transition literal", stale_literal),
    ] {
        assert_ne!(invalid, clean_text, "{case} mutation must apply");
        assert!(
            check_release_workflow_text(&invalid, &release).is_err(),
            "{case} must be rejected under the OIDC-only cleanup policy"
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
