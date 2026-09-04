use std::path::{Path, PathBuf};

use memcordon_ci::{config, policy};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

#[test]
fn dependabot_requires_each_independent_dependency_surface() {
    let exact = include_str!("../../../.github/dependabot.yml").replace("\r\n", "\n");
    policy::validate_dependabot_bytes(exact.as_bytes())
        .expect("the exact Dependabot dependency matrix should pass");

    let fuzz_update = r#"  - package-ecosystem: cargo
    directory: /fuzz
    schedule:
      interval: weekly
    open-pull-requests-limit: 3
"#;
    let cases = [
        (fuzz_update, ""),
        ("    directory: /fuzz\n", "    directory: /\n"),
        (
            "    directory: /fuzz\n    schedule:\n      interval: weekly\n",
            "    directory: /fuzz\n    schedule:\n      interval: daily\n",
        ),
        (
            "    directory: /fuzz\n    schedule:\n      interval: weekly\n    open-pull-requests-limit: 3\n",
            "    directory: /fuzz\n    schedule:\n      interval: weekly\n    open-pull-requests-limit: 4\n",
        ),
    ];

    for (expected, replacement) in cases {
        let invalid = exact.replacen(expected, replacement, 1);
        assert_ne!(invalid, exact, "Dependabot fixture mutation must apply");
        policy::validate_dependabot_bytes(invalid.as_bytes())
            .expect_err("a Dependabot dependency-surface regression must be rejected");
    }
}

#[test]
fn fuzz_dependency_cache_keys_require_the_fuzz_lockfile() {
    let root = repository_root();
    let repository_policy = config::policy(&root).expect("repository policy should parse");
    for relative in [
        ".github/workflows/deep-ci.yml",
        ".github/workflows/release.yml",
    ] {
        let exact = std::fs::read_to_string(root.join(relative))
            .expect("workflow fixture should be readable")
            .replace("\r\n", "\n");
        let invalid = exact.replacen("'fuzz/Cargo.lock', ", "", 1);
        assert_ne!(invalid, exact, "fuzz lockfile mutation must apply");
        let error = policy::validate_workflow_bytes(
            &root,
            Path::new(relative),
            invalid.as_bytes(),
            &repository_policy,
        )
        .expect_err("a fuzz dependency cache key without its lockfile must fail");
        assert!(
            error
                .to_string()
                .contains("fuzz manifest must include its lockfile"),
            "unexpected policy error: {error}"
        );
    }
}

#[test]
fn release_preflight_binds_provisioning_and_cache_to_toolchain_config() {
    let root = repository_root();
    let repository_policy = config::policy(&root).expect("repository policy should parse");
    let exact = std::fs::read_to_string(root.join(".github/workflows/release.yml"))
        .expect("release workflow fixture should be readable")
        .replace("\r\n", "\n");
    for (case, source, replacement, expected_error) in [
        (
            "missing MSRV install",
            "      - run: rustup toolchain install 1.85.0 --profile minimal\n",
            "",
            "release preflight toolchain provisioning differs",
        ),
        (
            "wrong MSRV install",
            "      - run: rustup toolchain install 1.85.0 --profile minimal\n",
            "      - run: rustup toolchain install 1.97.1 --profile minimal\n",
            "release preflight toolchain provisioning differs",
        ),
        (
            "wrong MSRV cache identity",
            "cargo-target-release-v3-preflight-1.97.1-msrv-1.85.0-",
            "cargo-target-release-v3-preflight-1.97.1-msrv-1.97.1-",
            "release preflight target cache identity differs",
        ),
    ] {
        let invalid = exact.replacen(source, replacement, 1);
        assert_ne!(invalid, exact, "{case} mutation must apply");
        let error = policy::validate_workflow_bytes(
            &root,
            Path::new(".github/workflows/release.yml"),
            invalid.as_bytes(),
            &repository_policy,
        )
        .expect_err("release preflight toolchain drift must fail");
        assert!(
            error.to_string().contains(expected_error),
            "unexpected {case} policy error: {error}"
        );
    }
}

#[test]
fn windows_arm_native_matrix_entries_are_structurally_required() {
    let root = repository_root();
    let repository_policy = config::policy(&root).expect("repository policy should parse");
    for (relative, job, fixture) in [
        (
            ".github/workflows/ci.yml",
            "CI native",
            include_str!("../../../.github/workflows/ci.yml"),
        ),
        (
            ".github/workflows/deep-ci.yml",
            "deep CI stress",
            include_str!("../../../.github/workflows/deep-ci.yml"),
        ),
        (
            ".github/workflows/release.yml",
            "release native",
            include_str!("../../../.github/workflows/release.yml"),
        ),
    ] {
        let exact = fixture.replace("\r\n", "\n");
        let windows_rows = "          - id: windows-x64\n            runner: windows-2025\n          - id: windows-arm64\n            runner: windows-11-arm\n";
        for replacement in [
            "          - id: windows-x64\n            runner: windows-2025\n",
            "          - id: windows-x64\n            runner: windows-2025\n          - id: windows-arm64\n            runner: windows-2025\n",
            "          - id: windows-arm64\n            runner: windows-11-arm\n",
            "          - id: windows-x64\n            runner: windows-11-arm\n          - id: windows-arm64\n            runner: windows-2025\n",
            "          - id: windows-x64\n            runner: windows-2025\n          - id: windows-x64\n            runner: windows-11-arm\n",
            "          - id: windows-x64\n            runner: windows-2025\n          - id: windows-other\n            runner: windows-11-arm\n",
        ] {
            let invalid = exact.replacen(windows_rows, replacement, 1);
            assert_ne!(invalid, exact, "{job} mutation must apply");
            let error = policy::validate_workflow_bytes(
                &root,
                Path::new(relative),
                invalid.as_bytes(),
                &repository_policy,
            )
            .expect_err("Windows ARM matrix regression must be rejected");
            assert!(
                error
                    .to_string()
                    .contains(&format!("{job} matrix entries differ")),
                "unexpected {job} policy error: {error}"
            );
        }
        let planted = exact
            .replacen(
                windows_rows,
                "          - id: windows-x64\n            runner: windows-2025\n",
                1,
            )
            .replacen("    name: ", "    name: windows-arm64 / ", 1);
        let planted_error = policy::validate_workflow_bytes(
            &root,
            Path::new(relative),
            planted.as_bytes(),
            &repository_policy,
        )
        .expect_err("Windows ARM text outside the matrix must not satisfy policy");
        assert!(
            planted_error
                .to_string()
                .contains(&format!("{job} matrix entries differ")),
            "unexpected planted {job} policy error: {planted_error}"
        );
        let direct_runner = exact.replacen(
            "    runs-on: ${{ matrix.runner }}\n",
            "    runs-on: windows-11-arm\n",
            1,
        );
        let runner_error = policy::validate_workflow_bytes(
            &root,
            Path::new(relative),
            direct_runner.as_bytes(),
            &repository_policy,
        )
        .expect_err("matrix jobs must select the typed runner field");
        assert!(
            runner_error
                .to_string()
                .contains(&format!("{job} runner selection differs")),
            "unexpected {job} runner policy error: {runner_error}"
        );
    }
}

#[test]
fn public_windows_release_smoke_is_structurally_required() {
    let root = repository_root();
    let repository_policy = config::policy(&root).expect("repository policy should parse");
    let exact = include_str!("../../../.github/workflows/release.yml").replace("\r\n", "\n");
    for (name, source, replacement, expected) in [
        (
            "ARM runner",
            "          - id: linux-x64\n            runner: ubuntu-24.04\n          - id: windows-x64\n            runner: windows-2025\n          - id: windows-arm64\n            runner: windows-11-arm\n",
            "          - id: linux-x64\n            runner: ubuntu-24.04\n          - id: windows-x64\n            runner: windows-2025\n",
            "verify-public job matrix entries differ",
        ),
        (
            "timeout",
            "    timeout-minutes: 90\n    permissions:\n      contents: read\n",
            "    timeout-minutes: 30\n    permissions:\n      contents: read\n",
            "verify-public timeout differs",
        ),
        (
            "public verification command",
            "      - run: rustup run 1.97.1 cargo run --locked --target-dir target/ci/verify-bootstrap --package memcordon-ci -- release verify-public\n",
            "",
            "verify-public step count differs",
        ),
        (
            "target cache path",
            "          path: target/ci/verify-bootstrap\n          key: cargo-target-release-verify-public-v2-",
            "          path: target/ci/other\n          key: cargo-target-release-verify-public-v2-",
            "verify-public verify-public-target cache inputs differ",
        ),
    ] {
        let invalid = exact.replacen(source, replacement, 1);
        assert_ne!(invalid, exact, "{name} mutation must apply");
        let error = policy::validate_workflow_bytes(
            &root,
            Path::new(".github/workflows/release.yml"),
            invalid.as_bytes(),
            &repository_policy,
        )
        .expect_err("public Windows release-smoke regression must fail");
        assert!(
            error.to_string().contains(expected),
            "unexpected {name} policy error: {error}"
        );
    }
}

#[test]
fn action_input_boolean_value_selection_is_rejected() {
    let root = repository_root();
    let exact = include_str!("../../../.github/workflows/release.yml").replace("\r\n", "\n");
    let explicit = r#"      - name: Check out pushed tag
        if: github.event_name == 'push'
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          ref: ${{ github.ref }}
          fetch-depth: 0
          persist-credentials: false
      - name: Check out dispatched tag
        if: github.event_name == 'workflow_dispatch'
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          ref: ${{ inputs.tag }}
          fetch-depth: 0
          persist-credentials: false
"#;
    let coalesced = r#"      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          ref: ${{ inputs.tag || github.ref }}
          fetch-depth: 0
          persist-credentials: false
"#;
    let invalid = exact.replacen(explicit, coalesced, 1);
    assert_ne!(invalid, exact, "checkout fixture mutation must apply");

    let repository_policy = config::policy(&root).expect("repository policy should parse");
    let error = policy::validate_workflow_bytes(
        &root,
        Path::new(".github/workflows/release.yml"),
        invalid.as_bytes(),
        &repository_policy,
    )
    .expect_err("Boolean value selection in an action input must be rejected");
    assert!(
        error
            .to_string()
            .contains("workflow action input may not select values with Boolean operators"),
        "unexpected policy error: {error}"
    );
}

#[test]
fn named_github_environments_are_rejected() {
    let root = repository_root();
    let exact = include_str!("../../../.github/workflows/release.yml").replace("\r\n", "\n");
    let invalid = exact.replacen(
        "    runs-on: ubuntu-24.04\n    timeout-minutes: 60\n",
        "    runs-on: ubuntu-24.04\n    environment: release\n    timeout-minutes: 60\n",
        1,
    );
    assert_ne!(invalid, exact, "environment fixture mutation must apply");

    let repository_policy = config::policy(&root).expect("repository policy should parse");
    let error = policy::validate_workflow_bytes(
        &root,
        Path::new(".github/workflows/release.yml"),
        invalid.as_bytes(),
        &repository_policy,
    )
    .expect_err("named GitHub environments must be rejected");
    assert!(
        error
            .to_string()
            .contains("named GitHub environments are forbidden"),
        "unexpected policy error: {error}"
    );
}

#[test]
fn certification_runner_regressions_are_rejected_structurally() {
    let root = repository_root();
    let repository_policy = config::policy(&root).expect("repository policy should parse");
    let backend =
        include_str!("../../../.github/workflows/backend-certification.yml").replace("\r\n", "\n");
    let release = include_str!("../../../.github/workflows/release.yml").replace("\r\n", "\n");
    let cases = [
        (
            Path::new(".github/workflows/backend-certification.yml"),
            backend.as_str(),
            "    runs-on: ubuntu-24.04\n",
            "    runs-on: [self-hosted, memcordon, linux, x64, cgroup-v2, ephemeral]\n",
        ),
        (
            Path::new(".github/workflows/backend-certification.yml"),
            backend.as_str(),
            "          - id: x64\n            runner: windows-2025\n",
            "          - id: x64\n            runner: [self-hosted, memcordon, windows, x64, job-object, ephemeral]\n",
        ),
        (
            Path::new(".github/workflows/release.yml"),
            release.as_str(),
            "  linux-certification:\n    name: Release / Linux sealed certification\n    needs: preflight\n    runs-on: ubuntu-24.04\n",
            "  linux-certification:\n    name: Release / Linux sealed certification\n    needs: preflight\n    runs-on: [self-hosted, memcordon, linux, x64, cgroup-v2, ephemeral]\n",
        ),
        (
            Path::new(".github/workflows/release.yml"),
            release.as_str(),
            "  windows-loader-production:\n    name: Release / Windows loader production / ${{ matrix.id }}\n    needs: native\n",
            "  windows-loader-production:\n    name: Release / Windows loader production / ${{ matrix.id }}\n    needs: native\n    runs-on: [self-hosted, memcordon, windows, x64, job-object, ephemeral]\n",
        ),
        (
            Path::new(".github/workflows/backend-certification.yml"),
            backend.as_str(),
            "    runs-on: ubuntu-24.04\n",
            "    runs-on: ubuntu-latest\n",
        ),
        (
            Path::new(".github/workflows/backend-certification.yml"),
            backend.as_str(),
            "          - id: x64\n            runner: windows-2025\n",
            "          - id: x64\n            runner: windows-latest\n",
        ),
        (
            Path::new(".github/workflows/release.yml"),
            release.as_str(),
            "  linux-certification:\n    name: Release / Linux sealed certification\n    needs: preflight\n    runs-on: ubuntu-24.04\n",
            "  linux-certification:\n    name: Release / Linux sealed certification\n    needs: preflight\n    runs-on: ubuntu-latest\n",
        ),
        (
            Path::new(".github/workflows/release.yml"),
            release.as_str(),
            "  windows-loader-production:\n    name: Release / Windows loader production / ${{ matrix.id }}\n    needs: native\n",
            "  windows-loader-production:\n    name: Release / Windows loader production / ${{ matrix.id }}\n    needs: native\n    runs-on: windows-latest\n",
        ),
    ];

    for (path, fixture, exact, replacement) in cases {
        let invalid = fixture.replacen(exact, replacement, 1);
        assert_ne!(
            invalid, fixture,
            "runner fixture mutation must apply: {path:?}"
        );
        policy::validate_workflow_bytes(&root, path, invalid.as_bytes(), &repository_policy)
            .expect_err("noncanonical certification runner must be rejected");
    }
}

#[test]
fn linux_certification_uploads_retain_hidden_failure_diagnostics() {
    let root = repository_root();
    let repository_policy = config::policy(&root).expect("repository policy should parse");
    for (path, fixture) in [
        (
            Path::new(".github/workflows/backend-certification.yml"),
            include_str!("../../../.github/workflows/backend-certification.yml"),
        ),
        (
            Path::new(".github/workflows/release.yml"),
            include_str!("../../../.github/workflows/release.yml"),
        ),
    ] {
        let normalized = fixture.replace("\r\n", "\n");
        let invalid = normalized.replacen("          include-hidden-files: true\n", "", 1);
        assert_ne!(
            invalid, normalized,
            "hidden-diagnostic fixture mutation must apply: {path:?}"
        );
        policy::validate_workflow_bytes(&root, path, invalid.as_bytes(), &repository_policy)
            .expect_err("Linux certification must upload hidden failure diagnostics");
    }
}

#[test]
fn deep_and_backend_workflows_require_unfiltered_push_and_manual_dispatch() {
    let root = repository_root();
    let repository_policy = config::policy(&root).expect("repository policy should parse");
    let expected_trigger = "on:\n  push:\n  workflow_dispatch:\n";
    let branch_filtered_push = "on:\n  push:\n    branches:\n      - main\n  workflow_dispatch:\n";
    let tag_filtered_push = "on:\n  push:\n    tags:\n      - release\n  workflow_dispatch:\n";
    let path_filtered_push = "on:\n  push:\n    paths:\n      - crates/**\n  workflow_dispatch:\n";
    let ignored_path_push =
        "on:\n  push:\n    paths-ignore:\n      - docs/**\n  workflow_dispatch:\n";
    let missing_dispatch = "on:\n  push:\n";
    let dispatch_inputs =
        "on:\n  push:\n  workflow_dispatch:\n    inputs:\n      reason:\n        required: false\n";
    let cases = [
        (
            Path::new(".github/workflows/deep-ci.yml"),
            include_str!("../../../.github/workflows/deep-ci.yml"),
            "on:\n  schedule:\n    - cron: \"17 3 * * 1\"\n  workflow_dispatch:\n",
        ),
        (
            Path::new(".github/workflows/backend-certification.yml"),
            include_str!("../../../.github/workflows/backend-certification.yml"),
            "on:\n  schedule:\n    - cron: \"43 4 * * 3\"\n  workflow_dispatch:\n",
        ),
    ];

    for (path, fixture, scheduled_trigger) in cases {
        let exact = fixture.replace("\r\n", "\n");
        policy::validate_workflow_bytes(&root, path, exact.as_bytes(), &repository_policy)
            .expect("exact push and manual workflow triggers should pass");
        for replacement in [
            scheduled_trigger,
            branch_filtered_push,
            tag_filtered_push,
            path_filtered_push,
            ignored_path_push,
            missing_dispatch,
            dispatch_inputs,
        ] {
            let invalid = exact.replacen(expected_trigger, replacement, 1);
            assert_ne!(
                invalid, exact,
                "workflow trigger fixture mutation must apply: {path:?}"
            );
            policy::validate_workflow_bytes(&root, path, invalid.as_bytes(), &repository_policy)
                .expect_err("workflow trigger regression must be rejected");
        }
    }

    let deep = include_str!("../../../.github/workflows/deep-ci.yml").replace("\r\n", "\n");
    let backend =
        include_str!("../../../.github/workflows/backend-certification.yml").replace("\r\n", "\n");
    let concurrency_cases = [
        (
            Path::new(".github/workflows/deep-ci.yml"),
            deep.as_str(),
            "  group: deep-ci-${{ github.ref }}\n",
            "  group: deep-ci-all\n",
        ),
        (
            Path::new(".github/workflows/deep-ci.yml"),
            deep.as_str(),
            "  cancel-in-progress: true\n",
            "  cancel-in-progress: false\n",
        ),
        (
            Path::new(".github/workflows/backend-certification.yml"),
            backend.as_str(),
            "  group: backend-certification-${{ github.ref }}\n",
            "  group: backend-certification-all\n",
        ),
        (
            Path::new(".github/workflows/backend-certification.yml"),
            backend.as_str(),
            "  cancel-in-progress: false\n",
            "  cancel-in-progress: true\n",
        ),
    ];
    for (path, fixture, exact, replacement) in concurrency_cases {
        let invalid = fixture.replacen(exact, replacement, 1);
        assert_ne!(
            invalid, fixture,
            "workflow concurrency fixture mutation must apply: {path:?}"
        );
        policy::validate_workflow_bytes(&root, path, invalid.as_bytes(), &repository_policy)
            .expect_err("workflow concurrency regression must be rejected");
    }
}

#[test]
fn ci_concurrency_separates_trigger_methods() {
    let root = repository_root();
    let repository_policy = config::policy(&root).expect("repository policy should parse");
    let exact = include_str!("../../../.github/workflows/ci.yml").replace("\r\n", "\n");
    policy::validate_workflow_bytes(
        &root,
        Path::new(".github/workflows/ci.yml"),
        exact.as_bytes(),
        &repository_policy,
    )
    .expect("CI concurrency should separate trigger methods");

    let invalid = exact.replacen("-${{ github.event_name }}", "", 1);
    assert_ne!(invalid, exact, "CI concurrency fixture mutation must apply");
    policy::validate_workflow_bytes(
        &root,
        Path::new(".github/workflows/ci.yml"),
        invalid.as_bytes(),
        &repository_policy,
    )
    .expect_err("CI concurrency without the trigger method must be rejected");
}
