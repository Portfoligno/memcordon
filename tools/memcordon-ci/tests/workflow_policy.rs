use std::path::{Path, PathBuf};

use memcordon_ci::{config, policy};
use serde_yaml::Value;
use syn::parse::Parser;
use syn::visit::Visit;

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

#[test]
fn private_candidate_inputs_require_both_native_linux_rows_and_exact_readback() {
    let root = repository_root();
    let repository_policy = config::policy(&root).unwrap();
    let workflow = include_str!("../../../.github/workflows/release.yml");
    policy::validate_workflow_bytes(
        &root,
        Path::new(".github/workflows/release.yml"),
        workflow.as_bytes(),
        &repository_policy,
    )
    .unwrap();
    for (original, replacement) in [
        (
            "  linux-private-candidate-inputs:\n",
            "  linux-private-candidate-inputs-disabled:\n",
        ),
        (
            "          - id: linux-arm64\n            runner: ubuntu-24.04-arm\n",
            "",
        ),
        (
            "    needs: native\n    strategy:\n",
            "    needs: preflight\n    strategy:\n",
        ),
        ("release verify-private-candidate", "release verify-public"),
        (
            "      - run: ./target/ci/control-bootstrap/ci-bootstrap/memcordon-ci --build-context target/ci/native-inputs.bin release verify-private-candidate",
            "      - if: false\n        run: ./target/ci/control-bootstrap/ci-bootstrap/memcordon-ci --build-context target/ci/native-inputs.bin release verify-private-candidate",
        ),
        (
            "name: release-native-${{ matrix.id }}\n          path: target/ci/release-inputs/release-native-${{ matrix.id }}",
            "name: release-native-linux-x64\n          path: target/ci/release-inputs/release-native-${{ matrix.id }}",
        ),
    ] {
        assert!(workflow.contains(original));
        let mutant = workflow.replace(original, replacement);
        assert!(
            policy::validate_workflow_bytes(
                &root,
                Path::new(".github/workflows/release.yml"),
                mutant.as_bytes(),
                &repository_policy,
            )
            .is_err(),
            "private candidate workflow mutation was accepted: {original}"
        );
    }
}

#[test]
fn private_native_jobs_are_explicitly_opt_in_target_exact_and_nonpublishing() {
    let root = repository_root();
    let repository_policy = config::policy(&root).unwrap();
    let workflow = include_str!("../../../.github/workflows/release.yml");
    policy::validate_workflow_bytes(
        &root,
        Path::new(".github/workflows/release.yml"),
        workflow.as_bytes(),
        &repository_policy,
    )
    .unwrap();
    for (original, replacement) in [
        (
            "private_native:\n        description: Run fail-closed private native qualification diagnostics",
            "private_native_disabled:\n        description: Run fail-closed private native qualification diagnostics",
        ),
        (
            "if: github.event_name == 'workflow_dispatch' && inputs.private_native == true",
            "if: github.event_name == 'workflow_dispatch'",
        ),
        (
            "  linux-private-candidate:\n",
            "  linux-private-candidate-disabled:\n",
        ),
        (
            "          - id: arm64\n            runner: ubuntu-24.04-arm",
            "          - id: arm64\n            runner: ubuntu-24.04",
        ),
        (
            "suite backend-linux-private-v4 --stage candidate-capability --target native",
            "suite backend-linux-private-v4 --stage final-public --target native",
        ),
        (
            "            asset: linux-arm64\n",
            "            asset: linux-x64\n",
        ),
        (
            "  linux-private-candidate:\n    name: Release / Linux private candidate / ${{ matrix.id }}\n    if: github.event_name == 'workflow_dispatch' && inputs.private_native == true\n    needs: linux-private-candidate-inputs\n    permissions:\n      contents: read\n      actions: read",
            "  linux-private-candidate:\n    name: Release / Linux private candidate / ${{ matrix.id }}\n    if: github.event_name == 'workflow_dispatch' && inputs.private_native == true\n    needs: linux-private-candidate-inputs\n    permissions:\n      contents: read\n      actions: none",
        ),
        (
            "          OBSERVER_INTENT_SHA256: ${{ inputs[format('observer_intent_sha256_{0}', matrix.id)] }}",
            "          OBSERVER_INTENT_SHA256: ${{ inputs.observer_intent_sha256_x64 }}",
        ),
        (
            "name: release-native-${{ matrix.asset }}",
            "name: release-native-linux-x64",
        ),
        (
            "path: target/ci/release-inputs/release-native-${{ matrix.asset }}",
            "path: target/ci/release-inputs/release-native-linux-x64",
        ),
        (
            "      - run: sudo -E ./target/ci/control-bootstrap/ci-bootstrap/memcordon-ci --build-context target/ci/native-inputs.bin release install-private-candidate\n",
            "",
        ),
        (
            "      - run: ./target/ci/control-bootstrap/ci-bootstrap/memcordon-ci --build-context target/ci/native-inputs.bin release verify-private-candidate\n      - run: sudo -E ./target/ci/control-bootstrap/ci-bootstrap/memcordon-ci --build-context target/ci/native-inputs.bin release install-private-candidate",
            "      - run: sudo -E ./target/ci/control-bootstrap/ci-bootstrap/memcordon-ci --build-context target/ci/native-inputs.bin release install-private-candidate\n      - run: ./target/ci/control-bootstrap/ci-bootstrap/memcordon-ci --build-context target/ci/native-inputs.bin release verify-private-candidate",
        ),
        (
            "  linux-private-final:\n    name: Release / Linux private final / ${{ matrix.id }}\n    if: github.event_name == 'workflow_dispatch' && inputs.private_native == true\n    needs: linux-private-candidate",
            "  linux-private-final:\n    name: Release / Linux private final / ${{ matrix.id }}\n    if: github.event_name == 'workflow_dispatch' && inputs.private_native == true\n    needs: linux-private-candidate-inputs",
        ),
    ] {
        assert!(
            workflow.contains(original),
            "missing policy fixture: {original}"
        );
        let mutant = workflow.replacen(original, replacement, 1);
        assert!(
            policy::validate_workflow_bytes(
                &root,
                Path::new(".github/workflows/release.yml"),
                mutant.as_bytes(),
                &repository_policy,
            )
            .is_err(),
            "private native workflow mutation was accepted: {original}"
        );
    }
}

#[test]
fn release_rehearsal_is_required_before_publication() {
    let root = repository_root();
    let repository_policy = config::policy(&root).expect("repository policy");
    let fixture = include_str!("../../../.github/workflows/release.yml").replace("\r\n", "\n");
    let fixtures = [fixture.clone(), fixture.replace('\n', "\r\n")];
    for fixture in &fixtures {
        policy::validate_workflow_bytes(
            &root,
            Path::new(".github/workflows/release.yml"),
            fixture.as_bytes(),
            &repository_policy,
        )
        .expect("complete release rehearsal gate");

        let fixture = fixture.replace("\r\n", "\n");
        policy::validate_workflow_bytes(
            &root,
            Path::new(".github/workflows/release.yml"),
            fixture.as_bytes(),
            &repository_policy,
        )
        .expect("normalized release rehearsal gate");

        for (original, replacement) in [
            ("      - rehearse-public\n", ""),
            (
                "          - id: windows-arm64\n            runner: windows-11-arm\n",
                "",
            ),
            (
                "    name: Release / rehearse public state / ${{ matrix.id }}",
                "    name: Release / unchecked public state / ${{ matrix.id }}",
            ),
            (
                "    timeout-minutes: 90\n    permissions:\n      contents: read\n    steps:",
                "    timeout-minutes: 90\n    permissions:\n      contents: write\n    steps:",
            ),
            (
                "release rehearse-public --bundle target/ci/release-bundle",
                "release verify-public --bundle target/ci/release-bundle",
            ),
            (
                "      - run: ./target/ci/control-bootstrap/ci-bootstrap/memcordon-ci --build-context target/ci/native-inputs.bin release rehearse-public",
                "      - if: false\n        run: ./target/ci/control-bootstrap/ci-bootstrap/memcordon-ci --build-context target/ci/native-inputs.bin release rehearse-public",
            ),
            (
                "    permissions:\n      contents: read\n    steps:",
                "    permissions:\n      contents: read\n    env:\n      REHEARSAL_MODE: skip\n    steps:",
            ),
            (
                "      - id: rehearse-public-deps\n        uses:",
                "      - id: rehearse-public-deps\n        continue-on-error: true\n        uses:",
            ),
            (
                "name: release-public-rehearsal-${{ matrix.id }}",
                "name: omitted-public-rehearsal-${{ matrix.id }}",
            ),
            (
                "path: target/ci/public-rehearsal/report.json",
                "path: target/ci/public-rehearsal/missing.json",
            ),
            (
                "key: ${{ steps.rehearse-public-deps.outputs.cache-primary-key }}",
                "key: stale-rehearsal-cache",
            ),
        ] {
            let rehearsal = fixture.find("  rehearse-public:\n").expect("rehearsal job");
            let offset = fixture[rehearsal..]
                .find(original)
                .expect("missing mutation anchor in rehearsal or publish");
            let start = rehearsal + offset;
            let mut invalid = fixture.to_owned();
            invalid.replace_range(start..start + original.len(), replacement);
            assert!(
                policy::validate_workflow_bytes(
                    &root,
                    Path::new(".github/workflows/release.yml"),
                    invalid.as_bytes(),
                    &repository_policy,
                )
                .is_err(),
                "release rehearsal mutation was accepted: {original}"
            );
        }
    }
}

#[test]
fn incident_path_regression_remains_in_the_native_workspace_suite() {
    struct Strings(Vec<String>);
    impl<'ast> Visit<'ast> for Strings {
        fn visit_lit_str(&mut self, literal: &'ast syn::LitStr) {
            self.0.push(literal.value());
        }

        fn visit_expr_macro(&mut self, expression: &'ast syn::ExprMacro) {
            if expression.mac.path.is_ident("vec") {
                let values =
                    syn::punctuated::Punctuated::<syn::LitStr, syn::Token![,]>::parse_terminated
                        .parse2(expression.mac.tokens.clone())
                        .expect("native suite argument vector parses");
                self.0.extend(values.iter().map(syn::LitStr::value));
            }
            syn::visit::visit_expr_macro(self, expression);
        }
    }

    let source = include_str!("build_context.rs");
    let file = syn::parse_file(source).expect("build-context tests parse");
    let incident = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(function)
                if function.sig.ident
                    == "isolated_install_child_uses_the_canonical_source_namespace" =>
            {
                Some(function)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(incident.len(), 1, "incident regression must be unique");
    let incident = incident[0];
    assert!(
        incident
            .attrs
            .iter()
            .any(|attr| attr.path().is_ident("test"))
    );
    assert!(
        !incident
            .attrs
            .iter()
            .any(|attr| attr.path().is_ident("ignore"))
    );
    let mut strings = Strings(Vec::new());
    strings.visit_item_fn(incident);
    assert!(
        strings
            .0
            .iter()
            .any(|value| value == "generated_package_unmanaged_child")
    );

    let suites_source = include_str!("../src/suites.rs");
    assert!(suites_source.contains("Suite::Native => native(root, &toolchains.stable, false)"));
    let suites = syn::parse_file(suites_source).expect("suite source parses");
    let native = suites
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == "native" => Some(function),
            _ => None,
        })
        .expect("native suite implementation");
    let mut native_strings = Strings(Vec::new());
    native_strings.visit_item_fn(native);
    assert!(native_strings.0.iter().any(|value| value == "test"));
    assert!(
        suites_source
            .contains("for command in memcordon_ci::native_test_plan::commands(release_mode)")
    );
    assert!(suites_source.contains(
        "cargo_with_deadline(root, stable, \"test\", command.arguments, command.deadline)"
    ));
    for release_mode in [false, true] {
        let commands = memcordon_ci::native_test_plan::commands(release_mode);
        assert!(!commands.is_empty(), "native test plan must run Cargo");
        for command in commands {
            for required in ["--workspace", "--all-targets", "--all-features"] {
                assert!(
                    command.arguments.contains(&required),
                    "native suite dropped {required} in release_mode={release_mode}"
                );
            }
        }
    }
}

#[test]
fn macos_deadline_rejects_missing_native_fingerprint_and_failure_evidence() {
    let root = repository_root();
    let repository_policy = config::policy(&root).expect("repository policy");
    let fixture = include_str!("../../../.github/workflows/ci.yml");
    policy::validate_workflow_bytes(
        &root,
        Path::new(".github/workflows/ci.yml"),
        fixture.as_bytes(),
        &repository_policy,
    )
    .expect("complete independent deadline lane");
    for missing in [
        "./ci-native-fingerprint.exe --output target/ci/native-inputs.bin",
        "target/ci/deadline-evidence",
    ] {
        let invalid = fixture.replace(missing, "missing-deadline-proof");
        assert!(
            policy::validate_workflow_bytes(
                &root,
                Path::new(".github/workflows/ci.yml"),
                invalid.as_bytes(),
                &repository_policy
            )
            .is_err(),
            "missing required evidence was accepted: {missing}"
        );
    }
}

fn workflow_with_job_timeout(fixture: &str, job_id: &str, timeout_minutes: u64) -> Vec<u8> {
    let mut document: Value =
        serde_yaml::from_str(fixture).expect("workflow fixture should deserialize");
    let jobs_key = Value::String(String::from("jobs"));
    let timeout_key = Value::String(String::from("timeout-minutes"));
    let job_key = Value::String(job_id.to_owned());
    let jobs = document
        .as_mapping_mut()
        .and_then(|workflow| workflow.get_mut(&jobs_key))
        .and_then(Value::as_mapping_mut)
        .expect("workflow fixture should contain jobs");
    let job = jobs
        .get_mut(&job_key)
        .and_then(Value::as_mapping_mut)
        .expect("workflow fixture should contain the selected job");
    job.insert(timeout_key, Value::Number(timeout_minutes.into()));
    serde_yaml::to_string(&document)
        .expect("workflow fixture should serialize")
        .into_bytes()
}

#[test]
fn deep_ci_fuzz_timeout_covers_the_complete_target_set() {
    let root = repository_root();
    let repository_policy = config::policy(&root).expect("repository policy should parse");
    let fixture = include_str!("../../../.github/workflows/deep-ci.yml");
    policy::validate_workflow_bytes(
        &root,
        Path::new(".github/workflows/deep-ci.yml"),
        fixture.as_bytes(),
        &repository_policy,
    )
    .expect("the exact deep CI workflow should pass");

    for timeout_minutes in [30, 45, 59, 61] {
        let invalid = workflow_with_job_timeout(fixture, "fuzz", timeout_minutes);
        let error = policy::validate_workflow_bytes(
            &root,
            Path::new(".github/workflows/deep-ci.yml"),
            &invalid,
            &repository_policy,
        )
        .expect_err("a changed fuzz shard deadline must fail");
        assert!(
            error
                .to_string()
                .contains("deep CI fuzz timeout differs from workload deadline"),
            "unexpected workflow policy error: {error}"
        );
    }
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
fn windows_package_channel_restores_lifecycle_evidence_at_its_leaf() {
    let root = repository_root();
    let repository_policy = config::policy(&root).expect("repository policy should parse");
    let exact = include_str!("../../../.github/workflows/release.yml").replace("\r\n", "\n");
    policy::validate_workflow_bytes(
        &root,
        Path::new(".github/workflows/release.yml"),
        exact.as_bytes(),
        &repository_policy,
    )
    .expect("the exact release workflow should restore lifecycle evidence at its leaf");

    let restored_at_report_root = r#"      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c
        with:
          name: release-windows-provider-lifecycle-${{ matrix.id }}
          path: target/ci/reports/windows-sealed-v2/provider-lifecycle
"#;
    let failed_layout = r#"      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c
        with:
          name: release-windows-provider-lifecycle-${{ matrix.id }}
          path: target/ci/reports/windows-sealed-v2
"#;
    let invalid = exact.replacen(restored_at_report_root, failed_layout, 1);
    assert_ne!(
        invalid, exact,
        "provider-lifecycle download mutation must apply"
    );
    let error = policy::validate_workflow_bytes(
        &root,
        Path::new(".github/workflows/release.yml"),
        invalid.as_bytes(),
        &repository_policy,
    )
    .expect_err("the failed package-channel evidence layout must be rejected");
    assert!(
        error
            .to_string()
            .contains("windows-package-channel download inputs differ"),
        "unexpected package-channel policy error: {error}"
    );
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
            "      - run: ./target/ci/control-bootstrap/ci-bootstrap/memcordon-ci --build-context target/ci/native-inputs.bin release verify-public\n",
            "",
            "verify-public step count differs",
        ),
        (
            "target cache path",
            "          path: target/ci/verify-bootstrap\n          key: managed-v2-cargo-target-release-verify-public-v2-",
            "          path: target/ci/other\n          key: managed-v2-cargo-target-release-verify-public-v2-",
            "verify-public verify-public-target cache inputs differ",
        ),
    ] {
        let verify = exact.find("  verify-public:\n").expect("verify-public job");
        let offset = exact[verify..]
            .find(source)
            .expect("verify-public mutation anchor");
        let start = verify + offset;
        let mut invalid = exact.clone();
        invalid.replace_range(start..start + source.len(), replacement);
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

#[test]
fn artifact_upload_action_retries_exactly_and_fails_closed() {
    let exact =
        include_str!("../../../.github/actions/upload-artifact/action.yml").replace("\r\n", "\n");
    policy::validate_upload_artifact_action_bytes(exact.as_bytes())
        .expect("the bounded artifact upload action should pass");

    let retry_two = exact
        .find("    - id: retry-two\n")
        .expect("final retry fixture must be present");
    let missing_final = &exact[..retry_two];
    policy::validate_upload_artifact_action_bytes(missing_final.as_bytes())
        .expect_err("a missing final retry must be rejected");

    for (name, source, replacement) in [
        (
            "pin",
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            "actions/upload-artifact@0000000000000000000000000000000000000000",
        ),
        (
            "retry condition",
            "steps.initial.outcome == 'failure'",
            "steps.initial.conclusion == 'failure'",
        ),
        (
            "retry overwrite",
            "        overwrite: true\n",
            "        overwrite: false\n",
        ),
        (
            "input forwarding",
            "        path: ${{ inputs.path }}\n",
            "        path: ${{ inputs.name }}\n",
        ),
        (
            "final failure",
            "    - id: retry-two\n      if:",
            "    - id: retry-two\n      continue-on-error: true\n      if:",
        ),
    ] {
        let invalid = exact.replacen(source, replacement, 1);
        assert_ne!(invalid, exact, "{name} mutation must apply");
        policy::validate_upload_artifact_action_bytes(invalid.as_bytes())
            .expect_err("artifact upload retry mutation must be rejected");
    }
}

#[test]
fn every_workflow_upload_uses_the_bounded_action() {
    let workflows = [
        include_str!("../../../.github/workflows/ci.yml"),
        include_str!("../../../.github/workflows/deep-ci.yml"),
        include_str!("../../../.github/workflows/backend-certification.yml"),
        include_str!("../../../.github/workflows/release.yml"),
    ];
    let local = "uses: ./.github/actions/upload-artifact";
    let direct = "uses: actions/upload-artifact@";
    let count: usize = workflows
        .iter()
        .map(|workflow| {
            assert!(
                !workflow.contains(direct),
                "workflow bypasses the bounded artifact upload action"
            );
            workflow.matches(local).count()
        })
        .sum();
    assert_eq!(count, 58, "workflow artifact upload inventory differs");
}
