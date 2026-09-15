use std::collections::BTreeSet;

use memcordon_ci::source_registry::coverage::{Coverage, Evidence, SkipPolicy, parse_test_list};
use memcordon_ci::source_registry::native_runner;

fn route() -> Coverage {
    Coverage {
        suite: "native".into(),
        cargo_package: "memcordon".into(),
        cargo_target: "bin:memcordon-sealed-agent".into(),
        test_binary: "memcordon-sealed-agent".into(),
        tests: vec!["windows::qualification::*".into()],
        runner: vec!["windows-x64".into(), "windows-arm64".into()],
        skip_policy: SkipPolicy::Forbidden,
        evidence: Evidence::Behavior,
    }
}

#[test]
fn native_list_requires_unique_test_records() {
    let names =
        parse_test_list("windows::qualification::reject: test\nwindows::other: test\n").unwrap();
    assert_eq!(names.len(), 2);
    for invalid in [
        "f: test\nf: test\n",
        "f: benchmark\n",
        "running 1 test\n",
        ": test\n",
    ] {
        assert!(parse_test_list(invalid).is_err(), "{invalid}");
    }
}

#[test]
fn declared_module_selectors_cannot_match_neighbor_or_absent_tests() {
    let names = parse_test_list(
        "windows::qualification::reject: test\nwindows::qualification_extra::accept: test\n",
    )
    .unwrap();
    assert_eq!(
        route().resolve(&names).unwrap(),
        BTreeSet::from(["windows::qualification::reject".into()])
    );
    assert!(route().resolve(&BTreeSet::new()).is_err());
    let mut malformed = route();
    malformed.tests = vec!["windows::*::reject".into()];
    assert!(malformed.resolve(&names).is_err());
}

#[test]
fn native_adapter_preserves_exact_selector_and_measures_executed_binary() {
    let directory = tempfile::tempdir().unwrap();
    let binary = std::env::current_exe().unwrap();
    native_runner::run(
        directory.path(),
        std::time::Duration::from_secs(30),
        &[
            binary.as_os_str().to_owned(),
            "--exact".into(),
            "native_list_requires_unique_test_records".into(),
        ],
    )
    .unwrap();
    let evidence = std::fs::read_dir(directory.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let evidence: native_runner::NativeExecution =
        serde_json::from_slice(&std::fs::read(evidence).unwrap()).unwrap();
    assert!(evidence.success);
    assert_eq!(evidence.binary, binary);
    assert_eq!(
        evidence.selected_tests,
        BTreeSet::from(["native_list_requires_unique_test_records".into()])
    );
    assert!(
        evidence
            .listed_tests
            .contains("native_adapter_preserves_exact_selector_and_measures_executed_binary")
    );
    assert_eq!(
        evidence
            .arguments
            .iter()
            .map(|argument| argument.display.as_str())
            .collect::<Vec<_>>(),
        ["--exact", "native_list_requires_unique_test_records"]
    );
}

#[test]
fn runner_configuration_is_structured_argv_even_for_spaces_and_metacharacters() {
    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("native runner;$value");
    let path = native_runner::write_configuration(
        directory.path(),
        &executable,
        std::time::Duration::from_secs(1),
    )
    .unwrap();
    let value: toml::Value = toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let arguments = value["target"]["cfg(all())"]["runner"].as_array().unwrap();
    assert_eq!(
        arguments.first().unwrap().as_str().unwrap(),
        executable.to_str().unwrap()
    );
    assert_eq!(arguments.last().unwrap().as_str().unwrap(), "--");
}

#[test]
fn cargo_runner_records_the_actual_selected_test_artifact() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    std::fs::create_dir(root.join("tests")).unwrap();
    std::fs::write(root.join("Cargo.toml"), "[package]\nname = \"native-evidence-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n[workspace]\n").unwrap();
    std::fs::write(root.join("tests/routes.rs"), "#[test]\nfn observed() { assert_eq!(2 + 2, 4); }\n#[test]\n#[ignore = \"explicit fixture\"]\nfn ignored_contract() {}\n").unwrap();
    let directory = root.join("evidence");
    let configuration = native_runner::write_configuration(
        &directory,
        std::path::Path::new(env!("CARGO_BIN_EXE_memcordon-ci")),
        std::time::Duration::from_secs(30),
    )
    .unwrap();
    let output = memcordon_ci::command::CommandSpec::new(
        env!("CARGO"),
        &root,
        std::time::Duration::from_secs(30),
    )
    .args(["test", "--offline", "--message-format=json", "--config"])
    .arg(configuration)
    .args(["--test", "routes", "--", "--exact", "observed"])
    .output()
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let transcript = native_runner::decode_cargo_stdout(&directory, &output.stdout).unwrap();
    memcordon_ci::capability::require_exact_standard_test_success(&transcript, "observed").unwrap();
    let evidence = native_runner::bind_artifacts(&directory, &output.stdout, true).unwrap();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].package_name, "native-evidence-fixture");
    assert_eq!(evidence[0].target_name, "routes");
    assert_eq!(
        evidence[0].execution.executed_tests,
        BTreeSet::from(["observed".into()])
    );
    assert_eq!(
        evidence[0].execution.ignored_tests,
        BTreeSet::from(["ignored_contract".into()])
    );
    let record_path = std::fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .unwrap();
    let mut record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&record_path).unwrap()).unwrap();
    record["schema"] = serde_json::json!(2);
    std::fs::write(&record_path, serde_json::to_vec(&record).unwrap()).unwrap();
    assert!(native_runner::bind_artifacts(&directory, &output.stdout, true).is_err());
    record["schema"] = serde_json::json!(1);
    record["binary_sha256"] = serde_json::json!("stale-binary-digest");
    std::fs::write(&record_path, serde_json::to_vec(&record).unwrap()).unwrap();
    assert!(native_runner::bind_artifacts(&directory, &output.stdout, true).is_err());
}

#[test]
fn framed_native_stdout_preserves_protocol_shaped_and_non_utf8_test_output() {
    let directory = std::path::Path::new("unique-command-directory");
    let native = b"{\"reason\":\"build-finished\",\"success\":true}\n\xff\n";
    let mut stream = b"{\"reason\":\"build-finished\",\"success\":true}\n".to_vec();
    let frame = native_runner::encode_native_stdout(directory, native).unwrap();
    stream.extend_from_slice(&frame);
    let doctest = b"ordinary doctest text\n{\"reason\":\"build-finished\",\"success\":true}\n{\"native_stdout_schema\":1,\"native_stdout_token\":\"unrelated\",\"bytes\":[]}\n";
    stream.extend_from_slice(doctest);
    let mut expected = native.to_vec();
    expected.extend_from_slice(doctest);
    assert_eq!(
        native_runner::decode_cargo_stdout(directory, &stream).unwrap(),
        expected
    );
    let mut invalid: serde_json::Value = serde_json::from_slice(&frame).unwrap();
    invalid["native_stdout_schema"] = serde_json::json!(2);
    assert!(
        native_runner::decode_cargo_stdout(directory, &serde_json::to_vec(&invalid).unwrap())
            .is_err()
    );
    invalid["native_stdout_schema"] = serde_json::json!(1);
    invalid["extra"] = serde_json::json!(1);
    assert!(
        native_runner::decode_cargo_stdout(directory, &serde_json::to_vec(&invalid).unwrap())
            .is_err()
    );
}

#[test]
fn skipped_or_unexecuted_tests_cannot_be_promoted_to_successful_coverage() {
    let failure = memcordon_ci::command::preserve_observed_outcome(
        Err(memcordon_testkit::ProcessTestError::Spawn(
            std::io::Error::other("original-spawn-failure"),
        )),
        Err(memcordon_ci::CiError::Message(
            "evidence-write-failure".into(),
        )),
    )
    .unwrap_err()
    .to_string();
    assert!(failure.contains("original-spawn-failure"));
    assert!(failure.contains("evidence-write-failure"));
    let selected = BTreeSet::from(["active".into(), "ignored".into()]);
    let ignored = BTreeSet::from(["ignored".into()]);
    let summary = b"test result: ok. 1 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s\n";
    assert_eq!(
        native_runner::verify_successful_execution(summary, &selected, &ignored, &[]).unwrap(),
        BTreeSet::from(["active".into()])
    );
    assert!(
        native_runner::verify_successful_execution(
            summary,
            &selected,
            &ignored,
            &["--include-ignored".into()]
        )
        .is_err()
    );
    assert!(
        native_runner::verify_successful_execution(
            b"test result: ok. 0 passed; 0 failed; 0 ignored;\n",
            &selected,
            &ignored,
            &[]
        )
        .is_err()
    );
    assert!(native_runner::verify_successful_execution(b"", &selected, &ignored, &[]).is_err());
}

fn attestation_fixture() -> (
    memcordon_ci::source_registry::coverage::Plan,
    serde_json::Value,
) {
    use memcordon_ci::source_registry::coverage::{Plan, PlannedSource};
    use memcordon_ci::source_registry::observation::digest;
    let plan = Plan {
        schema: 1,
        commit: "ab12".into(),
        suite: "native".into(),
        sources: vec![PlannedSource {
            source_id: "windows-contract".into(),
            route: route(),
        }],
    };
    let invocation = serde_json::json!({"program": {"display": "cargo", "raw": null}, "arguments": [], "current_directory": null});
    let typed: memcordon_ci::source_registry::observation::Invocation =
        serde_json::from_value(invocation.clone()).unwrap();
    let execution = serde_json::json!({"schema": 1, "binary": "agent.exe", "binary_sha256": "binary", "arguments": [], "listed_tests": ["windows::qualification::reject"], "selected_tests": ["windows::qualification::reject"], "ignored_tests": [], "executed_tests": ["windows::qualification::reject"], "stdout_sha256": "stdout", "stderr_sha256": "stderr", "success": true});
    let bound = serde_json::json!({"package_id": "package", "package_name": "memcordon", "manifest_path": "Cargo.toml", "target_name": "memcordon-sealed-agent", "target_kinds": ["bin"], "features": ["test-support"], "execution": execution});
    let observation = serde_json::json!({"toolchain": "stable", "invocation": invocation, "command_sha256": digest(&serde_json::to_vec(&typed).unwrap()), "stdout_sha256": "stdout", "stderr_sha256": "stderr", "exit_code": 0, "success": true, "error": null, "native_executions": [bound]});
    let journal = serde_json::json!({
        "schema": 1, "commit": plan.commit, "checkout_clean": true, "suite": "native", "workflow": "CI", "run_id": "123", "job": "native-windows-x64", "runner": "hosted-test-runner",
        "architecture": "x86_64", "platform": "windows", "execution_attested": false, "suite_success": true, "native_invocations": 1,
        "observations": [observation]
    });
    (plan, journal)
}

#[test]
fn attestation_rejects_wrong_identity_failed_suite_and_missing_execution() {
    use memcordon_ci::source_registry::observation::attest_bytes;
    let (plan, journal) = attestation_fixture();
    assert_eq!(
        attest_bytes(&plan, &serde_json::to_vec(&journal).unwrap())
            .unwrap()
            .sources
            .len(),
        1
    );
    for (key, value) in [
        ("commit", serde_json::json!("other")),
        ("suite", serde_json::json!("stress")),
        ("suite_success", serde_json::json!(false)),
        ("job", serde_json::Value::Null),
    ] {
        let mut invalid = journal.clone();
        invalid[key] = value;
        assert!(
            attest_bytes(&plan, &serde_json::to_vec(&invalid).unwrap()).is_err(),
            "{key}"
        );
    }
    let mut skipped = journal.clone();
    skipped["observations"][0]["native_executions"][0]["execution"]["executed_tests"] =
        serde_json::json!([]);
    assert!(attest_bytes(&plan, &serde_json::to_vec(&skipped).unwrap()).is_err());
    let mut replaced = journal;
    replaced["observations"][0]["invocation"]["program"]["display"] =
        serde_json::json!("replacement");
    assert!(attest_bytes(&plan, &serde_json::to_vec(&replaced).unwrap()).is_err());
}

#[test]
fn merge_requires_each_declared_runner_and_exact_coverage_digest() {
    use memcordon_ci::source_registry::observation::{attest_bytes, validate_merge};
    let (plan, journal) = attestation_fixture();
    let x64 = attest_bytes(&plan, &serde_json::to_vec(&journal).unwrap()).unwrap();
    assert!(validate_merge(&plan.commit, std::slice::from_ref(&plan), &[x64]).is_err());
    let x64 = attest_bytes(&plan, &serde_json::to_vec(&journal).unwrap()).unwrap();
    let mut arm_journal = journal;
    arm_journal["architecture"] = serde_json::json!("aarch64");
    let arm = attest_bytes(&plan, &serde_json::to_vec(&arm_journal).unwrap()).unwrap();
    let mut attestations = [x64, arm];
    validate_merge(&plan.commit, std::slice::from_ref(&plan), &attestations).unwrap();
    attestations[0].sources[0].coverage_sha256 = "changed".into();
    assert!(validate_merge(&plan.commit, std::slice::from_ref(&plan), &attestations).is_err());
}
