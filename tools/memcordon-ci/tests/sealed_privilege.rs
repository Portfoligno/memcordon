const PRIVILEGED_REASON: &str = "#[ignore = \"requires privileged Linux sealed certification\"]";
const CREDENTIAL_TRANSITION_REASON: &str =
    "#[ignore = \"requires privileged Linux sealed credential-transition certification\"]";

fn semantic_function_region(source: &str, signature: &str, next_signature: &str) -> Option<String> {
    let mut lines = source.lines();
    loop {
        if lines.next()? == signature {
            break;
        }
    }
    let mut region = Vec::new();
    for line in lines {
        if line == next_signature {
            return Some(region.join("\n"));
        }
        region.push(line);
    }
    None
}

#[test]
fn semantic_function_region_accepts_lf_and_crlf_without_broad_matching() {
    let lf = "fn selected() {\n    structured_call();\n}\n\nfn following() {\n}\n";
    let crlf = lf.replace('\n', "\r\n");
    let expected = "    structured_call();\n}\n";

    for source in [lf, crlf.as_str()] {
        assert_eq!(
            semantic_function_region(source, "fn selected() {", "fn following() {").as_deref(),
            Some(expected),
        );
        assert!(semantic_function_region(source, "fn selected", "fn following() {").is_none());
        assert!(semantic_function_region(source, "fn selected() {", "fn following").is_none());
    }
}

#[test]
fn post_guardian_errors_use_one_finalizer_and_deadline_proves_no_residue() {
    let launch = include_str!("../../../crates/memcordon-sealed-agent/src/linux/launch.rs");
    let execute =
        semantic_function_region(launch, "fn execute_inner(", "fn wait_command_exit_grace(")
            .expect("execute_inner must have a semantic boundary before its next helper");
    let channels = execute
        .find("cleanup_guard.set_guardian_channels(guardian_write, guardian_terminal_read);")
        .expect("guardian channels must enter the cleanup owner");
    let outcome = execute
        .find("let outcome = (|| -> Result<TerminalFacts, String> {")
        .expect("post-guardian work must enter one result funnel");
    let finalizer = execute
        .find("Err(error) => match cleanup_guard.finalize_failure()")
        .expect("every post-guardian error must use the explicit finalizer");
    assert!(channels < outcome && outcome < finalizer);
    assert!(execute.contains("MCSEALED-BOUNDARY-NOT-RETIRED: primary={error}; cleanup={cleanup}"));

    let scenarios = include_str!("../../../crates/memcordon-sealed-agent/tests/linux_sealed.rs");
    let deadline = semantic_function_region(
        scenarios,
        "fn sealed_expired_deadline_never_authorizes_and_retires() {",
        "fn sealed_staged_fixture_is_isolated_and_removed_after_retirement() {",
    )
    .expect("expired-deadline selector must have a semantic test boundary");
    for required in [
        "let transaction_path = record_path.with_extension(\"new\");",
        "!record_path.exists()",
        "!transaction_path.exists()",
        "!cgroup_path.exists()",
        "memcordon_sealed_agent::linux::recovery::recover()",
        "ambiguity.is_empty()",
    ] {
        assert!(
            deadline.contains(required),
            "expired-deadline retirement proof omitted {required}"
        );
    }
}

#[test]
fn generic_workspace_tests_ignore_every_privileged_linux_sealed_selector() {
    let privileged_tests = [
        include_str!("../../../crates/memcordon-sealed-agent/tests/linux_sealed.rs"),
        include_str!("../../../crates/memcordon-sealed-agent/tests/linux_faults.rs"),
        include_str!("../../../crates/memcordon-sealed-agent/tests/linux_recovery.rs"),
        include_str!("../../../crates/memcordon-sealed-agent/tests/linux_package.rs"),
    ];
    let ignored = privileged_tests
        .iter()
        .map(|source| {
            source.matches(PRIVILEGED_REASON).count()
                + source.matches(CREDENTIAL_TRANSITION_REASON).count()
        })
        .sum::<usize>();
    assert_eq!(ignored, 45, "all root-required selectors must be ignored");

    let provider = include_str!("../../../crates/memcordon-sealed-agent/tests/linux_provider.rs");
    assert!(!provider.contains(PRIVILEGED_REASON));
    assert_eq!(provider.matches("#[test]").count(), 3);
}

#[test]
fn dedicated_certification_explicitly_selects_ignored_tests() {
    let runner = include_str!("../src/sealed_linux.rs");
    assert!(runner.contains("if scenario.privileged()"));
    assert!(runner.contains("test_arguments.push(\"--ignored\")"));
    assert!(runner.contains("scenario.name, \"--exact\""));
    assert!(runner.contains("\"--test-threads=1\""));
    assert!(runner.contains("sealed-scenario-progress.json"));
    for state in ["Pending", "Running", "Passed", "Failed"] {
        assert!(
            runner.contains(state),
            "typed scenario progress omitted {state}"
        );
    }
    assert!(runner.contains("bounded_diagnostic_text(&message)"));
    assert!(runner.contains("progress[index].diagnostic = Some(diagnostic)"));
    assert!(runner.contains("observe_scenario_process"));
    assert!(runner.contains("evidence-status={evidence_status:?}"));
    assert!(runner.contains("failed to persist typed scenario evidence"));
    assert!(runner.contains("MCSEALED-CONCURRENCY-EVIDENCE:"));
    assert!(runner.contains("sealed-concurrency-report.json"));
    assert!(runner.contains("typed concurrency evidence did not prove live disjoint overlap"));
    assert!(runner.contains("MCSEALED-FAULT-EVIDENCE:"));
    assert!(runner.contains("parse_fault_evidence"));
    assert!(runner.contains("FaultInjectionReport"));
    assert!(runner.contains("schema_version: 2"));
    assert!(runner.contains("remove_file(report_dir.join(\"sealed-scenario-progress.json\"))"));
}

#[test]
fn fault_producer_emits_truthful_observation_before_contract_assertions() {
    let producer =
        include_str!("../../../crates/memcordon-sealed-agent/tests/support/sealed_faults.rs");
    let assertion = producer
        .find("assert_eq!(rejection.code, code)")
        .expect("fault producer must assert the exact rejection code");
    let emission = producer
        .find("emit_fault_evidence(selector, captured);")
        .expect("fault producer must emit typed evidence");
    assert!(
        emission < assertion,
        "truthful typed outcome must be emitted before selector contract assertions"
    );
}

#[test]
fn release_inventory_promotes_and_binds_public_provider_evidence() {
    let evidence = include_str!("../src/release_evidence.rs");
    assert!(evidence.contains("validate_linux_fault_evidence"));
    assert!(evidence.contains("LINUX_FAULT_EVIDENCE_TESTS"));
    let specification = include_str!("../../../spec/sealed-linux-v2.md");
    for name in [
        "provider-package-verification.json",
        "provider-qualification-v2.json",
        "setid-transition.json",
        "sudo-transition.json",
        "file-capability-transition.json",
        "caller-envelope.json",
        "mount-context.json",
        "fault-injection.json",
        "cleanup-leak-check.json",
    ] {
        assert!(evidence.contains(name), "release inventory omitted {name}");
        assert!(
            specification.contains(name),
            "sealed specification omitted {name}"
        );
    }
    for required in [
        "LinuxProviderPackageVerification",
        "validate_linux_provider_package",
        "validate_linux_public_launch",
        "linux_provider_binding",
        "linux_qualification_complete",
        "BoundaryMechanismEvidence::LinuxPidNamespaceCgroupV2",
        "CredentialTransitionDisposition::PreserveCallerEnvelope",
        "SupervisionTerminal::AttemptOutcome",
    ] {
        assert!(
            evidence.contains(required),
            "release validation omitted {required}"
        );
    }
}

#[test]
fn credential_redesign_fuzz_targets_bind_real_parser_surfaces() {
    let manifest = include_str!("../../../fuzz/Cargo.toml");
    let suite = include_str!("../src/suites.rs");
    let targets = [
        (
            "caller-envelope-status",
            include_str!("../../../fuzz/fuzz_targets/caller_envelope_status.rs"),
            "parse_proc_status",
        ),
        (
            "capability-mask",
            include_str!("../../../fuzz/fuzz_targets/capability_mask.rs"),
            "parse_capability_mask",
        ),
        (
            "namespace-identity",
            include_str!("../../../fuzz/fuzz_targets/namespace_identity.rs"),
            "parse_namespace_identity",
        ),
        (
            "broker-protocol-v2",
            include_str!("../../../fuzz/fuzz_targets/broker_protocol_v2.rs"),
            "decode_launch_broker_request",
        ),
        (
            "qualification-receipt-v2",
            include_str!("../../../fuzz/fuzz_targets/qualification_receipt_v2.rs"),
            "sealed_qualification_v2_is_valid",
        ),
        (
            "terminal-receipt-v2",
            include_str!("../../../fuzz/fuzz_targets/terminal_receipt_v2.rs"),
            "sealed_terminal_v2_is_valid",
        ),
        (
            "linux-evidence-v2",
            include_str!("../../../fuzz/fuzz_targets/linux_evidence_v2.rs"),
            "BoundaryMechanismEvidence",
        ),
        (
            "service-unit-policy",
            include_str!("../../../fuzz/fuzz_targets/service_unit_policy.rs"),
            "fuzz_linux_service_unit_policy",
        ),
        (
            "provider-recursion-proof",
            include_str!("../../../fuzz/fuzz_targets/provider_recursion_proof.rs"),
            "cgroup_membership_is_sealed",
        ),
        (
            "mount-context-manifest",
            include_str!("../../../fuzz/fuzz_targets/mount_context_manifest.rs"),
            "fuzz_linux_mount_context_manifest",
        ),
    ];

    for (target, source, parser) in targets {
        assert!(
            manifest.contains(&format!("name = \"{target}\"")),
            "fuzz manifest omitted {target}"
        );
        assert!(
            suite.contains(&format!("\"{target}\"")),
            "fuzz suite omitted {target}"
        );
        assert!(
            source.contains(parser),
            "{target} does not exercise {parser}"
        );
    }
}

#[test]
fn sealed_fixtures_are_isolated_and_status_assertions_are_mandatory() {
    let support = include_str!("../../../crates/memcordon-sealed-agent/tests/support/mod.rs");
    let scenarios = include_str!("../../../crates/memcordon-sealed-agent/tests/linux_sealed.rs");
    let fixture = include_str!(
        "../../../crates/memcordon-sealed-agent/src/bin/memcordon-sealed-test-fixture.rs"
    );

    for required in [
        ".tempdir_in(\"/tmp\")",
        ".create_new(true)",
        "directory_metadata.uid() != 0",
        "program_metadata.uid() != 0",
        "Permissions::from_mode(0o755)",
        "Permissions::from_mode(0o555)",
    ] {
        assert!(support.contains(required), "fixture omitted {required}");
    }
    assert!(!support.contains("set_permissions(Path::new(fixture())"));
    assert!(scenarios.contains("fixture mode {mode} did not complete successfully"));
    assert!(scenarios.contains("sealed_native_nonzero_exit_preserves_provenance"));
    assert!(scenarios.contains("assert_eq!(captured.facts.child_status, 17)"));
    assert!(scenarios.contains("retired attempt leaked its isolated fixture"));
    assert!(scenarios.contains("expired attempt leaked its isolated fixture"));
    assert!(fixture.contains("\"retained-stream\""));
    assert!(fixture.contains("Duration::from_millis(500)"));
    assert!(fixture.contains("if descendant == -1"));
    assert!(fixture.contains("retained-stdout-release"));
    assert!(fixture.contains("retained-stderr-release"));
    assert!(fixture.contains("\"fault-ready\""));
    assert!(scenarios.contains("prepare_fault_target"));
    assert!(!scenarios.contains("run(\"child\", Lifetime::Workload)"));
    for required in [
        ".request(\"retained-stream\", Lifetime::Workload)",
        "captured.execution_millis >= 400",
        "captured.execution_millis < 10_000",
        "captured.facts.exec_status, TargetExecStatus::Succeeded",
        "captured.facts.spawn_error_reported",
        "!captured.facts.deadline_exceeded",
        "!captured.facts.memory_limit_exceeded",
        "retained-stream attempt leaked its isolated fixture",
    ] {
        assert!(
            scenarios.contains(required),
            "retained-stream scenario omitted {required}"
        );
    }
}

#[test]
fn package_scenarios_tamper_and_recover_real_installed_state() {
    let package = include_str!("../../../crates/memcordon-sealed-agent/src/package.rs");
    let scenarios = include_str!("../../../crates/memcordon-sealed-agent/tests/linux_package.rs");
    let runner = include_str!("../src/sealed_linux.rs");

    for required in [
        "MCSEALED-PACKAGE-VERIFY: installed package is incomplete",
        "custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)",
        "metadata.uid() != 0 || metadata.gid() != 0",
        "metadata.mode() & 0o7777 != expected_mode",
        "actual != expected_bytes",
    ] {
        assert!(
            package.contains(required),
            "installed package verification omitted {required}"
        );
    }
    assert_eq!(package.matches("verify_installed_package()?;").count(), 2);
    let install = runner
        .find("privileged_agent(root, [\"package\", \"install\", \"--ephemeral-ci\"])")
        .expect("certification must install the provider");
    let verify = runner
        .find("agent(root, [\"package\", \"verify\"])")
        .expect("certification must verify the installed provider");
    let upgrade = runner
        .find("privileged_agent(root, [\"package\", \"upgrade\", \"--ephemeral-ci\"])")
        .expect("certification must upgrade the provider");
    assert!(install < verify && verify < upgrade);
    for required in [
        "tampered.set_mode(0o775)",
        "assert_eq!(rejected.status.code(), Some(125))",
        "rejection.starts_with(\"MCSEALED-PACKAGE-VERIFY:\")",
        "AttemptRecord::create(",
        "libc::pid_t::MAX",
        "record.transition(\"boundary-created\")",
        "record-only stale recovery fixture must not stage an attempt cgroup",
        "upgrade advertised before retiring the authenticated stale record",
        "stale_record.disarm()",
        "assert_successful_public_execution(&execution)",
        "spawn-class={:?}",
        "os-code={:?}",
        "provider-rejection={:?}",
        "target-released={}",
        "typed-terminal={terminal}",
        "libc::kill(frontend_pid, 0)",
        ".args([\"package\", \"uninstall\", \"--ephemeral-ci\"])",
        "refusing to uninstall while sealed recovery is ambiguous",
        "assert_eq!(std::fs::read(&record_path).unwrap(), authenticated_before)",
        "refused uninstall damaged the installed provider",
        "live_record.record.take().unwrap().retire().unwrap()",
        "assert!(!record_path.exists())",
    ] {
        assert!(
            scenarios.contains(required),
            "privileged package scenario omitted {required}"
        );
    }
}

#[test]
fn package_stop_suppresses_success_noise_and_bounds_failure_diagnostics() {
    let package = include_str!("../../../crates/memcordon-sealed-agent/src/package.rs");
    let stop = semantic_function_region(
        package,
        "fn stop_unit(unit: &str) -> Result<(), String> {",
        "fn systemctl_output_diagnostic(output: &std::process::Output) -> serde_json::Value {",
    )
    .expect("stop_unit must precede its structured diagnostic helper");
    for required in [
        ".args([\"stop\", unit])",
        ".output()",
        "if output.status.success()",
        "return Ok(())",
        "systemctl_output_diagnostic(&output)",
        "MCSEALED-PACKAGE-STOP: unit={unit}",
        "load-state={state}",
        "load-state-error={error}",
    ] {
        assert!(
            stop.contains(required),
            "package stop path omitted {required}"
        );
    }
    assert!(
        !stop.contains(".status()"),
        "successful systemctl output must not escape through inherited streams"
    );
    for required in [
        "MAXIMUM_BYTES: usize = 4 * 1024",
        "\"encoding\": \"utf-8\"",
        "\"encoding\": \"hex\"",
        "\"original_bytes\": bytes.len()",
        "\"truncated\": truncated",
    ] {
        assert!(
            package.contains(required),
            "bounded systemctl diagnostic omitted {required}"
        );
    }
}

#[test]
fn certification_uses_a_nonroot_frontend_with_the_provider_access_group() {
    let runner = include_str!("../src/sealed_linux.rs");
    let identity = include_str!("../src/sealed_identity.rs");
    assert!(runner.contains("authorized_nonroot_memcordon"));
    assert!(runner.contains("Path::new(\"/usr/bin/cat\")"));
    assert!(runner.contains("[\"/proc/self/status\"]"));
    assert!(runner.contains("parse_credential_readback"));
    assert!(identity.contains("pub const SETPRIV_PATH: &str = \"/usr/bin/setpriv\""));
    assert!(identity.contains("OsString::from(\"--clear-groups\")"));
    assert!(identity.contains("OsString::from(\"--no-new-privs\")"));
    assert!(!runner.contains("OsString::from(\"--user\")"));
    assert!(!runner.contains("OsString::from(\"--group\")"));
    assert!(runner.contains("report_dir.join(\".sealed-public-launch.json\")"));
    assert!(runner.contains("OsString::from(\"--sealed\")"));
    assert!(runner.contains("OsString::from(\"--report\")"));
    assert!(runner.contains("public_report.as_os_str().to_os_string()"));
    assert!(runner.contains("OsString::from(\"/usr/bin/true\")"));
}
