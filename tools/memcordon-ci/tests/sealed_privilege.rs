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
    let launch = include_str!(
        "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/linux/launch.rs"
    );
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

    let scenarios =
        include_str!("../../../crates/memcordon-cli/tests/sealed_agent/linux_sealed.rs");
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
        "crate::linux::recovery::recover()",
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
    const STABLE_LEASE_SELECTOR: &str =
        "sealed_package_stable_lease_survives_legacy_inode_replacement";
    let privileged_tests = [
        include_str!("../../../crates/memcordon-cli/tests/sealed_agent/linux_sealed.rs"),
        include_str!("../../../crates/memcordon-cli/tests/sealed_agent/linux_faults.rs"),
        include_str!("../../../crates/memcordon-cli/tests/sealed_agent/linux_recovery.rs"),
        include_str!("../../../crates/memcordon-cli/tests/sealed_agent/linux_package.rs"),
    ];
    let ignored = privileged_tests
        .iter()
        .map(|source| {
            source.matches(PRIVILEGED_REASON).count()
                + source.matches(CREDENTIAL_TRANSITION_REASON).count()
        })
        .sum::<usize>();
    assert_eq!(ignored, 46, "all root-required selectors must be ignored");
    assert_eq!(
        privileged_tests[3].matches(STABLE_LEASE_SELECTOR).count(),
        1
    );
    assert_eq!(
        include_str!("../src/sealed_linux.rs")
            .matches(STABLE_LEASE_SELECTOR)
            .count(),
        1,
        "the stable lease selector must remain in the certified scenario registry"
    );
    assert_eq!(
        include_str!("../src/release_evidence.rs")
            .matches(STABLE_LEASE_SELECTOR)
            .count(),
        1,
        "the stable lease selector must remain in release evidence"
    );

    let provider =
        include_str!("../../../crates/memcordon-cli/tests/sealed_agent/linux_provider.rs");
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
        include_str!("../../../crates/memcordon-cli/tests/sealed_agent/support/sealed_faults.rs");
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
            "cgroup_membership::is_sealed",
        ),
        (
            "mount-context-manifest",
            include_str!("../../../fuzz/fuzz_targets/mount_context_manifest.rs"),
            "fuzz_linux_mount_context_manifest",
        ),
        (
            "runtime-manifest",
            include_str!("../../../fuzz/fuzz_targets/runtime_manifest.rs"),
            "fuzz_runtime_manifest",
        ),
        (
            "release-asset-components",
            include_str!("../../../fuzz/fuzz_targets/release_asset_components.rs"),
            "config::Release",
        ),
        (
            "agent-package-inspection",
            include_str!("../../../fuzz/fuzz_targets/agent_package_inspection.rs"),
            "AgentPackageInspectionV1",
        ),
        (
            "installed-provider-inspection",
            include_str!("../../../fuzz/fuzz_targets/installed_provider_inspection.rs"),
            "InstalledProviderInspectionV1",
        ),
        (
            "cargo-bin-inventory",
            include_str!("../../../fuzz/fuzz_targets/cargo_bin_inventory.rs"),
            "toml::Value",
        ),
        (
            "channel-pairing",
            include_str!("../../../fuzz/fuzz_targets/channel_pairing.rs"),
            "source_commit",
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
    let support = include_str!("../../../crates/memcordon-cli/tests/sealed_agent/support/mod.rs");
    let scenarios =
        include_str!("../../../crates/memcordon-cli/tests/sealed_agent/linux_sealed.rs");
    let fixture =
        include_str!("../../../crates/memcordon-cli/src/bin/memcordon-sealed-test-fixture.rs");

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
    let package =
        include_str!("../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/package.rs");
    let scenarios =
        include_str!("../../../crates/memcordon-cli/tests/sealed_agent/linux_package.rs");
    let runner = include_str!("../src/sealed_linux.rs");

    for required in [
        "MCSEALED-PACKAGE-VERIFY: installed package is incomplete",
        "ArtifactAccess::MetadataOnly => libc::O_PATH",
        "ArtifactAccess::Readable => 0",
        "custom_flags(access_flag | libc::O_CLOEXEC | libc::O_NOFOLLOW)",
        "let metadata = file",
        ".metadata()",
        "metadata.uid() != expected_uid || metadata.gid() != expected_gid",
        "metadata.mode() & 0o7777 != expected_mode",
        "actual != expected_bytes",
        "verify_metadata_artifact(",
        "std::path::Path::new(crate::linux::service::PACKAGE_LEASE)",
        "verify_readable_artifact(",
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
        "\"schema_version\": 3",
        "\"/usr/libexec/memcordon-sealed-agent\"",
        "\"/run/memcordon-sealed-package.lock\"",
    ] {
        assert!(
            runner.contains(required),
            "package evidence omitted {required}"
        );
    }
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
        "assert_active_capability_caller_rejected(&execution)",
        "MCSEALED-CALLER-ENVELOPE-CAPTURE",
        "MCSEALED-CREDENTIAL-TRANSITION-POLICY: callers with active capability sets are unsupported",
        "BoundarySetupPhase::RequestValidation",
        "assert!(!rejection.target_created)",
        "assert!(!rejection.target_released)",
        "assert!(!rejection.cleanup_attempted)",
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
    let package =
        include_str!("../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/package.rs");
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
    assert!(identity.contains("OsString::from(\"--inh-caps=-all\")"));
    assert!(identity.contains("OsString::from(\"--ambient-caps=-all\")"));
    assert!(identity.contains("OsString::from(\"--no-new-privs\")"));
    assert!(!runner.contains("OsString::from(\"--user\")"));
    assert!(!runner.contains("OsString::from(\"--group\")"));
    assert!(
        runner.contains("const PRE_SCENARIO_PUBLIC_REPORT: &str = \".sealed-public-launch.json\"")
    );
    assert!(runner.contains(
        "const POST_UPGRADE_PUBLIC_REPORT: &str = \".sealed-post-scenario-public-launch.json\""
    ));
    assert!(runner.contains("OsString::from(\"--sealed\")"));
    assert!(runner.contains("OsString::from(\"--report\")"));
    assert!(runner.contains("public_report.as_os_str().to_os_string()"));
    assert!(runner.contains("OsString::from(\"/usr/bin/true\")"));
    assert_eq!(runner.matches("validate_public_launch(").count(), 3);
    let certification_start = runner
        .find("fn certification_body(")
        .expect("certification body must exist");
    let certification_end = runner[certification_start..]
        .find("pub fn certify(")
        .expect("certification wrapper must follow its body")
        + certification_start;
    let certification = &runner[certification_start..certification_end];
    let upgrade = certification
        .find("if scenario.name == \"sealed_package_upgrade_recovers_before_advertising\"")
        .expect("upgrade must own the clean nonroot public proof");
    let post_upgrade_proof = certification
        .find("validate_post_upgrade_public_proof(root, &identity, report_dir, &receipt)")
        .expect("upgrade must run the clean nonroot public proof");
    let passed = certification
        .find("progress[index].state = ScenarioProgressState::Passed")
        .expect("certification must record scenario success");
    assert!(upgrade < post_upgrade_proof && post_upgrade_proof < passed);
    assert!(
        certification.contains("ScenarioRunFailure::setup(\"post-upgrade-public-proof\", error)")
    );
    let proof_start = runner
        .find("fn validate_post_upgrade_public_proof(")
        .expect("post-upgrade public proof must have one explicit implementation");
    let proof_end = runner[proof_start..]
        .find("fn validate_public_execution_report(")
        .expect("public report validation must follow the post-upgrade proof")
        + proof_start;
    let proof = &runner[proof_start..proof_end];
    assert!(proof.contains("verify_frontend_credentials(root, identity)?"));
    assert_eq!(
        proof.matches("authorized_nonroot(root, identity").count(),
        1
    );
    assert!(proof.contains("[\"probe\"]"));
    assert_eq!(proof.matches("validate_public_launch(").count(), 1);
    let after_post_upgrade_dispatch = &certification[post_upgrade_proof..];
    assert!(!after_post_upgrade_dispatch.contains("verify_frontend_credentials("));
    assert!(!after_post_upgrade_dispatch.contains("authorized_nonroot("));
    assert!(!after_post_upgrade_dispatch.contains("validate_public_launch("));
    let post_loop_start = certification
        .find("let post_upgrade_public_path = report_dir.join(POST_UPGRADE_PUBLIC_REPORT)")
        .expect("evidence assembly must consume the post-upgrade public proof");
    let post_loop = &certification[post_loop_start..];
    assert!(post_loop.contains("let public_path = post_upgrade_public_path;"));
    assert!(runner.contains("if post_upgrade_report.is_file()"));
}

#[test]
fn package_refusal_preflight_preserves_live_service_state() {
    let package =
        include_str!("../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/package.rs");
    let package_tests =
        include_str!("../../../crates/memcordon-cli/tests/sealed_agent/linux_package.rs");
    let runner = include_str!("../src/sealed_linux.rs");

    let mutation_start = package
        .find("fn linux_mutation(")
        .expect("Linux package mutation must exist");
    let mutation_end = package[mutation_start..]
        .find("fn ensure_recovery_idle(")
        .expect("package recovery-idle proof must follow mutation")
        + mutation_start;
    let mutation = &package[mutation_start..mutation_end];
    let recovery_idle_start = mutation_end;
    let recovery_idle_end = package[recovery_idle_start..]
        .find("fn verify_client_access(")
        .expect("client access verification must follow recovery-idle proof")
        + recovery_idle_start;
    let recovery_idle = &package[recovery_idle_start..recovery_idle_end];
    assert!(recovery_idle.contains("crate::linux::recovery::recover()?"));
    assert!(recovery_idle.contains("live_attempt_exists()?"));
    let uninstall = mutation
        .find("if operation == \"uninstall\"")
        .expect("uninstall branch must exist");
    let uninstall_preflight = mutation[uninstall..]
        .find("ensure_recovery_idle(\"uninstall\")")
        .expect("uninstall must preflight authenticated state")
        + uninstall;
    let first_stop = mutation[uninstall..]
        .find("stop_unit(\"memcordon-sealed-agent.service\")")
        .expect("uninstall must stop the provider after preflight")
        + uninstall;
    let uninstall_post_stop = mutation[first_stop..]
        .find("ensure_recovery_idle(\"uninstall\")")
        .expect("uninstall must recover again after all units stop")
        + first_stop;
    assert!(uninstall_preflight < first_stop && first_stop < uninstall_post_stop);

    let upgrade = mutation
        .find("if operation == \"upgrade\"")
        .expect("upgrade branch must exist");
    let upgrade_preflight = mutation[upgrade..]
        .find("ensure_recovery_idle(\"upgrade\")")
        .expect("upgrade must preflight authenticated state")
        + upgrade;
    let upgrade_first_stop = mutation[upgrade..]
        .find("stop_unit(\"memcordon-sealed-agent.service\")")
        .expect("upgrade must stop the provider after preflight")
        + upgrade;
    let upgrade_post_stop = mutation[upgrade_first_stop..]
        .find("ensure_recovery_idle(\"upgrade\")")
        .expect("upgrade must recover again after all units stop")
        + upgrade_first_stop;
    assert!(upgrade_preflight < upgrade_first_stop && upgrade_first_stop < upgrade_post_stop);

    for lifecycle_call in [
        "stop_unit(\"memcordon-sealed-agent.service\")",
        "stop_unit(\"memcordon-sealed-launcher.service\")",
        "stop_unit(\"memcordon-sealed-agent.socket\")",
        "stop_unit(\"memcordon-sealed-launcher.socket\")",
        "ensure_unit_inactive(\"memcordon-sealed-agent.service\")",
        "ensure_unit_inactive(\"memcordon-sealed-launcher.service\")",
        "ensure_unit_inactive(\"memcordon-sealed-agent.socket\")",
        "ensure_unit_inactive(\"memcordon-sealed-launcher.socket\")",
    ] {
        assert_eq!(mutation.matches(lifecycle_call).count(), 2);
        let uninstall_lifecycle = mutation[uninstall..]
            .find(lifecycle_call)
            .expect("uninstall must retain every lifecycle boundary")
            + uninstall;
        let upgrade_lifecycle = mutation[upgrade..]
            .find(lifecycle_call)
            .expect("upgrade must retain every lifecycle boundary")
            + upgrade;
        assert!(
            uninstall_preflight < uninstall_lifecycle && uninstall_lifecycle < uninstall_post_stop
        );
        assert!(upgrade_preflight < upgrade_lifecycle && upgrade_lifecycle < upgrade_post_stop);
    }

    let refusal_start = package_tests
        .find("fn sealed_package_uninstall_refuses_live_authenticated_attempt()")
        .expect("uninstall-refusal scenario must exist");
    let refusal = &package_tests[refusal_start..];
    assert_eq!(refusal.matches("active_provider_unit_states()").count(), 2);
    assert_eq!(refusal.matches("installed_package_bytes()").count(), 2);
    assert!(
        refusal.contains("assert_eq!(std::fs::read(&record_path).unwrap(), authenticated_before)")
    );
    assert!(refusal.contains("let probe = Command::new(AGENT).arg(\"probe\")"));

    let inventory_start = runner
        .find("const SCENARIOS: &[Scenario] = &[")
        .expect("scenario inventory must exist");
    let inventory_end = runner[inventory_start..]
        .find("struct QualificationReceipt")
        .expect("qualification receipt must follow the scenario inventory")
        + inventory_start;
    let inventory = &runner[inventory_start..inventory_end];
    let upgrade_scenario = inventory
        .find("name: \"sealed_package_upgrade_recovers_before_advertising\"")
        .expect("upgrade scenario must remain certified");
    let uninstall_scenario = inventory
        .find("name: \"sealed_package_uninstall_refuses_live_authenticated_attempt\"")
        .expect("uninstall refusal scenario must remain certified");
    assert!(upgrade_scenario < uninstall_scenario);
    assert_eq!(
        inventory[upgrade_scenario..uninstall_scenario]
            .matches("name: ")
            .count(),
        1,
        "uninstall refusal must immediately follow the upgrade scenario"
    );
    assert_eq!(
        inventory[uninstall_scenario..].matches("name: ").count(),
        1,
        "uninstall refusal must remain the final scenario"
    );
}
