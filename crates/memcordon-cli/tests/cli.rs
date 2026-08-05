use std::ffi::{OsStr, OsString};
use std::process::Command;

use memcordon::invocation::{HelpKind, Invocation, LimitToken, route};

fn native(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

fn execution(values: &[&str]) -> memcordon::invocation::ExecutionArgs {
    match route(&native(values)).expect("invocation should parse") {
        Invocation::Execute(args) => args,
        other => panic!("expected execution, received {other:?}"),
    }
}

#[test]
fn canonical_boundaries_produce_identical_requests() {
    let concise = execution(&["+8GiB", "cargo", "test", "--workspace"]);
    let explicit = execution(&["+8GiB", "--", "cargo", "test", "--workspace"]);
    assert_eq!(concise, explicit);
    assert_eq!(
        concise.budgets.memory.expect("memory").bytes(),
        8 * 1024 * 1024 * 1024
    );
    assert_eq!(concise.command, native(&["cargo", "test", "--workspace"]));
}

#[test]
fn optional_and_order_independent_budgets_preserve_native_boundary() {
    let budgetless = execution(&["--", "+program", "--child", "+opaque"]);
    assert!(budgetless.budgets.memory.is_none());
    assert!(budgetless.budgets.deadline.is_none());
    assert_eq!(
        budgetless.command,
        native(&["+program", "--child", "+opaque"])
    );

    let memory_time = execution(&["+1GiB", "+1.5s", "program"]);
    let time_memory = execution(&["+1.5s", "+1GiB", "program"]);
    assert_eq!(memory_time.budgets.memory, time_memory.budgets.memory);
    assert_eq!(memory_time.budgets.deadline, time_memory.budgets.deadline);
    assert_ne!(
        memory_time.budgets.source_order,
        time_memory.budgets.source_order
    );
    assert_eq!(
        memory_time.budgets.deadline,
        Some(std::time::Duration::from_millis(1_500))
    );
    assert_eq!(
        route(&native(&["+0ms", "program"]))
            .expect_err("zero deadline must fail")
            .code,
        "MCCLI-BUDGET"
    );
}

#[test]
fn backoff_scalars_are_validated_after_order_independent_collection() {
    let first = execution(&[
        "--restart",
        "--backoff-max",
        "2s",
        "--backoff-initial",
        "1500ms",
        "--backoff-multiplier",
        "2.5",
        "+1GiB",
        "program",
    ]);
    let second = execution(&[
        "--restart",
        "--backoff-multiplier",
        "2.5",
        "--backoff-initial",
        "1500ms",
        "--backoff-max",
        "2s",
        "+1GiB",
        "program",
    ]);
    assert_eq!(first.policy.backoff, second.policy.backoff);
}

#[test]
fn wrapper_options_stop_at_the_limit() {
    let parsed = execution(&[
        "--enforcement=hard",
        "--wait-for",
        "workload",
        "--metric",
        "rss",
        "+2.5GiB",
        "--",
        "--unusual-program",
        "--enforcement",
        "watchdog",
        "+other",
    ]);
    assert_eq!(parsed.command[0], OsStr::new("--unusual-program"));
    assert_eq!(
        &parsed.command[1..],
        &native(&["--enforcement", "watchdog", "+other"])
    );
}

#[test]
fn child_delimiters_empty_arguments_and_literal_delimiter_program_are_preserved() {
    let cargo = execution(&["+1GiB", "cargo", "run", "--", "", "--child-flag"]);
    assert_eq!(
        cargo.command,
        native(&["cargo", "run", "--", "", "--child-flag"])
    );
    let delimiter = execution(&["+1GiB", "--", "--"]);
    assert_eq!(delimiter.command, native(&["--"]));
}

#[test]
fn limit_token_retains_raw_text_and_reuses_byte_size_grammar() {
    for (token, bytes) in [
        ("+8589934592", 8_589_934_592),
        ("+8GiB", 8_589_934_592),
        ("+8000MB", 8_000_000_000),
        ("+2.5GiB", 2_684_354_560),
    ] {
        let parsed = LimitToken::parse(OsString::from(token)).expect("limit should parse");
        assert_eq!(parsed.raw, OsStr::new(token));
        assert_eq!(parsed.bytes.bytes(), bytes);
    }
}

#[test]
fn invalid_limits_and_boundaries_have_stable_codes() {
    for (values, code) in [
        (&["+", "cargo"][..], "MCCLI-BUDGET"),
        (&["++8GiB", "cargo"][..], "MCCLI-BUDGET"),
        (&["+0B", "cargo"][..], "MCCLI-BUDGET"),
        (&["+8G", "cargo"][..], "MCCLI-BUDGET"),
        (&["+8GiB"][..], "MCCLI-MISSING-COMMAND"),
        (&["+8GiB", "--"][..], "MCCLI-MISSING-COMMAND"),
    ] {
        let error = route(&native(values)).expect_err("invocation should fail");
        assert_eq!(error.code, code, "values={values:?}");
    }
}

#[test]
fn removed_commands_route_only_to_migration_errors() {
    for (command, code) in [
        ("run", "MCCLI-LEGACY-RUN"),
        ("probe", "MCCLI-LEGACY-PROBE"),
        ("explain", "MCCLI-LEGACY-EXPLAIN"),
        ("cleanup", "MCCLI-LEGACY-CLEANUP"),
        ("version", "MCCLI-LEGACY-VERSION"),
        ("compat", "MCCLI-LEGACY-COMPAT"),
    ] {
        let error = route(&native(&[command])).expect_err("legacy command should fail");
        assert_eq!(error.code, code);
    }
}

#[test]
fn utilities_help_and_version_have_exact_root_routing() {
    assert_eq!(
        route(&native(&["--help"])),
        Ok(Invocation::Help(HelpKind::Root))
    );
    assert_eq!(route(&native(&["--version"])), Ok(Invocation::Version));
    assert!(matches!(
        route(&native(&["doctor", "--json", "--require", "hard"])),
        Ok(Invocation::Doctor(_))
    ));
    assert!(matches!(
        route(&native(&["plan", "--json", "+1GiB"])),
        Ok(Invocation::Plan(_))
    ));
    assert!(matches!(
        route(&native(&["clean", "--dry-run", "--json"])),
        Ok(Invocation::Clean(_))
    ));
}

#[test]
fn output_requests_are_validated_before_launch() {
    let parsed = execution(&[
        "--report",
        "target/result.json",
        "--summary",
        "+1GiB",
        "program",
    ]);
    assert!(parsed.output.summary);
    assert_eq!(
        parsed.output.report_path.as_deref(),
        Some(std::path::Path::new("target/result.json"))
    );
    assert_eq!(
        route(&native(&["--summary", "--quiet", "+1GiB", "program"]))
            .expect_err("output flags conflict")
            .code,
        "MCCLI-OUTPUT-CONFLICT"
    );
    assert_eq!(
        route(&native(&["--report", "-", "+1GiB", "program"]))
            .expect_err("stdout report is forbidden")
            .code,
        "MCCLI-REPORT-STDOUT"
    );
}

#[cfg(unix)]
#[test]
fn non_utf8_child_arguments_remain_native() {
    use std::os::unix::ffi::OsStringExt;

    let program = OsString::from_vec(vec![b'p', 0xff]);
    let argument = OsString::from_vec(vec![b'a', 0xfe]);
    let argv = vec![OsString::from("+1GiB"), program.clone(), argument.clone()];
    let Invocation::Execute(parsed) = route(&argv).expect("native child should parse") else {
        panic!("expected execution");
    };
    assert_eq!(parsed.command, vec![program, argument]);
}

#[cfg(unix)]
#[test]
fn non_utf8_limit_is_rejected_without_altering_later_child_tokens() {
    use std::os::unix::ffi::OsStringExt;

    let child = OsString::from_vec(vec![b'c', 0xfe]);
    let argv = vec![OsString::from_vec(vec![b'+', 0xff]), child.clone()];
    let error = route(&argv).expect_err("non-UTF-8 limit should fail");
    assert_eq!(error.code, "MCCLI-BUDGET-ENCODING");
    assert_eq!(argv[1], child);
}

#[test]
fn doctor_json_is_versioned_and_machine_readable() {
    let output = Command::new(env!("CARGO_BIN_EXE_memcordon"))
        .args(["doctor", "--json"])
        .output()
        .expect("doctor should run");
    assert!(output.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("doctor must emit JSON");
    assert_eq!(value["schema_version"], 2);
    assert_eq!(value["tool"]["name"], "memcordon");
    assert!(value.get("available").is_some());
    if !value["available"].as_array().is_none_or(Vec::is_empty) {
        assert!(value["available"][0]["deadline"]["supported"].is_boolean());
        assert!(value["available"][0]["restart"]["supported"].is_boolean());
        assert!(value["available"][0]["deadline_scopes"].is_array());
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
#[test]
fn plan_schema_two_carries_effects_limitations_and_source_order() {
    let output = Command::new(env!("CARGO_BIN_EXE_memcordon"))
        .args(["plan", "--json", "--restart", "+1s", "+1GiB"])
        .output()
        .expect("plan should run");
    assert!(output.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("plan must emit JSON");
    assert_eq!(value["schema_version"], 2);
    assert_eq!(value["budget_tokens"][0]["kind"], "time");
    assert_eq!(value["budget_tokens"][1]["kind"], "memory");
    assert!(
        value["resolution"]["effects"]
            .as_array()
            .is_some_and(|items| items.len() >= 6)
    );
    assert!(value["resolution"]["limitations"].is_array());
    assert_eq!(value["request"]["restart"]["enabled"], true);
    assert_eq!(value["resolution"]["effective"]["restart"]["enabled"], true);
}

#[test]
fn removed_run_binary_path_never_launches() {
    let output = Command::new(env!("CARGO_BIN_EXE_memcordon"))
        .args(["run", "+1GiB", "definitely-not-launched"])
        .output()
        .expect("migration diagnostic should run");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("MCCLI-LEGACY-RUN"));
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
#[test]
fn command_not_found_maps_to_127_and_produces_schema_three_failure_report() {
    let temporary = tempfile::tempdir().expect("temporary directory should exist");
    let report = temporary.path().join("failure.json");
    let missing = temporary.path().join("command-that-does-not-exist");
    let output = Command::new(env!("CARGO_BIN_EXE_memcordon"))
        .args(["--report"])
        .arg(&report)
        .arg("+1GiB")
        .arg(&missing)
        .output()
        .expect("wrapper should run");
    assert_eq!(output.status.code(), Some(127));
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(report).expect("failure report should be written"))
            .expect("failure report should be JSON");
    assert_eq!(value["schema_version"], 3);
    assert_eq!(value["supervision"]["wrapper_exit_code"], 127);
    assert_eq!(value["attempts"][0]["error"]["code"], "MCSPAWN-NOT-FOUND");
    assert_eq!(
        value["attempts"][0]["error"]["initial_spawn_failure"],
        "not-found"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn command_not_executable_maps_to_126_in_aggregate_report() {
    use std::os::unix::fs::PermissionsExt;

    let temporary = tempfile::tempdir().expect("temporary directory should exist");
    let report = temporary.path().join("failure.json");
    let target = temporary.path().join("not-executable");
    std::fs::write(&target, b"not executable\n").expect("fixture");
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).expect("permissions");
    let output = Command::new(env!("CARGO_BIN_EXE_memcordon"))
        .args(["--report"])
        .arg(&report)
        .arg("+1GiB")
        .arg(&target)
        .output()
        .expect("wrapper should run");
    assert_eq!(output.status.code(), Some(126));
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(report).expect("failure report should be written"))
            .expect("failure report should be JSON");
    assert_eq!(value["supervision"]["wrapper_exit_code"], 126);
    assert_eq!(
        value["attempts"][0]["error"]["initial_spawn_failure"],
        "not-executable"
    );
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
#[test]
fn clean_json_uses_schema_one() {
    let output = Command::new(env!("CARGO_BIN_EXE_memcordon"))
        .args(["clean", "--dry-run", "--json"])
        .output()
        .expect("clean should run");
    assert!(output.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("clean must emit JSON");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["dry_run"], true);
}

#[cfg(target_os = "macos")]
#[test]
fn schema_three_success_report_uses_plus_memory_invocation() {
    let temporary = tempfile::tempdir().expect("temporary directory should exist");
    let report = temporary.path().join("success.json");
    let output = Command::new(env!("CARGO_BIN_EXE_memcordon"))
        .args(["--enforcement", "watchdog", "--report"])
        .arg(&report)
        .args(["+1GiB", "/usr/bin/true"])
        .output()
        .expect("wrapper should run");
    assert_eq!(output.status.code(), Some(0));
    let bytes = std::fs::read(report).expect("report should exist");
    assert_eq!(bytes.last(), Some(&b'\n'));
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("report should be JSON");
    assert_eq!(value["schema_version"], 3);
    assert_eq!(value["invocation"]["syntax"], "plus-budgets-v1");
    assert_eq!(value["supervision"]["wrapper_exit_code"], 0);
    assert_eq!(
        value["attempts"][0]["outcome"]["cleanup"]["direct_child_reaped"],
        true
    );
}
