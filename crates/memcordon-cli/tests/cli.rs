use std::ffi::{OsStr, OsString};
use std::process::Command;

use memcordon::invocation::{
    BudgetToken, HELP_TOPIC_USAGE, HELP_USAGE, HelpKind, Invocation, LimitToken, route,
};
use memcordon::parse_duration;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use memcordon_core::EXECUTION_REPORT_SCHEMA_VERSION;
use memcordon_core::{DOCTOR_REPORT_SCHEMA_VERSION, Lifetime, PLAN_REPORT_SCHEMA_VERSION};

fn native(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

fn execution(values: &[&str]) -> memcordon::invocation::ExecutionArgs {
    match route(&native(values)).expect("invocation should parse") {
        Invocation::Execute(args) => args,
        other => panic!("expected execution, received {other:?}"),
    }
}

fn plan(values: &[&str]) -> memcordon::invocation::PlanArgs {
    match route(&native(values)).expect("plan should parse") {
        Invocation::Plan(args) => args,
        other => panic!("expected plan, received {other:?}"),
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

    let zero = execution(&["+0B", "+0ms", "program"]);
    assert_eq!(zero.budgets.memory.expect("memory").bytes(), 0);
    assert_eq!(zero.budgets.deadline, Some(std::time::Duration::ZERO));
    assert_eq!(zero.budgets.source_order.len(), 2);

    let zero_memory = execution(&["--metric", "rss", "+0B", "program"]);
    assert_eq!(zero_memory.budgets.memory.expect("memory").bytes(), 0);
    let zero_time = execution(&["--deadline-scope", "supervision", "+0ms", "program"]);
    assert_eq!(zero_time.budgets.deadline, Some(std::time::Duration::ZERO));
}

#[test]
fn execution_options_and_budgets_are_fully_interleavable() {
    let layouts = [
        &[
            "--metric",
            "rss",
            "--deadline-scope",
            "attempt",
            "+1GiB",
            "+1h",
            "program",
            "arg",
        ][..],
        &[
            "+1GiB",
            "+1h",
            "--metric",
            "rss",
            "--deadline-scope",
            "attempt",
            "program",
            "arg",
        ][..],
        &[
            "+1GiB",
            "--metric",
            "rss",
            "+1h",
            "--deadline-scope",
            "attempt",
            "program",
            "arg",
        ][..],
        &[
            "--metric",
            "rss",
            "+1GiB",
            "--deadline-scope",
            "attempt",
            "+1h",
            "program",
            "arg",
        ][..],
    ];
    let expected = execution(layouts[0]);
    for layout in &layouts[1..] {
        assert_eq!(execution(layout), expected, "layout={layout:?}");
    }

    let time_first = execution(&["+1h", "--summary", "+1GiB", "program"]);
    assert!(matches!(
        &time_first.budgets.source_order[..],
        [BudgetToken::Time { .. }, BudgetToken::Memory { .. }]
    ));
    let memory_first = execution(&["+1GiB", "--summary", "+1h", "program"]);
    assert!(matches!(
        &memory_first.budgets.source_order[..],
        [BudgetToken::Memory { .. }, BudgetToken::Time { .. }]
    ));
    assert_eq!(time_first.budgets.memory, memory_first.budgets.memory);
    assert_eq!(time_first.budgets.deadline, memory_first.budgets.deadline);
}

#[test]
fn interleaved_execution_preserves_option_values_and_command_opacity() {
    let separate_report = execution(&["+1GiB", "--report", "+artifact.json", "program"]);
    let inline_report = execution(&["+1GiB", "--report=+artifact.json", "program"]);
    assert_eq!(separate_report, inline_report);

    let opaque = execution(&[
        "+1GiB",
        "--summary",
        "+1h",
        "--wait-for",
        "workload",
        "program",
        "--wait-for",
        "command",
        "+2GiB",
        "--",
        "plan",
    ]);
    assert!(opaque.output.summary);
    assert_eq!(opaque.policy.wait_for, Lifetime::Workload);
    assert_eq!(
        opaque.command,
        native(&["program", "--wait-for", "command", "+2GiB", "--", "plan",])
    );

    let dash_command = execution(&[
        "+1GiB",
        "--metric",
        "rss",
        "--",
        "--program",
        "--metric",
        "watchdog",
        "+1h",
    ]);
    assert_eq!(
        dash_command.command,
        native(&["--program", "--metric", "watchdog", "+1h"])
    );
    let plus_command = execution(&["--", "+1GiB", "--metric", "rss"]);
    assert!(plus_command.budgets.source_order.is_empty());
    assert_eq!(plus_command.command, native(&["+1GiB", "--metric", "rss"]));
    assert_eq!(execution(&["+1GiB", "--", "--"]).command, native(&["--"]));

    for name in ["help", "doctor", "plan", "clean", "run"] {
        let utility_name = execution(&["+1GiB", "--quiet", name, "--json"]);
        assert!(utility_name.output.quiet);
        assert_eq!(utility_name.command, native(&[name, "--json"]));
    }
    let last_wait_for = execution(&[
        "--wait-for",
        "command",
        "+1GiB",
        "--wait-for",
        "workload",
        "program",
    ]);
    assert_eq!(last_wait_for.policy.wait_for, Lifetime::Workload);
    let opaque_budget = execution(&["program", "+bogus", "--summary"]);
    assert_eq!(
        opaque_budget.command,
        native(&["program", "+bogus", "--summary"])
    );
}

#[test]
fn interleaved_execution_keeps_validation_codes_and_explicit_boundaries() {
    for (values, code) in [
        (
            &["+1GiB", "--quiet", "+2GiB", "program"][..],
            "MCCLI-BUDGET-DUPLICATE-MEMORY",
        ),
        (
            &["+1s", "--summary", "+2s", "program"][..],
            "MCCLI-BUDGET-DUPLICATE-TIME",
        ),
        (
            &["+1GiB", "--quiet", "+1s", "--summary", "+2GiB", "program"][..],
            "MCCLI-BUDGET-COUNT",
        ),
        (
            &["--summary", "+1GiB", "--quiet", "program"][..],
            "MCCLI-OUTPUT-CONFLICT",
        ),
        (&["--metric", "+1GiB", "program"][..], "MCCLI-OPTION-VALUE"),
        (&["--signal-grace", "+1s", "program"][..], "MCCLI-DURATION"),
        (&["+1GiB", "--metric"][..], "MCCLI-MISSING-OPTION-VALUE"),
        (&["+bogus", "program"][..], "MCCLI-BUDGET"),
        (&["+1GiB", "--program"][..], "MCCLI-UNKNOWN-OPTION"),
    ] {
        assert_eq!(
            route(&native(values))
                .expect_err("invalid interleaving should fail")
                .code,
            code,
            "values={values:?}"
        );
    }
    assert_eq!(
        execution(&["+1GiB", "--", "--program"]).command,
        native(&["--program"])
    );
    assert_eq!(
        route(&native(&["+1GiB", "--help"]))
            .expect_err("help remains a wrapper option before the boundary")
            .code,
        "MCCLI-HELP"
    );
    assert_eq!(execution(&["--", "--help"]).command, native(&["--help"]));
}

#[test]
fn plan_options_and_budgets_are_fully_interleavable() {
    let layouts = [
        &[
            "plan",
            "--json",
            "--metric",
            "rss",
            "+1GiB",
            "--deadline-scope",
            "attempt",
            "+1h",
        ][..],
        &[
            "plan",
            "+1GiB",
            "--metric",
            "rss",
            "+1h",
            "--json",
            "--deadline-scope",
            "attempt",
        ][..],
        &[
            "plan",
            "--metric",
            "rss",
            "+1GiB",
            "--deadline-scope",
            "attempt",
            "+1h",
            "--json",
        ][..],
    ];
    let expected = plan(layouts[0]);
    for layout in &layouts[1..] {
        assert_eq!(plan(layout), expected, "layout={layout:?}");
    }

    let time_first = plan(&["plan", "+1h", "--json", "+1GiB", "--metric", "rss"]);
    assert!(matches!(
        &time_first.budgets.source_order[..],
        [BudgetToken::Time { .. }, BudgetToken::Memory { .. }]
    ));

    for (values, code) in [
        (
            &["plan", "+1GiB", "--json", "+2GiB"][..],
            "MCCLI-BUDGET-DUPLICATE-MEMORY",
        ),
        (
            &["plan", "+1s", "--json", "+2s"][..],
            "MCCLI-BUDGET-DUPLICATE-TIME",
        ),
        (
            &["plan", "+1GiB", "--", "+1h"][..],
            "MCCLI-DELIMITER-POSITION",
        ),
        (&["plan", "+1GiB", "program"][..], "MCCLI-UNKNOWN-OPTION"),
        (
            &["plan", "--metric", "--", "+1GiB"][..],
            "MCCLI-OPTION-VALUE",
        ),
    ] {
        assert_eq!(
            route(&native(values))
                .expect_err("invalid plan interleaving should fail")
                .code,
            code,
            "values={values:?}"
        );
    }
}

#[test]
fn duration_parser_accepts_decimal_hours_with_bounded_millisecond_semantics() {
    for (value, millis) in [
        ("0h", 0),
        ("1ms", 1),
        ("1s", 1_000),
        ("1m", 60_000),
        ("1h", 3_600_000),
        ("1.5h", 5_400_000),
        ("0.0000001h", 1),
        ("5124095576030h", 18_446_744_073_708_000_000),
        ("5124095576030.4h", 18_446_744_073_709_440_000),
    ] {
        assert_eq!(
            parse_duration(value),
            Ok(std::time::Duration::from_millis(millis)),
            "value={value}"
        );
    }

    for value in [
        "h", "1H", "1hr", "1hour", "1d", ".5h", "1.h", "1.2.3h", "-1h", "+1h", "1e2h", "1 h", "1",
        "",
    ] {
        assert!(parse_duration(value).is_err(), "value={value}");
    }

    for value in [
        "5124095576030.5h",
        "5124095576031h",
        "340282366920938463463374607431768211455h",
        "340282366920938463463374607431768211456h",
    ] {
        assert_eq!(
            parse_duration(value),
            Err("duration is too large".to_owned()),
            "value={value}"
        );
    }
    assert_eq!(
        parse_duration("1H"),
        Err("unsupported duration unit `H`".to_owned())
    );
}

#[test]
fn hour_unit_is_shared_by_time_budget_and_every_duration_option() {
    let parsed = execution(&[
        "--poll-interval",
        "1h",
        "--signal-grace",
        "1h",
        "--command-exit-grace",
        "1h",
        "--limit-grace",
        "1h",
        "--restart",
        "--backoff-base",
        "1h",
        "--backoff-asymptote",
        "1h",
        "--backoff-recovery-half-life",
        "1h",
        "--circuit-threshold",
        "2",
        "--circuit-cooldown",
        "1h",
        "--circuit-half-life",
        "1h",
        "+1h",
        "+1GiB",
        "program",
    ]);
    let hour = std::time::Duration::from_secs(60 * 60);
    assert_eq!(parsed.budgets.deadline, Some(hour));
    assert!(matches!(
        &parsed.budgets.source_order[0],
        BudgetToken::Time { raw, duration }
            if raw == OsStr::new("+1h") && *duration == hour
    ));
    assert_eq!(parsed.policy.poll_interval, hour);
    assert_eq!(parsed.policy.signal_grace, hour);
    assert_eq!(parsed.policy.command_exit_grace, hour);
    assert_eq!(parsed.policy.limit_grace, hour);
    assert_eq!(
        parsed.policy.policy(&parsed.budgets).command_exit_grace,
        hour
    );
    assert_eq!(parsed.policy.backoff.base_interval(), hour);
    assert_eq!(parsed.policy.backoff.asymptote_interval(), hour);
    assert_eq!(parsed.policy.backoff.recovery_half_life(), hour);
    let circuit = parsed
        .policy
        .circuit_breaker
        .expect("complete circuit policy");
    assert_eq!(circuit.cooldown(), hour);
    assert_eq!(circuit.half_life(), hour);

    for values in [&["+1H", "program"][..], &["+1d", "program"][..]] {
        assert_eq!(
            route(&native(values))
                .expect_err("unsupported time budget must fail")
                .code,
            "MCCLI-BUDGET"
        );
    }
    assert_eq!(
        route(&native(&["--signal-grace", "1H", "program"]))
            .expect_err("unsupported option duration must fail")
            .code,
        "MCCLI-DURATION"
    );
    assert_eq!(
        route(&native(&[
            "--command-exit-grace",
            "5124095576031h",
            "program"
        ]))
        .expect_err("overflowing command-exit grace must fail")
        .code,
        "MCCLI-DURATION"
    );
}

#[test]
fn command_exit_grace_is_command_only_and_last_value_wins() {
    assert_eq!(
        memcordon::invocation::PolicyArgs::default().command_exit_grace,
        std::time::Duration::ZERO
    );
    let parsed = execution(&[
        "--command-exit-grace",
        "0ms",
        "+1GiB",
        "--command-exit-grace",
        "250ms",
        "program",
    ]);
    assert_eq!(
        parsed.policy.command_exit_grace,
        std::time::Duration::from_millis(250)
    );
    let planned = plan(&["plan", "+1GiB", "--command-exit-grace", "250ms"]);
    assert_eq!(
        planned.policy.command_exit_grace,
        std::time::Duration::from_millis(250)
    );

    for values in [
        &[
            "--command-exit-grace",
            "0ms",
            "--wait-for",
            "workload",
            "program",
        ][..],
        &[
            "--wait-for",
            "workload",
            "--command-exit-grace",
            "1ms",
            "program",
        ][..],
    ] {
        assert_eq!(
            route(&native(values))
                .expect_err("workload completion conflicts with command-exit grace")
                .code,
            "MCUSAGE-COMMAND-EXIT-GRACE"
        );
    }
    for name in ["--command-grace", "--completion-grace", "--exit-grace"] {
        assert_eq!(
            route(&native(&[name, "1s", "program"]))
                .expect_err("noncanonical option name must fail")
                .code,
            "MCCLI-UNKNOWN-OPTION"
        );
    }
}

#[test]
fn half_life_backoff_scalars_are_validated_after_order_independent_collection() {
    let first = execution(&[
        "--restart",
        "--backoff-asymptote",
        "2s",
        "--backoff-base",
        "1500ms",
        "--backoff-recovery-half-life",
        "4s",
        "--backoff-multiplier",
        "2.5",
        "+1GiB",
        "program",
    ]);
    let second = execution(&[
        "--restart",
        "--backoff-multiplier",
        "2.5",
        "--backoff-recovery-half-life",
        "4s",
        "--backoff-base",
        "1500ms",
        "--backoff-asymptote",
        "2s",
        "+1GiB",
        "program",
    ]);
    assert_eq!(first.policy.backoff, second.policy.backoff);

    let partial = execution(&["--restart", "--backoff-base", "500ms", "+1GiB", "program"]);
    assert_eq!(
        partial.policy.backoff.base_interval(),
        std::time::Duration::from_millis(500)
    );
    assert_eq!(partial.policy.backoff.multiplier().numerator(), 4);
    assert_eq!(partial.policy.backoff.multiplier().denominator(), 1);
    assert_eq!(
        partial.policy.backoff.asymptote_interval(),
        std::time::Duration::from_secs(15 * 60)
    );
    assert_eq!(
        partial.policy.backoff.recovery_half_life(),
        std::time::Duration::from_secs(15 * 60)
    );

    let unit_multiplier =
        execution(&["--restart", "--backoff-multiplier", "1", "+1GiB", "program"]);
    assert_eq!(unit_multiplier.policy.backoff.multiplier().numerator(), 1);
    assert_eq!(unit_multiplier.policy.backoff.multiplier().denominator(), 1);

    for multiplier in ["0.999", "NaN", "inf"] {
        let error = route(&native(&[
            "--restart",
            "--backoff-multiplier",
            multiplier,
            "+1GiB",
            "program",
        ]))
        .expect_err("invalid multiplier must fail");
        assert_eq!(error.code, "MCUSAGE-BACKOFF");
    }

    let removed = route(&native(&[
        "--restart",
        "--backoff-initial",
        "1s",
        "+1GiB",
        "program",
    ]))
    .expect_err("the replaced backoff option must not coexist with the new grammar");
    assert_eq!(removed.code, "MCCLI-UNKNOWN-OPTION");
    let removed = route(&native(&[
        "--restart",
        "--backoff-max",
        "1s",
        "+1GiB",
        "program",
    ]))
    .expect_err("the renamed asymptote option must reject its old spelling");
    assert_eq!(removed.code, "MCCLI-UNKNOWN-OPTION");

    for (base, asymptote, expected_base, expected_asymptote) in [
        (
            "1s",
            "1s",
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(1),
        ),
        (
            "2s",
            "1s",
            std::time::Duration::from_secs(2),
            std::time::Duration::from_secs(1),
        ),
    ] {
        let parsed = execution(&[
            "--restart",
            "--backoff-base",
            base,
            "--backoff-asymptote",
            asymptote,
            "+1GiB",
            "program",
        ]);
        assert_eq!(parsed.policy.backoff.base_interval(), expected_base);
        assert_eq!(
            parsed.policy.backoff.asymptote_interval(),
            expected_asymptote
        );
    }

    for values in [
        &["--restart", "--backoff-base", "0ms", "+1GiB", "program"][..],
        &[
            "--restart",
            "--backoff-asymptote",
            "0ms",
            "+1GiB",
            "program",
        ][..],
        &[
            "--restart",
            "--backoff-recovery-half-life",
            "0ms",
            "+1GiB",
            "program",
        ][..],
    ] {
        let error = route(&native(values)).expect_err("invalid backoff must fail");
        assert_eq!(error.code, "MCUSAGE-BACKOFF");
        for option in [
            "--backoff-base",
            "--backoff-asymptote",
            "--backoff-recovery-half-life",
        ] {
            assert!(error.message.contains(option));
        }
    }
}

#[test]
fn circuit_breaker_uses_a_decayed_score_and_inherits_the_backoff_half_life() {
    let inherited = execution(&[
        "--restart",
        "--backoff-recovery-half-life",
        "4s",
        "--circuit-threshold",
        "2.5",
        "--circuit-cooldown",
        "3s",
        "+1GiB",
        "program",
    ]);
    let inherited_circuit = inherited
        .policy
        .circuit_breaker
        .expect("complete circuit policy");
    assert_eq!(inherited_circuit.threshold(), 2.5);
    assert_eq!(
        inherited_circuit.half_life(),
        inherited.policy.backoff.recovery_half_life()
    );
    assert_eq!(
        inherited_circuit.cooldown(),
        std::time::Duration::from_secs(3)
    );

    let explicit = execution(&[
        "--circuit-half-life",
        "1ms",
        "--circuit-cooldown",
        "0ms",
        "--circuit-threshold",
        "2.5",
        "--restart",
        "+1GiB",
        "program",
    ]);
    let explicit_circuit = explicit
        .policy
        .circuit_breaker
        .expect("complete circuit policy with override");
    assert_eq!(explicit_circuit.threshold(), 2.5);
    assert_eq!(
        explicit_circuit.half_life(),
        std::time::Duration::from_millis(1)
    );
    assert_eq!(explicit_circuit.cooldown(), std::time::Duration::ZERO);
}

#[test]
fn circuit_breaker_rejects_incomplete_invalid_and_removed_options() {
    for values in [
        &["--restart", "--circuit-threshold", "2", "+1GiB", "program"][..],
        &["--restart", "--circuit-cooldown", "1s", "+1GiB", "program"][..],
        &["--restart", "--circuit-half-life", "1s", "+1GiB", "program"][..],
    ] {
        assert_eq!(
            route(&native(values))
                .expect_err("invalid circuit policy must fail")
                .code,
            "MCUSAGE-CIRCUIT-INCOMPLETE"
        );
    }

    let zero_half_life = route(&native(&[
        "--restart",
        "--circuit-threshold",
        "2",
        "--circuit-cooldown",
        "0ms",
        "--circuit-half-life",
        "0ms",
        "+1GiB",
        "program",
    ]))
    .expect_err("zero circuit half-life must fail");
    assert_eq!(zero_half_life.code, "MCUSAGE-CIRCUIT-INCOMPLETE");
    assert!(zero_half_life.message.contains("at least 1ms"));

    let invalid_threshold = route(&native(&[
        "--restart",
        "--circuit-threshold",
        "0",
        "--circuit-cooldown",
        "0ms",
        "+1GiB",
        "program",
    ]))
    .expect_err("non-positive circuit threshold must fail");
    assert_eq!(invalid_threshold.code, "MCUSAGE-CIRCUIT-INCOMPLETE");
    assert!(invalid_threshold.message.contains("positive finite number"));

    let without_restart = route(&native(&[
        "--circuit-threshold",
        "2",
        "--circuit-cooldown",
        "1s",
        "+1GiB",
        "program",
    ]))
    .expect_err("circuit tuning without restart must fail");
    assert_eq!(without_restart.code, "MCUSAGE-RESTART-CONDITION");

    for removed in ["--restart-burst", "--restart-window", "--cooldown"] {
        let error = route(&native(&["--restart", removed, "1", "+1GiB", "program"]))
            .expect_err("removed circuit option must stay rejected");
        assert_eq!(error.code, "MCCLI-UNKNOWN-OPTION", "option={removed}");
    }
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
        (&["+8G", "cargo"][..], "MCCLI-BUDGET"),
        (&["+8GiB"][..], "MCCLI-MISSING-COMMAND"),
        (&["+8GiB", "--"][..], "MCCLI-MISSING-COMMAND"),
    ] {
        let error = route(&native(values)).expect_err("invocation should fail");
        assert_eq!(error.code, code, "values={values:?}");
    }
}

#[test]
fn compatibility_routes_return_stable_actionable_diagnostics() {
    for (command, code, replacement) in [
        ("run", "MCCLI-LEGACY-RUN", "memcordon [OPTION|BUDGET]..."),
        ("probe", "MCCLI-LEGACY-PROBE", "memcordon doctor"),
        ("explain", "MCCLI-LEGACY-EXPLAIN", "memcordon plan +MEMORY"),
        ("cleanup", "MCCLI-LEGACY-CLEANUP", "memcordon clean"),
        ("version", "MCCLI-LEGACY-VERSION", "memcordon --version"),
        (
            "compat",
            "MCCLI-LEGACY-COMPAT",
            "memcordon --enforcement watchdog +MEMORY",
        ),
    ] {
        let error = route(&native(&[command])).expect_err("compatibility route should fail");
        assert_eq!(error.code, code);
        assert!(error.message.contains(replacement), "command={command}");
    }
}

#[test]
fn utilities_help_and_version_have_exact_root_routing() {
    assert_eq!(
        route(&native(&["--help"])),
        Ok(Invocation::Help(HelpKind::Root))
    );
    assert_eq!(route(&native(&["--version"])), Ok(Invocation::Version));
    let help = route(&native(&["help"])).expect_err("bare help uses help output path");
    assert_eq!(help.code, "MCCLI-HELP");
    assert_eq!(help.message, HELP_USAGE);
    for (topic, expected) in HELP_TOPIC_USAGE {
        let error = route(&native(&["help", topic])).expect_err("topic help uses help output path");
        assert_eq!(error.code, "MCCLI-HELP");
        assert_eq!(error.message, *expected);
    }
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
fn topic_help_is_reserved_only_at_the_first_token() {
    for values in [
        &["--", "help", "restart"][..],
        &["+1GiB", "help", "restart"][..],
        &["--quiet", "help", "restart"][..],
    ] {
        let parsed = execution(values);
        assert_eq!(parsed.command, native(&["help", "restart"]));
    }
    let parsed = execution(&["program", "help", "restart"]);
    assert_eq!(parsed.command, native(&["program", "help", "restart"]));

    for values in [
        &["help", "restart", "extra"][..],
        &["help", "+1GiB", "program"][..],
        &["help", "--", "restart"][..],
    ] {
        let error = route(&native(values)).expect_err("help shape should fail");
        assert_eq!(error.code, "MCCLI-HELP-TOPIC-COUNT", "values={values:?}");
    }
    let unknown = route(&native(&["help", "run"])).expect_err("unknown topic should fail");
    assert_eq!(unknown.code, "MCCLI-HELP-TOPIC");
    assert!(unknown.message.contains("usage, budgets, memory"));
    assert_eq!(
        route(&native(&["run"]))
            .expect_err("legacy route should remain")
            .code,
        "MCCLI-LEGACY-RUN"
    );
    assert_eq!(
        route(&native(&["help", "__memcordon-launch"]))
            .expect_err("private route is not a topic")
            .code,
        "MCCLI-HELP-TOPIC"
    );
}

#[cfg(unix)]
#[test]
fn non_utf8_help_topic_has_a_stable_error() {
    use std::os::unix::ffi::OsStringExt;

    let argv = vec![OsString::from("help"), OsString::from_vec(vec![0xff])];
    let error = route(&argv).expect_err("non-UTF-8 topic should fail");
    assert_eq!(error.code, "MCCLI-HELP-TOPIC-ENCODING");
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
fn doctor_text_and_json_have_distinct_complete_shapes() {
    let text = Command::new(env!("CARGO_BIN_EXE_memcordon"))
        .arg("doctor")
        .output()
        .expect("doctor should run");
    assert!(text.status.success());
    assert!(text.stderr.is_empty());
    let lines = String::from_utf8(text.stdout)
        .expect("doctor text must be UTF-8")
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].starts_with("memcordon "));
    assert!(lines[1].starts_with("selected backend: "));

    let output = Command::new(env!("CARGO_BIN_EXE_memcordon"))
        .args(["doctor", "--json"])
        .output()
        .expect("doctor should run");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("doctor must emit JSON");
    assert!(!output.stdout.contains(&0x1b));
    assert_eq!(value["schema_version"], DOCTOR_REPORT_SCHEMA_VERSION);
    assert_eq!(value["tool"]["name"], "memcordon");
    assert!(value.get("selected").is_some());
    assert!(value["available"].is_array());
    assert!(value["unavailable"].is_array());
    for backend in value["available"].as_array().expect("available array") {
        assert!(backend["memory"]["supported"].is_boolean());
        assert!(backend["deadline"]["supported"].is_boolean());
        assert!(backend["restart"]["supported"].is_boolean());
        assert!(backend["deadline_scopes"].is_array());
        assert!(backend["limitations"].is_array());
    }
}

#[test]
fn inferred_restart_conditions_are_silent_but_remain_machine_readable() {
    let doctor = Command::new(env!("CARGO_BIN_EXE_memcordon"))
        .args(["doctor", "--json"])
        .output()
        .expect("doctor should run");
    assert!(doctor.status.success());
    let doctor: serde_json::Value =
        serde_json::from_slice(&doctor.stdout).expect("doctor must emit JSON");
    if doctor["selected"].is_null() {
        return;
    }

    for (budget, dormant_condition) in [("+1s", "memory-limit"), ("+1GiB", "deadline")] {
        let missing_command = "memcordon-command-that-does-not-exist";
        let inferred = Command::new(env!("CARGO_BIN_EXE_memcordon"))
            .args(["--restart", budget, missing_command])
            .output()
            .expect("inferred restart execution should run");
        let inferred_stderr = String::from_utf8_lossy(&inferred.stderr);
        let warning = format!("--restart-on {dormant_condition} is ineffective");
        assert!(
            !inferred_stderr.contains(&warning),
            "inferred restart condition emitted `{warning}`: {inferred_stderr}"
        );

        let explicit = Command::new(env!("CARGO_BIN_EXE_memcordon"))
            .args([
                "--restart-on",
                "both",
                budget,
                "memcordon-command-that-does-not-exist",
            ])
            .output()
            .expect("explicit restart execution should run");
        let explicit_stderr = String::from_utf8_lossy(&explicit.stderr);
        assert!(
            explicit_stderr.contains(&warning),
            "explicit restart condition omitted `{warning}`: {explicit_stderr}"
        );

        let plan = Command::new(env!("CARGO_BIN_EXE_memcordon"))
            .args(["plan", "--json", "--restart", budget])
            .output()
            .expect("plan should run");
        assert!(plan.status.success());
        let plan: serde_json::Value =
            serde_json::from_slice(&plan.stdout).expect("plan must emit JSON");
        assert_eq!(plan["request"]["restart"]["enablement_source"], "restart");
        assert_eq!(
            plan["request"]["restart"]["configured_conditions"],
            serde_json::json!(["memory-limit", "deadline"])
        );
        assert!(
            plan["resolution"]["effective"]["restart"]["dormant_conditions"]
                .as_array()
                .is_some_and(|conditions| conditions
                    .iter()
                    .any(|condition| condition["condition"] == dormant_condition))
        );
        assert!(
            plan["resolution"]["effects"]
                .as_array()
                .is_some_and(|effects| effects.iter().any(|effect| {
                    effect["option"] == "restart-on"
                        && effect["requested"] == dormant_condition
                        && effect["kind"] == "ignored"
                }))
        );
    }
}

#[test]
fn plan_text_and_json_have_distinct_resolution_shapes_when_backend_is_available() {
    let doctor = Command::new(env!("CARGO_BIN_EXE_memcordon"))
        .args(["doctor", "--json"])
        .output()
        .expect("doctor should run");
    assert!(doctor.status.success());
    let doctor: serde_json::Value =
        serde_json::from_slice(&doctor.stdout).expect("doctor must emit JSON");

    let text = Command::new(env!("CARGO_BIN_EXE_memcordon"))
        .arg("plan")
        .output()
        .expect("plan text should run");
    let json = Command::new(env!("CARGO_BIN_EXE_memcordon"))
        .args(["plan", "--json", "--command-exit-grace", "250ms"])
        .output()
        .expect("plan JSON should run");

    if doctor["selected"].is_null() {
        assert_eq!(text.status.code(), Some(125));
        assert_eq!(json.status.code(), Some(125));
        return;
    }

    assert!(text.status.success());
    assert!(text.stderr.is_empty());
    let lines = String::from_utf8(text.stdout)
        .expect("plan text must be UTF-8")
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].starts_with("selected backend: "));
    assert_eq!(lines[1], "launch proof: false");

    assert!(json.status.success());
    assert!(json.stderr.is_empty());
    let value: serde_json::Value =
        serde_json::from_slice(&json.stdout).expect("plan must emit JSON");
    assert!(!json.stdout.contains(&0x1b));
    assert_eq!(value["schema_version"], PLAN_REPORT_SCHEMA_VERSION);
    assert!(value["request"].is_object());
    assert!(value["resolution"]["backend"].is_object());
    assert!(value["resolution"]["effective"].is_object());
    assert!(value["resolution"]["effects"].is_array());
    assert!(value["resolution"]["limitations"].is_array());
    assert_eq!(value["resolution"]["launch_proof"], false);
    assert_eq!(value["request"]["command_exit_grace_ms"], 250);
    assert_eq!(
        value["resolution"]["effective"]["command_exit_grace_ms"],
        250
    );
    assert!(
        value["resolution"]["effects"]
            .as_array()
            .is_some_and(|effects| {
                effects
                    .iter()
                    .any(|effect| effect["option"] == "command-exit-grace")
            })
    );
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
#[test]
fn plan_json_preserves_explicit_zero_budgets() {
    let output = Command::new(env!("CARGO_BIN_EXE_memcordon"))
        .args(["plan", "--json", "+0B", "+0ms"])
        .output()
        .expect("plan should run");
    assert!(output.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("plan must emit JSON");

    assert_eq!(value["budget_tokens"][0]["kind"], "memory");
    assert_eq!(value["budget_tokens"][0]["token"], "+0B");
    assert_eq!(value["budget_tokens"][1]["kind"], "time");
    assert_eq!(value["budget_tokens"][1]["token"], "+0ms");
    assert_eq!(value["request"]["memory"]["limit_bytes"], 0);
    assert_eq!(value["request"]["deadline"]["duration_ms"], 0);
    assert_eq!(value["resolution"]["effective"]["memory"]["limit_bytes"], 0);
    assert_eq!(
        value["resolution"]["effective"]["deadline"]["duration_ms"],
        0
    );
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
#[test]
fn plan_restart_json_carries_half_life_defaults_and_source_order() {
    let output = Command::new(env!("CARGO_BIN_EXE_memcordon"))
        .args([
            "plan",
            "+1s",
            "--json",
            "--restart",
            "--backoff-multiplier",
            "1",
            "--circuit-threshold",
            "2.5",
            "+1GiB",
            "--circuit-cooldown",
            "5m",
        ])
        .output()
        .expect("plan should run");
    assert!(output.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("plan must emit JSON");
    assert_eq!(value["budget_tokens"][0]["kind"], "time");
    assert_eq!(value["budget_tokens"][0]["token"], "+1s");
    assert_eq!(value["budget_tokens"][1]["kind"], "memory");
    assert_eq!(value["budget_tokens"][1]["token"], "+1GiB");
    assert_eq!(value["request"]["restart"]["enabled"], true);
    assert_eq!(
        value["request"]["restart"]["backoff"]["model"],
        "half-life-logistic-v1"
    );
    assert_eq!(
        value["request"]["restart"]["backoff"]["base_interval_ms"],
        250
    );
    assert_eq!(
        value["request"]["restart"]["backoff"]["multiplier_numerator"],
        1
    );
    assert_eq!(
        value["request"]["restart"]["backoff"]["multiplier_denominator"],
        1
    );
    assert_eq!(
        value["request"]["restart"]["backoff"]["asymptote_interval_ms"],
        900_000
    );
    assert_eq!(
        value["request"]["restart"]["backoff"]["recovery_half_life_ms"],
        900_000
    );
    assert_eq!(
        value["request"]["restart"]["circuit_breaker"]["threshold"],
        2.5
    );
    assert_eq!(
        value["request"]["restart"]["circuit_breaker"]["half_life_ms"],
        900_000
    );
    assert_eq!(
        value["request"]["restart"]["circuit_breaker"]["cooldown_ms"],
        300_000
    );
    assert!(
        value["request"]["restart"]["circuit_breaker"]
            .get("burst")
            .is_none()
    );
    assert!(
        value["request"]["restart"]["circuit_breaker"]
            .get("window_ms")
            .is_none()
    );
    assert_eq!(
        value["resolution"]["backoff_sample_ms"],
        serde_json::json!([250])
    );
    assert_eq!(value["resolution"]["effective"]["restart"]["enabled"], true);
}

#[test]
fn removed_run_binary_path_never_launches() {
    let output = Command::new(env!("CARGO_BIN_EXE_memcordon"))
        .args(["run", "+1GiB", "definitely-not-launched"])
        .output()
        .expect("legacy diagnostic should run");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("MCCLI-LEGACY-RUN"));
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
#[test]
fn command_not_found_maps_to_127_and_produces_schema_five_failure_report() {
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
    assert_eq!(value["schema_version"], EXECUTION_REPORT_SCHEMA_VERSION);
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
    assert!(!output.stdout.contains(&0x1b));
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["dry_run"], true);
}

#[cfg(target_os = "macos")]
#[test]
fn schema_five_success_report_uses_plus_memory_invocation() {
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
    assert!(!bytes.contains(&0x1b));
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("report should be JSON");
    assert_eq!(value["schema_version"], EXECUTION_REPORT_SCHEMA_VERSION);
    assert_eq!(value["invocation"]["syntax"], "plus-budgets-v1");
    assert_eq!(value["supervision"]["wrapper_exit_code"], 0);
    assert_eq!(
        value["attempts"][0]["outcome"]["cleanup"]["direct_child_reaped"],
        true
    );
}
