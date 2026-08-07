use std::fs;
use std::path::Path;
use std::process::Command;

use memcordon::invocation::{
    CLEAN_USAGE, DOCTOR_USAGE, HELP_TOPIC_USAGE, HELP_USAGE, PLAN_USAGE, PUBLIC_POLICY_OPTIONS,
    PolicyArgs, REFERENCE_URL, ROOT_USAGE,
};
use memcordon_core::{
    CLEAN_REPORT_SCHEMA_VERSION, DOCTOR_REPORT_SCHEMA_VERSION, EXECUTION_REPORT_SCHEMA_VERSION,
    HalfLifeLogisticBackoffPolicy, Lifetime, PLAN_REPORT_SCHEMA_VERSION,
};

fn workspace_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("CLI crate should be inside the workspace")
        .to_path_buf()
}

fn stdout(arguments: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_memcordon"))
        .args(arguments)
        .output()
        .expect("memcordon should run");
    assert!(output.status.success(), "arguments={arguments:?}");
    assert!(output.stderr.is_empty(), "arguments={arguments:?}");
    String::from_utf8(output.stdout).expect("public help should be UTF-8")
}

fn option_line<'a>(help: &'a str, option: &str) -> &'a str {
    help.lines()
        .find(|line| line.trim_start().starts_with(option))
        .unwrap_or_else(|| panic!("help omits {option}"))
}

fn assert_option_default(help: &str, option: &str, expected: &str) {
    assert!(
        option_line(help, option).ends_with(&format!("; {expected}")),
        "{option} should advertise default {expected}"
    );
}

fn duration_default(duration: std::time::Duration) -> String {
    let millis = duration.as_millis();
    if millis % 60_000 == 0 {
        format!("{}m", millis / 60_000)
    } else if millis % 1_000 == 0 {
        format!("{}s", millis / 1_000)
    } else {
        format!("{millis}ms")
    }
}

fn multiplier_default(policy: HalfLifeLogisticBackoffPolicy) -> String {
    let multiplier = policy.multiplier();
    format!(
        "{}",
        f64::from(multiplier.numerator()) / f64::from(multiplier.denominator())
    )
}

fn assert_version_pinned_reference(help: &str) {
    let mut lines = help.lines();
    let reference = lines
        .find(|line| *line == "Reference:")
        .and_then(|_| lines.next())
        .expect("help should have a Reference URL")
        .trim();
    assert_eq!(reference, REFERENCE_URL);
    assert!(!help.contains("/blob/main/"));
}

fn normalized(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn generated_public_help_is_exact_complete_and_keeps_private_routes_hidden() {
    let reference_tag = REFERENCE_URL
        .strip_prefix(concat!(env!("CARGO_PKG_REPOSITORY"), "/blob/"))
        .and_then(|value| value.strip_suffix("/docs/reference.md"));
    assert_eq!(reference_tag, Some(env!("CARGO_PKG_VERSION")));

    for (arguments, expected) in [
        (&["--help"][..], ROOT_USAGE),
        (&["doctor", "--help"][..], DOCTOR_USAGE),
        (&["plan", "--help"][..], PLAN_USAGE),
        (&["clean", "--help"][..], CLEAN_USAGE),
    ] {
        assert_eq!(stdout(arguments), format!("{expected}\n"));
        assert_version_pinned_reference(expected);
        for private in ["__memcordon-launch", "__memcordon-guardian"] {
            assert!(!expected.contains(private));
        }
    }
    for (topic, expected) in HELP_TOPIC_USAGE {
        assert_eq!(stdout(&["help", topic]), format!("{expected}\n"));
        assert!(HELP_USAGE.contains(topic), "help index omits topic {topic}");
        assert_version_pinned_reference(expected);
        for private in ["__memcordon-launch", "__memcordon-guardian"] {
            assert!(!expected.contains(private));
        }
    }
    assert_eq!(stdout(&["help"]), format!("{HELP_USAGE}\n"));
    assert_version_pinned_reference(HELP_USAGE);
    assert!(!ROOT_USAGE.contains("\nHelp topics:\n"));
    assert!(!ROOT_USAGE.contains("\nCompletion:\n"));
    assert!(!ROOT_USAGE.contains("\nRules:\n"));
    assert!(ROOT_USAGE.contains("  help      List topics or show one topic"));
    let all = HELP_TOPIC_USAGE
        .iter()
        .find_map(|(topic, usage)| (*topic == "all").then_some(*usage))
        .expect("all topic should exist");
    for option in PUBLIC_POLICY_OPTIONS {
        assert!(all.contains(option), "all help omits {option}");
        assert!(PLAN_USAGE.contains(option), "plan help omits {option}");
        assert!(
            HELP_TOPIC_USAGE
                .iter()
                .any(|(topic, usage)| *topic != "all" && usage.contains(option)),
            "focused help topics omit {option}"
        );
    }
    for utility_surface in [
        "doctor --json",
        "doctor --require hard|watchdog",
        "plan --json",
        "clean --dry-run",
        "clean --json",
        "-V, --version",
    ] {
        assert!(
            all.contains(utility_surface),
            "all help omits {utility_surface}"
        );
    }
    for status in [
        "child status",
        "2             Usage error",
        "123           Elapsed-time deadline",
        "124           Confirmed memory limit",
        "125           Backend, setup, monitoring, cleanup, report, or restart failure",
        "126           Command found but not executable",
        "127           Command not found",
        "128 + signal  Unix interruption or child signal when applicable",
    ] {
        assert!(all.contains(status), "all help omits `{status}`");
    }
    assert!(!ROOT_USAGE.contains("--backoff-base"));
    for removed in ["--restart-burst", "--restart-window", "--cooldown"] {
        assert!(!all.contains(removed), "all help retains {removed}");
        assert!(!PLAN_USAGE.contains(removed), "plan help retains {removed}");
        for (topic, usage) in HELP_TOPIC_USAGE {
            assert!(!usage.contains(removed), "{topic} help retains {removed}");
        }
    }

    for (help, option, version) in [
        (all, "--report", EXECUTION_REPORT_SCHEMA_VERSION),
        (DOCTOR_USAGE, "--json", DOCTOR_REPORT_SCHEMA_VERSION),
        (PLAN_USAGE, "--json", PLAN_REPORT_SCHEMA_VERSION),
        (CLEAN_USAGE, "--json", CLEAN_REPORT_SCHEMA_VERSION),
    ] {
        assert!(
            option_line(help, option).contains(&format!("schema-{version}")),
            "{option} should advertise schema-{version}"
        );
    }
    let output = HELP_TOPIC_USAGE
        .iter()
        .find_map(|(topic, usage)| (*topic == "output").then_some(*usage))
        .expect("output topic should exist");
    for version in [
        CLEAN_REPORT_SCHEMA_VERSION,
        DOCTOR_REPORT_SCHEMA_VERSION,
        PLAN_REPORT_SCHEMA_VERSION,
        EXECUTION_REPORT_SCHEMA_VERSION,
    ] {
        assert!(output.contains(&format!("schema-{version}")));
    }
}

#[test]
fn reference_and_generated_help_cover_the_same_public_interface() {
    let reference = fs::read_to_string(workspace_root().join("docs/reference.md"))
        .expect("reference should be readable");
    for syntax in [
        "memcordon [OPTION|BUDGET]... [--] COMMAND [ARGUMENT]...",
        "memcordon help [TOPIC]",
        "memcordon doctor [--json] [--require hard|watchdog]",
        "memcordon plan [OPTION|BUDGET]...",
        "memcordon clean [--dry-run] [--json]",
    ] {
        assert!(reference.contains(syntax), "reference omits `{syntax}`");
    }
    for option in PUBLIC_POLICY_OPTIONS {
        assert!(reference.contains(option), "reference omits {option}");
    }
    for removed in ["--restart-burst", "--restart-window", "--cooldown"] {
        assert!(!reference.contains(removed), "reference retains {removed}");
    }
    let backoff = HalfLifeLogisticBackoffPolicy::default();
    let all = HELP_TOPIC_USAGE
        .iter()
        .find_map(|(topic, usage)| (*topic == "all").then_some(*usage))
        .expect("all topic should exist");
    let backoff_help = HELP_TOPIC_USAGE
        .iter()
        .find_map(|(topic, usage)| (*topic == "backoff").then_some(*usage))
        .expect("backoff topic should exist");
    for (option, default) in [
        ("--backoff-base", duration_default(backoff.base_interval())),
        ("--backoff-multiplier", multiplier_default(backoff)),
        (
            "--backoff-asymptote",
            duration_default(backoff.asymptote_interval()),
        ),
        (
            "--backoff-recovery-half-life",
            duration_default(backoff.recovery_half_life()),
        ),
    ] {
        assert_option_default(all, option, &default);
        assert_option_default(backoff_help, option, &default);
        assert_option_default(PLAN_USAGE, option, &default);
        let marker = format!("| `{option}` |");
        let line = reference
            .lines()
            .find(|line| line.starts_with(&marker))
            .unwrap_or_else(|| panic!("reference omits {option}"));
        assert!(line.ends_with(&format!("| `{default}` |")));
    }
}

#[test]
fn wait_for_help_documents_completion_and_cleanup_semantics() {
    let lifecycle = HELP_TOPIC_USAGE
        .iter()
        .find_map(|(topic, usage)| (*topic == "lifecycle").then_some(*usage))
        .expect("lifecycle topic should exist");
    let all = HELP_TOPIC_USAGE
        .iter()
        .find_map(|(topic, usage)| (*topic == "all").then_some(*usage))
        .expect("all topic should exist");

    for help in [ROOT_USAGE, HELP_USAGE, PLAN_USAGE, lifecycle, all] {
        assert!(!help.contains("Return after the command or workload"));
    }

    assert_eq!(PolicyArgs::default().wait_for, Lifetime::Command);
    assert_eq!(
        PolicyArgs::default().command_exit_grace,
        std::time::Duration::ZERO
    );
    for help in [lifecycle, all, PLAN_USAGE] {
        assert_option_default(help, "--wait-for", "command");
        assert_option_default(help, "--command-exit-grace", "0s");
    }
    assert_option_default(ROOT_USAGE, "--command-exit-grace", "0s");
    assert!(normalized(ROOT_USAGE).contains(
        "--wait-for command|workload Terminate remaining members after command exit or wait for workload empty; command"
    ));

    let lifecycle = normalized(lifecycle);
    for required in [
        "After the direct command exits, wait up to command-exit grace for the workload to empty naturally, then forcibly terminate and clean up remaining members.",
        "MemCordon returns only after cleanup, using the direct command's status when cleanup succeeds.",
        "wait until the workload is empty",
        "Without +TIME, this can wait indefinitely on Linux and macOS.",
        "Command-exit grace sends no signal and applies only to command mode.",
        "Signal grace applies only to external interruption.",
        "Limit grace requires +MEMORY or +TIME",
        "On Windows, workload is currently adjusted to command",
    ] {
        assert!(
            lifecycle.contains(required),
            "lifecycle help omits `{required}`"
        );
    }

    let all = normalized(all);
    assert!(all.contains("direct-command exit waits up to command-exit grace for natural drain"));
    assert!(all.contains("workload keeps those members running and waits for workload empty"));

    let reference = fs::read_to_string(workspace_root().join("docs/reference.md"))
        .expect("reference should be readable");
    assert!(reference.contains("## Completion and workload membership"));
    assert!(reference.contains("sleep 3600"));
}

#[test]
fn public_duration_grammar_documents_hour_units() {
    let budgets = HELP_TOPIC_USAGE
        .iter()
        .find_map(|(topic, usage)| (*topic == "budgets").then_some(*usage))
        .expect("budgets topic should exist");
    let all = HELP_TOPIC_USAGE
        .iter()
        .find_map(|(topic, usage)| (*topic == "all").then_some(*usage))
        .expect("all topic should exist");

    for help in [ROOT_USAGE, budgets, all, PLAN_USAGE] {
        let help = normalized(help);
        assert!(
            help.contains("+TIME Elapsed-time deadline; decimal ms, s, m, or h"),
            "public help omits the hour suffix"
        );
        assert!(!help.contains("does not accept h"));
    }

    let reference = fs::read_to_string(workspace_root().join("docs/reference.md"))
        .expect("reference should be readable");
    assert!(
        reference.contains(
            "Time budgets and duration-valued options use decimal `ms`, `s`, `m`, or `h`"
        )
    );
    assert!(!reference.contains("`h` is not accepted"));
    assert!(!reference.contains("including `h`"));
}

#[test]
fn public_invocation_grammar_documents_interleaved_options_and_budgets() {
    let usage = HELP_TOPIC_USAGE
        .iter()
        .find_map(|(topic, usage)| (*topic == "usage").then_some(*usage))
        .expect("usage topic should exist");
    let all = HELP_TOPIC_USAGE
        .iter()
        .find_map(|(topic, usage)| (*topic == "all").then_some(*usage))
        .expect("all topic should exist");

    for help in [ROOT_USAGE, usage, all, PLAN_USAGE] {
        assert!(!help.contains("Options come first"));
        assert!(!help.contains("Options precede"));
        assert!(!help.contains("contiguous budgets"));
        assert!(
            help.contains("[OPTION|BUDGET]..."),
            "public help omits mixed option/budget syntax"
        );
    }
    for help in [usage, all, PLAN_USAGE] {
        assert!(
            normalized(help).contains("may be interleaved"),
            "focused help omits the interleaving rule"
        );
    }

    let reference = fs::read_to_string(workspace_root().join("docs/reference.md"))
        .expect("reference should be readable");
    assert!(reference.contains("memcordon [OPTION|BUDGET]..."));
    assert!(reference.contains("memcordon plan [OPTION|BUDGET]..."));
    assert!(reference.contains("Options and budgets may be interleaved before the command."));
    assert!(!reference.contains("Options precede"));
    assert!(!reference.contains("Budgets are optional, contiguous"));
}
