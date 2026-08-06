use std::fs;
use std::path::Path;
use std::process::Command;

use memcordon::invocation::{
    CLEAN_USAGE, DOCTOR_USAGE, PLAN_USAGE, PUBLIC_POLICY_OPTIONS, REFERENCE_URL, ROOT_USAGE,
};
use memcordon_core::{
    CLEAN_REPORT_SCHEMA_VERSION, DOCTOR_REPORT_SCHEMA_VERSION, EXECUTION_REPORT_SCHEMA_VERSION,
    HalfLifeLogisticBackoffPolicy, PLAN_REPORT_SCHEMA_VERSION,
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

#[test]
fn generated_public_help_is_exact_complete_and_keeps_private_routes_hidden() {
    for (arguments, expected) in [
        (&["--help"][..], ROOT_USAGE),
        (&["doctor", "--help"][..], DOCTOR_USAGE),
        (&["plan", "--help"][..], PLAN_USAGE),
        (&["clean", "--help"][..], CLEAN_USAGE),
    ] {
        assert_eq!(stdout(arguments), format!("{expected}\n"));
        assert!(expected.contains(REFERENCE_URL));
        for private in ["__memcordon-launch", "__memcordon-guardian"] {
            assert!(!expected.contains(private));
        }
    }
    for option in PUBLIC_POLICY_OPTIONS {
        assert!(ROOT_USAGE.contains(option), "root help omits {option}");
        assert!(PLAN_USAGE.contains(option), "plan help omits {option}");
    }

    for (help, option, version) in [
        (ROOT_USAGE, "--report", EXECUTION_REPORT_SCHEMA_VERSION),
        (DOCTOR_USAGE, "--json", DOCTOR_REPORT_SCHEMA_VERSION),
        (PLAN_USAGE, "--json", PLAN_REPORT_SCHEMA_VERSION),
        (CLEAN_USAGE, "--json", CLEAN_REPORT_SCHEMA_VERSION),
    ] {
        assert!(
            option_line(help, option).contains(&format!("schema-{version}")),
            "{option} should advertise schema-{version}"
        );
    }
}

#[test]
fn reference_and_generated_help_cover_the_same_public_interface() {
    let reference = fs::read_to_string(workspace_root().join("docs/reference.md"))
        .expect("reference should be readable");
    for syntax in [
        "memcordon [EXECUTION OPTIONS] [BUDGET]... [--] COMMAND [ARGUMENT]...",
        "memcordon doctor [--json] [--require hard|watchdog]",
        "memcordon plan [POLICY OPTIONS] [--json] [BUDGET]...",
        "memcordon clean [--dry-run] [--json]",
    ] {
        assert!(reference.contains(syntax), "reference omits `{syntax}`");
    }
    for option in PUBLIC_POLICY_OPTIONS {
        assert!(reference.contains(option), "reference omits {option}");
    }
    let backoff = HalfLifeLogisticBackoffPolicy::default();
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
        assert_option_default(ROOT_USAGE, option, &default);
        assert_option_default(PLAN_USAGE, option, &default);
        let marker = format!("| `{option}` |");
        let line = reference
            .lines()
            .find(|line| line.starts_with(&marker))
            .unwrap_or_else(|| panic!("reference omits {option}"));
        assert!(line.ends_with(&format!("| `{default}` |")));
    }
}
