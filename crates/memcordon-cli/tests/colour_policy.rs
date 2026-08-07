use std::ffi::{OsStr, OsString};

use anstream::{AutoStream, ColorChoice};
use memcordon::invocation::{
    CLEAN_USAGE, DOCTOR_USAGE, HelpKind, Invocation, PLAN_USAGE, ROOT_USAGE, route,
};

#[allow(dead_code)]
#[path = "../src/presentation.rs"]
mod presentation;

use presentation::{ColourPolicy, force_colour_requested};

const ESCAPE: u8 = 0x1b;

fn policy(no_color: bool, force: Option<&str>, clicolor: Option<bool>) -> ColourPolicy {
    ColourPolicy::new(
        no_color,
        force_colour_requested(force.map(OsStr::new)),
        clicolor,
        false,
        false,
    )
}

fn render(arguments: &[&str], choice: ColorChoice) -> Vec<u8> {
    let argv = arguments.iter().map(OsString::from).collect::<Vec<_>>();
    let mut out = AutoStream::new(Vec::new(), choice);
    match route(&argv) {
        Ok(Invocation::Help(kind)) => {
            let help = match kind {
                HelpKind::Root => ROOT_USAGE,
                HelpKind::Doctor => DOCTOR_USAGE,
                HelpKind::Plan => PLAN_USAGE,
                HelpKind::Clean => CLEAN_USAGE,
            };
            presentation::write_help(&mut out, help).expect("help output should be writable");
        }
        Ok(Invocation::Version) => {
            presentation::write_version(&mut out, env!("CARGO_PKG_VERSION"))
                .expect("version output should be writable");
        }
        Err(error) if error.code == "MCCLI-HELP" => {
            presentation::write_help(&mut out, &error.message)
                .expect("topic help output should be writable");
        }
        Err(error) => {
            presentation::write_usage_error(&mut out, error.code, &error.message)
                .expect("usage diagnostic should be writable");
            if let Some(help) = error.help {
                presentation::write_help(&mut out, help).expect("error help should be writable");
            }
        }
        Ok(invocation) => panic!("unexpected routed invocation: {invocation:?}"),
    }
    out.into_inner()
}

fn assert_plain(bytes: &[u8]) {
    assert!(
        !bytes.contains(&ESCAPE),
        "plain output contains an ANSI escape: {:?}",
        String::from_utf8_lossy(bytes)
    );
}

fn assert_styled(bytes: &[u8]) {
    assert!(
        bytes.contains(&ESCAPE),
        "styled output contains no ANSI escape: {:?}",
        String::from_utf8_lossy(bytes)
    );
}

#[test]
fn redirected_and_explicitly_disabled_output_is_plain() {
    for policy in [policy(false, None, None), policy(false, Some("0"), None)] {
        assert_eq!(policy.choice(false), ColorChoice::Never);
    }
    assert!(!force_colour_requested(Some(OsStr::new(""))));
}

#[test]
fn explicit_force_styles_routed_human_output_and_typed_error_help() {
    let policy = policy(false, Some("1"), None);
    let choice = policy.choice(false);
    assert_eq!(choice, ColorChoice::Always);

    for arguments in [
        &["--help"][..],
        &["help"][..],
        &["help", "usage"][..],
        &["--version"][..],
    ] {
        assert_styled(&render(arguments, choice));
    }

    let missing = render(&[], choice);
    assert_styled(&missing);
    let first_line_end = missing
        .iter()
        .position(|byte| *byte == b'\n')
        .expect("diagnostic should have a first line");
    assert_styled(&missing[first_line_end + 1..]);
}

#[test]
fn no_color_wins_over_a_real_force() {
    assert_eq!(
        policy(true, Some("1"), None).choice(true),
        ColorChoice::Never
    );
}

#[test]
fn terminal_capabilities_and_clicolor_are_resolved_without_process_mutation() {
    assert_eq!(
        ColourPolicy::new(false, false, None, true, false).choice(true),
        ColorChoice::Always
    );
    assert_eq!(
        ColourPolicy::new(false, false, Some(true), false, false).choice(true),
        ColorChoice::Always
    );
    assert_eq!(
        ColourPolicy::new(false, false, None, false, true).choice(true),
        ColorChoice::Always
    );
    assert_eq!(
        ColourPolicy::new(false, false, Some(false), true, true).choice(true),
        ColorChoice::Never
    );
    assert_eq!(
        ColourPolicy::new(false, false, None, true, true).choice(false),
        ColorChoice::Never
    );
}

#[test]
fn typed_error_help_preserves_the_exact_plain_diagnostic() {
    let output = render(&[], ColorChoice::Never);
    assert_plain(&output);
    assert_eq!(
        String::from_utf8(output).expect("usage diagnostic should be UTF-8"),
        format!("error[MCCLI-MISSING-LIMIT]: no invocation supplied\n{ROOT_USAGE}\n")
    );
}

#[test]
fn forced_colour_never_decorates_machine_json() {
    assert_eq!(
        policy(false, Some("1"), None).choice(false),
        ColorChoice::Always
    );
    let value = serde_json::json!({"status": "ok"});
    let mut output = Vec::new();
    presentation::write_json(&mut output, &value).expect("machine JSON should be writable");
    assert_plain(&output);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output).expect("machine JSON should parse"),
        value
    );
}
