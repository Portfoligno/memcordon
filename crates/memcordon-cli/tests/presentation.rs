use std::io;

use anstream::{AutoStream, ColorChoice};
use memcordon::invocation::{
    CLEAN_USAGE, DOCTOR_USAGE, HELP_TOPIC_USAGE, HELP_USAGE, PLAN_USAGE, ROOT_USAGE,
};

#[allow(dead_code)]
#[path = "../src/presentation.rs"]
mod presentation;

use presentation::{ExecutionSummary, SummaryTone};

type Buffer = AutoStream<Vec<u8>>;

fn render(choice: ColorChoice, writer: &impl Fn(&mut Buffer) -> io::Result<()>) -> Vec<u8> {
    let mut output = AutoStream::new(Vec::new(), choice);
    writer(&mut output).expect("presentation rendering should succeed");
    output.into_inner()
}

fn assert_renderer(expected: &str, writer: impl Fn(&mut Buffer) -> io::Result<()>) {
    let plain = render(ColorChoice::Never, &writer);
    assert_eq!(String::from_utf8(plain).expect("plain output"), expected);

    let coloured = render(ColorChoice::AlwaysAnsi, &writer);
    assert!(
        coloured.contains(&0x1b),
        "forced output should contain ANSI"
    );
}

#[test]
fn every_help_document_is_exact_when_plain_and_styled_when_forced() {
    let command_help = [
        ROOT_USAGE,
        HELP_USAGE,
        DOCTOR_USAGE,
        PLAN_USAGE,
        CLEAN_USAGE,
    ];
    for help in command_help
        .into_iter()
        .chain(HELP_TOPIC_USAGE.iter().map(|(_, help)| *help))
    {
        assert_renderer(&format!("{help}\n"), |out| {
            presentation::write_help(out, help)
        });
    }
}

#[test]
fn multiline_leads_and_wrapped_option_terms_are_styled() {
    let all = HELP_TOPIC_USAGE
        .iter()
        .find_map(|(topic, help)| (*topic == "all").then_some(*help))
        .expect("all help topic");
    let coloured = String::from_utf8(render(ColorChoice::AlwaysAnsi, &|out| {
        presentation::write_help(out, all)
    }))
    .expect("coloured help output");

    for visible in [
        "optional memory and elapsed-time limits.",
        "--metric native|physical-footprint|rss|virtual",
        "--restart-on both|memory-limit|deadline",
    ] {
        let line = coloured
            .lines()
            .find(|line| line.contains(visible))
            .expect("expected help line");
        assert!(
            line.contains('\x1b'),
            "expected `{visible}` to be styled in help all"
        );
    }
}

#[test]
fn common_human_renderers_preserve_plain_visible_text() {
    assert_renderer("memcordon 0.3.8-dev\n", |out| {
        presentation::write_version(out, "0.3.8-dev")
    });
    assert_renderer("error[MCCLI-TEST]: bad input\n", |out| {
        presentation::write_usage_error(out, "MCCLI-TEST", "bad input")
    });
    assert_renderer("memcordon: fixture failure\n", |out| {
        presentation::write_runtime_error(out, "fixture failure")
    });
    assert_renderer(
        "memcordon: warning: --restart both is ineffective: no budget\n",
        |out| presentation::write_warning(out, "restart", "both", "no budget"),
    );
    assert_renderer("launch proof: false\n", |out| {
        presentation::write_label_value(out, "launch proof", false)
    });
    assert_renderer("selected backend: fixture-backend\n", |out| {
        presentation::write_selected_backend(out, "fixture-backend")
    });
    assert_renderer("selected backend: none\n", |out| {
        presentation::write_selected_backend(out, "none")
    });
    assert_renderer("removed fixture-object\n", |out| {
        presentation::write_clean_action(out, false, "fixture-object")
    });
    assert_renderer("would remove fixture-object\n", |out| {
        presentation::write_clean_action(out, true, "fixture-object")
    });
}

#[test]
fn summary_tones_preserve_outcomes_statuses_and_metadata() {
    for (outcome, tone, status) in [
        ("child exited", SummaryTone::Success, 0),
        ("child exited", SummaryTone::Warning, 7),
        ("memory limit exceeded", SummaryTone::Error, 124),
        ("deadline exceeded", SummaryTone::Error, 123),
        ("interrupted", SummaryTone::Warning, 130),
        ("monitor failed", SummaryTone::Error, 125),
        ("supervision deadline exceeded", SummaryTone::Error, 123),
        ("supervision failed", SummaryTone::Error, 125),
    ] {
        let expected =
            format!("memcordon: {outcome} {status}; backend fixture; attempts 2; restarts 1\n");
        assert_renderer(&expected, |out| {
            presentation::write_summary(
                out,
                ExecutionSummary {
                    outcome,
                    tone,
                    status,
                    backend: "fixture",
                    attempts: 2,
                    restarts: 1,
                    failure_code: None,
                    failure_phase: None,
                    failure_detail: None,
                },
            )
        });
    }
}

#[test]
fn failed_summary_preserves_the_typed_provider_rejection() {
    assert_renderer(
        "memcordon: supervision failed 125; backend linux-sealed-provider; attempts 1; restarts 0; error MCSEALED-TARGET-DESCRIPTORS-READBACK at resource-verification: permission denied\n",
        |out| {
            presentation::write_summary(
                out,
                ExecutionSummary {
                    outcome: "supervision failed",
                    tone: SummaryTone::Error,
                    status: 125,
                    backend: "linux-sealed-provider",
                    attempts: 1,
                    restarts: 0,
                    failure_code: Some("MCSEALED-TARGET-DESCRIPTORS-READBACK"),
                    failure_phase: Some("resource-verification"),
                    failure_detail: Some("permission denied"),
                },
            )
        },
    );
}
