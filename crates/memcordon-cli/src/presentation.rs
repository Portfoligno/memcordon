use std::fmt;
use std::io::{self, Write};

use anstream::{AutoStream, ColorChoice};
use anstyle::{AnsiColor, Style};

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Presentation;

impl Presentation {
    pub(crate) const fn automatic() -> Self {
        Self
    }

    pub(crate) fn stdout(self) -> AutoStream<std::io::Stdout> {
        AutoStream::new(std::io::stdout(), ColorChoice::Auto)
    }

    pub(crate) fn stderr(self) -> AutoStream<std::io::Stderr> {
        AutoStream::new(std::io::stderr(), ColorChoice::Auto)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SummaryTone {
    Success,
    Warning,
    Error,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ExecutionSummary<'a> {
    pub(crate) outcome: &'a str,
    pub(crate) tone: SummaryTone,
    pub(crate) status: i32,
    pub(crate) backend: &'a str,
    pub(crate) attempts: u64,
    pub(crate) restarts: u64,
}

fn error_style() -> Style {
    AnsiColor::Red.on_default().bold()
}

fn warning_style() -> Style {
    AnsiColor::Yellow.on_default().bold()
}

fn success_style() -> Style {
    AnsiColor::Green.on_default().bold()
}

fn label_style() -> Style {
    AnsiColor::Cyan.on_default().bold()
}

fn token_style() -> Style {
    AnsiColor::Green.on_default().bold()
}

fn code_style() -> Style {
    Style::new().bold()
}

fn tone_style(tone: SummaryTone) -> Style {
    match tone {
        SummaryTone::Success => success_style(),
        SummaryTone::Warning => warning_style(),
        SummaryTone::Error => error_style(),
    }
}

pub(crate) fn write_help(out: &mut impl Write, help: &str) -> io::Result<()> {
    let heading = label_style();
    let token = token_style();
    for (index, line) in help.lines().enumerate() {
        if index == 0 || (!line.starts_with(' ') && line.ends_with(':')) {
            writeln!(out, "{heading}{line}{heading:#}")?;
            continue;
        }

        let trimmed = line.trim_start_matches(' ');
        let indent = line
            .strip_suffix(trimmed)
            .expect("trimmed line must remain a suffix");
        if trimmed.starts_with("memcordon ") {
            writeln!(out, "{indent}{token}{trimmed}{token:#}")?;
            continue;
        }
        if !indent.is_empty()
            && let Some((term, description)) = split_aligned_term(trimmed)
        {
            writeln!(out, "{indent}{token}{term}{token:#}{description}")?;
            continue;
        }
        writeln!(out, "{line}")?;
    }
    Ok(())
}

fn split_aligned_term(line: &str) -> Option<(&str, &str)> {
    let boundary = line.find("  ")?;
    let (term, description) = line.split_at(boundary);
    (!term.is_empty() && !description.trim().is_empty()).then_some((term, description))
}

pub(crate) fn write_version(out: &mut impl Write, version: &str) -> io::Result<()> {
    let label = label_style();
    writeln!(out, "{label}memcordon{label:#} {version}")
}

pub(crate) fn write_usage_error(
    out: &mut impl Write,
    code: &str,
    message: impl fmt::Display,
) -> io::Result<()> {
    let error = error_style();
    let code_style = code_style();
    writeln!(
        out,
        "{error}error{error:#}[{code_style}{code}{code_style:#}]: {message}"
    )
}

pub(crate) fn write_runtime_error(
    out: &mut impl Write,
    message: impl fmt::Display,
) -> io::Result<()> {
    let error = error_style();
    writeln!(out, "{error}memcordon:{error:#} {message}")
}

pub(crate) fn write_warning(
    out: &mut impl Write,
    option: &str,
    requested: &str,
    reason: &str,
) -> io::Result<()> {
    let warning = warning_style();
    let option_style = label_style();
    writeln!(
        out,
        "memcordon: {warning}warning{warning:#}: {option_style}--{option}{option_style:#} {requested} is ineffective: {reason}"
    )
}

pub(crate) fn write_label_value(
    out: &mut impl Write,
    label: &str,
    value: impl fmt::Display,
) -> io::Result<()> {
    let label_style = label_style();
    writeln!(out, "{label_style}{label}{label_style:#}: {value}")
}

pub(crate) fn write_selected_backend(out: &mut impl Write, backend: &str) -> io::Result<()> {
    let label = label_style();
    let value = if backend == "none" {
        warning_style()
    } else {
        success_style()
    };
    writeln!(
        out,
        "{label}selected backend{label:#}: {value}{backend}{value:#}"
    )
}

pub(crate) fn write_clean_action(
    out: &mut impl Write,
    dry_run: bool,
    value: impl fmt::Display,
) -> io::Result<()> {
    let (action, style) = if dry_run {
        ("would remove", warning_style())
    } else {
        ("removed", success_style())
    };
    writeln!(out, "{style}{action}{style:#} {value}")
}

pub(crate) fn write_summary(out: &mut impl Write, summary: ExecutionSummary<'_>) -> io::Result<()> {
    let style = tone_style(summary.tone);
    writeln!(
        out,
        "memcordon: {style}{} {}{style:#}; backend {}; attempts {}; restarts {}",
        summary.outcome, summary.status, summary.backend, summary.attempts, summary.restarts
    )
}
