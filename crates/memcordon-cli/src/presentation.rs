use std::ffi::OsStr;
use std::fmt;
use std::io::IsTerminal;
use std::io::{self, Write};

use anstream::{AutoStream, ColorChoice};
use anstyle::{AnsiColor, Style};

#[derive(Clone, Copy, Debug)]
pub(crate) struct Presentation {
    stdout_choice: ColorChoice,
    stderr_choice: ColorChoice,
}

impl Presentation {
    pub(crate) fn automatic() -> Self {
        let policy = ColourPolicy::from_process();
        Self {
            stdout_choice: policy.choice(std::io::stdout().is_terminal()),
            stderr_choice: policy.choice(std::io::stderr().is_terminal()),
        }
    }

    pub(crate) fn stdout(self) -> AutoStream<std::io::Stdout> {
        AutoStream::new(std::io::stdout(), self.stdout_choice)
    }

    pub(crate) fn stderr(self) -> AutoStream<std::io::Stderr> {
        AutoStream::new(std::io::stderr(), self.stderr_choice)
    }

    pub(crate) fn machine_stdout() -> AutoStream<std::io::Stdout> {
        AutoStream::new(std::io::stdout(), ColorChoice::Never)
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ColourPolicy {
    no_color: bool,
    force_colour: bool,
    clicolor: Option<bool>,
    terminal_supports_color: bool,
    ci: bool,
}

impl ColourPolicy {
    pub(crate) const fn new(
        no_color: bool,
        force_colour: bool,
        clicolor: Option<bool>,
        terminal_supports_color: bool,
        ci: bool,
    ) -> Self {
        Self {
            no_color,
            force_colour,
            clicolor,
            terminal_supports_color,
            ci,
        }
    }

    fn from_process() -> Self {
        Self::new(
            anstyle_query::no_color(),
            force_colour_requested(std::env::var_os("CLICOLOR_FORCE").as_deref()),
            anstyle_query::clicolor(),
            anstyle_query::term_supports_color(),
            anstyle_query::is_ci(),
        )
    }

    pub(crate) const fn choice(self, is_terminal: bool) -> ColorChoice {
        if self.no_color {
            ColorChoice::Never
        } else if self.force_colour {
            ColorChoice::Always
        } else if matches!(self.clicolor, Some(false)) {
            ColorChoice::Never
        } else if is_terminal
            && (self.terminal_supports_color || matches!(self.clicolor, Some(true)) || self.ci)
        {
            ColorChoice::Always
        } else {
            ColorChoice::Never
        }
    }
}

pub(crate) fn force_colour_requested(value: Option<&OsStr>) -> bool {
    value.is_some_and(|value| !value.is_empty() && value != "0")
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
    let lines = help.lines().collect::<Vec<_>>();
    let mut in_lead = true;
    for (index, line) in lines.iter().copied().enumerate() {
        if line.is_empty() {
            in_lead = false;
        } else if in_lead || (!line.starts_with(' ') && line.ends_with(':')) {
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
        if !indent.is_empty() {
            if let Some((term, description)) = split_aligned_term(trimmed) {
                writeln!(out, "{indent}{token}{term}{token:#}{description}")?;
                continue;
            }
            if is_wrapped_term(trimmed, indent.len(), lines.get(index + 1).copied()) {
                writeln!(out, "{indent}{token}{trimmed}{token:#}")?;
                continue;
            }
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

fn is_wrapped_term(line: &str, indent: usize, next: Option<&str>) -> bool {
    (line.starts_with('-') || line.starts_with('+'))
        && next.is_some_and(|next| {
            let trimmed = next.trim_start_matches(' ');
            !trimmed.is_empty() && next.len() - trimmed.len() > indent
        })
}

pub(crate) fn write_version(out: &mut impl Write, version: &str) -> io::Result<()> {
    let label = label_style();
    writeln!(out, "{label}memcordon{label:#} {version}")
}

pub(crate) fn write_json(out: &mut impl Write, value: &impl serde::Serialize) -> io::Result<()> {
    serde_json::to_writer_pretty(&mut *out, value).map_err(io::Error::other)?;
    writeln!(out)
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
