//! Bounded actual unit diagnostics for the current Linux package lifetime.
use crate::{CiError, Result, command::CommandSpec};
use std::{fs, path::Path, time::Duration};

#[derive(Clone, Copy)]
pub enum PrivateUnitDiagnostic {
    Status,
    Journal,
}

impl PrivateUnitDiagnostic {
    fn name(self) -> &'static str {
        match self {
            Self::Status => "unit-status",
            Self::Journal => "unit-journal",
        }
    }
}

pub const PRIVATE_UNIT_DIAGNOSTIC_BYTES: usize = 1024 * 1024;
const PRIVATE_UNIT_DIAGNOSTIC_DEADLINE: Duration = Duration::from_secs(10);
const PRIVATE_UNITS: [&str; 6] = [
    "memcordon-sealed-agent.service",
    "memcordon-sealed-agent.socket",
    "memcordon-sealed-launcher.service",
    "memcordon-sealed-launcher.socket",
    "memcordon-sealed-network-launcher.service",
    "memcordon-sealed-network-launcher.socket",
];

/// Query only the selected installed units; collection cannot establish readiness.
pub fn private_unit_diagnostic_command(cwd: &Path, kind: PrivateUnitDiagnostic) -> CommandSpec {
    let command = CommandSpec::new("sudo", cwd, PRIVATE_UNIT_DIAGNOSTIC_DEADLINE).arg("-n");
    match kind {
        PrivateUnitDiagnostic::Status => command
            .args(["systemctl", "status", "--no-pager", "--full", "--"])
            .args(PRIVATE_UNITS),
        PrivateUnitDiagnostic::Journal => {
            let mut command = command.args([
                "journalctl",
                "--boot",
                "--no-pager",
                "--output=short-precise",
                "--lines=200",
            ]);
            for unit in PRIVATE_UNITS {
                command = command.arg("--unit").arg(unit);
            }
            command
        }
    }
}

/// Bounded original journal context, never an authenticated execution receipt.
pub fn private_unit_journal_excerpt(bytes: &[u8]) -> String {
    let mut summary = String::new();
    use std::fmt::Write;
    for marker in [
        "sealed provider rejected request:",
        "sealed launcher rejected request:",
    ] {
        let mut matches = bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| String::from_utf8_lossy(line).contains(marker));
        let first = matches.next();
        let mut last = first;
        let mut count = usize::from(first.is_some());
        for line in matches {
            last = Some(line);
            count += 1;
        }
        writeln!(summary, "worker-marker={marker}; observed-matches={count}")
            .expect("String writing cannot fail");
        for (position, line) in [("first", first), ("last", last)] {
            if let Some(line) = line {
                writeln!(
                    summary,
                    "{position}; observed-bytes={}; truncated={}; original={}",
                    line.len(),
                    line.len() > 512,
                    String::from_utf8_lossy(&line[..line.len().min(512)]),
                )
                .expect("String writing cannot fail");
            }
        }
    }
    writeln!(
        summary,
        "journal-observed-bytes={}; context-complete={}; head={}\ntail={}",
        bytes.len(),
        bytes.len() <= 1024,
        String::from_utf8_lossy(&bytes[..bytes.len().min(1024)]),
        String::from_utf8_lossy(&bytes[bytes.len().saturating_sub(1024)..]),
    )
    .expect("String writing cannot fail");
    summary
}

/// Record nonzero status as actual diagnostic data. Incomplete output never
/// becomes a successful empty observation, and an existing leaf is not replaced.
pub fn retain_private_unit_diagnostic(
    directory: &Path,
    kind: PrivateUnitDiagnostic,
    output: std::result::Result<
        memcordon_testkit::ObservedOutput,
        memcordon_testkit::ProcessTestError,
    >,
) -> Result<()> {
    use memcordon_testkit::ProcessTestError;
    use std::io::Write;

    let (streams, complete, readers, status, failure) = match &output {
        Ok(value) => (
            Some((value.stdout.as_slice(), value.stderr.as_slice())),
            true,
            Some((true, true)),
            Some(value.status),
            None,
        ),
        Err(ProcessTestError::Timeout {
            stdout,
            stderr,
            observation,
            ..
        }) => (
            Some((stdout.as_slice(), stderr.as_slice())),
            false,
            Some((
                observation.stdout_reader_finished,
                observation.stderr_reader_finished,
            )),
            observation.observed_status,
            output.as_ref().err().map(ToString::to_string),
        ),
        Err(error) => (None, false, None, None, Some(error.to_string())),
    };
    let (stdout_name, stderr_name, capture_name) = match kind {
        PrivateUnitDiagnostic::Status => (
            "unit-status.stdout.bin",
            "unit-status.stderr.bin",
            "unit-status.capture.json",
        ),
        PrivateUnitDiagnostic::Journal => (
            "unit-journal.stdout.bin",
            "unit-journal.stderr.bin",
            "unit-journal.capture.json",
        ),
    };
    let retain = |name: &str, bytes: &[u8]| -> Result<()> {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join(name))?
            .write_all(bytes)?;
        Ok(())
    };
    if let Some((stdout, stderr)) = streams {
        if stdout.len() > PRIVATE_UNIT_DIAGNOSTIC_BYTES
            || stderr.len() > PRIVATE_UNIT_DIAGNOSTIC_BYTES
        {
            return Err(CiError::Message(
                "unit diagnostic output exceeds retained bound".into(),
            ));
        }
        if matches!(kind, PrivateUnitDiagnostic::Journal) {
            // Publish the original pre-cleanup worker error before artifact
            // retention or uninstall can fail. This is a bounded diagnostic,
            // not evidence of successful execution or complete journal history.
            let _ = writeln!(
                std::io::stderr().lock(),
                "private-unit-journal; pre-cleanup=true; operation-complete={complete}; readers={readers:?}; status={status:?}; stderr-observed-bytes={}; stderr-truncated={}; stderr={}\n{}",
                stderr.len(),
                stderr.len() > 512,
                String::from_utf8_lossy(&stderr[..stderr.len().min(512)]),
                private_unit_journal_excerpt(stdout),
            );
        }
        retain(stdout_name, stdout)?;
        retain(stderr_name, stderr)?;
    }
    let capture = serde_json::json!({
        "format": "memcordon.private-unit-diagnostic-capture",
        "revision": 1,
        "operation": kind.name(),
        "units": PRIVATE_UNITS,
        "operation_complete": complete,
        "streams_available": streams.is_some(),
        "stdout_reader_finished": readers.map(|value| value.0),
        "stderr_reader_finished": readers.map(|value| value.1),
        "observed_exit_code": status.and_then(|value| value.code()),
        "observed_success": status.map(|value| value.success()),
        "failure": failure,
    });
    retain(capture_name, &serde_json::to_vec_pretty(&capture)?)?;
    if let Some(failure) = failure {
        return Err(CiError::Message(format!(
            "{} capture incomplete or unavailable: {failure}",
            kind.name()
        )));
    }
    Ok(())
}

/// Preserve the original body and cleanup results even when diagnostics fail.
pub fn diagnose_then_cleanup<T>(
    body: Result<()>,
    diagnose: impl FnOnce() -> Result<()>,
    cleanup: impl FnOnce() -> Result<T>,
) -> (Result<()>, Result<T>, Result<()>) {
    if crate::cancellation::observed().is_some() {
        // Preserve the primary failure, and give required cleanup priority over
        // optional journal acquisition during the runner's termination window.
        let cleanup = cleanup();
        let diagnostics = if body.is_err() {
            Err(CiError::Message(
                "optional unit diagnostics not attempted after cancellation".into(),
            ))
        } else {
            Ok(())
        };
        return (body, cleanup, diagnostics);
    }
    let diagnostics = if body.is_err() { diagnose() } else { Ok(()) };
    let cleanup = cleanup();
    (body, cleanup, diagnostics)
}

#[cfg(target_os = "linux")]
pub fn capture_private_unit_diagnostics(
    cwd: &Path,
    output: &Path,
    journal_diagnostic: &mut Option<String>,
    cutoff: std::time::Instant,
) -> Result<()> {
    let directory = output.join("pre-cleanup-units");
    fs::create_dir(&directory)?;
    let mut failures = Vec::new();
    for kind in [
        PrivateUnitDiagnostic::Status,
        PrivateUnitDiagnostic::Journal,
    ] {
        let remaining = cutoff
            .saturating_duration_since(std::time::Instant::now())
            .min(PRIVATE_UNIT_DIAGNOSTIC_DEADLINE);
        if remaining.is_zero() {
            return Err(CiError::Message(
                "original unit diagnostic cutoff exhausted".into(),
            ));
        }
        let command = private_unit_diagnostic_command(cwd, kind)
            .bounded_until(cutoff)
            .materialize();
        let observed = match command {
            Ok(mut command) => memcordon_testkit::run_with_deadline_external_stop_output_limit(
                &mut command,
                remaining,
                PRIVATE_UNIT_DIAGNOSTIC_BYTES,
                None,
                None,
                None,
                Some(std::sync::Arc::new(|| {
                    crate::cancellation::observed().is_some()
                })),
            ),
            Err(error) => Err(memcordon_testkit::ProcessTestError::Spawn(
                std::io::Error::other(error.to_string()),
            )),
        };
        if matches!(kind, PrivateUnitDiagnostic::Journal) {
            // Keep the original capture in memory as well: later cleanup
            // output must not displace it from the outer runner's error tail.
            *journal_diagnostic = Some(match &observed {
                Ok(value) => format!(
                    "original-pre-cleanup-journal; operation-complete=true; status={:?}\n{}",
                    value.status,
                    private_unit_journal_excerpt(&value.stdout),
                ),
                Err(memcordon_testkit::ProcessTestError::Timeout {
                    stdout,
                    observation,
                    ..
                }) => format!(
                    "original-pre-cleanup-journal; operation-complete=false; readers=({},{}) ; status={:?}\n{}",
                    observation.stdout_reader_finished,
                    observation.stderr_reader_finished,
                    observation.observed_status,
                    private_unit_journal_excerpt(stdout),
                ),
                Err(_) => "original-pre-cleanup-journal; streams-unavailable=true".into(),
            });
        }
        if let Err(error) = retain_private_unit_diagnostic(&directory, kind, observed) {
            failures.push(error.to_string());
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(CiError::Message(failures.join("; ")))
    }
}
