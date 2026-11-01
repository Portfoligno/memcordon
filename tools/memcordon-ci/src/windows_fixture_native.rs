//! Closed native fixture selection and proof of both distinct native executions.
use std::io;
use std::time::Duration;

pub const TARGET_DIR: &str = "target/ci/windows-fixture-native";
pub const TEST_SELECTOR: &str =
    "fresh_restricted_primary_namespace_access_is_observed_without_inherited_gate_capabilities";
pub const TRACE_TEST_SELECTOR: &str =
    "isolated_native_mock_and_owned_event_calls_preserve_original_results";
pub const TEST_SELECTORS: [&str; 2] = [TEST_SELECTOR, TRACE_TEST_SELECTOR];

pub struct Command {
    pub arguments: Vec<&'static str>,
    pub deadline: Duration,
}

pub fn commands(compile: Duration, execute: Duration) -> [Command; 2] {
    let base = vec![
        "--locked",
        "--target-dir",
        TARGET_DIR,
        "--package",
        "memcordon",
        "--test",
        "windows_namespace_primary",
        "--test",
        "windows_gate_call_trace",
        "--all-features",
    ];
    let mut compilation = base.clone();
    compilation.push("--no-run");
    let mut execution = base;
    execution.extend(["--", "--exact", "--nocapture"]);
    execution.extend(TEST_SELECTORS);
    [
        Command {
            arguments: compilation,
            deadline: compile,
        },
        Command {
            arguments: execution,
            deadline: execute,
        },
    ]
}

pub fn verify_selected_tests(stdout: &[u8]) -> io::Result<()> {
    let reject = || {
        io::Error::other(
            "native fixture requires both distinct selected tests, each executed once with one pass and no failure or ignored result",
        )
    };
    if stdout.len() > 1024 * 1024 {
        return Err(reject());
    }
    let text = std::str::from_utf8(stdout).map_err(|_| reject())?;
    let mut phase = 0;
    let mut seen = [false; 2];
    let mut summaries = 0usize;
    for line in text.lines().map(str::trim) {
        if line.starts_with("running ") {
            if line != "running 1 test" || phase != 0 || summaries >= TEST_SELECTORS.len() {
                return Err(reject());
            }
            phase = 1;
        }
        if let Some(record) = line
            .strip_prefix("test ")
            .filter(|_| !line.starts_with("test result:"))
        {
            let name = record.strip_suffix(" ... ok").ok_or_else(reject)?;
            let index = TEST_SELECTORS
                .iter()
                .position(|expected| *expected == name)
                .ok_or_else(reject)?;
            if phase != 1 || seen[index] {
                return Err(reject());
            }
            seen[index] = true;
            phase = 2;
        }
        if line.starts_with("test result:") {
            if phase != 2 {
                return Err(reject());
            }
            let summary = line.strip_prefix("test result: ok. ").ok_or_else(reject)?;
            let mut fields = summary.split("; ");
            for expected in ["1 passed", "0 failed", "0 ignored", "0 measured"] {
                if fields.next() != Some(expected) {
                    return Err(reject());
                }
            }
            let filtered = fields
                .next()
                .and_then(|field| field.strip_suffix(" filtered out"))
                .ok_or_else(reject)?;
            let elapsed = fields
                .next()
                .and_then(|field| field.strip_prefix("finished in "))
                .and_then(|field| field.strip_suffix('s'))
                .and_then(|field| field.parse::<f64>().ok());
            if filtered.parse::<u64>().is_err()
                || elapsed.is_none_or(|value| !value.is_finite() || value < 0.0)
                || fields.next().is_some()
            {
                return Err(reject());
            }
            summaries += 1;
            phase = 0;
        }
    }
    if phase == 0 && summaries == TEST_SELECTORS.len() && seen.into_iter().all(|seen| seen) {
        Ok(())
    } else {
        Err(reject())
    }
}
