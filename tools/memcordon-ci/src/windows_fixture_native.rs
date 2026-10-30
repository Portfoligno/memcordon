//! Closed native fixture selection and proof of actual one-test execution.
use std::io;
use std::time::Duration;

pub const TARGET_DIR: &str = "target/ci/windows-fixture-native";
pub const TEST_SELECTOR: &str =
    "fresh_restricted_primary_namespace_access_is_observed_without_inherited_gate_capabilities";

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
        "--all-features",
    ];
    let mut compilation = base.clone();
    compilation.push("--no-run");
    let mut execution = base;
    execution.extend([TEST_SELECTOR, "--", "--exact", "--nocapture"]);
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

pub fn verify_one_test(stdout: &[u8]) -> io::Result<()> {
    let reject = || {
        io::Error::other(
            "native fixture requires exactly one executed selected test with one pass and no failure or ignored result",
        )
    };
    if stdout.len() > 1024 * 1024 {
        return Err(reject());
    }
    let text = std::str::from_utf8(stdout).map_err(|_| reject())?;
    let mut running = 0;
    let mut selected = 0;
    let mut summaries = 0;
    for line in text.lines().map(str::trim) {
        if line.starts_with("running ") && (line.ends_with(" test") || line.ends_with(" tests")) {
            if line != "running 1 test" || (running, selected, summaries) != (0, 0, 0) {
                return Err(reject());
            }
            running += 1;
        }
        if let Some(record) = line
            .strip_prefix("test ")
            .filter(|_| !line.starts_with("test result:"))
        {
            if record.strip_suffix(" ... ok") != Some(TEST_SELECTOR)
                || (running, selected, summaries) != (1, 0, 0)
            {
                return Err(reject());
            }
            selected += 1;
        }
        if line.starts_with("test result:") {
            if (running, selected, summaries) != (1, 1, 0) {
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
            if filtered.parse::<u64>().is_err()
                || fields
                    .next()
                    .and_then(|field| field.strip_prefix("finished in "))
                    .is_none_or(str::is_empty)
                || fields.next().is_some()
            {
                return Err(reject());
            }
            summaries += 1;
        }
    }
    if (running, selected, summaries) == (1, 1, 1) {
        Ok(())
    } else {
        Err(reject())
    }
}
