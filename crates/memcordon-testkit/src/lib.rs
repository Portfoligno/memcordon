#![forbid(unsafe_code)]

use std::process::{Command, Output};
use std::time::{Duration, Instant};

pub fn run_with_deadline(command: &mut Command, deadline: Duration) -> Output {
    let started = Instant::now();
    let output = command.output().expect("test command should spawn");
    assert!(
        started.elapsed() <= deadline,
        "command exceeded deadline of {deadline:?}"
    );
    output
}

pub fn assert_stdout_empty(output: &Output) {
    assert!(
        output.stdout.is_empty(),
        "wrapper wrote unexpected stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}
