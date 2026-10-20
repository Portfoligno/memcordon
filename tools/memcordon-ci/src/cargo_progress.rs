//! Bounded observations of already-redacted Cargo lines, not compiler liveness proof.
use std::collections::VecDeque;
use std::time::Duration;

use serde::Serialize;

const RECORD_LIMIT: usize = 32;
const TEXT_LIMIT: usize = 512;

#[derive(Clone, Debug, Serialize)]
pub struct CargoProgressRecord {
    pub elapsed_us: u64,
    pub stream: &'static str,
    pub kind: &'static str,
    pub text: String,
    pub text_truncated: bool,
}

#[derive(Debug, Serialize)]
pub struct CargoProgress {
    clock_domain: &'static str,
    timestamp_meaning: &'static str,
    work_budget_us: u64,
    pub first_lock: Option<CargoProgressRecord>,
    pub first_compile: Option<CargoProgressRecord>,
    pub last_progress: Option<CargoProgressRecord>,
    pub records: VecDeque<CargoProgressRecord>,
    pub omitted_records: u64,
    pub truncated_texts: u64,
    pub omitted_lines: u64,
    pub omitted_chunks: u64,
    pub counter_saturated: bool,
}

impl CargoProgress {
    pub fn new(work_budget: Duration) -> Self {
        Self {
            clock_domain: "command-start-monotonic",
            timestamp_meaning: "logger-consumption-not-child-emission",
            work_budget_us: u64::try_from(work_budget.as_micros()).unwrap_or(u64::MAX),
            first_lock: None,
            first_compile: None,
            last_progress: None,
            records: VecDeque::new(),
            omitted_records: 0,
            truncated_texts: 0,
            omitted_lines: 0,
            omitted_chunks: 0,
            counter_saturated: false,
        }
    }

    /// Input is the existing logger's redacted, escaped complete line.
    pub fn observe_line(
        &mut self,
        elapsed: Duration,
        stream: memcordon_testkit::OutputStream,
        safe_line: &str,
    ) {
        let line = safe_line.trim_start();
        let kind = if line.starts_with("Blocking waiting for file lock") {
            "lock-wait"
        } else if line.starts_with("Compiling ") || line.starts_with("Checking ") {
            "compile"
        } else if line.starts_with("Finished ") {
            "finished"
        } else {
            return;
        };
        let elapsed_us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        let end = (0..=line.len().min(TEXT_LIMIT))
            .rev()
            .find(|end| line.is_char_boundary(*end))
            .expect("zero is a character boundary");
        let text = line[..end].to_owned();
        let record = CargoProgressRecord {
            elapsed_us,
            stream: match stream {
                memcordon_testkit::OutputStream::Stdout => "stdout",
                memcordon_testkit::OutputStream::Stderr => "stderr",
            },
            kind,
            text_truncated: text.len() != line.len(),
            text,
        };
        if record.text_truncated {
            increment(&mut self.truncated_texts, &mut self.counter_saturated);
        }
        if kind == "lock-wait" && self.first_lock.is_none() {
            self.first_lock = Some(record.clone());
        }
        if kind == "compile" && self.first_compile.is_none() {
            self.first_compile = Some(record.clone());
        }
        self.last_progress = Some(record.clone());
        if self.records.len() == RECORD_LIMIT {
            self.records.pop_front();
            increment(&mut self.omitted_records, &mut self.counter_saturated);
        }
        self.records.push_back(record);
    }

    pub fn finish(&mut self, omitted_lines: u64, omitted_chunks: u64) {
        self.omitted_lines = omitted_lines;
        self.omitted_chunks = omitted_chunks;
        self.counter_saturated |= omitted_lines == u64::MAX || omitted_chunks == u64::MAX;
    }
}

fn increment(value: &mut u64, saturated: &mut bool) {
    match value.checked_add(1) {
        Some(next) => *value = next,
        None => *saturated = true,
    }
}
