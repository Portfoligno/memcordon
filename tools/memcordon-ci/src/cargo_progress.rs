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
    pub native_process_samples: VecDeque<serde_json::Value>,
    pub unit_completions: Vec<serde_json::Value>,
    pub omitted_unit_completions: u64,
    #[serde(skip)]
    unit_completion_bytes: usize,
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
            native_process_samples: VecDeque::new(),
            unit_completions: Vec::new(),
            omitted_unit_completions: 0,
            unit_completion_bytes: 0,
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
        } else if line.starts_with("Running ") {
            "invocation"
        } else if line.starts_with("Fresh ") {
            "fresh-unit"
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

    pub fn observe_native_resources(
        &mut self,
        elapsed: Duration,
        sample: Result<serde_json::Value, String>,
    ) {
        if self.native_process_samples.len() == 4 {
            self.native_process_samples.pop_front();
        }
        self.native_process_samples.push_back(serde_json::json!({
            "elapsed_us":u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX),
            "meaning":"read-only sample requested during work; may overlap cancellation; not completion authority",
            "observation":sample
        }));
    }

    /// Inspect already-redacted JSON before log escaping. Retain only finite
    /// Cargo artifact identity fields, never messages, environment or argv.
    pub fn observe_artifact(&mut self, elapsed: Duration, line: &str) {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            return;
        };
        if value.get("reason").and_then(serde_json::Value::as_str) != Some("compiler-artifact") {
            return;
        }
        let identity = serde_json::json!({"package":value.get("package_id"),
            "target":value.pointer("/target/name"),"kind":value.pointer("/target/kind"),
            "profile":value.get("profile"),"features":value.get("features"),"fresh":value.get("fresh")});
        let completion = serde_json::json!({"observed_elapsed_us":u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX),
            "artifact":identity,"authority":"unit-message-only; owning-command-success-and-writer-settlement-required"});
        if let Ok(bytes) = serde_json::to_vec(&completion)
            && self.unit_completions.len() < 4096
            && self
                .unit_completion_bytes
                .checked_add(bytes.len())
                .is_some_and(|total| total <= 4 * 1024 * 1024)
        {
            self.unit_completion_bytes += bytes.len();
            self.unit_completions.push(completion);
        } else {
            increment(
                &mut self.omitted_unit_completions,
                &mut self.counter_saturated,
            );
        }
        self.observe_line(
            elapsed,
            memcordon_testkit::OutputStream::Stdout,
            &format!("Finished unit {identity}"),
        );
    }
}

fn increment(value: &mut u64, saturated: &mut bool) {
    match value.checked_add(1) {
        Some(next) => *value = next,
        None => *saturated = true,
    }
}
