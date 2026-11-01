//! Portable interpretation of observations from the original held relay target.

use crate::{CiError, Result};

const TEXT_BYTES: usize = 128;

/// Exact Linux pipe-writer implementations supported by the observed kernel ABI.
pub fn supported_pipe_writer(channel: &str) -> bool {
    matches!(channel.trim(), "pipe_write" | "anon_pipe_write")
}

/// Bound the original proc read itself, separately from diagnostic rendering.
pub fn read_native_text(reader: impl std::io::Read) -> std::io::Result<String> {
    use std::io::Read;
    const BYTES: u64 = 4096;
    let mut bytes = Vec::new();
    reader.take(BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > BYTES {
        return Err(std::io::Error::other(
            "original relay native text exceeds bound",
        ));
    }
    String::from_utf8(bytes)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

#[derive(Debug, serde::Serialize)]
pub struct WriteSample {
    pub number: Option<i64>,
    pub descriptor: Option<u64>,
    pub length: Option<u64>,
    pub wait_channel: String,
    pub wait_channel_truncated: bool,
    pub raw_syscall: String,
    pub raw_syscall_truncated: bool,
    supported_pipe_writer: bool,
}

impl WriteSample {
    pub fn parse(syscall: &str, wchan: &str) -> Self {
        let mut fields = syscall.split_whitespace();
        let number = fields.next().and_then(|value| value.parse().ok());
        let hex = |value: &str| {
            value
                .strip_prefix("0x")
                .and_then(|value| u64::from_str_radix(value, 16).ok())
        };
        let descriptor = fields.next().and_then(hex);
        let length = fields.nth(1).and_then(hex);
        let (wait_channel, wait_channel_truncated) = bounded(wchan.trim());
        let (raw_syscall, raw_syscall_truncated) = bounded(syscall.trim());
        Self {
            number,
            descriptor,
            length,
            wait_channel,
            wait_channel_truncated,
            raw_syscall,
            raw_syscall_truncated,
            supported_pipe_writer: supported_pipe_writer(wchan),
        }
    }

    fn checks(
        &self,
        expected_descriptor: u64,
        queued: u64,
        capacity: u64,
        write_number: i64,
    ) -> [bool; 7] {
        [
            queued > 0,
            queued <= capacity,
            queued <= capacity && capacity - queued < 4096,
            self.number == Some(write_number),
            self.descriptor == Some(expected_descriptor),
            self.length == Some(256),
            self.supported_pipe_writer,
        ]
    }

    pub fn predicates(
        &self,
        expected_descriptor: u64,
        queued: u64,
        capacity: u64,
        write_number: i64,
    ) -> serde_json::Value {
        let [
            queued_positive,
            queued_within_capacity,
            free_below_4096,
            write_syscall,
            expected_descriptor,
            length_256,
            supported_pipe_writer,
        ] = self.checks(expected_descriptor, queued, capacity, write_number);
        serde_json::json!({"queued_positive":queued_positive,"queued_within_capacity":queued_within_capacity,
            "free_below_4096":free_below_4096,"write_syscall":write_syscall,
            "expected_descriptor":expected_descriptor,"length_256":length_256,"supported_pipe_writer":supported_pipe_writer})
    }

    pub fn matches(
        &self,
        expected_descriptor: u64,
        queued: u64,
        capacity: u64,
        write_number: i64,
    ) -> bool {
        self.checks(expected_descriptor, queued, capacity, write_number)
            .into_iter()
            .all(|value| value)
    }
}

fn bounded(value: &str) -> (String, bool) {
    let mut end = value.len().min(TEXT_BYTES);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    (value[..end].to_owned(), value.len() > end)
}

/// Keep each independently attempted operation's original typed failure in order.
pub fn combine(primary: Result<()>, secondary: Result<()>) -> Result<()> {
    match (primary, secondary) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(primary), Err(secondary)) => Err(CiError::LaneFailures {
            primary: Box::new(primary),
            secondary: Box::new(secondary),
        }),
    }
}
