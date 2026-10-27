//! Closed selection and bounded encoding for failure-only gate observations.
use std::io::{self, Write};

pub const RECORD_BOUND: usize = 64 * 1024;
const JSON_BOUND: usize = RECORD_BOUND - 1024;
pub const GROUP_BOUND: usize = 64;
pub const SID_SUBAUTHORITIES: usize = 15;
pub const QUERY_BOUND: usize = 64 * 1024;

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut text = String::new();
    for byte in bytes {
        write!(&mut text, "{byte:02x}").expect("String formatting is infallible");
    }
    text
}

pub fn process_fallback(thread_open_error: u32) -> bool {
    thread_open_error == 1008 // ERROR_NO_TOKEN; every other failure stays unavailable.
}

pub fn group_extent(count: usize, stride: usize, start: usize, length: usize) -> bool {
    if count == 0 {
        return length >= size_of::<u32>();
    }
    count <= GROUP_BOUND
        && count
            .checked_mul(stride)
            .and_then(|n| start.checked_add(n))
            .is_some_and(|end| end <= length)
}

pub fn query_length(length: usize) -> bool {
    length != 0 && length <= QUERY_BOUND
}

pub fn impersonation_applicable(token_type: u32) -> Option<bool> {
    match token_type {
        1 => Some(false),
        2 => Some(true),
        _ => None,
    }
}

pub fn access_result(
    api: bool,
    raw: Option<u32>,
    granted: u32,
    status: bool,
    work_live: bool,
    unchanged: Option<bool>,
    within_bound: bool,
) -> serde_json::Value {
    serde_json::json!({"api_return":api,"raw_os_error":raw,"access_status":api.then_some(status),
        "granted_access":api.then_some(granted),"original_work_confirmed":work_live,
        "comparison_conclusive":api&&work_live&&unchanged==Some(true)&&within_bound})
}

pub fn sid_extent(bytes: &[u8]) -> Option<usize> {
    let prefix = 8_usize;
    if bytes.len() < prefix || bytes[0] != 1 || usize::from(bytes[1]) > SID_SUBAUTHORITIES {
        return None;
    }
    let size = usize::from(bytes[1])
        .checked_mul(size_of::<u32>())?
        .checked_add(prefix)?;
    (size <= bytes.len()).then_some(size)
}

pub fn encode(value: &serde_json::Value) -> io::Result<String> {
    struct Bounded(Vec<u8>);
    impl Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self
                .0
                .len()
                .checked_add(bytes.len())
                .is_none_or(|n| n > JSON_BOUND)
            {
                return Err(io::Error::other("controller gate diagnostic exceeds bound"));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut output = Bounded(Vec::new());
    serde_json::to_writer(&mut output, value).map_err(io::Error::other)?;
    String::from_utf8(output.0).map_err(io::Error::other)
}
