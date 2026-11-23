//! Post-failure, read-only observation of one already recorded process.
#![allow(unsafe_code)]

use crate::windows_application_error_status::ObserverStatus;
use crate::windows_installed_cases::LaterFailureSubject;
use serde::Deserialize;
use std::io::{Read, Write};
use std::mem::size_of;
use std::process::Stdio;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_TIMEOUT, GetLastError};
use windows_sys::Win32::System::EventLog::{
    EVT_HANDLE, EVT_VARIANT, EvtClose, EvtCreateRenderContext, EvtNext, EvtQuery,
    EvtQueryChannelPath, EvtQueryReverseDirection, EvtRender, EvtRenderContextValues,
    EvtRenderEventValues, EvtVarTypeFileTime, EvtVarTypeHexInt32, EvtVarTypeHexInt64,
    EvtVarTypeString, EvtVarTypeUInt32, EvtVarTypeUInt64,
};

const MAX_RECEIPT_BYTES: u64 = 256 * 1024;
const MAX_EVENTS: usize = 32;
const MAX_READ_TIME: Duration = Duration::from_secs(5);
// The owned-child helper uses this elapsed cutoff from immediately before
// spawn. Native-boundary setup precedes it, and timeout settlement may extend
// wall-clock return time beyond it.
const OBSERVER_CHILD_CUTOFF: Duration = Duration::from_secs(8);
const MAX_OBSERVER_OUTPUT: usize = 4096;
const WINDOW_TICKS: u64 = 180 * 10_000_000;
const UNIX_EPOCH_FILETIME: u64 = 116_444_736_000_000_000;
const MATCH_FIELDS: &[&str] = &[
    "Event/System/TimeCreated/@SystemTime",
    "Event/EventData/Data[@Name='ProcessId']",
    "Event/EventData/Data[@Name='ProcessCreationTime']",
    "Event/EventData/Data[@Name='AppName']",
    "Event/EventData/Data[@Name='ModuleName']",
    "Event/EventData/Data[@Name='ExceptionCode']",
];
const RENDER_HEADER_BYTES: usize = MATCH_FIELDS.len() * size_of::<EVT_VARIANT>();
const RENDER_BUFFER_BYTES: usize = 512 * size_of::<EVT_VARIANT>();
const MAX_TEXT_UNITS: usize = 256;

#[repr(C)]
struct RenderStorage {
    // A zero-size first field gives the byte buffer EVT_VARIANT alignment.
    _alignment: [EVT_VARIANT; 0],
    bytes: [u8; RENDER_BUFFER_BYTES],
}

const _: () = assert!(std::mem::offset_of!(RenderStorage, bytes) == 0);

#[derive(Deserialize)]
struct Receipt {
    original: Original,
}

#[derive(Deserialize)]
struct Original {
    target: Subject,
}

#[derive(Deserialize)]
struct Subject {
    process_id: u32,
    creation_time_100ns: u64,
}

struct EventHandle(EVT_HANDLE);

impl EventHandle {
    fn new(raw: EVT_HANDLE) -> Option<Self> {
        (raw != 0).then(|| Self(raw))
    }
}

impl Drop for EventHandle {
    fn drop(&mut self) {
        // SAFETY: this nonzero handle was returned by the event API and is owned here.
        unsafe { EvtClose(self.0) };
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

fn subject_from_stdin() -> Result<Subject, ()> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_RECEIPT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() as u64 > MAX_RECEIPT_BYTES {
        return Err(());
    }
    let receipt: Receipt = serde_json::from_slice(&bytes).map_err(|_| ())?;
    let subject = receipt.original.target;
    (subject.process_id != 0 && subject.creation_time_100ns != 0)
        .then_some(subject)
        .ok_or(())
}

fn current_filetime() -> Option<u64> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    let ticks = u64::try_from(elapsed.as_nanos() / 100).ok()?;
    UNIX_EPOCH_FILETIME.checked_add(ticks)
}

fn render_string(value: &EVT_VARIANT, bytes: &[u8]) -> Option<String> {
    if value.Type != EvtVarTypeString as u32 {
        return None;
    }
    // SAFETY: the rendering type selects the StringVal union member.
    let ptr = unsafe { value.Anonymous.StringVal };
    let mut offset = ptr.addr().checked_sub(bytes.as_ptr().addr())?;
    if offset < RENDER_HEADER_BYTES || offset % size_of::<u16>() != 0 {
        return None;
    }
    let mut text = Vec::new();
    for _ in 0..=MAX_TEXT_UNITS {
        let end = offset.checked_add(size_of::<u16>())?;
        let unit = u16::from_le_bytes(bytes.get(offset..end)?.try_into().ok()?);
        if unit == 0 {
            return String::from_utf16(&text).ok();
        }
        if text.len() == MAX_TEXT_UNITS {
            return None;
        }
        text.push(unit);
        offset = end;
    }
    None
}

#[allow(non_upper_case_globals)]
fn render_number(value: &EVT_VARIANT, bytes: &[u8], hex: bool) -> Option<u64> {
    match value.Type as i32 {
        EvtVarTypeUInt32 | EvtVarTypeHexInt32 => {
            // SAFETY: the rendering type selects the UInt32Val union member.
            Some(u64::from(unsafe { value.Anonymous.UInt32Val }))
        }
        EvtVarTypeUInt64 | EvtVarTypeHexInt64 => {
            // SAFETY: the rendering type selects the UInt64Val union member.
            Some(unsafe { value.Anonymous.UInt64Val })
        }
        EvtVarTypeFileTime => {
            // SAFETY: the rendering type selects the FileTimeVal union member.
            Some(unsafe { value.Anonymous.FileTimeVal })
        }
        _ => {
            let text = render_string(value, bytes)?;
            let text = text.trim();
            if let Some(digits) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
                u64::from_str_radix(digits, 16).ok()
            } else if hex {
                u64::from_str_radix(text, 16).ok()
            } else {
                text.parse().ok()
            }
        }
    }
}

fn event_timestamp(value: &EVT_VARIANT, bytes: &[u8]) -> Option<u64> {
    if value.Type == EvtVarTypeFileTime as u32 {
        // SAFETY: the rendering type selects the FileTimeVal union member.
        return Some(unsafe { value.Anonymous.FileTimeVal });
    }
    let text = render_string(value, bytes)?;
    let utc =
        time::OffsetDateTime::parse(&text, &time::format_description::well_known::Rfc3339).ok()?;
    UNIX_EPOCH_FILETIME.checked_add(u64::try_from(utc.unix_timestamp_nanos() / 100).ok()?)
}

fn match_event(
    context: &EventHandle,
    event: &EventHandle,
    subject: &Subject,
    limit: u64,
) -> Result<bool, ()> {
    let mut storage = RenderStorage {
        _alignment: [],
        bytes: [0; RENDER_BUFFER_BYTES],
    };
    let base = storage.bytes.as_mut_ptr();
    let capacity = RENDER_BUFFER_BYTES as u32;
    let mut used = 0;
    let mut count = 0;
    // SAFETY: live handles and a writable, aligned buffer of the declared byte length.
    let rendered = unsafe {
        EvtRender(
            context.0,
            event.0,
            EvtRenderEventValues,
            capacity,
            base.cast(),
            &mut used,
            &mut count,
        )
    };
    if rendered == 0
        || used > capacity
        || count as usize != MATCH_FIELDS.len()
        || (used as usize) < RENDER_HEADER_BYTES
    {
        return Err(());
    }
    let bytes = storage.bytes.get(..used as usize).ok_or(())?;
    // SAFETY: the aligned prefix contains the exact number of rendered variant headers.
    let values =
        unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast::<EVT_VARIANT>(), count as usize) };
    let text = |i| render_string(&values[i], bytes);
    if render_number(&values[1], bytes, false) != Some(u64::from(subject.process_id))
        || render_number(&values[2], bytes, false) != Some(subject.creation_time_100ns)
    {
        return Ok(false);
    }
    let timestamp = event_timestamp(&values[0], bytes).ok_or(())?;
    if timestamp < subject.creation_time_100ns || timestamp > limit {
        return Ok(false);
    }
    // Read and validate the remaining selected values without publishing them.
    // The only outward result is a fixed status token.
    let _ = text(3);
    let _ = text(4);
    let _ = render_number(&values[5], bytes, true);
    Ok(true)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObserveFailure {
    Unavailable,
    Timeout,
}

fn observe(subject: &Subject) -> Result<bool, ObserveFailure> {
    let unavailable = ObserveFailure::Unavailable;
    let timeout_failure = ObserveFailure::Timeout;
    let limit = current_filetime().ok_or(unavailable)?;
    if !(1..=WINDOW_TICKS).contains(
        &limit
            .checked_sub(subject.creation_time_100ns)
            .ok_or(unavailable)?,
    ) {
        return Err(unavailable);
    }
    let deadline = Instant::now() + MAX_READ_TIME;
    let channel = wide("Application");
    let filter = wide(
        "*[System[Provider[@Name='Application Error'] and EventID=1000 and TimeCreated[timediff(@SystemTime) <= 180000]]]",
    );
    // SAFETY: valid NUL-terminated local channel and filter; no remote session.
    let query = EventHandle::new(unsafe {
        EvtQuery(
            0,
            channel.as_ptr(),
            filter.as_ptr(),
            EvtQueryChannelPath | EvtQueryReverseDirection,
        )
    })
    .ok_or(unavailable)?;
    let paths: Vec<_> = MATCH_FIELDS.iter().map(|field| wide(field)).collect();
    let pointers: Vec<_> = paths.iter().map(|path| path.as_ptr()).collect();
    // SAFETY: pointer array and its NUL-terminated XPath strings live through the call.
    let context = EventHandle::new(unsafe {
        EvtCreateRenderContext(
            pointers.len() as u32,
            pointers.as_ptr(),
            EvtRenderContextValues,
        )
    })
    .ok_or(unavailable)?;
    let mut matched = None;
    for _ in 0..MAX_EVENTS {
        let budget = deadline
            .checked_duration_since(Instant::now())
            .ok_or(timeout_failure)?;
        let timeout = u32::try_from(budget.as_millis()).map_err(|_| unavailable)?;
        if timeout == 0 {
            return Err(timeout_failure);
        }
        let mut raw = 0;
        let mut count = 0;
        // SAFETY: live query handle and a writable one-element event handle buffer.
        let next = unsafe { EvtNext(query.0, 1, &mut raw, timeout, 0, &mut count) };
        if next == 0 {
            // SAFETY: queried immediately after the failing API call on this thread.
            return match unsafe { GetLastError() } {
                ERROR_NO_MORE_ITEMS => Ok(matched.unwrap_or(false)),
                ERROR_TIMEOUT => Err(timeout_failure),
                _ => Err(unavailable),
            };
        }
        let event = EventHandle::new(raw).ok_or(unavailable)?;
        if count != 1 {
            return Err(unavailable);
        }
        if match_event(&context, &event, subject, limit).map_err(|_| unavailable)? {
            if matched.replace(true).is_some() {
                return Err(unavailable);
            }
        }
    }
    Err(unavailable)
}

pub fn report_stdin() {
    let status = match subject_from_stdin() {
        Err(()) => ObserverStatus::MalformedResult,
        Ok(subject) => match observe(&subject) {
            Ok(true) => ObserverStatus::Matched,
            Ok(false) => ObserverStatus::NoMatch,
            Err(ObserveFailure::Unavailable) => ObserverStatus::Unavailable,
            Err(ObserveFailure::Timeout) => ObserverStatus::Timeout,
        },
    };
    let _ = writeln!(std::io::stdout().lock(), "{}", status.token());
}

/// Run the read-only observer only after the installed-test call has returned
/// its eligible failure receipt. The identity crosses a bounded child-stdin
/// pipe; it is absent from argv, paths, logs, and retained artifacts.
pub(crate) fn observe_after_cleanup(subject: &LaterFailureSubject) -> ObserverStatus {
    let (process_id, creation_time_100ns) = subject.process_identity();
    let receipt = serde_json::json!({
        "original": {
            "target": {
                "process_id": process_id,
                "creation_time_100ns": creation_time_100ns,
            }
        }
    });
    let Ok(bytes) = serde_json::to_vec(&receipt) else {
        return ObserverStatus::Unavailable;
    };
    let executable = match std::env::current_exe() {
        Ok(executable) => executable,
        Err(_) => return ObserverStatus::Unavailable,
    };
    let mut command = match crate::command::CommandSpec::new(
        executable,
        std::path::Path::new("."),
        OBSERVER_CHILD_CUTOFF,
    )
    .args(["ci", "observe-windows-application-error"])
    .cleared_environment()
    .materialize()
    {
        Ok(command) => command,
        Err(_) => return ObserverStatus::Unavailable,
    };
    // The reviewed command boundary clears the complete child environment;
    // the process identity remains confined to the bounded stdin pipe.
    command.stdin(Stdio::piped());

    let output = memcordon_testkit::run_with_deadline_owned_spawn_with_io_output_limit(
        command,
        OBSERVER_CHILD_CUTOFF,
        MAX_OBSERVER_OUTPUT,
        |mut command| command.spawn(),
        move |_, input, _| {
            let mut input =
                input.ok_or_else(|| std::io::Error::other("observer stdin pipe unavailable"))?;
            input.write_all(&bytes)?;
            Ok(())
        },
    );
    match output {
        Ok(output) => ObserverStatus::from_child_output(
            output.status.success(),
            &output.stdout,
            &output.stderr,
        ),
        Err(memcordon_testkit::ProcessTestError::Timeout { .. }) => ObserverStatus::Timeout,
        Err(memcordon_testkit::ProcessTestError::OutputLimit { .. }) => {
            ObserverStatus::MalformedResult
        }
        Err(_) => ObserverStatus::Unavailable,
    }
}
