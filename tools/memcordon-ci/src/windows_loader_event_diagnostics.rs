//! Read-only event candidates; never workload authority or retirement evidence.
use std::time::{Duration, Instant};

pub const MAX_CAPTURE_BYTES: usize = 256 * 1024;
pub const MAX_QUERY_DURATION: Duration = Duration::from_secs(5);
pub const QUERY_ARGUMENTS: &[&str] = &[
    "qe",
    "Application",
    "/q:*[System[(Provider[@Name='Application Error'] or Provider[@Name='Windows Error Reporting'] or Provider[@Name='SideBySide']) and TimeCreated[timediff(@SystemTime) <= 60000]]]",
    "/c:64",
    "/rd:true",
    "/f:xml",
    "/e:Events",
];

pub fn query_budget(caller_cutoff: Instant, now: Instant) -> Option<Duration> {
    caller_cutoff
        .checked_duration_since(now)
        .filter(|remaining| !remaining.is_zero())
        .map(|remaining| remaining.min(MAX_QUERY_DURATION))
}

#[cfg(windows)]
pub struct Capture {
    pub program: Option<std::path::PathBuf>,
    pub state: serde_json::Value,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[cfg(windows)]
#[allow(unsafe_code)] // Locate the actual OS utility using a bounded native directory query.
fn system_utility() -> std::io::Result<std::path::PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
    // SAFETY: zero-sized query requests the required native buffer length.
    let required = unsafe { GetSystemDirectoryW(std::ptr::null_mut(), 0) };
    if required == 0 {
        return Err(std::io::Error::last_os_error());
    }
    if required > u32::from(u16::MAX) {
        return Err(std::io::Error::other(
            "native system directory exceeds bounded UTF-16 query",
        ));
    }
    let mut buffer = vec![0u16; required as usize];
    // SAFETY: writable buffer has exactly the queried native capacity.
    let written = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), required) };
    if written == 0 {
        return Err(std::io::Error::last_os_error());
    }
    if written >= required {
        return Err(std::io::Error::other(
            "native system directory changed during observation",
        ));
    }
    let directory =
        std::path::PathBuf::from(std::ffi::OsString::from_wide(&buffer[..written as usize]));
    if !directory.is_absolute() {
        return Err(std::io::Error::other(
            "native system directory is not absolute",
        ));
    }
    Ok(directory.join("wevtutil.exe"))
}

#[cfg(windows)]
pub fn observe(caller_cutoff: Instant) -> Capture {
    use memcordon_testkit::ProcessTestError;
    let unavailable = |reason: String| Capture {
        program: None,
        state: serde_json::json!({"state":"unavailable","reason":reason,"event_correlation":"unverified-candidates"}),
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    let now = Instant::now();
    let Some(budget) = query_budget(caller_cutoff, now) else {
        return unavailable("original caller deadline exhausted".into());
    };
    let Some(cutoff) = now.checked_add(budget) else {
        return unavailable("OS diagnostic cutoff overflow".into());
    };
    let program = match system_utility() {
        Ok(program) => program,
        Err(error) => return unavailable(error.to_string()),
    };
    let mut command = std::process::Command::new(&program);
    command.args(QUERY_ARGUMENTS).env_clear();
    let Some(remaining) = query_budget(cutoff, Instant::now()) else {
        return unavailable("original OS diagnostic cutoff exhausted before spawn".into());
    };
    // Each stream is capped at half the total retained-byte allowance.
    match memcordon_testkit::run_with_deadline_output_limit(
        &mut command,
        remaining,
        MAX_CAPTURE_BYTES / 2,
    ) {
        Ok(output) => Capture {
            program: Some(program),
            stdout: output.stdout,
            stderr: output.stderr,
            state: serde_json::json!({"state":"completed","native_status":output.status.code(),"query_succeeded":output.status.success(),
                "capture_complete":true,"elapsed_ms":output.elapsed.as_millis(),"event_correlation":"unverified-candidates"}),
        },
        Err(error) => {
            let detail = error.to_string().chars().take(4096).collect::<String>();
            let (stdout, stderr, native) = match error {
                ProcessTestError::Callback {
                    stdout,
                    stderr,
                    capture_complete,
                    observed_status,
                    termination,
                    cleanup,
                    ..
                } => (
                    stdout,
                    stderr,
                    serde_json::json!({"capture_complete":capture_complete,"observed_status":observed_status.map(|status|status.code()),"termination":termination.map(|status|status.code()),"cleanup":cleanup}),
                ),
                ProcessTestError::OutputLimit {
                    stdout,
                    stderr,
                    termination,
                    cleanup,
                }
                | ProcessTestError::Cancelled {
                    stdout,
                    stderr,
                    termination,
                    cleanup,
                    ..
                } => (
                    stdout,
                    stderr,
                    serde_json::json!({"capture_complete":false,"termination":termination.map(|status|status.code()),"cleanup":cleanup}),
                ),
                ProcessTestError::Timeout {
                    stdout,
                    stderr,
                    observation,
                    cleanup,
                    ..
                } => (
                    stdout,
                    stderr,
                    serde_json::json!({"capture_complete":false,"observed_status":observation.observed_status.map(|status|status.code()),"cleanup":cleanup}),
                ),
                _ => (
                    Vec::new(),
                    Vec::new(),
                    serde_json::json!({"capture_complete":false,"cleanup":"unknown"}),
                ),
            };
            Capture {
                program: Some(program),
                stdout,
                stderr,
                state: serde_json::json!({"state":"query-failed","detail":detail,"native":native,"event_correlation":"unverified-candidates"}),
            }
        }
    }
}
