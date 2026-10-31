//! Diagnostic projection only; a retained failure never authorizes gate access.
use crate::CiError;
use memcordon_testkit::ProcessTestError;
use serde::Deserialize;
use serde_json::Value;

const PREFIX: &[u8] = b"original-gate-failure-before-control ";
const RECORD_BYTES: usize = 2048;
const CAPTURE_BYTES: usize = 4 * 1024 * 1024;

pub struct Expected<'a> {
    pub case: &'a Value,
    pub challenge_sha256: &'a str,
    pub gate_name_utf16_sha256: &'a str,
    pub fixture_pid: u32,
    pub fixture_birth: u128,
    pub guardian: Option<(u32, u128)>,
    pub guardian_query_failed: bool,
}

#[derive(Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Failure {
    format: String,
    revision: u32,
    diagnostic_only: bool,
    operation: String,
    desired_access: u32,
    original_raw_os_error: Option<i32>,
    original_kind: String,
    binding: Binding,
    control: String,
}

#[derive(Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Binding {
    case: Value,
    gate_name_utf16_sha256: String,
    challenge_sha256: String,
    next_transcript_sequence: u64,
}

fn original_code(stderr: &[u8], expected: &Expected<'_>) -> Result<i32, &'static str> {
    if stderr.len() > CAPTURE_BYTES {
        return Err("capture-exceeds-original-bound");
    }
    if expected.fixture_pid == 0 || expected.fixture_birth == 0 {
        return Err("original-held-fixture-identity-unavailable");
    }
    let mut original: Option<Failure> = None;
    for line in stderr.split_inclusive(|byte| *byte == b'\n') {
        let Some(bytes) = line.strip_prefix(PREFIX) else {
            continue;
        };
        let bytes = bytes
            .strip_suffix(b"\n")
            .ok_or("original-record-truncated")?;
        if bytes.len() > RECORD_BYTES {
            return Err("original-record-exceeds-bound");
        }
        memcordon_core::canonical_json::reject_duplicate_json_keys(bytes)
            .map_err(|_| "original-record-invalid-json")?;
        let failure: Failure =
            serde_json::from_slice(bytes).map_err(|_| "original-record-invalid")?;
        if failure.format != "memcordon.original-gate-failure-before-control"
            || failure.revision != 1
            || !failure.diagnostic_only
            || failure.operation != "OpenEventW-controller-wait"
            || failure.desired_access != 0x0010_0000
            || failure.control != "pending"
            || failure.original_raw_os_error.is_none_or(|code| code == 0)
            || failure.original_kind.is_empty()
            || failure.original_kind.len() > 128
            || failure.binding.case != *expected.case
            || failure.binding.challenge_sha256 != expected.challenge_sha256
            || failure.binding.gate_name_utf16_sha256 != expected.gate_name_utf16_sha256
        {
            return Err("original-record-binding-or-operation-differs");
        }
        if original.as_ref().is_some_and(|prior| prior != &failure) {
            return Err("conflicting-original-records");
        }
        original = Some(failure);
    }
    original
        .and_then(|failure| failure.original_raw_os_error)
        .ok_or("original-record-unavailable")
}

pub fn callback_failure(error: ProcessTestError, expected: Option<&Expected<'_>>) -> CiError {
    let projection = match (&error, expected) {
        (
            ProcessTestError::Callback {
                stderr,
                capture_complete: true,
                cleanup: Ok(()),
                ..
            },
            Some(expected),
        ) if expected.guardian_query_failed => original_code(stderr, expected),
        (
            ProcessTestError::Callback {
                capture_complete: false,
                ..
            },
            _,
        ) => Err("original-capture-incomplete"),
        (
            ProcessTestError::Callback {
                cleanup: Err(_), ..
            },
            _,
        ) => Err("original-capture-cleanup-unsettled"),
        (ProcessTestError::Callback { .. }, None) => Err("original-held-binding-unavailable"),
        (ProcessTestError::Callback { .. }, Some(_)) => {
            Err("original-guardian-query-failure-unavailable")
        }
        _ => return CiError::Process(error),
    };
    match projection {
        Ok(code) => {
            let expected =
                expected.expect("a bound projection requires original controller observations");
            CiError::LaneFailures {
                primary: Box::new(CiError::SettledCommandFailure(format!(
                    "original target gate failure (diagnostic-only): operation=OpenEventW-controller-wait; desired-access=0x00100000; raw-os-error={code}; controller-held-fixture-pid={}; controller-held-fixture-birth={}; target-association=unavailable-after-failed-query; case={}; challenge-sha256={}; gate-name-utf16-sha256={}",
                    expected.fixture_pid, expected.fixture_birth, expected.case,
                    expected.challenge_sha256, expected.gate_name_utf16_sha256,
                ))),
                secondary: Box::new(CiError::Process(error).context(format!("original guardian query; controller-held-guardian={:?}; query-association=unavailable", expected.guardian))),
            }
        }
        Err(reason) => CiError::Process(error).context(format!(
            "original target gate diagnostic unavailable: {reason}"
        )),
    }
}
