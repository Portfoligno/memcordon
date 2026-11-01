//! Diagnostic projection only; a retained failure never authorizes gate access.
use crate::CiError;
use memcordon_testkit::ProcessTestError;
use serde::Deserialize;
use serde_json::Value;

const PREFIX: &[u8] = b"original-gate-failure-before-control ";
const RECORD_BYTES: usize = 2048;
const CAPTURE_BYTES: usize = 4 * 1024 * 1024;

fn retained_stderr(error: &ProcessTestError) -> String {
    let ProcessTestError::Callback {
        stderr,
        capture_complete,
        ..
    } = error
    else {
        return "original callback stderr unavailable".into();
    };
    const EXCERPT_BYTES: usize = 4 * 1024;
    if stderr.len() <= EXCERPT_BYTES {
        format!(
            "original-stderr-bytes={}; capture-complete={capture_complete}; original-stderr={:?}",
            stderr.len(),
            String::from_utf8_lossy(stderr)
        )
    } else {
        let half = EXCERPT_BYTES / 2;
        format!(
            "original-stderr-bytes={}; capture-complete={capture_complete}; original-stderr-head={:?}; omitted-bytes={}; original-stderr-tail={:?}",
            stderr.len(),
            String::from_utf8_lossy(&stderr[..half]),
            stderr.len() - EXCERPT_BYTES,
            String::from_utf8_lossy(&stderr[stderr.len() - half..])
        )
    }
}

pub struct Expected<'a> {
    pub case: &'a Value,
    pub challenge_sha256: &'a str,
    pub gate_name_utf16_sha256: &'a str,
    pub fixture: Option<(u32, u128)>,
    pub guardian: Option<(u32, u128)>,
    pub guardian_query_failed: bool,
    pub pre_handoff_control: Option<&'a str>,
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
        ) => {
            if expected
                .fixture
                .is_some_and(|(pid, birth)| pid == 0 || birth == 0)
            {
                Err("original-held-fixture-identity-invalid")
            } else {
                original_code(stderr, expected)
            }
        }
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
        (ProcessTestError::Callback { .. }, None) => Err("original-case-binding-unavailable"),
        _ => return CiError::Process(error),
    };
    match projection {
        Ok(code) => {
            let expected =
                expected.expect("a bound projection requires original controller observations");
            let holder = match expected.fixture {
                Some((pid, birth)) => format!(
                    "controller-held-target=observed; controller-held-fixture-pid={pid}; controller-held-fixture-birth={birth}"
                ),
                None => "controller-held-target=unavailable".into(),
            };
            let association = if expected.guardian_query_failed {
                "unavailable-after-failed-query"
            } else {
                "unavailable"
            };
            let control = match expected.pre_handoff_control {
                Some(value) if value.len() <= RECORD_BYTES => value,
                Some(_) => "unavailable: control-summary-exceeds-bound",
                None => "unavailable",
            };
            CiError::LaneFailures {
                primary: Box::new(CiError::SettledCommandFailure(format!(
                    "original captured gate failure (diagnostic-only): operation=OpenEventW-controller-wait; desired-access=0x00100000; raw-os-error={code}; {holder}; target-association={association}; acceptance-authority=false; case={}; challenge-sha256={}; gate-name-utf16-sha256={}; pre-handoff-control={}",
                    expected.case,
                    expected.challenge_sha256, expected.gate_name_utf16_sha256,
                    control,
                ))),
                secondary: Box::new(CiError::Process(error).context(format!("original callback failure; guardian-query-failed={}; controller-held-guardian={:?}; query-association=unavailable", expected.guardian_query_failed, expected.guardian))),
            }
        }
        Err(reason) => {
            let stderr = retained_stderr(&error);
            // The raw excerpt is already bounded. Debug escaping can expand it by
            // six bytes per input byte; avoid clipping its middle a second time.
            CiError::Context {
                context: format!(
                    "original fixture callback failure; named-gate diagnostic unavailable: {reason}; {stderr}"
                ),
                source: Box::new(CiError::Process(error)),
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Control {
    format: String,
    revision: u32,
    diagnostic_only: bool,
    case: Value,
    challenge_sha256: String,
    gate_name_utf16_sha256: String,
    expected_token_envelope: memcordon_core::WindowsCallerTokenEnvelopeV1,
    child_pid: u32,
    child_exit_status: u32,
    child_settled: bool,
    same_retained_primary_token_input: bool,
    source_token_stable_identity_security_unchanged: bool,
    selected_token_stable_identity_security_unchanged: bool,
    same_original_event_identity_proved: bool,
    acceptance_authority: bool,
}

pub fn control_summary(
    controller: &[u8],
    child: &[u8],
    input: &crate::windows_consumer_readiness::descriptor::gate_precondition::Input,
    case: &Value,
    challenge: &str,
    name: &str,
) -> Result<String, String> {
    use crate::windows_consumer_readiness::descriptor::gate_precondition::{
        Observation, RECORD_BYTES,
    };
    if controller.len() > RECORD_BYTES {
        return Err("control-controller-record-exceeds-bound".into());
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(controller)?;
    let controller: Control =
        serde_json::from_slice(controller).map_err(|error| error.to_string())?;
    if controller.format != "memcordon.fixture-gate-precondition-controller"
        || controller.revision != 1
        || !controller.diagnostic_only
        || controller.case != *case
        || controller.challenge_sha256 != challenge
        || controller.gate_name_utf16_sha256 != name
        || controller.child_pid == 0
        || controller.child_exit_status != 0
        || !controller.child_settled
        || !controller.same_retained_primary_token_input
        || !controller.source_token_stable_identity_security_unchanged
        || !controller.selected_token_stable_identity_security_unchanged
        || controller.same_original_event_identity_proved
        || controller.acceptance_authority
    {
        return Err("control-controller-binding-or-settlement-differs".into());
    }
    let child = Observation::parse(child)?;
    child.validate(
        input,
        case,
        challenge,
        name,
        &controller.expected_token_envelope,
    )?;
    let envelope = serde_json::to_vec(&controller.expected_token_envelope)
        .map_err(|error| error.to_string())?;
    Ok(format!(
        "diagnostic-only independent-control-child={}; child-settled=true; same-retained-token-input=true; opened={}; native-error={:?}; session={}; controller-record-token-envelope-sha256={}; same-original-event-identity-proved=false; acceptance-authority=false",
        controller.child_pid,
        child.opened,
        child.native_error,
        child.token_envelope.session_id,
        crate::windows_consumer_readiness::descriptor::gate_precondition::sha256(&envelope)
    ))
}

#[derive(Debug)]
struct RetirementQuery {
    index: usize,
    original: std::io::Error,
}
impl std::fmt::Display for RetirementQuery {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            out,
            "original controller-held fixture retirement query failed; member-index={}; native-code={:?}; {}",
            self.index,
            self.original.raw_os_error(),
            self.original
        )
    }
}
impl std::error::Error for RetirementQuery {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}

/// Only the existing original handles supply these observations; never reopen a PID.
pub fn retired_family(
    observations: impl IntoIterator<Item = std::io::Result<bool>>,
) -> std::io::Result<()> {
    let mut seen = false;
    for (index, observation) in observations.into_iter().enumerate() {
        seen = true;
        let retired = observation.map_err(|original| {
            std::io::Error::new(original.kind(), RetirementQuery { index, original })
        })?;
        if !retired {
            return Err(std::io::Error::other(format!(
                "original controller-held fixture remains live; member-index={index}"
            )));
        }
    }
    if !seen {
        return Err(std::io::Error::other(
            "original controller-held fixture ownership unavailable: no fixture admitted; retirement=unobserved",
        ));
    }
    Ok(())
}
