//! One bounded initial holder observation; failure never authorizes readiness.
use crate::selected_policy::{Domain, VerifiedPolicy};
use memcordon_core::WindowsProcessIdentityV1;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_FRAME_BYTES: usize = 4096;
pub const FRAME_SCHEMA_VERSION: u32 = 2;

#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitQueryError {
    pub native_code: u32,
}

#[cfg(windows)]
impl std::fmt::Display for ExitQueryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "GetExitCodeProcess failed with Win32 {}",
            self.native_code
        )
    }
}

#[cfg(windows)]
impl std::error::Error for ExitQueryError {}

/// A successful query returns only the child status, never ambient last-error.
///
/// # Safety
/// A nonnull handle must reference the caller's retained process with query
/// access and remain open during this call. Null is supported as an API error.
#[cfg(windows)]
pub unsafe fn query_exit(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> Result<u32, ExitQueryError> {
    let mut status = 0;
    // SAFETY: caller retains the process handle; status is writable output.
    if unsafe { windows_sys::Win32::System::Threading::GetExitCodeProcess(handle, &mut status) }
        == 0
    {
        // SAFETY: capture this API failure immediately on its calling thread.
        let native_code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        Err(ExitQueryError { native_code })
    } else {
        Ok(status)
    }
}
const MAX_OPERATION: usize = 128;
const MAX_DETAIL: usize = 512;
const MAX_CLEANUP: usize = 256;
const MAX_CLEANUP_RECORDS: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub diagnostic_id: String,
    pub request_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadyPolicy {
    pub session_id: u32,
    pub desktop: String,
    pub station_sha256: String,
    pub desktop_sha256: String,
    pub station_policy: VerifiedPolicy,
    pub desktop_policy: VerifiedPolicy,
    pub gate: String,
    pub gate_sddl: String,
    pub gate_sha256: String,
    pub gate_policy: VerifiedPolicy,
    pub target_envelope_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage {
    InheritedHandles,
    Identity,
    Request,
    Deadlines,
    HolderToken,
    TargetToken,
    Privileges,
    StationSecurity,
    DesktopSecurity,
    WindowStation,
    Desktop,
    ObjectSecurity,
    Gate,
    GateSecurity,
    Readiness,
    Cleanup,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Outcome {
    Ready {
        policy: Box<ReadyPolicy>,
    },
    Failure {
        stage: Stage,
        operation: String,
        native_code: Option<u32>,
        detail: String,
        cleanup: Vec<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Frame {
    pub schema_version: u32,
    pub identity: WindowsProcessIdentityV1,
    pub observed_request: Option<Binding>,
    pub outcome: Outcome,
}

fn shorten(value: &str, maximum: usize) -> String {
    const MARKER: &str = "[truncated]";
    let mut encoded = 0;
    let mut retained_end = 0;
    let marker_budget = maximum - MARKER.len();
    for (index, character) in value.char_indices() {
        // Count actual JSON string encoding, excluding its two quote bytes.
        // Each scalar has finite serialization cost; never encode all input.
        let cost = serde_json::to_string(&character)
            .expect("Unicode scalar serializes")
            .len()
            - "\"\"".len();
        if encoded + cost > maximum {
            let mut result = value[..retained_end].to_owned();
            result.push_str(MARKER);
            return result;
        }
        encoded += cost;
        if encoded <= marker_budget {
            retained_end = index + character.len_utf8();
        }
    }
    value.to_owned()
}

impl Frame {
    pub fn failure(
        identity: WindowsProcessIdentityV1,
        observed_request: Option<Binding>,
        stage: Stage,
        operation: &str,
        native_code: Option<u32>,
        detail: &str,
        cleanup: &[String],
    ) -> Self {
        let mut retained = cleanup
            .iter()
            .take(MAX_CLEANUP_RECORDS)
            .map(|record| shorten(record, MAX_CLEANUP))
            .collect::<Vec<_>>();
        if cleanup.len() > MAX_CLEANUP_RECORDS {
            *retained
                .last_mut()
                .expect("positive cleanup retention limit") =
                "[additional cleanup records truncated]".into();
        }
        Self {
            schema_version: FRAME_SCHEMA_VERSION,
            identity,
            observed_request,
            outcome: Outcome::Failure {
                stage,
                operation: shorten(operation, MAX_OPERATION),
                native_code,
                detail: shorten(detail, MAX_DETAIL),
                cleanup: retained,
            },
        }
    }
}

fn digest(value: &str) -> bool {
    value.len() == Sha256::output_size() * 2 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn binding_valid(binding: &Binding) -> bool {
    digest(&binding.diagnostic_id) && digest(&binding.request_sha256)
}

fn text_valid(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.contains('\0')
}

fn validate(frame: &Frame) -> Result<(), String> {
    if frame.schema_version != FRAME_SCHEMA_VERSION
        || frame.identity.process_id == 0
        || frame.identity.creation_time_100ns == 0
        || frame
            .observed_request
            .as_ref()
            .is_some_and(|binding| !binding_valid(binding))
    {
        return Err("holder initial frame schema/identity/request differs".into());
    }
    let valid = match &frame.outcome {
        Outcome::Ready { policy } => {
            frame.observed_request.is_some()
                && text_valid(&policy.desktop, MAX_FRAME_BYTES)
                && text_valid(&policy.gate, MAX_FRAME_BYTES)
                && text_valid(&policy.gate_sddl, MAX_FRAME_BYTES)
                && policy
                    .station_policy
                    .validate_shape(Domain::Station)
                    .is_ok()
                && policy
                    .desktop_policy
                    .validate_shape(Domain::Desktop)
                    .is_ok()
                && policy.gate_policy.validate_shape(Domain::Gate).is_ok()
                && [
                    &policy.station_sha256,
                    &policy.desktop_sha256,
                    &policy.gate_sha256,
                    &policy.target_envelope_sha256,
                ]
                .into_iter()
                .all(|value| digest(value))
        }
        Outcome::Failure {
            operation,
            detail,
            cleanup,
            ..
        } => {
            text_valid(operation, MAX_OPERATION)
                && text_valid(detail, MAX_DETAIL)
                && cleanup.len() <= MAX_CLEANUP_RECORDS
                && cleanup.iter().all(|record| text_valid(record, MAX_CLEANUP))
        }
    };
    if !valid {
        return Err("holder initial frame outcome fields differ".into());
    }
    Ok(())
}

pub fn encode(frame: &Frame) -> Result<Vec<u8>, String> {
    validate(frame)?;
    let mut bytes = serde_json::to_vec(frame).map_err(|error| error.to_string())?;
    if bytes.len() >= MAX_FRAME_BYTES {
        return Err("holder initial frame exceeds byte bound".into());
    }
    bytes.push(b'\n');
    Ok(bytes)
}

/// A parsed diagnostic failure can never release a target, including at cutoff.
pub fn ready_policy(
    frame: &Frame,
    holder_ended: bool,
    work_expired: bool,
) -> Result<&ReadyPolicy, String> {
    validate(frame)?;
    match &frame.outcome {
        Outcome::Failure {
            stage,
            operation,
            native_code,
            detail,
            cleanup,
        } => Err(format!(
            "holder pre-readiness failure stage={stage:?} operation={operation} native_code={native_code:?}: {detail}; holder cleanup={cleanup:?}; observed_request={:?}",
            frame.observed_request
        )),
        Outcome::Ready { .. } if holder_ended => {
            Err("target-session holder exited after readiness; live objects unavailable".into())
        }
        Outcome::Ready { .. } if work_expired => {
            Err("original work cutoff expired before holder readiness release".into())
        }
        Outcome::Ready { policy } => Ok(policy),
    }
}

pub fn decode_initial(
    bytes: &[u8],
    expected_identity: &WindowsProcessIdentityV1,
    expected_binding: &Binding,
    ended: bool,
) -> Result<Option<Frame>, String> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err("holder initial frame exceeds byte bound".into());
    }
    let Some(end) = bytes.iter().position(|byte| *byte == b'\n') else {
        return if ended || bytes.len() == MAX_FRAME_BYTES {
            Err(if bytes.is_empty() {
                "holder initial frame absent"
            } else {
                "holder initial frame truncated"
            }
            .into())
        } else {
            Ok(None)
        };
    };
    if end + 1 != bytes.len() {
        return Err("holder initial frame has trailing data".into());
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes[..end])
        .map_err(|error| format!("holder initial frame malformed: {error}"))?;
    let frame: Frame = serde_json::from_slice(&bytes[..end])
        .map_err(|error| format!("holder initial frame malformed: {error}"))?;
    validate(&frame)?;
    if &frame.identity != expected_identity
        || !binding_valid(expected_binding)
        || frame
            .observed_request
            .as_ref()
            .is_some_and(|binding| binding != expected_binding)
    {
        return Err("holder initial frame differs from held identity/request".into());
    }
    Ok(Some(frame))
}
