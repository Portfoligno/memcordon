//! Pure retention of an already-read original event descriptor; not security authority.
use super::protocol;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fmt::Write, io};

pub const NATIVE_BOUND: usize = 64 * 1024;
pub const RECORD_BOUND: usize = 2 * NATIVE_BOUND + 2 * protocol::FRAME_BOUND;
pub const CHUNK_HEX_CHARS: usize = 4096;
#[derive(Debug, PartialEq, Eq)]
pub struct Snapshot {
    bytes: Vec<u8>,
    native_length: u32,
    sha256: String,
    information: u32,
}
fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "original event security evidence refused",
    )
}
fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut text, "{byte:02x}").expect("String writes are infallible");
    }
    text
}
impl Snapshot {
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    pub fn new(bytes: Vec<u8>, native_length: u32) -> io::Result<Self> {
        Self::capture(bytes, native_length, 7)
    }
    pub fn label(bytes: Vec<u8>, native_length: u32) -> io::Result<Self> {
        Self::capture(bytes, native_length, 16)
    }
    fn capture(bytes: Vec<u8>, native_length: u32, information: u32) -> io::Result<Self> {
        if bytes.is_empty()
            || bytes.len() > NATIVE_BOUND
            || usize::try_from(native_length).ok() != Some(bytes.len())
        {
            return Err(refused());
        }
        let sha256 = hex(&Sha256::digest(&bytes));
        Ok(Self {
            bytes,
            native_length,
            sha256,
            information,
        })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn native_length(&self) -> u32 {
        self.native_length
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LabelStage {
    BeforeSize,
    Size,
    SizeBound,
    BeforeRead,
    Read,
    Extent,
    AfterRead,
    Projection,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum LabelUnavailable {
    Deadline {
        stage: LabelStage,
    },
    Native {
        stage: LabelStage,
        raw_error: Option<i32>,
    },
    Bound {
        stage: LabelStage,
    },
}
#[derive(Debug, PartialEq, Eq)]
pub enum LabelObservation {
    Present(Snapshot),
    Unavailable(LabelUnavailable),
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReadbackObservation {
    NotRequested,
    Present(Snapshot),
    Unavailable {
        raw_error: Option<i32>,
        deadline: bool,
    },
}

#[derive(Debug, serde::Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum AuthzObservation {
    Unavailable {
        stage: &'static str,
        reason: memcordon_core::BoundedText<512>,
        raw_error: Option<i32>,
        deadline: bool,
    },
    Evaluated {
        engine: &'static str,
        scope: &'static str,
        diagnostic_only: bool,
        acceptance_authority: bool,
        sampling: &'static str,
        descriptor_sha256: String,
        desired_access: u32,
        source_token_id: u64,
        source_modified_id: u64,
        context_matches: bool,
        user_matches: bool,
        groups_match: bool,
        restricted_match: bool,
        privileges_match: bool,
        source_unchanged: bool,
        api_success: bool,
        native_error: Option<i32>,
        reply_error: Option<u32>,
        granted: Option<u32>,
        conclusion: &'static str,
    },
}
impl AuthzObservation {
    pub fn unavailable(stage: &'static str, error: &io::Error) -> Self {
        Self::Unavailable {
            stage,
            reason: memcordon_core::BoundedText::new(&error.to_string()).unwrap_or_else(|_| {
                memcordon_core::BoundedText::new("diagnostic reason exceeds bound")
                    .expect("fixed reason fits")
            }),
            raw_error: error.raw_os_error(),
            deadline: error.kind() == io::ErrorKind::TimedOut,
        }
    }
    pub fn conclusion(correlated: bool, api: bool, error: u32, granted: u32) -> &'static str {
        if !correlated {
            "uncorrelated"
        } else if !api {
            "api-failure"
        } else if error == 0 && granted == 0x0010_0000 {
            "supplied-data-allow"
        } else if error == 5 && granted == 0 {
            "supplied-data-denial"
        } else {
            "inconsistent"
        }
    }
}

fn readback_value(readback: &ReadbackObservation, original: &Snapshot) -> io::Result<Value> {
    Ok(match readback {
        ReadbackObservation::NotRequested => {
            json!({"state":"not-requested","reason":"no-original-event-open-failure"})
        }
        ReadbackObservation::Present(snapshot) => {
            if snapshot.information != 7 {
                return Err(refused());
            }
            json!({"state":"present","phase":"post-failure","source":"same-retained-controller-event-handle",
                "sampling":"sequential-non-atomic","security_information":snapshot.information,
                "native_length":snapshot.native_length,"sha256":snapshot.sha256,
                "bytes_equal_prelaunch":snapshot.bytes == original.bytes,
                "hash_equal_prelaunch":snapshot.sha256 == original.sha256,
                "native_bytes_retained":false})
        }
        ReadbackObservation::Unavailable {
            raw_error,
            deadline,
        } => json!({"state":"unavailable","raw_error":raw_error,"deadline":deadline}),
    })
}

fn snapshot_value(snapshot: &Snapshot) -> Value {
    json!({"phase":"prelaunch","security_information":snapshot.information,
        "native_length":snapshot.native_length(),"sha256":snapshot.sha256,
        "chunk_hex_chars":CHUNK_HEX_CHARS,
        "native_bytes_hex_chunks":snapshot.bytes().chunks(CHUNK_HEX_CHARS / 2).map(hex).collect::<Vec<_>>()})
}

pub struct Association<'a> {
    pub request: &'a protocol::Request,
    pub response: &'a protocol::Response,
    pub original_name: &'a [u16],
    pub controller_handle: u64,
    pub child_pid: u32,
    pub child_birth: u64,
    pub parent_prelaunch_token: &'a Result<
        memcordon_windows_launch_core::TokenObservationV1,
        memcordon_windows_launch_core::ObservationUnavailable,
    >,
    pub parent_default_acl_bytes: &'a Option<Vec<u8>>,
    pub label: &'a LabelObservation,
    pub post_failure: &'a ReadbackObservation,
}
pub fn failure(association: &Association<'_>, snapshot: &Snapshot) -> io::Result<Value> {
    protocol::encode_request(association.request)?;
    let encoded_response = protocol::encode_response(association.response)?;
    if protocol::decode_response(&encoded_response)? != *association.response {
        return Err(refused());
    }
    association
        .response
        .diagnostics
        .validate_correspondence(association.request)?;
    if association.request.nonce != association.response.nonce
        || association.response.success
        || association.controller_handle == 0
        || association.child_pid == 0
        || association.child_birth == 0
        || snapshot.information != 7
    {
        return Err(refused());
    }
    let expected: Vec<u16> = if association.request.cell == protocol::Cell::Local {
        "Local\\"
            .encode_utf16()
            .chain(association.request.event.encode_utf16())
            .collect()
    } else {
        association
            .request
            .alias
            .encode_utf16()
            .chain(Some(u16::from(b'\\')))
            .chain(association.request.event.encode_utf16())
            .collect()
    };
    if association.original_name != expected {
        return Err(refused());
    }
    let parent = match association.parent_prelaunch_token {
        Ok(value) => {
            value.validate().map_err(|_| refused())?;
            if value.envelope != association.request.expected_token {
                return Err(refused());
            }
            json!({"state":"present","observation":value})
        }
        Err(reason) => json!({"state":"unavailable","reason":reason}),
    };
    if association
        .parent_default_acl_bytes
        .as_ref()
        .is_some_and(|bytes| bytes.len() > NATIVE_BOUND)
    {
        return Err(refused());
    }
    let default_encoded =
        serde_json::to_vec(association.parent_default_acl_bytes).map_err(|_| refused())?;
    if hex(&Sha256::digest(default_encoded)) != association.request.expected_default_acl_sha256 {
        return Err(refused());
    }
    let label = match association.label {
        LabelObservation::Present(value) => {
            if value.information != 16 {
                return Err(refused());
            }
            json!({"state":"present","snapshot":snapshot_value(value)})
        }
        LabelObservation::Unavailable(reason) => {
            json!({"state":"unavailable","requested_information":16,"reason":reason})
        }
    };
    if !matches!(association.post_failure, ReadbackObservation::NotRequested)
        && association.response.phase != protocol::Phase::Event
    {
        return Err(refused());
    }
    let post_failure = readback_value(association.post_failure, snapshot)?;
    // Keep the exact original native core separate from independently bounded
    // optional observations. These are not a normalized replacement wire frame.
    let mut core = serde_json::to_value(association.response).map_err(|_| refused())?;
    core.as_object_mut()
        .ok_or_else(refused)?
        .remove("diagnostics");
    let mut value = json!({
        "format":"memcordon.namespace-primary-event-security-failure","revision":2,
        "diagnostic_only":true,"acceptance_authority":false,
        "cell":association.request.cell,"nonce":association.request.nonce,
        "original_child":{"pid":association.child_pid,"birth":association.child_birth},
        "original_controller_event":{"handle":association.controller_handle,"handle_scope":"controller-process-local-observation-only"},
        "requested_open":{"name_utf16":association.original_name,"desired_access":0x0010_0000u32,"inherit_handle":false},
        "original_response":core,
        "original_response_scope":"original native core; optional wire diagnostics retained separately",
        "worker_diagnostics":{"sampling":"sequential-non-atomic","observation":association.response.diagnostics},
        "parent_prelaunch_token":{"role":"derived-token-prelaunch","sampling":"sequential-non-atomic","observation":parent,
            "default_acl_sha256":association.request.expected_default_acl_sha256,
            "default_acl_bytes":association.parent_default_acl_bytes},
        "security_snapshot":snapshot_value(snapshot),
        "label_snapshot":label,
        "post_failure_security_readback":post_failure,
        "post_failure_security_readback_observed":matches!(association.post_failure, ReadbackObservation::Present(_)),
        "cross_process_event_identity_observed":false,
        "cleanup_observed":false,
        "interpretation":"original retained controller event snapshots; no named-open access verdict or completed cross-process identity/cleanup proof"
    });
    // Optional observations are all-or-unavailable; never truncate the existing
    // authoritative original descriptor or change a native result to fit.
    if matches!(association.label, LabelObservation::Present(_))
        && serde_json::to_vec_pretty(&value)
            .map_err(|_| refused())?
            .len()
            > RECORD_BOUND
    {
        value["label_snapshot"] = json!({"state":"unavailable","requested_information":16,"reason":"combined-record-bound"});
    }
    if serde_json::to_vec_pretty(&value)
        .map_err(|_| refused())?
        .len()
        > RECORD_BOUND
    {
        value["parent_prelaunch_token"] = json!({"state":"unavailable","role":"derived-token-prelaunch","reason":"combined-record-bound"});
        value["worker_diagnostics"] = json!({"state":"unavailable-in-parent-record","reason":"combined-record-bound","original_wire_diagnostics_retained":false});
    }
    if serde_json::to_vec_pretty(&value)
        .map_err(|_| refused())?
        .len()
        > RECORD_BOUND
    {
        return Err(refused());
    }
    Ok(value)
}
