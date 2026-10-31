//! Bounded observations of failed diagnostic publication, never authority.
use serde::Serialize;
use sha2::Digest;
use std::{error::Error, fmt, io};

pub const DISPLAY_BOUND: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage {
    RetainParentOpen,
    RetainParentIdentity,
    Sequence,
    Encode,
    ParentIdentity,
    ParentOpen,
    NamedParentIdentity,
    ParentVerification,
    PendingCreate,
    PendingWrite,
    PendingFlush,
    PendingRewind,
    PendingReadback,
    PendingReadbackVerification,
    Replace,
    PendingIdentity,
    FinalOpen,
    FinalIdentity,
    FinalVerification,
    FinalLength,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FileObservation {
    pub volume: u32,
    pub index: u64,
    pub attributes: u32,
    pub links: u32,
    pub length: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ObservationError {
    pub kind: String,
    pub native_code: Option<i32>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Context {
    phase: Option<String>,
    phase_bytes: usize,
    phase_sha256: String,
    record_debug: Option<bool>,
    sequence: u64,
    binding: serde_json::Value,
    pub parent: Option<FileObservation>,
    pub stage_file: Option<FileObservation>,
    pub stage_observation_error: Option<ObservationError>,
    pub readback_verified: bool,
    pub same_parent_paths: bool,
    pub parent_path_sha256: Option<String>,
}

fn digest(bytes: &[u8]) -> String {
    String::from(memcordon_core::DiagnosticSha256::from_bytes(
        sha2::Sha256::digest(bytes).into(),
    ))
}

fn identity(value: &serde_json::Value) -> Option<memcordon_core::WindowsProcessIdentityV1> {
    let identity = memcordon_core::WindowsProcessIdentityV1 {
        process_id: value.get("process_id")?.as_u64()?.try_into().ok()?,
        creation_time_100ns: value.get("creation_time_100ns")?.as_u64()?,
    };
    (identity.process_id != 0 && identity.creation_time_100ns != 0).then_some(identity)
}

impl Context {
    pub fn new(
        phase: &str,
        debug: Option<bool>,
        sequence: u64,
        binding: &serde_json::Value,
    ) -> Self {
        let image = binding
            .get("selected_image_sha256")
            .and_then(serde_json::Value::as_str)
            .filter(|value| {
                value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
            });
        let challenge: Option<Vec<u8>> = binding
            .get("challenge")
            .and_then(serde_json::Value::as_array)
            .filter(|values| values.len() <= 4096)
            .and_then(|values| {
                values
                    .iter()
                    .map(|value| value.as_u64()?.try_into().ok())
                    .collect()
            });
        Self {
            phase: (phase.len() <= 256).then(|| phase.to_owned()),
            phase_bytes: phase.len(),
            phase_sha256: digest(phase.as_bytes()),
            record_debug: debug,
            sequence,
            binding: serde_json::json!({"original_compiler":identity(&binding["original_child"]),
                "original_parent":identity(&binding["parent"]),"selected_image_sha256":image,
                "challenge_sha256":challenge.as_deref().map(digest)}),
            parent: None,
            stage_file: None,
            stage_observation_error: None,
            readback_verified: false,
            same_parent_paths: false,
            parent_path_sha256: None,
        }
    }

    pub fn encode(&self, stage: Stage) -> io::Result<Vec<u8>> {
        let options = match stage {
            Stage::RetainParentOpen | Stage::ParentOpen => Some(
                serde_json::json!({"read":true,"write":false,"share_flags":3,"no_follow":true,"directory":true}),
            ),
            Stage::PendingCreate => Some(
                serde_json::json!({"read":true,"write":true,"create_new":true,"share_flags":5,"no_follow":true}),
            ),
            Stage::FinalOpen => Some(
                serde_json::json!({"read":true,"write":false,"share_flags":7,"no_follow":true}),
            ),
            _ => None,
        };
        let bytes = serde_json::to_vec(&serde_json::json!({"diagnostic_only":true,"operation":stage,"context":self,
            "configured_open_options":options,"rename_flags":if stage == Stage::Replace {Some(9u32)}else{None},
            "same_parent_paths":self.same_parent_paths,"destination_identity_security_sharing":"unavailable","acceptance_authority":false}))
            .map_err(io::Error::other)?;
        if bytes.len() > DISPLAY_BOUND {
            return Err(io::Error::other("publication error context exceeds bound"));
        }
        Ok(bytes)
    }

    pub fn failure(&self, stage: Stage, original: io::Error) -> io::Error {
        io::Error::new(
            original.kind(),
            Failure {
                context: self.clone(),
                stage,
                original,
            },
        )
    }
}

pub struct Failure {
    context: Context,
    stage: Stage,
    original: io::Error,
}
impl Failure {
    pub fn context(&self) -> &Context {
        &self.context
    }
    pub fn stage(&self) -> Stage {
        self.stage
    }
}
impl fmt::Display for Failure {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            out,
            "{}; toolchain-diagnostic-publication={}; original-raw-os-error={:?}; publication-operation-context=",
            self.original,
            self.context()
                .phase
                .as_deref()
                .unwrap_or("bounded-phase-hash"),
            self.original.raw_os_error()
        )?;
        match self.context().encode(self.stage()) {
            Ok(bytes) => out.write_str(std::str::from_utf8(&bytes).map_err(|_| fmt::Error)?),
            Err(_) => out.write_str("{\"available\":false,\"reason\":\"context-encoding-failed\"}"),
        }
    }
}
impl fmt::Debug for Failure {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, out)
    }
}
impl Error for Failure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.original)
    }
}
