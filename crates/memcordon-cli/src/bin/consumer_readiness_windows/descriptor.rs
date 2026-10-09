//! Private owned workload inputs. These are never provider authorization.
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const MAX_DESCRIPTOR_BYTES: usize = 64 * 1024;
pub const CHURN_CREATIONS: u32 = 4096;
// One TCP peer remains live alongside the cohort, so 63 leaves preserve the
// profile's maximum of 64 simultaneous workload descendants.
pub const CHURN_LIVE: u32 = 63;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Case {
    Joint,
    EndpointMismatch,
    Toolchain,
    EmptyStreams,
    BinaryStreams,
    BinaryFiles,
    NativeArgv,
    Churn,
    ApplicationExit,
    DeadlineDemand,
    HeldDemand,
    MemoryDemand,
    RootFirst,
    IntermediateFirst,
    NestedJob,
    BreakawayDenied,
    AllowedTokenChange,
    Envelope,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Toolchain {
    pub rustc: PathBuf,
    pub native_linker: PathBuf,
    pub native_library_directories: Vec<PathBuf>,
    pub library_source: PathBuf,
    pub test_source: PathBuf,
    pub child_source: PathBuf,
    pub dll_source: PathBuf,
    pub loader_source: PathBuf,
    pub target: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Sentinel {
    pub handle: usize,
    pub volume_serial_number: u32,
    pub file_index: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub format: String,
    pub revision: u32,
    pub case: Case,
    pub output_root: PathBuf,
    pub transcript: PathBuf,
    pub challenge: Vec<u8>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub arguments: Vec<String>,
    pub application_status: u32,
    pub churn_creations: u32,
    pub churn_live: u32,
    pub denied_write_paths: Vec<PathBuf>,
    pub sentinel_handles: Vec<Sentinel>,
    pub descendant_gate: Option<String>,
    pub start_gate: Option<String>,
    pub completion_gate: Option<String>,
    pub cohort_gate: Option<String>,
    pub generation_gate: Option<String>,
    pub toolchain: Option<Toolchain>,
}

impl Descriptor {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_DESCRIPTOR_BYTES {
            return Err("fixture descriptor exceeds byte bound".into());
        }
        // Deriving Deserialize directly for the struct rejects repeated fields,
        // unlike decoding through a JSON Value first.
        let value: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.format != "memcordon.fixture-workload" || self.revision != 1 {
            return Err("unsupported fixture workload format/revision".into());
        }
        if !self.output_root.is_absolute()
            || !self.transcript.is_absolute()
            || !self.transcript.starts_with(&self.output_root)
            || self
                .output_root
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
            || self
                .transcript
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err("fixture outputs must be bounded beneath an absolute granted root".into());
        }
        if self.challenge.is_empty()
            || self.challenge.len() > 4096
            || self.stdout.len() > 16 * 1024
            || self.stderr.len() > 16 * 1024
            || self.arguments.len() > 64
            || self.denied_write_paths.len() > 16
            || self.sentinel_handles.len() > 16
            || self
                .arguments
                .iter()
                .any(|a| a.contains('\0') || a.len() > 4096)
            || self.application_status > 255
        {
            return Err("fixture workload parameter exceeds its bound".into());
        }
        if self.case == Case::Churn
            && (self.churn_creations < CHURN_CREATIONS
                || self.churn_creations > 65536
                || self.churn_live == 0
                || self.churn_live > CHURN_LIVE)
        {
            return Err("churn requires 4096 cumulative creations and bounded live cohorts".into());
        }
        if self.case == Case::Churn
            && (self.cohort_gate.is_none() || self.generation_gate.is_none())
        {
            return Err(
                "successful churn requires independent native cohort/generation barriers".into(),
            );
        }
        if matches!(self.case, Case::Toolchain | Case::Joint | Case::Churn)
            && self.toolchain.is_none()
        {
            return Err("toolchain case requires explicitly bound compiler/source inputs".into());
        }
        if matches!(self.case, Case::RootFirst | Case::IntermediateFirst)
            && self.descendant_gate.as_ref().is_none_or(|name| {
                !name.starts_with("Local\\memcordon-readiness-")
                    || name.len() > 200
                    || name.encode_utf16().any(|c| c == 0)
            })
        {
            return Err("descendant case requires a unique native controller event".into());
        }
        match &self.toolchain {
            Some(t)
                if ![
                    &t.rustc,
                    &t.native_linker,
                    &t.library_source,
                    &t.test_source,
                    &t.child_source,
                    &t.dll_source,
                    &t.loader_source,
                ]
                .iter()
                .all(|p| p.is_absolute())
                    || t.native_library_directories.len() != 3
                    || t.native_library_directories
                        .iter()
                        .any(|path| !path.is_absolute())
                    || !matches!(
                        t.target.as_str(),
                        "x86_64-pc-windows-msvc" | "aarch64-pc-windows-msvc"
                    ) =>
            {
                return Err("invalid Windows toolchain paths/target".into());
            }
            _ => {}
        }
        Ok(())
    }
}
