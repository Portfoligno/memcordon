//! Private owned workload inputs. These are never provider authorization.
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[path = "controller_gate_access_input.rs"]
pub mod gate_access;
#[path = "toolchain_command.rs"]
pub mod toolchain_command;

pub const MAX_DESCRIPTOR_BYTES: usize = 64 * 1024;
pub const CHURN_CREATIONS: u32 = 4096;
// One TCP peer remains live alongside the cohort, so 63 leaves preserve the
// profile's maximum of 64 simultaneous workload descendants.
pub const CHURN_LIVE: u32 = 63;
pub const MAX_TOOLCHAIN_IMAGES: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolchainImage {
    pub path: PathBuf,
    pub sha256: String,
}

/// Freeze only executable members of the already measured owned-input catalog.
/// Both the descriptor producer and native controller use this projection.
pub fn project_toolchain_images(
    measured: impl IntoIterator<Item = (PathBuf, String)>,
) -> Result<Vec<ToolchainImage>, String> {
    let mut images = std::collections::BTreeMap::new();
    for (path, sha256) in measured {
        if !path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
        {
            continue;
        }
        if !path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
            || path
                .as_os_str()
                .to_str()
                .is_none_or(|text| text.contains('\0'))
        {
            return Err("selected compiler image path is not an absolute ordinary path".into());
        }
        memcordon_core::BoundedText::<64>::new(&sha256)
            .and_then(memcordon_core::DiagnosticSha256::try_from)
            .map_err(str::to_owned)?;
        if images.len() >= MAX_TOOLCHAIN_IMAGES
            || images
                .insert(path.clone(), ToolchainImage { path, sha256 })
                .is_some()
        {
            return Err(
                "selected compiler image inventory repeats a path or exceeds its bound".into(),
            );
        }
    }
    if images.is_empty() {
        return Err("selected compiler image inventory is empty".into());
    }
    Ok(images.into_values().collect())
}

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
    pub native_work_cutoff_ticks: u64,
    pub native_work_frequency: u64,
    pub linker_mode: LinkerMode,
    pub input_root: PathBuf,
    pub rustc: PathBuf,
    pub native_linker: PathBuf,
    pub selected_images: Vec<ToolchainImage>,
    pub native_library_directories: Vec<PathBuf>,
    pub library_source: PathBuf,
    pub test_source: PathBuf,
    pub child_source: PathBuf,
    pub dll_source: PathBuf,
    pub loader_source: PathBuf,
    pub target: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum LinkerMode {
    BundledLldLink,
}

impl Toolchain {
    pub fn validate_selected_images(&self) -> Result<(), String> {
        toolchain_command::linker_argument(self)?;
        let projected = project_toolchain_images(
            self.selected_images
                .iter()
                .map(|image| (image.path.clone(), image.sha256.clone())),
        )?;
        if projected != self.selected_images
            || [&self.rustc, &self.native_linker]
                .iter()
                .any(|path| !projected.iter().any(|image| &image.path == *path))
        {
            return Err("selected compiler image inventory is not canonical or omits the original compiler/linker".into());
        }
        Ok(())
    }

    pub fn admits_created_image(&self, path: &Path, sha256: &str) -> bool {
        self.selected_images
            .binary_search_by(|image| image.path.as_path().cmp(path))
            .is_ok_and(|index| self.selected_images[index].sha256 == sha256)
    }
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gate_access_diagnostic: Option<gate_access::Input>,
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
        if let Some(diagnostic) = &self.gate_access_diagnostic {
            let name = self
                .start_gate
                .as_ref()
                .ok_or("gate access diagnostic lacks original gate name")?;
            diagnostic
                .validate(&name.encode_utf16().collect::<Vec<_>>(), &self.challenge)
                .map_err(|error| error.to_string())?;
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
                    || t.native_work_cutoff_ticks == 0
                    || t.native_work_frequency == 0
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
        if let Some(toolchain) = &self.toolchain {
            toolchain.validate_selected_images()?;
        }
        if serde_json::to_vec(self)
            .map_err(|error| error.to_string())?
            .len()
            > MAX_DESCRIPTOR_BYTES
        {
            return Err("fixture descriptor exceeds byte bound".into());
        }
        Ok(())
    }
}
