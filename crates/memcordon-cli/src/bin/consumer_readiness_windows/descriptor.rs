//! Private owned workload inputs. These are never provider authorization.
pub use memcordon_platform::windows_private_fixture_binding::{
    DotLocalInput, PrivateFixtureAncestor, PrivateFixtureBinding, PrivateFixtureFile,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[path = "controller_start.rs"]
pub mod controller_start;
#[path = "controller_gate_access_input.rs"]
pub mod gate_access;
#[path = "gate_precondition_input.rs"]
pub mod gate_precondition;
#[path = "matched_control_record.rs"]
pub mod matched;
#[path = "matched_control_plan.rs"]
pub mod matched_plan;
#[path = "original_listener_observation.rs"]
pub mod original_listener_observation;
#[path = "stream_bytes.rs"]
mod stream_bytes;
#[path = "toolchain_command.rs"]
pub mod toolchain_command;
#[path = "winsock_registry_manifest.rs"]
pub mod winsock_registry;

pub const MAX_DESCRIPTOR_BYTES: usize = 64 * 1024;
pub const DESCRIPTOR_REVISION: u32 = 2;
pub const MAX_STREAM_BYTES: usize = stream_bytes::MAX_STREAM_BYTES;
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
    EmptyInput,
    BinaryStreams,
    BinaryFiles,
    NativeArgv,
    Churn,
    ApplicationExit,
    DeadlineDemand,
    HeldDemand,
    CapacityCompletion,
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

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "transport", rename_all = "kebab-case", deny_unknown_fields)]
pub enum StartTransport {
    #[default]
    NamedEvent,
    ControllerStdin {
        version: u32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlClock {
    pub revision: u32,
    pub work_cutoff_qpc: u64,
    pub qpc_frequency: u64,
}
impl ControlClock {
    pub fn validate(&self) -> Result<(), String> {
        if self.revision != 1 || self.work_cutoff_qpc == 0 || self.qpc_frequency == 0 {
            return Err("invalid original fixture control clock".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_control: Option<matched::Binding>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub provider_input_experiment: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provider_input_paths: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_input_binding: Option<PrivateFixtureBinding>,
    pub format: String,
    pub revision: u32,
    pub case: Case,
    pub output_root: PathBuf,
    pub transcript: PathBuf,
    pub challenge: Vec<u8>,
    #[serde(rename = "stdout_base64", with = "stream_bytes")]
    pub stdout: Vec<u8>,
    #[serde(rename = "stderr_base64", with = "stream_bytes")]
    pub stderr: Vec<u8>,
    pub arguments: Vec<String>,
    pub application_status: u32,
    pub churn_creations: u32,
    pub churn_live: u32,
    pub denied_write_paths: Vec<PathBuf>,
    pub sentinel_handles: Vec<Sentinel>,
    pub descendant_gate: Option<String>,
    pub start_gate: Option<String>,
    #[serde(default)]
    pub start_transport: StartTransport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_clock: Option<ControlClock>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub winsock_registry: Option<winsock_registry::Declaration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gate_access_diagnostic: Option<gate_access::Input>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gate_precondition: Option<gate_precondition::Input>,
    pub completion_gate: Option<String>,
    pub cohort_gate: Option<String>,
    pub generation_gate: Option<String>,
    pub toolchain: Option<Toolchain>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl Descriptor {
    fn registry_start_version(&self) -> u32 {
        if self.provider_input_experiment {
            if self
                .provider_input_binding
                .as_ref()
                .is_some_and(PrivateFixtureBinding::file_layout)
            {
                controller_start::PRIVATE_FILE_VERSION
            } else {
                controller_start::PRIVATE_VERSION
            }
        } else {
            controller_start::REGISTRY_VERSION
        }
    }
    /// Check exact candidate bytes and context. The caller must still authenticate
    /// this freshly computed digest against the original owned START frame before
    /// using any registry capability, fixture witness or mutation target. This
    /// parsed data grants no native authority by itself.
    pub fn parse_authenticated_peer(
        bytes: &[u8],
        expected_digest: [u8; 32],
        challenge: &[u8],
        output_root: &Path,
        clock: &ControlClock,
    ) -> Result<(Self, [u8; 32]), String> {
        if bytes.len() > MAX_DESCRIPTOR_BYTES {
            return Err("peer descriptor exceeds byte bound".into());
        }
        let actual_digest = controller_start::descriptor_digest(bytes);
        if actual_digest != expected_digest {
            return Err("peer original descriptor bytes differ".into());
        }
        let descriptor = Self::parse(bytes)?;
        if descriptor.challenge != challenge
            || descriptor.output_root != output_root
            || descriptor.control_clock.as_ref() != Some(clock)
            || descriptor.winsock_registry.is_none()
            || !matches!(
                descriptor.start_transport,
                StartTransport::ControllerStdin { version }
                    if version == descriptor.registry_start_version()
            )
        {
            return Err("peer original descriptor context differs".into());
        }
        Ok((descriptor, actual_digest))
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_DESCRIPTOR_BYTES {
            return Err("fixture descriptor exceeds byte bound".into());
        }
        // Deriving Deserialize directly for the struct rejects repeated fields,
        // unlike decoding through a JSON Value first.
        let value: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        value.validate()?;
        if matches!(
            value.start_transport,
            StartTransport::ControllerStdin { .. }
        ) && value.control_clock.is_none()
        {
            return Err("wire controller stdin START lacks original work clock".into());
        }
        if value.case == Case::Envelope
            && value.matched_control.is_none()
            && value.control_clock.is_none()
        {
            return Err("wire invocation readback lacks original work clock".into());
        }
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.case == Case::CapacityCompletion {
            let valid_gate = |name: &String| {
                name.starts_with("Local\\memcordon-readiness-")
                    && name.len() <= 200
                    && !name.contains('\0')
            };
            if self
                .cohort_gate
                .as_ref()
                .is_none_or(|name| !valid_gate(name))
                || self
                    .start_gate
                    .as_ref()
                    .is_none_or(|name| !valid_gate(name))
                || self.cohort_gate == self.start_gate
                || self.completion_gate.as_ref().is_some_and(|name| {
                    !valid_gate(name)
                        || Some(name) == self.cohort_gate.as_ref()
                        || Some(name) == self.start_gate.as_ref()
                })
                || self.generation_gate.is_some()
                || self.toolchain.is_some()
                || self.winsock_registry.is_some()
                || self.provider_input_experiment
                || self.matched_control.is_some()
                || self.descendant_gate.is_some()
                || !self.stdout.is_empty()
                || !self.stderr.is_empty()
                || self.application_status != 0
                || self.churn_creations != 0
                || self.churn_live != 0
                || !self.denied_write_paths.is_empty()
                || self.start_transport != StartTransport::NamedEvent
            {
                return Err(
                    "capacity completion requires distinct owned gates and an empty natural result"
                        .into(),
                );
            }
        }
        if let Some(binding) = &self.matched_control {
            let expected = match self.case {
                Case::BinaryFiles => matched::Scope::BinaryFiles,
                Case::Envelope => matched::Scope::Envelope,
                Case::Joint if binding.scope == matched::Scope::JointListenerPrefix => {
                    matched::Scope::JointListenerPrefix
                }
                Case::Joint if binding.scope == matched::Scope::ProviderListenerSelection => {
                    matched::Scope::ProviderListenerSelection
                }
                _ => return Err("matched measurement scope and fixture case differ".into()),
            };
            if binding.scope != expected
                || self.provider_input_experiment
                    != (expected == matched::Scope::ProviderListenerSelection)
                || self.winsock_registry.is_some()
                    != matches!(
                        expected,
                        matched::Scope::JointListenerPrefix
                            | matched::Scope::ProviderListenerSelection
                    )
                || self.toolchain.is_some()
                || !matches!(
                    self.start_transport,
                    StartTransport::ControllerStdin {
                        version
                    } if version == if expected == matched::Scope::ProviderListenerSelection { self.registry_start_version() } else if expected == matched::Scope::JointListenerPrefix { controller_start::REGISTRY_VERSION } else { controller_start::VERSION }
                )
                || self.control_clock.is_none()
                || !(self.denied_write_paths.is_empty()
                    || (expected == matched::Scope::Envelope && self.denied_write_paths.len() == 2))
            {
                return Err("matched measurement descriptor scope/input/START differs".into());
            }
        }
        memcordon_platform::windows_private_fixture_binding::validate_declaration(
            self.provider_input_experiment,
            &self.provider_input_paths,
            self.provider_input_binding.as_ref(),
        )?;
        if let Some(binding) = &self.provider_input_binding {
            binding.validate_output(&self.output_root)?;
        }
        if self.provider_input_experiment
            && (self.winsock_registry.is_none()
                || !matches!(
                    self.start_transport,
                    StartTransport::ControllerStdin {
                        version
                    } if version==self.registry_start_version()
                ))
        {
            return Err(
                "private fixture transfer requires authenticated registry and directory START"
                    .into(),
            );
        }
        if !self.provider_input_experiment && !self.provider_input_paths.is_empty() {
            return Err("provider input paths require explicit experiment".into());
        }
        if self.provider_input_experiment
            && (self.case != Case::Joint
                || !(if self
                    .provider_input_binding
                    .as_ref()
                    .is_some_and(PrivateFixtureBinding::file_layout)
                {
                    3..=10
                } else {
                    2..=9
                })
                .contains(&self.provider_input_paths.len()))
        {
            return Err(if self.provider_input_binding.as_ref().is_some_and(PrivateFixtureBinding::file_layout) {
                "provider input file experiment requires Joint and three to ten declared private inputs"
            } else {
                "provider input experiment requires Joint and two to nine declared private inputs"
            }.into());
        }
        if self.format != "memcordon.fixture-workload" || self.revision != DESCRIPTOR_REVISION {
            return Err("unsupported fixture workload format/revision".into());
        }
        if let StartTransport::ControllerStdin { version } = self.start_transport {
            let declared = self.winsock_registry.is_some();
            if version
                != if self.provider_input_experiment {
                    self.registry_start_version()
                } else if declared {
                    controller_start::REGISTRY_VERSION
                } else {
                    controller_start::VERSION
                }
                || !(if declared {
                    matches!(
                        self.case,
                        Case::Joint | Case::EndpointMismatch | Case::Churn
                    )
                } else {
                    matches!(self.case, Case::Envelope | Case::Joint)
                        || (self.case == Case::BinaryFiles
                            && self.matched_control.as_ref().is_some_and(|binding| {
                                binding.scope == matched::Scope::BinaryFiles
                            }))
                })
                || self.start_gate.is_none()
            {
                return Err("controller stdin requires supported versioned Envelope/Joint control and separate diagnostic name".into());
            }
            if let Some(input) = &self.control_clock {
                input.validate()?;
            }
        } else if let Some(clock) = &self.control_clock {
            if self.case != Case::Envelope || self.matched_control.is_some() {
                return Err(
                    "named-event START clock requires an unpaired Envelope readback".into(),
                );
            }
            clock.validate()?;
        }
        if let Some(registry) = &self.winsock_registry {
            registry.validate()?;
            if !matches!(
                self.start_transport,
                StartTransport::ControllerStdin { version }
                    if version == self.registry_start_version()
            ) {
                return Err(
                    "Winsock registry dependency requires its exact versioned owned stdin".into(),
                );
            }
        }
        if let Some(control) = &self.gate_precondition {
            control.validate()?;
            if self.case != Case::Envelope || self.start_gate.is_none() {
                return Err("gate precondition control requires an original envelope gate".into());
            }
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
            || self.stdout.len() > MAX_STREAM_BYTES
            || self.stderr.len() > MAX_STREAM_BYTES
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
            && !self.matched_control.as_ref().is_some_and(|binding| {
                matches!(
                    binding.scope,
                    matched::Scope::JointListenerPrefix | matched::Scope::ProviderListenerSelection
                )
            })
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
