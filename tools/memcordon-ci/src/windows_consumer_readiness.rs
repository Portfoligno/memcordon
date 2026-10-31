//! Positive Windows workload assessment. Diagnostics cannot satisfy these cases.
use crate::{CiError, Result};
use memcordon_core::ChildTermination;
use memcordon_core::execution_facts::{CleanupStateV1, OutcomeKindV1};
use memcordon_core::result_v3::{ReleaseKnowledgeV3, ResultV3, RuntimeExecutionV3};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[path = "../../../crates/memcordon-cli/src/bin/consumer_readiness_windows/descriptor.rs"]
pub mod descriptor;
#[path = "windows_gate_label.rs"]
#[cfg(windows)]
mod gate_label;
#[cfg(windows)]
#[path = "windows_gate_namespace.rs"]
mod gate_namespace;
#[cfg(windows)]
#[path = "../../../crates/memcordon-cli/src/bin/consumer_readiness_windows/controller_gate_resolution.rs"]
mod gate_resolution;
#[cfg(windows)]
#[path = "windows_gate_security.rs"]
mod gate_security;
#[cfg(windows)]
#[path = "windows_guardian_query.rs"]
mod guardian_query;
#[cfg(windows)]
#[path = "windows_start_gate_policy.rs"]
mod start_gate_policy;
#[cfg(windows)]
#[path = "windows_toolchain_sampling.rs"]
mod toolchain_sampling;

pub fn validate_toolchain_inventory(
    toolchain: &descriptor::Toolchain,
    measured: &[descriptor::ToolchainImage],
) -> Result<()> {
    toolchain
        .validate_selected_images()
        .map_err(CiError::Message)?;
    if toolchain.selected_images != measured {
        return Err(CiError::Message(
            "native compiler descriptor differs from measured executable inventory".into(),
        ));
    }
    Ok(())
}

#[path = "windows_loader_event_diagnostics.rs"]
pub mod loader_event_diagnostics;

#[cfg(windows)]
#[path = "windows_workload_diagnostic.rs"]
mod workload_diagnostic;

#[cfg(windows)]
#[path = "../../../crates/memcordon-cli/src/bin/consumer_readiness_windows/fixture_environment.rs"]
pub(crate) mod fixture_environment;

/// PID ancestry is meaningful only for processes that can belong to this
/// original root lifetime. A preexisting process cannot become its descendant
/// when an intermediate parent PID is reused in a later snapshot.
pub fn rooted_process_depth(
    candidate: (u32, u128),
    root: (u32, u128),
    parents: &std::collections::BTreeMap<u32, u32>,
) -> Option<usize> {
    if candidate.1 < root.1 || (candidate.0 == root.0 && candidate.1 != root.1) {
        return None;
    }
    let mut current = candidate.0;
    for depth in 0..=16 {
        if current == root.0 {
            return Some(depth);
        }
        current = *parents.get(&current)?;
    }
    None
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseKey {
    pub family: String,
    pub scenario: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseInput {
    pub key: CaseKey,
    pub descriptor: descriptor::Descriptor,
    pub descriptor_path: PathBuf,
    pub workload_request: PathBuf,
    pub expected_token: TokenObservation,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenObservation {
    pub user_sid: Vec<u8>,
    pub restricted: bool,
    pub integrity_rid: u32,
    pub elevated: bool,
    pub restricting_sids: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuiteInput {
    pub format: String,
    pub revision: u32,
    pub cases: Vec<CaseInput>,
}

/// Explicit provisioning inputs, independent of consumer source or ambient
/// installation. The source/image and toolchain paths are measured by the owner.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsReadinessPlan {
    pub request_template: PathBuf,
    pub toolchain: descriptor::Toolchain,
    pub candidate_output_root: PathBuf,
    pub protected_write_probes: Vec<PathBuf>,
}

#[cfg(windows)]
pub fn prepare_installed(
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
    plan: &WindowsReadinessPlan,
    input: &Path,
) -> Result<()> {
    native::prepare(
        config,
        plan,
        input,
        crate::windows_installed_cases::WindowsLeaseDeadlines::finite_default().work,
    )
}

#[cfg(not(windows))]
pub fn prepare_installed(
    _: &crate::windows_installed_cases::InstalledWindowsPayload,
    _: &WindowsReadinessPlan,
    _: &Path,
) -> Result<()> {
    Err(CiError::Message(
        "Windows readiness provisioning requires a native Windows host".into(),
    ))
}

#[cfg(windows)]
pub fn provision_from_source(
    root: &Path,
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
) -> Result<()> {
    provision_from_source_until(
        root,
        config,
        crate::windows_installed_cases::WindowsLeaseDeadlines::finite_default().work,
    )
}

#[cfg(windows)]
pub fn provision_from_source_until(
    root: &Path,
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
    work_deadline: std::time::Instant,
) -> Result<()> {
    native::provision(root, config, work_deadline)
}

#[cfg(windows)]
pub(crate) fn cleanup_provider_probe(
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
) -> Result<()> {
    native::cleanup_provider_probe(config)
}

#[cfg(not(windows))]
pub fn provision_from_source(
    _: &Path,
    _: &crate::windows_installed_cases::InstalledWindowsPayload,
) -> Result<()> {
    Err(CiError::Message(
        "Windows readiness provisioning requires native Windows".into(),
    ))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseAssessment {
    pub key: CaseKey,
    pub behavior: std::result::Result<(), String>,
    pub collection: std::result::Result<(), String>,
    pub retirement: std::result::Result<(), String>,
    pub descriptor_sha256: String,
    pub result_sha256: Option<String>,
    pub stdout_sha256: Option<String>,
    pub stderr_sha256: Option<String>,
    pub transcript_sha256: Option<String>,
    pub request_sha256: Option<String>,
    pub terminal_observation_sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    sequence: u32,
    stage: String,
    pid: u32,
    ordinal: Option<u32>,
    value: Vec<u8>,
}

pub fn positive_keys() -> BTreeSet<CaseKey> {
    let mut keys = BTreeSet::new();
    for (family, scenarios) in [
        (
            "C-IO",
            &[
                "empty-input",
                "empty-message",
                "binary-streams",
                "binary-file",
                "native-argv",
                "bounded-large-output",
            ][..],
        ),
        (
            "C-STATUS",
            &[
                "zero", "nonzero", "exit-123", "exit-124", "exit-125", "exit-126", "exit-127",
                "deadline", "memory",
            ][..],
        ),
        ("C-PARSER", &["valid-current-result"][..]),
        ("C-LIFETIME", &["root-first"][..]),
        ("W-RETIREMENT", &["natural", "output-backpressure"][..]),
        ("W-UPGRADE", &["fresh-positive"][..]),
        ("C-ADMISSION", &["positive"][..]),
        (
            "W-BINDING",
            &["effective-caller-token", "restricted-token-preserved"][..],
        ),
        (
            "W-ENVELOPE",
            &["ordinary", "restricted", "sentinel-handles"][..],
        ),
        (
            "W-JOINT",
            &["ordinary", "restricted", "endpoint-mismatch"][..],
        ),
        ("W-TOOLCHAIN", &["ordinary", "restricted"][..]),
        (
            "W-IO",
            &[
                "empty-stdout-stderr",
                "empty-message",
                "embedded-nul",
                "all-bytes",
                "invalid-utf8",
                "final-fragment",
                "backpressure-separated-streams",
                "empty-file",
                "binary-file",
                "argv-empty",
                "argv-whitespace",
                "argv-quotes",
                "argv-backslashes",
                "argv-unicode",
                "argv-path",
            ][..],
        ),
        ("W-CHURN", &["natural-4096-three-generations"][..]),
        (
            "W-DESCENDANT",
            &[
                "root-first",
                "intermediate-parent-first",
                "nested-job",
                "breakaway-denial",
                "allowed-token-change",
            ][..],
        ),
        (
            "W-STATUS",
            &[
                "zero",
                "nonzero",
                "exit-123",
                "exit-124",
                "exit-125",
                "exit-126",
                "exit-127",
                "target-failure",
                "deadline",
                "memory",
            ][..],
        ),
    ] {
        for scenario in scenarios {
            keys.insert(CaseKey {
                family: family.into(),
                scenario: (*scenario).into(),
            });
        }
    }
    keys
}

pub fn validate_suite(input: &SuiteInput) -> Result<()> {
    if input.format != "memcordon.windows-readiness-input" || input.revision != 2 {
        return Err(CiError::Message(
            "unsupported Windows readiness input format/revision".into(),
        ));
    }
    let mut keys = BTreeSet::new();
    for case in &input.cases {
        if !keys.insert(case.key.clone()) {
            return Err(CiError::Message("duplicate Windows positive case".into()));
        }
        validate_descriptor(&case.key, &case.descriptor)?;
        if !case.workload_request.is_absolute()
            || !case.descriptor_path.is_absolute()
            || matches!(
                case.key.scenario.as_str(),
                "restricted" | "restricted-token-preserved"
            ) && !case.expected_token.restricted
        {
            return Err(CiError::Message(
                "case input lacks exact contract/path/caller binding".into(),
            ));
        }
        validate_vectors(case)?;
        let expected = expected_fixture_case(&case.key)?;
        if case.descriptor.case != expected {
            return Err(CiError::Message(
                "case descriptor substituted another positive workload".into(),
            ));
        }
        let status = expected_status(&case.key);
        if case.descriptor.application_status != status {
            return Err(CiError::Message(
                "case descriptor substituted target outcome".into(),
            ));
        }
        if matches!(case.key.family.as_str(), "W-JOINT" | "W-ENVELOPE")
            && case.key.scenario == "restricted"
            && case.descriptor.denied_write_paths.len() < 2
        {
            return Err(CiError::Message(
                "restricted composite must probe protected driver/provider writes".into(),
            ));
        }
    }
    if keys != positive_keys() {
        return Err(CiError::Message(
            "Windows positive case set is incomplete or unknown".into(),
        ));
    }
    Ok(())
}

fn validate_vectors(case: &CaseInput) -> Result<()> {
    let d = &case.descriptor;
    if case.key.family == "W-IO" {
        let valid = match case.key.scenario.as_str() {
            "all-bytes" => {
                d.stdout == (0..=255).collect::<Vec<u8>>()
                    && d.stderr == (0..=255).rev().collect::<Vec<u8>>()
            }
            "embedded-nul" => d.stdout.contains(&0) && d.stderr.contains(&0),
            "invalid-utf8" => {
                std::str::from_utf8(&d.stdout).is_err() && std::str::from_utf8(&d.stderr).is_err()
            }
            "final-fragment" => {
                !d.stdout.is_empty()
                    && !d.stderr.is_empty()
                    && !d.stdout.ends_with(b"\n")
                    && !d.stderr.ends_with(b"\n")
            }
            "backpressure-separated-streams" => {
                d.stdout.len() >= 8192 && d.stderr.len() >= 8192 && d.stdout != d.stderr
            }
            "empty-stdout-stderr" => d.stdout.is_empty() && d.stderr.is_empty(),
            "argv-empty" => d.arguments.iter().any(String::is_empty),
            "argv-whitespace" => d
                .arguments
                .iter()
                .any(|a| a.contains(' ') || a.contains('\t')),
            "argv-quotes" => d.arguments.iter().any(|a| a.contains('"')),
            "argv-backslashes" => d.arguments.iter().any(|a| a.ends_with('\\')),
            "argv-unicode" => d.arguments.iter().any(|a| !a.is_ascii()),
            "argv-path" => d
                .arguments
                .iter()
                .any(|a| a.contains('\\') && a.contains(' ')),
            _ => true,
        };
        if !valid {
            return Err(CiError::Message(
                "Windows byte/argv scenario omitted its required vector".into(),
            ));
        }
    }
    if case.key.family == "W-CHURN" && d.churn_live != descriptor::CHURN_LIVE {
        return Err(CiError::Message("churn must retain 63 cohort leaves plus one TCP peer within the frozen 64-live-child bound".into()));
    }
    Ok(())
}

/// Deterministic execution inputs shared by provisioning and portable boundary checks.
pub struct FixtureParameters {
    pub case: descriptor::Case,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub arguments: Vec<String>,
    pub application_status: u32,
}

pub fn fixture_parameters(key: &CaseKey) -> Result<FixtureParameters> {
    let case = expected_fixture_case(key)?;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut arguments = Vec::new();
    if key.family == "W-IO" {
        match key.scenario.as_str() {
            "all-bytes" => {
                stdout = (0..=255).collect();
                stderr = (0..=255).rev().collect();
            }
            "embedded-nul" => {
                stdout = vec![1, 0, 2];
                stderr = vec![3, 0, 4];
            }
            "invalid-utf8" => {
                stdout = vec![255, 128];
                stderr = vec![254, 129];
            }
            "final-fragment" => {
                stdout = b"final-fragment".to_vec();
                stderr = b"stderr-fragment".to_vec();
            }
            "backpressure-separated-streams" => {
                stdout = (0..=255).cycle().take(8192).collect();
                stderr = (0..=255).rev().cycle().take(8192).collect();
            }
            "argv-empty" => arguments.push(String::new()),
            "argv-whitespace" => arguments.push("space and\ttab".into()),
            "argv-quotes" => arguments.push("literal \"quotes\"".into()),
            "argv-backslashes" => arguments.push("trailing\\".into()),
            "argv-unicode" => arguments.push("日本語-λ".into()),
            "argv-path" => arguments.push("C:\\path with spaces\\file".into()),
            _ => {}
        }
    }
    if key.family == "W-RETIREMENT" && key.scenario == "output-backpressure" {
        stdout = (u8::MIN..=u8::MAX).cycle().take(16384).collect();
        stderr = (u8::MIN..=u8::MAX).rev().cycle().take(16384).collect();
    }
    if key.family == "C-IO" {
        match key.scenario.as_str() {
            "binary-streams" => {
                stdout = (u8::MIN..=u8::MAX).collect();
                stderr = (u8::MIN..=u8::MAX).rev().collect();
            }
            "bounded-large-output" => {
                stdout = (u8::MIN..=u8::MAX).cycle().take(16384).collect();
                stderr = (u8::MIN..=u8::MAX).rev().cycle().take(16384).collect();
            }
            "native-argv" => {
                arguments = vec![
                    String::new(),
                    "space and\ttab".into(),
                    "literal \"quotes\"".into(),
                    "trailing\\".into(),
                    "日本語-λ".into(),
                    "C:\\path with spaces\\file".into(),
                ]
            }
            _ => {}
        }
    }
    Ok(FixtureParameters {
        case,
        stdout,
        stderr,
        arguments,
        application_status: expected_status(key),
    })
}

/// Validate the actual input once complete, retaining its case and wire-size boundary.
pub fn validate_descriptor(key: &CaseKey, descriptor: &descriptor::Descriptor) -> Result<()> {
    let bytes = serde_json::to_vec(descriptor).map_err(|error| {
        CiError::Message(format!(
            "Windows fixture {}/{} encoding failed: {error}; limit={}",
            key.family,
            key.scenario,
            descriptor::MAX_DESCRIPTOR_BYTES
        ))
    })?;
    descriptor.validate().map_err(|error| {
        CiError::Message(format!(
            "Windows fixture {}/{} descriptor invalid: {error}; encoded-bytes={} limit={}",
            key.family,
            key.scenario,
            bytes.len(),
            descriptor::MAX_DESCRIPTOR_BYTES
        ))
    })
}

fn expected_fixture_case(key: &CaseKey) -> Result<descriptor::Case> {
    use descriptor::Case;
    let case = match key.family.as_str() {
        "W-ENVELOPE" | "W-BINDING" | "C-ADMISSION" | "C-PARSER" | "W-UPGRADE" => Case::Envelope,
        "C-LIFETIME" if key.scenario == "root-first" => Case::RootFirst,
        "C-IO" => match key.scenario.as_str() {
            "empty-input" => Case::EmptyInput,
            "empty-message" => Case::Joint,
            "binary-file" => Case::BinaryFiles,
            "native-argv" => Case::NativeArgv,
            "binary-streams" | "bounded-large-output" => Case::BinaryStreams,
            _ => return Err(CiError::Message("unknown common IO scenario".into())),
        },
        "W-RETIREMENT" if key.scenario == "natural" => Case::ApplicationExit,
        "W-RETIREMENT" if key.scenario == "output-backpressure" => Case::BinaryStreams,
        "W-JOINT" if key.scenario == "endpoint-mismatch" => Case::EndpointMismatch,
        "W-JOINT" => Case::Joint,
        "W-TOOLCHAIN" => Case::Toolchain,
        "W-CHURN" => Case::Churn,
        "W-IO" => match key.scenario.as_str() {
            "empty-stdout-stderr" => Case::EmptyStreams,
            "empty-message" => Case::Joint,
            "empty-file" | "binary-file" => Case::BinaryFiles,
            value if value.starts_with("argv-") => Case::NativeArgv,
            _ => Case::BinaryStreams,
        },
        "W-STATUS" | "C-STATUS" if key.scenario == "deadline" => Case::DeadlineDemand,
        "W-STATUS" | "C-STATUS" if key.scenario == "memory" => Case::MemoryDemand,
        "W-STATUS" | "C-STATUS" => Case::ApplicationExit,
        "W-DESCENDANT" => match key.scenario.as_str() {
            "root-first" => Case::RootFirst,
            "intermediate-parent-first" => Case::IntermediateFirst,
            "nested-job" => Case::NestedJob,
            "breakaway-denial" => Case::BreakawayDenied,
            "allowed-token-change" => Case::AllowedTokenChange,
            _ => return Err(CiError::Message("unknown descendant scenario".into())),
        },
        _ => return Err(CiError::Message("unknown Windows positive family".into())),
    };
    Ok(case)
}

fn expected_status(key: &CaseKey) -> u32 {
    if key.family == "W-JOINT" && key.scenario == "endpoint-mismatch" {
        return 42;
    }
    if matches!(key.family.as_str(), "W-STATUS" | "C-STATUS") {
        match key.scenario.as_str() {
            "nonzero" | "target-failure" => 17,
            value => value
                .strip_prefix("exit-")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
        }
    } else {
        0
    }
}

pub fn public_command(
    cli: &Path,
    fixture: &Path,
    directory: &Path,
    report: &Path,
    case: &CaseInput,
) -> Result<crate::command::CommandSpec> {
    public_command_observation(
        cli,
        fixture,
        directory,
        report,
        case,
        FrontendObservation::Terminal,
    )
}

#[cfg(windows)]
pub(crate) fn public_refusal_command(
    cli: &Path,
    fixture: &Path,
    directory: &Path,
    report: &Path,
    case: &CaseInput,
) -> Result<crate::command::CommandSpec> {
    public_command_observation(
        cli,
        fixture,
        directory,
        report,
        case,
        FrontendObservation::Request,
    )
}

#[cfg(windows)]
pub(crate) fn public_component_command(
    cli: &Path,
    fixture: &Path,
    directory: &Path,
    report: &Path,
    case: &CaseInput,
) -> Result<crate::command::CommandSpec> {
    public_command_observation(
        cli,
        fixture,
        directory,
        report,
        case,
        FrontendObservation::None,
    )
}

enum FrontendObservation<'a> {
    Terminal,
    #[cfg(windows)]
    Request,
    #[cfg(windows)]
    None,
    Diagnostic {
        selection: &'a Path,
        observation: &'a Path,
        system_environment: bool,
    },
}

pub fn support_loader_command(
    cli: &Path,
    fixture: &Path,
    directory: &Path,
    report: &Path,
    case: &CaseInput,
    selection: &Path,
    observation: &Path,
) -> Result<crate::command::CommandSpec> {
    support_loader_command_with_environment::<false>(
        cli,
        fixture,
        directory,
        report,
        case,
        selection,
        observation,
    )
}

pub fn installed_support_loader_command(
    cli: &Path,
    fixture: &Path,
    directory: &Path,
    report: &Path,
    case: &CaseInput,
    selection: &Path,
    observation: &Path,
) -> Result<crate::command::CommandSpec> {
    support_loader_command_with_environment::<true>(
        cli,
        fixture,
        directory,
        report,
        case,
        selection,
        observation,
    )
}

fn support_loader_command_with_environment<const SYSTEM_ENVIRONMENT: bool>(
    cli: &Path,
    fixture: &Path,
    directory: &Path,
    report: &Path,
    case: &CaseInput,
    selection: &Path,
    observation: &Path,
) -> Result<crate::command::CommandSpec> {
    if case.key.family != "W-ENVELOPE"
        || case.key.scenario != "restricted"
        || !case.expected_token.restricted
        || case.descriptor.case != descriptor::Case::Envelope
        || !case.descriptor.arguments.is_empty()
        || !case.descriptor.stdout.is_empty()
        || !case.descriptor.stderr.is_empty()
        || case.descriptor.application_status != 0
    {
        return Err(CiError::Message(
            "loader diagnostic requires the exact restricted envelope case".into(),
        ));
    }
    case.descriptor.validate().map_err(CiError::Message)?;
    if !case.workload_request.is_absolute() || !case.descriptor_path.is_absolute() {
        return Err(CiError::Message(
            "diagnostic contract/input paths are not selected absolute paths".into(),
        ));
    }
    public_command_observation(
        cli,
        fixture,
        directory,
        report,
        case,
        FrontendObservation::Diagnostic {
            selection,
            observation,
            system_environment: SYSTEM_ENVIRONMENT,
        },
    )
}

fn public_command_observation(
    cli: &Path,
    fixture: &Path,
    directory: &Path,
    report: &Path,
    case: &CaseInput,
    observation: FrontendObservation<'_>,
) -> Result<crate::command::CommandSpec> {
    let terminal_observation = matches!(observation, FrontendObservation::Terminal);
    let system_environment = terminal_observation
        || matches!(
            observation,
            FrontendObservation::Diagnostic {
                system_environment: true,
                ..
            }
        );
    #[cfg(windows)]
    let request_observation = matches!(observation, FrontendObservation::Request);
    #[cfg(not(windows))]
    let request_observation = false;
    let mut args: Vec<OsString> = ["+4GiB", "+600s"].into_iter().map(OsString::from).collect();
    // A named request on the ordinary backend is a deliberately unsupported
    // public request. Every other readiness operation selects sealed runtime.
    if case.key.scenario != "unsupported-public-request" {
        args.push("--sealed".into());
    }
    args.push("--workload-request".into());
    if case.descriptor.case == descriptor::Case::DeadlineDemand {
        args[1] = "+10s".into();
    }
    if case.descriptor.case == descriptor::Case::MemoryDemand {
        args[0] = "+64MiB".into();
    }
    args.push(std::path::absolute(&case.workload_request)?.into_os_string());
    args.extend(["--report-format", "result-v3", "--report"].map(OsString::from));
    args.push(std::path::absolute(report)?.into_os_string());
    if terminal_observation {
        args.push("--windows-terminal-observation".into());
        args.push(
            std::path::absolute(report)?
                .with_extension("terminal-observation.json")
                .into_os_string(),
        );
    } else if request_observation && case.key.scenario != "unsupported-public-request" {
        args.push("--windows-request-observation".into());
        args.push(
            std::path::absolute(directory)?
                .join("provider-request.bin")
                .into_os_string(),
        );
    }
    args.push("--".into());
    args.push(std::path::absolute(fixture)?.into_os_string());
    args.push("consumer-readiness-windows".into());
    args.push(case.descriptor_path.clone().into_os_string());
    args.extend(case.descriptor.arguments.iter().map(OsString::from));
    if let FrontendObservation::Diagnostic {
        selection,
        observation,
        ..
    } = observation
    {
        args = [
            OsString::from("__windows-loader-diagnostic"),
            selection.as_os_str().to_owned(),
            observation.as_os_str().to_owned(),
        ]
        .into_iter()
        .chain(args)
        .collect();
    }
    let cli = std::path::absolute(cli)?;
    if case.expected_token.restricted {
        let mut restricted: Vec<OsString> = vec![
            "consumer-readiness-windows".into(),
            if system_environment {
                "system-restricted-frontend"
            } else {
                "restricted-frontend"
            }
            .into(),
            cli.into_os_string(),
        ];
        restricted.extend(args);
        Ok(crate::command::CommandSpec::new(
            std::path::absolute(fixture)?,
            &std::path::absolute(directory)?,
            Duration::from_secs(660),
        )
        .args(restricted))
    } else if case.key.scenario == "sentinel-handles" {
        let mut sentinel: Vec<OsString> = vec![
            "consumer-readiness-windows".into(),
            if terminal_observation {
                "system-sentinel-frontend"
            } else {
                "sentinel-frontend"
            }
            .into(),
            case.descriptor_path.clone().into_os_string(),
            cli.into_os_string(),
        ];
        sentinel.extend(args);
        Ok(crate::command::CommandSpec::new(
            std::path::absolute(fixture)?,
            &std::path::absolute(directory)?,
            Duration::from_secs(660),
        )
        .args(sentinel))
    } else if terminal_observation {
        let mut ordinary: Vec<OsString> = vec![
            "consumer-readiness-windows".into(),
            "system-frontend".into(),
            cli.into_os_string(),
        ];
        ordinary.extend(args);
        Ok(crate::command::CommandSpec::new(
            std::path::absolute(fixture)?,
            &std::path::absolute(directory)?,
            Duration::from_secs(660),
        )
        .args(ordinary))
    } else {
        Ok(crate::command::CommandSpec::new(
            cli,
            &std::path::absolute(directory)?,
            Duration::from_secs(660),
        )
        .args(args))
    }
}

fn events(bytes: &[u8]) -> Result<Vec<Event>> {
    decode_events(bytes, false)
}

// Only the native controller uses this while holding the transcript writer
// alive. A partial final frame is a publication in progress, never evidence.
#[cfg(windows)]
fn live_events(bytes: &[u8]) -> Result<Vec<Event>> {
    decode_events(bytes, true)
}

#[cfg(windows)]
pub(crate) fn live_capacity_completion(bytes: &[u8]) -> Result<bool> {
    Ok(live_events(bytes)?
        .iter()
        .any(|event| event.stage == "capacity-live-before-natural-completion"))
}

#[cfg(windows)]
pub(crate) fn live_demand_child(
    bytes: &[u8],
    root_pid: u32,
) -> Result<Option<memcordon_core::WindowsProcessIdentityV1>> {
    let events = live_events(bytes)?;
    if !events
        .iter()
        .any(|event| event.stage == "policy-demand-started" && event.pid == root_pid)
    {
        return Ok(None);
    }
    let children: Vec<_> = events
        .iter()
        .filter(|event| event.stage == "child-created")
        .collect();
    if children.len() != 1 || children[0].pid != root_pid || children[0].ordinal != Some(0) {
        return Err(CiError::Message(
            "demand live publication lacks the exact owned descendant".into(),
        ));
    }
    serde_json::from_slice(&children[0].value)
        .map(Some)
        .map_err(CiError::from)
}

fn decode_events(bytes: &[u8], live: bool) -> Result<Vec<Event>> {
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(CiError::Message("fixture transcript exceeds bound".into()));
    }
    let mut remaining = bytes;
    let mut result = Vec::new();
    while !remaining.is_empty() {
        if live && remaining.len() < 4 {
            break;
        }
        let length_bytes = remaining
            .get(..4)
            .ok_or_else(|| CiError::Message("truncated fixture event length".into()))?;
        let length =
            u32::from_le_bytes(length_bytes.try_into().expect("checked four-byte length")) as usize;
        remaining = &remaining[length_bytes.len()..];
        if length > 64 * 1024 {
            return Err(CiError::Message("fixture event exceeds bound".into()));
        }
        if live && remaining.len() < length {
            break;
        }
        let event_bytes = remaining
            .get(..length)
            .ok_or_else(|| CiError::Message("truncated fixture event".into()))?;
        let event: Event = serde_json::from_slice(event_bytes)?;
        if event.sequence as usize != result.len() || event.pid == 0 {
            return Err(CiError::Message(
                "fixture sequence or native process identity differs".into(),
            ));
        }
        result.push(event);
        if result.len() > 200_000 {
            return Err(CiError::Message("fixture event count exceeds bound".into()));
        }
        remaining = &remaining[length..];
    }
    Ok(result)
}

/// A launch refusal or abnormal completion cannot satisfy the live positive-fixture barrier.
/// This observation only rejects; it never supplies accepted workload authority.
pub fn current_native(result: &ResultV3) -> Result<&memcordon_core::WindowsSealedEvidenceV3> {
    match &result.runtime {
        RuntimeExecutionV3::WindowsSealed { native, .. } => Ok(native),
        _ => Err(CiError::Message(
            "current result lacks actual Windows native execution".into(),
        )),
    }
}
pub fn current_association(
    result: &ResultV3,
) -> Result<&memcordon_core::execution_facts::ProviderAttemptAssociationV1> {
    current_native(result)?
        .frontend_provider_association
        .as_ref()
        .ok_or_else(|| {
            CiError::Message("current Windows result lacks actual provider association".into())
        })
}
pub fn check_positive_barrier_result(
    bytes: &[u8],
    provider: &memcordon_core::PublicProviderBindingV1,
) -> Result<()> {
    let result = ResultV3::parse(bytes).map_err(CiError::Message)?;
    if result.provider.as_ref() != Some(provider) {
        return Err(CiError::Message(
            "positive fixture provider binding differs from selected installed image".into(),
        ));
    }
    if result.release != ReleaseKnowledgeV3::Released
        || matches!(
            result.outcome.kind,
            OutcomeKindV1::LaunchFailure | OutcomeKindV1::ProviderFailure | OutcomeKindV1::Unknown
        )
        || (result.outcome.kind == OutcomeKindV1::Completed && result.outcome.wrapper_status != 0)
    {
        let mut detail = format!(
            "positive fixture launch already failed or completed abnormally; wrapper-status={}; outcome={:?}; release={:?}",
            result.outcome.wrapper_status, result.outcome.kind, result.release
        );
        if let Some(ChildTermination::WindowsStatus { status }) = result.outcome.native_termination
        {
            detail.push_str(&format!("; windows-status={status} (0x{status:08X})"));
        }
        if let Some(rejection) = &result.windows_rejection {
            detail.push_str(&format!("; {}: {}", rejection.code, rejection.detail));
        }
        if let Some(failure) = &result.provider_failure {
            detail.push_str(&format!(
                "; original-provider-failure={:?}",
                failure.original
            ));
        } else {
            detail.push_str("; no original provider failure observed");
        }
        for diagnostic in result.diagnostics.as_slice() {
            detail.push_str("; ");
            detail.push_str(diagnostic.as_str());
        }
        return Err(CiError::Message(detail));
    }
    Ok(())
}
pub fn released_target_loader_event_candidate(result: &ResultV3) -> bool {
    result.release == ReleaseKnowledgeV3::Released
        && result.outcome.kind == OutcomeKindV1::Completed
        && result.outcome.wrapper_status == 125
        && matches!(
            result.outcome.native_termination,
            Some(ChildTermination::WindowsStatus { status: 0xC0000142 })
        )
        && validate_retirement(result).is_ok()
}

/// Original frontend exit observations retained by the running controller.
pub struct FrontendExit {
    pub status: i32,
    pub original_pid: Option<u32>,
}

pub fn assess(
    case: &CaseInput,
    result_bytes: &[u8],
    stdout: &[u8],
    stderr: &[u8],
    transcript: &[u8],
    frontend: FrontendExit,
    expected_association: &memcordon_core::execution_facts::ProviderAttemptAssociationV1,
) -> Result<()> {
    let FrontendExit {
        status: native_status,
        original_pid: frontend_pid,
    } = frontend;
    let result = ResultV3::parse(result_bytes).map_err(CiError::Message)?;
    let target_status = expected_status(&case.key);
    let policy_kind = match case.descriptor.case {
        descriptor::Case::DeadlineDemand => Some(OutcomeKindV1::Deadline),
        descriptor::Case::MemoryDemand => Some(OutcomeKindV1::ConfirmedMemoryLimit),
        _ => None,
    };
    if result.release != ReleaseKnowledgeV3::Released
        || result.outcome.kind != policy_kind.unwrap_or(OutcomeKindV1::Completed)
        || result.outcome.wrapper_status != native_status
        || !result.diagnostics.as_slice().is_empty()
        || policy_kind.is_none()
            && !matches!(result.outcome.native_termination.as_ref(),
            Some(ChildTermination::WindowsStatus { status }) if *status == target_status)
            && !matches!(result.outcome.native_termination.as_ref(), Some(ChildTermination::ExitCode { code }) if *code == target_status as i32)
    {
        return Err(CiError::Message(format!(
            "positive Windows case {}/{} did not complete with exact application origin/status; expected-kind={:?}; expected-target-status={target_status}; observed-kind={:?}; wrapper-status={}; native-status={native_status}; release={:?}; termination={:?}; diagnostics={}",
            case.key.family,
            case.key.scenario,
            policy_kind.unwrap_or(OutcomeKindV1::Completed),
            result.outcome.kind,
            result.outcome.wrapper_status,
            result.release,
            result.outcome.native_termination,
            result.diagnostics.as_slice().len(),
        )));
    }
    if current_association(&result)? != expected_association {
        return Err(CiError::Message(
            "positive result differs from independently held provider/attempt/request association"
                .into(),
        ));
    }
    validate_retirement(&result)?;
    let event = events(transcript)?;
    let first = event
        .first()
        .ok_or_else(|| CiError::Message("empty fixture transcript".into()))?;
    let last = event.last().expect("nonempty transcript");
    if first.stage != "started"
        || first.value != case.descriptor.challenge
        || policy_kind.is_none()
            && (last.stage != "finished" || last.value != case.descriptor.challenge)
    {
        return Err(CiError::Message(
            "fixture start/finish/challenge evidence differs".into(),
        ));
    }
    if current_native(&result)?
        .target_identity
        .as_ref()
        .map(|identity| identity.process_id)
        != Some(first.pid)
    {
        return Err(CiError::Message(
            "fixture root differs from authenticated target identity".into(),
        ));
    }
    let envelope = event
        .iter()
        .find(|e| e.stage == "token-envelope")
        .ok_or_else(|| CiError::Message("fixture omitted target token readback".into()))?;
    let observed: TokenObservation = serde_json::from_slice(&envelope.value)?;
    if observed != case.expected_token {
        return Err(CiError::Message(
            "native target token differs from protected caller expectation".into(),
        ));
    }
    if case.key.scenario == "sentinel-handles"
        && !event.iter().any(|event| {
            event.stage == "sentinel-handles-excluded" && event.value == 1u32.to_le_bytes()
        })
    {
        return Err(CiError::Message(
            "frontend sentinel case did not independently exercise exclusion".into(),
        ));
    }
    if case.descriptor.case == descriptor::Case::BinaryStreams {
        if stdout != case.descriptor.stdout.repeat(128)
            || stderr != case.descriptor.stderr.repeat(128)
        {
            return Err(CiError::Message(
                "exact independent stdout/stderr bytes differ".into(),
            ));
        }
    } else {
        crate::windows_status_streams::validate(
            stdout,
            stderr,
            native_status,
            result.outcome.kind,
            frontend_pid,
            case.expected_token.restricted,
        )
        .map_err(CiError::Message)?;
    }
    let has = |stage: &str| event.iter().any(|e| e.stage == stage);
    if policy_kind.is_some() && (!has("policy-demand-started") || has("finished")) {
        return Err(CiError::Message(
            "policy case did not hold genuine demand until authenticated forced termination".into(),
        ));
    }
    if case.descriptor.case == descriptor::Case::AllowedTokenChange {
        let changed = event
            .iter()
            .find(|e| e.stage == "allowed-token-change-retained-job")
            .ok_or_else(|| {
                CiError::Message("allowed token-change job observation missing".into())
            })?;
        let changed: TokenObservation = serde_json::from_slice(&changed.value)?;
        if !changed.restricted
            || changed.user_sid != case.expected_token.user_sid
            || changed.restricting_sids != vec![vec![1, 1, 0, 0, 0, 0, 0, 5, 12, 0, 0, 0]]
        {
            return Err(CiError::Message(
                "allowed token-change descendant envelope differs".into(),
            ));
        }
    }
    match case.descriptor.case {
        descriptor::Case::Joint | descriptor::Case::Churn => {
            for stage in [
                "tcp-listener-owned",
                "named-pipe-while-tcp-owned",
                "binary-files",
                "toolchain-compiled",
                "toolchain-test-child-dll-complete",
                "tcp-peer-complete",
            ] {
                if !has(stage) {
                    return Err(CiError::Message(
                        "composite fixture omitted a required genuine operation".into(),
                    ));
                }
            }
        }
        descriptor::Case::EndpointMismatch => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Refusal {
                kind: String,
                allowed_port: u16,
                observed_port: u16,
            }
            let failure = event
                .iter()
                .find(|e| e.stage == "endpoint-policy-refused-before-readiness")
                .ok_or_else(|| {
                    CiError::Message("endpoint mismatch omitted typed refusal".into())
                })?;
            let refusal: Refusal = serde_json::from_slice(&failure.value)?;
            if refusal.kind != "numeric-port-policy-mismatch"
                || refusal.allowed_port == refusal.observed_port
                || has("tcp-peer-complete")
                || has("named-pipe-while-tcp-owned")
            {
                return Err(CiError::Message(
                    "endpoint mismatch was not refused before readiness/application dispatch"
                        .into(),
                ));
            }
        }
        descriptor::Case::Toolchain
            if !has("toolchain-compiled") || !has("toolchain-test-child-dll-complete") =>
        {
            return Err(CiError::Message(
                "toolchain fixture omitted compile/child/DLL stage".into(),
            ));
        }
        _ => {}
    }
    if case.descriptor.case == descriptor::Case::Churn {
        let created: BTreeSet<_> = event
            .iter()
            .filter(|e| e.stage == "child-created")
            .filter_map(|e| e.ordinal)
            .collect();
        let completed: BTreeSet<_> = event
            .iter()
            .filter(|e| e.stage == "child-completed")
            .filter_map(|e| e.ordinal)
            .collect();
        let expected: BTreeSet<_> = (0..case.descriptor.churn_creations).collect();
        if created != expected
            || completed != expected
            || event.iter().filter(|e| e.stage == "child-created").count() != expected.len()
            || event
                .iter()
                .filter(|e| e.stage == "child-completed")
                .count()
                != expected.len()
        {
            return Err(CiError::Message(
                "churn omitted/duplicated a planned creation or completion".into(),
            ));
        }
    }
    Ok(())
}

pub fn validate_retirement(result: &ResultV3) -> Result<()> {
    result.validate().map_err(CiError::Message)?;
    let observation = current_native(result)?;
    if result.cleanup.state != CleanupStateV1::Complete
        || result
            .cleanup
            .obligations
            .as_slice()
            .iter()
            .any(|obligation| !obligation.settled)
        || !observation.caller_token_authenticated
        || !observation.initial_target_token_matches_caller
        || !observation.job_list_applied_at_creation
        || !observation.handle_list_applied_at_creation
        || !observation.target_still_suspended_during_verification
        || !observation.inherited_handles_verified
        || !observation.active_processes_zero
        || !observation.direct_target_reaped
        || !observation.relays_retired
        || !observation.guardian_reaped
        || !observation.final_job_handles_closed
    {
        return Err(CiError::Message(
            "native Windows boundary or authoritative retirement is incomplete".into(),
        ));
    }
    Ok(())
}

pub fn accepted(records: &[CaseAssessment]) -> bool {
    let keys: BTreeSet<_> = records.iter().map(|record| record.key.clone()).collect();
    keys == positive_keys()
        && keys.len() == records.len()
        && records.iter().all(|record| {
            record.behavior.is_ok()
                && record.collection.is_ok()
                && record.retirement.is_ok()
                && record.result_sha256.is_some()
                && record.stdout_sha256.is_some()
                && record.stderr_sha256.is_some()
                && record.transcript_sha256.is_some()
                && record.terminal_observation_sha256.is_some()
                && record.request_sha256.is_some()
        })
}

#[cfg(not(windows))]
pub fn run_installed(
    _: &crate::windows_installed_cases::InstalledWindowsPayload,
    _: &Path,
    _: &mut Vec<CaseAssessment>,
) -> Result<()> {
    Err(CiError::Message(
        "Windows readiness requires a native Windows execution host".into(),
    ))
}

#[cfg(windows)]
pub fn run_installed(
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
    input_path: &Path,
    assessments: &mut Vec<CaseAssessment>,
) -> Result<()> {
    run_installed_until(
        config,
        input_path,
        assessments,
        std::time::Instant::now() + Duration::from_secs(660),
    )
}

#[cfg(any(windows, test))]
pub(crate) fn write_workload_request(
    output_directory: &Path,
    key: &CaseKey,
    bytes: &[u8],
) -> Result<PathBuf> {
    use std::io::Write;
    let directory = std::path::absolute(output_directory)?
        .join(&key.family)
        .join(&key.scenario);
    std::fs::create_dir_all(&directory)?;
    let path = directory.join("workload-request.json");
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?
        .write_all(bytes)?;
    Ok(path)
}

#[cfg(test)]
#[path = "../tests/private/windows_activated_contract.rs"]
mod activated_contract_tests;

#[cfg(all(test, windows))]
#[path = "../tests/private/windows_component_barriers.rs"]
mod component_barrier_tests;

#[cfg(windows)]
pub fn run_installed_until(
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
    input_path: &Path,
    assessments: &mut Vec<CaseAssessment>,
    work_deadline: std::time::Instant,
) -> Result<()> {
    native::run(config, input_path, assessments, work_deadline, None)
}

#[cfg(windows)]
pub fn run_installed_with_deadlines(
    config: &crate::windows_installed_cases::InstalledWindowsPayload,
    input_path: &Path,
    assessments: &mut Vec<CaseAssessment>,
    deadlines: crate::windows_installed_cases::WindowsLeaseDeadlines,
) -> Result<()> {
    native::run(
        config,
        input_path,
        assessments,
        deadlines.work,
        Some(deadlines),
    )
}

#[cfg(windows)]
pub(crate) mod native {
    use super::*;
    use crate::command::CommandSpec;
    use crate::windows_owned_guardian::{
        GuardianAssociationIdentity, GuardianBaseline, HeldGuardian,
    };
    use memcordon_testkit::WindowsImageProcess;
    use std::fs::{self, OpenOptions};
    use std::io::{self, Read, Write};
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::sync::{Arc, Mutex};
    use std::time::Instant;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    struct HeldConsoleImage {
        _file: fs::File,
        path: PathBuf,
        sha256: String,
        identity: serde_json::Value,
    }

    fn hold_console_image() -> io::Result<HeldConsoleImage> {
        use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
        let path = memcordon_testkit::windows_console_host_path()?;
        // Deny write/delete sharing while the original measured image is held.
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || metadata.len() > 16 * 1024 * 1024
        {
            return Err(io::Error::other(
                "native console image is not a bounded ordinary file",
            ));
        }
        let information = memcordon_testkit::windows_held_file_identity(&file)?;
        if information.length != metadata.len() {
            return Err(io::Error::other(
                "held native console file identity length differs",
            ));
        }
        let mut bytes = Vec::new();
        (&file).take(16 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 != metadata.len() {
            return Err(io::Error::other("held native console image length changed"));
        }
        Ok(HeldConsoleImage {
            _file: file,
            path,
            sha256: crate::windows_causal_acceptance::sha256(&bytes),
            identity: serde_json::to_value(information).map_err(io::Error::other)?,
        })
    }

    fn provision_budget(deadline: Instant) -> Result<Duration> {
        let remaining = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(30));
        if remaining.is_zero() {
            return Err(CiError::Message(
                "original Windows provisioning work deadline exhausted".into(),
            ));
        }
        Ok(remaining)
    }

    pub fn provision(
        root: &Path,
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        work_deadline: Instant,
    ) -> Result<()> {
        use memcordon_core::workload_request::*;
        use std::num::NonZeroU64;
        let directory = std::path::absolute(&config.output_directory)?;
        fs::create_dir_all(&directory)?;
        let locked = crate::config::toolchains(root)?.stable;
        let locate_budget = provision_budget(work_deadline)?;
        let mut locate = CommandSpec::new("rustup", root, locate_budget)
            .args([
                OsString::from("which"),
                "--toolchain".into(),
                locked.clone().into(),
                "rustc".into(),
            ])
            .materialize()?;
        let located = memcordon_testkit::run_with_deadline_output_limit(
            &mut locate,
            locate_budget,
            16 * 1024,
        )
        .map_err(|error| CiError::Message(error.to_string()))?;
        if !located.status.success() {
            return Err(CiError::Message(
                "locked native Rust compiler is unavailable".into(),
            ));
        }
        let compiler = PathBuf::from(
            std::str::from_utf8(&located.stdout)
                .map_err(|error| CiError::Message(error.to_string()))?
                .trim(),
        );
        if !compiler.is_absolute() {
            return Err(CiError::Message(
                "locked compiler resolved to a nonabsolute path".into(),
            ));
        }
        let version_budget = provision_budget(work_deadline)?;
        let mut version = CommandSpec::new(&compiler, root, version_budget)
            .arg("-vV")
            .materialize()?;
        let version = memcordon_testkit::run_with_deadline_output_limit(
            &mut version,
            version_budget,
            16 * 1024,
        )
        .map_err(|error| CiError::Message(error.to_string()))?;
        let text = std::str::from_utf8(&version.stdout)
            .map_err(|error| CiError::Message(error.to_string()))?;
        if !version.status.success()
            || !text
                .lines()
                .any(|line| line.strip_prefix("release: ") == Some(locked.as_str()))
            || !text
                .lines()
                .any(|line| line.strip_prefix("host: ") == Some(config.target.as_str()))
        {
            return Err(CiError::Message(
                "locked compiler version/native host differs from selected channel target".into(),
            ));
        }
        fs::write(
            directory.join("windows-toolchain-version.txt"),
            &version.stdout,
        )?;
        let sources = std::path::absolute(root)?
            .join("crates")
            .join("memcordon-cli")
            .join("tests")
            .join("fixtures")
            .join("windows_readiness");
        let (native_work_cutoff_ticks, native_work_frequency) =
            memcordon_testkit::windows_native_work_cutoff(work_deadline)?;
        let mut toolchain = descriptor::Toolchain {
            native_work_cutoff_ticks,
            native_work_frequency,
            linker_mode: descriptor::LinkerMode::BundledLldLink,
            input_root: PathBuf::new(),
            rustc: compiler,
            native_linker: PathBuf::new(),
            selected_images: Vec::new(),
            native_library_directories: Vec::new(),
            library_source: sources.join("library.rs"),
            test_source: sources.join("tests.rs"),
            child_source: sources.join("child.rs"),
            dll_source: sources.join("dll.rs"),
            loader_source: sources.join("loader.rs"),
            target: config.target.clone(),
        };
        let mut measured = Vec::new();
        for path in [
            &toolchain.rustc,
            &toolchain.library_source,
            &toolchain.test_source,
            &toolchain.child_source,
            &toolchain.dll_source,
            &toolchain.loader_source,
        ] {
            let bytes = read(path, 64 * 1024 * 1024)?;
            measured.push(crate::windows_installed_cases::SelectedArtifact {
                path: path.clone(),
                sha256: crate::windows_causal_acceptance::sha256(&bytes),
            });
        }
        let measurement = serde_json::to_vec_pretty(&measured)?;
        fs::write(
            directory.join("windows-toolchain-inputs.json"),
            &measurement,
        )?;
        let snapshot_budget = provision_budget(work_deadline)?;
        let mut snapshot = CommandSpec::new(&config.fixture.path, &directory, snapshot_budget)
            .args(["consumer-readiness-windows", "token-snapshot"])
            .materialize()?;
        let snapshot = memcordon_testkit::run_with_deadline_output_limit(
            &mut snapshot,
            snapshot_budget,
            16 * 1024,
        )
        .map_err(|error| CiError::Message(error.to_string()))?;
        if !snapshot.status.success() {
            return Err(CiError::Message(
                "native caller SID observation failed".into(),
            ));
        }
        let token: TokenObservation = serde_json::from_slice(&snapshot.stdout)?;
        let sid = sid_text(&token.user_sid)?;
        let input_acl = format!("D:P(A;OICI;GA;;;{sid})(A;OICI;GRGX;;;RC)(A;OICI;GA;;;SY)");
        set_directory_acl(&directory, &input_acl)?;
        // Executable files have effective authority but no child inheritance.
        // Keep the same ordered principals and rights as the input directory.
        let image_acl = format!("D:P(A;;GA;;;{sid})(A;;GRGX;;;RC)(A;;GA;;;SY)");
        for image in [&config.cli.path, &config.fixture.path] {
            set_directory_acl(image, &image_acl)?;
        }
        let owned_inputs = directory.join("locked-inputs");
        fs::create_dir(&owned_inputs)?;
        let compiler_root = toolchain
            .rustc
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| {
                CiError::Message("locked native compiler has no toolchain root".into())
            })?;
        let copied_compiler = owned_inputs.join("toolchain");
        let mut copied_measurements = Vec::new();
        copy_owned_inputs(
            compiler_root,
            &copied_compiler,
            &mut copied_measurements,
            work_deadline,
        )?;
        toolchain.rustc = copied_compiler.join("bin").join("rustc.exe");
        let (_measured_msvc_linker, libraries) = provision_native_linker(
            config,
            &owned_inputs,
            &mut copied_measurements,
            work_deadline,
        )?;
        toolchain.input_root = owned_inputs.clone();
        toolchain.native_linker = copied_compiler
            .join("lib")
            .join("rustlib")
            .join(&toolchain.target)
            .join("bin")
            .join("rust-lld.exe");
        toolchain.native_library_directories = libraries;
        verify_native_pe(&toolchain.rustc, &toolchain.target)?;
        verify_native_pe(&toolchain.native_linker, &toolchain.target)?;
        let copied_sources = owned_inputs.join("sources");
        fs::create_dir(&copied_sources)?;
        for source in [
            &mut toolchain.library_source,
            &mut toolchain.test_source,
            &mut toolchain.child_source,
            &mut toolchain.dll_source,
            &mut toolchain.loader_source,
        ] {
            provision_budget(work_deadline)?;
            let destination = copied_sources.join(
                source
                    .file_name()
                    .ok_or_else(|| CiError::Message("native source name missing".into()))?,
            );
            let bytes = read(source, 1024 * 1024)?;
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&destination)?
                .write_all(&bytes)?;
            let persisted = read(&destination, 1024 * 1024)?;
            if persisted != bytes {
                return Err(CiError::Message(
                    "copied native source readback differs".into(),
                ));
            }
            copied_measurements.push(crate::windows_installed_cases::SelectedArtifact {
                path: destination.clone(),
                sha256: crate::windows_causal_acceptance::sha256(&persisted),
            });
            *source = destination;
        }
        toolchain.selected_images = descriptor::project_toolchain_images(
            copied_measurements
                .iter()
                .map(|image| (image.path.clone(), image.sha256.clone())),
        )
        .map_err(CiError::Message)?;
        toolchain
            .validate_selected_images()
            .map_err(CiError::Message)?;
        fs::write(
            directory.join("windows-owned-inputs.json"),
            serde_json::to_vec_pretty(&copied_measurements)?,
        )?;
        let request = memcordon_core::workload_request::WorkloadRequestV1::parse(br#"{"format":"memcordon.workload-request","revision":1,"runtime":{"kind":"windows-sealed","profile":"windows-sealed-current-token-v1"},"requirements":[]}"#).map_err(|error| CiError::Message(error.to_string()))?;
        let template = directory.join("windows-request-template.json");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&template)?
            .write_all(
                &request
                    .canonical_bytes()
                    .map_err(|error| CiError::Message(error.to_string()))?,
            )?;
        let candidate = directory.join("candidate-outputs");
        fs::create_dir(&candidate)?;
        let provider_root = config
            .installed_agent
            .path
            .parent()
            .ok_or_else(|| CiError::Message("installed agent root missing".into()))?;
        let driver_probe = directory.join("protected-driver-probe");
        let provider_probe = provider_root.join("protected-readiness-probe");
        fs::create_dir(&driver_probe)?;
        let candidate_acl = format!("D:P(A;OICI;GA;;;{sid})(A;OICI;GA;;;RC)(A;OICI;GA;;;SY)");
        let protected_acl =
            format!("D:P(D;OICI;GW;;;RC)(A;OICI;GA;;;{sid})(A;OICI;GRGX;;;RC)(A;OICI;GA;;;SY)");
        set_directory_acl(&candidate, &candidate_acl)?;
        set_directory_acl(&driver_probe, &protected_acl)?;
        fs::write(
            directory.join("windows-readiness-acl.json"),
            serde_json::to_vec_pretty(&[
                (&candidate, &candidate_acl),
                (&driver_probe, &protected_acl),
                (&provider_probe, &protected_acl),
            ])?,
        )?;
        let plan = WindowsReadinessPlan {
            request_template: template,
            toolchain,
            candidate_output_root: candidate,
            protected_write_probes: vec![
                driver_probe.join("denied-write.bin"),
                provider_probe.join("denied-write.bin"),
            ],
        };
        prepare(
            config,
            &plan,
            &directory.join("windows-readiness-input.json"),
            work_deadline,
        )
    }

    fn copy_owned_inputs(
        source: &Path,
        destination: &Path,
        measured: &mut Vec<crate::windows_installed_cases::SelectedArtifact>,
        work_deadline: Instant,
    ) -> Result<()> {
        provision_budget(work_deadline)?;
        if destination.components().count() > 256 {
            return Err(CiError::Message(
                "owned native input depth exceeds bound".into(),
            ));
        }
        if measured.len() > 200_000 {
            return Err(CiError::Message(
                "owned native input file count exceeds bound".into(),
            ));
        }
        let metadata = fs::symlink_metadata(source)?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(CiError::Message(
                "owned native inputs cannot follow reparse points".into(),
            ));
        }
        if metadata.is_dir() {
            fs::create_dir(destination)?;
            for entry in fs::read_dir(source)? {
                let entry = entry?;
                copy_owned_inputs(
                    &entry.path(),
                    &destination.join(entry.file_name()),
                    measured,
                    work_deadline,
                )?;
            }
        } else if metadata.is_file() {
            let bytes = read(source, 512 * 1024 * 1024)?;
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(destination)?
                .write_all(&bytes)?;
            let persisted = read(destination, 512 * 1024 * 1024)?;
            if persisted != bytes {
                return Err(CiError::Message(
                    "copied native toolchain input readback differs".into(),
                ));
            }
            measured.push(crate::windows_installed_cases::SelectedArtifact {
                path: destination.to_owned(),
                sha256: crate::windows_causal_acceptance::sha256(&persisted),
            });
        } else {
            return Err(CiError::Message(
                "native toolchain input is not an ordinary file/directory".into(),
            ));
        }
        Ok(())
    }

    #[allow(unsafe_code)] // Read-only bounded native registry discovery; no ambient environment lookup.
    fn registry_text(key: &str, value: &str, view: u32) -> Result<String> {
        use windows_sys::Win32::System::Registry::{
            HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RegGetValueW,
        };
        let key: Vec<_> = key.encode_utf16().chain(Some(0)).collect();
        let value: Vec<_> = value.encode_utf16().chain(Some(0)).collect();
        let mut buffer = vec![0u16; 16_384];
        let mut bytes = (buffer.len() * 2) as u32;
        // SAFETY: held bounded writable UTF-16 buffer and terminated read-only registry names.
        let status = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_SZ | view,
                std::ptr::null_mut(),
                buffer.as_mut_ptr().cast(),
                &mut bytes,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32).into());
        }
        if bytes < 2 || bytes as usize > buffer.len() * 2 || bytes % 2 != 0 {
            return Err(CiError::Message(
                "native registry text exceeds bound".into(),
            ));
        }
        buffer.truncate(bytes as usize / 2);
        if buffer.pop() != Some(0) || buffer.contains(&0) {
            return Err(CiError::Message(
                "native registry text lacks exact terminator".into(),
            ));
        }
        String::from_utf16(&buffer).map_err(|error| CiError::Message(error.to_string()))
    }

    fn verify_native_pe(path: &Path, target: &str) -> Result<()> {
        use std::io::{Read, Seek, SeekFrom};
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let mut dos = [0u8; 64];
        file.read_exact(&mut dos)?;
        if &dos[..2] != b"MZ" {
            return Err(CiError::Message(
                "native compiler/linker lacks a DOS PE header".into(),
            ));
        }
        let offset = u32::from_le_bytes(dos[60..64].try_into().expect("fixed PE header width"));
        if u64::from(offset) > file.metadata()?.len().saturating_sub(6) {
            return Err(CiError::Message(
                "native compiler/linker PE header offset exceeds held input".into(),
            ));
        }
        file.seek(SeekFrom::Start(u64::from(offset)))?;
        let mut header = [0u8; 6];
        file.read_exact(&mut header)?;
        let expected = match target {
            "x86_64-pc-windows-msvc" => 0x8664u16,
            "aarch64-pc-windows-msvc" => 0xaa64u16,
            _ => {
                return Err(CiError::Message(
                    "unsupported native toolchain PE target".into(),
                ));
            }
        };
        if &header[..4] != b"PE\0\0" || u16::from_le_bytes([header[4], header[5]]) != expected {
            return Err(CiError::Message(
                "measured compiler/linker PE machine differs from native target".into(),
            ));
        }
        Ok(())
    }

    fn provision_native_linker(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        inputs: &Path,
        measured: &mut Vec<crate::windows_installed_cases::SelectedArtifact>,
        work_deadline: Instant,
    ) -> Result<(PathBuf, Vec<PathBuf>)> {
        use windows_sys::Win32::System::Registry::RRF_SUBKEY_WOW6432KEY;
        let program_files = PathBuf::from(registry_text(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion",
            "ProgramFilesDir (x86)",
            0,
        )?);
        let vswhere = program_files
            .join("Microsoft Visual Studio")
            .join("Installer")
            .join("vswhere.exe");
        if !vswhere.is_absolute() {
            return Err(CiError::Message(
                "native VS discovery path is not absolute".into(),
            ));
        }
        let bytes = read(&vswhere, 16 * 1024 * 1024)?;
        measured.push(crate::windows_installed_cases::SelectedArtifact {
            path: vswhere.clone(),
            sha256: crate::windows_causal_acceptance::sha256(&bytes),
        });
        let discover_budget = provision_budget(work_deadline)?;
        let mut discover = CommandSpec::new(&vswhere, &config.output_directory, discover_budget)
            .args([
                "-latest",
                "-products",
                "*",
                "-requires",
                "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                "-property",
                "installationPath",
                "-utf8",
            ])
            .materialize()?;
        let output = memcordon_testkit::run_with_deadline_output_limit(
            &mut discover,
            discover_budget,
            16 * 1024,
        )
        .map_err(|error| CiError::Message(error.to_string()))?;
        if !output.status.success() || !output.stderr.is_empty() {
            return Err(CiError::Message("native VS discovery failed".into()));
        }
        fs::write(
            config.output_directory.join("windows-vs-discovery.txt"),
            &output.stdout,
        )?;
        let installation = PathBuf::from(
            std::str::from_utf8(&output.stdout)
                .map_err(|error| CiError::Message(error.to_string()))?
                .trim(),
        );
        if !installation.is_absolute() {
            return Err(CiError::Message("native VS installation missing".into()));
        }
        let version_bytes = read(
            &installation
                .join("VC")
                .join("Auxiliary")
                .join("Build")
                .join("Microsoft.VCToolsVersion.default.txt"),
            1024,
        )?;
        let version = std::str::from_utf8(&version_bytes)
            .map_err(|error| CiError::Message(error.to_string()))?
            .trim();
        if version.is_empty()
            || !version
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.')
        {
            return Err(CiError::Message(
                "native VC toolset version is invalid".into(),
            ));
        }
        let architecture = match config.target.as_str() {
            "x86_64-pc-windows-msvc" => "x64",
            "aarch64-pc-windows-msvc" => "arm64",
            _ => return Err(CiError::Message("unsupported native linker target".into())),
        };
        let toolset = installation
            .join("VC")
            .join("Tools")
            .join("MSVC")
            .join(version);
        let linker_root = toolset
            .join("bin")
            .join(format!("Host{architecture}"))
            .join(architecture);
        let linker = inputs.join("msvc-bin");
        copy_owned_inputs(&linker_root, &linker, measured, work_deadline)?;
        let vc_library = inputs.join("msvc-lib");
        copy_owned_inputs(
            &toolset.join("lib").join(architecture),
            &vc_library,
            measured,
            work_deadline,
        )?;
        let sdk = PathBuf::from(registry_text(
            r"SOFTWARE\Microsoft\Windows Kits\Installed Roots",
            "KitsRoot10",
            RRF_SUBKEY_WOW6432KEY,
        )?);
        if !sdk.is_absolute() {
            return Err(CiError::Message("native SDK root is not absolute".into()));
        }
        let mut versions = Vec::new();
        for entry in fs::read_dir(sdk.join("Lib"))? {
            provision_budget(work_deadline)?;
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let numbers: Option<Vec<u32>> = name.split('.').map(|part| part.parse().ok()).collect();
            if let Some(numbers) = numbers.filter(|numbers| numbers.len() == 4) {
                if versions.len() > 256 {
                    return Err(CiError::Message(
                        "native SDK version list exceeds bound".into(),
                    ));
                }
                versions.push((numbers, entry.path()));
            }
        }
        versions.sort_by(|left, right| left.0.cmp(&right.0));
        let selected = versions
            .pop()
            .ok_or_else(|| CiError::Message("native SDK libraries unavailable".into()))?
            .1;
        let ucrt = inputs.join("sdk-ucrt");
        copy_owned_inputs(
            &selected.join("ucrt").join(architecture),
            &ucrt,
            measured,
            work_deadline,
        )?;
        let um = inputs.join("sdk-um");
        copy_owned_inputs(
            &selected.join("um").join(architecture),
            &um,
            measured,
            work_deadline,
        )?;
        Ok((linker.join("link.exe"), vec![vc_library, ucrt, um]))
    }

    pub fn cleanup_provider_probe(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
    ) -> Result<()> {
        let provider_root = config
            .installed_agent
            .path
            .parent()
            .ok_or_else(|| CiError::Message("installed agent root missing".into()))?;
        let probe = provider_root.join("protected-readiness-probe");
        if !probe.try_exists()? {
            return Ok(());
        }
        let input: SuiteInput = serde_json::from_slice(&read(
            &config.output_directory.join("windows-readiness-input.json"),
            4 * 1024 * 1024,
        )?)?;
        validate_suite(&input)?;
        let caller = input
            .cases
            .iter()
            .find(|case| case.key.scenario == "ordinary")
            .ok_or_else(|| CiError::Message("owned caller missing for probe cleanup".into()))?;
        let sid = sid_text(&caller.expected_token.user_sid)?;
        set_directory_acl(&probe, &format!("D:P(A;OICI;GA;;;{sid})(A;OICI;GA;;;SY)"))?;
        // Only the explicitly owned empty probe directory is removed. A probe
        // write that unexpectedly succeeded remains evidence and makes this fail.
        fs::remove_dir(probe)?;
        Ok(())
    }

    pub(crate) fn prepare_owned_probe_image(path: &Path, caller_sid: &[u8]) -> Result<()> {
        let sid = sid_text(caller_sid)?;
        set_directory_acl(
            path,
            &format!("D:P(A;;GA;;;{sid})(A;;GRGX;;;RC)(A;;GA;;;SY)"),
        )
    }

    #[allow(unsafe_code)] // Native ACL installation/readback only on explicitly owned paths.
    fn set_directory_acl(path: &Path, sddl: &str) -> Result<()> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
            SE_FILE_OBJECT, SetNamedSecurityInfoW,
        };
        use windows_sys::Win32::Security::{
            DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
            IsValidAcl, PROTECTED_DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED,
        };
        let sddl: Vec<_> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut security = std::ptr::null_mut();
        // SAFETY: terminated explicit SDDL and writable native output pointer.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut security,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        let operation = (|| -> Result<()> {
            let mut present = 0;
            let mut defaulted = 0;
            let mut acl = std::ptr::null_mut();
            // SAFETY: successful conversion owns a valid descriptor until LocalFree.
            if unsafe {
                GetSecurityDescriptorDacl(security, &mut present, &mut acl, &mut defaulted)
            } == 0
                || present == 0
                || acl.is_null()
            {
                return Err(CiError::Message(
                    "explicit readiness ACL did not contain a DACL".into(),
                ));
            }
            let mut name: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            // SAFETY: owned setup directory, exact parsed DACL, terminated mutable path.
            let status = unsafe {
                SetNamedSecurityInfoW(
                    name.as_mut_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    acl,
                    std::ptr::null_mut(),
                )
            };
            if status != 0 {
                return Err(io::Error::from_raw_os_error(status as i32).into());
            }
            let mut actual_acl = std::ptr::null_mut();
            let mut actual_security = std::ptr::null_mut();
            // SAFETY: same exact owned path; API allocates the returned descriptor.
            let status = unsafe {
                GetNamedSecurityInfoW(
                    name.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut actual_acl,
                    std::ptr::null_mut(),
                    &mut actual_security,
                )
            };
            if status != 0 {
                return Err(io::Error::from_raw_os_error(status as i32).into());
            }
            let mut control = 0;
            let mut revision = 0;
            // SAFETY: descriptor/ACL pointers are owned API outputs, valid until
            // LocalFree. Native validation precedes every bounded ACL slice.
            let comparison = unsafe {
                if actual_acl.is_null() || IsValidAcl(acl) == 0 || IsValidAcl(actual_acl) == 0 {
                    Err("native readiness DACL is absent or malformed".to_owned())
                } else if GetSecurityDescriptorControl(actual_security, &mut control, &mut revision)
                    == 0
                {
                    Err(io::Error::last_os_error().to_string())
                } else {
                    crate::windows_readiness_acl::verify_file_dacl(
                        std::slice::from_raw_parts(acl.cast::<u8>(), (*acl).AclSize as usize),
                        std::slice::from_raw_parts(
                            actual_acl.cast::<u8>(),
                            (*actual_acl).AclSize as usize,
                        ),
                        control & SE_DACL_PROTECTED != 0,
                    )
                }
            };
            // SAFETY: GetNamedSecurityInfoW allocated this independent descriptor.
            unsafe { LocalFree(actual_security) };
            comparison.map_err(|detail| {
                let bytes = path.as_os_str().as_encoded_bytes();
                let object = String::from_utf8_lossy(&bytes[..bytes.len().min(512)]);
                let object_type = match fs::symlink_metadata(path) {
                    Ok(metadata) if metadata.is_dir() => "directory",
                    Ok(metadata) if metadata.is_file() => "file",
                    Ok(_) => "other",
                    Err(_) => "unavailable",
                };
                CiError::Message(format!(
                    "native readiness directory DACL readback differs: {detail}; object={object:?}; object-path-truncated={}; object-type={object_type}",
                    bytes.len() > 512,
                ))
            })?;
            Ok(())
        })();
        // SAFETY: conversion allocated this one security descriptor with LocalAlloc.
        unsafe { LocalFree(security) };
        operation
    }

    #[allow(unsafe_code)] // Bounded aligned SID conversion with native allocation ownership.
    fn sid_text(bytes: &[u8]) -> Result<String> {
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
        super::start_gate_policy::validate_sid(bytes)?;
        let mut aligned = vec![0u32; bytes.len().div_ceil(std::mem::size_of::<u32>())];
        // SAFETY: aligned allocation covers the full bounded SID byte representation.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), aligned.as_mut_ptr().cast(), bytes.len())
        };
        // Extent is checked before either native function may inspect the SID.
        if unsafe { windows_sys::Win32::Security::IsValidSid(aligned.as_mut_ptr().cast()) } == 0
            || unsafe { windows_sys::Win32::Security::GetLengthSid(aligned.as_mut_ptr().cast()) }
                as usize
                != bytes.len()
        {
            return Err(CiError::Message(
                "selected caller native SID validity or length differs".into(),
            ));
        }
        let mut text = std::ptr::null_mut();
        // SAFETY: bounded SID observed from the held native caller token.
        if unsafe { ConvertSidToStringSidW(aligned.as_mut_ptr().cast(), &mut text) } == 0 {
            return Err(io::Error::last_os_error().into());
        }
        let mut length = 0usize;
        // SAFETY: successful conversion guarantees a terminated native SID string.
        let authority_width = ((1u64 << (bytes[2..8].len() * 8)) - 1)
            .to_string()
            .len()
            .max("0x".len() + bytes[2..8].len() * 2);
        let text_bound = "S-1-".len()
            + authority_width
            + usize::from(bytes[1]) * ("-".len() + u32::MAX.to_string().len())
            + 1;
        while length < text_bound && unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        let converted = if length == text_bound {
            Err(CiError::Message(
                "native caller SID string exceeds bound".into(),
            ))
        } else {
            String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
                .map_err(|error| CiError::Message(error.to_string()))
        };
        // SAFETY: conversion allocated this string with LocalAlloc.
        unsafe { LocalFree(text.cast()) };
        converted
    }

    fn bounded_vec<T, const N: usize>(values: Vec<T>) -> Result<memcordon_core::BoundedVec<T, N>> {
        let mut result = memcordon_core::BoundedVec::default();
        for value in values {
            result.try_push(value).map_err(|_| {
                CiError::Message("readiness collection exceeds its declared bound".into())
            })?;
        }
        Ok(result)
    }

    pub fn prepare(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        plan: &WindowsReadinessPlan,
        input_path: &Path,
        work_deadline: Instant,
    ) -> Result<()> {
        if !plan.candidate_output_root.is_absolute() || plan.protected_write_probes.len() < 2 {
            return Err(CiError::Message(
                "native Windows plan must grant a candidate root and protect driver/provider paths"
                    .into(),
            ));
        }
        // Observe each actual native caller context outside target execution.
        let snapshot = |restricted: bool| -> Result<TokenObservation> {
            let mut args: Vec<OsString> = vec!["consumer-readiness-windows".into()];
            if restricted {
                args.extend([
                    "restricted-frontend".into(),
                    config.fixture.path.clone().into_os_string(),
                    "consumer-readiness-windows".into(),
                ]);
            }
            args.push("token-snapshot".into());
            let budget = provision_budget(work_deadline)?;
            let mut command =
                CommandSpec::new(&config.fixture.path, &config.output_directory, budget)
                    .args(args)
                    .materialize()?;
            command.env_clear();
            let output =
                memcordon_testkit::run_with_deadline_output_limit(&mut command, budget, 16 * 1024)
                    .map_err(|error| CiError::Message(error.to_string()))?;
            crate::release::source::write_diagnostic_json(
                &config.output_directory.join(if restricted {
                    "windows-restricted-token-capture.json"
                } else {
                    "windows-ordinary-token-capture.json"
                }),
                &serde_json::json!({
                    "format":"memcordon.windows-caller-token-capture",
                    "revision":1,
                    "restricted":restricted,
                    "program_debug":format!("{:?}",command.get_program()),
                    "arguments_debug":command.get_args().map(|argument|format!("{argument:?}")).collect::<Vec<_>>(),
                    "status":output.status.code(),
                    "success":output.status.success(),
                    "stdout":output.stdout,
                    "stderr":output.stderr,
                }),
            )?;
            if !output.status.success() || !output.stderr.is_empty() {
                return Err(CiError::Message(
                    crate::windows_caller_snapshot_diagnostic::failure(
                        restricted,
                        output.status.code(),
                        &output.stdout,
                        &output.stderr,
                    ),
                ));
            }
            let token: TokenObservation = serde_json::from_slice(&output.stdout)?;
            if token.restricted != restricted {
                return Err(CiError::Message(
                    "native caller restriction differs from required variant".into(),
                ));
            }
            if restricted
                && token.restricting_sids != vec![vec![1, 1, 0, 0, 0, 0, 0, 5, 12, 0, 0, 0]]
            {
                return Err(CiError::Message("native restricted caller does not use the independently granted RestrictedCode principal".into()));
            }
            let path = config.output_directory.join(if restricted {
                "windows-restricted-token.json"
            } else {
                "windows-ordinary-token.json"
            });
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?;
            file.write_all(&output.stdout)?;
            file.sync_all()?;
            if read(&path, 16 * 1024)? != output.stdout {
                return Err(CiError::Message(
                    "caller token named readback differs".into(),
                ));
            }
            Ok(token)
        };
        let ordinary = snapshot(false)?;
        let restricted = snapshot(true)?;
        let random = random_challenge()?;
        let run = crate::windows_causal_acceptance::sha256(&random);
        let mut cases = Vec::new();
        for key in positive_keys() {
            provision_budget(work_deadline)?;
            let output = plan
                .candidate_output_root
                .join(&key.family)
                .join(&key.scenario);
            let FixtureParameters {
                case,
                stdout,
                stderr,
                arguments,
                application_status: status,
            } = fixture_parameters(&key)?;
            let event_stem = format!(
                "Local\\memcordon-readiness-{run}-{}-{}",
                key.family, key.scenario
            );
            let start_gate = Some(event_stem.clone());
            let descendant_gate = matches!(
                case,
                descriptor::Case::RootFirst | descriptor::Case::IntermediateFirst
            )
            .then(|| {
                PathBuf::from(&event_stem)
                    .with_extension("descendant")
                    .to_string_lossy()
                    .into_owned()
            });
            let caller = if matches!(
                key.scenario.as_str(),
                "restricted" | "restricted-token-preserved"
            ) {
                restricted.clone()
            } else {
                ordinary.clone()
            };
            let descriptor = descriptor::Descriptor {
                format: "memcordon.fixture-workload".into(),
                revision: descriptor::DESCRIPTOR_REVISION,
                case,
                output_root: output.clone(),
                transcript: output.join("fixture-events.bin"),
                challenge: random_challenge()?.to_vec(),
                stdout,
                stderr,
                arguments,
                application_status: status,
                churn_creations: descriptor::CHURN_CREATIONS,
                churn_live: descriptor::CHURN_LIVE,
                denied_write_paths: if matches!(
                    key.scenario.as_str(),
                    "restricted" | "restricted-token-preserved"
                ) {
                    plan.protected_write_probes.clone()
                } else {
                    Vec::new()
                },
                sentinel_handles: Vec::new(),
                descendant_gate,
                start_gate,
                gate_access_diagnostic: None,
                completion_gate: None,
                cohort_gate: (case == descriptor::Case::Churn)
                    .then(|| format!("{event_stem}-cohort")),
                generation_gate: (case == descriptor::Case::Churn)
                    .then(|| format!("{event_stem}-generation")),
                toolchain: matches!(
                    case,
                    descriptor::Case::Toolchain | descriptor::Case::Joint | descriptor::Case::Churn
                )
                .then(|| plan.toolchain.clone()),
            };
            validate_descriptor(&key, &descriptor)?;
            cases.push(CaseInput {
                key,
                descriptor,
                descriptor_path: output.with_extension("input.json"),
                workload_request: plan.request_template.clone(),
                expected_token: caller,
            });
        }
        // The sentinel frontend creates/holds the exact native file and adds its
        // identity to the descriptor before launching the actual public frontend.
        let suite = SuiteInput {
            format: "memcordon.windows-readiness-input".into(),
            revision: 2,
            cases,
        };
        let bytes = serde_json::to_vec_pretty(&suite)?;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(input_path)?
            .write_all(&bytes)?;
        Ok(())
    }

    pub(crate) fn read(path: &Path, bound: usize) -> Result<Vec<u8>> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || metadata.len() > bound as u64
        {
            return Err(CiError::Message(
                "readiness evidence is not a bounded ordinary file".into(),
            ));
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take((bound + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > bound {
            return Err(CiError::Message(
                "readiness evidence exceeded bound during read".into(),
            ));
        }
        Ok(bytes)
    }

    fn retain_callback_product_context(
        public_report: &Path,
        report: &Path,
        provider: &memcordon_core::PublicProviderBindingV1,
    ) -> Result<serde_json::Value> {
        if !public_report.try_exists()? {
            return Ok(serde_json::json!({"authority":"diagnostic-only", "result":"absent"}));
        }
        let bytes = read(
            public_report,
            crate::windows_causal_acceptance::MAX_REPORT_BYTES,
        )?;
        let result = ResultV3::parse(&bytes).map_err(CiError::Message)?;
        let association = super::current_association(&result)?;
        if &association.provider != provider {
            return Err(CiError::Message(
                "callback product context provider differs".into(),
            ));
        }
        let retain = |extension: &str, bytes: &[u8]| -> Result<serde_json::Value> {
            let path = report.with_extension(extension);
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            if read(&path, bytes.len())? != bytes {
                return Err(CiError::Message(
                    "callback product context copy differs".into(),
                ));
            }
            Ok(
                serde_json::json!({"path":path,"sha256":crate::windows_causal_acceptance::sha256(bytes)}),
            )
        };
        // Preserve the original independently of any sidecar read or validation error.
        let original = retain("failed-frontend.json", &bytes)?;
        let terminal_context = (|| -> Result<serde_json::Value> {
            let path = public_report.with_extension("terminal-observation.json");
            if !path.try_exists()? {
                return Ok(serde_json::json!({"state":"absent"}));
            }
            let bytes = read(&path, memcordon_platform::MAX_TERMINAL_OBSERVATION_BYTES)?;
            let terminal: memcordon_platform::AuthenticatedWindowsTerminalObservation =
                serde_json::from_slice(&bytes)?;
            if terminal.format != "memcordon.windows-terminal-observation"
                || terminal.revision != 2
                || terminal.provider != association.provider
                || terminal.terminal.attempt_id != String::from(association.attempt_id.clone())
                || terminal.terminal.request_sha256
                    != String::from(association.request_sha256.clone())
                || terminal.terminal.validate_for_attempt().is_err()
                || !terminal.frontend_delivery.is_consistent()
                || terminal.frontend_delivery.attempt_id != terminal.terminal.attempt_id
                || terminal.frontend_delivery.nonce != terminal.terminal.nonce
                || terminal.frontend_delivery.request_sha256 != terminal.terminal.request_sha256
                || crate::windows_causal_acceptance::sha256(&terminal.provider_request)
                    != terminal.terminal.request_sha256
            {
                return Err(CiError::Message(
                    "callback terminal context association differs".into(),
                ));
            }
            retain("failed-terminal-observation.json", &bytes)
        })()
        .map_err(|error| error.to_string());
        Ok(
            serde_json::json!({"authority":"diagnostic-only", "original":original,
            "terminal":terminal_context, "terminal_use":"associated context, never outcome acceptance"}),
        )
    }

    #[allow(unsafe_code)] // Fixed-size native cryptographic challenge generation.
    pub(crate) fn random_challenge() -> Result<[u8; 32]> {
        let mut random = [0u8; 32];
        // SAFETY: fixed writable output buffer and system-preferred native RNG.
        if unsafe {
            windows_sys::Win32::Security::Cryptography::BCryptGenRandom(
                std::ptr::null_mut(),
                random.as_mut_ptr(),
                random.len() as u32,
                windows_sys::Win32::Security::Cryptography::BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        } < 0
        {
            return Err(CiError::Message(
                "fresh readiness challenge generation failed".into(),
            ));
        }
        if random.iter().all(|byte| *byte == 0) {
            return Err(CiError::Message(
                "native readiness challenge was all zero".into(),
            ));
        }
        Ok(random)
    }

    const CONTROLLER_GATE_SDDL: &str = super::start_gate_policy::BASE_SDDL;

    struct PreparedGateInput {
        input: CaseInput,
        gate: Arc<OwnedHandle>,
        prelaunch_security: serde_json::Value,
        prelaunch_label: serde_json::Value,
        binding_setup: serde_json::Value,
        original_descriptor_sha256: Option<String>,
        requested_sddl: String,
        namespace: Option<super::gate_namespace::Discovery>,
    }

    fn prepare_gate_input(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        input: &CaseInput,
        work_deadline: Instant,
    ) -> Result<PreparedGateInput> {
        let name = input.descriptor.start_gate.as_ref().ok_or_else(|| {
            CiError::Message("positive input omitted held-root native barrier".into())
        })?;
        provision_budget(work_deadline)?;
        let observed_path = config
            .output_directory
            .join(if input.expected_token.restricted {
                "windows-restricted-token.json"
            } else {
                "windows-ordinary-token.json"
            });
        let selected: TokenObservation = serde_json::from_slice(&read(&observed_path, 16 * 1024)?)?;
        if selected != input.expected_token {
            return Err(CiError::Message(
                "start-gate waiter differs from original selected native caller observation".into(),
            ));
        }
        provision_budget(work_deadline)?;
        let (gate, requested_sddl) = start_gate_create(name, &selected.user_sid, work_deadline)?;
        let gate = Arc::new(gate);
        let mut final_input = input.clone();
        // Serialized suite input is a plan, never a substitute descriptor owner.
        final_input.descriptor.gate_access_diagnostic = None;
        let mut prelaunch_security =
            serde_json::json!({"state":"unavailable","reason":"comparison-not-requested"});
        let mut binding_setup = prelaunch_security.clone();
        let mut original_descriptor_sha256 = None;
        let mut prelaunch_label =
            serde_json::json!({"state":"unavailable","reason":"comparison-not-requested"});
        let mut namespace = None;
        if super::start_gate_policy::capture_restricted_gate(&input.key.family, &input.key.scenario)
        {
            prelaunch_label =
                gate_query_result(super::workload_diagnostic::gate_mandatory_label_snapshot(
                    gate.as_ref(),
                    work_deadline,
                ));
            match super::workload_diagnostic::gate_security_snapshot(gate.as_ref(), work_deadline) {
                Ok(snapshot) => {
                    original_descriptor_sha256 = Some(snapshot.descriptor_sha256.clone());
                    let binding = (|| -> io::Result<descriptor::gate_access::Input> {
                        let bytes = hex::decode(&snapshot.descriptor_bytes_hex).map_err(|_| {
                            io::Error::other("original held gate descriptor encoding differs")
                        })?;
                        let name: Vec<u16> = name.encode_utf16().collect();
                        let name_bytes: Vec<u8> =
                            name.iter().flat_map(|unit| unit.to_le_bytes()).collect();
                        let (work_cutoff_qpc, qpc_frequency) =
                            memcordon_testkit::windows_native_work_cutoff(work_deadline)?;
                        let binding = descriptor::gate_access::Input {
                            revision: 1,
                            descriptor: bytes,
                            descriptor_sha256: snapshot.descriptor_sha256.clone(),
                            name_utf16_sha256: crate::windows_causal_acceptance::sha256(
                                &name_bytes,
                            ),
                            challenge_sha256: crate::windows_causal_acceptance::sha256(
                                &input.descriptor.challenge,
                            ),
                            work_cutoff_qpc,
                            qpc_frequency,
                            namespace: None,
                        };
                        binding.validate(&name, &input.descriptor.challenge)?;
                        Ok(binding)
                    })();
                    match binding {
                        Ok(mut binding) => {
                            let name: Vec<u16> = name.encode_utf16().collect();
                            let discovered = super::gate_namespace::discover(
                                gate.as_ref(),
                                &name,
                                &binding,
                                || {
                                    provision_budget(work_deadline)
                                        .map(|_| ())
                                        .map_err(io::Error::other)
                                },
                            );
                            binding.namespace = discovered.proof.clone();
                            namespace = Some(discovered);
                            final_input.descriptor.gate_access_diagnostic = Some(binding);
                            binding_setup = serde_json::json!({"state":"observed","source":"same original held event before final descriptor freeze"});
                        }
                        Err(error) => binding_setup = gate_query_result::<()>(Err(error)),
                    }
                    prelaunch_security = gate_query_result(Ok(snapshot));
                }
                Err(error) => {
                    prelaunch_security = gate_query_result::<()>(Err(error));
                    binding_setup = serde_json::json!({"state":"unavailable","reason":"original-snapshot-unavailable"});
                }
            }
        }
        if final_input
            .descriptor
            .gate_access_diagnostic
            .as_ref()
            .is_some_and(|binding| binding.namespace.is_some())
            && serde_json::to_vec(&final_input.descriptor)?.len() > descriptor::MAX_DESCRIPTOR_BYTES
        {
            final_input
                .descriptor
                .gate_access_diagnostic
                .as_mut()
                .expect("checked access input")
                .namespace = None;
        }
        if final_input.descriptor.gate_access_diagnostic.is_some()
            && serde_json::to_vec(&final_input.descriptor)?.len() > descriptor::MAX_DESCRIPTOR_BYTES
        {
            final_input.descriptor.gate_access_diagnostic = None;
            binding_setup = serde_json::json!({"state":"unavailable","reason":"original-descriptor-aggregate-bound"});
        }
        validate_descriptor(&final_input.key, &final_input.descriptor)?;
        Ok(PreparedGateInput {
            input: final_input,
            gate,
            prelaunch_security,
            prelaunch_label,
            binding_setup,
            original_descriptor_sha256,
            requested_sddl,
            namespace,
        })
    }

    fn gate_query_result<T: serde::Serialize>(result: io::Result<T>) -> serde_json::Value {
        match result {
            Ok(value) => match serde_json::to_value(value) {
                Ok(value) => serde_json::json!({"state":"observed","value":value}),
                Err(_) => serde_json::json!({"state":"unavailable","stage":"serialize-query"}),
            },
            Err(error) => {
                serde_json::json!({"state":"unavailable","kind":format!("{:?}",error.kind()),
                "raw_os_error":error.raw_os_error()})
            }
        }
    }

    pub(crate) fn event_create(name: &str) -> Result<OwnedHandle> {
        event_create_with_policy(name, CONTROLLER_GATE_SDDL)
    }

    pub(crate) fn start_gate_create(
        name: &str,
        selected_user: &[u8],
        deadline: Instant,
    ) -> Result<(OwnedHandle, String)> {
        provision_budget(deadline)?;
        let sid = sid_text(selected_user)?;
        let policy = super::start_gate_policy::sddl(selected_user, &sid)?;
        provision_budget(deadline)?;
        let owner = event_create_with_policy(name, &policy)?;
        provision_budget(deadline)?;
        Ok((owner, policy))
    }

    #[allow(unsafe_code)] // Creates only the exclusive owned event with the supplied reviewed role policy.
    fn event_create_with_policy(name: &str, policy: &str) -> Result<OwnedHandle> {
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
        use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
        use windows_sys::Win32::System::Threading::CreateEventW;
        let name: Vec<_> = name.encode_utf16().chain(Some(0)).collect();
        let sddl: Vec<_> = policy.encode_utf16().chain(Some(0)).collect();
        let mut security = std::ptr::null_mut();
        // SAFETY: terminated reviewed event ACL; restricted caller receives wait only.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut security,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: security,
            bInheritHandle: 0,
        };
        // SAFETY: exact terminated nonce name and held native ACL allocation.
        let handle = unsafe { CreateEventW(&attributes, 1, 0, name.as_ptr()) };
        let error = io::Error::last_os_error();
        // SAFETY: descriptor allocated by the conversion API and no longer borrowed.
        unsafe { LocalFree(security) };
        if handle.is_null() {
            return Err(error.into());
        }
        let reused = error.raw_os_error() == Some(183);
        // SAFETY: successful creation transfers one event reference.
        let owned = unsafe { OwnedHandle::from_raw_handle(handle.cast()) };
        if reused {
            return Err(CiError::Message(
                "readiness event name reused an existing resource".into(),
            ));
        }
        Ok(owned)
    }

    #[allow(unsafe_code)] // Signals only the independently held controller event.
    pub(crate) fn signal(event: &OwnedHandle) -> io::Result<()> {
        use windows_sys::Win32::System::Threading::SetEvent;
        // SAFETY: owned manual-reset event remains held through signaling.
        if unsafe { SetEvent(event.as_raw_handle()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    #[allow(unsafe_code)] // Opens only the protected descriptor's exact native event.
    fn descendant_release(name: &str) -> io::Result<()> {
        use windows_sys::Win32::System::Threading::{OpenEventW, SetEvent};
        let name: Vec<_> = name.encode_utf16().chain(Some(0)).collect();
        // SAFETY: opens the exact nonce-bound event published in the protected input.
        let handle = unsafe { OpenEventW(2, 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fresh event reference transfers once.
        let _owned = unsafe { OwnedHandle::from_raw_handle(handle.cast()) };
        // SAFETY: explicit event has EVENT_MODIFY_STATE access.
        if unsafe { SetEvent(handle) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn fixture_products(input: &CaseInput) -> Result<()> {
        let root = &input.descriptor.output_root;
        let bytes: Vec<u8> = (0..=255).collect();
        match input.descriptor.case {
            descriptor::Case::NativeArgv => {
                let actual: serde_json::Value =
                    serde_json::from_slice(&read(&root.join("native-argv.json"), 64 * 1024)?)?;
                let expected = serde_json::json!({
                    "encoding": "windows_utf16",
                    "values": input.descriptor.arguments.iter().map(|argument| argument.encode_utf16().collect::<Vec<_>>()).collect::<Vec<_>>(),
                });
                if actual != expected {
                    return Err(CiError::Message(
                        "independently observed native argv differs from selected arguments".into(),
                    ));
                }
            }
            descriptor::Case::Joint | descriptor::Case::Churn | descriptor::Case::BinaryFiles => {
                if !read(&root.join("nested").join("empty.bin"), 1)?.is_empty()
                    || read(&root.join("nested").join("all-bytes.bin"), 256)? != bytes
                    || read(&root.join("nested").join("challenge.bin"), 4096)?
                        != input.descriptor.challenge
                {
                    return Err(CiError::Message(
                        "independent binary file products differ".into(),
                    ));
                }
                let names: BTreeSet<_> = fs::read_dir(root.join("nested"))?
                    .map(|entry| entry.map(|entry| entry.file_name()))
                    .collect::<io::Result<_>>()?;
                if names
                    != ["empty.bin", "all-bytes.bin", "challenge.bin"]
                        .map(OsString::from)
                        .into_iter()
                        .collect()
                {
                    return Err(CiError::Message(
                        "binary output filenames/count differ".into(),
                    ));
                }
            }
            descriptor::Case::RootFirst | descriptor::Case::IntermediateFirst => {
                if read(&root.join("descendant-output.bin"), 4096)? != input.descriptor.challenge {
                    return Err(CiError::Message(
                        "held descendant failed to produce its independent product".into(),
                    ));
                }
            }
            descriptor::Case::AllowedTokenChange => {
                if read(&root.join("token-change-output.bin"), 4096)? != input.descriptor.challenge
                {
                    return Err(CiError::Message(
                        "allowed token-change descendant byte product differs".into(),
                    ));
                }
            }
            _ => {}
        }
        if matches!(
            input.descriptor.case,
            descriptor::Case::Toolchain | descriptor::Case::Joint | descriptor::Case::Churn
        ) {
            if !read(&root.join("compiled").join("dll-empty.bin"), 1)?.is_empty()
                || read(&root.join("compiled").join("dll-output.bin"), 256)? != bytes
                || read(&root.join("compiled").join("child-output.bin"), 4096)?
                    != input.descriptor.challenge
            {
                return Err(CiError::Message(
                    "independent compiled child/DLL byte products differ".into(),
                ));
            }
        }
        if matches!(
            input.descriptor.case,
            descriptor::Case::Joint | descriptor::Case::Churn
        ) {
            let mut pipe_expected = Vec::new();
            for payload in [
                &[][..],
                &[0, 255, 128][..],
                input.descriptor.challenge.as_slice(),
            ] {
                pipe_expected.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                pipe_expected.extend_from_slice(payload);
            }
            for name in [
                "named-pipe-server-received.bin",
                "named-pipe-client-received.bin",
            ] {
                if read(&root.join(name), 8192)? != pipe_expected {
                    return Err(CiError::Message(format!(
                        "independent named pipe receiver product differs: {name}"
                    )));
                }
            }
            for (name, header) in [
                (
                    "tcp-peer-received.bin",
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".as_slice(),
                ),
                (
                    "tcp-server-received.bin",
                    b"GET /readiness HTTP/1.1\r\nHost: localhost\r\n\r\n".as_slice(),
                ),
            ] {
                let mut expected = Vec::new();
                for payload in [
                    header,
                    &[],
                    &[0, 255, 128, 10],
                    input.descriptor.challenge.as_slice(),
                ] {
                    expected.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                    expected.extend_from_slice(payload);
                }
                if read(&root.join(name), 8192)? != expected {
                    return Err(CiError::Message(format!(
                        "independent TCP receiver product differs: {name}"
                    )));
                }
            }
        }
        Ok(())
    }

    #[allow(unsafe_code)] // Query-only native TCP table; bounded aligned output buffer.
    fn native_listener_owner(pid: u32, port: u16) -> io::Result<()> {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            GetExtendedTcpTable, TCP_TABLE_OWNER_PID_ALL,
        };
        let mut size = 0_u32;
        // SAFETY: size-only native query has no output table pointer.
        let sizing = unsafe {
            GetExtendedTcpTable(
                std::ptr::null_mut(),
                &mut size,
                0,
                2,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if sizing != 122 || size == 0 || size > 4 * 1024 * 1024 {
            return Err(io::Error::other(format!(
                "native TCP table sizing failed: {sizing}"
            )));
        }
        let mut words = vec![0_u32; (size as usize).div_ceil(4)];
        let capacity = words.len() * 4;
        // SAFETY: DWORD-aligned initialized storage covers the supplied byte capacity.
        let status = unsafe {
            GetExtendedTcpTable(
                words.as_mut_ptr().cast(),
                &mut size,
                0,
                2,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        if size as usize > capacity || size < 4 {
            return Err(io::Error::other("native TCP table size differs"));
        }
        let count = words[0] as usize;
        if count > (size as usize - 4) / 24 {
            return Err(io::Error::other(
                "native TCP table row count exceeds returned bytes",
            ));
        }
        let matching = words[1..1 + count * 6]
            .chunks_exact(6)
            .filter(|row| {
                row[0] == 2
                    && row[1] == u32::from_ne_bytes([127, 0, 0, 1])
                    && u16::from_be(row[2] as u16) == port
                    && row[5] == pid
            })
            .count();
        if matching != 1 {
            return Err(io::Error::other(
                "held fixture does not own exactly one native loopback listener",
            ));
        }
        Ok(())
    }

    #[allow(unsafe_code)] // Bounded query-only ToolHelp snapshot with owned handle.
    pub(crate) fn process_parents() -> io::Result<std::collections::BTreeMap<u32, u32>> {
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
            TH32CS_SNAPPROCESS,
        };
        // SAFETY: bounded query-only native snapshot; no process state is changed.
        let handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful snapshot transfers one owned native handle.
        let owned = unsafe { OwnedHandle::from_raw_handle(handle.cast()) };
        let mut entry = PROCESSENTRY32W::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut parents = std::collections::BTreeMap::new();
        // SAFETY: correctly initialized output buffer and held snapshot handle.
        let mut next = unsafe { Process32FirstW(owned.as_raw_handle(), &mut entry) };
        while next != 0 {
            parents.insert(entry.th32ProcessID, entry.th32ParentProcessID);
            if parents.len() > 131_072 {
                return Err(io::Error::other(
                    "native process snapshot exceeds controller bound",
                ));
            }
            // SAFETY: same held snapshot and correctly sized output buffer.
            next = unsafe { Process32NextW(owned.as_raw_handle(), &mut entry) };
        }
        if io::Error::last_os_error().raw_os_error() != Some(18) {
            return Err(io::Error::last_os_error());
        }
        Ok(parents)
    }

    fn toolchain_observation_error(operation: &str, path: &Path, error: io::Error) -> io::Error {
        let displayed = path.to_string_lossy();
        let excerpt: String = displayed.chars().take(256).collect();
        io::Error::new(
            error.kind(),
            format!(
                "native toolchain observer {operation}; path={excerpt:?}; path-truncated={}; raw-os-error={:?}; {error}",
                displayed.chars().count() > 256,
                error.raw_os_error(),
            ),
        )
    }

    struct ToolchainTranscriptSnapshot {
        complete: bool,
        last_root_stage: &'static str,
    }

    fn toolchain_completion_published(
        transcript: &Path,
        root_pid: u32,
        deadline: Instant,
    ) -> io::Result<ToolchainTranscriptSnapshot> {
        let published = super::live_events(
            &read(transcript, 16 * 1024 * 1024)
                .map_err(io::Error::other)
                .map_err(|error| {
                    toolchain_observation_error("read fixture transcript", transcript, error)
                })?,
        )
        .map_err(io::Error::other)?;
        if Instant::now() >= deadline {
            return Err(io::Error::other(
                "native compiler descendant observer deadline expired",
            ));
        }
        // Only emit a closed static vocabulary from the already parsed frames.
        // Unknown stages remain explicitly unavailable, never arbitrary content.
        let last_root_stage = match published
            .iter()
            .rev()
            .find(|event| event.pid == root_pid)
            .map(|event| event.stage.as_str())
        {
            Some("started") => "started",
            Some("native-argv-observed") => "native-argv-observed",
            Some("token-envelope") => "token-envelope",
            Some("controller-released") => "controller-released",
            Some("tcp-listener-owned") => "tcp-listener-owned",
            Some("named-pipe-while-tcp-owned") => "named-pipe-while-tcp-owned",
            Some("binary-files") => "binary-files",
            Some("toolchain-ready-for-native-observer") => "toolchain-ready-for-native-observer",
            Some("toolchain-compiled") => "toolchain-compiled",
            Some("toolchain-test-child-dll-complete") => "toolchain-test-child-dll-complete",
            Some("tcp-peer-complete") => "tcp-peer-complete",
            Some("finished") => "finished",
            Some(_) => "unavailable-unrecognized-stage",
            None => "unavailable-no-root-event",
        };
        Ok(ToolchainTranscriptSnapshot {
            complete: published.iter().any(|event| {
                event.pid == root_pid && event.stage == "toolchain-test-child-dll-complete"
            }),
            last_root_stage,
        })
    }

    fn toolchain_observation_complete(
        transcript: &Path,
        root_pid: u32,
        family: &Arc<Mutex<Vec<WindowsImageProcess>>>,
        deadline: Instant,
    ) -> io::Result<bool> {
        if toolchain_completion_published(transcript, root_pid, deadline)?.complete {
            return Ok(true);
        }
        let (retired, native_status) = {
            let held = family
                .lock()
                .map_err(|_| io::Error::other("compiler family ownership poisoned"))?;
            // The original root is retained first; descendants are only appended.
            // Never reacquire ownership from a numeric PID after retirement.
            let root = held
                .first()
                .filter(|root| root.identity.pid == root_pid)
                .ok_or_else(|| {
                    io::Error::other("native compiler observer lost its held fixture root")
                })?;
            let retired = root.has_exited()?;
            // This diagnostic query uses THAT SAME original retained handle.
            // Its failure cannot replace the original premature-retirement error.
            let native_status = retired.then(|| root.native_exit_status());
            (retired, native_status)
        };
        if retired {
            // A final durable event may have raced the native retirement read.
            let final_snapshot = toolchain_completion_published(transcript, root_pid, deadline)?;
            if final_snapshot.complete {
                return Ok(true);
            }
            let native_status = match native_status {
                Some(Ok(Some(status))) => format!("observed:{status:#010x}"),
                Some(Ok(None)) => "unavailable-not-observed".into(),
                Some(Err(error)) => format!(
                    "unavailable-query-error; kind={:?}; raw-os-error={:?}",
                    error.kind(),
                    error.raw_os_error(),
                ),
                None => "unavailable-not-queried".into(),
            };
            return Err(io::Error::other(format!(
                "native compiler fixture retired before publishing toolchain completion; held-root-native-exit={native_status}; last-validated-root-stage={}",
                final_snapshot.last_root_stage,
            )));
        }
        Ok(false)
    }

    struct ToolchainObservationImages<'a> {
        images: &'a [descriptor::ToolchainImage],
        clock: (u64, u64),
    }

    struct PendingHelperSample {
        hint: super::toolchain_sampling::Hint,
        sample: memcordon_testkit::WindowsThreadActivitySample,
        path: PathBuf,
    }

    struct HelperSampleContext<'a> {
        directory: &'a Path,
        output_root: &'a Path,
        challenge: &'a [u8],
        root_pid: u32,
        family: &'a Arc<Mutex<Vec<WindowsImageProcess>>>,
        images: &'a [descriptor::ToolchainImage],
        clock: (u64, u64),
        deadline: Instant,
    }

    struct ToolchainAdmission {
        image_sha256: String,
        parent: super::toolchain_sampling::Identity,
    }

    fn validate_helper_owners(
        context: &HelperSampleContext<'_>,
        held: &[WindowsImageProcess],
        hint: &super::toolchain_sampling::Hint,
        admitted: &std::collections::BTreeMap<
            super::toolchain_sampling::Identity,
            ToolchainAdmission,
        >,
    ) -> io::Result<()> {
        use super::toolchain_sampling as sampling;
        let identity = |owner: &WindowsImageProcess| sampling::Identity {
            pid: owner.identity.pid,
            birth: owner.identity.birth,
        };
        let fixture = held
            .iter()
            .find(|owner| owner.identity.pid == context.root_pid)
            .ok_or_else(|| {
                io::Error::other("original held fixture absent from helper diagnostic")
            })?;
        let compiler = held
            .iter()
            .find(|owner| identity(owner) == hint.compiler)
            .ok_or_else(|| io::Error::other("hint compiler is not an original held owner"))?;
        if fixture.has_exited()?
            || !compiler.has_exited()?
            || admitted
                .get(&hint.compiler)
                .map(|admission| admission.image_sha256.as_str())
                != hint.binding["selected_image_sha256"].as_str()
            || admitted
                .get(&hint.compiler)
                .is_none_or(|admission| admission.parent != identity(fixture))
        {
            return Err(io::Error::other(
                "hint original compiler retirement or admitted image differs",
            ));
        }
        for survivor in &hint.survivors {
            let owner = held
                .iter()
                .find(|owner| identity(owner) == survivor.identity)
                .ok_or_else(|| io::Error::other("hint survivor lacks original held owner"))?;
            if owner.has_exited()?
                || owner.native_parent_process_id()? != survivor.parent.pid
                || !held
                    .iter()
                    .any(|parent| identity(parent) == survivor.parent)
                || admitted.get(&survivor.identity).is_none_or(|admission| {
                    admission.image_sha256 != survivor.image_sha256
                        || admission.parent != survivor.parent
                })
            {
                return Err(io::Error::other(
                    "hint survivor native parent, liveness or admitted image differs",
                ));
            }
        }
        super::toolchain_sampling::live(context.deadline)
    }

    fn begin_helper_sample(
        context: &HelperSampleContext<'_>,
        seen: &mut BTreeSet<super::toolchain_sampling::Identity>,
        attempted: &mut BTreeSet<(super::toolchain_sampling::Identity, u64)>,
        admitted: &std::collections::BTreeMap<
            super::toolchain_sampling::Identity,
            ToolchainAdmission,
        >,
        owners: &mut Vec<std::fs::File>,
    ) -> io::Result<Option<PendingHelperSample>> {
        use super::toolchain_sampling as sampling;
        if Instant::now() >= context.deadline {
            return Ok(None);
        }
        let mut records = Vec::new();
        for leaf in [
            "toolchain-current-phase.json",
            "toolchain-current-debug.json",
        ] {
            sampling::live(context.deadline)?;
            let path = context.output_root.join("compiled").join(leaf);
            if !path.try_exists()? {
                return Ok(None);
            }
            let bytes = read(&path, sampling::RECORD_BOUND).map_err(io::Error::other)?;
            sampling::live(context.deadline)?;
            memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)
                .map_err(io::Error::other)?;
            records.push(
                serde_json::from_slice::<serde_json::Value>(&bytes).map_err(io::Error::other)?,
            );
            sampling::live(context.deadline)?;
            if records.len() == 1
                && seen.iter().any(|identity| {
                    records[0]["binding"]["original_child"]["process_id"].as_u64()
                        == Some(u64::from(identity.pid))
                        && records[0]["binding"]["original_child"]["creation_time_100ns"]
                            .as_u64()
                            .map(u128::from)
                            == Some(identity.birth)
                })
            {
                return Ok(None);
            }
        }
        // Most sweeps legitimately precede original compiler exit. These hints
        // never provide admission, ACK or native retirement authority.
        let Some(version) = sampling::candidate(&records[0], &records[1])? else {
            return Ok(None);
        };
        if attempted.contains(&version) || attempted.len() >= 4096 {
            return Ok(None);
        }
        attempted.insert(version);
        let held = context
            .family
            .lock()
            .map_err(|_| io::Error::other("compiler family ownership poisoned"))?;
        let identity = |owner: &WindowsImageProcess| sampling::Identity {
            pid: owner.identity.pid,
            birth: owner.identity.birth,
        };
        let fixture = held
            .iter()
            .find(|owner| owner.identity.pid == context.root_pid)
            .ok_or_else(|| {
                io::Error::other("original held fixture absent from helper diagnostic")
            })?;
        let images = context
            .images
            .iter()
            .map(|image| image.sha256.clone())
            .collect();
        let hint = sampling::hint(
            &records[0],
            &records[1],
            context.challenge,
            identity(fixture),
            context.clock,
            &images,
        )?;
        if seen.contains(&hint.compiler) {
            return Ok(None);
        }
        if seen.len() >= 4096 {
            return Err(io::Error::other(
                "helper diagnostic compiler inventory exceeds finite bound",
            ));
        }
        validate_helper_owners(context, &held, &hint, admitted)?;
        // One exact owner is sampled; additional survivors remain explicitly
        // omitted from this finite diagnostic rather than called complete.
        let survivor = hint
            .survivors
            .first()
            .expect("nonempty validated inventory");
        let owner = held
            .iter()
            .find(|owner| identity(owner) == survivor.identity)
            .expect("validated owner");
        seen.insert(hint.compiler);
        let sample = owner.begin_thread_activity_sample(context.deadline)?;
        let path = context.directory.join(format!(
            "native-toolchain-helper-activity-{}-{}.json",
            hint.compiler.pid, hint.compiler.birth
        ));
        let bytes = sampling::encode_until(
            &hint,
            &[sample.first_observation().clone()],
            false,
            context.deadline,
        )?;
        owners.push(sampling::publish(
            context.directory,
            &path,
            &bytes,
            context.deadline,
        )?);
        Ok(Some(PendingHelperSample { hint, sample, path }))
    }

    fn observe_toolchain_descendants(
        directory: &Path,
        output_root: &Path,
        challenge: &[u8],
        transcript: &Path,
        root_pid: u32,
        family: &Arc<Mutex<Vec<WindowsImageProcess>>>,
        selected: ToolchainObservationImages<'_>,
        work_deadline: Instant,
    ) -> io::Result<()> {
        let deadline = work_deadline.min(Instant::now() + Duration::from_secs(600));
        let mut ordinal = 0u32;
        let mut admitted = std::collections::BTreeMap::new();
        let mut seen = BTreeSet::new();
        let mut attempted = BTreeSet::new();
        let mut pending: Option<PendingHelperSample> = None;
        let mut diagnostic_owners = Vec::new();
        let mut diagnostic_error = None;
        let context = HelperSampleContext {
            directory,
            output_root,
            challenge,
            root_pid,
            family,
            images: selected.images,
            clock: selected.clock,
            deadline,
        };
        let outcome = (|| {
            loop {
                if let Some(mut round) = pending.take() {
                    let value = round.sample.finish(deadline);
                    let result = super::toolchain_sampling::encode_until(
                        &round.hint,
                        &[value],
                        true,
                        deadline,
                    )
                    .and_then(|bytes| {
                        super::toolchain_sampling::publish(directory, &round.path, &bytes, deadline)
                    });
                    match result {
                        Ok(owner) => diagnostic_owners.push(owner),
                        Err(error) => {
                            diagnostic_error.get_or_insert(error);
                        }
                    }
                }
                if toolchain_observation_complete(transcript, root_pid, family, deadline)? {
                    return Ok(());
                }
                for image in selected.images {
                    if toolchain_observation_complete(transcript, root_pid, family, deadline)? {
                        return Ok(());
                    }
                    let processes =
                        memcordon_testkit::windows_processes_for_image_until(&image.path, deadline)
                            .map_err(|error| {
                                toolchain_observation_error("image census", &image.path, error)
                            })?;
                    for process in processes {
                        if process.has_exited()? {
                            continue;
                        }
                        let mut held = family
                            .lock()
                            .map_err(|_| io::Error::other("compiler family ownership poisoned"))?;
                        if held
                            .iter()
                            .any(|existing| existing.identity == process.identity)
                        {
                            continue;
                        }
                        let parent_pid = process.native_parent_process_id()?;
                        let Some(parent) =
                            held.iter().find(|parent| parent.identity.pid == parent_pid)
                        else {
                            continue;
                        };
                        if parent.has_exited()?
                            || parent.identity.birth > process.identity.birth
                            || process.has_exited()?
                        {
                            continue;
                        }
                        let parent_birth = parent.identity.birth;
                        if held
                            .iter()
                            .find(|root| root.identity.pid == root_pid)
                            .is_none_or(|root| !matches!(root.has_exited(), Ok(false)))
                        {
                            return Err(io::Error::other(
                                "native compiler observer lost its held live fixture root",
                            ));
                        }
                        ordinal = ordinal.checked_add(1).ok_or_else(|| {
                            io::Error::other("compiler native observation count overflow")
                        })?;
                        if ordinal > 4096 {
                            return Err(io::Error::other(
                                "compiler native descendant observation exceeds finite bound",
                            ));
                        }
                        let bytes=serde_json::to_vec(&serde_json::json!({
                        "format":"memcordon.windows-native-toolchain-descendant","revision":1,"ordinal":ordinal,
                        "root_pid":root_pid,"pid":process.identity.pid,"birth":process.identity.birth,
                        "parent_pid":parent_pid,"parent_birth":parent_birth,"image_sha256":image.sha256,
                        "native_parent_edge_observed":true,"parent_and_child_held_live":true,
                    })).map_err(io::Error::other)?;
                        let path =
                            directory.join(format!("native-toolchain-descendant-{ordinal}.json"));
                        let mut file = OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(&path)
                            .map_err(|error| {
                                toolchain_observation_error(
                                    "create exclusive descendant record",
                                    &path,
                                    error,
                                )
                            })?;
                        file.write_all(&bytes).map_err(|error| {
                            toolchain_observation_error("write descendant record", &path, error)
                        })?;
                        file.sync_all().map_err(|error| {
                            toolchain_observation_error("sync descendant record", &path, error)
                        })?;
                        if read(&path, 16 * 1024)
                            .map_err(io::Error::other)
                            .map_err(|error| {
                                toolchain_observation_error("read descendant record", &path, error)
                            })?
                            != bytes
                        {
                            return Err(io::Error::other(
                                "native compiler descendant named readback differs",
                            ));
                        }
                        let child_identity = process.identity;
                        held.push(process);
                        if Instant::now() >= deadline
                            || !held.iter().any(|owner| {
                                owner.identity == child_identity
                                    && matches!(owner.has_exited(), Ok(false))
                            })
                            || !held.iter().any(|owner| {
                                owner.identity.pid == parent_pid
                                    && owner.identity.birth == parent_birth
                                    && matches!(owner.has_exited(), Ok(false))
                            })
                        {
                            return Err(io::Error::other(
                                "toolchain creation acknowledgment lost live ownership or original cutoff",
                            ));
                        }
                        let descendant: serde_json::Value =
                            serde_json::from_slice(&bytes).map_err(io::Error::other)?;
                        let ack = serde_json::to_vec(&serde_json::json!({
                            "format":"memcordon.windows-toolchain-creation-ack","revision":1,
                            "challenge":challenge,"descendant":descendant,
                        }))
                        .map_err(io::Error::other)?;
                        if ack.len() > 16 * 1024 {
                            return Err(io::Error::other(
                                "toolchain creation acknowledgment exceeds finite bound",
                            ));
                        }
                        let ack_path = output_root.join(format!(
                            "native-toolchain-{}-{}.ack.json",
                            child_identity.pid, child_identity.birth
                        ));
                        let mut ack_file = tempfile::NamedTempFile::new_in(output_root)?;
                        ack_file.write_all(&ack)?;
                        ack_file.as_file().sync_all()?;
                        if read(ack_file.path(), 16 * 1024).map_err(io::Error::other)? != ack {
                            return Err(io::Error::other(
                                "staged toolchain acknowledgment named readback differs",
                            ));
                        }
                        // Close the writable handle before the atomic no-clobber
                        // publication so the child never opens partial bytes or
                        // conflicts with the publisher's write-sharing access.
                        ack_file
                            .into_temp_path()
                            .persist_noclobber(&ack_path)
                            .map_err(io::Error::other)?;
                        if read(&ack_path, 16 * 1024).map_err(io::Error::other)? != ack {
                            return Err(io::Error::other(
                                "toolchain creation acknowledgment named readback differs",
                            ));
                        }
                        // Publish the sequencing hint only after the atomic rename
                        // and final ACK readback have both released their handles.
                        // The child still validates the complete original ACK.
                        drop(
                            OpenOptions::new()
                                .write(true)
                                .create_new(true)
                                .open(ack_path.with_extension("published"))?,
                        );
                        admitted.insert(
                            super::toolchain_sampling::Identity {
                                pid: child_identity.pid,
                                birth: child_identity.birth,
                            },
                            ToolchainAdmission {
                                image_sha256: image.sha256.clone(),
                                parent: super::toolchain_sampling::Identity {
                                    pid: parent_pid,
                                    birth: parent_birth,
                                },
                            },
                        );
                    }
                }
                {
                    match begin_helper_sample(
                        &context,
                        &mut seen,
                        &mut attempted,
                        &admitted,
                        &mut diagnostic_owners,
                    ) {
                        Ok(round) => pending = round,
                        Err(mut error) => {
                            if diagnostic_error.is_none() {
                                let bytes = super::toolchain_sampling::live(deadline).and_then(|_|serde_json::to_vec(&serde_json::json!({
                            "format":"memcordon.windows-held-compiler-helper-activity-error","revision":1,
                            "diagnostic_only":true,"sampling_refused_or_incomplete":true,"compiler_acceptance":false,
                            "fixture_pid":root_pid,"challenge":challenge,"native_identity_not_verified":true,
                            "native_work_cutoff_ticks":selected.clock.0,"native_work_frequency":selected.clock.1,
                            "error":crate::command::bounded_excerpt(error.to_string().as_bytes()),
                            "kind":format!("{:?}",error.kind()),"raw_os_error":error.raw_os_error(),
                        })).map_err(io::Error::other));
                                match bytes.and_then(|bytes| {
                                    super::toolchain_sampling::publish(
                                        directory,
                                        &directory
                                            .join("native-toolchain-helper-diagnostic-error.json"),
                                        &bytes,
                                        deadline,
                                    )
                                }) {
                                    Ok(owner) => diagnostic_owners.push(owner),
                                    Err(retention) => {
                                        error = io::Error::new(
                                            error.kind(),
                                            format!(
                                                "{error}; helper-diagnostic-retention={retention}"
                                            ),
                                        )
                                    }
                                }
                                diagnostic_error = Some(error);
                            }
                        }
                    }
                }
                if toolchain_observation_complete(transcript, root_pid, family, deadline)? {
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::other(
                        "native compiler descendant observer deadline expired",
                    ));
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        })();
        match (outcome, diagnostic_error) {
            (Err(original), Some(diagnostic)) => Err(io::Error::new(
                original.kind(),
                format!("{original}; held-helper-diagnostic={diagnostic}"),
            )),
            (Err(original), None) => Err(original),
            (Ok(()), Some(diagnostic)) => {
                eprintln!(
                    "held-helper diagnostic unavailable; original compiler observation succeeded: {diagnostic}"
                );
                Ok(())
            }
            (Ok(()), None) => Ok(()),
        }
    }

    pub(crate) fn execute(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        input: &CaseInput,
        record: &mut CaseAssessment,
    ) -> Result<()> {
        execute_until(
            config,
            input,
            record,
            Instant::now() + Duration::from_secs(660),
        )
    }

    pub(crate) fn execute_until(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        input: &CaseInput,
        record: &mut CaseAssessment,
        work_deadline: Instant,
    ) -> Result<()> {
        execute_until_with_cleanup(config, input, record, work_deadline, None)
    }

    fn execute_until_with_cleanup(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        input: &CaseInput,
        record: &mut CaseAssessment,
        work_deadline: Instant,
        cleanup: Option<Instant>,
    ) -> Result<()> {
        let baseline = GuardianBaseline::quiescent(
            &config.installed_agent.path,
            &config.installed_manifest.path,
            &config.installed_agent.sha256,
            &config.installed_manifest.sha256,
        )?;
        execute_with_baseline_clocks(
            config,
            input,
            record,
            baseline,
            Vec::new(),
            None,
            ExecutionClocks {
                work: work_deadline,
                cleanup,
            },
        )
    }

    pub(crate) struct HeldFixtureExclusion {
        pub observation: memcordon_core::WindowsGuardianAttemptObservation,
        pub family: Vec<WindowsImageProcess>,
    }

    pub(crate) fn execute_with_baseline(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        input: &CaseInput,
        record: &mut CaseAssessment,
        baseline: GuardianBaseline,
        excluded: Vec<GuardianAssociationIdentity>,
        excluded_fixture: Option<HeldFixtureExclusion>,
    ) -> Result<()> {
        execute_with_baseline_until(
            config,
            input,
            record,
            baseline,
            excluded,
            excluded_fixture,
            Instant::now() + Duration::from_secs(660),
        )
    }

    pub(crate) fn execute_with_baseline_until(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        input: &CaseInput,
        record: &mut CaseAssessment,
        baseline: GuardianBaseline,
        excluded: Vec<GuardianAssociationIdentity>,
        excluded_fixture: Option<HeldFixtureExclusion>,
        work_deadline: Instant,
    ) -> Result<()> {
        execute_with_baseline_clocks(
            config,
            input,
            record,
            baseline,
            excluded,
            excluded_fixture,
            ExecutionClocks {
                work: work_deadline,
                cleanup: None,
            },
        )
    }

    struct ExecutionClocks {
        work: Instant,
        cleanup: Option<Instant>,
    }

    fn execute_with_baseline_clocks(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        input: &CaseInput,
        record: &mut CaseAssessment,
        baseline: GuardianBaseline,
        excluded: Vec<GuardianAssociationIdentity>,
        excluded_fixture: Option<HeldFixtureExclusion>,
        clocks: ExecutionClocks,
    ) -> Result<()> {
        let work_deadline = clocks.work;
        let work_budget = work_deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(660));
        if work_budget.is_zero() {
            return Err(CiError::Message(
                "original Windows work deadline exhausted before positive launch".into(),
            ));
        }
        let require_global_quiescence = excluded.is_empty();
        if let Some(owned) = &excluded_fixture {
            let root = owned
                .observation
                .live_target_identity
                .as_ref()
                .ok_or_else(|| {
                    CiError::Message("overlap excluded root identity unavailable".into())
                })?;
            if excluded.len() != 1
                || !owned.observation.is_consistent()
                || owned.observation.association.provider != config.provider
                || owned.observation.guardian_identity.process_id != excluded[0].process_id
                || owned.observation.guardian_identity.creation_time_100ns
                    != excluded[0].creation_time_100ns
                || owned.family.len() != 2
                || owned
                    .family
                    .iter()
                    .any(|process| !matches!(process.has_exited(), Ok(false)))
                || !owned.family.iter().any(|process| {
                    process.identity.pid == root.process_id
                        && process.identity.birth == u128::from(root.creation_time_100ns)
                })
            {
                return Err(CiError::Message(
                    "overlap exclusion is not the exact independently held live first family"
                        .into(),
                ));
            }
        } else if !excluded.is_empty() {
            return Err(CiError::Message(
                "guardian overlap exclusion requires independently held fixture family".into(),
            ));
        }
        let guardian_owner = Arc::new(Mutex::new(Vec::<HeldGuardian>::new()));
        let observed_guardian_owner = Arc::clone(&guardian_owner);
        let prepared = prepare_gate_input(config, input, work_deadline)?;
        let input = &prepared.input;
        let gate_name = input.descriptor.start_gate.as_ref().ok_or_else(|| {
            CiError::Message("positive input omitted held-root native barrier".into())
        })?;
        let gate = Arc::clone(&prepared.gate);
        let callback_gate = Arc::clone(&gate);
        let endpoint_event = (input.descriptor.case == descriptor::Case::EndpointMismatch)
            .then(|| event_create(&format!("{gate_name}-endpoint-observed")))
            .transpose()?;
        let toolchain_event = matches!(
            input.descriptor.case,
            descriptor::Case::Toolchain | descriptor::Case::Joint | descriptor::Case::Churn
        )
        .then(|| event_create(&format!("{gate_name}-toolchain-observer")))
        .transpose()?;
        let mut toolchain_images = Vec::new();
        if toolchain_event.is_some() {
            let measured: Vec<crate::windows_installed_cases::SelectedArtifact> =
                serde_json::from_slice(&read(
                    &config.output_directory.join("windows-owned-inputs.json"),
                    64 * 1024 * 1024,
                )?)?;
            let selected = descriptor::project_toolchain_images(
                measured.into_iter().map(|image| (image.path, image.sha256)),
            )
            .map_err(CiError::Message)?;
            let toolchain = input.descriptor.toolchain.as_ref().ok_or_else(|| {
                CiError::Message("native compiler descriptor inventory absent".into())
            })?;
            super::validate_toolchain_inventory(toolchain, &selected)?;
            for image in selected {
                if crate::windows_causal_acceptance::sha256(&read(&image.path, 512 * 1024 * 1024)?)
                    != image.sha256
                {
                    return Err(CiError::Message("native compiler observer input image is unmeasured or exceeds finite closure".into()));
                }
                toolchain_images.push(image);
            }
            if toolchain_images.is_empty() {
                return Err(CiError::Message(
                    "native compiler observer has no measured compiler/linker images".into(),
                ));
            }
        }
        let cohort_event = input
            .descriptor
            .cohort_gate
            .as_ref()
            .map(|name| event_create(name))
            .transpose()?;
        let generation_event = input
            .descriptor
            .generation_gate
            .as_ref()
            .map(|name| event_create(name))
            .transpose()?;
        let family = Arc::new(Mutex::new(Vec::<WindowsImageProcess>::new()));
        let console_owners = Arc::new(Mutex::new(Vec::<WindowsImageProcess>::new()));
        let held_console_owners = Arc::clone(&console_owners);
        let console_image = if input.descriptor.case == descriptor::Case::Churn {
            Some(Arc::new(hold_console_image()?))
        } else {
            None
        };
        let held_console_image = console_image.clone();
        let association = Arc::new(Mutex::new(None));
        let held_family = Arc::clone(&family);
        let held_association = Arc::clone(&association);
        let frontend = Arc::new(Mutex::new(None::<WindowsImageProcess>));
        let held_frontend = Arc::clone(&frontend);
        let capture_frontend_identity = expected_status(&input.key) != 0
            || matches!(
                input.descriptor.case,
                descriptor::Case::DeadlineDemand | descriptor::Case::MemoryDemand
            );
        let report = config
            .output_directory
            .join(&input.key.family)
            .join(&input.key.scenario)
            .join("result.json");
        fs::create_dir_all(report.parent().expect("case report has parent"))?;
        if report.try_exists()?
            || input.descriptor_path.try_exists()?
            || input.descriptor.transcript.try_exists()?
        {
            return Err(CiError::Message(
                "positive case cannot reuse old report/input/transcript paths".into(),
            ));
        }
        fs::create_dir_all(&input.descriptor.output_root)?;
        let descriptor_bytes = serde_json::to_vec(&input.descriptor)?;
        validate_descriptor(&input.key, &input.descriptor)?;
        descriptor::Descriptor::parse(&descriptor_bytes).map_err(|error| {
            CiError::Message(format!(
                "Windows fixture {}/{} publication failed: {error}; encoded-bytes={} limit={}",
                input.key.family,
                input.key.scenario,
                descriptor_bytes.len(),
                descriptor::MAX_DESCRIPTOR_BYTES
            ))
        })?;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&input.descriptor_path)?
            .write_all(&descriptor_bytes)?;
        let challenge_path = report
            .parent()
            .expect("case report has parent")
            .join("challenge.bin");
        let mut challenge_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&challenge_path)?;
        challenge_file.write_all(&input.descriptor.challenge)?;
        challenge_file.sync_all()?;
        if read(&challenge_path, 4096)? != input.descriptor.challenge {
            return Err(CiError::Message(
                "positive challenge named readback differs".into(),
            ));
        }
        record.descriptor_sha256 = crate::windows_causal_acceptance::sha256(&descriptor_bytes);
        let public_report = input.descriptor.output_root.join("frontend-result.json");
        let mut command = public_command(
            &config.cli.path,
            &config.fixture.path,
            &config.output_directory,
            &public_report,
            input,
        )?
        .materialize()?;
        // Workload inputs are absolute owned paths; ambient controller secrets
        // must never enter the authenticated launch request or its observation.
        command.env_clear();
        command.stdin(std::process::Stdio::null());
        let execution_sha256 = if command.get_program() == config.fixture.path.as_os_str() {
            config.fixture.sha256.clone()
        } else {
            config.cli.sha256.clone()
        };
        use std::os::windows::ffi::OsStrExt;
        let invocation = serde_json::json!({
            "format":"memcordon.windows-positive-invocation","revision":1,
            "frontend_environment":fixture_environment::entries()?,
            "target":config.target,
            "executable_sha256":execution_sha256,
            "public_executable_sha256":config.cli.sha256,
            "public_program_utf16":config.cli.path.as_os_str().encode_wide().collect::<Vec<_>>(),
            "program_utf16":command.get_program().encode_wide().collect::<Vec<_>>(),
            "argv_utf16":command.get_args().map(|argument|argument.encode_wide().collect::<Vec<_>>()).collect::<Vec<_>>(),
            "cwd_utf16":config.output_directory.as_os_str().encode_wide().collect::<Vec<_>>(),
            "environment_cleared":true,
        });
        let invocation_bytes = serde_json::to_vec(&invocation)?;
        let invocation_path = report
            .parent()
            .expect("case report has parent")
            .join("native-invocation.json");
        let mut invocation_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&invocation_path)?;
        invocation_file.write_all(&invocation_bytes)?;
        invocation_file.sync_all()?;
        if read(&invocation_path, 256 * 1024)? != invocation_bytes {
            return Err(CiError::Message(
                "positive native invocation named readback differs".into(),
            ));
        }
        let fixture = config.fixture.path.clone();
        let transcript = input.descriptor.transcript.clone();
        let toolchain_output_root = input.descriptor.output_root.clone();
        let toolchain_challenge = input.descriptor.challenge.clone();
        let toolchain_clock = input.descriptor.toolchain.as_ref().map(|toolchain| {
            (
                toolchain.native_work_cutoff_ticks,
                toolchain.native_work_frequency,
            )
        });
        let cli = config.cli.path.clone();
        let directory = report.parent().expect("case report has parent").to_owned();
        let guardian_query = Arc::new(Mutex::new(super::guardian_query::Trace::new(
            serde_json::json!({
                "case":input.key,"provider":config.provider,"source_commit":config.source_commit,
                "target":config.target,"selected_cli":config.cli,
                "challenge_sha256":crate::windows_causal_acceptance::sha256(&input.descriptor.challenge),
                "descriptor_sha256":record.descriptor_sha256,
            }),
        )));
        let callback_guardian_query = Arc::clone(&guardian_query);
        let gate_root_diagnostic = Arc::new(Mutex::new(None::<serde_json::Value>));
        let callback_gate_root_diagnostic = Arc::clone(&gate_root_diagnostic);
        let capture_gate_diagnostic = super::start_gate_policy::capture_restricted_gate(
            &input.key.family,
            &input.key.scenario,
        );
        let gate_diagnostic = capture_gate_diagnostic.then(|| {
            let name_utf16: Vec<_> = gate_name.encode_utf16().collect();
            let name_bytes: Vec<_> = name_utf16.iter().flat_map(|unit| unit.to_le_bytes()).collect();
            serde_json::json!({
                "format":"memcordon.windows-controller-gate-diagnostic","revision":1,
                "authority":"diagnostic-only; never gate access or workload acceptance",
                "case":input.key,"challenge_sha256":crate::windows_causal_acceptance::sha256(&input.descriptor.challenge),
                "source_commit":config.source_commit,"target":config.target,"fixture_sha256":config.fixture.sha256,
                "descriptor_sha256":record.descriptor_sha256,
                "requested_name_utf16":name_utf16,"requested_name_sha256":crate::windows_causal_acceptance::sha256(&name_bytes),
                "name_binding":"original exclusive CreateEventW argument; optional controller directory discovery is reported separately",
                "requested_sddl":prepared.requested_sddl,"fixture_requested_access":0x0010_0000_u32,
                "actual_security_information":7,
                "same_held_event_security":prepared.prelaunch_security,
                "same_held_event_mandatory_label":prepared.prelaunch_label,
                "access_comparison_input":prepared.binding_setup,
                "controller":gate_query_result(super::workload_diagnostic::gate_controller_context(work_deadline)),
                "original_fixture":null,
            })
        });
        let expected_provider = config.provider.clone();
        let barrier_report = public_report.clone();
        let descendant_gate = input.descriptor.descendant_gate.clone();
        let intermediate_first = input.descriptor.case == descriptor::Case::IntermediateFirst;
        let owns_tcp = matches!(
            input.descriptor.case,
            descriptor::Case::Joint | descriptor::Case::Churn | descriptor::Case::EndpointMismatch
        );
        let native_started_utc = std::time::SystemTime::now();
        let work_budget = work_budget.min(work_deadline.saturating_duration_since(Instant::now()));
        if work_budget.is_zero() {
            return Err(CiError::Message(
                "original Windows work deadline exhausted during observer preparation".into(),
            ));
        }
        let output = memcordon_testkit::run_with_deadline_owned_spawn_with_io_output_limit(
            command,
            work_budget,
            4 * 1024 * 1024,
            |mut command| command.spawn(),
            move |wrapper_pid, _, _| {
                let deadline = work_deadline.min(Instant::now() + Duration::from_secs(60));
                let (held, root_pid) = loop {
                    if barrier_report.try_exists()? {
                        super::check_positive_barrier_result(
                            &read(
                                &barrier_report,
                                crate::windows_causal_acceptance::MAX_REPORT_BYTES,
                            )
                            .map_err(io::Error::other)?,
                            &expected_provider,
                        )
                        .map_err(|error| {
                            io::Error::other(format!(
                                "{error}; retained-result={}",
                                barrier_report.display()
                            ))
                        })?;
                    }
                    let mut held =
                        memcordon_testkit::windows_processes_for_image_until(&fixture, deadline)?;
                    if transcript.is_file() && !held.is_empty() {
                        let published = super::live_events(
                            &read(&transcript, 16 * 1024 * 1024).map_err(io::Error::other)?,
                        )
                        .map_err(io::Error::other)?;
                        if let Some(started) = published.first() {
                            held.retain(|process| process.identity.pid == started.pid);
                            if held.len() == 1 && !held[0].has_exited()? {
                                break (held, started.pid);
                            }
                        }
                    }
                    if Instant::now() >= deadline {
                        return Err(io::Error::other("native held fixture barrier unavailable"));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                };
                if capture_gate_diagnostic {
                    let root = held
                        .first()
                        .expect("one original held fixture was admitted");
                    let observation = serde_json::json!({
                        "pid":root.identity.pid,"birth":root.identity.birth.to_string(),
                        "binding":"same original held fixture admitted by existing barrier",
                        "retired_at_query":gate_query_result(root.has_exited()),
                        "token_envelope":gate_query_result(root.original_token_envelope(work_deadline)),
                    });
                    match callback_gate_root_diagnostic.lock() {
                        Ok(mut value) => *value = Some(observation),
                        Err(poisoned) => {
                            *poisoned.into_inner() = Some(
                                serde_json::json!({"state":"unavailable","stage":"diagnostic-lock-poisoned"}),
                            )
                        }
                    }
                }
                *held_family
                    .lock()
                    .map_err(|_| io::Error::other("fixture ownership poisoned"))? = held;
                if capture_frontend_identity {
                    let mut selected = Vec::new();
                    for process in
                        memcordon_testkit::windows_processes_for_image_until(&cli, deadline)?
                    {
                        if process.native_parent_process_id()? == wrapper_pid
                            && !process.has_exited()?
                        {
                            selected.push(process);
                        }
                    }
                    if selected.len() != 1 {
                        return Err(io::Error::other(
                            "status fixture lacks one original held frontend child",
                        ));
                    }
                    *held_frontend
                        .lock()
                        .map_err(|_| io::Error::other("frontend ownership poisoned"))? =
                        selected.pop();
                }
                let guardian = baseline
                    .hold_new_guardian_excluding(&excluded)
                    .map_err(io::Error::other)?;
                let guardian_identity = guardian.identity.clone();
                let adopted = super::guardian_query::adopt(&observed_guardian_owner, guardian);
                super::guardian_query::update(&callback_guardian_query, |trace| {
                    trace.guardian(serde_json::json!(guardian_identity));
                    trace.stage(if adopted.is_ok() {
                        "command-materialization"
                    } else {
                        "guardian-adoption-failed"
                    });
                });
                adopted?;
                let query_started = Instant::now();
                let query_cutoff = work_deadline.min(query_started + Duration::from_secs(30));
                let query_budget = query_cutoff.saturating_duration_since(query_started);
                if query_budget.is_zero() {
                    return Err(io::Error::other(
                        "original Windows work deadline exhausted before association query",
                    ));
                }
                let mut query = CommandSpec::new(&cli, &directory, query_budget)
                    .args([
                        OsString::from("__observe-windows-guardian"),
                        guardian_identity.process_id.to_string().into(),
                        guardian_identity.creation_time_100ns.to_string().into(),
                    ])
                    .materialize()
                    .map_err(io::Error::other)?;
                let query_budget = query_cutoff
                    .saturating_duration_since(Instant::now())
                    .min(work_deadline.saturating_duration_since(Instant::now()));
                if query_budget.is_zero() {
                    return Err(io::Error::other(
                        "original Windows work deadline exhausted during association query setup",
                    ));
                }
                super::guardian_query::update(&callback_guardian_query, |trace| {
                    trace.stage("command-capture")
                });
                let observed = memcordon_testkit::run_with_deadline_output_limit(
                    &mut query,
                    query_budget,
                    super::guardian_query::STREAM_BOUND,
                )
                .map_err(io::Error::other)?;
                let observed_stdout = observed.stdout.clone();
                let failure = super::guardian_query::update(&callback_guardian_query, |trace| {
                    trace.captured(observed);
                    trace.stage("returned-output");
                    trace.failure()
                });
                if let Some(failure) = failure {
                    return Err(failure);
                }
                super::guardian_query::update(&callback_guardian_query, |trace| {
                    trace.stage("association-parse")
                });
                let observed: memcordon_core::WindowsGuardianAttemptObservation =
                    serde_json::from_slice(&observed_stdout).map_err(io::Error::other)?;
                super::guardian_query::update(&callback_guardian_query, |trace| {
                    trace.stage("association-validation")
                });
                if !observed.is_consistent()
                    || observed.association.provider != expected_provider
                    || observed.guardian_identity.process_id != guardian_identity.process_id
                    || observed.guardian_identity.creation_time_100ns
                        != guardian_identity.creation_time_100ns
                {
                    return Err(io::Error::other(
                        "positive native guardian association differs",
                    ));
                }
                let expected = memcordon_core::execution_facts::ProviderAttemptAssociationV1 {
                    provider: observed.association.provider.clone(),
                    attempt_id: observed.association.attempt_id.clone(),
                    request_sha256: observed.association.request_sha256.clone(),
                };
                *held_association
                    .lock()
                    .map_err(|_| io::Error::other("association ownership poisoned"))? =
                    Some(expected);
                super::guardian_query::update(&callback_guardian_query, |trace| {
                    trace.stage("association-publication")
                });
                let observation_path = directory.join("live-observation.json");
                let staging = directory.join("live-observation.pending");
                let bytes = serde_json::to_vec(&observed).map_err(io::Error::other)?;
                let mut publication = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&staging)?;
                publication.write_all(&bytes)?;
                publication.sync_all()?;
                drop(publication);
                fs::rename(&staging, &observation_path)?;
                if read(&observation_path, 32 * 1024).map_err(io::Error::other)? != bytes {
                    return Err(io::Error::other(
                        "live native association named publication differs",
                    ));
                }
                let identity_path = directory.join("live-held-guardian.json");
                let staging = directory.join("live-held-guardian.pending");
                let bytes = serde_json::to_vec(&guardian_identity).map_err(io::Error::other)?;
                let mut publication = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&staging)?;
                publication.write_all(&bytes)?;
                publication.sync_all()?;
                drop(publication);
                fs::rename(&staging, &identity_path)?;
                super::guardian_query::update(&callback_guardian_query, |trace| {
                    trace.stage("association-admitted")
                });
                signal(callback_gate.as_ref())?;
                if owns_tcp {
                    let deadline = work_deadline.min(Instant::now() + Duration::from_secs(60));
                    let port = loop {
                        let published = super::live_events(
                            &read(&transcript, 16 * 1024 * 1024).map_err(io::Error::other)?,
                        )
                        .map_err(io::Error::other)?;
                        if let Some(listener) = published
                            .iter()
                            .find(|event| event.stage == "tcp-listener-owned")
                        {
                            if listener.pid != root_pid || listener.value.len() != 2 {
                                return Err(io::Error::other(
                                    "native listener observation differs from held root",
                                ));
                            }
                            break u16::from_le_bytes(
                                listener
                                    .value
                                    .as_slice()
                                    .try_into()
                                    .expect("checked port length"),
                            );
                        }
                        if Instant::now() >= deadline {
                            return Err(io::Error::other(
                                "native listener publication deadline expired",
                            ));
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    };
                    let held = held_family
                        .lock()
                        .map_err(|_| io::Error::other("fixture ownership poisoned"))?;
                    if held.len() != 1 || held[0].has_exited()? {
                        return Err(io::Error::other("native listener root is not held live"));
                    }
                    native_listener_owner(root_pid, port)?;
                    let refusal =
                        match std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)) {
                            Ok(_) => {
                                return Err(io::Error::other(
                                    "controller acquired held fixture endpoint",
                                ));
                            }
                            Err(error) => error,
                        };
                    if refusal.raw_os_error() != Some(10048) {
                        return Err(refusal);
                    }
                    native_listener_owner(root_pid, port)?;
                    if held[0].has_exited()? {
                        return Err(io::Error::other(
                            "native listener owner retired during observation",
                        ));
                    }
                    let bytes = serde_json::to_vec(&serde_json::json!({
                        "format": "memcordon.windows-native-listener", "revision": 1,
                        "root_pid": root_pid, "root_creation_time_100ns": held[0].identity.birth,
                        "address": "127.0.0.1", "port": port, "held_owner_live": true,
                        "native_table_owner_observed_before_and_after": true, "conflicting_bind_win32_code": refusal.raw_os_error(),
                    })).map_err(io::Error::other)?;
                    let path = directory.join("native-listener.json");
                    let mut file = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&path)?;
                    file.write_all(&bytes)?;
                    file.sync_all()?;
                    if read(&path, 16 * 1024).map_err(io::Error::other)? != bytes {
                        return Err(io::Error::other("native listener named readback differs"));
                    }
                    drop(held);
                    if let Some(endpoint_event) = endpoint_event {
                        signal(&endpoint_event)?;
                    } else {
                        let peer_identity = loop {
                            let published = super::live_events(
                                &read(&transcript, 16 * 1024 * 1024).map_err(io::Error::other)?,
                            )
                            .map_err(io::Error::other)?;
                            if let Some(peer) = published
                                .iter()
                                .find(|event| event.stage == "tcp-peer-created")
                            {
                                if peer.pid != root_pid {
                                    return Err(io::Error::other(
                                        "TCP peer publisher differs from held root",
                                    ));
                                }
                                break serde_json::from_slice::<
                                    memcordon_core::WindowsProcessIdentityV1,
                                >(&peer.value)
                                .map_err(io::Error::other)?;
                            }
                            if Instant::now() >= deadline {
                                return Err(io::Error::other(
                                    "native TCP peer publication deadline expired",
                                ));
                            }
                            std::thread::sleep(Duration::from_millis(10));
                        };
                        let peer = memcordon_testkit::windows_processes_for_image_until(
                            &fixture, deadline,
                        )?
                        .into_iter()
                        .find(|process| process.identity.pid == peer_identity.process_id)
                        .ok_or_else(|| io::Error::other("native TCP peer handle unavailable"))?;
                        let mut held = held_family
                            .lock()
                            .map_err(|_| io::Error::other("fixture ownership poisoned"))?;
                        let parents = process_parents()?;
                        if held.len() != 1
                            || held[0].has_exited()?
                            || peer.has_exited()?
                            || peer.identity.birth != u128::from(peer_identity.creation_time_100ns)
                            || held[0].identity.birth > peer.identity.birth
                            || parents.get(&peer.identity.pid) != Some(&root_pid)
                        {
                            return Err(io::Error::other(
                                "native held TCP peer identity or live ancestry differs",
                            ));
                        }
                        let bytes = serde_json::to_vec(&serde_json::json!({
                            "format":"memcordon.windows-native-tcp-peer", "revision":1,
                            "pid":peer.identity.pid, "birth":peer.identity.birth,
                            "parent_pid":root_pid, "parent_birth":held[0].identity.birth,
                            "native_parent_edge_observed":true, "parent_and_child_held_live":true,
                        }))
                        .map_err(io::Error::other)?;
                        let path = directory.join("native-tcp-peer.json");
                        let mut file = OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(&path)?;
                        file.write_all(&bytes)?;
                        file.sync_all()?;
                        if read(&path, 16 * 1024).map_err(io::Error::other)? != bytes {
                            return Err(io::Error::other("native TCP peer named readback differs"));
                        }
                        held.push(peer);
                    }
                }
                if let Some(toolchain_event) = toolchain_event {
                    signal(&toolchain_event)?;
                    observe_toolchain_descendants(
                        &directory,
                        &toolchain_output_root,
                        &toolchain_challenge,
                        &transcript,
                        root_pid,
                        &held_family,
                        ToolchainObservationImages {
                            images: &toolchain_images,
                            clock: toolchain_clock.ok_or_else(|| {
                                io::Error::other("toolchain diagnostic original clock absent")
                            })?,
                        },
                        work_deadline,
                    )?;
                }
                if let (Some(cohort), Some(generation)) = (cohort_event, generation_event) {
                    let deadline = work_deadline.min(Instant::now() + Duration::from_secs(600));
                    let mut released_cohort = 0;
                    let mut released_generation = 0;
                    loop {
                        let published = super::live_events(
                            &read(&transcript, 16 * 1024 * 1024).map_err(io::Error::other)?,
                        )
                        .map_err(io::Error::other)?;
                        for event in &published {
                            let controller = match (event.stage.as_str(), event.ordinal) {
                                ("cohort-live", Some(ordinal)) if ordinal > released_cohort => {
                                    released_cohort = ordinal;
                                    Some(&cohort)
                                }
                                ("generation-live", Some(ordinal))
                                    if ordinal > released_generation =>
                                {
                                    released_generation = ordinal;
                                    Some(&generation)
                                }
                                _ => None,
                            };
                            if let Some(controller) = controller {
                                let parents = process_parents()?;
                                let active = memcordon_testkit::windows_processes_for_image_until(
                                    &fixture, deadline,
                                )?;
                                let mut family = held_family
                                    .lock()
                                    .map_err(|_| io::Error::other("fixture ownership poisoned"))?;
                                let root = family
                                    .iter()
                                    .find(|held| held.identity.pid == root_pid)
                                    .ok_or_else(|| {
                                        io::Error::other("original churn root owner absent")
                                    })?;
                                if root.has_exited()? {
                                    return Err(io::Error::other(
                                        "original churn root retired before barrier",
                                    ));
                                }
                                let root_identity = (root.identity.pid, root.identity.birth);
                                let mut generation_depths = std::collections::BTreeSet::new();
                                let mut live_children = 0usize;
                                for process in active {
                                    let Some(depth) = rooted_process_depth(
                                        (process.identity.pid, process.identity.birth),
                                        root_identity,
                                        &parents,
                                    ) else {
                                        continue;
                                    };
                                    if process.has_exited()? {
                                        continue;
                                    }
                                    if depth != 0 {
                                        live_children += 1;
                                    }
                                    if event.stage == "generation-live" {
                                        generation_depths.insert(depth);
                                    }
                                    if !family.iter().any(|held| held.identity == process.identity)
                                    {
                                        if process.has_exited()? {
                                            return Err(io::Error::other(
                                                "churn controller observed an already retired process",
                                            ));
                                        }
                                        family.push(process);
                                    }
                                }
                                if event.stage == "generation-live"
                                    && ![1, 2, 3]
                                        .iter()
                                        .all(|depth| generation_depths.contains(depth))
                                {
                                    return Err(io::Error::other(
                                        "native held snapshot omitted a generation in the three-generation branch",
                                    ));
                                }
                                {
                                    for process in family
                                        .iter()
                                        .filter(|process| !process.has_exited().unwrap_or(true))
                                    {
                                        let Some(depth) = rooted_process_depth(
                                            (process.identity.pid, process.identity.birth),
                                            root_identity,
                                            &parents,
                                        ) else {
                                            continue;
                                        };
                                        if depth == 0 {
                                            continue;
                                        }
                                        let parent_pid =
                                            *parents.get(&process.identity.pid).ok_or_else(
                                                || io::Error::other("held ancestor edge missing"),
                                            )?;
                                        let parent = family.iter().find(|parent| parent.identity.pid == parent_pid && !parent.has_exited().unwrap_or(true))
                                            .ok_or_else(|| {
                                                let candidates = family.iter().filter(|held| held.identity.pid == parent_pid);
                                                let candidate_count = candidates.clone().count();
                                                let candidates: Vec<_> = candidates.take(8).map(|held| {
                                                    let state = match held.has_exited() {
                                                        Ok(exited) => format!("exited={exited}"),
                                                        Err(error) => format!("unavailable-kind={:?}; raw-os-error={:?}", error.kind(), error.raw_os_error()),
                                                    };
                                                    (held.identity.birth, state)
                                                }).collect();
                                                io::Error::other(format!(
                                                    "generation ancestor was not independently held live; stage={}; ordinal={:?}; root-pid={root_pid}; child-pid={}; child-birth={}; depth={depth}; parent-pid={parent_pid}; held-parent-count={candidate_count}; held-parent-observations={candidates:?}; observations-truncated={}",
                                                    event.stage, event.ordinal, process.identity.pid, process.identity.birth, candidate_count > 8,
                                                ))
                                            })?;
                                        if parent.identity.birth > process.identity.birth {
                                            return Err(io::Error::other(
                                                "ToolHelp parent PID was reused after child creation",
                                            ));
                                        }
                                    }
                                }
                                if event.stage == "cohort-live" {
                                    let end = event.ordinal.expect("matched ordinal");
                                    let count = u32::from_le_bytes(
                                        event.value.as_slice().try_into().map_err(|_| {
                                            io::Error::other("invalid cohort count")
                                        })?,
                                    );
                                    if count == 0 || count > descriptor::CHURN_LIVE || count > end {
                                        return Err(io::Error::other(
                                            "cohort count differs from frozen controller bound",
                                        ));
                                    }
                                    if live_children != count as usize + 1 || live_children > 64 {
                                        return Err(io::Error::other(
                                            "native live population differs from cohort leaves plus retained TCP peer",
                                        ));
                                    }
                                    let children: Vec<_> = published
                                        .iter()
                                        .filter(|e| {
                                            e.stage == "child-created"
                                                && e.ordinal
                                                    .is_some_and(|n| n >= end - count && n < end)
                                        })
                                        .collect();
                                    let ordinals: BTreeSet<_> =
                                        children.iter().filter_map(|child| child.ordinal).collect();
                                    if children.len() != count as usize
                                        || ordinals != (end - count..end).collect()
                                    {
                                        return Err(io::Error::other(
                                            "cohort publication omitted or duplicated a required ordinal",
                                        ));
                                    }
                                    let mut unique = BTreeSet::new();
                                    for child in children {
                                        let identity: memcordon_core::WindowsProcessIdentityV1 =
                                            serde_json::from_slice(&child.value)
                                                .map_err(io::Error::other)?;
                                        if !unique.insert((
                                            identity.process_id,
                                            identity.creation_time_100ns,
                                        )) {
                                            return Err(io::Error::other(
                                                "cohort publication duplicated a native process identity",
                                            ));
                                        }
                                        if !family.iter().any(|p| {
                                            p.identity.pid == identity.process_id
                                                && p.identity.birth
                                                    == u128::from(identity.creation_time_100ns)
                                                && !p.has_exited().unwrap_or(true)
                                        }) {
                                            return Err(io::Error::other(
                                                "churn cohort identity was not held live before release",
                                            ));
                                        }
                                    }
                                }
                                let mut live_members = Vec::new();
                                for member in family
                                    .iter()
                                    .filter(|process| !process.has_exited().unwrap_or(true))
                                {
                                    if rooted_process_depth(
                                        (member.identity.pid, member.identity.birth),
                                        root_identity,
                                        &parents,
                                    )
                                    .is_none()
                                    {
                                        continue;
                                    }
                                    let parent = if member.identity.pid == root_pid {
                                        None
                                    } else {
                                        let parent_pid = *parents
                                            .get(&member.identity.pid)
                                            .ok_or_else(|| {
                                                io::Error::other("churn live ancestry edge missing")
                                            })?;
                                        Some(
                                            family
                                                .iter()
                                                .find(|parent| {
                                                    parent.identity.pid == parent_pid
                                                        && !parent.has_exited().unwrap_or(true)
                                                })
                                                .ok_or_else(|| {
                                                    io::Error::other(
                                                        "churn live ancestry owner missing",
                                                    )
                                                })?,
                                        )
                                    };
                                    live_members.push(serde_json::json!({
                                        "pid":member.identity.pid,"birth":member.identity.birth,
                                        "parent_pid":parent.map(|parent| parent.identity.pid),
                                        "parent_birth":parent.map(|parent| parent.identity.birth),
                                        "held_live_before_release":true,
                                    }));
                                }
                                let bytes = serde_json::to_vec(&serde_json::json!({
                                    "format":"memcordon.windows-native-churn-barrier","revision":1,
                                    "stage":event.stage,"ordinal":event.ordinal,"root_pid":root_pid,
                                    "live_children":live_children,"members":live_members,
                                }))
                                .map_err(io::Error::other)?;
                                let path = directory.join(format!(
                                    "native-{}-{}.json",
                                    event.stage,
                                    event.ordinal.expect("controller ordinal")
                                ));
                                let mut file = OpenOptions::new()
                                    .write(true)
                                    .create_new(true)
                                    .open(&path)?;
                                file.write_all(&bytes)?;
                                file.sync_all()?;
                                if read(&path, 128 * 1024).map_err(io::Error::other)? != bytes {
                                    return Err(io::Error::other(
                                        "native churn ancestry named readback differs",
                                    ));
                                }
                                let root = family
                                    .iter()
                                    .find(|held| {
                                        (held.identity.pid, held.identity.birth) == root_identity
                                    })
                                    .ok_or_else(|| {
                                        io::Error::other("original diagnostic root owner absent")
                                    })?;
                                let console_image =
                                    held_console_image.as_ref().ok_or_else(|| {
                                        io::Error::other("held native console image absent")
                                    })?;
                                let candidates = root.direct_children_for_image_until(
                                    &console_image.path,
                                    deadline,
                                )?;
                                let mut console = held_console_owners.lock().map_err(|_| {
                                    io::Error::other("native console ownership poisoned")
                                })?;
                                for candidate in candidates {
                                    if candidate.has_exited()? {
                                        continue;
                                    }
                                    if family
                                        .iter()
                                        .any(|held| held.identity == candidate.identity)
                                    {
                                        return Err(io::Error::other(
                                            "console identity overlaps fixture ownership",
                                        ));
                                    }
                                    if console.iter().any(|held| {
                                        held.identity.pid == candidate.identity.pid
                                            && held.identity.birth != candidate.identity.birth
                                    }) {
                                        return Err(io::Error::other(
                                            "console PID differs from original held birth",
                                        ));
                                    }
                                    if !console
                                        .iter()
                                        .any(|held| held.identity == candidate.identity)
                                    {
                                        if console.len() >= 8 {
                                            return Err(io::Error::other(
                                                "native console owners exceed finite bound",
                                            ));
                                        }
                                        console.push(candidate);
                                    }
                                }
                                if root.has_exited()? {
                                    return Err(io::Error::other(
                                        "original console parent retired before publication",
                                    ));
                                }
                                let owners = console
                                    .iter()
                                    .map(|owner| {
                                        Ok(serde_json::json!({
                                            "pid":owner.identity.pid,"birth":owner.identity.birth,
                                            "native_parent_pid":owner.native_parent_process_id()?,
                                            "exited":owner.has_exited()?,
                                        }))
                                    })
                                    .collect::<io::Result<Vec<_>>>()?;
                                let console_bytes = serde_json::to_vec(&serde_json::json!({
                                    "format":"memcordon.windows-native-console-owners","revision":1,
                                    "root_pid":root_identity.0,"root_birth":root_identity.1,
                                    "root_held_live":true,"job_membership_established":false,
                                    "image_utf16":console_image.path.as_os_str().encode_wide().collect::<Vec<_>>(),
                                    "image_sha256":console_image.sha256,"image_file_identity":console_image.identity,
                                    "owners":owners,
                                })).map_err(io::Error::other)?;
                                if console_bytes.len() > 256 * 1024 {
                                    return Err(io::Error::other(
                                        "native console ownership exceeds finite bound",
                                    ));
                                }
                                let console_path = directory.join(format!(
                                    "native-console-owners-{}-{}.json",
                                    event.stage,
                                    event.ordinal.expect("controller ordinal"),
                                ));
                                let mut console_file = OpenOptions::new()
                                    .write(true)
                                    .create_new(true)
                                    .open(&console_path)?;
                                console_file.write_all(&console_bytes)?;
                                console_file.sync_all()?;
                                if read(&console_path, 256 * 1024).map_err(io::Error::other)?
                                    != console_bytes
                                {
                                    return Err(io::Error::other(
                                        "native console ownership named readback differs",
                                    ));
                                }
                                drop(console);
                                let known: Vec<_> =
                                    family.iter().map(|held| held.identity).collect();
                                let diagnostic = match root
                                    .diagnose_unheld_direct_children(&known, deadline)
                                {
                                    Ok(value) => value,
                                    Err(error) => {
                                        let detail = error.to_string();
                                        serde_json::json!({"format":"memcordon.windows-unheld-direct-child-diagnostic","revision":1,
                                            "root_pid":root_identity.0,"root_birth":root_identity.1,
                                            "job_membership_established":false,"accepted_family_modified":false,
                                            "unavailable_kind":format!("{:?}",error.kind()),"raw_os_error":error.raw_os_error(),
                                            "detail":detail.chars().take(512).collect::<String>(),"detail_truncated":detail.chars().count()>512})
                                    }
                                };
                                let bytes =
                                    serde_json::to_vec(&diagnostic).map_err(io::Error::other)?;
                                if bytes.len() > 256 * 1024 {
                                    return Err(io::Error::other(
                                        "native child diagnostic exceeds finite bound",
                                    ));
                                }
                                let path = directory.join(format!(
                                    "native-unheld-children-{}-{}.json",
                                    event.stage,
                                    event.ordinal.expect("controller ordinal"),
                                ));
                                let mut file = OpenOptions::new()
                                    .write(true)
                                    .create_new(true)
                                    .open(&path)?;
                                file.write_all(&bytes)?;
                                file.sync_all()?;
                                if read(&path, 256 * 1024).map_err(io::Error::other)? != bytes {
                                    return Err(io::Error::other(
                                        "native child diagnostic named readback differs",
                                    ));
                                }
                                if Instant::now() >= deadline {
                                    return Err(io::Error::other(
                                        "original churn cutoff exhausted before release",
                                    ));
                                }
                                if root.has_exited()? {
                                    return Err(io::Error::other(
                                        "original console parent retired before barrier release",
                                    ));
                                }
                                drop(family);
                                signal(controller)?;
                            }
                        }
                        if published.iter().any(|e| e.stage == "churn-complete") {
                            break;
                        }
                        if Instant::now() >= deadline {
                            return Err(io::Error::other(
                                "churn native controller deadline expired",
                            ));
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
                if let Some(name) = descendant_gate {
                    let deadline = work_deadline.min(Instant::now() + Duration::from_secs(60));
                    let mut intermediate_held = false;
                    loop {
                        let events = super::live_events(
                            &read(&transcript, 16 * 1024 * 1024).map_err(io::Error::other)?,
                        )
                        .map_err(io::Error::other)?;
                        if intermediate_first && !intermediate_held {
                            if let Some(event) = events
                                .iter()
                                .find(|event| event.stage == "intermediate-live-with-descendant")
                            {
                                #[derive(Deserialize)]
                                #[serde(deny_unknown_fields)]
                                struct Intermediate {
                                    parent: memcordon_core::WindowsProcessIdentityV1,
                                    child: memcordon_core::WindowsProcessIdentityV1,
                                }
                                let identities: Intermediate = serde_json::from_slice(&event.value)
                                    .map_err(io::Error::other)?;
                                let mut active =
                                    memcordon_testkit::windows_processes_for_image_until(
                                        &fixture, deadline,
                                    )?;
                                let parents = process_parents()?;
                                let mut family = held_family
                                    .lock()
                                    .map_err(|_| io::Error::other("fixture ownership poisoned"))?;
                                let root = family
                                    .first()
                                    .ok_or_else(|| io::Error::other("held root missing"))?;
                                if root.has_exited()?
                                    || parents.get(&identities.parent.process_id) != Some(&root_pid)
                                    || parents.get(&identities.child.process_id)
                                        != Some(&identities.parent.process_id)
                                    || root.identity.birth
                                        > u128::from(identities.parent.creation_time_100ns)
                                    || identities.parent.creation_time_100ns
                                        > identities.child.creation_time_100ns
                                {
                                    return Err(io::Error::other(
                                        "intermediate native ancestry/ordering differs",
                                    ));
                                }
                                for expected in
                                    [identities.parent.clone(), identities.child.clone()]
                                {
                                    let index = active
                                        .iter()
                                        .position(|held| {
                                            held.identity.pid == expected.process_id
                                                && held.identity.birth
                                                    == u128::from(expected.creation_time_100ns)
                                        })
                                        .ok_or_else(|| {
                                            io::Error::other(
                                                "intermediate native held identity missing",
                                            )
                                        })?;
                                    let held = active.swap_remove(index);
                                    if held.has_exited()? {
                                        return Err(io::Error::other(
                                            "intermediate family already retired before controller",
                                        ));
                                    }
                                    family.push(held);
                                }
                                let bytes = serde_json::to_vec(&serde_json::json!({
                                    "format":"memcordon.windows-intermediate-live-family","revision":1,
                                    "root_pid":root_pid,"root_birth":family[0].identity.birth,
                                    "parent":identities.parent,"child":identities.child,
                                    "native_parent_edges_observed":true,"all_three_held_live":true
                                })).map_err(io::Error::other)?;
                                let mut file = OpenOptions::new()
                                    .write(true)
                                    .create_new(true)
                                    .open(directory.join("held-intermediate-family.json"))?;
                                file.write_all(&bytes)?;
                                file.sync_all()?;
                                drop(family);
                                descendant_release(&format!("{name}-intermediate-live"))?;
                                intermediate_held = true;
                            }
                        }
                        if let Some(event) = events.iter().find(|event| {
                            event.stage
                                == if intermediate_first {
                                    "intermediate-exits-with-live-descendant"
                                } else {
                                    "root-exits-with-live-descendant"
                                }
                        }) {
                            let child: memcordon_core::WindowsProcessIdentityV1 =
                                serde_json::from_slice(&event.value).map_err(io::Error::other)?;
                            let active = memcordon_testkit::windows_processes_for_image_until(
                                &fixture, deadline,
                            )?;
                            let held_child = active
                                .into_iter()
                                .find(|p| {
                                    p.identity.pid == child.process_id
                                        && p.identity.birth == u128::from(child.creation_time_100ns)
                                })
                                .ok_or_else(|| {
                                    io::Error::other("descendant native barrier identity differs")
                                })?;
                            let mut family = held_family
                                .lock()
                                .map_err(|_| io::Error::other("fixture ownership poisoned"))?;
                            let root_live = family
                                .first()
                                .is_some_and(|p| !p.has_exited().unwrap_or(false));
                            if root_live != intermediate_first {
                                drop(family);
                            } else {
                                if held_child.has_exited()? {
                                    return Err(io::Error::other(
                                        "descendant exited before root native observation",
                                    ));
                                }
                                if intermediate_first
                                    && (!intermediate_held
                                        || family.len() != 3
                                        || !family[1].has_exited()?)
                                {
                                    return Err(io::Error::other(
                                        "intermediate did not retire before its held live descendant",
                                    ));
                                }
                                if !family
                                    .iter()
                                    .any(|held| held.identity == held_child.identity)
                                {
                                    family.push(held_child);
                                }
                                drop(family);
                                descendant_release(&name)?;
                                break;
                            }
                        }
                        if Instant::now() >= deadline {
                            return Err(io::Error::other(
                                "root-first native ordering barrier not observed",
                            ));
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
                Ok(())
            },
        );
        let controller_resolution = if capture_gate_diagnostic && output.is_err() {
            let name: Vec<u16> = gate_name.encode_utf16().chain(Some(0)).collect();
            Some(super::gate_resolution::query(
                &name,
                Some(gate.as_ref()),
                || {
                    provision_budget(work_deadline)
                        .map(|_| ())
                        .map_err(io::Error::other)
                },
            ))
        } else {
            None
        };
        let gate_retention = (|| -> Result<()> {
            let Some(mut diagnostic) = gate_diagnostic else {
                return Ok(());
            };
            diagnostic["controller_context_named_resolution"] =
                serde_json::to_value(controller_resolution)?;
            diagnostic["controller_native_namespace_discovery"] = prepared
                .namespace
                .as_ref()
                .map(|value| value.observation.clone())
                .unwrap_or_else(
                    || serde_json::json!({"state":"unavailable","reason":"not-requested"}),
                );
            diagnostic["controller_native_namespace_descriptor_included"] = serde_json::json!(
                prepared
                    .input
                    .descriptor
                    .gate_access_diagnostic
                    .as_ref()
                    .is_some_and(|input| input.namespace.is_some())
            );
            diagnostic["controller_native_namespace_final_readback"] = prepared
                .namespace
                .as_ref()
                .map(|value| {
                    value.recheck(gate.as_ref(), || {
                        provision_budget(work_deadline)
                            .map(|_| ())
                            .map_err(io::Error::other)
                    })
                })
                .unwrap_or_else(
                    || serde_json::json!({"state":"unavailable","reason":"no-original-discovery"}),
                );
            let original = match gate_root_diagnostic.lock() {
                Ok(value) => value.clone(),
                Err(_) => Some(
                    serde_json::json!({"state":"unavailable","stage":"diagnostic-lock-poisoned"}),
                ),
            };
            diagnostic["original_fixture"] = original.unwrap_or_else(|| serde_json::json!({
                "state":"unavailable","reason":"existing barrier did not admit an original held fixture; no PID reopen attempted"
            }));
            let deadline = clocks.cleanup.unwrap_or(work_deadline);
            if Instant::now() >= deadline {
                return Err(CiError::Message(
                    "original controller-gate diagnostic retention cutoff elapsed".into(),
                ));
            }
            let final_security =
                super::workload_diagnostic::gate_security_snapshot(gate.as_ref(), deadline);
            let unchanged = prepared
                .original_descriptor_sha256
                .as_ref()
                .zip(final_security.as_ref().ok())
                .map(|(original, current)| original == &current.descriptor_sha256);
            diagnostic["descriptor_unchanged_since_prelaunch"] = serde_json::json!(unchanged);
            diagnostic["descriptor_comparison"] = serde_json::json!(match unchanged {
                Some(true) => "unchanged; inspect failed-call access result",
                Some(false) => "inconclusive: original descriptor drift",
                None => "inconclusive: original or final descriptor unavailable",
            });
            diagnostic["final_same_held_event_security"] = gate_query_result(final_security);
            diagnostic["final_same_held_event_mandatory_label"] = gate_query_result(
                super::workload_diagnostic::gate_mandatory_label_snapshot(gate.as_ref(), deadline),
            );
            let bytes = serde_json::to_vec(&diagnostic)?;
            if bytes.len() > 8 * super::gate_security::BYTE_BOUND {
                return Err(CiError::Message(
                    "controller-gate diagnostic exceeds bounded record".into(),
                ));
            }
            drop(crate::windows_native_files::publish_owned_file(
                &report.with_extension("controller-gate-security.json"),
                &bytes,
            )?);
            if Instant::now() >= deadline {
                return Err(CiError::Message(
                    "original controller-gate diagnostic retention cutoff elapsed".into(),
                ));
            }
            Ok(())
        })();
        let query_retention = (|| -> Result<()> {
            let snapshot =
                super::guardian_query::update(&guardian_query, |trace| trace.snapshot())?;
            let Some(snapshot) = snapshot else {
                return Ok(());
            };
            let deadline = clocks.cleanup.unwrap_or(work_deadline);
            for (extension, bytes) in [
                ("guardian-query.stdout.bin", snapshot.stdout),
                ("guardian-query.stderr.bin", snapshot.stderr),
                ("guardian-query.json", Some(snapshot.record)),
            ] {
                let Some(bytes) = bytes else {
                    continue;
                };
                if Instant::now() >= deadline {
                    return Err(CiError::Message(
                        "original guardian query retention cutoff exhausted".into(),
                    ));
                }
                drop(crate::windows_native_files::publish_owned_file(
                    &report.with_extension(extension),
                    &bytes,
                )?);
                if Instant::now() >= deadline {
                    return Err(CiError::Message(
                        "original guardian query retention cutoff exhausted".into(),
                    ));
                }
            }
            Ok(())
        })();
        let failure_case = serde_json::to_value(input.descriptor.case).ok();
        let failure_fixture = family.lock().ok().and_then(|held| {
            held.first()
                .map(|process| (process.identity.pid, process.identity.birth))
        });
        let failure_guardian = guardian_owner.lock().ok().and_then(|held| {
            held.first().map(|process| {
                (
                    process.identity.process_id,
                    u128::from(process.identity.creation_time_100ns),
                )
            })
        });
        let expected_gate_failure = match (
            failure_case.as_ref(),
            input.descriptor.gate_access_diagnostic.as_ref(),
            failure_fixture,
        ) {
            (Some(case), Some(binding), Some((fixture_pid, fixture_birth))) => {
                Some(crate::windows_original_gate_failure::Expected {
                    case,
                    challenge_sha256: &binding.challenge_sha256,
                    gate_name_utf16_sha256: &binding.name_utf16_sha256,
                    fixture_pid,
                    fixture_birth,
                    guardian: failure_guardian,
                    guardian_query_failed: super::guardian_query::update(
                        &guardian_query,
                        |trace| trace.failure().is_some(),
                    ),
                })
            }
            _ => None,
        };
        let callback_error = |error| {
            crate::windows_original_gate_failure::callback_failure(
                error,
                expected_gate_failure.as_ref(),
            )
        };
        let collection = (|| -> Result<()> {
            if let Err(memcordon_testkit::ProcessTestError::Callback {
                stdout,
                stderr,
                capture_complete,
                observed_status,
                termination,
                cleanup,
                error,
            }) = &output
            {
                let retention = (|| -> Result<()> {
                    let product_context = if *capture_complete && cleanup.is_ok() {
                        retain_callback_product_context(&public_report, &report, &config.provider)
                            .map_err(|error| error.to_string())
                    } else {
                        Err("callback capture or cleanup is unsettled".to_owned())
                    };
                    let diagnostic = serde_json::to_vec(&serde_json::json!({
                        "format":"memcordon.windows-positive-callback-failure", "revision":1,
                        "error":error.to_string(), "capture_complete":capture_complete,
                        "observed_status":observed_status.map(|status| status.code()),
                        "termination":termination.map(|status| status.code()), "cleanup":cleanup,
                        "product_context":product_context,
                    }))?;
                    for (extension, bytes) in [
                        ("stdout.bin", stdout.as_slice()),
                        ("stderr.bin", stderr.as_slice()),
                        ("callback-failure.json", diagnostic.as_slice()),
                    ] {
                        let path = report.with_extension(extension);
                        let mut file = OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(&path)?;
                        file.write_all(bytes)?;
                        file.sync_all()?;
                        if read(&path, 16 * 1024 * 1024)? != bytes {
                            return Err(CiError::Message(
                                "callback capture named readback differs".into(),
                            ));
                        }
                    }
                    Ok(())
                })();
                if let Err(retention) = retention {
                    return Err(CiError::LaneFailures {
                        primary: Box::new(callback_error(
                            output.expect_err("callback failure was matched"),
                        )),
                        secondary: Box::new(
                            retention.context("callback diagnostic retention failed"),
                        ),
                    });
                }
                if *capture_complete
                    && cleanup.is_ok()
                    && input.key.family == "W-ENVELOPE"
                    && input.key.scenario == "restricted"
                {
                    let diagnostics = (|| -> Result<()> {
                        let bytes = read(
                            &public_report,
                            crate::windows_causal_acceptance::MAX_REPORT_BYTES,
                        )?;
                        let original = ResultV3::parse(&bytes).map_err(CiError::Message)?;
                        if original.provider.as_ref() != Some(&config.provider) {
                            return Err(CiError::Message(
                                "OS diagnostic original result provider differs".into(),
                            ));
                        }
                        let bootstrap_refusal = original.release == ReleaseKnowledgeV3::NotReleased
                            && original.diagnostics.as_slice().iter().any(|detail| {
                                detail.as_str().contains("MCSPAWN-FAILED")
                                    && detail.as_str().contains("bootstrap_role=loader-control")
                            });
                        let released_target =
                            super::released_target_loader_event_candidate(&original);
                        if !bootstrap_refusal && !released_target {
                            return Ok(());
                        }
                        if released_target {
                            let descriptor = super::workload_diagnostic::gate_sddl(gate.as_ref())?;
                            drop(crate::windows_native_files::publish_owned_file(
                                &report.with_extension("original-gate.sddl"),
                                descriptor.as_bytes(),
                            )?);
                        }
                        let capture = super::loader_event_diagnostics::observe(work_deadline);
                        let observed_utc = std::time::SystemTime::now();
                        let failure = &original.diagnostics;
                        let unix_millis = |time: std::time::SystemTime| {
                            time.duration_since(std::time::UNIX_EPOCH)
                                .map(|duration| duration.as_millis())
                                .map_err(|error| CiError::Message(error.to_string()))
                        };
                        let metadata = serde_json::to_vec(&serde_json::json!({
                            "format":"memcordon.windows-loader-os-event-candidates","revision":1,
                            "case":input.key,"provider":config.provider,"source_commit":config.source_commit,
                            "association":super::current_association(&original).ok(),
                            "installed_images":config.installed_components,"original_result":public_report,
                            "original_result_sha256":crate::windows_causal_acceptance::sha256(&bytes),
                            "original_failure":failure,
                            "trigger":if released_target { "released-target-initialization-failure" } else { "bootstrap-launch-refusal" },
                            "original_outcome":original.outcome,
                            "observed_target_pid":super::current_native(&original).ok().and_then(|native| native.target_identity.as_ref()).map(|identity| identity.process_id),
                            "observed_target_pid_is_not_faulting_identity":true,
                            "controller_started_unix_millis":unix_millis(native_started_utc)?,
                            "controller_observed_unix_millis":unix_millis(observed_utc)?,
                            "bootstrap_birth_identity":null,"event_correlation":"unverified-candidates",
                            "correlation_missing":["trusted-bootstrap-birth","validated-faulting-process-id-and-starttime"],
                            "event_execution_pid_is_not_faulting_process_identity":true,
                            "program":capture.program,"argv":super::loader_event_diagnostics::QUERY_ARGUMENTS,
                            "total_output_limit":super::loader_event_diagnostics::MAX_CAPTURE_BYTES,
                            "query":capture.state
                        }))?;
                        for (extension, bytes) in [
                            ("os-events.stdout.xml", capture.stdout.as_slice()),
                            ("os-events.stderr.bin", capture.stderr.as_slice()),
                            ("os-events.json", metadata.as_slice()),
                        ] {
                            let path = report.with_extension(extension);
                            let mut file = OpenOptions::new()
                                .write(true)
                                .create_new(true)
                                .open(&path)?;
                            file.write_all(bytes)?;
                            file.sync_all()?;
                            if read(&path, bytes.len())? != bytes {
                                return Err(CiError::Message(
                                    "OS diagnostic named readback differs".into(),
                                ));
                            }
                        }
                        Ok(())
                    })();
                    if let Err(diagnostic) = diagnostics {
                        return Err(CiError::LaneFailures {
                            primary: Box::new(callback_error(
                                output.expect_err("callback failure was matched"),
                            )),
                            secondary: Box::new(
                                diagnostic.context("secondary OS diagnostic retention failed"),
                            ),
                        });
                    }
                }
            }
            let output = output.map_err(callback_error)?;
            let exit_bytes = serde_json::to_vec(&serde_json::json!({
                "format":"memcordon.windows-positive-exit","revision":1,
                "target":config.target,"executable_sha256":execution_sha256,"public_executable_sha256":config.cli.sha256,
                "native_status":output.status.code(),"capture_complete":true,
            }))?;
            let exit_path = report
                .parent()
                .expect("case report has parent")
                .join("native-exit.json");
            let mut exit_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&exit_path)?;
            exit_file.write_all(&exit_bytes)?;
            exit_file.sync_all()?;
            if read(&exit_path, 16 * 1024)? != exit_bytes {
                return Err(CiError::Message(
                    "positive native exit named readback differs".into(),
                ));
            }
            fs::write(report.with_extension("stdout.bin"), &output.stdout)?;
            fs::write(report.with_extension("stderr.bin"), &output.stderr)?;
            let result_bytes = read(
                &public_report,
                crate::windows_causal_acceptance::MAX_REPORT_BYTES,
            )?;
            let terminal_bytes = read(
                &public_report.with_extension("terminal-observation.json"),
                memcordon_platform::MAX_TERMINAL_OBSERVATION_BYTES,
            )?;
            // The restricted frontend publishes only in its declared candidate
            // output tree. After native retirement the ordinary controller takes
            // immutable copies into its protected record tree for verification.
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&report)?
                .write_all(&result_bytes)?;
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(report.with_extension("terminal-observation.json"))?
                .write_all(&terminal_bytes)?;
            let terminal: memcordon_platform::AuthenticatedWindowsTerminalObservation =
                serde_json::from_slice(&terminal_bytes)?;
            let final_descriptor_bytes =
                read(&input.descriptor_path, descriptor::MAX_DESCRIPTOR_BYTES)?;
            let mut final_descriptor: descriptor::Descriptor =
                serde_json::from_slice(&final_descriptor_bytes)?;
            final_descriptor.validate().map_err(CiError::Message)?;
            if input.key.family == "W-ENVELOPE" && input.key.scenario == "sentinel-handles" {
                if final_descriptor.sentinel_handles.len() != 1 {
                    return Err(CiError::Message(
                        "native sentinel frontend did not augment exactly one held identity".into(),
                    ));
                }
                final_descriptor.sentinel_handles.clear();
            }
            if serde_json::to_vec(&final_descriptor)? != descriptor_bytes {
                return Err(CiError::Message(
                    "final fixture descriptor differs beyond authorized sentinel augmentation"
                        .into(),
                ));
            }
            record.descriptor_sha256 =
                crate::windows_causal_acceptance::sha256(&final_descriptor_bytes);
            let transcript = read(&input.descriptor.transcript, 16 * 1024 * 1024)?;
            record.result_sha256 = Some(crate::windows_causal_acceptance::sha256(&result_bytes));
            record.stdout_sha256 = Some(crate::windows_causal_acceptance::sha256(&output.stdout));
            record.stderr_sha256 = Some(crate::windows_causal_acceptance::sha256(&output.stderr));
            record.transcript_sha256 = Some(crate::windows_causal_acceptance::sha256(&transcript));
            record.terminal_observation_sha256 =
                Some(crate::windows_causal_acceptance::sha256(&terminal_bytes));
            record.collection = Ok(());
            let held = association
                .lock()
                .map_err(|_| CiError::Message("association ownership poisoned".into()))?;
            let held = held.as_ref().ok_or_else(|| {
                CiError::Message("native request/attempt association not held".into())
            })?;
            assess(
                input,
                &result_bytes,
                &output.stdout,
                &output.stderr,
                &transcript,
                FrontendExit {
                    status: output
                        .status
                        .code()
                        .ok_or_else(|| CiError::Message("missing native frontend status".into()))?,
                    original_pid: {
                        let frontend = frontend
                            .lock()
                            .map_err(|_| CiError::Message("frontend ownership poisoned".into()))?;
                        match frontend.as_ref() {
                            Some(process) if process.has_exited()? => Some(process.identity.pid),
                            Some(_) => {
                                return Err(CiError::Message(
                                    "original status frontend remains live after wrapper exit"
                                        .into(),
                                ));
                            }
                            None => None,
                        }
                    },
                },
                held,
            )?;
            if terminal.format != "memcordon.windows-terminal-observation"
                || terminal.revision != 2
                || terminal.provider != held.provider
                || terminal.terminal.attempt_id != String::from(held.attempt_id.clone())
                || terminal.terminal.request_sha256 != String::from(held.request_sha256.clone())
                || terminal.terminal.validate_for_attempt().is_err()
                || !terminal.frontend_delivery.is_consistent()
                || terminal.frontend_delivery.attempt_id != terminal.terminal.attempt_id
                || terminal.frontend_delivery.nonce != terminal.terminal.nonce
                || terminal.frontend_delivery.request_sha256 != terminal.terminal.request_sha256
            {
                return Err(CiError::Message(
                    "authenticated terminal sidecar differs from held attempt/request/provider"
                        .into(),
                ));
            }
            let request: memcordon_core::WindowsLaunchRequestV2 =
                serde_json::from_slice(&terminal.provider_request)?;
            let contract = memcordon_core::workload_request::WorkloadRequestV1::parse(&read(
                &input.workload_request,
                256 * 1024,
            )?)
            .map_err(|error| CiError::Message(error.to_string()))?;
            if crate::windows_causal_acceptance::sha256(&terminal.provider_request)
                != terminal.terminal.request_sha256
                || request.expected_provider_binding != held.provider
                || request.nonce != terminal.terminal.nonce
                || request.workload_request.as_ref() != Some(&contract)
                || request.environment != fixture_environment::entries()?
            {
                return Err(CiError::Message("exact observed launch request differs from held binding, declared contract or native system prerequisite environment".into()));
            }
            if input.descriptor.case == descriptor::Case::Churn {
                let observation = &terminal.terminal.process_observation;
                let native_family = family
                    .lock()
                    .map_err(|_| CiError::Message("fixture ownership poisoned".into()))?;
                let native_console = console_owners
                    .lock()
                    .map_err(|_| CiError::Message("native console ownership poisoned".into()))?;
                let identities: Vec<_> = native_family
                    .iter()
                    .chain(native_console.iter())
                    .map(|process| {
                        Ok(memcordon_core::WindowsProcessIdentityV1 {
                            process_id: process.identity.pid,
                            creation_time_100ns: u64::try_from(process.identity.birth).map_err(
                                |_| {
                                    CiError::Message(
                                        "native process birth exceeds Windows FILETIME width"
                                            .into(),
                                    )
                                },
                            )?,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                let root = identities
                    .first()
                    .cloned()
                    .ok_or_else(|| CiError::Message("native root handle missing".into()))?;
                crate::windows_causal_acceptance::validate_process_observation(
                    observation,
                    &identities,
                    &crate::windows_causal_acceptance::ObservationExpectation {
                        root,
                        attempt_id: terminal.terminal.attempt_id.clone(),
                        nonce: terminal.terminal.nonce.clone(),
                        request_sha256: terminal.terminal.request_sha256.clone(),
                        worker_loss_before_freeze: false,
                    },
                )?;
                let memcordon_core::ProcessObservationCoverageV1::Sampled {
                    policy,
                    counters,
                    omissions,
                    ..
                } = &observation.coverage
                else {
                    return Err(CiError::Message(
                        "successful churn cannot substitute unavailable sampling".into(),
                    ));
                };
                if input.descriptor.churn_creations as usize <= policy.sample_slots()
                    || counters.sample_evictions == 0
                    || omissions.sample_eviction == 0
                {
                    return Err(CiError::Message("successful churn did not exercise the selected sample capacity/eviction policy".into()));
                }
            }
            fixture_products(input)?;
            record.behavior = Ok(());
            Ok(())
        })();
        if let Err(error) = &collection {
            record.behavior = Err(error.to_string());
        }
        let retirement = (|| -> Result<()> {
            let held = family
                .lock()
                .map_err(|_| CiError::Message("fixture ownership poisoned".into()))?;
            if held.is_empty() || held.iter().any(|p| !p.has_exited().unwrap_or(false)) {
                return Err(CiError::Message(
                    "independently held fixture family did not retire".into(),
                ));
            }
            let remaining = memcordon_testkit::windows_processes_for_image_until(
                &config.fixture.path,
                work_deadline,
            )?;
            if let Some(owned) = &excluded_fixture {
                let expected: BTreeSet<_> = owned
                    .family
                    .iter()
                    .map(|process| (process.identity.pid, process.identity.birth))
                    .collect();
                let actual: BTreeSet<_> = remaining
                    .iter()
                    .map(|process| (process.identity.pid, process.identity.birth))
                    .collect();
                if expected.len() != owned.family.len()
                    || actual != expected
                    || owned
                        .family
                        .iter()
                        .any(|process| !matches!(process.has_exited(), Ok(false)))
                {
                    return Err(CiError::Message(
                        "overlap remaining population differs from independently held first family"
                            .into(),
                    ));
                }
            } else if !remaining.is_empty() {
                return Err(CiError::Message(
                    "same-image population remains after isolated fixture retirement".into(),
                ));
            }
            let root = held
                .first()
                .ok_or_else(|| CiError::Message("native retirement root hold absent".into()))?
                .identity;
            let mut identities: Vec<_> = held.iter().map(|process|->Result<serde_json::Value> {
                let (parent_pid,parent_birth)=if process.identity==root {(None,None)} else {
                    let parent_pid=process.native_parent_process_id()?;
                    let parent=held.iter().find(|parent|parent.identity.pid==parent_pid&&parent.identity.birth<=process.identity.birth)
                        .ok_or_else(||CiError::Message("retained native descendant lacks its exact held ancestor".into()))?;
                    (Some(parent_pid),Some(parent.identity.birth))
                };
                Ok(serde_json::json!({"pid":process.identity.pid,"birth":process.identity.birth,
                    "parent_pid":parent_pid,"parent_birth":parent_birth,"retirement_observed":true}))
            }).collect::<Result<Vec<_>>>()?;
            let console = console_owners
                .lock()
                .map_err(|_| CiError::Message("native console ownership poisoned".into()))?;
            for process in console.iter() {
                if !process.has_exited()?
                    || process.native_parent_process_id()? != root.pid
                    || process.identity.birth < root.birth
                    || held.iter().any(|owner| owner.identity == process.identity)
                {
                    return Err(CiError::Message(
                        "original held console child retirement differs".into(),
                    ));
                }
                identities.push(serde_json::json!({
                    "pid":process.identity.pid,"birth":process.identity.birth,
                    "parent_pid":root.pid,"parent_birth":root.birth,"retirement_observed":true,
                }));
            }
            drop(console);
            drop(held);
            let guardian = guardian_owner
                .lock()
                .map_err(|_| CiError::Message("guardian ownership poisoned".into()))?;
            if guardian.len() != 1 {
                return Err(CiError::Message(format!(
                    "held native guardian cardinality differs; retained-owners={}",
                    guardian.len()
                )));
            }
            if !guardian[0].has_retired()? {
                return Err(CiError::Message(
                    "exact held native guardian has not retired".into(),
                ));
            }
            if require_global_quiescence {
                GuardianBaseline::quiescent(
                    &config.installed_agent.path,
                    &config.installed_manifest.path,
                    &config.installed_agent.sha256,
                    &config.installed_manifest.sha256,
                )?;
            }
            let association = association
                .lock()
                .map_err(|_| CiError::Message("association ownership poisoned".into()))?;
            let association = association
                .as_ref()
                .ok_or_else(|| CiError::Message("held retirement association missing".into()))?;
            let mut observed = serde_json::json!({
                "format":"memcordon.windows-native-positive-retirement", "revision":1,
                "association":association, "held_processes":identities,
                "guardian_identity":guardian[0].identity,
                "guardian_retirement_observed":true, "same_image_processes_absent":remaining.is_empty(),
                "global_quiescence_required":require_global_quiescence,
            });
            if let Some(owned) = &excluded_fixture {
                observed["format"] = "memcordon.windows-native-overlap-retirement".into();
                observed["excluded_live_association"] = serde_json::to_value(&owned.observation)?;
                observed["excluded_held_processes"] = serde_json::json!(owned.family.iter().map(|process|serde_json::json!({
                    "pid":process.identity.pid,"birth":process.identity.birth,"held_live_before_overlap":true,"still_live_at_own_retirement":true,
                })).collect::<Vec<_>>());
            }
            let bytes = serde_json::to_vec(&observed)?;
            let path = report
                .parent()
                .expect("case report has parent")
                .join("native-retirement.json");
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            if read(&path, 16 * 1024 * 1024)? != bytes {
                return Err(CiError::Message(
                    "native retirement named readback differs".into(),
                ));
            }
            Ok(())
        })();
        record.retirement = retirement.as_ref().map(|_| ()).map_err(ToString::to_string);
        let gate_retention = match (gate_retention, query_retention) {
            (Err(original), Err(query)) => Err(CiError::Message(format!(
                "{original}; secondary guardian query retention={query}"
            ))),
            (Err(original), _) => Err(original),
            (Ok(()), query) => query,
        };
        if let Err(error) = gate_retention {
            eprintln!("optional native gate diagnostics unavailable: {error}");
        }
        match (collection, retirement) {
            (Err(primary), Err(cleanup)) => Err(CiError::LaneFailures {
                primary: Box::new(primary),
                secondary: Box::new(cleanup.context("owned retirement")),
            }),
            (Err(primary), _) => Err(primary),
            (Ok(()), retirement) => retirement,
        }
    }

    pub fn run(
        config: &crate::windows_installed_cases::InstalledWindowsPayload,
        input_path: &Path,
        assessments: &mut Vec<CaseAssessment>,
        work_deadline: Instant,
        diagnostic_deadlines: Option<crate::windows_installed_cases::WindowsLeaseDeadlines>,
    ) -> Result<()> {
        let input: SuiteInput = serde_json::from_slice(&read(input_path, 4 * 1024 * 1024)?)?;
        validate_suite(&input)?;
        let caller = input
            .cases
            .iter()
            .find(|case| case.key.scenario == "ordinary")
            .ok_or_else(|| CiError::Message("ordinary native caller snapshot missing".into()))?;
        let sid = sid_text(&caller.expected_token.user_sid)?;
        let provider_root = config
            .installed_agent
            .path
            .parent()
            .ok_or_else(|| CiError::Message("installed agent root missing".into()))?;
        let provider_probe = provider_root.join("protected-readiness-probe");
        fs::create_dir(&provider_probe)?;
        set_directory_acl(
            &provider_probe,
            &format!("D:P(D;OICI;GW;;;RC)(A;OICI;GA;;;{sid})(A;OICI;GRGX;;;RC)(A;OICI;GA;;;SY)"),
        )?;
        assessments.extend(input.cases.iter().map(|case| CaseAssessment {
            key: case.key.clone(),
            behavior: Err("case not run".into()),
            collection: Err("case not collected".into()),
            retirement: Err("case retirement not observed".into()),
            descriptor_sha256: String::new(),
            result_sha256: None,
            stdout_sha256: None,
            stderr_sha256: None,
            transcript_sha256: None,
            request_sha256: None,
            terminal_observation_sha256: None,
        }));
        let mut first_error = None;
        for (case, assessment) in input.cases.iter().zip(assessments.iter_mut()) {
            let mut execution = case.clone();
            let request_bytes = read(
                &case.workload_request,
                memcordon_core::workload_limits::REQUEST_BYTES,
            )?;
            execution.workload_request =
                write_workload_request(&config.output_directory, &case.key, &request_bytes)?;
            let request =
                memcordon_core::workload_request::WorkloadRequestV1::parse(&request_bytes)
                    .map_err(|error| CiError::Message(error.to_string()))?;
            assessment.request_sha256 = Some(String::from(
                request
                    .digest()
                    .map_err(|error| CiError::Message(error.to_string()))?,
            ));
            if let Err(error) = execute_until_with_cleanup(
                config,
                &execution,
                assessment,
                work_deadline,
                diagnostic_deadlines.map(|deadlines| deadlines.cleanup),
            ) {
                let error = error.context(format!(
                    "Windows required case {}/{} failed after original case cleanup",
                    case.key.family, case.key.scenario
                ));
                eprintln!("{error}");
                first_error = Some(error);
                break;
            }
        }
        if let Some(error) = first_error {
            Err(error)
        } else if accepted(assessments) {
            Ok(())
        } else {
            Err(CiError::Message("Windows positive suite incomplete".into()))
        }
    }
}
