//! Installed-channel lifecycle using selected payload bytes and the public CLI.
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::windows_causal_acceptance::{InstalledCaseResult, InstalledChannel};
use crate::{CiError, Result};

#[derive(Serialize)]
struct PackageOperationCapture<'a> {
    format: &'static str,
    revision: u32,
    operation: &'a str,
    operation_complete: bool,
    streams_available: bool,
    stdout_reader_finished: Option<bool>,
    stderr_reader_finished: Option<bool>,
    observed_exit_code: Option<i32>,
    failure: Option<String>,
}

/// Retain actual bounded package output before assessing native success. Timeout
/// streams are snapshots; cleanup does not turn them into a completed operation.
pub fn retain_package_operation(
    directory: &Path,
    operation: &str,
    output: std::result::Result<
        memcordon_testkit::ObservedOutput,
        memcordon_testkit::ProcessTestError,
    >,
) -> std::result::Result<(), String> {
    let (stdout_name, stderr_name, capture_name) = match operation {
        "install" => (
            "package-install.stdout.bin",
            "package-install.stderr.bin",
            "package-install.capture.json",
        ),
        "upgrade" => (
            "package-upgrade.stdout.bin",
            "package-upgrade.stderr.bin",
            "package-upgrade.capture.json",
        ),
        "uninstall" => (
            "package-uninstall.stdout.bin",
            "package-uninstall.stderr.bin",
            "package-uninstall.capture.json",
        ),
        "verify" => (
            "package-verify.stdout.bin",
            "package-verify.stderr.bin",
            "package-verify.capture.json",
        ),
        _ => return Err("unknown package operation".to_owned()),
    };
    let streams = match &output {
        Ok(output) => Some((output.stdout.as_slice(), output.stderr.as_slice())),
        Err(memcordon_testkit::ProcessTestError::Timeout { stdout, stderr, .. }) => {
            Some((stdout.as_slice(), stderr.as_slice()))
        }
        Err(_) => None,
    };
    if let Some((stdout, stderr)) = streams {
        let limit = crate::windows_causal_acceptance::MAX_STREAM_BYTES;
        if stdout.len() > limit || stderr.len() > limit {
            return Err("package output exceeds retained stream bound".to_owned());
        }
        for (name, bytes) in [(stdout_name, stdout), (stderr_name, stderr)] {
            if let Err(error) = retain_package_leaf(directory, name, bytes, None) {
                // Only assess on this exceptional recording path, so losing a
                // diagnostic file cannot replace the native failure itself.
                let mut failure = match &output {
                    Ok(output) => format!(
                        "package {operation} native exit: {:?}",
                        output.status.code()
                    ),
                    Err(memcordon_testkit::ProcessTestError::Timeout {
                        deadline, cleanup, ..
                    }) => format!(
                        "package {operation} timed out after {deadline:?}; capture incomplete; cleanup {cleanup:?}"
                    ),
                    Err(error) => format!("package {operation} failed: {error}"),
                };
                append_package_stderr(&mut failure, stderr);
                return Err(format!("{failure}; {error}"));
            }
        }
    }
    let mut capture = PackageOperationCapture {
        format: "memcordon.package-operation-capture",
        revision: 1,
        operation,
        operation_complete: false,
        streams_available: false,
        stdout_reader_finished: None,
        stderr_reader_finished: None,
        observed_exit_code: None,
        failure: None,
    };
    let stderr = match output {
        Ok(output) => {
            capture.operation_complete = true;
            capture.streams_available = true;
            capture.stdout_reader_finished = Some(true);
            capture.stderr_reader_finished = Some(true);
            capture.observed_exit_code = output.status.code();
            if !output.status.success() {
                capture.failure = Some(format!(
                    "package {operation} failed: {:?}",
                    output.status.code()
                ));
            }
            Some(output.stderr)
        }
        Err(memcordon_testkit::ProcessTestError::Timeout {
            deadline,
            stdout: _,
            stderr,
            cleanup,
            observation,
        }) => {
            capture.streams_available = true;
            capture.stdout_reader_finished = Some(observation.stdout_reader_finished);
            capture.stderr_reader_finished = Some(observation.stderr_reader_finished);
            capture.observed_exit_code =
                observation.observed_status.and_then(|status| status.code());
            capture.failure = Some(format!(
                "package {operation} timed out after {deadline:?}; capture incomplete; cleanup {cleanup:?}"
            ));
            Some(stderr)
        }
        Err(error) => {
            capture.failure = Some(format!(
                "package {operation} failed: {error}; output unavailable"
            ));
            None
        }
    };
    if let (Some(stderr), Some(failure)) = (stderr, &mut capture.failure) {
        // Keep errors useful and bounded; the exact binary stream remains in
        // its separate diagnostic leaf, including any non-UTF-8 bytes.
        append_package_stderr(failure, &stderr);
    }
    let bytes = serde_json::to_vec_pretty(&capture).map_err(|error| error.to_string())?;
    retain_package_leaf(directory, capture_name, &bytes, capture.failure.as_deref())?;
    match capture.failure {
        Some(failure) => Err(failure),
        None => Ok(()),
    }
}

fn append_package_stderr(failure: &mut String, stderr: &[u8]) {
    const ERROR_STDERR_BYTES: usize = 4096;
    let prefix = &stderr[..stderr.len().min(ERROR_STDERR_BYTES)];
    failure.push_str("; stderr: ");
    failure.push_str(&String::from_utf8_lossy(prefix));
    if prefix.len() != stderr.len() {
        failure.push_str(" [truncated; see bounded raw stream capture]");
    }
}

fn retain_package_leaf(
    directory: &Path,
    name: &str,
    bytes: &[u8],
    operation_failure: Option<&str>,
) -> std::result::Result<(), String> {
    let result = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join(name))
        .and_then(|mut file| file.write_all(bytes));
    result.map_err(|error| {
        let failure = operation_failure.unwrap_or("package operation status not assessed");
        format!("{failure}; retaining package diagnostic {name} failed: {error}")
    })
}

/// Record the observation subprocess independently of the workload streams.
/// Recording does not accept its status or grant any guardian authority.
pub fn retain_guardian_query_capture(
    directory: &Path,
    output: &std::result::Result<
        memcordon_testkit::ObservedOutput,
        memcordon_testkit::ProcessTestError,
    >,
) -> std::result::Result<(), String> {
    let mut capture = PackageOperationCapture {
        format: "memcordon.guardian-observation-capture",
        revision: 1,
        operation: "observe-guardian",
        operation_complete: false,
        streams_available: false,
        stdout_reader_finished: None,
        stderr_reader_finished: None,
        observed_exit_code: None,
        failure: None,
    };
    let streams = match output {
        Ok(output) => {
            capture.operation_complete = true;
            capture.streams_available = true;
            capture.stdout_reader_finished = Some(true);
            capture.stderr_reader_finished = Some(true);
            capture.observed_exit_code = output.status.code();
            if !output.status.success() || output.stdout.len() > 16 * 1024 {
                capture.failure = Some(format!(
                    "live guardian association query failed or exceeded bound; native exit {:?}",
                    output.status.code()
                ));
            }
            Some((output.stdout.as_slice(), output.stderr.as_slice()))
        }
        Err(memcordon_testkit::ProcessTestError::Timeout {
            deadline,
            stdout,
            stderr,
            cleanup,
            observation,
        }) => {
            capture.streams_available = true;
            capture.stdout_reader_finished = Some(observation.stdout_reader_finished);
            capture.stderr_reader_finished = Some(observation.stderr_reader_finished);
            capture.observed_exit_code = observation
                .observed_status
                .as_ref()
                .and_then(std::process::ExitStatus::code);
            capture.failure = Some(format!(
                "guardian observation timed out after {deadline:?}; capture incomplete; cleanup {cleanup:?}"
            ));
            Some((stdout.as_slice(), stderr.as_slice()))
        }
        Err(error) => {
            capture.failure = Some(format!("guardian observation output unavailable: {error}"));
            None
        }
    };
    if let (Some((_, stderr)), Some(failure)) = (streams, &mut capture.failure) {
        append_package_stderr(failure, stderr);
    }
    let retain = |name: &str, bytes: &[u8]| {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join(name))
            .and_then(|mut file| file.write_all(bytes))
            .map_err(|error| {
                format!(
                    "{}; retaining guardian query diagnostic {name} failed: {error}",
                    capture
                        .failure
                        .as_deref()
                        .unwrap_or("guardian query status not assessed")
                )
            })
    };
    if let Some((stdout, stderr)) = streams {
        if stdout.len() > 16 * 1024 || stderr.len() > 16 * 1024 {
            return Err(format!(
                "{}; guardian query output exceeds retained stream bound",
                capture
                    .failure
                    .as_deref()
                    .unwrap_or("guardian query status not assessed")
            ));
        }
        retain("guardian-query.stdout.bin", stdout)?;
        retain("guardian-query.stderr.bin", stderr)?;
    }
    let bytes = serde_json::to_vec_pretty(&capture).map_err(|error| error.to_string())?;
    retain("guardian-query.capture.json", &bytes)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedArtifact {
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledWindowsPayload {
    pub channel: InstalledChannel,
    pub source_commit: String,
    pub version: String,
    pub target: String,
    pub artifacts: Vec<SelectedArtifact>,
    pub cli: SelectedArtifact,
    pub agent: SelectedArtifact,
    pub components: Vec<SelectedArtifact>,
    pub installed_components: Vec<SelectedArtifact>,
    pub fixture: SelectedArtifact,
    pub installed_agent: SelectedArtifact,
    pub installed_manifest: SelectedArtifact,
    pub provider: memcordon_core::PublicProviderBindingV1,
    pub output_directory: PathBuf,
}

/// Complete measured rc.19 Cargo runtime, acquired separately from this cell.
/// Its CLI-only native archive cannot supply this predecessor.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsUpgradePredecessor {
    pub format: String,
    pub revision: u32,
    pub payload: InstalledWindowsPayload,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsLeasePhase {
    BeforeOldInstall,
    AfterOldInstall,
    AfterOldVerify,
    BeforeCurrentUpgrade,
    AfterCurrentUpgrade,
    BeforeUninstall,
    AfterUninstall,
}

#[derive(Clone, Copy, Debug)]
pub struct WindowsLeaseDeadlines {
    pub work: std::time::Instant,
    pub cleanup: std::time::Instant,
    pub work_deadline_unix_millis: u64,
    pub cleanup_deadline_unix_millis: u64,
}

impl WindowsLeaseDeadlines {
    /// Clamp a native work operation to the original cutoff. Exhaustion is an
    /// error before spawning; no retry receives a renewed operation budget.
    pub fn work_budget(self, maximum: std::time::Duration) -> Result<std::time::Duration> {
        let remaining = self
            .work
            .saturating_duration_since(std::time::Instant::now())
            .min(maximum);
        if remaining.is_zero() {
            return Err(CiError::Message(
                "original Windows work deadline exhausted".into(),
            ));
        }
        Ok(remaining)
    }
    pub fn cleanup_budget(self, maximum: std::time::Duration) -> Result<std::time::Duration> {
        let remaining = self
            .cleanup
            .saturating_duration_since(std::time::Instant::now())
            .min(maximum);
        if remaining.is_zero() {
            return Err(CiError::Message(
                "reserved Windows cleanup deadline exhausted; retirement uncertain".into(),
            ));
        }
        Ok(remaining)
    }
    pub(crate) fn finite_default() -> Self {
        let start = std::time::Instant::now();
        let unix = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("native Windows clock precedes Unix epoch")
                .as_millis(),
        )
        .expect("native Windows clock exceeds u64 milliseconds");
        Self {
            work: start + std::time::Duration::from_secs(135 * 60),
            cleanup: start + std::time::Duration::from_secs(150 * 60),
            work_deadline_unix_millis: unix
                .checked_add(135 * 60 * 1000)
                .expect("native Windows work deadline overflow"),
            cleanup_deadline_unix_millis: unix
                .checked_add(150 * 60 * 1000)
                .expect("native Windows cleanup deadline overflow"),
        }
    }
}

pub struct WindowsLeaseEvent<'a> {
    pub phase: WindowsLeasePhase,
    pub subject: &'a InstalledWindowsPayload,
    pub operation: Option<&'static str>,
    pub result: Option<&'a std::result::Result<(), String>>,
    /// Actual capture products published by retain_package_operation.
    pub capture: Option<PathBuf>,
    pub stdout: Option<PathBuf>,
    pub stderr: Option<PathBuf>,
}

#[cfg(windows)]
fn lease_event<'a>(
    phase: WindowsLeasePhase,
    subject: &'a InstalledWindowsPayload,
    operation: Option<&'static str>,
    result: Option<&'a std::result::Result<(), String>>,
) -> WindowsLeaseEvent<'a> {
    let leaf = |suffix: &str| {
        operation.map(|operation| {
            subject
                .output_directory
                .join(format!("package-{operation}.{suffix}"))
        })
    };
    WindowsLeaseEvent {
        phase,
        subject,
        operation,
        result,
        capture: result.and_then(|_| leaf("capture.json")),
        stdout: result.and_then(|_| leaf("stdout.bin")),
        stderr: result.and_then(|_| leaf("stderr.bin")),
    }
}

/// Resolve selected paths in the driver context before changing the child cwd.
pub fn installed_public_command(
    cli: &Path,
    fixture: &Path,
    directory: &Path,
    report: &Path,
    mode: &str,
) -> Result<crate::command::CommandSpec> {
    let cli = std::path::absolute(cli)?;
    let fixture = std::path::absolute(fixture)?;
    let directory = std::path::absolute(directory)?;
    let report = std::path::absolute(report)?;
    Ok(
        crate::command::CommandSpec::new(cli, &directory, std::time::Duration::from_secs(180))
            .args([
                std::ffi::OsString::from("+4GiB"),
                std::ffi::OsString::from("+120s"),
                std::ffi::OsString::from("--sealed"),
                std::ffi::OsString::from("--report-format"),
                std::ffi::OsString::from("result-v1"),
                std::ffi::OsString::from("--report"),
                report.into_os_string(),
                std::ffi::OsString::from("--"),
                fixture.into_os_string(),
                std::ffi::OsString::from(mode),
            ]),
    )
}

impl InstalledWindowsPayload {
    /// Bind the installed case inputs to the measured channel payload, independently
    /// of any report produced by the workload. This is inventory, not permission.
    #[expect(
        clippy::too_many_arguments,
        reason = "materialization joins independently selected source, channel, binary graph and installation paths"
    )]
    pub fn from_materialized(
        channel: InstalledChannel,
        source: &crate::release::source::BuildSourceIdentity,
        distribution: &crate::release::distribution::TargetDistribution,
        artifacts: Vec<SelectedArtifact>,
        payload_directory: &std::path::Path,
        fixture: SelectedArtifact,
        installed_directory: &std::path::Path,
        output_directory: PathBuf,
    ) -> Result<Self> {
        use crate::release::{artifacts as files, target};
        use memcordon_core::runtime_manifest::{RuntimeComponentRole, RuntimeManifest};
        source.validate()?;
        distribution.validate()?;
        if !distribution.target.ends_with("-pc-windows-msvc")
            || !distribution
                .features
                .iter()
                .any(|feature| feature == "windows-sealed-runtime")
            || artifacts.is_empty()
            || artifacts.len() > 16
        {
            return Err(CiError::Message(
                "installed cases require a selected Windows runtime payload".into(),
            ));
        }
        let expected: std::collections::BTreeSet<_> = [
            "memcordon",
            "memcordon-sealed-agent",
            "memcordon-target-desktop-bootstrap",
            "memcordon-session-broker",
        ]
        .into_iter()
        .collect();
        if distribution
            .binaries
            .iter()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>()
            != expected
        {
            return Err(CiError::Message(
                "Windows readiness requires all four exact production components".into(),
            ));
        }
        let bytes = files::read_file(&payload_directory.join("runtime-manifest.json"))?;
        let manifest = RuntimeManifest::parse(&bytes).map_err(CiError::Message)?;
        if manifest.source_commit != source.commit()
            || manifest.version != source.version().to_string()
            || manifest.target != distribution.target
            || manifest.components.len() != distribution.binaries.len()
        {
            return Err(CiError::Message(
                "installed manifest differs from selected source/distribution".into(),
            ));
        }
        let mut cli = None;
        let mut agent = None;
        let mut components = Vec::new();
        let mut installed_components = Vec::new();
        for binary in &distribution.binaries {
            let name = target::binary_name(binary, &distribution.target);
            let component = manifest
                .components
                .iter()
                .find(|component| component.path == name)
                .ok_or_else(|| {
                    CiError::Message("selected binary is absent from measured manifest".into())
                })?;
            let measured = files::read_file(&payload_directory.join(&name))?;
            target::validate_executable(&measured, &distribution.target)?;
            if component.size != measured.len() as u64
                || component.sha256 != files::checksum(&measured)
            {
                return Err(CiError::Message(
                    "installed channel binary differs from measured manifest".into(),
                ));
            }
            let artifact = SelectedArtifact {
                path: payload_directory.join(&name),
                sha256: component.sha256.clone(),
            };
            installed_components.push(SelectedArtifact {
                path: installed_directory.join(&name),
                sha256: component.sha256.clone(),
            });
            components.push(artifact.clone());
            match component.role {
                RuntimeComponentRole::PublicCli => cli = Some(artifact),
                RuntimeComponentRole::SealedAgent => agent = Some(artifact),
                _ => {}
            }
        }
        // The fixture is a separate test input and never a production component.
        if manifest
            .components
            .iter()
            .any(|component| component.path == "memcordon-test-fixture.exe")
        {
            return Err(CiError::Message(
                "fixture must not be a production runtime component".into(),
            ));
        }
        let fixture_bytes = files::read_file(&fixture.path)?;
        target::validate_executable(&fixture_bytes, &distribution.target)?;
        if files::checksum(&fixture_bytes) != fixture.sha256 {
            return Err(CiError::Message(
                "selected native fixture bytes changed".into(),
            ));
        }
        for artifact in &artifacts {
            if files::checksum(&files::read_file(&artifact.path)?) != artifact.sha256 {
                return Err(CiError::Message(
                    "selected channel artifact bytes changed".into(),
                ));
            }
        }
        let agent =
            agent.ok_or_else(|| CiError::Message("selected payload lacks sealed agent".into()))?;
        Ok(Self {
            channel,
            source_commit: source.commit().to_owned(),
            version: source.version().to_string(),
            target: distribution.target.clone(),
            artifacts,
            cli: cli.ok_or_else(|| CiError::Message("selected payload lacks public CLI".into()))?,
            installed_agent: SelectedArtifact {
                path: installed_directory.join("memcordon-sealed-agent.exe"),
                sha256: agent.sha256.clone(),
            },
            installed_manifest: SelectedArtifact {
                path: installed_directory.join("runtime-manifest.json"),
                sha256: files::checksum(&bytes),
            },
            agent,
            components,
            installed_components,
            fixture,
            provider: manifest.public_binding(&bytes).map_err(CiError::Message)?,
            output_directory,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledWindowsAssessment {
    pub channel: InstalledChannel,
    pub target: String,
    pub source_commit: String,
    pub version: String,
    pub artifacts: Vec<SelectedArtifact>,
    pub public_smoke_before: std::result::Result<(), String>,
    pub cases: Vec<InstalledCaseResult>,
    pub positive_cases: Vec<crate::windows_consumer_readiness::CaseAssessment>,
    pub positive_suite: std::result::Result<(), String>,
    pub loss_cases: Vec<crate::windows_readiness_faults::LossAssessment>,
    pub loss_suite: std::result::Result<(), String>,
    pub capacity_cases: Vec<crate::windows_readiness_capacity::CapacityAssessment>,
    pub capacity_suite: std::result::Result<(), String>,
    pub refusal_cases: Vec<crate::windows_readiness_refusals::RefusalAssessment>,
    pub refusal_suite: std::result::Result<(), String>,
    pub retained_state_recovery: std::result::Result<(), String>,
    pub public_smoke_after: std::result::Result<(), String>,
    pub package_upgrade: std::result::Result<(), String>,
    pub package_uninstall: std::result::Result<(), String>,
}

impl InstalledWindowsAssessment {
    pub fn accepted(&self) -> bool {
        self.public_smoke_before.is_ok()
            && self.retained_state_recovery.is_ok()
            && self.public_smoke_after.is_ok()
            && self.package_upgrade.is_ok()
            && self.package_uninstall.is_ok()
            && self.positive_suite.is_ok()
            && self.loss_suite.is_ok()
            && crate::windows_readiness_faults::accepted(&self.loss_cases)
            && self.capacity_suite.is_ok()
            && crate::windows_readiness_capacity::accepted(&self.capacity_cases)
            && self.refusal_suite.is_ok()
            && crate::windows_readiness_refusals::accepted(&self.refusal_cases)
            && crate::windows_consumer_readiness::accepted(&self.positive_cases)
            && self.cases.len() == 2
            && self.cases.iter().map(|case| case.case).eq([
                crate::windows_causal_acceptance::InstalledCase::SamplingPopulation,
                crate::windows_causal_acceptance::InstalledCase::GuardianLossAfterRelease,
            ])
            && self.cases.iter().all(InstalledCaseResult::accepted)
    }
}

#[cfg(not(windows))]
pub fn run_cases_for_installed_payload(
    _: &InstalledWindowsPayload,
) -> Result<InstalledWindowsAssessment> {
    Err(CiError::Message(
        "selected installed Windows cases require a native Windows host".to_owned(),
    ))
}

/// Validate an acquired subject before any installation or workload mutation.
#[cfg(windows)]
pub(crate) fn validate_installed_selection(config: &InstalledWindowsPayload) -> Result<()> {
    native::verify_selected(config)
}

#[cfg(windows)]
mod native {
    use std::fs;
    use std::io;
    use std::path::Path;
    use std::process::Command;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    use memcordon_core::result_v1::{
        AuthorizationV1, CleanupStateV1, LaunchStateV1, OutcomeKindV1, ResultV1,
    };
    use memcordon_testkit::{OutputSnapshot, ProcessTestError, WindowsImageProcess};

    use super::*;
    use crate::command::CommandSpec;
    use crate::windows_causal_acceptance::{
        self as acceptance, CaseFailure, CleanupFailure, CollectedFailure, CollectionFailure,
        InstalledCase, MAX_REPORT_BYTES, MAX_STREAM_BYTES,
    };
    use crate::windows_owned_guardian::GuardianBaseline;

    fn read_bounded(path: &Path, bound: usize) -> Result<Vec<u8>> {
        use std::io::Read;
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
        };
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let meta = file.metadata()?;
        if !meta.file_type().is_file()
            || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || meta.len() > u64::try_from(bound).expect("finite file bound")
        {
            return Err(CiError::Message(
                "installed case file is not a bounded regular file".to_owned(),
            ));
        }
        let mut bytes = Vec::new();
        (&file)
            .take(u64::try_from(bound).expect("finite file bound") + 1)
            .read_to_end(&mut bytes)?;
        let after = file.metadata()?;
        if bytes.len() > bound
            || bytes.len() as u64 != meta.len()
            || after.len() != meta.len()
            || after.last_write_time() != meta.last_write_time()
            || after.creation_time() != meta.creation_time()
        {
            return Err(CiError::Message(
                "installed case file grew beyond its bound".to_owned(),
            ));
        }
        Ok(bytes)
    }

    fn verify_file(artifact: &SelectedArtifact) -> Result<()> {
        let bytes = read_bounded(&artifact.path, 512 * 1024 * 1024)?;
        if acceptance::sha256(&bytes) != artifact.sha256 {
            return Err(CiError::Message(
                "selected installed artifact bytes changed".to_owned(),
            ));
        }
        Ok(())
    }

    pub(super) fn verify_selected(config: &InstalledWindowsPayload) -> Result<()> {
        let target = match std::env::consts::ARCH {
            "x86_64" => "x86_64-pc-windows-msvc",
            "aarch64" => "aarch64-pc-windows-msvc",
            _ => {
                return Err(CiError::Message(
                    "unsupported native Windows architecture".to_owned(),
                ));
            }
        };
        if config.target != target
            || config.artifacts.is_empty()
            || config.artifacts.len() > 16
            || config.version.is_empty()
            || !config.provider.is_consistent()
            || config.provider.source_commit.as_str() != config.source_commit
            || String::from(config.provider.runtime_manifest_sha256.clone())
                != config.installed_manifest.sha256
            || config.installed_agent.sha256 != config.agent.sha256
            || config.components.len() != 4
            || config.installed_components.len() != 4
        {
            return Err(CiError::Message(
                "selected installed channel identity differs".to_owned(),
            ));
        }
        if config.channel == InstalledChannel::CargoPackage
            && (config.artifacts.len() != 4
                || config.artifacts.iter().any(|artifact| {
                    artifact
                        .path
                        .extension()
                        .is_none_or(|extension| extension != "crate")
                }))
        {
            return Err(CiError::Message(
                "Cargo installed channel requires the four actual packaged crate inputs".to_owned(),
            ));
        }
        for artifact in config
            .artifacts
            .iter()
            .chain(config.components.iter())
            .chain([&config.cli, &config.agent, &config.fixture])
        {
            verify_file(artifact)?;
        }
        let mut command = CommandSpec::new(
            &config.cli.path,
            config.cli.path.parent().ok_or_else(|| {
                CiError::Message("selected Windows CLI payload parent missing".into())
            })?,
            Duration::from_secs(30),
        )
        .arg("--version")
        .materialize()?;
        let output = memcordon_testkit::run_with_deadline_output_limit(
            &mut command,
            Duration::from_secs(30),
            16 * 1024,
        )
        .map_err(|error| CiError::Message(error.to_string()))?;
        let text = std::str::from_utf8(&output.stdout)
            .map_err(|error| CiError::Message(error.to_string()))?;
        if !output.status.success()
            || text.trim().split_whitespace().last() != Some(config.version.as_str())
        {
            return Err(CiError::Message(
                "selected installed CLI version differs".to_owned(),
            ));
        }
        Ok(())
    }

    fn package(
        config: &InstalledWindowsPayload,
        operation: &str,
        deadline: std::time::Instant,
    ) -> std::result::Result<(), String> {
        let budget = deadline
            .saturating_duration_since(std::time::Instant::now())
            .min(Duration::from_secs(120));
        if budget.is_zero() {
            return Err(
                "original Windows installation deadline exhausted before package mutation".into(),
            );
        }
        let mut command = CommandSpec::new(&config.agent.path, &config.output_directory, budget)
            .args(["package", operation])
            .materialize()
            .map_err(|error| error.to_string())?;
        let output = memcordon_testkit::run_with_deadline_output_limit(
            &mut command,
            budget,
            MAX_STREAM_BYTES,
        );
        retain_package_operation(&config.output_directory, operation, output)
    }

    fn quiescent(config: &InstalledWindowsPayload) -> Result<GuardianBaseline> {
        GuardianBaseline::quiescent(
            &config.installed_agent.path,
            &config.installed_manifest.path,
            &config.installed_agent.sha256,
            &config.installed_manifest.sha256,
        )
    }

    fn public_command(
        config: &InstalledWindowsPayload,
        report: &Path,
        mode: &str,
    ) -> Result<Command> {
        installed_public_command(
            &config.cli.path,
            &config.fixture.path,
            &config.output_directory,
            report,
            mode,
        )?
        .materialize()
    }

    fn smoke(
        config: &InstalledWindowsPayload,
        path: &Path,
        deadlines: WindowsLeaseDeadlines,
    ) -> std::result::Result<(), String> {
        let budget = deadlines
            .work_budget(Duration::from_secs(180))
            .map_err(|error| error.to_string())?;
        let mut command =
            public_command(config, path, "exit").map_err(|error| error.to_string())?;
        command.args(["--code", "0"]);
        let output = memcordon_testkit::run_with_deadline_output_limit(
            &mut command,
            budget,
            MAX_STREAM_BYTES,
        )
        .map_err(|error| error.to_string())?;
        let result = ResultV1::parse(
            &read_bounded(path, MAX_REPORT_BYTES).map_err(|error| error.to_string())?,
        )?;
        if output.status.success()
            && result.outcome.kind == OutcomeKindV1::Completed
            && result.cleanup.state == CleanupStateV1::Complete
            && result.authorization == AuthorizationV1::Granted
        {
            Ok(())
        } else {
            Err("installed public success smoke failed".to_owned())
        }
    }

    fn recover_retained_state(
        config: &InstalledWindowsPayload,
        deadlines: WindowsLeaseDeadlines,
    ) -> std::result::Result<(), String> {
        let budget = deadlines
            .cleanup_budget(Duration::from_secs(60))
            .map_err(|error| error.to_string())?;
        let millis = budget.as_millis().min(30000).max(1).to_string();
        let mut command = CommandSpec::new(&config.cli.path, &config.output_directory, budget)
            .args(["windows-recover", "converge", millis.as_str()])
            .materialize()
            .map_err(|error| error.to_string())?;
        let output = memcordon_testkit::run_with_deadline_output_limit(
            &mut command,
            budget,
            MAX_STREAM_BYTES,
        )
        .map_err(|error| error.to_string())?;
        fs::write(
            config.output_directory.join("recovery.stdout.bin"),
            &output.stdout,
        )
        .map_err(|error| error.to_string())?;
        fs::write(
            config.output_directory.join("recovery.stderr.bin"),
            &output.stderr,
        )
        .map_err(|error| error.to_string())?;
        if !output.status.success() {
            return Err("supported native retained-state recovery failed".into());
        }
        let inventory: memcordon_core::WindowsRecoveryInventoryV1 =
            serde_json::from_slice(&output.stdout).map_err(|error| error.to_string())?;
        if !inventory.is_consistent()
            || inventory.provider_generation != config.provider.generation.as_str()
            || inventory.executing != 0
            || inventory.incomplete_proof != 0
            || inventory.unacknowledged_outboxes != 0
            || inventory.ack_retirement_in_progress != 0
            || inventory.active_admissions != 0
            || inventory.quarantined != 0
        {
            return Err(
                "native recovery inventory is not quiescent for the selected provider".into(),
            );
        }
        Ok(())
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct GuardianReady {
        schema_version: u32,
        pid: u32,
        birth: u128,
    }

    fn wait_ready(
        snapshot: &OutputSnapshot,
        case: InstalledCase,
        fixture: &Path,
        work_deadline: Instant,
    ) -> io::Result<Vec<WindowsImageProcess>> {
        let deadline = work_deadline.min(Instant::now() + Duration::from_secs(90));
        loop {
            let stdout = snapshot.stdout()?;
            let ready = match case {
                InstalledCase::SamplingPopulation => acceptance::parse_fixture_readiness(&stdout)
                    .is_ok_and(|family| {
                        family.len() == acceptance::WINDOWS_CAUSAL_CONCURRENT_CHILDREN + 1
                    }),
                InstalledCase::GuardianLossAfterRelease => {
                    let marker = b"MEMCORDON-GUARDIAN-LOSS-READY:";
                    let records = stdout
                        .split(|byte| *byte == b'\n')
                        .filter_map(|line| line.strip_prefix(marker))
                        .collect::<Vec<_>>();
                    if records.len() > 1 {
                        return Err(io::Error::other("duplicate guardian fixture readiness"));
                    }
                    if let Some(bytes) = records.first() {
                        if stdout.last() != Some(&b'\n') {
                            false
                        } else {
                            let ready: GuardianReady =
                                serde_json::from_slice(bytes).map_err(io::Error::other)?;
                            ready.schema_version == 1 && ready.pid != 0 && ready.birth != 0
                        }
                    } else {
                        false
                    }
                }
            };
            if ready {
                let family = memcordon_testkit::windows_processes_for_image(fixture)?;
                let expected = if case == InstalledCase::SamplingPopulation {
                    acceptance::WINDOWS_CAUSAL_CONCURRENT_CHILDREN + 1
                } else {
                    1
                };
                if family.len() != expected {
                    return Err(io::Error::other(
                        "trusted fixture native family identity is incomplete",
                    ));
                }
                let held: std::collections::BTreeSet<_> = family
                    .iter()
                    .map(|process| (process.identity.pid, process.identity.birth))
                    .collect();
                let reported: std::collections::BTreeSet<_> = match case {
                    InstalledCase::SamplingPopulation => {
                        acceptance::parse_fixture_readiness(&stdout)
                            .map_err(io::Error::other)?
                            .into_iter()
                            .map(|process| (process.pid, process.birth))
                            .collect()
                    }
                    InstalledCase::GuardianLossAfterRelease => {
                        let record = stdout
                            .split(|byte| *byte == b'\n')
                            .find_map(|line| line.strip_prefix(b"MEMCORDON-GUARDIAN-LOSS-READY:"))
                            .ok_or_else(|| io::Error::other("guardian readiness disappeared"))?;
                        let ready: GuardianReady =
                            serde_json::from_slice(record).map_err(io::Error::other)?;
                        std::collections::BTreeSet::from([(ready.pid, ready.birth)])
                    }
                };
                if held != reported {
                    return Err(io::Error::other(
                        "fixture readiness differs from held native identities",
                    ));
                }
                return Ok(family);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::other(
                    "trusted fixture readiness was not observed before deadline",
                ));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn run_case(
        config: &InstalledWindowsPayload,
        case: InstalledCase,
        deadlines: WindowsLeaseDeadlines,
    ) -> InstalledCaseResult {
        let family = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::new(Mutex::new(None::<OutputSnapshot>));
        let association = Arc::new(Mutex::new(
            None::<memcordon_core::WindowsGuardianAttemptObservation>,
        ));
        let mut assessment = InstalledCaseResult {
            case,
            behavior: Err(CaseFailure {
                reason: "case was not executed".to_owned(),
            }),
            collection: Err(CollectionFailure {
                reason: "case output was not collected".to_owned(),
            }),
            workload_cleanup: Err(CleanupFailure {
                reason: "workload retirement was not observed".to_owned(),
            }),
            package_cleanup: Err(CleanupFailure {
                reason: "package uninstall has not run".to_owned(),
            }),
        };
        let operation = (|| -> Result<()> {
            let baseline = quiescent(config)?;
            let report_path = config
                .output_directory
                .join(case.name())
                .with_extension("json");
            if report_path.try_exists()? {
                return Err(CiError::Message(
                    "installed case report path already exists".to_owned(),
                ));
            }
            let mode = match case {
                InstalledCase::SamplingPopulation => "windows-inventory-capacity",
                InstalledCase::GuardianLossAfterRelease => "windows-guardian-loss-hold",
            };
            let command = public_command(config, &report_path, mode)?;
            let observed_family = Arc::clone(&family);
            let observed_output = Arc::clone(&captured);
            let observed_association = Arc::clone(&association);
            let expected_provider = config.provider.clone();
            let cli = config.cli.path.clone();
            let output_directory = config.output_directory.clone();
            let fixture = config.fixture.path.clone();
            let budget = deadlines.work_budget(Duration::from_secs(180))?;
            let execution = memcordon_testkit::run_with_deadline_owned_spawn_with_io_output_limit(
                command,
                budget,
                MAX_STREAM_BYTES,
                |mut command| command.spawn(),
                move |_, _, snapshot| {
                    *observed_output
                        .lock()
                        .map_err(|_| io::Error::other("output observer poisoned"))? =
                        Some(snapshot.clone());
                    let ready = wait_ready(&snapshot, case, &fixture, deadlines.work)?;
                    *observed_family
                        .lock()
                        .map_err(|_| io::Error::other("fixture family owner poisoned"))? = ready;
                    if case == InstalledCase::GuardianLossAfterRelease {
                        let mut guardian =
                            baseline.hold_new_guardian().map_err(io::Error::other)?;
                        let query_budget = deadlines
                            .work_budget(Duration::from_secs(30))
                            .map_err(io::Error::other)?;
                        let mut command = CommandSpec::new(&cli, &output_directory, query_budget)
                            .args([
                                std::ffi::OsString::from("__observe-windows-guardian"),
                                guardian.identity.process_id.to_string().into(),
                                guardian.identity.creation_time_100ns.to_string().into(),
                            ])
                            .materialize()
                            .map_err(io::Error::other)?;
                        let output = memcordon_testkit::run_with_deadline_output_limit(
                            &mut command,
                            query_budget,
                            16 * 1024,
                        );
                        retain_guardian_query_capture(&output_directory, &output)
                            .map_err(io::Error::other)?;
                        let output = output.map_err(io::Error::other)?;
                        if output.stdout.len() > 16 * 1024 || !output.status.success() {
                            let mut failure = format!(
                                "live guardian association query failed or exceeded bound; native exit {:?}",
                                output.status.code()
                            );
                            append_package_stderr(&mut failure, &output.stderr);
                            return Err(io::Error::other(failure));
                        }
                        fs::write(
                            output_directory.join("guardian-live-association.json"),
                            &output.stdout,
                        )?;
                        let observed: memcordon_core::WindowsGuardianAttemptObservation =
                            serde_json::from_slice(&output.stdout).map_err(io::Error::other)?;
                        if !observed.is_consistent()
                            || observed.association.provider != expected_provider
                            || observed.guardian_identity.process_id != guardian.identity.process_id
                            || observed.guardian_identity.creation_time_100ns
                                != guardian.identity.creation_time_100ns
                        {
                            return Err(io::Error::other(
                                "live association differs from independently held guardian/provider",
                            ));
                        }
                        *observed_association.lock().map_err(|_| {
                            io::Error::other("guardian association owner poisoned")
                        })? = Some(observed);
                        guardian.terminate_owned().map_err(io::Error::other)?;
                    }
                    Ok(())
                },
            );
            let (stdout, stderr, status, timed_out, execution_error) = match execution {
                Ok(output) => (
                    output.stdout,
                    output.stderr,
                    output.status.code(),
                    false,
                    None,
                ),
                Err(ProcessTestError::Timeout { stdout, stderr, .. }) => {
                    (stdout, stderr, None, true, None)
                }
                Err(error) => {
                    let snapshot = captured
                        .lock()
                        .map_err(|_| CiError::Message("output observer poisoned".into()))?;
                    let (stdout, stderr) = if let Some(snapshot) = snapshot.as_ref() {
                        (snapshot.stdout()?, snapshot.stderr()?)
                    } else {
                        (Vec::new(), Vec::new())
                    };
                    (stdout, stderr, None, false, Some(error.to_string()))
                }
            };
            // Preserve raw observations before parsing or any package mutation.
            fs::write(
                config
                    .output_directory
                    .join(case.name())
                    .with_extension("stdout.bin"),
                &stdout,
            )?;
            fs::write(
                config
                    .output_directory
                    .join(case.name())
                    .with_extension("stderr.bin"),
                &stderr,
            )?;
            if let Some(error) = execution_error {
                return Err(CiError::Message(error));
            }
            let report_bytes = read_bounded(&report_path, MAX_REPORT_BYTES)?;
            let result = ResultV1::parse(&report_bytes).map_err(CiError::Message)?;
            let projection = if case == InstalledCase::GuardianLossAfterRelease {
                let reported = result.provider_association.as_ref().ok_or_else(|| {
                    CiError::Message(
                        "public result omitted actual provider invocation association".to_owned(),
                    )
                })?;
                let held = association
                    .lock()
                    .map_err(|_| CiError::Message("guardian association owner poisoned".into()))?;
                let observed = held.as_ref().ok_or_else(|| {
                    CiError::Message(
                        "live guardian association was not independently observed".into(),
                    )
                })?;
                acceptance::validate_live_guardian_association(
                    reported,
                    observed,
                    &config.provider,
                )?;
                let association = &observed.association;
                let projection = result.diagnostics.as_ref().ok_or_else(|| {
                    CiError::Message("public result omitted the causal original".to_owned())
                })?;
                Some(acceptance::validate_guardian_failure_projection(
                    &serde_json::to_vec(projection)?,
                    &config.provider,
                    &association.attempt_id,
                    &association.request_sha256,
                )?)
            } else {
                None
            };
            assessment.collection = Ok(CollectedFailure {
                report_sha256: acceptance::sha256(&report_bytes),
                stdout_sha256: acceptance::sha256(&stdout),
                stderr_sha256: acceptance::sha256(&stderr),
                provider_failure: projection,
            });
            let behavior = !timed_out
                && status == Some(result.outcome.wrapper_status)
                && result.authorization == AuthorizationV1::Granted
                && matches!(
                    result.launch.state,
                    LaunchStateV1::ReleaseIssued | LaunchStateV1::ExecObserved
                )
                && result.cleanup.state == CleanupStateV1::Complete
                && match case {
                    InstalledCase::SamplingPopulation => {
                        result.outcome.kind == OutcomeKindV1::Deadline
                            && result.diagnostics.is_none()
                    }
                    InstalledCase::GuardianLossAfterRelease => {
                        result.outcome.kind == OutcomeKindV1::ProviderFailure
                    }
                };
            assessment.behavior = if behavior {
                Ok(())
            } else {
                Err(CaseFailure {
                    reason: "installed case public outcome or retirement differed".to_owned(),
                })
            };
            let observed = family
                .lock()
                .map_err(|_| CiError::Message("fixture family owner poisoned".to_owned()))?;
            if observed.is_empty() {
                return Err(CiError::Message(
                    "native fixture family was not retained".to_owned(),
                ));
            }
            Ok(())
        })();
        if let Err(error) = operation {
            assessment.behavior = Err(CaseFailure {
                reason: error.to_string(),
            });
        }
        // This independent native image-family check still runs after collection
        // or semantic validation failure. Self-expiry is never accepted as cleanup.
        let cleanup = (|| -> Result<()> {
            let deadline = deadlines
                .cleanup
                .min(Instant::now() + Duration::from_secs(30));
            loop {
                let observed = family
                    .lock()
                    .map_err(|_| CiError::Message("fixture family owner poisoned".into()))?;
                if observed.is_empty() {
                    return Err(CiError::Message(
                        "native fixture family retirement is unknown".into(),
                    ));
                }
                let held_retired = observed
                    .iter()
                    .map(WindowsImageProcess::has_exited)
                    .collect::<io::Result<Vec<_>>>()?
                    .into_iter()
                    .all(|exited| exited);
                if held_retired
                    && memcordon_testkit::windows_processes_for_image(&config.fixture.path)?
                        .is_empty()
                {
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    return Err(CiError::Message(
                        "installed fixture family remains live".to_owned(),
                    ));
                }
                thread::sleep(Duration::from_millis(20));
            }
        })();
        assessment.workload_cleanup = cleanup.map_err(|error| CleanupFailure {
            reason: error.to_string(),
        });
        assessment
    }

    pub fn run(
        config: &InstalledWindowsPayload,
        observer: &mut impl FnMut(WindowsLeaseEvent<'_>) -> Result<()>,
        deadlines: WindowsLeaseDeadlines,
        source_root: Option<&Path>,
    ) -> Result<InstalledWindowsAssessment> {
        if deadlines.work >= deadlines.cleanup {
            return Err(CiError::Message(
                "Windows lease must reserve original cleanup time after work cutoff".into(),
            ));
        }
        fs::create_dir_all(&config.output_directory)?;
        verify_selected(config)?;
        let predecessor_bytes = read_bounded(
            &config
                .output_directory
                .join("windows-upgrade-predecessor.json"),
            2 * 1024 * 1024,
        )?;
        memcordon_core::workload_contract::reject_duplicate_json_keys(&predecessor_bytes)
            .map_err(CiError::Message)?;
        let predecessor: WindowsUpgradePredecessor = serde_json::from_slice(&predecessor_bytes)?;
        let older = &predecessor.payload;
        if predecessor.format != "memcordon.windows-upgrade-predecessor"
            || predecessor.revision != 1
            || older.channel != InstalledChannel::CargoPackage
            || older.version != "0.5.7-rc.19"
            || older.source_commit != "a02e8f1e845349e27706c11d6d57acb27090223a"
            || older.target != config.target
            || older.output_directory == config.output_directory
            || semver::Version::parse(&older.version)
                .map_err(|error| CiError::Message(error.to_string()))?
                >= semver::Version::parse(&config.version)
                    .map_err(|error| CiError::Message(error.to_string()))?
        {
            return Err(CiError::Message(
                "Windows upgrade requires exact older complete rc.19 Cargo runtime".into(),
            ));
        }
        verify_selected(older)?;
        // Package commands use this owned diagnostic directory as their cwd.
        // Materializing the predecessor payload does not create case output.
        if source_root.is_some() {
            fs::create_dir(&older.output_directory)?;
        }
        if memcordon_testkit::windows_available_memory_bytes()? < 4 * 1024 * 1024 * 1024 {
            return Err(CiError::Message(
                "selected Windows installed fixture requires 4 GiB available memory".to_owned(),
            ));
        }
        let mut assessment = InstalledWindowsAssessment {
            channel: config.channel,
            target: config.target.clone(),
            source_commit: config.source_commit.clone(),
            version: config.version.clone(),
            artifacts: config.artifacts.clone(),
            public_smoke_before: Err("installation did not complete".to_owned()),
            cases: Vec::new(),
            positive_cases: Vec::new(),
            positive_suite: Err("positive readiness suite was not executed".into()),
            loss_cases: Vec::new(),
            loss_suite: Err("external native loss suite was not executed".into()),
            capacity_cases: Vec::new(),
            capacity_suite: Err("capacity suite was not executed".into()),
            refusal_cases: Vec::new(),
            refusal_suite: Err("preauthorization refusal suite was not executed".into()),
            retained_state_recovery: Err("retained-state recovery was not executed".to_owned()),
            public_smoke_after: Err("postrecovery smoke was not executed".to_owned()),
            package_upgrade: Err("upgrade was not executed".to_owned()),
            package_uninstall: Err("uninstall was not executed".to_owned()),
        };
        let mut current_upgrade_started = false;
        let mut old_install_started = false;
        let operation = (|| -> std::result::Result<(), String> {
            observer(lease_event(
                WindowsLeasePhase::BeforeOldInstall,
                older,
                Some("install"),
                None,
            ))
            .map_err(|error| error.to_string())?;
            old_install_started = true;
            let old_install = package(older, "install", deadlines.work);
            observer(lease_event(
                WindowsLeasePhase::AfterOldInstall,
                older,
                Some("install"),
                Some(&old_install),
            ))
            .map_err(|error| error.to_string())?;
            old_install?;
            let old_verify = package(older, "verify", deadlines.work);
            observer(lease_event(
                WindowsLeasePhase::AfterOldVerify,
                older,
                Some("verify"),
                Some(&old_verify),
            ))
            .map_err(|error| error.to_string())?;
            old_verify?;
            for component in &older.installed_components {
                verify_file(component).map_err(|error| error.to_string())?;
            }
            verify_file(&older.installed_manifest).map_err(|error| error.to_string())?;
            drop(quiescent(older).map_err(|error| error.to_string())?);
            smoke(
                older,
                &older.output_directory.join("predecessor-smoke.json"),
                deadlines,
            )?;
            observer(lease_event(
                WindowsLeasePhase::BeforeCurrentUpgrade,
                config,
                Some("upgrade"),
                None,
            ))
            .map_err(|error| error.to_string())?;
            current_upgrade_started = true;
            assessment.package_upgrade = package(config, "upgrade", deadlines.work);
            observer(lease_event(
                WindowsLeasePhase::AfterCurrentUpgrade,
                config,
                Some("upgrade"),
                Some(&assessment.package_upgrade),
            ))
            .map_err(|error| error.to_string())?;
            assessment.package_upgrade.clone()?;
            package(config, "verify", deadlines.work)?;
            verify_file(&config.installed_agent).map_err(|error| error.to_string())?;
            verify_file(&config.installed_manifest).map_err(|error| error.to_string())?;
            for component in &config.installed_components {
                verify_file(component).map_err(|error| error.to_string())?;
            }
            drop(quiescent(config).map_err(|error| error.to_string())?);
            if let Some(root) = source_root {
                crate::windows_consumer_readiness::provision_from_source_until(
                    root,
                    config,
                    deadlines.work,
                )
                .map_err(|error| error.to_string())?;
            }
            assessment.positive_suite = crate::windows_consumer_readiness::run_installed_until(
                config,
                &config.output_directory.join("windows-readiness-input.json"),
                &mut assessment.positive_cases,
                deadlines.work,
            )
            .map_err(|error| error.to_string());
            assessment.positive_suite.clone()?;
            assessment.loss_suite = crate::windows_readiness_faults::run_until(
                config,
                &config.output_directory.join("windows-readiness-input.json"),
                &mut assessment.loss_cases,
                deadlines,
            )
            .map_err(|error| error.to_string());
            assessment.loss_suite.clone()?;
            assessment.capacity_suite = crate::windows_readiness_capacity::run_until(
                config,
                &config.output_directory.join("windows-readiness-input.json"),
                &mut assessment.capacity_cases,
                deadlines.work,
            )
            .map_err(|error| error.to_string());
            assessment.capacity_suite.clone()?;
            assessment.refusal_suite = crate::windows_readiness_refusals::run_until(
                config,
                &config.output_directory.join("windows-readiness-input.json"),
                &mut assessment.refusal_cases,
                deadlines,
            )
            .map_err(|error| error.to_string());
            assessment.refusal_suite.clone()?;
            assessment.public_smoke_before = smoke(
                config,
                &config.output_directory.join("smoke-before.json"),
                deadlines,
            );
            assessment.public_smoke_before.clone()?;
            for case in [
                InstalledCase::SamplingPopulation,
                InstalledCase::GuardianLossAfterRelease,
            ] {
                assessment.cases.push(run_case(config, case, deadlines));
                let case = assessment.cases.last().expect("case was appended");
                if case.workload_cleanup.is_err() {
                    return Err("cannot establish fixture quiescence for later cases".to_owned());
                }
                drop(quiescent(config).map_err(|error| error.to_string())?);
            }
            assessment.retained_state_recovery = recover_retained_state(config, deadlines);
            assessment.retained_state_recovery.clone()?;
            drop(quiescent(config).map_err(|error| error.to_string())?);
            assessment.public_smoke_after = smoke(
                config,
                &config.output_directory.join("smoke-after.json"),
                deadlines,
            );
            assessment.public_smoke_after.clone()?;
            Ok(())
        })();
        // Ordinary uninstall owns cleanup even if installation, collection or a
        // causal assertion failed; its success never rewrites the case behavior.
        let probe_cleanup = crate::windows_consumer_readiness::cleanup_provider_probe(config)
            .map_err(|error| error.to_string());
        let cleanup_subject = if current_upgrade_started {
            config
        } else {
            older
        };
        let before_uninstall = if old_install_started {
            observer(lease_event(
                WindowsLeasePhase::BeforeUninstall,
                cleanup_subject,
                Some("uninstall"),
                None,
            ))
        } else {
            Ok(())
        };
        let uninstall = if old_install_started {
            package(cleanup_subject, "uninstall", deadlines.cleanup)
        } else {
            Err("owned predecessor install never started; no package removal attempted".into())
        };
        let after_uninstall = if old_install_started {
            observer(lease_event(
                WindowsLeasePhase::AfterUninstall,
                cleanup_subject,
                Some("uninstall"),
                Some(&uninstall),
            ))
        } else {
            Ok(())
        };
        assessment.package_uninstall = match (probe_cleanup, uninstall) {
            (Ok(()), result) => result,
            (Err(probe), Ok(())) => Err(probe),
            (Err(probe), Err(uninstall)) => Err(format!("{probe}; package uninstall: {uninstall}")),
        };
        for failure in [before_uninstall, after_uninstall]
            .into_iter()
            .filter_map(std::result::Result::err)
        {
            assessment.package_uninstall = Err(match assessment.package_uninstall {
                Ok(()) => failure.to_string(),
                Err(existing) => format!("{existing}; lease observation: {failure}"),
            });
        }
        for case in &mut assessment.cases {
            case.package_cleanup = assessment
                .package_uninstall
                .clone()
                .map_err(|reason| CleanupFailure { reason });
        }
        if let Err(error) = operation {
            if assessment.public_smoke_before.is_err() {
                assessment.public_smoke_before = Err(error);
            }
        }
        let bytes = serde_json::to_vec_pretty(&assessment)?;
        if bytes.len() > acceptance::MAX_SUMMARY_BYTES {
            return Err(CiError::Message(
                "installed case assessment exceeds byte bound".to_owned(),
            ));
        }
        fs::write(
            config.output_directory.join("installed-assessment.json"),
            bytes,
        )?;
        Ok(assessment)
    }
}

#[cfg(windows)]
pub fn run_cases_for_installed_payload(
    config: &InstalledWindowsPayload,
) -> Result<InstalledWindowsAssessment> {
    native::run(
        config,
        &mut |_| Ok(()),
        WindowsLeaseDeadlines::finite_default(),
        None,
    )
}

#[cfg(windows)]
pub fn run_with_observer(
    config: &InstalledWindowsPayload,
    observer: &mut impl FnMut(WindowsLeaseEvent<'_>) -> Result<()>,
) -> Result<InstalledWindowsAssessment> {
    native::run(
        config,
        observer,
        WindowsLeaseDeadlines::finite_default(),
        None,
    )
}

#[cfg(windows)]
pub fn run_with_observer_until(
    config: &InstalledWindowsPayload,
    observer: &mut impl FnMut(WindowsLeaseEvent<'_>) -> Result<()>,
    deadlines: WindowsLeaseDeadlines,
) -> Result<InstalledWindowsAssessment> {
    native::run(config, observer, deadlines, None)
}

/// Provision epoch-bound readiness only after the actual selected upgrade and
/// verification. Any provisioning failure remains inside the installation's
/// existing cleanup owner and original work/cleanup deadlines.
#[cfg(windows)]
pub fn run_from_source_with_observer_until(
    root: &Path,
    config: &InstalledWindowsPayload,
    observer: &mut impl FnMut(WindowsLeaseEvent<'_>) -> Result<()>,
    deadlines: WindowsLeaseDeadlines,
) -> Result<InstalledWindowsAssessment> {
    let source = crate::release::source::BuildSourceIdentity::working(root)?;
    if source.commit() != config.source_commit || source.version().to_string() != config.version {
        return Err(CiError::Message(
            "Windows provisioning source differs from selected installed runtime".into(),
        ));
    }
    native::run(config, observer, deadlines, Some(root))
}

#[cfg(not(windows))]
pub fn run_from_source_with_observer_until(
    _: &Path,
    _: &InstalledWindowsPayload,
    _: &mut impl FnMut(WindowsLeaseEvent<'_>) -> Result<()>,
    _: WindowsLeaseDeadlines,
) -> Result<InstalledWindowsAssessment> {
    Err(CiError::Message(
        "source-provisioned Windows lease requires native Windows".into(),
    ))
}

#[cfg(not(windows))]
pub fn run_with_observer(
    _: &InstalledWindowsPayload,
    _: &mut impl FnMut(WindowsLeaseEvent<'_>) -> Result<()>,
) -> Result<InstalledWindowsAssessment> {
    Err(CiError::Message(
        "installed Windows lease observation requires native Windows".into(),
    ))
}
