//! Installed-channel lifecycle using selected payload bytes and the public CLI.
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::windows_causal_acceptance::{InstalledCaseResult, InstalledChannel};
use crate::{CiError, Result};

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
    pub fixture: SelectedArtifact,
    pub installed_agent: SelectedArtifact,
    pub installed_manifest: SelectedArtifact,
    pub provider: memcordon_core::PublicProviderBindingV1,
    pub output_directory: PathBuf,
}

impl InstalledWindowsPayload {
    /// Bind the installed case inputs to the measured channel payload, independently
    /// of any report produced by the workload. This is inventory, not permission.
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
                path: payload_directory.join(name),
                sha256: component.sha256.clone(),
            };
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

    fn verify_selected(config: &InstalledWindowsPayload) -> Result<()> {
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
            .chain([&config.cli, &config.agent, &config.fixture])
        {
            verify_file(artifact)?;
        }
        let mut command = CommandSpec::new(
            &config.cli.path,
            &config.output_directory,
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
    ) -> std::result::Result<(), String> {
        let mut command = CommandSpec::new(
            &config.agent.path,
            &config.output_directory,
            Duration::from_secs(120),
        )
        .args(["package", operation])
        .materialize()
        .map_err(|error| error.to_string())?;
        let output = memcordon_testkit::run_with_deadline_output_limit(
            &mut command,
            Duration::from_secs(120),
            MAX_STREAM_BYTES,
        )
        .map_err(|error| error.to_string())?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "package {operation} failed: {:?}",
                output.status.code()
            ))
        }
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
        CommandSpec::new(
            &config.cli.path,
            &config.output_directory,
            Duration::from_secs(180),
        )
        .args([
            std::ffi::OsString::from("+4GiB"),
            std::ffi::OsString::from("+120s"),
            std::ffi::OsString::from("--sealed"),
            std::ffi::OsString::from("--report-format"),
            std::ffi::OsString::from("result-v1"),
            std::ffi::OsString::from("--report"),
            report.as_os_str().to_os_string(),
            std::ffi::OsString::from("--"),
            config.fixture.path.as_os_str().to_os_string(),
            std::ffi::OsString::from(mode),
        ])
        .materialize()
    }

    fn smoke(config: &InstalledWindowsPayload, path: &Path) -> std::result::Result<(), String> {
        let mut command =
            public_command(config, path, "exit").map_err(|error| error.to_string())?;
        command.args(["--code", "0"]);
        let output = memcordon_testkit::run_with_deadline_output_limit(
            &mut command,
            Duration::from_secs(180),
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

    fn recover_retained_state(config: &InstalledWindowsPayload) -> std::result::Result<(), String> {
        let mut command = CommandSpec::new(
            &config.cli.path,
            &config.output_directory,
            Duration::from_secs(60),
        )
        .args(["windows-recover", "converge", "30000"])
        .materialize()
        .map_err(|error| error.to_string())?;
        let output = memcordon_testkit::run_with_deadline_output_limit(
            &mut command,
            Duration::from_secs(60),
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
    ) -> io::Result<Vec<WindowsImageProcess>> {
        let deadline = Instant::now() + Duration::from_secs(90);
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

    fn run_case(config: &InstalledWindowsPayload, case: InstalledCase) -> InstalledCaseResult {
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
            let execution = memcordon_testkit::run_with_deadline_owned_spawn_with_io_output_limit(
                command,
                Duration::from_secs(180),
                MAX_STREAM_BYTES,
                |mut command| command.spawn(),
                move |_, _, snapshot| {
                    *observed_output
                        .lock()
                        .map_err(|_| io::Error::other("output observer poisoned"))? =
                        Some(snapshot.clone());
                    let ready = wait_ready(&snapshot, case, &fixture)?;
                    *observed_family
                        .lock()
                        .map_err(|_| io::Error::other("fixture family owner poisoned"))? = ready;
                    if case == InstalledCase::GuardianLossAfterRelease {
                        let mut guardian =
                            baseline.hold_new_guardian().map_err(io::Error::other)?;
                        let mut command =
                            CommandSpec::new(&cli, &output_directory, Duration::from_secs(30))
                                .args([
                                    std::ffi::OsString::from("__observe-windows-guardian"),
                                    guardian.identity.process_id.to_string().into(),
                                    guardian.identity.creation_time_100ns.to_string().into(),
                                ])
                                .materialize()
                                .map_err(io::Error::other)?;
                        let output = memcordon_testkit::run_with_deadline_output_limit(
                            &mut command,
                            Duration::from_secs(30),
                            16 * 1024,
                        )
                        .map_err(io::Error::other)?;
                        if output.stdout.len() > 16 * 1024 || !output.status.success() {
                            return Err(io::Error::other(
                                "live guardian association query failed or exceeded bound",
                            ));
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
            let deadline = Instant::now() + Duration::from_secs(30);
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

    pub fn run(config: &InstalledWindowsPayload) -> Result<InstalledWindowsAssessment> {
        fs::create_dir_all(&config.output_directory)?;
        verify_selected(config)?;
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
            retained_state_recovery: Err("retained-state recovery was not executed".to_owned()),
            public_smoke_after: Err("postrecovery smoke was not executed".to_owned()),
            package_upgrade: Err("upgrade was not executed".to_owned()),
            package_uninstall: Err("uninstall was not executed".to_owned()),
        };
        let operation = (|| -> std::result::Result<(), String> {
            package(config, "install")?;
            verify_file(&config.installed_agent).map_err(|error| error.to_string())?;
            verify_file(&config.installed_manifest).map_err(|error| error.to_string())?;
            drop(quiescent(config).map_err(|error| error.to_string())?);
            assessment.public_smoke_before =
                smoke(config, &config.output_directory.join("smoke-before.json"));
            assessment.public_smoke_before.clone()?;
            for case in [
                InstalledCase::SamplingPopulation,
                InstalledCase::GuardianLossAfterRelease,
            ] {
                assessment.cases.push(run_case(config, case));
                let case = assessment.cases.last().expect("case was appended");
                if case.workload_cleanup.is_err() {
                    return Err("cannot establish fixture quiescence for later cases".to_owned());
                }
                drop(quiescent(config).map_err(|error| error.to_string())?);
            }
            assessment.retained_state_recovery = recover_retained_state(config);
            assessment.retained_state_recovery.clone()?;
            drop(quiescent(config).map_err(|error| error.to_string())?);
            assessment.public_smoke_after =
                smoke(config, &config.output_directory.join("smoke-after.json"));
            assessment.public_smoke_after.clone()?;
            assessment.package_upgrade = package(config, "upgrade");
            assessment.package_upgrade.clone()?;
            Ok(())
        })();
        // Ordinary uninstall owns cleanup even if installation, collection or a
        // causal assertion failed; its success never rewrites the case behavior.
        assessment.package_uninstall = package(config, "uninstall");
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
    native::run(config)
}
