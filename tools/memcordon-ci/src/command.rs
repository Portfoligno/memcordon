use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use memcordon_testkit::ObservedOutput;

use crate::{CiError, Result};

/// Reject native command failure before decoding its successful-response schema.
pub fn require_successful_output(operation: &str, output: &ObservedOutput) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    let end = output.stderr.len().min(2048);
    Err(CiError::Message(format!(
        "{operation}: native command failed; status={:?}; stdout-bytes={}; stderr-bytes={}; stderr-truncated={}; stderr={:?}",
        output.status,
        output.stdout.len(),
        output.stderr.len(),
        end != output.stderr.len(),
        String::from_utf8_lossy(&output.stderr[..end])
    )))
}

/// Keep a known native failure visible even when publishing its receipt fails.
/// Successful work still requires receipt publication to succeed.
pub fn require_successful_retained_output(
    operation: &str,
    output: &ObservedOutput,
    retention: Result<()>,
) -> Result<()> {
    match require_successful_output(operation, output) {
        Ok(()) => retention,
        Err(primary) => {
            let stdout_end = output.stdout.len().min(2048);
            let retention_error = retention.err().map(|error| error.to_string());
            let retention_bytes = retention_error
                .as_ref()
                .map_or(&[][..], |error| error.as_bytes());
            let retention_end = retention_bytes.len().min(2048);
            Err(CiError::Message(format!(
                "{primary}; stdout-truncated={}; stdout={:?}; receipt-error-present={}; receipt-error-bytes={}; receipt-error-truncated={}; receipt-error={:?}",
                stdout_end != output.stdout.len(),
                String::from_utf8_lossy(&output.stdout[..stdout_end]),
                retention_error.is_some(),
                retention_bytes.len(),
                retention_end != retention_bytes.len(),
                String::from_utf8_lossy(&retention_bytes[..retention_end]),
            )))
        }
    }
}

#[derive(Clone, Debug)]
pub struct CommandSpec {
    program: PathBuf,
    arguments: Vec<OsString>,
    toolchain: Option<ToolchainInvocation>,
    current_dir: PathBuf,
    deadline: Duration,
    operation_deadline: Option<Instant>,
    phase: Option<CiPhase>,
    selection: Option<serde_json::Value>,
    isolated_cargo_home: Option<PathBuf>,
    miri_sysroot: Option<PathBuf>,
    clear_environment: bool,
    bootstrap_environment: bool,
    output_limit: usize,
    defer_group_failure: bool,
    peer_stop_policy: Option<PeerStopPolicy>,
}

/// Reviewed native ownership behavior when an independent peer fails.
#[derive(Clone, Copy, Debug)]
pub enum PeerStopPolicy {
    CancelAndSettle,
    FinishOwnedPhase,
}

#[derive(Clone, Copy, Debug)]
pub enum CiPhase {
    SourceCheck,
    Package,
    ProductBuild,
    NativeCompile,
    NativeExecute,
    InstalledConsumer,
    Assembly,
}

impl CiPhase {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::SourceCheck => "source-check",
            Self::Package => "package",
            Self::ProductBuild => "product-build",
            Self::NativeCompile => "native-compile",
            Self::NativeExecute => "native-execute",
            Self::InstalledConsumer => "installed-consumer",
            Self::Assembly => "assembly",
        }
    }
}

/// Keep the cleanup allowance outside the next child's execution allowance.
pub fn remaining_budget(
    original: Duration,
    remaining: Duration,
    cleanup: Duration,
) -> Result<Duration> {
    let available = remaining
        .checked_sub(cleanup)
        .filter(|value| !value.is_zero())
        .ok_or_else(|| CiError::Message("BudgetExhaustedBeforePhase".into()))?;
    Ok(original.min(available))
}

#[derive(Clone, Debug)]
enum ToolchainInvocation {
    Cargo {
        toolchain: String,
    },
    Program {
        toolchain: String,
        executable: PathBuf,
    },
}

impl CommandSpec {
    pub fn new(program: impl Into<PathBuf>, current_dir: &Path, deadline: Duration) -> Self {
        Self {
            program: program.into(),
            arguments: Vec::new(),
            toolchain: None,
            current_dir: current_dir.to_path_buf(),
            deadline,
            operation_deadline: None,
            phase: None,
            selection: None,
            isolated_cargo_home: None,
            miri_sysroot: None,
            clear_environment: false,
            bootstrap_environment: false,
            output_limit: 16 * 1024 * 1024,
            defer_group_failure: false,
            peer_stop_policy: None,
        }
    }

    /// Cargo compilation through the explicitly selected rustup toolchain.
    pub fn cargo(
        rustup: impl Into<PathBuf>,
        current_dir: &Path,
        toolchain: &str,
        deadline: Duration,
    ) -> Self {
        let mut command = Self::new(rustup, current_dir, deadline);
        command.toolchain = Some(ToolchainInvocation::Cargo {
            toolchain: toolchain.into(),
        });
        command
    }

    /// A tool that compiles through the selected toolchain, such as cargo-fuzz.
    pub fn toolchain_program(
        rustup: impl Into<PathBuf>,
        current_dir: &Path,
        toolchain: &str,
        executable: impl Into<PathBuf>,
        deadline: Duration,
    ) -> Self {
        let mut command = Self::new(rustup, current_dir, deadline);
        command.toolchain = Some(ToolchainInvocation::Program {
            toolchain: toolchain.into(),
            executable: executable.into(),
        });
        command
    }

    pub fn arg(mut self, argument: impl Into<OsString>) -> Self {
        self.arguments.push(argument.into());
        self
    }

    /// Optional cache version probes can reject an image and rebuild it.
    /// Their caller still propagates unknown native settlement as a failure.
    pub fn defer_group_failure(mut self) -> Self {
        self.defer_group_failure = true;
        self
    }

    pub fn peer_stop_policy(mut self, policy: PeerStopPolicy) -> Self {
        self.peer_stop_policy = Some(policy);
        self
    }

    pub fn bounded_until(mut self, deadline: Instant) -> Self {
        self.operation_deadline = Some(deadline);
        self
    }

    pub fn phase(mut self, phase: CiPhase) -> Self {
        self.phase = Some(phase);
        self
    }

    pub fn selection(
        mut self,
        source: &crate::release::source::BuildSourceIdentity,
        target: Option<&str>,
    ) -> Self {
        self.selection = Some(serde_json::json!({"source": source, "target": target}));
        self
    }

    fn available_budget(&self) -> Result<Duration> {
        if crate::preparation::active_group().is_some_and(|group| !group.may_start()) {
            return Err(CiError::NotStartedAfterFailure);
        }
        let deadline = match (self.operation_deadline, crate::preparation::active_group()) {
            (Some(deadline), Some(group)) => Some(deadline.min(group.deadline())),
            (None, Some(group)) => Some(group.deadline()),
            (deadline, None) => deadline,
        };
        match deadline {
            Some(deadline) => remaining_budget(
                self.deadline,
                deadline.saturating_duration_since(Instant::now()),
                Duration::from_secs(10),
            ),
            None => Ok(self.deadline),
        }
    }

    pub fn args<I, S>(mut self, arguments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.arguments.extend(arguments.into_iter().map(Into::into));
        self
    }

    pub fn isolated_cargo(mut self, home: &Path) -> Self {
        self.isolated_cargo_home = Some(home.to_path_buf());
        self
    }

    pub fn miri_sysroot(mut self, root: &Path) -> Self {
        self.miri_sysroot = Some(root.to_path_buf());
        self
    }

    pub fn apply_environment(&self, command: &mut Command) {
        if self.clear_environment {
            command.env_clear();
        }
        if self.bootstrap_environment {
            for (name, _) in std::env::vars_os() {
                let text = name.to_string_lossy().to_ascii_uppercase();
                if ["TOKEN", "SECRET", "PASSWORD", "CREDENTIAL"]
                    .iter()
                    .any(|part| text.contains(part))
                    || text.ends_with("_PROXY")
                    || text == "PROXY"
                    || matches!(text.as_str(), "GITHUB_OUTPUT" | "GITHUB_STEP_SUMMARY")
                {
                    command.env_remove(name);
                }
            }
        }
        if let Some(root) = &self.miri_sysroot {
            command.env("MIRI_SYSROOT", root);
        }
        if let Some(home) = &self.isolated_cargo_home {
            for (name, _) in std::env::vars_os() {
                let name_text = name.to_string_lossy();
                if name_text.starts_with("CARGO_")
                    || name_text.starts_with("RUSTC_")
                    || matches!(
                        name_text.as_ref(),
                        "RUSTC" | "RUSTFLAGS" | "RUSTDOC" | "RUSTDOCFLAGS"
                    )
                {
                    command.env_remove(name);
                }
            }
            command.env("CARGO_HOME", home);
        }
        command
            .env_remove("GH_TOKEN")
            .env_remove("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
            .env_remove("ACTIONS_ID_TOKEN_REQUEST_URL");
        command.env_remove("CARGO_REGISTRY_TOKEN");
        command.env_remove("CARGO_REGISTRIES_CRATES_IO_TOKEN");
        command.env_remove("GITHUB_TOKEN");
        if crate::preparation::active_group().is_some()
            || matches!(&self.toolchain, Some(ToolchainInvocation::Cargo { .. }))
                && self
                    .arguments
                    .first()
                    .is_some_and(|argument| argument == OsStr::new("test"))
        {
            // Test fixtures can call real release emitters concurrently. Their
            // observations must not enter the enclosing runner step's channels.
            // Production children retain these channels for owner transitions.
            command.env_remove("GITHUB_OUTPUT");
            command.env_remove("GITHUB_STEP_SUMMARY");
        }
    }
    pub fn cleared_environment(mut self) -> Self {
        self.clear_environment = true;
        self
    }

    pub fn bootstrap_environment(mut self) -> Self {
        self.bootstrap_environment = true;
        self
    }

    pub fn run(&self) -> Result<Vec<u8>> {
        let mut command = crate::work_outcome::WorkOutcome::before_start(self.materialize())?;
        let output = self.observe_with_progress(&mut command, true)?;
        if output.status.success() {
            Ok(output.stdout)
        } else {
            Err(CiError::SettledCommandFailure(format!(
                "subprocess failed with {}; stdout={:?}; stderr={:?}",
                output.status,
                bounded_excerpt(&output.stdout),
                bounded_excerpt(&output.stderr)
            )))
        }
    }

    pub fn materialize(&self) -> Result<Command> {
        if let Some(home) = &self.isolated_cargo_home {
            for ancestor in self.current_dir.ancestors() {
                for name in ["config", "config.toml"] {
                    if ancestor.join(".cargo").join(name).try_exists()? {
                        return Err(CiError::Message(
                            "candidate Cargo refuses inherited ancestor configuration".into(),
                        ));
                    }
                }
            }
            for name in ["config", "config.toml", "credentials", "credentials.toml"] {
                if home.join(name).try_exists()? {
                    return Err(CiError::Message(
                        "candidate Cargo home contains ambient configuration or credentials".into(),
                    ));
                }
            }
        }
        let mut command = Command::new(&self.program);
        match &self.toolchain {
            Some(ToolchainInvocation::Cargo { toolchain }) => {
                command.args(["run", toolchain, "cargo"]);
            }
            Some(ToolchainInvocation::Program {
                toolchain,
                executable,
            }) => {
                command.args(["run", toolchain]).arg(executable);
            }
            None => {}
        }
        let mut arguments = self.arguments.clone();
        if matches!(&self.toolchain, Some(ToolchainInvocation::Cargo { .. }))
            && arguments.first().is_some_and(|argument| {
                matches!(
                    argument.to_str(),
                    Some("build" | "check" | "clippy" | "rustdoc" | "test" | "install")
                )
            })
            && let Some(group) = crate::preparation::active_group()
        {
            let mut selected = false;
            let mut index = 0;
            while index < arguments.len() {
                if arguments[index] == "--" {
                    break;
                }
                if let Some(count) = arguments[index].to_str().and_then(|text| {
                    text.strip_prefix("--jobs=")
                        .or_else(|| text.strip_prefix("-j").filter(|suffix| !suffix.is_empty()))
                }) {
                    let count = count
                        .parse::<usize>()
                        .ok()
                        .filter(|count| *count > 0)
                        .ok_or_else(|| {
                            CiError::Message("Cargo jobs must be a positive typed count".into())
                        })?;
                    arguments[index] = OsString::from("--jobs");
                    arguments.insert(index + 1, count.to_string().into());
                }
                if arguments[index] == "--jobs" || arguments[index] == "-j" {
                    if selected {
                        return Err(CiError::Message(
                            "conflicting duplicate Cargo jobs arguments".into(),
                        ));
                    }
                    arguments[index] = OsString::from("--jobs");
                    let jobs = arguments
                        .get_mut(index + 1)
                        .ok_or_else(|| CiError::Message("Cargo job argument is missing".into()))?;
                    let count = jobs
                        .to_str()
                        .and_then(|text| text.parse::<usize>().ok())
                        .filter(|count| *count > 0)
                        .ok_or_else(|| {
                            CiError::Message("Cargo jobs must be a positive typed count".into())
                        })?;
                    if count > group.compiler_jobs() {
                        return Err(CiError::Message(
                            "explicit Cargo jobs exceeds inherited compiler budget".into(),
                        ));
                    }
                    *jobs = count.to_string().into();
                    selected = true;
                    index += 1;
                }
                index += 1;
            }
            if !selected {
                let index = arguments
                    .iter()
                    .position(|argument| argument == "--")
                    .unwrap_or(arguments.len());
                arguments.splice(
                    index..index,
                    [
                        OsString::from("--jobs"),
                        group.compiler_jobs().to_string().into(),
                    ],
                );
            }
        }
        command.args(&arguments).current_dir(&self.current_dir);
        self.apply_environment(&mut command);
        if matches!(&self.toolchain,
            Some(ToolchainInvocation::Program { executable, .. })
                if executable.file_name().is_some_and(|name| matches!(name.to_str(), Some("cargo-fuzz" | "cargo-fuzz.exe"))))
            && let Some(group) = crate::preparation::active_group()
        {
            // cargo-fuzz owns its Cargo invocation; use Cargo's standard compiler
            // limit without altering the fuzz campaign or harness arguments.
            command.env("CARGO_BUILD_JOBS", group.compiler_jobs().to_string());
        }
        Ok(command)
    }

    pub fn output(&self) -> Result<ObservedOutput> {
        let mut command = crate::work_outcome::WorkOutcome::before_start(self.materialize())?;
        eprintln!("ci subprocess program: {:?}", command.get_program());
        for argument in command.get_args() {
            eprintln!("ci subprocess argument: {argument:?}");
        }
        eprintln!("ci subprocess deadline: {:?}", self.deadline);
        self.observe(&mut command)
    }

    /// Capture a subprocess for callers that own a machine-readable protocol.
    /// Materialization, credential removal, and the deadline remain identical
    /// to `output`; only invocation diagnostics are suppressed.
    pub fn output_quiet(&self) -> Result<ObservedOutput> {
        self.output_owned().into_result()
    }

    /// The native observation is retained before any semantic error formatting.
    pub fn output_owned(&self) -> crate::work_outcome::WorkOutcome<ObservedOutput> {
        use crate::work_outcome::{WorkOutcome, WriterSettlement};
        match self.materialize() {
            Ok(mut command) => WorkOutcome::from_result(self.observe(&mut command)),
            Err(error) => WorkOutcome::observed(Err(error), WriterSettlement::NotStarted),
        }
    }

    pub fn run_owned(&self) -> crate::work_outcome::WorkOutcome<Vec<u8>> {
        self.output_owned()
            .validate_after(|output| {
                if output.status.success() {
                    Ok(())
                } else {
                    Err(CiError::SettledCommandFailure(format!(
                        "subprocess failed with {}; stdout={:?}; stderr={:?}",
                        output.status,
                        bounded_excerpt(&output.stdout),
                        bounded_excerpt(&output.stderr)
                    )))
                }
            })
            .map(|output| output.stdout)
    }

    /// Bound both capture workers before they allocate subprocess output.
    pub fn output_limit(mut self, bytes: usize) -> Self {
        assert!(bytes > 0);
        self.output_limit = bytes;
        self
    }

    /// Observe the exact creation child before its sole native wait owner runs.
    /// An observation error never drops that child: bounded settlement still
    /// runs before the original observation error is returned.
    #[cfg(target_os = "linux")]
    pub fn output_quiet_with_creation(
        &self,
        observe_creation: impl FnOnce(&std::process::Child) -> Result<()>,
    ) -> Result<ObservedOutput> {
        self.output_quiet_with_creation_mode(observe_creation, false)
    }

    /// Observe the genuine executed image while the original child is stopped
    /// at its kernel exec event, then release it under the same cutoff.
    #[cfg(target_os = "linux")]
    pub fn output_quiet_with_exec_observation(
        &self,
        observe_creation: impl FnOnce(&std::process::Child) -> Result<()>,
    ) -> Result<ObservedOutput> {
        self.output_quiet_with_creation_mode(observe_creation, true)
    }

    #[cfg(target_os = "linux")]
    fn output_quiet_with_creation_mode(
        &self,
        observe_creation: impl FnOnce(&std::process::Child) -> Result<()>,
        hold_exec: bool,
    ) -> Result<ObservedOutput> {
        let command = crate::work_outcome::WorkOutcome::before_start(self.materialize())?;
        let budget = crate::work_outcome::WorkOutcome::before_start(self.available_budget())?;
        let deadline = self
            .operation_deadline
            .unwrap_or(Instant::now() + budget)
            .min(Instant::now() + budget);
        let mut observation_error = None;
        let output = memcordon_testkit::run_with_deadline_owned_spawn_after_output_limit(
            command,
            budget,
            self.output_limit,
            |mut command| {
                if hold_exec {
                    memcordon_testkit::configure_native_exec_observation(&mut command);
                }
                let child = command.spawn()?;
                let observed = (|| -> Result<()> {
                    let stop = if hold_exec {
                        Some(memcordon_testkit::NativeExecObservation::acquire(
                            &child, deadline,
                        )?)
                    } else {
                        None
                    };
                    observe_creation(&child)?;
                    if let Some(stop) = stop {
                        if Instant::now() >= deadline {
                            return Err(CiError::Message(
                                "original exec observation cutoff exhausted before release".into(),
                            ));
                        }
                        stop.release()?;
                    }
                    Ok(())
                })();
                if let Err(error) = observed {
                    observation_error = Some(error);
                }
                Ok(child)
            },
            |_| Ok(()),
        );
        let writers = crate::work_outcome::native_settlement(&output);
        let result = match (output, observation_error) {
            (Ok(output), None) => Ok(output),
            (Ok(_), Some(error)) => Err(error),
            (Err(error), original) => Err(CiError::Message(format!(
                "native creation observation={original:?}; native settlement={error}"
            ))),
        };
        crate::work_outcome::WorkOutcome::observed(result, writers).into_result()
    }

    /// Supply an already retained finite input without blocking a pipe before
    /// the sole deadline owner starts. Creation failures still settle the child.
    #[cfg(unix)]
    pub fn output_quiet_with_stdin_and_creation(
        &self,
        input: &std::fs::File,
        observe_creation: impl FnOnce(&std::process::Child) -> Result<()>,
    ) -> Result<ObservedOutput> {
        use std::io::{Read, Seek, SeekFrom};
        let metadata = input.metadata()?;
        let flags = rustix::fs::fcntl_getfl(input).map_err(std::io::Error::from)?;
        if !metadata.is_file()
            || metadata.len() > 65536
            || flags & rustix::fs::OFlags::ACCMODE != rustix::fs::OFlags::RDONLY
        {
            return Err(CiError::Message(
                "native recovery stdin is not a finite readonly record".into(),
            ));
        }
        let mut supplied = input.try_clone()?;
        supplied.seek(SeekFrom::Start(0))?;
        let mut command = self.materialize()?;
        command.stdin(std::process::Stdio::piped());
        let mut observation_error = None;
        let deliver_input = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed_creation = std::sync::Arc::clone(&deliver_input);
        let output = memcordon_testkit::run_with_deadline_owned_spawn_with_io_output_limit(
            command,
            self.available_budget()?,
            self.output_limit,
            |mut command| {
                let child = command.spawn()?;
                if let Err(error) = observe_creation(&child) {
                    observation_error = Some(error);
                } else {
                    observed_creation.store(true, std::sync::atomic::Ordering::Release);
                }
                Ok(child)
            },
            move |_, stdin, _| {
                let mut stdin = stdin
                    .ok_or_else(|| std::io::Error::other("native recovery input pipe absent"))?;
                if deliver_input.load(std::sync::atomic::Ordering::Acquire) {
                    let mut bounded = supplied.take(metadata.len() + 1);
                    if std::io::copy(&mut bounded, &mut stdin)? != metadata.len() {
                        return Err(std::io::Error::other(
                            "native recovery input length changed during delivery",
                        ));
                    }
                }
                Ok(())
            },
        );
        let writers = crate::work_outcome::native_settlement(&output);
        let result = match (output, observation_error) {
            (Ok(output), None) => Ok(output),
            (Ok(_), Some(error)) => Err(error),
            (Err(error), original) => Err(CiError::Message(format!(
                "native creation observation={original:?}; native settlement={error}"
            ))),
        };
        crate::work_outcome::WorkOutcome::observed(result, writers).into_result()
    }

    fn observe(&self, command: &mut Command) -> Result<ObservedOutput> {
        self.observe_with_progress(command, false)
    }

    fn observe_with_progress(
        &self,
        command: &mut Command,
        progress: bool,
    ) -> Result<ObservedOutput> {
        let group = crate::preparation::active_group();
        if group.as_ref().is_some_and(|group| !group.may_start()) {
            return Err(CiError::NotStartedAfterFailure);
        }
        let budget = crate::work_outcome::WorkOutcome::before_start(self.available_budget())?;
        let started = Instant::now();
        let diagnostic_directory = if self.phase.is_some() {
            let directory = self.current_dir.join("target/ci/reports/execution");
            std::fs::create_dir_all(&directory)?;
            Some(
                tempfile::Builder::new()
                    .prefix("operation-")
                    .tempdir_in(directory)?
                    .keep(),
            )
        } else {
            None
        };
        let report = |state: &str,
                      observed_budget: Duration,
                      result: Option<
            &std::result::Result<ObservedOutput, memcordon_testkit::ProcessTestError>,
        >,
                      cargo_progress: Option<&crate::cargo_progress::CargoProgress>|
         -> Result<()> {
            let Some(phase) = self.phase else {
                return Ok(());
            };
            let mut value = serde_json::json!({"phase": phase.name(), "state": state, "program": self.program.to_string_lossy(), "arguments": self.arguments.iter().map(|argument| argument.to_string_lossy()).collect::<Vec<_>>(), "toolchain": format!("{:?}", self.toolchain), "original-budget-ms": self.deadline.as_millis(), "available-budget-ms": observed_budget.as_millis(), "elapsed-ms": started.elapsed().as_millis()});
            value["selection"] = self.selection.clone().unwrap_or(serde_json::Value::Null);
            if let Some(cargo_progress) = cargo_progress {
                value["cargo-progress"] = serde_json::to_value(cargo_progress)?;
            }
            if let Some(group) = &group {
                let (failure, stop, elapsed) = group.timing();
                value["operation-timing"] = serde_json::json!({
                    "first-failure-observed-us": failure,
                    "peer-stop-requested-us": stop,
                    "owner-observed-us": elapsed,
                });
            }
            if let Some(result) = result {
                match result {
                    Ok(output) => {
                        value["termination"] = status_json(output.status);
                        value["cleanup"] = serde_json::json!("complete");
                        value["stdout"] = excerpt_json(&output.stdout);
                        value["stderr"] = excerpt_json(&output.stderr);
                    }
                    Err(memcordon_testkit::ProcessTestError::Timeout {
                        stdout,
                        stderr,
                        cleanup,
                        observation,
                        ..
                    }) => {
                        value["timed-out"] = serde_json::json!(true);
                        value["cleanup"] = serde_json::json!(if cleanup.is_ok() {
                            "complete"
                        } else {
                            "incomplete"
                        });
                        value["termination"] = observation
                            .observed_status
                            .map(status_json)
                            .unwrap_or(serde_json::Value::Null);
                        value["stdout"] = excerpt_json(stdout);
                        value["stderr"] = excerpt_json(stderr);
                        value["observation"] = serde_json::json!({"child-id": observation.child_id, "phase": "before-settlement", "clock-domain": "harness-monotonic", "timeout-observed-ms": observation.timeout_observed.as_millis(), "stdout-reader-finished": observation.stdout_reader_finished, "stderr-reader-finished": observation.stderr_reader_finished});
                    }
                    Err(memcordon_testkit::ProcessTestError::Cancelled {
                        stdout,
                        stderr,
                        cleanup,
                        termination,
                        observation,
                    }) => {
                        value["cancelled-by-peer"] = serde_json::json!(true);
                        value["cleanup"] = serde_json::json!(if cleanup.is_ok()
                            && observation.callback_completed
                            && observation.stdout_reader_finished
                            && observation.stderr_reader_finished
                        {
                            "complete"
                        } else {
                            "incomplete"
                        });
                        value["termination"] = observation
                            .observed_status
                            .map(status_json)
                            .unwrap_or(serde_json::Value::Null);
                        value["settlement-termination"] = termination
                            .map(status_json)
                            .unwrap_or(serde_json::Value::Null);
                        value["stdout"] = excerpt_json(stdout);
                        value["stderr"] = excerpt_json(stderr);
                        value["observation"] = serde_json::json!({"child-id": observation.child_id, "clock-domain": "harness-monotonic", "cancellation-observed-ms": observation.cancellation_observed.as_millis(), "callback-completed": observation.callback_completed, "stdout-reader-finished": observation.stdout_reader_finished, "stderr-reader-finished": observation.stderr_reader_finished});
                    }
                    Err(memcordon_testkit::ProcessTestError::OutputLimit {
                        stdout,
                        stderr,
                        cleanup,
                        termination,
                    }) => {
                        value["output-limited"] = serde_json::json!(true);
                        value["termination"] = termination
                            .map(status_json)
                            .unwrap_or(serde_json::Value::Null);
                        value["cleanup"] = serde_json::json!(if cleanup.is_ok() {
                            "complete"
                        } else {
                            "incomplete"
                        });
                        value["stdout"] = excerpt_json(stdout);
                        value["stderr"] = excerpt_json(stderr);
                    }
                    Err(error) => {
                        value["cleanup"] = serde_json::json!("unknown");
                        value["error"] =
                            serde_json::json!(bounded_excerpt(error.to_string().as_bytes()));
                        value["output-limited"] = serde_json::json!(
                            error
                                .to_string()
                                .contains("subprocess output exceeds byte limit")
                        );
                    }
                }
            }
            let directory = diagnostic_directory
                .as_ref()
                .expect("phase diagnostics allocated");
            let temporary = directory.join(phase.name()).with_extension("tmp");
            let path = directory.join(phase.name()).with_extension("json");
            crate::release::source::write_diagnostic_json(&temporary, &value)?;
            std::fs::rename(temporary, path)?;
            Ok(())
        };
        if let Err(error) = report("in-progress", budget, None, None) {
            eprintln!("diagnostic retention incomplete: {error}");
        }
        let budget = self.available_budget()?;
        let ordinary = (matches!(&self.toolchain, Some(ToolchainInvocation::Cargo { .. }))
            && self.arguments.first().is_some_and(|argument| {
                matches!(
                    argument.to_str(),
                    Some(
                        "build" | "check" | "clippy" | "rustdoc" | "fetch" | "metadata" | "install"
                    )
                ) || (argument == "test"
                    && self.arguments.iter().any(|argument| argument == "--no-run"))
            }))
            || matches!(&self.toolchain,
                Some(ToolchainInvocation::Program { executable, .. })
                if executable.file_name().is_some_and(|name| matches!(name.to_str(), Some("cargo-audit" | "cargo-audit.exe" | "cargo-deny" | "cargo-deny.exe"))));
        let cancel_safe = match self.peer_stop_policy {
            Some(PeerStopPolicy::CancelAndSettle) => true,
            Some(PeerStopPolicy::FinishOwnedPhase) => false,
            None => ordinary,
        };
        let cancellation = if cancel_safe {
            group.as_ref().map(|group| group.requested.clone())
        } else {
            None
        };
        let observe_cargo_progress = cfg!(target_os = "macos")
            && matches!(self.phase, Some(CiPhase::NativeCompile))
            && matches!(self.toolchain, Some(ToolchainInvocation::Cargo { .. }));
        let (result, logger_settled, cargo_progress) = std::thread::scope(|scope| {
            let lane = match std::thread::current().name() {
                Some("ci-source-lane") => "first",
                Some("ci-auxiliary-lane") => "second",
                _ => "owner",
            };
            let phase = self.phase.map_or("command", CiPhase::name);
            let (sender, receiver) =
                std::sync::mpsc::sync_channel::<memcordon_testkit::ProgressChunk>(32);
            let omitted = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
            let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let logger_done = done.clone();
            let secrets: Vec<String> = [
                "GH_TOKEN",
                "GITHUB_TOKEN",
                "CARGO_REGISTRY_TOKEN",
                "CARGO_REGISTRIES_CRATES_IO_TOKEN",
                "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
            ]
            .into_iter()
            .filter_map(|key| std::env::var(key).ok())
            .filter(|value| !value.is_empty())
            .collect();
            let logger = scope.spawn(move || {
                let mut cargo_progress = observe_cargo_progress
                    .then(|| crate::cargo_progress::CargoProgress::new(budget));
                let mut pending = [Vec::new(), Vec::new()];
                let mut discarding = [false, false];
                let mut remaining: usize = 1024 * 1024;
                let mut omitted_lines = 0_u64;
                let mut final_chunks = 0;
                loop {
                    let next = if logger_done.load(std::sync::atomic::Ordering::Acquire) {
                        if final_chunks == 32 {
                            break;
                        }
                        final_chunks += 1;
                        receiver
                            .try_recv()
                            .map_err(|_| std::sync::mpsc::RecvTimeoutError::Disconnected)
                    } else {
                        receiver.recv_timeout(Duration::from_millis(25))
                    };
                    let chunk = match next {
                        Ok(chunk) => chunk,
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                    };
                    let stream = match chunk.stream {
                        memcordon_testkit::OutputStream::Stdout => 0,
                        memcordon_testkit::OutputStream::Stderr => 1,
                    };
                    for byte in chunk.bytes {
                        if byte == b'\n' {
                            if !discarding[stream] && remaining > 0 {
                                let mut text =
                                    String::from_utf8_lossy(&pending[stream]).into_owned();
                                for secret in &secrets {
                                    text = text.replace(secret, "[redacted]");
                                }
                                let lower = text.to_ascii_lowercase();
                                if [
                                    "authorization:",
                                    "access_token",
                                    "refresh_token",
                                    "password=",
                                    "token=",
                                ]
                                .iter()
                                .any(|field| lower.contains(field))
                                {
                                    text = "[sensitive HTTP material redacted]".into();
                                }
                                let safe: String =
                                    text.chars().flat_map(char::escape_default).collect();
                                if let Some(observed) = &mut cargo_progress {
                                    observed.observe_line(started.elapsed(), chunk.stream, &safe);
                                }
                                remaining = remaining.saturating_sub(safe.len());
                                eprintln!("[ci {lane} {phase} {:?}] {safe}", chunk.stream);
                            } else if !discarding[stream] {
                                omitted_lines = omitted_lines.saturating_add(1);
                            }
                            pending[stream].clear();
                            discarding[stream] = false;
                        } else if pending[stream].len() < 8192 && !discarding[stream] {
                            pending[stream].push(byte);
                        } else {
                            // Discard an oversized whole line instead of leaking a
                            // credential split at the progress/capture boundary.
                            pending[stream].clear();
                            discarding[stream] = true;
                            omitted_lines = omitted_lines.saturating_add(1);
                        }
                    }
                }
                omitted_lines = omitted_lines.saturating_add(
                    u64::try_from(pending.iter().filter(|line| !line.is_empty()).count())
                        .unwrap_or(u64::MAX),
                );
                if omitted_lines != 0 {
                    eprintln!(
                        "[ci child] omitted {omitted_lines} incomplete or oversized progress lines"
                    );
                }
                (cargo_progress, omitted_lines)
            });
            let progress = progress.then(|| memcordon_testkit::ProgressOutput {
                sender,
                omitted: omitted.clone(),
            });
            let failure = if self.defer_group_failure {
                None
            } else {
                group.clone().map(|group| {
                    let operation = self.phase.map_or("command", CiPhase::name);
                    std::sync::Arc::new(move |notice| {
                        group.request_command_failure_notice(operation, notice)
                    })
                        as std::sync::Arc<
                            dyn Fn(memcordon_testkit::NativeFailureNotice) + Send + Sync,
                        >
                })
            };
            let result = memcordon_testkit::run_with_deadline_failure_notice_output_limit(
                command,
                budget,
                self.output_limit,
                cancellation,
                progress,
                failure,
            );
            done.store(true, std::sync::atomic::Ordering::Release);
            // Incomplete reader settlement cannot keep the logger waiting for
            // a sender forever. The native result remains authoritative.
            let (logger_settled, mut cargo_progress, omitted_lines) = match logger.join() {
                Ok((observed, omitted_lines)) => (true, observed, omitted_lines),
                Err(_) => (false, None, 0),
            };
            let omitted = omitted.load(std::sync::atomic::Ordering::Acquire);
            if let Some(observed) = &mut cargo_progress {
                observed.finish(omitted_lines, omitted);
            }
            if omitted != 0 {
                eprintln!("[ci child] omitted {omitted} progress chunks");
            }
            (result, logger_settled, cargo_progress)
        });
        if !self.defer_group_failure
            && (result.as_ref().is_err()
                || result.as_ref().is_ok_and(|output| !output.status.success()))
            && let Some(group) = &group
        {
            group.request_after_failure();
        }
        if !logger_settled && let Some(group) = &group {
            group.close_admission();
        }
        if let (Err(error), Some(group)) = (&result, &group) {
            use memcordon_testkit::ProcessTestError;
            let unsettled = match error {
                ProcessTestError::Wait(_) | ProcessTestError::Output(_) => true,
                ProcessTestError::Callback {
                    cleanup,
                    capture_complete,
                    ..
                } => cleanup.is_err() || !capture_complete,
                ProcessTestError::OutputLimit { cleanup, .. } => cleanup.is_err(),
                ProcessTestError::Timeout {
                    cleanup,
                    observation,
                    ..
                } => cleanup.is_err() || !observation.callback_completed,
                ProcessTestError::Cancelled {
                    cleanup,
                    observation,
                    ..
                } => {
                    cleanup.is_err()
                        || !observation.callback_completed
                        || !observation.stdout_reader_finished
                        || !observation.stderr_reader_finished
                }
                ProcessTestError::Spawn(_) => false,
            };
            if unsettled {
                group.close_admission();
            }
        }
        let state = if result.as_ref().is_ok_and(|output| output.status.success()) {
            "completed"
        } else {
            "failed"
        };
        if let Err(error) = report(state, budget, Some(&result), cargo_progress.as_ref()) {
            eprintln!("diagnostic retention incomplete: {error}");
        }
        finish_native_observation(result, logger_settled).into_result()
    }
}

fn finish_native_observation(
    result: std::result::Result<ObservedOutput, memcordon_testkit::ProcessTestError>,
    logger_settled: bool,
) -> crate::work_outcome::WorkOutcome<ObservedOutput> {
    let writers = if logger_settled {
        crate::work_outcome::native_settlement(&result)
    } else {
        crate::work_outcome::WriterSettlement::Unknown
    };
    let result = result.map_err(|error| match error {
            memcordon_testkit::ProcessTestError::Spawn(error) => CiError::CommandSpawnFailure(error),
            memcordon_testkit::ProcessTestError::OutputLimit { stdout, stderr, cleanup, termination } => CiError::Message(format!("subprocess output exceeds byte limit; cleanup={cleanup:?}; termination={termination:?}; stdout={:?}; stderr={:?}", bounded_excerpt(&stdout), bounded_excerpt(&stderr))),
            memcordon_testkit::ProcessTestError::Timeout { deadline, stdout, stderr, cleanup, observation } => CiError::Message(format!("subprocess exceeded {deadline:?}; cleanup={cleanup:?}; observation={observation:?}; stdout={:?}; stderr={:?}", bounded_excerpt(&stdout), bounded_excerpt(&stderr))),
            memcordon_testkit::ProcessTestError::Cancelled { stdout, stderr, cleanup, termination, observation } => {
                let settled = cleanup.is_ok() && observation.callback_completed && observation.stdout_reader_finished && observation.stderr_reader_finished;
                let details = format!("cleanup={cleanup:?}; termination={termination:?}; observation={observation:?}; stdout={:?}; stderr={:?}", bounded_excerpt(&stdout), bounded_excerpt(&stderr));
                if settled { CiError::SettledCancellation(details) } else { CiError::Cancelled(details) }
            },
            error => CiError::Message(bounded_excerpt(error.to_string().as_bytes())),
        });
    crate::work_outcome::WorkOutcome::observed(result, writers).postcondition(if logger_settled {
        Ok(())
    } else {
        Err(CiError::Message("bounded progress logger panicked".into()))
    })
}

#[cfg(test)]
#[path = "../tests/private/native_observation.rs"]
mod native_observation_tests;

pub fn bounded_excerpt(bytes: &[u8]) -> String {
    excerpt(bytes).0
}

fn excerpt(bytes: &[u8]) -> (String, bool) {
    let limit = 64 * 1024;
    let first = String::from_utf8_lossy(&bytes[..bytes.len().min(limit)]);
    if bytes.len() <= limit && first.len() <= limit {
        return (first.into_owned(), false);
    }
    let failures = libtest_failure_sections(bytes);
    if !failures.is_empty() {
        let before = " [excerpt truncated; libtest failure sections] ";
        let after = " [excerpt truncated; remaining output] ";
        let content_budget = limit - before.len() - after.len();
        let failure_budget = content_budget / 2;
        let head_budget = (content_budget - failure_budget) / 2;
        let tail_budget = content_budget - failure_budget - head_budget;
        let mut text = String::with_capacity(limit);
        append_excerpt_head(&mut text, bytes, head_budget);
        text.push_str(before);
        let section_budget = failure_budget / failures.len();
        let remainder = failure_budget % failures.len();
        for (index, failure) in failures.into_iter().enumerate() {
            text.push_str(
                &head_tail_excerpt(failure, section_budget + usize::from(index < remainder)).0,
            );
        }
        text.push_str(after);
        append_excerpt_tail(&mut text, bytes, tail_budget);
        return (text, true);
    }
    head_tail_excerpt(bytes, limit)
}

fn libtest_failure_sections(bytes: &[u8]) -> Vec<&[u8]> {
    let mut offset = 0;
    let mut start = None;
    let mut sections = Vec::new();
    for raw_line in bytes.split_inclusive(|byte| *byte == b'\n') {
        let line = raw_line.strip_suffix(b"\n").unwrap_or(raw_line);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line == b"failures:" && start.is_none() {
            start = Some(offset);
        }
        offset += raw_line.len();
        if line.starts_with(b"test result: FAILED.")
            && let Some(start) = start
        {
            sections.push(&bytes[start..offset]);
        }
        if line.starts_with(b"test result: ") {
            start = None;
        }
    }
    sections
}

fn head_tail_excerpt(bytes: &[u8], limit: usize) -> (String, bool) {
    let first = String::from_utf8_lossy(&bytes[..bytes.len().min(limit)]);
    if bytes.len() <= limit && first.len() <= limit {
        return (first.into_owned(), false);
    }
    let marker = " [excerpt truncated] ";
    if limit <= marker.len() {
        let mut text = String::new();
        append_excerpt_head(&mut text, bytes, limit);
        return (text, true);
    }
    let content_budget = limit - marker.len();
    let head_budget = content_budget / 2;
    let tail_budget = content_budget - head_budget;
    let mut text = String::with_capacity(limit);
    append_excerpt_head(&mut text, bytes, head_budget);
    text.push_str(marker);
    append_excerpt_tail(&mut text, bytes, tail_budget);
    (text, true)
}

fn append_excerpt_head(text: &mut String, bytes: &[u8], head_budget: usize) {
    let head = String::from_utf8_lossy(&bytes[..bytes.len().min(head_budget)]);
    let head_end = head
        .char_indices()
        .map(|(offset, character)| offset + character.len_utf8())
        .take_while(|&end| end <= head_budget)
        .last()
        .unwrap_or(0);
    text.push_str(&head[..head_end]);
}

fn append_excerpt_tail(text: &mut String, bytes: &[u8], tail_budget: usize) {
    let tail = String::from_utf8_lossy(&bytes[bytes.len().saturating_sub(tail_budget)..]);
    let tail_start = tail
        .char_indices()
        .find(|&(offset, _)| offset >= tail.len().saturating_sub(tail_budget))
        .map_or(tail.len(), |(offset, _)| offset);
    text.push_str(&tail[tail_start..]);
}

fn excerpt_json(bytes: &[u8]) -> serde_json::Value {
    let (text, truncated) = excerpt(bytes);
    serde_json::json!({"text": text, "byte-count": bytes.len(), "truncated": truncated})
}

fn status_json(status: std::process::ExitStatus) -> serde_json::Value {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return serde_json::json!({"unix-signal": signal, "core-dumped": status.core_dumped()});
        }
        serde_json::json!({"exit-code": status.code()})
    }
    #[cfg(windows)]
    {
        serde_json::json!({"windows-status": status.code().map(|code| code as u32)})
    }
}

pub fn rustup_cargo(
    root: &Path,
    toolchain: &str,
    arguments: impl IntoIterator<Item = impl AsRef<OsStr>>,
    deadline: Duration,
) -> CommandSpec {
    let mut spec = CommandSpec::cargo("rustup", root, toolchain, deadline);
    for argument in arguments {
        spec = spec.arg(argument.as_ref().to_os_string());
    }
    spec
}

pub struct PackageOutput {
    target: PathBuf,
}

impl PackageOutput {
    pub fn new(root: &Path, target: Option<&Path>) -> Result<Self> {
        let target = target.unwrap_or_else(|| Path::new("target"));
        let target = if target.is_absolute() {
            target.to_path_buf()
        } else {
            root.join(target)
        };
        Ok(Self { target })
    }

    pub fn archive_directory(&self) -> PathBuf {
        self.target.join("package")
    }

    pub fn command(&self, root: &Path, stable: &str, packages: &[String]) -> CommandSpec {
        let mut command = rustup_cargo(
            root,
            stable,
            [
                "package",
                "--locked",
                "--no-verify",
                "--registry",
                "crates-io",
                "--target-dir",
            ],
            Duration::from_secs(30 * 60),
        )
        .arg(&self.target);
        for package in packages {
            command = command.args(["--package", package]);
        }
        command
    }
}

pub fn supply_chain_commands(root: &Path, stable: &str) -> [CommandSpec; 2] {
    let bin = root.join("target").join("ci-tools").join("bin");
    [
        CommandSpec::toolchain_program(
            "rustup",
            root,
            stable,
            bin.join(if cfg!(windows) {
                "cargo-audit.exe"
            } else {
                "cargo-audit"
            }),
            Duration::from_secs(10 * 60),
        )
        .args(["audit", "--deny", "warnings"]),
        CommandSpec::toolchain_program(
            "rustup",
            root,
            stable,
            bin.join(if cfg!(windows) {
                "cargo-deny.exe"
            } else {
                "cargo-deny"
            }),
            Duration::from_secs(10 * 60),
        )
        .args(["--config", "ci/deny.toml", "check"]),
    ]
}

pub fn git(root: &Path, arguments: impl IntoIterator<Item = impl AsRef<OsStr>>) -> Result<Vec<u8>> {
    CommandSpec::new("git", root, Duration::from_secs(120))
        .args(
            arguments
                .into_iter()
                .map(|value| value.as_ref().to_os_string()),
        )
        .run()
}
