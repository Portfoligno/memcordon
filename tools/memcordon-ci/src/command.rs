use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use memcordon_testkit::{ObservedOutput, run_with_deadline_output_limit};

use crate::{CiError, Result};

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
    clear_environment: bool,
    output_limit: usize,
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
    fn name(self) -> &'static str {
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
            clear_environment: false,
            output_limit: 16 * 1024 * 1024,
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
        match self.operation_deadline {
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

    pub fn apply_environment(&self, command: &mut Command) {
        if self.clear_environment {
            command.env_clear();
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
    }
    pub fn cleared_environment(mut self) -> Self {
        self.clear_environment = true;
        self
    }

    pub fn run(&self) -> Result<Vec<u8>> {
        let output = self.output()?;
        if output.status.success() {
            if !output.stdout.is_empty() {
                print!("{}", String::from_utf8_lossy(&output.stdout));
            }
            if !output.stderr.is_empty() {
                eprint!("{}", String::from_utf8_lossy(&output.stderr));
            }
            Ok(output.stdout)
        } else {
            Err(CiError::Message(format!(
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
        command.args(&self.arguments).current_dir(&self.current_dir);
        self.apply_environment(&mut command);
        Ok(command)
    }

    pub fn output(&self) -> Result<ObservedOutput> {
        let mut command = self.materialize()?;
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
        let mut command = self.materialize()?;
        self.observe(&mut command)
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
        let command = self.materialize()?;
        let mut observation_error = None;
        let output = memcordon_testkit::run_with_deadline_owned_spawn_after_output_limit(
            command,
            self.available_budget()?,
            self.output_limit,
            |mut command| {
                let child = command.spawn()?;
                if let Err(error) = observe_creation(&child) {
                    observation_error = Some(error);
                }
                Ok(child)
            },
            |_| Ok(()),
        );
        match (output, observation_error) {
            (Ok(output), None) => Ok(output),
            (Ok(_), Some(error)) => Err(error),
            (Err(error), original) => Err(CiError::Message(format!(
                "native creation observation={original:?}; native settlement={error}"
            ))),
        }
    }

    fn observe(&self, command: &mut Command) -> Result<ObservedOutput> {
        let budget = self.available_budget()?;
        let started = Instant::now();
        let report = |state: &str,
                      observed_budget: Duration,
                      result: Option<
            &std::result::Result<ObservedOutput, memcordon_testkit::ProcessTestError>,
        >|
         -> Result<()> {
            let Some(phase) = self.phase else {
                return Ok(());
            };
            let mut value = serde_json::json!({"phase": phase.name(), "state": state, "program": self.program.to_string_lossy(), "arguments": self.arguments.iter().map(|argument| argument.to_string_lossy()).collect::<Vec<_>>(), "toolchain": format!("{:?}", self.toolchain), "original-budget-ms": self.deadline.as_millis(), "available-budget-ms": observed_budget.as_millis(), "elapsed-ms": started.elapsed().as_millis()});
            value["selection"] = self.selection.clone().unwrap_or(serde_json::Value::Null);
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
            let directory = self.current_dir.join("target/ci/reports/execution");
            std::fs::create_dir_all(&directory)?;
            let temporary = directory.join(phase.name()).with_extension("tmp");
            let path = directory.join(phase.name()).with_extension("json");
            crate::release::source::write_json(&temporary, &value)?;
            std::fs::rename(temporary, path)?;
            Ok(())
        };
        if let Err(error) = report("in-progress", budget, None) {
            eprintln!("diagnostic retention incomplete: {error}");
        }
        let budget = self.available_budget()?;
        let result = run_with_deadline_output_limit(command, budget, self.output_limit);
        let state = if result.as_ref().is_ok_and(|output| output.status.success()) {
            "completed"
        } else {
            "failed"
        };
        if let Err(error) = report(state, budget, Some(&result)) {
            eprintln!("diagnostic retention incomplete: {error}");
        }
        result.map_err(|error| match error {
            memcordon_testkit::ProcessTestError::OutputLimit { stdout, stderr, cleanup, termination } => CiError::Message(format!("subprocess output exceeds byte limit; cleanup={cleanup:?}; termination={termination:?}; stdout={:?}; stderr={:?}", bounded_excerpt(&stdout), bounded_excerpt(&stderr))),
            memcordon_testkit::ProcessTestError::Timeout { deadline, stdout, stderr, cleanup, observation } => CiError::Message(format!("subprocess exceeded {deadline:?}; cleanup={cleanup:?}; observation={observation:?}; stdout={:?}; stderr={:?}", bounded_excerpt(&stdout), bounded_excerpt(&stderr))),
            error => CiError::Message(bounded_excerpt(error.to_string().as_bytes())),
        })
    }
}

pub fn bounded_excerpt(bytes: &[u8]) -> String {
    excerpt(bytes).0
}

fn excerpt(bytes: &[u8]) -> (String, bool) {
    let limit = 64 * 1024;
    let first = String::from_utf8_lossy(&bytes[..bytes.len().min(limit)]);
    if bytes.len() <= limit && first.len() <= limit {
        return (first.into_owned(), false);
    }
    if let Some(failure) = libtest_failure_section(bytes) {
        let before = " [excerpt truncated; first libtest failure section] ";
        let after = " [excerpt truncated; remaining output] ";
        let content_budget = limit - before.len() - after.len();
        let failure_budget = content_budget / 2;
        let head_budget = (content_budget - failure_budget) / 2;
        let tail_budget = content_budget - failure_budget - head_budget;
        let mut text = String::with_capacity(limit);
        append_excerpt_head(&mut text, bytes, head_budget);
        text.push_str(before);
        text.push_str(&head_tail_excerpt(failure, failure_budget).0);
        text.push_str(after);
        append_excerpt_tail(&mut text, bytes, tail_budget);
        return (text, true);
    }
    head_tail_excerpt(bytes, limit)
}

fn libtest_failure_section(bytes: &[u8]) -> Option<&[u8]> {
    let mut offset = 0;
    let mut start = None;
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
            return Some(&bytes[start..offset]);
        }
        if line.starts_with(b"test result: ") {
            start = None;
        }
    }
    None
}

fn head_tail_excerpt(bytes: &[u8], limit: usize) -> (String, bool) {
    let first = String::from_utf8_lossy(&bytes[..bytes.len().min(limit)]);
    if bytes.len() <= limit && first.len() <= limit {
        return (first.into_owned(), false);
    }
    let marker = " [excerpt truncated] ";
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
