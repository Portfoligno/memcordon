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

    pub fn apply_environment(&self, command: &mut Command) {
        command
            .env_remove("GH_TOKEN")
            .env_remove("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
            .env_remove("ACTIONS_ID_TOKEN_REQUEST_URL");
        command.env_remove("CARGO_REGISTRY_TOKEN");
        command.env_remove("CARGO_REGISTRIES_CRATES_IO_TOKEN");
        command.env_remove("GITHUB_TOKEN");
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
        let result = run_with_deadline_output_limit(command, budget, 16 * 1024 * 1024);
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
    let shown = &bytes[..bytes.len().min(64 * 1024)];
    let mut text = String::from_utf8_lossy(shown).into_owned();
    if shown.len() != bytes.len() {
        text.push_str(" [excerpt truncated]");
    }
    text
}

fn excerpt_json(bytes: &[u8]) -> serde_json::Value {
    serde_json::json!({"text": bounded_excerpt(bytes), "byte-count": bytes.len(), "truncated": bytes.len() > 64 * 1024})
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
