use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use memcordon_testkit::{ObservedOutput, run_with_deadline};

use crate::{CiError, Result};

#[derive(Clone, Debug)]
pub struct CommandSpec {
    program: PathBuf,
    arguments: Vec<OsString>,
    toolchain: Option<ToolchainInvocation>,
    credential_policy: CredentialPolicy,
    current_dir: PathBuf,
    deadline: Duration,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CredentialPolicy {
    RemoveInherited,
    InheritCratesIoToken,
}

impl CommandSpec {
    pub fn new(program: impl Into<PathBuf>, current_dir: &Path, deadline: Duration) -> Self {
        Self {
            program: program.into(),
            arguments: Vec::new(),
            toolchain: None,
            credential_policy: CredentialPolicy::RemoveInherited,
            current_dir: current_dir.to_path_buf(),
            deadline,
        }
    }

    /// Cargo compilation with explicit toolchain ownership. `rustup` is used
    /// only outside a managed build; managed builds select measured executables.
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

    pub fn args<I, S>(mut self, arguments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.arguments.extend(arguments.into_iter().map(Into::into));
        self
    }

    pub fn inherit_crates_io_registry_token(mut self) -> Self {
        self.credential_policy = CredentialPolicy::InheritCratesIoToken;
        self
    }

    pub fn apply_environment(&self, command: &mut Command) {
        command.env_remove("CARGO_REGISTRY_TOKEN");
        if self.credential_policy == CredentialPolicy::RemoveInherited {
            command.env_remove("CARGO_REGISTRIES_CRATES_IO_TOKEN");
        }
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
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )))
        }
    }

    pub fn materialize(
        &self,
        context: Option<&crate::build_context::ValidatedBuildContext>,
    ) -> Result<Command> {
        self.materialize_native(context, None)
    }

    fn materialize_native(
        &self,
        context: Option<&crate::build_context::ValidatedBuildContext>,
        runner: Option<&crate::source_registry::native_runner::RunnerConfiguration>,
    ) -> Result<Command> {
        let mut command = match (&self.toolchain, context) {
            (Some(ToolchainInvocation::Cargo { toolchain }), Some(context)) => match runner {
                Some(runner) => context.cargo_command_with_native_runner(
                    toolchain,
                    &self.arguments,
                    &self.current_dir,
                    runner,
                )?,
                None => context.cargo_command(toolchain, &self.arguments, &self.current_dir)?,
            },
            (
                Some(ToolchainInvocation::Program {
                    toolchain,
                    executable,
                }),
                Some(context),
            ) => context.toolchain_command(
                toolchain,
                executable,
                &self.arguments,
                &self.current_dir,
            )?,
            (invocation, _) => {
                let mut command = Command::new(&self.program);
                match invocation {
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
                if let Some(runner) = runner {
                    runner.verify(&self.current_dir)?;
                    command.arg("--config").arg(runner.path());
                }
                command.args(&self.arguments).current_dir(&self.current_dir);
                command
            }
        };
        self.apply_environment(&mut command);
        Ok(command)
    }

    pub fn output(&self) -> Result<ObservedOutput> {
        let mut observed = self.clone();
        let mut native_directory = None;
        let mut runner = None;
        if matches!(self.toolchain, Some(ToolchainInvocation::Cargo { .. }))
            && self
                .arguments
                .first()
                .is_some_and(|argument| argument == "test")
            && !self.arguments.iter().any(|argument| argument == "--no-run")
            && let Some(configuration) =
                crate::source_registry::observation::native_configuration(self.deadline)?
        {
            native_directory = configuration.path().parent().map(Path::to_path_buf);
            if self.arguments.iter().any(|argument| {
                argument.to_str().is_some_and(|text| {
                    text == "--message-format" || text.starts_with("--message-format=")
                })
            }) {
                return Err(CiError::Message(
                    "native evidence owns Cargo's artifact message format".into(),
                ));
            }
            observed.arguments.insert(
                1,
                OsString::from("--message-format=json-render-diagnostics"),
            );
            runner = Some(configuration);
        }
        let mut command =
            observed.materialize_native(crate::build_context::active(), runner.as_ref())?;
        eprintln!("ci subprocess program: {:?}", command.get_program());
        for argument in command.get_args() {
            eprintln!("ci subprocess argument: {argument:?}");
        }
        eprintln!("ci subprocess deadline: {:?}", self.deadline);
        let mut result = run_with_deadline(&mut command, self.deadline);
        let toolchain = match &self.toolchain {
            Some(
                ToolchainInvocation::Cargo { toolchain }
                | ToolchainInvocation::Program { toolchain, .. },
            ) => Some(toolchain.as_str()),
            None => None,
        };
        let recorded = match &result {
            Ok(output) => crate::source_registry::observation::record(
                &command,
                Ok(output),
                native_directory.as_deref(),
                toolchain,
            ),
            Err(error) => crate::source_registry::observation::record(
                &command,
                Err(&error.to_string()),
                native_directory.as_deref(),
                toolchain,
            ),
        };
        let runner_checked = runner
            .as_ref()
            .map_or(Ok(()), |runner| runner.verify(&self.current_dir));
        let decoded = if let Some(directory) = native_directory.as_deref()
            && let Ok(output) = &mut result
        {
            crate::source_registry::native_runner::decode_cargo_stdout(directory, &output.stdout)
                .map(|stdout| output.stdout = stdout)
        } else {
            Ok(())
        };
        let evidence_failures: Vec<_> = [recorded, runner_checked, decoded]
            .into_iter()
            .filter_map(std::result::Result::err)
            .map(|error| error.to_string())
            .collect();
        let recorded = if evidence_failures.is_empty() {
            Ok(())
        } else {
            Err(CiError::Message(evidence_failures.join("; ")))
        };
        preserve_observed_outcome(result, recorded)
    }
}

/// Evidence errors remain fatal while preserving the original process outcome.
pub fn preserve_observed_outcome(
    result: std::result::Result<ObservedOutput, memcordon_testkit::ProcessTestError>,
    recorded: Result<()>,
) -> Result<ObservedOutput> {
    if let Err(evidence_error) = recorded {
        let original = match &result {
            Ok(output) => format!(
                "status={}; stdout={:?}; stderr={:?}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
            Err(error) => error.to_string(),
        };
        return Err(CiError::Message(format!(
            "subprocess observation failed: {evidence_error}; original subprocess outcome: {original}"
        )));
    }
    result.map_err(Into::into)
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
        Ok(Self {
            target: crate::build_context::environment::paths::command_output_path(&target)?,
        })
    }

    pub fn archive_directory(&self) -> PathBuf {
        self.target.join("package")
    }

    pub fn command(&self, root: &Path, stable: &str, packages: &[String]) -> CommandSpec {
        let mut command = rustup_cargo(
            root,
            stable,
            ["package", "--locked", "--no-verify", "--target-dir"],
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
