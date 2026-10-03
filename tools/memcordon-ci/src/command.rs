use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use memcordon_testkit::{ObservedOutput, run_with_deadline_output_limit};

use crate::{CiError, Result};

#[derive(Clone, Debug)]
pub struct CommandSpec {
    program: PathBuf,
    arguments: Vec<OsString>,
    toolchain: Option<ToolchainInvocation>,
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

impl CommandSpec {
    pub fn new(program: impl Into<PathBuf>, current_dir: &Path, deadline: Duration) -> Self {
        Self {
            program: program.into(),
            arguments: Vec::new(),
            toolchain: None,
            current_dir: current_dir.to_path_buf(),
            deadline,
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
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
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
        run_with_deadline_output_limit(&mut command, self.deadline, 16 * 1024 * 1024)
            .map_err(Into::into)
    }

    /// Capture a subprocess for callers that own a machine-readable protocol.
    /// Materialization, credential removal, and the deadline remain identical
    /// to `output`; only invocation diagnostics are suppressed.
    pub fn output_quiet(&self) -> Result<ObservedOutput> {
        let mut command = self.materialize()?;
        run_with_deadline_output_limit(&mut command, self.deadline, 16 * 1024 * 1024)
            .map_err(Into::into)
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
