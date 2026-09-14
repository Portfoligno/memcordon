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
        let mut command = match (&self.toolchain, context) {
            (Some(ToolchainInvocation::Cargo { toolchain }), Some(context)) => {
                context.cargo_command(toolchain, &self.arguments, &self.current_dir)?
            }
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
                command.args(&self.arguments).current_dir(&self.current_dir);
                command
            }
        };
        self.apply_environment(&mut command);
        Ok(command)
    }

    pub fn output(&self) -> Result<ObservedOutput> {
        let mut command = self.materialize(crate::build_context::active())?;
        eprintln!("ci subprocess program: {:?}", command.get_program());
        for argument in command.get_args() {
            eprintln!("ci subprocess argument: {argument:?}");
        }
        eprintln!("ci subprocess deadline: {:?}", self.deadline);
        run_with_deadline(&mut command, self.deadline).map_err(Into::into)
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

pub fn git(root: &Path, arguments: impl IntoIterator<Item = impl AsRef<OsStr>>) -> Result<Vec<u8>> {
    CommandSpec::new("git", root, Duration::from_secs(120))
        .args(
            arguments
                .into_iter()
                .map(|value| value.as_ref().to_os_string()),
        )
        .run()
}
