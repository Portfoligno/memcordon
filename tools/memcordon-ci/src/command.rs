use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use memcordon_testkit::run_with_deadline;

use crate::{CiError, Result};

#[derive(Clone, Debug)]
pub struct CommandSpec {
    program: PathBuf,
    arguments: Vec<OsString>,
    environment: Vec<(OsString, OsString)>,
    current_dir: PathBuf,
    deadline: Duration,
}

impl CommandSpec {
    pub fn new(program: impl Into<PathBuf>, current_dir: &Path, deadline: Duration) -> Self {
        Self {
            program: program.into(),
            arguments: Vec::new(),
            environment: Vec::new(),
            current_dir: current_dir.to_path_buf(),
            deadline,
        }
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

    pub fn environment_variable(
        mut self,
        name: impl Into<OsString>,
        value: impl Into<OsString>,
    ) -> Self {
        self.environment.push((name.into(), value.into()));
        self
    }

    pub fn run(&self) -> Result<Vec<u8>> {
        eprintln!("ci subprocess program: {:?}", self.program);
        for argument in &self.arguments {
            eprintln!("ci subprocess argument: {argument:?}");
        }
        eprintln!("ci subprocess deadline: {:?}", self.deadline);
        let mut command = Command::new(&self.program);
        command
            .args(&self.arguments)
            .env_remove("CARGO_REGISTRY_TOKEN")
            .env_remove("CARGO_REGISTRIES_CRATES_IO_TOKEN")
            .envs(self.environment.iter().map(|(name, value)| (name, value)))
            .current_dir(&self.current_dir);
        let output = run_with_deadline(&mut command, self.deadline)?;
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
}

pub fn rustup_cargo(
    root: &Path,
    toolchain: &str,
    arguments: impl IntoIterator<Item = impl AsRef<OsStr>>,
    deadline: Duration,
) -> CommandSpec {
    let mut spec = CommandSpec::new("rustup", root, deadline).args(["run", toolchain, "cargo"]);
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
