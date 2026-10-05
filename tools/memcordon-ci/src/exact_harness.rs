//! Reuse Cargo-selected test executables while proving each exact case executes.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::command::{CommandSpec, rustup_cargo};
use crate::{CiError, Result, capability};

pub fn resolve_executable(output: &[u8], target: &str) -> Result<PathBuf> {
    resolve_artifact(output, target, "test", true)
}

pub fn resolve_binary(output: &[u8], target: &str) -> Result<PathBuf> {
    resolve_artifact(output, target, "bin", false)
}

fn resolve_artifact(output: &[u8], target: &str, kind: &str, test: bool) -> Result<PathBuf> {
    let output = std::str::from_utf8(output)
        .map_err(|_| CiError::Message("Cargo output is not UTF-8".into()))?;
    let mut executables = Vec::new();
    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        let message: serde_json::Value = serde_json::from_str(line)?;
        if message["reason"] == "compiler-artifact"
            && message["target"]["name"] == target
            && message["profile"]["test"] == test
            && message["target"]["kind"]
                .as_array()
                .is_some_and(|kinds| kinds.iter().any(|observed| observed == kind))
            && let Some(executable) = message["executable"].as_str()
        {
            executables.push(PathBuf::from(executable));
        }
    }
    if executables.len() != 1 {
        return Err(CiError::Message(format!(
            "Cargo must identify exactly one test harness for {target}"
        )));
    }
    Ok(executables.remove(0))
}

pub fn require_selected_watchdog(output: &[u8]) -> Result<()> {
    let probe: serde_json::Value = serde_json::from_slice(output)?;
    let selected = &probe["selected"];
    if selected["name"] != "macos-watchdog"
        || selected["containment"]["supported"] != true
        || selected["deadline"]["supported"] != true
    {
        return Err(CiError::Message(
            "required macOS native scenario backend unavailable".into(),
        ));
    }
    Ok(())
}

pub fn require_listed_exactly_once(output: &[u8], selected: &str) -> Result<()> {
    if output.len() > 1024 * 1024 || selected.is_empty() {
        return Err(CiError::Message(
            "exact test listing is unbounded or selection empty".into(),
        ));
    }
    let listing = std::str::from_utf8(output)
        .map_err(|_| CiError::Message("test listing is not UTF-8".into()))?;
    let count = listing
        .lines()
        .filter_map(|line| line.strip_suffix(": test"))
        .filter(|name| *name == selected)
        .count();
    if count != 1 {
        return Err(CiError::Message(format!(
            "selected exact test {selected} occurs {count} times in harness listing"
        )));
    }
    Ok(())
}

#[derive(Default)]
pub struct ExactHarnessRunner {
    compiled: BTreeMap<HarnessKey, (PathBuf, Vec<u8>)>,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
struct HarnessKey {
    root: PathBuf,
    stable: String,
    target_dir: String,
    package: String,
    feature: String,
    target: String,
}

impl ExactHarnessRunner {
    #[allow(clippy::too_many_arguments)]
    fn prepare(
        &mut self,
        root: &Path,
        stable: &str,
        target_dir: &str,
        package: &str,
        feature: &str,
        target: &str,
        selected: &str,
    ) -> Result<PathBuf> {
        let key = HarnessKey {
            root: root.to_path_buf(),
            stable: stable.into(),
            target_dir: target_dir.into(),
            package: package.into(),
            feature: feature.into(),
            target: target.into(),
        };
        if let std::collections::btree_map::Entry::Vacant(entry) = self.compiled.entry(key.clone())
        {
            let output = rustup_cargo(
                root,
                stable,
                [
                    "test",
                    "--locked",
                    "--target-dir",
                    target_dir,
                    "--package",
                    package,
                    "--features",
                    feature,
                    "--test",
                    target,
                    "--no-run",
                    "--message-format=json",
                ],
                Duration::from_secs(25 * 60),
            )
            .run()?;
            if cfg!(target_os = "macos") && package == "memcordon" {
                let image = resolve_binary(&output, "memcordon")?;
                let probe = CommandSpec::new(image, root, Duration::from_secs(30))
                    .args(["doctor", "--json"])
                    .run()?;
                require_selected_watchdog(&probe)?;
            }
            let executable = resolve_executable(&output, target)?;
            let listing = CommandSpec::new(&executable, root, Duration::from_secs(30))
                .args(["--list", "--format", "terse"])
                .run()?;
            entry.insert((executable, listing));
        }
        let (executable, listing) = &self.compiled[&key];
        require_listed_exactly_once(listing, selected)?;
        Ok(executable.clone())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_selected(
        &mut self,
        root: &Path,
        stable: &str,
        target_dir: &str,
        package: &str,
        feature: &str,
        target: &str,
        selected: &[&str],
    ) -> Result<()> {
        if selected.is_empty()
            || selected
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != selected.len()
        {
            return Err(CiError::Message(
                "exact selection must be nonempty and unique".into(),
            ));
        }
        for name in selected {
            self.prepare(root, stable, target_dir, package, feature, target, name)?;
        }
        for name in selected {
            self.run(root, stable, target_dir, package, feature, target, name)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run(
        &mut self,
        root: &Path,
        stable: &str,
        target_dir: &str,
        package: &str,
        feature: &str,
        target: &str,
        selected: &str,
    ) -> Result<()> {
        let executable =
            self.prepare(root, stable, target_dir, package, feature, target, selected)?;
        let mut execution =
            CommandSpec::new(executable, root, Duration::from_secs(15 * 60)).args([
                selected,
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "--color=never",
            ]);
        if selected.starts_with("required_") {
            execution = execution.arg("--ignored");
        }
        capability::require_exact_standard_test_success(&execution.run()?, selected)
    }
}
