//! Each shard derives its own current selection and owns compilation/execution.
use crate::{
    CiError, Result,
    command::{CiPhase, CommandSpec},
    failure_mode::FailureMode,
    native_coverage::{Selection, Selector, Target},
};
use serde_json::Value;
use std::{
    path::Path,
    time::{Duration, Instant},
};

fn error(message: &str) -> CiError {
    CiError::Message(message.into())
}
fn cargo(root: &Path, toolchain: &str, budget: Duration, cutoff: Instant) -> CommandSpec {
    CommandSpec::cargo("rustup", root, toolchain, budget)
        .bounded_until(cutoff)
        .output_limit(64 * 1024 * 1024)
}

pub fn selection_command(
    root: &Path,
    toolchain: &str,
    directory: &Path,
    selectors: &[String],
    compile: bool,
    failure_mode: FailureMode,
    cutoff: Instant,
) -> CommandSpec {
    let recipes = crate::native_test_plan::commands_for_platform(
        true,
        failure_mode,
        crate::native_test_plan::NativePlatform::MacOs,
    );
    let mut command = cargo(
        root,
        toolchain,
        recipes[usize::from(!compile)].deadline,
        cutoff,
    )
    .args(["test", "--target-dir"])
    .arg(directory)
    .args(selectors)
    .arg("--message-format=json-render-diagnostics")
    .phase(if compile {
        CiPhase::NativeCompile
    } else {
        CiPhase::NativeExecute
    });
    if compile {
        command = command.args(["--no-run", "--verbose"]);
    } else if failure_mode == FailureMode::CollectAll {
        command = command.arg("--no-fail-fast");
    }
    command
}

pub fn support_command(
    root: &Path,
    toolchain: &str,
    directory: &Path,
    selectors: &[String],
    compile: bool,
    failure_mode: FailureMode,
    cutoff: Instant,
) -> CommandSpec {
    let recipes = crate::native_test_plan::commands_for_platform(
        true,
        failure_mode,
        crate::native_test_plan::NativePlatform::MacOs,
    );
    cargo(
        root,
        toolchain,
        recipes[usize::from(!compile)].deadline,
        cutoff,
    )
    .args(["build", "--target-dir"])
    .arg(directory)
    .args(selectors)
    .phase(if compile {
        CiPhase::NativeCompile
    } else {
        CiPhase::NativeExecute
    })
}

pub fn select_metadata(metadata: &Value, index: usize, count: usize) -> Result<Selection> {
    let members = metadata["workspace_members"]
        .as_array()
        .ok_or_else(|| error("Cargo workspace members absent"))?;
    let packages = metadata["packages"]
        .as_array()
        .ok_or_else(|| error("Cargo packages absent"))?;
    let mut targets = Vec::new();
    for package in packages
        .iter()
        .filter(|package| members.contains(&package["id"]))
    {
        let package_id = package["id"]
            .as_str()
            .ok_or_else(|| error("Cargo package id absent"))?;
        for target in package["targets"]
            .as_array()
            .ok_or_else(|| error("Cargo targets absent"))?
        {
            let name = target["name"]
                .as_str()
                .ok_or_else(|| error("Cargo target name absent"))?;
            if name.is_empty() || name.starts_with('-') || name.chars().any(char::is_control) {
                return Err(error("Cargo target name invalid"));
            }
            let kinds = target["kind"]
                .as_array()
                .ok_or_else(|| error("Cargo target kinds absent"))?;
            let kind: Vec<_> = kinds.iter().map(Value::as_str).collect();
            let selector = match kind.as_slice() {
                [Some("custom-build")] => continue,
                [Some("bin")] => Selector::Bin(name.into()),
                [Some("test")] => Selector::Test(name.into()),
                [Some("bench")] => Selector::Bench(name.into()),
                [Some("example")] => Selector::Example(name.into()),
                [Some("proc-macro")] => Selector::Lib,
                _ if !kind.is_empty()
                    && kind.iter().all(|kind| {
                        matches!(
                            kind,
                            Some("lib" | "rlib" | "dylib" | "cdylib" | "staticlib")
                        )
                    }) =>
                {
                    Selector::Lib
                }
                _ => return Err(error("Cargo target kind unsupported or ambiguous")),
            };
            targets.push(Target {
                package: package_id.into(),
                selector,
            });
        }
    }
    crate::native_coverage::select(&targets, index, count).map_err(CiError::Message)
}

pub fn run_shard(
    root: &Path,
    index: usize,
    count: usize,
    profile: &str,
    failure_mode: FailureMode,
) -> Result<()> {
    if failure_mode != FailureMode::StopAfterFailure {
        return Err(error("native shards require stop-after-failure"));
    }
    if profile != "release" {
        return Err(error("native shards require the existing release profile"));
    }
    let cutoff = Instant::now() + Duration::from_secs(140 * 60);
    crate::preparation::with_operation(failure_mode, cutoff, || {
        crate::workflow_output::revoke_compilation("compiled-native-complete")?;
        let toolchain = crate::config::toolchains(root)?.stable;
        let metadata = cargo(root, &toolchain, Duration::from_secs(120), cutoff)
            .args([
                "metadata",
                "--format-version",
                "1",
                "--all-features",
                "--locked",
            ])
            .run_owned()
            .into_result()?;
        let selection = select_metadata(&serde_json::from_slice(&metadata)?, index, count)?;
        let selectors = crate::native_coverage::arguments(&selection, profile);
        eprintln!(
            "native shard {index}/{count}: {} selector groups",
            selection.selectors.len()
        );
        if !selection.support_binaries.is_empty() {
            let mut support: Vec<String> = [
                "--workspace",
                "--all-features",
                "--locked",
                "--profile",
                profile,
            ]
            .into_iter()
            .map(str::to_owned)
            .collect();
            for binary in &selection.support_binaries {
                support.extend(["--bin".into(), binary.clone()]);
            }
            support_command(
                root,
                &toolchain,
                Path::new("target/ci/native"),
                &support,
                true,
                failure_mode,
                cutoff,
            )
            .run()?;
        }
        for compile in [true, false] {
            let outcome = selection_command(
                root,
                &toolchain,
                Path::new("target/ci/native"),
                &selectors,
                compile,
                failure_mode,
                cutoff,
            )
            .run_owned();
            let settled = outcome.writers().permits_reading();
            outcome.into_result()?;
            if !settled || Instant::now() >= cutoff {
                return Err(error(
                    "native shard did not settle under its original cutoff",
                ));
            }
        }
        crate::workflow_output::compilation_complete("compiled-native-complete")
    })
}
