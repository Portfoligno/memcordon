//! Execute current native tests and check selection in the same operation.
use crate::{CiError, Result, command::CommandSpec, failure_mode::FailureMode};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const LINUX_REQUIRED: &[&str] = &[
    "protocol_tests::current_unsupported_versions_reject_before_payload_allocation",
    "native_current_filter::current_filter_vectors_match_profile",
    "native_descriptor_custody::native_exec_stop_precedes_first_target_instruction_and_detach_releases_it",
    "native_descriptor_custody::native_trusted_exit_and_eof_do_not_substitute_for_exec_event",
    "native_descriptor_custody::native_unexpected_stop_fails_and_owned_drop_kills_then_reaps_exact_child",
    "native_descriptor_custody::native_tracer_death_exitkill_retires_trusted_child_before_exec",
];

fn error(message: &str) -> CiError {
    CiError::Message(message.into())
}
pub fn assert_one_test(output: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(output).map_err(|_| error("native test output is not UTF8"))?;
    if !text
        .lines()
        .any(|line| line.starts_with("test result: ok. 1 passed; 0 failed; 0 ignored;"))
    {
        return Err(error("required exact native test did not execute once"));
    }
    Ok(())
}

pub fn run(root: &Path, diagnostics: &Path) -> Result<()> {
    let features = if cfg!(target_os = "linux") {
        "private-tcp,test-support"
    } else if cfg!(target_os = "windows") {
        "windows-sealed-runtime,test-support"
    } else {
        return Err(error(
            "native components require a Linux or Windows backend",
        ));
    };
    let cutoff = Instant::now() + Duration::from_secs(150 * 60);
    crate::preparation::with_operation(FailureMode::StopAfterFailure, cutoff, || {
        let toolchain = crate::config::toolchains(root)?.stable;
        let bytes = CommandSpec::cargo("rustup", root, &toolchain, Duration::from_secs(60 * 60))
            .args([
                "test",
                "--locked",
                "--release",
                "--target-dir",
                "target/ci/native",
                "-p",
                "memcordon",
                "--features",
                features,
                "--test",
                "sealed_agent",
                "--no-run",
                "--message-format=json",
            ])
            .bounded_until(cutoff)
            .output_limit(64 * 1024 * 1024)
            .run_owned()
            .into_result()?;
        let mut executables = Vec::new();
        for line in bytes.split(|byte| *byte == b'\n') {
            let Ok(record) = serde_json::from_slice::<serde_json::Value>(line) else {
                continue;
            };
            if record["reason"] == "compiler-artifact"
                && record["target"]["name"] == "sealed_agent"
                && record["profile"]["test"] == true
                && let Some(path) = record["executable"].as_str()
            {
                executables.push(PathBuf::from(path));
            }
        }
        executables.sort();
        executables.dedup();
        if executables.len() != 1 {
            return Err(error("native operational harness is missing or ambiguous"));
        }
        let executable = &executables[0];
        let command = || {
            CommandSpec::new(executable, root, Duration::from_secs(135 * 60)).bounded_until(cutoff)
        };
        command().run()?;
        let required = if cfg!(target_os = "linux") {
            LINUX_REQUIRED
        } else {
            crate::windows_readiness_native_tests::REQUIRED_TESTS
        };
        for name in required {
            let listing = command()
                .args(["--list", "--exact", name])
                .run_owned()
                .into_result()?;
            if !std::str::from_utf8(&listing)
                .map_err(|_| error("native test listing is not UTF8"))?
                .lines()
                .any(|line| line.strip_suffix(": test") == Some(*name))
            {
                return Err(error("required native test is absent"));
            }
            let selected =
                if cfg!(target_os = "linux") && name.starts_with("native_descriptor_custody::") {
                    CommandSpec::new("sudo", root, Duration::from_secs(135 * 60))
                        .args(["--non-interactive", "--"])
                        .arg(executable)
                        .bounded_until(cutoff)
                } else {
                    command()
                };
            let bytes = selected
                .args(["--exact", "--include-ignored", name])
                .run_owned()
                .into_result()?;
            assert_one_test(&bytes)?;
        }
        #[cfg(windows)]
        super::windows_component_tests::run(root, cutoff - Duration::from_secs(15 * 60), cutoff)?;
        #[cfg(target_os = "linux")]
        super::linux_installed_tests::run_components(
            root,
            diagnostics,
            cutoff - Duration::from_secs(15 * 60),
            cutoff,
        )?;
        #[cfg(not(target_os = "linux"))]
        let _ = diagnostics;
        Ok(())
    })
}
