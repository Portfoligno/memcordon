#![cfg(feature = "test-fixtures")]

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use memcordon_platform::test_support::ProcessIdentity;
#[cfg(unix)]
use memcordon_testkit::run_with_deadline_after;
use memcordon_testkit::{ObservedOutput, assert_stdout_empty, run_with_deadline};

static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

fn fixture() -> &'static str {
    env!("CARGO_BIN_EXE_memcordon-test-fixture")
}

fn temporary_pid_file() -> PathBuf {
    let number = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "memcordon-lifecycle-{}-{number}.pid",
        std::process::id()
    ))
}

fn backend_available() -> bool {
    let output = Command::new(env!("CARGO_BIN_EXE_memcordon"))
        .args(["probe", "--json"])
        .output()
        .expect("probe should run");
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("probe output should be JSON");
    value
        .get("selected")
        .is_some_and(|selected| !selected.is_null())
}

fn configured_iterations(name: &str) -> u32 {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ci/policy.toml");
    let policy: toml::Value = fs::read_to_string(path)
        .expect("CI policy should be readable")
        .parse()
        .expect("CI policy should be valid TOML");
    policy["test"][name]
        .as_integer()
        .and_then(|value| value.try_into().ok())
        .filter(|value: &u32| *value > 0)
        .expect("configured iteration count should be positive")
}

fn wrapped(command: impl AsRef<OsStr>, args: &[&str]) -> Command {
    let mut invocation = Command::new(env!("CARGO_BIN_EXE_memcordon"));
    invocation.args([
        "run",
        "--enforcement",
        if cfg!(target_os = "macos") {
            "watchdog"
        } else {
            "hard"
        },
        "--memory",
        "8GiB",
        "--",
    ]);
    invocation.arg(command);
    invocation.args(args);
    invocation
}

fn completed(command: &mut Command, deadline: Duration) -> ObservedOutput {
    run_with_deadline(command, deadline).unwrap_or_else(|error| panic!("{error}"))
}

fn read_identity(path: &Path) -> ProcessIdentity {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        match fs::read_to_string(path) {
            Ok(value) => {
                let mut fields = value.split_whitespace();
                let pid = fields
                    .next()
                    .and_then(|field| field.parse::<u32>().ok())
                    .expect("PID file should contain a process id");
                let birth = fields
                    .next()
                    .and_then(|field| field.parse::<u128>().ok())
                    .expect("PID file should contain a birth identity");
                assert!(
                    fields.next().is_none(),
                    "PID file should contain one identity"
                );
                return ProcessIdentity { pid, birth };
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("PID file was not readable: {error}"),
        }
    }
}

fn assert_process_gone(identity: ProcessIdentity) {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        if !identity
            .still_exists()
            .expect("process identity query should succeed")
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "process identity {identity:?} survived cleanup"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn hard_unavailability_refuses_before_target_execution() {
    if backend_available() {
        return;
    }
    let marker = temporary_pid_file();
    let mut invocation = Command::new(env!("CARGO_BIN_EXE_memcordon"));
    invocation.args([
        "run",
        "--enforcement",
        "hard",
        "--memory",
        "1GiB",
        "--",
        fixture(),
        "exit",
        "--code",
        "0",
        "--pid-file",
    ]);
    invocation.arg(&marker);
    let output = completed(&mut invocation, Duration::from_secs(2));
    assert_eq!(output.status.code(), Some(125));
    assert!(!marker.exists(), "unavailable hard backend released target");
}

#[test]
fn immediate_success_failure_and_status_are_reaped_and_preserved() {
    if !backend_available() {
        return;
    }
    let iterations = configured_iterations("fast_short_child_iterations");
    for iteration in 0..iterations {
        let code = [0, 1, 37][iteration as usize % 3];
        let output = completed(
            &mut wrapped(fixture(), &["exit", "--code", &code.to_string()]),
            Duration::from_secs(2),
        );
        assert_eq!(output.status.code(), Some(code), "iteration {iteration}");
        assert_stdout_empty(&output);
    }
}

#[cfg(target_os = "macos")]
#[test]
fn macos_system_success_and_failure_smoke_tests_are_bounded() {
    let success = completed(&mut wrapped("/usr/bin/true", &[]), Duration::from_secs(2));
    assert_eq!(success.status.code(), Some(0));
    assert_stdout_empty(&success);
    let failure = completed(&mut wrapped("/usr/bin/false", &[]), Duration::from_secs(2));
    assert_eq!(failure.status.code(), Some(1));
    assert_stdout_empty(&failure);
}

#[test]
fn confirmed_limit_has_dedicated_status() {
    if !backend_available() {
        return;
    }
    let mut invocation = Command::new(env!("CARGO_BIN_EXE_memcordon"));
    invocation.args([
        "run",
        "--enforcement",
        if cfg!(target_os = "macos") {
            "watchdog"
        } else {
            "hard"
        },
        "--memory",
        if cfg!(target_os = "macos") {
            "1B"
        } else {
            "32MiB"
        },
        "--",
        fixture(),
        "allocate",
        "--bytes",
        "64MiB",
        "--hold",
        "30s",
    ]);
    let output = completed(&mut invocation, Duration::from_secs(5));
    assert_eq!(output.status.code(), Some(124));
    assert_stdout_empty(&output);
}

#[test]
fn command_lifetime_kills_background_descendant_by_birth_identity() {
    if !backend_available() {
        return;
    }
    let pid_file = temporary_pid_file();
    let mut invocation = wrapped(fixture(), &["spawn-background", "--child-duration", "30s"]);
    invocation.arg("--pid-file").arg(&pid_file);
    let output = completed(&mut invocation, Duration::from_secs(3));
    assert_eq!(output.status.code(), Some(0));
    assert_stdout_empty(&output);
    let identity = read_identity(&pid_file);
    assert_process_gone(identity);
    fs::remove_file(pid_file).expect("temporary PID file should be removable");
}

#[cfg(unix)]
#[test]
fn wrapper_interrupt_is_forwarded_cleaned_and_mapped() {
    if !backend_available() {
        return;
    }
    let mut invocation = wrapped(fixture(), &["hold", "--duration", "30s"]);
    let output = run_with_deadline_after(&mut invocation, Duration::from_secs(3), |wrapper_pid| {
        thread::sleep(Duration::from_millis(100));
        let wrapper_pid = i32::try_from(wrapper_pid).map_err(io::Error::other)?;
        // SAFETY: this process id belongs to the wrapper just spawned by the test boundary.
        if unsafe { libc::kill(wrapper_pid, libc::SIGINT) } == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    })
    .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(output.status.code(), Some(130));
    assert_stdout_empty(&output);
}

#[cfg(target_os = "macos")]
#[test]
fn virtual_metric_is_explicitly_supported() {
    let mut invocation = Command::new(env!("CARGO_BIN_EXE_memcordon"));
    invocation.args([
        "run",
        "--enforcement",
        "watchdog",
        "--metric",
        "virtual",
        "--memory",
        "1TiB",
        "--",
        "/usr/bin/true",
    ]);
    let output = completed(&mut invocation, Duration::from_secs(2));
    assert_eq!(output.status.code(), Some(0));
    assert_stdout_empty(&output);
}

#[cfg(unix)]
#[test]
fn guardian_kills_workload_after_wrapper_crash() {
    if !backend_available() {
        return;
    }
    let pid_file = temporary_pid_file();
    let callback_pid_file = pid_file.clone();
    let mut invocation = wrapped(fixture(), &["hold", "--duration", "30s"]);
    invocation.arg("--pid-file").arg(&pid_file);
    let output = run_with_deadline_after(
        &mut invocation,
        Duration::from_secs(3),
        move |wrapper_pid| {
            let child_identity = read_identity(&callback_pid_file);
            let wrapper_pid = i32::try_from(wrapper_pid).map_err(io::Error::other)?;
            // SAFETY: this process id belongs to the wrapper just spawned by the test boundary.
            if unsafe { libc::kill(wrapper_pid, libc::SIGKILL) } == -1 {
                return Err(io::Error::last_os_error());
            }
            assert_process_gone(child_identity);
            Ok(())
        },
    )
    .unwrap_or_else(|error| panic!("{error}"));
    assert!(output.status.code().is_none());
    fs::remove_file(pid_file).expect("temporary PID file should be removable");
}
