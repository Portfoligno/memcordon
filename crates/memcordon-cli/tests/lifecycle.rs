#![cfg(target_os = "macos")]

use std::io::{BufRead, BufReader};
use std::process::Command;
use std::process::Stdio;
use std::thread;
use std::time::Duration;

use memcordon_testkit::{assert_stdout_empty, run_with_deadline};

fn wrapped(command: &str, args: &[&str]) -> Command {
    let mut invocation = Command::new(env!("CARGO_BIN_EXE_memcordon"));
    invocation.args([
        "run",
        "--enforcement",
        "watchdog",
        "--memory",
        "8GiB",
        "--",
        command,
    ]);
    invocation.args(args);
    invocation
}

#[test]
fn immediate_success_is_reaped_and_preserved() {
    let output = run_with_deadline(&mut wrapped("/usr/bin/true", &[]), Duration::from_secs(2));
    assert_eq!(output.status.code(), Some(0));
    assert_stdout_empty(&output);
}

#[test]
fn immediate_failure_is_reaped_and_preserved() {
    let output = run_with_deadline(&mut wrapped("/usr/bin/false", &[]), Duration::from_secs(2));
    assert_eq!(output.status.code(), Some(1));
    assert_stdout_empty(&output);
}

#[test]
fn arbitrary_exit_status_is_preserved() {
    let output = run_with_deadline(
        &mut wrapped("/bin/sh", &["-c", "exit 37"]),
        Duration::from_secs(2),
    );
    assert_eq!(output.status.code(), Some(37));
    assert_stdout_empty(&output);
}

#[test]
fn sampled_limit_has_dedicated_status() {
    let mut invocation = Command::new(env!("CARGO_BIN_EXE_memcordon"));
    invocation.args([
        "run",
        "--enforcement",
        "watchdog",
        "--memory",
        "1B",
        "--",
        "/bin/sh",
        "-c",
        "while :; do :; done",
    ]);
    let output = run_with_deadline(&mut invocation, Duration::from_secs(3));
    assert_eq!(output.status.code(), Some(124));
    assert_stdout_empty(&output);
}

#[test]
fn command_lifetime_kills_background_descendant() {
    let output = run_with_deadline(
        &mut wrapped("/bin/sh", &["-c", "sleep 30 & echo $!"]),
        Duration::from_secs(2),
    );
    assert_eq!(output.status.code(), Some(0));
    let pid: i32 = String::from_utf8(output.stdout)
        .expect("PID output should be UTF-8")
        .trim()
        .parse()
        .expect("child should print a PID");
    thread::sleep(Duration::from_millis(50));
    // SAFETY: signal zero performs a liveness/permission check and does not modify the process.
    let result = unsafe { libc::kill(pid, 0) };
    assert_eq!(result, -1, "background descendant {pid} survived cleanup");
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    );
}

#[test]
fn wrapper_interrupt_is_forwarded_cleaned_and_mapped() {
    let mut invocation = wrapped("/bin/sh", &["-c", "while :; do sleep 1; done"]);
    invocation.stdout(Stdio::piped()).stderr(Stdio::piped());
    let wrapper = invocation.spawn().expect("wrapper should spawn");
    thread::sleep(Duration::from_millis(100));
    let wrapper_pid = i32::try_from(wrapper.id()).expect("wrapper PID should fit i32");
    // SAFETY: the PID belongs to the wrapper spawned above and SIGINT is a valid signal.
    assert_eq!(unsafe { libc::kill(wrapper_pid, libc::SIGINT) }, 0);
    let output = wrapper
        .wait_with_output()
        .expect("interrupted wrapper should be waitable");
    assert_eq!(output.status.code(), Some(130));
    assert_stdout_empty(&output);
}

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
    let output = run_with_deadline(&mut invocation, Duration::from_secs(2));
    assert_eq!(output.status.code(), Some(0));
    assert_stdout_empty(&output);
}

#[test]
fn guardian_kills_workload_after_wrapper_crash() {
    let mut invocation = wrapped("/bin/sh", &["-c", "echo $$; while :; do sleep 1; done"]);
    invocation.stdout(Stdio::piped()).stderr(Stdio::null());
    let mut wrapper = invocation.spawn().expect("wrapper should spawn");
    let stdout = wrapper
        .stdout
        .take()
        .expect("wrapper stdout should be piped");
    let mut line = String::new();
    BufReader::new(stdout)
        .read_line(&mut line)
        .expect("child should print its PID");
    let child_pid: i32 = line.trim().parse().expect("child PID should parse");
    let wrapper_pid = i32::try_from(wrapper.id()).expect("wrapper PID should fit i32");
    // SAFETY: both PIDs belong to processes created by this test.
    assert_eq!(unsafe { libc::kill(wrapper_pid, libc::SIGKILL) }, 0);
    wrapper.wait().expect("crashed wrapper should be reapable");
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        // SAFETY: signal zero only checks whether the child still exists.
        if unsafe { libc::kill(child_pid, 0) } == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "guardian did not kill child {child_pid}"
        );
        thread::sleep(Duration::from_millis(10));
    }
}
