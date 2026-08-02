use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::thread;
use std::time::Duration;

use memcordon_core::ByteSize;

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("memcordon-test-fixture: {}", message.as_ref());
    std::process::exit(2);
}

fn take_value(args: &mut impl Iterator<Item = OsString>, option: &str) -> OsString {
    args.next()
        .unwrap_or_else(|| fail(format!("{option} requires a value")))
}

fn parse_duration(value: &OsStr) -> Duration {
    let value = value
        .to_str()
        .unwrap_or_else(|| fail("duration must be valid UTF-8"));
    let (number, multiplier) = if let Some(number) = value.strip_suffix("ms") {
        (number, 1_u64)
    } else if let Some(number) = value.strip_suffix('s') {
        (number, 1_000)
    } else if let Some(number) = value.strip_suffix('m') {
        (number, 60_000)
    } else {
        fail("duration must end in ms, s, or m")
    };
    let amount = number
        .parse::<u64>()
        .unwrap_or_else(|_| fail("duration must contain an unsigned integer"));
    Duration::from_millis(
        amount
            .checked_mul(multiplier)
            .unwrap_or_else(|| fail("duration is too large")),
    )
}

fn assert_native_containment(mut args: impl Iterator<Item = OsString>) {
    let mut memory = None;
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--memory") => {
                memory = Some(
                    take_value(&mut args, "--memory")
                        .to_str()
                        .and_then(|text| ByteSize::from_str(text).ok())
                        .unwrap_or_else(|| fail("invalid containment memory size"))
                        .bytes(),
                )
            }
            _ => fail("unexpected containment argument"),
        }
    }
    memcordon_platform::test_support::assert_native_containment(
        memory.unwrap_or_else(|| fail("assert-native-containment requires --memory")),
    )
    .unwrap_or_else(|error| fail(error.to_string()));
}

fn write_pid(path: Option<&Path>) {
    if let Some(path) = path {
        let identity = memcordon_platform::test_support::ProcessIdentity::current()
            .unwrap_or_else(|error| fail(format!("cannot observe process identity: {error}")));
        let mut bytes = format!("{} {}", identity.pid, identity.birth).into_bytes();
        bytes.push(b'\n');
        fs::write(path, bytes)
            .unwrap_or_else(|error| fail(format!("cannot write PID file: {error}")));
    }
}

fn touch_allocation(bytes: u64) -> Vec<u8> {
    let length = usize::try_from(bytes).unwrap_or_else(|_| fail("allocation does not fit usize"));
    let mut memory = vec![0_u8; length];
    for byte in memory.iter_mut().step_by(4096) {
        *byte = 1;
    }
    memory
}

fn parse_pid_and_duration(
    mut args: impl Iterator<Item = OsString>,
) -> (Option<PathBuf>, Option<Duration>) {
    let mut pid_file = None;
    let mut duration = None;
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--pid-file") => {
                pid_file = Some(PathBuf::from(take_value(&mut args, "--pid-file")))
            }
            Some("--duration") | Some("--hold") => {
                duration = Some(parse_duration(&take_value(&mut args, "--duration")))
            }
            _ => fail("unexpected fixture argument"),
        }
    }
    (pid_file, duration)
}

fn hold(args: impl Iterator<Item = OsString>) {
    let (pid_file, duration) = parse_pid_and_duration(args);
    write_pid(pid_file.as_deref());
    thread::sleep(duration.unwrap_or(Duration::from_secs(30)));
}

fn exit_fixture(mut args: impl Iterator<Item = OsString>) -> i32 {
    let mut code = None;
    let mut pid_file = None;
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--code") => {
                let value = take_value(&mut args, "--code");
                let parsed = value
                    .to_str()
                    .and_then(|text| text.parse::<u8>().ok())
                    .unwrap_or_else(|| fail("exit code must be in 0..=255"));
                code = Some(i32::from(parsed));
            }
            Some("--pid-file") => {
                pid_file = Some(PathBuf::from(take_value(&mut args, "--pid-file")))
            }
            _ => fail("unexpected exit argument"),
        }
    }
    write_pid(pid_file.as_deref());
    code.unwrap_or_else(|| fail("exit requires --code"))
}

fn allocate(mut args: impl Iterator<Item = OsString>, release_before_hold: bool) {
    let mut bytes = None;
    let mut duration = None;
    let mut pid_file = None;
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--bytes") => {
                let value = take_value(&mut args, "--bytes");
                bytes = Some(
                    value
                        .to_str()
                        .and_then(|text| ByteSize::from_str(text).ok())
                        .unwrap_or_else(|| fail("invalid byte size"))
                        .bytes(),
                );
            }
            Some("--hold") => duration = Some(parse_duration(&take_value(&mut args, "--hold"))),
            Some("--pid-file") => {
                pid_file = Some(PathBuf::from(take_value(&mut args, "--pid-file")))
            }
            _ => fail("unexpected allocation argument"),
        }
    }
    write_pid(pid_file.as_deref());
    let memory = touch_allocation(bytes.unwrap_or_else(|| fail("allocation requires --bytes")));
    if release_before_hold {
        drop(memory);
        thread::yield_now();
        thread::sleep(duration.unwrap_or(Duration::from_secs(30)));
    } else {
        thread::sleep(duration.unwrap_or(Duration::from_secs(30)));
        drop(memory);
    }
}

#[allow(clippy::zombie_processes)]
fn spawn_background(mut args: impl Iterator<Item = OsString>) {
    let mut duration = None;
    let mut pid_file = None;
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--child-duration") => duration = Some(take_value(&mut args, "--child-duration")),
            Some("--pid-file") => {
                pid_file = Some(PathBuf::from(take_value(&mut args, "--pid-file")))
            }
            _ => fail("unexpected spawn-background argument"),
        }
    }
    let executable = std::env::current_exe().unwrap_or_else(|error| fail(error.to_string()));
    let mut command = Command::new(executable);
    command
        .arg("hold")
        .arg("--duration")
        .arg(duration.unwrap_or_else(|| OsString::from("30s")))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Deliberately do not wait: this fixture tests whether MemCordon owns and cleans a
    // descendant after its direct child exits. The outer test session remains the safety net.
    let child = command
        .spawn()
        .unwrap_or_else(|error| fail(format!("background child failed to spawn: {error}")));
    let path = pid_file.unwrap_or_else(|| fail("spawn-background requires --pid-file"));
    let identity = memcordon_platform::test_support::ProcessIdentity::for_pid(child.id())
        .unwrap_or_else(|error| fail(format!("cannot observe child identity: {error}")));
    let mut bytes = format!("{} {}", identity.pid, identity.birth).into_bytes();
    bytes.push(b'\n');
    fs::write(path, bytes).unwrap_or_else(|error| fail(error.to_string()));
}

#[allow(clippy::zombie_processes)]
fn fork_continually(mut args: impl Iterator<Item = OsString>) {
    let mut pid_file = None;
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--pid-file") => {
                pid_file = Some(PathBuf::from(take_value(&mut args, "--pid-file")))
            }
            _ => fail("unexpected fork-continually argument"),
        }
    }
    let path = pid_file.unwrap_or_else(|| fail("fork-continually requires --pid-file"));
    let executable = std::env::current_exe().unwrap_or_else(|error| fail(error.to_string()));
    loop {
        let child = Command::new(&executable)
            .args(["hold", "--duration", "30s"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|error| fail(format!("continual child failed to spawn: {error}")));
        let identity = memcordon_platform::test_support::ProcessIdentity::for_pid(child.id())
            .unwrap_or_else(|error| fail(format!("cannot observe child identity: {error}")));
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap_or_else(|error| fail(format!("cannot append child identity: {error}")));
        writeln!(file, "{} {}", identity.pid, identity.birth)
            .unwrap_or_else(|error| fail(format!("cannot record child identity: {error}")));
        thread::sleep(Duration::from_millis(5));
    }
}

fn spawn_tree(mut args: impl Iterator<Item = OsString>) {
    let mut depth = None;
    let mut breadth = None;
    let mut leaf_mode = None;
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--depth") => {
                depth = take_value(&mut args, "--depth")
                    .to_str()
                    .and_then(|v| v.parse().ok())
            }
            Some("--breadth") => {
                breadth = take_value(&mut args, "--breadth")
                    .to_str()
                    .and_then(|v| v.parse().ok())
            }
            Some("--leaf-mode") => {
                leaf_mode = take_value(&mut args, "--leaf-mode")
                    .to_str()
                    .map(str::to_owned)
            }
            _ => fail("unexpected spawn-tree argument"),
        }
    }
    let depth: u32 = depth.unwrap_or_else(|| fail("spawn-tree requires --depth"));
    let breadth: u32 = breadth.unwrap_or_else(|| fail("spawn-tree requires --breadth"));
    let mode = leaf_mode.unwrap_or_else(|| fail("spawn-tree requires --leaf-mode"));
    if mode != "hold" && mode != "allocate" {
        fail("leaf mode must be hold or allocate");
    }
    let executable = std::env::current_exe().unwrap_or_else(|error| fail(error.to_string()));
    let mut children: Vec<Child> = Vec::new();
    for _ in 0..breadth {
        let mut command = Command::new(&executable);
        if depth == 0 {
            if mode == "allocate" {
                command.args(["allocate", "--bytes", "16MiB", "--hold", "30s"]);
            } else {
                command.args(["hold", "--duration", "30s"]);
            }
        } else {
            command
                .arg("spawn-tree")
                .arg("--depth")
                .arg((depth - 1).to_string())
                .arg("--breadth")
                .arg(breadth.to_string())
                .arg("--leaf-mode")
                .arg(&mode);
        }
        children.push(
            command
                .spawn()
                .unwrap_or_else(|error| fail(error.to_string())),
        );
    }
    thread::sleep(Duration::from_secs(30));
    for mut child in children {
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[cfg(windows)]
fn attempt_job_breakaway() {
    use std::os::windows::process::CommandExt;

    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
    let executable = std::env::current_exe().unwrap_or_else(|error| fail(error.to_string()));
    let result = Command::new(executable)
        .args(["exit", "--code", "0"])
        .creation_flags(CREATE_BREAKAWAY_FROM_JOB)
        .status();
    if let Ok(status) = result {
        fail(format!(
            "Job Object unexpectedly allowed breakaway child with status {status}"
        ));
    }
}

#[cfg(not(windows))]
fn attempt_job_breakaway() {
    fail("Job Object breakaway fixture is only available on Windows");
}

#[cfg(unix)]
fn new_session_and_hold() {
    // SAFETY: setsid has no Rust memory-safety preconditions for the current process.
    if unsafe { libc::setsid() } == -1 {
        fail(io::Error::last_os_error().to_string());
    }
    thread::sleep(Duration::from_secs(30));
}

#[cfg(not(unix))]
fn new_session_and_hold() {
    fail("new-session-and-hold is Unix-only");
}

fn main() {
    let mut args = std::env::args_os();
    let _program = args.next();
    let command = args
        .next()
        .and_then(|value| value.to_str().map(str::to_owned))
        .unwrap_or_else(|| fail("a fixture subcommand is required"));
    let status = match command.as_str() {
        "exit" => exit_fixture(args),
        "hold" | "wait-for-signal" => {
            hold(args);
            0
        }
        "spin" => {
            let (pid_file, _) = parse_pid_and_duration(args);
            write_pid(pid_file.as_deref());
            loop {
                std::hint::spin_loop();
            }
        }
        "allocate" => {
            allocate(args, false);
            0
        }
        "burst" => {
            allocate(args, true);
            0
        }
        "spawn-background" => {
            spawn_background(args);
            0
        }
        "fork-continually" => {
            fork_continually(args);
            0
        }
        "monitor-failure" => {
            hold(args);
            0
        }
        "spawn-tree" => {
            spawn_tree(args);
            0
        }
        "print-pid-and-hold" => {
            println!("{}", std::process::id());
            io::stdout()
                .flush()
                .unwrap_or_else(|error| fail(error.to_string()));
            hold(args);
            0
        }
        "new-session-and-hold" => {
            new_session_and_hold();
            0
        }
        "assert-native-containment" => {
            assert_native_containment(args);
            0
        }
        "attempt-job-breakaway" => {
            attempt_job_breakaway();
            0
        }
        _ => fail("unknown fixture subcommand"),
    };
    std::process::exit(status);
}
