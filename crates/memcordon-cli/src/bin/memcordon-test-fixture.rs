use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};

use memcordon_core::{ByteSize, NativeArgument};

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
    memcordon::parse_duration(value).unwrap_or_else(|error| fail(error))
}

fn assert_native_containment(mut args: impl Iterator<Item = OsString>) {
    let mut memory = None;
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--limit") => {
                memory = Some(
                    take_value(&mut args, "--limit")
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
        memory.unwrap_or_else(|| fail("assert-native-containment requires --limit")),
    )
    .unwrap_or_else(|error| fail(error.to_string()));
}

fn write_pid(path: Option<&Path>) {
    if let Some(path) = path {
        let identity = memcordon_platform::test_support::ProcessIdentity::current()
            .unwrap_or_else(|error| fail(format!("cannot observe process identity: {error}")));
        identity
            .publish_to(path)
            .unwrap_or_else(|error| fail(format!("cannot write PID file: {error}")));
    }
}

fn record_argv(mut args: impl Iterator<Item = OsString>) {
    let output = PathBuf::from(take_value(&mut args, "record-argv output path"));
    let arguments: Vec<NativeArgument> = args
        .map(|argument| NativeArgument::from_os(&argument))
        .collect();
    let mut bytes = serde_json::to_vec_pretty(&arguments)
        .unwrap_or_else(|error| fail(format!("cannot serialize argv: {error}")));
    bytes.push(b'\n');
    fs::write(output, bytes).unwrap_or_else(|error| fail(format!("cannot write argv: {error}")));
}

fn assert_no_memcordon_environment(args: impl Iterator<Item = OsString>) {
    if args.count() != 0 {
        fail("assert-no-memcordon-environment accepts no arguments");
    }
    if let Some((name, _)) = std::env::vars_os().find(|(name, _)| {
        name.to_string_lossy()
            .to_ascii_uppercase()
            .starts_with("MEMCORDON_")
    }) {
        fail(format!(
            "target inherited unexpected MemCordon environment key {}",
            name.to_string_lossy()
        ));
    }
}

fn tcp_loopback(mut args: impl Iterator<Item = OsString>) {
    use std::io::{Read, Write};
    let marker = PathBuf::from(take_value(&mut args, "TCP completion marker"));
    if args.next().is_some() {
        fail("tcp-loopback accepts one marker path");
    }
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .unwrap_or_else(|error| fail(error.to_string()));
    let address = listener.local_addr().unwrap();
    let worker = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        stream.write_all(&byte).unwrap();
    });
    let mut stream =
        std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"x").unwrap();
    let mut byte = [0];
    stream.read_exact(&mut byte).unwrap();
    assert_eq!(&byte, b"x");
    worker.join().unwrap();
    fs::write(marker, b"tcp-echo-complete\n").unwrap();
}

fn tcp_client(mut args: impl Iterator<Item = OsString>) {
    use std::io::{Read, Write};
    let port: u16 = take_value(&mut args, "TCP peer port")
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let marker = PathBuf::from(take_value(&mut args, "TCP completion marker"));
    if args.next().is_some() {
        fail("tcp-client accepts port and marker");
    }
    let address = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port));
    let mut stream =
        std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"x").unwrap();
    let mut byte = [0];
    stream.read_exact(&mut byte).unwrap();
    assert_eq!(&byte, b"x");
    fs::write(marker, b"tcp-echo-complete\n").unwrap();
}

fn gate_marker(mut args: impl Iterator<Item = OsString>) {
    let path = PathBuf::from(take_value(&mut args, "gate-marker path"));
    if args.next().is_some() {
        fail("gate-marker accepts exactly one path");
    }
    fs::write(path, b"target-executed\n")
        .unwrap_or_else(|error| fail(format!("cannot write gate marker: {error}")));
}

fn gate_wait(mut args: impl Iterator<Item = OsString>) {
    let ready = PathBuf::from(take_value(&mut args, "ready marker"));
    let finish = PathBuf::from(take_value(&mut args, "finish marker"));
    if args.next().is_some() {
        fail("gate-wait accepts ready and finish paths");
    }
    fs::write(ready, b"authorized\n").unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(90);
    while !finish.exists() {
        if std::time::Instant::now() >= deadline {
            fail("gate-wait deadline expired");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn gate_failure(mut args: impl Iterator<Item = OsString>) {
    let mut phase = None;
    let mut marker = None;
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--phase") => phase = Some(take_value(&mut args, "--phase")),
            Some("--marker") => marker = Some(PathBuf::from(take_value(&mut args, "--marker"))),
            _ => fail("unexpected gate-failure argument"),
        }
    }
    if phase.is_none() {
        fail("gate-failure requires --phase");
    }
    let marker = marker.unwrap_or_else(|| fail("gate-failure requires --marker"));
    fs::write(marker, b"target-executed\n")
        .unwrap_or_else(|error| fail(format!("cannot write gate-failure marker: {error}")));
}

fn touch_allocation(bytes: u64) -> Vec<u8> {
    let length = usize::try_from(bytes).unwrap_or_else(|_| fail("allocation does not fit usize"));
    let mut memory = vec![0_u8; length];
    for byte in memory.iter_mut().step_by(4096) {
        *byte = 1;
    }
    memory
}

fn parse_pid_duration_and_completion(
    mut args: impl Iterator<Item = OsString>,
) -> (Option<PathBuf>, Option<Duration>, Option<PathBuf>) {
    let mut pid_file = None;
    let mut duration = None;
    let mut completion_marker = None;
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--pid-file") => {
                pid_file = Some(PathBuf::from(take_value(&mut args, "--pid-file")))
            }
            Some("--duration") | Some("--hold") => {
                duration = Some(parse_duration(&take_value(&mut args, "--duration")))
            }
            Some("--completion-marker") => {
                completion_marker =
                    Some(PathBuf::from(take_value(&mut args, "--completion-marker")))
            }
            _ => fail("unexpected fixture argument"),
        }
    }
    (pid_file, duration, completion_marker)
}

fn hold(args: impl Iterator<Item = OsString>) {
    let (pid_file, duration, completion_marker) = parse_pid_duration_and_completion(args);
    write_pid(pid_file.as_deref());
    thread::sleep(duration.unwrap_or(Duration::from_secs(30)));
    if let Some(path) = completion_marker {
        fs::write(path, b"completed\n")
            .unwrap_or_else(|error| fail(format!("cannot write completion marker: {error}")));
    }
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
fn spawn_background(mut args: impl Iterator<Item = OsString>) -> i32 {
    let mut duration = None;
    let mut pid_file = None;
    let mut completion_marker = None;
    let mut exit_code = None;
    let mut exit_gate = None;
    let mut child_group_gate = None;
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--child-duration") => duration = Some(take_value(&mut args, "--child-duration")),
            Some("--pid-file") => {
                pid_file = Some(PathBuf::from(take_value(&mut args, "--pid-file")))
            }
            Some("--exit-gate") => {
                exit_gate = Some(PathBuf::from(take_value(&mut args, "--exit-gate")))
            }
            Some("--child-group-gate") => {
                child_group_gate = Some(PathBuf::from(take_value(&mut args, "--child-group-gate")))
            }
            Some("--completion-marker") => {
                completion_marker =
                    Some(PathBuf::from(take_value(&mut args, "--completion-marker")))
            }
            Some("--exit-code") => {
                let value = take_value(&mut args, "--exit-code");
                exit_code = Some(
                    value
                        .to_str()
                        .and_then(|value| value.parse::<u8>().ok())
                        .unwrap_or_else(|| fail("exit code must be in 0..=255")),
                )
            }
            _ => fail("unexpected spawn-background argument"),
        }
    }
    let executable = std::env::current_exe().unwrap_or_else(|error| fail(error.to_string()));
    let mut command = Command::new(executable);
    if let Some(gate) = child_group_gate {
        command.arg("macos-gated-group-change").arg(gate);
    } else {
        command
            .arg("hold")
            .arg("--duration")
            .arg(duration.unwrap_or_else(|| OsString::from("30s")));
    }
    command.stdout(Stdio::null()).stderr(Stdio::null());
    if let Some(path) = completion_marker {
        command.arg("--completion-marker").arg(path);
    }
    // Deliberately do not wait: this fixture tests whether MemCordon owns and cleans a
    // descendant after its direct child exits. The outer test session remains the safety net.
    let child = command
        .spawn()
        .unwrap_or_else(|error| fail(format!("background child failed to spawn: {error}")));
    let path = pid_file.unwrap_or_else(|| fail("spawn-background requires --pid-file"));
    let identity = memcordon_platform::test_support::ProcessIdentity::for_pid(child.id())
        .unwrap_or_else(|error| fail(format!("cannot observe child identity: {error}")));
    identity
        .publish_to(&path)
        .unwrap_or_else(|error| fail(format!("cannot write child PID file: {error}")));
    if let Some(gate) = exit_gate {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !gate.exists() {
            if Instant::now() >= deadline {
                fail("background root exit gate timed out");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    i32::from(exit_code.unwrap_or(0))
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
        #[cfg(target_os = "macos")]
        "__macos-guardian" => loop {
            std::thread::park();
        },
        #[cfg(target_os = "macos")]
        "macos-gated-group-change" => {
            let gate = PathBuf::from(take_value(&mut args, "group transition gate"));
            let deadline = Instant::now() + Duration::from_secs(10);
            while !gate.exists() {
                if Instant::now() >= deadline {
                    fail("group transition gate timed out");
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            // SAFETY: this disposable descendant deliberately changes its own session/group.
            if unsafe { libc::setsid() } < 0 {
                fail("descendant setsid failed");
            }
            std::fs::write(gate.with_extension("changed"), b"changed\n")
                .unwrap_or_else(|error| fail(error.to_string()));
            std::thread::sleep(Duration::from_secs(20));
            0
        }
        #[cfg(target_os = "macos")]
        "macos-custody-wrapper" => {
            let image = PathBuf::from(take_value(&mut args, "memcordon image"));
            let fixture = PathBuf::from(take_value(&mut args, "fixture image"));
            let pid_file = PathBuf::from(take_value(&mut args, "descendant marker"));
            let marker = PathBuf::from(take_value(&mut args, "guardian marker"));
            memcordon_platform::test_support::macos_custody_wrapper(
                &image, &fixture, &pid_file, &marker,
            )
            .unwrap_or_else(|error| fail(error));
            0
        }
        #[cfg(target_os = "macos")]
        "macos-closed-stdio" => {
            use std::os::unix::process::CommandExt;
            let program = take_value(&mut args, "native executable");
            // SAFETY: this disposable fixture process deliberately has closed standard streams.
            for descriptor in [0, 1, 2] {
                unsafe { libc::close(descriptor) };
            }
            let _ = Command::new(program).args(args).exec();
            126
        }
        "exit" => exit_fixture(args),
        "hold" | "wait-for-signal" => {
            hold(args);
            0
        }
        "spin" => {
            let (pid_file, _, _) = parse_pid_duration_and_completion(args);
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
        "spawn-background" => spawn_background(args),
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
        "record-argv" => {
            record_argv(args);
            0
        }
        "assert-no-memcordon-environment" => {
            assert_no_memcordon_environment(args);
            0
        }
        "gate-marker" => {
            gate_marker(args);
            0
        }
        "gate-wait" => {
            gate_wait(args);
            0
        }
        "tcp-loopback" => {
            tcp_loopback(args);
            0
        }
        "tcp-client" => {
            tcp_client(args);
            0
        }
        "gate-failure" => {
            gate_failure(args);
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
