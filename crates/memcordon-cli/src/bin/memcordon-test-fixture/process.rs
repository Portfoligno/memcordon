//! Fixture process handlers; invoked only through the command registry.
use super::*;

pub(super) fn assert_native_containment(mut args: impl Iterator<Item = OsString>) {
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

pub(super) fn hold(args: impl Iterator<Item = OsString>) {
    let (pid_file, duration, completion_marker) = parse_pid_duration_and_completion(args);
    write_pid(pid_file.as_deref());
    thread::sleep(duration.unwrap_or(Duration::from_secs(30)));
    if let Some(path) = completion_marker {
        fs::write(path, b"completed\n")
            .unwrap_or_else(|error| fail(format!("cannot write completion marker: {error}")));
    }
}

pub(super) fn exit_fixture(mut args: impl Iterator<Item = OsString>) -> i32 {
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

#[allow(clippy::zombie_processes)]
pub(super) fn spawn_background(mut args: impl Iterator<Item = OsString>) -> i32 {
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
pub(super) fn fork_continually(mut args: impl Iterator<Item = OsString>) {
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

pub(super) fn spawn_tree(mut args: impl Iterator<Item = OsString>) {
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

#[cfg(unix)]
pub(super) fn new_session_and_hold() {
    // SAFETY: setsid has no Rust memory-safety preconditions for the current process.
    if unsafe { libc::setsid() } == -1 {
        fail(std_io::Error::last_os_error().to_string());
    }
    thread::sleep(Duration::from_secs(30));
}

#[cfg(not(unix))]
pub(super) fn new_session_and_hold() {
    fail("new-session-and-hold is Unix-only");
}

pub(super) fn command_exit(args: std::env::ArgsOs) -> i32 {
    exit_fixture(args)
}

pub(super) fn command_hold(args: std::env::ArgsOs) -> i32 {
    {
        hold(args);
        0
    }
}

pub(super) fn command_spin(args: std::env::ArgsOs) -> i32 {
    {
        let (pid_file, _, _) = parse_pid_duration_and_completion(args);
        write_pid(pid_file.as_deref());
        loop {
            std::hint::spin_loop();
        }
    }
}

pub(super) fn command_spawn_background(args: std::env::ArgsOs) -> i32 {
    spawn_background(args)
}

pub(super) fn command_fork_continually(args: std::env::ArgsOs) -> i32 {
    {
        fork_continually(args);
        0
    }
}

pub(super) fn command_monitor_failure(args: std::env::ArgsOs) -> i32 {
    {
        hold(args);
        0
    }
}

pub(super) fn command_spawn_tree(args: std::env::ArgsOs) -> i32 {
    {
        spawn_tree(args);
        0
    }
}

pub(super) fn command_print_pid_and_hold(args: std::env::ArgsOs) -> i32 {
    {
        println!("{}", std::process::id());
        std_io::stdout()
            .flush()
            .unwrap_or_else(|error| fail(error.to_string()));
        hold(args);
        0
    }
}

pub(super) fn command_new_session_and_hold(_args: std::env::ArgsOs) -> i32 {
    {
        new_session_and_hold();
        0
    }
}

pub(super) fn command_assert_native_containment(args: std::env::ArgsOs) -> i32 {
    {
        assert_native_containment(args);
        0
    }
}
