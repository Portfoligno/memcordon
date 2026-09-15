//! Fixture io handlers; invoked only through the command registry.
use super::*;

pub(super) fn record_argv(mut args: impl Iterator<Item = OsString>) {
    let output = PathBuf::from(take_value(&mut args, "record-argv output path"));
    let arguments: Vec<NativeArgument> = args
        .map(|argument| NativeArgument::from_os(&argument))
        .collect();
    let mut bytes = serde_json::to_vec_pretty(&arguments)
        .unwrap_or_else(|error| fail(format!("cannot serialize argv: {error}")));
    bytes.push(b'\n');
    fs::write(output, bytes).unwrap_or_else(|error| fail(format!("cannot write argv: {error}")));
}

pub(super) fn assert_no_memcordon_environment(args: impl Iterator<Item = OsString>) {
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

pub(super) fn gate_marker(mut args: impl Iterator<Item = OsString>) {
    let path = PathBuf::from(take_value(&mut args, "gate-marker path"));
    if args.next().is_some() {
        fail("gate-marker accepts exactly one path");
    }
    fs::write(path, b"target-executed\n")
        .unwrap_or_else(|error| fail(format!("cannot write gate marker: {error}")));
}

pub(super) fn gate_wait(mut args: impl Iterator<Item = OsString>) {
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

pub(super) fn gate_failure(mut args: impl Iterator<Item = OsString>) {
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

pub(super) fn command_record_argv(args: std::env::ArgsOs) -> i32 {
    {
        record_argv(args);
        0
    }
}

pub(super) fn command_assert_no_memcordon_environment(args: std::env::ArgsOs) -> i32 {
    {
        assert_no_memcordon_environment(args);
        0
    }
}

pub(super) fn command_gate_marker(args: std::env::ArgsOs) -> i32 {
    {
        gate_marker(args);
        0
    }
}

pub(super) fn command_gate_wait(args: std::env::ArgsOs) -> i32 {
    {
        gate_wait(args);
        0
    }
}

pub(super) fn command_gate_failure(args: std::env::ArgsOs) -> i32 {
    {
        gate_failure(args);
        0
    }
}
