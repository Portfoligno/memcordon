use memcordon_core::{ByteSize, NativeArgument};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self as std_io, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};

mod io;
#[cfg(target_os = "macos")]
mod macos;
mod memory;
mod network;
mod process;
mod registry;
mod windows;

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

fn write_pid(path: Option<&Path>) {
    if let Some(path) = path {
        let identity = memcordon_platform::test_support::ProcessIdentity::current()
            .unwrap_or_else(|error| fail(format!("cannot observe process identity: {error}")));
        identity
            .publish_to(path)
            .unwrap_or_else(|error| fail(format!("cannot write PID file: {error}")));
    }
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

fn main() {
    let mut args = std::env::args_os();
    let _program = args.next();
    let command = args
        .next()
        .and_then(|value| value.to_str().map(str::to_owned))
        .unwrap_or_else(|| fail("a fixture subcommand is required"));
    if command == "--fixture-inventory-json" {
        if args.next().is_some() {
            fail("fixture inventory accepts no arguments");
        }
        println!(
            "{}",
            serde_json::to_string(registry::COMMANDS).expect("fixture inventory serializes")
        );
        return;
    }
    let command = registry::COMMANDS
        .iter()
        .find(|entry| entry.name == command)
        .unwrap_or_else(|| fail("unknown fixture subcommand"));
    std::process::exit((command.handler)(args));
}
