//! Deterministic native fixtures used by the oracle integration tests.
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use super::inventory::{NativeProcessApi, ProcessApi};

pub(super) fn run(arguments: &[OsString]) -> super::Result<()> {
    let (mode, rest) = arguments
        .split_first()
        .ok_or("native fixture mode missing")?;
    if mode == "sleep" {
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    let path = Path::new(rest.first().ok_or("native fixture output missing")?);
    if mode == "echo" {
        let own = NativeProcessApi
            .observation(unsafe { libc::getpid() })?
            .ok_or("native fixture identity absent")?;
        let argv: Vec<Vec<u8>> = rest
            .iter()
            .skip(1)
            .map(|argument| argument.as_bytes().to_vec())
            .collect();
        return super::marker::write_json_atomic(
            path,
            &serde_json::json!({"observation":own,"arguments":argv}),
        );
    }
    if mode == "child" {
        let action = rest.get(1).ok_or("native child action missing")?;
        if action == "group" && unsafe { libc::setpgid(0, 0) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let own = NativeProcessApi
            .observation(unsafe { libc::getpid() })?
            .ok_or("native fixture identity absent")?;
        super::marker::write_json_atomic(path, &own)?;
        if action == "escape" {
            let trigger = path.with_extension("escape");
            while !trigger.exists() {
                std::thread::sleep(Duration::from_millis(5));
            }
            if unsafe { libc::setsid() } < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            super::marker::write_json_atomic(&path.with_extension("escaped"), &true)?;
        }
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    if mode == "children" {
        let count: usize = rest
            .get(1)
            .and_then(|argument| argument.to_str())
            .ok_or("native child count missing")?
            .parse()?;
        if !(1..=3).contains(&count) {
            return Err("native fixture only supports one to three children".into());
        }
        let mut children = Vec::new();
        for _ in 0..count {
            children.push(
                Command::new(std::env::current_exe()?)
                    .args(["--native-fixture", "sleep"])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()?,
            );
        }
        let pids: Vec<u32> = children.iter().map(std::process::Child::id).collect();
        super::marker::write_json_atomic(path, &pids)?;
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    if mode == "malformed-report" || mode == "missing-report" {
        let report = Path::new(rest.get(1).ok_or("report fixture path missing")?);
        let mut target = Command::new(std::env::current_exe()?)
            .args(["--fixture", "sleep"])
            .arg(path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        while !path.exists() {
            if target.try_wait()?.is_some() {
                return Err("report fixture target failed".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        std::thread::sleep(Duration::from_millis(100));
        if mode == "malformed-report" {
            std::fs::write(report, b"{malformed\n")?;
        }
        std::process::exit(123);
    }
    if mode == "leader-exit" || mode == "group" || mode == "escape" {
        let action = if mode == "leader-exit" {
            "sleep"
        } else {
            mode.to_str().ok_or("invalid native mode")?
        };
        let mut child = Command::new(std::env::current_exe()?)
            .args(["--native-fixture", "child"])
            .arg(path)
            .arg(action)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        while !path.exists() {
            if child.try_wait()?.is_some() {
                return Err("native child failed before marker".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        if mode == "leader-exit" {
            return Ok(());
        }
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    Err("unknown native fixture mode".into())
}
