//! Rebuilt with rustc before any native compiled-target cache is restored.
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[path = "ci-build-environment.rs"]
mod environment;

fn capture(program: &str, arguments: &[&str]) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_secs(15);
    let program = program.to_owned();
    let arguments: Vec<String> = arguments.iter().map(|value| (*value).to_owned()).collect();
    let environment = environment::closed_environment(&std::env::vars_os().collect())?;
    let (sender, receiver) = mpsc::sync_channel(0);
    std::thread::spawn(move || {
        let result = Command::new(program)
            .args(arguments)
            .env_clear()
            .envs(environment)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();
        if let Err(mpsc::SendError(Ok(mut child))) = sender.send(result) {
            let _ = child.kill();
            let _ = child.wait();
        }
    });
    let mut child = receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(io::Error::other)??;
    let mut stream = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("missing output"))?;
    let (sender, receiver) = mpsc::sync_channel(0);
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stream
            .by_ref()
            .take(1_048_577)
            .read_to_end(&mut bytes)
            .map(|_| bytes);
        let _ = sender.send(result);
    });
    loop {
        if Instant::now() >= deadline {
            let _ = child.kill();
            return Err(io::Error::other("native fingerprint command timeout"));
        }
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                return Err(io::Error::other("native fingerprint command failed"));
            }
            let bytes = receiver
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .map_err(io::Error::other)??;
            if bytes.len() > 1_048_576 {
                return Err(io::Error::other("native fingerprint output exceeds bound"));
            }
            return Ok(bytes);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn run() -> io::Result<()> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.len() != 2 || arguments[0] != "--output" {
        return Err(io::Error::other(
            "usage: ci-native-fingerprint --output PATH",
        ));
    }
    let root = std::env::current_dir()?.canonicalize()?;
    let path = root.join(&arguments[1]);
    let env = environment::closed_environment(&std::env::vars_os().collect())?;
    let home = env
        .get(std::ffi::OsStr::new(if cfg!(windows) {
            "USERPROFILE"
        } else {
            "HOME"
        }))
        .ok_or_else(|| io::Error::other("managed home missing"))?;
    environment::reject_cargo_configuration(&root, &Path::new(home).join(".cargo"))?;
    let cargo_home = root.join("target/ci/source-home");
    environment::reject_cargo_configuration(&root, &cargo_home)?;
    let work = root.join("target/ci/control-work");
    fs::create_dir_all(&work)?;
    fs::create_dir_all(&cargo_home)?;
    let rustup = environment::resolve_tool(std::ffi::OsStr::new("rustup"), &env)?;
    let job = std::env::var("GITHUB_JOB").unwrap_or_default();
    if job.contains("miri") || job.contains("fuzz") {
        let policy = fs::read_to_string(root.join("ci/toolchains.toml"))?;
        let nightly = policy
            .lines()
            .find_map(|line| {
                line.strip_prefix("miri = \"")
                    .and_then(|value| value.strip_suffix('"'))
            })
            .ok_or_else(|| io::Error::other("pinned nightly policy missing"))?;
        let mut install = Command::new(&rustup);
        install
            .args([
                "toolchain",
                "install",
                nightly,
                "--profile",
                "minimal",
                "--component",
                "miri",
                "--component",
                "rust-src",
            ])
            .env_clear()
            .envs(&env);
        run_bounded(&mut install)?;
        if job.contains("miri") {
            let mut setup = Command::new(&rustup);
            setup
                .args(["run", nightly, "cargo", "miri", "setup"])
                .current_dir(&work)
                .env_clear()
                .envs(&env)
                .env("CARGO_HOME", &cargo_home);
            run_bounded(&mut setup)?;
        }
    }
    let cargo_path = capture(
        rustup
            .to_str()
            .ok_or_else(|| io::Error::other("non-Unicode rustup path"))?,
        &["which", "--toolchain", "1.97.1", "cargo"],
    )?;
    let cargo = std::path::PathBuf::from(
        String::from_utf8(cargo_path)
            .map_err(io::Error::other)?
            .trim(),
    );
    let bin = cargo
        .parent()
        .ok_or_else(|| io::Error::other("invalid Cargo path"))?;
    let mut fetch = Command::new(&cargo);
    fetch
        .args(["fetch", "--locked", "--manifest-path"])
        .arg(root.join("Cargo.toml"))
        .current_dir(&work)
        .env_clear()
        .envs(&env)
        .env("CARGO_HOME", &cargo_home)
        .env(
            "RUSTC",
            bin.join(if cfg!(windows) { "rustc.exe" } else { "rustc" }),
        );
    run_bounded(&mut fetch)?;
    if job.contains("fuzz") {
        let mut fetch = Command::new(&cargo);
        fetch
            .args(["fetch", "--locked", "--manifest-path"])
            .arg(root.join("fuzz/Cargo.toml"))
            .current_dir(&work)
            .env_clear()
            .envs(&env)
            .env("CARGO_HOME", &cargo_home)
            .env(
                "RUSTC",
                bin.join(if cfg!(windows) { "rustc.exe" } else { "rustc" }),
            );
        run_bounded(&mut fetch)?;
    }
    let mut build = Command::new(&cargo);
    build
        .args(["build", "--locked", "--offline", "--manifest-path"])
        .arg(root.join("Cargo.toml"))
        .args(["--target-dir"])
        .arg(root.join("target/ci/control-bootstrap"))
        .args(["--package", "memcordon-ci"])
        .current_dir(&work)
        .env_clear()
        .envs(&env)
        .env("CARGO_HOME", &cargo_home)
        .env(
            "RUSTC",
            bin.join(if cfg!(windows) { "rustc.exe" } else { "rustc" }),
        )
        .env(
            "RUSTDOC",
            bin.join(if cfg!(windows) {
                "rustdoc.exe"
            } else {
                "rustdoc"
            }),
        );
    run_bounded(&mut build)?;
    // Auxiliary packages have their own published lockfiles. Acquire and build
    // them before measuring source trees, so later compilation cannot introduce
    // an unmeasured resolver or toolchain input into a shared cache identity.
    let tool_policy = fs::read_to_string(root.join("ci/tools.toml"))?;
    let selected: &[(&str, &str)] = if job.contains("fuzz") {
        &[("cargo_fuzz", "cargo-fuzz")]
    } else if job.contains("supply") || job.contains("preflight") {
        &[("cargo_audit", "cargo-audit"), ("cargo_deny", "cargo-deny")]
    } else {
        &[]
    };
    for (key, package) in selected {
        let version = tool_policy
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once('=')?;
                (name.trim() == *key)
                    .then(|| {
                        value
                            .trim()
                            .strip_prefix('"')
                            .and_then(|value| value.strip_suffix('"'))
                    })
                    .flatten()
            })
            .ok_or_else(|| io::Error::other("pinned auxiliary tool policy missing"))?;
        let mut install = Command::new(&cargo);
        install
            .args([
                "install",
                package,
                "--locked",
                "--version",
                version,
                "--root",
            ])
            .arg(root.join("target/ci-tools"))
            .arg("--target-dir")
            .arg(root.join("target/ci-tools/build"))
            .current_dir(&work)
            .env_clear()
            .envs(&env)
            .env("CARGO_HOME", &cargo_home)
            .env(
                "RUSTC",
                bin.join(if cfg!(windows) { "rustc.exe" } else { "rustc" }),
            );
        run_bounded(&mut install)?;
    }
    let controller = root
        .join("target/ci/control-bootstrap/debug")
        .join(if cfg!(windows) {
            "memcordon-ci.exe"
        } else {
            "memcordon-ci"
        });
    let mut plan = Command::new(controller);
    plan.args(["build-context", "--output"])
        .arg(path)
        .current_dir(&root)
        .env_clear()
        .envs(env);
    for key in [
        "GITHUB_JOB",
        "GITHUB_WORKFLOW",
        "GITHUB_SHA",
        "RUNNER_OS",
        "RUNNER_ARCH",
        "ImageOS",
        "ImageVersion",
    ] {
        if let Some(value) = std::env::var_os(key) {
            plan.env(key, value);
        }
    }
    run_bounded(&mut plan)
}

fn run_bounded(command: &mut Command) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(1800);
    let mut child = command.spawn()?;
    loop {
        if let Some(status) = child.try_wait()? {
            return if status.success() {
                Ok(())
            } else {
                Err(io::Error::other("managed bootstrap command failed"))
            };
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            return Err(io::Error::other("managed bootstrap deadline exceeded"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("native fingerprint: {error}");
        std::process::exit(1);
    }
}
