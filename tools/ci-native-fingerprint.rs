//! Rebuilt with rustc before any native compiled-target cache is restored.
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub const CONTROL_PROFILE: &str = "ci-bootstrap";
pub const PREPARATION_PROFILES: &[&str] = &[
    "stable",
    "msrv",
    "miri",
    "fuzz",
    "supply-chain",
    "release-preflight",
];

pub fn parse_preparation_arguments(arguments: &[OsString]) -> io::Result<(&str, &Path, bool)> {
    if !matches!(arguments.len(), 4 | 6)
        || arguments[0] != "--profile"
        || arguments[2] != "--output"
        || arguments[3].is_empty()
        || arguments[3]
            .to_str()
            .is_some_and(|value| value.starts_with("--"))
    {
        return Err(io::Error::other(
            "usage: ci-native-fingerprint --profile PROFILE --output PATH [--trace-inventory true|false]",
        ));
    }
    let profile = arguments[1]
        .to_str()
        .filter(|profile| PREPARATION_PROFILES.contains(profile))
        .ok_or_else(|| io::Error::other("unknown preparation profile"))?;
    let trace_inventory = if arguments.len() == 6 {
        if arguments[4] != "--trace-inventory" {
            return Err(io::Error::other("unknown native fingerprint option"));
        }
        match arguments[5].to_str() {
            Some("true") => true,
            Some("false") => false,
            _ => return Err(io::Error::other("trace-inventory must be true or false")),
        }
    } else {
        false
    };
    if trace_inventory && !cfg!(windows) {
        return Err(io::Error::other("inventory tracing requires Windows"));
    }
    Ok((profile, Path::new(&arguments[3]), trace_inventory))
}

pub fn promote_tool(staging: &Path, destination: &Path, expected_digest: &str) -> io::Result<()> {
    if !fs::symlink_metadata(staging)?.file_type().is_file() {
        return Err(io::Error::other("staged tool must be a regular executable"));
    }
    if bounded::sha256::digest(&mut fs::File::open(staging)?)? != expected_digest {
        return Err(io::Error::other("staged tool changed before promotion"));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| io::Error::other("tool destination lacks parent"))?;
    fs::create_dir_all(parent)?;
    let temporary = destination.with_extension("promoting");
    fs::copy(staging, &temporary)?;
    if bounded::sha256::digest(&mut fs::File::open(&temporary)?)? != expected_digest {
        return Err(io::Error::other("tool promotion changed executable bytes"));
    }
    if destination.exists() {
        fs::remove_file(destination)?;
    }
    fs::rename(temporary, destination)
}

#[path = "ci-build-environment.rs"]
mod environment;

#[path = "ci-bounded-command.rs"]
mod bounded;

#[cfg(windows)]
#[path = "ci-inventory-trace.rs"]
mod inventory_trace;

pub fn capture(
    program: &str,
    arguments: &[&str],
    environment: &BTreeMap<OsString, OsString>,
) -> io::Result<Vec<u8>> {
    capture_with_budget(program, arguments, environment, Duration::from_secs(15))
}

fn capture_with_budget(
    program: &str,
    arguments: &[&str],
    environment: &BTreeMap<OsString, OsString>,
    budget: Duration,
) -> io::Result<Vec<u8>> {
    let description = format!("program={program:?} arguments={arguments:?}");
    let deadline = Instant::now() + budget;
    let program = program.to_owned();
    let arguments: Vec<String> = arguments.iter().map(|value| (*value).to_owned()).collect();
    let environment = environment.clone();
    let (sender, receiver) = mpsc::sync_channel(0);
    std::thread::spawn(move || {
        let result = Command::new(program)
            .args(arguments)
            .env_clear()
            .envs(environment)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
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
            return Err(io::Error::other(format!(
                "native fingerprint command timeout: {description}"
            )));
        }
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                return Err(io::Error::other(format!(
                    "native fingerprint command failed: {description}, status={status}"
                )));
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

#[cfg(windows)]
fn configure_recording_environment(
    command: &mut Command,
    environment: &BTreeMap<OsString, OsString>,
    temporary: Option<&Path>,
) {
    command.env_clear().envs(environment);
    if let Some(directory) = temporary {
        command.env("TEMP", directory).env("TMP", directory);
    }
}

fn run() -> io::Result<()> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    #[cfg(windows)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "--internal-trace-volume-qualification")
    {
        if arguments.len() != 3 {
            return Err(io::Error::other(
                "invalid volume qualification worker arguments",
            ));
        }
        return inventory_trace::qualify_volume_worker(
            Path::new(&arguments[1]),
            Path::new(&arguments[2]),
            configure_recording_environment,
        );
    }
    #[cfg(windows)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "--qualify-trace-volume")
    {
        if arguments.len() != 1 {
            return Err(io::Error::other(
                "volume qualification takes no extra arguments",
            ));
        }
        let root = environment::command_path(&std::env::current_dir()?)?;
        let journal =
            bounded::Journal::create(&root.join("target/ci/reports/inventory-observation/v1"))?;
        let env = environment::closed_environment(&std::env::vars_os().collect())?;
        return inventory_trace::qualify_volume(
            &root,
            journal.directory(),
            &env,
            configure_recording_environment,
        );
    }
    #[cfg(windows)]
    if arguments
        .first()
        .is_some_and(|argument| argument == "--internal-inventory-trace-worker")
    {
        if arguments.len() != 4 {
            return Err(io::Error::other("invalid recorder worker arguments"));
        }
        return inventory_trace::worker(
            Path::new(&arguments[1]),
            Path::new(&arguments[2]),
            &arguments[3],
            configure_recording_environment,
        );
    }
    let (profile, output, trace_inventory) = parse_preparation_arguments(&arguments)?;
    #[cfg(not(windows))]
    let _ = trace_inventory;
    let root = environment::command_path(&std::env::current_dir()?)?;
    let path = root.join(output);
    bounded::revoke(&path)?;
    let mut journal =
        bounded::Journal::create(&root.join("target/ci/reports/inventory-observation/v1"))?;
    let candidate = journal.directory().join("candidate-context.json");
    let ambient = std::env::vars_os().collect();
    let env = environment::closed_environment(&ambient)?;
    #[cfg(windows)]
    let env = {
        let mut env = env;
        let arch = environment::msvc::Architecture::native()?;
        let discovery = environment::windows_discovery_environment(&ambient)?;
        environment::windows_compiler::configure(
            &mut env,
            &discovery,
            arch,
            |query, arguments, discovery| {
                capture(
                    query
                        .to_str()
                        .ok_or_else(|| io::Error::other("non-Unicode vswhere path"))?,
                    arguments,
                    discovery,
                )
            },
        )?;
        env
    };
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
    if matches!(profile, "msrv" | "release-preflight") {
        let policy = fs::read_to_string(root.join("ci/toolchains.toml"))?;
        let msrv = policy
            .lines()
            .find_map(|line| {
                line.strip_prefix("msrv = \"")
                    .and_then(|value| value.strip_suffix('"'))
            })
            .ok_or_else(|| io::Error::other("pinned MSRV policy missing"))?;
        let mut install = Command::new(&rustup);
        install
            .args(["toolchain", "install", msrv, "--profile", "minimal"])
            .env_clear()
            .envs(&env);
        run_bounded("install MSRV toolchain", &mut install, &mut journal)?;
    }
    if matches!(profile, "miri" | "fuzz") {
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
        run_bounded("install nightly toolchain", &mut install, &mut journal)?;
        if profile == "miri" {
            let mut setup = Command::new(&rustup);
            setup
                .args(["run", nightly, "cargo", "miri", "setup"])
                .current_dir(&work)
                .env_clear()
                .envs(&env)
                .env("CARGO_HOME", &cargo_home);
            run_bounded("prepare Miri sysroot", &mut setup, &mut journal)?;
        }
    }
    let cargo_path = capture(
        rustup
            .to_str()
            .ok_or_else(|| io::Error::other("non-Unicode rustup path"))?,
        &["which", "--toolchain", "1.97.1", "cargo"],
        &env,
    )?;
    let cargo = std::path::PathBuf::from(
        String::from_utf8(cargo_path)
            .map_err(io::Error::other)?
            .trim(),
    );
    let cargo = environment::paths::command_program(&cargo)?;
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
    run_bounded("fetch workspace sources", &mut fetch, &mut journal)?;
    if profile == "fuzz" {
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
        run_bounded("fetch fuzz sources", &mut fetch, &mut journal)?;
    }
    let mut build = Command::new(&cargo);
    build
        .args(["build", "--locked", "--offline", "--manifest-path"])
        .arg(root.join("Cargo.toml"))
        .args(["--target-dir"])
        .arg(root.join("target/ci/control-bootstrap"))
        .args(["--package", "memcordon-ci"])
        .args(["--profile", CONTROL_PROFILE])
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
    let group_deadline = bounded::GroupDeadline::new(bounded::CHILD_BUDGET)?;
    journal.group_start(group_deadline)?;
    let mut controller_journal = journal.task(bounded::TaskKind::Controller)?;
    bounded::run_in_group(
        &mut build,
        "compile fingerprint controller",
        &mut controller_journal,
        group_deadline,
    )?;
    // Auxiliary packages have their own published lockfiles. Acquire and build
    // them before measuring source trees, so later compilation cannot introduce
    // an unmeasured resolver or toolchain input into a shared cache identity.
    let tool_policy = fs::read_to_string(root.join("ci/tools.toml"))?;
    let selected: &[(&str, &str)] = if profile == "fuzz" {
        &[("cargo_fuzz", "cargo-fuzz")]
    } else if matches!(profile, "supply-chain" | "release-preflight") {
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
        let staging = root.join("target/ci-tools/staging").join(package);
        if staging.exists() {
            fs::remove_dir_all(&staging)?;
        }
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
            .arg(&staging)
            .arg("--target-dir")
            .arg(root.join("target/ci-tools/build").join(package))
            .current_dir(&work)
            .env_clear()
            .envs(&env)
            .env("CARGO_HOME", &cargo_home)
            .env(
                "RUSTC",
                bin.join(if cfg!(windows) { "rustc.exe" } else { "rustc" }),
            );
        let auxiliary = journal.task(bounded::TaskKind::Auxiliary)?;
        let kind = match *package {
            "cargo-audit" => bounded::TaskKind::CargoAudit,
            "cargo-deny" => bounded::TaskKind::CargoDeny,
            "cargo-fuzz" => bounded::TaskKind::CargoFuzz,
            _ => unreachable!("closed tool inventory"),
        };
        let mut tool_journal = auxiliary.task(kind)?;
        bounded::run_in_group(
            &mut install,
            "install managed native tool",
            &mut tool_journal,
            group_deadline,
        )?;
        let mut name = std::path::PathBuf::from(package);
        if cfg!(windows) {
            name.set_extension("exe");
        }
        let executable = staging.join("bin").join(&name);
        let identity = capture_with_budget(
            executable
                .to_str()
                .ok_or_else(|| io::Error::other("non-Unicode staged executable"))?,
            &["--version"],
            &env,
            group_deadline.remaining()?.min(Duration::from_secs(15)),
        )?;
        if identity.len() > 8192
            || !String::from_utf8_lossy(&identity)
                .split_whitespace()
                .any(|value| value == version)
        {
            return Err(io::Error::other(
                "staged tool version differs from pinned policy",
            ));
        }
        group_deadline.remaining()?;
        let digest = bounded::sha256::digest(&mut fs::File::open(&executable)?)?;
        promote_tool(
            &executable,
            &root.join("target/ci-tools/bin").join(name),
            &digest,
        )?;
    }
    group_deadline.remaining()?;
    journal.group_outcome(&[Ok(()), Ok(())])?;
    let controller = root
        .join("target/ci/control-bootstrap")
        .join(CONTROL_PROFILE)
        .join(if cfg!(windows) {
            "memcordon-ci.exe"
        } else {
            "memcordon-ci"
        });
    let mut plan = Command::new(controller);
    plan.args(["build-context", "--profile", profile, "--output"])
        .arg(&candidate)
        .arg("--observation-dir")
        .arg(journal.directory())
        .current_dir(&root)
        .env_clear()
        .envs(&env);
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
    #[cfg(windows)]
    let completion = if trace_inventory {
        let mut recording = inventory_trace::Session::new(
            &root,
            journal.directory(),
            &env,
            configure_recording_environment,
        );
        inventory_trace::around(&mut recording, || {
            run_bounded("prepare fingerprint context", &mut plan, &mut journal)
        })?
    } else {
        run_bounded("prepare fingerprint context", &mut plan, &mut journal)?
    };
    #[cfg(not(windows))]
    let completion = run_bounded("prepare fingerprint context", &mut plan, &mut journal)?;
    bounded::publish(&candidate, &path, &journal, &completion)
}

fn run_bounded(
    label: &str,
    command: &mut Command,
    journal: &mut bounded::Journal,
) -> io::Result<bounded::Completion> {
    environment::progress::phase(label, || bounded::run(command, label, journal))
}

fn main() {
    if let Err(error) = run() {
        eprintln!("native fingerprint: {error}");
        std::process::exit(1);
    }
}
