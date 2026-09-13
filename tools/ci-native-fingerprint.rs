//! Rebuilt with rustc before any native compiled-target cache is restored.
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

fn capture(program: &str, arguments: &[&str]) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_secs(15);
    let program = program.to_owned();
    let arguments: Vec<String> = arguments.iter().map(|value| (*value).to_owned()).collect();
    let (sender, receiver) = mpsc::sync_channel(0);
    std::thread::spawn(move || {
        let result = Command::new(program)
            .args(arguments)
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

fn field(output: &mut Vec<u8>, name: &[u8], value: &[u8]) -> io::Result<()> {
    for bytes in [name, value] {
        output.extend_from_slice(
            &u64::try_from(bytes.len())
                .map_err(io::Error::other)?
                .to_le_bytes(),
        );
        output.extend_from_slice(bytes);
    }
    Ok(())
}

fn run() -> io::Result<()> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.len() != 2 || arguments[0] != "--output" {
        return Err(io::Error::other(
            "usage: ci-native-fingerprint --output PATH",
        ));
    }
    let path = Path::new(&arguments[1]);
    if !capture("git", &["status", "--porcelain", "--untracked-files=all"])?.is_empty() {
        return Err(io::Error::other(
            "native qualification requires an unchanged source checkout",
        ));
    }
    let mut bytes = b"memcordon-native-inputs-v1\0".to_vec();
    for (name, program, args) in [
        ("commit", "git", vec!["rev-parse", "HEAD"]),
        ("rustc", "rustup", vec!["run", "1.97.1", "rustc", "-vV"]),
        ("os", "sw_vers", vec![]),
        ("kernel", "uname", vec!["-a"]),
        ("xcode", "xcodebuild", vec!["-version"]),
        (
            "sdk",
            "xcrun",
            vec!["--sdk", "macosx", "--show-sdk-version"],
        ),
        (
            "sdk-path",
            "xcrun",
            vec!["--sdk", "macosx", "--show-sdk-path"],
        ),
        ("clang", "xcrun", vec!["clang", "--version"]),
    ] {
        field(&mut bytes, name.as_bytes(), &capture(program, &args)?)?;
    }
    for name in [
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CC",
        "CXX",
        "CFLAGS",
        "CXXFLAGS",
        "CPPFLAGS",
        "SDKROOT",
        "MACOSX_DEPLOYMENT_TARGET",
    ] {
        match std::env::var(name) {
            Ok(value) => field(&mut bytes, name.as_bytes(), value.as_bytes())?,
            Err(std::env::VarError::NotPresent) => field(&mut bytes, name.as_bytes(), b"<absent>")?,
            Err(error) => return Err(io::Error::other(error)),
        }
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)
}

fn main() {
    if let Err(error) = run() {
        eprintln!("native fingerprint: {error}");
        std::process::exit(1);
    }
}
