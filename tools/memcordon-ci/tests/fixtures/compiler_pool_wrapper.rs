//! Standalone real-rustc observer for the shared Cargo jobserver fixture.
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

fn record(root: &Path, delta: i32) {
    let lock = root.with_extension("lock");
    let cutoff = Instant::now() + Duration::from_secs(10);
    loop {
        match fs::create_dir(&lock) {
            Ok(()) => break,
            Err(error)
                if error.kind() == std::io::ErrorKind::AlreadyExists && Instant::now() < cutoff =>
            {
                std::thread::sleep(Duration::from_millis(1))
            }
            Err(error) => panic!("compiler observation lock: {error}"),
        }
    }
    let count = fs::read_to_string(root.with_extension("count"))
        .unwrap_or_else(|_| "0".into())
        .parse::<i32>()
        .unwrap()
        + delta;
    assert!(count >= 0);
    fs::write(root.with_extension("count"), count.to_string()).unwrap();
    let settled = root.with_extension("settled").is_file();
    writeln!(
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(root.with_extension("events"))
            .unwrap(),
        "{} {delta} {count} {settled}",
        std::process::id()
    )
    .unwrap();
    fs::remove_dir(lock).unwrap();
}

fn main() {
    let mut arguments = std::env::args_os().skip(1);
    let compiler = arguments.next().expect("actual rustc argv");
    let arguments: Vec<_> = arguments.collect();
    let compilation = arguments
        .iter()
        .any(|arg| arg.to_str().is_some_and(|arg| arg.starts_with("--emit")))
        && !arguments
            .iter()
            .any(|arg| arg.to_str().is_some_and(|arg| arg.starts_with("--print")));
    let root: PathBuf = std::env::current_exe().unwrap();
    if compilation {
        record(&root, 1);
        std::thread::sleep(Duration::from_millis(150));
    }
    let result = Command::new(compiler).args(arguments).status();
    if compilation {
        record(&root, -1);
    }
    std::process::exit(result.expect("actual rustc child").code().unwrap_or(1));
}
