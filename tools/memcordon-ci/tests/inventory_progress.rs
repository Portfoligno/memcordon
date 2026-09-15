use memcordon_ci::inventory_progress::{InventoryProgress, Operation};
use std::path::Path;
use std::time::{Duration, Instant};

#[test]
fn operation_costs_preserve_results_errors_and_active_path() {
    let path = Path::new("native\ninput\twith spaces");
    let mut progress = InventoryProgress::new(path);
    let result: Result<Vec<u8>, &str> = progress.run(Operation::Metadata, path, || {
        let active = progress.snapshot();
        assert!(active.contains("operation=Metadata"), "{active}");
        assert!(active.contains(&format!("path={path:?}")), "{active}");
        assert_eq!(active.lines().count(), 1);
        Ok(vec![0, 255])
    });
    assert_eq!(result.unwrap(), [0, 255]);
    let result: Result<(), &str> = progress.run(Operation::Open, path, || Err("original error"));
    assert_eq!(result.unwrap_err(), "original error");
    progress.record_chunk(Duration::from_millis(2), Duration::from_millis(3), 17);
    progress.record_chunk(Duration::from_millis(5), Duration::from_millis(7), 23);
    let snapshot = progress.snapshot();
    for expected in [
        "Metadata_count=1",
        "Open_count=1",
        "Canonicalize_count=0",
        "bytes=40",
        "read_ms=7",
        "hash_ms=10",
        "operation=idle",
    ] {
        assert!(
            snapshot.split_whitespace().any(|field| field == expected),
            "{snapshot}"
        );
    }
    let started = Instant::now();
    progress.finish(false);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "finish must wake the 30-second observer"
    );
}

#[test]
fn blocked_operation_emits_heartbeat_without_changing_stdout() {
    use std::fs;
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::thread;

    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("inventory_fixture.rs");
    let executable = temporary.path().join("inventory_fixture.exe");
    let module = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/inventory_progress.rs")
        .canonicalize()
        .unwrap();
    let declaration =
        format!("#[allow(dead_code)]\n#[path = {module:?}]\nmod inventory_progress;\n");
    let body = r#"use inventory_progress::{InventoryProgress, Operation};
fn main() {
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(5));
        std::process::exit(124);
    });
    let path = std::path::Path::new("blocked\ninput");
    let mut progress = InventoryProgress::new_with_interval(path, std::time::Duration::from_millis(10));
    progress.run(Operation::ReadHash, path, || {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)
    }).unwrap();
    progress.finish(true);
    println!("native-protocol");
}
"#;
    fs::write(&source, [declaration.as_bytes(), body.as_bytes()].concat()).unwrap();
    let mut compile = Command::new("rustup");
    compile
        .args(["run", "1.97.1", "rustc", "--edition=2021"])
        .arg(&source)
        .arg("-o")
        .arg(&executable);
    let compiled =
        memcordon_testkit::run_with_deadline(&mut compile, Duration::from_secs(20)).unwrap();
    assert!(compiled.status.success(), "{:?}", compiled.stderr);
    let mut child = Command::new(&executable)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let (sender, receiver) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut lines = Vec::new();
        for line in BufReader::new(stderr).lines() {
            let line = line.unwrap();
            if line.starts_with("[native inventory] progress ") {
                let _ = sender.send(line.clone());
            }
            lines.push(line);
        }
        lines
    });
    let heartbeat = receiver.recv_timeout(Duration::from_secs(3));
    if heartbeat.is_ok() {
        child.stdin.take().unwrap().write_all(b"release\n").unwrap();
    } else {
        let _ = child.kill();
    }
    let output = child.wait_with_output().unwrap();
    let lines = reader.join().unwrap();
    let heartbeat = heartbeat.expect("observer must report while the operation is blocked");
    assert!(heartbeat.contains("operation=ReadHash"), "{heartbeat}");
    assert!(
        heartbeat.contains("path=\"blocked\\ninput\""),
        "{heartbeat}"
    );
    assert!(output.status.success(), "{lines:?}");
    assert_eq!(output.stdout, b"native-protocol\n");
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.starts_with("[native inventory] complete "))
            .count(),
        1
    );
    assert!(
        lines
            .iter()
            .all(|line| line.starts_with("[native inventory] ")),
        "{lines:?}"
    );
}
