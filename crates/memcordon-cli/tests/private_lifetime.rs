#![cfg(unix)]

#[path = "../src/bin/memcordon-sealed-agent/linux/private_lifetime.rs"]
mod private_lifetime;
#[allow(dead_code)]
#[path = "../src/bin/memcordon-sealed-agent/request.rs"]
mod request;

use private_lifetime::reap_private_descendants;
use request::Lifetime;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

fn run_isolated_helper(name: &str) {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", name, "--ignored", "--nocapture"]);
    let output = memcordon_testkit::run_with_deadline_output_limit(
        &mut command,
        Duration::from_secs(5),
        16 * 1024,
    )
    .unwrap();
    assert!(
        output.status.success(),
        "helper status {:?}, stderr {:?}, stdout {:?}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout),
    );
}

#[test]
fn command_lifetime_returns_before_held_descendant_completes() {
    run_isolated_helper("command_lifetime_helper");
}

#[test]
fn workload_lifetime_waits_for_actual_descendant_completion() {
    run_isolated_helper("workload_lifetime_helper");
}

fn held_child() -> (Child, ChildStdin, BufReader<ChildStdout>) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "held_descendant_helper",
            "--ignored",
            "--nocapture",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let gate = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    loop {
        let mut line = String::new();
        assert_ne!(stdout.read_line(&mut line).unwrap(), 0);
        if line.trim() == "DESCENDANT_READY" {
            break;
        }
    }
    assert!(child.try_wait().unwrap().is_none());
    (child, gate, stdout)
}

#[test]
#[ignore = "isolated actual native child-reaping case"]
fn command_lifetime_helper() {
    let (mut child, mut gate, _stdout) = held_child();
    assert_eq!(reap_private_descendants(Lifetime::Command).unwrap(), 0);
    assert!(child.try_wait().unwrap().is_none());
    gate.write_all(b"x").unwrap();
    assert!(child.wait().unwrap().success());
}

#[test]
#[ignore = "isolated actual native child-reaping case"]
fn workload_lifetime_helper() {
    let (mut child, mut gate, _stdout) = held_child();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (finished_tx, finished_rx) = mpsc::channel();
    std::thread::scope(|scope| {
        let worker = scope.spawn(move || {
            entered_tx.send(()).unwrap();
            finished_tx
                .send(reap_private_descendants(Lifetime::Workload))
                .unwrap();
        });
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(matches!(
            finished_rx.recv_timeout(Duration::from_millis(30)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        assert!(child.try_wait().unwrap().is_none());
        gate.write_all(b"x").unwrap();
        assert_eq!(
            finished_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .unwrap(),
            1
        );
        worker.join().unwrap();
    });
    // The actual native helper reaped the exact child; no status is invented
    // for the std::process::Child wrapper after that ownership transfer.
    assert_eq!(child.wait().unwrap_err().raw_os_error(), Some(libc::ECHILD));
}

#[test]
#[ignore = "actual pipe-held descendant for the isolated native wait cases"]
fn held_descendant_helper() {
    println!("DESCENDANT_READY");
    std::io::stdout().flush().unwrap();
    let mut byte = [0_u8; 1];
    std::io::stdin().read_exact(&mut byte).unwrap();
    assert_eq!(byte, *b"x");
}
