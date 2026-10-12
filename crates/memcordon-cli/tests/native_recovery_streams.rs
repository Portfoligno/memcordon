#![cfg(unix)]

#[path = "sealed_agent/native_recovery_streams.rs"]
mod native_recovery_streams;

use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn directory() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "memcordon-recovery-streams-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&path).unwrap();
    path
}

#[test]
fn actual_socket_endpoints_capture_bytes_and_eof_before_boundary() {
    let root = directory();
    let (mut capture, [stdin, stdout, stderr]) =
        native_recovery_streams::Capture::acquire(&root, Instant::now() + Duration::from_secs(5))
            .unwrap();
    let mut stdin = UnixStream::from(stdin);
    assert_eq!(stdin.read(&mut [0_u8; 1]).unwrap(), 0);
    let mut stdout = UnixStream::from(stdout);
    let mut stderr = UnixStream::from(stderr);
    let bytes = [0xa5_u8; 4096];
    for _ in 0..128 {
        stdout.write_all(&bytes).unwrap();
        capture.observe(false).unwrap();
    }
    stderr.write_all(b"actual stderr\0\xff").unwrap();
    drop(stdout);
    drop(stderr);
    capture.observe(true).unwrap();
    assert_eq!(
        fs::read(root.join("target-stdout.bin")).unwrap(),
        bytes.repeat(128)
    );
    assert_eq!(
        fs::read(root.join("target-stderr.bin")).unwrap(),
        b"actual stderr\0\xff"
    );
    assert!(
        native_recovery_streams::Capture::acquire(&root, Instant::now() + Duration::from_secs(1))
            .is_err()
    );
    drop(capture);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn unfinished_peer_refuses_at_original_deadline() {
    let root = directory();
    let (mut capture, endpoints) = native_recovery_streams::Capture::acquire(
        &root,
        Instant::now() + Duration::from_millis(10),
    )
    .unwrap();
    assert!(capture.observe(true).unwrap_err().contains("deadline"));
    drop(endpoints);
    drop(capture);
    fs::remove_dir_all(root).unwrap();
}
