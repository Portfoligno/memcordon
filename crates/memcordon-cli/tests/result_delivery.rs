#![cfg(all(target_os = "macos", feature = "test-fixtures"))]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn bounded(mut command: Command) -> std::process::ExitStatus {
    let started = Instant::now();
    let (sender, receiver) = std::sync::mpsc::sync_channel(0);
    std::thread::spawn(move || {
        let result = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        if let Err(std::sync::mpsc::SendError(Ok(mut child))) = sender.send(result) {
            let _ = child.kill();
            let _ = child.wait();
        }
    });
    let mut child = receiver
        .recv_timeout(Duration::from_secs(5))
        .expect("native creation deadline")
        .expect("native fixture spawn");
    loop {
        if let Some(status) = child.try_wait().expect("nonblocking native wait") {
            return status;
        }
        if started.elapsed() > Duration::from_secs(5) {
            child.kill().expect("fixture cancellation");
            let teardown = Instant::now();
            while teardown.elapsed() < Duration::from_secs(2) {
                if child
                    .try_wait()
                    .expect("fixture reap observation")
                    .is_some()
                {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            panic!("native result writer exceeded independent outer deadline");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn result_writer_stalls_before_write_rename_and_ack_are_cancelled_and_reaped() {
    let directory = tempfile::tempdir().expect("controlled native fixture directory");
    let input = directory.path().join("input.json");
    let mut baseline = Command::new(env!("CARGO_BIN_EXE_memcordon"));
    baseline
        .args(["+0ms", "--report"])
        .arg(&input)
        .args(["--", "/usr/bin/true"]);
    assert_eq!(bounded(baseline).code(), Some(123));
    for phase in ["before-write", "before-rename", "before-ack"] {
        let phase_directory = directory.path().join(phase);
        std::fs::create_dir(&phase_directory).expect("phase directory");
        let output = phase_directory.join("output.json");
        let marker = phase_directory.join("barrier.json");
        let mut command = Command::new(env!("CARGO_BIN_EXE_memcordon"));
        command
            .args(["__result-writer-fault", phase])
            .arg(&input)
            .arg(&output)
            .arg(&marker);
        let started = Instant::now();
        assert_eq!(bounded(command).code(), Some(125), "{phase}");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{phase} exceeded delivery reserve and tolerance"
        );
        let marker: (u32, memcordon_core::ReportWritePhase) = serde_json::from_slice(
            &std::fs::read(marker).expect("actual native persistence barrier reached"),
        )
        .expect("typed barrier marker");
        // A surviving or unreaped child retains its PID. The parent must reap
        // before the fixture completes; ESRCH corroborates that observation.
        assert_eq!(
            unsafe { libc::kill(i32::try_from(marker.0).expect("native PID"), 0) },
            -1,
            "writer survives {phase}"
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
        if phase == "before-ack" {
            let report: memcordon_core::MemcordonReport = serde_json::from_slice(
                &std::fs::read(&output).expect("rename completed before barrier"),
            )
            .expect("valid prepared report");
            assert_eq!(report.schema_version, 10);
            // A committed report still does not turn failed delivery into success.
        } else {
            assert!(!output.exists(), "pre-rename barrier committed report");
        }
    }
}

#[test]
fn mutation_synchronous_final_stderr_is_detected() {
    let started = Instant::now();
    let (sender, receiver) = std::sync::mpsc::sync_channel(0);
    std::thread::spawn(move || {
        let result = Command::new(env!("CARGO_BIN_EXE_memcordon"))
            .arg("__result-writer-synchronous-stderr-mutant")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn();
        if let Err(std::sync::mpsc::SendError(Ok(mut child))) = sender.send(result) {
            let _ = child.kill();
            let _ = child.wait();
        }
    });
    let mut child = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("bounded mutant creation")
        .expect("mutant spawned");
    while started.elapsed() < Duration::from_millis(1500) {
        assert!(
            child.try_wait().expect("native observation").is_none(),
            "mutation must actually block at the unread final sink"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    // The independent controller rejects the missed one-second return contract
    // before teardown. Cleanup cannot convert that rejection into acceptance.
    child.kill().expect("mutant cancellation");
    let teardown = Instant::now();
    loop {
        if child.try_wait().expect("mutant reap observation").is_some() {
            break;
        }
        assert!(
            teardown.elapsed() < Duration::from_secs(2),
            "mutant remained an unresolved native obligation"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
