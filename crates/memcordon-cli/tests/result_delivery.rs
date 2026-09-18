#![cfg(all(target_os = "macos", feature = "test-fixtures"))]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[path = "support/delivery_evidence.rs"]
mod delivery_evidence;

#[test]
fn inherited_evidence_endpoint_is_owned_and_parent_remains_cloexec() {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args([
        "--exact",
        "isolated_evidence_endpoint_ownership",
        "--ignored",
        "--test-threads=1",
    ]);
    let output = memcordon_testkit::run_with_deadline(&mut command, Duration::from_secs(5))
        .expect("isolated ownership fixture must finish within the existing fixture bound");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("test isolated_evidence_endpoint_ownership ... ok"),
        "ownership assertions must execute: {output:?}"
    );
}

#[test]
#[ignore = "invoked by inherited_evidence_endpoint_is_owned_and_parent_remains_cloexec"]
fn isolated_evidence_endpoint_ownership() {
    // Create endpoints after exec in a process running only this fixture.
    // Parallel sibling forks can otherwise retain CLOEXEC endpoints until exec,
    // making immediate EOF an observation of unrelated child preparation.
    use std::io::Read;
    use std::os::unix::net::UnixStream;
    let (mut reader, writer) = UnixStream::pair().unwrap();
    reader.set_nonblocking(true).unwrap();
    let mut command = Command::new("/usr/bin/true");
    let descriptor =
        memcordon_platform::test_support::inherit_test_descriptor(&mut command, writer.into())
            .unwrap();
    // SAFETY: the command owns the live endpoint until it is dropped below.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0);
    let mut byte = [0_u8];
    assert_eq!(
        reader.read(&mut byte).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    drop(command);
    assert_eq!(reader.read(&mut byte).unwrap(), 0);
}

#[test]
fn failed_report_sink_has_separate_evidence_and_full_evidence_pipe_never_blocks() {
    let directory = tempfile::tempdir().unwrap();
    for full in [false, true] {
        let output = directory.path().join("absent-parent/report.json");
        let mut command = Command::new(env!("CARGO_BIN_EXE_memcordon"));
        let mut evidence = delivery_evidence::Evidence::attach(&mut command);
        if full {
            evidence.fill();
        }
        command
            .args(["+0ms", "--report"])
            .arg(&output)
            .args(["--", "/usr/bin/true"]);
        assert_eq!(bounded(command).code(), Some(125));
        assert!(!output.exists());
        let text = evidence.finish();
        if !full {
            let record: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(record["stage"], "writer_exit");
            assert_eq!(record["writer_exit_code"], 125);
        }
    }
}

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
        let evidence = delivery_evidence::Evidence::attach(&mut command);
        command
            .args(["__result-writer-fault", phase])
            .arg(&input)
            .arg(&output)
            .arg(&marker);
        let started = Instant::now();
        assert_eq!(bounded(command).code(), Some(125), "{phase}");
        let evidence: serde_json::Value = serde_json::from_str(&evidence.finish()).unwrap();
        assert_eq!(evidence["schema"], 1);
        assert_eq!(evidence["stage"], "writer_deadline");
        let phases = evidence["writer"]["phases"].as_array().unwrap();
        assert_eq!(phases.first().unwrap(), "entered");
        assert_eq!(
            phases.last().unwrap().as_str(),
            Some(phase.replace('-', "_").as_str())
        );
        assert_eq!(evidence["writer"]["malformed"], false);
        assert_eq!(evidence["writer"]["truncated"], false);
        assert!(evidence["writer"]["os_error"].is_null());
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
