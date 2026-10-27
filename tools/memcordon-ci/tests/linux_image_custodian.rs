#![cfg(target_os = "linux")]

#[path = "../src/release/linux_image_custodian.rs"]
pub mod custodian;
#[path = "../src/release/linux_image_custody.rs"]
pub mod linux_image_custody;

use memcordon_platform::test_support::{
    ImageCustodyPeer, ImageCustodySocket, image_custody_cutoff_nanos,
};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Worker(Child, Instant);
impl Drop for Worker {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        loop {
            match self.0.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < self.1 => std::thread::sleep(Duration::from_millis(1)),
                Ok(None) | Err(_) => {
                    eprintln!(
                        "native custody test worker retirement unobserved at original cutoff"
                    );
                    break;
                }
            }
        }
    }
}

fn spawn_worker(selector: &'static str, deadline: Instant) -> (ImageCustodySocket, Worker) {
    let (parent, child) = ImageCustodySocket::pair().unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", selector, "--ignored", "--nocapture"])
        .stdin(child.into_stdio())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let worker = Worker(command.spawn().unwrap(), deadline);
    // Command retains its configured Stdio even after successful spawn. Drop
    // that redundant child endpoint BEFORE waiting for a completion or EOF.
    // Failed spawn still unwinds the configured Command and its owned Stdio.
    drop(command);
    (parent, worker)
}

fn retire_worker(worker: &mut Worker) -> std::process::ExitStatus {
    loop {
        assert!(
            Instant::now() < worker.1,
            "native custody worker retirement exceeded original test cutoff"
        );
        if let Some(status) = worker.0.try_wait().unwrap() {
            return status;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn isolated_native_custody_contract_exceeds_single_process_frontier() {
    let original_limit = rustix::process::getrlimit(rustix::process::Resource::Nofile);
    let deadline = Instant::now() + Duration::from_secs(120);
    let (parent, mut worker) = spawn_worker(
        "custodian::native_tests::isolated_contract_worker",
        deadline,
    );
    let peer = ImageCustodyPeer {
        pid: worker.0.id(),
        ..ImageCustodyPeer::current()
    };
    parent
        .send(
            &image_custody_cutoff_nanos(deadline).unwrap().to_le_bytes(),
            None,
            deadline,
        )
        .unwrap();
    // A zero-selected worker exits without this authenticated completion packet.
    assert_eq!(
        parent.receive(peer, deadline).unwrap().bytes,
        b"all-native-custody-checks-retired"
    );
    assert!(retire_worker(&mut worker).success());
    assert_eq!(
        rustix::process::getrlimit(rustix::process::Resource::Nofile),
        original_limit
    );
}

#[test]
fn failed_or_zero_selected_worker_refuses_completion_before_original_cutoff() {
    for (selector, expected_success) in [
        ("failed_worker_without_completion", false),
        ("intentionally_nonexistent_custody_worker", true),
    ] {
        let deadline = Instant::now() + Duration::from_secs(10);
        let (parent, mut worker) = spawn_worker(selector, deadline);
        let peer = ImageCustodyPeer {
            pid: worker.0.id(),
            ..ImageCustodyPeer::current()
        };
        let error = match parent.receive(peer, deadline) {
            Ok(_) => panic!("worker without genuine completion must be refused"),
            Err(error) => error,
        };
        assert_ne!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            Instant::now() < deadline,
            "worker closure must surface before the cutoff"
        );
        assert_eq!(retire_worker(&mut worker).success(), expected_success);
    }
}

#[test]
#[ignore = "selected only by the owned missing-completion regression"]
fn failed_worker_without_completion() {
    // No protocol completion is published. Kernel exit closes the inherited
    // endpoint; the parent must retain the failed result and native exit.
    std::process::exit(1);
}
