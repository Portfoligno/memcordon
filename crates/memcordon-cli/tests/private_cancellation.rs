#![cfg(unix)]

#[path = "../src/bin/memcordon-sealed-agent/linux/private_cancellation.rs"]
mod private_cancellation;

use private_cancellation::{PrivateCancellation, observe_cancellation};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct HeldChild(Child);
impl Drop for HeldChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "bounded child invoked by actual cancellation ownership regression"]
fn held_frontend() {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut byte = [0];
        let _ = sender.send(std::io::stdin().read(&mut byte));
    });
    assert_eq!(
        receiver
            .recv_timeout(Duration::from_secs(3))
            .unwrap()
            .unwrap(),
        0
    );
}

fn frontend() -> HeldChild {
    HeldChild(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "--ignored", "held_frontend"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    )
}

#[test]
fn authenticated_cancel_or_eof_with_live_frontend_is_controlled() {
    let mut frontend = frontend();
    assert!(frontend.0.try_wait().unwrap().is_none());
    for eof in [false, true] {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        if eof {
            drop(writer);
        } else {
            writer.write_all(&[1]).unwrap();
        }
        assert_eq!(
            observe_cancellation(&reader, || {
                frontend
                    .0
                    .try_wait()
                    .map(|status| status.is_some())
                    .map_err(|error| error.to_string())
            })
            .unwrap(),
            Some(PrivateCancellation::Controlled)
        );
        assert!(frontend.0.try_wait().unwrap().is_none());
    }
    // Release the real held child and observe its native exit, rather than
    // equating the prior exchange EOF with process death.
    frontend.0.stdin.take();
    assert!(frontend.0.wait().unwrap().success());
    let (reader, mut writer) = UnixStream::pair().unwrap();
    writer.write_all(&[1]).unwrap();
    assert_eq!(
        observe_cancellation(&reader, || {
            frontend
                .0
                .try_wait()
                .map(|status| status.is_some())
                .map_err(|error| error.to_string())
        })
        .unwrap(),
        Some(PrivateCancellation::FrontendLost)
    );
}

#[test]
fn pending_invalid_and_unproven_frontend_states_do_not_claim_loss() {
    let (reader, mut writer) = UnixStream::pair().unwrap();
    assert_eq!(
        observe_cancellation(&reader, || panic!("no cancellation requested")).unwrap(),
        None
    );
    writer.write_all(&[9]).unwrap();
    assert!(
        observe_cancellation(&reader, || panic!(
            "invalid input cannot supply ownership proof"
        ))
        .unwrap_err()
        .contains("invalid exchange byte")
    );
    let (reader, mut writer) = UnixStream::pair().unwrap();
    writer.write_all(&[1]).unwrap();
    assert_eq!(
        observe_cancellation(&reader, || Err(
            "actual native observation unavailable".into()
        ))
        .unwrap_err(),
        "actual native observation unavailable"
    );
}
