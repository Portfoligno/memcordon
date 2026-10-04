#![cfg(unix)]

#[path = "../src/bin/private_owner_loss_observation.rs"]
mod private_owner_loss_observation;

use private_owner_loss_observation::poll_exited;

#[test]
fn only_positive_pidfd_readiness_proves_termination() {
    assert!(!poll_exited(0, 0).unwrap());
    assert!(poll_exited(1, libc::POLLIN).unwrap());
    assert!(poll_exited(1, libc::POLLIN | libc::POLLHUP).unwrap());
    for (status, events) in [
        (-1, 0),
        (0, libc::POLLIN),
        (1, 0),
        (1, libc::POLLHUP),
        (1, libc::POLLERR),
        (1, libc::POLLNVAL),
        (1, libc::POLLOUT),
        (1, libc::POLLIN | libc::POLLERR),
        (1, libc::POLLIN | libc::POLLNVAL),
        (2, libc::POLLIN),
    ] {
        assert!(poll_exited(status, events).is_err());
    }
}

#[cfg(target_os = "linux")]
mod native {
    use super::private_owner_loss_observation::pidfd_exited;
    use memcordon_platform::test_support::ProcessIdentity;
    use std::io::Read;
    use std::os::fd::{AsFd, FromRawFd, OwnedFd};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    struct HeldChild(Child);
    impl Drop for HeldChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    #[ignore = "bounded real child invoked by native pidfd observation regression"]
    fn stdin_held_child() {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(std::io::stdin().read(&mut [0]));
        });
        let _ = receiver.recv_timeout(Duration::from_secs(5)).unwrap();
    }

    #[test]
    fn unreaped_native_child_is_dead_on_held_pidfd() {
        let mut child = HeldChild(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "--ignored", "native::stdin_held_child"])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let identity = ProcessIdentity::for_pid(child.0.id()).unwrap();
        // SAFETY: pidfd_open targets this owned, still-unreaped native child.
        let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, child.0.id(), 0) };
        assert!(descriptor >= 0);
        // SAFETY: successful pidfd_open returns a uniquely owned descriptor.
        let pidfd = unsafe { OwnedFd::from_raw_fd(i32::try_from(descriptor).unwrap()) };
        assert!(!pidfd_exited(pidfd.as_fd()).unwrap());
        child.0.kill().unwrap();
        let until = Instant::now() + Duration::from_secs(3);
        while !pidfd_exited(pidfd.as_fd()).unwrap() {
            assert!(Instant::now() < until, "native child did not exit");
            std::thread::sleep(Duration::from_millis(1));
        }
        // No wait/try_wait has reaped this child: its matching native birth
        // remains observable, but the same retained pidfd proves termination.
        assert_eq!(ProcessIdentity::for_pid(child.0.id()).unwrap(), identity);
        assert!(identity.still_exists().unwrap());
        assert!(!child.0.wait().unwrap().success());
        assert!(pidfd_exited(pidfd.as_fd()).unwrap());
    }

    #[test]
    fn unrelated_descriptor_cannot_prove_process_termination() {
        let file = tempfile::tempfile().unwrap();
        assert!(pidfd_exited(file.as_fd()).is_err());
        let (reader, writer) = std::os::unix::net::UnixStream::pair().unwrap();
        drop(writer);
        assert!(pidfd_exited(reader.as_fd()).is_err());
    }
}
