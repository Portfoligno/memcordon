use super::*;
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::process::{Child, Command, Stdio};

struct OriginalChild {
    child: Child,
    init: NamespaceInit,
    deadline: Instant,
    reaped: bool,
}

impl OriginalChild {
    fn start() -> Self {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--ignored",
                "--exact",
                "linux::private_lifecycle::init_exit_tests::original_init_exit_test_worker",
                "--nocapture",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = command.spawn().unwrap();
        drop(command);
        let pid = child.id() as libc::pid_t;
        // SAFETY: pidfd_open queries the actual owned child; flags zero.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            let _ = child.kill();
            loop {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    panic!("original fixture pidfd unavailable: {error}");
                }
                if Instant::now() >= deadline {
                    std::process::abort();
                }
                std::thread::yield_now();
            }
        }
        // SAFETY: successful syscall returned one newly owned descriptor.
        let pidfd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        Self {
            child,
            init: NamespaceInit {
                host_pid: pid,
                pidfd,
            },
            deadline,
            reaped: false,
        }
    }
    fn reap(&mut self) -> i32 {
        let status =
            wait_exact_child(self.init.host_pid, self.init.pidfd.as_fd(), self.deadline).unwrap();
        self.reaped = true;
        status
    }
}

impl Drop for OriginalChild {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            if wait_exact_child(self.init.host_pid, self.init.pidfd.as_fd(), self.deadline).is_err()
            {
                // A fixture must not detach an unresolved native child.
                std::process::abort();
            }
        }
    }
}

#[test]
fn immediate_sample_and_eventual_original_reap_are_distinct() {
    let mut child = OriginalChild::start();
    let mut diagnostic = InitExitDiagnostic {
        initial: Some(observe_init_exit(&child.init)),
        ..Default::default()
    };
    assert_eq!(diagnostic.initial.as_deref(), Some("not-observed"));
    assert!(
        wait_exact_child(
            child.init.host_pid,
            child.init.pidfd.as_fd(),
            Instant::now()
        )
        .is_err()
    );
    diagnostic.before_containment = Some(observe_init_exit(&child.init));
    child.child.stdin.as_mut().unwrap().write_all(b"x").unwrap();
    let raw = child.reap();
    diagnostic.reaped = Some((child.init.host_pid, raw));
    assert!(libc::WIFEXITED(raw));
    assert_eq!(libc::WEXITSTATUS(raw), 23);
    let detail = diagnostic.detail();
    assert!(detail.contains("containment-attempted=false"));
    assert!(detail.contains("exit=Some(23)"));
    assert!(observe_init_exit(&child.init).starts_with("query-error:"));
}

#[test]
fn containment_signal_is_not_attributed_to_initial_exit() {
    let mut child = OriginalChild::start();
    let mut diagnostic = InitExitDiagnostic {
        initial: Some(observe_init_exit(&child.init)),
        before_containment: Some(observe_init_exit(&child.init)),
        containment_attempted: true,
        ..Default::default()
    };
    child.child.kill().unwrap();
    let raw = child.reap();
    diagnostic.reaped = Some((child.init.host_pid, raw));
    assert!(libc::WIFSIGNALED(raw));
    assert_eq!(libc::WTERMSIG(raw), libc::SIGKILL);
    assert!(diagnostic.detail().contains("containment-attempted=true"));
    assert_eq!(diagnostic.initial.as_deref(), Some("not-observed"));
}

#[test]
#[ignore = "driven by the original-child parent tests"]
fn original_init_exit_test_worker() {
    let mut byte = [0];
    std::io::stdin().read_exact(&mut byte).unwrap();
    std::process::exit(23);
}
