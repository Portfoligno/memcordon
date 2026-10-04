#![cfg(target_os = "linux")]

// Root-native component tests. They exercise real guardian/cgroup ownership;
// they do not claim an installed private request or namespace-init execution.
use crate::linux::{
    CGROUP_ROOT,
    cgroup::{AttemptCgroup, prepare_private_root},
    private_attempt::ProcessIdentityV4,
    private_guardian::{GuardianTriggerV4, PrivateGuardian},
};
use std::{
    fs,
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

struct NativeChild {
    pid: libc::pid_t,
    pidfd: OwnedFd,
    deadline: Instant,
    reaped: bool,
}

impl NativeChild {
    fn paused(deadline: Instant) -> Self {
        // SAFETY: the child executes only pause/_exit, without Rust allocation,
        // locks, inherited destructors, or external argv interpretation.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "native fork: {}", std::io::Error::last_os_error());
        if pid == 0 {
            loop {
                // SAFETY: pause has no memory arguments; this child is trusted.
                unsafe { libc::pause() };
            }
        }
        // SAFETY: this is our still-unreaped direct child, whose PID cannot be
        // reused before its owner waits.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
        if raw < 0 {
            let error = std::io::Error::last_os_error();
            // SAFETY: failure cleanup targets only the unreaped fork result.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, std::ptr::null_mut(), 0);
            }
            panic!("native pidfd_open: {error}");
        }
        // SAFETY: successful pidfd_open returns one fresh owned descriptor.
        let child = Self {
            pid,
            pidfd: unsafe { OwnedFd::from_raw_fd(raw) },
            deadline,
            reaped: false,
        };
        ProcessIdentityV4::observe(pid, child.pidfd.as_fd()).unwrap();
        child
    }

    fn kill(&self) {
        // SAFETY: the signal uses this exact retained child pidfd, never an
        // identity copied from a report or a PID-only process lookup.
        let status = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                libc::SIGKILL,
                0,
                0,
            )
        };
        assert_eq!(
            status,
            0,
            "native pidfd signal: {}",
            std::io::Error::last_os_error()
        );
    }

    fn reap_sigkill(&mut self) {
        loop {
            let mut status = 0;
            // SAFETY: waitpid observes only our exact unreaped direct child.
            let waited = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
            if waited == self.pid {
                self.reaped = true;
                assert!(libc::WIFSIGNALED(status));
                assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
                return;
            }
            if waited < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::Interrupted {
                    panic!("owned native wait: {error}");
                }
            }
            assert!(
                Instant::now() < self.deadline,
                "owned native child not reaped before original deadline"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn live(&self) -> bool {
        let mut fd = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll borrows one initialized record and this held descriptor.
        let result = unsafe { libc::poll(&mut fd, 1, 0) };
        assert!(
            result >= 0,
            "native pidfd poll: {}",
            std::io::Error::last_os_error()
        );
        result == 0
    }
}

impl Drop for NativeChild {
    fn drop(&mut self) {
        if !self.reaped {
            if self.live() {
                self.kill();
            }
            self.reap_sigkill();
        }
    }
}

struct NativeGroup {
    group: AttemptCgroup,
    path: PathBuf,
    attempt: [u8; 16],
    deadline: Instant,
}

impl NativeGroup {
    fn create(deadline: Instant) -> Self {
        // SAFETY: geteuid has no pointer arguments or mutable native state.
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "this selected native case requires root"
        );
        prepare_private_root().unwrap();
        let attempt = crate::policy_registry::native::random_nonce().unwrap().0;
        let identity: String = attempt.iter().map(|byte| format!("{byte:02x}")).collect();
        let group =
            AttemptCgroup::create(&identity, None, crate::request::SwapLimit::Host).unwrap();
        Self {
            group,
            path: Path::new(CGROUP_ROOT).join(identity),
            attempt,
            deadline,
        }
    }

    fn attach(&self, child: &NativeChild) {
        assert!(child.live());
        fs::write(self.path.join("cgroup.procs"), child.pid.to_string()).unwrap();
        assert_eq!(self.group.member_pids().unwrap(), vec![child.pid]);
        ProcessIdentityV4::observe(child.pid, child.pidfd.as_fd()).unwrap();
    }
}

impl Drop for NativeGroup {
    fn drop(&mut self) {
        if self.path.exists() {
            self.group.clone().kill_and_retire(self.deadline).unwrap();
        }
    }
}

fn loss(frontend_lost: bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    let group = NativeGroup::create(deadline);
    let mut frontend = NativeChild::paused(deadline);
    let mut worker = NativeChild::paused(deadline);
    let mut target = NativeChild::paused(deadline);
    group.attach(&target);
    let guardian = PrivateGuardian::spawn(
        group.attempt,
        frontend.pidfd.as_fd(),
        worker.pidfd.as_fd(),
        target.pidfd.as_fd(),
        group.group.clone(),
        deadline,
    )
    .unwrap();
    assert!(guardian.is_live());
    let guardian_identity = guardian.identity().unwrap();
    assert!(guardian_identity.pid > 0);
    if frontend_lost {
        frontend.kill();
        frontend.reap_sigkill();
    } else {
        worker.kill();
        worker.reap_sigkill();
    }
    let (terminal, retirement) = guardian.finish_after_loss_observed(deadline).unwrap();
    assert_eq!(terminal.attempt_id, group.attempt);
    assert_eq!(
        terminal.trigger,
        if frontend_lost {
            GuardianTriggerV4::FrontendLost
        } else {
            GuardianTriggerV4::WorkerLost
        }
    );
    assert!(terminal.boundary_retired);
    let raw = serde_json::to_value(retirement.expect("actual native retirement bytes")).unwrap();
    assert_eq!(
        raw["cgroup_path"],
        serde_json::to_value(&group.path).unwrap()
    );
    assert!(raw["cgroup_inode"].as_u64().unwrap() > 0);
    assert!(raw["last_members"].as_array().unwrap().is_empty());
    let empty = raw["empty_monotonic_ns"].as_u64().unwrap();
    let removed = raw["removed_monotonic_ns"].as_u64().unwrap();
    assert!(empty > 0 && removed >= empty);
    assert!(!group.path.exists());
    target.reap_sigkill();
    if frontend_lost {
        // The production guardian gives this live worker bounded grace and
        // then kills its exact pidfd after frontend loss.
        worker.reap_sigkill();
    } else {
        assert!(frontend.live());
        frontend.kill();
        frontend.reap_sigkill();
    }
}

#[test]
#[ignore = "requires root and a real delegated cgroup-v2 subtree; selected explicitly by native CI"]
fn native_private_frontend_loss_retires_exact_guarded_cgroup() {
    loss(true);
}

#[test]
#[ignore = "requires root and a real delegated cgroup-v2 subtree; selected explicitly by native CI"]
fn native_private_worker_loss_retires_exact_guarded_cgroup() {
    loss(false);
}

#[test]
#[ignore = "requires root and a real delegated cgroup-v2 subtree; selected explicitly by native CI"]
fn native_private_guardian_loss_never_fabricates_cgroup_retirement() {
    let deadline = Instant::now() + Duration::from_secs(20);
    let group = NativeGroup::create(deadline);
    let mut frontend = NativeChild::paused(deadline);
    let mut worker = NativeChild::paused(deadline);
    let mut target = NativeChild::paused(deadline);
    group.attach(&target);
    let guardian = PrivateGuardian::spawn(
        group.attempt,
        frontend.pidfd.as_fd(),
        worker.pidfd.as_fd(),
        target.pidfd.as_fd(),
        group.group.clone(),
        deadline,
    )
    .unwrap();
    let before = guardian.identity().unwrap();
    let death = guardian.kill_for_probe(deadline).unwrap();
    assert_eq!(death.identity, before);
    assert_eq!(death.signal, libc::SIGKILL);
    assert!(target.live());
    assert_eq!(group.group.member_pids().unwrap(), vec![target.pid]);
    // Guardian death is an observed failure, not a cleanup receipt. The live
    // provider must perform and observe the actual remaining native retirement.
    let retirement = group
        .group
        .clone()
        .kill_and_retire_observed(deadline)
        .unwrap();
    let raw = serde_json::to_value(retirement).unwrap();
    assert!(raw["last_members"].as_array().unwrap().is_empty());
    assert!(!group.path.exists());
    target.reap_sigkill();
    for child in [&mut frontend, &mut worker] {
        assert!(child.live());
        child.kill();
        child.reap_sigkill();
    }
}
