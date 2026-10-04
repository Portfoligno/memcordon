#![cfg(target_os = "linux")]

use crate::linux::descriptor_custody::{
    ExpectedGatedDescriptorInventory, ExpectedPrivateExecState, PrivateExecObserver,
    provider_owned_byte_pipes, verify_pipe_end, verify_private_gated_descriptor_inventory,
};
use crate::linux::execution_identity::{ResolvedTargetIdentity, apply_target_identity};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

#[test]
fn provider_owned_pipes_relay_bytes_without_frontend_descriptor_inheritance() {
    let (target, provider) = provider_owned_byte_pipes().unwrap();
    target.verify_native_directions().unwrap();
    assert!(verify_pipe_end(target.stdin_fd().as_raw_fd(), libc::O_WRONLY).is_err());
    assert!(verify_pipe_end(target.stdout_fd().as_raw_fd(), libc::O_RDONLY).is_err());
    let mut relay = provider.into_relay_streams();

    let source = b"private stdin bytes";
    let (mut frontend, mut frontend_peer) = UnixStream::pair().unwrap();
    frontend_peer.write_all(source).unwrap();
    frontend_peer.shutdown(Shutdown::Write).unwrap();
    assert_eq!(
        relay.copy_stdin_from(&mut frontend).unwrap(),
        source.len() as u64
    );
    let mut target_stdin = std::fs::File::from(target.stdin_fd().try_clone_to_owned().unwrap());
    let mut received = vec![0_u8; source.len()];
    target_stdin.read_exact(&mut received).unwrap();
    assert_eq!(received, source);
    assert_eq!(target_stdin.read(&mut [0_u8; 1]).unwrap(), 0);

    let stdout = b"private stdout bytes";
    let mut target_stdout = std::fs::File::from(target.stdout_fd().try_clone_to_owned().unwrap());
    target_stdout.write_all(stdout).unwrap();
    let mut captured = vec![0_u8; stdout.len()];
    relay.stdout_reader.read_exact(&mut captured).unwrap();
    assert_eq!(captured, stdout);

    let stderr = b"private stderr bytes";
    let mut target_stderr = std::fs::File::from(target.stderr_fd().try_clone_to_owned().unwrap());
    target_stderr.write_all(stderr).unwrap();
    let mut captured = vec![0_u8; stderr.len()];
    relay.stderr_reader.read_exact(&mut captured).unwrap();
    assert_eq!(captured, stderr);
}

#[test]
fn socket_valued_frontend_stdio_is_not_a_target_pipe() {
    let (frontend, _peer) = UnixStream::pair().unwrap();
    assert!(verify_pipe_end(frontend.as_raw_fd(), libc::O_RDONLY).is_err());
    assert!(verify_pipe_end(frontend.as_raw_fd(), libc::O_WRONLY).is_err());
    let (target, provider) = provider_owned_byte_pipes().unwrap();
    target.verify_native_directions().unwrap();
    drop((frontend, target, provider));
}

#[test]
fn gated_verifier_rejects_a_process_with_extra_descriptors() {
    let (target, _provider) = provider_owned_byte_pipes().unwrap();
    let mut raw = [-1_i32; 2];
    // SAFETY: socketpair initializes both slots on success; each descriptor is
    // transferred to exactly one OwnedFd below.
    assert_eq!(
        unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                raw.as_mut_ptr(),
            )
        },
        0
    );
    // SAFETY: successful socketpair returned two separately owned descriptors.
    let control = unsafe { OwnedFd::from_raw_fd(raw[0]) };
    // SAFETY: successful socketpair returned two separately owned descriptors.
    let child_control = unsafe { OwnedFd::from_raw_fd(raw[1]) };
    let elf = std::fs::File::open("/proc/self/exe").unwrap();
    let expected = ExpectedGatedDescriptorInventory::capture(
        &target,
        control.as_fd(),
        child_control.as_fd(),
        elf.as_fd(),
    )
    .unwrap();
    assert!(
        verify_private_gated_descriptor_inventory(std::process::id() as i32, expected).is_err()
    );
    drop(control);
}

struct TraceChild {
    pid: libc::pid_t,
    pidfd: OwnedFd,
    reaped: bool,
}

impl TraceChild {
    fn wait(&mut self, deadline: Instant) -> i32 {
        loop {
            let mut status = 0;
            // SAFETY: this fixture retains exclusive wait ownership of its child.
            let waited =
                unsafe { libc::waitpid(self.pid, &raw mut status, libc::__WALL | libc::WNOHANG) };
            if waited == self.pid {
                assert!(libc::WIFEXITED(status) || libc::WIFSIGNALED(status));
                self.reaped = true;
                return status;
            }
            assert!(
                waited == 0
                    || std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
            );
            assert!(
                Instant::now() < deadline,
                "owned native child did not retire"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

impl Drop for TraceChild {
    fn drop(&mut self) {
        if !self.reaped {
            // SAFETY: the held pidfd names this exact unreaped fixture child.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
            let _ = self.wait(Instant::now() + Duration::from_secs(5));
        }
    }
}

fn traced_fixture(
    mode: TraceFixtureMode,
) -> (
    TraceChild,
    PrivateExecObserver,
    crate::linux::descriptor_custody::ProviderRelayStreams,
) {
    // These fixtures deliberately exercise the real credential transition and
    // kernel ptrace/procfs policy. A nonroot run is not a successful substitute.
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "native credential/ptrace fixture requires root"
    );
    let identity = ResolvedTargetIdentity::for_native_test(65534, 65534).unwrap();
    let (stdio, pipes) = provider_owned_byte_pipes().unwrap();
    let elf = std::fs::File::open("/usr/bin/printf").unwrap();
    let expected =
        ExpectedPrivateExecState::capture(elf.as_fd(), &stdio, identity.clone()).unwrap();
    let program = c"printf";
    let marker = c"entered";
    let argv = [program.as_ptr(), marker.as_ptr(), std::ptr::null()];
    let environment = [std::ptr::null::<libc::c_char>()];
    // SAFETY: the child is a trusted test setup stub and never returns to the
    // multithreaded harness. All argument storage is prepared before fork.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        unsafe {
            if libc::ptrace(
                libc::PTRACE_TRACEME,
                0,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            ) == -1
                || libc::raise(libc::SIGSTOP) != 0
            {
                libc::_exit(125);
            }
        }
        if matches!(mode, TraceFixtureMode::Exit) {
            unsafe { libc::_exit(42) };
        }
        if matches!(mode, TraceFixtureMode::UnexpectedStop) {
            unsafe {
                libc::raise(libc::SIGSTOP);
                libc::_exit(43);
            }
        }
        if stdio.install_at_standard_fds().is_err() || apply_target_identity(&identity).is_err() {
            unsafe { libc::_exit(125) };
        }
        unsafe {
            if libc::dup2(elf.as_raw_fd(), 3) != 3
                || libc::fcntl(3, libc::F_SETFD, libc::FD_CLOEXEC) != 0
                || libc::syscall(libc::SYS_close_range, 4_u32, u32::MAX, 0_u32) != 0
            {
                libc::_exit(125);
            }
            libc::syscall(
                libc::SYS_execveat,
                3,
                c"".as_ptr(),
                argv.as_ptr(),
                environment.as_ptr(),
                libc::AT_EMPTY_PATH,
            );
            libc::_exit(126);
        }
    }
    drop(stdio);
    // SAFETY: pid is the fixture's direct child, stopped before any exec.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    assert!(raw >= 0);
    let child = TraceChild {
        pid,
        pidfd: unsafe { OwnedFd::from_raw_fd(raw) },
        reaped: false,
    };
    let observer = PrivateExecObserver::observe_initial_stop(
        pid,
        child.pidfd.as_fd(),
        expected,
        Instant::now() + Duration::from_secs(5),
    )
    .unwrap();
    (child, observer, pipes.into_relay_streams())
}

#[test]
#[ignore = "requires native Linux root, real credential transition and ptrace/procfs access"]
fn native_exec_stop_precedes_first_target_instruction_and_detach_releases_it() {
    let (mut child, mut observer, mut relay) = traced_fixture(TraceFixtureMode::Exec);
    let proof = observer
        .observe_exec_and_detach_with_observer(Instant::now() + Duration::from_secs(5), || {
            let mut pipe = libc::pollfd {
                fd: relay.stdout_reader.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // The actual executable cannot write its first marker at the kernel
            // exec-event stop, even after a deliberate observer delay.
            assert_eq!(unsafe { libc::poll(&raw mut pipe, 1, 50) }, 0);
        })
        .unwrap();
    assert_eq!(proof.pid(), child.pid);
    let status = child.wait(Instant::now() + Duration::from_secs(5));
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
    let mut output = Vec::new();
    relay.stdout_reader.read_to_end(&mut output).unwrap();
    assert_eq!(output, b"entered");
}

#[test]
#[ignore = "requires native Linux root and ptrace"]
fn native_trusted_exit_and_eof_do_not_substitute_for_exec_event() {
    let (mut child, mut observer, _relay) = traced_fixture(TraceFixtureMode::Exit);
    let failure = observer
        .observe_exec_and_detach(Some(Instant::now() + Duration::from_secs(5)))
        .err()
        .expect("trusted exit must fail without an exec event");
    assert!(failure.to_string().contains("without an exec event"));
    // The observer consumed the real terminal status while rejecting it.
    child.reaped = true;
}

#[derive(Clone, Copy)]
enum TraceFixtureMode {
    Exec,
    Exit,
    UnexpectedStop,
}

#[test]
#[ignore = "requires native Linux root and ptrace"]
fn native_unexpected_stop_fails_and_owned_drop_kills_then_reaps_exact_child() {
    let (mut child, mut observer, _relay) = traced_fixture(TraceFixtureMode::UnexpectedStop);
    let error = observer
        .observe_exec_and_detach(Some(Instant::now() + Duration::from_secs(5)))
        .err()
        .expect("a signal stop must not become an exec observation");
    assert!(error.to_string().contains("unexpected native stop"));
    drop(observer);
    let status = child.wait(Instant::now() + Duration::from_secs(5));
    assert!(libc::WIFSIGNALED(status));
    assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
}

#[test]
#[ignore = "requires native Linux root, ptrace and an isolated subreaper fixture"]
fn native_tracer_death_exitkill_retires_trusted_child_before_exec() {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command.args([
        "--exact",
        "native_descriptor_custody::trace_owner_exitkill_fixture",
        "--ignored",
        "--test-threads=1",
        "--nocapture",
    ]);
    let output = memcordon_testkit::run_with_deadline_output_limit(
        &mut command,
        Duration::from_secs(15),
        16 * 1024,
    )
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
}

#[test]
#[ignore = "isolated native child fixture; selected only by native_tracer_death test"]
fn trace_owner_exitkill_fixture() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    // This process is the isolated fixture created above. Subreaper ownership
    // ensures it can actually reap the target orphaned by abrupt tracer death.
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
        0
    );
    let mut raw = [-1; 2];
    assert_eq!(unsafe { libc::pipe2(raw.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    let read = unsafe { OwnedFd::from_raw_fd(raw[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(raw[1]) };
    let tracer_pid = unsafe { libc::fork() };
    assert!(tracer_pid >= 0);
    if tracer_pid == 0 {
        drop(read);
        let (child, _observer, _relay) = traced_fixture(TraceFixtureMode::UnexpectedStop);
        let pid = child.pid.to_be_bytes();
        if unsafe { libc::write(write.as_raw_fd(), pid.as_ptr().cast(), pid.len()) }
            != pid.len() as isize
        {
            unsafe { libc::_exit(125) };
        }
        // No destructor, explicit kill or reap runs in the dying tracer.
        unsafe { libc::_exit(77) };
    }
    drop(write);
    let tracer_raw_pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, tracer_pid, 0) } as i32;
    assert!(tracer_raw_pidfd >= 0);
    let mut tracer = TraceChild {
        pid: tracer_pid,
        pidfd: unsafe { OwnedFd::from_raw_fd(tracer_raw_pidfd) },
        reaped: false,
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut readiness = libc::pollfd {
        fd: read.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert!(unsafe { libc::poll(&raw mut readiness, 1, 5000) } > 0);
    let mut bytes = [0; std::mem::size_of::<libc::pid_t>()];
    std::fs::File::from(read).read_exact(&mut bytes).unwrap();
    let target_pid = libc::pid_t::from_be_bytes(bytes);
    assert!(target_pid > 0 && target_pid != tracer_pid);
    let status = tracer.wait(deadline);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 77);
    loop {
        let mut target_status = 0;
        let waited = unsafe { libc::waitpid(target_pid, &raw mut target_status, libc::WNOHANG) };
        if waited == target_pid {
            assert!(libc::WIFSIGNALED(target_status));
            assert_eq!(libc::WTERMSIG(target_status), libc::SIGKILL);
            break;
        }
        assert!(
            waited == 0
                || std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
        );
        assert!(
            Instant::now() < deadline,
            "EXITKILL target was not killed and reaped"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}
