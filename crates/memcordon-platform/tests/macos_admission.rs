#![cfg(all(target_os = "macos", feature = "test-support"))]

use memcordon_core::{CommandSpec, Policy, ReleaseEvidence, RunOutcome};
use memcordon_platform::test_support::MacosAdmission;
use memcordon_platform::{
    CallerSignalSnapshot, CancellationHandle, MacosExecutionContext, macos_continuous_nanos,
};
use std::sync::{Arc, Barrier};

#[test]
fn cancelled_supervision_with_no_helper_is_a_reportable_interruption() {
    let cancellation = CancellationHandle::new();
    cancellation.interrupt(libc::SIGINT).unwrap();
    let context = MacosExecutionContext::host_managed(
        macos_continuous_nanos().unwrap(),
        CallerSignalSnapshot::capture().unwrap(),
        cancellation,
    )
    .unwrap();
    let execution = context
        .supervise(memcordon_platform::SupervisorRequest {
            policy: Policy::unbounded(),
            restart: memcordon_core::RestartPolicy::Never,
            command: CommandSpec::new("/nonexistent-target"),
            memcordon_executable: None,
            resolved_backend: None,
        })
        .unwrap();
    assert_eq!(execution.targets_authorized(), 0);
    assert_eq!(execution.wrapper_exit_code(), 130);
    assert_eq!(execution.attempts().total, 1);
}

#[test]
fn host_cancellation_handle_cannot_own_two_contexts() {
    let cancellation = CancellationHandle::new();
    let snapshot = CallerSignalSnapshot::capture().unwrap();
    let origin = macos_continuous_nanos().unwrap();
    let context =
        MacosExecutionContext::host_managed(origin, snapshot.clone(), cancellation.clone())
            .unwrap();
    assert!(
        MacosExecutionContext::host_managed(origin, snapshot.clone(), cancellation.clone())
            .is_err()
    );
    cancellation.interrupt(libc::SIGHUP).unwrap();
    context.finish().unwrap();
    assert!(MacosExecutionContext::host_managed(origin, snapshot, cancellation).is_err());
}

#[test]
fn cancellation_before_commit_remains_sticky_across_attempts() {
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        let admission = MacosAdmission::new();
        admission.record(signal);
        admission.record(libc::SIGTERM);
        assert_eq!(admission.interruption(), Some(signal));
        assert_eq!(
            admission.commit().unwrap_err().kind(),
            std::io::ErrorKind::Interrupted
        );
        admission.next_attempt();
        assert_eq!(
            admission.commit().unwrap_err().kind(),
            std::io::ErrorKind::Interrupted
        );
        assert_eq!(admission.interruption(), Some(signal));
    }
}

#[test]
fn commit_and_cancellation_share_one_ordered_state() {
    for _ in 0..128 {
        let admission = Arc::new(MacosAdmission::new());
        let barrier = Arc::new(Barrier::new(2));
        let producer = admission.clone();
        let ready = barrier.clone();
        let thread = std::thread::spawn(move || {
            ready.wait();
            producer.record(libc::SIGINT);
        });
        barrier.wait();
        let committed = admission.commit();
        thread.join().unwrap();
        if let Err(error) = committed {
            assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
        }
        assert_eq!(admission.interruption(), Some(libc::SIGINT));
        admission.next_attempt();
        assert!(admission.commit().is_err());
    }
}

#[test]
fn committed_admission_is_not_a_second_release_permission() {
    let admission = MacosAdmission::new();
    admission.commit().unwrap();
    assert_eq!(
        admission.commit().unwrap_err().kind(),
        std::io::ErrorKind::AlreadyExists
    );
    admission.record(libc::SIGHUP);
    admission.next_attempt();
    assert_eq!(admission.interruption(), Some(libc::SIGHUP));
    assert_eq!(
        admission.commit().unwrap_err().kind(),
        std::io::ErrorKind::Interrupted
    );
}

#[test]
fn host_managed_pre_cancelled_run_never_resolves_or_creates_a_helper() {
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        let cancellation = CancellationHandle::new();
        cancellation.interrupt(signal).unwrap();
        let context = MacosExecutionContext::host_managed(
            macos_continuous_nanos().unwrap(),
            CallerSignalSnapshot::capture().unwrap(),
            cancellation,
        )
        .unwrap();
        let execution = context
            .run(
                Policy::unbounded(),
                &CommandSpec::new("/nonexistent-target"),
                std::path::Path::new("/nonexistent-helper"),
            )
            .unwrap();
        assert!(
            matches!(execution.outcome, RunOutcome::Interrupted { signal: observed, child_after_termination: None, ref cleanup } if observed.signal == signal && cleanup.direct_child_reaped && cleanup.workload_empty == Some(true) && cleanup.errors.is_empty())
        );
        assert!(execution.child_pid.is_none());
        assert!(!execution.launch.target_released);
        let runtime = execution.runtime.unwrap();
        assert_eq!(runtime.release, ReleaseEvidence::NotIssued);
        assert!(runtime.is_consistent());
    }
}

#[test]
fn owned_signal_actions_restore_in_isolated_process() {
    use std::os::fd::AsFd;

    // Keep nested libtest output out of the outer named-test success transcript,
    // while retaining the isolated fixture's failure diagnostics on stderr.
    let diagnostics = std::io::stderr().as_fd().try_clone_to_owned().unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "owned_signal_actions_fixture",
            "--test-threads=1",
        ])
        .stdout(std::process::Stdio::from(diagnostics))
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "isolated signal fixture exited {status}");
            break;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("signal fixture exceeded deadline");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
#[ignore = "isolated signal mutation fixture"]
fn owned_signal_actions_fixture() {
    unsafe extern "C" fn handler(_: i32) {}
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = handler as *const () as libc::sighandler_t;
        action.sa_flags = libc::SA_RESTART;
        unsafe {
            libc::sigemptyset(&mut action.sa_mask);
            libc::sigaddset(&mut action.sa_mask, libc::SIGUSR1);
        }
        assert_eq!(
            unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) },
            0
        );
    }
    for _ in 0..2 {
        let context = MacosExecutionContext::owned(macos_continuous_nanos().unwrap()).unwrap();
        assert!(MacosExecutionContext::owned(macos_continuous_nanos().unwrap()).is_err());
        assert!(context.interruption().is_none());
        assert_eq!(unsafe { libc::raise(libc::SIGINT) }, 0);
        assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
        assert_eq!(context.interruption(), Some(libc::SIGINT));
        context.finish().unwrap();
        for failure in [1, 2] {
            assert_eq!(
                memcordon_platform::test_support::macos_signal_installation(Some(failure), None)
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EIO)
            );
        }
        for interrupt in [0, 1, 2] {
            assert_eq!(
                memcordon_platform::test_support::macos_signal_installation(None, Some(interrupt))
                    .unwrap(),
                Some(libc::SIGINT)
            );
        }
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            let mut restored: libc::sigaction = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe { libc::sigaction(signal, std::ptr::null(), &mut restored) },
                0
            );
            assert_eq!(
                restored.sa_sigaction,
                handler as *const () as libc::sighandler_t
            );
            assert_eq!(restored.sa_flags & libc::SA_RESTART, libc::SA_RESTART);
            assert_eq!(
                unsafe { libc::sigismember(&restored.sa_mask, libc::SIGUSR1) },
                1
            );
        }
    }
}
