#![cfg(target_os = "linux")]

mod support;

#[cfg(feature = "test-support")]
use memcordon_sealed_agent::linux::launch::FaultPoint;
use memcordon_sealed_agent::request::Lifetime;

fn run(mode: &str, lifetime: Lifetime) {
    let facts = support::execute(mode, lifetime).expect("native sealed launch must complete");
    support::assert_retired(&facts);
}

#[test]
fn sealed_direct_exit_retires_fresh_boundary() {
    run("exit", Lifetime::Command);
}

#[test]
fn sealed_child_outlives_direct_target_until_cleanup() {
    run("child", Lifetime::Command);
}

#[test]
fn sealed_double_fork_remains_in_pid_namespace_and_cgroup() {
    run("double-fork", Lifetime::Command);
}

#[test]
fn sealed_setsid_daemon_remains_contained() {
    run("setsid", Lifetime::Command);
}

#[test]
fn sealed_retained_streams_do_not_finish_before_retirement() {
    run("child", Lifetime::Workload);
}

#[test]
fn sealed_fork_storm_is_empty_before_result() {
    run("fork-storm", Lifetime::Command);
}

#[test]
fn sealed_fork_during_cleanup_cannot_survive() {
    run("fork-storm", Lifetime::Command);
}

#[test]
fn sealed_target_cannot_move_to_parent_or_sibling_cgroup() {
    run("deny-cgroup", Lifetime::Command);
}

#[test]
fn sealed_target_cannot_setns_into_host_namespace() {
    run("deny-setns", Lifetime::Command);
}

#[test]
fn sealed_target_cannot_mount_writable_cgroup_view() {
    run("deny-cgroup-mount", Lifetime::Command);
}

#[test]
fn sealed_target_inherits_only_verified_descriptors() {
    run("identity", Lifetime::Command);
}

#[test]
fn sealed_target_cannot_disable_namespace_init() {
    run("child", Lifetime::Command);
}

#[test]
#[cfg(feature = "test-support")]
fn sealed_frontend_loss_before_authorization_never_runs_target() {
    let marker = std::path::Path::new("/tmp/memcordon-sealed-preauthorization-marker");
    let _ = std::fs::remove_file(marker);
    let error = support::execute_fault("mark", FaultPoint::FrontendLossBeforeAuthorization)
        .expect_err("frontend loss must abort authorization");
    assert!(error.contains("before authorization"));
    assert!(!marker.exists(), "gated target ran before authorization");
}

#[test]
#[cfg(feature = "test-support")]
fn sealed_frontend_loss_after_authorization_triggers_guardian() {
    let error = support::execute_fault("child", FaultPoint::FrontendLossAfterAuthorization)
        .expect_err("frontend loss cannot report success");
    assert!(error.contains("after authorization"));
}

#[test]
#[cfg(feature = "test-support")]
fn sealed_provider_worker_loss_triggers_guardian() {
    let worker = unsafe { libc::fork() };
    assert!(worker >= 0);
    if worker == 0 {
        support::exit_as_provider_worker();
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(worker, &raw mut status, 0) }, worker);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 86);
    let cgroup =
        std::path::Path::new("/sys/fs/cgroup/memcordon-sealed/44444444444444444444444444444444");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while cgroup.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(
        !cgroup.exists(),
        "guardian did not retire provider-loss boundary"
    );
}

#[test]
#[cfg(feature = "test-support")]
fn sealed_guardian_loss_before_authorization_fails_closed() {
    let marker = std::path::Path::new("/tmp/memcordon-sealed-preauthorization-marker");
    let _ = std::fs::remove_file(marker);
    let error = support::execute_fault("mark", FaultPoint::GuardianLossBeforeAuthorization)
        .expect_err("guardian loss must abort authorization");
    assert!(error.contains("before authorization"));
    assert!(
        !marker.exists(),
        "target ran after preauthorization guardian loss"
    );
}

#[test]
#[cfg(feature = "test-support")]
fn sealed_guardian_loss_after_authorization_cannot_report_success() {
    let error = support::execute_fault("child", FaultPoint::GuardianLossAfterAuthorization)
        .expect_err("guardian loss cannot report success");
    assert!(error.contains("after authorization"));
}

#[test]
fn sealed_exec_failure_preserves_native_provenance() {
    let facts = support::execute("fail", Lifetime::Command).unwrap();
    assert_eq!(facts.child_status, 17);
    support::assert_retired(&facts);
}

#[test]
fn sealed_restart_uses_fresh_retired_boundary() {
    let first = support::execute("exit", Lifetime::Command).unwrap();
    let second = support::execute("exit", Lifetime::Command).unwrap();
    assert_ne!(first.target_pid, second.target_pid);
    support::assert_retired(&first);
    support::assert_retired(&second);
}

#[test]
fn sealed_simultaneous_attempts_have_disjoint_boundaries() {
    let left = std::thread::spawn(|| support::execute("child", Lifetime::Command));
    let right = std::thread::spawn(|| support::execute("child", Lifetime::Command));
    let left = left.join().unwrap().unwrap();
    let right = right.join().unwrap().unwrap();
    assert_ne!(left.target_pid, right.target_pid);
    support::assert_retired(&left);
    support::assert_retired(&right);
}
