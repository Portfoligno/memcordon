use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

#[cfg(target_os = "linux")]
use memcordon_ci::private_supervisor::verify_recorded_process_exited;
use memcordon_ci::private_supervisor::{
    parse_linux_child_stat, supervise_private_case_process,
    supervise_private_case_process_with_observer,
};

#[test]
fn proc_identity_parser_handles_embedded_parentheses_without_pid_substitution() {
    let mut fields = vec!["S".to_owned()];
    fields.extend((0..18).map(|_| "1".to_owned()));
    fields.push("98765".to_owned());
    let stat = format!("123 (native (fixture) name) {}", fields.join(" "));
    let identity = parse_linux_child_stat(&stat, 123).unwrap();
    assert_eq!(identity.pid, 123);
    assert_eq!(identity.start_time_ticks, 98765);
    assert!(parse_linux_child_stat(&stat, 124).is_err());
    assert!(parse_linux_child_stat("123 (fixture) S 1", 123).is_err());
}

#[test]
fn supervisor_observes_real_child_exit_without_converting_it_to_case_success() {
    #[cfg(unix)]
    {
        let success =
            supervise_private_case_process(Path::new("/usr/bin/true"), &[], Duration::from_secs(3))
                .unwrap();
        assert!(success.status.success());
        assert!(success.stdout.is_empty());
        assert!(success.stderr.is_empty());
        #[cfg(target_os = "linux")]
        assert!(success.linux_child.is_some());
        #[cfg(not(target_os = "linux"))]
        assert!(success.linux_child.is_none());

        let failure = supervise_private_case_process(
            Path::new("/usr/bin/false"),
            &[],
            Duration::from_secs(3),
        )
        .unwrap();
        assert!(!failure.status.success());
        assert!(failure.stdout.is_empty());
        assert!(failure.stderr.is_empty());
        #[cfg(target_os = "linux")]
        assert!(failure.linux_child.is_some());
    }
}

#[test]
fn supervisor_rejects_unbounded_or_relative_process_specs() {
    assert!(
        supervise_private_case_process(Path::new("relative"), &[], Duration::from_secs(1)).is_err()
    );
    assert!(
        supervise_private_case_process(Path::new("/usr/bin/true"), &[], Duration::ZERO).is_err()
    );
    let arguments = vec![OsString::from("argument"); 65];
    assert!(
        supervise_private_case_process(
            Path::new("/usr/bin/true"),
            &arguments,
            Duration::from_secs(1)
        )
        .is_err()
    );
}

#[test]
#[cfg(target_os = "linux")]
fn pidfd_exit_readback_rejects_live_identity_and_accepts_retired_identity() {
    let mut child = std::process::Command::new("/bin/sleep")
        .arg("5")
        .spawn()
        .unwrap();
    let pid = child.id();
    let stat =
        std::fs::read_to_string(Path::new("/proc").join(pid.to_string()).join("stat")).unwrap();
    let identity = parse_linux_child_stat(&stat, pid).unwrap();
    assert!(verify_recorded_process_exited(identity).is_err());
    child.kill().unwrap();
    child.wait().unwrap();
    verify_recorded_process_exited(identity).unwrap();
}

#[test]
#[cfg(unix)]
fn supervisor_kills_overdue_or_output_blocked_children() {
    let overdue = supervise_private_case_process(
        Path::new("/bin/sleep"),
        &[OsString::from("2")],
        Duration::from_millis(20),
    );
    assert!(overdue.is_err());

    let output_blocked =
        supervise_private_case_process(Path::new("/usr/bin/yes"), &[], Duration::from_millis(100));
    assert!(output_blocked.is_err());
}

#[test]
#[cfg(unix)]
fn supervisor_captures_one_live_observation_before_child_exit() {
    let mut calls = 0;
    let (process, observed) = supervise_private_case_process_with_observer(
        Path::new("/bin/sleep"),
        &[OsString::from("1")],
        Duration::from_secs(3),
        || {
            calls += 1;
            Ok((calls == 2).then_some(calls))
        },
    )
    .unwrap();
    assert!(process.status.success());
    assert_eq!(observed, Some(2));
    assert_eq!(calls, 2);
}
