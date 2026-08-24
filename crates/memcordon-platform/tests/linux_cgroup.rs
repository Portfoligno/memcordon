#![cfg(all(target_os = "linux", feature = "test-support"))]

use std::fs;

use memcordon_core::BoundaryRequirement;
use memcordon_platform::test_support::{
    linux_configure, linux_launcher_status, linux_launcher_status_timeout,
    linux_limit_delta_is_authoritative, linux_monitor_errors, linux_probe_from_results,
    linux_verify,
};

fn status(kind: u8, errno: i32) -> [u8; 12] {
    let mut record = [0_u8; 12];
    record[..4].copy_from_slice(b"MCLS");
    record[4] = 1;
    record[5] = kind;
    record[8..].copy_from_slice(&errno.to_ne_bytes());
    record
}

#[test]
fn limit_evidence_requires_counter_delta() {
    assert!(linux_limit_delta_is_authoritative());
}

#[test]
fn cgroup_controls_are_written_exactly() {
    let temporary = tempfile::tempdir().expect("temporary cgroup should exist");
    for control in ["memory.oom.group", "memory.max", "memory.swap.max"] {
        fs::write(temporary.path().join(control), b"").expect("control should exist");
    }
    let expected = 192 * 1024 * 1024;
    linux_configure(temporary.path(), expected).expect("controls should configure");
    assert_eq!(
        fs::read_to_string(temporary.path().join("memory.max")).expect("memory.max"),
        format!("{expected}\n")
    );
    assert_eq!(
        fs::read_to_string(temporary.path().join("memory.swap.max")).expect("memory.swap.max"),
        "0\n"
    );
    assert_eq!(
        fs::read_to_string(temporary.path().join("memory.oom.group")).expect("memory.oom.group"),
        "1\n"
    );
}

#[test]
fn monitor_file_errors_are_reported_instead_of_treated_as_success() {
    let temporary = tempfile::tempdir().expect("temporary cgroup should exist");
    assert!(linux_monitor_errors(temporary.path()));
}

#[test]
fn cgroup_identity_verification_rejects_the_wrong_process() {
    let temporary = tempfile::tempdir().expect("temporary cgroup should exist");
    fs::write(temporary.path().join("cgroup.procs"), "41\n42\n").expect("membership should write");
    linux_verify(temporary.path(), 42).expect("member should verify");
    assert!(linux_verify(temporary.path(), 43).is_err());
}

#[test]
fn launcher_status_requires_ready_then_eof_or_error() {
    assert_eq!(
        linux_launcher_status(&status(1, 0)).expect("clean exec"),
        None
    );
    let mut failed = status(1, 0).to_vec();
    failed.extend(status(2, libc::ENOENT));
    assert_eq!(
        linux_launcher_status(&failed).expect("exec error record"),
        Some(libc::ENOENT)
    );
    assert!(linux_launcher_status(&[]).is_err());
    assert!(linux_launcher_status(&status(2, libc::EIO)).is_err());
}

#[test]
fn launcher_status_rejects_malformed_and_trailing_records() {
    let ready = status(1, 0);
    for malformed in [
        {
            let mut value = ready;
            value[0] = b'X';
            value.to_vec()
        },
        {
            let mut value = ready;
            value[4] = 2;
            value.to_vec()
        },
        {
            let mut value = ready;
            value[6] = 1;
            value.to_vec()
        },
        status(3, 0).to_vec(),
        status(1, libc::EIO).to_vec(),
        ready[..11].to_vec(),
        [ready.as_slice(), ready.as_slice()].concat(),
        [
            ready.as_slice(),
            status(2, libc::EIO).as_slice(),
            ready.as_slice(),
        ]
        .concat(),
    ] {
        assert!(linux_launcher_status(&malformed).is_err());
    }
}

#[test]
fn launcher_status_reports_a_live_incomplete_stream_as_timeout() {
    assert_eq!(
        linux_launcher_status_timeout(),
        std::io::ErrorKind::TimedOut
    );
}

#[test]
fn qualified_provider_is_selected_without_caller_delegation() {
    let report = linux_probe_from_results(
        Err("caller cgroup is not delegated".to_owned()),
        Ok(("provider-v1".to_owned(), "ab".repeat(32))),
    );
    assert!(report.selected.is_none());
    let sealed = report
        .selected_for(BoundaryRequirement::Sealed)
        .expect("qualified independent provider must satisfy sealed selection");
    assert_eq!(sealed.name, "linux-sealed-provider");
    assert_eq!(report.available.len(), 1);
    assert_eq!(report.unavailable.len(), 1);
    assert_eq!(report.unavailable[0].name, "linux-cgroup-v2");
    assert_eq!(
        report.unavailable[0].reason,
        "caller cgroup is not delegated"
    );
    assert!(report.selected_for(BoundaryRequirement::Standard).is_none());
}

#[test]
fn unavailable_provider_never_promotes_sealed_capability() {
    let report = linux_probe_from_results(
        Ok(()),
        Err("provider endpoint permission denied".to_owned()),
    );
    assert_eq!(
        report
            .selected_for(BoundaryRequirement::Standard)
            .expect("standard backend remains available")
            .name,
        "linux-cgroup-v2"
    );
    assert!(report.selected_for(BoundaryRequirement::Sealed).is_none());
    assert!(report.unavailable.iter().any(|backend| {
        backend.name == "linux-sealed-provider"
            && backend.reason == "provider endpoint permission denied"
    }));
}

#[test]
fn standard_and_sealed_selection_remain_independent_when_both_are_available() {
    let report = linux_probe_from_results(Ok(()), Ok(("provider-v1".to_owned(), "cd".repeat(32))));
    assert_eq!(report.selected.as_ref().unwrap().name, "linux-cgroup-v2");
    assert_eq!(
        report
            .selected_for(BoundaryRequirement::Standard)
            .unwrap()
            .name,
        "linux-cgroup-v2"
    );
    assert_eq!(
        report
            .selected_for(BoundaryRequirement::Sealed)
            .unwrap()
            .name,
        "linux-sealed-provider"
    );
}
