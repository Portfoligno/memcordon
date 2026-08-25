#![cfg(all(target_os = "linux", feature = "test-support"))]

use crate::linux::launch::{
    decode_namespace_startup_record_for_test, namespace_startup_failure_record_for_test,
    namespace_startup_ready_record_for_test, target_after_startup_ready_for_test,
};
use crate::linux::namespace::NamespaceInitPhase;

#[test]
fn namespace_startup_failure_preserves_phase_and_native_errno() {
    for phase in [
        NamespaceInitPhase::MountIsolation,
        NamespaceInitPhase::CgroupViewIsolation,
        NamespaceInitPhase::ProcMount,
        NamespaceInitPhase::ChildSubreaper,
        NamespaceInitPhase::TargetFork,
    ] {
        let record = namespace_startup_failure_record_for_test(phase, libc::EACCES);
        let error = decode_namespace_startup_record_for_test(&record)
            .unwrap()
            .expect("failure record must retain an error");
        assert_eq!(error.phase, phase);
        assert_eq!(error.os_code, libc::EACCES);
    }
}

#[test]
fn namespace_startup_ready_record_is_exact() {
    let record = namespace_startup_ready_record_for_test();
    assert_eq!(decode_namespace_startup_record_for_test(&record), Ok(None));
}

#[test]
fn gated_target_is_ineligible_until_typed_startup_readiness() {
    let init_pid = 100;
    let members = [init_pid, 101];
    assert_eq!(
        target_after_startup_ready_for_test(false, init_pid, &members),
        None
    );
    assert_eq!(
        target_after_startup_ready_for_test(true, init_pid, &members),
        Some(101)
    );
}

#[test]
fn namespace_startup_parser_rejects_malformed_or_unproven_records() {
    let valid =
        namespace_startup_failure_record_for_test(NamespaceInitPhase::TargetFork, libc::EAGAIN);
    for record in [
        &valid[..valid.len() - 1],
        &[2, 2, 5, 0, 0, 0, 0, 1],
        &[1, 9, 5, 0, 0, 0, 0, 1],
        &[1, 2, 9, 0, 0, 0, 0, 1],
        &[1, 2, 5, 1, 0, 0, 0, 1],
        &[1, 2, 5, 0, 0, 0, 0, 0],
        &[1, 1, 5, 0, 0, 0, 0, 1],
    ] {
        assert!(decode_namespace_startup_record_for_test(record).is_err());
    }
}
