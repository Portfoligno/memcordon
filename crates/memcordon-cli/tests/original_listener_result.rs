#[path = "../src/bin/consumer_readiness_windows/original_listener_result.rs"]
mod original;
use original::*;
use std::cell::Cell;
use std::io;
use std::io::Write;
use std::rc::Rc;

fn proof() -> CallbackProof {
    CallbackProof {
        operation: Operation::TcpListenerBind,
        version: 5,
        called: 1,
        callback_outcome: 2,
        clock_live: 1,
        raw_error_present: 1,
        raw_error: 10106,
        original_thread: 7,
        expected_thread: 7,
        started_qpc: 10,
        finished_qpc: 20,
        cutoff_qpc: 100,
        expected_cutoff_qpc: 100,
        frequency: 1000,
        expected_frequency: 1000,
    }
}

#[test]
fn original_error_is_invoked_once_and_survives_optional_retention_failure() {
    let calls = Cell::new(0);
    let mut invocation = Invocation::<()>::default();
    assert!(!invocation.invoked());
    assert!(matches!(
        invocation.invoke_once(|| {
            calls.set(calls.get() + 1);
            (Err(io::Error::from_raw_os_error(10106)), 37)
        }),
        InvokeOutcome::Returned(37)
    ));
    let witness = invocation.freeze_listener_failure(&proof()).unwrap();
    let retention: io::Result<()> = Err(io::Error::other("optional retention unavailable"));
    assert!(retention.is_err());
    assert_eq!(invocation.freeze_listener_failure(&proof()), Some(witness));
    assert_eq!(witness.api(), Operation::TcpListenerBind);
    assert_eq!(witness.raw_os_error(), 10106);
    assert!(matches!(
        invocation.invoke_once(|| {
            calls.set(99);
            (Ok(()), ())
        }),
        InvokeOutcome::AlreadyInvoked
    ));
    assert_eq!(calls.get(), 1);
    assert_eq!(
        invocation
            .take_result()
            .unwrap()
            .unwrap_err()
            .raw_os_error(),
        Some(10106)
    );
    assert!(invocation.freeze_listener_failure(&proof()).is_none());
}

#[test]
fn absent_custom_and_panicked_results_cannot_mint_original_error() {
    let mut invocation = Invocation::<()>::default();
    assert!(invocation.freeze_listener_failure(&proof()).is_none());
    assert!(invocation.take_result().is_none());
    assert!(invocation.take_panic().is_none());
    invocation.invoke_once(|| (Err(io::Error::other("10106")), ()));
    assert!(invocation.freeze_listener_failure(&proof()).is_none());
    let mut panicked = Invocation::<()>::default();
    io::stderr()
        .write_all(b"original-panic-phase: before-invoke\n")
        .expect("write fixed panic diagnostic");
    assert!(matches!(
        panicked.invoke_once(|| panic!("original panic")),
        InvokeOutcome::<()>::Panicked
    ));
    io::stderr()
        .write_all(b"original-panic-phase: after-invoke\n")
        .expect("write fixed panic diagnostic");
    assert!(panicked.freeze_listener_failure(&proof()).is_none());
    io::stderr()
        .write_all(b"original-panic-phase: after-freeze\n")
        .expect("write fixed panic diagnostic");
    let payload = panicked.take_panic().unwrap();
    io::stderr()
        .write_all(b"original-panic-phase: after-take-panic\n")
        .expect("write fixed panic diagnostic");
    assert_eq!(payload.downcast_ref::<&str>(), Some(&"original panic"));
    io::stderr()
        .write_all(b"original-panic-phase: after-downcast\n")
        .expect("write fixed panic diagnostic");
    assert!(panicked.result_ref().is_none());
    io::stderr()
        .write_all(b"original-panic-phase: test-body-end\n")
        .expect("write fixed panic diagnostic");
}

#[test]
fn contradictory_callback_operation_identity_and_clock_proofs_are_rejected() {
    let mut invocation = Invocation::<()>::default();
    invocation.invoke_once(|| (Err(io::Error::from_raw_os_error(10106)), ()));
    let mutations: &[fn(&mut CallbackProof)] = &[
        |p| p.operation = Operation::TcpStreamConnect,
        |p| p.version = 3,
        |p| p.called = 0,
        |p| p.callback_outcome = 1,
        |p| p.clock_live = 0,
        |p| p.raw_error_present = 0,
        |p| p.raw_error = 5,
        |p| p.original_thread = 0,
        |p| p.expected_thread += 1,
        |p| p.started_qpc = 0,
        |p| p.finished_qpc = 9,
        |p| p.finished_qpc = 100,
        |p| p.expected_cutoff_qpc += 1,
        |p| p.frequency = 0,
        |p| p.expected_frequency += 1,
    ];
    for mutate in mutations {
        let mut invalid = proof();
        mutate(&mut invalid);
        assert!(
            invocation.freeze_listener_failure(&invalid).is_none(),
            "{invalid:?}"
        );
    }
}

#[test]
fn original_success_keeps_the_same_owned_resource_until_taken_and_dropped() {
    struct Owned(Rc<Cell<usize>>);
    impl Drop for Owned {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let drops = Rc::new(Cell::new(0));
    let owner = Owned(drops.clone());
    let mut invocation = Invocation::default();
    invocation.invoke_once(|| (Ok(owner), ()));
    assert!(invocation.result_ref().unwrap().is_ok());
    assert!(invocation.freeze_listener_failure(&proof()).is_none());
    assert_eq!(drops.get(), 0);
    let result = invocation.take_result().unwrap();
    assert_eq!(drops.get(), 0);
    drop(result);
    assert_eq!(drops.get(), 1);
}

#[test]
fn raw_numeric_code_is_preserved_without_interpreting_internal_native_domain() {
    for code in [0, -1, 5, 10106] {
        let mut invocation = Invocation::<()>::default();
        invocation.invoke_once(|| (Err(io::Error::from_raw_os_error(code)), ()));
        let mut observed = proof();
        observed.raw_error = code;
        assert_eq!(
            invocation
                .freeze_listener_failure(&observed)
                .unwrap()
                .raw_os_error(),
            code
        );
    }
}
