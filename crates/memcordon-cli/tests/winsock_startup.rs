#[path = "../src/bin/consumer_readiness_windows/winsock_startup.rs"]
mod startup;
use std::{cell::Cell, rc::Rc};

#[test]
fn explicit_success_owns_exactly_one_reference_until_drop() {
    let count = Rc::new(Cell::new(0));
    let cleanup = Rc::clone(&count);
    let owner = startup::acquire(0, 0x0202, move || cleanup.set(cleanup.get() + 1)).unwrap();
    assert_eq!(count.get(), 0);
    drop(owner);
    assert_eq!(count.get(), 1);
}

#[test]
fn direct_failure_never_cleans_up_and_retains_native_source() {
    let count = Cell::new(0);
    let error = startup::acquire(10107, 0, || count.set(count.get() + 1))
        .err()
        .expect("startup fails");
    assert_eq!(count.get(), 0);
    assert!(error.to_string().contains("direct-return=10107"));
    assert!(error.to_string().contains("negotiated=None"));
    let source = std::error::Error::source(error.get_ref().unwrap()).unwrap();
    assert_eq!(
        source
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .raw_os_error(),
        Some(10107)
    );
}

#[test]
fn incompatible_success_retains_negotiation_and_balances_its_reference() {
    let count = Cell::new(0);
    let error = startup::acquire(0, 0x0101, || count.set(count.get() + 1))
        .err()
        .expect("version fails");
    assert_eq!(count.get(), 1);
    assert!(error.to_string().contains("direct-return=0"));
    assert!(error.to_string().contains("Some(257)"));
    assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    assert!(std::error::Error::source(error.get_ref().unwrap()).is_none());
    assert!(error.raw_os_error().is_none()); // Successful negotiation mismatch invents no native failure.
}
