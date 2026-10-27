#[path = "../src/release/linux_refusal_census.rs"]
mod census;
#[path = "../src/release/linux_recovery_io.rs"]
mod recovery_io;

use std::io;
use std::time::{Duration, Instant};

fn contextual(error: census::DisappearanceFailure) -> io::Error {
    error.contextualize(
        "census-task-directory-next",
        std::path::Path::new("/proc/12/task"),
        std::path::Path::new("/proc/12"),
        recovery_io::context,
    )
}

#[test]
fn missing_requires_original_retirement() {
    let deadline = Instant::now() + Duration::from_secs(1);
    assert!(census::disappeared(io::Error::from_raw_os_error(2), deadline, || Ok(true)).is_ok());
    let survivor = contextual(
        census::disappeared(io::Error::from_raw_os_error(2), deadline, || Ok(false)).unwrap_err(),
    );
    assert_eq!(survivor.kind(), io::ErrorKind::NotFound);
    let proof = contextual(
        census::disappeared(io::Error::from_raw_os_error(2), deadline, || {
            Err(io::Error::from_raw_os_error(5))
        })
        .unwrap_err(),
    );
    let rendered = proof.to_string();
    assert!(rendered.contains("census-task-directory-next"));
    assert!(rendered.contains("census-original-pidfd-poll"));
    assert!(rendered.contains("Some(2)") && rendered.contains("Some(5)"));
    assert!(std::error::Error::source(&proof).is_some());
}

#[test]
fn other_errors_and_expiry_never_query_or_become_absence() {
    assert_eq!(
        contextual(
            census::disappeared(
                io::Error::from(io::ErrorKind::PermissionDenied),
                Instant::now() + Duration::from_secs(1),
                || panic!("permission error is not disappearance")
            )
            .unwrap_err()
        )
        .kind(),
        io::ErrorKind::PermissionDenied
    );
    let original = io::Error::from_raw_os_error(13);
    let expected_kind = original.kind();
    assert_ne!(expected_kind, io::ErrorKind::NotFound);
    let native = contextual(
        census::disappeared(original, Instant::now() + Duration::from_secs(1), || {
            panic!("native non-disappearance error must not query retirement")
        })
        .unwrap_err(),
    );
    assert_eq!(native.kind(), expected_kind);
    let mut source = std::error::Error::source(&native);
    let mut original_retained = false;
    while let Some(error) = source {
        if error
            .downcast_ref::<io::Error>()
            .is_some_and(|error| error.raw_os_error() == Some(13))
        {
            original_retained = true;
            break;
        }
        source = error.source();
    }
    assert!(
        original_retained,
        "original native error13 must remain in the source chain"
    );
    let elapsed = contextual(
        census::disappeared(io::Error::from_raw_os_error(2), Instant::now(), || {
            panic!("expired census must not query")
        })
        .unwrap_err(),
    );
    assert_eq!(elapsed.kind(), io::ErrorKind::TimedOut);
    assert!(
        elapsed
            .to_string()
            .contains("census-retirement-proof-cutoff")
    );
    assert!(elapsed.to_string().contains("Some(2)"));
}

#[test]
fn process_birth_binding_rejects_pid_reuse_without_inventing_invalid_zero() {
    assert!(census::require_same_birth(0, 0).is_ok());
    assert!(census::require_same_birth(u64::MAX, u64::MAX).is_ok());
    assert_eq!(
        census::require_same_birth(12, 13).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}
