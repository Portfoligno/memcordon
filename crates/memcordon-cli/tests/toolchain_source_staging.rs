#[path = "../src/bin/consumer_readiness_windows/toolchain_source_staging.rs"]
mod source_staging;

use source_staging::{MAX_SOURCE_BYTES, stage};
use std::fs;
use std::io::ErrorKind;
use std::time::{Duration, Instant};

#[test]
fn stages_exact_bytes_at_the_bound_without_replacing_the_destination() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("selected.rs");
    let destination = directory.path().join("library.rs");
    let bytes = vec![0x0a; MAX_SOURCE_BYTES as usize];
    fs::write(&source, &bytes).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    stage(&source, &destination, deadline).unwrap();
    assert_eq!(fs::read(&destination).unwrap(), bytes);

    fs::write(&source, b"new source bytes").unwrap();
    let error = stage(&source, &destination, deadline).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::AlreadyExists);
    assert_eq!(fs::read(&destination).unwrap(), bytes);
}

#[test]
fn over_limit_nonregular_and_expired_sources_never_create_the_destination() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("selected.rs");
    let destination = directory.path().join("library.rs");
    fs::File::create(&source)
        .unwrap()
        .set_len(MAX_SOURCE_BYTES + 1)
        .unwrap();
    let error = stage(
        &source,
        &destination,
        Instant::now() + Duration::from_secs(5),
    )
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidData);
    assert!(!destination.exists());

    assert!(
        stage(
            directory.path(),
            &destination,
            Instant::now() + Duration::from_secs(5),
        )
        .is_err()
    );
    assert!(!destination.exists());

    fs::write(&source, b"fn main() {}").unwrap();
    let error = stage(&source, &destination, Instant::now()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::TimedOut);
    assert!(!destination.exists());
}
