use super::*;
use std::time::Duration;

#[test]
fn expired_prepare_never_builds_request_or_transfers_originals() {
    let original = duplicate(
        unsafe { GetCurrentProcess() },
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
        false,
    )
    .unwrap();
    let identity = process_identity(original.as_raw_handle()).unwrap();
    let retained = duplicate(
        original.as_raw_handle(),
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
        false,
    )
    .unwrap();
    let now = Instant::now();
    let snapshot = WindowsWaitObserverSnapshot {
        process: original,
        identity,
        threads: Vec::new(),
        omitted_threads: 0,
        deadline: now,
    };
    let image = File::open(std::env::current_exe().unwrap()).unwrap();
    let result = WindowsWaitObserver::prepare(
        Path::new("unselected.exe"),
        &image,
        snapshot,
        now,
        now + Duration::from_secs(1),
        |_| panic!("expired preparation must not invoke request construction"),
    );
    match result {
        Err(cause) => assert_eq!(cause.kind(), io::ErrorKind::TimedOut),
        Ok(_) => panic!("expired preparation created an observer"),
    }
    assert_eq!(
        process_identity(retained.as_raw_handle()).unwrap(),
        identity
    );
    assert!(!signaled(retained.as_raw_handle()).unwrap());
}

#[test]
fn identical_bytes_at_another_inode_do_not_attest_selected_image() {
    let root = tempfile::tempdir().unwrap();
    let first = root.path().join("selected.bin");
    let other = root.path().join("substitute.bin");
    let bytes = b"same bytes do not supply selected native identity";
    std::fs::write(&first, bytes).unwrap();
    std::fs::write(&other, bytes).unwrap();
    let first = File::open(first).unwrap();
    let other = File::open(other).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    assert!(same_image(&first, &first, deadline).is_ok());
    assert!(same_image(&first, &other, deadline).is_err());
    assert_eq!(
        same_image(&first, &first, Instant::now())
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
}
