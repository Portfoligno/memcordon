use memcordon_ci::rehearsal_support::coordinator;
use std::fs;

#[test]
fn concurrent_negative_controls_preserve_original_and_peer_input_views() {
    #[cfg(unix)]
    let directory = tempfile::tempdir_in("/tmp").unwrap();
    #[cfg(not(unix))]
    let directory = tempfile::tempdir().unwrap();
    let envelope = directory.path().join("candidate.json");
    let payload = directory.path().join("payload.crate");
    fs::write(&envelope, b"original envelope bytes\n").unwrap();
    fs::write(&payload, b"original payload bytes\n").unwrap();
    coordinator::assert_parallel_input_isolation(directory.path()).unwrap();
    assert_eq!(fs::read(envelope).unwrap(), b"original envelope bytes\n");
    assert_eq!(fs::read(payload).unwrap(), b"original payload bytes\n");
}

#[test]
fn rehearsal_rejects_unbounded_worker_count_before_touching_inputs() {
    let nonexistent = std::path::Path::new("must-not-read-or-create");
    for jobs in [0, 3, usize::MAX] {
        let error =
            coordinator::run_with_jobs(nonexistent, nonexistent, nonexistent, nonexistent, jobs)
                .unwrap_err();
        assert_eq!(error.to_string(), "rehearsal jobs must be one or two");
    }
}
