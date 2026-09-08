use super::*;

fn snapshot() -> Snapshot {
    let digest = "01".repeat(32);
    let mut record = WindowsAttemptRecordV1::new(
        digest.clone(),
        digest.clone(),
        memcordon_core::WindowsProcessIdentityV1 {
            process_id: 1,
            creation_time_100ns: 1,
        },
        digest.clone(),
        digest,
    )
    .unwrap();
    record.record_revision = 1;
    Snapshot {
        expected_revision: 0,
        record: Box::new(record),
        completion: None,
    }
}

fn frozen_lane() -> (Lane, mpsc::Receiver<Snapshot>) {
    let (sender, receiver) = mpsc::sync_channel(PENDING_SNAPSHOTS);
    (
        Lane {
            sender,
            quarantined: Arc::new(AtomicBool::new(false)),
            pending: Arc::new(AtomicUsize::new(0)),
            completion_signal: Arc::new((Mutex::new(()), Condvar::new())),
            failure: Arc::new(Mutex::new(None)),
        },
        receiver,
    )
}

#[test]
fn frozen_writer_bounds_queue_without_claiming_commit_or_waiting_on_io() {
    let (lane, receiver) = frozen_lane();
    try_submit(&lane, snapshot()).unwrap();
    let in_flight = receiver.try_recv().unwrap();
    for _ in 0..PENDING_SNAPSHOTS {
        try_submit(&lane, snapshot()).unwrap();
    }
    assert_eq!(lane.pending.load(Ordering::Acquire), PENDING_SNAPSHOTS + 1);
    assert_eq!(
        try_submit(&lane, snapshot()).unwrap_err(),
        "attempt writer queue full"
    );
    assert_eq!(lane.pending.load(Ordering::Acquire), PENDING_SNAPSHOTS + 1);
    assert_eq!(
        in_flight.record.causal_diagnostics.durable_through_sequence,
        None
    );
    lane.quarantined.store(true, Ordering::Release);
    assert_eq!(
        try_submit(&lane, snapshot()).unwrap_err(),
        "attempt writer is quarantined"
    );
    assert_eq!(lane.pending.load(Ordering::Acquire), PENDING_SNAPSHOTS + 1);
}

#[test]
fn writer_unavailable_and_completion_contention_fail_without_pending_leaks() {
    let (lane, receiver) = frozen_lane();
    let completing = lane.completion_signal.0.lock().unwrap();
    assert_eq!(
        try_submit(&lane, snapshot()).unwrap_err(),
        "attempt writer completion is busy"
    );
    assert_eq!(lane.pending.load(Ordering::Acquire), 0);
    drop(completing);
    drop(receiver);
    assert_eq!(
        try_submit(&lane, snapshot()).unwrap_err(),
        "attempt writer unavailable"
    );
    assert_eq!(lane.pending.load(Ordering::Acquire), 0);
}

#[test]
fn cloned_lane_cannot_enqueue_after_retirement_proof() {
    let (lane, receiver) = frozen_lane();
    let registered = Arc::new(lane);
    let stale_clone = Arc::clone(&registered);
    close_lane(&registered).unwrap();
    drop(registered);
    assert_eq!(
        try_submit(&stale_clone, snapshot()).unwrap_err(),
        "attempt writer is quarantined"
    );
    assert!(receiver.try_recv().is_err());
    assert_eq!(stale_clone.pending.load(Ordering::Acquire), 0);
}

#[test]
fn retire_cannot_prove_completion_while_an_enqueue_is_in_flight() {
    let (lane, _receiver) = frozen_lane();
    try_submit(&lane, snapshot()).unwrap();
    assert!(close_lane(&lane).is_err());
    assert!(lane.quarantined.load(Ordering::Acquire));
    assert_eq!(lane.pending.load(Ordering::Acquire), 1);
}
