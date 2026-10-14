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
            publisher_error: Arc::new(OnceLock::new()),
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
    assert!(
        try_submit(&lane, snapshot())
            .unwrap_err()
            .contains("publisher-error=unobserved")
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
    assert!(
        try_submit(&stale_clone, snapshot())
            .unwrap_err()
            .contains("publisher-error=unobserved")
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

#[test]
fn asynchronous_publisher_error_survives_one_shot_event_delivery() {
    let lane = new_lane(|_, _| {
        Err(format!(
            "publication phase=Flush: original native failure; {}",
            "界".repeat(2048)
        ))
    })
    .unwrap();
    try_submit(&lane, snapshot()).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while lane.pending.load(Ordering::Acquire) != 0 && std::time::Instant::now() < deadline {
        std::thread::yield_now();
    }
    assert_eq!(lane.pending.load(Ordering::Acquire), 0);
    assert!(lane.quarantined.load(Ordering::Acquire));
    let first = quarantine_detail(&lane);
    assert!(first.contains("publication phase=Flush: original native failure"));
    assert!(first.contains("detail-truncated=true"));
    assert!(first.len() < 2300);
    assert!(take_failure(&lane).is_some());
    assert!(take_failure(&lane).is_none());
    assert_eq!(quarantine_detail(&lane), first);
    assert!(try_submit(&lane, snapshot()).is_err());
    assert!(close_lane(&lane).is_err());
}

#[test]
fn synchronous_publisher_error_and_timeout_uncertainty_remain_distinct() {
    let lane = new_lane(|_, _| Err("publication phase=Rename: native failure".into())).unwrap();
    let (completion, receiver) = mpsc::sync_channel(1);
    let mut value = snapshot();
    value.completion = Some(completion);
    try_submit(&lane, value).unwrap();
    assert_eq!(
        receiver
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap_err(),
        "publication phase=Rename: native failure"
    );
    let first = quarantine_detail(&lane);
    take_failure(&lane);
    assert_eq!(quarantine_detail(&lane), first);
    let (uncertain, _receiver) = frozen_lane();
    uncertain.quarantined.store(true, Ordering::Release);
    assert!(quarantine_detail(&uncertain).contains("publisher-error=unobserved"));
    assert!(!quarantine_detail(&uncertain).contains("first-publisher-error="));
    assert!(close_lane(&uncertain).is_err());
}

#[test]
fn late_publisher_failure_remains_visible_after_timeout_quarantine() {
    let (started, observed) = mpsc::sync_channel(1);
    let (release, blocked) = mpsc::sync_channel(1);
    let lane = new_lane(move |_, _| {
        started.send(()).unwrap();
        blocked.recv_timeout(Duration::from_secs(2)).unwrap();
        super::super::diagnostics::capture(memcordon_core::CausalEventV1 {
            sequence: 0,
            origin: memcordon_core::DiagnosticOriginV1::RecordWriter,
            category: memcordon_core::FailureCategoryV1::Persistence,
            operation: memcordon_core::FailureOperationV1::StoreRecord,
            code: memcordon_core::FailureCodeV1::RecordIo,
            native_code: Some(memcordon_core::NativeFailureCodeV1::Win32(5)),
            observed_phase: memcordon_core::AttemptObservationPhaseV1::Terminalizing,
            safe_detail: memcordon_core::SafeDiagnosticDetailV1::ProviderMessage {
                id: memcordon_core::SafeMessageIdV1::CommitNotConfirmed,
            },
            detail_redacted: true,
            detail_truncated: false,
            terminalization_reference: None,
        });
        Err("publication phase=Flush: late denied native failure".into())
    })
    .unwrap();
    try_submit(&lane, snapshot()).unwrap();
    observed.recv_timeout(Duration::from_secs(2)).unwrap();
    lane.quarantined.store(true, Ordering::Release);
    assert!(quarantine_detail(&lane).contains("publisher-error=unobserved"));
    assert_eq!(lane.pending.load(Ordering::Acquire), 1);
    release.send(()).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while lane.pending.load(Ordering::Acquire) != 0 && std::time::Instant::now() < deadline {
        let _ = quarantine_detail(&lane);
        std::thread::yield_now();
    }
    assert_eq!(lane.pending.load(Ordering::Acquire), 0);
    let retained = quarantine_detail(&lane);
    assert!(retained.starts_with("native-code=Some(Win32(5))"));
    assert!(retained.contains("publication phase=Flush: late denied native failure"));
    take_failure(&lane);
    assert_eq!(quarantine_detail(&lane), retained);
    assert!(lane.quarantined.load(Ordering::Acquire));
    assert!(close_lane(&lane).is_err());
}

#[test]
fn post_cleanup_handoff_drains_before_loading_and_submitting_next_revision() {
    let mut initial = snapshot().record;
    initial.record_revision = 1;
    let durable = Arc::new(Mutex::new(*initial));
    let published = Arc::clone(&durable);
    let (started, observed) = mpsc::sync_channel(1);
    let (release, blocked) = mpsc::sync_channel(1);
    let mut first = true;
    let lane = new_lane(move |record, expected| {
        if first {
            first = false;
            started.send(()).unwrap();
            blocked.recv_timeout(Duration::from_secs(2)).unwrap();
        }
        let mut durable = published.lock().unwrap();
        assert_eq!(durable.record_revision, expected);
        assert_eq!(record.record_revision, expected + 1);
        *durable = record.clone();
        Ok(())
    })
    .unwrap();
    let mut cleanup = durable.lock().unwrap().clone();
    cleanup.record_revision = 2;
    cleanup.cleanup_state.guardian_reaped = true;
    try_submit(
        &lane,
        Snapshot {
            expected_revision: 1,
            record: Box::new(cleanup),
            completion: None,
        },
    )
    .unwrap();
    observed.recv_timeout(Duration::from_secs(2)).unwrap();
    let owner_lane = Arc::clone(&lane);
    let owner_durable = Arc::clone(&durable);
    let (entered, entering) = mpsc::sync_channel(1);
    let (loaded, loading) = mpsc::sync_channel(1);
    let owner = std::thread::spawn(move || {
        wait_for_lane_observed(&owner_lane, "same-owner-fixture", || {
            let _ = entered.try_send(());
        })
        .unwrap();
        let mut current = owner_durable.lock().unwrap().clone();
        loaded.send(current.record_revision).unwrap();
        assert!(current.cleanup_state.guardian_reaped);
        let expected_revision = current.record_revision;
        current.record_revision += 1;
        current.causal_diagnostics.loss.writer_unavailable = true;
        let (completion, done) = mpsc::sync_channel(1);
        try_submit(
            &owner_lane,
            Snapshot {
                expected_revision,
                record: Box::new(current),
                completion: Some(completion),
            },
        )
        .unwrap();
        done.recv_timeout(Duration::from_secs(2)).unwrap().unwrap();
    });
    entering.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(matches!(loading.try_recv(), Err(mpsc::TryRecvError::Empty)));
    assert_eq!(durable.lock().unwrap().record_revision, 1);
    release.send(()).unwrap();
    assert_eq!(loading.recv_timeout(Duration::from_secs(2)).unwrap(), 2);
    owner.join().unwrap();
    assert_eq!(durable.lock().unwrap().record_revision, 3);
    assert!(durable.lock().unwrap().cleanup_state.guardian_reaped);
    assert!(
        durable
            .lock()
            .unwrap()
            .causal_diagnostics
            .loss
            .writer_unavailable
    );
    assert!(!lane.quarantined.load(Ordering::Acquire));
}
