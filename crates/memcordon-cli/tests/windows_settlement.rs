#[path = "../src/bin/memcordon-sealed-agent/windows/settlement.rs"]
mod settlement;

use settlement::SettlementGate;
use std::sync::{Arc, Barrier, mpsc};
use std::time::{Duration, Instant};

#[test]
fn job_retirement_does_not_authorize_recovery_before_terminal_acknowledgment() {
    let gate = Arc::new(SettlementGate::default());
    let worker = gate.enter().unwrap();
    let cleanup_gate = Arc::clone(&gate);
    let (attempted, attempts) = mpsc::channel();
    let (recovered, recovery) = mpsc::channel();
    let cleanup = std::thread::spawn(move || {
        let _exclusive = cleanup_gate
            .settle_until(Instant::now() + Duration::from_secs(2), || {
                attempted.send(()).unwrap();
                // Native Job handles and the durable admission have retired.
                Ok(true)
            })
            .unwrap();
        recovered.send(()).unwrap();
    });
    attempts.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(recovery.try_recv().is_err());
    // The same worker still owns final publication, rejection staging if needed,
    // and terminal acknowledgment after native Job retirement.
    drop(worker);
    recovery.recv_timeout(Duration::from_secs(1)).unwrap();
    cleanup.join().unwrap();
}

#[test]
fn admitted_worker_can_start_and_settle_while_cleanup_drives_convergence() {
    let gate = Arc::new(SettlementGate::default());
    let admitted = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let cleanup_gate = Arc::clone(&gate);
    let cleanup_admitted = Arc::clone(&admitted);
    let (attempted, attempts) = mpsc::channel();
    let cleanup = std::thread::spawn(move || {
        let _exclusive = cleanup_gate
            .settle_until(Instant::now() + Duration::from_secs(2), || {
                attempted.send(()).unwrap();
                Ok(!cleanup_admitted.load(std::sync::atomic::Ordering::SeqCst))
            })
            .unwrap();
    });
    attempts.recv_timeout(Duration::from_secs(1)).unwrap();
    let worker = gate.enter().unwrap();
    admitted.store(false, std::sync::atomic::Ordering::SeqCst);
    drop(worker);
    cleanup.join().unwrap();
}

#[test]
fn recovery_lease_excludes_replay_writes_until_inventory_completes() {
    let gate = Arc::new(SettlementGate::default());
    let recovery = gate.settle_until(Instant::now(), || Ok(true)).unwrap();
    let replay_gate = Arc::clone(&gate);
    let barrier = Arc::new(Barrier::new(2));
    let replay_barrier = Arc::clone(&barrier);
    let (entered, entry) = mpsc::channel();
    let replay = std::thread::spawn(move || {
        replay_barrier.wait();
        let _worker = replay_gate.enter().unwrap();
        entered.send(()).unwrap();
    });
    barrier.wait();
    assert!(entry.try_recv().is_err());
    drop(recovery);
    entry.recv_timeout(Duration::from_secs(1)).unwrap();
    replay.join().unwrap();
}

#[test]
fn unsettled_writer_times_out_without_entering_recovery() {
    let gate = SettlementGate::default();
    let _worker = gate.enter().unwrap();
    let error = gate.settle_until(Instant::now(), || Ok(true)).unwrap_err();
    assert!(error.contains("phase=wait-launcher-settlement"));
}

#[test]
fn worker_unwind_releases_liveness_for_durable_recovery() {
    let gate = Arc::new(SettlementGate::default());
    let worker_gate = Arc::clone(&gate);
    assert!(
        std::thread::spawn(move || {
            let _worker = worker_gate.enter().unwrap();
            panic!("simulate worker failure retaining durable outbox");
        })
        .join()
        .is_err()
    );
    let _recovery = gate.settle_until(Instant::now(), || Ok(true)).unwrap();
}

#[test]
fn failed_recovery_poison_prevents_new_writers() {
    let gate = Arc::new(SettlementGate::default());
    let recovery_gate = Arc::clone(&gate);
    assert!(
        std::thread::spawn(move || {
            let _recovery = recovery_gate
                .settle_until(Instant::now(), || Ok(true))
                .unwrap();
            panic!("simulate interrupted recovery");
        })
        .join()
        .is_err()
    );
    assert!(gate.enter().is_err());
    assert!(gate.settle_until(Instant::now(), || Ok(true)).is_err());
}
