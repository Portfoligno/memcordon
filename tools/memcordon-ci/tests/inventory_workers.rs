use memcordon_ci::inventory_reader::BUFFER_SIZE;
use memcordon_ci::inventory_workers::{InventoryWorkers, WORKERS};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

#[cfg(windows)]
#[test]
fn native_snapshot_retains_every_digest_across_full_batches_and_tail() {
    use memcordon_ci::build_context::BuildInputSnapshot;
    use sha2::{Digest, Sha256};
    #[derive(serde::Serialize)]
    struct ExpectedInput {
        path: String,
        kind: &'static str,
        mode: u32,
        digest: String,
    }
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let mut expected = vec![ExpectedInput {
        path: hex::encode(root.as_os_str().as_encoded_bytes()),
        kind: "directory",
        mode: u32::from(root.metadata().unwrap().permissions().readonly()),
        digest: String::new(),
    }];
    for index in 0..WORKERS * 2 + 1 {
        let path = root.join(format!("input {index}.bin"));
        let bytes = vec![u8::try_from(index).unwrap(); index * 17];
        std::fs::write(&path, &bytes).unwrap();
        expected.push(ExpectedInput {
            path: hex::encode(path.canonicalize().unwrap().as_os_str().as_encoded_bytes()),
            kind: "file",
            mode: u32::from(path.metadata().unwrap().permissions().readonly()),
            digest: hex::encode(Sha256::digest(&bytes)),
        });
    }
    expected.sort_by(|left, right| left.path.cmp(&right.path));
    let serial_digest = hex::encode(Sha256::digest(serde_json::to_vec(&expected).unwrap()));
    let snapshot = BuildInputSnapshot::capture_native_tree(&root).unwrap();
    assert_eq!(snapshot.digest().unwrap(), serial_digest);
    snapshot.audit().unwrap();
    let final_path = root.join(format!("input {}.bin", WORKERS * 2));
    std::fs::write(final_path, b"changed final batch bytes").unwrap();
    assert!(snapshot.audit().is_err());
}

#[test]
fn bounded_readers_run_concurrently_and_preserve_indexed_results() {
    let barrier = Arc::new(Barrier::new(WORKERS));
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let mut pool = InventoryWorkers::new({
        let barrier = Arc::clone(&barrier);
        let active = Arc::clone(&active);
        let peak = Arc::clone(&peak);
        move |value: usize, buffer: &mut [u8]| {
            assert_eq!(buffer.len(), BUFFER_SIZE);
            let current = active.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(current, Ordering::SeqCst);
            barrier.wait();
            active.fetch_sub(1, Ordering::SeqCst);
            value
        }
    })
    .unwrap();
    let mut completed = Vec::new();
    for batch in 0..2 {
        for offset in (0..WORKERS).rev() {
            completed.extend(pool.submit(batch * WORKERS + offset, offset).unwrap());
        }
    }
    completed.extend(pool.drain().unwrap());
    completed.sort_by_key(|entry| entry.0);
    assert_eq!(
        completed,
        (0..WORKERS * 2)
            .map(|index| (index, index % WORKERS))
            .collect::<Vec<_>>()
    );
    assert_eq!(peak.load(Ordering::SeqCst), WORKERS);
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert!(pool.drain().unwrap().is_empty());
}

#[test]
fn tail_and_task_errors_preserve_every_result() {
    let mut pool = InventoryWorkers::new(|value: usize, _: &mut [u8]| {
        if value == 1 {
            Err("original file failure")
        } else {
            Ok(value)
        }
    })
    .unwrap();
    assert!(pool.submit(8, 0).unwrap().is_empty());
    assert!(pool.submit(3, 1).unwrap().is_empty());
    assert_eq!(
        pool.drain().unwrap(),
        vec![(3, Err("original file failure")), (8, Ok(0))]
    );
}

#[test]
fn task_panic_is_an_error_and_remaining_tasks_are_joined() {
    let completed = Arc::new(AtomicUsize::new(0));
    let mut pool = InventoryWorkers::new({
        let completed = Arc::clone(&completed);
        move |value: usize, _: &mut [u8]| {
            completed.fetch_add(1, Ordering::SeqCst);
            assert_ne!(value, 0, "injected worker failure");
        }
    })
    .unwrap();
    for value in 0..WORKERS - 1 {
        assert!(pool.submit(value, value).unwrap().is_empty());
    }
    let error = pool
        .submit(WORKERS - 1, WORKERS - 1)
        .and_then(|_| pool.drain())
        .unwrap_err();
    assert!(error.to_string().contains("worker panicked"));
    drop(pool);
    assert_eq!(completed.load(Ordering::SeqCst), WORKERS);
}

#[test]
fn next_file_starts_while_an_earlier_file_is_still_blocked() {
    use std::sync::{Mutex, mpsc};
    use std::time::Duration;
    let (release, wait) = mpsc::sync_channel(1);
    let wait = Arc::new(Mutex::new(wait));
    let (started, observed) = mpsc::sync_channel(1);
    let controller = std::thread::spawn(move || {
        let mut pool = InventoryWorkers::new(move |index: usize, _: &mut [u8]| {
            if index == 0 {
                wait.lock().unwrap().recv().unwrap();
            }
            if index == WORKERS {
                started.send(()).unwrap();
            }
            index
        })
        .unwrap();
        let mut results = Vec::new();
        for index in 0..=WORKERS {
            results.extend(pool.submit(index, index).unwrap());
        }
        results.extend(pool.drain().unwrap());
        results.sort_by_key(|entry| entry.0);
        results
    });
    let next_started = observed.recv_timeout(Duration::from_secs(2));
    // Always unblock and join before asserting, including a regressed batch scheduler.
    release.send(()).unwrap();
    let results = controller.join().unwrap();
    assert!(
        next_started.is_ok(),
        "next task was held behind the first task: {next_started:?}"
    );
    assert_eq!(
        results,
        (0..=WORKERS)
            .map(|index| (index, index))
            .collect::<Vec<_>>()
    );
}

#[test]
fn early_drop_joins_queued_tail_without_draining_results() {
    let completed = Arc::new(AtomicUsize::new(0));
    let mut pool = InventoryWorkers::new({
        let completed = Arc::clone(&completed);
        move |(): (), _: &mut [u8]| {
            completed.fetch_add(1, Ordering::SeqCst);
        }
    })
    .unwrap();
    for index in 0..WORKERS - 1 {
        assert!(pool.submit(index, ()).unwrap().is_empty());
    }
    drop(pool);
    assert_eq!(completed.load(Ordering::SeqCst), WORKERS - 1);
}
