use memcordon_ci::inventory_reader::BUFFER_SIZE;
use memcordon_ci::inventory_workers::{CAPACITY, InventoryWorkers, WORKERS};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

#[test]
fn idle_preparation_capacity_serves_reads_without_growing_the_pipeline_budget() {
    use memcordon_ci::inventory_workers::InventoryExecutor;
    use std::sync::{Condvar, Mutex, mpsc};
    use std::time::Duration;

    let executor = InventoryExecutor::native_pipeline().unwrap();
    let mut preparation = InventoryWorkers::with_executor(Arc::clone(&executor), |value, _| value);
    assert_eq!(preparation.map_ordered(["prepared"]).unwrap(), ["prepared"]);
    let released = Arc::new((Mutex::new(false), Condvar::new()));
    let (started, observed) = mpsc::channel();
    let mut reads = InventoryWorkers::with_executor(executor, {
        let released = Arc::clone(&released);
        move |value, buffer| {
            assert_eq!(buffer.len(), BUFFER_SIZE);
            started.send(()).unwrap();
            let (lock, wake) = &*released;
            let mut ready = lock.lock().unwrap();
            while !*ready {
                ready = wake.wait(ready).unwrap();
            }
            value
        }
    });
    // This exceeds one stage's former reservation while staying below its
    // unchanged admission capacity. No read may complete before the assertion.
    for index in 0..WORKERS + 1 {
        assert!(reads.submit(index, index).unwrap().is_empty());
    }
    let borrowed_idle_capacity =
        (0..WORKERS + 1).all(|_| observed.recv_timeout(Duration::from_secs(5)).is_ok());
    let (lock, wake) = &*released;
    *lock.lock().unwrap() = true;
    wake.notify_all();
    let completed = reads.drain().unwrap();
    assert!(
        borrowed_idle_capacity,
        "idle resolver threads must service queued reads"
    );
    assert_eq!(
        completed,
        (0..WORKERS + 1)
            .map(|index| (index, index))
            .collect::<Vec<_>>()
    );
    drop(reads);
    assert_eq!(
        preparation.map_ordered(["next directory"]).unwrap(),
        ["next directory"]
    );
}

#[test]
fn shared_stage_drop_settles_its_tail_and_preserves_other_stage_errors() {
    use memcordon_ci::inventory_workers::InventoryExecutor;
    let executor = InventoryExecutor::native_pipeline().unwrap();
    let completed = Arc::new(AtomicUsize::new(0));
    let mut first = InventoryWorkers::with_executor(Arc::clone(&executor), {
        let completed = Arc::clone(&completed);
        move |_: usize, _| {
            completed.fetch_add(1, Ordering::SeqCst);
        }
    });
    let mut second = InventoryWorkers::with_executor(executor, |value, _| {
        if value == 1 {
            Err("ordered failure")
        } else {
            Ok(value)
        }
    });
    for index in 0..CAPACITY - 1 {
        assert!(first.submit(index, index).unwrap().is_empty());
    }
    for index in [2, 0, 1] {
        assert!(second.submit(index, index).unwrap().is_empty());
    }
    drop(first);
    assert_eq!(completed.load(Ordering::SeqCst), CAPACITY - 1);
    assert_eq!(
        second.drain().unwrap(),
        [(0, Ok(0)), (1, Err("ordered failure")), (2, Ok(2))]
    );
    assert_eq!(
        second.map_ordered([0, 1, 2]).unwrap(),
        [Ok(0), Err("ordered failure"), Ok(2)]
    );
}

#[test]
fn ordered_preparation_overlaps_slow_entries_and_preserves_errors_and_tail() {
    use std::sync::{Mutex, mpsc};
    use std::time::Duration;

    let (release, wait) = mpsc::sync_channel(1);
    let wait = Mutex::new(wait);
    let (started, observed) = mpsc::sync_channel(1);
    let count = CAPACITY * 2 + 3;
    let controller = std::thread::spawn(move || {
        let mut pool = InventoryWorkers::new(move |index: usize, _: &mut [u8]| {
            if index == 0 {
                wait.lock().unwrap().recv().unwrap();
            }
            if index == CAPACITY + 1 {
                started.send(()).unwrap();
            }
            if index == 1 || index == count - 1 {
                Err(index)
            } else {
                Ok(index)
            }
        })
        .unwrap();
        let results = pool.map_ordered(0..count).unwrap();
        assert!(pool.drain().unwrap().is_empty());
        assert!(pool.map_ordered(std::iter::empty()).unwrap().is_empty());
        let next_directory = pool.map_ordered([count, count + 1]).unwrap();
        (results, next_directory)
    });
    let progressed = observed.recv_timeout(Duration::from_secs(2));
    // Release the deliberately slow first entry and join even on regression.
    release.send(()).unwrap();
    let (results, next_directory) = controller.join().unwrap();
    assert!(
        progressed.is_ok(),
        "preparation stalled behind the first entry: {progressed:?}"
    );
    assert_eq!(
        results,
        (0..count)
            .map(|index| {
                if index == 1 || index == count - 1 {
                    Err(index)
                } else {
                    Ok(index)
                }
            })
            .collect::<Vec<_>>()
    );
    assert_eq!(next_directory, vec![Ok(count), Ok(count + 1)]);
}

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
    let nested = root.join("nested");
    std::fs::create_dir(&nested).unwrap();
    let mut expected = vec![ExpectedInput {
        path: hex::encode(root.as_os_str().as_encoded_bytes()),
        kind: "directory",
        mode: u32::from(root.metadata().unwrap().permissions().readonly()),
        digest: String::new(),
    }];
    expected.push(ExpectedInput {
        path: hex::encode(nested.as_os_str().as_encoded_bytes()),
        kind: "directory",
        mode: u32::from(nested.metadata().unwrap().permissions().readonly()),
        digest: String::new(),
    });
    for index in 0..CAPACITY * 2 + 1 {
        let parent = if index % 2 == 0 { &root } else { &nested };
        let path = parent.join(format!("input {index}.bin"));
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
    let final_path = root.join(format!("input {}.bin", CAPACITY * 2));
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
    for value in 0..CAPACITY - 1 {
        assert!(pool.submit(value, value).unwrap().is_empty());
    }
    let error = pool
        .submit(CAPACITY - 1, CAPACITY - 1)
        .and_then(|_| pool.drain())
        .unwrap_err();
    assert!(error.to_string().contains("worker panicked"));
    drop(pool);
    assert_eq!(completed.load(Ordering::SeqCst), CAPACITY);
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
    for index in 0..CAPACITY - 1 {
        assert!(pool.submit(index, ()).unwrap().is_empty());
    }
    drop(pool);
    assert_eq!(completed.load(Ordering::SeqCst), CAPACITY - 1);
}

#[test]
fn traversal_prepares_queued_files_while_every_reader_is_blocked() {
    use std::sync::{Condvar, Mutex, mpsc};
    use std::time::Duration;

    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let (admitted, observed) = mpsc::sync_channel(1);
    let controller = std::thread::spawn({
        let gate = Arc::clone(&gate);
        move || {
            let mut pool = InventoryWorkers::new(move |index: usize, _: &mut [u8]| {
                let (released, condition) = &*gate;
                let _released = condition
                    .wait_while(released.lock().unwrap(), |released| !*released)
                    .unwrap();
                index
            })
            .unwrap();
            let mut completed = Vec::new();
            for index in 0..CAPACITY - 1 {
                completed.extend(pool.submit(index, index).unwrap());
            }
            admitted.send(()).unwrap();
            completed.extend(pool.drain().unwrap());
            completed.sort_by_key(|entry| entry.0);
            completed
        }
    });
    let admission = observed.recv_timeout(Duration::from_secs(2));
    // Release and join even if admission regresses to the number of readers.
    let (released, condition) = &*gate;
    *released.lock().unwrap() = true;
    condition.notify_all();
    let completed = controller.join().unwrap();
    assert!(admission.is_ok(), "traversal waited for I/O: {admission:?}");
    assert_eq!(
        completed,
        (0..CAPACITY - 1)
            .map(|index| (index, index))
            .collect::<Vec<_>>()
    );
}
