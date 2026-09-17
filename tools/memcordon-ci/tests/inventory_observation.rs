use memcordon_ci::inventory_progress::{InventoryProgress, Operation, TaskClass, TaskState};
use std::path::Path;
use std::time::Duration;

#[test]
fn nested_read_leaf_and_panic_restore_actor_without_fake_commit() {
    let progress = InventoryProgress::new(Path::new("fixture"));
    let error = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        progress.run(
            Operation::ReadHash,
            Path::new("fixture"),
            || -> std::io::Result<()> {
                progress.run(
                    Operation::Read,
                    Path::new("fixture"),
                    || -> std::io::Result<()> {
                        let snapshot = progress.structured_snapshot();
                        assert_eq!(snapshot.actors[0].operation, Some(Operation::Read as usize));
                        progress.record_chunk(Duration::from_millis(2), Duration::ZERO, 12);
                        panic!("reader failed");
                    },
                )
            },
        )
    }));
    assert!(error.is_err());
    progress
        .run(Operation::Metadata, Path::new("next"), || {
            Ok::<_, std::io::Error>(())
        })
        .unwrap();
    let snapshot = progress.structured_snapshot();
    assert!(
        snapshot
            .actors
            .iter()
            .all(|actor| actor.operation.is_none())
    );
    assert_eq!(snapshot.actors[0].counters.as_ref().unwrap().bytes, 12);
    assert_eq!(snapshot.tasks.files_committed, 0);
}

#[test]
fn online_task_ledger_reconciles_without_retaining_finished_paths() {
    let progress = InventoryProgress::new(Path::new("fixture"));
    for id in 0..1000 {
        for state in [TaskState::Offered, TaskState::Started, TaskState::Ready] {
            progress
                .task_transition(id, TaskClass::File, state)
                .unwrap();
        }
        progress.file_validated(3);
        progress
            .task_transition(id, TaskClass::File, TaskState::Received)
            .unwrap();
        progress.file_committed(3);
    }
    let snapshot = progress.structured_snapshot();
    assert_eq!(snapshot.outstanding, 0);
    assert_eq!(snapshot.tasks.files_attempted, 1000);
    assert_eq!(snapshot.tasks.files_completed, 1000);
    assert_eq!(snapshot.tasks.files_committed, 1000);
    assert_eq!(snapshot.tasks.committed_bytes, 3000);
    assert!(
        progress
            .task_transition(999, TaskClass::File, TaskState::Received)
            .is_err()
    );
}

#[test]
fn cancellation_is_shared_but_does_not_invent_completed_work() {
    let progress = InventoryProgress::new(Path::new("fixture"));
    let worker = progress.worker();
    progress.cancellation().cancel();
    assert_eq!(
        worker.cancellation().check().unwrap_err().kind(),
        std::io::ErrorKind::Interrupted
    );
    assert_eq!(progress.structured_snapshot().tasks.files_completed, 0);
}
