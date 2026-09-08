//! Exclusive bounded attempt writers. Writer threads own no workload handles.
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, LazyLock, Mutex};
use std::time::Duration;

use super::record::WindowsAttemptRecordV1;

#[cfg(test)]
#[path = "../../../../tests/sealed_agent/windows_writer_queue.rs"]
mod writer_queue_tests;

// Owner, working and both queued snapshots share immutable outbox backing.
// Five record-sized slots cover the bounded writer phases documented in
// spec/windows-causal-diagnostics-v1.md; independent readers reserve three more.
// Remaining installation capacity charges retained files by their actual bytes.
const MAX_WRITER_LANES: usize = 1;
const PENDING_SNAPSHOTS: usize = 2;
const COMMIT_OBSERVATION_DEADLINE: Duration = Duration::from_secs(30);

struct Snapshot {
    expected_revision: u64,
    record: Box<WindowsAttemptRecordV1>,
    completion: Option<SyncSender<Result<Box<WindowsAttemptRecordV1>, String>>>,
}

struct Lane {
    sender: SyncSender<Snapshot>,
    quarantined: Arc<AtomicBool>,
    pending: Arc<AtomicUsize>,
    completion_signal: Arc<(Mutex<()>, Condvar)>,
    failure: Arc<Mutex<Option<memcordon_core::CausalEventV1>>>,
}

static LANES: LazyLock<Mutex<BTreeMap<String, Arc<Lane>>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

fn lane(record: &WindowsAttemptRecordV1) -> Result<Arc<Lane>, String> {
    let mut lanes = LANES
        .try_lock()
        .map_err(|_| "diagnostic writer registry unavailable".to_owned())?;
    if let Some(lane) = lanes.get(&record.attempt_id) {
        return Ok(Arc::clone(lane));
    }
    if lanes.len() >= MAX_WRITER_LANES {
        return Err("attempt writer capacity exhausted".to_owned());
    }
    super::record::reserve_writer_admission(&record.attempt_id, &record.request_sha256)?;
    let lane = new_lane(|record, revision| record.publish_exclusive(revision))?;
    lanes.insert(record.attempt_id.clone(), Arc::clone(&lane));
    Ok(lane)
}

fn new_lane(
    mut publish: impl FnMut(&mut WindowsAttemptRecordV1, u64) -> Result<(), String> + Send + 'static,
) -> Result<Arc<Lane>, String> {
    let (sender, receiver) = mpsc::sync_channel::<Snapshot>(PENDING_SNAPSHOTS);
    let quarantined = Arc::new(AtomicBool::new(false));
    let worker_quarantined = Arc::clone(&quarantined);
    let pending = Arc::new(AtomicUsize::new(0));
    let worker_pending = Arc::clone(&pending);
    let completion_signal = Arc::new((Mutex::new(()), Condvar::new()));
    let worker_completion = Arc::clone(&completion_signal);
    let failure = Arc::new(Mutex::new(None));
    let worker_failure = Arc::clone(&failure);
    std::thread::Builder::new()
        .name("memcordon-attempt-writer".to_owned())
        .spawn(move || {
            while let Ok(mut next) = receiver.recv() {
                if worker_quarantined.load(Ordering::Acquire) {
                    break;
                }
                let _capture = super::diagnostics::AttemptDiagnosticScope::enter();
                super::diagnostics::set_phase(
                    memcordon_core::AttemptObservationPhaseV1::Terminalizing,
                );
                let result = publish(&mut next.record, next.expected_revision);
                if result.is_err() {
                    let mut observations = memcordon_core::WindowsCausalDiagnosticsV1::default();
                    super::diagnostics::merge_into(&mut observations);
                    let event = match observations.original {
                        memcordon_core::OriginalFailureV1::Observed { event } => event,
                        _ => memcordon_core::CausalEventV1 {
                            sequence: 0,
                            origin: memcordon_core::DiagnosticOriginV1::RecordWriter,
                            category: memcordon_core::FailureCategoryV1::Persistence,
                            operation: memcordon_core::FailureOperationV1::StoreRecord,
                            code: memcordon_core::FailureCodeV1::UnexpectedProviderFailure,
                            native_code: None,
                            observed_phase:
                                memcordon_core::AttemptObservationPhaseV1::Terminalizing,
                            safe_detail: memcordon_core::SafeDiagnosticDetailV1::ProviderMessage {
                                id: memcordon_core::SafeMessageIdV1::CommitNotConfirmed,
                            },
                            detail_redacted: true,
                            detail_truncated: false,
                            terminalization_reference: None,
                        },
                    };
                    if let Ok(mut failure) = worker_failure.lock() {
                        *failure = Some(event);
                    }
                    worker_quarantined.store(true, Ordering::Release);
                }
                if let Ok(_guard) = worker_completion.0.lock() {
                    worker_pending.fetch_sub(1, Ordering::AcqRel);
                    worker_completion.1.notify_all();
                } else {
                    worker_quarantined.store(true, Ordering::Release);
                }
                if let Some(completion) = next.completion {
                    let _ = completion.try_send(result.map(|()| next.record));
                }
            }
        })
        .map_err(|error| error.to_string())?;
    let lane = Arc::new(Lane {
        sender,
        quarantined,
        pending,
        completion_signal,
        failure,
    });
    Ok(lane)
}

#[cfg(feature = "test-support")]
pub(super) struct TestPublisherLane {
    attempt_id: String,
}
#[cfg(feature = "test-support")]
impl TestPublisherLane {
    pub(super) fn finish(self) -> Result<(), String> {
        wait_for_pending(&self.attempt_id)
    }
}
#[cfg(feature = "test-support")]
impl Drop for TestPublisherLane {
    fn drop(&mut self) {
        if let Ok(mut lanes) = LANES.lock() {
            lanes.remove(&self.attempt_id);
        }
    }
}
#[cfg(feature = "test-support")]
pub(super) fn test_publisher_lane(
    attempt_id: &str,
    publish: impl FnMut(&mut WindowsAttemptRecordV1, u64) -> Result<(), String> + Send + 'static,
) -> Result<TestPublisherLane, String> {
    let mut lanes = LANES
        .lock()
        .map_err(|_| "writer fixture registry poisoned")?;
    if lanes.contains_key(attempt_id) || lanes.len() >= MAX_WRITER_LANES {
        return Err("writer fixture lane already occupied".into());
    }
    lanes.insert(attempt_id.into(), new_lane(publish)?);
    Ok(TestPublisherLane {
        attempt_id: attempt_id.into(),
    })
}

/// Used only after workload cleanup, before terminalization reads a snapshot
/// that an asynchronous cleanup publication may still be replacing.
pub(super) fn wait_for_pending(attempt_id: &str) -> Result<(), String> {
    let lane = LANES
        .try_lock()
        .map_err(|_| "attempt writer registry unavailable".to_owned())?
        .get(attempt_id)
        .cloned();
    let Some(lane) = lane else {
        return Ok(());
    };
    let guard = lane
        .completion_signal
        .0
        .lock()
        .map_err(|_| "attempt writer completion unavailable".to_owned())?;
    let (_guard, timeout) = lane
        .completion_signal
        .1
        .wait_timeout_while(guard, COMMIT_OBSERVATION_DEADLINE, |_| {
            lane.pending.load(Ordering::Acquire) != 0 && !lane.quarantined.load(Ordering::Acquire)
        })
        .map_err(|_| "attempt writer completion unavailable".to_owned())?;
    if timeout.timed_out() || lane.quarantined.load(Ordering::Acquire) {
        lane.quarantined.store(true, Ordering::Release);
        if let Some(event) = take_failure(&lane) {
            super::diagnostics::capture(event);
        }
        return Err("attempt cleanup publication is unconfirmed".to_owned());
    }
    Ok(())
}

fn take_failure(lane: &Lane) -> Option<memcordon_core::CausalEventV1> {
    if let Ok(mut failure) = lane.failure.try_lock() {
        return failure.take();
    }
    None
}

fn try_submit(lane: &Lane, snapshot: Snapshot) -> Result<(), String> {
    let _submission = lane
        .completion_signal
        .0
        .try_lock()
        .map_err(|_| "attempt writer completion is busy".to_owned())?;
    if lane.quarantined.load(Ordering::Acquire) {
        return Err("attempt writer is quarantined".to_owned());
    }
    lane.pending.fetch_add(1, Ordering::AcqRel);
    lane.sender.try_send(snapshot).map_err(|error| {
        lane.pending.fetch_sub(1, Ordering::AcqRel);
        match error {
            TrySendError::Full(_) => "attempt writer queue full",
            TrySendError::Disconnected(_) => "attempt writer unavailable",
        }
        .to_owned()
    })
}

pub(super) fn commit(record: &mut WindowsAttemptRecordV1) -> Result<(), String> {
    let lane = lane(record)?;
    if lane.quarantined.load(Ordering::Acquire) {
        return Err("attempt writer is quarantined".to_owned());
    }
    let expected_revision = record.record_revision;
    let mut snapshot = record.clone();
    snapshot.record_revision = expected_revision
        .checked_add(1)
        .ok_or_else(|| "attempt revision exhausted".to_owned())?;
    let (completion, observed) = mpsc::sync_channel(1);
    try_submit(
        &lane,
        Snapshot {
            expected_revision,
            record: Box::new(snapshot),
            completion: Some(completion),
        },
    )?;
    match observed.recv_timeout(COMMIT_OBSERVATION_DEADLINE) {
        Ok(Ok(snapshot)) => {
            *record = *snapshot;
            Ok(())
        }
        Ok(Err(error)) => {
            if let Some(event) = take_failure(&lane) {
                super::diagnostics::observe_record(&mut record.causal_diagnostics, event, false);
            }
            record.causal_diagnostics.loss.persistence_failure_observed = true;
            Err(error)
        }
        Err(_) => {
            lane.quarantined.store(true, Ordering::Release);
            record.causal_diagnostics.loss.writer_unavailable = true;
            Err("attempt commit not confirmed; writer quarantined".to_owned())
        }
    }
}

pub(super) fn try_commit_diagnostics(record: &mut WindowsAttemptRecordV1) -> Result<(), String> {
    let lane = lane(record)?;
    if lane.quarantined.load(Ordering::Acquire) {
        return Err("attempt writer is quarantined".to_owned());
    }
    let mut snapshot = record.clone();
    snapshot.record_revision = record
        .record_revision
        .checked_add(1)
        .ok_or_else(|| "attempt revision exhausted".to_owned())?;
    let next_revision = snapshot.record_revision;
    try_submit(
        &lane,
        Snapshot {
            expected_revision: record.record_revision,
            record: Box::new(snapshot),
            completion: None,
        },
    )?;
    // This is assigned ownership order, not a durable acknowledgement. The
    // journal watermark remains at the last confirmed committed sequence.
    record.record_revision = next_revision;
    Ok(())
}

pub(super) fn ensure_no_quarantined_writer() -> Result<(), String> {
    let lanes = LANES
        .try_lock()
        .map_err(|_| "attempt writer registry unavailable".to_owned())?;
    if lanes
        .values()
        .any(|lane| lane.quarantined.load(Ordering::Acquire))
    {
        return Err("attempt writer publication remains unconfirmed".to_owned());
    }
    Ok(())
}

/// Called before the existing retirement authority removes the record.
/// A quarantined lane remains charged because an in-flight publish may survive.
pub(super) fn retire(attempt_id: &str) -> Result<(), String> {
    let mut lanes = LANES
        .try_lock()
        .map_err(|_| "attempt writer registry unavailable".to_owned())?;
    if let Some(lane) = lanes.get(attempt_id) {
        close_lane(lane)?;
    }
    let local_writer_stopped = lanes.remove(attempt_id).is_some();
    super::record::retire_writer_admission(attempt_id, local_writer_stopped)
}

fn close_lane(lane: &Lane) -> Result<(), String> {
    let _submission = lane
        .completion_signal
        .0
        .try_lock()
        .map_err(|_| "attempt writer publication is completing".to_owned())?;
    if lane.quarantined.swap(true, Ordering::AcqRel) || lane.pending.load(Ordering::Acquire) != 0 {
        return Err("cannot retire an unconfirmed attempt writer".to_owned());
    }
    Ok(())
}

pub(super) struct PublicationGuard(super::pipe::OwnedHandle);
impl PublicationGuard {
    pub(super) fn acquire(attempt_id: &str) -> Result<Self, String> {
        use windows_sys::Win32::Foundation::{WAIT_ABANDONED, WAIT_OBJECT_0};
        use windows_sys::Win32::System::Threading::{CreateMutexW, WaitForSingleObject};
        super::record::validate_attempt_id(attempt_id)?;
        let security =
            super::security::SecurityDescriptor::from_sddl(&super::security::private_pipe_sddl()?)?;
        let attributes = security.attributes(false);
        let name: Vec<u16> = format!("Global\\MemCordon.Attempt.Writer.{attempt_id}")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: attributes and the terminated name outlive this call.
        let raw = unsafe { CreateMutexW(&raw const attributes, 0, name.as_ptr()) };
        let handle = super::pipe::OwnedHandle::new(raw)?;
        security.verify_kernel_object(handle.raw(), super::security::SecurityObjectKind::Mutex)?;
        // No waiting on another service or a stalled writer is introduced.
        let wait = unsafe { WaitForSingleObject(handle.raw(), 0) };
        if wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED {
            return Err("attempt publication owner is unavailable".to_owned());
        }
        Ok(Self(handle))
    }
}
impl Drop for PublicationGuard {
    fn drop(&mut self) {
        // SAFETY: this thread acquired the mutex and owns its live handle.
        unsafe {
            windows_sys::Win32::System::Threading::ReleaseMutex(self.0.raw());
        }
    }
}
