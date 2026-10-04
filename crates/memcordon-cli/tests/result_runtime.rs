#![cfg(all(target_os = "macos", feature = "test-support"))]

use memcordon_platform::{
    DeliveryLimits, DeliveryOutcome, DeliveryRequest, DeliveryStage, MacosDeliveryRuntime,
    WriterFrame, WriterImage,
};
use std::io::Cursor;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

fn runtime(capacity: usize) -> MacosDeliveryRuntime {
    MacosDeliveryRuntime::new(
        DeliveryLimits {
            max_in_flight: NonZeroUsize::new(capacity).unwrap(),
            max_total_bytes: capacity * 4096,
        },
        WriterImage::Installed(env!("CARGO_BIN_EXE_memcordon").into()),
    )
    .unwrap()
}
fn request() -> DeliveryRequest {
    DeliveryRequest::new(vec![b'\n'], None, None, None)
}

fn semantic_report(directory: &std::path::Path) -> memcordon_core::ResultReport {
    let path = directory.join("source.json");
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_memcordon"));
    command
        .args(["+1s", "--report"])
        .arg(&path)
        .args(["--", "/usr/bin/true"]);
    let output =
        memcordon_testkit::run_with_deadline(&mut command, Duration::from_secs(8)).unwrap();
    assert!(
        output.status.success(),
        "actual ordinary execution fixture: {output:?}"
    );
    memcordon_core::ResultReport::Legacy(
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap(),
    )
}

#[test]
fn distinct_destinations_use_two_lanes_same_destination_is_busy_and_bytes_are_finalized_once() {
    let directory = tempfile::tempdir().unwrap();
    let report = semantic_report(directory.path());
    let first_path = directory.path().join("first.json");
    let second_path = directory.path().join("second.json");
    let marker = directory.path().join("barrier");
    std::fs::write(&first_path, b"previous complete bytes\n").unwrap();
    let runtime = MacosDeliveryRuntime::new(
        DeliveryLimits {
            max_in_flight: NonZeroUsize::new(2).unwrap(),
            max_total_bytes: 2 * 64 * 1024,
        },
        WriterImage::Installed(env!("CARGO_BIN_EXE_memcordon").into()),
    )
    .unwrap();
    let mut first = DeliveryRequest::new(
        Vec::new(),
        Some(first_path.clone()),
        Some(report.clone()),
        None,
    );
    first.barrier = Some((
        memcordon_core::ReportWritePhase::BeforeWrite,
        marker.as_os_str().as_encoded_bytes().to_vec(),
    ));
    let owner = runtime.clone();
    let operation = std::thread::spawn(move || owner.deliver(first));
    let limit = Instant::now() + Duration::from_millis(800);
    while !marker.exists() {
        assert!(
            Instant::now() < limit,
            "actual writer never reached atomic barrier"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(matches!(
        runtime.deliver(DeliveryRequest::new(
            Vec::new(),
            Some(first_path.clone()),
            Some(report.clone()),
            None
        )),
        DeliveryOutcome::Busy
    ));
    let second = runtime.deliver(DeliveryRequest::new(
        Vec::new(),
        Some(second_path.clone()),
        Some(report.clone()),
        None,
    ));
    let DeliveryOutcome::Completed { observation } = second else {
        panic!("distinct path rejected: {second:?}")
    };
    assert!(!observation.cleanup_outstanding);
    assert!(observation.frame_transferred);
    let mut expected = report;
    expected.prepare_writer(
        observation
            .writer_pid
            .expect("actual owned native writer PID"),
    );
    assert_eq!(
        std::fs::read(second_path).unwrap(),
        expected.to_bytes().unwrap(),
        "writer must persist exact finalized owner bytes"
    );
    assert!(
        matches!(operation.join().unwrap(), DeliveryOutcome::Uncertain { observation, .. } if observation.frame_transferred)
    );
    assert_eq!(
        std::fs::read(first_path).unwrap(),
        b"previous complete bytes\n"
    );
    drain(&runtime);
}
fn drain(runtime: &MacosDeliveryRuntime) {
    let limit = Instant::now() + Duration::from_secs(5);
    while runtime.outstanding() != 0 {
        assert!(
            Instant::now() < limit,
            "actual native writer obligation remains charged"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn delayed_native_publication_keeps_capacity_and_independent_runtime_usable() {
    let runtime = runtime(1);
    let gate = Arc::new(AtomicBool::new(false));
    let entered = Arc::new(AtomicBool::new(false));
    let owner = runtime.clone();
    let mut pending = request();
    pending.creation_gate = Some(gate.clone());
    pending.creation_entered = Some(entered.clone());
    let started = Instant::now();
    let operation = std::thread::spawn(move || owner.deliver(pending));
    let limit = Instant::now() + Duration::from_secs(2);
    while !entered.load(Ordering::Acquire) {
        assert!(Instant::now() < limit);
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(matches!(runtime.deliver(request()), DeliveryOutcome::Busy));
    assert!(matches!(
        self::runtime(1).deliver(request()),
        DeliveryOutcome::Completed { .. }
    ));
    let outcome = operation.join().unwrap();
    assert!(
        started.elapsed() < Duration::from_millis(1500),
        "caller return budget renewed while creation was delayed"
    );
    assert!(
        matches!(outcome, DeliveryOutcome::Failed { observation, .. } if !observation.frame_transferred)
    );
    assert_eq!(
        runtime.outstanding(),
        1,
        "late native writer was discarded at caller timeout"
    );
    gate.store(true, Ordering::Release);
    drain(&runtime);
    assert!(matches!(
        runtime.deliver(request()),
        DeliveryOutcome::Completed { .. }
    ));
}

#[test]
fn last_runtime_drop_is_bounded_and_late_writer_stays_owned_until_actual_reap() {
    let runtime = runtime(1);
    let observer = runtime.observer();
    let gate = Arc::new(AtomicBool::new(false));
    let entered = Arc::new(AtomicBool::new(false));
    let mut pending = request();
    pending.creation_gate = Some(gate.clone());
    pending.creation_entered = Some(entered.clone());
    let outcome = runtime.deliver(pending);
    assert!(
        entered.load(Ordering::Acquire),
        "actual creation must precede the delayed-publication fixture"
    );
    assert!(matches!(outcome, DeliveryOutcome::Failed { .. }));
    let started = Instant::now();
    drop(runtime);
    assert!(
        started.elapsed() < Duration::from_millis(50),
        "Drop waited for native retirement"
    );
    assert_eq!(observer.outstanding(), 1);
    gate.store(true, Ordering::Release);
    let limit = Instant::now() + Duration::from_secs(5);
    while observer.outstanding() != 0 {
        assert!(
            Instant::now() < limit,
            "closed runtime lost its actual writer"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn worker_panic_retains_and_reaps_actual_native_writer_then_lane_reuses() {
    let runtime = runtime(1);
    let mut pending = request();
    pending.panic_after_spawn = true;
    assert!(
        matches!(runtime.deliver(pending), DeliveryOutcome::Failed { stage: DeliveryStage::OwnerThread, observation, .. }
        if observation.writer_pid.is_some() && !observation.cleanup_outstanding)
    );
    drain(&runtime);
    assert!(matches!(
        runtime.deliver(request()),
        DeliveryOutcome::Completed { .. }
    ));
}

#[test]
fn aggregate_payload_budget_rejects_oversize_before_native_creation() {
    let runtime = runtime(2);
    let oversized = DeliveryRequest::new(vec![b'x'; 4096], None, None, None);
    assert!(
        matches!(runtime.deliver(oversized), DeliveryOutcome::Failed { stage: DeliveryStage::Serialization, observation, .. }
        if observation.writer_pid.is_none())
    );
    assert_eq!(runtime.outstanding(), 0);
}

#[test]
fn one_frame_preserves_exact_bytes_and_rejects_partial_extra_and_oversize() {
    let frame = WriterFrame {
        diagnostics: vec![0, 255, b'\n'],
        report_path: Some(b"/tmp/report".to_vec()),
        report: Some(b"final bytes\n".to_vec()),
        barrier: None,
        delay_before_write: false,
    };
    let bytes = frame.encode(4096).unwrap();
    let decoded = WriterFrame::read(&mut Cursor::new(&bytes)).unwrap();
    assert_eq!(decoded.diagnostics, frame.diagnostics);
    assert_eq!(decoded.report, frame.report);
    assert_eq!(decoded.report_path, frame.report_path);
    assert!(WriterFrame::read(&mut Cursor::new(&bytes[..bytes.len() - size_of::<u8>()])).is_err());
    let mut extra = bytes.clone();
    extra.extend(&bytes);
    assert!(WriterFrame::read(&mut Cursor::new(extra)).is_err());
    assert!(frame.encode(bytes.len() - size_of::<u8>()).is_err());
}
