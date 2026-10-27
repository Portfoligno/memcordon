#[path = "../src/windows_guardian_query.rs"]
mod query;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

fn output(code: i32, stdout: &[u8], stderr: &[u8]) -> memcordon_testkit::ObservedOutput {
    #[cfg(unix)]
    let status = {
        use std::os::unix::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(code << 8)
    };
    #[cfg(windows)]
    let status = {
        use std::os::windows::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(code as u32)
    };
    memcordon_testkit::ObservedOutput {
        status,
        stdout: stdout.to_vec(),
        stderr: stderr.to_vec(),
        elapsed: Duration::from_millis(1),
    }
}

#[test]
fn actual_nested_failure_preserves_distinct_status_streams_and_source_binding() {
    let binding = serde_json::json!({"case":{"family":"W-ENVELOPE","scenario":"restricted"},"source_commit":"original-source","challenge_sha256":"original-challenge"});
    let trace = Mutex::new(query::Trace::new(binding.clone()));
    query::update(&trace, |trace| {
        trace.guardian(serde_json::json!({"process_id":20,"creation_time_100ns":200}));
        trace.stage("returned-output");
        trace.captured(output(
            27,
            b"distinct nested stdout",
            b"error[MCCLI-WINDOWS-LIVE-GUARDIAN]: original refusal",
        ));
    });
    let (failure, snapshot) = query::update(&trace, |trace| {
        (
            trace.failure().unwrap().to_string(),
            trace.snapshot().unwrap().unwrap(),
        )
    });
    assert!(failure.starts_with("positive live guardian association query failed"));
    assert!(failure.contains("nested-status=Some(27)"));
    assert!(!failure.contains("nested-status=Some(1)"));
    let record: serde_json::Value = serde_json::from_slice(&snapshot.record).unwrap();
    assert_eq!(record["binding"], binding);
    assert_eq!(record["status_code"], 27);
    assert_eq!(record["status_success"], false);
    assert_eq!(record["diagnostic_only"], true);
    for (name, bytes) in [
        ("stdout", snapshot.stdout.unwrap()),
        ("stderr", snapshot.stderr.unwrap()),
    ] {
        assert_eq!(record[name]["length"], bytes.len());
        assert_eq!(
            record[name]["sha256"],
            memcordon_readiness_verifier::sha256(&bytes)
        );
    }
}

#[test]
fn absent_output_is_not_empty_capture_and_retention_failure_cannot_change_status() {
    let mut trace = query::Trace::new(serde_json::json!({}));
    assert!(trace.snapshot().unwrap().is_none());
    trace.guardian(serde_json::json!({"process_id":20,"creation_time_100ns":200}));
    trace.stage("command-capture");
    let snapshot = trace.snapshot().unwrap().unwrap();
    let record: serde_json::Value = serde_json::from_slice(&snapshot.record).unwrap();
    assert_eq!(record["output_observed"], false);
    assert!(record["status_code"].is_null());
    assert!(snapshot.stdout.is_none() && snapshot.stderr.is_none());
    trace.captured(output(27, b"", &vec![0; query::STREAM_BOUND + 1]));
    let original = trace.failure().unwrap().to_string();
    assert!(trace.snapshot().is_err());
    assert_eq!(trace.failure().unwrap().to_string(), original);
    trace.captured(output(0, b"malformed success", b""));
    assert!(trace.failure().is_none());
    assert!(
        serde_json::from_slice::<memcordon_core::WindowsGuardianAttemptObservation>(
            b"malformed success"
        )
        .is_err()
    );
}

#[test]
fn adoption_keeps_original_owners_across_setup_failures_and_slot_invariants() {
    #[derive(Debug)]
    struct Witness(Arc<AtomicUsize>);
    impl Drop for Witness {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    for stage in ["materialization", "capture", "parse", "publication"] {
        let drops = Arc::new(AtomicUsize::new(0));
        let slot = Mutex::new(Vec::new());
        query::adopt(&slot, Witness(Arc::clone(&drops))).unwrap();
        let failure: std::io::Result<()> = Err(std::io::Error::other(stage));
        assert!(failure.is_err());
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert!(query::adopt(&slot, Witness(Arc::clone(&drops))).is_err());
        assert_eq!(slot.lock().unwrap().len(), 2);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(slot);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
    }
    let drops = Arc::new(AtomicUsize::new(0));
    let slot = Mutex::new(Vec::new());
    query::adopt(&slot, Witness(Arc::clone(&drops))).unwrap();
    assert!(
        std::panic::catch_unwind(|| {
            let _guard = slot.lock().unwrap();
            panic!("injected custody mutex poison");
        })
        .is_err()
    );
    assert!(query::adopt(&slot, Witness(Arc::clone(&drops))).is_err());
    assert_eq!(slot.lock().unwrap_err().into_inner().len(), 2);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(slot);
    assert_eq!(drops.load(Ordering::SeqCst), 2);
}
