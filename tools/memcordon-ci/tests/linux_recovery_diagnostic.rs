use memcordon_ci::release::linux_recovery_diagnostic::{contract::*, failure, receipt};

#[test]
fn original_cleanup_cutoff_conversion_is_conservative_and_checked() {
    assert_eq!(
        monotonic_cleanup_cutoff(200, 7_000_000, 150).unwrap(),
        56_000_000
    );
    assert_eq!(monotonic_cleanup_cutoff(102, 7, 100).unwrap(), 1_000_007);
    for (deadline, monotonic, wall) in [
        (100, 7, 100),
        (101, 7, 100),
        (99, 7, 100),
        (u64::MAX, 0, 1),
        (3, u64::MAX, 1),
    ] {
        assert!(monotonic_cleanup_cutoff(deadline, monotonic, wall).is_err());
    }
    // An earlier monotonic sample deliberately subtracts time spent sampling.
    let original = monotonic_cleanup_cutoff(200, 7_000_000, 150).unwrap();
    assert!(original < monotonic_cleanup_cutoff(200, 8_000_000, 150).unwrap());
}

fn failed() -> (Vec<u8>, RecoveryFailure) {
    let (input, result) = original();
    (
        input,
        RecoveryFailure {
            format: "memcordon.original-native-recovery-failure".into(),
            revision: 1,
            input_sha256: result.input_sha256,
            context: result.context,
            identity: result.identity,
            native_target: result.native_target,
            scope_id: result.scope_id,
            recovery_harness_owner_sha256: result.recovery_harness_owner_sha256,
            original_records: result.original_records,
            original_cleanup_deadline_unix_millis: 200,
            monotonic_cutoff_nanos: Some(1_000),
            observed_unix_millis: 200,
            stage: "package-lease-acquisition".into(),
            recovery_entered: false,
            error: "original lease deadline exhausted with contention".into(),
            lease: LeaseObservation {
                started_monotonic_nanos: Some(100),
                finished_monotonic_nanos: Some(1_000),
                contention_count: 3,
                lock_acquired: false,
                validated_acquisition: false,
                held_device: Some(1),
                held_inode: Some(2),
                native_error: Some(11),
                operation: "flock".into(),
            },
        },
    )
}

#[test]
fn bound_failed_operation_never_substitutes_for_success_receipt() {
    let (input, mut result) = failed();
    let bytes = serde_json::to_vec(&result).unwrap();
    let summary = failure(&bytes, &input).unwrap();
    assert_eq!(summary["diagnostic_only"], true);
    assert_eq!(summary["operation_failed"], true);
    assert_eq!(summary["recovery_entered"], false);
    assert_eq!(summary["within_original_cleanup"], false);
    assert!(summary.get("outstanding").is_none());
    assert!(summary.get("success").is_none());
    assert!(receipt(&bytes, &input).is_err());
    result.lease.finished_monotonic_nanos = None;
    assert!(
        failure(&serde_json::to_vec(&result).unwrap(), &input).is_ok(),
        "failed clock observation must not fabricate or erase the primary failure"
    );
    result.stage = "persisted-recovery".into();
    result.recovery_entered = true;
    result.lease.lock_acquired = true;
    result.lease.validated_acquisition = true;
    assert!(failure(&serde_json::to_vec(&result).unwrap(), &input).is_ok());
    result.stage = "cleanup-cutoff-conversion".into();
    result.monotonic_cutoff_nanos = None;
    result.recovery_entered = false;
    result.lease.lock_acquired = false;
    result.lease.validated_acquisition = false;
    assert!(
        failure(&serde_json::to_vec(&result).unwrap(), &input).is_err(),
        "conversion failure cannot claim a prior lease operation"
    );
    result.lease = LeaseObservation {
        started_monotonic_nanos: None,
        finished_monotonic_nanos: None,
        contention_count: 0,
        lock_acquired: false,
        validated_acquisition: false,
        held_device: None,
        held_inode: None,
        native_error: None,
        operation: "not-started".into(),
    };
    assert!(failure(&serde_json::to_vec(&result).unwrap(), &input).is_ok());
    result.stage = "root-authentication".into();
    result.monotonic_cutoff_nanos = Some(1_000);
    assert!(failure(&serde_json::to_vec(&result).unwrap(), &input).is_ok());
    result.lease.contention_count = 1;
    assert!(failure(&serde_json::to_vec(&result).unwrap(), &input).is_err());
}

#[test]
fn failed_operation_requires_original_association_and_coherent_stage_facts() {
    let (input, result) = failed();
    let original = serde_json::to_value(result).unwrap();
    let mut foreign_identity = original["identity"].clone();
    foreign_identity["run_id"] = serde_json::json!("another-run");
    for (field, value) in [
        ("format", serde_json::json!("another-format")),
        ("revision", serde_json::json!(2)),
        ("input_sha256", serde_json::json!("a".repeat(64))),
        ("context", serde_json::json!("another-context")),
        ("identity", foreign_identity),
        (
            "native_target",
            serde_json::json!("aarch64-unknown-linux-gnu"),
        ),
        ("scope_id", serde_json::json!("another-scope")),
        (
            "recovery_harness_owner_sha256",
            serde_json::json!("7".repeat(64)),
        ),
        (
            "original_records",
            serde_json::json!([["lease_owner", "8".repeat(64)]]),
        ),
        (
            "original_cleanup_deadline_unix_millis",
            serde_json::json!(201),
        ),
    ] {
        let mut changed = original.clone();
        changed[field] = value;
        serde_json::from_value::<RecoveryFailure>(changed.clone()).unwrap();
        assert!(
            failure(&serde_json::to_vec(&changed).unwrap(), &input).is_err(),
            "{field}"
        );
    }
    for (field, value) in [
        ("stage", serde_json::json!("success")),
        ("recovery_entered", serde_json::json!(true)),
        ("monotonic_cutoff_nanos", serde_json::Value::Null),
        ("error", serde_json::json!("x".repeat(4097))),
    ] {
        let mut changed = original.clone();
        changed[field] = value;
        assert!(failure(&serde_json::to_vec(&changed).unwrap(), &input).is_err());
    }
    let mut changed = original.clone();
    changed["lease"]["validated_acquisition"] = serde_json::json!(true);
    assert!(failure(&serde_json::to_vec(&changed).unwrap(), &input).is_err());
    let mut acquired = original.clone();
    acquired["lease"]["lock_acquired"] = serde_json::json!(true);
    acquired["lease"]["native_error"] = serde_json::Value::Null;
    acquired["lease"]["operation"] = serde_json::json!("post-lock-cutoff-and-identity");
    acquired["error"] = serde_json::json!("original cutoff expired at acquisition");
    assert!(failure(&serde_json::to_vec(&acquired).unwrap(), &input).is_ok());
    for field in ["held_device", "held_inode", "started_monotonic_nanos"] {
        let mut missing = acquired.clone();
        missing["lease"][field] = serde_json::Value::Null;
        assert!(
            failure(&serde_json::to_vec(&missing).unwrap(), &input).is_err(),
            "acquisition requires measured {field}"
        );
    }
    changed = original;
    changed["lease"]["finished_monotonic_nanos"] = serde_json::json!(99);
    assert!(failure(&serde_json::to_vec(&changed).unwrap(), &input).is_err());
    for malformed in [
        b"".as_slice(),
        b"not-json",
        b"{\"revision\":1,\"revision\":1}",
    ] {
        assert!(failure(malformed, &input).is_err());
    }
}

fn original() -> (Vec<u8>, RecoveryResult) {
    let input = Input {
        format: "memcordon.original-native-recovery-input".into(),
        revision: 1,
        identity: Identity {
            run_id: "original-run".into(),
            source_commit: "1".repeat(40),
            source_tree_sha256: "2".repeat(64),
            version: "0.5.6".into(),
        },
        native_target: "x86_64-unknown-linux-gnu".into(),
        scope_id: "original-scope".into(),
        artifact_root: "/original/stage".into(),
        original_artifact_root: "/original".into(),
        origin_sha256: "3".repeat(64),
        work_deadline_unix_millis: 100,
        cleanup_deadline_unix_millis: 200,
        recovery_harness_owner_sha256: "4".repeat(64),
        context: Context::InterruptedLease {
            lease_owner: Record {
                path: "/original/stage/input-lease_owner.bin".into(),
                length: 1,
                sha256: "5".repeat(64),
            },
            resources_acquired: None,
        },
    };
    let bytes = serde_json::to_vec(&input).unwrap();
    let result = RecoveryResult {
        format: "memcordon.original-native-recovery-result".into(),
        revision: 1,
        input_sha256: memcordon_ci::release::artifacts::checksum(&bytes),
        context: input.context.kind().into(),
        identity: input.identity,
        native_target: input.native_target,
        scope_id: input.scope_id,
        recovery_harness_owner_sha256: input.recovery_harness_owner_sha256,
        original_records: vec![("lease_owner".into(), "5".repeat(64))],
        completed_unix_millis: 150,
        within_original_cleanup: true,
        outstanding: vec!["ambiguous authenticated resource".into()],
    };
    (bytes, result)
}

#[test]
fn bound_nonzero_receipt_reports_obligations_and_cutoff_without_success_authority() {
    let (input, mut result) = original();
    let summary = receipt(&serde_json::to_vec(&result).unwrap(), &input).unwrap();
    assert_eq!(summary["diagnostic_only"], true);
    assert_eq!(summary["outstanding_count"], 1);
    assert_eq!(summary["within_original_cleanup"], true);
    assert!(summary.get("success").is_none());
    result.outstanding.clear();
    result.completed_unix_millis = 200;
    result.within_original_cleanup = false;
    let expired = receipt(&serde_json::to_vec(&result).unwrap(), &input).unwrap();
    assert_eq!(expired["outstanding_count"], 0);
    assert_eq!(expired["within_original_cleanup"], false);
    result.completed_unix_millis = 150;
    result.within_original_cleanup = true;
    let in_time = receipt(&serde_json::to_vec(&result).unwrap(), &input).unwrap();
    assert!(
        in_time["post_persistence_cutoff_state"]
            .as_str()
            .unwrap()
            .contains("not established")
    );
}

#[test]
fn malformed_missing_and_misbound_receipts_never_receive_bound_labels() {
    let (input, result) = original();
    for bytes in [
        b"".as_slice(),
        b"not-json",
        b"{\"revision\":1,\"revision\":1}",
    ] {
        assert!(receipt(bytes, &input).is_err());
    }
    let original = serde_json::to_value(result).unwrap();
    for field in [
        "format",
        "revision",
        "input_sha256",
        "context",
        "identity",
        "native_target",
        "scope_id",
        "recovery_harness_owner_sha256",
        "original_records",
        "within_original_cleanup",
    ] {
        let mut changed = original.clone();
        changed[field] = serde_json::Value::Null;
        assert!(
            receipt(&serde_json::to_vec(&changed).unwrap(), &input).is_err(),
            "{field}"
        );
    }
    for field in [
        "format",
        "input_sha256",
        "context",
        "native_target",
        "scope_id",
        "recovery_harness_owner_sha256",
    ] {
        let mut changed = original.clone();
        changed[field] = serde_json::json!("different-original-binding");
        assert!(
            receipt(&serde_json::to_vec(&changed).unwrap(), &input).is_err(),
            "same-type {field}"
        );
    }
    let mut changed = original.clone();
    changed["identity"]["run_id"] = serde_json::json!("different-run");
    assert!(receipt(&serde_json::to_vec(&changed).unwrap(), &input).is_err());
    let mut changed = original.clone();
    changed["original_records"][0][1] = serde_json::json!("6".repeat(64));
    assert!(receipt(&serde_json::to_vec(&changed).unwrap(), &input).is_err());
    let mut changed = original;
    changed["within_original_cleanup"] = serde_json::json!(false);
    assert!(receipt(&serde_json::to_vec(&changed).unwrap(), &input).is_err());
}
