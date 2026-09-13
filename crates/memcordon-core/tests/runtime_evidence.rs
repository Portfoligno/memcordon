use std::num::NonZeroU32;

use memcordon_core::{
    ClockDomain, DeliveryEvidence, ReleaseEvidence, RetirementEvidence, RuntimeEvidenceV1,
};

fn complete() -> RuntimeEvidenceV1 {
    RuntimeEvidenceV1 {
        schema_version: 1,
        clock: ClockDomain::DarwinContinuousTicksV1 {
            boot_identity: "fixture-boot".to_owned(),
            ticks_per_second: 1_000_000_000,
        },
        run_origin: 10,
        attempt_origin: 20,
        work_expires: Some(100),
        startup_expires: 80,
        release: ReleaseEvidence::Issued {
            at: 40,
            exec_confirmed: true,
        },
        target_pid: NonZeroU32::new(123),
        terminal_observed: Some(100),
        force_requested: Some(100),
        force_expires: Some(100),
        retirement_expires: Some(130),
        delivery_expires: Some(140),
        retirement: RetirementEvidence::Complete {
            at: 120,
            target_reaped_or_absent: true,
            group_reconciled: true,
            detached_identities_discharged: true,
            native_obligations_settled: true,
            policy_retired: true,
        },
        delivery: DeliveryEvidence::Prepared,
    }
}

#[test]
fn completed_runtime_round_trips_without_claiming_its_own_delivery() {
    let record = complete();
    assert!(record.is_consistent());
    assert_eq!(
        serde_json::from_value::<RuntimeEvidenceV1>(serde_json::to_value(&record).unwrap())
            .unwrap(),
        record
    );
}

#[test]
fn release_at_startup_or_work_expiry_is_rejected() {
    for expiry in [80, 100] {
        let mut record = complete();
        record.release = ReleaseEvidence::Issued {
            at: expiry,
            exec_confirmed: false,
        };
        assert!(!record.is_consistent());
    }
}

#[test]
fn unknown_release_and_incomplete_native_proof_cannot_claim_retirement() {
    let mut record = complete();
    record.release = ReleaseEvidence::Unknown;
    assert!(!record.is_consistent());
    let mut value = serde_json::to_value(complete()).unwrap();
    value["retirement"]["native_obligations_settled"] = false.into();
    assert!(serde_json::from_value::<RuntimeEvidenceV1>(value).is_err());
}

#[test]
fn strict_runtime_decoder_rejects_missing_identity_zero_pid_and_extra_fields() {
    for replacement in [serde_json::Value::Null, 0.into()] {
        let mut value = serde_json::to_value(complete()).unwrap();
        value["target_pid"] = replacement;
        assert!(serde_json::from_value::<RuntimeEvidenceV1>(value).is_err());
    }
    let mut value = serde_json::to_value(complete()).unwrap();
    value["future_authority"] = true.into();
    assert!(serde_json::from_value::<RuntimeEvidenceV1>(value).is_err());
}

#[test]
fn late_cleanup_does_not_extend_the_original_retirement_boundary() {
    let mut value = serde_json::to_value(complete()).unwrap();
    value["retirement"]["at"] = 131.into();
    assert!(serde_json::from_value::<RuntimeEvidenceV1>(value).is_err());
}

#[test]
fn pending_retirement_requires_bounded_nonempty_obligations_and_positive_owner() {
    let mut value = serde_json::to_value(complete()).unwrap();
    value["retirement"] = serde_json::json!({
        "state": "pending", "owner": { "pid": 77, "start_identity": 10 },
        "obligations": ["group-reconciliation"]
    });
    assert!(serde_json::from_value::<RuntimeEvidenceV1>(value.clone()).is_ok());
    let mut empty = value.clone();
    empty["retirement"]["obligations"] = serde_json::json!([]);
    assert!(serde_json::from_value::<RuntimeEvidenceV1>(empty).is_err());
    value["retirement"]["obligations"] = serde_json::json!(vec![
        "group-reconciliation";
        memcordon_core::MAX_RETIREMENT_OBLIGATIONS
            + 1
    ]);
    assert!(serde_json::from_value::<RuntimeEvidenceV1>(value).is_err());
}

#[test]
fn pre_release_deadline_preserves_absence_and_independent_retirement_reserve() {
    let mut record = complete();
    record.release = ReleaseEvidence::NotIssued;
    record.target_pid = None;
    record.startup_expires = 20;
    record.work_expires = Some(20);
    record.terminal_observed = Some(20);
    record.force_expires = Some(20);
    assert!(record.is_consistent());
}
