//! Structural finite-vector checks; no native capacity observation is claimed.
use memcordon_readiness_verifier::*;

fn key(scenario: &str) -> CaseKey {
    CaseKey {
        target: "x86_64-pc-windows-msvc".into(),
        channel: Some("candidate-native".into()),
        family: "W-CAPACITY".into(),
        scenario: scenario.into(),
        evidence_class: EvidenceClass::InstalledProduct,
    }
}
fn vector(attempts: usize, inventories: usize, overlap: bool) -> WindowsCapacityEvidence {
    WindowsCapacityEvidence {
        attempts: (0..attempts)
            .map(|n| format!("case/attempt-{n}/evidence.json"))
            .collect(),
        inventories: (0..inventories)
            .map(|n| format!("case/inventory-{n}.json"))
            .collect(),
        overlap_live_association: overlap.then(|| "case/overlap-live-association.json".into()),
        overlap_held_guardian: overlap.then(|| "case/overlap-held-guardian.json".into()),
    }
}
#[test]
fn capacity_requires_every_distinct_constituent_and_overlap_owner() {
    for (scenario, attempts, inventories, overlap) in [
        ("serial-retirement", 3, 4, false),
        ("bounded-concurrency", 2, 2, true),
        ("fresh-positive-after-recovery", 1, 2, false),
    ] {
        let baseline = vector(attempts, inventories, overlap);
        assert!(validate_windows_capacity_shape(&baseline, &key(scenario)).is_ok());
        let mut omitted = baseline.clone();
        omitted.attempts.pop();
        assert!(validate_windows_capacity_shape(&omitted, &key(scenario)).is_err());
        let mut omitted = baseline.clone();
        omitted.inventories.pop();
        assert!(validate_windows_capacity_shape(&omitted, &key(scenario)).is_err());
        let mut reused = baseline.clone();
        reused.inventories[0] = reused.attempts[0].clone();
        assert!(validate_windows_capacity_shape(&reused, &key(scenario)).is_err());
        let mut changed = baseline.clone();
        changed.overlap_live_association = if overlap {
            None
        } else {
            Some("extra.json".into())
        };
        assert!(validate_windows_capacity_shape(&changed, &key(scenario)).is_err());
    }
    assert!(validate_windows_capacity_shape(&vector(3, 4, false), &key("unknown")).is_err());
}

#[test]
fn capacity_inventory_rejects_other_generation_and_unsettled_authority() {
    let baseline = serde_json::json!({"schema_version":1,"challenge":"actual-response-challenge","provider_generation":"selected-generation",
        "current_boot_identity":"same-boot","executing":0,"incomplete_proof":0,"unacknowledged_outboxes":0,
        "ack_retirement_in_progress":0,"completed_tombstones":4,"active_admissions":0,"quarantined":0});
    assert!(validate_windows_capacity_inventory(&baseline, "selected-generation").is_ok());
    for field in [
        "executing",
        "incomplete_proof",
        "unacknowledged_outboxes",
        "ack_retirement_in_progress",
        "active_admissions",
        "quarantined",
    ] {
        let mut changed = baseline.clone();
        changed[field] = serde_json::json!(1);
        assert!(
            validate_windows_capacity_inventory(&changed, "selected-generation").is_err(),
            "{field}"
        );
    }
    assert!(validate_windows_capacity_inventory(&baseline, "different-generation").is_err());
    let mut changed = baseline.clone();
    changed["authority_unsettled"] = serde_json::json!(false);
    assert!(validate_windows_capacity_inventory(&changed, "selected-generation").is_err());
    let mut changed = baseline.clone();
    changed["completed_tombstones"] = serde_json::json!(u64::from(u32::MAX) + 1);
    assert!(validate_windows_capacity_inventory(&changed, "selected-generation").is_err());
}
#[test]
fn raw_overlap_exclusions_reject_missing_reassociated_or_unheld_native_owners() {
    use memcordon_readiness_verifier::{HeldProcessIdentity, validate_windows_capacity_exclusions};
    use serde_json::json;
    // Structural vectors exercise the production binding decoder. They do not
    // represent executed Windows processes or an observed capacity verdict.
    let live = json!({"association":{"attempt_id":"first","request_sha256":"aa"},"live_nonce":"first-nonce"});
    let raw = json!([
        {"pid":11,"birth":101,"held_live_before_overlap":true,"still_live_at_own_retirement":true},
        {"pid":12,"birth":102,"held_live_before_overlap":true,"still_live_at_own_retirement":true}
    ]);
    let expected = [(11, 101), (12, 102)];
    validate_windows_capacity_exclusions(&raw, &live, &live, &expected, &[]).unwrap();
    let mut changed = raw.clone();
    changed.as_array_mut().unwrap().pop();
    assert!(validate_windows_capacity_exclusions(&changed, &live, &live, &expected, &[]).is_err());
    for field in [
        "pid",
        "birth",
        "held_live_before_overlap",
        "still_live_at_own_retirement",
    ] {
        let mut changed = raw.clone();
        changed[1][field] = if field == "pid" {
            json!(13)
        } else if field == "birth" {
            json!(103)
        } else {
            json!(false)
        };
        assert!(
            validate_windows_capacity_exclusions(&changed, &live, &live, &expected, &[]).is_err(),
            "{field}"
        );
    }
    let mut duplicate = raw.clone();
    duplicate[1] = duplicate[0].clone();
    assert!(
        validate_windows_capacity_exclusions(&duplicate, &live, &live, &expected, &[]).is_err()
    );
    let mut unknown = raw.clone();
    unknown[0]["selected"] = json!(true);
    assert!(validate_windows_capacity_exclusions(&unknown, &live, &live, &expected, &[]).is_err());
    let mut other = live.clone();
    other["association"]["attempt_id"] = json!("other");
    assert!(validate_windows_capacity_exclusions(&raw, &other, &live, &expected, &[]).is_err());
    let own = [HeldProcessIdentity {
        pid: 12,
        birth: 102,
        parent_pid: Some(11),
        parent_birth: Some(101),
        retirement_observed: true,
    }];
    assert!(validate_windows_capacity_exclusions(&raw, &live, &live, &expected, &own).is_err());
    assert!(
        validate_windows_capacity_exclusions(&raw, &live, &live, &[(11, 101), (11, 101)], &[])
            .is_err()
    );
}
