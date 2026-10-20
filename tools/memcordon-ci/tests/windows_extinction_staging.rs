#[path = "../src/windows_extinction_staging.rs"]
mod staging;

use memcordon_core::WindowsRecoveryInventoryV1;

fn retained_inventory() -> WindowsRecoveryInventoryV1 {
    // Real Converge response shape: successful transport retains authority.
    serde_json::from_value(serde_json::json!({
        "schema_version": 1,
        "challenge": "215c2a2801d550871a93e496c3c5a9efe67898f3f10dda5bddbcf40f8ca0c5b2",
        "provider_generation": "0.5.8-dev:047d36d19343ce928a174acca25c2742f7a6128b",
        "current_boot_identity": "134368488375000000",
        "executing": 0,
        "incomplete_proof": 0,
        "unacknowledged_outboxes": 1,
        "ack_retirement_in_progress": 0,
        "completed_tombstones": 8,
        "active_admissions": 1,
        "quarantined": 0
    }))
    .unwrap()
}

#[test]
fn successful_query_admits_only_next_authenticated_recovery() {
    let inventory = retained_inventory();
    assert!(inventory.authority_unsettled());
    assert!(staging::accepts_pending_authority(
        Some(0),
        &inventory,
        &inventory.provider_generation
    ));
    for status in [None, Some(1), Some(125)] {
        assert!(!staging::accepts_pending_authority(
            status,
            &inventory,
            &inventory.provider_generation
        ));
    }
    assert!(!staging::accepts_pending_authority(
        Some(0),
        &inventory,
        "foreign-provider"
    ));
}

#[test]
fn staging_preserves_exact_outbox_and_proof_conditions() {
    let inventory = retained_inventory();
    for count in [0, 2] {
        let mut changed = inventory.clone();
        changed.unacknowledged_outboxes = count;
        assert!(!staging::accepts_pending_authority(
            Some(0),
            &changed,
            &inventory.provider_generation
        ));
    }
    let mut changed = inventory.clone();
    changed.incomplete_proof = 1;
    assert!(!staging::accepts_pending_authority(
        Some(0),
        &changed,
        &inventory.provider_generation
    ));
}

#[test]
fn malformed_inventory_cannot_admit_recovery() {
    let inventory = retained_inventory();
    let mut invalid = vec![inventory.clone(); 5];
    invalid[0].schema_version = 2;
    invalid[1].challenge.clear();
    invalid[2].provider_generation.clear();
    invalid[3].current_boot_identity.clear();
    invalid[4].completed_tombstones = u32::MAX;
    for changed in invalid {
        assert!(!changed.is_consistent());
        assert!(!staging::accepts_pending_authority(
            Some(0),
            &changed,
            &inventory.provider_generation
        ));
    }
}
