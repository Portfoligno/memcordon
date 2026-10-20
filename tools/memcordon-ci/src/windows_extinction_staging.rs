/// A successful convergence query may still retain the exact outbox for ACK.
/// This admits only the next authenticated recovery operation, never closure.
pub fn accepts_pending_authority(
    native_status: Option<i32>,
    inventory: &memcordon_core::WindowsRecoveryInventoryV1,
    provider_generation: &str,
) -> bool {
    native_status == Some(0)
        && inventory.is_consistent()
        && inventory.provider_generation == provider_generation
        && inventory.unacknowledged_outboxes == 1
        && inventory.incomplete_proof == 0
}
