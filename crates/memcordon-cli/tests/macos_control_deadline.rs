#![cfg(all(target_os = "macos", feature = "test-fixtures"))]

#[test]
fn complete_exec_receipt_survives_post_write_deadline() {
    memcordon_platform::test_support::complete_exec_receipt_survives_post_write_deadline();
}

#[test]
fn buffered_child_status_does_not_delay_inventory() {
    memcordon_platform::test_support::buffered_child_status_does_not_delay_inventory();
}

#[test]
fn delayed_child_status_retains_observation_and_reaping() {
    memcordon_platform::test_support::delayed_child_status_retains_observation_and_reaping();
}

#[test]
fn delayed_child_status_cannot_be_confused_with_inventory() {
    memcordon_platform::test_support::delayed_child_status_cannot_be_confused_with_inventory();
}

#[test]
fn expired_unsent_inventory_preserves_the_retirement_channel() {
    memcordon_platform::test_support::macos_expired_control_request_preserves_retirement().unwrap();
}

#[test]
fn partially_sent_control_frames_cannot_be_reused_for_retirement() {
    memcordon_platform::test_support::macos_partial_control_frame_invalidates_retirement().unwrap();
}
