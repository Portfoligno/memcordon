#![cfg(all(target_os = "macos", feature = "test-fixtures"))]

#[test]
fn expired_unsent_inventory_preserves_the_retirement_channel() {
    memcordon_platform::test_support::macos_expired_control_request_preserves_retirement().unwrap();
}

#[test]
fn partially_sent_control_frames_cannot_be_reused_for_retirement() {
    memcordon_platform::test_support::macos_partial_control_frame_invalidates_retirement().unwrap();
}
