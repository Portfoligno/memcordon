#![cfg(all(target_os = "macos", feature = "test-fixtures"))]

use std::path::Path;

#[test]
fn confirmed_exec_receipt_retains_the_startup_deadline() {
    memcordon_platform::test_support::macos_delayed_released_receipt(Path::new(env!(
        "CARGO_BIN_EXE_memcordon"
    )))
    .unwrap();
}

#[test]
fn heartbeat_retains_the_inspection_deadline() {
    memcordon_platform::test_support::macos_delayed_heartbeat(Path::new(env!(
        "CARGO_BIN_EXE_memcordon"
    )))
    .unwrap();
}

#[test]
fn observed_status_retains_the_retirement_reserve() {
    memcordon_platform::test_support::macos_delayed_observed_status(Path::new(env!(
        "CARGO_BIN_EXE_memcordon"
    )))
    .unwrap();
}

#[test]
fn retired_receipt_retains_the_cleanup_deadline() {
    memcordon_platform::test_support::macos_delayed_retired_receipt(Path::new(env!(
        "CARGO_BIN_EXE_memcordon"
    )))
    .unwrap();
}

#[test]
fn reaped_status_retains_the_cleanup_deadline() {
    memcordon_platform::test_support::macos_delayed_reaped_status(Path::new(env!(
        "CARGO_BIN_EXE_memcordon"
    )))
    .unwrap();
}

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
