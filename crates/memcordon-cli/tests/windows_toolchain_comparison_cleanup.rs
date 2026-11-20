#![cfg(all(windows, feature = "test-fixtures"))]

#[path = "../src/bin/consumer_readiness_windows/toolchain_process_wait.rs"]
mod toolchain_process_wait;

#[test]
fn failed_comparison_setup_retires_the_still_owned_child() {
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_memcordon-test-fixture"))
        .args(["hold", "--duration", "30s"])
        .spawn()
        .expect("spawn comparison cleanup fixture");
    let before = toolchain_process_wait::wait_retired(&child, 0);
    let (signaled, status) =
        toolchain_process_wait::terminate_failed_child(&mut child, || Ok(5_000));
    assert!(
        before.is_err(),
        "fixture unexpectedly retired before cleanup"
    );
    assert!(signaled, "termination request did not prove retirement");
    assert!(status.expect("retired child native status").is_some());
    toolchain_process_wait::wait_retired(&child, 0).expect("still-held child must remain signaled");
}
