use super::*;

#[test]
fn service_relay_event_survives_worker_handle_and_requires_exact_signal() {
    let event_name = format!(
        "Local\\MemCordonSealedRelayRetirement-Test-{}",
        std::process::id()
    );
    let wide_name = pipe::wide_null(&event_name);
    // SAFETY: private named event with no inherited handle.
    let worker_event =
        OwnedHandle::new(unsafe { CreateEventW(ptr::null(), 1, 0, wide_name.as_ptr()) })
            .expect("create relay event");
    let frontend_event = super::super::process::duplicate_owned(worker_event.raw())
        .expect("duplicate frontend event");
    let attempt_id = format!("{:064x}", std::process::id());
    let nonce = "relay-recovery-nonce";
    let request_sha256 = "relay-recovery-request";
    let frontend = memcordon_core::WindowsProcessIdentityV1 {
        process_id: std::process::id(),
        creation_time_100ns: 1,
    };
    register_relay_retirement_event(
        &attempt_id,
        nonce,
        request_sha256,
        &frontend,
        &event_name,
        worker_event.raw(),
    )
    .expect("register service proof handle");
    drop(worker_event);
    assert!(
        !frontend_relay_retired_for_recovery(
            &attempt_id,
            nonce,
            request_sha256,
            &frontend,
            &event_name
        )
        .expect("unsignaled event")
    );
    assert!(
        frontend_relay_retired_for_recovery(
            &attempt_id,
            "wrong-nonce",
            request_sha256,
            &frontend,
            &event_name
        )
        .is_err()
    );
    // SAFETY: the test owns a second handle to the exact event object.
    assert_ne!(unsafe { SetEvent(frontend_event.raw()) }, 0);
    assert!(
        frontend_relay_retired_for_recovery(
            &attempt_id,
            nonce,
            request_sha256,
            &frontend,
            &event_name
        )
        .expect("signaled event")
    );
    retire_relay_retirement_event(&attempt_id).expect("close service proof handle");
    assert!(
        frontend_relay_retired_for_recovery(
            &attempt_id,
            nonce,
            request_sha256,
            &frontend,
            &event_name
        )
        .expect("named event survives service duplicate closure")
    );
    drop(frontend_event);
    assert!(
        !frontend_relay_retired_for_recovery(
            &attempt_id,
            nonce,
            request_sha256,
            &frontend,
            &event_name
        )
        .expect("event vanished after last owner closed")
    );
}
