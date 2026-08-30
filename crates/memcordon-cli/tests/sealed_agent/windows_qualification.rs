use memcordon_core::{
    WINDOWS_PUBLIC_PROTOCOL_VERSION, WindowsProcessIdentityV1, WindowsRelayPhaseV1,
};
use std::cell::Cell;

#[test]
fn qualification_accepts_only_locally_derived_pre_stream_reject_attempts() {
    let nonce = "qualification-reject-binding";
    let request_sha256 = "ab".repeat(32);
    let caller = WindowsProcessIdentityV1 {
        process_id: 42,
        creation_time_100ns: 123_456_789,
    };
    let process_attempt = crate::windows::qualification::qualification_process_attempt_id(
        nonce,
        &request_sha256,
        &caller,
    );
    let pretarget_attempt =
        crate::windows::qualification::qualification_pretarget_attempt_id(nonce, &request_sha256);
    assert_ne!(process_attempt, pretarget_attempt);
    let rejection = crate::windows::record::pretarget_rejection(
        "MCSEALED-WINDOWS-TEST",
        "bound pre-stream rejection".to_owned(),
    );

    for returned_attempt in [&process_attempt, &pretarget_attempt] {
        crate::windows::qualification::validate_native_reject(
            WINDOWS_PUBLIC_PROTOCOL_VERSION,
            returned_attempt,
            nonce,
            &request_sha256,
            &rejection,
            None,
            &process_attempt,
            &pretarget_attempt,
            nonce,
            &request_sha256,
            WindowsRelayPhaseV1::AwaitStreams,
        )
        .unwrap();
    }

    let error = crate::windows::qualification::validate_native_reject(
        WINDOWS_PUBLIC_PROTOCOL_VERSION,
        &"cd".repeat(32),
        nonce,
        &request_sha256,
        &rejection,
        None,
        &process_attempt,
        &pretarget_attempt,
        nonce,
        &request_sha256,
        WindowsRelayPhaseV1::AwaitStreams,
    )
    .unwrap_err();
    assert!(error.contains("variant=reject"));
    assert!(error.contains("predicate=attempt-id"));

    for (schema, returned_nonce, returned_digest, observed_rejection, predicate) in [
        (
            WINDOWS_PUBLIC_PROTOCOL_VERSION + 1,
            nonce,
            request_sha256.as_str(),
            rejection.clone(),
            "schema",
        ),
        (
            WINDOWS_PUBLIC_PROTOCOL_VERSION,
            "wrong-nonce",
            request_sha256.as_str(),
            rejection.clone(),
            "nonce",
        ),
        (
            WINDOWS_PUBLIC_PROTOCOL_VERSION,
            nonce,
            "wrong-digest",
            rejection.clone(),
            "request-digest",
        ),
        (
            WINDOWS_PUBLIC_PROTOCOL_VERSION,
            nonce,
            request_sha256.as_str(),
            {
                let mut inconsistent = rejection.clone();
                inconsistent.code = "not-stable".to_owned();
                inconsistent
            },
            "rejection-consistency",
        ),
    ] {
        let error = crate::windows::qualification::validate_native_reject(
            schema,
            &process_attempt,
            returned_nonce,
            returned_digest,
            &observed_rejection,
            None,
            &process_attempt,
            &pretarget_attempt,
            nonce,
            &request_sha256,
            WindowsRelayPhaseV1::AwaitStreams,
        )
        .unwrap_err();
        assert!(error.contains(&format!("predicate={predicate}")));
    }
}

#[test]
fn qualification_post_stream_reject_is_pinned_to_the_active_attempt() {
    let nonce = "qualification-active-reject";
    let request_sha256 = "ef".repeat(32);
    let active_attempt = "12".repeat(32);
    let rejection = crate::windows::record::pretarget_rejection(
        "MCSEALED-WINDOWS-TEST",
        "bound post-stream rejection".to_owned(),
    );
    crate::windows::qualification::validate_native_reject(
        WINDOWS_PUBLIC_PROTOCOL_VERSION,
        &active_attempt,
        nonce,
        &request_sha256,
        &rejection,
        Some(&active_attempt),
        &"34".repeat(32),
        &"56".repeat(32),
        nonce,
        &request_sha256,
        WindowsRelayPhaseV1::Authorized,
    )
    .unwrap();

    let error = crate::windows::qualification::validate_native_reject(
        WINDOWS_PUBLIC_PROTOCOL_VERSION,
        &"78".repeat(32),
        nonce,
        &request_sha256,
        &rejection,
        Some(&active_attempt),
        &"34".repeat(32),
        &"56".repeat(32),
        nonce,
        &request_sha256,
        WindowsRelayPhaseV1::Authorized,
    )
    .unwrap_err();
    assert!(error.contains("predicate=attempt-id"));
}

#[test]
fn failed_qualification_terminal_is_acknowledged_before_semantics_propagate() {
    let semantic_latched = Cell::new(false);
    let acknowledgment_attempted = Cell::new(false);
    let pending_terminal_outbox = Cell::new(true);
    let semantic_result = {
        semantic_latched.set(true);
        Err::<(), _>("primary semantic failure".to_owned())
    };

    let error = crate::windows::qualification::acknowledge_latched_qualification_terminal_for_test(
        semantic_result,
        "attempt-bound-terminal",
        "nonce-bound-terminal",
        &"ab".repeat(32),
        || {
            assert!(
                semantic_latched.get(),
                "semantics must be latched before ACK"
            );
            acknowledgment_attempted.set(true);
            pending_terminal_outbox.set(false);
            Ok(())
        },
    )
    .unwrap_err();

    assert!(acknowledgment_attempted.get());
    assert!(
        !pending_terminal_outbox.get(),
        "a successfully forwarded bound ACK must permit launcher outbox retirement"
    );
    assert_eq!(error, "primary semantic failure");
}

#[test]
fn failed_terminal_ack_preserves_primary_and_secondary_evidence() {
    let acknowledgment_attempted = Cell::new(false);
    let pending_terminal_outbox = Cell::new(true);
    let error = crate::windows::qualification::acknowledge_latched_qualification_terminal_for_test(
        Err::<(), _>("primary semantic failure".to_owned()),
        "attempt-bound-terminal",
        "nonce-bound-terminal",
        &"cd".repeat(32),
        || {
            acknowledgment_attempted.set(true);
            Err("native pipe write failed".to_owned())
        },
    )
    .unwrap_err();

    assert!(acknowledgment_attempted.get());
    assert!(
        pending_terminal_outbox.get(),
        "a failed ACK must leave the durable terminal outbox pending"
    );
    assert!(error.starts_with("primary semantic failure;"));
    assert!(error.contains("terminal acknowledgment failed after bound receipt was latched"));
    assert!(error.contains("MCSEALED-WINDOWS-TERMINAL-ACKNOWLEDGMENT"));
    assert!(error.contains("stage=bound-receipt-write"));
    assert!(error.contains("api=WriteFile(named-pipe-frame)"));
    assert!(error.contains("attempt_id=attempt-bound-terminal"));
    assert!(error.contains("request_sha256=cdcd"));
    assert!(error.ends_with("detail=native pipe write failed"));

    let acknowledgment_only =
        crate::windows::qualification::acknowledge_latched_qualification_terminal_for_test(
            Ok("semantic evidence"),
            "attempt-bound-terminal",
            "nonce-bound-terminal",
            &"ef".repeat(32),
            || Err("native pipe write failed".to_owned()),
        )
        .unwrap_err();
    assert!(acknowledgment_only.starts_with("MCSEALED-WINDOWS-TERMINAL-ACKNOWLEDGMENT"));
    assert!(!acknowledgment_only.contains("primary semantic failure"));
}
