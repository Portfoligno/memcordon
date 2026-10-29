use memcordon_core::{WindowsProviderRequestV4, WindowsTerminalDrainControl};

#[test]
fn cancellation_in_flight_does_not_replace_terminal_ack_or_cross_attempts() {
    let cancel = WindowsProviderRequestV4::Cancel {
        schema_version: 4,
        attempt_id: "actual-attempt".into(),
        nonce: "actual-nonce".into(),
        request_sha256: "actual-request".into(),
        signal: 2,
    };
    let ack = WindowsProviderRequestV4::TerminalAcknowledged {
        schema_version: 4,
        attempt_id: "actual-attempt".into(),
        nonce: "actual-nonce".into(),
        request_sha256: "actual-request".into(),
        terminal_response_sha256: "actual-terminal".into(),
    };
    assert_eq!(
        cancel.terminal_drain_control(
            "actual-attempt",
            "actual-nonce",
            "actual-request",
            "actual-terminal"
        ),
        Some(WindowsTerminalDrainControl::Cancellation)
    );
    assert_eq!(
        ack.terminal_drain_control(
            "actual-attempt",
            "actual-nonce",
            "actual-request",
            "actual-terminal"
        ),
        Some(WindowsTerminalDrainControl::Acknowledgment)
    );
    for message in [cancel, ack] {
        for (attempt, nonce, request, terminal) in [
            (
                "foreign-attempt",
                "actual-nonce",
                "actual-request",
                "actual-terminal",
            ),
            (
                "actual-attempt",
                "foreign-nonce",
                "actual-request",
                "actual-terminal",
            ),
            (
                "actual-attempt",
                "actual-nonce",
                "foreign-request",
                "actual-terminal",
            ),
        ] {
            assert_eq!(
                message.terminal_drain_control(attempt, nonce, request, terminal),
                None
            );
        }
    }
    assert_eq!(
        WindowsProviderRequestV4::TerminalAcknowledged {
            schema_version: 4,
            attempt_id: "actual-attempt".into(),
            nonce: "actual-nonce".into(),
            request_sha256: "actual-request".into(),
            terminal_response_sha256: "foreign-terminal".into()
        }
        .terminal_drain_control(
            "actual-attempt",
            "actual-nonce",
            "actual-request",
            "actual-terminal"
        ),
        None
    );
}
