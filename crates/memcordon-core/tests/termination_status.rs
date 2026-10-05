use memcordon_core::ChildTermination;

#[test]
fn successful_platform_statuses_preserve_their_typed_json_forms() {
    for (termination, expected) in [
        (
            ChildTermination::ExitCode { code: 0 },
            serde_json::json!({"kind":"exit-code", "code":0}),
        ),
        (
            ChildTermination::WindowsStatus { status: 0 },
            serde_json::json!({"kind":"windows-status", "status":0}),
        ),
    ] {
        let observed = serde_json::to_value(&termination).unwrap();
        assert_eq!(observed, expected);
        assert_eq!(
            serde_json::from_value::<ChildTermination>(observed).unwrap(),
            termination
        );
    }
    assert_ne!(
        ChildTermination::ExitCode { code: 0 },
        ChildTermination::WindowsStatus { status: 0 }
    );
}
