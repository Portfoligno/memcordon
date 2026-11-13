use memcordon_ci::linux_execution_order::prioritize_bytes;

#[test]
fn local_priority_keeps_every_case_payload_and_both_relative_orders() {
    let catalogue = vec![
        ("L-MIX-01", "joint-build-tcp-unix-http", 10),
        ("L-LIFE-03", "deadline", 11),
        ("C-IO", "binary-streams", 12),
        ("L-MIX-05", "binary-streams", 13),
        ("C-IO", "binary-file", 14),
        ("C-IO", "empty-message", 15),
        ("L-MIX-05", "empty-message", 16),
        ("C-IO", "empty-input", 17),
        ("L-MIX-05", "empty-input", 18),
        ("C-IO", "bounded-large-output", 19),
        ("L-MIX-05", "bounded-large-output", 20),
        ("L-LIFE-05", "relay-backpressure", 21),
        ("other", "binary-streams", 22),
    ];
    let execution = prioritize_bytes(catalogue.clone(), |entry| (entry.0, entry.1));
    let expected = [12, 13, 15, 16, 17, 18, 19, 20, 10, 11, 14, 21, 22];
    assert_eq!(
        execution.iter().map(|entry| entry.2).collect::<Vec<_>>(),
        expected
    );
    for entry in &catalogue {
        assert_eq!(
            execution
                .iter()
                .filter(|candidate| *candidate == entry)
                .count(),
            1
        );
    }
    assert_eq!(catalogue[0], ("L-MIX-01", "joint-build-tcp-unix-http", 10));
}

#[test]
fn empty_or_already_prioritized_execution_is_unchanged() {
    let empty: Vec<(String, String)> = Vec::new();
    assert!(prioritize_bytes(empty, |entry| (&entry.0, &entry.1)).is_empty());
    let cases = vec![("C-IO", "binary-streams"), ("L-MIX-01", "joint")];
    assert_eq!(
        prioritize_bytes(cases.clone(), |entry| (entry.0, entry.1)),
        cases
    );
}
