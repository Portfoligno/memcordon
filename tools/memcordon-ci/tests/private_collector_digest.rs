use memcordon_ci::private_completed_run::collect_private_q_after_completed_producer;
use memcordon_ci::private_suite::parse_collector_intent_digest;
use memcordon_core::workload_codec::hash_bytes;

#[test]
fn candidate_channel_accepts_only_a_bounded_lowercase_nonempty_sha256_digest() {
    let expected = hash_bytes(b"independently protected collector intent");
    let encoded = String::from(expected.clone());
    assert_eq!(parse_collector_intent_digest(&encoded).unwrap(), expected);
    for invalid in [
        String::new(),
        "0".repeat(encoded.len()),
        String::from(hash_bytes(&[])),
        encoded.to_ascii_uppercase(),
        encoded[..encoded.len() - 1].to_owned(),
        format!("{encoded}0"),
        format!("{encoded}\n"),
    ] {
        assert!(
            parse_collector_intent_digest(&invalid).is_err(),
            "accepted {invalid:?}"
        );
    }
}

#[test]
fn cq_collector_rejects_nonfresh_or_relative_output_before_actions_readback() {
    let root = std::path::Path::new("/tmp/collector-fixture-unavailable");
    assert!(
        collect_private_q_after_completed_producer(
            root,
            root,
            std::path::Path::new("relative-q-bundle.json")
        )
        .is_err()
    );
    assert!(
        collect_private_q_after_completed_producer(root, root, std::path::Path::new("/tmp"))
            .is_err()
    );
}
