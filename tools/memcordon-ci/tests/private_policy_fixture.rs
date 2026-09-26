#[path = "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/linux/private_release_policy_fixture.rs"]
mod private_release_policy_fixture;

#[test]
fn reviewed_policy_topology_is_embedded_and_exact() {
    let fixture = private_release_policy_fixture::acquire_reviewed_policy_fixture().unwrap();
    assert_eq!(fixture.branch_order()[0], "wrong-grant");
    assert_eq!(fixture.branch_order()[1], "wrong-profile");
    assert_eq!(fixture.branch_order()[2], "unapproved-changed-port-plan");
    assert_eq!(fixture.branch_order()[3], "committed-port-tamper");
    assert_ne!(
        fixture.digest(),
        memcordon_core::workload_codec::hash_bytes(b"")
    );
}
