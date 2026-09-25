use crate::linux::private_release_child_owner::{
    chain_matches_for_test, has_decimal_id_for_test, parse_namespace_chain_for_test,
    parse_status_ids_for_test,
};

#[test]
fn descendant_status_parser_requires_single_kernel_parent_and_group() {
    assert_eq!(
        parse_status_ids_for_test("Name:\tworker\nTgid:\t102\nPPid:\t101\n").unwrap(),
        (102, 101)
    );
    assert!(parse_status_ids_for_test("Tgid:\t102\n").is_err());
    assert!(parse_status_ids_for_test("Tgid:\t102\nTgid:\t102\nPPid:\t101\n").is_err());
    assert!(parse_status_ids_for_test("Tgid:\t102\nPPid:\t-1\n").is_err());
}

#[test]
fn descendant_cgroup_membership_parser_rejects_duplicates_and_invalid_ids() {
    assert!(has_decimal_id_for_test(b"101\n102\n103\n", 102).unwrap());
    assert!(!has_decimal_id_for_test(b"101\n103\n", 102).unwrap());
    assert!(has_decimal_id_for_test(b"102\n102\n", 102).is_err());
    assert!(has_decimal_id_for_test(b"102\nx\n", 102).is_err());
}

#[test]
fn namespace_pid_chain_uses_innermost_target_id_without_confusing_host_pid() {
    assert_eq!(
        parse_namespace_chain_for_test("Name:\tworker\nNSpid:\t4210\t7\n").unwrap(),
        vec![4210, 7]
    );
    assert!(chain_matches_for_test(&[4210, 50, 7], 4210, 7));
    assert!(!chain_matches_for_test(&[4210, 50, 7], 50, 7));
    assert!(!chain_matches_for_test(&[4210, 50, 7], 4210, 50));
    assert!(parse_namespace_chain_for_test("NSpid:\t4210\t7\nNSpid:\t4210\t7\n").is_err());
    assert!(parse_namespace_chain_for_test("NSpid:\t4210\t0\n").is_err());
    assert!(parse_namespace_chain_for_test("NSpid:\t0\t7\n").is_err());
    assert!(parse_namespace_chain_for_test("Name:\tworker\n").is_err());
}
