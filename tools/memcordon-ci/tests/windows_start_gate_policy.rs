#[path = "../src/windows_start_gate_policy.rs"]
mod policy;

#[test]
fn selected_waiter_is_exact_noninheritable_sync_without_changing_existing_grants() {
    let user = [1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 42, 0, 0, 0];
    let actual = policy::sddl(&user, "S-1-5-21-42").unwrap();
    assert_eq!(policy::WAIT_ACCESS, 0x0010_0000);
    assert_eq!(
        actual,
        format!("{}(A;;0x00100000;;;S-1-5-21-42)", policy::BASE_SDDL)
    );
    for text in [
        "S-1-5-21-43",
        "S-1-5-21-42-1",
        "S-1-5-21",
        "S-1-5-21-42)(A;;GA;;;WD)",
        "BA",
    ] {
        assert!(policy::sddl(&user, text).is_err());
    }
}

#[test]
fn full_binary_sid_extent_precedes_native_conversion_and_policy_admission() {
    let valid = [1, 1, 0, 0, 0, 0, 0, 5, 42, 0, 0, 0];
    for length in 0..valid.len() {
        assert!(policy::validate_sid(&valid[..length]).is_err());
    }
    let mut oversized = valid.to_vec();
    oversized.push(0);
    assert!(policy::validate_sid(&oversized).is_err());
    let mut wrong = valid;
    wrong[0] = 2;
    assert!(policy::validate_sid(&wrong).is_err());
    let mut wrong = valid;
    wrong[1] = 16;
    assert!(policy::validate_sid(&wrong).is_err());
    assert!(policy::sddl(&valid, "S-1-5-4294967296").is_err());
    assert!(policy::sddl(&valid, "S-1-281474976710656-42").is_err());
}
