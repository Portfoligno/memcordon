use memcordon_windows_loader_lab::holder_sid_attributes::require_no_deny_only;

#[test]
fn clean_current_sid_state_does_not_depend_on_filtering_history() {
    // Enabled/default/mandatory/owner/integrity/logon flags carry no deny-only
    // authority. Historical filtering is deliberately not an input to policy.
    require_no_deny_only(0, [0x7, 0xf, 0x60, 0xc000_0007]).unwrap();
    require_no_deny_only(0, []).unwrap();
}

#[test]
fn enabled_administrators_cannot_hide_another_deny_only_group() {
    let error = require_no_deny_only(0, [0xf, 0x7, 0x17, 0x7]).unwrap_err();
    assert_eq!(error, "creation carrier has deny-only group SID at index=2");
    assert!(require_no_deny_only(0, [0x10]).is_err());
}

#[test]
fn user_deny_only_is_rejected_even_with_clean_group_state() {
    assert_eq!(
        require_no_deny_only(0x10, [0xf, 0x7]).unwrap_err(),
        "creation carrier has deny-only user SID"
    );
    assert_eq!(
        require_no_deny_only(0x17, [0x10]).unwrap_err(),
        "creation carrier has deny-only user SID"
    );
}
