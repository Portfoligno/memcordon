//! Current SID authority policy, independent of historical token filtering.

/// Reject deny-only user or group state, including groups unrelated to
/// Administrators. Native callers supply their fully bounded SID inventory.
pub fn require_no_deny_only(
    user_attributes: u32,
    group_attributes: impl IntoIterator<Item = u32>,
) -> Result<(), String> {
    // SE_GROUP_USE_FOR_DENY_ONLY, defined by the Windows access-token contract.
    const DENY_ONLY: u32 = 0x10;
    if user_attributes & DENY_ONLY != 0 {
        return Err("creation carrier has deny-only user SID".into());
    }
    for (index, attributes) in group_attributes.into_iter().enumerate() {
        if attributes & DENY_ONLY != 0 {
            return Err(format!(
                "creation carrier has deny-only group SID at index={index}"
            ));
        }
    }
    Ok(())
}
