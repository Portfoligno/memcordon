//! Closed ACL contract for a test-owned namespace, never a child event policy.
use std::io;

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "namespace ACL contract differs",
    )
}

pub fn user_sid(user_acl: &[u8]) -> io::Result<&[u8]> {
    // Reuse the source-used planner's finite ACL/SID grammar first.
    let planned = super::policy::plan(Some(user_acl))?;
    if user_acl.len() < 24
        || user_acl[4..6] != 1u16.to_le_bytes()
        || user_acl[8..10] != [0, 0]
        || user_acl[12..16] != 0x1000_0000u32.to_le_bytes()
        || usize::from(u16::from_le_bytes([user_acl[10], user_acl[11]])) != user_acl.len() - 8
        || planned.len() == user_acl.len()
    {
        return Err(invalid());
    }
    Ok(&user_acl[16..])
}

pub fn plan(user_acl: &[u8]) -> io::Result<Vec<u8>> {
    let sid = user_sid(user_acl)?;
    let result = super::policy::plan(Some(user_acl))?;
    validate(&result, sid)?;
    Ok(result)
}

pub fn validate(raw: &[u8], user: &[u8]) -> io::Result<()> {
    if super::policy::plan(Some(raw))? != raw || raw[4..6] != 2u16.to_le_bytes() {
        return Err(invalid());
    }
    let first_size = usize::from(u16::from_le_bytes([raw[10], raw[11]]));
    let second = 8usize.checked_add(first_size).ok_or_else(invalid)?;
    let first = raw.get(8..second).ok_or_else(invalid)?;
    let last = raw.get(second..).ok_or_else(invalid)?;
    for (ace, sid) in [(first, user), (last, super::policy::RESTRICTED_CODE_SID)] {
        if ace.len() < 16
            || ace[0..2] != [0, 0]
            || usize::from(u16::from_le_bytes([ace[2], ace[3]])) != ace.len()
            || ace[4..8] != 0x1000_0000u32.to_le_bytes()
            || &ace[8..] != sid
        {
            return Err(invalid());
        }
    }
    Ok(())
}
