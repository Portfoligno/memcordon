//! Default-created-object policy for the trusted RC-restricted readiness fixture.
//! This is not a transformation of arbitrary provider caller tokens.
use std::io;

pub const MAX_ACL_BYTES: usize = 8 * 1024;
pub const MAX_ACES: usize = 64;
/// Canonical binary S-1-5-12: revision, count, identifier authority, RID.
pub const RESTRICTED_CODE_SID: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 12, 0, 0, 0];

const ACL_REVISION: u8 = 2;
const ACL_HEADER_BYTES: usize = 8;
const ACE_HEADER_BYTES: usize = 4;
const MASK_BYTES: usize = std::mem::size_of::<u32>();
const SID_HEADER_BYTES: usize = 8;
const MAX_SID_SUB_AUTHORITIES: usize = 15;
const ACCESS_ALLOWED: u8 = 0;
const ACCESS_DENIED: u8 = 1;
const VALID_INHERIT_FLAGS: u8 = 0x1f;
const GENERIC_ALL: u32 = 0x1000_0000;

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason)
}

/// Preserve every original ACE and append only an explicit RC GENERIC_ALL
/// allow. The supported closed form is a packed revision-2 ACL containing
/// basic allow/deny ACEs; null, opaque capacity and unknown semantics refuse.
pub fn plan(existing: Option<&[u8]>) -> io::Result<Vec<u8>> {
    append_grant(existing, RESTRICTED_CODE_SID, true)
}

/// Append only the existing token user's explicit allow for a disposable
/// diagnostic token. Keep every original ACE and its order.
#[cfg(any(windows, test))]
pub(super) fn plan_console_user(existing: Option<&[u8]>, user: &[u8]) -> io::Result<Vec<u8>> {
    if !exact_sid(user) {
        return Err(invalid("console calibration user SID differs"));
    }
    append_grant(existing, user, false)
}

fn exact_sid(sid: &[u8]) -> bool {
    sid.len() >= SID_HEADER_BYTES
        && sid[0] == 1
        && usize::from(sid[1]) <= MAX_SID_SUB_AUTHORITIES
        && sid.len() == SID_HEADER_BYTES + usize::from(sid[1]) * MASK_BYTES
}

fn append_grant(existing: Option<&[u8]>, grantee: &[u8], rc_policy: bool) -> io::Result<Vec<u8>> {
    let raw = existing.ok_or_else(|| invalid("restricted fixture default ACL must be non-null"))?;
    if raw.len() < ACL_HEADER_BYTES || raw.len() > MAX_ACL_BYTES {
        return Err(invalid(
            "fixture default ACL extent exceeds its finite bound",
        ));
    }
    let size = usize::from(u16::from_le_bytes([raw[2], raw[3]]));
    let count = usize::from(u16::from_le_bytes([raw[4], raw[5]]));
    if raw[0] != ACL_REVISION
        || raw[1] != 0
        || raw[6] != 0
        || raw[7] != 0
        || size != raw.len()
        || size % MASK_BYTES != 0
        || count > MAX_ACES
    {
        return Err(invalid(
            "fixture default ACL header is unsupported or inconsistent",
        ));
    }
    let mut offset = ACL_HEADER_BYTES;
    let mut exact_grant_present = false;
    for _ in 0..count {
        let header_end = offset
            .checked_add(ACE_HEADER_BYTES)
            .ok_or_else(|| invalid("fixture ACE header extent overflows"))?;
        let header = raw
            .get(offset..header_end)
            .ok_or_else(|| invalid("fixture ACE header is truncated"))?;
        let kind = header[0];
        let flags = header[1];
        let length = usize::from(u16::from_le_bytes([header[2], header[3]]));
        let sid_offset = ACE_HEADER_BYTES + MASK_BYTES;
        if !matches!(kind, ACCESS_ALLOWED | ACCESS_DENIED)
            || flags & !VALID_INHERIT_FLAGS != 0
            || length < sid_offset + SID_HEADER_BYTES
            || length % MASK_BYTES != 0
        {
            return Err(invalid("fixture ACE type, flags or extent is unsupported"));
        }
        let end = offset
            .checked_add(length)
            .ok_or_else(|| invalid("fixture ACE extent overflows"))?;
        let ace = raw
            .get(offset..end)
            .ok_or_else(|| invalid("fixture ACE exceeds the original ACL"))?;
        let sid = &ace[sid_offset..];
        if !exact_sid(sid) {
            return Err(invalid(
                "fixture ACE SID is not an exact supported binary SID",
            ));
        }
        if sid == grantee {
            let mask = u32::from_le_bytes(
                ace[ACE_HEADER_BYTES..sid_offset]
                    .try_into()
                    .expect("checked ACE mask extent"),
            );
            let exact = kind == ACCESS_ALLOWED && flags == 0 && mask == GENERIC_ALL;
            if rc_policy && (exact_grant_present || !exact) {
                return Err(invalid(
                    "fixture default ACL has conflicting Restricted Code ACEs",
                ));
            }
            exact_grant_present |= exact;
        }
        offset = end;
    }
    if offset != raw.len() {
        return Err(invalid(
            "fixture default ACL has unsupported unused or trailing bytes",
        ));
    }
    if exact_grant_present {
        return Ok(raw.to_vec());
    }
    let ace_size = ACE_HEADER_BYTES + MASK_BYTES + grantee.len();
    let final_size = raw
        .len()
        .checked_add(ace_size)
        .filter(|size| *size <= MAX_ACL_BYTES)
        .ok_or_else(|| invalid("fixture RC ACL append exceeds its original bound"))?;
    let final_count = count
        .checked_add(1)
        .filter(|count| *count <= MAX_ACES)
        .ok_or_else(|| invalid("fixture RC ACE append exceeds its original bound"))?;
    let final_size =
        u16::try_from(final_size).map_err(|_| invalid("fixture ACL size exceeds native extent"))?;
    let final_count = u16::try_from(final_count)
        .map_err(|_| invalid("fixture ACE count exceeds native extent"))?;
    let ace_size = u16::try_from(ace_size).expect("bounded basic RC ACE size");
    let mut result = Vec::with_capacity(usize::from(final_size));
    result.extend_from_slice(raw);
    result.extend_from_slice(&[ACCESS_ALLOWED, 0]);
    result.extend_from_slice(&ace_size.to_le_bytes());
    result.extend_from_slice(&GENERIC_ALL.to_le_bytes());
    result.extend_from_slice(grantee);
    result[2..4].copy_from_slice(&final_size.to_le_bytes());
    result[4..6].copy_from_slice(&final_count.to_le_bytes());
    Ok(result)
}

#[cfg(test)]
#[test]
fn console_user_variant_preserves_all_previous_aces() {
    const USER: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 19, 0, 0, 0];
    let empty = [ACL_REVISION, 0, ACL_HEADER_BYTES as u8, 0, 0, 0, 0, 0];
    let original = plan(Some(&empty)).unwrap();
    let planned = plan_console_user(Some(&original), USER).unwrap();
    assert_eq!(
        &planned[ACL_HEADER_BYTES..original.len()],
        &original[ACL_HEADER_BYTES..]
    );
    let ace = &planned[original.len()..];
    assert_eq!(&ace[..2], &[ACCESS_ALLOWED, 0]);
    assert_eq!(
        &ace[ACE_HEADER_BYTES..ACE_HEADER_BYTES + MASK_BYTES],
        &GENERIC_ALL.to_le_bytes()
    );
    assert_eq!(&ace[ACE_HEADER_BYTES + MASK_BYTES..], USER);
    assert_eq!(plan_console_user(Some(&planned), USER).unwrap(), planned);
    assert!(plan_console_user(Some(&original), &USER[..USER.len() - 1]).is_err());
    assert!(plan_console_user(None, USER).is_err());
}
