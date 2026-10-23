//! TokenHasRestrictions (class 21) has BOOLEAN payload, not DWORD payload.
//! Microsoft's maintainer clarified DWORD pointer alignment separately from
//! the one-byte returned value despite the enumeration reference saying DWORD:
//! https://github.com/microsoft/win32metadata/discussions/2308

/// Decode only the returned class-21 BOOLEAN; padding is never flag data.
pub fn decode(storage: &[u8], returned: u32) -> Result<u32, String> {
    if returned != size_of::<u8>() as u32 {
        return Err(format!("invalid BOOLEAN extent={returned}"));
    }
    let value = storage.first().ok_or("BOOLEAN storage truncated")?;
    Ok(u32::from(*value))
}
