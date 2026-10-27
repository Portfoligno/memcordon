//! Start-gate-only selected waiter policy. Other event roles keep their policy.
use std::io;
pub const BASE_SDDL: &str = "D:P(A;;GA;;;OW)(A;;GA;;;SY)(A;;0x00100000;;;RC)";
pub const WAIT_ACCESS: u32 = 0x0010_0000;

pub fn validate_sid(bytes: &[u8]) -> io::Result<()> {
    const HEADER: usize = 8;
    const MAX_SUBAUTHORITIES: usize = 15;
    let Some(&count) = bytes.get(1) else {
        return Err(io::Error::other("selected waiter SID header absent"));
    };
    if bytes.first() != Some(&1)
        || usize::from(count) > MAX_SUBAUTHORITIES
        || bytes.len() != HEADER + usize::from(count) * std::mem::size_of::<u32>()
    {
        return Err(io::Error::other(
            "selected waiter SID extent or revision differs",
        ));
    }
    Ok(())
}

/// Native SID text is generated only after the validated native SID query.
/// Match its numeric components back to the exact selected binary SID before
/// inserting it in SDDL, so this helper cannot accept arbitrary policy text.
pub fn sddl(bytes: &[u8], native_text: &str) -> io::Result<String> {
    validate_sid(bytes)?;
    let invalid = || io::Error::other("selected waiter native SID text differs from binary SID");
    let mut fields = native_text
        .strip_prefix("S-")
        .ok_or_else(invalid)?
        .split('-');
    if fields.next() != Some("1") {
        return Err(invalid());
    }
    let authority_text = fields.next().ok_or_else(invalid)?;
    let authority = if let Some(hex) = authority_text
        .strip_prefix("0x")
        .or_else(|| authority_text.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).map_err(|_| invalid())?
    } else {
        authority_text.parse::<u64>().map_err(|_| invalid())?
    };
    let expected = bytes[2..8]
        .iter()
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
    if authority != expected {
        return Err(invalid());
    }
    for chunk in bytes[8..].chunks_exact(std::mem::size_of::<u32>()) {
        let value = fields
            .next()
            .ok_or_else(invalid)?
            .parse::<u32>()
            .map_err(|_| invalid())?;
        if value != u32::from_le_bytes(chunk.try_into().expect("exact native subauthority width")) {
            return Err(invalid());
        }
    }
    if fields.next().is_some()
        || native_text
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() && !matches!(byte, b'S' | b'x' | b'X' | b'-'))
    {
        return Err(invalid());
    }
    let mask_width = "0x".len() + std::mem::size_of::<u32>() * 2;
    Ok(format!(
        "{BASE_SDDL}(A;;{WAIT_ACCESS:#0mask_width$x};;;{native_text})"
    ))
}
