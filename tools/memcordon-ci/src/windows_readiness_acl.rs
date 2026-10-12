//! Exact file authority comparison independent of ACL allocation bookkeeping.
//! Mirrors the sealed agent's ordered effective and inheritance projections.

#[derive(Clone, Debug, Eq, PartialEq)]
struct Ace {
    kind: u8,
    flags: u8,
    mask: u32,
    sid: Vec<u8>,
}

fn file_mask(mask: u32) -> u32 {
    let mut mapped = mask & !0xf000_0000;
    for (generic, specific) in [
        (0x8000_0000, 0x0012_0089), // FILE_GENERIC_READ
        (0x4000_0000, 0x0012_0116), // FILE_GENERIC_WRITE
        (0x2000_0000, 0x0012_00a0), // FILE_GENERIC_EXECUTE
        (0x1000_0000, 0x001f_01ff), // FILE_ALL_ACCESS
    ] {
        if mask & generic != 0 {
            mapped |= specific;
        }
    }
    mapped
}

fn entries(bytes: &[u8]) -> Result<Vec<Ace>, String> {
    if bytes.len() < 8 || !matches!(bytes[0], 2 | 4) {
        return Err("readiness ACL header malformed".into());
    }
    let size = usize::from(u16::from_le_bytes([bytes[2], bytes[3]]));
    let count = usize::from(u16::from_le_bytes([bytes[4], bytes[5]]));
    if size < 8 || size > bytes.len() || count > (size - 8) / 16 {
        return Err("readiness ACL size/count malformed".into());
    }
    let mut offset = 8;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let header = bytes
            .get(offset..offset + 4)
            .filter(|_| offset + 4 <= size)
            .ok_or("readiness ACE header truncated")?;
        let length = usize::from(u16::from_le_bytes([header[2], header[3]]));
        if length < 16 || length > size - offset || !matches!(header[0], 0 | 1) {
            return Err("readiness ACE kind/size malformed".into());
        }
        let flags = header[1];
        if flags & !0x1f != 0 || flags & 0x08 != 0 && flags & 0x03 == 0 {
            return Err("readiness ACE inheritance flags malformed".into());
        }
        let ace = &bytes[offset..offset + length];
        let sid = &ace[8..];
        if sid[0] != 1 || sid[1] > 15 || sid.len() != 8 + usize::from(sid[1]) * 4 {
            return Err("readiness ACE SID malformed".into());
        }
        entries.push(Ace {
            kind: header[0],
            flags,
            mask: file_mask(u32::from_le_bytes(ace[4..8].try_into().unwrap())),
            sid: sid.to_vec(),
        });
        offset += length;
    }
    // Remaining allocation bytes do not describe an ACE or grant authority.
    Ok(entries)
}

fn projection(entries: &[Ace]) -> (Vec<Ace>, Vec<Ace>) {
    let mut effective = Vec::new();
    let mut inheritance = Vec::new();
    for entry in entries {
        if entry.flags & 0x08 == 0 {
            let mut entry = entry.clone();
            entry.flags &= !0x0f;
            effective.push(entry);
        }
        if entry.flags & 0x03 != 0 {
            let mut entry = entry.clone();
            entry.flags &= !0x08;
            inheritance.push(entry);
        }
    }
    (effective, inheritance)
}

fn authority_detail(entries: &[Ace]) -> String {
    // Native ACLs are bounded, but diagnostics retain at most eight ordered
    // entries. Parsed SIDs contain at most fifteen subauthorities each.
    format!(
        "count={}; first-eight={:?}; truncated={}",
        entries.len(),
        &entries[..entries.len().min(8)],
        entries.len() > 8,
    )
}

pub(crate) fn verify_file_dacl(
    expected: &[u8],
    actual: &[u8],
    actual_protected: bool,
) -> Result<(), String> {
    if !actual_protected {
        return Err("readiness DACL is not protected".into());
    }
    let expected = projection(&entries(expected)?);
    let actual = projection(&entries(actual)?);
    if expected.0 != actual.0 {
        return Err(format!(
            "readiness DACL ordered effective authority differs; expected {}; actual {}",
            authority_detail(&expected.0),
            authority_detail(&actual.0),
        ));
    }
    if expected.1 != actual.1 {
        return Err(format!(
            "readiness DACL ordered inheritance authority differs; expected {}; actual {}",
            authority_detail(&expected.1),
            authority_detail(&actual.1),
        ));
    }
    Ok(())
}
