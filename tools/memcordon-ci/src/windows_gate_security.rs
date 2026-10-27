//! Bounded, diagnostic-only interpretation of an actual self-relative descriptor.
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io;

pub const BYTE_BOUND: usize = 64 * 1024;
const ACE_BOUND: usize = 64;
const HEADER: usize = 20;

#[derive(Debug, Serialize)]
pub struct Snapshot {
    pub descriptor_sha256: String,
    pub descriptor_bytes_hex: String,
    pub descriptor_length: usize,
    pub revision: u8,
    pub control: u16,
    pub owner_sid_hex: Option<String>,
    pub group_sid_hex: Option<String>,
    pub dacl_present: bool,
    pub dacl_null: bool,
    pub acl_revision: Option<u8>,
    pub acl_bytes: Option<usize>,
    pub declared_ace_count: Option<usize>,
    pub unused_acl_bytes: Option<usize>,
    pub aces: Vec<Ace>,
}

#[derive(Debug, Serialize)]
pub struct Ace {
    pub ordinal: usize,
    pub native_type: u8,
    pub flags: u8,
    pub bytes: usize,
    pub raw_u32_at_offset_four: Option<u32>,
    pub sha256: String,
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn range(bytes: &[u8], start: usize, length: usize) -> io::Result<&[u8]> {
    start
        .checked_add(length)
        .and_then(|end| bytes.get(start..end))
        .ok_or_else(|| invalid("gate security native extent outside returned descriptor"))
}

fn word(bytes: &[u8], offset: usize) -> io::Result<u16> {
    Ok(u16::from_le_bytes(
        range(bytes, offset, size_of::<u16>())?
            .try_into()
            .map_err(|_| invalid("gate security WORD extent differs"))?,
    ))
}

fn dword(bytes: &[u8], offset: usize) -> io::Result<u32> {
    Ok(u32::from_le_bytes(
        range(bytes, offset, size_of::<u32>())?
            .try_into()
            .map_err(|_| invalid("gate security DWORD extent differs"))?,
    ))
}

fn sid(bytes: &[u8], offset: usize) -> io::Result<Option<String>> {
    if offset == 0 {
        return Ok(None);
    }
    if offset < HEADER || !offset.is_multiple_of(size_of::<u32>()) {
        return Err(invalid("gate security SID offset differs"));
    }
    let header = range(bytes, offset, 8)?;
    if header[0] != 1 || header[1] > 15 {
        return Err(invalid("gate security SID revision/count differs"));
    }
    let length = 8usize
        .checked_add(
            usize::from(header[1])
                .checked_mul(size_of::<u32>())
                .ok_or_else(|| invalid("gate security SID length overflow"))?,
        )
        .ok_or_else(|| invalid("gate security SID length overflow"))?;
    Ok(Some(hex::encode(range(bytes, offset, length)?)))
}

pub fn parse(bytes: &[u8]) -> io::Result<Snapshot> {
    if bytes.len() < HEADER || bytes.len() > BYTE_BOUND || bytes[0] != 1 {
        return Err(invalid(
            "gate security descriptor revision/length bound differs",
        ));
    }
    let control = word(bytes, 2)?;
    if control & 0x8000 == 0 {
        return Err(invalid("gate security descriptor is not self-relative"));
    }
    let owner_sid_hex = sid(bytes, dword(bytes, 4)? as usize)?;
    let group_sid_hex = sid(bytes, dword(bytes, 8)? as usize)?;
    let acl_offset = dword(bytes, 16)? as usize;
    let present = control & 4 != 0;
    let mut snapshot = Snapshot {
        descriptor_sha256: hex::encode(Sha256::digest(bytes)),
        descriptor_bytes_hex: hex::encode(bytes),
        descriptor_length: bytes.len(),
        revision: bytes[0],
        control,
        owner_sid_hex,
        group_sid_hex,
        dacl_present: present,
        dacl_null: present && acl_offset == 0,
        acl_revision: None,
        acl_bytes: None,
        declared_ace_count: None,
        unused_acl_bytes: None,
        aces: Vec::new(),
    };
    if !present {
        if acl_offset != 0 {
            return Err(invalid("gate security absent DACL has an offset"));
        }
        return Ok(snapshot);
    }
    if acl_offset == 0 {
        return Ok(snapshot);
    }
    if acl_offset < HEADER || !acl_offset.is_multiple_of(size_of::<u32>()) {
        return Err(invalid("gate security ACL offset differs"));
    }
    let header = range(bytes, acl_offset, 8)?;
    let length = usize::from(word(header, 2)?);
    let count = usize::from(word(header, 4)?);
    if !matches!(header[0], 2 | 4) || length < header.len() || count > ACE_BOUND {
        return Err(invalid(
            "gate security ACL revision/length/count bound differs",
        ));
    }
    let acl = range(bytes, acl_offset, length)?;
    let mut offset = header.len();
    for ordinal in 0..count {
        let ace_header = range(acl, offset, 4)?;
        let length = usize::from(word(ace_header, 2)?);
        if length < ace_header.len() || !length.is_multiple_of(size_of::<u32>()) {
            return Err(invalid("gate security declared ACE extent differs"));
        }
        let ace = range(acl, offset, length)?;
        snapshot.aces.push(Ace {
            ordinal,
            native_type: ace[0],
            flags: ace[1],
            bytes: length,
            raw_u32_at_offset_four: if length >= 2 * size_of::<u32>() {
                Some(dword(ace, 4)?)
            } else {
                None
            },
            sha256: hex::encode(Sha256::digest(ace)),
        });
        offset = offset
            .checked_add(length)
            .ok_or_else(|| invalid("gate security ACE offset overflow"))?;
    }
    snapshot.acl_revision = Some(header[0]);
    snapshot.acl_bytes = Some(length);
    snapshot.declared_ace_count = Some(count);
    snapshot.unused_acl_bytes = Some(length - offset);
    Ok(snapshot)
}
