//! LABEL_SECURITY_INFORMATION only; never discretionary authorization evidence.
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io;

pub const BYTE_BOUND: usize = 64 * 1024;
const HEADER: usize = 20;
const ACL_HEADER: usize = 8;
const SID_HEADER: usize = 8;

#[derive(Debug, Serialize)]
pub struct Snapshot {
    pub information: u32,
    pub descriptor_sha256: String,
    pub descriptor_bytes_hex: String,
    pub descriptor_length: usize,
    pub control: u16,
    pub sacl_present: bool,
    pub sacl_null: bool,
    pub interpretation: &'static str,
    pub label: Option<Label>,
}

#[derive(Debug, Serialize)]
pub struct Label {
    pub flags: u8,
    pub mask: u32,
    pub sid_revision: u8,
    pub identifier_authority: u64,
    pub subauthorities: Vec<u32>,
    pub sid_hex: String,
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "held event label descriptor representation differs",
    )
}
fn extent(bytes: &[u8], start: usize, length: usize) -> io::Result<&[u8]> {
    bytes
        .get(start..start.checked_add(length).ok_or_else(invalid)?)
        .ok_or_else(invalid)
}
fn word(bytes: &[u8], start: usize) -> io::Result<u16> {
    Ok(u16::from_le_bytes(
        extent(bytes, start, size_of::<u16>())?
            .try_into()
            .map_err(|_| invalid())?,
    ))
}
fn dword(bytes: &[u8], start: usize) -> io::Result<u32> {
    Ok(u32::from_le_bytes(
        extent(bytes, start, size_of::<u32>())?
            .try_into()
            .map_err(|_| invalid())?,
    ))
}

pub fn parse(bytes: &[u8]) -> io::Result<Snapshot> {
    if bytes.len() < HEADER || bytes.len() > BYTE_BOUND || bytes[0] != 1 {
        return Err(invalid());
    }
    let control = word(bytes, 2)?;
    if control & 0x8000 == 0 {
        return Err(invalid());
    }
    // A label-only response must not substitute owner/group/DACL facts.
    if dword(bytes, 4)? != 0 || dword(bytes, 8)? != 0 || dword(bytes, 16)? != 0 || control & 4 != 0
    {
        return Err(invalid());
    }
    let offset = dword(bytes, 12)? as usize;
    let present = control & 0x10 != 0;
    let mut snapshot = Snapshot {
        information: 0x10,
        descriptor_sha256: hex::encode(Sha256::digest(bytes)),
        descriptor_bytes_hex: hex::encode(bytes),
        descriptor_length: bytes.len(),
        control,
        sacl_present: present,
        sacl_null: present && offset == 0,
        interpretation: "no explicit label observed; default interpretation unknown",
        label: None,
    };
    if !present {
        if offset != 0 {
            return Err(invalid());
        }
        return Ok(snapshot);
    }
    if offset == 0 {
        return Ok(snapshot);
    }
    if offset < HEADER || !offset.is_multiple_of(size_of::<u32>()) {
        return Err(invalid());
    }
    let header = extent(bytes, offset, ACL_HEADER)?;
    let length = usize::from(word(header, 2)?);
    let count = usize::from(word(header, 4)?);
    if !matches!(header[0], 2 | 4) || length < ACL_HEADER || count > 1 {
        return Err(invalid());
    }
    let acl = extent(bytes, offset, length)?;
    if count == 0 {
        return Ok(snapshot);
    }
    let ace_header = extent(acl, ACL_HEADER, 4)?;
    let ace_length = usize::from(word(ace_header, 2)?);
    if ace_header[0] != 0x11 || !ace_length.is_multiple_of(size_of::<u32>()) {
        return Err(invalid());
    }
    let ace = extent(acl, ACL_HEADER, ace_length)?;
    let sid = extent(ace, 8, ace_length.checked_sub(8).ok_or_else(invalid)?)?;
    let sid_header = extent(sid, 0, SID_HEADER)?;
    if sid_header[0] != 1 || sid_header[1] != 1 || sid.len() != SID_HEADER + size_of::<u32>() {
        return Err(invalid());
    }
    let authority = sid_header[2..SID_HEADER]
        .iter()
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
    if authority != 16 {
        return Err(invalid());
    }
    snapshot.label = Some(Label {
        flags: ace[1],
        mask: dword(ace, 4)?,
        sid_revision: sid[0],
        identifier_authority: authority,
        subauthorities: vec![dword(sid, SID_HEADER)?],
        sid_hex: hex::encode(sid),
    });
    snapshot.interpretation =
        "explicit mandatory label observed; named-open causation not established";
    Ok(snapshot)
}
