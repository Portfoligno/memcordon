//! Bounded positional planning and exact whole-image validation for one owned mutation.
use sha2::{Digest, Sha256};
use std::{io, time::Instant};

const ELF_HEADER: usize = 64;
const ELF_MAGIC: &[u8] = b"\x7fELF\x02\x01\x01";
const PROGRAM_HEADER: usize = 56;
const DYNAMIC_RECORD: u64 = 16;
const HEADER_BOUND: u16 = 256;
const DYNAMIC_BOUND: u64 = 1024 * 1024;
const STRING_BOUND: usize = 4096;
const BUFFER: usize = 64 * 1024;
const REPLACEMENT: &[u8] = b"/work\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Patch {
    offset: u64,
    before: Vec<u8>,
    after: Vec<u8>,
}
impl Patch {
    pub fn offset(&self) -> u64 {
        self.offset
    }
    pub fn before(&self) -> &[u8] {
        &self.before
    }
    pub fn after(&self) -> &[u8] {
        &self.after
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Plan {
    patches: [Patch; 2],
}
impl Plan {
    pub fn patches(&self) -> &[Patch] {
        &self.patches
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    BeforeOriginal,
    AfterOriginal,
    BeforeWrites,
    AfterWrites,
    AfterFinal,
}

fn invalid(stage: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, stage)
}
fn live(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "original ELF mutation cutoff exhausted",
        ))
    } else {
        Ok(())
    }
}
fn end(offset: u64, size: u64, length: u64) -> io::Result<u64> {
    offset
        .checked_add(size)
        .filter(|end| *end <= length)
        .ok_or_else(|| invalid("ELF mutation file-backed range differs"))
}
fn exact(
    read: &mut impl FnMut(u64, &mut [u8]) -> io::Result<usize>,
    offset: u64,
    bytes: &mut [u8],
    length: u64,
    deadline: Instant,
) -> io::Result<()> {
    end(offset, bytes.len() as u64, length)?;
    let mut count = 0usize;
    while count < bytes.len() {
        live(deadline)?;
        let at = offset
            .checked_add(count as u64)
            .ok_or_else(|| invalid("ELF read offset overflow"))?;
        let actual = read(at, &mut bytes[count..])?;
        live(deadline)?;
        if actual == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "ELF mutation read truncated",
            ));
        }
        if actual > bytes.len() - count {
            return Err(invalid("ELF mutation read count differs"));
        }
        count += actual;
    }
    Ok(())
}
fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}
fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0; std::mem::size_of::<u64>()];
    let width = value.len();
    value.copy_from_slice(&bytes[offset..offset + width]);
    u64::from_le_bytes(value)
}
#[derive(Clone, Copy)]
struct Segment {
    file: u64,
    address: u64,
    size: u64,
}

pub fn plan(
    length: u64,
    deadline: Instant,
    mut read: impl FnMut(u64, &mut [u8]) -> io::Result<usize>,
) -> io::Result<Plan> {
    live(deadline)?;
    let mut header = [0; ELF_HEADER];
    exact(&mut read, 0, &mut header, length, deadline)?;
    if header.get(..ELF_MAGIC.len()) != Some(ELF_MAGIC)
        || u16_at(&header, 52) as usize != ELF_HEADER
    {
        return Err(invalid(
            "ELF mutation requires complete ELF64 little-endian header",
        ));
    }
    let phoff = u64_at(&header, 32);
    let stride = u64::from(u16_at(&header, 54));
    let count = u16_at(&header, 56);
    if phoff < ELF_HEADER as u64
        || stride < PROGRAM_HEADER as u64
        || count == 0
        || count > HEADER_BOUND
    {
        return Err(invalid("ELF mutation program-header bounds differ"));
    }
    end(
        phoff,
        stride
            .checked_mul(u64::from(count))
            .ok_or_else(|| invalid("ELF header table overflow"))?,
        length,
    )?;
    let mut loads = Vec::new();
    let mut dynamic = None;
    for ordinal in 0..count {
        let offset = phoff
            .checked_add(
                u64::from(ordinal)
                    .checked_mul(stride)
                    .ok_or_else(|| invalid("ELF program-header multiplication overflow"))?,
            )
            .ok_or_else(|| invalid("ELF program-header offset overflow"))?;
        let mut bytes = [0; PROGRAM_HEADER];
        exact(&mut read, offset, &mut bytes, length, deadline)?;
        let kind = u32::from_le_bytes(
            bytes[..std::mem::size_of::<u32>()]
                .try_into()
                .map_err(|_| invalid("ELF program-header kind differs"))?,
        );
        if kind != 1 && kind != 2 {
            continue;
        }
        let segment = Segment {
            file: u64_at(&bytes, 8),
            address: u64_at(&bytes, 16),
            size: u64_at(&bytes, 32),
        };
        let memory = u64_at(&bytes, 40);
        end(segment.file, segment.size, length)?;
        if segment.size > memory || segment.address.checked_add(memory).is_none() {
            return Err(invalid("ELF mutation load memory range differs"));
        }
        if kind == 1 {
            loads.push(segment);
        } else if dynamic.replace(segment).is_some() {
            return Err(invalid("ELF mutation dynamic segment ambiguous"));
        }
    }
    let dynamic = dynamic.ok_or_else(|| invalid("ELF mutation dynamic segment absent"))?;
    if dynamic.size == 0 || dynamic.size > DYNAMIC_BOUND || dynamic.size % DYNAMIC_RECORD != 0 {
        return Err(invalid("ELF mutation dynamic segment bound differs"));
    }
    let mapped_dynamic = loads
        .iter()
        .filter(|load| {
            dynamic.file.checked_sub(load.file).is_some_and(|delta| {
                delta
                    .checked_add(dynamic.size)
                    .is_some_and(|end| end <= load.size)
                    && load.address.checked_add(delta) == Some(dynamic.address)
            })
        })
        .count();
    if mapped_dynamic != 1 {
        return Err(invalid(
            "ELF mutation dynamic mapping ambiguous or unbacked",
        ));
    }
    let mut string_address = None;
    let mut string_size = None;
    let mut needed = None;
    let mut terminated = false;
    for ordinal in 0..dynamic.size / DYNAMIC_RECORD {
        let offset = dynamic
            .file
            .checked_add(
                ordinal
                    .checked_mul(DYNAMIC_RECORD)
                    .ok_or_else(|| invalid("ELF dynamic record multiplication overflow"))?,
            )
            .ok_or_else(|| invalid("ELF dynamic record offset overflow"))?;
        let mut bytes = [0; DYNAMIC_RECORD as usize];
        exact(&mut read, offset, &mut bytes, length, deadline)?;
        let tag = u64_at(&bytes, 0);
        let value = u64_at(&bytes, 8);
        match tag {
            0 => {
                terminated = true;
                break;
            }
            1 if needed.is_none() => needed = Some((offset, value)),
            5 if string_address.replace(value).is_some() => {
                return Err(invalid("ELF mutation string table ambiguous"));
            }
            10 if string_size.replace(value).is_some() => {
                return Err(invalid("ELF mutation string size ambiguous"));
            }
            _ => {}
        }
    }
    if !terminated {
        return Err(invalid("ELF mutation dynamic table unterminated"));
    }
    let address = string_address.ok_or_else(|| invalid("ELF mutation string table absent"))?;
    let (tag_offset, needed_index) =
        needed.ok_or_else(|| invalid("ELF mutation needed entry absent"))?;
    let mut mappings = loads.iter().filter_map(|load| {
        address
            .checked_sub(load.address)
            .filter(|delta| *delta < load.size)
            .and_then(|delta| {
                load.file
                    .checked_add(delta)
                    .map(|offset| (offset, load.size - delta))
            })
    });
    let (base, available) = mappings
        .next()
        .ok_or_else(|| invalid("ELF mutation string table unbacked"))?;
    if mappings.next().is_some() {
        return Err(invalid("ELF mutation string mapping ambiguous"));
    }
    let table_size = string_size.unwrap_or(available);
    if table_size == 0 || table_size > available || needed_index >= table_size {
        return Err(invalid(
            "ELF mutation needed string exceeds file-backed string table",
        ));
    }
    let position = base
        .checked_add(needed_index)
        .ok_or_else(|| invalid("ELF needed string offset overflow"))?;
    let scan = (table_size - needed_index).min((STRING_BOUND + 1) as u64) as usize;
    let mut name = vec![0; scan];
    exact(&mut read, position, &mut name, length, deadline)?;
    let nul = name
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| invalid("ELF mutation needed string lacks bounded terminator"))?;
    if nul < REPLACEMENT.len() - 1 {
        return Err(invalid("ELF mutation needed string too short"));
    }
    let tag_end = end(tag_offset, std::mem::size_of::<u64>() as u64, length)?;
    let string_end = end(position, REPLACEMENT.len() as u64, length)?;
    if tag_offset < string_end && position < tag_end {
        return Err(invalid("ELF mutation patch ranges overlap"));
    }
    let mut patches = [
        Patch {
            offset: tag_offset,
            before: 1u64.to_le_bytes().to_vec(),
            after: 15u64.to_le_bytes().to_vec(),
        },
        Patch {
            offset: position,
            before: name[..REPLACEMENT.len()].to_vec(),
            after: REPLACEMENT.to_vec(),
        },
    ];
    patches.sort_by_key(|patch| patch.offset);
    live(deadline)?;
    Ok(Plan { patches })
}

fn stream(
    length: u64,
    deadline: Instant,
    read: &mut impl FnMut(u64, &mut [u8]) -> io::Result<usize>,
    patches: &[Patch],
) -> io::Result<(String, String)> {
    let mut original = Sha256::new();
    let mut expected = Sha256::new();
    let mut buffer = [0; BUFFER];
    let mut offset = 0u64;
    while offset < length {
        let amount = (length - offset).min(buffer.len() as u64) as usize;
        exact(read, offset, &mut buffer[..amount], length, deadline)?;
        original.update(&buffer[..amount]);
        let chunk_end = offset
            .checked_add(amount as u64)
            .ok_or_else(|| invalid("ELF stream offset overflow"))?;
        for patch in patches {
            let patch_end = patch
                .offset
                .checked_add(patch.after.len() as u64)
                .ok_or_else(|| invalid("ELF patch extent overflow"))?;
            let start = offset.max(patch.offset);
            let end = chunk_end.min(patch_end);
            if start < end {
                let destination = (start - offset) as usize;
                let source = (start - patch.offset) as usize;
                let size = (end - start) as usize;
                buffer[destination..destination + size]
                    .copy_from_slice(&patch.after[source..source + size]);
            }
        }
        if !patches.is_empty() {
            expected.update(&buffer[..amount]);
        }
        offset = chunk_end;
    }
    live(deadline)?;
    let mut excess = [0];
    if read(length, &mut excess)? != 0 {
        return Err(invalid("ELF mutation exact length changed"));
    }
    live(deadline)?;
    let original = hex::encode(original.finalize());
    let expected = if patches.is_empty() {
        original.clone()
    } else {
        hex::encode(expected.finalize())
    };
    Ok((original, expected))
}

pub fn mutate(
    length: u64,
    original_sha: &str,
    deadline: Instant,
    mut read: impl FnMut(u64, &mut [u8]) -> io::Result<usize>,
    mut write: impl FnMut(u64, &[u8]) -> io::Result<()>,
    mut sync: impl FnMut() -> io::Result<()>,
    mut check: impl FnMut(Stage) -> io::Result<()>,
) -> io::Result<String> {
    let plan = plan(length, deadline, &mut read)?;
    live(deadline)?;
    check(Stage::BeforeOriginal)?;
    live(deadline)?;
    let (original, expected) = stream(length, deadline, &mut read, plan.patches())?;
    check(Stage::AfterOriginal)?;
    live(deadline)?;
    if original != original_sha {
        return Err(invalid("ELF mutation original manifest digest differs"));
    }
    for patch in plan.patches() {
        let mut bytes = vec![0; patch.before().len()];
        exact(&mut read, patch.offset(), &mut bytes, length, deadline)?;
        if bytes != patch.before() {
            return Err(invalid("ELF mutation patch preimage changed"));
        }
    }
    check(Stage::BeforeWrites)?;
    live(deadline)?;
    for patch in plan.patches() {
        live(deadline)?;
        write(patch.offset(), patch.after())?;
        live(deadline)?;
    }
    sync()?;
    live(deadline)?;
    for patch in plan.patches() {
        let mut bytes = vec![0; patch.after().len()];
        exact(&mut read, patch.offset(), &mut bytes, length, deadline)?;
        if bytes != patch.after() {
            return Err(invalid("ELF mutation patch readback differs"));
        }
    }
    check(Stage::AfterWrites)?;
    live(deadline)?;
    let (actual, _) = stream(length, deadline, &mut read, &[])?;
    check(Stage::AfterFinal)?;
    live(deadline)?;
    if actual != expected {
        return Err(invalid("ELF mutation full patched digest differs"));
    }
    Ok(actual)
}
