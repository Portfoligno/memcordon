//! In-place mutation of one real ELF dynamic entry for the loader refusal case.
//! This only prepares bytes; native prelaunch refusal remains independently tested.
use memcordon_core::elf_closure::{ElfDependencies, inspect};
use serde_json::{Value, json};

const ELF_HEADER: u64 = 64;
const PROGRAM_HEADER: u64 = 56;
const DYNAMIC_ENTRY: u64 = 16;
const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_STRTAB: u64 = 5;
const DT_STRSZ: u64 = 10;
const DT_RPATH: u64 = 15;
const DT_DEBUG: u64 = 21;
const DT_RUNPATH: u64 = 29;

fn span(bytes: &[u8], at: u64, size: u64) -> Result<&[u8], String> {
    let end = at.checked_add(size).ok_or("ELF mutation extent overflow")?;
    let start = usize::try_from(at).map_err(|_| "ELF mutation offset overflow")?;
    let end = usize::try_from(end).map_err(|_| "ELF mutation end overflow")?;
    bytes
        .get(start..end)
        .ok_or_else(|| "ELF mutation extent exceeds file".into())
}
fn word16(bytes: &[u8], at: u64) -> Result<u16, String> {
    Ok(u16::from_le_bytes(
        span(bytes, at, 2)?.try_into().expect("fixed ELF16"),
    ))
}
fn word32(bytes: &[u8], at: u64) -> Result<u32, String> {
    Ok(u32::from_le_bytes(
        span(bytes, at, 4)?.try_into().expect("fixed ELF32"),
    ))
}
fn word64(bytes: &[u8], at: u64) -> Result<u64, String> {
    Ok(u64::from_le_bytes(
        span(bytes, at, 8)?.try_into().expect("fixed ELF64"),
    ))
}
fn inspect_bytes(bytes: &[u8], target: &str) -> Result<ElfDependencies, String> {
    inspect(
        |at, output| {
            output.copy_from_slice(span(bytes, at, output.len() as u64)?);
            Ok(())
        },
        bytes.len() as u64,
        target,
    )?
    .ok_or_else(|| "RPATH fixture is not native ELF".into())
}

#[derive(Clone, Copy)]
struct Segment {
    offset: u64,
    address: u64,
    size: u64,
}

fn mapped(loads: &[Segment], address: u64, size: u64) -> Result<u64, String> {
    let candidates: Vec<_> = loads
        .iter()
        .filter_map(|load| {
            address
                .checked_sub(load.address)
                .filter(|relative| {
                    relative
                        .checked_add(size)
                        .is_some_and(|end| end <= load.size)
                })
                .and_then(|relative| load.offset.checked_add(relative))
        })
        .collect();
    if candidates.len() != 1 {
        return Err("ELF mutation address does not resolve to exactly one file-backed load".into());
    }
    Ok(candidates[0])
}

fn overlaps(at: u64, size: u64, other: u64, other_size: u64) -> bool {
    // Both spans were already checked before use.
    at < other + other_size && other < at + size
}

pub fn mutate(original: &[u8], target: &str) -> Result<(Vec<u8>, Value), String> {
    let before = inspect_bytes(original, target)?;
    let machine = match target {
        "x86_64-unknown-linux-gnu" => 62,
        "aarch64-unknown-linux-gnu" => 183,
        _ => return Err("RPATH fixture target is unsupported".into()),
    };
    if span(original, 0, 7)? != b"\x7fELF\x02\x01\x01"
        || !matches!(word16(original, 16)?, 2..=3)
        || word16(original, 18)? != machine
        || word32(original, 20)? != 1
        || word16(original, 52)? != ELF_HEADER as u16
        || word16(original, 54)? != PROGRAM_HEADER as u16
    {
        return Err("RPATH fixture ELF64LE executable header differs".into());
    }
    let table = word64(original, 32)?;
    let count = u64::from(word16(original, 56)?);
    if table < ELF_HEADER || count == 0 || count > 512 {
        return Err("RPATH fixture program header inventory is invalid".into());
    }
    let table_size = count * PROGRAM_HEADER;
    span(original, table, table_size)?;
    let mut loads = Vec::new();
    let mut dynamic = None;
    for index in 0..count {
        let at = table + index * PROGRAM_HEADER;
        let segment = Segment {
            offset: word64(original, at + 8)?,
            address: word64(original, at + 16)?,
            size: word64(original, at + 32)?,
        };
        span(original, segment.offset, segment.size)?;
        if segment.address.checked_add(segment.size).is_none() {
            return Err("ELF segment address overflow".into());
        }
        match word32(original, at)? {
            1 => {
                let memory = word64(original, at + 40)?;
                if segment.size > memory || segment.address.checked_add(memory).is_none() {
                    return Err("ELF load file span exceeds memory span".into());
                }
                loads.push(segment);
            }
            2 if dynamic.replace(segment).is_some()
                || segment.size == 0
                || !segment.size.is_multiple_of(DYNAMIC_ENTRY)
                || segment.size > DYNAMIC_ENTRY * 16384 =>
            {
                return Err("ELF dynamic segment is duplicate, malformed or excessive".into());
            }
            _ => {}
        }
    }
    let dynamic = dynamic.ok_or("RPATH fixture has no dynamic segment")?;
    if mapped(&loads, dynamic.address, dynamic.size)? != dynamic.offset
        || overlaps(dynamic.offset, dynamic.size, 0, ELF_HEADER)
        || overlaps(dynamic.offset, dynamic.size, table, table_size)
    {
        return Err("ELF dynamic segment file/VA or header relationship differs".into());
    }
    let mut needed = None;
    let mut strings = None;
    let mut string_size = None;
    let mut debug = None;
    let mut terminator = None;
    for index in 0..dynamic.size / DYNAMIC_ENTRY {
        let at = dynamic.offset + index * DYNAMIC_ENTRY;
        let tag = word64(original, at)?;
        let value = word64(original, at + 8)?;
        match tag {
            DT_NULL => {
                terminator = Some(at);
                break;
            }
            DT_NEEDED => {
                if needed.is_none() {
                    needed = Some(value);
                }
            }
            DT_STRTAB => {
                if strings.replace(value).is_some() {
                    return Err("duplicate ELF string table".into());
                }
            }
            DT_STRSZ => {
                if string_size.replace(value).is_some() {
                    return Err("duplicate ELF string size".into());
                }
            }
            DT_DEBUG => {
                if debug.replace((at, value)).is_some() {
                    return Err("ambiguous duplicate DT_DEBUG".into());
                }
            }
            DT_RPATH | DT_RUNPATH => {
                return Err("RPATH fixture already has loader search policy".into());
            }
            _ => {}
        }
    }
    let end = terminator.ok_or("ELF dynamic table has no terminator")?;
    let strings = strings.ok_or("ELF string table absent")?;
    let string_size = string_size
        .filter(|size| *size != 0)
        .ok_or("ELF string size absent or zero")?;
    let string_offset = mapped(&loads, strings, string_size)?;
    let string_bytes = span(original, string_offset, string_size)?;
    if overlaps(dynamic.offset, dynamic.size, string_offset, string_size) {
        return Err("ELF dynamic and string table spans overlap".into());
    }
    let needed = needed.ok_or("RPATH fixture has no needed dependency")?;
    let tail = string_bytes
        .get(usize::try_from(needed).map_err(|_| "ELF needed offset overflow")?..)
        .ok_or("ELF needed string offset outside table")?;
    let name_end = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or("ELF needed string is unterminated")?;
    if name_end == 0 || name_end > 4096 {
        return Err("ELF needed basename is empty or excessive".into());
    }
    let name =
        std::str::from_utf8(&tail[..name_end]).map_err(|_| "ELF needed basename is not UTF8")?;
    if name == "."
        || name == ".."
        || name
            .bytes()
            .any(|byte| matches!(byte, b'/' | b'\\' | b':' | b'$'))
    {
        return Err("ELF needed string is not a supported relative search basename".into());
    }
    let spare = end
        .checked_add(DYNAMIC_ENTRY * 2)
        .filter(|after| *after <= dynamic.offset + dynamic.size)
        .is_some_and(|_| {
            span(original, end, DYNAMIC_ENTRY * 2)
                .is_ok_and(|bytes| bytes.iter().all(|byte| *byte == 0))
        });
    let (slot, strategy) = if spare {
        (end, "spare-null")
    } else if let Some((at, 0)) = debug {
        (at, "zero-dt-debug")
    } else {
        return Err(format!(
            "no supported RPATH mutation slot; dynamic-offset={}; dynamic-bytes={}; terminator-offset={end}; debug={debug:?}",
            dynamic.offset, dynamic.size
        ));
    };
    let old_tag = word64(original, slot)?;
    let old_value = word64(original, slot + 8)?;
    let at = usize::try_from(slot).map_err(|_| "ELF selected offset overflow")?;
    let entry_end = at
        .checked_add(DYNAMIC_ENTRY as usize)
        .ok_or("ELF selected entry overflow")?;
    let mut mutated = original.to_vec();
    mutated[at..at + 8].copy_from_slice(&DT_RUNPATH.to_le_bytes());
    mutated[at + 8..entry_end].copy_from_slice(&needed.to_le_bytes());
    let after = inspect_bytes(&mutated, target)?;
    if after.interpreter != before.interpreter
        || after.needed != before.needed
        || after.search_paths.len() != 1
        || after.search_paths[0] != name
        || !before.search_paths.is_empty()
        || mutated.len() != original.len()
        || original[..at] != mutated[..at]
        || original[entry_end..] != mutated[entry_end..]
    {
        return Err("RPATH mutation changed more than the selected loader search entry".into());
    }
    let details = json!({"strategy":strategy,"offset":slot,"old_tag":old_tag,"old_value":old_value,
        "new_tag":DT_RUNPATH,"new_value":needed,"string_offset":needed,"search":name,
        "source_sha256":String::from(memcordon_core::hash_bytes(original)),
        "mutated_sha256":String::from(memcordon_core::hash_bytes(&mutated))});
    Ok((mutated, details))
}
