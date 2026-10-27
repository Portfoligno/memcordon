//! Controller-only counted directory buffers; no native pointer is dereferenced here.
use super::namespace_input::component;
use serde::Serialize;
use std::io;

pub const MAX_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ParseFailure {
    pub field: &'static str,
    pub reason: &'static str,
    pub returned_bytes: usize,
    pub header_bytes: usize,
    pub base_aligned: bool,
    pub length: Option<u16>,
    pub maximum_length: Option<u16>,
    pub relative_offset: Option<usize>,
    pub address_aligned: Option<bool>,
    pub checked_extent: Option<usize>,
}
impl std::fmt::Display for ParseFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "gate namespace directory field={} reason={}",
            self.field, self.reason
        )
    }
}
impl std::error::Error for ParseFailure {}

#[derive(Clone, Copy, Debug)]
pub struct Counted {
    pub length: u16,
    pub maximum_length: u16,
    pub address: usize,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: Vec<u16>,
    pub kind: Vec<u16>,
    name_failure: ParseFailure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryClass {
    Directory,
    SelectedEvent,
    Ignored,
}

impl Entry {
    pub fn classify(&self, expected_leaf: &[u16]) -> io::Result<EntryClass> {
        let class = if self.kind.iter().copied().eq("Directory".encode_utf16()) {
            EntryClass::Directory
        } else if self.kind.iter().copied().eq("Event".encode_utf16()) && self.name == expected_leaf
        {
            EntryClass::SelectedEvent
        } else {
            return Ok(EntryClass::Ignored);
        };
        // Only a traversed directory or the exact selected Event becomes a
        // path component. Unknown object kinds remain structurally checked data.
        if component(&self.name).is_err() {
            let mut failure = self.name_failure.clone();
            failure.reason = component_reason(&self.name);
            return Err(io::Error::new(io::ErrorKind::InvalidData, failure));
        }
        Ok(class)
    }
}

fn component_reason(units: &[u16]) -> &'static str {
    if units.is_empty() {
        "component-empty"
    } else if units.contains(&0) {
        "component-nul"
    } else if units.contains(&u16::from(b'/')) {
        "component-slash"
    } else if units.contains(&u16::from(b'\\')) {
        "component-backslash"
    } else if units.iter().copied().eq(".".encode_utf16()) {
        "component-dot"
    } else if units.iter().copied().eq("..".encode_utf16()) {
        "component-dot-dot"
    } else {
        "component-refused"
    }
}

pub fn entry(
    buffer: &[u8],
    base: usize,
    name: Counted,
    kind: Counted,
    header_bytes: usize,
) -> io::Result<Entry> {
    entry_detailed(buffer, base, name, kind, header_bytes)
        .map_err(|failure| io::Error::new(io::ErrorKind::InvalidData, failure))
}

pub fn entry_detailed(
    buffer: &[u8],
    base: usize,
    name: Counted,
    kind: Counted,
    header_bytes: usize,
) -> Result<Entry, ParseFailure> {
    let fail = |field, reason, value: Option<Counted>| {
        let offset = value.and_then(|value| value.address.checked_sub(base));
        ParseFailure {
            field,
            reason,
            returned_bytes: buffer.len(),
            header_bytes,
            base_aligned: base & (align_of::<u16>() - 1) == 0,
            length: value.map(|value| value.length),
            maximum_length: value.map(|value| value.maximum_length),
            relative_offset: offset,
            address_aligned: value.map(|value| value.address & (align_of::<u16>() - 1) == 0),
            checked_extent: offset
                .and_then(|start| start.checked_add(usize::from(value?.maximum_length))),
        }
    };
    if buffer.len() > MAX_BUFFER_BYTES {
        return Err(fail("buffer", "allocation-bound", None));
    }
    if header_bytes == 0 {
        return Err(fail("header", "empty-header", None));
    }
    if header_bytes > buffer.len() {
        return Err(fail("header", "outside-returned-buffer", None));
    }
    if base & (align_of::<u16>() - 1) != 0 {
        return Err(fail("buffer", "base-misaligned", None));
    }
    if base.checked_add(buffer.len()).is_none() {
        return Err(fail("buffer", "base-extent-overflow", None));
    }
    let read = |field, value: Counted| -> Result<Vec<u16>, ParseFailure> {
        let refusal = |reason| fail(field, reason, Some(value));
        let length = usize::from(value.length);
        let maximum = usize::from(value.maximum_length);
        let start = value
            .address
            .checked_sub(base)
            .ok_or_else(|| refusal("pointer-before-buffer"))?;
        if length == 0 {
            return Err(refusal("empty-length"));
        }
        if length > maximum {
            return Err(refusal("length-exceeds-maximum"));
        }
        if length & (size_of::<u16>() - 1) != 0 {
            return Err(refusal("odd-length"));
        }
        if maximum & (size_of::<u16>() - 1) != 0 {
            return Err(refusal("odd-maximum"));
        }
        if value.address & (align_of::<u16>() - 1) != 0 {
            return Err(refusal("address-misaligned"));
        }
        if start < header_bytes {
            return Err(refusal("overlaps-header"));
        }
        let end = start
            .checked_add(maximum)
            .ok_or_else(|| refusal("extent-overflow"))?;
        if end > buffer.len() {
            return Err(refusal("outside-returned-buffer"));
        }
        let bytes = buffer
            .get(
                start
                    ..start
                        .checked_add(length)
                        .ok_or_else(|| refusal("extent-overflow"))?,
            )
            .ok_or_else(|| refusal("outside-returned-buffer"))?;
        let units: Vec<_> = bytes
            .chunks_exact(size_of::<u16>())
            .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
            .collect();
        Ok(units)
    };
    Ok(Entry {
        name: read("name", name)?,
        kind: read("kind", kind)?,
        name_failure: fail("name", "component-refused", Some(name)),
    })
}
