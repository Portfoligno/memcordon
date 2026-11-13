//! Bounded PE resource inventory. Neither XML interpretation nor loader authority.
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, ops::Range};

pub const RECORD_BYTES: usize = 32 * 1024;
const MAX_ENTRIES: usize = 1024;
const MAX_LEAVES: usize = 64;
const MAX_PAYLOAD: usize = 1024 * 1024;
#[derive(Clone, Copy, Debug)]
enum Failure {
    Truncated,
    Dos,
    Pe,
    Optional,
    Sections,
    AmbiguousRva,
    UnbackedRva,
    ResourceExtent,
    DirectoryDepth,
    DirectoryAlias,
    EntryPartition,
    DuplicateEntry,
    ResourceName,
    Language,
    DataEntry,
    EntryBound,
    LeafBound,
    PayloadBound,
    EmptyManifest,
    OutputBound,
}
impl Failure {
    fn label(self) -> &'static str {
        match self {
            Self::Truncated => "truncated",
            Self::Dos => "dos-header",
            Self::Pe => "pe-header",
            Self::Optional => "optional-header",
            Self::Sections => "section-layout",
            Self::AmbiguousRva => "ambiguous-rva",
            Self::UnbackedRva => "unbacked-rva",
            Self::ResourceExtent => "resource-extent",
            Self::DirectoryDepth => "resource-depth",
            Self::DirectoryAlias => "resource-cycle-or-directory-alias",
            Self::EntryPartition => "resource-name-id-partition",
            Self::DuplicateEntry => "duplicate-resource-entry",
            Self::ResourceName => "resource-name",
            Self::Language => "resource-language",
            Self::DataEntry => "resource-data-entry",
            Self::EntryBound => "resource-entry-bound",
            Self::LeafBound => "manifest-leaf-bound",
            Self::PayloadBound => "manifest-payload-bound",
            Self::EmptyManifest => "empty-manifest-tree",
            Self::OutputBound => "inventory-output-bound",
        }
    }
}
type Result<T> = std::result::Result<T, Failure>;
fn range(offset: usize, length: usize, limit: usize) -> Result<Range<usize>> {
    let end = offset.checked_add(length).ok_or(Failure::Truncated)?;
    if end > limit {
        return Err(Failure::Truncated);
    }
    Ok(offset..end)
}
fn u16_at(bytes: &[u8], offset: usize) -> Result<u16> {
    let slice = &bytes[range(offset, 2, bytes.len())?];
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    let slice = &bytes[range(offset, 4, bytes.len())?];
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}
fn overlaps(left: &Range<usize>, right: &Range<usize>) -> bool {
    left.start < right.end && right.start < left.end
}
#[derive(Clone)]
struct Section {
    virtual_range: Range<usize>,
    raw: Range<usize>,
}
struct Image<'a> {
    bytes: &'a [u8],
    headers: usize,
    image_size: usize,
    sections: Vec<Section>,
    resource: Option<(u32, u32)>,
}
impl<'a> Image<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.get(..2) != Some(b"MZ") {
            return Err(Failure::Dos);
        }
        let pe = u32_at(bytes, 0x3c)? as usize;
        if pe < 64 {
            return Err(Failure::Pe);
        }
        if bytes.get(range(pe, 4, bytes.len())?) != Some(b"PE\0\0") {
            return Err(Failure::Pe);
        }
        let coff = pe.checked_add(4).ok_or(Failure::Pe)?;
        range(coff, 20, bytes.len())?;
        let count = usize::from(u16_at(bytes, coff + 2)?);
        // Windows PE image loaders document a maximum of 96 sections.
        if count == 0 || count > 96 {
            return Err(Failure::Sections);
        }
        let optional = coff + 20;
        let optional_size = usize::from(u16_at(bytes, coff + 16)?);
        range(optional, optional_size, bytes.len())?;
        let (directory_count_at, directory_at) = match u16_at(bytes, optional)? {
            0x10b => (92, 96),
            0x20b => (108, 112),
            _ => return Err(Failure::Optional),
        };
        if optional_size < directory_at {
            return Err(Failure::Optional);
        }
        let directories = u32_at(bytes, optional + directory_count_at)? as usize;
        let directory_bytes = directories.checked_mul(8).ok_or(Failure::Optional)?;
        if directory_at
            .checked_add(directory_bytes)
            .is_none_or(|end| end > optional_size)
        {
            return Err(Failure::Optional);
        }
        let headers = u32_at(bytes, optional + 60)? as usize;
        let image_size = u32_at(bytes, optional + 56)? as usize;
        let table = optional + optional_size;
        let table_end = range(
            table,
            count.checked_mul(40).ok_or(Failure::Sections)?,
            bytes.len(),
        )?
        .end;
        if headers < table_end || headers > bytes.len() || headers > image_size {
            return Err(Failure::Sections);
        }
        let mut sections = Vec::<Section>::new();
        for index in 0..count {
            let entry = table + index * 40;
            let virtual_size = u32_at(bytes, entry + 8)? as usize;
            let va = u32_at(bytes, entry + 12)? as usize;
            let raw_size = u32_at(bytes, entry + 16)? as usize;
            let raw_offset = u32_at(bytes, entry + 20)? as usize;
            let virtual_end = va
                .checked_add(virtual_size.max(raw_size))
                .ok_or(Failure::Sections)?;
            if virtual_end > u32::MAX as usize || virtual_end > image_size {
                return Err(Failure::Sections);
            }
            let virtual_range = va..virtual_end;
            let raw = range(raw_offset, raw_size, bytes.len())?;
            if (!virtual_range.is_empty() && overlaps(&virtual_range, &(0..headers)))
                || (!raw.is_empty() && overlaps(&raw, &(0..headers)))
            {
                return Err(Failure::AmbiguousRva);
            }
            if sections.iter().any(|other| {
                (!virtual_range.is_empty()
                    && !other.virtual_range.is_empty()
                    && overlaps(&virtual_range, &other.virtual_range))
                    || (!raw.is_empty() && !other.raw.is_empty() && overlaps(&raw, &other.raw))
            }) {
                return Err(Failure::AmbiguousRva);
            }
            sections.push(Section { virtual_range, raw });
        }
        let resource = if directories > 2 {
            let rva = u32_at(bytes, optional + directory_at + 16)?;
            let size = u32_at(bytes, optional + directory_at + 20)?;
            match (rva, size) {
                (0, 0) => None,
                (0, _) | (_, 0) => return Err(Failure::ResourceExtent),
                _ => Some((rva, size)),
            }
        } else {
            None
        };
        Ok(Self {
            bytes,
            headers,
            image_size,
            sections,
            resource,
        })
    }
    fn map(&self, rva: u32, length: u32) -> Result<Range<usize>> {
        let start = rva as usize;
        let length = length as usize;
        let end = start.checked_add(length).ok_or(Failure::UnbackedRva)?;
        if end > u32::MAX as usize {
            return Err(Failure::UnbackedRva);
        }
        let mut mapped = None;
        if start < self.headers && end <= self.headers {
            mapped = Some(range(start, length, self.bytes.len())?);
        }
        for section in &self.sections {
            if start >= section.virtual_range.start
                && start < section.virtual_range.end
                && end <= section.virtual_range.end
            {
                let delta = start - section.virtual_range.start;
                if delta
                    .checked_add(length)
                    .is_none_or(|end| end > section.raw.len())
                {
                    return Err(Failure::UnbackedRva);
                }
                let candidate = range(section.raw.start + delta, length, self.bytes.len())?;
                if mapped.replace(candidate).is_some() {
                    return Err(Failure::AmbiguousRva);
                }
            }
        }
        mapped.ok_or(Failure::UnbackedRva)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(untagged)]
enum Name {
    Id { id: u32 },
    Text { utf16: Vec<u16> },
}
#[derive(Serialize)]
struct Leaf {
    name: Name,
    language: u32,
    payload_bytes: u32,
    sha256: [u8; 32],
    application_id_1: bool,
    code_page: u32,
}
#[derive(Default)]
struct Inventory {
    entries: usize,
    leaves_observed: usize,
    payload: usize,
    manifest_type_observed: bool,
    leaves: Vec<Leaf>,
}
struct Walker<'a, 'b> {
    image: &'a Image<'b>,
    resource_rva: u32,
    resource_length: usize,
    directories: BTreeSet<usize>,
    inventory: &'a mut Inventory,
}
impl Walker<'_, '_> {
    fn bytes(&self, relative: usize, length: usize) -> Result<&[u8]> {
        range(relative, length, self.resource_length).map_err(|_| Failure::ResourceExtent)?;
        let rva = self
            .resource_rva
            .checked_add(u32::try_from(relative).map_err(|_| Failure::ResourceExtent)?)
            .ok_or(Failure::ResourceExtent)?;
        let mapped = self.image.map(
            rva,
            u32::try_from(length).map_err(|_| Failure::ResourceExtent)?,
        )?;
        Ok(&self.image.bytes[mapped])
    }
    fn name(&self, encoded: u32) -> Result<Name> {
        if encoded & 0x80000000 == 0 {
            if encoded > u16::MAX as u32 {
                return Err(Failure::ResourceName);
            }
            return Ok(Name::Id { id: encoded });
        }
        let offset = (encoded & 0x7fffffff) as usize;
        if offset & 1 != 0 {
            return Err(Failure::ResourceName);
        }
        let length = usize::from(u16_at(self.bytes(offset, 2)?, 0)?);
        if length == 0 || length > 128 {
            return Err(Failure::ResourceName);
        }
        let bytes = self.bytes(
            offset + 2,
            length.checked_mul(2).ok_or(Failure::ResourceName)?,
        )?;
        let utf16 = bytes
            .chunks_exact(2)
            .map(|part| u16::from_le_bytes([part[0], part[1]]))
            .collect::<Vec<_>>();
        if utf16.contains(&0) || String::from_utf16(&utf16).is_err() {
            return Err(Failure::ResourceName);
        }
        Ok(Name::Text { utf16 })
    }
    fn walk(
        &mut self,
        offset: usize,
        depth: usize,
        manifest: bool,
        name: Option<Name>,
    ) -> Result<()> {
        if depth > 2 {
            return Err(Failure::DirectoryDepth);
        }
        if offset & 3 != 0 {
            return Err(Failure::ResourceExtent);
        }
        if !self.directories.insert(offset) {
            return Err(Failure::DirectoryAlias);
        }
        let header = self.bytes(offset, 16)?;
        let named = usize::from(u16_at(header, 12)?);
        let ids = usize::from(u16_at(header, 14)?);
        let count = named.checked_add(ids).ok_or(Failure::EntryBound)?;
        if manifest && count == 0 {
            return Err(Failure::EmptyManifest);
        }
        if self
            .inventory
            .entries
            .checked_add(count)
            .is_none_or(|total| total > MAX_ENTRIES)
        {
            return Err(Failure::EntryBound);
        }
        let entries = self
            .bytes(
                offset + 16,
                count.checked_mul(8).ok_or(Failure::EntryBound)?,
            )?
            .to_vec();
        let mut keys = BTreeSet::new();
        for index in 0..count {
            if self.inventory.entries == MAX_ENTRIES {
                return Err(Failure::EntryBound);
            }
            let key = u32_at(&entries, index * 8)?;
            let target = u32_at(&entries, index * 8 + 4)?;
            self.inventory.entries += 1;
            if (key & 0x80000000 != 0) != (index < named) {
                return Err(Failure::EntryPartition);
            }
            let key = self.name(key)?;
            if !keys.insert(key.clone()) {
                return Err(Failure::DuplicateEntry);
            }
            let is_manifest = if depth == 0 {
                key == Name::Id { id: 24 }
            } else {
                manifest
            };
            if depth == 0 && is_manifest {
                self.inventory.manifest_type_observed = true;
            }
            if depth < 2 {
                if target & 0x80000000 == 0 {
                    return Err(Failure::DirectoryDepth);
                }
                let selected = if depth == 1 { Some(key) } else { None };
                self.walk(
                    (target & 0x7fffffff) as usize,
                    depth + 1,
                    is_manifest,
                    selected,
                )?;
            } else {
                if target & 0x80000000 != 0 {
                    return Err(Failure::DirectoryDepth);
                }
                let Name::Id { id: language } = key else {
                    return Err(Failure::Language);
                };
                let target = target as usize;
                if target & 3 != 0 {
                    return Err(Failure::ResourceExtent);
                }
                let data = self.bytes(target, 16)?;
                let rva = u32_at(data, 0)?;
                let length = u32_at(data, 4)?;
                let code_page = u32_at(data, 8)?;
                if u32_at(data, 12)? != 0 {
                    return Err(Failure::DataEntry);
                }
                let payload = self.image.map(rva, length)?;
                if is_manifest {
                    self.inventory.leaves_observed += 1;
                    if self.inventory.leaves_observed > MAX_LEAVES {
                        return Err(Failure::LeafBound);
                    }
                    let total = self
                        .inventory
                        .payload
                        .checked_add(length as usize)
                        .ok_or(Failure::PayloadBound)?;
                    if total > MAX_PAYLOAD {
                        return Err(Failure::PayloadBound);
                    }
                    self.inventory.payload = total;
                    let name = name.clone().ok_or(Failure::DirectoryDepth)?;
                    let application_id_1 = name == Name::Id { id: 1 };
                    self.inventory.leaves.push(Leaf {
                        name,
                        language,
                        payload_bytes: length,
                        sha256: Sha256::digest(&self.image.bytes[payload]).into(),
                        application_id_1,
                        code_page,
                    });
                }
            }
        }
        Ok(())
    }
}

/// Inventory the actual selected bytes. An incomplete traversal can never establish absence.
pub fn inventory(bytes: &[u8]) -> Value {
    let mut observed = Inventory::default();
    let parsed = (|| -> Result<()> {
        let image = Image::parse(bytes)?;
        if let Some((rva, length)) = image.resource {
            if rva
                .checked_add(length)
                .is_none_or(|end| end as usize > image.image_size)
            {
                return Err(Failure::ResourceExtent);
            }
            let mut walker = Walker {
                image: &image,
                resource_rva: rva,
                resource_length: length as usize,
                directories: BTreeSet::new(),
                inventory: &mut observed,
            };
            walker.walk(0, 0, false, None)?;
            if observed.manifest_type_observed && observed.leaves.is_empty() {
                return Err(Failure::EmptyManifest);
            }
        }
        Ok(())
    })();
    let error = parsed.err();
    let mut value = json!({"format":"memcordon.fixture-pe-manifest-inventory","revision":1,"diagnostic_only":true,"acceptance_authority":false,"loader_eligibility_proved":false,"image_bytes":bytes.len(),"image_sha256":<[u8;32]>::from(Sha256::digest(bytes)),"parser_complete":error.is_none(),"status":if error.is_some(){"incomplete"}else if observed.leaves.is_empty(){"complete_no_manifest"}else{"manifest_present"},"failure":error.map(Failure::label),"manifest_type_observed":observed.manifest_type_observed,"entries_visited":observed.entries,"manifest_leaves_observed":observed.leaves_observed,"manifest_payload_bytes_hashed":observed.payload,"manifests":observed.leaves,"manifests_omitted_for_bound":0});
    let mut omitted = 0;
    while serde_json::to_vec(&value).is_ok_and(|bytes| bytes.len() > RECORD_BYTES) {
        value["parser_complete"] = json!(false);
        value["status"] = json!("incomplete");
        value["failure"] = json!(Failure::OutputBound.label());
        if value["manifests"]
            .as_array_mut()
            .and_then(Vec::pop)
            .is_none()
        {
            break;
        }
        omitted += 1;
        value["manifests_omitted_for_bound"] = json!(omitted);
    }
    value
}
