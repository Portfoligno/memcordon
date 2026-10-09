//! Bounded ELF64 dependency inspection for administrator-owned image closure.
//! This parses held bytes; it does not execute a loader or resolve host paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElfDependencies {
    pub interpreter: Option<String>,
    pub needed: Vec<String>,
    pub search_paths: Vec<String>,
}

pub fn inspect(
    mut read: impl FnMut(u64, &mut [u8]) -> Result<(), String>,
    length: u64,
    target: &str,
) -> Result<Option<ElfDependencies>, String> {
    fn u16_at(bytes: &[u8], at: usize) -> u16 {
        u16::from_le_bytes(bytes[at..at + 2].try_into().expect("fixed ELF field"))
    }
    fn u32_at(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().expect("fixed ELF field"))
    }
    fn u64_at(bytes: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(bytes[at..at + 8].try_into().expect("fixed ELF field"))
    }
    fn bounded_range(offset: u64, size: u64, length: u64) -> Result<(), String> {
        if offset.checked_add(size).is_none_or(|end| end > length) {
            return Err("ELF range exceeds held member".into());
        }
        Ok(())
    }
    fn string(bytes: &[u8], offset: u64) -> Result<String, String> {
        let offset = usize::try_from(offset).map_err(|_| "ELF string offset overflow")?;
        let tail = bytes.get(offset..).ok_or("ELF string outside table")?;
        let end = tail
            .iter()
            .position(|byte| *byte == 0)
            .ok_or("ELF string is unterminated")?;
        if end == 0 || end > 4096 {
            return Err("ELF dependency string is empty or excessive".into());
        }
        std::str::from_utf8(&tail[..end])
            .map(str::to_owned)
            .map_err(|error| error.to_string())
    }
    if length < 4 {
        return Ok(None);
    }
    let mut magic = [0; 4];
    read(0, &mut magic)?;
    if magic != *b"\x7fELF" {
        return Ok(None);
    }
    bounded_range(0, 64, length)?;
    let mut header = [0; 64];
    read(0, &mut header)?;
    let machine = match target {
        "x86_64-unknown-linux-gnu" => 62,
        "aarch64-unknown-linux-gnu" => 183,
        _ => return Err("ELF target unsupported".into()),
    };
    if header[4] != 2
        || header[5] != 1
        || header[6] != 1
        || u16_at(&header, 18) != machine
        || u32_at(&header, 20) != 1
        || !matches!(u16_at(&header, 16), 1 | 2 | 3)
        || u16_at(&header, 52) != 64
    {
        return Err("ELF native class/ABI/header differs".into());
    }
    if u16_at(&header, 16) == 1 {
        if u16_at(&header, 56) != 0 {
            return Err(
                "relocatable compiler input unexpectedly has loader program headers".into(),
            );
        }
        return Ok(Some(ElfDependencies {
            interpreter: None,
            needed: Vec::new(),
            search_paths: Vec::new(),
        }));
    }
    if u16_at(&header, 54) != 56 {
        return Err("ELF loader program-header width differs".into());
    }
    let count = u16_at(&header, 56);
    if count == 0 || count > 4096 {
        return Err("ELF program-header count is unsupported".into());
    }
    let table = u64_at(&header, 32);
    bounded_range(table, u64::from(count) * 56, length)?;
    let mut loads = Vec::new();
    let mut dynamic = None;
    let mut interpreter = None;
    for index in 0..count {
        let mut ph = [0; 56];
        read(table + u64::from(index) * 56, &mut ph)?;
        let offset = u64_at(&ph, 8);
        let address = u64_at(&ph, 16);
        let size = u64_at(&ph, 32);
        bounded_range(offset, size, length)?;
        match u32_at(&ph, 0) {
            1 => {
                if size > u64_at(&ph, 40) {
                    return Err("ELF load file span exceeds memory span".into());
                }
                loads.push((address, offset, size));
            }
            2 => {
                if dynamic.replace((offset, size)).is_some()
                    || size == 0
                    || size % 16 != 0
                    || size > 16 * 16384
                {
                    return Err("ELF dynamic segment is duplicate or excessive".into());
                }
            }
            3 => {
                if interpreter.is_some() || size < 2 || size > 4096 {
                    return Err("ELF interpreter segment is duplicate or excessive".into());
                }
                let mut bytes = vec![0; size as usize];
                read(offset, &mut bytes)?;
                if bytes.last() != Some(&0) || bytes[..bytes.len() - 1].contains(&0) {
                    return Err("ELF interpreter has invalid termination".into());
                }
                let path = string(&bytes, 0)?;
                if !path.starts_with('/') {
                    return Err("ELF interpreter is not target-root absolute".into());
                }
                interpreter = Some(path);
            }
            _ => (),
        }
    }
    let mut result = ElfDependencies {
        interpreter,
        needed: Vec::new(),
        search_paths: Vec::new(),
    };
    let Some((offset, size)) = dynamic else {
        return Ok(Some(result));
    };
    let mut strings = None;
    let mut string_size = None;
    let mut required = Vec::new();
    let mut paths = Vec::new();
    let mut terminated = false;
    for index in 0..size / 16 {
        let mut entry = [0; 16];
        read(offset + index * 16, &mut entry)?;
        let value = u64_at(&entry, 8);
        match u64_at(&entry, 0) {
            0 => {
                terminated = true;
                break;
            }
            1 => required.push(value),
            5 => {
                if strings.replace(value).is_some() {
                    return Err("ELF has duplicate string table".into());
                }
            }
            10 => {
                if string_size.replace(value).is_some() {
                    return Err("ELF has duplicate string size".into());
                }
            }
            15 | 29 => paths.push(value),
            // Loader auditing/filtering can introduce additional executable authority.
            0x7fff_fffd | 0x7fff_ffff | 0x6fff_fefb | 0x6fff_fefc => {
                return Err("ELF loader audit/filter extension is forbidden".into());
            }
            _ => (),
        }
    }
    if !terminated {
        return Err("ELF dynamic table lacks terminator".into());
    }
    if required.is_empty() && paths.is_empty() {
        return Ok(Some(result));
    }
    let address = strings.ok_or("ELF dependency string table absent")?;
    let size = string_size.ok_or("ELF dependency string size absent")?;
    if size == 0 || size > 1024 * 1024 {
        return Err("ELF dependency string table exceeds bound".into());
    }
    let candidates = loads
        .iter()
        .filter_map(|(start, offset, span)| {
            address
                .checked_sub(*start)
                .filter(|relative| relative.checked_add(size).is_some_and(|end| end <= *span))
                .and_then(|relative| offset.checked_add(relative))
        })
        .collect::<Vec<_>>();
    if candidates.len() != 1 {
        return Err("ELF string table does not resolve to one held file span".into());
    }
    let mut bytes = vec![0; size as usize];
    read(candidates[0], &mut bytes)?;
    for offset in required {
        let name = string(&bytes, offset)?;
        if name.contains('/') || name == "." || name == ".." {
            return Err("ELF needed dependency is not a library basename".into());
        }
        if !result.needed.contains(&name) {
            result.needed.push(name);
        }
    }
    for offset in paths {
        for path in string(&bytes, offset)?.split(':') {
            if path.is_empty() {
                return Err("ELF search path includes ambient cwd".into());
            }
            result.search_paths.push(path.to_owned());
        }
    }
    Ok(Some(result))
}
