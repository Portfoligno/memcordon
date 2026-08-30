use std::collections::BTreeSet;

pub const WINDOWS_PE_MACHINE_AMD64: u16 = 0x8664;
pub const WINDOWS_PE_MACHINE_ARM64: u16 = 0xaa64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsPeImports {
    pub machine: u16,
    pub normal: Vec<String>,
    pub delayed: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowsPeImportSymbol {
    Name { hint: u16, name: String },
    Ordinal(u16),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsPeImportDescriptor {
    pub ordinal: u32,
    pub dll: String,
    pub symbols: Vec<WindowsPeImportSymbol>,
    pub lookup_table_rva: u32,
    pub iat_rva: u32,
    pub bound_timestamp: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowsPeExportTarget {
    DirectRva(u32),
    Forwarder(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsPeExport {
    pub ordinal: u32,
    pub name: Option<String>,
    pub target: WindowsPeExportTarget,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsPeLoaderContract {
    pub machine: u16,
    pub normal: Vec<WindowsPeImportDescriptor>,
    pub delayed: Vec<WindowsPeImportDescriptor>,
    pub exports: Vec<WindowsPeExport>,
}

#[derive(Clone, Copy)]
enum PeLayout {
    File,
    MappedImage,
}

const MAX_IMPORT_DESCRIPTORS: usize = 1_024;
const MAX_IMPORT_THUNKS: usize = 16_384;
const MAX_EXPORTS: usize = 65_536;
const MAX_PE_STRING_BYTES: usize = 4_096;

fn word(bytes: &[u8], offset: usize) -> Result<u16, String> {
    let value = bytes
        .get(offset..offset.checked_add(2).ok_or("PE offset overflow")?)
        .ok_or("PE field is truncated")?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn dword(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let value = bytes
        .get(offset..offset.checked_add(4).ok_or("PE offset overflow")?)
        .ok_or("PE field is truncated")?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn qword(bytes: &[u8], offset: usize) -> Result<u64, String> {
    let value = bytes
        .get(offset..offset.checked_add(8).ok_or("PE offset overflow")?)
        .ok_or("PE field is truncated")?;
    Ok(u64::from_le_bytes(
        value.try_into().expect("eight-byte PE field"),
    ))
}

#[derive(Clone, Copy)]
struct Section {
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
}

fn rva_offset(
    bytes: &[u8],
    rva: u32,
    size_of_headers: u32,
    sections: &[Section],
) -> Result<usize, String> {
    if rva < size_of_headers {
        let offset = rva as usize;
        return bytes
            .get(offset..)
            .map(|_| offset)
            .ok_or_else(|| "PE header RVA is outside the image".to_owned());
    }
    for section in sections {
        let end = section
            .virtual_address
            .checked_add(section.virtual_size.max(section.raw_size))
            .ok_or("PE section RVA overflows")?;
        if rva >= section.virtual_address && rva < end {
            let within = rva - section.virtual_address;
            if within >= section.raw_size {
                return Err("PE RVA points outside section file data".to_owned());
            }
            let offset = section
                .raw_offset
                .checked_add(within)
                .ok_or("PE section file offset overflows")? as usize;
            return bytes
                .get(offset..)
                .map(|_| offset)
                .ok_or_else(|| "PE section file offset is outside the image".to_owned());
        }
    }
    Err("PE RVA is not mapped by a section".to_owned())
}

fn layout_rva_offset(
    bytes: &[u8],
    rva: u32,
    size_of_headers: u32,
    sections: &[Section],
    layout: PeLayout,
) -> Result<usize, String> {
    match layout {
        PeLayout::File => rva_offset(bytes, rva, size_of_headers, sections),
        PeLayout::MappedImage => bytes
            .get(rva as usize..)
            .map(|_| rva as usize)
            .ok_or_else(|| "PE mapped-image RVA is outside the view".to_owned()),
    }
}

fn ascii_string(bytes: &[u8], offset: usize, class: &str) -> Result<String, String> {
    let tail = bytes
        .get(offset..)
        .ok_or_else(|| format!("PE {class} string offset is outside the image"))?;
    let bounded = &tail[..tail.len().min(MAX_PE_STRING_BYTES + 1)];
    let length = bounded
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| format!("PE {class} string is unterminated or exceeds its bound"))?;
    let value = std::str::from_utf8(&bounded[..length])
        .map_err(|_| format!("PE {class} string is not UTF-8"))?;
    if value.is_empty() || !value.is_ascii() {
        return Err(format!("PE {class} string is not canonical ASCII"));
    }
    Ok(value.to_owned())
}

fn dll_name(bytes: &[u8], offset: usize) -> Result<String, String> {
    let name = ascii_string(bytes, offset, "import name")?;
    if name.is_empty() || !name.is_ascii() || name.contains(['/', '\\']) {
        return Err("PE import name is not a canonical DLL basename".to_owned());
    }
    Ok(name.to_ascii_uppercase())
}

struct PeHeaders {
    machine: u16,
    image_base: u64,
    size_of_headers: u32,
    sections: Vec<Section>,
    export_rva: u32,
    export_size: u32,
    normal_rva: u32,
    normal_size: u32,
    delay_rva: u32,
    delay_size: u32,
}

fn pe_headers(bytes: &[u8]) -> Result<PeHeaders, String> {
    if bytes.get(..2) != Some(b"MZ") {
        return Err("Windows helper lacks the DOS header".to_owned());
    }
    let pe = dword(bytes, 0x3c)? as usize;
    if bytes.get(pe..pe.checked_add(4).ok_or("PE header offset overflow")?) != Some(b"PE\0\0") {
        return Err("Windows helper lacks the PE signature".to_owned());
    }
    let machine = word(bytes, pe + 4)?;
    if !matches!(machine, WINDOWS_PE_MACHINE_AMD64 | WINDOWS_PE_MACHINE_ARM64) {
        return Err(format!(
            "Windows helper has unsupported PE machine 0x{machine:04x}"
        ));
    }
    let section_count = word(bytes, pe + 6)? as usize;
    let optional_size = word(bytes, pe + 20)? as usize;
    let optional = pe
        .checked_add(24)
        .ok_or("PE optional-header offset overflow")?;
    if word(bytes, optional)? != 0x20b || optional_size < 224 {
        return Err("Windows helper is not a complete PE32+ image".to_owned());
    }
    let optional_end = optional
        .checked_add(optional_size)
        .ok_or("PE optional-header size overflow")?;
    bytes
        .get(optional..optional_end)
        .ok_or("PE optional header is truncated")?;
    let image_base = qword(bytes, optional + 24)?;
    let size_of_headers = dword(bytes, optional + 60)?;
    if dword(bytes, optional + 108)? <= 13 {
        return Err("Windows helper lacks required PE data directories".to_owned());
    }
    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let offset = optional_end
            .checked_add(index.checked_mul(40).ok_or("PE section index overflow")?)
            .ok_or("PE section offset overflow")?;
        bytes
            .get(offset..offset.checked_add(40).ok_or("PE section header overflow")?)
            .ok_or("PE section header is truncated")?;
        sections.push(Section {
            virtual_size: dword(bytes, offset + 8)?,
            virtual_address: dword(bytes, offset + 12)?,
            raw_size: dword(bytes, offset + 16)?,
            raw_offset: dword(bytes, offset + 20)?,
        });
    }
    Ok(PeHeaders {
        machine,
        image_base,
        size_of_headers,
        sections,
        export_rva: dword(bytes, optional + 112)?,
        export_size: dword(bytes, optional + 116)?,
        normal_rva: dword(bytes, optional + 120)?,
        normal_size: dword(bytes, optional + 124)?,
        delay_rva: dword(bytes, optional + 216)?,
        delay_size: dword(bytes, optional + 220)?,
    })
}

fn va_or_rva(value: u32, image_base: u64, rva_based: bool, field: &str) -> Result<u32, String> {
    if rva_based || value == 0 {
        return Ok(value);
    }
    let relative = u64::from(value)
        .checked_sub(image_base)
        .ok_or_else(|| format!("PE delay import {field} precedes image base"))?;
    u32::try_from(relative).map_err(|_| format!("PE delay import {field} RVA is too large"))
}

fn import_symbols(
    bytes: &[u8],
    lookup_rva: u32,
    headers: &PeHeaders,
    layout: PeLayout,
) -> Result<Vec<WindowsPeImportSymbol>, String> {
    if lookup_rva == 0 {
        return Err("PE import descriptor has no lookup or IAT table".to_owned());
    }
    let start = layout_rva_offset(
        bytes,
        lookup_rva,
        headers.size_of_headers,
        &headers.sections,
        layout,
    )?;
    let mut symbols = Vec::new();
    for index in 0..MAX_IMPORT_THUNKS {
        let offset = start
            .checked_add(index.checked_mul(8).ok_or("PE thunk index overflow")?)
            .ok_or("PE thunk offset overflow")?;
        let thunk = qword(bytes, offset)?;
        if thunk == 0 {
            return Ok(symbols);
        }
        if thunk & (1_u64 << 63) != 0 {
            if thunk & !((1_u64 << 63) | 0xffff) != 0 {
                return Err("PE ordinal thunk has reserved bits".to_owned());
            }
            symbols.push(WindowsPeImportSymbol::Ordinal(thunk as u16));
        } else {
            let name_rva = u32::try_from(thunk).map_err(|_| "PE name thunk RVA is too large")?;
            let name_offset = layout_rva_offset(
                bytes,
                name_rva,
                headers.size_of_headers,
                &headers.sections,
                layout,
            )?;
            let hint = word(bytes, name_offset)?;
            let name = ascii_string(bytes, name_offset + 2, "import symbol")?;
            symbols.push(WindowsPeImportSymbol::Name { hint, name });
        }
    }
    Err("PE import thunk table exceeds its bound or is unterminated".to_owned())
}

fn import_descriptors(
    bytes: &[u8],
    directory_rva: u32,
    directory_size: u32,
    delay: bool,
    headers: &PeHeaders,
    layout: PeLayout,
) -> Result<Vec<WindowsPeImportDescriptor>, String> {
    if directory_rva == 0 && directory_size == 0 {
        return Ok(Vec::new());
    }
    if directory_rva == 0 || directory_size == 0 {
        return Err("PE import directory is partially absent".to_owned());
    }
    let descriptor_size = if delay { 32 } else { 20 };
    let start = layout_rva_offset(
        bytes,
        directory_rva,
        headers.size_of_headers,
        &headers.sections,
        layout,
    )?;
    let maximum = (directory_size as usize / descriptor_size).min(MAX_IMPORT_DESCRIPTORS);
    if maximum == 0 {
        return Err("PE import directory cannot hold a descriptor".to_owned());
    }
    let mut descriptors = Vec::new();
    for index in 0..maximum {
        let offset = start
            .checked_add(
                index
                    .checked_mul(descriptor_size)
                    .ok_or("PE import index overflow")?,
            )
            .ok_or("PE import descriptor offset overflow")?;
        let descriptor = bytes
            .get(
                offset
                    ..offset
                        .checked_add(descriptor_size)
                        .ok_or("PE import descriptor overflow")?,
            )
            .ok_or("PE import descriptor is truncated")?;
        if descriptor.iter().all(|byte| *byte == 0) {
            return Ok(descriptors);
        }
        let rva_based = !delay || dword(bytes, offset)? & 1 != 0;
        let raw_name = dword(bytes, offset + if delay { 4 } else { 12 })?;
        let name_rva = va_or_rva(raw_name, headers.image_base, rva_based, "name")?;
        if name_rva == 0 {
            return Err("PE import descriptor has no DLL name".to_owned());
        }
        let iat_rva = va_or_rva(
            dword(bytes, offset + if delay { 12 } else { 16 })?,
            headers.image_base,
            rva_based,
            "IAT",
        )?;
        let raw_lookup = dword(bytes, offset + if delay { 16 } else { 0 })?;
        let lookup_table_rva = va_or_rva(
            if raw_lookup == 0 { iat_rva } else { raw_lookup },
            headers.image_base,
            rva_based,
            "lookup table",
        )?;
        let dll = dll_name(
            bytes,
            layout_rva_offset(
                bytes,
                name_rva,
                headers.size_of_headers,
                &headers.sections,
                layout,
            )?,
        )?;
        descriptors.push(WindowsPeImportDescriptor {
            ordinal: index as u32,
            dll,
            symbols: import_symbols(bytes, lookup_table_rva, headers, layout)?,
            lookup_table_rva,
            iat_rva,
            bound_timestamp: dword(bytes, offset + if delay { 28 } else { 4 })?,
        });
    }
    Err("PE import directory has no terminating descriptor within its bound".to_owned())
}

fn exports(
    bytes: &[u8],
    headers: &PeHeaders,
    layout: PeLayout,
) -> Result<Vec<WindowsPeExport>, String> {
    if headers.export_rva == 0 && headers.export_size == 0 {
        return Ok(Vec::new());
    }
    if headers.export_rva == 0 || headers.export_size < 40 {
        return Err("PE export directory is partially absent or truncated".to_owned());
    }
    let directory = layout_rva_offset(
        bytes,
        headers.export_rva,
        headers.size_of_headers,
        &headers.sections,
        layout,
    )?;
    let ordinal_base = dword(bytes, directory + 16)?;
    let function_count = dword(bytes, directory + 20)? as usize;
    let name_count = dword(bytes, directory + 24)? as usize;
    if function_count > MAX_EXPORTS || name_count > function_count || name_count > MAX_EXPORTS {
        return Err("PE export inventory exceeds its bound".to_owned());
    }
    let functions = layout_rva_offset(
        bytes,
        dword(bytes, directory + 28)?,
        headers.size_of_headers,
        &headers.sections,
        layout,
    )?;
    let names = layout_rva_offset(
        bytes,
        dword(bytes, directory + 32)?,
        headers.size_of_headers,
        &headers.sections,
        layout,
    )?;
    let ordinals = layout_rva_offset(
        bytes,
        dword(bytes, directory + 36)?,
        headers.size_of_headers,
        &headers.sections,
        layout,
    )?;
    let mut export_names = vec![None; function_count];
    for index in 0..name_count {
        let name_rva = dword(bytes, names + index * 4)?;
        let function_index = word(bytes, ordinals + index * 2)? as usize;
        if function_index >= function_count || export_names[function_index].is_some() {
            return Err("PE export name ordinal is invalid or duplicated".to_owned());
        }
        export_names[function_index] = Some(ascii_string(
            bytes,
            layout_rva_offset(
                bytes,
                name_rva,
                headers.size_of_headers,
                &headers.sections,
                layout,
            )?,
            "export name",
        )?);
    }
    let forwarder_end = headers
        .export_rva
        .checked_add(headers.export_size)
        .ok_or("PE export directory RVA overflows")?;
    let mut result = Vec::new();
    for (index, name) in export_names.into_iter().enumerate() {
        let target_rva = dword(bytes, functions + index * 4)?;
        if target_rva == 0 {
            continue;
        }
        let target = if target_rva >= headers.export_rva && target_rva < forwarder_end {
            WindowsPeExportTarget::Forwarder(ascii_string(
                bytes,
                layout_rva_offset(
                    bytes,
                    target_rva,
                    headers.size_of_headers,
                    &headers.sections,
                    layout,
                )?,
                "export forwarder",
            )?)
        } else {
            WindowsPeExportTarget::DirectRva(target_rva)
        };
        result.push(WindowsPeExport {
            ordinal: ordinal_base
                .checked_add(index as u32)
                .ok_or("PE export ordinal overflows")?,
            name,
            target,
        });
    }
    Ok(result)
}

fn parse_windows_pe_loader_contract_with_layout(
    bytes: &[u8],
    layout: PeLayout,
) -> Result<WindowsPeLoaderContract, String> {
    let headers = pe_headers(bytes)?;
    Ok(WindowsPeLoaderContract {
        machine: headers.machine,
        normal: import_descriptors(
            bytes,
            headers.normal_rva,
            headers.normal_size,
            false,
            &headers,
            layout,
        )?,
        delayed: import_descriptors(
            bytes,
            headers.delay_rva,
            headers.delay_size,
            true,
            &headers,
            layout,
        )?,
        exports: exports(bytes, &headers, layout)?,
    })
}

pub fn parse_windows_pe_loader_contract(bytes: &[u8]) -> Result<WindowsPeLoaderContract, String> {
    parse_windows_pe_loader_contract_with_layout(bytes, PeLayout::File)
}

pub fn parse_windows_pe_mapped_loader_contract(
    bytes: &[u8],
) -> Result<WindowsPeLoaderContract, String> {
    parse_windows_pe_loader_contract_with_layout(bytes, PeLayout::MappedImage)
}

#[allow(clippy::too_many_arguments)]
fn import_names(
    bytes: &[u8],
    directory_rva: u32,
    directory_size: u32,
    descriptor_size: usize,
    name_field: usize,
    delay: bool,
    image_base: u64,
    size_of_headers: u32,
    sections: &[Section],
) -> Result<Vec<String>, String> {
    if directory_rva == 0 && directory_size == 0 {
        return Ok(Vec::new());
    }
    if directory_rva == 0 || directory_size == 0 {
        return Err("PE import directory is partially absent".to_owned());
    }
    let start = rva_offset(bytes, directory_rva, size_of_headers, sections)?;
    let maximum = directory_size as usize / descriptor_size;
    if maximum == 0 {
        return Err("PE import directory cannot hold a descriptor".to_owned());
    }
    let mut imports = BTreeSet::new();
    for index in 0..maximum {
        let offset = start
            .checked_add(
                index
                    .checked_mul(descriptor_size)
                    .ok_or("PE import index overflow")?,
            )
            .ok_or("PE import descriptor offset overflow")?;
        let end = offset
            .checked_add(descriptor_size)
            .ok_or("PE import descriptor overflow")?;
        let descriptor = bytes
            .get(offset..end)
            .ok_or("PE import descriptor is truncated")?;
        if descriptor.iter().all(|byte| *byte == 0) {
            return Ok(imports.into_iter().collect());
        }
        let raw_name = dword(bytes, offset + name_field)?;
        if raw_name == 0 {
            return Err("PE import descriptor has no DLL name".to_owned());
        }
        let name_rva = if delay && dword(bytes, offset)? & 1 == 0 {
            let relative = u64::from(raw_name)
                .checked_sub(image_base)
                .ok_or("PE delay import name precedes image base")?;
            u32::try_from(relative).map_err(|_| "PE delay import name RVA is too large")?
        } else {
            raw_name
        };
        imports.insert(dll_name(
            bytes,
            rva_offset(bytes, name_rva, size_of_headers, sections)?,
        )?);
    }
    Err("PE import directory has no terminating descriptor".to_owned())
}

pub fn parse_windows_pe_imports(bytes: &[u8]) -> Result<WindowsPeImports, String> {
    let headers = pe_headers(bytes)?;
    let normal = import_names(
        bytes,
        headers.normal_rva,
        headers.normal_size,
        20,
        12,
        false,
        headers.image_base,
        headers.size_of_headers,
        &headers.sections,
    )?;
    let delayed = import_names(
        bytes,
        headers.delay_rva,
        headers.delay_size,
        32,
        4,
        true,
        headers.image_base,
        headers.size_of_headers,
        &headers.sections,
    )?;
    Ok(WindowsPeImports {
        machine: headers.machine,
        normal,
        delayed,
    })
}

pub fn verify_target_desktop_bootstrap_pe(bytes: &[u8]) -> Result<WindowsPeImports, String> {
    let imports = parse_windows_pe_imports(bytes)?;
    const DENIED: &[&str] = &[
        "USER32.DLL",
        "GDI32.DLL",
        "GDI32FULL.DLL",
        "COMCTL32.DLL",
        "COMDLG32.DLL",
        "OLE32.DLL",
        "OLEAUT32.DLL",
        "SHELL32.DLL",
        "SHLWAPI.DLL",
    ];
    if let Some(name) = imports.normal.iter().chain(&imports.delayed).find(|name| {
        DENIED.contains(&name.as_str())
            || name.as_str() == "UCRTBASE.DLL"
            || name.as_str() == "MSVCRT.DLL"
            || name.starts_with("VCRUNTIME")
            || name.starts_with("MSVCP")
            || name.starts_with("API-MS-WIN-CRT-")
    }) {
        return Err(format!(
            "target desktop bootstrap PE imports forbidden dynamic loader dependency {name}"
        ));
    }
    Ok(imports)
}

pub fn verify_session_broker_pe(bytes: &[u8]) -> Result<WindowsPeImports, String> {
    let imports = parse_windows_pe_imports(bytes)?;
    // The fixed one-shot broker has no UI, shell, COM, or network role. Keep
    // those broad surfaces out of both eager and delay-load import tables.
    const DENIED: &[&str] = &[
        "USER32.DLL",
        "GDI32.DLL",
        "GDI32FULL.DLL",
        "COMCTL32.DLL",
        "COMDLG32.DLL",
        "OLE32.DLL",
        "OLEAUT32.DLL",
        "SHELL32.DLL",
        "SHLWAPI.DLL",
        "URLMON.DLL",
        "WINHTTP.DLL",
        "WININET.DLL",
        "WS2_32.DLL",
    ];
    if let Some(name) = imports
        .normal
        .iter()
        .chain(&imports.delayed)
        .find(|name| DENIED.contains(&name.as_str()))
    {
        return Err(format!(
            "session broker PE imports forbidden general-purpose dependency {name}"
        ));
    }
    Ok(imports)
}
