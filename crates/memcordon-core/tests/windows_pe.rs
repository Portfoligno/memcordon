use memcordon_core::{
    WINDOWS_PE_MACHINE_AMD64, WINDOWS_PE_MACHINE_ARM64, WindowsPeImportSymbol,
    parse_windows_pe_imports, parse_windows_pe_loader_contract,
    parse_windows_pe_mapped_loader_contract, verify_session_broker_pe,
    verify_target_desktop_bootstrap_pe,
};

fn put_word(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn session_broker_import_gate_rejects_ui_shell_com_and_network_dependencies() {
    verify_session_broker_pe(&synthetic_pe("ADVAPI32.dll", false))
        .expect("service-control imports belong to the fixed broker role");
    for dll in [
        "USER32.dll",
        "SHELL32.dll",
        "OLE32.dll",
        "WINHTTP.dll",
        "WS2_32.dll",
    ] {
        for delayed in [false, true] {
            let error = verify_session_broker_pe(&synthetic_pe(dll, delayed))
                .expect_err("general-purpose broker imports must fail closed");
            assert!(error.contains(&dll.to_ascii_uppercase()));
        }
    }
}

fn put_dword(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_qword(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn synthetic_pe(dll: &str, delayed: bool) -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x600];
    bytes[..2].copy_from_slice(b"MZ");
    put_dword(&mut bytes, 0x3c, 0x80);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    put_word(&mut bytes, 0x84, WINDOWS_PE_MACHINE_AMD64);
    put_word(&mut bytes, 0x86, 1);
    put_word(&mut bytes, 0x94, 0xf0);
    let optional = 0x98;
    put_word(&mut bytes, optional, 0x20b);
    put_qword(&mut bytes, optional + 24, 0x0000_0001_4000_0000);
    put_dword(&mut bytes, optional + 60, 0x200);
    put_dword(&mut bytes, optional + 108, 16);
    let section = optional + 0xf0;
    put_dword(&mut bytes, section + 8, 0x400);
    put_dword(&mut bytes, section + 12, 0x1000);
    put_dword(&mut bytes, section + 16, 0x400);
    put_dword(&mut bytes, section + 20, 0x200);

    let (directory, descriptor, name_rva, name_offset, size) = if delayed {
        (optional + 216, 0x300, 0x1180, 0x380, 64)
    } else {
        (optional + 120, 0x200, 0x1080, 0x280, 40)
    };
    put_dword(
        &mut bytes,
        directory,
        0x1000 + u32::try_from(descriptor - 0x200).expect("test RVA"),
    );
    put_dword(&mut bytes, directory + 4, size);
    if delayed {
        put_dword(&mut bytes, descriptor, 1);
        put_dword(&mut bytes, descriptor + 4, name_rva);
    } else {
        put_dword(&mut bytes, descriptor + 12, name_rva);
    }
    bytes[name_offset..name_offset + dll.len()].copy_from_slice(dll.as_bytes());
    bytes[name_offset + dll.len()] = 0;
    bytes
}

fn synthetic_ordered_loader_pe(machine: u16, dlls: &[&str]) -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x1200];
    bytes[..2].copy_from_slice(b"MZ");
    put_dword(&mut bytes, 0x3c, 0x80);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    put_word(&mut bytes, 0x84, machine);
    put_word(&mut bytes, 0x86, 1);
    put_word(&mut bytes, 0x94, 0xf0);
    let optional = 0x98;
    put_word(&mut bytes, optional, 0x20b);
    put_qword(&mut bytes, optional + 24, 0x0000_0001_4000_0000);
    put_dword(&mut bytes, optional + 60, 0x200);
    put_dword(&mut bytes, optional + 108, 16);
    put_dword(&mut bytes, optional + 120, 0x1000);
    put_dword(
        &mut bytes,
        optional + 124,
        u32::try_from((dlls.len() + 1) * 20).unwrap(),
    );
    let section = optional + 0xf0;
    put_dword(&mut bytes, section + 8, 0x1000);
    put_dword(&mut bytes, section + 12, 0x1000);
    put_dword(&mut bytes, section + 16, 0x1000);
    put_dword(&mut bytes, section + 20, 0x200);
    for (index, dll) in dlls.iter().enumerate() {
        let descriptor = 0x200 + index * 20;
        let name = 0x400 + index * 0x40;
        let thunk = 0x700 + index * 0x20;
        let symbol = 0xa00 + index * 0x40;
        let rva = |offset: usize| 0x1000 + u32::try_from(offset - 0x200).unwrap();
        put_dword(&mut bytes, descriptor, rva(thunk));
        put_dword(&mut bytes, descriptor + 12, rva(name));
        put_dword(&mut bytes, descriptor + 16, rva(thunk));
        bytes[name..name + dll.len()].copy_from_slice(dll.as_bytes());
        bytes[name + dll.len()] = 0;
        put_qword(&mut bytes, thunk, u64::from(rva(symbol)));
        put_qword(&mut bytes, thunk + 8, (1_u64 << 63) | 7);
        put_word(&mut bytes, symbol, index as u16);
        let symbol_name = format!("Imported{index}");
        bytes[symbol + 2..symbol + 2 + symbol_name.len()].copy_from_slice(symbol_name.as_bytes());
        bytes[symbol + 2 + symbol_name.len()] = 0;
    }
    bytes
}

fn mapped_image(file: &[u8]) -> Vec<u8> {
    let mut mapped = vec![0_u8; 0x3000];
    mapped[..0x200].copy_from_slice(&file[..0x200]);
    mapped[0x1000..0x2000].copy_from_slice(&file[0x200..0x1200]);
    mapped
}

#[test]
fn import_parser_accepts_minimal_non_ui_image() {
    let parsed = parse_windows_pe_imports(&synthetic_pe("KERNEL32.dll", false))
        .expect("synthetic PE should parse");
    assert_eq!(parsed.machine, WINDOWS_PE_MACHINE_AMD64);
    assert_eq!(parsed.normal, ["KERNEL32.DLL"]);
    assert!(parsed.delayed.is_empty());
    verify_target_desktop_bootstrap_pe(&synthetic_pe("KERNEL32.dll", false))
        .expect("kernel-only helper should satisfy the loader contract");
}

#[test]
fn import_gate_rejects_ui_dependency_in_normal_and_delay_tables() {
    for delayed in [false, true] {
        let error = verify_target_desktop_bootstrap_pe(&synthetic_pe("user32.dll", delayed))
            .expect_err("USER32 must be absent from every pre-entry import table");
        assert!(error.contains("USER32.DLL"));
    }
}

#[test]
fn import_gate_rejects_dynamic_crt_dependency_in_normal_and_delay_tables() {
    for dll in [
        "VCRUNTIME140.dll",
        "VCRUNTIME140_1.dll",
        "MSVCP140.dll",
        "MSVCRT.dll",
        "UCRTBASE.dll",
        "api-ms-win-crt-runtime-l1-1-0.dll",
    ] {
        for delayed in [false, true] {
            let error = verify_target_desktop_bootstrap_pe(&synthetic_pe(dll, delayed))
                .expect_err("dynamic CRT imports must fail the loader-safe contract");
            assert!(error.contains(&dll.to_ascii_uppercase()));
        }
    }
}

#[test]
fn import_parser_rejects_unterminated_descriptor_directory() {
    let mut bytes = synthetic_pe("KERNEL32.dll", false);
    let optional = 0x98;
    put_dword(&mut bytes, optional + 124, 20);
    let error = parse_windows_pe_imports(&bytes)
        .expect_err("descriptor directory without terminator must fail closed");
    assert!(error.contains("terminating descriptor"));
}

#[test]
fn detailed_import_parser_preserves_descriptor_and_thunk_order_for_native_machines() {
    for machine in [WINDOWS_PE_MACHINE_AMD64, WINDOWS_PE_MACHINE_ARM64] {
        let file = synthetic_ordered_loader_pe(machine, &["KERNEL32.dll", "ADVAPI32.dll"]);
        let detailed = parse_windows_pe_loader_contract(&file).unwrap();
        assert_eq!(detailed.machine, machine);
        assert_eq!(detailed.normal[0].ordinal, 0);
        assert_eq!(detailed.normal[0].dll, "KERNEL32.DLL");
        assert_eq!(detailed.normal[1].ordinal, 1);
        assert_eq!(detailed.normal[1].dll, "ADVAPI32.DLL");
        assert!(matches!(
            &detailed.normal[0].symbols[..],
            [WindowsPeImportSymbol::Name { hint: 0, name }, WindowsPeImportSymbol::Ordinal(7)]
                if name == "Imported0"
        ));
        let legacy = parse_windows_pe_imports(&file).unwrap();
        assert_eq!(legacy.normal, ["ADVAPI32.DLL", "KERNEL32.DLL"]);
        assert_eq!(
            parse_windows_pe_mapped_loader_contract(&mapped_image(&file)).unwrap(),
            detailed,
        );
    }
}

#[test]
fn detailed_import_parser_rejects_unterminated_thunks() {
    let mut file = synthetic_ordered_loader_pe(WINDOWS_PE_MACHINE_AMD64, &["KERNEL32.dll"]);
    for offset in (0x700..0x1200).step_by(8) {
        put_qword(&mut file, offset, (1_u64 << 63) | 7);
    }
    let error = parse_windows_pe_loader_contract(&file).unwrap_err();
    assert!(error.contains("truncated") || error.contains("bound"));
}
