use memcordon_readiness_verifier::current::linux_images::inspect_elf;
fn elf() -> Vec<u8> {
    let mut bytes = vec![0; 512];
    bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
    bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&3_u16.to_le_bytes());
    let mut header = |index: usize, kind: u32, file: u64, address: u64, size: u64| {
        let at = 64 + 56 * index;
        bytes[at..at + 4].copy_from_slice(&kind.to_le_bytes());
        bytes[at + 8..at + 16].copy_from_slice(&file.to_le_bytes());
        bytes[at + 16..at + 24].copy_from_slice(&address.to_le_bytes());
        bytes[at + 32..at + 40].copy_from_slice(&size.to_le_bytes());
    };
    header(0, 1, 0, 0x400000, 512);
    header(1, 3, 240, 0, b"/lib64/ld-linux-x86-64.so.2\0".len() as u64);
    header(2, 2, 288, 0, 96);
    bytes[240..240 + b"/lib64/ld-linux-x86-64.so.2\0".len()]
        .copy_from_slice(b"/lib64/ld-linux-x86-64.so.2\0");
    for (index, (tag, value)) in [
        (5_u64, 0x400000_u64 + 400),
        (10, 17),
        (1, 1),
        (29, 11),
        (0, 0),
    ]
    .into_iter()
    .enumerate()
    {
        let at = 288 + index * 16;
        bytes[at..at + 8].copy_from_slice(&tag.to_le_bytes());
        bytes[at + 8..at + 16].copy_from_slice(&value.to_le_bytes());
    }
    bytes[400..417].copy_from_slice(b"\0libc.so.6\0/work\0");
    bytes
}
#[test]
fn independent_current_elf_decoder_binds_real_interpreter_and_dynamic_strings() {
    let bytes = elf();
    let parsed = inspect_elf(&bytes, "x86_64-unknown-linux-gnu").unwrap();
    assert_eq!(
        parsed.interpreter.as_deref(),
        Some("/lib64/ld-linux-x86-64.so.2")
    );
    assert_eq!(parsed.needed, ["libc.so.6"]);
    assert_eq!(parsed.paths, ["/work"]);
    for (at, value) in [(296, 0xffff_u64), (344, 999)] {
        let mut changed = bytes.clone();
        changed[at..at + 8].copy_from_slice(&value.to_le_bytes());
        assert!(inspect_elf(&changed, "x86_64-unknown-linux-gnu").is_err());
    }
    assert!(inspect_elf(&bytes, "aarch64-unknown-linux-gnu").is_err());
    let mut changed = bytes;
    changed[56..58].copy_from_slice(&513_u16.to_le_bytes());
    assert!(inspect_elf(&changed, "x86_64-unknown-linux-gnu").is_err());
}
#[test]
fn runpath_negative_requires_one_actual_dynamic_entry_and_unchanged_source_bytes() {
    use memcordon_readiness_verifier::current::linux_images::verify_relative_runpath_probe;
    let mut original = elf();
    let at = 288 + 3 * 16;
    original[at..at + 16].fill(0);
    let mut probe = original.clone();
    probe[at..at + 8].copy_from_slice(&29_u64.to_le_bytes());
    probe[at + 8..at + 16].copy_from_slice(&1_u64.to_le_bytes());
    assert_eq!(
        verify_relative_runpath_probe(&original, &probe, at, "x86_64-unknown-linux-gnu").unwrap(),
        "libc.so.6"
    );
    let mut changed = probe.clone();
    changed[480] = 1;
    assert!(
        verify_relative_runpath_probe(&original, &changed, at, "x86_64-unknown-linux-gnu").is_err()
    );
    let mut changed = probe.clone();
    changed[at + 8..at + 16].copy_from_slice(&11_u64.to_le_bytes());
    assert!(
        verify_relative_runpath_probe(&original, &changed, at, "x86_64-unknown-linux-gnu").is_err()
    );
    assert!(
        verify_relative_runpath_probe(&original, &probe, at + 1, "x86_64-unknown-linux-gnu")
            .is_err()
    );
    assert!(
        verify_relative_runpath_probe(&original, &probe, at, "aarch64-unknown-linux-gnu").is_err()
    );
}
