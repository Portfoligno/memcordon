use memcordon_core::elf_closure::{ElfDependencies, inspect};

fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn vector() -> Vec<u8> {
    let mut bytes = vec![0; 512];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    put16(&mut bytes, 16, 3);
    put16(&mut bytes, 18, 62);
    put32(&mut bytes, 20, 1);
    put64(&mut bytes, 32, 64);
    put16(&mut bytes, 52, 64);
    put16(&mut bytes, 54, 56);
    put16(&mut bytes, 56, 3);
    put32(&mut bytes, 64, 1);
    put64(&mut bytes, 80, 0x400000);
    put64(&mut bytes, 96, 512);
    put64(&mut bytes, 104, 512);
    put32(&mut bytes, 120, 2);
    put64(&mut bytes, 128, 256);
    put64(&mut bytes, 152, 80);
    let interpreter = b"/lib/ld-test.so\0";
    put32(&mut bytes, 176, 3);
    put64(&mut bytes, 184, 336);
    put64(&mut bytes, 208, interpreter.len() as u64);
    bytes[336..336 + interpreter.len()].copy_from_slice(interpreter);
    let strings = b"\0libtest.so\0/lib\0";
    bytes[384..384 + strings.len()].copy_from_slice(strings);
    for (index, (tag, value)) in [
        (1, 1),
        (5, 0x400180),
        (10, strings.len() as u64),
        (29, 12),
        (0, 0),
    ]
    .into_iter()
    .enumerate()
    {
        put64(&mut bytes, 256 + index * 16, tag);
        put64(&mut bytes, 264 + index * 16, value);
    }
    bytes
}
fn parse(bytes: &[u8]) -> Result<Option<ElfDependencies>, String> {
    inspect(
        |offset, output| {
            let start = usize::try_from(offset).map_err(|error| error.to_string())?;
            let input = bytes
                .get(start..start + output.len())
                .ok_or("read exceeds fixture")?;
            output.copy_from_slice(input);
            Ok(())
        },
        bytes.len() as u64,
        "x86_64-unknown-linux-gnu",
    )
}
#[test]
fn independently_constructed_loader_vector_has_exact_dependencies() {
    assert_eq!(
        parse(&vector()).unwrap(),
        Some(ElfDependencies {
            interpreter: Some("/lib/ld-test.so".into()),
            needed: vec!["libtest.so".into()],
            search_paths: vec!["/lib".into()]
        })
    );
    assert_eq!(parse(b"ordinary locked source input").unwrap(), None);
    let mut relocatable = vector();
    put16(&mut relocatable, 16, 1);
    put16(&mut relocatable, 56, 0);
    put16(&mut relocatable, 54, 0);
    assert_eq!(
        parse(&relocatable).unwrap(),
        Some(ElfDependencies {
            interpreter: None,
            needed: vec![],
            search_paths: vec![]
        })
    );
}
#[test]
fn malformed_native_abi_ranges_and_loader_authority_are_rejected() {
    let mut wrong = vector();
    put16(&mut wrong, 18, 183);
    assert!(parse(&wrong).is_err());
    let mut wrong = vector();
    put64(&mut wrong, 152, u64::MAX);
    assert!(parse(&wrong).is_err());
    let mut wrong = vector();
    put64(&mut wrong, 320, 1);
    assert!(parse(&wrong).is_err(), "dynamic terminator is mandatory");
    let mut wrong = vector();
    put64(&mut wrong, 304, 0x6fff_fefc);
    assert!(
        parse(&wrong).is_err(),
        "loader auditing cannot introduce authority"
    );
    let mut wrong = vector();
    wrong[384 + 1] = b'/';
    assert!(
        parse(&wrong).is_err(),
        "DT_NEEDED must not introduce cwd/absolute search paths"
    );
    let mut wrong = vector();
    wrong[384 + 12] = b':';
    assert!(
        parse(&wrong).is_err(),
        "empty search component introduces cwd"
    );
}
