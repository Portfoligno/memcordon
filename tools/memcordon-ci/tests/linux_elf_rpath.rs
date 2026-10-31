use memcordon_ci::linux_elf_rpath::mutate;
use serde_json::Value;

const BASE: u64 = 0x400000;
const HEADERS: usize = 64;
const PROGRAM: usize = 56;
const DYNAMIC: usize = 512;
const STRINGS: usize = 1024;
const INTERPRETER: usize = 768;
const ENTRY: usize = 16;

fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn segment(bytes: &mut [u8], index: usize, kind: u32, offset: usize, size: usize) {
    let at = HEADERS + index * PROGRAM;
    put32(bytes, at, kind);
    put64(bytes, at + 8, offset as u64);
    put64(bytes, at + 16, BASE + offset as u64);
    put64(bytes, at + 32, size as u64);
    put64(bytes, at + 40, size as u64);
}
fn dynamic(bytes: &mut [u8], index: usize, tag: u64, value: u64) {
    put64(bytes, DYNAMIC + index * ENTRY, tag);
    put64(bytes, DYNAMIC + index * ENTRY + 8, value);
}
fn fixture(spare: bool, machine: u16) -> Vec<u8> {
    let mut bytes = vec![0; 2048];
    let magic = b"\x7fELF\x02\x01\x01";
    bytes[..magic.len()].copy_from_slice(magic);
    put16(&mut bytes, 16, 3);
    put16(&mut bytes, 18, machine);
    put32(&mut bytes, 20, 1);
    put64(&mut bytes, 32, HEADERS as u64);
    put16(&mut bytes, 52, 64);
    put16(&mut bytes, 54, PROGRAM as u16);
    put16(&mut bytes, 56, 3);
    let size = bytes.len();
    segment(&mut bytes, 0, 1, 0, size);
    segment(&mut bytes, 1, 2, DYNAMIC, (6 + usize::from(spare)) * ENTRY);
    let interpreter = b"/lib64/ld-linux-x86-64.so.2\0";
    segment(&mut bytes, 2, 3, INTERPRETER, interpreter.len());
    bytes[INTERPRETER..INTERPRETER + interpreter.len()].copy_from_slice(interpreter);
    let strings = b"\0libgcc_s.so.1\0libc.so.6\0";
    bytes[STRINGS..STRINGS + strings.len()].copy_from_slice(strings);
    dynamic(&mut bytes, 0, 5, BASE + STRINGS as u64);
    dynamic(&mut bytes, 1, 10, strings.len() as u64);
    dynamic(&mut bytes, 2, 1, 1);
    dynamic(&mut bytes, 3, 1, 1 + b"libgcc_s.so.1\0".len() as u64);
    dynamic(&mut bytes, 4, 21, 0);
    dynamic(&mut bytes, 5, 0, 0);
    bytes[size - 1] = 0xa5;
    bytes
}

fn inspect(bytes: &[u8], target: &str) -> memcordon_core::elf_closure::ElfDependencies {
    memcordon_core::elf_closure::inspect(
        |at, out| {
            let at = usize::try_from(at).unwrap();
            out.copy_from_slice(&bytes[at..at + out.len()]);
            Ok(())
        },
        bytes.len() as u64,
        target,
    )
    .unwrap()
    .unwrap()
}

fn assert_change(original: &[u8], mutated: &[u8], details: &Value, target: &str) {
    let at = details["offset"].as_u64().unwrap() as usize;
    assert_eq!(original.len(), mutated.len());
    assert_eq!(original[..at], mutated[..at]);
    assert_eq!(original[at + ENTRY..], mutated[at + ENTRY..]);
    assert_eq!(&mutated[at..at + 8], &29u64.to_le_bytes());
    assert_eq!(&mutated[at + 8..at + ENTRY], &1u64.to_le_bytes());
    let before = inspect(original, target);
    let after = inspect(mutated, target);
    assert_eq!(before.interpreter, after.interpreter);
    assert_eq!(before.needed, after.needed);
    assert_eq!(after.needed, ["libgcc_s.so.1", "libc.so.6"]);
    assert!(before.search_paths.is_empty());
    assert_eq!(after.search_paths, ["libgcc_s.so.1"]);
    assert_eq!(
        details["source_sha256"],
        String::from(memcordon_core::hash_bytes(original))
    );
    assert_eq!(
        details["mutated_sha256"],
        String::from(memcordon_core::hash_bytes(mutated))
    );
}

#[test]
fn spare_null_and_single_null_debug_layouts_preserve_every_other_byte_and_dependency() {
    for (machine, target) in [
        (62, "x86_64-unknown-linux-gnu"),
        (183, "aarch64-unknown-linux-gnu"),
    ] {
        for spare in [false, true] {
            for kind in [2, 3] {
                let mut original = fixture(spare, machine);
                put16(&mut original, 16, kind);
                let (mutated, details) = mutate(&original, target).unwrap();
                assert_change(&original, &mutated, &details, target);
                assert_eq!(
                    details["strategy"],
                    if spare { "spare-null" } else { "zero-dt-debug" }
                );
                assert_eq!(details["old_tag"], if spare { 0 } else { 21 });
                assert_eq!(details["old_value"], 0);
                if !spare {
                    assert_eq!(
                        &mutated[DYNAMIC + 5 * ENTRY..DYNAMIC + 6 * ENTRY],
                        &original[DYNAMIC + 5 * ENTRY..DYNAMIC + 6 * ENTRY]
                    );
                }
            }
        }
    }
}

#[test]
fn unsupported_or_ambiguous_slot_never_consumes_the_only_terminator_or_outside_padding() {
    let original = fixture(false, 62);
    for (tag, value) in [(3, 0), (21, 1)] {
        let mut bytes = original.clone();
        dynamic(&mut bytes, 4, tag, value);
        let error = mutate(&bytes, "x86_64-unknown-linux-gnu").unwrap_err();
        assert!(
            error.contains("no supported RPATH mutation slot"),
            "{error}"
        );
        // The zero padding immediately beyond PT_DYNAMIC must not become a slot.
        assert!(
            bytes[DYNAMIC + 6 * ENTRY..DYNAMIC + 7 * ENTRY]
                .iter()
                .all(|byte| *byte == 0)
        );
    }
    let mut duplicate = original.clone();
    dynamic(&mut duplicate, 3, 21, 0);
    assert!(
        mutate(&duplicate, "x86_64-unknown-linux-gnu")
            .unwrap_err()
            .contains("duplicate DT_DEBUG")
    );
    for tag in [15, 29] {
        let mut existing = original.clone();
        dynamic(&mut existing, 4, tag, 1);
        assert!(mutate(&existing, "x86_64-unknown-linux-gnu").is_err());
    }
}

#[test]
fn malformed_header_mapping_dynamic_and_string_extents_fail_without_a_mutation() {
    let original = fixture(false, 62);
    let mut cases = Vec::new();
    for at in [4, 5, 6] {
        let mut bytes = original.clone();
        bytes[at] = 0xff;
        cases.push(bytes);
    }
    for (at, value) in [(16, 1), (18, 183), (52, 63), (54, 55), (56, 0), (56, 513)] {
        let mut bytes = original.clone();
        put16(&mut bytes, at, value);
        cases.push(bytes);
    }
    for (at, value) in [
        (32, u64::MAX),
        (HEADERS + PROGRAM + 8, u64::MAX),
        (HEADERS + PROGRAM + 16, BASE + DYNAMIC as u64 + 1),
        (HEADERS + PROGRAM + 32, 95),
        (HEADERS + PROGRAM + 32, u64::MAX),
        (DYNAMIC + 8, u64::MAX),
        (DYNAMIC + ENTRY + 8, 0),
        (DYNAMIC + ENTRY + 8, u64::MAX),
        (DYNAMIC + 2 * ENTRY + 8, 4096),
    ] {
        let mut bytes = original.clone();
        put64(&mut bytes, at, value);
        cases.push(bytes);
    }
    let mut duplicate = original.clone();
    put16(&mut duplicate, 56, 4);
    segment(&mut duplicate, 3, 2, DYNAMIC, 6 * ENTRY);
    cases.push(duplicate);
    let mut ambiguous = original.clone();
    put16(&mut ambiguous, 56, 4);
    let size = ambiguous.len();
    segment(&mut ambiguous, 3, 1, 0, size);
    cases.push(ambiguous);
    let mut no_end = original.clone();
    dynamic(&mut no_end, 5, 3, 0);
    cases.push(no_end);
    let mut duplicate_strings = original.clone();
    dynamic(&mut duplicate_strings, 1, 5, BASE + STRINGS as u64);
    cases.push(duplicate_strings);
    let mut unterminated = original.clone();
    unterminated[STRINGS + 1..STRINGS + b"\0libgcc_s.so.1\0libc.so.6\0".len()].fill(b'x');
    cases.push(unterminated);
    for prefix in *b"/:$\\" {
        let mut bytes = original.clone();
        bytes[STRINGS + 1] = prefix;
        cases.push(bytes);
    }
    for bytes in cases {
        assert!(mutate(&bytes, "x86_64-unknown-linux-gnu").is_err());
    }
    for length in 0..64 {
        assert!(mutate(&original[..length], "x86_64-unknown-linux-gnu").is_err());
    }
    assert!(mutate(&original, "unsupported-target").is_err());
}
