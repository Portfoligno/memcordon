#[path = "../src/release/linux_elf_patch.rs"]
mod patch;

use patch::Stage;
use sha2::{Digest, Sha256};
use std::{
    cell::{Cell, RefCell},
    io,
    time::{Duration, Instant},
};

const BASE: u64 = 0x400000;
const PHOFF: usize = 64;
const STRIDE: usize = 56;
const DYNAMIC: usize = 256;
const NEEDED_TAG: usize = DYNAMIC + 2 * 16;

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + std::mem::size_of_val(&value)].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + std::mem::size_of_val(&value)].copy_from_slice(&value.to_le_bytes());
}
fn segment(bytes: &mut [u8], ordinal: usize, kind: u32, offset: u64, size: u64) {
    let at = PHOFF + ordinal * STRIDE;
    bytes[at..at + std::mem::size_of_val(&kind)].copy_from_slice(&kind.to_le_bytes());
    put64(bytes, at + 8, offset);
    put64(bytes, at + 16, BASE + offset);
    put64(bytes, at + 32, size);
    put64(bytes, at + 40, size);
}
fn fixture(length: usize, strings: usize) -> Vec<u8> {
    let mut bytes = vec![0; length];
    let magic = b"\x7fELF\x02\x01\x01";
    bytes[..magic.len()].copy_from_slice(magic);
    put16(&mut bytes, 52, PHOFF as u16);
    put16(&mut bytes, 54, STRIDE as u16);
    put16(&mut bytes, 56, 2);
    put64(&mut bytes, 32, PHOFF as u64);
    segment(&mut bytes, 0, 1, 0, length as u64);
    segment(&mut bytes, 1, 2, DYNAMIC as u64, 4 * 16);
    put64(&mut bytes, DYNAMIC, 5);
    put64(&mut bytes, DYNAMIC + 8, BASE + strings as u64);
    put64(&mut bytes, DYNAMIC + 16, 10);
    put64(&mut bytes, DYNAMIC + 24, 256);
    put64(&mut bytes, NEEDED_TAG, 1);
    put64(&mut bytes, NEEDED_TAG + 8, 1);
    let name = b"libfixture.so\0";
    bytes[strings + 1..strings + 1 + name.len()].copy_from_slice(name);
    bytes[length - 1] = 0x7d;
    bytes
}
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn read(bytes: &[u8], offset: u64, output: &mut [u8]) -> io::Result<usize> {
    let offset = usize::try_from(offset).map_err(|_| io::ErrorKind::InvalidInput)?;
    let available = bytes.get(offset..).ok_or(io::ErrorKind::UnexpectedEof)?;
    let count = available.len().min(output.len());
    output[..count].copy_from_slice(&available[..count]);
    Ok(count)
}
fn expected(mut bytes: Vec<u8>, strings: usize) -> Vec<u8> {
    put64(&mut bytes, NEEDED_TAG, 15);
    let replacement = b"/work\0";
    bytes[strings + 1..strings + 1 + replacement.len()].copy_from_slice(replacement);
    bytes
}

#[test]
fn real_plan_and_dual_hash_change_only_two_extents_even_across_stream_boundary() {
    for (length, strings) in [(4096, 1024), (128 * 1024, 64 * 1024 - 4)] {
        let original = fixture(length, strings);
        let data = RefCell::new(original.clone());
        let stages = RefCell::new(Vec::new());
        let max_read = Cell::new(0);
        let plan = patch::plan(length as u64, deadline(), |at, out| {
            read(&original, at, out)
        })
        .unwrap();
        assert_eq!(plan.patches().len(), 2);
        assert_eq!(plan.patches()[0].offset(), NEEDED_TAG as u64);
        assert_eq!(plan.patches()[0].before(), &1u64.to_le_bytes());
        assert_eq!(plan.patches()[1].offset(), strings as u64 + 1);
        let actual = patch::mutate(
            length as u64,
            &sha(&original),
            deadline(),
            |at, out| {
                max_read.set(max_read.get().max(out.len()));
                read(&data.borrow(), at, out)
            },
            |at, bytes| {
                let at = at as usize;
                data.borrow_mut()[at..at + bytes.len()].copy_from_slice(bytes);
                Ok(())
            },
            || Ok(()),
            |stage| {
                stages.borrow_mut().push(stage);
                Ok(())
            },
        )
        .unwrap();
        let expected = expected(original.clone(), strings);
        assert_eq!(*data.borrow(), expected);
        assert_eq!(data.borrow().len(), original.len());
        assert_eq!(actual, sha(&expected));
        assert!(max_read.get() <= 64 * 1024);
        assert_eq!(
            *stages.borrow(),
            [
                Stage::BeforeOriginal,
                Stage::AfterOriginal,
                Stage::BeforeWrites,
                Stage::AfterWrites,
                Stage::AfterFinal
            ]
        );
    }
}

#[test]
fn malformed_ranges_and_ambiguous_structure_fail_before_any_write() {
    let original = fixture(8192, 1024);
    let mut cases = Vec::new();
    for at in [4, 5, 6] {
        let mut value = original.clone();
        value[at] = 0xff;
        cases.push(value);
    }
    for (at, value) in [
        (32, u64::MAX),
        (PHOFF + 8, u64::MAX),
        (DYNAMIC + 8, u64::MAX),
        (DYNAMIC + 24, u64::MAX),
        (NEEDED_TAG + 8, 256),
    ] {
        let mut bytes = original.clone();
        put64(&mut bytes, at, value);
        cases.push(bytes);
    }
    for (at, value) in [(54, 55), (56, 257), (52, 0)] {
        let mut bytes = original.clone();
        put16(&mut bytes, at, value);
        cases.push(bytes);
    }
    let mut odd = original.clone();
    put64(&mut odd, PHOFF + STRIDE + 32, 63);
    cases.push(odd);
    let mut huge = original.clone();
    put64(&mut huge, PHOFF + STRIDE + 32, 1024 * 1024 + 16);
    cases.push(huge);
    let mut short = original.clone();
    short[1025..1027].copy_from_slice(b"a\0");
    cases.push(short);
    let mut no_nul = original.clone();
    no_nul[1025..1280].fill(b'x');
    cases.push(no_nul);
    let mut too_long = original.clone();
    put64(&mut too_long, DYNAMIC + 24, 6000);
    too_long[1025..1025 + 4097].fill(b'x');
    cases.push(too_long);
    let mut unbacked = original.clone();
    put64(&mut unbacked, PHOFF + 32, 1026);
    cases.push(unbacked);
    let mut ambiguous = original.clone();
    put16(&mut ambiguous, 56, 3);
    segment(&mut ambiguous, 2, 1, 0, original.len() as u64);
    cases.push(ambiguous);
    let mut duplicate_dynamic = original.clone();
    put16(&mut duplicate_dynamic, 56, 3);
    segment(&mut duplicate_dynamic, 2, 2, DYNAMIC as u64, 4 * 16);
    cases.push(duplicate_dynamic);
    let mut duplicate_string = original.clone();
    put64(&mut duplicate_string, DYNAMIC + 16, 5);
    cases.push(duplicate_string);
    let mut no_end = original.clone();
    put64(&mut no_end, DYNAMIC + 3 * 16, 1);
    cases.push(no_end);
    let mut overlap = original.clone();
    put64(&mut overlap, DYNAMIC + 8, BASE + NEEDED_TAG as u64);
    put64(&mut overlap, NEEDED_TAG + 8, 0);
    cases.push(overlap);
    for bytes in cases {
        let writes = Cell::new(0);
        assert!(
            patch::mutate(
                bytes.len() as u64,
                &sha(&bytes),
                deadline(),
                |at, out| read(&bytes, at, out),
                |_, _| {
                    writes.set(writes.get() + 1);
                    Ok(())
                },
                || Ok(()),
                |_| Ok(())
            )
            .is_err()
        );
        assert_eq!(writes.get(), 0);
    }
    for length in 0..64 {
        assert!(
            patch::plan(length, deadline(), |at, out| read(
                &original[..length as usize],
                at,
                out
            ))
            .is_err()
        );
    }
}

#[test]
fn manifest_hash_length_and_preimage_mismatch_never_authorize_writes() {
    let original = fixture(4096, 1024);
    for (length, digest) in [
        (original.len() as u64, sha(b"different manifest")),
        (original.len() as u64 - 1, sha(&original)),
        (original.len() as u64 + 1, sha(&original)),
    ] {
        assert!(
            patch::mutate(
                length,
                &digest,
                deadline(),
                |at, out| read(&original, at, out),
                |_, _| panic!("mismatched manifest must not write"),
                || Ok(()),
                |_| Ok(())
            )
            .is_err()
        );
    }
    let data = RefCell::new(original.clone());
    let error = patch::mutate(
        original.len() as u64,
        &sha(&original),
        deadline(),
        |at, out| read(&data.borrow(), at, out),
        |_, _| panic!("changed preimage must not write"),
        || Ok(()),
        |stage| {
            if stage == Stage::AfterOriginal {
                data.borrow_mut()[NEEDED_TAG] = 42;
            }
            Ok(())
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("preimage"));
}

#[test]
fn short_reads_partial_writes_and_postwrite_changes_remain_explicit_failures() {
    let original = fixture(4096, 1024);
    let data = RefCell::new(original.clone());
    let result = patch::mutate(
        original.len() as u64,
        &sha(&original),
        deadline(),
        |at, out| {
            let amount = out.len().min(3);
            read(&data.borrow(), at, &mut out[..amount])
        },
        |at, bytes| {
            let at = at as usize;
            data.borrow_mut()[at..at + bytes.len()].copy_from_slice(bytes);
            Ok(())
        },
        || Ok(()),
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(result, sha(&expected(original.clone(), 1024)));

    let data = RefCell::new(original.clone());
    let writes = Cell::new(0);
    let error = patch::mutate(
        original.len() as u64,
        &sha(&original),
        deadline(),
        |at, out| read(&data.borrow(), at, out),
        |at, bytes| {
            writes.set(writes.get() + 1);
            let at = at as usize;
            if writes.get() == 2 {
                data.borrow_mut()[at] = bytes[0];
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "injected partial second patch",
                ));
            }
            data.borrow_mut()[at..at + bytes.len()].copy_from_slice(bytes);
            Ok(())
        },
        || Ok(()),
        |_| Ok(()),
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WriteZero);
    assert_eq!(writes.get(), 2);
    assert_eq!(
        &data.borrow()[NEEDED_TAG..NEEDED_TAG + 8],
        &15u64.to_le_bytes()
    );
    assert_eq!(data.borrow()[1025], b'/');
    assert_eq!(&data.borrow()[1026..1031], &original[1026..1031]);

    let data = RefCell::new(original.clone());
    let error = patch::mutate(
        original.len() as u64,
        &sha(&original),
        deadline(),
        |at, out| read(&data.borrow(), at, out),
        |at, bytes| {
            let at = at as usize;
            data.borrow_mut()[at..at + bytes.len()].copy_from_slice(bytes);
            Ok(())
        },
        || Ok(()),
        |stage| {
            if stage == Stage::AfterWrites {
                data.borrow_mut()[3500] ^= 1;
            }
            Ok(())
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("full patched digest"));
}

#[test]
fn original_deadline_and_guard_refusals_cannot_become_mutation_success() {
    let original = fixture(4096, 1024);
    let error = patch::mutate(
        original.len() as u64,
        &sha(&original),
        Instant::now(),
        |_, _| panic!("expired operation must not read"),
        |_, _| panic!("expired operation must not write"),
        || panic!("expired operation must not sync"),
        |_| panic!("expired operation must not refresh guards"),
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    for denied in [
        Stage::BeforeOriginal,
        Stage::AfterOriginal,
        Stage::BeforeWrites,
        Stage::AfterWrites,
        Stage::AfterFinal,
    ] {
        let data = RefCell::new(original.clone());
        let writes = Cell::new(0);
        let error = patch::mutate(
            original.len() as u64,
            &sha(&original),
            deadline(),
            |at, out| read(&data.borrow(), at, out),
            |at, bytes| {
                writes.set(writes.get() + 1);
                let at = at as usize;
                data.borrow_mut()[at..at + bytes.len()].copy_from_slice(bytes);
                Ok(())
            },
            || Ok(()),
            |stage| {
                if stage == denied {
                    Err(io::ErrorKind::TimedOut.into())
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            writes.get(),
            if matches!(denied, Stage::AfterWrites | Stage::AfterFinal) {
                2
            } else {
                0
            }
        );
    }
}

#[cfg(unix)]
#[test]
#[ignore = "full sparse image hashing belongs to native CI, not local lightweight gates"]
fn sparse_image_larger_than_old_buffer_bound_is_mutated_on_same_held_inode() {
    use std::{
        fs::OpenOptions,
        os::unix::fs::{FileExt, MetadataExt},
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct OwnedPath(std::path::PathBuf);
    impl Drop for OwnedPath {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let path = std::env::temp_dir().join(format!(
        "memcordon-elf-patch-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    let path = OwnedPath(path);
    let length = 64 * 1024 * 1024 + 1;
    let small = fixture(4096, 1024);
    file.set_len(length).unwrap();
    file.write_all_at(&small, 0).unwrap();
    let sentinel = b"distant-original-suffix";
    file.write_all_at(sentinel, length - sentinel.len() as u64)
        .unwrap();
    file.sync_all().unwrap();
    let original_id = (
        file.metadata().unwrap().dev(),
        file.metadata().unwrap().ino(),
    );
    let hash_file = || {
        let mut hasher = Sha256::new();
        let mut buffer = [0; 64 * 1024];
        let mut at = 0;
        loop {
            let count = file.read_at(&mut buffer, at).unwrap();
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
            at += count as u64;
        }
        assert_eq!(at, length);
        hex::encode(hasher.finalize())
    };
    let original = hash_file();
    let cutoff = Instant::now() + Duration::from_secs(60);
    let result = patch::mutate(
        length,
        &original,
        cutoff,
        |at, out| file.read_at(out, at),
        |at, bytes| file.write_all_at(bytes, at),
        || file.sync_all(),
        |_| {
            let held = file.metadata()?;
            let named = std::fs::metadata(&path.0)?;
            if (held.dev(), held.ino()) != original_id
                || (named.dev(), named.ino()) != original_id
                || held.len() != length
                || held.nlink() != 1
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(result, hash_file());
    assert_ne!(result, original);
    let mut tag = [0; 8];
    file.read_exact_at(&mut tag, NEEDED_TAG as u64).unwrap();
    assert_eq!(tag, 15u64.to_le_bytes());
    let mut path_bytes = [0; b"/work\0".len()];
    file.read_exact_at(&mut path_bytes, 1025).unwrap();
    assert_eq!(&path_bytes, b"/work\0");
    let mut distant = vec![0; sentinel.len()];
    file.read_exact_at(&mut distant, length - sentinel.len() as u64)
        .unwrap();
    assert_eq!(distant, sentinel);
}
