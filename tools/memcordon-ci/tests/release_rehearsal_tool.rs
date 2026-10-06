use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Cursor,
};

use memcordon_ci::release::{rehearsal_tool, target};

fn image() -> Vec<u8> {
    let mut elf = vec![0; 64];
    elf[..b"\x7fELF".len()].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[18] = 62;
    elf
}

fn directory() -> tempfile::TempDir {
    if cfg!(unix) {
        tempfile::tempdir_in("/tmp").unwrap()
    } else {
        tempfile::tempdir().unwrap()
    }
}

#[test]
fn helper_archive_is_separate_deterministic_executable_and_requires_fresh_output() {
    let temporary = directory();
    let source = temporary.path().join(rehearsal_tool::EXECUTABLE);
    fs::write(&source, image()).unwrap();
    let first = temporary.path().join("first");
    let second = temporary.path().join("second");
    rehearsal_tool::package_file(&source, &first).unwrap();
    rehearsal_tool::package_file(&source, &second).unwrap();
    let bytes = fs::read(first.join(rehearsal_tool::ARCHIVE)).unwrap();
    assert_eq!(
        bytes,
        fs::read(second.join(rehearsal_tool::ARCHIVE)).unwrap()
    );
    assert_eq!(fs::read_dir(&first).unwrap().count(), 1);
    let inventory = target::decode_archive(&bytes, "x86_64-unknown-linux-gnu").unwrap();
    assert_eq!(
        inventory,
        BTreeMap::from([(rehearsal_tool::EXECUTABLE.into(), image())])
    );
    assert!(rehearsal_tool::package_file(&source, &first).is_err());
    fs::write(&source, b"not an executable\n").unwrap();
    let invalid = temporary.path().join("invalid");
    assert!(rehearsal_tool::package_file(&source, &invalid).is_err());
    assert!(!invalid.exists());
    let mut wrong_architecture = image();
    wrong_architecture[18] = 183;
    fs::write(&source, wrong_architecture).unwrap();
    assert!(rehearsal_tool::package_file(&source, &invalid).is_err());
    let oversized = fs::File::create(&source).unwrap();
    oversized
        .set_len(memcordon_ci::release::artifacts::MAX_FILE_BYTES + 1)
        .unwrap();
    assert!(rehearsal_tool::package_file(&source, &invalid).is_err());
    assert!(!invalid.exists());
}

#[test]
fn helper_archive_rejects_wrong_mode_extra_duplicate_symlink_and_streams() {
    let target = "x86_64-unknown-linux-gnu";
    let members = BTreeMap::from([(rehearsal_tool::EXECUTABLE.into(), image())]);
    let names = BTreeSet::from([rehearsal_tool::EXECUTABLE.into()]);
    let valid = target::encode_archive(target, &members, &names).unwrap();
    rehearsal_tool::validate_archive(&valid).unwrap();
    let wrong_mode = target::encode_archive(target, &members, &BTreeSet::new()).unwrap();
    assert!(rehearsal_tool::validate_archive(&wrong_mode).is_err());
    let mut extra = members.clone();
    extra.insert("memcordon-ci".into(), image());
    assert!(
        rehearsal_tool::validate_archive(&target::encode_archive(target, &extra, &names).unwrap())
            .is_err()
    );
    let mut trailing = valid.clone();
    trailing.extend_from_slice(b"unexpected");
    assert!(rehearsal_tool::validate_archive(&trailing).is_err());
    assert!(rehearsal_tool::validate_archive(&valid[..valid.len() / 2]).is_err());
    for symlink in [false, true] {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        for _ in 0..if symlink { 1 } else { 2 } {
            let body = if symlink { Vec::new() } else { image() };
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o755);
            if symlink {
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_link_name("outside").unwrap();
            }
            header.set_cksum();
            archive
                .append_data(&mut header, rehearsal_tool::EXECUTABLE, Cursor::new(body))
                .unwrap();
        }
        let bytes = archive.into_inner().unwrap().finish().unwrap();
        assert!(rehearsal_tool::validate_archive(&bytes).is_err());
    }
}

#[cfg(unix)]
#[test]
fn sibling_image_symlinks_are_rejected_without_creating_output() {
    let temporary = directory();
    let original = temporary.path().join("image");
    let link = temporary.path().join("link");
    fs::write(&original, image()).unwrap();
    std::os::unix::fs::symlink(&original, &link).unwrap();
    let output = temporary.path().join("output");
    assert!(rehearsal_tool::package_file(&link, &output).is_err());
    assert!(!output.exists());
}
