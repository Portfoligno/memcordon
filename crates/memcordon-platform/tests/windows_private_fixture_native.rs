#![cfg(all(windows, feature = "test-support"))]

use memcordon_platform::{
    test_support::{windows_held_file_metadata, windows_private_fixture as native},
    windows_private_fixture_binding::{PrivateFixtureAncestor, PrivateFixtureBinding},
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::windows::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    FILE_SHARE_READ, FILE_SHARE_WRITE,
};

struct OwnedSetup {
    binding: PrivateFixtureBinding,
    paths: Vec<PathBuf>,
    holds: Vec<File>,
}
impl Drop for OwnedSetup {
    fn drop(&mut self) {
        self.holds.clear();
        fs::remove_dir_all(&self.binding.local_directory.path).unwrap();
    }
}
fn directory(path: &Path) -> (File, PrivateFixtureAncestor) {
    let file = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .unwrap();
    let metadata = windows_held_file_metadata(&file).unwrap();
    (
        file,
        PrivateFixtureAncestor {
            path: path.to_owned(),
            volume_serial: metadata.volume_serial,
            file_index: metadata.file_index,
            attributes: metadata.attributes,
        },
    )
}
fn owned_setup(fixture: PathBuf, cutoff: Instant) -> OwnedSetup {
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&fixture)
        .unwrap();
    let metadata = windows_held_file_metadata(&file).unwrap();
    assert_eq!(
        metadata.links, 1,
        "native fixture setup requires an independent regular image"
    );
    let mut bytes = Vec::new();
    (&file).read_to_end(&mut bytes).unwrap();
    let sha256 = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let mut holds = vec![file];
    let mut ancestors = Vec::new();
    for path in fixture
        .parent()
        .unwrap()
        .ancestors()
        .filter(|path| !path.as_os_str().is_empty())
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        let (file, ancestor) = directory(path);
        holds.push(file);
        ancestors.push(ancestor);
    }
    let mut name = fixture.file_name().unwrap().to_os_string();
    name.push(".local");
    let local = fixture.parent().unwrap().join(name);
    // Do not adopt or remove any preexisting test/user namespace.
    fs::create_dir(&local).unwrap();
    let provider = local.join("provider-input.dat");
    fs::write(&provider, b"owned regular mutation-target fixture").unwrap();
    let (local_file, local_directory) = directory(&local);
    holds.push(local_file);
    let binding = PrivateFixtureBinding {
        revision: 1,
        fixture: fixture.clone(),
        volume_serial: metadata.volume_serial,
        file_index: metadata.file_index,
        attributes: metadata.attributes,
        links: metadata.links,
        bytes: metadata.length,
        sha256,
        native_path_utf16: native::query_native_name(&holds[0], cutoff).unwrap(),
        ancestors,
        local_directory,
    };
    let paths = vec![fixture, provider];
    binding.validate(&paths).unwrap();
    OwnedSetup {
        binding,
        paths,
        holds,
    }
}

#[test]
fn actual_main_image_requires_exact_object_content_ancestry_and_separate_output() {
    let cutoff = Instant::now() + Duration::from_secs(30);
    let fixture = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
    let setup = owned_setup(fixture, cutoff);
    let output = tempfile::tempdir().unwrap();
    let verified = native::verify(&setup.binding, &setup.paths, output.path(), cutoff).unwrap();
    assert_eq!(verified.fixture(), setup.binding.fixture.as_path());
    assert_eq!(
        verified.local_directory(),
        setup.binding.local_directory.path.as_path()
    );
    assert_eq!(verified.observation()["native_backing_name_join"], true);
    assert_eq!(
        verified.observation()["temporary_query_handles_closed"],
        true
    );
    assert_eq!(
        verified.observation()["in_memory_image_byte_integrity_proved"],
        false
    );

    let mut wrong = setup.binding.clone();
    wrong.file_index = wrong.file_index.checked_add(1).unwrap();
    assert!(native::verify(&wrong, &setup.paths, output.path(), cutoff).is_err());
    let mut wrong = setup.binding.clone();
    wrong.bytes = wrong.bytes.checked_add(1).unwrap();
    assert!(native::verify(&wrong, &setup.paths, output.path(), cutoff).is_err());
    let mut wrong = setup.binding.clone();
    let mut hash = wrong.sha256.into_bytes();
    let first = hash.first_mut().unwrap();
    *first = if *first == b'0' { b'1' } else { b'0' };
    wrong.sha256 = String::from_utf8(hash).unwrap();
    assert!(native::verify(&wrong, &setup.paths, output.path(), cutoff).is_err());
    let mut wrong = setup.binding.clone();
    wrong.ancestors.last_mut().unwrap().file_index += 1;
    let refusal = native::verify(&wrong, &setup.paths, output.path(), cutoff)
        .err()
        .unwrap();
    let detail = native::failure_record(&refusal);
    assert_eq!(detail["progress"]["role"], "input-ancestor");
    assert_eq!(detail["progress"]["index"], wrong.ancestors.len() - 1);
    assert_eq!(detail["progress"]["count"], wrong.ancestors.len());
    assert_eq!(detail["progress"]["substage"], "identity-compare");
    assert_eq!(
        detail["progress"]["requested_win32_mask"],
        windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES
    );
    assert_eq!(detail["progress"]["cutoff_before"], true);
    assert!(detail["progress"]["cutoff_after"].is_null());
    assert!(detail["native_code"].is_null());
    let mut wrong = setup.binding.clone();
    wrong.local_directory.file_index += 1;
    let refusal = native::verify(&wrong, &setup.paths, output.path(), cutoff)
        .err()
        .unwrap();
    assert_eq!(
        native::failure_record(&refusal)["progress"]["role"],
        "local-directory"
    );
    for change in [0x400, 0x10] {
        let mut wrong = setup.binding.clone();
        wrong.attributes |= change;
        assert!(native::verify(&wrong, &setup.paths, output.path(), cutoff).is_err());
    }
    let mut wrong = setup.binding.clone();
    wrong.links = 2;
    assert!(native::verify(&wrong, &setup.paths, output.path(), cutoff).is_err());
    let mut wrong = setup.binding.clone();
    wrong.native_path_utf16.push(0);
    assert!(native::verify(&wrong, &setup.paths, output.path(), cutoff).is_err());
    assert!(native::verify(&setup.binding, &setup.paths, output.path(), Instant::now()).is_err());
    let parent = setup.binding.fixture.parent().unwrap();
    let alias = PathBuf::from(parent.as_os_str().to_string_lossy().to_uppercase());
    // Establish the alias as a native object fact before testing rejection.
    let (_, alias_metadata) = directory(&alias);
    assert_eq!(
        alias_metadata.volume_serial,
        setup.binding.ancestors.last().unwrap().volume_serial
    );
    assert_eq!(
        alias_metadata.file_index,
        setup.binding.ancestors.last().unwrap().file_index
    );
    let refusal = native::verify_output(&setup.binding, &alias, cutoff)
        .err()
        .unwrap();
    assert_eq!(
        native::failure_record(&refusal)["progress"]["role"],
        "output-ancestor"
    );
    assert_eq!(
        native::failure_record(&refusal)["progress"]["substage"],
        "output-alias-compare"
    );
    assert!(native::verify(&setup.binding, &setup.paths, &alias, cutoff).is_err());

    let copy_root = tempfile::tempdir().unwrap();
    let copy = copy_root
        .path()
        .join(setup.binding.fixture.file_name().unwrap());
    fs::copy(&setup.binding.fixture, &copy).unwrap();
    let copied = owned_setup(fs::canonicalize(copy).unwrap(), cutoff);
    assert_eq!(copied.binding.sha256, setup.binding.sha256);
    assert_ne!(
        (copied.binding.volume_serial, copied.binding.file_index),
        (setup.binding.volume_serial, setup.binding.file_index)
    );
    let refusal = native::verify(&copied.binding, &copied.paths, output.path(), cutoff)
        .err()
        .unwrap();
    assert_eq!(
        native::failure_record(&refusal)["phase"],
        "mapping-to-held-native-name"
    );
}
