#![cfg(all(windows, feature = "test-support"))]

use memcordon_platform::{
    test_support::{windows_held_file_metadata, windows_private_fixture as native},
    windows_private_fixture_binding::{
        DotLocalInput, PrivateFixtureAncestor, PrivateFixtureBinding, PrivateFixtureFile,
    },
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
    output_holds: Vec<File>,
}
impl OwnedSetup {
    fn directories(&self) -> native::BorrowedPrivateDirectories<'_> {
        native::BorrowedPrivateDirectories {
            input: &self.holds[1..1 + self.binding.ancestors.len()],
            local: &self.holds[1 + self.binding.ancestors.len()],
            output: &self.output_holds,
        }
    }
}
impl Drop for OwnedSetup {
    fn drop(&mut self) {
        self.holds.clear();
        self.output_holds.clear();
        match &self.binding.local_input {
            DotLocalInput::Directory(directory) => fs::remove_dir_all(&directory.path).unwrap(),
            DotLocalInput::File(marker) => {
                fs::remove_file(&marker.path).unwrap();
                fs::remove_file(&self.paths[2]).unwrap();
            }
        }
    }
}
fn directory(path: &Path) -> (File, PrivateFixtureAncestor) {
    let file = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .unwrap();
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    let mut raw = std::ptr::null_mut();
    // SAFETY: duplicate this owned directory into this process with exact
    // metadata-only rights; returned reference is uniquely adopted below.
    assert_ne!(
        unsafe {
            windows_sys::Win32::Foundation::DuplicateHandle(
                windows_sys::Win32::System::Threading::GetCurrentProcess(),
                file.as_raw_handle(),
                windows_sys::Win32::System::Threading::GetCurrentProcess(),
                &mut raw,
                FILE_READ_ATTRIBUTES,
                0,
                0,
            )
        },
        0
    );
    let file = unsafe { File::from_raw_handle(raw) };
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
fn owned_setup(fixture: PathBuf, output: &Path, cutoff: Instant) -> OwnedSetup {
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
    let mut output_holds = Vec::new();
    let mut output_ancestors = Vec::new();
    for path in output.ancestors().collect::<Vec<_>>().into_iter().rev() {
        let (file, expected) = directory(path);
        output_holds.push(file);
        output_ancestors.push(expected);
    }
    let binding = PrivateFixtureBinding {
        revision: 2,
        fixture: fixture.clone(),
        volume_serial: metadata.volume_serial,
        file_index: metadata.file_index,
        attributes: metadata.attributes,
        links: metadata.links,
        bytes: metadata.length,
        sha256,
        native_path_utf16: native::query_native_name(&holds[0], cutoff).unwrap(),
        ancestors,
        local_input: DotLocalInput::Directory(local_directory),
        output_ancestors,
    };
    let paths = vec![fixture, provider];
    binding.validate(&paths).unwrap();
    binding.validate_output(output).unwrap();
    OwnedSetup {
        binding,
        paths,
        holds,
        output_holds,
    }
}

#[test]
fn actual_main_image_requires_exact_object_content_ancestry_and_separate_output() {
    let cutoff = Instant::now() + Duration::from_secs(30);
    let fixture = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
    let output = tempfile::tempdir().unwrap();
    let mut setup = owned_setup(fixture, output.path(), cutoff);
    let verified = native::verify(
        &setup.binding,
        &setup.paths,
        output.path(),
        setup.directories(),
        cutoff,
    )
    .unwrap();
    assert_eq!(verified.fixture(), setup.binding.fixture.as_path());
    assert_eq!(
        verified.provider_directory(),
        setup.binding.local_input.path()
    );
    assert_eq!(verified.observation()["native_backing_name_join"], true);
    assert_eq!(
        verified.observation()["named_fixture_query_handle_closed"],
        true
    );
    assert_eq!(
        verified.observation()["in_memory_image_byte_integrity_proved"],
        false
    );

    let mut wrong = setup.binding.clone();
    wrong.file_index = wrong.file_index.checked_add(1).unwrap();
    assert!(
        native::verify(
            &wrong,
            &setup.paths,
            output.path(),
            setup.directories(),
            cutoff
        )
        .is_err()
    );
    let mut wrong = setup.binding.clone();
    wrong.bytes = wrong.bytes.checked_add(1).unwrap();
    assert!(
        native::verify(
            &wrong,
            &setup.paths,
            output.path(),
            setup.directories(),
            cutoff
        )
        .is_err()
    );
    let mut wrong = setup.binding.clone();
    let mut hash = wrong.sha256.into_bytes();
    let first = hash.first_mut().unwrap();
    *first = if *first == b'0' { b'1' } else { b'0' };
    wrong.sha256 = String::from_utf8(hash).unwrap();
    assert!(
        native::verify(
            &wrong,
            &setup.paths,
            output.path(),
            setup.directories(),
            cutoff
        )
        .is_err()
    );
    let mut wrong = setup.binding.clone();
    wrong.ancestors.last_mut().unwrap().file_index += 1;
    let refusal = native::verify(
        &wrong,
        &setup.paths,
        output.path(),
        setup.directories(),
        cutoff,
    )
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
    let DotLocalInput::Directory(local) = &mut wrong.local_input else {
        panic!("directory setup changed")
    };
    local.file_index += 1;
    let refusal = native::verify(
        &wrong,
        &setup.paths,
        output.path(),
        setup.directories(),
        cutoff,
    )
    .err()
    .unwrap();
    assert_eq!(
        native::failure_record(&refusal)["progress"]["role"],
        "local-directory"
    );
    let mut wrong = setup.binding.clone();
    let unused_identity = wrong
        .ancestors
        .iter()
        .chain(wrong.output_ancestors.iter())
        .chain(std::iter::once(match &wrong.local_input {
            DotLocalInput::Directory(directory) => directory,
            _ => panic!("directory setup changed"),
        }))
        .map(|ancestor| ancestor.file_index)
        .chain(std::iter::once(wrong.file_index))
        .max()
        .unwrap()
        .checked_add(1)
        .unwrap();
    wrong.output_ancestors.last_mut().unwrap().file_index = unused_identity;
    wrong.validate_output(output.path()).unwrap();
    let refusal = native::verify(
        &wrong,
        &setup.paths,
        output.path(),
        setup.directories(),
        cutoff,
    )
    .err()
    .unwrap();
    assert_eq!(
        native::failure_record(&refusal)["progress"]["role"],
        "output-ancestor"
    );
    assert_eq!(
        native::failure_record(&refusal)["progress"]["substage"],
        "identity-compare"
    );
    // Ordinary File opens may include SYNCHRONIZE. A metadata declaration is
    // insufficient: the actual transferred handle must grant exactly128.
    let extra = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES | 0x0010_0000)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(setup.binding.local_input.path())
        .unwrap();
    let mut directories = setup.directories();
    directories.local = &extra;
    let refusal = native::verify(
        &setup.binding,
        &setup.paths,
        output.path(),
        directories,
        cutoff,
    )
    .err()
    .unwrap();
    let detail = native::failure_record(&refusal);
    assert_eq!(detail["progress"]["role"], "local-directory");
    assert_eq!(detail["progress"]["substage"], "granted-access-compare");
    assert_ne!(
        detail["progress"]["observed_granted_access"],
        FILE_READ_ATTRIBUTES
    );
    drop(extra);
    for change in [0x400, 0x10] {
        let mut wrong = setup.binding.clone();
        wrong.attributes |= change;
        assert!(
            native::verify(
                &wrong,
                &setup.paths,
                output.path(),
                setup.directories(),
                cutoff
            )
            .is_err()
        );
    }
    let mut wrong = setup.binding.clone();
    wrong.links = 2;
    assert!(
        native::verify(
            &wrong,
            &setup.paths,
            output.path(),
            setup.directories(),
            cutoff
        )
        .is_err()
    );
    let mut wrong = setup.binding.clone();
    wrong.native_path_utf16.push(0);
    assert!(
        native::verify(
            &wrong,
            &setup.paths,
            output.path(),
            setup.directories(),
            cutoff
        )
        .is_err()
    );
    assert!(
        native::verify(
            &setup.binding,
            &setup.paths,
            output.path(),
            setup.directories(),
            Instant::now()
        )
        .is_err()
    );
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
    let refusal = native::verify_output(&setup.binding, &alias, setup.directories(), cutoff)
        .err()
        .unwrap();
    assert_eq!(
        native::failure_record(&refusal)["progress"]["role"],
        "output-ancestor"
    );
    assert_eq!(
        native::failure_record(&refusal)["progress"]["substage"],
        "output-path-validation"
    );
    assert!(
        native::verify(
            &setup.binding,
            &setup.paths,
            &alias,
            setup.directories(),
            cutoff
        )
        .is_err()
    );

    let copy_root = tempfile::tempdir().unwrap();
    let copy = copy_root
        .path()
        .join(setup.binding.fixture.file_name().unwrap());
    fs::copy(&setup.binding.fixture, &copy).unwrap();
    let copied = owned_setup(fs::canonicalize(copy).unwrap(), output.path(), cutoff);
    assert_eq!(copied.binding.sha256, setup.binding.sha256);
    assert_ne!(
        (copied.binding.volume_serial, copied.binding.file_index),
        (setup.binding.volume_serial, setup.binding.file_index)
    );
    let refusal = native::verify(
        &copied.binding,
        &copied.paths,
        output.path(),
        copied.directories(),
        cutoff,
    )
    .err()
    .unwrap();
    assert_eq!(
        native::failure_record(&refusal)["phase"],
        "mapping-to-held-native-name"
    );

    // The independent FILE layout uses an actual empty file and a sibling,
    // never a directory witness relabeled as a file. Reuse this test's cutoff.
    assert!(Instant::now() < cutoff);
    let marker_path = setup.binding.local_input.path().to_owned();
    setup.holds.pop();
    fs::remove_dir_all(&marker_path).unwrap();
    drop(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&marker_path)
            .unwrap(),
    );
    let (marker_handle, marker_identity) = directory(&marker_path);
    let metadata = windows_held_file_metadata(&marker_handle).unwrap();
    let marker = PrivateFixtureFile {
        path: marker_path.clone(),
        volume_serial: marker_identity.volume_serial,
        file_index: marker_identity.file_index,
        attributes: metadata.attributes,
        links: metadata.links,
        bytes: metadata.length,
        sha256: Sha256::digest([])
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        native_path_utf16: native::query_native_name(&marker_handle, cutoff).unwrap(),
    };
    setup.holds.push(marker_handle);
    let sibling = setup.binding.fixture.with_extension("provider-input.dat");
    drop(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&sibling)
            .unwrap(),
    );
    setup.binding.revision = 3;
    setup.binding.local_input = DotLocalInput::File(marker.clone());
    setup.paths = vec![setup.binding.fixture.clone(), marker_path, sibling];
    let verified = native::verify(
        &setup.binding,
        &setup.paths,
        output.path(),
        setup.directories(),
        cutoff,
    )
    .unwrap();
    assert_eq!(verified.observation()["local_marker_file_verified"], true);
    assert_eq!(
        verified.provider_directory(),
        setup.binding.fixture.parent().unwrap()
    );
    for change in 0..6 {
        let mut wrong = setup.binding.clone();
        let DotLocalInput::File(marker) = &mut wrong.local_input else {
            unreachable!()
        };
        match change {
            0 => marker.file_index += 1,
            1 => marker.sha256 = "aa".repeat(32),
            2 => marker.bytes = 1,
            3 => marker.links = 2,
            4 => marker.attributes |= 0x10,
            _ => marker.attributes |= 0x400,
        }
        assert!(
            native::verify(
                &wrong,
                &setup.paths,
                output.path(),
                setup.directories(),
                cutoff
            )
            .is_err()
        );
    }
    // A structurally valid foreign marker must still fail the actual object join.
    let mut wrong = setup.binding.clone();
    let absent_index = wrong
        .ancestors
        .iter()
        .chain(&wrong.output_ancestors)
        .map(|item| item.file_index)
        .chain([
            wrong.file_index,
            match &wrong.local_input {
                DotLocalInput::File(marker) => marker.file_index,
                _ => unreachable!(),
            },
        ])
        .max()
        .unwrap()
        .checked_add(1)
        .unwrap();
    let DotLocalInput::File(marker) = &mut wrong.local_input else {
        unreachable!()
    };
    marker.file_index = absent_index;
    wrong.validate(&setup.paths).unwrap();
    let refusal = native::verify(
        &wrong,
        &setup.paths,
        output.path(),
        setup.directories(),
        cutoff,
    )
    .err()
    .unwrap();
    assert_eq!(
        native::failure_record(&refusal)["progress"]["substage"],
        "marker-identity-compare"
    );
    let extra = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(setup.binding.local_input.path())
        .unwrap();
    let mut refs = setup.directories();
    refs.local = &extra;
    assert!(native::verify(&setup.binding, &setup.paths, output.path(), refs, cutoff).is_err());
    drop(extra);
}
