#![cfg(windows)]

use memcordon_ci::windows_native_files::{
    copy_compiler_artifact, hold_artifact, verify_named_artifact,
};
use std::{fs, os::windows::io::AsRawHandle, path::Path};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
};

fn identity(path: &Path) -> (u32, u64, u32) {
    let file = fs::File::open(path).unwrap();
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    assert_ne!(
        unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut info) },
        0
    );
    (
        info.dwVolumeSerialNumber,
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        info.nNumberOfLinks,
    )
}

#[test]
fn workload_preparation_materializes_cargo_alias_into_independent_held_executable() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path().canonicalize().unwrap();
    let build = root.join("build");
    let release = build.join("release");
    let reports = root.join("reports");
    fs::create_dir_all(&release).unwrap();
    fs::create_dir(&reports).unwrap();
    let source = release.join("memcordon-windows-loader-lab.exe");
    let alias = release.join("cargo-output-alias.exe");
    let bytes = b"actual measured compiler-style artifact bytes";
    fs::write(&source, bytes).unwrap();
    fs::hard_link(&source, &alias).unwrap();
    let before = identity(&source);
    assert_eq!(before.2, 2);
    assert_eq!(identity(&alias), before);
    assert!(hold_artifact(&source, None, 128 * 1024 * 1024).is_err());

    let executable = reports.join("result.exe");
    let expected = memcordon_ci::windows_causal_acceptance::sha256(bytes);
    let wrong_report = reports.join("wrong-source.exe");
    let foreign_digest = memcordon_ci::windows_causal_acceptance::sha256(b"foreign bytes");
    assert!(copy_compiler_artifact(&source, &build, &wrong_report, &foreign_digest).is_err());
    assert!(!wrong_report.exists());
    let held = copy_compiler_artifact(&source, &build, &executable, &expected).unwrap();
    assert!(!executable.starts_with(&build));
    assert_eq!(executable.parent(), Some(reports.as_path()));
    let copied = identity(&executable);
    assert_eq!(copied.2, 1);
    assert_ne!((copied.0, copied.1), (before.0, before.1));
    assert_eq!(held.bytes, bytes);
    assert_eq!(
        held.sha256,
        memcordon_ci::windows_causal_acceptance::sha256(bytes)
    );
    verify_named_artifact(&held, &executable).unwrap();
    assert_eq!(identity(&source), before);
    assert_eq!(identity(&alias), before);
    assert_eq!(fs::read(&source).unwrap(), bytes);
    assert_eq!(fs::read(&alias).unwrap(), bytes);
    assert!(hold_artifact(&source, None, 128 * 1024 * 1024).is_err());

    assert!(copy_compiler_artifact(&source, &build, &executable, &expected).is_err());
    verify_named_artifact(&held, &executable).unwrap();
    let wrong = reports.join("wrong-digest.exe");
    let foreign_digest = memcordon_ci::windows_causal_acceptance::sha256(b"foreign bytes");
    assert!(copy_compiler_artifact(&source, &build, &wrong, &foreign_digest).is_err());
    assert!(!wrong.exists());
    assert_eq!(identity(&source), before);
    assert_eq!(identity(&alias), before);
}

#[test]
fn oversized_compiler_output_is_rejected_before_publication() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path().canonicalize().unwrap();
    let build = root.join("build");
    let release = build.join("release");
    let reports = root.join("reports");
    fs::create_dir_all(&release).unwrap();
    fs::create_dir(&reports).unwrap();
    let source = release.join("memcordon-windows-loader-lab.exe");
    let file = fs::File::create(&source).unwrap();
    let oversized = 512 * 1024 * 1024 + 1;
    file.set_len(oversized).unwrap();
    assert_eq!(file.metadata().unwrap().len(), oversized);
    drop(file);
    let report = reports.join("result.exe");
    let expected = memcordon_ci::windows_causal_acceptance::sha256(b"selected bounded source");
    assert!(copy_compiler_artifact(&source, &build, &report, &expected).is_err());
    assert!(!report.exists());
    assert_eq!(fs::metadata(&source).unwrap().len(), oversized);
}
