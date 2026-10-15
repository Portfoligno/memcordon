use memcordon_ci::cache_restore::{self, RestoreMode};
use std::{fs, path::Path};

fn seed(root: &Path, relative: &str) {
    let target = root.join(relative);
    fs::create_dir_all(&target).unwrap();
    fs::write(target.join("stale-product"), b"restored bytes").unwrap();
}

fn preserve(root: &Path) -> Vec<(&'static str, Vec<u8>)> {
    [
        "target/ci/miri-second/stale-product",
        "target/ci/release/driver",
        "target/ci/reports/current",
        ".release/prepared/current",
    ]
    .into_iter()
    .map(|relative| {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let bytes = relative.as_bytes().to_vec();
        fs::write(path, &bytes).unwrap();
        (relative, bytes)
    })
    .collect()
}

fn unchanged(root: &Path, originals: &[(&str, Vec<u8>)]) {
    for (relative, bytes) in originals {
        assert_eq!(&fs::read(root.join(relative)).unwrap(), bytes);
    }
}

#[test]
fn missing_and_invalid_miri_markers_discard_only_the_selected_seed() {
    for mode in [RestoreMode::Exact, RestoreMode::Compatible] {
        for marker in [None, Some(b"invalid marker".as_slice())] {
            let fixture = tempfile::tempdir().unwrap();
            let root = fixture.path();
            seed(root, "target/ci/miri-first");
            let originals = preserve(root);
            if let Some(bytes) = marker {
                fs::write(root.join("target/ci/miri-first/CACHEDIR.TAG"), bytes).unwrap();
            }
            // No workspace or toolchain configuration exists: cold disposal
            // must not invoke Cargo or manufacture authority for its guard.
            cache_restore::prepare(root, "miri", "first", mode).unwrap();
            assert!(!root.join("target/ci/miri-first").exists());
            assert!(!root.join("target/CACHEDIR.TAG").exists());
            unchanged(root, &originals);
        }
    }
}

#[test]
fn multi_root_and_auxiliary_fallbacks_remain_finite() {
    for mode in [RestoreMode::Exact, RestoreMode::Compatible] {
        for (purpose, selected) in [
            ("quality", ["target/ci/quality", "target/ci/quality-doc"]),
            ("native-auxiliary", ["target/debug", "target/release"]),
        ] {
            let fixture = tempfile::tempdir().unwrap();
            let root = fixture.path();
            for relative in selected {
                seed(root, relative);
            }
            let originals = preserve(root);
            cache_restore::prepare(root, purpose, "complete", mode).unwrap();
            for relative in selected {
                assert!(!root.join(relative).exists());
            }
            assert!(root.join("target").is_dir());
            assert!(!root.join("target/CACHEDIR.TAG").exists());
            unchanged(root, &originals);
        }
    }
}

#[cfg(unix)]
#[test]
fn missing_marker_cannot_authorize_disposal_of_an_active_writer() {
    for mode in [RestoreMode::Exact, RestoreMode::Compatible] {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path();
        seed(root, "target/ci/miri-first");
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(root.join("target/ci/miri-first/.cargo-lock"))
            .unwrap();
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
        assert!(cache_restore::prepare(root, "miri", "first", mode).is_err());
        assert_eq!(
            fs::read(root.join("target/ci/miri-first/stale-product")).unwrap(),
            b"restored bytes"
        );
    }
}

#[cfg(unix)]
#[test]
fn every_root_and_marker_kind_is_validated_before_cold_disposal() {
    use std::os::unix::fs::symlink;
    for mode in [RestoreMode::Exact, RestoreMode::Compatible] {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path();
        seed(root, "target/ci/quality");
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), root.join("target/ci/quality-doc")).unwrap();
        assert!(cache_restore::prepare(root, "quality", "complete", mode).is_err());
        assert!(root.join("target/ci/quality/stale-product").exists());

        seed(root, "target/ci/miri-first");
        let external_marker = outside.path().join("marker");
        fs::write(&external_marker, b"external bytes").unwrap();
        symlink(
            &external_marker,
            root.join("target/ci/miri-first/CACHEDIR.TAG"),
        )
        .unwrap();
        assert!(cache_restore::prepare(root, "miri", "first", mode).is_err());
        assert!(root.join("target/ci/miri-first/stale-product").exists());
        assert_eq!(fs::read(external_marker).unwrap(), b"external bytes");
    }
}

#[cfg(unix)]
#[test]
fn auxiliary_parent_fifo_is_refused_without_blocking() {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command.args([
        "--exact",
        "auxiliary_fifo_helper",
        "--ignored",
        "--nocapture",
    ]);
    let output =
        memcordon_testkit::run_with_deadline(&mut command, std::time::Duration::from_secs(5))
            .unwrap();
    assert!(output.status.success(), "{output:?}");
}

#[cfg(unix)]
#[test]
#[ignore = "isolated bounded auxiliary marker-kind fixture"]
fn auxiliary_fifo_helper() {
    use std::os::unix::ffi::OsStrExt;
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    seed(root, "target/debug");
    seed(root, "target/release");
    let marker =
        std::ffi::CString::new(root.join("target/CACHEDIR.TAG").as_os_str().as_bytes()).unwrap();
    // SAFETY: the owned CString is a live terminated path for the native call.
    assert_eq!(unsafe { libc::mkfifo(marker.as_ptr(), 0o600) }, 0);
    for mode in [RestoreMode::Exact, RestoreMode::Compatible] {
        assert!(cache_restore::prepare(root, "native-auxiliary", "complete", mode).is_err());
        assert!(root.join("target/debug/stale-product").exists());
        assert!(root.join("target/release/stale-product").exists());
    }
}
