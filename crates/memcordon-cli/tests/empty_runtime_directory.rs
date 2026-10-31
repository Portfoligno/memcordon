#![cfg(unix)]
#[path = "../src/bin/empty_runtime_directory.rs"]
mod retirement;

use std::{
    ffi::OsStr,
    fs::{self, File},
    os::unix::fs::{MetadataExt, PermissionsExt},
    time::{Duration, Instant},
};

fn cutoff() -> Instant {
    Instant::now() + Duration::from_secs(60)
}

#[test]
// Linux's held-directory post-unlink link count is part of the product guard.
// Darwin retains a different vnode link count; no production guard is relaxed.
#[cfg(target_os = "linux")]
fn empty_root_is_removed_and_original_unlinked_handle_is_idempotent() {
    let owner = tempfile::tempdir().unwrap();
    let path = fs::canonicalize(owner.path()).unwrap();
    let parent = File::open(&path).unwrap();
    let uid = parent.metadata().unwrap().uid();
    fs::create_dir(path.join("root")).unwrap();
    let held = File::open(path.join("root")).unwrap();
    retirement::retire(&parent, OsStr::new("root"), &held, uid, cutoff()).unwrap();
    assert!(!path.join("root").exists());
    assert_eq!(held.metadata().unwrap().nlink(), 0);
    retirement::retire(&parent, OsStr::new("root"), &held, uid, cutoff()).unwrap();
    owner.close().unwrap();
}

#[test]
fn nonempty_root_preserves_unknown_contents_and_refuses_removal() {
    let owner = tempfile::tempdir().unwrap();
    let parent = File::open(owner.path()).unwrap();
    let root = owner.path().join("root");
    fs::create_dir(&root).unwrap();
    let held = File::open(&root).unwrap();
    fs::write(root.join("unknown"), b"retain actual state").unwrap();
    assert!(
        retirement::retire(
            &parent,
            OsStr::new("root"),
            &held,
            parent.metadata().unwrap().uid(),
            cutoff()
        )
        .is_err()
    );
    assert_eq!(
        fs::read(root.join("unknown")).unwrap(),
        b"retain actual state"
    );
    assert_ne!(held.metadata().unwrap().nlink(), 0);
    owner.close().unwrap();
}

#[test]
fn absent_name_does_not_authorize_a_moved_original_or_replacement_inode() {
    let owner = tempfile::tempdir().unwrap();
    let parent = File::open(owner.path()).unwrap();
    let uid = parent.metadata().unwrap().uid();
    let root = owner.path().join("root");
    let moved = owner.path().join("moved");
    fs::create_dir(&root).unwrap();
    let held = File::open(&root).unwrap();
    fs::rename(&root, &moved).unwrap();
    assert!(retirement::retire(&parent, OsStr::new("root"), &held, uid, cutoff()).is_err());
    fs::create_dir(&root).unwrap();
    let replacement = fs::metadata(&root).unwrap().ino();
    let error = retirement::retire(&parent, OsStr::new("root"), &held, uid, cutoff()).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(fs::metadata(&root).unwrap().ino(), replacement);
    assert_eq!(
        fs::metadata(&moved).unwrap().ino(),
        held.metadata().unwrap().ino()
    );
    owner.close().unwrap();
}

#[test]
fn links_unsafe_ownership_permissions_and_expired_cutoffs_remain_errors() {
    use std::os::unix::fs::symlink;
    let owner = tempfile::tempdir().unwrap();
    let parent = File::open(owner.path()).unwrap();
    let uid = parent.metadata().unwrap().uid();
    let root = owner.path().join("root");
    fs::create_dir(&root).unwrap();
    let held = File::open(&root).unwrap();
    symlink(&root, owner.path().join("link")).unwrap();
    assert!(retirement::retire(&parent, OsStr::new("link"), &held, uid, cutoff()).is_err());
    assert!(
        retirement::retire(
            &parent,
            OsStr::new("root"),
            &held,
            uid.wrapping_add(1),
            cutoff()
        )
        .is_err()
    );
    fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(retirement::retire(&parent, OsStr::new("root"), &held, uid, cutoff()).is_err());
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(retirement::retire(&parent, OsStr::new("root"), &held, uid, Instant::now()).is_err());
    assert!(retirement::retire(&parent, OsStr::new("../root"), &held, uid, cutoff()).is_err());
    for name in ["root/", "link/"] {
        assert_eq!(
            retirement::retire(&parent, OsStr::new(name), &held, uid, cutoff())
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
    }
    assert!(root.is_dir());
    owner.close().unwrap();
}
