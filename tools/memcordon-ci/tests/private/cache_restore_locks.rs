use super::settled_locks;

#[test]
fn overlapping_profiles_and_marker_parent_hold_each_cargo_lock_once() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    let debug = target.join("debug");
    let release = target.join("release");
    for profile in [&debug, &release] {
        std::fs::create_dir_all(profile).unwrap();
        std::fs::write(profile.join(".cargo-lock"), b"").unwrap();
    }
    // These are the auxiliary archive directories plus CACHEDIR.TAG's parent.
    let locks = settled_locks(&[debug.clone(), release.clone(), target.clone(), debug]).unwrap();
    assert_eq!(locks.len(), 2);
    #[cfg(unix)]
    {
        let error = settled_locks(std::slice::from_ref(&target)).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("active Cargo writer"));
        assert!(message.contains(".cargo-lock"));
        assert!(message.contains(target.to_str().unwrap()));
    }
    drop(locks);
    assert_eq!(settled_locks(&[target]).unwrap().len(), 2);
}

#[cfg(unix)]
#[test]
fn independently_held_lock_blocks_settlement_with_path_context() {
    let temp = tempfile::tempdir().unwrap();
    let lock_path = temp.path().join(".cargo-lock");
    let foreign = std::fs::File::create(&lock_path).unwrap();
    rustix::fs::flock(
        &foreign,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
    .unwrap();
    let error = settled_locks(&[temp.path().to_owned()]).unwrap_err();
    assert!(error.to_string().contains("active Cargo writer"));
    assert!(error.to_string().contains(lock_path.to_str().unwrap()));
    drop(foreign);
    assert_eq!(settled_locks(&[temp.path().to_owned()]).unwrap().len(), 1);
}
