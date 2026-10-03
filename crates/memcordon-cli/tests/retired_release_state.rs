#[path = "../src/bin/memcordon-sealed-agent/linux/retired_state.rs"]
mod retired_state;

#[test]
fn stale_release_registration_is_rejected_before_any_old_decode() {
    let directory = tempfile::tempdir().unwrap();
    let parent = directory.path().canonicalize().unwrap();
    let path = parent.join("pending.v2.json");
    assert!(retired_state::require_absent(&path).is_ok());
    std::fs::write(&path, b"not even valid JSON").unwrap();
    assert!(retired_state::require_absent(&path).is_err());
    std::fs::remove_file(&path).unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("missing-target", &path).unwrap();
        assert!(retired_state::require_absent(&path).is_err());
        std::fs::remove_file(&path).unwrap();
        let linked_parent = parent.join("linked");
        std::os::unix::fs::symlink(&parent, &linked_parent).unwrap();
        assert!(retired_state::require_absent(&linked_parent.join("missing.json")).is_err());
    }
}
