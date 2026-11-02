use memcordon_ci::storage_observation::snapshot;
use std::{
    fs,
    time::{Duration, Instant},
};

#[test]
fn pathname_inventory_counts_files_and_hardlinks_without_claiming_unique_storage() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("small-target");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("first"), b"abcdef").unwrap();
    fs::hard_link(target.join("first"), target.join("second")).unwrap();
    let value = snapshot(
        root.path(),
        Some(&target),
        true,
        Instant::now() + Duration::from_secs(2),
    );
    let inventory = &value["roles"][0]["inventory"];
    assert_eq!(inventory["files"], 2);
    assert_eq!(inventory["logical_bytes_by_path"], 12);
    assert_eq!(inventory["hardlinks_counted_per_path"], true);
    assert_eq!(inventory["unique_physical_usage"], false);
    assert_eq!(value["acceptance_authority"], false);
    assert_eq!(value["mutation_performed"], false);
    assert_eq!(fs::read(target.join("first")).unwrap(), b"abcdef");
}

#[cfg(unix)]
#[test]
fn symlink_children_and_symlink_root_are_not_traversed() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("outside-bytes"), [1u8; 1024]).unwrap();
    let target = root.path().join("inside");
    fs::create_dir(&target).unwrap();
    symlink(outside.path(), target.join("link")).unwrap();
    let value = snapshot(
        root.path(),
        Some(&target),
        true,
        Instant::now() + Duration::from_secs(2),
    );
    assert_eq!(value["roles"][0]["inventory"]["symlinks"], 1);
    assert_eq!(value["roles"][0]["inventory"]["files"], 0);
    let value = snapshot(
        root.path(),
        Some(&target.join("link")),
        true,
        Instant::now() + Duration::from_secs(2),
    );
    assert_eq!(value["roles"][0]["inventory"]["symlinks"], 1);
    assert_eq!(value["roles"][0]["inventory"]["files"], 0);
}

#[test]
fn expired_and_missing_observations_are_bounded_nonfatal_and_inventory_is_optional() {
    let root = tempfile::tempdir().unwrap();
    let expired = snapshot(root.path(), None, true, Instant::now());
    assert_eq!(expired["workspace"]["status"], "cutoff");
    assert_eq!(expired["roles"][0]["inventory"]["time_truncated"], true);
    assert_eq!(expired["roles"][0]["inventory"]["entries"], 0);
    let missing = snapshot(
        root.path(),
        None,
        true,
        Instant::now() + Duration::from_secs(2),
    );
    assert!(missing["roles"][0]["inventory"]["errors"].as_u64().unwrap() > 0);
    assert_eq!(missing["roles"][0]["inventory"]["complete"], false);
    let brief = snapshot(
        root.path(),
        None,
        false,
        Instant::now() + Duration::from_secs(2),
    );
    assert!(brief["roles"][0]["inventory"].is_null());
    assert!(serde_json::to_vec(&missing).unwrap().len() < 16 * 1024);
}

#[test]
fn deeper_directories_are_reported_partial_without_scanning_the_tail() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("depth-target");
    fs::create_dir(&target).unwrap();
    let mut tail = target.clone();
    for _ in 0..34 {
        tail.push("child");
        fs::create_dir(&tail).unwrap();
    }
    fs::write(tail.join("not-observed"), b"tail").unwrap();
    let competing = root.path().join("target/ci-runtime");
    fs::create_dir_all(&competing).unwrap();
    fs::write(competing.join("live-runtime"), b"runtime").unwrap();
    let value = snapshot(
        root.path(),
        Some(&target),
        true,
        Instant::now() + Duration::from_secs(2),
    );
    let inventory = &value["roles"][0]["inventory"];
    assert_eq!(inventory["depth_truncated"], true);
    assert_eq!(inventory["complete"], false);
    assert_eq!(inventory["files"], 0);
    assert!(inventory["entries"].as_u64().unwrap() <= 33);
    assert_eq!(value["roles"][1]["inventory"]["files"], 1);
    assert_eq!(value["roles"][1]["inventory"]["logical_bytes_by_path"], 7);
}
