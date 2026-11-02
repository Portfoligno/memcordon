use memcordon_ci::installed_failure_carriers::select;
use std::{
    collections::BTreeSet,
    fs,
    time::{Duration, SystemTime},
};

#[test]
fn finite_original_carriers_survive_newer_files_within_the_same_count_bound() {
    let root = tempfile::tempdir().unwrap();
    let mut expected = Vec::new();
    for case in ["C-IO/empty-message", "W-JOINT/restricted"] {
        for file in [
            "result.callback-failure.json",
            "result.stderr.bin",
            "result.winsock-startup-trace.json",
            "result.listener-call-trace.json",
        ] {
            let path = root.path().join("windows-installed").join(case).join(file);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, b"original").unwrap();
            fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_times(
                    fs::FileTimes::new()
                        .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1)),
                )
                .unwrap();
            expected.push(path);
        }
    }
    for index in 0..180 {
        fs::write(
            root.path().join(format!("recent-{index:03}.json")),
            b"newer",
        )
        .unwrap();
    }
    let selected = select(root.path()).unwrap();
    assert_eq!(&selected[..expected.len()], expected.as_slice());
    assert_eq!(selected.len(), 128);
    assert_eq!(
        selected.iter().collect::<BTreeSet<_>>().len(),
        selected.len()
    );
    assert_eq!(fs::read(&selected[0]).unwrap(), b"original");
}

#[cfg(unix)]
#[test]
fn finite_priority_does_not_follow_leaf_or_parent_symlinks() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(
        outside.path().join("result.listener-call-trace.json"),
        b"outside",
    )
    .unwrap();
    let case = root.path().join("windows-installed/C-IO/empty-message");
    fs::create_dir_all(&case).unwrap();
    symlink(
        outside.path().join("result.listener-call-trace.json"),
        case.join("result.listener-call-trace.json"),
    )
    .unwrap();
    fs::create_dir_all(root.path().join("windows-installed/W-JOINT")).unwrap();
    symlink(
        outside.path(),
        root.path().join("windows-installed/W-JOINT/restricted"),
    )
    .unwrap();
    assert!(select(root.path()).unwrap().is_empty());
    assert_eq!(
        fs::read(outside.path().join("result.listener-call-trace.json")).unwrap(),
        b"outside"
    );
}

#[test]
fn absent_priority_does_not_suppress_ordinary_recent_diagnostics() {
    let root = tempfile::tempdir().unwrap();
    let wanted = root.path().join("other.json");
    fs::write(&wanted, b"diagnostic").unwrap();
    fs::write(root.path().join("workload.exe"), b"not-a-carrier").unwrap();
    assert_eq!(select(root.path()).unwrap(), vec![wanted]);
}
