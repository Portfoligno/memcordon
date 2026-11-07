use memcordon_ci::{
    installed_failure_carriers::{package_cleanup_paths, paths, select},
    release::installed_consumer::windows_case_output_directory,
};
use std::{
    collections::BTreeSet,
    fs,
    time::{Duration, SystemTime},
};

#[test]
fn finite_original_carriers_survive_newer_files_within_the_same_count_bound() {
    let root = tempfile::tempdir().unwrap();
    // Use the production directory seam, not the retention helper's relative list.
    let producer_output = windows_case_output_directory(root.path());
    assert_eq!(producer_output, root.path().join("windows-installed"));
    let mut expected = Vec::new();
    for case in ["C-IO/empty-message", "W-JOINT/restricted"] {
        for file in [
            "result.callback-failure.json",
            "result.failed-frontend.json",
            "result.failed-terminal-observation.json",
            "result.stderr.bin",
            "result.winsock-startup-trace.json",
            "result.listener-call-trace.json",
            "result.listener-native-file-requests.json",
            "result.peer-spawn-call-trace.json",
            "result.tcp-peer-stdout.json",
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
    let fileio = root
        .path()
        .join("windows-installed/W-JOINT/restricted/result.loader-fileio.json");
    fs::write(&fileio, b"original fileio").unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&fileio)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(SystemTime::UNIX_EPOCH))
        .unwrap();
    expected.push(fileio);
    let inventory = root
        .path()
        .join("windows-installed/fixture-manifest-inventory.json");
    fs::write(&inventory, b"original inventory").unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&inventory)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(SystemTime::UNIX_EPOCH))
        .unwrap();
    expected.push(inventory);
    let report = producer_output.join("C-IO/native-argv/result");
    fs::create_dir_all(report.parent().unwrap()).unwrap();
    for extension in [
        "guardian-query.json",
        "guardian-query.stdout.bin",
        "guardian-query.stderr.bin",
        "callback-failure.json",
        "stderr.bin",
    ] {
        // Match the actual query/callback producer's report.with_extension seam.
        let path = report.with_extension(extension);
        fs::write(&path, b"original native argv diagnostic").unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(SystemTime::UNIX_EPOCH))
            .unwrap();
        expected.push(path);
    }
    for name in [
        "package-uninstall.stdout.bin",
        "package-uninstall.stderr.bin",
        "package-uninstall.capture.json",
        "package-uninstall.invocation.json",
        "recovery.stdout.bin",
        "recovery.stderr.bin",
    ] {
        let path = producer_output.join(name);
        fs::write(&path, b"original cleanup capture").unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(SystemTime::UNIX_EPOCH))
            .unwrap();
        expected.push(path);
    }
    let uploaded = paths(root.path().to_str().unwrap())
        .lines()
        .map(std::path::PathBuf::from)
        .collect::<Vec<_>>();
    assert_eq!(uploaded, expected);
    assert!(uploaded.iter().all(|path| path.is_file()));
    // The provider experiment uses its own output directory directly.
    let provider_output = tempfile::tempdir().unwrap();
    let direct = package_cleanup_paths(provider_output.path().to_str().unwrap())
        .lines()
        .map(std::path::PathBuf::from)
        .collect::<Vec<_>>();
    assert_eq!(direct.len(), 6);
    for path in &direct {
        assert_eq!(path.parent(), Some(provider_output.path()));
        fs::write(path, b"direct provider capture").unwrap();
    }
    assert!(direct.iter().all(|path| path.is_file()));
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
