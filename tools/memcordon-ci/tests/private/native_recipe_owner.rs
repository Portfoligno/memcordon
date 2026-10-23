//! Linux root-only ownership tests, not admission or cache qualifications.
use super::*;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

fn fixture(output: &Path, executable: &Path, pidfd: bool) -> NativeTestOwner {
    assert_eq!(
        rustix::process::geteuid().as_raw(),
        0,
        "requires owned root observer"
    );
    let image = File::open(executable).unwrap();
    let mut child = std::process::Command::new(executable)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let process_id = child.id();
    let stdout = child.stdout.take().map(capture);
    let stderr = child.stderr.take().map(capture);
    let mut owner = NativeTestOwner {
        _ancestry: vec![File::open(output).unwrap()],
        publications: Default::default(),
        native_quiescent: false,
        child,
        pidfd: None,
        image,
        process_id,
        birth: None,
        output: output.into(),
        stdout,
        stderr,
        stdout_bytes: None,
        stderr_bytes: None,
        capture_failure: None,
        status: None,
        image_sha256: artifacts::checksum(&fs::read(executable).unwrap()),
        input_delivered: false,
        delivery_started: false,
        admission_refused: true,
        admission_refusal: Some(br#"{"admission":false,"input_delivered":false}"#.to_vec()),
        crash_helpers: Vec::new(),
        crash_failures: Vec::new(),
    };
    if pidfd {
        let descriptor = rustix::process::pidfd_open(
            rustix::process::Pid::from_raw(i32::try_from(process_id).unwrap()).unwrap(),
            rustix::process::PidfdFlags::empty(),
        );
        match descriptor {
            Ok(descriptor) => owner.pidfd = Some(descriptor),
            Err(error) => {
                let _ = owner.stop();
                let _ = owner.finish(Instant::now() + Duration::from_secs(2));
                panic!("native fixture pidfd acquisition failed: {error}");
            }
        }
    }
    owner
}

fn executable(root: &Path) -> PathBuf {
    let executable = root.join("owned-stdin-reader");
    // A unique inode avoids borrowing any unrelated process's image identity.
    fs::copy("/bin/cat", &executable).unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o555)).unwrap();
    executable
}

#[test]
#[ignore = "requires Linux root, proc custody and actual native process retirement"]
fn rejected_stdin_owner_settles_without_erasing_primary_failure() {
    for pidfd in [true, false] {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let executable = executable(root.path());
        let owner = fixture(root.path(), &executable, pidfd);
        assert!(!owner.input_delivered);
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut batch = NativeRecipeBatch {
            failures: vec!["original image refusal".into()],
            owners: Vec::new(),
        };
        assert!(batch.settle_refused("fixture", owner, deadline));
        assert!(batch.owners.is_empty());
        assert_eq!(batch.failures[0], "original image refusal");
        let exit: serde_json::Value =
            serde_json::from_slice(&fs::read(root.path().join("native-exit.json")).unwrap())
                .unwrap();
        assert_eq!(exit["input_delivered"], false);
        assert_eq!(exit["capture_complete"], true);
        assert_eq!(exit.as_object().unwrap().len(), 3);
        let refusal_exit: serde_json::Value = serde_json::from_slice(
            &fs::read(root.path().join("native-refusal-exit.json")).unwrap(),
        )
        .unwrap();
        assert!(refusal_exit["raw_wait_status"].as_i64().is_some());
        assert!(root.path().join("native-retirement.json").is_file());
        assert!(root.path().join("native-admission-refusal.json").is_file());
    }
}

#[test]
#[ignore = "requires Linux root and actual same-image ownership recovery"]
fn unresolved_same_image_retains_original_owner_until_same_cutoff_settlement() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let executable = executable(root.path());
    let output = root.path().join("owner");
    fs::create_dir(&output).unwrap();
    let owner = fixture(&output, &executable, true);
    let original_pid = owner.process_id;
    let mut helper = std::process::Command::new(&executable)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut batch = NativeRecipeBatch {
        failures: vec!["original image refusal".into()],
        owners: Vec::new(),
    };
    let admitted_next = batch.settle_refused("fixture", owner, deadline);
    let stopped = helper.kill();
    let waited = helper.wait();
    assert!(!admitted_next, "later same-image work cannot be admitted");
    assert!(stopped.is_ok() && waited.is_ok());
    assert_eq!(batch.owners.len(), 1);
    assert_eq!(batch.owners[0].1.process_id, original_pid);
    batch.settle(deadline).unwrap();
    assert!(batch.owners.is_empty());
    assert_eq!(batch.failures[0], "original image refusal");
}
