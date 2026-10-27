#![cfg(all(windows, feature = "test-support"))]

use memcordon_platform::test_support::{WindowsImageProcess, windows_processes_for_image_until};
use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const TEST_WAIT: Duration = Duration::from_secs(30);

struct ChildOwner(Child);
impl Drop for ChildOwner {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "invoked by bounded original-held-thread parent regression"]
fn sampled_child() {
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut byte = [0];
        let _ = send.send(std::io::stdin().read(&mut byte));
    });
    assert_eq!(receive.recv_timeout(TEST_WAIT).unwrap().unwrap(), 0);
}

fn held(pid: u32, deadline: Instant) -> WindowsImageProcess {
    windows_processes_for_image_until(&std::env::current_exe().unwrap(), deadline)
        .unwrap()
        .into_iter()
        .find(|process| process.identity.pid == pid)
        .expect("exact already-owned test process")
}

#[test]
fn same_original_thread_handles_observe_retirement_without_live_exit_time_fabrication() {
    let deadline = Instant::now() + TEST_WAIT;
    let mut child = ChildOwner(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "--ignored", "sampled_child"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let process = held(child.0.id(), deadline);
    let mut round = process.begin_thread_activity_sample(deadline).unwrap();
    let first = round.first_observation().clone();
    assert_eq!(first["complete"], false);
    assert!(first["second"].is_null());
    assert_eq!(first["identity"]["pid"], process.identity.pid);
    assert_eq!(
        first["identity"]["birth"],
        serde_json::json!(process.identity.birth)
    );
    assert_eq!(first["thread_access_mask"], 0x0010_0800u32);
    let observations = first["first"]["threads"].as_array().unwrap();
    assert!(
        observations
            .iter()
            .any(|record| record.get("observed").is_some())
    );
    for record in observations {
        if record["observed"]["retired"] == false {
            assert!(record["observed"]["exit_time_100ns"].is_null());
        }
    }
    assert!(
        observations
            .iter()
            .any(|record| record["observed"]["retired"] == false)
    );
    // Only the duplicate of the same held process and original thread handles
    // remain in the sample; no naked PID is reacquired for the second pass.
    drop(process);
    assert_eq!(
        round
            .wait_original_threads_retired_until(Instant::now())
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::TimedOut
    );
    assert_eq!(round.first_observation(), &first);
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    round.wait_original_threads_retired_until(deadline).unwrap();
    let finished = round.finish(deadline);
    assert_eq!(finished["first"], first["first"]);
    assert_eq!(
        finished["second"]["observed"]["process_before"]["retired"],
        true
    );
    for record in finished["second"]["observed"]["threads"]
        .as_array()
        .unwrap()
    {
        let Some(observed) = record.get("observed") else {
            continue;
        };
        assert_eq!(observed["retired"], true);
        assert!(observed["exit_time_100ns"].is_u64());
        let original = observations
            .iter()
            .find(|first| first["observed"]["tid"] == observed["tid"])
            .unwrap();
        assert_eq!(observed["birth"], original["observed"]["birth"]);
        assert_eq!(observed["owner_pid"], child.0.id());
        assert_eq!(observed["unchanged_counters_are_not_deadlock"], true);
    }
    assert!(serde_json::to_vec(&finished).unwrap().len() <= 96 * 1024);
    assert!(round.wait_original_threads_retired_until(deadline).is_err());
    assert_eq!(
        round.finish(Instant::now() + Duration::from_secs(60)),
        finished
    );
}

#[test]
fn expired_second_pass_preserves_first_and_cannot_renew_the_original_round() {
    let deadline = Instant::now() + TEST_WAIT;
    let process = held(std::process::id(), deadline);
    assert!(
        process
            .begin_thread_activity_sample(Instant::now())
            .is_err()
    );
    let mut round = process.begin_thread_activity_sample(deadline).unwrap();
    let first = round.first_observation().clone();
    let expired = round.finish(Instant::now());
    assert_eq!(expired["first"], first["first"]);
    assert_eq!(expired["complete"], false);
    assert_eq!(expired["second"]["error"]["kind"], "TimedOut");
    assert_eq!(round.finish(deadline), expired);
}

#[test]
fn synchronous_rename_refuses_wrong_parent_names_and_expired_cutoffs_before_mutation() {
    use memcordon_platform::test_support::{
        windows_open_synchronous_rename_source, windows_prepare_persistent_stage,
    };
    use std::ffi::{OsStr, OsString};
    use std::fs::{File, OpenOptions};
    use std::os::windows::{ffi::OsStringExt, fs::OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_ARCHIVE, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_DELETE, FILE_SHARE_READ,
    };

    let deadline = Instant::now() + TEST_WAIT;
    let temporary = tempfile::tempdir().unwrap();
    let original = temporary.path().join("original");
    let other = temporary.path().join("other");
    std::fs::create_dir(&original).unwrap();
    std::fs::create_dir(&other).unwrap();
    let stage = OsStr::new("stage");
    let destination = OsStr::new("published.json");
    std::fs::write(original.join(stage), b"original stage bytes").unwrap();
    std::fs::write(other.join(stage), b"original stage bytes").unwrap();
    std::fs::write(original.join(destination), b"previous published bytes").unwrap();
    let readback = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
        .open(original.join(stage))
        .unwrap();
    let previous = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
        .open(original.join(destination))
        .unwrap();
    let directory = |path: &std::path::Path| {
        OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .unwrap()
    };
    let parent = directory(&original);
    let wrong_parent = directory(&other);
    assert!(
        windows_open_synchronous_rename_source(&wrong_parent, stage, &readback, deadline).is_err()
    );
    assert_eq!(
        windows_open_synchronous_rename_source(&parent, stage, &readback, Instant::now())
            .err()
            .unwrap()
            .kind(),
        std::io::ErrorKind::TimedOut
    );
    let mut malformed: Vec<OsString> = [
        "",
        ".",
        "..",
        "nested/name",
        "nested\\name",
        "name:stream",
        "name\0tail",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    // Even a component within the general path envelope must fit the native
    // UNICODE_STRING u16 byte extent, including its terminator.
    let source_extent = OsString::from_wide(&vec![
        u16::from(b'a');
        usize::from(u16::MAX)
            / std::mem::size_of::<u16>()
    ]);
    assert_eq!(
        windows_open_synchronous_rename_source(&parent, &source_extent, &readback, deadline)
            .err()
            .unwrap()
            .kind(),
        std::io::ErrorKind::InvalidInput
    );
    malformed.push(OsString::from_wide(&vec![
        u16::from(b'a');
        usize::from(u16::MAX)
            / std::mem::size_of::<u16>()
            + 1
    ]));
    for name in &malformed {
        assert_eq!(
            windows_open_synchronous_rename_source(&parent, name, &readback, deadline)
                .err()
                .unwrap()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
    }
    let source =
        windows_open_synchronous_rename_source(&parent, stage, &readback, deadline).unwrap();
    windows_prepare_persistent_stage(source.as_file(), deadline).unwrap();
    for name in &malformed {
        assert_eq!(
            source.rename(name, deadline).err().unwrap().kind(),
            std::io::ErrorKind::InvalidInput
        );
    }
    assert_eq!(
        source
            .rename(destination, Instant::now())
            .err()
            .unwrap()
            .kind(),
        std::io::ErrorKind::TimedOut
    );
    assert_eq!(
        std::fs::read(original.join(destination)).unwrap(),
        b"previous published bytes"
    );
    assert_eq!(
        std::fs::read(original.join(stage)).unwrap(),
        b"original stage bytes"
    );
    let committed = source.rename(destination, deadline).unwrap();
    // This fixture has no pathname-cleanup owner; the publisher regression
    // separately checks immediate TempPath disarm at this same commit boundary.
    committed.verify(deadline).unwrap();
    drop(source);
    assert!(!original.join(stage).exists());
    assert_eq!(
        std::fs::read(original.join(destination)).unwrap(),
        b"original stage bytes"
    );
    let final_file = File::open(original.join(destination)).unwrap();
    assert_eq!(
        memcordon_platform::test_support::windows_held_file_metadata(&final_file)
            .unwrap()
            .attributes,
        FILE_ATTRIBUTE_ARCHIVE
    );
    let mut old_bytes = Vec::new();
    (&previous).read_to_end(&mut old_bytes).unwrap();
    assert_eq!(old_bytes, b"previous published bytes");
}
