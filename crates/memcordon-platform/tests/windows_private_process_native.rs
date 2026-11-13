#![cfg(all(windows, feature = "test-support"))]

use memcordon_platform::test_support::{
    ProcessIdentity, duplicate_directory_metadata_into_child, duplicate_marker_metadata_into_child,
    windows_fixture_input_processes_for_image_until, windows_held_file_metadata,
};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle},
    },
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};
use windows_sys::{
    Wdk::Foundation::{NtQueryObject, ObjectBasicInformation},
    Win32::{
        Foundation::{FILETIME, GetHandleInformation, HANDLE_FLAG_INHERIT},
        Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ, FILE_SHARE_WRITE,
        },
        System::{Threading::GetProcessTimes, WindowsProgramming::PUBLIC_OBJECT_BASIC_INFORMATION},
    },
};

const SELECTOR: &str =
    "held_child_admission_and_metadata_references_preserve_exact_owners_and_rights";
const CHILD_MARKER: &str = "--skip=memcordon-private-metadata-child";

struct ChildOwner {
    child: Option<Child>,
    cutoff: Instant,
}
impl std::ops::Deref for ChildOwner {
    type Target = Child;
    fn deref(&self) -> &Child {
        self.child.as_ref().expect("owned native test child")
    }
}
impl std::ops::DerefMut for ChildOwner {
    fn deref_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("owned native test child")
    }
}
impl ChildOwner {
    fn wait_until_exit(&mut self) -> io::Result<ExitStatus> {
        loop {
            if Instant::now() >= self.cutoff {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "original native test child retirement cutoff",
                ));
            }
            if let Some(status) = self.try_wait()? {
                if Instant::now() >= self.cutoff {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "native test exit observation returned after original cutoff",
                    ));
                }
                return Ok(status);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
impl Drop for ChildOwner {
    fn drop(&mut self) {
        if Instant::now() < self.cutoff
            && self.try_wait().ok().flatten().is_none()
            && Instant::now() < self.cutoff
        {
            let _ = self.kill();
        }
        if let Err(error) = self.wait_until_exit() {
            // An unproved child remains actually owned until this test process
            // exits, without an unbounded wait or a replacement PID handle.
            std::mem::forget(self.child.take().expect("unsettled original test owner"));
            if !std::thread::panicking() {
                panic!("{error}");
            }
        }
    }
}

fn spawn(cutoff: Instant) -> ChildOwner {
    ChildOwner {
        child: Some(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", SELECTOR, "--nocapture", CHILD_MARKER])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        ),
        cutoff,
    }
}

fn identity(child: &Child) -> ProcessIdentity {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    assert_ne!(
        unsafe {
            GetProcessTimes(
                child.as_raw_handle(),
                &mut creation,
                &mut exit,
                &mut kernel,
                &mut user,
            )
        },
        0
    );
    ProcessIdentity {
        pid: child.id(),
        birth: (u128::from(creation.dwHighDateTime) << 32) | u128::from(creation.dwLowDateTime),
    }
}

fn received_reference() {
    let mut input = std::io::stdin().lock();
    let mut word = [0u8; 8];
    input.read_exact(&mut word).unwrap();
    let raw = u64::from_le_bytes(word);
    assert!(raw > 0 && raw <= isize::MAX as u64);
    // Test-only receiver adopts exactly the one slot sent by its owned parent.
    let file = unsafe { File::from_raw_handle(raw as usize as _) };
    let mut flags = 0;
    assert_ne!(
        unsafe { GetHandleInformation(file.as_raw_handle(), &mut flags) },
        0
    );
    assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
    let mut basic = PUBLIC_OBJECT_BASIC_INFORMATION::default();
    let mut returned = 0;
    let extent = std::mem::size_of_val(&basic) as u32;
    assert!(
        unsafe {
            NtQueryObject(
                file.as_raw_handle(),
                ObjectBasicInformation,
                (&mut basic as *mut PUBLIC_OBJECT_BASIC_INFORMATION).cast(),
                extent,
                &mut returned,
            )
        } >= 0
    );
    assert_eq!(returned, extent);
    assert_eq!(basic.GrantedAccess, FILE_READ_ATTRIBUTES);
    let metadata = windows_held_file_metadata(&file).unwrap();
    input.read_exact(&mut word).unwrap();
    assert_eq!(metadata.file_index, u64::from_le_bytes(word));
    let mut volume = [0u8; 4];
    input.read_exact(&mut volume).unwrap();
    assert_eq!(metadata.volume_serial, u32::from_le_bytes(volume));
}

#[test]
fn held_child_admission_and_metadata_references_preserve_exact_owners_and_rights() {
    if std::env::args().any(|argument| argument == CHILD_MARKER) {
        received_reference();
        return;
    }
    let cutoff = Instant::now() + Duration::from_secs(45);
    let executable = std::env::current_exe().unwrap();
    let root = windows_fixture_input_processes_for_image_until(&executable, cutoff)
        .unwrap()
        .into_iter()
        .find(|process| process.identity.pid == std::process::id())
        .unwrap();
    assert!(root.same_object_reference(&root.clone()));
    assert!(root.duplicate_pending_child(0, cutoff).is_err());
    assert!(root.duplicate_pending_child(u64::MAX, cutoff).is_err());
    let directory = tempfile::tempdir().unwrap();
    let source = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(directory.path())
        .unwrap();
    let metadata = windows_held_file_metadata(&source).unwrap();
    let temporary = source.try_clone().unwrap();
    let stale = temporary.as_raw_handle() as usize as u64;
    drop(temporary);
    // A closed scalar may already have been recycled. Either native duplicate
    // refusal or the actual process/object join must reject its claimed owner.
    if let Ok(recycled) = root.duplicate_pending_child(stale, cutoff) {
        assert!(
            recycled
                .admit(&root, root.identity, &executable, cutoff)
                .is_err()
        );
    }
    // A valid scalar for a different native type cannot become a process owner.
    // Duplication may reject incompatible rights before the admission query.
    if let Ok(wrong_type) =
        root.duplicate_pending_child(source.as_raw_handle() as usize as u64, cutoff)
    {
        assert!(
            wrong_type
                .admit(&root, root.identity, &executable, cutoff)
                .is_err()
        );
        assert!(wrong_type.has_exited().is_err());
    }
    for ordinal in [0, 1, 2, 128, 129] {
        let mut child = spawn(cutoff);
        let expected = identity(&child);
        let pending = root
            .duplicate_pending_child(child.as_raw_handle() as usize as u64, cutoff)
            .unwrap();
        let wrong = ProcessIdentity {
            birth: expected.birth + 1,
            ..expected
        };
        assert!(pending.admit(&root, wrong, &executable, cutoff).is_err());
        assert!(!pending.has_exited().unwrap());
        let admitted = pending.admit(&root, expected, &executable, cutoff).unwrap();
        assert_eq!(admitted.identity, expected);
        assert!(!admitted.has_exited().unwrap());
        let mut count = 0;
        for _ in 0..ordinal {
            duplicate_directory_metadata_into_child(&child, &source, cutoff, &mut count).unwrap();
        }
        if ordinal == 129 {
            assert!(
                duplicate_directory_metadata_into_child(&child, &source, cutoff, &mut count)
                    .is_err()
            );
            assert_eq!(count, 129);
        }
        let expired = Instant::now();
        assert!(
            duplicate_directory_metadata_into_child(&child, &source, expired, &mut count).is_err()
        );
        assert_eq!(count, ordinal);
        child.kill().unwrap();
        child.wait_until_exit().unwrap();
        // Exact independently-retained controller owner remains usable after
        // local Child settlement, including unpublished partial delivery slots.
        assert!(pending.has_exited().unwrap());
        assert!(admitted.has_exited().unwrap());
        assert!(
            admitted
                .duplicate_directory_metadata(&source, cutoff, &mut count)
                .is_err()
        );
        assert_eq!(count, ordinal);
    }
    let mut child = spawn(cutoff);
    let expected = identity(&child);
    let pending = root
        .duplicate_pending_child(child.as_raw_handle() as usize as u64, cutoff)
        .unwrap();
    let admitted = pending.admit(&root, expected, &executable, cutoff).unwrap();
    let mut count = 0;
    let transferred =
        duplicate_directory_metadata_into_child(&child, &source, cutoff, &mut count).unwrap();
    assert_eq!(count, 1);
    let mut input = child.stdin.take().unwrap();
    input.write_all(&transferred.to_le_bytes()).unwrap();
    input.write_all(&metadata.file_index.to_le_bytes()).unwrap();
    input
        .write_all(&metadata.volume_serial.to_le_bytes())
        .unwrap();
    drop(input);
    assert!(child.wait_until_exit().unwrap().success());
    assert!(admitted.has_exited().unwrap());
    assert!(pending.has_exited().unwrap());

    // FILE marker transfer is distinct from directory ancestry transfer and
    // still yields exact query-only/noninheritable rights in the real child.
    let marker_path = directory.path().join("fixture.exe.local");
    std::fs::write(&marker_path, []).unwrap();
    let marker = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&marker_path)
        .unwrap();
    let marker_metadata = windows_held_file_metadata(&marker).unwrap();
    let mut child = spawn(cutoff);
    let expected = identity(&child);
    let pending = root
        .duplicate_pending_child(child.as_raw_handle() as usize as u64, cutoff)
        .unwrap();
    let admitted = pending.admit(&root, expected, &executable, cutoff).unwrap();
    let mut count = 0;
    assert!(duplicate_directory_metadata_into_child(&child, &marker, cutoff, &mut count).is_err());
    assert!(duplicate_marker_metadata_into_child(&child, &source, cutoff, &mut count).is_err());
    assert_eq!(count, 0);
    let transferred =
        duplicate_marker_metadata_into_child(&child, &marker, cutoff, &mut count).unwrap();
    // Admission preserves a query/liveness witness, not PROCESS_DUP_HANDLE.
    let refused = admitted
        .duplicate_marker_metadata(&marker, cutoff, &mut count)
        .unwrap_err();
    assert_eq!(refused.raw_os_error(), Some(5));
    assert_eq!(count, 1);
    let mut input = child.stdin.take().unwrap();
    input.write_all(&transferred.to_le_bytes()).unwrap();
    input
        .write_all(&marker_metadata.file_index.to_le_bytes())
        .unwrap();
    input
        .write_all(&marker_metadata.volume_serial.to_le_bytes())
        .unwrap();
    drop(input);
    assert!(child.wait_until_exit().unwrap().success());
    assert!(admitted.has_exited().unwrap());
    assert!(pending.has_exited().unwrap());
}
