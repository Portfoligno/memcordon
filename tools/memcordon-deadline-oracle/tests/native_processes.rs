#![cfg(target_os = "macos")]
#![allow(dead_code)]

#[path = "../src/native/inventory.rs"]
mod inventory;

use inventory::{NativeProcessApi, ProcessIdentity, ProcessObservation};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    child: Child,
    session: i32,
    directory: PathBuf,
    known: BTreeSet<ProcessIdentity>,
}
impl Fixture {
    fn launch(mode: &str, extra: &[OsString]) -> Self {
        let directory = Path::new("/tmp").join(format!(
            "memcordon-native-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("ready.json");
        let binary = env!("CARGO_BIN_EXE_memcordon-deadline-oracle");
        let child = Command::new(binary)
            .arg("--session-exec")
            .arg(binary)
            .args(["--native-fixture", mode])
            .arg(&path)
            .args(extra)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let session = i32::try_from(child.id()).unwrap();
        let mut fixture = Self {
            child,
            session,
            directory,
            known: BTreeSet::new(),
        };
        let boundary = Instant::now() + Duration::from_secs(3);
        while !path.exists() && Instant::now() < boundary {
            fixture.discover();
            if let Some(status) = fixture.child.try_wait().unwrap() {
                assert!(
                    status.success() && path.exists(),
                    "fixture failed before readiness: {status}"
                );
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(path.exists(), "fixture readiness timed out");
        fixture.discover();
        fixture
    }
    fn discover(&mut self) {
        if let Ok(snapshot) = inventory::session_snapshot(&NativeProcessApi, self.session) {
            self.known
                .extend(snapshot.members.into_iter().map(|member| member.identity));
        }
    }
    fn path(&self) -> PathBuf {
        self.directory.join("ready.json")
    }
    fn observation(&mut self) -> ProcessObservation {
        let observation: ProcessObservation =
            serde_json::from_slice(&fs::read(self.path()).unwrap()).unwrap();
        self.known.insert(observation.identity);
        observation
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.discover();
        for identity in self.known.iter().copied() {
            if inventory::same_identity(&NativeProcessApi, identity).unwrap_or(false) {
                unsafe {
                    libc::kill(identity.pid, libc::SIGKILL);
                }
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        let boundary = Instant::now() + Duration::from_secs(3);
        while Instant::now() < boundary
            && self.known.iter().any(|identity| {
                inventory::same_identity(&NativeProcessApi, *identity).unwrap_or(true)
            })
        {
            std::thread::sleep(Duration::from_millis(5));
        }
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn native_libproc_child_counts_one_two_three_are_exact() {
    unsafe extern "C" {
        fn proc_listchildpids(parent: i32, buffer: *mut std::ffi::c_void, bytes: i32) -> i32;
    }
    for count in 1..=3 {
        let fixture = Fixture::launch("children", &[OsString::from(count.to_string())]);
        let mut expected: Vec<i32> =
            serde_json::from_slice(&fs::read(fixture.path()).unwrap()).unwrap();
        expected.sort_unstable();
        let mut buffer = [0_i32; 8];
        let slots = unsafe {
            proc_listchildpids(
                fixture.session,
                buffer.as_mut_ptr().cast(),
                i32::try_from(std::mem::size_of_val(&buffer)).unwrap(),
            )
        };
        assert_eq!(slots, count);
        let mut actual = buffer[..usize::try_from(slots).unwrap()].to_vec();
        actual.sort_unstable();
        assert_eq!(actual, expected);
        assert_ne!(
            actual.len(),
            usize::try_from(slots).unwrap() / std::mem::size_of::<i32>(),
            "old adapter misses every child"
        );
    }
}

#[test]
fn session_exec_preserves_session_and_non_utf8_argv() {
    let arguments = [
        OsString::from("argument with spaces"),
        OsString::from_vec(vec![b'x', 0xff, b'y']),
    ];
    let fixture = Fixture::launch("echo", &arguments);
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.path()).unwrap()).unwrap();
    assert_eq!(value["observation"]["session_id"], fixture.session);
    assert_eq!(value["observation"]["process_group"], fixture.session);
    assert_eq!(value["observation"]["identity"]["pid"], fixture.session);
    assert_ne!(unsafe { libc::getsid(0) }, fixture.session);
    let bytes: Vec<Vec<u8>> = serde_json::from_value(value["arguments"].clone()).unwrap();
    use std::os::unix::ffi::OsStrExt;
    assert_eq!(
        bytes,
        arguments
            .iter()
            .map(|argument| argument.as_bytes().to_vec())
            .collect::<Vec<_>>()
    );
}

#[test]
fn session_inventory_survives_leader_exit_and_process_group_changes() {
    for mode in ["leader-exit", "group"] {
        let mut fixture = Fixture::launch(mode, &[]);
        let child = fixture.observation();
        if mode == "leader-exit" {
            assert!(fixture.child.wait().unwrap().success());
        }
        let snapshot = inventory::session_snapshot(&NativeProcessApi, fixture.session).unwrap();
        assert!(
            snapshot
                .members
                .iter()
                .any(|member| member.identity == child.identity)
        );
        assert_eq!(child.session_id, fixture.session);
        if mode == "group" {
            assert_eq!(child.process_group, child.identity.pid);
            assert_ne!(child.process_group, fixture.session);
        }
    }
}

#[test]
fn known_identity_remains_live_after_native_session_escape() {
    let mut fixture = Fixture::launch("escape", &[]);
    let child = fixture.observation();
    fs::write(fixture.path().with_extension("escape"), b"true\n").unwrap();
    let boundary = Instant::now() + Duration::from_secs(3);
    while !fixture.path().with_extension("escaped").exists() && Instant::now() < boundary {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(fixture.path().with_extension("escaped").exists());
    let snapshot = inventory::session_snapshot(&NativeProcessApi, fixture.session).unwrap();
    assert!(
        !snapshot
            .members
            .iter()
            .any(|member| member.identity == child.identity)
    );
    assert!(inventory::same_identity(&NativeProcessApi, child.identity).unwrap());
}
