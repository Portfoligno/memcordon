#![cfg(target_os = "linux")]

use crate::linux::private_root::MountedPrivateRoot;
use memcordon_core::workload_contract::LogicalId;
use memcordon_core::workload_contract_v3::{
    BoundObjectRef, ExclusiveAdministratorIdentityRef, RootRelativePath,
};
use memcordon_core::workload_registry_v3::{RootLayoutDefinitionV1, WritableRootV1};
use memcordon_core::{BoundedVec, DiagnosticSha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::num::NonZeroU64;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::{Duration, Instant};

fn path(value: &str) -> RootRelativePath {
    RootRelativePath::new(value.into()).unwrap()
}
fn object(value: &str) -> BoundObjectRef {
    BoundObjectRef {
        id: LogicalId::new(value.into()).unwrap(),
        digest: DiagnosticSha256::from_bytes([1; 32]),
    }
}
fn layout(generated_execution: bool) -> RootLayoutDefinitionV1 {
    let mut roots = BoundedVec::default();
    for name in ["work", "nested/cache"] {
        roots
            .try_push(WritableRootV1 {
                id: LogicalId::new(name.replace('/', "-")).unwrap(),
                path: path(name),
                byte_limit: NonZeroU64::new(4096).unwrap(),
                generated_execution,
            })
            .unwrap();
    }
    RootLayoutDefinitionV1 {
        format: "memcordon.root-layout".into(),
        revision: 1,
        layout_id: LogicalId::new("pinned-mount-test".into()).unwrap(),
        runtime_image: object("runtime"),
        input_image: object("input"),
        writable_roots: roots,
        output_files: BoundedVec::default(),
    }
}
fn identity() -> ExclusiveAdministratorIdentityRef {
    ExclusiveAdministratorIdentityRef {
        identity: object("account"),
        exclusive_use_policy: object("exclusive"),
    }
}
fn read_output(root: &MountedPrivateRoot, selected: &str, uid: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    root.open_output_for_test(&path(selected), uid)
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    bytes
}

#[test]
fn pinned_writable_directory_identity_and_file_refusals_remain_exact() {
    let temporary = tempfile::Builder::new()
        .prefix("memcordon-mount-pins-")
        .tempdir_in("/dev/shm")
        .unwrap();
    fs::create_dir(temporary.path().join("work")).unwrap();
    fs::create_dir_all(temporary.path().join("nested/cache")).unwrap();
    fs::write(temporary.path().join("work/value"), b"original").unwrap();
    fs::write(temporary.path().join("nested/cache/value"), b"nested").unwrap();
    let top = File::open(temporary.path()).unwrap();
    let mut flags = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    assert_eq!(
        unsafe { libc::fstatvfs(top.as_raw_fd(), flags.as_mut_ptr()) },
        0
    );
    let generated_execution = unsafe { flags.assume_init() }.f_flag & libc::ST_NOEXEC == 0;
    let mut root = MountedPrivateRoot::capture_for_test(
        top,
        layout(generated_execution),
        identity(),
        Instant::now() + Duration::from_secs(5),
    )
    .unwrap();
    // This ordinary-directory test proves descriptor association, not namespace teardown.
    fs::rename(
        temporary.path().join("work"),
        temporary.path().join("renamed"),
    )
    .unwrap();
    fs::create_dir(temporary.path().join("work")).unwrap();
    fs::write(temporary.path().join("work/value"), b"replacement").unwrap();
    let uid = unsafe { libc::geteuid() };
    assert_eq!(read_output(&root, "work/value", uid), b"original");
    assert_eq!(read_output(&root, "nested/cache/value", uid), b"nested");
    std::os::unix::fs::symlink("value", temporary.path().join("renamed/link")).unwrap();
    assert!(root.open_output_for_test(&path("work/link"), uid).is_err());
    fs::hard_link(
        temporary.path().join("renamed/value"),
        temporary.path().join("renamed/alias"),
    )
    .unwrap();
    assert!(root.open_output_for_test(&path("work/value"), uid).is_err());
    root.invalidate_pin_for_test(true);
    assert!(
        root.open_output_for_test(&path("nested/cache/value"), uid)
            .unwrap_err()
            .contains("immutable layout")
    );
    root.invalidate_pin_for_test(false);
    assert!(
        root.open_output_for_test(&path("nested/cache/value"), uid)
            .unwrap_err()
            .contains("pins absent")
    );
}

/// Called by the existing root-only native account-retirement component.
/// The process observer reaps the exact namespace child before output reads.
pub(super) fn writable_submounts_survive_namespace_reap(deadline: Instant) {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let temporary = tempfile::tempdir_in("/tmp").unwrap();
    let staging = temporary.path().join("root");
    fs::create_dir(&staging).unwrap();
    let socket = temporary.path().join("control");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let captured = std::sync::Arc::new(std::sync::Mutex::new(None));
    let capture = std::sync::Arc::clone(&captured);
    let input = serde_json::to_vec(&(staging, socket)).unwrap();
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "native_writable_mounts::writable_namespace_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .stdin(std::process::Stdio::piped());
    let output = memcordon_testkit::run_with_deadline_owned_spawn_with_io_output_limit(
        command,
        deadline.saturating_duration_since(Instant::now()),
        65536,
        |mut command| command.spawn(),
        move |_, stdin, _| {
            let mut stdin =
                stdin.ok_or_else(|| std::io::Error::other("namespace fixture stdin absent"))?;
            stdin.write_all(&input)?;
            drop(stdin);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(value) => break value,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(2))
                    }
                    Err(error) => return Err(error),
                }
            };
            stream.set_read_timeout(Some(deadline.saturating_duration_since(Instant::now())))?;
            let (_, mut descriptors) =
                crate::linux::transport::receive(&stream).map_err(std::io::Error::other)?;
            if descriptors.len() != 1 {
                return Err(std::io::Error::other(
                    "namespace fixture root count differs",
                ));
            }
            let top = File::from(descriptors.remove(0));
            let root = MountedPrivateRoot::capture_for_test(
                top.try_clone()?,
                layout(false),
                identity(),
                deadline,
            )
            .map_err(std::io::Error::other)?;
            *capture
                .lock()
                .map_err(|_| std::io::Error::other("namespace capture poisoned"))? =
                Some((root, top));
            stream.write_all(b"R")?;
            Ok(())
        },
    )
    .unwrap();
    assert!(
        output.status.success(),
        "namespace child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let (root, top) = captured.lock().unwrap().take().unwrap();
    let ordinary_work =
        crate::linux::runtime_image::directory_at(top.as_fd(), "work", false).unwrap();
    assert!(
        crate::linux::runtime_image::open_relative(ordinary_work.as_fd(), &path("value"), false)
            .is_err(),
        "top-root traversal must no longer reach the disconnected writable mount"
    );
    assert_eq!(read_output(&root, "work/value", 0), b"first-native-mount");
    assert_eq!(
        read_output(&root, "nested/cache/value", 0),
        b"nested-native-mount"
    );
    assert!(root.open_output_for_test(&path("work/link"), 0).is_err());
    assert!(root.open_output_for_test(&path("work/hard"), 0).is_err());
    assert!(root.open_output_for_test(&path("work/value"), 1).is_err());
}

#[test]
#[ignore = "only invoked by the root-only native mount lifetime regression"]
fn writable_namespace_child() {
    use std::os::unix::ffi::OsStrExt;
    fn mount(target: &Path, flags: libc::c_ulong) {
        let target = std::ffi::CString::new(target.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe {
                libc::mount(
                    c"tmpfs".as_ptr(),
                    target.as_ptr(),
                    c"tmpfs".as_ptr(),
                    flags,
                    c"mode=0700,size=1048576".as_ptr().cast(),
                )
            },
            0,
            "{}",
            std::io::Error::last_os_error()
        );
    }
    let mut input = Vec::new();
    std::io::stdin()
        .take(65537)
        .read_to_end(&mut input)
        .unwrap();
    assert!(input.len() <= 65536);
    let (staging, socket): (std::path::PathBuf, std::path::PathBuf) =
        serde_json::from_slice(&input).unwrap();
    assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNS) }, 0);
    assert_eq!(
        unsafe {
            libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            )
        },
        0
    );
    mount(&staging, libc::MS_NOSUID | libc::MS_NODEV);
    for name in ["work", "nested/cache"] {
        fs::create_dir_all(staging.join(name)).unwrap();
        mount(
            &staging.join(name),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        );
    }
    fs::write(staging.join("work/value"), b"first-native-mount").unwrap();
    fs::write(staging.join("nested/cache/value"), b"nested-native-mount").unwrap();
    std::os::unix::fs::symlink("value", staging.join("work/link")).unwrap();
    fs::write(staging.join("work/hard"), b"hardlinked").unwrap();
    fs::hard_link(staging.join("work/hard"), staging.join("work/alias")).unwrap();
    let root = File::open(&staging).unwrap();
    let mut stream = UnixStream::connect(socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let frame = crate::protocol::Frame {
        kind: crate::protocol::MessageKind::LaunchPrepared,
        nonce: [1; 16],
        attempt_id: [2; 16],
        payload: Vec::new(),
    };
    let mut bytes = Vec::new();
    crate::protocol::write_frame(&mut bytes, &frame).unwrap();
    crate::linux::transport::send(&stream, &bytes, &[root.as_raw_fd()]).unwrap();
    let mut release = [0];
    stream.read_exact(&mut release).unwrap();
    assert_eq!(release, *b"R");
    // Returning drops the last process-owned mount namespace; the parent has
    // only root/mount files, and its child observer proves native reap.
}
