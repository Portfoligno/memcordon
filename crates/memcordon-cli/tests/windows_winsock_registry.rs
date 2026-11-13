#![cfg(all(windows, feature = "test-fixtures"))]

#[path = "../src/bin/consumer_readiness_windows/controller_start.rs"]
pub mod controller_start;
mod descriptor {
    pub use super::controller_start;
}
#[path = "../src/bin/consumer_readiness_windows/fixture_default_dacl.rs"]
mod fixture_default_dacl;
#[path = "../src/bin/consumer_readiness_windows/matched_control_process.rs"]
mod matched_process;
#[path = "../src/bin/consumer_readiness_windows/native_fixture_default_dacl.rs"]
mod native_fixture_default_dacl;

fn native_birth(handle: windows_sys::Win32::Foundation::HANDLE) -> u64 {
    use windows_sys::Win32::{Foundation::FILETIME, System::Threading::GetProcessTimes};
    let mut birth = FILETIME::default();
    let mut exit = birth;
    let mut kernel = birth;
    let mut user = birth;
    // SAFETY: query a borrowed original live process into fixed native outputs.
    assert_ne!(
        unsafe { GetProcessTimes(handle, &mut birth, &mut exit, &mut kernel, &mut user) },
        0
    );
    u64::from(birth.dwHighDateTime) << 32 | u64::from(birth.dwLowDateTime)
}

fn native_clock() -> (i64, i64) {
    use windows_sys::Win32::System::Performance::{
        QueryPerformanceCounter, QueryPerformanceFrequency,
    };
    let mut now = 0;
    let mut frequency = 0;
    // SAFETY: fixed writable scalar outputs from the shared system QPC clock.
    assert_ne!(unsafe { QueryPerformanceCounter(&mut now) }, 0);
    assert_ne!(unsafe { QueryPerformanceFrequency(&mut frequency) }, 0);
    assert!(now >= 0 && frequency > 0);
    (now, frequency)
}
fn original_instant(cutoff: i64, frequency: i64) -> std::time::Instant {
    let (now, actual) = native_clock();
    assert_eq!(actual, frequency);
    assert!(now < cutoff);
    std::time::Instant::now()
        + std::time::Duration::from_secs_f64((cutoff - now) as f64 / frequency as f64)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct AdmissionTestInput {
    ready: std::path::PathBuf,
    work: i64,
    cleanup: i64,
    frequency: i64,
}
#[derive(serde::Serialize, serde::Deserialize)]
struct AdmissionTestReady {
    ready: controller_start::ProviderDirectReady,
    wrong_object: u64,
}

fn check_actual_committed_publication(
    ready: &controller_start::ProviderDirectReady,
    path: &std::path::Path,
) {
    use std::{
        io::{Read, Seek, Write},
        os::windows::fs::OpenOptionsExt,
    };
    let bytes = ready.committed_bytes().unwrap();
    let mut original = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(1)
        .open(path)
        .unwrap();
    let mut reader = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(3)
        .open(path)
        .unwrap();
    let mut previous = 0;
    for extent in [0, 3, 4, bytes.len() - 40, bytes.len() - 1, bytes.len()] {
        original.write_all(&bytes[previous..extent]).unwrap();
        original.sync_all().unwrap();
        previous = extent;
        reader.rewind().unwrap();
        let mut observed = vec![];
        (&mut reader)
            .take((controller_start::MAX_PROVIDER_READY_BYTES + 45) as u64)
            .read_to_end(&mut observed)
            .unwrap();
        let decoded =
            controller_start::ProviderDirectReady::from_committed_prefix(&observed).unwrap();
        assert_eq!(decoded.is_some(), extent == bytes.len());
        if let Some(decoded) = decoded {
            assert!(
                decoded.original_process_reference == ready.original_process_reference,
                "committed private reference changed"
            );
            assert_eq!(decoded.direct, ready.direct);
        }
    }
}

fn check_atomic_ready_publisher(
    ready: &controller_start::ProviderDirectReady,
    path: &std::path::Path,
    work: std::time::Instant,
) {
    use std::{
        io::{Read, Seek, Write},
        os::windows::fs::OpenOptionsExt,
    };
    let live = || {
        if std::time::Instant::now() < work {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "original Ready test cutoff",
            ))
        }
    };
    let mut owner = ready.publish(path, live).unwrap();
    let identity = memcordon_testkit::windows_held_file_metadata(&owner).unwrap();
    assert!(!path.with_extension("ready-pending").try_exists().unwrap());
    let mut bytes = vec![];
    owner.rewind().unwrap();
    (&mut owner)
        .take((controller_start::MAX_PROVIDER_READY_BYTES + 45) as u64)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(
        bytes == ready.committed_bytes().unwrap(),
        "atomic Ready exact bytes differ"
    );
    assert!(
        controller_start::ProviderDirectReady::from_committed_prefix(&bytes)
            .unwrap()
            .is_some()
    );
    let reader = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(3)
        .open(path)
        .unwrap();
    assert_eq!(
        memcordon_testkit::windows_held_file_metadata(&reader)
            .unwrap()
            .file_index,
        identity.file_index
    );
    assert_eq!(
        std::fs::OpenOptions::new()
            .write(true)
            .share_mode(3)
            .open(path)
            .err()
            .expect("original sharing boundary must reject access")
            .raw_os_error(),
        Some(32)
    );
    assert_eq!(
        std::fs::OpenOptions::new()
            .read(true)
            .access_mode(0x10080)
            .share_mode(3)
            .open(path)
            .err()
            .expect("original sharing boundary must reject access")
            .raw_os_error(),
        Some(32)
    );
    let existing = ready
        .publish(path, live)
        .err()
        .expect("existing Ready must not be replaced");
    assert_eq!(
        memcordon_testkit::windows_held_file_metadata(&owner)
            .unwrap()
            .file_index,
        identity.file_index
    );
    owner.rewind().unwrap();
    let mut after = vec![];
    (&mut owner)
        .take((controller_start::MAX_PROVIDER_READY_BYTES + 45) as u64)
        .read_to_end(&mut after)
        .unwrap();
    assert!(after == bytes, "existing final Ready changed after refusal");
    assert!(path.with_extension("ready-pending").is_file());
    let conflict = path.with_file_name("already-owned-pending.bin");
    let pending = conflict.with_extension("ready-pending");
    let mut original = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(1)
        .open(&pending)
        .unwrap();
    original.write_all(b"untouched pending owner").unwrap();
    original.sync_all().unwrap();
    let pending_identity = memcordon_testkit::windows_held_file_metadata(&original).unwrap();
    assert!(ready.publish(&conflict, live).is_err());
    assert!(!conflict.try_exists().unwrap());
    assert_eq!(
        memcordon_testkit::windows_held_file_metadata(&original)
            .unwrap()
            .file_index,
        pending_identity.file_index
    );
    original.rewind().unwrap();
    let mut retained = vec![];
    original.read_to_end(&mut retained).unwrap();
    assert_eq!(retained, b"untouched pending owner");
    drop(existing);
    drop(reader);
    drop(owner);
    let cleanup = std::fs::OpenOptions::new()
        .write(true)
        .share_mode(3)
        .open(path)
        .unwrap();
    drop(cleanup);
}

#[test]
#[ignore = "private original broker for native direct-reference admission"]
fn original_direct_reference_broker() {
    use std::{
        io::{BufRead, Read, Write},
        os::windows::{
            ffi::OsStrExt,
            fs::OpenOptionsExt,
            io::{AsRawHandle, FromRawHandle, OwnedHandle},
        },
    };
    use windows_sys::Win32::{
        Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation},
        Security::TOKEN_ALL_ACCESS,
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    let mut source = std::io::stdin().lock().take(16 * 1024);
    let mut line = String::new();
    source.read_line(&mut line).unwrap();
    assert!(line.len() < 16 * 1024);
    let input: AdmissionTestInput = serde_json::from_str(&line).unwrap();
    let work = original_instant(input.work, input.frequency);
    let cleanup = original_instant(input.cleanup, input.frequency);
    let image = std::env::current_exe().unwrap();
    let held = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&image)
        .unwrap();
    let wrong_image = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(input.ready.with_extension("unrelated-image"))
        .unwrap();
    let mut caller = matched_process::Caller::select(false, vec![], work, |restricted| {
        assert!(!restricted);
        let mut source = std::ptr::null_mut();
        let mut derived = std::ptr::null_mut();
        // SAFETY: acquire two actual current-primary owners, with no enabling,
        // replacement token or fabricated snapshot in this ordinary control.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut source) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let source = unsafe { OwnedHandle::from_raw_handle(source) };
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut derived) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok((source, unsafe { OwnedHandle::from_raw_handle(derived) }))
    })
    .unwrap();
    matched_process::Caller::retain_inputs(
        &mut caller,
        vec![held, wrong_image.try_clone().unwrap()],
    )
    .unwrap();
    caller.verify_unchanged(work).unwrap();
    let measurement = caller.measurement();
    assert!(
        measurement["source"] == measurement["selected"],
        "ordinary caller snapshot changed"
    );
    use sha2::Digest;
    let acl = caller.default_acl().unwrap();
    assert!(!acl.is_empty());
    assert_eq!(
        measurement["selected"]["default_acl_sha256"],
        serde_json::json!(<[u8; 32]>::from(sha2::Sha256::digest(acl)))
    );
    let negative_job = matched_process::Job::create(work).unwrap();
    let stdio: Vec<_> = (0..3)
        .map(|_| {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("NUL")
                .unwrap();
            // SAFETY: only this fixture-owned stdio reference becomes inheritable;
            // the production HANDLE_LIST still bounds actual child inheritance.
            assert_ne!(
                unsafe {
                    SetHandleInformation(
                        file.as_raw_handle(),
                        HANDLE_FLAG_INHERIT,
                        HANDLE_FLAG_INHERIT,
                    )
                },
                0
            );
            file
        })
        .collect();
    let environment = std::env::vars_os()
        .map(|(name, value)| memcordon_core::WindowsEnvironmentEntryV1 {
            name: name.encode_wide().collect(),
            value: value.encode_wide().collect(),
        })
        .collect::<Vec<_>>();
    let args = vec![
        image.clone().into_os_string(),
        "--exact".into(),
        "registry_direct_recipient".into(),
        "--ignored".into(),
    ];
    let rejected = matched_process::Process::create(
        caller.clone(),
        matched_process::Launch {
            image_role: matched_process::Image::Frontend,
            image: &image,
            argv: &args,
            environment: &environment,
            cwd: input.ready.parent().unwrap(),
            stdio: [
                stdio[0].as_raw_handle(),
                stdio[1].as_raw_handle(),
                stdio[2].as_raw_handle(),
            ],
            job: Some(negative_job.clone()),
            work,
            cleanup,
        },
    );
    let rejected = rejected
        .err()
        .expect("unrelated held frontend image must reject");
    assert!(rejected.to_string().contains("same held immutable input"));
    assert_eq!(negative_job.active(work).unwrap(), 0);
    drop(negative_job);
    let job = matched_process::Job::create(work).unwrap();
    let mut direct = matched_process::Process::create(
        caller.clone(),
        matched_process::Launch {
            image_role: matched_process::Image::Fixture,
            image: &image,
            argv: &args,
            environment: &environment,
            cwd: input.ready.parent().unwrap(),
            stdio: [
                stdio[0].as_raw_handle(),
                stdio[1].as_raw_handle(),
                stdio[2].as_raw_handle(),
            ],
            job: Some(job),
            work,
            cleanup,
        },
    )
    .unwrap();
    assert!(direct.needs_settlement());
    assert!(
        matched_process::Caller::retain_inputs(&mut caller, vec![wrong_image.try_clone().unwrap()])
            .is_err()
    );
    caller.verify_unchanged(work).unwrap();
    use windows_sys::Win32::System::Registry::{
        HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, RegCloseKey, RegCreateKeyExW,
    };
    let key_name: Vec<_> = format!(
        "Software\\memcordon-direct-test-{}-{}",
        std::process::id(),
        input.work
    )
    .encode_utf16()
    .chain(Some(0))
    .collect();
    let mut key = std::ptr::null_mut();
    let mut disposition = 0;
    assert_eq!(
        unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                key_name.as_ptr(),
                0,
                std::ptr::null(),
                0,
                KEY_READ | KEY_WRITE | 0x10000,
                std::ptr::null(),
                &mut key,
                &mut disposition,
            )
        },
        0
    );
    struct Key(windows_sys::Win32::System::Registry::HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            unsafe { RegCloseKey(self.0) };
        }
    }
    let key = Key(key);
    assert_eq!(disposition, 1);
    let source_name: Vec<_> = "source-owned".encode_utf16().chain(Some(0)).collect();
    assert_eq!(
        unsafe {
            windows_sys::Win32::System::Registry::RegSetValueExW(
                key.0,
                source_name.as_ptr(),
                0,
                windows_sys::Win32::System::Registry::REG_DWORD,
                1u32.to_le_bytes().as_ptr(),
                4,
            )
        },
        0
    );
    let recipient_key = direct
        .duplicate_registry(key.0 as usize as u64, work)
        .unwrap();
    std::fs::write(
        input.ready.parent().unwrap().join("key-transfer.bin"),
        recipient_key.to_le_bytes(),
    )
    .unwrap();
    // Process::create uses the actual suspended, creation-time Job-list path.
    let broker = controller_start::BrokerIdentity {
        pid: std::process::id(),
        birth: native_birth(unsafe { GetCurrentProcess() }),
    };
    let mut owner = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(1)
        .open(&input.ready)
        .unwrap();
    let ready = AdmissionTestReady {
        ready: controller_start::ProviderDirectReady {
            revision: 1,
            scope: controller_start::ProviderControlScope::ListenerSelection,
            broker,
            direct: controller_start::BrokerIdentity {
                pid: direct.pid,
                birth: direct.birth,
            },
            pair_sha256: [1; 32],
            input_sha256: [2; 32],
            direct_descriptor_sha256: [3; 32],
            selected_token_sha256: caller.token_hash(work).unwrap(),
            original_process_reference: direct.original_process_reference(work).unwrap(),
            qpc_frequency: input.frequency as u64,
            cutoff_qpc: input.work as u64,
        },
        wrong_object: owner.as_raw_handle() as usize as u64,
    };
    owner
        .write_all(&serde_json::to_vec(&ready).unwrap())
        .unwrap();
    owner.sync_all().unwrap();
    // Test-only finite coordination; raw references remain private, not stdout.
    std::fs::write(input.ready.with_extension("published"), b"ready").unwrap();
    let mut finish = [0];
    source.read_exact(&mut finish).unwrap();
    assert_eq!(finish, [1]);
    direct.resume(work).unwrap();
    assert_eq!(direct.settle(cleanup).unwrap(), 0);
    assert!(!direct.needs_settlement());
    caller.verify_unchanged(work).unwrap();
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtDeleteKey(key: windows_sys::Win32::System::Registry::HKEY) -> i32;
    }
    assert_eq!(unsafe { NtDeleteKey(key.0) }, 0);
    drop(owner);
}

#[test]
#[ignore = "private direct recipient for exact KEY_READ capability exercise"]
fn registry_direct_recipient() {
    use windows_sys::Win32::System::Registry::{
        REG_DWORD, RegCloseKey, RegQueryInfoKeyW, RegSetValueExW,
    };
    let bytes = std::fs::read(std::env::current_dir().unwrap().join("key-transfer.bin")).unwrap();
    let raw = u64::from_le_bytes(bytes.try_into().unwrap());
    let key = raw as usize as windows_sys::Win32::System::Registry::HKEY;
    struct Key(windows_sys::Win32::System::Registry::HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            unsafe { RegCloseKey(self.0) };
        }
    }
    let key = Key(key);
    assert_eq!(
        unsafe {
            RegQueryInfoKeyW(
                key.0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        },
        0
    );
    let name: Vec<_> = "not-permitted".encode_utf16().chain(Some(0)).collect();
    let value = 1u32.to_le_bytes();
    assert_eq!(
        unsafe { RegSetValueExW(key.0, name.as_ptr(), 0, REG_DWORD, value.as_ptr(), 4) },
        5
    );
    drop(key);
}

#[test]
fn ready_native_sharing_allows_the_controller_reader_but_blocks_new_writers_and_delete_access() {
    use std::{io::Write, os::windows::fs::OpenOptionsExt};
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("ready.bin");
    let mut original = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(1)
        .open(&path)
        .unwrap();
    original.write_all(b"committed fixture bytes").unwrap();
    original.sync_all().unwrap();
    assert_eq!(
        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(&path)
            .err()
            .expect("original sharing boundary must reject access")
            .raw_os_error(),
        Some(32)
    );
    let reader = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(3)
        .open(&path)
        .unwrap();
    assert_eq!(
        std::fs::OpenOptions::new()
            .write(true)
            .share_mode(3)
            .open(&path)
            .err()
            .expect("original sharing boundary must reject access")
            .raw_os_error(),
        Some(32)
    );
    assert_eq!(
        std::fs::OpenOptions::new()
            .read(true)
            .access_mode(0x10080)
            .share_mode(3)
            .open(&path)
            .err()
            .expect("original sharing boundary must reject access")
            .raw_os_error(),
        Some(32)
    );
    assert_eq!(
        memcordon_testkit::windows_held_file_metadata(&original)
            .unwrap()
            .file_index,
        memcordon_testkit::windows_held_file_metadata(&reader)
            .unwrap()
            .file_index
    );
}

#[test]
fn native_original_direct_reference_admission_rejects_stale_or_unrelated_authority_and_retires_exact_child()
 {
    use memcordon_platform::test_support::{ProcessIdentity, WindowsImageProcess};
    use std::{
        io::{Read, Seek, Write},
        os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    use windows_sys::Win32::{Foundation::WAIT_OBJECT_0, System::Threading::WaitForSingleObject};
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("private-ready.bin");
    let (now, frequency) = native_clock();
    let input = AdmissionTestInput {
        ready: path.clone(),
        work: now + frequency * 20,
        cleanup: now + frequency * 30,
        frequency,
    };
    let work = original_instant(input.work, frequency);
    let cleanup = original_instant(input.cleanup, frequency);
    let mut stderr = tempfile::tempfile().unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "original_direct_reference_broker", "--ignored"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr.try_clone().unwrap()))
        .spawn()
        .unwrap();
    struct Broker(std::process::Child);
    impl Drop for Broker {
        fn drop(&mut self) {
            let _ = self.0.kill();
        }
    }
    let mut child = Broker(child);
    let broker_id = ProcessIdentity {
        pid: child.0.id(),
        birth: u128::from(native_birth(child.0.as_raw_handle())),
    };
    let mut stale = broker_id;
    stale.birth += 1;
    assert!(WindowsImageProcess::from_original_child(&child.0, stale, work).is_err());
    stale = broker_id;
    stale.pid += 1;
    assert!(WindowsImageProcess::from_original_child(&child.0, stale, work).is_err());
    let broker = WindowsImageProcess::from_original_child(&child.0, broker_id, work).unwrap();
    let mut wire = serde_json::to_vec(&input).unwrap();
    wire.push(b'\n');
    child.0.stdin.as_mut().unwrap().write_all(&wire).unwrap();
    while !path.with_extension("published").try_exists().unwrap() {
        assert!(Instant::now() < work);
        if broker.has_exited().unwrap() {
            stderr.rewind().unwrap();
            let mut error = vec![];
            (&mut stderr).take(65537).read_to_end(&mut error).unwrap();
            assert!(error.len() <= 65536);
            panic!(
                "original native broker failed: {}",
                String::from_utf8_lossy(&error)
            );
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(3)
        .open(&path)
        .unwrap();
    let mut bytes = Vec::new();
    (&mut file).take(8193).read_to_end(&mut bytes).unwrap();
    assert!(bytes.len() <= 8192);
    let ready: AdmissionTestReady = serde_json::from_slice(&bytes).unwrap();
    check_actual_committed_publication(&ready.ready, &path.with_extension("committed"));
    check_atomic_ready_publisher(&ready.ready, &path.with_file_name("atomic-ready.bin"), work);
    let identity = ProcessIdentity {
        pid: ready.ready.direct.pid,
        birth: u128::from(ready.ready.direct.birth),
    };
    let image = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(std::env::current_exe().unwrap())
        .unwrap();
    let wrong = tempfile::tempfile().unwrap();
    let mut pending = Vec::new();
    for field in ["pid", "birth", "image", "token", "cutoff"] {
        let owner = broker
            .duplicate_pending_direct_root(ready.ready.original_process_reference, work)
            .unwrap();
        let mut expected = identity;
        let mut token = ready.ready.selected_token_sha256;
        let mut cutoff = work;
        let mut fixture = &image;
        match field {
            "pid" => expected.pid += 1,
            "birth" => expected.birth += 1,
            "image" => fixture = &wrong,
            "token" => token[0] ^= 1,
            "cutoff" => cutoff = Instant::now() - Duration::from_millis(1),
            _ => unreachable!(),
        }
        assert!(
            owner
                .admit_selected_direct_root(&broker, expected, fixture, &token, cutoff)
                .is_err(),
            "{field}"
        );
        pending.push((owner, field == "cutoff"));
    }
    if let Ok(owner) = broker.duplicate_pending_direct_root(ready.wrong_object, work) {
        assert!(
            owner
                .admit_selected_direct_root(
                    &broker,
                    identity,
                    &image,
                    &ready.ready.selected_token_sha256,
                    work
                )
                .is_err()
        );
        drop(owner);
    }
    assert!(
        broker
            .duplicate_pending_direct_root(
                ready.ready.original_process_reference,
                Instant::now() - Duration::from_millis(1)
            )
            .is_err()
    );
    let owner = broker
        .duplicate_pending_direct_root(ready.ready.original_process_reference, work)
        .unwrap();
    let direct = owner
        .admit_selected_direct_root(
            &broker,
            identity,
            &image,
            &ready.ready.selected_token_sha256,
            work,
        )
        .unwrap();
    assert!(!direct.has_exited().unwrap());
    child.0.stdin.as_mut().unwrap().write_all(&[1]).unwrap();
    drop(child.0.stdin.take());
    let remaining = cleanup
        .saturating_duration_since(Instant::now())
        .as_millis()
        .min(u128::from(u32::MAX - 1)) as u32;
    assert_eq!(
        unsafe { WaitForSingleObject(child.0.as_raw_handle(), remaining) },
        WAIT_OBJECT_0
    );
    let status = child.0.wait().unwrap();
    if !status.success() {
        stderr.rewind().unwrap();
        let mut error = vec![];
        (&mut stderr).take(65537).read_to_end(&mut error).unwrap();
        assert!(error.len() <= 65536);
        panic!(
            "original native broker failed: {}",
            String::from_utf8_lossy(&error)
        );
    }
    assert!(direct.has_exited().unwrap());
    assert!(owner.has_exited().unwrap());
    for (owner, unqueried) in pending {
        // A different admitted reference cannot upgrade an unqueried owner.
        if unqueried {
            assert!(owner.has_exited().is_err());
        } else {
            assert!(owner.has_exited().unwrap());
        }
        drop(owner);
    }
    assert!(broker.has_exited().unwrap());
}

#[test]
#[ignore = "private stdin-blocked original recipient for the transfer test"]
fn registry_original_recipient() {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::io::stdin().read_to_end(&mut bytes).unwrap();
    assert!(bytes.is_empty());
}

#[test]
fn registry_transfer_is_bound_to_original_live_child_and_keeps_debt_until_native_retirement() {
    use std::{
        os::windows::io::AsRawHandle,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    use windows_sys::Win32::{
        Foundation::{FILETIME, WAIT_OBJECT_0},
        System::Threading::{GetProcessTimes, WaitForSingleObject},
    };
    let started = Instant::now();
    let work = started + Duration::from_secs(10);
    let cleanup = started + Duration::from_secs(20);
    let unique = format!(
        "{:08x}{:032x}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let mut projection =
        memcordon_testkit::WindowsWinsockRegistryProjection::create(&unique, work, cleanup)
            .unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "registry_original_recipient", "--ignored"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    struct Owner(std::process::Child);
    impl Drop for Owner {
        fn drop(&mut self) {
            let _ = self.0.kill();
        }
    }
    let mut child = Owner(child);
    let mut created = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exited = created;
    let mut kernel = created;
    let mut user = created;
    // SAFETY: query the original retained Child process handle into fixed outputs.
    assert_ne!(
        unsafe {
            GetProcessTimes(
                child.0.as_raw_handle(),
                &mut created,
                &mut exited,
                &mut kernel,
                &mut user,
            )
        },
        0
    );
    let birth = u64::from(created.dwHighDateTime) << 32 | u64::from(created.dwLowDateTime);
    let pid = child.0.id();
    assert!(
        projection
            .duplicate_into_child(&child.0, pid.wrapping_add(1), birth, work)
            .is_err()
    );
    assert!(
        projection
            .duplicate_into_child(&child.0, pid, birth.wrapping_add(1), work)
            .is_err()
    );
    assert!(
        projection
            .duplicate_into_child(&child.0, pid, birth, work + Duration::from_millis(1))
            .is_err()
    );
    let recipient_relative = projection
        .duplicate_into_child(&child.0, pid, birth, work)
        .unwrap();
    assert_ne!(recipient_relative, 0); // Never adopt or close a child-relative scalar here.
    assert!(projection.retire_if_safe().is_err());
    std::thread::sleep(work.saturating_duration_since(Instant::now()));
    assert!(
        projection
            .duplicate_into_child(&child.0, pid, birth, work)
            .is_err()
    );
    drop(child.0.stdin.take());
    let remaining = cleanup
        .saturating_duration_since(Instant::now())
        .as_millis()
        .min(u128::from(u32::MAX - 1)) as u32;
    // SAFETY: wait only on the same held recipient, within original cleanup cutoff.
    assert_eq!(
        unsafe { WaitForSingleObject(child.0.as_raw_handle(), remaining) },
        WAIT_OBJECT_0
    );
    assert!(child.0.wait().unwrap().success());
    projection.recipients_retired();
    projection.retire_if_safe().unwrap();
}

#[test]
fn owned_registry_projection_preserves_restricted_reads_and_refuses_mutation() {
    let fixture = env!("CARGO_BIN_EXE_memcordon-test-fixture");
    let mut command = std::process::Command::new(fixture);
    command
        .stdin(std::process::Stdio::null())
        .args(["consumer-readiness-windows", "winsock-registry-self-check"]);
    let output = memcordon_testkit::run_with_deadline_output_limit(
        &mut command,
        std::time::Duration::from_secs(10),
        64 * 1024,
    )
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
