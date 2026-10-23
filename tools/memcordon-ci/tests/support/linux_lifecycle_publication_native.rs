//! Actual runner-to-root fixture. Included privately by the production helper.
use super::*;
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const ROOT_TEST: &str = "release::linux_lifecycle_diagnostics::native_tests::root_publication_role";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Input {
    namespace: PathBuf,
    runner_uid: u32,
    device: u64,
    inode: u64,
    deadline_unix_millis: u64,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}

fn selection() -> (SourceIdentity, ProductKey) {
    (
        SourceIdentity {
            run_id: "mixed-uid-native-fixture".into(),
            source_commit: "1".repeat(40),
            source_tree_sha256: "2".repeat(64),
            version: "0.5.6".into(),
        },
        ProductKey {
            target: if cfg!(target_arch = "aarch64") {
                "aarch64-unknown-linux-gnu"
            } else {
                "x86_64-unknown-linux-gnu"
            }
            .into(),
            channel: "candidate-native".into(),
        },
    )
}

#[test]
fn runner_namespace_uses_actual_root_publication_role() {
    let uid = rustix::process::geteuid().as_raw();
    assert_ne!(
        uid, 0,
        "mixed-UID fixture must start as the actual CI runner"
    );
    let namespace = tempfile::Builder::new()
        .prefix("memcordon-publication-native-")
        .tempdir()
        .unwrap();
    std::fs::create_dir(namespace.path().join("runner-descendant")).unwrap();
    let metadata = std::fs::symlink_metadata(namespace.path()).unwrap();
    assert_eq!(metadata.uid(), uid);
    let cutoff = Instant::now() + Duration::from_secs(20);
    let input = Input {
        namespace: namespace.path().to_owned(),
        runner_uid: uid,
        device: metadata.dev(),
        inode: metadata.ino(),
        deadline_unix_millis: now() + 20_000,
    };
    let input_path = namespace.path().join("input.json");
    std::fs::write(&input_path, serde_json::to_vec(&input).unwrap()).unwrap();
    let input_file = File::open(&input_path).unwrap();
    let executable = std::env::current_exe().unwrap();
    let output = crate::command::CommandSpec::new(
        "sudo",
        &std::env::current_dir().unwrap(),
        Duration::from_secs(20),
    )
    .arg("-n")
    .arg(&executable)
    .args([
        "--exact",
        ROOT_TEST,
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ])
    .bounded_until(cutoff)
    .output_limit(64 * 1024)
    .output_quiet_with_stdin_and_creation(&input_file, |_| Ok(()))
    .unwrap();
    assert!(
        output.status.success(),
        "actual privileged fixture failed: status={:?} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("mixed-UID publication verified"));
}

fn exercise(input: &Input, held: &HeldCellPublication) -> Result<()> {
    let live = || {
        if now() < input.deadline_unix_millis {
            Ok(())
        } else {
            Err(CiError::Message(
                "original mixed-UID fixture cutoff expired".into(),
            ))
        }
    };
    live()?;
    let namespace = &held.mapping[0].1;
    let prefix = &held.mapping[2].1;
    let mut artifacts = Vec::new();
    let path = held.prefix().join("phase-journal.bin");
    let file = publish(held, &path, b"real mixed-UID publication", &mut artifacts)?;
    let metadata = file.metadata()?;
    if metadata.uid() != 0
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || artifacts.len() != 1
        || artifacts[0].path
            != format!(
                "{}/candidate-native/phase-journal.bin",
                selection().1.target
            )
    {
        return Err(CiError::Message(
            "mixed-UID actual publication identity/path differs".into(),
        ));
    }
    let source = rustix::fs::statat(
        namespace,
        "runner-descendant",
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|error| CiError::Message(error.to_string()))?;
    if source.st_uid != input.runner_uid {
        return Err(CiError::Message(
            "wrong-owner fixture was not created by original runner".into(),
        ));
    }
    rustix::fs::renameat(namespace, "runner-descendant", prefix, "wrong-owner")
        .map_err(|error| CiError::Message(error.to_string()))?;
    let wrong = publish(
        held,
        &held.prefix().join("wrong-owner/refused"),
        b"x",
        &mut artifacts,
    )
    .err()
    .ok_or_else(|| CiError::Message("accepted runner-owned privileged descendant".into()))?
    .to_string();
    if !wrong.contains("expected_uid=0")
        || !wrong.contains(&format!("observed_uid={}", input.runner_uid))
    {
        return Err(CiError::Message(format!(
            "wrong-owner metadata was not retained: {wrong}"
        )));
    }
    let original_mode = prefix.metadata()?.mode() & 0o7777;
    rustix::fs::fchmod(prefix, rustix::fs::Mode::from_raw_mode(0o777))
        .map_err(|error| CiError::Message(error.to_string()))?;
    let refused = publish(
        held,
        &held.prefix().join("writable-refused"),
        b"x",
        &mut artifacts,
    )
    .is_err();
    rustix::fs::fchmod(prefix, rustix::fs::Mode::from_raw_mode(original_mode))
        .map_err(|error| CiError::Message(error.to_string()))?;
    if !refused || artifacts.len() != 1 {
        return Err(CiError::Message(
            "writable controller prefix was admitted or rejection registered an artifact".into(),
        ));
    }
    live()?;
    held.verify()?;
    eprintln!(
        "real publication transport_uid={} controller_uid={} global_artifact={}",
        input.runner_uid, held.uid, artifacts[0].path
    );
    Ok(())
}

fn cleanup(held: &HeldCellPublication) -> Result<()> {
    held.verify()?;
    let prefix = &held.mapping[2].1;
    for (leaf, flags) in [
        ("phase-journal.bin", rustix::fs::AtFlags::empty()),
        ("wrong-owner", rustix::fs::AtFlags::REMOVEDIR),
    ] {
        match rustix::fs::unlinkat(prefix, leaf, flags) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => {}
            Err(error) => {
                return Err(CiError::Message(format!(
                    "native fixture cleanup {leaf}: {error}"
                )));
            }
        }
    }
    let target = &held.mapping[1].1;
    let channel = held.prefix().file_name().expect("fixed channel");
    let current = rustix::fs::statat(target, channel, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| CiError::Message(error.to_string()))?;
    let original =
        rustix::fs::fstat(prefix).map_err(|error| CiError::Message(error.to_string()))?;
    if (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino) {
        return Err(CiError::Message(
            "native fixture cleanup cell replaced".into(),
        ));
    }
    rustix::fs::unlinkat(target, channel, rustix::fs::AtFlags::REMOVEDIR)
        .map_err(|error| CiError::Message(error.to_string()))?;
    rustix::fs::unlinkat(
        target,
        "publication-target-owner.json",
        rustix::fs::AtFlags::empty(),
    )
    .map_err(|error| CiError::Message(error.to_string()))?;
    let target_name = held.mapping[1].0.file_name().expect("fixed target");
    let current = rustix::fs::statat(
        &held.mapping[0].1,
        target_name,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|error| CiError::Message(error.to_string()))?;
    let original =
        rustix::fs::fstat(target).map_err(|error| CiError::Message(error.to_string()))?;
    if (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino) {
        return Err(CiError::Message(
            "native fixture cleanup target replaced".into(),
        ));
    }
    rustix::fs::unlinkat(
        &held.mapping[0].1,
        target_name,
        rustix::fs::AtFlags::REMOVEDIR,
    )
    .map_err(|error| CiError::Message(error.to_string()))?;
    Ok(())
}

#[test]
#[ignore = "invoked by runner fixture through exact privileged role"]
fn root_publication_role() {
    assert_eq!(rustix::process::geteuid().as_raw(), 0);
    assert!(
        std::env::args_os().skip(1).eq([
            "--exact",
            ROOT_TEST,
            "--ignored",
            "--nocapture",
            "--test-threads=1"
        ]
        .map(std::ffi::OsString::from))
    );
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(8193)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 8192);
    let input: Input = serde_json::from_slice(&bytes).unwrap();
    assert_ne!(input.runner_uid, 0);
    assert!(now() < input.deadline_unix_millis);
    let namespace = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&input.namespace)
        .unwrap();
    let metadata = namespace.metadata().unwrap();
    assert_eq!(
        (metadata.dev(), metadata.ino(), metadata.uid()),
        (input.device, input.inode, input.runner_uid)
    );
    let (identity, cell) = selection();
    let held = HeldCellPublication::create(&input.namespace, &identity, &cell).unwrap();
    let operation = exercise(&input, &held);
    let retired = cleanup(&held);
    assert!(
        operation.is_ok() && retired.is_ok(),
        "native mixed-UID operation={operation:?} cleanup={retired:?}"
    );
    println!("mixed-UID publication verified");
}
