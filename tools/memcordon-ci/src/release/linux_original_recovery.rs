//! Genuine private measured-fixture recovery and retained native process evidence.
#[path = "../../../../crates/memcordon-cli/src/bin/original_native_recovery_contract.rs"]
pub mod contract;
use super::{artifacts, linux_recovery_harness::HeldRecoveryHarness};
use crate::{CiError, Result, command::CommandSpec, linux_consumer_readiness::HeldLinuxProcess};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    os::unix::process::ExitStatusExt,
    path::Path,
    time::{Duration, Instant},
};

pub struct ObservedRecovery {
    pub invocation: serde_json::Value,
    pub process: serde_json::Value,
    pub capture: serde_json::Value,
    pub input_bytes: Vec<u8>,
    pub result_bytes: Vec<u8>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub result: contract::RecoveryResult,
    pub original_fixture: serde_json::Value,
}
impl ObservedRecovery {
    pub fn proof(&self) -> &serde_json::Value {
        &self.original_fixture
    }
}
fn create(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(
        path.parent()
            .ok_or_else(|| CiError::Message("original recovery record parent absent".into()))?,
    )?
    .sync_all()?;
    Ok(())
}
pub fn record(path: &Path) -> Result<contract::Record> {
    let bytes = super::linux_mixed_installed::read_owned_resource(path, contract::RECORD_BOUND)?;
    Ok(contract::Record {
        path: path.to_owned(),
        length: bytes.len() as u64,
        sha256: artifacts::checksum(&bytes),
    })
}
pub fn run(
    harness: &HeldRecoveryHarness,
    input: &contract::Input,
    deadline: Instant,
) -> Result<ObservedRecovery> {
    harness.verify()?;
    if input.recovery_harness_owner_sha256 != harness.owner_sha256()?
        || input.scope_id != harness.owner().scope_id
        || input.identity.run_id != harness.owner().identity.run_id
        || input.identity.source_commit != harness.owner().identity.source_commit
        || input.identity.source_tree_sha256 != harness.owner().identity.source_tree_sha256
        || input.identity.version != harness.owner().identity.version
        || input.native_target != harness.owner().cell.target
        || input.work_deadline_unix_millis != harness.owner().work_deadline_unix_millis
        || input.cleanup_deadline_unix_millis != harness.owner().cleanup_deadline_unix_millis
        || Instant::now() >= deadline
    {
        return Err(CiError::Message(
            "original recovery harness/source/deadline association differs".into(),
        ));
    }
    let original_root = input.artifact_root.clone();
    let stage_parent = harness
        .owner()
        .owner_path
        .parent()
        .ok_or_else(|| CiError::Message("original recovery staging parent absent".into()))?;
    let _stage_ancestry = super::linux_native_component::protected_directory(stage_parent)?;
    let stage = tempfile::Builder::new()
        .prefix("original-recovery-")
        .tempdir_in(stage_parent)?
        .keep();
    let mut input = input.clone();
    input.original_artifact_root = original_root.clone();
    input.artifact_root = stage.clone();
    let mut origin_records = serde_json::Map::new();
    let mut originals = Vec::new();
    for (role, reference) in input.context.records_mut() {
        let original_path = reference.path.clone();
        let mut source = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&original_path)?;
        let before = source.metadata()?;
        if !before.is_file()
            || before.uid() != 0
            || before.nlink() != 1
            || before.mode() & 0o022 != 0
            || before.len() != reference.length
            || before.len() > contract::RECORD_BOUND
        {
            return Err(CiError::Message(
                "original recovery source record custody differs".into(),
            ));
        }
        let mut bytes = Vec::new();
        std::io::Read::by_ref(&mut source)
            .take(contract::RECORD_BOUND + 1)
            .read_to_end(&mut bytes)?;
        if stamp(&before) != stamp(&source.metadata()?)
            || stamp(&before) != stamp(&std::fs::symlink_metadata(&original_path)?)
            || bytes.len() as u64 != before.len()
            || artifacts::checksum(&bytes) != reference.sha256
        {
            return Err(CiError::Message(
                "original recovery source changed before staging".into(),
            ));
        }
        let staged_path = stage.join(format!("input-{role}.bin"));
        create(&staged_path, &bytes)?;
        origin_records.insert(
            role.into(),
            serde_json::json!({"original_path":original_path,"staged_path":staged_path,
            "length":reference.length,"sha256":reference.sha256,"native_identity":stamp(&before)}),
        );
        originals.push((original_path, source, before));
        reference.path = staged_path;
    }
    let origin_bytes = serde_json::to_vec(
        &serde_json::json!({"format":"memcordon.original-native-recovery-origin","revision":1,
        "original_artifact_root":original_root,"records":origin_records}),
    )?;
    create(
        &stage.join("original-native-recovery-origin.json"),
        &origin_bytes,
    )?;
    input.origin_sha256 = artifacts::checksum(&origin_bytes);
    let input_bytes = serde_json::to_vec(&input)?;
    contract::Input::decode(&input_bytes)
        .map_err(CiError::Message)?
        .validate(&stage, unix_millis()?)
        .map_err(CiError::Message)?;
    let retained_attempt = original_root.join(
        stage
            .file_name()
            .ok_or_else(|| CiError::Message("original recovery stage leaf absent".into()))?,
    );
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&retained_attempt)?;
    File::open(&original_root)?.sync_all()?;
    create(
        &retained_attempt.join("stage.json"),
        &serde_json::to_vec(&serde_json::json!({
        "stage":stage,"input_sha256":artifacts::checksum(&input_bytes),"origin_sha256":input.origin_sha256}))?,
    )?;
    let root = &input.artifact_root;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)?;
    let directory_identity = directory.metadata()?;
    if directory_identity.uid() != 0 || directory_identity.mode() & 0o022 != 0 {
        return Err(CiError::Message(
            "original recovery case directory is not protected".into(),
        ));
    }
    let input_path = root.join("original-native-recovery-input.json");
    create(&input_path, &input_bytes)?;
    let stdin = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&input_path)?;
    let owner_bytes = super::linux_mixed_installed::read_owned_resource(
        &harness.owner().owner_path,
        16 * 1024 * 1024,
    )?;
    if artifacts::checksum(&owner_bytes) != input.recovery_harness_owner_sha256 {
        return Err(CiError::Message(
            "original recovery owner bytes changed".into(),
        ));
    }
    create(
        &root.join("original-native-recovery-owner.json"),
        &owner_bytes,
    )?;
    let arguments = [
        "--exact",
        contract::TEST_NAME,
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ];
    let invocation = serde_json::json!({"format":"memcordon.original-native-recovery-invocation","revision":1,
        "identity":input.identity,"native_target":input.native_target,"scope_id":input.scope_id,
        "program":harness.harness().executable,"arguments":arguments,"working_directory":root,
        "input_sha256":artifacts::checksum(&input_bytes),"harness_owner_sha256":input.recovery_harness_owner_sha256,
        "executable_sha256":harness.harness().sha256,"cleared_environment":true,"timeout_millis":300000,
        "work_deadline_unix_millis":input.work_deadline_unix_millis,"cleanup_deadline_unix_millis":input.cleanup_deadline_unix_millis});
    let invocation_bytes = serde_json::to_vec(&invocation)?;
    create(
        &root.join("original-native-recovery-invocation.json"),
        &invocation_bytes,
    )?;
    let mut held = None;
    let mut creation = None;
    let observed = CommandSpec::new(&harness.harness().executable, root, Duration::from_secs(300))
        .args(arguments).cleared_environment().bounded_until(deadline).output_limit(4 * 1024 * 1024)
        .output_quiet_with_stdin_and_creation(&stdin, |child| {
            let birth = crate::linux_consumer_readiness::process_birth(child.id()).map_err(CiError::Message)?;
            let mut process = HeldLinuxProcess::acquire(child.id(), birth).map_err(CiError::Message)?;
            let image = process.hold_executable_image(deadline).map_err(CiError::Message)?;
            if image["sha256"] != harness.harness().sha256
                || image["device"] != harness.owner().device || image["inode"] != harness.owner().inode {
                return Err(CiError::Message("original recovery process image differs from measured harness".into()));
            }
            creation = Some(serde_json::json!({"identity":process.retirement_identity().map_err(CiError::Message)?,"image":image}));
            held = Some(process);
            Ok(())
        })?;
    create(
        &root.join("original-native-recovery-stdout.bin"),
        &observed.stdout,
    )?;
    create(
        &root.join("original-native-recovery-stderr.bin"),
        &observed.stderr,
    )?;
    let process = held
        .as_ref()
        .ok_or_else(|| CiError::Message("original recovery process owner absent".into()))?;
    let retired = process.exited().map_err(CiError::Message)?;
    let process = serde_json::json!({"format":"memcordon.original-native-recovery-process","revision":1,
        "invocation_sha256":artifacts::checksum(&invocation_bytes),"creation":creation,
        "native_wait_status":observed.status.into_raw(),"status":observed.status.code(),
        "retirement":process.retirement_identity().map_err(CiError::Message)?,"pidfd_retirement_observed":retired});
    create(
        &root.join("original-native-recovery-process.json"),
        &serde_json::to_vec(&process)?,
    )?;
    let capture = serde_json::json!({"format":"memcordon.original-native-recovery-capture","revision":1,
        "invocation_sha256":artifacts::checksum(&invocation_bytes),"input_sha256":artifacts::checksum(&input_bytes),
        "status":observed.status.code(),"native_wait_status":observed.status.into_raw(),
        "stdout_sha256":artifacts::checksum(&observed.stdout),"stderr_sha256":artifacts::checksum(&observed.stderr)});
    create(
        &root.join("original-native-recovery-capture.json"),
        &serde_json::to_vec(&capture)?,
    )?;
    for (path, file, before) in &originals {
        if stamp(before) != stamp(&file.metadata()?)
            || stamp(before) != stamp(&std::fs::symlink_metadata(path)?)
        {
            return Err(CiError::Message(
                "original recovery source changed during native recovery".into(),
            ));
        }
    }
    for leaf in [
        "original-native-recovery-origin.json",
        "original-native-recovery-input.json",
        "original-native-recovery-owner.json",
        "original-native-recovery-invocation.json",
        "original-native-recovery-process.json",
        "original-native-recovery-capture.json",
        "original-native-recovery-stdout.bin",
        "original-native-recovery-stderr.bin",
        contract::RESULT_LEAF,
    ] {
        let path = root.join(leaf);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                let bytes =
                    super::linux_mixed_installed::read_owned_resource(&path, 16 * 1024 * 1024)?;
                create(&retained_attempt.join(leaf), &bytes)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    harness.verify()?;
    let named = std::fs::symlink_metadata(root)?;
    if (named.dev(), named.ino()) != (directory_identity.dev(), directory_identity.ino())
        || !named.is_dir()
        || !retired
        || !observed.status.success()
    {
        return Err(CiError::Message(
            "original measured recovery failed or original scope/process changed".into(),
        ));
    }
    let result_bytes = super::linux_mixed_installed::read_owned_resource(
        &root.join(contract::RESULT_LEAF),
        4 * 1024 * 1024,
    )?;
    memcordon_core::canonical_json::reject_duplicate_json_keys(&result_bytes)
        .map_err(CiError::Message)?;
    let result: contract::RecoveryResult = serde_json::from_slice(&result_bytes)?;
    if result.format != "memcordon.original-native-recovery-result"
        || result.revision != 1
        || result.input_sha256 != artifacts::checksum(&input_bytes)
        || result.context != input.context.kind()
        || result.identity != input.identity
        || result.native_target != input.native_target
        || result.scope_id != input.scope_id
        || result.recovery_harness_owner_sha256 != input.recovery_harness_owner_sha256
        || result.original_records
            != input
                .context
                .records()
                .iter()
                .map(|(role, record)| ((*role).to_owned(), record.sha256.clone()))
                .collect::<Vec<_>>()
        || !result.outstanding.is_empty()
        || !result.within_original_cleanup
        || result.completed_unix_millis >= input.cleanup_deadline_unix_millis
        || Instant::now() >= deadline
    {
        return Err(CiError::Message(
            "original measured recovery result retains obligations or differs from original input"
                .into(),
        ));
    }
    let mut projection = Vec::new();
    let mut sources = vec![
        (
            harness.owner().owner_path.clone(),
            "owner.json".to_owned(),
            1024 * 1024,
        ),
        (
            harness.owner().compiler_output.clone(),
            "cargo-output.jsonl".to_owned(),
            16 * 1024 * 1024,
        ),
        (
            harness.owner().compiler_errors.clone(),
            "cargo-stderr.bin".to_owned(),
            16 * 1024 * 1024,
        ),
    ];
    for (index, (path, _, bound)) in harness.owner().acquisition_records.iter().enumerate() {
        sources.push((path.clone(), format!("acquisition-{index}.bin"), *bound));
    }
    for (index, (path, leaf, bound)) in sources.into_iter().enumerate() {
        if index == 5 {
            let metadata = std::fs::symlink_metadata(&path)?;
            projection.push(
                serde_json::json!({"original":path,"artifact":leaf,"length":metadata.len(),
                "sha256":harness.owner().acquisition_records[2].1}),
            );
        } else {
            let bytes = super::linux_mixed_installed::read_owned_resource(&path, bound)?;
            projection.push(serde_json::json!({"original":path,"artifact":leaf,"length":bytes.len(),"sha256":artifacts::checksum(&bytes)}));
        }
    }
    harness.verify()?;
    let mut proof_capture = capture.clone();
    proof_capture["stdout"] = serde_json::to_value(&observed.stdout)?;
    proof_capture["stderr"] = serde_json::to_value(&observed.stderr)?;
    let original_fixture = serde_json::json!({"format":"memcordon.original-native-recovery-proof","revision":1,
        "capture":proof_capture,
        "invocation_bytes":invocation_bytes,"input_bytes":input_bytes,"result_bytes":result_bytes,
        "owner_bytes":owner_bytes,"origin_bytes":origin_bytes,
        "acquisition_projection":{"format":"memcordon.original-native-recovery-acquisition-projection","revision":1,
            "owner_sha256":input.recovery_harness_owner_sha256,"records":projection}});
    Ok(ObservedRecovery {
        original_fixture,
        invocation,
        process,
        capture,
        input_bytes,
        result_bytes,
        stdout: observed.stdout,
        stderr: observed.stderr,
        result,
    })
}

fn stamp(m: &std::fs::Metadata) -> (u64, u64, u64, u32, u32, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.uid(),
        m.mode(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn unix_millis() -> Result<u64> {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| CiError::Message(error.to_string()))?
            .as_millis(),
    )
    .map_err(|error| CiError::Message(error.to_string()))
}
