//! Original measured recovery uses production native ownership, never CLI admission.
#[path = "../../src/bin/original_native_recovery_checkpoint.rs"]
mod checkpoint;
#[path = "../../src/bin/original_native_recovery_contract.rs"]
pub(crate) mod contract;
#[path = "../../src/bin/original_native_recovery_delivery.rs"]
mod delivery;

use contract::{Context, Input, RecoveryResult};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn publish_failure(directory: &File, bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() > contract::FAILURE_BOUND {
        return Err("original recovery failure exceeds bound".into());
    }
    let mut file = File::from(
        rustix::fs::openat(
            directory,
            contract::FAILURE_LEAF,
            rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_raw_mode(0o600),
        )
        .map_err(|error| error.to_string())?,
    );
    let before = file.metadata().map_err(|error| error.to_string())?;
    if !before.is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || before.mode() & 0o7777 != 0o600
    {
        return Err("original recovery failure file custody differs".into());
    }
    file.write_all(bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    directory.sync_all().map_err(|error| error.to_string())?;
    let mut named = File::from(
        rustix::fs::openat(
            directory,
            contract::FAILURE_LEAF,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| error.to_string())?,
    );
    let after = named.metadata().map_err(|error| error.to_string())?;
    let mut readback = Vec::new();
    std::io::Read::by_ref(&mut named)
        .take(contract::FAILURE_BOUND as u64 + 1)
        .read_to_end(&mut readback)
        .map_err(|error| error.to_string())?;
    let final_held = named.metadata().map_err(|error| error.to_string())?;
    let final_named = rustix::fs::statat(
        directory,
        contract::FAILURE_LEAF,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|error| error.to_string())?;
    if final_held.dev() != after.dev()
        || final_held.ino() != after.ino()
        || final_held.len() != after.len()
        || final_held.ctime() != after.ctime()
        || final_held.ctime_nsec() != after.ctime_nsec()
        || final_named.st_dev != final_held.dev()
        || final_named.st_ino != final_held.ino()
        || final_named.st_uid != 0
        || final_named.st_nlink != 1
        || final_named.st_mode & 0o177777 != 0o100600
        || final_named.st_size != bytes.len() as i64
        || final_named.st_ctime != final_held.ctime()
        || final_named.st_ctime_nsec != final_held.ctime_nsec() as u64
        || after.dev() != before.dev()
        || after.ino() != before.ino()
        || after.uid() != 0
        || after.nlink() != 1
        || after.mode() & 0o7777 != 0o600
        || after.len() != bytes.len() as u64
        || readback != bytes
    {
        return Err("original recovery failure publication readback differs".into());
    }
    Ok(())
}

fn now() -> Result<u64, String> {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_millis(),
    )
    .map_err(|error| error.to_string())
}
fn open(path: &std::path::Path, directory: bool) -> Result<File, String> {
    let mut flags =
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW;
    if directory {
        flags |= rustix::fs::OFlags::DIRECTORY;
    }
    rustix::fs::openat2(
        rustix::fs::CWD,
        path,
        flags,
        rustix::fs::Mode::empty(),
        rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
    )
    .map(File::from)
    .map_err(|error| error.to_string())
}
fn read(record: &contract::Record) -> Result<(File, Vec<u8>), String> {
    let mut file = open(&record.path, false)?;
    let before = file.metadata().map_err(|error| error.to_string())?;
    if !before.is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || before.mode() & 0o022 != 0
        || before.len() != record.length
    {
        return Err("original recovery input record custody differs".into());
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(contract::RECORD_BOUND + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let after = file.metadata().map_err(|error| error.to_string())?;
    let named = std::fs::symlink_metadata(&record.path).map_err(|error| error.to_string())?;
    let identity = |metadata: &std::fs::Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.nlink(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        )
    };
    if identity(&before) != identity(&after)
        || identity(&before) != identity(&named)
        || !named.is_file()
        || hash(&bytes) != record.sha256
    {
        return Err("original recovery input record changed".into());
    }
    Ok((file, bytes))
}
fn json(bytes: &[u8]) -> Result<serde_json::Value, String> {
    memcordon_core::canonical_json::reject_duplicate_json_keys(bytes)?;
    serde_json::from_slice(bytes).map_err(|error| error.to_string())
}
fn validate_records(
    input: &Input,
    records: &BTreeMap<&str, Vec<u8>>,
    harness_owner: &serde_json::Value,
) -> Result<(), String> {
    if let Context::Component { recipe_id, .. } = &input.context {
        let native = json(&records["native_input"])?;
        let boundary = json(&records["boundary"])?;
        let ownership = json(&records["ownership"])?;
        let journal =
            crate::linux::private_attempt::PrivateAttemptRecordV4::parse(&records["journal"])?;
        let reference =
            memcordon_core::workload_admission_v3::RuntimeMixedAdmissionSnapshot::parse(
                &records["reference"],
            )?;
        let reservation_bytes: Vec<u8> =
            serde_json::from_value(ownership["account"]["reservation"]["bytes"].clone())
                .map_err(|e| e.to_string())?;
        let reservation = json(&reservation_bytes)?;
        let attempt: Vec<u8> =
            serde_json::from_value(reservation["attempt"].clone()).map_err(|e| e.to_string())?;
        if native["run_id"] != input.identity.run_id
            || recipe_id != "original-native-components-v1"
            || native["recipe_id"] != *recipe_id
            || native["native_target"] != input.native_target
            || native["artifact_root"]
                != serde_json::to_value(&input.original_artifact_root)
                    .map_err(|error| error.to_string())?
            || native["work_deadline_unix_millis"] != input.work_deadline_unix_millis
            || native["cleanup_deadline_unix_millis"] != input.cleanup_deadline_unix_millis
            || boundary["run_id"] != native["run_id"]
            || boundary["recipe_id"] != native["recipe_id"]
            || boundary["native_target"] != native["native_target"]
            || boundary["fixture_sha256"] != native["fixture_sha256"]
            || ownership["account"]["attempt_id"] != boundary["native"]["attempt_id"]
            || !ownership["account"]["account_uid"].is_u64()
            || !ownership["account"]["reference"].is_object()
            || !ownership["account"]["reservation"].is_object()
            || journal.mixed_admission_metadata.as_ref() != Some(&reference)
            || journal.attempt_id.as_str() != reference.attempt_id.as_str()
            || reference.attempt_id.as_str()
                != boundary["native"]["attempt_id"]
                    .as_str()
                    .ok_or("original boundary attempt absent")?
            || ownership["journal_sha256"] != hash(&records["journal"])
            || ownership["account"]["reference"]["account_uid"]
                != ownership["account"]["account_uid"]
            || reservation["uid"] != ownership["account"]["account_uid"]
            || hex::encode(attempt) != reference.attempt_id.as_str()
        {
            return Err("original recovery component association differs".into());
        }
        return Ok(());
    }
    let owner = json(&records["lease_owner"])?;
    if owner["identity"]
        != serde_json::to_value(&input.identity).map_err(|error| error.to_string())?
        || owner["cell"]["target"] != input.native_target
        || owner["lease_id"] != input.scope_id
        || owner["work_deadline_unix_millis"] != input.work_deadline_unix_millis
        || owner["cleanup_deadline_unix_millis"] != input.cleanup_deadline_unix_millis
        || owner["cell"] != harness_owner["cell"]
        || harness_owner["owner_path"]
            != serde_json::to_value(
                std::path::Path::new(
                    owner["admin_root"]
                        .as_str()
                        .ok_or("original lease admin root absent")?,
                )
                .join("recovery-harness-owner.json"),
            )
            .map_err(|error| error.to_string())?
    {
        return Err("original recovery installed lease association differs".into());
    }
    if matches!(input.context, Context::InterruptedLease { .. }) {
        if let Some(bytes) = records.get("resources_acquired") {
            let acquired = json(bytes)?;
            checkpoint::validate_interrupted_checkpoint(&owner, &acquired)?;
        }
        return Ok(());
    }
    let prepared: memcordon_core::mixed_observation::MixedPreparedObservationV2 =
        serde_json::from_slice(&records["prepared"]).map_err(|error| error.to_string())?;
    prepared.validate()?;
    for role in ["allocation_journal", "phase_journal", "original_journal"] {
        if let Some(bytes) = records.get(role) {
            let journal = crate::linux::private_attempt::PrivateAttemptRecordV4::parse(bytes)?;
            if journal.mixed_admission_metadata.as_ref() != Some(&prepared.admission)
                || journal.attempt_id.as_str() != prepared.admission.attempt_id.as_str()
            {
                return Err("original recovery journal substitutes prepared admission".into());
            }
        }
    }
    if let Some(bytes) = records.get("original_reservation") {
        let reservation = json(bytes)?;
        let attempt: Vec<u8> = serde_json::from_value(reservation["attempt"].clone())
            .map_err(|error| error.to_string())?;
        if hex::encode(attempt) != prepared.admission.attempt_id.as_str()
            || reservation["uid"]
                .as_u64()
                .is_none_or(|uid| uid == 0 || uid > u32::MAX as u64)
        {
            return Err("original recovery reservation substitutes prepared attempt".into());
        }
    }
    if matches!(input.context, Context::Lifecycle { .. }) {
        let intent = json(&records["controller_intent"])?;
        let action = json(&records["controller_action"])?;
        if intent["attempt_id"] != prepared.admission.attempt_id.as_str()
            || intent["identity"] != owner["identity"]
            || intent["cell"] != owner["cell"]
            || intent["lease_id"] != owner["lease_id"]
            || intent["journal_sha256"] != hash(&records["phase_journal"])
            || action["native_status"] != 0
        {
            return Err("original recovery lifecycle intervention differs".into());
        }
    }
    if matches!(input.context, Context::Delivery { .. }) {
        let invocation = json(&records["frontend_invocation"])?;
        delivery::validate_contract(
            &records["original_contract"],
            &prepared,
            &input.identity.source_commit,
        )?;
        let destination = json(&records["report_destination"])?;
        let failure = json(&records["report_delivery_failure"])?;
        delivery::validate(
            &invocation,
            &records["original_contract"],
            &destination,
            &failure,
            prepared.caller.pid,
            prepared.admission.caller_uid,
        )?;
    }
    Ok(())
}

#[test]
#[ignore = "original measured root/package owner and frozen native records required"]
fn native_original_recovery_emit_actual_receipt() {
    run().unwrap();
}
fn run() -> Result<(), String> {
    let expected = [
        "--exact",
        contract::TEST_NAME,
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ];
    if std::env::args_os()
        .skip(1)
        .ne(expected.iter().map(std::ffi::OsString::from))
    {
        return Err("original recovery fixture requires its exact measured operation".into());
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(contract::INPUT_BOUND as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let input = Input::decode(&bytes)?;
    input.validate(
        &std::env::current_dir().map_err(|error| error.to_string())?,
        now()?,
    )?;
    let origin_bytes = crate::linux::protected_read::read_protected_absolute(
        &input
            .artifact_root
            .join("original-native-recovery-origin.json"),
        contract::RECORD_BOUND,
        Some(0o600),
    )?;
    let origin = json(&origin_bytes)?;
    if hash(&origin_bytes) != input.origin_sha256
        || origin["format"] != "memcordon.original-native-recovery-origin"
        || origin["revision"] != 1
        || origin["original_artifact_root"]
            != serde_json::to_value(&input.original_artifact_root)
                .map_err(|error| error.to_string())?
    {
        return Err("original recovery staged scope differs".into());
    }
    let directory = open(&input.artifact_root, true)?;
    let root = directory.metadata().map_err(|error| error.to_string())?;
    if root.uid() != 0 || root.mode() & 0o022 != 0 {
        return Err("original recovery result directory is not protected".into());
    }
    let mut held = Vec::new();
    let mut records = BTreeMap::new();
    for (role, record) in input.context.records() {
        let reference = &origin["records"][role];
        if reference["sha256"] != record.sha256
            || reference["length"] != record.length
            || reference["staged_path"]
                != serde_json::to_value(&record.path).map_err(|error| error.to_string())?
        {
            return Err("original recovery staged record association differs".into());
        }
        crate::linux::protected_read::read_protected_absolute(
            &record.path,
            contract::RECORD_BOUND,
            Some(0o600),
        )?;
        let (file, bytes) = read(record)?;
        held.push(file);
        records.insert(role, bytes);
    }
    let harness_owner_bytes = crate::linux::protected_read::read_protected_absolute(
        &input
            .artifact_root
            .join("original-native-recovery-owner.json"),
        1024 * 1024,
        Some(0o600),
    )?;
    let harness_owner = json(&harness_owner_bytes)?;
    if hash(&harness_owner_bytes) != input.recovery_harness_owner_sha256
        || harness_owner["format"] != "memcordon.original-native-recovery-harness-owner"
        || harness_owner["revision"] != 1
        || harness_owner["identity"]
            != serde_json::to_value(&input.identity).map_err(|error| error.to_string())?
        || harness_owner["scope_id"] != input.scope_id
        || harness_owner["cell"]["target"] != input.native_target
        || harness_owner["work_deadline_unix_millis"] != input.work_deadline_unix_millis
        || harness_owner["cleanup_deadline_unix_millis"] != input.cleanup_deadline_unix_millis
    {
        return Err("original recovery measured owner/input association differs".into());
    }
    validate_records(&input, &records, &harness_owner)?;
    let sampled_monotonic = crate::linux::clock::monotonic_nanos()?;
    let before_recovery = now()?;
    let mut observation = crate::linux::recovery::AdministrationObservation {
        stage: "cleanup-cutoff-conversion",
        ..Default::default()
    };
    let cutoff = contract::monotonic_cleanup_cutoff(
        input.cleanup_deadline_unix_millis,
        sampled_monotonic,
        before_recovery,
    );
    let recovery = match cutoff.as_ref() {
        Ok(cutoff) => crate::linux::recovery::recover_authenticated_administration_until(
            *cutoff,
            &mut observation,
        ),
        Err(error) => Err(error.clone()),
    };
    let lease = contract::LeaseObservation {
        started_monotonic_nanos: observation.lease.started_monotonic_nanos,
        finished_monotonic_nanos: observation.lease.finished_monotonic_nanos,
        contention_count: observation.lease.contention_count,
        lock_acquired: observation.lease.lock_acquired,
        validated_acquisition: observation.lease.validated_acquisition,
        held_device: observation.lease.held_device,
        held_inode: observation.lease.held_inode,
        native_error: observation.lease.native_error,
        operation: observation.lease.operation.clone(),
    };
    eprintln!("original recovery lease observation: {lease:?}");
    let outstanding = match recovery {
        Ok(outstanding) => outstanding,
        Err(primary) => {
            let mut detail = primary.clone();
            if detail.len() > 4096 {
                let mut end = 4096 - "[truncated]".len();
                while !detail.is_char_boundary(end) {
                    end -= 1;
                }
                detail.truncate(end);
                detail.push_str("[truncated]");
            }
            let publication = (|| {
                let failure = contract::RecoveryFailure {
                    format: "memcordon.original-native-recovery-failure".into(),
                    revision: 1,
                    input_sha256: hash(&bytes),
                    context: input.context.kind().into(),
                    identity: input.identity.clone(),
                    native_target: input.native_target.clone(),
                    scope_id: input.scope_id.clone(),
                    recovery_harness_owner_sha256: input.recovery_harness_owner_sha256.clone(),
                    original_records: input
                        .context
                        .records()
                        .iter()
                        .map(|(role, record)| ((*role).into(), record.sha256.clone()))
                        .collect(),
                    original_cleanup_deadline_unix_millis: input.cleanup_deadline_unix_millis,
                    monotonic_cutoff_nanos: cutoff.ok(),
                    observed_unix_millis: now()?,
                    stage: observation.stage.into(),
                    recovery_entered: observation.recovery_entered,
                    error: detail,
                    lease,
                };
                serde_json::to_vec(&failure)
                    .map_err(|error| error.to_string())
                    .and_then(|output| publish_failure(&directory, &output))
            })();
            return Err(match publication {
                Ok(()) => primary,
                Err(secondary) => format!("{primary}; failure diagnostic publication: {secondary}"),
            });
        }
    };
    let completed = now()?;
    let result = RecoveryResult {
        format: "memcordon.original-native-recovery-result".into(),
        revision: 1,
        input_sha256: hash(&bytes),
        context: input.context.kind().into(),
        identity: input.identity.clone(),
        native_target: input.native_target.clone(),
        scope_id: input.scope_id.clone(),
        recovery_harness_owner_sha256: input.recovery_harness_owner_sha256.clone(),
        original_records: input
            .context
            .records()
            .iter()
            .map(|(role, record)| ((*role).into(), record.sha256.clone()))
            .collect(),
        completed_unix_millis: completed,
        within_original_cleanup: completed < input.cleanup_deadline_unix_millis,
        outstanding,
    };
    let output = serde_json::to_vec(&result).map_err(|error| error.to_string())?;
    if output.len() > 4 * 1024 * 1024 {
        return Err("original recovery result exceeds bound".into());
    }
    let mut file = File::from(
        rustix::fs::openat(
            &directory,
            contract::RESULT_LEAF,
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_raw_mode(0o600),
        )
        .map_err(|error| error.to_string())?,
    );
    file.write_all(&output).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    directory.sync_all().map_err(|error| error.to_string())?;
    drop(held);
    let after_persistence = now()?;
    if !result.within_original_cleanup
        || !result.outstanding.is_empty()
        || after_persistence >= input.cleanup_deadline_unix_millis
    {
        return Err(format!(
            "original native recovery failed: outstanding_count={} completion_expired={} post_persistence_expired={} before_recovery_unix_millis={before_recovery} completed_unix_millis={completed} after_persistence_unix_millis={after_persistence} original_cleanup_deadline_unix_millis={}",
            result.outstanding.len(),
            !result.within_original_cleanup,
            after_persistence >= input.cleanup_deadline_unix_millis,
            input.cleanup_deadline_unix_millis
        ));
    }
    Ok(())
}
