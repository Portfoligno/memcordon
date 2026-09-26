//! Detached specialist reconstruction. Every input is an exact authenticated
//! origin leaf; structural composites never construct a capability alone.

use crate::private_kernel_observer::VerifiedKernelIntervalV1;
use crate::private_observer_session::{ObserverEvidenceV1, ObserverIntervalRecordV1};
use crate::private_origin_replay::{replay_origin_clock, replay_origin_kernel_interval};
use crate::private_process_clock::VerifiedProcClockCalibrationV1;
use crate::private_public_completion::AuthenticatedCompletedPublicEvidenceV2;
use crate::private_public_dispatch::{
    ObservedInstalledPublicCaseV3, StructuralProviderFrameReadbackV2,
};
use crate::private_public_plan::{StaticPublicSuiteIntentV1, prepared_public_case_recipe_v1};
use crate::{CiError, Result};
use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};
use std::collections::BTreeMap;
use std::path::Path;

fn fail<T>(message: &str) -> Result<T> {
    Err(CiError::Message(message.into()))
}
fn path(prefix: &str, name: &str) -> String {
    Path::new(prefix).join(name).to_string_lossy().into_owned()
}

pub(crate) fn interval(
    origin: &impl ObserverEvidenceV1,
    record_path: &str,
    purpose: &str,
) -> Result<(VerifiedKernelIntervalV1, VerifiedProcClockCalibrationV1)> {
    let record: ObserverIntervalRecordV1 =
        crate::private_observer_session::strict_json(origin.leaf(record_path)?, 64 * 1024)?;
    let matches = origin
        .descriptor()
        .intervals
        .iter()
        .filter(|entry| entry.interval_id == record.interval_id)
        .collect::<Vec<_>>();
    let [enrolled] = matches.as_slice() else {
        return fail("specialist interval enrollment absent or ambiguous");
    };
    if **enrolled != record || record.purpose != purpose {
        return fail("specialist exact interval role differs");
    }
    let capture = replay_origin_kernel_interval(origin, &record.capture_path)?;
    let parent = Path::new(&record.capture_path)
        .parent()
        .ok_or_else(|| CiError::Message("specialist capture parent absent".into()))?;
    let clock_path = parent.join("clock.json").to_string_lossy().into_owned();
    let clock = replay_origin_clock(origin, &record, &clock_path)?;
    Ok((capture, clock))
}

pub(crate) fn provider(
    origin: &impl ObserverEvidenceV1,
    prefix: &str,
) -> Result<StructuralProviderFrameReadbackV2> {
    let raw_prefix = path(prefix, "raw");
    let mut leaves = BTreeMap::new();
    let record = origin.leaf(&path(prefix, "record.json"))?;
    // Exact closed names and digests come from the authenticated original
    // provider record; the genuine origin accessor supplies each raw leaf.
    for name in crate::private_public_dispatch::public_provider_source_leaf_names(record)? {
        if leaves
            .insert(
                name.clone(),
                origin.leaf(&path(&raw_prefix, &name))?.to_vec(),
            )
            .is_some()
        {
            return fail("specialist provider leaf inventory aliases");
        }
    }
    crate::private_public_dispatch::parse_structural_provider_case_from_leaves(
        origin.leaf(&path(prefix, "record.json"))?,
        &leaves,
    )
}

pub(crate) fn bind_provider(
    intent: &StaticPublicSuiteIntentV1,
    origin: &impl ObserverEvidenceV1,
    provider: &StructuralProviderFrameReadbackV2,
    selector: &str,
    generation: u32,
) -> Result<[u8; 32]> {
    let (challenge, _) = prepared_public_case_recipe_v1(
        intent,
        &origin.descriptor().session_nonce,
        generation,
        selector,
    )?;
    let expected_key = memcordon_core::private_release_case_v1::private_release_case_key_v1(
        memcordon_core::private_release_case_v1::PrivateReleaseStageV1::FinalPublic,
        selector,
        &challenge,
    )
    .map_err(CiError::Message)?;
    let generation = origin
        .descriptor()
        .generations
        .iter()
        .find(|entry| entry.generation == generation)
        .ok_or_else(|| CiError::Message("specialist generation absent".into()))?;
    let raw: serde_json::Value =
        crate::private_observer_session::strict_json(&provider.record_bytes, 128 * 1024)?;
    if provider.result_key != expected_key
        || raw.get("selector").and_then(serde_json::Value::as_str) != Some(selector)
        || raw.get("challenge").and_then(serde_json::Value::as_str)
            != Some(hex::encode(challenge).as_str())
        || raw.get("peer_uid").and_then(serde_json::Value::as_u64)
            != Some(u64::from(intent.public_uid))
        || raw.get("peer_gid").and_then(serde_json::Value::as_u64)
            != Some(u64::from(intent.public_gid))
        || raw.get("installation_epoch")
            != Some(&serde_json::to_value(&generation.installation_epoch)?)
        || raw.get("active_h1_receipt_sha256")
            != Some(&serde_json::to_value(&generation.installed_receipt_sha256)?)
        || raw.get("manifest_sha256") != Some(&serde_json::to_value(&intent.manifest_sha256)?)
        || raw.get("qualification_sha256")
            != Some(&serde_json::to_value(&intent.qualification_sha256)?)
    {
        return fail("specialist provider differs from protected recipe/generation/caller");
    }
    let recipe = &intent
        .scenarios
        .iter()
        .find(|case| case.selector == selector)
        .ok_or_else(|| CiError::Message("specialist recipe absent".into()))?
        .recipe;
    for attempt in &provider.attempts {
        if let Some(identity) = &attempt.target_identity {
            if identity.entrypoint_sha256
                != intent
                    .scenarios
                    .iter()
                    .find(|case| case.selector == selector)
                    .expect("checked")
                    .fixture_sha256
                || recipe.fixture_argv.first().map(String::as_str)
                    != Some(identity.entrypoint_path.as_str())
            {
                return fail("specialist approved image differs from protected recipe");
            }
        }
    }
    Ok(challenge)
}

#[cfg(unix)]
pub(crate) fn observed(
    origin: &impl ObserverEvidenceV1,
    prefix: &str,
    intent: &StaticPublicSuiteIntentV1,
    h1: &DiagnosticSha256,
    child: &memcordon_core::private_public_case_v2::FinalPublicChildIdentityV2,
    outcome: crate::private_public_v2::ExpectedPublicV2Outcome,
) -> Result<ObservedInstalledPublicCaseV3> {
    use std::os::unix::process::ExitStatusExt;
    let stdio = origin.leaf(&path(prefix, "stdio.bin"))?;
    let mut bytes = stdio
        .strip_prefix(b"memcordon/public-stdio/v1\0")
        .ok_or_else(|| CiError::Message("specialist supervisor stdio domain differs".into()))?;
    fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N]> {
        let head = bytes
            .get(..N)
            .ok_or_else(|| CiError::Message("specialist stdio truncated".into()))?;
        let value = head.try_into().expect("boundedarray");
        *bytes = &bytes[N..];
        Ok(value)
    }
    let pid = u32::from_le_bytes(take(&mut bytes)?);
    let start = u64::from_le_bytes(take(&mut bytes)?);
    let status = i32::from_le_bytes(take(&mut bytes)?);
    let stdout_len = u32::from_le_bytes(take(&mut bytes)?) as usize;
    if stdout_len > 1024 * 1024 {
        return fail("specialist stdout exceeds fixed budget");
    }
    let stdout = bytes
        .get(..stdout_len)
        .ok_or_else(|| CiError::Message("specialist stdout truncated".into()))?
        .to_vec();
    bytes = &bytes[stdout_len..];
    let stderr_len = u32::from_le_bytes(take(&mut bytes)?) as usize;
    if stderr_len > 1024 * 1024
        || bytes.len() != stderr_len
        || pid != child.pid
        || start != child.start_time_ticks
        || child.uid != intent.public_uid
        || child.gid != intent.public_gid
        || !child.supplementary_groups_empty
        || child.executable_sha256 != intent.public_cli_sha256
    {
        return fail("specialist independently held public child differs");
    }
    let process = crate::private_supervisor::SupervisedProcessV2 {
        status: std::process::ExitStatus::from_raw(status),
        stdout,
        stderr: bytes.to_vec(),
        linux_child: Some(crate::private_supervisor::LinuxChildIdentityV1 {
            pid,
            start_time_ticks: start,
        }),
    };
    let report = origin.leaf(&path(prefix, "report.json"))?;
    let abi = match intent.observer_subject.target.as_str() {
        "x86_64-unknown-linux-gnu" => {
            memcordon_core::workload_evidence_v2::QualifiedNativeAbiV2::X86_64LinuxGnu
        }
        "aarch64-unknown-linux-gnu" => {
            memcordon_core::workload_evidence_v2::QualifiedNativeAbiV2::Aarch64LinuxGnu
        }
        _ => return fail("specialist native ABI differs"),
    };
    let parsed = crate::private_public_v2::validate_structural_public_v2_readback(
        &process,
        report,
        &crate::private_public_v2::ExpectedPublicV2Readback {
            source_commit: &intent.observer_subject.source_commit,
            native_abi: abi,
            archive_sha256: &intent.archive_sha256,
            runtime_manifest_sha256: &intent.manifest_sha256,
            qualification_sha256: &intent.qualification_sha256,
            host_receipt_sha256: h1,
            report_owner_uid: intent.public_uid,
            outcome,
        },
    )?;
    Ok(ObservedInstalledPublicCaseV3 {
        process,
        report: Some(parsed),
        dual_report: None,
        report_bytes: Some(report.to_vec()),
        stdio_bytes: stdio.to_vec(),
        cli_sha256: intent.public_cli_sha256.clone(),
        argv_sha256: child.argv_sha256.clone(),
        working_directory_sha256: child.working_directory_sha256.clone(),
        live_samples: BTreeMap::new(),
    })
}

#[cfg(unix)]
pub(crate) fn replay_completed_public_abi(
    intent: &StaticPublicSuiteIntentV1,
    completed: &AuthenticatedCompletedPublicEvidenceV2,
) -> Result<crate::private_public_verify::VerifiedPublicAbiCompositeV1> {
    replay_public_abi_origin(intent, completed.origin())
}
pub(crate) fn replay_public_abi_origin(
    intent: &StaticPublicSuiteIntentV1,
    origin: &impl ObserverEvidenceV1,
) -> Result<crate::private_public_verify::VerifiedPublicAbiCompositeV1> {
    use crate::private_public_abi_filtered::*;
    use crate::private_public_abi_outer::*;
    let bytes = origin.leaf("composites/abi/composite.json")?;
    let case =
        memcordon_core::private_public_abi_composite_v1::PublicAbiCompositeCaseV1::parse(bytes)
            .map_err(CiError::Message)?;
    let (outer_interval, outer_clock) =
        interval(origin, "composites/abi/outer/interval.json", "abi-outer")?;
    let (filtered_interval, filtered_clock) = interval(
        origin,
        "composites/abi/filtered/interval.json",
        "abi-filtered",
    )?;
    let generation = origin
        .descriptor()
        .generations
        .iter()
        .find(|entry| entry.installation_epoch == case.installation_epoch)
        .ok_or_else(|| CiError::Message("ABI generation absent".into()))?;
    let provider = provider(origin, "composites/abi/filtered/provider")?;
    let challenge = bind_provider(
        intent,
        origin,
        &provider,
        &case.selector,
        generation.generation,
    )?;
    if challenge != case.challenge {
        return fail("ABI composite challenge is not the prepared challenge");
    }
    let outer_raw = origin.leaf("composites/abi/outer/outer-control.raw.json")?;
    let raw: serde_json::Value =
        crate::private_observer_session::strict_json(outer_raw, 16 * 1024)?;
    let start = raw
        .pointer("/outer/service/start_time")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| CiError::Message("outer ABI live service start absent".into()))?;
    let outer = readback_public_abi_outer_v1(
        origin.leaf("composites/abi/outer/request.json")?,
        outer_raw,
        &ExpectedPublicAbiOuterV1 {
            target: &intent.observer_subject.target,
            challenge: &challenge,
            h1_sha256: &generation.installed_receipt_sha256,
            installation_epoch: &generation.installation_epoch,
            service_pid: outer_interval.coordinator_pid(),
            service_start_ticks: start,
            service_cgroup_inode: outer_interval.cgroup_inode(),
        },
    )?;
    let outer_join = join_public_abi_outer_kernel_v1(&outer, &outer_interval, &outer_clock)?;
    let [attempt] = provider.attempts.as_slice() else {
        return fail("ABI filtered attempt count differs");
    };
    let target = attempt
        .target_identity
        .as_ref()
        .ok_or_else(|| CiError::Message("ABI filtered target absent".into()))?;
    let scenario = intent
        .scenarios
        .iter()
        .find(|scenario| scenario.selector == case.selector)
        .ok_or_else(|| CiError::Message("ABI recipe absent".into()))?;
    let recipe = &scenario.recipe;
    let checkpoint = origin.leaf("composites/abi/filtered/target/checkpoint-file.bin")?;
    let checkpoint_value: memcordon_core::workload_evidence_v2::PrivateTcpCheckpointV2 =
        crate::private_observer_session::strict_json(checkpoint, 4096)?;
    let checkpoint_digest = checkpoint_value
        .canonical_digest()
        .map_err(CiError::Message)?;
    let helper = raw
        .get("branches")
        .and_then(serde_json::Value::as_array)
        .and_then(|branches| {
            branches.iter().find(|branch| {
                branch.get("branch").and_then(serde_json::Value::as_str) == Some("arm32")
            })
        });
    let host = crate::private_final_install::FinalHostReadbackV1::parse_bounded(
        origin.leaf("composites/abi/outer/host.json")?,
    )?;
    if host.source_commit() != intent.observer_subject.source_commit
        || host.target() != intent.observer_subject.target
        || host.boot_id() != origin.descriptor().boot_id
        || host.installation_epoch() != &generation.installation_epoch
        || host.active_h1_receipt_sha256() != &generation.installed_receipt_sha256
        || host.manifest_sha256() != &generation.installed_manifest_sha256
        || host.qualification_sha256() != &intent.qualification_sha256
        || host.agent_sha256() != &scenario.fixture_sha256
        || host.filter_sha256() != &recipe.filter_sha256
    {
        return fail("public ABI independently retained H1 differs from enrolled generation");
    }
    let outer_record: crate::private_observer_session::ObserverIntervalRecordV1 =
        crate::private_observer_session::strict_json(
            origin.leaf("composites/abi/outer/interval.json")?,
            128 * 1024,
        )?;
    if !outer_record
        .sample_paths
        .iter()
        .any(|path| path == "composites/abi/outer/host.json")
    {
        return fail("public ABI H1 source was not enrolled in actual outer interval");
    }
    let helper_identity = match (
        intent.observer_subject.target.as_str(),
        host.arm32_helper_sha256(),
    ) {
        ("x86_64-unknown-linux-gnu", None) if helper.is_none() => None,
        ("aarch64-unknown-linux-gnu", Some(expected)) => {
            for path in [
                "composites/abi/outer/helper-image.raw",
                "composites/abi/outer/helper-image.json",
            ] {
                if !outer_record
                    .sample_paths
                    .iter()
                    .any(|sample| sample == path)
                {
                    return fail(
                        "public ABI original helper was not held in enrolled outer interval",
                    );
                }
            }
            let pair = validate_public_abi_helper_image_v1(
                origin.leaf("composites/abi/outer/helper-image.raw")?,
                origin.leaf("composites/abi/outer/helper-image.json")?,
                expected,
            )?;
            let branch = helper
                .ok_or_else(|| CiError::Message("public ABI actual ARM branch absent".into()))?;
            if branch
                .get("exec_device")
                .and_then(serde_json::Value::as_u64)
                != Some(pair.0)
                || branch.get("exec_inode").and_then(serde_json::Value::as_u64) != Some(pair.1)
            {
                return fail(
                    "public ABI native helper execution differs from independently held H1 object",
                );
            }
            Some(pair)
        }
        _ => return fail("public ABI original H1 helper inventory differs from target"),
    };
    let filtered = readback_public_abi_filtered_v1(
        origin.leaf("composites/abi/filtered/target/report.json")?,
        origin.leaf("composites/abi/filtered/target/protected.json")?,
        checkpoint,
        &ExpectedPublicAbiFilteredV1 {
            target: &intent.observer_subject.target,
            challenge: &challenge,
            result_key: &provider.result_key,
            boot_id: &origin.descriptor().boot_id,
            installation_epoch: &generation.installation_epoch,
            active_h1_receipt_sha256: &generation.installed_receipt_sha256,
            attempt_id: &attempt.attempt_id,
            target_pid: target.target.pid,
            target_start_ticks: target.target.start_time,
            target_uid: recipe.target_uid,
            target_gid: recipe.target_gid,
            checkpoint_sha256: &checkpoint_digest,
            filter_sha256: &recipe.filter_sha256,
            network_namespace_inode: target.network_namespace_inode,
            helper_device: helper_identity.map(|pair| pair.0),
            helper_inode: helper_identity.map(|pair| pair.1),
        },
    )?;
    let filtered_join = join_public_abi_filtered_kernel_v1(
        &filtered,
        &filtered_interval,
        &filtered_clock,
        target.entrypoint_device,
        target.entrypoint_inode,
    )?;
    let target_join = crate::private_public_kernel_join::join_public_case_kernel_targets(
        &filtered_interval,
        &filtered_clock,
        &provider.result_key,
        &[
            crate::private_public_kernel_join::ProtectedPublicTargetExpectationV1 {
                attempt_id: attempt.attempt_id.clone(),
                pid: target.target.pid,
                start_ticks: target.target.start_time,
                network_namespace_inode: target.network_namespace_inode,
                entrypoint_sha256: target.entrypoint_sha256.clone(),
                entrypoint_device: target.entrypoint_device,
                entrypoint_inode: target.entrypoint_inode,
                entrypoint_path: target.entrypoint_path.clone(),
            },
        ],
    )?;
    let observed = observed(
        origin,
        "composites/abi/filtered/cli",
        intent,
        &generation.installed_receipt_sha256,
        &case.filtered_child,
        crate::private_public_v2::ExpectedPublicV2Outcome::Exited(0),
    )?;
    crate::private_public_verify::verify_public_abi_composite(
        bytes,
        &observed,
        &provider,
        &outer,
        &outer_join,
        &filtered,
        &filtered_join,
        &filtered_interval,
        &target_join,
    )
}

#[cfg(unix)]
pub(crate) fn replay_completed_public_reuse(
    intent: &StaticPublicSuiteIntentV1,
    completed: &AuthenticatedCompletedPublicEvidenceV2,
) -> Result<crate::private_public_verify::VerifiedPublicReuseCompositeV1> {
    replay_public_reuse_origin(intent, completed.origin())
}
pub(crate) fn replay_public_reuse_origin(
    intent: &StaticPublicSuiteIntentV1,
    origin: &impl ObserverEvidenceV1,
) -> Result<crate::private_public_verify::VerifiedPublicReuseCompositeV1> {
    use crate::private_public_reuse_join::*;
    let bytes = origin.leaf("composites/reuse/composite.json")?;
    let case =
        memcordon_core::private_public_reuse_composite_v1::PublicReuseCompositeCaseV1::parse(bytes)
            .map_err(CiError::Message)?;
    let (first, first_clock) = interval(
        origin,
        "composites/reuse/first-interval.json",
        "reuse-first",
    )?;
    let (blocked, _) = interval(
        origin,
        "composites/reuse/blocked-interval.json",
        "reuse-blocked",
    )?;
    let (recovery, _) = interval(
        origin,
        "composites/reuse/recovery-interval.json",
        "recovery",
    )?;
    let generation = origin
        .descriptor()
        .generations
        .iter()
        .find(|entry| entry.installation_epoch == case.installation_epoch)
        .ok_or_else(|| CiError::Message("reuse generation absent".into()))?;
    let provider = provider(origin, "composites/reuse/provider")?;
    let challenge = bind_provider(
        intent,
        origin,
        &provider,
        &case.selector,
        generation.generation,
    )?;
    if challenge != case.challenge {
        return fail("reuse composite prepared challenge differs");
    }
    let incomplete = origin.leaf("composites/reuse/incomplete-v4.bin")?;
    let durable: serde_json::Value =
        crate::private_observer_session::strict_json(incomplete, 1024 * 1024)?;
    let detached = origin.leaf("composites/reuse/detached-readback.bin")?;
    let record = detached
        .strip_suffix(b"\n")
        .ok_or_else(|| CiError::Message("reuse installed readback newline absent".into()))?;
    let transcript: serde_json::Value =
        crate::private_observer_session::strict_json(record, 16 * 1024)?;
    if case.durable_incomplete_snapshot_sha256 != hash_bytes(incomplete)
        || transcript.get("durable_incomplete_state_sha256")
            != Some(&serde_json::to_value(hash_bytes(incomplete))?)
        || durable.get("phase").and_then(serde_json::Value::as_str) != Some("cleanup-incomplete")
        || case.protected_reuse_transcript_sha256 != hash_bytes(record)
        || case.provider_sha256 != hash_bytes(&provider.record_bytes)
    {
        return fail("reuse exact durable failure/readback inventory differs");
    }
    let [first_attempt, blocked_attempt] = provider.attempts.as_slice() else {
        return fail("reuse ordered attempt count differs");
    };
    if durable
        .get("attempt_id")
        .and_then(serde_json::Value::as_str)
        != Some(first_attempt.attempt_id.as_str())
    {
        return fail("reuse durable attempt generation differs");
    }
    let record_interval: ObserverIntervalRecordV1 = crate::private_observer_session::strict_json(
        origin.leaf("composites/reuse/recovery-interval.json")?,
        64 * 1024,
    )?;
    let holder_clock = replay_origin_clock(
        origin,
        &record_interval,
        "composites/reuse/holder-clock.json",
    )?;
    let failure = origin.leaf("composites/reuse/first-failure.bin")?;
    let blocked_request = origin.leaf("composites/reuse/blocked-request.bin")?;
    let blocked_rejection = origin.leaf("composites/reuse/blocked-rejection.bin")?;
    let recovered = origin.leaf("composites/reuse/recovered-cleanup.bin")?;
    let joined = join_public_reuse_v1(&ExpectedPublicReuseLiveV1 {
        protected_record_bytes: record,
        detached_stdout: detached,
        detached: ExpectedPublicReuseV1 {
            result_key: &provider.result_key,
            boot_id: &origin.descriptor().boot_id,
            installation_epoch: &generation.installation_epoch,
            active_h1_receipt_sha256: &generation.installed_receipt_sha256,
            first_attempt_id: &first_attempt.attempt_id,
            second_attempt_id: &blocked_attempt.attempt_id,
            cleanup_failure_bytes: failure,
            blocked_request_bytes: blocked_request,
            blocked_rejection_bytes: blocked_rejection,
            recovered_cleanup_bytes: recovered,
            expected_failure_code: "MCSEALED-PRIVATE-REUSE-CLEANUP-INCOMPLETE",
            expected_blocked_code: "MCSEALED-PRIVATE-REUSE-BLOCKED",
        },
        provider: &provider,
        first_clock: &first_clock,
        holder_clock: &holder_clock,
        first_interval: &first,
        blocked_interval: &blocked,
        recovery_interval: &recovery,
    })?;
    let observed = observed(
        origin,
        "composites/reuse/cli",
        intent,
        &generation.installed_receipt_sha256,
        &case.child,
        crate::private_public_v2::ExpectedPublicV2Outcome::AllocatedUnverified,
    )?;
    if observed.report_bytes.as_ref().map(|raw| hash_bytes(raw)) != Some(case.report_sha256.clone())
        || hash_bytes(&observed.stdio_bytes) != case.stdio_sha256
    {
        return fail("reuse independent child/report bytes differ");
    }
    // Retain actual holder inventory as mandatory raw inputs. A close event
    // alone must not stand in for the earlier obstruction's live fd custody.
    let holder: serde_json::Value = crate::private_observer_session::strict_json(
        origin.leaf("composites/reuse/holder-identity.json")?,
        4096,
    )?;
    let holder_fd = origin.leaf("composites/reuse/holder-namespace-fd.bin")?;
    if holder_fd.is_empty()
        || holder_fd.len() > 4096
        || holder.get("pid").and_then(serde_json::Value::as_u64)
            != Some(u64::from(holder_clock.reader_identity().0))
    {
        return fail("reuse independently retained holder fd/identity absent");
    }
    crate::private_public_reuse_live::validate_holder_fd_source(
        record,
        holder_fd,
        origin.leaf("composites/reuse/holder-open.json")?,
        holder_clock.reader_identity().0,
        holder_clock.reader_identity().1,
    )?;
    let source: serde_json::Value =
        crate::private_observer_session::strict_json(holder_fd, 16 * 1024)?;
    let held = crate::private_source_carrier::decode_held_source(
        origin.leaf("composites/reuse/holder-sample.bin")?,
        |path| origin.leaf(path).map(ToOwned::to_owned),
    )?;
    crate::private_candidate_network_facts::validate_held_proc_identity(&held)?;
    let original_host = host(
        origin,
        intent,
        "composites/reuse/host.json",
        generation.generation,
    )?;
    let metadata: serde_json::Value = crate::private_observer_session::strict_json(
        held.leaves
            .get("image-metadata.json")
            .ok_or_else(|| CiError::Message("reuse holder image metadata absent".into()))?,
        8192,
    )?;
    let status = std::str::from_utf8(
        held.leaves
            .get("status.raw")
            .ok_or_else(|| CiError::Message("reuse holder raw status absent".into()))?,
    )
    .map_err(|_| CiError::Message("reuse holder status not UTF8".into()))?;
    let scalar = |name: &str| -> Result<Vec<u64>> {
        let values = status
            .lines()
            .filter_map(|line| line.strip_prefix(name))
            .collect::<Vec<_>>();
        if values.len() != 1 {
            return fail("reuse holder credential fields duplicate/missing");
        }
        values[0]
            .split_whitespace()
            .map(|word| {
                word.parse()
                    .map_err(|_| CiError::Message("reuse holder credential malformed".into()))
            })
            .collect()
    };
    let expected_argv = [
        AGENT_FOR_REUSE,
        "package",
        "public-reuse-hold",
        "--selector",
        case.selector.as_str(),
        "--challenge",
        &hex::encode(case.challenge),
        "--dispatch-key",
        &String::from(provider.result_key.clone()),
    ];
    let cmdline = held
        .leaves
        .get("cmdline.raw")
        .ok_or_else(|| CiError::Message("reuse holder cmdline absent".into()))?;
    let actual_argv = cmdline
        .strip_suffix(&[0])
        .ok_or_else(|| CiError::Message("reuse holder argv terminator absent".into()))?
        .split(|byte| *byte == 0)
        .collect::<Vec<_>>();
    let mode = metadata
        .get("mode")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| CiError::Message("reuse holder image mode absent".into()))?;
    if !record_interval
        .sample_paths
        .iter()
        .any(|path| path == "composites/reuse/holder-sample.bin")
        || !record_interval
            .sample_paths
            .iter()
            .any(|path| path == "composites/reuse/holder-namespace-fd.bin")
        || (held.pid, held.start_time_ticks) != holder_clock.reader_identity()
        || held.begin_monotonic_ns < record_interval.begin_monotonic_ns
        || held.end_monotonic_ns > record_interval.end_monotonic_ns
        || source
            .get("observed_monotonic_ns")
            .and_then(serde_json::Value::as_u64)
            != Some(held.begin_monotonic_ns)
        || held.executable_sha256 != *original_host.agent_sha256()
        || metadata.get("sha256") != Some(&serde_json::to_value(original_host.agent_sha256())?)
        || metadata.get("device").and_then(serde_json::Value::as_u64)
            != Some(held.executable_device)
        || metadata.get("inode").and_then(serde_json::Value::as_u64) != Some(held.executable_inode)
        || metadata.get("uid").and_then(serde_json::Value::as_u64) != Some(0)
        || metadata.get("gid").and_then(serde_json::Value::as_u64) != Some(0)
        || metadata.get("nlink").and_then(serde_json::Value::as_u64) != Some(1)
        || mode & 0o170000 != 0o100000
        || mode & 0o022 != 0
        || mode & 0o111 == 0
        || scalar("Uid:")? != vec![0; 4]
        || scalar("Gid:")? != vec![0; 4]
        || actual_argv
            != expected_argv
                .iter()
                .map(|arg| arg.as_bytes())
                .collect::<Vec<_>>()
    {
        return fail("reuse independently held installed root helper/original interval differs");
    }
    crate::private_public_verify::verify_public_reuse_composite(
        bytes, &joined, &first, &blocked, &recovery,
    )
}

const AGENT_FOR_REUSE: &str = "/usr/libexec/memcordon-sealed-agent";

pub(crate) fn host(
    origin: &impl ObserverEvidenceV1,
    intent: &StaticPublicSuiteIntentV1,
    path: &str,
    generation: u32,
) -> Result<crate::private_final_install::FinalHostReadbackV1> {
    let actual =
        crate::private_final_install::FinalHostReadbackV1::parse_bounded(origin.leaf(path)?)?;
    let generation = origin
        .descriptor()
        .generations
        .iter()
        .find(|entry| entry.generation == generation)
        .ok_or_else(|| CiError::Message("historical installed generation absent".into()))?;
    if actual.boot_id() != origin.descriptor().boot_id
        || actual.source_commit() != intent.observer_subject.source_commit
        || actual.version() != intent.observer_subject.release_version
        || actual.target() != intent.observer_subject.target
        || actual.manifest_sha256() != &intent.manifest_sha256
        || actual.qualification_sha256() != &intent.qualification_sha256
        || actual.public_cli_sha256() != &intent.public_cli_sha256
        || actual.installation_epoch() != &generation.installation_epoch
        || actual.active_h1_receipt_sha256() != &generation.installed_receipt_sha256
    {
        return fail("historical host readback differs from enrolled same-A generations");
    }
    Ok(actual)
}

pub(crate) fn target_join(
    provider: &StructuralProviderFrameReadbackV2,
    interval: &VerifiedKernelIntervalV1,
    clock: &VerifiedProcClockCalibrationV1,
) -> Result<crate::private_public_kernel_join::VerifiedPublicCaseKernelJoinV1> {
    let targets = provider
        .attempts
        .iter()
        .map(|attempt| -> Result<_> {
            let target = attempt
                .target_identity
                .as_ref()
                .ok_or_else(|| CiError::Message("historical positive target absent".into()))?;
            Ok(
                crate::private_public_kernel_join::ProtectedPublicTargetExpectationV1 {
                    attempt_id: attempt.attempt_id.clone(),
                    pid: target.target.pid,
                    start_ticks: target.target.start_time,
                    network_namespace_inode: target.network_namespace_inode,
                    entrypoint_sha256: target.entrypoint_sha256.clone(),
                    entrypoint_device: target.entrypoint_device,
                    entrypoint_inode: target.entrypoint_inode,
                    entrypoint_path: target.entrypoint_path.clone(),
                },
            )
        })
        .collect::<Result<Vec<_>>>()?;
    crate::private_public_kernel_join::join_public_case_kernel_targets(
        interval,
        clock,
        &provider.result_key,
        &targets,
    )
}

pub(crate) fn replay_completed_public_history(
    intent: &StaticPublicSuiteIntentV1,
    completed: &AuthenticatedCompletedPublicEvidenceV2,
) -> Result<crate::private_public_verify::VerifiedHistoricalPublicEpochV1> {
    replay_public_history_origin(intent, completed.origin())
}

pub(crate) fn replay_public_history_origin(
    intent: &StaticPublicSuiteIntentV1,
    origin: &impl ObserverEvidenceV1,
) -> Result<crate::private_public_verify::VerifiedHistoricalPublicEpochV1> {
    use crate::private_public_epoch_join::*;
    let [e0_generation, e1_generation] = origin.descriptor().generations.as_slice() else {
        return fail("historical proof requires exactly two ordered installed generations");
    };
    let e0_host = host(
        origin,
        intent,
        "historical/e0/host.json",
        e0_generation.generation,
    )?;
    let e1_host = host(
        origin,
        intent,
        "cases/16/host.json",
        e1_generation.generation,
    )?;
    let e0_provider = provider(origin, "historical/e0/provider")?;
    let e1_provider = provider(origin, "cases/16/provider")?;
    let e0_challenge = bind_provider(
        intent,
        origin,
        &e0_provider,
        "private_tcp::caller_identity_and_epoch_bound",
        e0_generation.generation,
    )?;
    let e1_challenge = bind_provider(
        intent,
        origin,
        &e1_provider,
        "private_tcp::native_tcp_bind_listen_connect",
        e1_generation.generation,
    )?;
    let (e0_interval, e0_clock) = interval(origin, "historical/e0/interval.json", "historical")?;
    let (e1_interval, e1_clock) = interval(origin, "cases/16/interval.json", "ordinary")?;
    let e0_join = target_join(&e0_provider, &e0_interval, &e0_clock)?;
    let e1_join = target_join(&e1_provider, &e1_interval, &e1_clock)?;
    let (replay, _) = interval(origin, "historical/replay/interval.json", "historical")?;
    let (spoof, _) = interval(origin, "historical/spoof/interval.json", "caller-spoof")?;
    let spoof_record: ObserverIntervalRecordV1 = crate::private_observer_session::strict_json(
        origin.leaf("historical/spoof/interval.json")?,
        64 * 1024,
    )?;
    let original = crate::private_kernel_replay::parse_capture_v2_with_budget(
        spoof.capture_bytes()?,
        &spoof_record.logical_case_key,
        crate::private_kernel_replay::CaptureStageV2::FinalPublic,
    )?;
    crate::private_public_caller_replay::validate_public_caller_sources(
        intent,
        origin.descriptor(),
        &spoof_record,
        original.events(),
        spoof.clock_inputs().ok_or_else(|| {
            CiError::Message("historical caller original calibrated reader absent".into())
        })?,
        |path| origin.leaf(path).map(ToOwned::to_owned),
    )?;
    let replay_record = origin.leaf("historical/replay/record.json")?;
    let replay_rejection = origin.leaf("historical/replay/rejection.bin")?;
    let spoof_record = origin.leaf("historical/spoof/record.json")?;
    let spoof_rejection = origin.leaf("historical/spoof/rejection.bin")?;
    let spoof_request = origin.leaf("historical/spoof/request.bin")?;
    let spoof_grant = origin.leaf("historical/spoof/grant-decision.json")?;
    let raw: serde_json::Value =
        crate::private_observer_session::strict_json(spoof_record, 16 * 1024)?;
    let peer_pid = raw
        .get("authenticated_peer_pid")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| CiError::Message("historical spoof actual registered PID absent".into()))?;
    let peer_start = raw
        .get("authenticated_peer_start_ticks")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            CiError::Message("historical spoof actual registered start absent".into())
        })?;
    let spoof_challenge = crate::private_public_plan::prepared_public_spoof_challenge_v1(
        intent,
        &origin.descriptor().session_nonce,
        e1_generation.generation,
    )?;
    let spoof_key = memcordon_core::private_release_case_v1::private_release_case_key_v1(
        memcordon_core::private_release_case_v1::PrivateReleaseStageV1::FinalPublic,
        "private_tcp::caller_identity_and_epoch_bound",
        &spoof_challenge,
    )
    .map_err(CiError::Message)?;
    let e0_challenge = hex::encode(e0_challenge);
    let e1_challenge = hex::encode(e1_challenge);
    let spoof_challenge = hex::encode(spoof_challenge);
    if origin.leaf("historical/replay/request.bin")?
        != e0_provider
            .attempts
            .first()
            .ok_or_else(|| CiError::Message("historical original E0 request absent".into()))?
            .request_bytes
    {
        return fail("historical replay does not retain exact E0 submitted bytes");
    }
    let joined = join_public_epoch_transition_v1(&ExpectedPublicEpochTransitionV1 {
        e0: PublicEpochPositiveV1 {
            selector: "private_tcp::caller_identity_and_epoch_bound",
            challenge: &e0_challenge,
            host: &e0_host,
            provider: &e0_provider,
            kernel_join: &e0_join,
            interval: &e0_interval,
        },
        e1: PublicEpochPositiveV1 {
            selector: "private_tcp::native_tcp_bind_listen_connect",
            challenge: &e1_challenge,
            host: &e1_host,
            provider: &e1_provider,
            kernel_join: &e1_join,
            interval: &e1_interval,
        },
        protected_archive_sha256: &intent.archive_sha256,
        upgrade_archive_sha256: &intent.archive_sha256,
        replay_record_bytes: replay_record,
        replay_rejection_bytes: replay_rejection,
        replay_stdout: origin.leaf("historical/replay/stdout.bin")?,
        replay_interval: &replay,
        spoof_record_bytes: spoof_record,
        spoof_stdout: origin.leaf("historical/spoof/stdout.bin")?,
        spoof_request_bytes: spoof_request,
        spoof_rejection_bytes: spoof_rejection,
        spoof_expected: ExpectedPublicSpoofV1 {
            selector: "private_tcp::caller_identity_and_epoch_bound",
            challenge: &spoof_challenge,
            result_key: &spoof_key,
            authorized_uid: intent.public_uid,
            unauthorized_uid: intent.historical_spoof_uid,
            unauthorized_gid: intent.historical_spoof_gid,
            registered_peer_pid: peer_pid,
            registered_peer_start_ticks: peer_start,
            installation_epoch: &e1_generation.installation_epoch,
            active_h1_receipt_sha256: &e1_generation.installed_receipt_sha256,
            request_bytes: spoof_request,
            grant_decision_bytes: spoof_grant,
            rejection_code: "MCSEALED-PRIVATE-PUBLIC-GRANT-REJECTED",
        },
        spoof_interval: &spoof,
    })?;
    if hash_bytes(origin.leaf("historical/epoch-transition.json")?) != *joined.transcript_sha256() {
        return fail("historical canonical full epoch join transcript differs");
    }
    crate::private_public_verify::VerifiedHistoricalPublicEpochV1::from_live_join(
        &joined,
        &origin.descriptor().boot_id,
    )
}

#[cfg(unix)]
pub(crate) fn replay_completed_public_specialists(
    intent: &StaticPublicSuiteIntentV1,
    completed: &AuthenticatedCompletedPublicEvidenceV2,
) -> Result<crate::private_public_verify::PublicSpecialistProofsV1> {
    intent.validate()?;
    let proof = crate::private_public_verify::PublicSpecialistProofsV1 {
        abi: replay_completed_public_abi(intent, completed)?,
        reuse: replay_completed_public_reuse(intent, completed)?,
        historical: replay_completed_public_history(intent, completed)?,
        policy: crate::private_public_policy_replay::replay_completed_public_policy(
            intent, completed,
        )?,
    };
    proof.verify_completed_links(intent, completed.origin(), &[])?;
    Ok(proof)
}
