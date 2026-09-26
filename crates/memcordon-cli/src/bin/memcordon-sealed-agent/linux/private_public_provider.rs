//! Root-custodied provider observations for an installed public V2
//! case. This is not a final-public case certificate: CLI stdio/report, kernel
//! observations and retirement still require independent detached witnesses.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

/// Actual installed preparation operands. This root-only diagnostic readback
/// cannot authorize a contract or enroll a controller; admission still checks
/// the independently protected approval and the exact pinned preparer image.
pub(crate) fn preparation_context_v2() -> Result<String, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("public preparation context requires root".into());
    }
    let installed = crate::package::acquire_verified_private_qualification_lease()?;
    let policy = crate::policy_registry::native::Lease::acquire()?;
    let activation = policy
        .read_v2()?
        .ok_or("active public V2 registry absent")?;
    installed.revalidate_release_boundary()?;
    serde_json::to_string(&serde_json::json!({
        "schema_version": 2,
        "installation_epoch": installed.generation_digest(),
        "active_h1_receipt_sha256": installed.active_host_receipt_sha256(),
        "manifest_sha256": installed.runtime_manifest_sha256(),
        "qualification_sha256": installed.qualification_digest(),
        "policy_epoch": activation.epoch,
        "registry_sha256": activation.registry.canonical_digest()?,
    }))
    .map_err(|error| error.to_string())
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum PublicFaultPlanV1 {
    DropAuthorizationAtDurableIntent,
    KillPinnedFrontendAtTargetLive,
    KillPinnedGuardianAtTargetLive,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PublicFaultTriggerV1 {
    schema_version: u8,
    fault: PublicFaultPlanV1,
    attempt_id: String,
    result_key: DiagnosticSha256,
    request_sha256: DiagnosticSha256,
    checkpoint_sha256: DiagnosticSha256,
    victim: super::private_attempt::ProcessIdentityV4,
    target: super::private_attempt::ProcessIdentityV4,
    durable_attempt_bytes: Vec<u8>,
    target_tcp_bytes: Vec<u8>,
    target_socket_inodes: Vec<u64>,
    operation_errno: Option<i32>,
}

fn fault_plan(selector: &str) -> Option<PublicFaultPlanV1> {
    match selector {
        "private_tcp::authorization_uncertainty_retired" => {
            Some(PublicFaultPlanV1::DropAuthorizationAtDurableIntent)
        }
        "private_tcp::frontend_loss_retired" => {
            Some(PublicFaultPlanV1::KillPinnedFrontendAtTargetLive)
        }
        "private_tcp::guardian_loss_retired" => {
            Some(PublicFaultPlanV1::KillPinnedGuardianAtTargetLive)
        }
        _ => None,
    }
}

fn fault_context(
    attempt_id: &str,
    phase: super::private_attempt::PrivateAttemptPhase,
) -> Result<Option<(PathBuf, PublicFaultTriggerV1)>, String> {
    if !Path::new(ROOT).exists() {
        return Ok(None);
    }
    let root = root()?;
    let _lock = lock(&root)?;
    let Some(record) = read_pending(&root)? else {
        return Ok(None);
    };
    let Some(fault) = fault_plan(&record.selector) else {
        return Ok(None);
    };
    let Some(reservation) = record
        .inflight
        .iter()
        .find(|entry| entry.attempt_id == attempt_id)
    else {
        return Ok(None);
    };
    verify_installed(&record)?;
    let directory = root
        .join(String::from(record.result_key.clone()))
        .join(format!("{}-{attempt_id}", reservation.ordinal));
    let bytes = read_file(
        &Path::new(super::STATE_ROOT).join(attempt_id),
        super::private_attempt::MAX_PRIVATE_RECORD_BYTES as u64,
        0o600,
    )?
    .ok_or("public fault durable attempt absent")?;
    reject_duplicate_json_keys(&bytes)?;
    let durable: super::private_attempt::PrivateAttemptRecordV4 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    durable.validate()?;
    if durable.attempt_id.as_str() != attempt_id
        || durable.phase != phase
        || durable.frontend.pid != record.peer_pid
        || durable.frontend.start_time != record.peer_start_time_ticks
    {
        return Err("public fault durable phase/actor differs".into());
    }
    let target = durable
        .target
        .as_ref()
        .ok_or("public fault target absent")?
        .clone();
    let victim = match fault {
        PublicFaultPlanV1::KillPinnedGuardianAtTargetLive => durable
            .guardian
            .as_ref()
            .ok_or("public fault guardian absent")?
            .clone(),
        PublicFaultPlanV1::KillPinnedFrontendAtTargetLive => durable.frontend.clone(),
        PublicFaultPlanV1::DropAuthorizationAtDurableIntent => target.clone(),
    };
    Ok(Some((
        directory,
        PublicFaultTriggerV1 {
            schema_version: 1,
            fault,
            attempt_id: attempt_id.into(),
            result_key: record.result_key,
            request_sha256: reservation.request_sha256.clone(),
            checkpoint_sha256: durable
                .checkpoint_digest
                .ok_or("public fault checkpoint absent")?,
            victim,
            target,
            durable_attempt_bytes: bytes,
            target_tcp_bytes: Vec::new(),
            target_socket_inodes: Vec::new(),
            operation_errno: None,
        },
    )))
}

fn pin_fault_process(
    identity: &super::private_attempt::ProcessIdentityV4,
) -> Result<std::os::fd::OwnedFd, String> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, identity.pid, 0) } as i32;
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    if super::private_attempt::ProcessIdentityV4::observe(identity.pid as i32, fd.as_fd())?
        != *identity
    {
        return Err("public fault process identity changed".into());
    }
    Ok(fd)
}

/// Called after exact durable ReleaseIntent, before the one-byte permit send.
/// Shutdown targets the owner-held transport, never an artifact-selected fd.
pub(crate) fn interrupt_public_authorization(
    attempt_id: &str,
    control: &File,
) -> Result<bool, String> {
    let Some((directory, mut trigger)) = fault_context(
        attempt_id,
        super::private_attempt::PrivateAttemptPhase::ReleaseIntent,
    )?
    else {
        return Ok(false);
    };
    if trigger.fault != PublicFaultPlanV1::DropAuthorizationAtDurableIntent {
        return Ok(false);
    }
    let _target = pin_fault_process(&trigger.target)?;
    if unsafe { libc::shutdown(control.as_raw_fd(), libc::SHUT_WR) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let release = [1_u8];
    let sent = unsafe {
        libc::send(
            control.as_raw_fd(),
            release.as_ptr().cast(),
            release.len(),
            libc::MSG_NOSIGNAL,
        )
    };
    let errno = std::io::Error::last_os_error().raw_os_error();
    if sent != -1 || errno != Some(libc::EPIPE) {
        return Err("public authorization fault did not produce EPIPE".into());
    }
    trigger.operation_errno = errno;
    write_new(
        &directory.join("fault-trigger-v1.json"),
        &serde_json::to_vec(&trigger).map_err(|error| error.to_string())?,
    )?;
    Ok(true)
}

/// Fixed signal fault at independently measured executed-target TCP liveness.
/// Pidfd identity and the held durable generation are checked before signaling.
pub(crate) fn trigger_public_live_fault(
    attempt_id: &str,
    mut tick_relay: impl FnMut() -> Result<(), String>,
) -> Result<bool, String> {
    let Some((directory, mut trigger)) = fault_context(
        attempt_id,
        super::private_attempt::PrivateAttemptPhase::ExecutionObserved,
    )?
    else {
        return Ok(false);
    };
    if trigger.fault == PublicFaultPlanV1::DropAuthorizationAtDurableIntent {
        return Ok(false);
    }
    let target = pin_fault_process(&trigger.target)?;
    let victim = pin_fault_process(&trigger.victim)?;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        tick_relay()?;
        let proc = Path::new("/proc").join(trigger.target.pid.to_string());
        let mut sockets = Vec::new();
        for entry in fs::read_dir(proc.join("fd")).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            if let Ok(link) = fs::read_link(entry.path()) {
                if let Some(inode) = link
                    .to_str()
                    .and_then(|text| text.strip_prefix("socket:["))
                    .and_then(|text| text.strip_suffix(']'))
                    .and_then(|text| text.parse::<u64>().ok())
                {
                    sockets.push(inode);
                }
            }
        }
        let tcp = fs::read(proc.join("net/tcp")).map_err(|error| error.to_string())?;
        if tcp.len() > 16 * 1024 {
            return Err("public target TCP snapshot too large".into());
        }
        let text = std::str::from_utf8(&tcp).map_err(|error| error.to_string())?;
        let mut listener = false;
        let mut established = false;
        for line in text.lines().skip(1) {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() > 9
                && fields[9]
                    .parse::<u64>()
                    .ok()
                    .is_some_and(|inode| sockets.contains(&inode))
            {
                listener |= fields[3] == "0A";
                established |= fields[3] == "01";
            }
        }
        if listener && established {
            trigger.target_tcp_bytes = tcp;
            trigger.target_socket_inodes = sockets;
            break;
        }
        if std::time::Instant::now() >= deadline {
            return Err("public fault target did not establish TCP barrier".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    // Persist the measured live fault context before the signal. Independent
    // root CI must retain its held-target raw measurements and acknowledge the
    // exact canonical gate, while the relay continues forwarding real output.
    let gate_bytes = serde_json::to_vec(&trigger).map_err(|error| error.to_string())?;
    write_new(&directory.join("fault-live-gate-v1.json"), &gate_bytes)?;
    let gate_digest = hash_bytes(&gate_bytes);
    let ack_path = directory.join("fault-live-gate-v1.ack");
    loop {
        tick_relay()?;
        match fs::symlink_metadata(&ack_path) {
            Ok(_) => {
                let ack = read_file(&ack_path, 32, 0o600)?.ok_or("public fault ACK disappeared")?;
                if ack.as_slice() != gate_digest.bytes() {
                    return Err("public fault live sampler ACK differs".into());
                }
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
        if std::time::Instant::now() >= deadline {
            return Err("public fault independent live sampler ACK timed out".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if super::private_attempt::ProcessIdentityV4::observe(
        trigger.target.pid as i32,
        target.as_fd(),
    )? != trigger.target
        || super::private_attempt::ProcessIdentityV4::observe(
            trigger.victim.pid as i32,
            victim.as_fd(),
        )? != trigger.victim
    {
        return Err("public fault pinned subject changed".into());
    }
    let signaled = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            victim.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if signaled != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    write_new(
        &directory.join("fault-trigger-v1.json"),
        &serde_json::to_vec(&trigger).map_err(|error| error.to_string())?,
    )?;
    Ok(true)
}

pub(crate) fn observe_public_cgroup_retirement(
    attempt_id: &str,
    bytes: &[u8],
) -> Result<(), String> {
    if !Path::new(ROOT).exists() {
        return Ok(());
    }
    let root = root()?;
    let _lock = lock(&root)?;
    let Some(provider) = read_pending(&root)? else {
        return Ok(());
    };
    let Some(reservation) = provider
        .inflight
        .iter()
        .find(|entry| entry.attempt_id == attempt_id)
    else {
        return Ok(());
    };
    verify_installed(&provider)?;
    let directory = root
        .join(String::from(provider.result_key))
        .join(format!("{}-{attempt_id}", reservation.ordinal));
    write_new(&directory.join("cgroup-retirement-v1.json"), bytes)
}

pub(crate) fn observe_public_durable_phase(
    record: &super::private_attempt::PrivateAttemptRecordV4,
) -> Result<(), String> {
    if !Path::new(ROOT).exists() {
        return Ok(());
    }
    let root = root()?;
    let _lock = lock(&root)?;
    let Some(provider) = read_pending(&root)? else {
        return Ok(());
    };
    let Some(reservation) = provider
        .inflight
        .iter()
        .find(|entry| entry.attempt_id == record.attempt_id.as_str())
    else {
        return Ok(());
    };
    let leaf = match record.phase {
        super::private_attempt::PrivateAttemptPhase::CheckpointCommitted => {
            "checkpoint-committed-v4.bin"
        }
        super::private_attempt::PrivateAttemptPhase::ReleaseIntent => "release-intent-v4.bin",
        super::private_attempt::PrivateAttemptPhase::ExecutionObserved => {
            "execution-observed-v4.bin"
        }
        _ => return Err("public durable phase outside declared observation".into()),
    };
    let bytes = read_file(
        &Path::new(super::STATE_ROOT).join(record.attempt_id.as_str()),
        super::private_attempt::MAX_PRIVATE_RECORD_BYTES as u64,
        0o600,
    )?
    .ok_or("public durable phase readback absent")?;
    let actual: super::private_attempt::PrivateAttemptRecordV4 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if actual != *record {
        return Err("public durable phase readback changed".into());
    }
    let directory = root.join(String::from(provider.result_key)).join(format!(
        "{}-{}",
        reservation.ordinal,
        record.attempt_id.as_str()
    ));
    write_new(&directory.join(leaf), &bytes)
}

/// Explicitly enrolled prepared-public sampling barrier. It exposes original
/// native state before exec/GO, never a pass verdict. Legacy runs without the
/// independently protected preparation policy do not gain a new barrier.
pub(crate) fn wait_public_phase_gate(
    record: &super::private_attempt::PrivateAttemptRecordV4,
    phase: &str,
    mut require_live: impl FnMut() -> Result<(), String>,
) -> Result<(), String> {
    use memcordon_core::private_public_preparation_v2::{
        ApprovedPublicPreparationPolicyV2, PreparedPublicDispatchRecordV2,
    };
    if !Path::new(ROOT).exists()
        || matches!(fs::symlink_metadata(PREPARATION_POLICY_V2),Err(error) if error.kind()==std::io::ErrorKind::NotFound)
    {
        return Ok(());
    }
    let selected = {
        let root = root()?;
        let _lock = lock(&root)?;
        read_pending(&root)?
    };
    let Some(provider) = selected else {
        return Ok(());
    };
    let Some(reservation) = provider
        .inflight
        .iter()
        .find(|entry| entry.attempt_id == record.attempt_id.as_str())
    else {
        return Ok(());
    };
    let policy = super::installed_release_qualification::read_protected_absolute(
        Path::new(PREPARATION_POLICY_V2),
        MAX_RECORD,
        Some(0o600),
    )?;
    reject_duplicate_json_keys(&policy)?;
    let approved: ApprovedPublicPreparationPolicyV2 =
        serde_json::from_slice(&policy).map_err(|error| error.to_string())?;
    let admission_path = Path::new("/run/memcordon-final-public/prepared-v2")
        .join(String::from(provider.result_key.clone()))
        .join("admission.json");
    let admission = super::installed_release_qualification::read_protected_absolute(
        &admission_path,
        MAX_RECORD * 8,
        Some(0o600),
    )?;
    reject_duplicate_json_keys(&admission)?;
    let prepared: PreparedPublicDispatchRecordV2 =
        serde_json::from_slice(&admission).map_err(|error| error.to_string())?;
    let contract = pinned_contract(
        Path::new(&prepared.contract_path),
        &prepared.contract_file_sha256,
    )?;
    prepared.validate(&approved, &contract)?;
    if prepared.result_key != provider.result_key
        || prepared.selector != provider.selector
        || prepared.challenge != decode_challenge(&provider.challenge)?
        || prepared.installation_epoch != provider.installation_epoch
        || prepared.active_h1_receipt_sha256 != provider.active_h1_receipt_sha256
        || !matches!(
            (phase, record.phase),
            (
                "pre-exec",
                super::private_attempt::PrivateAttemptPhase::TargetGated
            ) | (
                "release-intent",
                super::private_attempt::PrivateAttemptPhase::ReleaseIntent
            )
        )
    {
        return Err("prepared public phase gate differs from actual admitted case/phase".into());
    }
    let target = record
        .target
        .as_ref()
        .ok_or("public phase gate actual target absent")?;
    let directory = root()?
        .join(String::from(provider.result_key.clone()))
        .join(format!(
            "{}-{}",
            reservation.ordinal,
            record.attempt_id.as_str()
        ));
    let durable = read_file(
        &Path::new(super::STATE_ROOT).join(record.attempt_id.as_str()),
        super::private_attempt::MAX_PRIVATE_RECORD_BYTES as u64,
        0o600,
    )?
    .ok_or("public phase gate durable original absent")?;
    let actual: super::private_attempt::PrivateAttemptRecordV4 =
        serde_json::from_slice(&durable).map_err(|error| error.to_string())?;
    if actual != *record {
        return Err("public phase gate reopened native record differs".into());
    }
    let source_name = if phase == "pre-exec" {
        "public-pre-exec-source-v3.bin"
    } else {
        "public-release-intent-source-v3.bin"
    };
    let gate_name = if phase == "pre-exec" {
        "public-pre-exec-gate-v3.json"
    } else {
        "public-release-intent-gate-v3.json"
    };
    let ack_name = if phase == "pre-exec" {
        "public-pre-exec-gate-v3.ack"
    } else {
        "public-release-intent-gate-v3.ack"
    };
    let gate=serde_json::to_vec(&serde_json::json!({"schema_version":3,"selector":provider.selector,"result_key":provider.result_key,"attempt_id":record.attempt_id,"ordinal":reservation.ordinal,"phase":phase,"target":target,"boot_identity":record.boot_identity,"durable_source_sha256":hash_bytes(&durable),"prepared_admission_sha256":hash_bytes(&admission)})).map_err(|error|error.to_string())?;
    write_new(&directory.join(source_name), &durable)?;
    write_new(&directory.join(gate_name), &gate)?;
    let expected = hash_bytes(&gate);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        require_live()?;
        if let Some(ack) = read_file(&directory.join(ack_name), 32, 0o600)? {
            if ack.as_slice() != expected.bytes() {
                return Err("public phase sampler ACK differs from exact original gate".into());
            }
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err("public prepared phase source sampling deadline expired".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

pub(crate) fn observe_public_fault_retirement(
    attempt_id: &str,
    bytes: &[u8],
) -> Result<(), String> {
    if !Path::new(ROOT).exists() {
        return Ok(());
    }
    let root = root()?;
    let _lock = lock(&root)?;
    let Some(provider) = read_pending(&root)? else {
        return Ok(());
    };
    let Some(reservation) = provider
        .inflight
        .iter()
        .find(|entry| entry.attempt_id == attempt_id)
    else {
        return Ok(());
    };
    if fault_plan(&provider.selector).is_none() {
        return Ok(());
    }
    let directory = root
        .join(String::from(provider.result_key))
        .join(format!("{}-{attempt_id}", reservation.ordinal));
    if read_file(&directory.join("fault-trigger-v1.json"), MAX_RECORD, 0o600)?.is_none() {
        return Err("fault retirement lacks trigger".into());
    }
    if fs::symlink_metadata(Path::new(super::STATE_ROOT).join(attempt_id)).is_ok() {
        return Err("fault retirement left durable active record".into());
    }
    write_new(&directory.join("fault-retirement-v1.json"), bytes)
}

pub(crate) fn retain_public_fault_failure(
    attempt_id: &str,
    detail: &str,
    possibly_released: bool,
    cleanup_complete: bool,
) -> Result<(), String> {
    if !Path::new(ROOT).exists() {
        return Ok(());
    }
    let root = root()?;
    let _lock = lock(&root)?;
    let Some(provider) = read_pending(&root)? else {
        return Ok(());
    };
    let Some(reservation) = provider
        .inflight
        .iter()
        .find(|entry| entry.attempt_id == attempt_id)
    else {
        return Ok(());
    };
    if fault_plan(&provider.selector).is_none() {
        return Ok(());
    }
    let directory = root
        .join(String::from(provider.result_key))
        .join(format!("{}-{attempt_id}", reservation.ordinal));
    if read_file(&directory.join("fault-trigger-v1.json"), MAX_RECORD, 0o600)?.is_none() {
        return Err("fault failure lacks authenticated trigger".into());
    }
    let bytes = serde_json::to_vec(
        &serde_json::json!({"schema_version":1,"attempt_id":attempt_id,"detail":detail,
        "possibly_released":possibly_released,"cleanup_complete":cleanup_complete}),
    )
    .map_err(|error| error.to_string())?;
    write_new(&directory.join("fault-failure-v1.json"), &bytes)
}

use memcordon_core::private_release_branch_v1::{
    PolicyOperationBranchV1, one_policy_port_changed, policy_branch_challenge_v1,
};
use memcordon_core::workload_codec::{contract_digest_v2, hash_bytes};
use memcordon_core::workload_contract::WorkloadContract;
use memcordon_core::{DiagnosticSha256, workload_contract::reject_duplicate_json_keys};
use serde::{Deserialize, Serialize};

use crate::protocol::{Frame, MessageKind};

const ROOT: &str = "/var/lib/memcordon/sealed/private-public-cases";
const INTENT: &str = "/etc/memcordon/release-trust/final-public-dispatch.v1.json";
const PREPARATION_POLICY_V2: &str = "/etc/memcordon/release-trust/final-public-preparation.v2.json";
const PENDING: &str = "pending.v2.json";
const MAX_RECORD: u64 = 128 * 1024;
const MAX_RAW: u64 = crate::protocol::MAX_FRAME_LENGTH as u64;

pub(crate) fn retain_descriptor_auxiliary(
    selector: &str,
    key: &DiagnosticSha256,
    bytes: &[u8],
) -> Result<(), String> {
    let root = root()?;
    let _lock = lock(&root)?;
    let record = read_pending(&root)?.ok_or("descriptor auxiliary pending case absent")?;
    if record.selector != selector
        || record.result_key != *key
        || !record.inflight.is_empty()
        || !record.attempts.is_empty()
        || !matches!(record.phase.as_str(), "registered" | "plan-accepted")
        || bytes.is_empty()
        || bytes.len() > 16384
    {
        return Err("descriptor auxiliary exact registered case differs".into());
    }
    verify_installed(&record)?;
    write_new(
        &root
            .join(String::from(key.clone()))
            .join("descriptor-auxiliary-v1.json"),
        bytes,
    )
}

/// Versioned, case-linked controls under independently installed static
/// approval. The helper is disposable and grants neither product origin nor
/// launch authority; its two real held phases must be sampled before ACK.
pub(crate) fn run_prepared_facility_controls(
    selector: &str,
    challenge_hex: &str,
    revision_hex: &str,
) -> Result<(), String> {
    use memcordon_core::private_facility_source_v1::{
        FacilityPhaseV1, facility_source_revision_sha256,
    };
    use memcordon_core::private_public_preparation_v2::{
        ApprovedPublicPreparationPolicyV2, PreparedPublicDispatchRecordV2, PublicPreparedRoleV2,
    };
    if unsafe { libc::geteuid() } != 0 {
        return Err("public Facility source requires root".into());
    }
    // Includes independently pinned parent supervisor executable admission.
    read_admitted_dispatch_intent(selector, challenge_hex)?;
    let revision = DiagnosticSha256::from_bytes(decode_challenge(revision_hex)?);
    if revision != facility_source_revision_sha256() {
        return Err("public Facility source revision differs".into());
    }
    let policy = super::installed_release_qualification::read_protected_absolute(
        Path::new(PREPARATION_POLICY_V2),
        MAX_RECORD,
        Some(0o600),
    )?;
    reject_duplicate_json_keys(&policy)?;
    let approved: ApprovedPublicPreparationPolicyV2 =
        serde_json::from_slice(&policy).map_err(|error| error.to_string())?;
    approved.validate()?;
    let root = root()?;
    let _lock = lock(&root)?;
    let record = read_pending(&root)?.ok_or("public Facility source pending case absent")?;
    if record.selector != selector
        || record.challenge != challenge_hex
        || !record.attempts.is_empty()
        || !record.inflight.is_empty()
        || record.phase != "registered"
    {
        return Err("public Facility source is not the exact pre-launch registered case".into());
    }
    let key = String::from(record.result_key.clone());
    let admission = super::installed_release_qualification::read_protected_absolute(
        &Path::new("/run/memcordon-final-public/prepared-v2")
            .join(&key)
            .join("admission.json"),
        MAX_RECORD * 8,
        Some(0o600),
    )?;
    reject_duplicate_json_keys(&admission)?;
    let prepared: PreparedPublicDispatchRecordV2 =
        serde_json::from_slice(&admission).map_err(|error| error.to_string())?;
    prepared.validate(
        &approved,
        &pinned_contract(
            Path::new(&prepared.contract_path),
            &prepared.contract_file_sha256,
        )?,
    )?;
    if prepared.role != PublicPreparedRoleV2::Ordinary
        || prepared.result_key != record.result_key
        || prepared.selector != selector
        || prepared.challenge != decode_challenge(challenge_hex)?
        || prepared.installation_epoch != record.installation_epoch
        || prepared.active_h1_receipt_sha256 != record.active_h1_receipt_sha256
        || approved
            .cases
            .iter()
            .find(|case| case.selector == selector)
            .and_then(|case| case.facility_source_sha256.as_ref())
            != Some(&revision)
    {
        return Err("public Facility source exact preparation/opt-in differs".into());
    }
    let lease = crate::package::acquire_verified_private_qualification_lease()?;
    verify_installed(&record)?;
    let abi = match approved.target.as_str() {
        "x86_64-unknown-linux-gnu" => super::network_filter::NativeAbi::X86_64,
        "aarch64-unknown-linux-gnu" => super::network_filter::NativeAbi::Aarch64,
        _ => return Err("public Facility ABI unsupported".into()),
    };
    let directory = root.join(&key);
    check_directory(&directory, Some(0o700))?;
    let report = super::private_release_facility_controls::run_owned(
        selector,
        &record.result_key,
        abi,
        lease.filter_digest(),
        |phase, helper, objects, status| {
            lease.revalidate_release_boundary()?;
            let (gate_name, ack_name) = match phase {
                FacilityPhaseV1::Outer => (
                    "facility-helper-outer-v1.json",
                    "facility-helper-outer-v1.ack",
                ),
                FacilityPhaseV1::Private => (
                    "facility-helper-private-v1.json",
                    "facility-helper-private-v1.ack",
                ),
            };
            let gate=serde_json::to_vec(&serde_json::json!({"schema_version":1,"selector":selector,"parent_result_key":record.result_key,
            "prepared_admission_sha256":hash_bytes(&admission),"installation_epoch":record.installation_epoch,
            "active_h1_receipt_sha256":record.active_h1_receipt_sha256,"manifest_sha256":record.manifest_sha256,
            "qualification_sha256":record.qualification_sha256,"source_revision_sha256":revision,"phase":phase,
            "helper":helper,"objects":objects,"status":status,"observed_monotonic_ns":super::clock::monotonic_nanos()?})).map_err(|error|error.to_string())?;
            write_new(&directory.join(gate_name), &gate)?;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            loop {
                if let Some(ack) = read_file(&directory.join(ack_name), 32, 0o600)? {
                    if ack.as_slice() != hash_bytes(&gate).bytes() {
                        return Err("public Facility gate ACK differs".into());
                    }
                    lease.revalidate_release_boundary()?;
                    return Ok(());
                }
                if std::time::Instant::now() >= deadline {
                    return Err("public Facility gate sampling deadline expired".into());
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        },
    )?;
    lease.revalidate_release_boundary()?;
    write_new(
        &directory.join("facility-source-v1.json"),
        &serde_json::to_vec(&report).map_err(|error| error.to_string())?,
    )
}

#[derive(Deserialize)]
struct DispatchIntent {
    schema_version: u8,
    source_commit: String,
    target: String,
    manifest_sha256: DiagnosticSha256,
    qualification_sha256: DiagnosticSha256,
    public_cli_sha256: DiagnosticSha256,
    public_uid: u32,
    public_gid: u32,
    historical_e0: Option<HistoricalDispatchCase>,
    historical_spoof: Option<HistoricalSpoofDispatchCase>,
    policy: Option<PolicyDispatch>,
    cases: Vec<DispatchCase>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDispatch {
    base_challenge: String,
    branches: Vec<PolicyDispatchBranch>,
}

#[derive(Deserialize)]
#[allow(dead_code)] // CI-owned fixture/report routing is parsed but never admission authority.
struct PolicyDispatchBranch {
    #[serde(flatten)]
    case: DispatchCase,
    policy_branch: PolicyOperationBranchV1,
    tampered_contract_path: Option<PathBuf>,
    tampered_contract_sha256: Option<DiagnosticSha256>,
    fixture_path: PathBuf,
    fixture_sha256: DiagnosticSha256,
    expected_plan_path: Option<PathBuf>,
    expected_plan_sha256: Option<DiagnosticSha256>,
    report_path: PathBuf,
    outcome: String,
}

#[derive(Deserialize)]
struct DispatchCase {
    selector: String,
    challenge: String,
    contract_path: PathBuf,
    contract_sha256: DiagnosticSha256,
}

#[derive(Deserialize)]
struct HistoricalDispatchCase {
    #[serde(flatten)]
    case: DispatchCase,
    e0_installation_epoch_sha256: DiagnosticSha256,
    e0_h1_receipt_sha256: DiagnosticSha256,
}

#[derive(Deserialize)]
struct HistoricalSpoofDispatchCase {
    #[serde(flatten)]
    case: DispatchCase,
    unauthorized_uid: u32,
    unauthorized_gid: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderRecordV2 {
    schema_version: u8,
    evidence_scope: String,
    selector: String,
    challenge: String,
    result_key: DiagnosticSha256,
    contract_digest: DiagnosticSha256,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy_branch: Option<PolicyOperationBranchV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy_base_challenge_sha256: Option<DiagnosticSha256>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tampered_contract_digest: Option<DiagnosticSha256>,
    peer_pid: u32,
    peer_start_time_ticks: u64,
    peer_uid: u32,
    peer_gid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    spoof_authorized_uid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    spoof_contract_file_sha256: Option<DiagnosticSha256>,
    installation_epoch: DiagnosticSha256,
    manifest_sha256: DiagnosticSha256,
    qualification_sha256: DiagnosticSha256,
    active_h1_receipt_sha256: DiagnosticSha256,
    plan_request_sha256: Option<DiagnosticSha256>,
    plan_response_sha256: Option<DiagnosticSha256>,
    plan_response_kind: Option<u16>,
    grant_decision_sha256: Option<DiagnosticSha256>,
    expected_launch_exchanges: u8,
    attempts: Vec<ProviderAttemptV2>,
    inflight: Vec<ProviderInflightV2>,
    terminal_sha256: Option<DiagnosticSha256>,
    phase: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderAttemptV2 {
    ordinal: u8,
    attempt_id: String,
    launch_request_sha256: DiagnosticSha256,
    launch_response_sha256: DiagnosticSha256,
    launch_response_kind: u16,
    terminal_sha256: Option<DiagnosticSha256>,
    cleanup_sha256: Option<DiagnosticSha256>,
    target_identity_sha256: Option<DiagnosticSha256>,
    fault_trigger_sha256: Option<DiagnosticSha256>,
    fault_failure_sha256: Option<DiagnosticSha256>,
    fault_retirement_sha256: Option<DiagnosticSha256>,
    fault_recovery_sha256: Option<DiagnosticSha256>,
    checkpoint_committed_sha256: Option<DiagnosticSha256>,
    release_intent_sha256: Option<DiagnosticSha256>,
    execution_observed_sha256: Option<DiagnosticSha256>,
    #[serde(default)]
    cgroup_retirement_sha256: Option<DiagnosticSha256>,
    phase: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderInflightV2 {
    ordinal: u8,
    attempt_id: String,
    nonce: String,
    request_sha256: DiagnosticSha256,
}

/// Read-only current provider binding for the distinct public reuse fixture.
/// It cannot authorize a launch, mutate the transcript, or create a result.
#[derive(Clone)]
pub(crate) struct ReuseProviderBindingV1 {
    pub(crate) result_key: DiagnosticSha256,
    pub(crate) challenge: String,
    pub(crate) installation_epoch: DiagnosticSha256,
    pub(crate) active_h1_receipt_sha256: DiagnosticSha256,
    pub(crate) first_attempt_id: Option<String>,
    pub(crate) ordinal: u8,
}

pub(crate) fn current_reuse_binding(
    expected_key: Option<&DiagnosticSha256>,
    attempt_id: Option<&str>,
) -> Result<ReuseProviderBindingV1, String> {
    let root = root()?;
    let _lock = lock(&root)?;
    let record = read_pending(&root)?.ok_or("final-public reuse registration absent")?;
    if record.selector != "private_tcp::retirement_failure_blocks_reuse"
        || expected_key.is_some_and(|key| record.result_key != *key)
        || record.expected_launch_exchanges != 2
        || record.phase != "plan-accepted"
    {
        return Err("final-public reuse provider binding differs".into());
    }
    verify_installed(&record)?;
    let ordinal = u8::try_from(record.attempts.len()).map_err(|error| error.to_string())?;
    if let Some(attempt_id) = attempt_id {
        let inflight = record
            .inflight
            .first()
            .ok_or("final-public reuse attempt not reserved")?;
        if inflight.ordinal != ordinal || inflight.attempt_id != attempt_id {
            return Err("final-public reuse attempt binding differs".into());
        }
    }
    Ok(ReuseProviderBindingV1 {
        result_key: record.result_key,
        challenge: record.challenge,
        installation_epoch: record.installation_epoch,
        active_h1_receipt_sha256: record.active_h1_receipt_sha256,
        first_attempt_id: record
            .attempts
            .first()
            .map(|attempt| attempt.attempt_id.clone()),
        ordinal,
    })
}

pub(crate) fn reuse_holder_registration_pending(key: &DiagnosticSha256) -> Result<bool, String> {
    let directory = root()?;
    let _lock = lock(&directory)?;
    let record = read_pending(&directory)?.ok_or("reuse holder registration absent")?;
    verify_installed(&record)?;
    if record.result_key != *key
        || record.selector != "private_tcp::retirement_failure_blocks_reuse"
        || record.expected_launch_exchanges != 2
    {
        return Err("reuse holder initial registration key/selector differs".into());
    }
    Ok(record.phase == "registered" && record.attempts.is_empty() && record.inflight.is_empty())
}

/// New prepared helper path shares the independently admitted CI parent and
/// immutable current-H1 case recipe; legacy installations retain their gate.
pub(crate) fn verify_prepared_reuse_helper_admission(
    selector: &str,
    challenge: &str,
) -> Result<(), String> {
    match std::fs::symlink_metadata(PREPARATION_POLICY_V2) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
        Ok(_) => {
            if selector != "private_tcp::retirement_failure_blocks_reuse" {
                return Err("prepared reuse helper selector differs".into());
            }
            read_admitted_dispatch_intent(selector, challenge)?;
            Ok(())
        }
    }
}

pub(crate) fn reuse_binding_for_attempt(
    attempt_id: &str,
) -> Result<Option<ReuseProviderBindingV1>, String> {
    if !Path::new(ROOT).exists() {
        return Ok(None);
    }
    let root = root()?;
    let _lock = lock(&root)?;
    let Some(record) = read_pending(&root)? else {
        return Ok(None);
    };
    if record.selector != "private_tcp::retirement_failure_blocks_reuse" {
        return Ok(None);
    }
    let Some(inflight) = record.inflight.first() else {
        return Ok(None);
    };
    if inflight.attempt_id != attempt_id {
        return Ok(None);
    }
    verify_installed(&record)?;
    let ordinal = u8::try_from(record.attempts.len()).map_err(|error| error.to_string())?;
    if record.expected_launch_exchanges != 2 || inflight.ordinal != ordinal {
        return Err("final-public reuse inflight ordinal differs".into());
    }
    Ok(Some(ReuseProviderBindingV1 {
        result_key: record.result_key,
        challenge: record.challenge,
        installation_epoch: record.installation_epoch,
        active_h1_receipt_sha256: record.active_h1_receipt_sha256,
        first_attempt_id: record
            .attempts
            .first()
            .map(|attempt| attempt.attempt_id.clone()),
        ordinal,
    }))
}

#[derive(Clone)]
pub(crate) struct AbiFilteredProviderBindingV1 {
    pub(crate) result_key: DiagnosticSha256,
    pub(crate) challenge: String,
    pub(crate) installation_epoch: DiagnosticSha256,
    pub(crate) active_h1_receipt_sha256: DiagnosticSha256,
}

pub(crate) fn abi_filtered_binding_for_attempt(
    attempt_id: &str,
) -> Result<Option<AbiFilteredProviderBindingV1>, String> {
    if !Path::new(ROOT).exists() {
        return Ok(None);
    }
    let root = root()?;
    let _lock = lock(&root)?;
    let Some(record) = read_pending(&root)? else {
        return Ok(None);
    };
    if record.selector != "private_tcp::abi_alternate_entry_denied" {
        return Ok(None);
    }
    let inflight = record
        .inflight
        .first()
        .ok_or("final-public ABI launch reservation absent")?;
    if record.expected_launch_exchanges != 1
        || record.attempts.len() != 0
        || inflight.ordinal != 0
        || inflight.attempt_id != attempt_id
    {
        return Err("final-public ABI launch reservation differs".into());
    }
    verify_installed(&record)?;
    Ok(Some(AbiFilteredProviderBindingV1 {
        result_key: record.result_key,
        challenge: record.challenge,
        installation_epoch: record.installation_epoch,
        active_h1_receipt_sha256: record.active_h1_receipt_sha256,
    }))
}

pub(crate) fn abi_filtered_attempt_reserved(attempt_id: &str) -> Result<bool, String> {
    Ok(abi_filtered_binding_for_attempt(attempt_id)?.is_some())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedPublicSpoofV1 {
    schema_version: u8,
    selector: String,
    challenge: String,
    result_key: DiagnosticSha256,
    authenticated_peer_uid: u32,
    authenticated_peer_gid: u32,
    authenticated_peer_pid: u32,
    authenticated_peer_start_ticks: u64,
    authorized_uid: u32,
    installation_epoch: DiagnosticSha256,
    active_h1_receipt_sha256: DiagnosticSha256,
    contract_file_sha256: DiagnosticSha256,
    grant_decision_sha256: DiagnosticSha256,
    request_sha256: DiagnosticSha256,
    rejection_sha256: DiagnosticSha256,
    rejection_code: String,
    durable_attempt_record_absent: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderTargetGateV1 {
    schema_version: u8,
    evidence_scope: String,
    attempt_id: String,
    request_sha256: DiagnosticSha256,
    durable_attempt_record_sha256: DiagnosticSha256,
    target: super::private_attempt::ProcessIdentityV4,
    namespace_init: super::private_attempt::ProcessIdentityV4,
    network_namespace_inode: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderTargetIdentityV1 {
    #[serde(flatten)]
    gated: ProviderTargetGateV1,
    entrypoint_sha256: DiagnosticSha256,
    entrypoint_device: u64,
    entrypoint_inode: u64,
    entrypoint_path: String,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum ProviderGrantOutcomeV1 {
    Granted {
        grant: memcordon_core::workload_registry_v2::PolicyGrantV2,
    },
    Rejected {
        rejection: memcordon_core::workload_registry_v2::AdmissionRejectionV2,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderGrantDecisionV1 {
    schema_version: u8,
    evidence_scope: String,
    selector: String,
    challenge: String,
    result_key: DiagnosticSha256,
    contract_digest: DiagnosticSha256,
    peer_pid: u32,
    peer_start_time_ticks: u64,
    peer_uid: u32,
    peer_gid: u32,
    installation_epoch: DiagnosticSha256,
    active_h1_receipt_sha256: DiagnosticSha256,
    registry_digest: DiagnosticSha256,
    policy_epoch: memcordon_core::workload_contract::PolicyEpoch,
    plan_request_sha256: DiagnosticSha256,
    plan_response_sha256: DiagnosticSha256,
    plan_response_kind: u16,
    outcome: ProviderGrantOutcomeV1,
}

fn expected_launch_exchanges(
    selector: &str,
    branch: Option<PolicyOperationBranchV1>,
) -> Result<u8, String> {
    if selector == "private_tcp::wrong_grant_profile_and_port_rejected" {
        return match branch {
            Some(
                PolicyOperationBranchV1::AcceptedControl
                | PolicyOperationBranchV1::CommittedPortTamper,
            ) => Ok(1),
            Some(
                PolicyOperationBranchV1::WrongGrant
                | PolicyOperationBranchV1::WrongProfile
                | PolicyOperationBranchV1::UnapprovedChangedPortPlan,
            ) => Ok(0),
            None => Err("final-public policy branch absent".into()),
        };
    }
    if branch.is_some() {
        return Err("final-public nonpolicy selector has policy branch".into());
    }
    match selector {
        "private_tcp::dual_attempt_namespace_isolation"
        | "private_tcp::retirement_failure_blocks_reuse" => Ok(2),
        _ => Ok(1),
    }
}

fn policy_plan_denial(
    branch: Option<PolicyOperationBranchV1>,
) -> Option<memcordon_core::workload_registry_v2::AdmissionCodeV2> {
    use memcordon_core::workload_registry_v2::AdmissionCodeV2;
    match branch {
        Some(PolicyOperationBranchV1::WrongGrant) => Some(AdmissionCodeV2::ProfileNotAuthorized),
        Some(PolicyOperationBranchV1::WrongProfile) => Some(AdmissionCodeV2::ProfileDigestMismatch),
        Some(PolicyOperationBranchV1::UnapprovedChangedPortPlan) => {
            Some(AdmissionCodeV2::PlanNotApproved)
        }
        _ => None,
    }
}

#[cfg(feature = "test-support")]
pub(crate) fn expected_launch_exchanges_for_test(selector: &str) -> Result<u8, String> {
    expected_launch_exchanges(selector, None)
}

#[cfg(feature = "test-support")]
pub(crate) fn expected_policy_launch_exchanges_for_test(
    branch: PolicyOperationBranchV1,
) -> Result<u8, String> {
    expected_launch_exchanges(
        "private_tcp::wrong_grant_profile_and_port_rejected",
        Some(branch),
    )
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderCleanupObservationV1 {
    schema_version: u8,
    evidence_scope: String,
    attempt_id: String,
    terminal_sha256: DiagnosticSha256,
    provider_response_kind: u16,
    durable_attempt_record_absent: bool,
    boot_id: String,
}

fn decode_challenge(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("final-public challenge syntax differs".into());
    }
    let mut result = [0_u8; 32];
    for (output, pair) in result.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let high = (pair[0] as char)
            .to_digit(16)
            .ok_or("final-public challenge digit differs")?;
        let low = (pair[1] as char)
            .to_digit(16)
            .ok_or("final-public challenge digit differs")?;
        *output = ((high << 4) | low) as u8;
    }
    if result == [0; 32] {
        return Err("final-public challenge is zero".into());
    }
    Ok(result)
}

fn pinned_contract(
    path: &Path,
    expected: &DiagnosticSha256,
) -> Result<memcordon_core::workload_contract::WorkloadContractV2, String> {
    if !path.starts_with("/run/memcordon-final-public/")
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err("final-public contract path differs".into());
    }
    let bytes =
        super::installed_release_qualification::read_protected_absolute(path, 1024 * 1024, None)?;
    if hash_bytes(&bytes) != *expected {
        return Err("final-public protected contract differs".into());
    }
    let WorkloadContract::V2(contract) = WorkloadContract::parse(&bytes)? else {
        return Err("final-public contract is not V2".into());
    };
    Ok(contract)
}

fn policy_dispatch_branch<'a>(
    intent: &'a DispatchIntent,
    selector: &str,
    challenge_hex: &str,
) -> Result<Option<(&'a PolicyDispatchBranch, DiagnosticSha256)>, String> {
    if selector != "private_tcp::wrong_grant_profile_and_port_rejected" {
        return Ok(None);
    }
    let policy = intent
        .policy
        .as_ref()
        .ok_or("final-public policy dispatch absent")?;
    let base = decode_challenge(&policy.base_challenge)?;
    let base_case = intent.cases.iter().find(|entry| entry.selector == selector);
    if policy.branches.len() != PolicyOperationBranchV1::ALL.len()
        || intent
            .cases
            .iter()
            .filter(|entry| entry.selector == selector)
            .count()
            != 1
        || base_case.is_none_or(|entry| {
            entry.challenge != policy.base_challenge
                || policy
                    .branches
                    .first()
                    .is_none_or(|accepted| entry.contract_sha256 != accepted.case.contract_sha256)
        })
    {
        return Err("final-public policy composite intent differs".into());
    }
    for (entry, branch) in policy.branches.iter().zip(PolicyOperationBranchV1::ALL) {
        let derived = policy_branch_challenge_v1(&base, branch).map_err(str::to_owned)?;
        if entry.case.selector != selector
            || entry.policy_branch != branch
            || decode_challenge(&entry.case.challenge)? != derived
            || entry.case.challenge == policy.base_challenge
            || entry.tampered_contract_path.is_some()
                != (branch == PolicyOperationBranchV1::CommittedPortTamper)
            || entry.tampered_contract_sha256.is_some()
                != (branch == PolicyOperationBranchV1::CommittedPortTamper)
            || branch == PolicyOperationBranchV1::CommittedPortTamper
                && entry.case.contract_sha256 != policy.branches[0].case.contract_sha256
            || entry.expected_plan_path.is_some() != entry.expected_plan_sha256.is_some()
            || entry.expected_plan_path.is_some()
                != matches!(
                    branch,
                    PolicyOperationBranchV1::AcceptedControl
                        | PolicyOperationBranchV1::CommittedPortTamper
                )
            || entry.outcome.is_empty()
        {
            return Err("final-public policy derived branch intent differs".into());
        }
    }
    let selected = policy
        .branches
        .iter()
        .find(|entry| entry.case.challenge == challenge_hex)
        .ok_or("final-public policy branch challenge is not root-pinned")?;
    Ok(Some((selected, hash_bytes(&base))))
}

#[cfg(feature = "test-support")]
pub(crate) fn decode_challenge_for_test(value: &str) -> Result<[u8; 32], String> {
    decode_challenge(value)
}

fn check_directory(path: &Path, exact_mode: Option<u32>) -> Result<(), String> {
    let meta = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !meta.is_dir()
        || meta.uid() != 0
        || meta.mode() & 0o022 != 0
        || exact_mode.is_some_and(|mode| meta.mode() & 0o7777 != mode)
    {
        return Err("final-public provider directory protection differs".into());
    }
    Ok(())
}

fn root() -> Result<PathBuf, String> {
    let parent = Path::new("/var/lib/memcordon/sealed");
    for path in [
        Path::new("/var"),
        Path::new("/var/lib"),
        Path::new("/var/lib/memcordon"),
        parent,
    ] {
        check_directory(path, None)?;
    }
    let root = PathBuf::from(ROOT);
    match fs::create_dir(&root) {
        Ok(()) => fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.to_string()),
    }
    check_directory(&root, Some(0o700))?;
    Ok(root)
}

fn lock(root: &Path) -> Result<File, String> {
    lock_mode(root, false)
}

fn lock_mode(root: &Path, nonblocking: bool) -> Result<File, String> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root.join("lock"))
        .map_err(|error| error.to_string())?;
    let meta = file.metadata().map_err(|error| error.to_string())?;
    if !meta.is_file() || meta.uid() != 0 || meta.nlink() != 1 || meta.mode() & 0o7777 != 0o600 {
        return Err("final-public provider lock protection differs".into());
    }
    let flags = libc::LOCK_EX | if nonblocking { libc::LOCK_NB } else { 0 };
    if unsafe { libc::flock(file.as_raw_fd(), flags) } < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(file)
}

fn read_file(path: &Path, maximum: u64, mode: u32) -> Result<Option<Vec<u8>>, String> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let before = file.metadata().map_err(|error| error.to_string())?;
    if !before.is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || before.mode() & 0o7777 != mode
        || before.len() == 0
        || before.len() > maximum
    {
        return Err("final-public provider file protection differs".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let after = file.metadata().map_err(|error| error.to_string())?;
    if bytes.len() as u64 != before.len()
        || (
            before.dev(),
            before.ino(),
            before.len(),
            before.mode(),
            before.uid(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.len(),
            after.mode(),
            after.uid(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        )
    {
        return Err("final-public provider file changed during readback".into());
    }
    Ok(Some(bytes))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_RAW {
        return Err("final-public provider record bound differs".into());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| error.to_string())?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string())?;
    File::open(path.parent().ok_or("provider parent absent")?)
        .and_then(|parent| parent.sync_all())
        .map_err(|error| error.to_string())
}

fn replace_pending(root: &Path, record: &ProviderRecordV2) -> Result<(), String> {
    let bytes = serde_json::to_vec(record).map_err(|error| error.to_string())?;
    let temporary = root.join("pending.v2.new");
    write_new(&temporary, &bytes)?;
    fs::rename(&temporary, root.join(PENDING)).map_err(|error| error.to_string())?;
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())
}

fn read_pending(root: &Path) -> Result<Option<ProviderRecordV2>, String> {
    let Some(bytes) = read_file(&root.join(PENDING), MAX_RECORD, 0o600)? else {
        return Ok(None);
    };
    reject_duplicate_json_keys(&bytes)?;
    let record: ProviderRecordV2 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if record.schema_version != 3 || record.evidence_scope != "provider-frames-only" {
        return Err("final-public provider pending schema differs".into());
    }
    if record.expected_launch_exchanges > 2
        || record.attempts.len() + record.inflight.len()
            > usize::from(record.expected_launch_exchanges)
        || (record.inflight.len() > 1
            && record.selector != "private_tcp::dual_attempt_namespace_isolation")
    {
        return Err("public provider reservation bound differs".into());
    }
    Ok(Some(record))
}

/// Package mutations must not carry a one-shot actor registration across an
/// installation epoch. A completed E0 transcript remains detached and inert.
pub(crate) fn require_idle_for_package_mutation() -> Result<File, String> {
    let root = root()?;
    let guard = lock_mode(&root, true)?;
    if read_pending(&root)?.is_some()
        || root.join("pending.v2.new").exists()
        || root.join("pending.v1.json").exists()
        || root.join("pending.v1.new").exists()
    {
        return Err("final-public provider registration is active or interrupted".into());
    }
    Ok(guard)
}

fn observed_child(pid: libc::pid_t) -> Result<(u32, u64), String> {
    if pid <= 0 {
        return Err("final-public child pid differs".into());
    }
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let pidfd = unsafe { File::from_raw_fd(fd) };
    let identity = super::private_attempt::ProcessIdentityV4::observe(pid, pidfd.as_fd())?;
    Ok((identity.pid, identity.start_time))
}

/// Explicit opt-in keeps legacy admission unchanged. A runtime preparation
/// cannot enable this policy, choose a new grant, or become observer origin.
fn read_admitted_dispatch_intent(
    selector: &str,
    challenge_hex: &str,
) -> Result<DispatchIntent, String> {
    use memcordon_core::private_public_preparation_v2::{
        ApprovedPublicPreparationPolicyV2, PreparedPublicDispatchRecordV2, PublicPreparedRoleV2,
    };
    if !matches!(fs::symlink_metadata(PREPARATION_POLICY_V2),Err(error) if error.kind()==std::io::ErrorKind::NotFound)
    {
        let bytes = super::installed_release_qualification::read_protected_absolute(
            Path::new(PREPARATION_POLICY_V2),
            MAX_RECORD,
            Some(0o600),
        )?;
        reject_duplicate_json_keys(&bytes)?;
        let approved: ApprovedPublicPreparationPolicyV2 =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        approved.validate()?;
        let parent = unsafe { libc::getppid() };
        let parent_before = observed_child(parent)?;
        let image = File::open(Path::new("/proc").join(parent.to_string()).join("exe"))
            .map_err(|error| error.to_string())?;
        let metadata = image.metadata().map_err(|error| error.to_string())?;
        if metadata.uid() != 0
            || !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.mode() & 0o022 != 0
        {
            return Err("public preparer executable is not an enrolled protected image".into());
        }
        let mut image_bytes = Vec::new();
        (&image)
            .take(64 * 1024 * 1024 + 1)
            .read_to_end(&mut image_bytes)
            .map_err(|error| error.to_string())?;
        let image_after = image.metadata().map_err(|error| error.to_string())?;
        if image_bytes.len() > 64 * 1024 * 1024
            || image_bytes.len() as u64 != metadata.len()
            || image_after.dev() != metadata.dev()
            || image_after.ino() != metadata.ino()
            || image_after.len() != metadata.len()
            || image_after.ctime() != metadata.ctime()
            || image_after.ctime_nsec() != metadata.ctime_nsec()
            || hash_bytes(&image_bytes) != approved.preparer_image_sha256
            || observed_child(parent)? != parent_before
        {
            return Err("public preparer pinned executable/process changed".into());
        }
        let challenge = decode_challenge(challenge_hex)?;
        let key =
            super::private_public_release_case::FinalPublicCaseSpecV1::new(selector, challenge)?
                .result_key();
        let path = Path::new("/run/memcordon-final-public/prepared-v2")
            .join(String::from(key.clone()))
            .join("admission.json");
        let bytes = super::installed_release_qualification::read_protected_absolute(
            &path,
            MAX_RECORD * 8,
            Some(0o600),
        )?;
        reject_duplicate_json_keys(&bytes)?;
        let prepared: PreparedPublicDispatchRecordV2 =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        let contract = pinned_contract(
            Path::new(&prepared.contract_path),
            &prepared.contract_file_sha256,
        )?;
        prepared.validate(&approved, &contract)?;
        if prepared.selector != selector
            || prepared.challenge != challenge
            || prepared.result_key != key
        {
            return Err("public preparation is not the selected exact case".into());
        }
        let lease = crate::package::acquire_verified_private_qualification_lease()?;
        if prepared.installation_epoch != *lease.generation_digest()
            || prepared.active_h1_receipt_sha256 != *lease.active_host_receipt_sha256()
            || approved.source_commit != lease.source_commit()
            || approved.manifest_sha256 != *lease.runtime_manifest_sha256()
            || approved.qualification_sha256 != *lease.qualification_digest()
        {
            return Err("public preparation differs from actual installed H1 generation".into());
        }
        reject_duplicate_json_keys(&prepared.dispatch_bytes)?;
        let intent: DispatchIntent =
            serde_json::from_slice(&prepared.dispatch_bytes).map_err(|error| error.to_string())?;
        if intent.schema_version != 1
            || intent.source_commit != approved.source_commit
            || intent.target != approved.target
            || intent.manifest_sha256 != approved.manifest_sha256
            || intent.qualification_sha256 != approved.qualification_sha256
            || intent.public_cli_sha256 != approved.public_cli_sha256
            || intent.public_uid != approved.public_uid
            || intent.public_gid != approved.public_gid
        {
            return Err("prepared diagnostic routing changed static release/caller pins".into());
        }
        let selected = match prepared.role {
            PublicPreparedRoleV2::Ordinary => intent
                .cases
                .iter()
                .find(|case| case.selector == selector && case.challenge == challenge_hex),
            PublicPreparedRoleV2::HistoricalE0 => intent
                .historical_e0
                .as_ref()
                .filter(|entry| {
                    entry.e0_installation_epoch_sha256 == prepared.installation_epoch
                        && entry.e0_h1_receipt_sha256 == prepared.active_h1_receipt_sha256
                })
                .map(|entry| &entry.case),
            PublicPreparedRoleV2::CallerSpoof => intent
                .historical_spoof
                .as_ref()
                .filter(|entry| {
                    entry.unauthorized_uid == approved.historical_spoof_uid
                        && entry.unauthorized_gid == approved.historical_spoof_gid
                })
                .map(|entry| &entry.case),
            PublicPreparedRoleV2::Policy { branch } => intent
                .policy
                .as_ref()
                .and_then(|policy| {
                    policy
                        .branches
                        .iter()
                        .find(|entry| entry.policy_branch == branch)
                })
                .map(|entry| &entry.case),
        }
        .ok_or("prepared exact diagnostic routing role absent")?;
        if selected.selector != prepared.selector
            || selected.challenge != challenge_hex
            || selected.contract_path != Path::new(&prepared.contract_path)
            || selected.contract_sha256 != prepared.contract_file_sha256
        {
            return Err("prepared routing selected a different exact contract".into());
        }
        // A policy preparation never accepts an artifact-chosen base nonce.
        if let PublicPreparedRoleV2::Policy { branch } = prepared.role {
            let base = approved.challenge(
                prepared.session_nonce,
                prepared.generation,
                selector,
                PublicPreparedRoleV2::Ordinary,
            )?;
            let policy = intent.policy.as_ref().ok_or("prepared policy absent")?;
            if policy.base_challenge != String::from(DiagnosticSha256::from_bytes(base))
                || policy.branches.len() != 5
                || policy
                    .branches
                    .iter()
                    .filter(|entry| entry.policy_branch == branch)
                    .count()
                    != 1
            {
                return Err("prepared policy base/branch inventory differs".into());
            }
        }
        lease.revalidate_release_boundary()?;
        Ok(intent)
    } else {
        let bytes = super::installed_release_qualification::read_protected_absolute(
            Path::new(INTENT),
            MAX_RECORD,
            Some(0o600),
        )?;
        reject_duplicate_json_keys(&bytes)?;
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())
    }
}

pub(crate) fn register(
    selector: &str,
    challenge_hex: &str,
    child_pid: libc::pid_t,
    child_start_time_ticks: u64,
) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("final-public provider registration requires root".into());
    }
    let current = fs::metadata(std::env::current_exe().map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())?;
    let installed = fs::symlink_metadata("/usr/libexec/memcordon-sealed-agent")
        .map_err(|error| error.to_string())?;
    if !installed.is_file() || (current.dev(), current.ino()) != (installed.dev(), installed.ino())
    {
        return Err("final-public registration requires installed agent image".into());
    }
    let challenge = decode_challenge(challenge_hex)?;
    let case = super::private_public_release_case::FinalPublicCaseSpecV1::new(selector, challenge)?;
    let (observed_pid, observed_start) = observed_child(child_pid)?;
    if observed_start != child_start_time_ticks {
        return Err("final-public child identity changed before registration".into());
    }
    let intent = read_admitted_dispatch_intent(selector, challenge_hex)?;
    if intent.schema_version != 1 || intent.public_uid == 0 || intent.public_gid == 0 {
        return Err("final-public dispatch peer identity differs".into());
    }
    let policy_branch = policy_dispatch_branch(&intent, selector, challenge_hex)?;
    let ordinary = if policy_branch.is_none() {
        intent
            .cases
            .iter()
            .find(|entry| entry.selector == selector && entry.challenge == challenge_hex)
    } else {
        None
    };
    let historical = intent
        .historical_e0
        .as_ref()
        .filter(|entry| entry.case.selector == selector && entry.case.challenge == challenge_hex);
    let spoof = intent
        .historical_spoof
        .as_ref()
        .filter(|entry| entry.case.selector == selector && entry.case.challenge == challenge_hex);
    if usize::from(ordinary.is_some())
        + usize::from(historical.is_some())
        + usize::from(policy_branch.is_some())
        + usize::from(spoof.is_some())
        != 1
    {
        return Err("final-public challenge is absent or multiply root-pinned".into());
    }
    let pinned = policy_branch
        .as_ref()
        .map(|(entry, _)| &entry.case)
        .or(ordinary)
        .or_else(|| historical.map(|entry| &entry.case))
        .or_else(|| spoof.map(|entry| &entry.case))
        .expect("exactly one dispatch entry");
    let contract = pinned_contract(&pinned.contract_path, &pinned.contract_sha256)?;
    let tampered_contract_digest = if let Some((entry, _)) = policy_branch.as_ref() {
        match (
            &entry.tampered_contract_path,
            &entry.tampered_contract_sha256,
        ) {
            (Some(path), Some(digest)) => {
                let changed = pinned_contract(path, digest)?;
                if !one_policy_port_changed(&contract, &changed) {
                    return Err("final-public committed tamper is not one port change".into());
                }
                Some(contract_digest_v2(&changed)?)
            }
            (None, None) => None,
            _ => return Err("final-public tampered contract pin differs".into()),
        }
    } else {
        None
    };
    let lease = crate::package::acquire_verified_private_qualification_lease()?;
    if let Some(spoof) = spoof {
        if spoof.case.selector != "private_tcp::caller_identity_and_epoch_bound"
            || spoof.unauthorized_uid == 0
            || spoof.unauthorized_gid == 0
            || spoof.unauthorized_uid == intent.public_uid
            || spoof.case.challenge
                == intent
                    .historical_e0
                    .as_ref()
                    .map(|case| case.case.challenge.as_str())
                    .unwrap_or("")
            || intent
                .cases
                .iter()
                .any(|entry| entry.selector == selector && entry.challenge == challenge_hex)
        {
            return Err("final-public spoof principal or challenge is not independent".into());
        }
    }
    if let Some(historical) = historical {
        if historical.case.selector != "private_tcp::caller_identity_and_epoch_bound"
            || historical.e0_installation_epoch_sha256 != *lease.generation_digest()
            || historical.e0_h1_receipt_sha256 != *lease.active_host_receipt_sha256()
            || intent.cases.iter().any(|entry| {
                entry.selector == historical.case.selector
                    && entry.challenge == historical.case.challenge
            })
        {
            return Err("final-public historical E0 H1/epoch pin differs".into());
        }
    }
    let installed = super::runtime_manifest::source_v3_candidate(Path::new(
        "/usr/libexec/memcordon-sealed-agent",
    ))?
    .ok_or("final-public installed M1 absent")?;
    let public_cli_sha256 = installed
        .manifest
        .components
        .iter()
        .find(|component| component.id == "public-cli")
        .ok_or("final-public installed CLI absent")?
        .sha256
        .as_str();
    if intent.source_commit != lease.source_commit()
        || intent.target != installed.manifest.target
        || intent.manifest_sha256 != *lease.runtime_manifest_sha256()
        || intent.qualification_sha256 != *lease.qualification_digest()
        || String::from(intent.public_cli_sha256.clone()) != public_cli_sha256
    {
        return Err("final-public dispatch differs from installed release".into());
    }
    let record = ProviderRecordV2 {
        schema_version: 3,
        evidence_scope: "provider-frames-only".into(),
        selector: selector.into(),
        challenge: challenge_hex.into(),
        result_key: case.result_key(),
        contract_digest: contract_digest_v2(&contract)?,
        policy_branch: policy_branch.as_ref().map(|(entry, _)| entry.policy_branch),
        policy_base_challenge_sha256: policy_branch.as_ref().map(|(_, digest)| digest.clone()),
        tampered_contract_digest,
        peer_pid: observed_pid,
        peer_start_time_ticks: observed_start,
        peer_uid: spoof.map_or(intent.public_uid, |entry| entry.unauthorized_uid),
        peer_gid: spoof.map_or(intent.public_gid, |entry| entry.unauthorized_gid),
        spoof_authorized_uid: spoof.map(|_| intent.public_uid),
        spoof_contract_file_sha256: spoof.map(|_| pinned.contract_sha256.clone()),
        installation_epoch: lease.generation_digest().clone(),
        manifest_sha256: lease.runtime_manifest_sha256().clone(),
        qualification_sha256: lease.qualification_digest().clone(),
        active_h1_receipt_sha256: lease.active_host_receipt_sha256().clone(),
        plan_request_sha256: None,
        plan_response_sha256: None,
        plan_response_kind: None,
        grant_decision_sha256: None,
        expected_launch_exchanges: if spoof.is_some() {
            0
        } else {
            expected_launch_exchanges(
                selector,
                policy_branch.as_ref().map(|(entry, _)| entry.policy_branch),
            )?
        },
        attempts: Vec::new(),
        inflight: Vec::new(),
        terminal_sha256: None,
        phase: "registered".into(),
    };
    lease.revalidate_release_boundary()?;
    let root = root()?;
    let _lock = lock(&root)?;
    if read_pending(&root)?.is_some()
        || root.join("pending.v2.new").exists()
        || root.join("pending.v1.json").exists()
        || root.join("pending.v1.new").exists()
    {
        return Err("final-public provider already has pending registration".into());
    }
    let directory = root.join(String::from(record.result_key.clone()));
    fs::create_dir(&directory).map_err(|error| error.to_string())?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())?;
    check_directory(&directory, Some(0o700))?;
    write_new(
        &root.join(PENDING),
        &serde_json::to_vec(&record).map_err(|error| error.to_string())?,
    )?;
    lease.revalidate_release_boundary()
}

fn matching_contract(
    request: &Frame,
    record: &ProviderRecordV2,
    launch: bool,
) -> Result<bool, String> {
    let contract = if launch {
        crate::request::decode_network_launch_request(&request.payload)
            .map_err(|error| format!("final-public launch decode: {error:?}"))?
            .contract
    } else {
        let WorkloadContract::V2(contract) = WorkloadContract::parse(&request.payload)? else {
            return Ok(false);
        };
        contract
    };
    let expected =
        if launch && record.policy_branch == Some(PolicyOperationBranchV1::CommittedPortTamper) {
            record
                .tampered_contract_digest
                .as_ref()
                .ok_or("final-public tampered contract pin absent")?
        } else {
            &record.contract_digest
        };
    Ok(contract_digest_v2(&contract)? == *expected)
}

fn verify_launch_plan_link(
    directory: &Path,
    record: &ProviderRecordV2,
    launch_payload: &[u8],
) -> Result<(), String> {
    let launch = crate::request::decode_network_launch_request(launch_payload)
        .map_err(|error| format!("final-public launch plan link: {error:?}"))?;
    let expected = launch
        .expected_plan
        .ok_or("final-public launch lacks exact plan precondition")?;
    let plan_response = read_file(&directory.join("plan-response.bin"), MAX_RAW, 0o600)?
        .ok_or("final-public plan response absent at launch")?;
    let plan_contract =
        if record.policy_branch == Some(PolicyOperationBranchV1::CommittedPortTamper) {
            let plan_request = read_file(&directory.join("plan-request.bin"), MAX_RAW, 0o600)?
                .ok_or("final-public frozen original plan absent")?;
            let WorkloadContract::V2(original) = WorkloadContract::parse(&plan_request)? else {
                return Err("final-public frozen original plan is not V2".into());
            };
            if contract_digest_v2(&original)? != record.contract_digest
                || Some(contract_digest_v2(&launch.contract)?) != record.tampered_contract_digest
                || !one_policy_port_changed(&original, &launch.contract)
            {
                return Err("final-public frozen launch contract differs".into());
            }
            original
        } else {
            launch.contract.clone()
        };
    let receipt = memcordon_core::workload_plan_v2::PrivatePlanReceiptV2::parse_for_contract(
        &plan_response,
        &plan_contract,
    )?;
    if expected
        != memcordon_core::workload_plan_v2::PrivatePlanPreconditionV1::from_receipt(&receipt)?
        || receipt.generation_digest != record.installation_epoch
        || receipt.installed_qualification_sha256 != record.qualification_sha256
        || receipt.runtime_manifest_sha256 != record.manifest_sha256
        || receipt.contract_digest != record.contract_digest
    {
        return Err("final-public launch differs from authenticated plan/H1".into());
    }
    Ok(())
}

fn check_peer(
    record: &ProviderRecordV2,
    pid: libc::pid_t,
    uid: u32,
    gid: u32,
) -> Result<(), String> {
    let (observed_pid, observed_start) = observed_child(pid)?;
    let peer_executable = fs::metadata(format!("/proc/{pid}/exe"))
        .map_err(|error| format!("final-public peer executable: {error}"))?;
    let installed_cli = fs::symlink_metadata("/usr/bin/memcordon")
        .map_err(|error| format!("final-public installed CLI: {error}"))?;
    let after = observed_child(pid)?;
    if record.peer_pid != observed_pid
        || record.peer_start_time_ticks != observed_start
        || after != (observed_pid, observed_start)
        || record.peer_uid != uid
        || record.peer_gid != gid
        || !installed_cli.is_file()
        || (peer_executable.dev(), peer_executable.ino())
            != (installed_cli.dev(), installed_cli.ino())
    {
        return Err("final-public registered child differs from provider peer".into());
    }
    Ok(())
}

fn verify_installed(record: &ProviderRecordV2) -> Result<(), String> {
    let lease = crate::package::acquire_verified_private_qualification_lease()?;
    if record.installation_epoch != *lease.generation_digest()
        || record.manifest_sha256 != *lease.runtime_manifest_sha256()
        || record.qualification_sha256 != *lease.qualification_digest()
        || record.active_h1_receipt_sha256 != *lease.active_host_receipt_sha256()
    {
        return Err("final-public provider release changed after registration".into());
    }
    lease.revalidate_release_boundary()
}

fn finalize(root: &Path, record: &ProviderRecordV2) -> Result<(), String> {
    let directory = root.join(String::from(record.result_key.clone()));
    check_directory(&directory, Some(0o700))?;
    write_new(
        &directory.join("provider.json"),
        &serde_json::to_vec(record).map_err(|error| error.to_string())?,
    )?;
    fs::remove_file(root.join(PENDING)).map_err(|error| error.to_string())?;
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())
}

/// Only an independently admitted, versioned CallerSpoof case may hold the
/// authenticated original peer before policy resolution. The old route has
/// no implicit gate and this source protocol grants no launch authority.
pub(crate) fn hold_prepared_caller_spoof(
    request: &Frame,
    pid: libc::pid_t,
    uid: u32,
    gid: u32,
) -> Result<(), String> {
    use memcordon_core::private_public_preparation_v2::{
        ApprovedPublicPreparationPolicyV2, PreparedPublicDispatchRecordV2, PublicPreparedRoleV2,
    };
    if matches!(fs::symlink_metadata(PREPARATION_POLICY_V2),Err(error) if error.kind()==std::io::ErrorKind::NotFound)
    {
        return Ok(());
    }
    let root = root()?;
    let _lock = lock(&root)?;
    let Some(record) = read_pending(&root)? else {
        return Ok(());
    };
    if record.spoof_authorized_uid.is_none() || !matching_contract(request, &record, false)? {
        return Ok(());
    }
    check_peer(&record, pid, uid, gid)?;
    verify_installed(&record)?;
    let approval = super::installed_release_qualification::read_protected_absolute(
        Path::new(PREPARATION_POLICY_V2),
        MAX_RECORD,
        Some(0o600),
    )?;
    reject_duplicate_json_keys(&approval)?;
    let approved: ApprovedPublicPreparationPolicyV2 =
        serde_json::from_slice(&approval).map_err(|error| error.to_string())?;
    approved.validate()?;
    let admission_path = Path::new("/run/memcordon-final-public/prepared-v2")
        .join(String::from(record.result_key.clone()))
        .join("admission.json");
    let admission = super::installed_release_qualification::read_protected_absolute(
        &admission_path,
        MAX_RECORD * 8,
        Some(0o600),
    )?;
    reject_duplicate_json_keys(&admission)?;
    let prepared: PreparedPublicDispatchRecordV2 =
        serde_json::from_slice(&admission).map_err(|error| error.to_string())?;
    let contract = pinned_contract(
        Path::new(&prepared.contract_path),
        &prepared.contract_file_sha256,
    )?;
    prepared.validate(&approved, &contract)?;
    if prepared.role != PublicPreparedRoleV2::CallerSpoof
        || prepared.result_key != record.result_key
        || prepared.selector != record.selector
        || prepared.challenge != decode_challenge(&record.challenge)?
        || prepared.installation_epoch != record.installation_epoch
        || prepared.active_h1_receipt_sha256 != record.active_h1_receipt_sha256
        || prepared.contract_file_sha256 != hash_bytes(&request.payload)
        || uid != approved.historical_spoof_uid
        || gid != approved.historical_spoof_gid
        || uid == approved.public_uid
        || record.phase != "registered"
        || !record.attempts.is_empty()
        || !record.inflight.is_empty()
        || record.expected_launch_exchanges != 0
        || request.kind != MessageKind::PrivatePlan
        || request.attempt_id != [0; 16]
    {
        return Err("prepared CallerSpoof exact original admission/peer differs".into());
    }
    let directory = root.join(String::from(record.result_key.clone()));
    check_directory(&directory, Some(0o700))?;
    let gate=serde_json::to_vec(&serde_json::json!({"schema_version":1,"selector":record.selector,"result_key":record.result_key,
        "prepared_admission_sha256":hash_bytes(&admission),"installation_epoch":record.installation_epoch,"active_h1_receipt_sha256":record.active_h1_receipt_sha256,
        "runtime_manifest_sha256":record.manifest_sha256,"installed_qualification_sha256":record.qualification_sha256,
        "request_sha256":hash_bytes(&request.payload),"caller":{"pid":record.peer_pid,"start_time_ticks":record.peer_start_time_ticks,"uid":uid,"gid":gid},
        "observed_monotonic_ns":super::clock::monotonic_nanos()?})).map_err(|error|error.to_string())?;
    write_new(&directory.join("caller-spoof-ready-v1.json"), &gate)?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if let Some(ack) = read_file(&directory.join("caller-spoof-ready-v1.ack"), 32, 0o600)? {
            if ack.as_slice() != hash_bytes(&gate).bytes() {
                return Err("prepared CallerSpoof root ACK differs".into());
            }
            break;
        }
        if std::time::Instant::now() >= deadline {
            return Err("prepared CallerSpoof original peer observation absent".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    check_peer(&record, pid, uid, gid)?;
    verify_installed(&record)
}

pub(crate) fn observe_plan(
    request: &Frame,
    response: &Frame,
    pid: libc::pid_t,
    uid: u32,
    gid: u32,
) -> Result<(), String> {
    let root = root()?;
    let _lock = lock(&root)?;
    let Some(mut record) = read_pending(&root)? else {
        return Ok(());
    };
    if !matching_contract(request, &record, false)? {
        return Ok(());
    }
    check_peer(&record, pid, uid, gid)?;
    verify_installed(&record)?;
    if record.phase != "registered" || request.kind != MessageKind::PrivatePlan {
        return Err("final-public provider plan replay differs".into());
    }
    if response.nonce != request.nonce || response.attempt_id != request.attempt_id {
        return Err("final-public provider plan frame identity differs".into());
    }
    let directory = root.join(String::from(record.result_key.clone()));
    check_directory(&directory, Some(0o700))?;
    if let Some(authorized_uid) = record.spoof_authorized_uid {
        let rejection =
            memcordon_core::provider_rejection_wire::RejectionWireV1::parse(&response.payload)?;
        if response.kind != MessageKind::Rejected
            || record.spoof_contract_file_sha256 != Some(hash_bytes(&request.payload))
            || request.attempt_id != [0; 16]
            || record.expected_launch_exchanges != 0
            || !record.attempts.is_empty()
            || !record.inflight.is_empty()
            || rejection.code != "MCSEALED-PRIVATE-PUBLIC-GRANT-REJECTED"
            || rejection.phase
                != memcordon_core::provider_rejection_wire::RejectionPhaseV1::RequestValidation
            || rejection.target_created
            || rejection.target_released
            || rejection.cleanup.attempted
            || !rejection.cleanup.errors.is_empty()
        {
            return Err("final-public authenticated spoof denial differs".into());
        }
        record.plan_request_sha256 = Some(hash_bytes(&request.payload));
        record.plan_response_sha256 = Some(hash_bytes(&response.payload));
        record.plan_response_kind = Some(response.kind as u16);
        let grant_decision_sha256 =
            read_grant_decision(&directory, &record, &request.payload, &response.payload)?;
        record.grant_decision_sha256 = Some(grant_decision_sha256.clone());
        let spoof = ProtectedPublicSpoofV1 {
            schema_version: 1,
            selector: record.selector.clone(),
            challenge: record.challenge.clone(),
            result_key: record.result_key.clone(),
            authenticated_peer_uid: uid,
            authenticated_peer_gid: gid,
            authenticated_peer_pid: pid as u32,
            authenticated_peer_start_ticks: record.peer_start_time_ticks,
            authorized_uid,
            installation_epoch: record.installation_epoch.clone(),
            active_h1_receipt_sha256: record.active_h1_receipt_sha256.clone(),
            contract_file_sha256: record
                .spoof_contract_file_sha256
                .clone()
                .expect("spoof contract file hash was pinned at registration"),
            grant_decision_sha256,
            request_sha256: hash_bytes(&request.payload),
            rejection_sha256: hash_bytes(&response.payload),
            rejection_code: rejection.code,
            durable_attempt_record_absent: true,
        };
        write_new(&directory.join("spoof-request.bin"), &request.payload)?;
        write_new(&directory.join("spoof-rejection.bin"), &response.payload)?;
        write_new(
            &directory.join("spoof.json"),
            &serde_json::to_vec(&spoof).map_err(|error| error.to_string())?,
        )?;
        record.phase = "spoof-rejected".into();
        return finalize(&root, &record);
    }
    write_new(&directory.join("plan-request.bin"), &request.payload)?;
    write_new(&directory.join("request.bin"), &request.payload)?;
    write_new(&directory.join("plan-response.bin"), &response.payload)?;
    record.plan_request_sha256 = Some(hash_bytes(&request.payload));
    record.plan_response_sha256 = Some(hash_bytes(&response.payload));
    record.plan_response_kind = Some(response.kind as u16);
    record.grant_decision_sha256 = Some(read_grant_decision(
        &directory,
        &record,
        &request.payload,
        &response.payload,
    )?);
    record.phase = match response.kind {
        MessageKind::PrivatePlanReceipt => "plan-accepted".into(),
        MessageKind::Rejected => "plan-rejected".into(),
        _ => return Err("final-public provider plan response kind differs".into()),
    };
    if response.kind == MessageKind::Rejected {
        if policy_plan_denial(record.policy_branch).is_none() {
            return Err("final-public positive case lacked provider grant".into());
        }
        let rejection =
            memcordon_core::provider_rejection_wire::RejectionWireV1::parse(&response.payload)?;
        if rejection.code != "MCSEALED-PRIVATE-PUBLIC-GRANT-REJECTED"
            || rejection.target_created
            || rejection.target_released
            || rejection.cleanup.attempted
        {
            return Err("final-public wrong-grant rejection differs".into());
        }
        write_new(&directory.join("terminal.bin"), &response.payload)?;
        record.terminal_sha256 = Some(hash_bytes(&response.payload));
        record.phase = "plan-rejected".into();
        finalize(&root, &record)
    } else {
        if policy_plan_denial(record.policy_branch).is_some() {
            return Err("final-public negative policy branch was admitted".into());
        }
        replace_pending(&root, &record)
    }
}

/// Capture the exact selected grant or typed denial while the service still
/// holds the authenticated V2 policy lease used to decide this plan frame.
pub(crate) fn observe_plan_authority(
    request: &Frame,
    response: &Frame,
    pid: libc::pid_t,
    uid: u32,
    gid: u32,
    activation: &crate::policy_registry::ActivationV2,
    resolution: &Result<
        &memcordon_core::workload_registry_v2::PolicyGrantV2,
        memcordon_core::workload_registry_v2::AdmissionRejectionV2,
    >,
) -> Result<(), String> {
    if matches!(fs::symlink_metadata(ROOT), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
    {
        return Ok(());
    }
    let root = root()?;
    let _lock = lock(&root)?;
    let Some(record) = read_pending(&root)? else {
        return Ok(());
    };
    if !matching_contract(request, &record, false)? {
        return Ok(());
    }
    check_peer(&record, pid, uid, gid)?;
    verify_installed(&record)?;
    if record.phase != "registered"
        || request.kind != MessageKind::PrivatePlan
        || response.nonce != request.nonce
        || response.attempt_id != request.attempt_id
        || activation.registry.canonical_digest()? != activation.registry_digest
    {
        return Err("final-public grant decision context differs".into());
    }
    let outcome = match resolution {
        Ok(grant) if response.kind == MessageKind::PrivatePlanReceipt => {
            ProviderGrantOutcomeV1::Granted {
                grant: (*grant).clone(),
            }
        }
        Err(rejection) if response.kind == MessageKind::Rejected => {
            let wire =
                memcordon_core::provider_rejection_wire::RejectionWireV1::parse(&response.payload)?;
            if wire.code != "MCSEALED-PRIVATE-PUBLIC-GRANT-REJECTED"
                || wire.target_created
                || wire.target_released
            {
                return Err("final-public grant denial response differs".into());
            }
            ProviderGrantOutcomeV1::Rejected {
                rejection: rejection.clone(),
            }
        }
        _ => return Err("final-public grant decision response kind differs".into()),
    };
    let decision = ProviderGrantDecisionV1 {
        schema_version: 1,
        evidence_scope: "lease-bound-v2-grant-decision".into(),
        selector: record.selector.clone(),
        challenge: record.challenge.clone(),
        result_key: record.result_key.clone(),
        contract_digest: record.contract_digest.clone(),
        peer_pid: record.peer_pid,
        peer_start_time_ticks: record.peer_start_time_ticks,
        peer_uid: record.peer_uid,
        peer_gid: record.peer_gid,
        installation_epoch: record.installation_epoch.clone(),
        active_h1_receipt_sha256: record.active_h1_receipt_sha256.clone(),
        registry_digest: activation.registry_digest.clone(),
        policy_epoch: activation.epoch.clone(),
        plan_request_sha256: hash_bytes(&request.payload),
        plan_response_sha256: hash_bytes(&response.payload),
        plan_response_kind: response.kind as u16,
        outcome,
    };
    let directory = root.join(String::from(record.result_key));
    check_directory(&directory, Some(0o700))?;
    write_new(
        &directory.join("grant-decision.json"),
        &serde_json::to_vec(&decision).map_err(|error| error.to_string())?,
    )
}

fn read_grant_decision(
    directory: &Path,
    record: &ProviderRecordV2,
    plan_request: &[u8],
    plan_response: &[u8],
) -> Result<DiagnosticSha256, String> {
    let bytes = read_file(&directory.join("grant-decision.json"), MAX_RECORD, 0o600)?
        .ok_or("final-public grant decision authority absent")?;
    reject_duplicate_json_keys(&bytes)?;
    let decision: ProviderGrantDecisionV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if decision.schema_version != 1
        || decision.evidence_scope != "lease-bound-v2-grant-decision"
        || decision.selector != record.selector
        || decision.challenge != record.challenge
        || decision.result_key != record.result_key
        || decision.contract_digest != record.contract_digest
        || decision.peer_pid != record.peer_pid
        || decision.peer_start_time_ticks != record.peer_start_time_ticks
        || decision.peer_uid != record.peer_uid
        || decision.peer_gid != record.peer_gid
        || decision.installation_epoch != record.installation_epoch
        || decision.active_h1_receipt_sha256 != record.active_h1_receipt_sha256
        || decision.plan_request_sha256 != hash_bytes(plan_request)
        || decision.plan_response_sha256 != hash_bytes(plan_response)
        || Some(decision.plan_response_kind) != record.plan_response_kind
    {
        return Err("final-public grant decision identity differs".into());
    }
    let contract = match memcordon_core::workload_contract::WorkloadContract::parse(plan_request)? {
        memcordon_core::workload_contract::WorkloadContract::V2(contract) => contract,
        _ => return Err("final-public grant decision contract is not V2".into()),
    };
    let policy_root = Path::new("/var/lib/memcordon/policy");
    check_directory(policy_root, None)?;
    let registry_path = policy_root.join(format!(
        "{}.snapshot",
        String::from(decision.registry_digest.clone())
    ));
    let registry_bytes = read_file(
        &registry_path,
        memcordon_core::workload_limits::REGISTRY_BYTES as u64,
        0o600,
    )?
    .ok_or("final-public protected V2 registry snapshot absent")?;
    let registry = memcordon_core::workload_registry_v2::PolicyRegistryV2::parse(&registry_bytes)?;
    if registry.canonical_digest()? != decision.registry_digest {
        return Err("final-public grant decision registry snapshot differs".into());
    }
    let resolved = memcordon_core::workload_registry_v2::resolve_v2(
        &registry,
        &decision.policy_epoch,
        &contract,
        &memcordon_core::workload_registry::CallerSelector::Linux {
            uid: decision.peer_uid,
        },
        memcordon_core::workload_registry_v2::ProfileKindV2::LinuxTcp4PrivateV1,
        &record.qualification_sha256,
    );
    match &decision.outcome {
        ProviderGrantOutcomeV1::Granted { grant }
            if decision.plan_response_kind == MessageKind::PrivatePlanReceipt as u16 =>
        {
            let receipt =
                memcordon_core::workload_plan_v2::PrivatePlanReceiptV2::parse_for_contract(
                    plan_response,
                    &contract,
                )?;
            if receipt.registry_digest != decision.registry_digest
                || receipt.generation_digest != decision.installation_epoch
                || !matches!(resolved, Ok(selected) if selected == grant)
                || grant.id != contract.authorization.grant_id
                || grant.revision != contract.authorization.grant_revision
                || !grant.enabled
                || !grant
                    .approved_plans
                    .as_slice()
                    .contains(&contract.workload_plan_digest)
            {
                return Err("final-public selected grant differs from plan receipt".into());
            }
        }
        ProviderGrantOutcomeV1::Rejected { rejection: claimed }
            if decision.plan_response_kind == MessageKind::Rejected as u16 =>
        {
            let rejection =
                memcordon_core::provider_rejection_wire::RejectionWireV1::parse(plan_response)?;
            if rejection.code != "MCSEALED-PRIVATE-PUBLIC-GRANT-REJECTED"
                || rejection.target_created
                || rejection.target_released
                || rejection.cleanup.attempted
                || !matches!(resolved, Err(actual) if &actual == claimed)
                || !(policy_plan_denial(record.policy_branch).as_ref() == Some(&claimed.code)
                    || record.spoof_authorized_uid.is_some()
                        && claimed.code == memcordon_core::workload_registry_v2::AdmissionCodeV2::ProfileNotAuthorized)
            {
                return Err("final-public typed grant denial differs".into());
            }
        }
        _ => return Err("final-public grant outcome/frame kind differs".into()),
    }
    Ok(hash_bytes(&bytes))
}

/// Reserve the exact launch frame before any broker allocation. This is the
/// only bridge from the authenticated public actor to a later live target.
fn verify_prepared_launch_argv(
    record: &ProviderRecordV2,
    request: &Frame,
    ordinal: u8,
) -> Result<(), String> {
    use memcordon_core::private_public_preparation_v2::{
        ApprovedPublicPreparationPolicyV2, PreparedPublicDispatchRecordV2,
    };
    if matches!(fs::symlink_metadata(PREPARATION_POLICY_V2),Err(error) if error.kind()==std::io::ErrorKind::NotFound)
    {
        return Ok(()); // Legacy diagnostic route; no new prepared approval.
    }
    let approval = super::installed_release_qualification::read_protected_absolute(
        Path::new(PREPARATION_POLICY_V2),
        MAX_RECORD,
        Some(0o600),
    )?;
    reject_duplicate_json_keys(&approval)?;
    let approved: ApprovedPublicPreparationPolicyV2 =
        serde_json::from_slice(&approval).map_err(|error| error.to_string())?;
    approved.validate()?;
    let path = Path::new("/run/memcordon-final-public/prepared-v2")
        .join(String::from(record.result_key.clone()))
        .join("admission.json");
    let bytes = super::installed_release_qualification::read_protected_absolute(
        &path,
        MAX_RECORD * 8,
        Some(0o600),
    )?;
    reject_duplicate_json_keys(&bytes)?;
    let prepared: PreparedPublicDispatchRecordV2 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    let contract = pinned_contract(
        Path::new(&prepared.contract_path),
        &prepared.contract_file_sha256,
    )?;
    prepared.validate(&approved, &contract)?;
    if prepared.result_key != record.result_key
        || prepared.selector != record.selector
        || prepared.installation_epoch != record.installation_epoch
        || prepared.active_h1_receipt_sha256 != record.active_h1_receipt_sha256
        || prepared.challenge != decode_challenge(&record.challenge)?
    {
        return Err("prepared launch argv subject differs from active registered case".into());
    }
    let expected = approved.fixture_argv(
        prepared.session_nonce,
        prepared.generation,
        &prepared.selector,
        prepared.role,
        ordinal,
    )?;
    let actual = crate::request::decode_network_launch_request(&request.payload)
        .map_err(|error| format!("prepared exact launch argv decode: {error:?}"))?;
    if actual.launch.program != expected[0].as_bytes()
        || actual
            .launch
            .arguments
            .iter()
            .map(Vec::as_slice)
            .ne(expected.iter().skip(1).map(|argument| argument.as_bytes()))
    {
        return Err(
            "prepared launch argv or dual ordinal challenge was not independently approved".into(),
        );
    }
    Ok(())
}

pub(crate) fn begin_launch(
    request: &Frame,
    pid: libc::pid_t,
    uid: u32,
    gid: u32,
) -> Result<(), String> {
    let root = root()?;
    let _lock = lock(&root)?;
    let Some(mut record) = read_pending(&root)? else {
        return Ok(());
    };
    if !matching_contract(request, &record, true)? {
        return Ok(());
    }
    check_peer(&record, pid, uid, gid)?;
    verify_installed(&record)?;
    let ordinal = u8::try_from(record.attempts.len() + record.inflight.len())
        .map_err(|error| error.to_string())?;
    verify_prepared_launch_argv(&record, request, ordinal)?;
    let attempt_id = request
        .attempt_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if request.kind != MessageKind::PrivateLaunch
        || record.phase != "plan-accepted"
        || (!record.inflight.is_empty()
            && record.selector != "private_tcp::dual_attempt_namespace_isolation")
        || record.inflight.len() >= 2
        || ordinal >= record.expected_launch_exchanges
        || request.attempt_id == [0; 16]
        || record
            .attempts
            .iter()
            .any(|entry| entry.attempt_id == attempt_id)
        || record
            .inflight
            .iter()
            .any(|entry| entry.attempt_id == attempt_id)
    {
        return Err("final-public launch reservation replay or phase differs".into());
    }
    let directory = root.join(String::from(record.result_key.clone()));
    check_directory(&directory, Some(0o700))?;
    verify_launch_plan_link(&directory, &record, &request.payload)?;
    let attempt_directory = directory.join(format!("{ordinal}-{attempt_id}"));
    fs::create_dir(&attempt_directory).map_err(|error| error.to_string())?;
    fs::set_permissions(&attempt_directory, fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())?;
    check_directory(&attempt_directory, Some(0o700))?;
    write_new(&attempt_directory.join("request.bin"), &request.payload)?;
    record.inflight.push(ProviderInflightV2 {
        ordinal,
        attempt_id,
        nonce: request
            .nonce
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        request_sha256: hash_bytes(&request.payload),
    });
    replace_pending(&root, &record)
}

/// Called by the durable attempt owner immediately after TargetGated sync,
/// while the pidfd-bound target and namespace init are still live.
pub(crate) fn observe_gated_target(
    attempt_id: &str,
    target: &super::private_attempt::ProcessIdentityV4,
    namespace_init: &super::private_attempt::ProcessIdentityV4,
    network_namespace_inode: u64,
) -> Result<(), String> {
    if matches!(fs::symlink_metadata(ROOT), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
    {
        return Ok(());
    }
    let root = root()?;
    let _lock = lock(&root)?;
    let Some(record) = read_pending(&root)? else {
        return Ok(());
    };
    let Some(inflight) = record
        .inflight
        .iter()
        .find(|entry| entry.attempt_id == attempt_id)
    else {
        return Ok(());
    };
    if inflight.attempt_id != attempt_id {
        return Err("final-public active reservation differs from gated attempt".into());
    }
    verify_installed(&record)?;
    if network_namespace_inode == 0
        || observed_child(target.pid as libc::pid_t)? != (target.pid, target.start_time)
        || observed_child(namespace_init.pid as libc::pid_t)?
            != (namespace_init.pid, namespace_init.start_time)
    {
        return Err("final-public gated target identity changed".into());
    }
    let durable_bytes = read_file(
        &Path::new(super::STATE_ROOT).join(attempt_id),
        super::private_attempt::MAX_PRIVATE_RECORD_BYTES as u64,
        0o600,
    )?
    .ok_or("final-public durable gated attempt absent")?;
    reject_duplicate_json_keys(&durable_bytes)?;
    let durable: super::private_attempt::PrivateAttemptRecordV4 =
        serde_json::from_slice(&durable_bytes).map_err(|error| error.to_string())?;
    if durable.attempt_id.as_str() != attempt_id
        || durable.phase != super::private_attempt::PrivateAttemptPhase::TargetGated
        || durable.target.as_ref() != Some(target)
        || durable.namespace_init.as_ref() != Some(namespace_init)
        || durable.network_namespace_inode != Some(network_namespace_inode)
    {
        return Err("final-public durable gated target differs".into());
    }
    let identity = ProviderTargetGateV1 {
        schema_version: 1,
        evidence_scope: "durable-live-target-gated".into(),
        attempt_id: attempt_id.into(),
        request_sha256: inflight.request_sha256.clone(),
        durable_attempt_record_sha256: hash_bytes(&durable_bytes),
        target: target.clone(),
        namespace_init: namespace_init.clone(),
        network_namespace_inode,
    };
    let attempt_directory = root
        .join(String::from(record.result_key))
        .join(format!("{}-{}", inflight.ordinal, attempt_id));
    check_directory(&attempt_directory, Some(0o700))?;
    // Retain the exact synced TargetGated checkpoint, not a wrapper digest.
    // The private attempt owner has already synced it before this callback.
    write_new(
        &attempt_directory.join("gated-attempt-v4.bin"),
        &durable_bytes,
    )?;
    write_new(
        &attempt_directory.join("target-identity.pending.json"),
        &serde_json::to_vec(&identity).map_err(|error| error.to_string())?,
    )
}

/// Complete the live target witness from the same pinned, verified ELF fd
/// that the broker transferred to the gated target. A path stat is never
/// substituted for this descriptor identity.
pub(crate) fn observe_gated_entrypoint(
    attempt_id: &str,
    approved_digest: &DiagnosticSha256,
    device: u64,
    inode: u64,
) -> Result<(), String> {
    if matches!(fs::symlink_metadata(ROOT), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
    {
        return Ok(());
    }
    let root = root()?;
    let _lock = lock(&root)?;
    let Some(record) = read_pending(&root)? else {
        return Ok(());
    };
    let Some(inflight) = record
        .inflight
        .iter()
        .find(|entry| entry.attempt_id == attempt_id)
    else {
        return Ok(());
    };
    if inflight.attempt_id != attempt_id || device == 0 || inode == 0 {
        return Err("final-public pinned entrypoint reservation differs".into());
    }
    verify_installed(&record)?;
    let attempt_directory = root
        .join(String::from(record.result_key))
        .join(format!("{}-{attempt_id}", inflight.ordinal));
    check_directory(&attempt_directory, Some(0o700))?;
    let gate_bytes = read_file(
        &attempt_directory.join("target-identity.pending.json"),
        MAX_RECORD,
        0o600,
    )?
    .ok_or("final-public gated target identity pending leaf absent")?;
    reject_duplicate_json_keys(&gate_bytes)?;
    let gate: ProviderTargetGateV1 =
        serde_json::from_slice(&gate_bytes).map_err(|error| error.to_string())?;
    if gate.schema_version != 1
        || gate.evidence_scope != "durable-live-target-gated"
        || gate.attempt_id != attempt_id
        || gate.request_sha256 != inflight.request_sha256
        || observed_child(gate.target.pid as libc::pid_t)?
            != (gate.target.pid, gate.target.start_time)
    {
        return Err("final-public gated target changed before ELF join".into());
    }
    let request_bytes = read_file(&attempt_directory.join("request.bin"), MAX_RAW, 0o600)?
        .ok_or("final-public reserved request absent at ELF join")?;
    let launch = crate::request::decode_network_launch_request(&request_bytes)
        .map_err(|error| format!("final-public ELF join request: {error:?}"))?;
    let path = std::str::from_utf8(&launch.launch.program).map_err(|error| error.to_string())?;
    let durable_bytes = read_file(
        &Path::new(super::STATE_ROOT).join(attempt_id),
        super::private_attempt::MAX_PRIVATE_RECORD_BYTES as u64,
        0o600,
    )?
    .ok_or("final-public gated attempt absent at ELF join")?;
    reject_duplicate_json_keys(&durable_bytes)?;
    let durable: super::private_attempt::PrivateAttemptRecordV4 =
        serde_json::from_slice(&durable_bytes).map_err(|error| error.to_string())?;
    let admission = durable
        .admission
        .as_ref()
        .ok_or("final-public gated admission absent at ELF join")?;
    if durable.phase != super::private_attempt::PrivateAttemptPhase::TargetGated
        || durable.target.as_ref() != Some(&gate.target)
        || durable.namespace_init.as_ref() != Some(&gate.namespace_init)
        || durable.network_namespace_inode != Some(gate.network_namespace_inode)
        || !admission
            .identity
            .entrypoints
            .as_slice()
            .iter()
            .any(|entry| entry.absolute_path.as_str() == path && &entry.sha256 == approved_digest)
    {
        return Err("final-public pinned ELF differs from gated admission".into());
    }
    let identity = ProviderTargetIdentityV1 {
        gated: gate,
        entrypoint_sha256: approved_digest.clone(),
        entrypoint_device: device,
        entrypoint_inode: inode,
        entrypoint_path: path.into(),
    };
    write_new(
        &attempt_directory.join("target-identity.json"),
        &serde_json::to_vec(&identity).map_err(|error| error.to_string())?,
    )?;
    fs::remove_file(attempt_directory.join("target-identity.pending.json"))
        .map_err(|error| error.to_string())?;
    File::open(&attempt_directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())
}

pub(crate) fn observe_launch(
    request: &Frame,
    response: &Frame,
    pid: libc::pid_t,
    uid: u32,
    gid: u32,
) -> Result<(), String> {
    let root = root()?;
    let _lock = lock(&root)?;
    let Some(mut record) = read_pending(&root)? else {
        return Ok(());
    };
    if !matching_contract(request, &record, true)? {
        return Ok(());
    }
    verify_installed(&record)?;
    if record.phase != "plan-accepted" || request.kind != MessageKind::PrivateLaunch {
        return Err("final-public provider launch without exact plan".into());
    }
    if response.nonce != request.nonce || response.attempt_id != request.attempt_id {
        return Err("final-public provider launch frame identity differs".into());
    }
    let attempt_id = request
        .attempt_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if attempt_id.bytes().all(|byte| byte == b'0') {
        return Err("final-public launch lacks attempt identity".into());
    }
    let directory = root.join(String::from(record.result_key.clone()));
    check_directory(&directory, Some(0o700))?;
    let ordinal = record
        .inflight
        .iter()
        .find(|entry| entry.attempt_id == attempt_id)
        .ok_or("final-public launch not reserved")?
        .ordinal;
    if ordinal >= record.expected_launch_exchanges
        || record
            .attempts
            .iter()
            .any(|entry| entry.attempt_id == attempt_id)
    {
        return Err("final-public launch exchange replay or bound differs".into());
    }
    let inflight = record
        .inflight
        .iter()
        .find(|entry| entry.attempt_id == attempt_id)
        .ok_or("final-public launch was not reserved before allocation")?;
    if inflight.ordinal != ordinal
        || inflight.attempt_id != attempt_id
        || inflight.nonce
            != request
                .nonce
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        || inflight.request_sha256 != hash_bytes(&request.payload)
    {
        return Err("final-public launch reservation frame differs".into());
    }
    let attempt_directory = directory.join(format!("{ordinal}-{attempt_id}"));
    check_directory(&attempt_directory, Some(0o700))?;
    let reserved_request = read_file(&attempt_directory.join("request.bin"), MAX_RAW, 0o600)?
        .ok_or("final-public reserved launch request absent")?;
    if reserved_request != request.payload {
        return Err("final-public reserved launch request changed".into());
    }
    write_new(&attempt_directory.join("response.bin"), &response.payload)?;
    let target_identity_bytes = read_file(
        &attempt_directory.join("target-identity.json"),
        MAX_RECORD,
        0o600,
    )?;
    if read_file(
        &attempt_directory.join("target-identity.pending.json"),
        MAX_RECORD,
        0o600,
    )?
    .is_some()
    {
        return Err("final-public live target identity was not committed".into());
    }
    if response.kind == MessageKind::Terminal && target_identity_bytes.is_none() {
        return Err("final-public terminal lacks live target identity".into());
    }
    let reuse = record.selector == "private_tcp::retirement_failure_blocks_reuse";
    let fault = fault_plan(&record.selector);
    let fault_trigger = read_file(
        &attempt_directory.join("fault-trigger-v1.json"),
        MAX_RAW,
        0o600,
    )?;
    let fault_failure = read_file(
        &attempt_directory.join("fault-failure-v1.json"),
        MAX_RAW,
        0o600,
    )?;
    let fault_retirement = read_file(
        &attempt_directory.join("fault-retirement-v1.json"),
        MAX_RAW,
        0o600,
    )?;
    if let Some(plan) = fault {
        let trigger_bytes = fault_trigger
            .as_ref()
            .ok_or("final-public fault lacks physical trigger")?;
        reject_duplicate_json_keys(trigger_bytes)?;
        let trigger: PublicFaultTriggerV1 =
            serde_json::from_slice(trigger_bytes).map_err(|error| error.to_string())?;
        if trigger.schema_version != 1
            || trigger.fault != plan
            || trigger.attempt_id != attempt_id
            || trigger.result_key != record.result_key
            || trigger.request_sha256 != hash_bytes(&request.payload)
            || plan == PublicFaultPlanV1::DropAuthorizationAtDurableIntent
                && trigger.operation_errno != Some(libc::EPIPE)
            || plan != PublicFaultPlanV1::DropAuthorizationAtDurableIntent
                && (trigger.target_tcp_bytes.is_empty() || trigger.target_socket_inodes.len() < 2)
        {
            return Err("final-public fault physical trigger differs".into());
        }
        if plan == PublicFaultPlanV1::KillPinnedFrontendAtTargetLive {
            // begin_launch authenticated the live executable before reservation;
            // this exact pidfd signal intentionally removes that peer. Do not
            // require /proc/exe to survive its death or accept a replacement PID.
            if trigger.victim.pid != record.peer_pid
                || trigger.victim.start_time != record.peer_start_time_ticks
                || pid as u32 != record.peer_pid
                || uid != record.peer_uid
                || gid != record.peer_gid
            {
                return Err("final-public fault frontend credentials differ".into());
            }
        } else {
            check_peer(&record, pid, uid, gid)?;
        }
        if fault_retirement.is_none() && fault_failure.is_none() {
            return Err("final-public fault lacks observed outcome".into());
        }
    } else if fault_trigger.is_some() || fault_failure.is_some() || fault_retirement.is_some() {
        return Err("final-public ordinary attempt contains undeclared fault".into());
    } else {
        check_peer(&record, pid, uid, gid)?;
    }
    if response.kind == MessageKind::Rejected {
        let rejection =
            memcordon_core::provider_rejection_wire::RejectionWireV1::parse(&response.payload)?;
        if reuse && ordinal == 0 {
            if rejection.code != "MCSEALED-PRIVATE-REUSE-CLEANUP-INCOMPLETE"
                || !rejection.target_created
                || !rejection.target_released
                || !rejection.cleanup.attempted
                || rejection.cleanup.sealed_boundary_retired
                || rejection.cleanup.errors.is_empty()
                || target_identity_bytes.is_none()
            {
                return Err("final-public reuse first cleanup failure differs".into());
            }
        } else if reuse && ordinal == 1 {
            if rejection.code != "MCSEALED-PRIVATE-REUSE-BLOCKED"
                || rejection.target_created
                || rejection.target_released
                || rejection.cleanup.attempted
                || target_identity_bytes.is_some()
            {
                return Err("final-public reuse second allocation was not blocked".into());
            }
        } else if fault.is_some() {
            if !rejection.target_created
                || !rejection.target_released
                || !rejection.cleanup.attempted
                || target_identity_bytes.is_none()
                || rejection.cleanup.sealed_boundary_retired != fault_retirement.is_some()
                || fault_failure.is_none()
            {
                return Err("final-public fault rejection actual cleanup differs".into());
            }
        } else if rejection.target_created
            || rejection.target_released
            || target_identity_bytes.is_some()
        {
            return Err("final-public launch rejection allocated a target".into());
        }
        if record.policy_branch == Some(PolicyOperationBranchV1::CommittedPortTamper)
            && (rejection.code != "MCSEALED-PRIVATE-EXPECTED-PLAN" || rejection.cleanup.attempted)
        {
            return Err("final-public frozen port rejection code differs".into());
        }
    }
    if record.policy_branch == Some(PolicyOperationBranchV1::AcceptedControl)
        && response.kind != MessageKind::Terminal
        || record.policy_branch == Some(PolicyOperationBranchV1::CommittedPortTamper)
            && response.kind != MessageKind::Rejected
    {
        return Err("final-public policy branch launch outcome differs".into());
    }
    if record.selector == "private_tcp::abi_alternate_entry_denied"
        && (ordinal != 0 || response.kind != MessageKind::Terminal)
    {
        return Err("final-public ABI target did not finish all compat branches".into());
    }
    let mut attempt = ProviderAttemptV2 {
        ordinal,
        attempt_id: attempt_id.clone(),
        launch_request_sha256: hash_bytes(&request.payload),
        launch_response_sha256: hash_bytes(&response.payload),
        launch_response_kind: response.kind as u16,
        terminal_sha256: None,
        cleanup_sha256: None,
        target_identity_sha256: target_identity_bytes
            .as_ref()
            .map(|bytes| hash_bytes(bytes)),
        fault_trigger_sha256: fault_trigger.as_ref().map(|bytes| hash_bytes(bytes)),
        fault_failure_sha256: fault_failure.as_ref().map(|bytes| hash_bytes(bytes)),
        fault_retirement_sha256: fault_retirement.as_ref().map(|bytes| hash_bytes(bytes)),
        fault_recovery_sha256: None,
        checkpoint_committed_sha256: read_file(
            &attempt_directory.join("checkpoint-committed-v4.bin"),
            MAX_RAW,
            0o600,
        )?
        .as_ref()
        .map(|bytes| hash_bytes(bytes)),
        release_intent_sha256: read_file(
            &attempt_directory.join("release-intent-v4.bin"),
            MAX_RAW,
            0o600,
        )?
        .as_ref()
        .map(|bytes| hash_bytes(bytes)),
        execution_observed_sha256: read_file(
            &attempt_directory.join("execution-observed-v4.bin"),
            MAX_RAW,
            0o600,
        )?
        .as_ref()
        .map(|bytes| hash_bytes(bytes)),
        cgroup_retirement_sha256: read_file(
            &attempt_directory.join("cgroup-retirement-v1.json"),
            MAX_RAW,
            0o600,
        )?
        .as_ref()
        .map(|bytes| hash_bytes(bytes)),
        phase: "nonterminal-observed".into(),
    };
    if reuse && ordinal == 0 {
        attempt.phase = "cleanup-incomplete-observed".into();
    }
    if reuse && ordinal == 1 {
        attempt.phase = "reuse-blocked-observed".into();
    }
    if response.kind == MessageKind::Terminal {
        if record.selector == "private_tcp::abi_alternate_entry_denied" {
            let identity_bytes = target_identity_bytes
                .as_ref()
                .ok_or("final-public ABI target identity absent")?;
            reject_duplicate_json_keys(identity_bytes)?;
            let identity: ProviderTargetIdentityV1 =
                serde_json::from_slice(identity_bytes).map_err(|error| error.to_string())?;
            super::private_public_abi_filtered::verify_protected_report(
                &record.result_key,
                &record.challenge,
                &attempt.attempt_id,
                &identity.gated.target,
            )?;
        }
        let attempt_path = Path::new(super::STATE_ROOT).join(&attempt_id);
        if read_file(
            &attempt_path,
            super::private_attempt::MAX_PRIVATE_RECORD_BYTES as u64,
            0o600,
        )?
        .is_some()
        {
            return Err("final-public terminal left a durable active attempt".into());
        }
        let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|error| error.to_string())?;
        let cleanup = ProviderCleanupObservationV1 {
            schema_version: 1,
            evidence_scope: "post-terminal-state-readback".into(),
            attempt_id: attempt_id.clone(),
            terminal_sha256: hash_bytes(&response.payload),
            provider_response_kind: response.kind as u16,
            durable_attempt_record_absent: true,
            boot_id: boot_id.trim().into(),
        };
        let cleanup_bytes = serde_json::to_vec(&cleanup).map_err(|error| error.to_string())?;
        write_new(&attempt_directory.join("terminal.bin"), &response.payload)?;
        write_new(&attempt_directory.join("cleanup.bin"), &cleanup_bytes)?;
        attempt.terminal_sha256 = Some(hash_bytes(&response.payload));
        attempt.cleanup_sha256 = Some(hash_bytes(&cleanup_bytes));
        attempt.phase = "terminal-observed".into();
    }
    if fault.is_some() {
        attempt.phase = if fault_retirement.is_some() {
            "fault-retired-observed"
        } else {
            "fault-cleanup-incomplete-observed"
        }
        .into();
        if response.kind == MessageKind::Rejected
            && let Some(bytes) = &fault_retirement
        {
            write_new(&attempt_directory.join("cleanup.bin"), bytes)?;
            attempt.cleanup_sha256 = Some(hash_bytes(bytes));
        }
    }
    record.attempts.push(attempt);
    record
        .inflight
        .retain(|entry| entry.attempt_id != attempt_id);
    record.attempts.sort_by_key(|entry| entry.ordinal);
    if fault.is_some() && fault_retirement.is_none() {
        record.phase = "awaiting-fault-recovery".into();
        replace_pending(&root, &record)
    } else if reuse && record.attempts.len() == usize::from(record.expected_launch_exchanges) {
        record.phase = "awaiting-reuse-recovery".into();
        replace_pending(&root, &record)
    } else if record.attempts.len() == usize::from(record.expected_launch_exchanges) {
        record.phase = "launch-exchanges-complete".into();
        finalize(&root, &record)
    } else {
        replace_pending(&root, &record)
    }
}

/// Complete the two-attempt reuse transcript only after the separate root
/// recovery operation has removed the exact durable incomplete V4 record.
/// The first response remains a rejection; this attaches later cleanup, not
/// a fabricated first terminal.
/// A separate root recovery operation. It cannot change the original response
/// or create a terminal; it removes only an exact inactive incomplete record.
pub(crate) fn recover_public_fault(
    selector: &str,
    key_hex: &str,
    attempt_id: &str,
) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("public fault recovery requires root".into());
    }
    let key: DiagnosticSha256 =
        serde_json::from_value(serde_json::Value::String(key_hex.to_owned()))
            .map_err(|error| error.to_string())?;
    let root = root()?;
    let _lock = lock(&root)?;
    let mut record = read_pending(&root)?.ok_or("public fault recovery pending absent")?;
    if record.result_key != key
        || record.selector != selector
        || fault_plan(selector).is_none()
        || record.phase != "awaiting-fault-recovery"
        || record.attempts.len() != 1
        || !record.inflight.is_empty()
        || record.attempts[0].attempt_id != attempt_id
        || record.attempts[0].phase != "fault-cleanup-incomplete-observed"
        || record.attempts[0].launch_response_kind != MessageKind::Rejected as u16
        || record.attempts[0].fault_trigger_sha256.is_none()
        || record.attempts[0].fault_failure_sha256.is_none()
        || record.attempts[0].terminal_sha256.is_some()
    {
        return Err("public fault recovery exact pending outcome differs".into());
    }
    verify_installed(&record)?;
    let directory = root
        .join(String::from(key.clone()))
        .join(format!("0-{attempt_id}"));
    let bytes = read_file(
        &Path::new(super::STATE_ROOT).join(attempt_id),
        super::private_attempt::MAX_PRIVATE_RECORD_BYTES as u64,
        0o600,
    )?
    .ok_or("public fault recovery incomplete durable record absent")?;
    let incomplete = super::private_attempt::PrivateAttemptRecordV4::parse(&bytes)?;
    let trigger_bytes = read_file(&directory.join("fault-trigger-v1.json"), MAX_RAW, 0o600)?
        .ok_or("public fault recovery trigger absent")?;
    if record.attempts[0].fault_trigger_sha256.as_ref() != Some(&hash_bytes(&trigger_bytes)) {
        return Err("public fault recovery trigger changed".into());
    }
    let trigger: PublicFaultTriggerV1 =
        serde_json::from_slice(&trigger_bytes).map_err(|error| error.to_string())?;
    if trigger.request_sha256 != record.attempts[0].launch_request_sha256
        || incomplete.target.as_ref() != Some(&trigger.target)
        || incomplete.checkpoint_digest.as_ref() != Some(&trigger.checkpoint_sha256)
    {
        return Err("public fault recovery request/target/checkpoint differs".into());
    }
    // This shared inactive-record primitive independently checks absent cgroup,
    // absent exact process generations, live policy reference and unchanged
    // owner-only durable file before unlink + parent sync.
    super::private_attempt::recover_exact_reuse_incomplete(attempt_id, &incomplete)?;
    let recovered=serde_json::to_vec(&serde_json::json!({"schema_version":1,"evidence_scope":"post-fault-exact-incomplete-recovery",
        "result_key":key,"attempt_id":attempt_id,"original_incomplete_bytes":bytes,"durable_attempt_record_absent":true})).map_err(|error|error.to_string())?;
    write_new(&directory.join("fault-recovery-v1.json"), &recovered)?;
    record.attempts[0].fault_recovery_sha256 = Some(hash_bytes(&recovered));
    record.attempts[0].cleanup_sha256 = Some(hash_bytes(&recovered));
    write_new(&directory.join("cleanup.bin"), &recovered)?;
    record.attempts[0].phase = "fault-recovered-after-incomplete".into();
    record.phase = "launch-exchanges-complete".into();
    finalize(&root, &record)
}

pub(crate) fn preflight_reuse_recovery(
    result_key: &DiagnosticSha256,
    first_attempt_id: &str,
    second_attempt_id: &str,
) -> Result<(), String> {
    let root = root()?;
    let _lock = lock(&root)?;
    let record = read_pending(&root)?.ok_or("final-public reuse pending provider absent")?;
    if record.selector != "private_tcp::retirement_failure_blocks_reuse"
        || record.result_key != *result_key
        || record.phase != "awaiting-reuse-recovery"
        || record.attempts.len() != 2
        || record.attempts[0].attempt_id != first_attempt_id
        || record.attempts[0].phase != "cleanup-incomplete-observed"
        || record.attempts[0].launch_response_kind != MessageKind::Rejected as u16
        || record.attempts[0].target_identity_sha256.is_none()
        || record.attempts[0].terminal_sha256.is_some()
        || record.attempts[0].cleanup_sha256.is_some()
        || record.attempts[1].attempt_id != second_attempt_id
        || record.attempts[1].phase != "reuse-blocked-observed"
        || record.attempts[1].launch_response_kind != MessageKind::Rejected as u16
        || record.attempts[1].target_identity_sha256.is_some()
        || record.attempts[1].terminal_sha256.is_some()
        || record.attempts[1].cleanup_sha256.is_some()
        || !record.inflight.is_empty()
    {
        return Err("final-public reuse provider not ready for recovery".into());
    }
    verify_installed(&record)
}

pub(crate) fn complete_reuse_recovery(
    result_key: &DiagnosticSha256,
    first_attempt_id: &str,
    recovered_cleanup_bytes: &[u8],
) -> Result<(), String> {
    if recovered_cleanup_bytes.is_empty() || recovered_cleanup_bytes.len() > MAX_RAW as usize {
        return Err("final-public reuse recovered cleanup bound differs".into());
    }
    super::private_public_reuse::verify_recovered_cleanup_bytes(
        recovered_cleanup_bytes,
        result_key,
        first_attempt_id,
    )?;
    let root = root()?;
    let _lock = lock(&root)?;
    let mut record = read_pending(&root)?.ok_or("final-public reuse pending provider absent")?;
    if record.selector != "private_tcp::retirement_failure_blocks_reuse"
        || record.result_key != *result_key
        || record.phase != "awaiting-reuse-recovery"
        || record.attempts.len() != 2
        || record.attempts[0].attempt_id != first_attempt_id
        || record.attempts[0].launch_response_kind != MessageKind::Rejected as u16
        || record.attempts[0].terminal_sha256.is_some()
        || record.attempts[0].cleanup_sha256.is_some()
        || record.attempts[0].target_identity_sha256.is_none()
        || record.attempts[1].launch_response_kind != MessageKind::Rejected as u16
        || record.attempts[1].target_identity_sha256.is_some()
        || !record.inflight.is_empty()
    {
        return Err("final-public reuse provider recovery phase differs".into());
    }
    verify_installed(&record)?;
    let directory = root.join(String::from(result_key.clone()));
    check_directory(&directory, Some(0o700))?;
    let attempt_directory = directory.join(format!("0-{first_attempt_id}"));
    check_directory(&attempt_directory, Some(0o700))?;
    let durable = Path::new(super::STATE_ROOT).join(first_attempt_id);
    if fs::symlink_metadata(&durable).is_ok() {
        return Err("final-public reuse durable attempt still exists".into());
    }
    write_new(
        &attempt_directory.join("cleanup.bin"),
        recovered_cleanup_bytes,
    )?;
    record.attempts[0].cleanup_sha256 = Some(hash_bytes(recovered_cleanup_bytes));
    record.attempts[0].phase = "recovered-after-incomplete".into();
    record.phase = "launch-exchanges-complete".into();
    finalize(&root, &record)
}

/// Detached, root-only readback of provider-owned facts. The caller must
/// independently join CLI report/stdio, kernel observation and retirement.
pub(crate) fn verify_completed(selector: &str, challenge_hex: &str) -> Result<String, String> {
    verify_completed_inner(selector, challenge_hex, true)
}

/// Detached readback for the separate, kernel-authenticated nonroot spoof
/// registration. This is a provider denial only; the caller must still join
/// an independently observed complete no-allocation interval.
pub(crate) fn verify_public_spoof(selector: &str, challenge_hex: &str) -> Result<String, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("final-public spoof readback requires root".into());
    }
    let current = fs::metadata(std::env::current_exe().map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())?;
    let installed = fs::symlink_metadata("/usr/libexec/memcordon-sealed-agent")
        .map_err(|error| error.to_string())?;
    if !installed.is_file() || (current.dev(), current.ino()) != (installed.dev(), installed.ino())
    {
        return Err("final-public spoof readback requires installed agent image".into());
    }
    if selector != "private_tcp::caller_identity_and_epoch_bound" {
        return Err("final-public spoof selector differs".into());
    }
    let challenge = decode_challenge(challenge_hex)?;
    let case = super::private_public_release_case::FinalPublicCaseSpecV1::new(selector, challenge)?;
    let intent = read_admitted_dispatch_intent(selector, challenge_hex)?;
    let entry = intent
        .historical_spoof
        .as_ref()
        .ok_or("final-public protected spoof intent absent")?;
    if intent.schema_version != 1
        || entry.case.selector != selector
        || entry.case.challenge != challenge_hex
        || entry.unauthorized_uid == 0
        || entry.unauthorized_gid == 0
        || entry.unauthorized_uid == intent.public_uid
        || intent
            .cases
            .iter()
            .any(|candidate| candidate.selector == selector && candidate.challenge == challenge_hex)
        || intent.historical_e0.as_ref().is_some_and(|candidate| {
            candidate.case.selector == selector && candidate.case.challenge == challenge_hex
        })
    {
        return Err("final-public protected spoof intent differs".into());
    }
    let contract = pinned_contract(&entry.case.contract_path, &entry.case.contract_sha256)?;
    let lease = crate::package::acquire_verified_private_qualification_lease()?;
    let installed = super::runtime_manifest::source_v3_candidate(Path::new(
        "/usr/libexec/memcordon-sealed-agent",
    ))?
    .ok_or("final-public installed M1 absent at spoof readback")?;
    let public_cli_sha256 = installed
        .manifest
        .components
        .iter()
        .find(|component| component.id == "public-cli")
        .ok_or("final-public installed CLI absent at spoof readback")?
        .sha256
        .as_str();
    if intent.source_commit != lease.source_commit()
        || intent.target != installed.manifest.target
        || intent.manifest_sha256 != *lease.runtime_manifest_sha256()
        || intent.qualification_sha256 != *lease.qualification_digest()
        || String::from(intent.public_cli_sha256.clone()) != public_cli_sha256
    {
        return Err("final-public spoof intent differs from installed release".into());
    }
    let root = root()?;
    let _lock = lock(&root)?;
    if read_pending(&root)?
        .as_ref()
        .is_some_and(|pending| pending.result_key == case.result_key())
        || root.join("pending.v2.new").exists()
    {
        return Err("final-public spoof registration is not committed".into());
    }
    let directory = root.join(String::from(case.result_key()));
    check_directory(&directory, Some(0o700))?;
    let record_bytes = read_file(&directory.join("provider.json"), MAX_RECORD, 0o600)?
        .ok_or("final-public spoof provider record absent")?;
    reject_duplicate_json_keys(&record_bytes)?;
    let record: ProviderRecordV2 =
        serde_json::from_slice(&record_bytes).map_err(|error| error.to_string())?;
    let spoof_bytes = read_file(&directory.join("spoof.json"), MAX_RECORD, 0o600)?
        .ok_or("final-public spoof denial record absent")?;
    reject_duplicate_json_keys(&spoof_bytes)?;
    let spoof: ProtectedPublicSpoofV1 =
        serde_json::from_slice(&spoof_bytes).map_err(|error| error.to_string())?;
    if serde_json::to_vec(&spoof).map_err(|error| error.to_string())? != spoof_bytes {
        return Err("final-public spoof record is not canonical".into());
    }
    let request = read_file(&directory.join("spoof-request.bin"), MAX_RAW, 0o600)?
        .ok_or("final-public spoof request absent")?;
    let rejection_bytes = read_file(&directory.join("spoof-rejection.bin"), MAX_RAW, 0o600)?
        .ok_or("final-public spoof rejection absent")?;
    let rejection =
        memcordon_core::provider_rejection_wire::RejectionWireV1::parse(&rejection_bytes)?;
    if record.schema_version != 3
        || record.evidence_scope != "provider-frames-only"
        || record.phase != "spoof-rejected"
        || record.selector != selector
        || record.challenge != challenge_hex
        || record.result_key != case.result_key()
        || record.contract_digest != contract_digest_v2(&contract)?
        || record.peer_uid != entry.unauthorized_uid
        || record.peer_gid != entry.unauthorized_gid
        || record.spoof_authorized_uid != Some(intent.public_uid)
        || record.spoof_contract_file_sha256 != Some(entry.case.contract_sha256.clone())
        || hash_bytes(&request) != entry.case.contract_sha256
        || record.policy_branch.is_some()
        || record.policy_base_challenge_sha256.is_some()
        || record.tampered_contract_digest.is_some()
        || record.expected_launch_exchanges != 0
        || !record.attempts.is_empty()
        || !record.inflight.is_empty()
        || record.terminal_sha256.is_some()
        || record.plan_request_sha256 != Some(hash_bytes(&request))
        || record.plan_response_sha256 != Some(hash_bytes(&rejection_bytes))
        || record.plan_response_kind != Some(MessageKind::Rejected as u16)
        || record.installation_epoch != *lease.generation_digest()
        || record.manifest_sha256 != *lease.runtime_manifest_sha256()
        || record.qualification_sha256 != *lease.qualification_digest()
        || record.active_h1_receipt_sha256 != *lease.active_host_receipt_sha256()
        || spoof.schema_version != 1
        || spoof.selector != selector
        || spoof.challenge != challenge_hex
        || spoof.result_key != record.result_key
        || spoof.authenticated_peer_uid != record.peer_uid
        || spoof.authenticated_peer_gid != record.peer_gid
        || spoof.authenticated_peer_pid != record.peer_pid
        || spoof.authenticated_peer_start_ticks != record.peer_start_time_ticks
        || spoof.authorized_uid != intent.public_uid
        || spoof.installation_epoch != record.installation_epoch
        || spoof.active_h1_receipt_sha256 != record.active_h1_receipt_sha256
        || spoof.contract_file_sha256 != entry.case.contract_sha256
        || spoof.grant_decision_sha256
            != record
                .grant_decision_sha256
                .clone()
                .ok_or("final-public spoof grant digest absent")?
        || spoof.request_sha256 != hash_bytes(&request)
        || spoof.rejection_sha256 != hash_bytes(&rejection_bytes)
        || spoof.rejection_code != "MCSEALED-PRIVATE-PUBLIC-GRANT-REJECTED"
        || rejection.code != spoof.rejection_code
        || rejection.phase
            != memcordon_core::provider_rejection_wire::RejectionPhaseV1::RequestValidation
        || rejection.target_created
        || rejection.target_released
        || rejection.cleanup.attempted
        || !rejection.cleanup.errors.is_empty()
        || !spoof.durable_attempt_record_absent
        || Some(read_grant_decision(
            &directory,
            &record,
            &request,
            &rejection_bytes,
        )?) != record.grant_decision_sha256
    {
        return Err("final-public detached spoof denial differs".into());
    }
    lease.revalidate_release_boundary()?;
    String::from_utf8(spoof_bytes).map_err(|error| error.to_string())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PublicEpochReplayReadbackV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    original_request_sha256: DiagnosticSha256,
    e0_installation_epoch_sha256: DiagnosticSha256,
    e0_h1_receipt_sha256: DiagnosticSha256,
    e1_installation_epoch_sha256: DiagnosticSha256,
    e1_h1_receipt_sha256: DiagnosticSha256,
    rejection_sha256: DiagnosticSha256,
    rejection_code: String,
    durable_attempt_record_absent: bool,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct PublicEpochHandoffReadbackV1 {
    schema_version: u8,
    selector: String,
    e0_result_key: DiagnosticSha256,
    e1_result_key: DiagnosticSha256,
    e0_installation_epoch_sha256: DiagnosticSha256,
    e1_installation_epoch_sha256: DiagnosticSha256,
    e0_h1_receipt_sha256: DiagnosticSha256,
    e1_h1_receipt_sha256: DiagnosticSha256,
    original_request_sha256: DiagnosticSha256,
    replay_record_sha256: DiagnosticSha256,
    replay_rejection_sha256: DiagnosticSha256,
}

/// Detached join of two separately completed, generation-bound provider
/// registrations and the protected one-shot E1 replay record.
pub(crate) fn verify_public_epoch_handoff(
    selector: &str,
    e0_challenge: &str,
    e1_challenge: &str,
) -> Result<String, String> {
    if selector != "private_tcp::caller_identity_and_epoch_bound" || e0_challenge == e1_challenge {
        return Err("final-public epoch handoff identities differ".into());
    }
    let lease = crate::package::acquire_verified_private_qualification_lease()?;
    let e0_bytes = verify_completed_inner(selector, e0_challenge, false)?;
    let e1_bytes = verify_completed_inner(selector, e1_challenge, true)?;
    let e0: ProviderRecordV2 =
        serde_json::from_str(&e0_bytes).map_err(|error| error.to_string())?;
    let e1: ProviderRecordV2 =
        serde_json::from_str(&e1_bytes).map_err(|error| error.to_string())?;
    let replay_bytes = read_file(
        &Path::new(ROOT)
            .join(String::from(e0.result_key.clone()))
            .join("epoch-replay.json"),
        MAX_RECORD,
        0o600,
    )?
    .ok_or("final-public E1 replay record absent")?;
    if read_file(
        &Path::new(ROOT)
            .join(String::from(e0.result_key.clone()))
            .join("epoch-replay.pending"),
        MAX_RECORD,
        0o600,
    )?
    .is_some()
    {
        return Err("final-public E1 replay is interrupted".into());
    }
    reject_duplicate_json_keys(&replay_bytes)?;
    let replay: PublicEpochReplayReadbackV1 =
        serde_json::from_slice(&replay_bytes).map_err(|error| error.to_string())?;
    let replay_rejection = read_file(
        &Path::new(ROOT)
            .join(String::from(e0.result_key.clone()))
            .join("epoch-replay-rejection.bin"),
        MAX_RAW,
        0o600,
    )?
    .ok_or("final-public E1 replay rejection raw absent")?;
    let replay_rejection_wire =
        memcordon_core::provider_rejection_wire::RejectionWireV1::parse(&replay_rejection)?;
    if e0.phase != "launch-exchanges-complete"
        || e1.phase != "launch-exchanges-complete"
        || e0.attempts.len() != 1
        || e1.attempts.len() != 1
        || e0.attempts[0].phase != "terminal-observed"
        || e1.attempts[0].phase != "terminal-observed"
        || e0.result_key == e1.result_key
        || e0.installation_epoch == e1.installation_epoch
        || e0.active_h1_receipt_sha256 == e1.active_h1_receipt_sha256
        || e0.manifest_sha256 != e1.manifest_sha256
        || e0.qualification_sha256 != e1.qualification_sha256
        || e1.installation_epoch != *lease.generation_digest()
        || e1.active_h1_receipt_sha256 != *lease.active_host_receipt_sha256()
        || replay.schema_version != 1
        || replay.selector != selector
        || replay.result_key != e0.result_key
        || replay.original_request_sha256 != e0.attempts[0].launch_request_sha256
        || replay.e0_installation_epoch_sha256 != e0.installation_epoch
        || replay.e0_h1_receipt_sha256 != e0.active_h1_receipt_sha256
        || replay.e1_installation_epoch_sha256 != e1.installation_epoch
        || replay.e1_h1_receipt_sha256 != e1.active_h1_receipt_sha256
        || replay.rejection_code != "MCSEALED-PRIVATE-EXPECTED-PLAN"
        || replay_rejection_wire.code != replay.rejection_code
        || replay_rejection_wire.target_created
        || replay_rejection_wire.target_released
        || hash_bytes(&replay_rejection) != replay.rejection_sha256
        || !replay.durable_attempt_record_absent
    {
        return Err("final-public epoch handoff readback differs".into());
    }
    lease.revalidate_release_boundary()?;
    let handoff = PublicEpochHandoffReadbackV1 {
        schema_version: 1,
        selector: selector.into(),
        e0_result_key: e0.result_key,
        e1_result_key: e1.result_key,
        e0_installation_epoch_sha256: e0.installation_epoch,
        e1_installation_epoch_sha256: e1.installation_epoch,
        e0_h1_receipt_sha256: e0.active_h1_receipt_sha256,
        e1_h1_receipt_sha256: e1.active_h1_receipt_sha256,
        original_request_sha256: replay.original_request_sha256,
        replay_record_sha256: hash_bytes(&replay_bytes),
        replay_rejection_sha256: replay.rejection_sha256,
    };
    serde_json::to_string(&handoff).map_err(|error| error.to_string())
}

/// Replay the exact protected E0 launch payload against the E1 provider. This
/// establishes a real preallocation rejection, not the CI-owned no-allocation
/// interval or the independent fresh E1 control.
pub(crate) fn replay_public_epoch(selector: &str, challenge_hex: &str) -> Result<String, String> {
    if selector != "private_tcp::caller_identity_and_epoch_bound" {
        return Err("final-public epoch replay selector differs".into());
    }
    let verified = verify_completed_inner(selector, challenge_hex, false)?;
    let e0: ProviderRecordV2 =
        serde_json::from_str(&verified).map_err(|error| error.to_string())?;
    if e0.phase != "launch-exchanges-complete" || e0.attempts.len() != 1 {
        return Err("final-public E0 transcript differs".into());
    }
    let attempt = &e0.attempts[0];
    if attempt.phase != "terminal-observed" {
        return Err("final-public E0 attempt was not retired".into());
    }
    let lease = crate::package::acquire_verified_private_qualification_lease()?;
    if e0.installation_epoch == *lease.generation_digest()
        || e0.active_h1_receipt_sha256 == *lease.active_host_receipt_sha256()
        || e0.manifest_sha256 != *lease.runtime_manifest_sha256()
        || e0.qualification_sha256 != *lease.qualification_digest()
    {
        return Err("final-public E0/E1 release handoff differs".into());
    }
    let directory = Path::new(ROOT).join(String::from(e0.result_key.clone()));
    let request_bytes = read_file(
        &directory.join(format!("0-{}/request.bin", attempt.attempt_id)),
        MAX_RAW,
        0o600,
    )?
    .ok_or("final-public E0 launch request absent")?;
    if hash_bytes(&request_bytes) != attempt.launch_request_sha256 {
        return Err("final-public E0 launch request changed".into());
    }
    let old = crate::request::decode_network_launch_request(&request_bytes)
        .map_err(|error| format!("final-public E0 request decode: {error:?}"))?;
    let expected_plan = old
        .expected_plan
        .ok_or("final-public E0 request lacks plan precondition")?;
    expected_plan.verify_current(&old.contract, &e0.installation_epoch)?;
    if expected_plan
        .verify_current(&old.contract, lease.generation_digest())
        .is_ok()
    {
        return Err("final-public old request remains admissible at E1".into());
    }
    let attempt_path = Path::new(super::STATE_ROOT).join(&attempt.attempt_id);
    if read_file(
        &attempt_path,
        super::private_attempt::MAX_PRIVATE_RECORD_BYTES as u64,
        0o600,
    )?
    .is_some()
    {
        return Err("final-public E0 attempt remained allocated before replay".into());
    }
    // Reserve this historical replay before contacting the service. A crash
    // leaves the marker and cannot silently authorize another replay.
    {
        let root = root()?;
        let _lock = lock(&root)?;
        if read_file(&directory.join("epoch-replay.json"), MAX_RECORD, 0o600)?.is_some()
            || read_file(&directory.join("epoch-replay.pending"), MAX_RECORD, 0o600)?.is_some()
        {
            return Err("final-public historical replay already used or interrupted".into());
        }
        let marker = serde_json::to_vec(&(
            &e0.result_key,
            lease.generation_digest(),
            lease.active_host_receipt_sha256(),
            &attempt.launch_request_sha256,
        ))
        .map_err(|error| error.to_string())?;
        write_new(&directory.join("epoch-replay.pending"), &marker)?;
    }
    let mut attempt_id = [0_u8; 16];
    for (index, pair) in attempt.attempt_id.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair).map_err(|error| error.to_string())?;
        attempt_id[index] = u8::from_str_radix(text, 16).map_err(|error| error.to_string())?;
    }
    let nonce = super::launcher::nonce()?;
    let request = Frame {
        kind: MessageKind::PrivateLaunch,
        nonce,
        attempt_id,
        payload: request_bytes,
    };
    let mut stream = std::os::unix::net::UnixStream::connect(super::SOCKET_PATH)
        .map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .and_then(|()| stream.set_write_timeout(Some(Duration::from_secs(10))))
        .map_err(|error| error.to_string())?;
    super::launcher::authenticate_control_service(&stream)?;
    let mut encoded = Vec::new();
    crate::protocol::write_network_frame(&mut encoded, &request)
        .map_err(|error| error.to_string())?;
    super::transport::send(&stream, &encoded, &[])?;
    let response =
        crate::protocol::read_network_frame(&mut stream).map_err(|error| error.to_string())?;
    if response.kind != MessageKind::Rejected
        || response.nonce != nonce
        || response.attempt_id != attempt_id
    {
        return Err("final-public E1 replay response differs".into());
    }
    let rejection =
        memcordon_core::provider_rejection_wire::RejectionWireV1::parse(&response.payload)?;
    if rejection.code != "MCSEALED-PRIVATE-EXPECTED-PLAN"
        || rejection.target_created
        || rejection.target_released
        || read_file(
            &attempt_path,
            super::private_attempt::MAX_PRIVATE_RECORD_BYTES as u64,
            0o600,
        )?
        .is_some()
    {
        return Err("final-public E1 replay was not preallocation-rejected".into());
    }
    lease.revalidate_release_boundary()?;
    let readback = PublicEpochReplayReadbackV1 {
        schema_version: 1,
        selector: selector.into(),
        result_key: e0.result_key,
        original_request_sha256: attempt.launch_request_sha256.clone(),
        e0_installation_epoch_sha256: e0.installation_epoch,
        e0_h1_receipt_sha256: e0.active_h1_receipt_sha256,
        e1_installation_epoch_sha256: lease.generation_digest().clone(),
        e1_h1_receipt_sha256: lease.active_host_receipt_sha256().clone(),
        rejection_sha256: hash_bytes(&response.payload),
        rejection_code: rejection.code,
        durable_attempt_record_absent: true,
    };
    let encoded = serde_json::to_vec(&readback).map_err(|error| error.to_string())?;
    let root = root()?;
    let _lock = lock(&root)?;
    check_directory(&directory, Some(0o700))?;
    if read_file(&directory.join("epoch-replay.pending"), MAX_RECORD, 0o600)?.is_none() {
        return Err("final-public historical replay reservation vanished".into());
    }
    write_new(
        &directory.join("epoch-replay-rejection.bin"),
        &response.payload,
    )?;
    write_new(&directory.join("epoch-replay.json"), &encoded)?;
    fs::remove_file(directory.join("epoch-replay.pending")).map_err(|error| error.to_string())?;
    File::open(&directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())?;
    String::from_utf8(encoded).map_err(|error| error.to_string())
}

fn verify_completed_inner(
    selector: &str,
    challenge_hex: &str,
    require_current_generation: bool,
) -> Result<String, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("final-public provider readback requires root".into());
    }
    let current = fs::metadata(std::env::current_exe().map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())?;
    let installed = fs::symlink_metadata("/usr/libexec/memcordon-sealed-agent")
        .map_err(|error| error.to_string())?;
    if !installed.is_file() || (current.dev(), current.ino()) != (installed.dev(), installed.ino())
    {
        return Err("final-public readback requires installed agent image".into());
    }
    let challenge = decode_challenge(challenge_hex)?;
    let case = super::private_public_release_case::FinalPublicCaseSpecV1::new(selector, challenge)?;
    let root = root()?;
    let _lock = lock(&root)?;
    if read_pending(&root)?
        .as_ref()
        .is_some_and(|pending| pending.result_key == case.result_key())
        || root.join("pending.v2.new").exists()
    {
        return Err("final-public provider completion is not committed".into());
    }
    let directory = root.join(String::from(case.result_key()));
    check_directory(&directory, Some(0o700))?;
    let bytes = read_file(&directory.join("provider.json"), MAX_RECORD, 0o600)?
        .ok_or("final-public provider completion absent")?;
    reject_duplicate_json_keys(&bytes)?;
    let record: ProviderRecordV2 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if record.schema_version != 3
        || record.evidence_scope != "provider-frames-only"
        || record.selector != selector
        || record.challenge != challenge_hex
        || record.result_key != case.result_key()
        || record.expected_launch_exchanges
            != expected_launch_exchanges(selector, record.policy_branch)?
        || !record.inflight.is_empty()
        || record.plan_request_sha256.is_none()
        || record.plan_response_sha256.is_none()
        || record.grant_decision_sha256.is_none()
        || !matches!(
            record.phase.as_str(),
            "plan-rejected" | "launch-exchanges-complete"
        )
    {
        return Err("final-public provider completion identity differs".into());
    }
    if selector == "private_tcp::wrong_grant_profile_and_port_rejected" {
        let intent = read_admitted_dispatch_intent(selector, challenge_hex)?;
        let (entry, base_digest) = policy_dispatch_branch(&intent, selector, challenge_hex)?
            .ok_or("final-public policy branch intent absent at readback")?;
        let pinned = pinned_contract(&entry.case.contract_path, &entry.case.contract_sha256)?;
        let tampered = match (
            &entry.tampered_contract_path,
            &entry.tampered_contract_sha256,
        ) {
            (Some(path), Some(digest)) => {
                Some(contract_digest_v2(&pinned_contract(path, digest)?)?)
            }
            (None, None) => None,
            _ => return Err("final-public policy tampered contract pin differs".into()),
        };
        if record.policy_branch != Some(entry.policy_branch)
            || record.policy_base_challenge_sha256 != Some(base_digest)
            || record.peer_uid != intent.public_uid
            || record.peer_gid != intent.public_gid
            || record.contract_digest != contract_digest_v2(&pinned)?
            || record.tampered_contract_digest != tampered
            || record.plan_request_sha256 != Some(entry.case.contract_sha256.clone())
        {
            return Err("final-public policy branch detached intent differs".into());
        }
    } else if record.policy_branch.is_some()
        || record.policy_base_challenge_sha256.is_some()
        || record.tampered_contract_digest.is_some()
    {
        return Err("final-public ordinary case has policy branch".into());
    }
    let required = [
        ("plan-request.bin", record.plan_request_sha256.as_ref()),
        ("request.bin", record.plan_request_sha256.as_ref()),
        ("plan-response.bin", record.plan_response_sha256.as_ref()),
        ("grant-decision.json", record.grant_decision_sha256.as_ref()),
        ("terminal.bin", record.terminal_sha256.as_ref()),
    ];
    for (leaf, expected) in required {
        let actual = read_file(&directory.join(leaf), MAX_RAW, 0o600)?;
        match (actual.as_deref(), expected) {
            (Some(bytes), Some(digest)) if &hash_bytes(bytes) == digest => {}
            (None, None) => {}
            _ => return Err(format!("final-public provider {leaf} differs")),
        }
    }
    let plan_request = read_file(&directory.join("plan-request.bin"), MAX_RAW, 0o600)?
        .ok_or("final-public plan request absent at grant readback")?;
    let plan_response = read_file(&directory.join("plan-response.bin"), MAX_RAW, 0o600)?
        .ok_or("final-public plan response absent at grant readback")?;
    if Some(read_grant_decision(
        &directory,
        &record,
        &plan_request,
        &plan_response,
    )?) != record.grant_decision_sha256
    {
        return Err("final-public grant decision detached hash differs".into());
    }
    if record.phase == "plan-rejected" {
        if record.expected_launch_exchanges != 0
            || record.plan_response_kind != Some(MessageKind::Rejected as u16)
            || record.terminal_sha256 != record.plan_response_sha256
            || !record.attempts.is_empty()
            || policy_plan_denial(record.policy_branch).is_none()
        {
            return Err("final-public provider rejection readback differs".into());
        }
    } else if record.plan_response_kind != Some(MessageKind::PrivatePlanReceipt as u16)
        || record.terminal_sha256.is_some()
        || record.attempts.len() != usize::from(record.expected_launch_exchanges)
    {
        return Err("final-public provider launch count differs".into());
    }
    if record.selector == "private_tcp::abi_alternate_entry_denied"
        && (record.phase != "launch-exchanges-complete"
            || record.attempts.len() != 1
            || record.attempts[0].launch_response_kind != MessageKind::Terminal as u16)
    {
        return Err("final-public ABI completion did not include one complete target".into());
    }
    if record.policy_branch == Some(PolicyOperationBranchV1::AcceptedControl)
        && record
            .attempts
            .first()
            .is_none_or(|entry| entry.launch_response_kind != MessageKind::Terminal as u16)
        || record.policy_branch == Some(PolicyOperationBranchV1::CommittedPortTamper)
            && record
                .attempts
                .first()
                .is_none_or(|entry| entry.launch_response_kind != MessageKind::Rejected as u16)
    {
        return Err("final-public policy launch branch differs".into());
    }
    let mut seen = std::collections::HashSet::new();
    for (ordinal, attempt) in record.attempts.iter().enumerate() {
        if usize::from(attempt.ordinal) != ordinal
            || attempt.attempt_id.len() != 32
            || attempt.attempt_id.bytes().all(|byte| byte == b'0')
            || !attempt
                .attempt_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !seen.insert(&attempt.attempt_id)
        {
            return Err("final-public provider attempt identity differs".into());
        }
        let attempt_directory =
            directory.join(format!("{}-{}", attempt.ordinal, attempt.attempt_id));
        check_directory(&attempt_directory, Some(0o700))?;
        let launch_request = read_file(&attempt_directory.join("request.bin"), MAX_RAW, 0o600)?
            .ok_or("final-public launch request absent at plan join")?;
        verify_launch_plan_link(&directory, &record, &launch_request)?;
        if read_file(
            &attempt_directory.join("target-identity.pending.json"),
            MAX_RECORD,
            0o600,
        )?
        .is_some()
        {
            return Err("final-public target identity gate was interrupted".into());
        }
        for (leaf, expected) in [
            ("request.bin", Some(&attempt.launch_request_sha256)),
            ("response.bin", Some(&attempt.launch_response_sha256)),
            ("terminal.bin", attempt.terminal_sha256.as_ref()),
            ("cleanup.bin", attempt.cleanup_sha256.as_ref()),
            (
                "target-identity.json",
                attempt.target_identity_sha256.as_ref(),
            ),
            (
                "fault-trigger-v1.json",
                attempt.fault_trigger_sha256.as_ref(),
            ),
            (
                "fault-failure-v1.json",
                attempt.fault_failure_sha256.as_ref(),
            ),
            (
                "fault-retirement-v1.json",
                attempt.fault_retirement_sha256.as_ref(),
            ),
            (
                "fault-recovery-v1.json",
                attempt.fault_recovery_sha256.as_ref(),
            ),
            (
                "checkpoint-committed-v4.bin",
                attempt.checkpoint_committed_sha256.as_ref(),
            ),
            (
                "release-intent-v4.bin",
                attempt.release_intent_sha256.as_ref(),
            ),
            (
                "execution-observed-v4.bin",
                attempt.execution_observed_sha256.as_ref(),
            ),
            (
                "cgroup-retirement-v1.json",
                attempt.cgroup_retirement_sha256.as_ref(),
            ),
        ] {
            let actual = read_file(&attempt_directory.join(leaf), MAX_RAW, 0o600)?;
            match (actual.as_deref(), expected) {
                (Some(bytes), Some(digest)) if &hash_bytes(bytes) == digest => {}
                (None, None) => {}
                _ => {
                    return Err(format!(
                        "final-public provider attempt {ordinal} {leaf} differs"
                    ));
                }
            }
        }
        if let Some(identity_sha256) = &attempt.target_identity_sha256 {
            let identity_bytes = read_file(
                &attempt_directory.join("target-identity.json"),
                MAX_RECORD,
                0o600,
            )?
            .ok_or("final-public protected target identity absent")?;
            reject_duplicate_json_keys(&identity_bytes)?;
            let identity: ProviderTargetIdentityV1 =
                serde_json::from_slice(&identity_bytes).map_err(|error| error.to_string())?;
            if hash_bytes(&identity_bytes) != *identity_sha256
                || identity.gated.schema_version != 1
                || identity.gated.evidence_scope != "durable-live-target-gated"
                || identity.gated.attempt_id != attempt.attempt_id
                || identity.gated.request_sha256 != attempt.launch_request_sha256
                || identity.gated.target.pid == 0
                || identity.gated.target.start_time == 0
                || identity.gated.namespace_init.pid == 0
                || identity.gated.namespace_init.start_time == 0
                || identity.gated.network_namespace_inode == 0
                || identity.gated.target == identity.gated.namespace_init
                || identity.entrypoint_device == 0
                || identity.entrypoint_inode == 0
                || !identity.entrypoint_path.starts_with('/')
                || identity.entrypoint_path.contains('\0')
            {
                return Err("final-public protected target identity differs".into());
            }
            if record.selector == "private_tcp::abi_alternate_entry_denied" {
                if ordinal != 0 || attempt.launch_response_kind != MessageKind::Terminal as u16 {
                    return Err("final-public ABI provider outcome differs".into());
                }
                super::private_public_abi_filtered::verify_protected_report(
                    &record.result_key,
                    &record.challenge,
                    &attempt.attempt_id,
                    &identity.gated.target,
                )?;
            }
        }
        let reuse = record.selector == super::private_public_reuse::SELECTOR;
        if let Some(plan) = fault_plan(&record.selector) {
            if !matches!(
                attempt.phase.as_str(),
                "fault-retired-observed" | "fault-recovered-after-incomplete"
            ) || attempt.fault_trigger_sha256.is_none()
                || attempt.cleanup_sha256.is_none()
                || attempt.target_identity_sha256.is_none()
                || attempt.checkpoint_committed_sha256.is_none()
                || attempt.release_intent_sha256.is_none()
                || fs::symlink_metadata(Path::new(super::STATE_ROOT).join(&attempt.attempt_id))
                    .is_ok()
            {
                return Err("final-public completed fault settlement differs".into());
            }
            let trigger_bytes = read_file(
                &attempt_directory.join("fault-trigger-v1.json"),
                MAX_RAW,
                0o600,
            )?
            .ok_or("fault trigger absent")?;
            reject_duplicate_json_keys(&trigger_bytes)?;
            let trigger: PublicFaultTriggerV1 =
                serde_json::from_slice(&trigger_bytes).map_err(|error| error.to_string())?;
            let durable = super::private_attempt::PrivateAttemptRecordV4::parse(
                &trigger.durable_attempt_bytes,
            )?;
            if trigger.schema_version != 1
                || trigger.fault != plan
                || trigger.attempt_id != attempt.attempt_id
                || trigger.result_key != record.result_key
                || trigger.request_sha256 != attempt.launch_request_sha256
                || durable.target.as_ref() != Some(&trigger.target)
                || durable.checkpoint_digest.as_ref() != Some(&trigger.checkpoint_sha256)
                || plan == PublicFaultPlanV1::DropAuthorizationAtDurableIntent
                    && (trigger.operation_errno != Some(libc::EPIPE)
                        || durable.phase
                            != super::private_attempt::PrivateAttemptPhase::ReleaseIntent
                        || attempt.execution_observed_sha256.is_some()
                        || attempt.launch_response_kind != MessageKind::Rejected as u16
                        || attempt.terminal_sha256.is_some())
                || plan != PublicFaultPlanV1::DropAuthorizationAtDurableIntent
                    && (trigger.target_tcp_bytes.is_empty()
                        || trigger.target_socket_inodes.len() < 2
                        || durable.phase
                            != super::private_attempt::PrivateAttemptPhase::ExecutionObserved
                        || attempt.execution_observed_sha256.is_none())
                || attempt.phase == "fault-retired-observed"
                    && attempt.fault_retirement_sha256.is_none()
                || attempt.phase == "fault-recovered-after-incomplete"
                    && (attempt.fault_recovery_sha256.is_none()
                        || attempt.fault_failure_sha256.is_none()
                        || attempt.launch_response_kind != MessageKind::Rejected as u16
                        || attempt.terminal_sha256.is_some())
            {
                return Err("final-public completed fault trigger/outcome differs".into());
            }
            if attempt.launch_response_kind == MessageKind::Rejected as u16 {
                let response = read_file(&attempt_directory.join("response.bin"), MAX_RAW, 0o600)?
                    .ok_or("fault rejection absent")?;
                let rejection =
                    memcordon_core::provider_rejection_wire::RejectionWireV1::parse(&response)?;
                if !rejection.target_created
                    || !rejection.target_released
                    || !rejection.cleanup.attempted
                    || rejection.cleanup.sealed_boundary_retired
                        != (attempt.phase == "fault-retired-observed")
                {
                    return Err("final-public original fault rejection differs".into());
                }
            } else if attempt.launch_response_kind != MessageKind::Terminal as u16
                || attempt.terminal_sha256.as_ref() != Some(&attempt.launch_response_sha256)
            {
                return Err("final-public original fault response differs".into());
            }
            continue;
        }
        if reuse && ordinal == 0 {
            if attempt.phase != "recovered-after-incomplete"
                || attempt.launch_response_kind != MessageKind::Rejected as u16
                || attempt.terminal_sha256.is_some()
                || attempt.cleanup_sha256.is_none()
                || attempt.target_identity_sha256.is_none()
            {
                return Err("final-public reuse first attempt readback differs".into());
            }
            let response_bytes =
                read_file(&attempt_directory.join("response.bin"), MAX_RAW, 0o600)?
                    .ok_or("final-public reuse first response absent")?;
            super::private_public_reuse::verify_provider_response_bytes(
                &record.result_key,
                ordinal,
                &response_bytes,
            )?;
            let rejection =
                memcordon_core::provider_rejection_wire::RejectionWireV1::parse(&response_bytes)?;
            if rejection.code != "MCSEALED-PRIVATE-REUSE-CLEANUP-INCOMPLETE"
                || !rejection.target_created
                || !rejection.target_released
                || !rejection.cleanup.attempted
                || rejection.cleanup.sealed_boundary_retired
                || rejection.cleanup.errors.is_empty()
            {
                return Err("final-public reuse first rejection differs".into());
            }
            let cleanup_bytes = read_file(&attempt_directory.join("cleanup.bin"), MAX_RAW, 0o600)?
                .ok_or("final-public reuse recovery cleanup absent")?;
            super::private_public_reuse::verify_recovered_cleanup_bytes(
                &cleanup_bytes,
                &record.result_key,
                &attempt.attempt_id,
            )?;
            if fs::symlink_metadata(Path::new(super::STATE_ROOT).join(&attempt.attempt_id)).is_ok()
            {
                return Err("final-public reuse durable attempt still exists".into());
            }
        } else if reuse && ordinal == 1 {
            if attempt.phase != "reuse-blocked-observed"
                || attempt.launch_response_kind != MessageKind::Rejected as u16
                || attempt.terminal_sha256.is_some()
                || attempt.cleanup_sha256.is_some()
                || attempt.target_identity_sha256.is_some()
            {
                return Err("final-public reuse blocked attempt readback differs".into());
            }
            let response_bytes =
                read_file(&attempt_directory.join("response.bin"), MAX_RAW, 0o600)?
                    .ok_or("final-public reuse blocked response absent")?;
            super::private_public_reuse::verify_provider_response_bytes(
                &record.result_key,
                ordinal,
                &response_bytes,
            )?;
            let rejection =
                memcordon_core::provider_rejection_wire::RejectionWireV1::parse(&response_bytes)?;
            if rejection.code != "MCSEALED-PRIVATE-REUSE-BLOCKED"
                || rejection.target_created
                || rejection.target_released
                || rejection.cleanup.attempted
                || !rejection.cleanup.errors.is_empty()
            {
                return Err("final-public reuse blocked rejection differs".into());
            }
        } else if attempt.launch_response_kind == MessageKind::Terminal as u16 {
            if attempt.phase != "terminal-observed"
                || attempt.terminal_sha256.as_ref() != Some(&attempt.launch_response_sha256)
                || attempt.cleanup_sha256.is_none()
                || attempt.target_identity_sha256.is_none()
            {
                return Err("final-public provider terminal attempt differs".into());
            }
            let cleanup_bytes = read_file(&attempt_directory.join("cleanup.bin"), MAX_RAW, 0o600)?
                .ok_or("final-public provider cleanup absent")?;
            reject_duplicate_json_keys(&cleanup_bytes)?;
            let cleanup: ProviderCleanupObservationV1 =
                serde_json::from_slice(&cleanup_bytes).map_err(|error| error.to_string())?;
            let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .map_err(|error| error.to_string())?;
            if cleanup.schema_version != 1
                || cleanup.evidence_scope != "post-terminal-state-readback"
                || cleanup.provider_response_kind != MessageKind::Terminal as u16
                || !cleanup.durable_attempt_record_absent
                || cleanup.boot_id != boot.trim()
                || cleanup.attempt_id != attempt.attempt_id
                || cleanup.terminal_sha256 != attempt.launch_response_sha256
                || read_file(
                    &Path::new(super::STATE_ROOT).join(&attempt.attempt_id),
                    super::private_attempt::MAX_PRIVATE_RECORD_BYTES as u64,
                    0o600,
                )?
                .is_some()
            {
                return Err("final-public provider cleanup readback differs".into());
            }
        } else if attempt.phase != "nonterminal-observed"
            || attempt.terminal_sha256.is_some()
            || attempt.cleanup_sha256.is_some()
            || attempt.launch_response_kind == MessageKind::Rejected as u16
                && attempt.target_identity_sha256.is_some()
        {
            return Err("final-public provider nonterminal attempt differs".into());
        }
        if !reuse && attempt.launch_response_kind == MessageKind::Rejected as u16 {
            let response_bytes =
                read_file(&attempt_directory.join("response.bin"), MAX_RAW, 0o600)?
                    .ok_or("final-public launch rejection raw absent")?;
            let rejection =
                memcordon_core::provider_rejection_wire::RejectionWireV1::parse(&response_bytes)?;
            if rejection.target_created
                || rejection.target_released
                || record.policy_branch == Some(PolicyOperationBranchV1::CommittedPortTamper)
                    && (rejection.code != "MCSEALED-PRIVATE-EXPECTED-PLAN"
                        || rejection.cleanup.attempted)
            {
                return Err("final-public launch rejection target state differs".into());
            }
        }
    }
    if require_current_generation {
        verify_installed(&record)?;
    }
    String::from_utf8(bytes).map_err(|error| error.to_string())
}
