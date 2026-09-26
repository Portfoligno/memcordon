//! Root-custodied provider observations for an installed public V2
//! case. This is not a final-public case certificate: CLI stdio/report, kernel
//! observations and retirement still require independent detached witnesses.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

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
const PENDING: &str = "pending.v2.json";
const MAX_RECORD: u64 = 128 * 1024;
const MAX_RAW: u64 = crate::protocol::MAX_FRAME_LENGTH as u64;

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
    inflight: Option<ProviderInflightV2>,
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
            .as_ref()
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
    let Some(inflight) = record.inflight.as_ref() else {
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
        .as_ref()
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
    if record.schema_version != 2 || record.evidence_scope != "provider-frames-only" {
        return Err("final-public provider pending schema differs".into());
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
    let intent_bytes = super::installed_release_qualification::read_protected_absolute(
        Path::new(INTENT),
        MAX_RECORD,
        Some(0o600),
    )?;
    reject_duplicate_json_keys(&intent_bytes)?;
    let intent: DispatchIntent =
        serde_json::from_slice(&intent_bytes).map_err(|error| error.to_string())?;
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
        schema_version: 2,
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
        inflight: None,
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
            || record.inflight.is_some()
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
    let ordinal = u8::try_from(record.attempts.len()).map_err(|error| error.to_string())?;
    let attempt_id = request
        .attempt_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if request.kind != MessageKind::PrivateLaunch
        || record.phase != "plan-accepted"
        || record.inflight.is_some()
        || ordinal >= record.expected_launch_exchanges
        || request.attempt_id == [0; 16]
        || record
            .attempts
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
    record.inflight = Some(ProviderInflightV2 {
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
    let Some(inflight) = record.inflight.as_ref() else {
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
    let Some(inflight) = record.inflight.as_ref() else {
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
    check_peer(&record, pid, uid, gid)?;
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
    let ordinal = u8::try_from(record.attempts.len()).map_err(|error| error.to_string())?;
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
        .as_ref()
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
            attempt_id,
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
    record.attempts.push(attempt);
    record.inflight = None;
    if reuse && record.attempts.len() == usize::from(record.expected_launch_exchanges) {
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
        || record.inflight.is_some()
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
        || record.inflight.is_some()
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
    let intent_bytes = super::installed_release_qualification::read_protected_absolute(
        Path::new(INTENT),
        MAX_RECORD,
        Some(0o600),
    )?;
    reject_duplicate_json_keys(&intent_bytes)?;
    let intent: DispatchIntent =
        serde_json::from_slice(&intent_bytes).map_err(|error| error.to_string())?;
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
    if record.schema_version != 2
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
        || record.inflight.is_some()
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
    if record.schema_version != 2
        || record.evidence_scope != "provider-frames-only"
        || record.selector != selector
        || record.challenge != challenge_hex
        || record.result_key != case.result_key()
        || record.expected_launch_exchanges
            != expected_launch_exchanges(selector, record.policy_branch)?
        || record.inflight.is_some()
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
        let intent_bytes = super::installed_release_qualification::read_protected_absolute(
            Path::new(INTENT),
            MAX_RECORD,
            Some(0o600),
        )?;
        reject_duplicate_json_keys(&intent_bytes)?;
        let intent: DispatchIntent =
            serde_json::from_slice(&intent_bytes).map_err(|error| error.to_string())?;
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
