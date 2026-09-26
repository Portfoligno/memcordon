//! Installed nonroot CLI execution for a final-public case.
//!
//! This produces direct process and report observations only. P requires the
//! full selector-specific protected terminal, live kernel and retirement join.

#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::time::Duration;

use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_codec::hash_bytes;

use crate::private_public_v2::StructuralPublicV2Readback;
#[cfg(target_os = "linux")]
use crate::private_public_v2::{
    ExpectedPublicV2Readback, public_v2_argv_with_expected_plan, read_structural_public_v2_report,
};
use crate::private_supervisor::SupervisedProcessV2;
#[cfg(target_os = "linux")]
use crate::private_supervisor::{LinuxChildIdentityV1, parse_linux_child_stat};
#[cfg(target_os = "linux")]
use crate::{CiError, Result};

/// Hidden nonroot argv-preserving gate. The parent registers this exact live
/// PID/start before writing the one-byte release token; the same process then
/// replaces its image with the fixed installed public CLI via native exec.
#[cfg(target_os = "linux")]
pub fn run_public_child_gate(
    fd: i32,
    working_directory: &Path,
    cli: &Path,
    argv: &[std::ffi::OsString],
) -> Result<()> {
    use std::os::unix::process::CommandExt;
    if unsafe { libc::geteuid() } == 0
        || fd != 3
        || cli != Path::new("/usr/bin/memcordon")
        || !working_directory.starts_with("/run/memcordon-final-public/")
        || argv.is_empty()
        || argv.len() > 16
    {
        return Err(CiError::Message(
            "public child gate identity differs".into(),
        ));
    }
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(CiError::Message(
            "public child gate cannot disable ptrace".into(),
        ));
    }
    let mut byte = [0_u8; 1];
    let count = unsafe { libc::read(fd, byte.as_mut_ptr().cast(), 1) };
    if count != 1 || byte != [0xa5] {
        return Err(CiError::Message(
            "public child gate was not registered".into(),
        ));
    }
    unsafe { libc::close(fd) };
    let error = std::process::Command::new(cli)
        .args(argv)
        .env_clear()
        .current_dir(working_directory)
        .exec();
    Err(CiError::Message(format!(
        "installed public CLI exec failed: {error}"
    )))
}

#[cfg(not(target_os = "linux"))]
pub fn run_public_child_gate(
    _fd: i32,
    _working_directory: &std::path::Path,
    _cli: &std::path::Path,
    _argv: &[std::ffi::OsString],
) -> crate::Result<()> {
    Err(crate::CiError::Message(
        "public child gate requires Linux".into(),
    ))
}

pub struct ObservedInstalledPublicCaseV3 {
    pub process: SupervisedProcessV2,
    pub report: Option<StructuralPublicV2Readback>,
    pub report_bytes: Option<Vec<u8>>,
    pub stdio_bytes: Vec<u8>,
    pub cli_sha256: DiagnosticSha256,
    pub argv_sha256: DiagnosticSha256,
    pub working_directory_sha256: DiagnosticSha256,
}

/// Exact supervisor-owned byte framing; neither the CLI nor provider writes
/// this attachment. Length fields make binary stdout/stderr unambiguous.
pub fn canonical_public_stdio_v1(
    pid: u32,
    start_time_ticks: u64,
    raw_status: i32,
    stdout: &[u8],
    stderr: &[u8],
) -> crate::Result<Vec<u8>> {
    if pid == 0 || start_time_ticks == 0 || stdout.len() > 1024 * 1024 || stderr.len() > 1024 * 1024
    {
        return Err(crate::CiError::Message(
            "public stdio supervisor bound differs".into(),
        ));
    }
    let mut bytes = b"memcordon/public-stdio/v1\0".to_vec();
    bytes.extend_from_slice(&pid.to_le_bytes());
    bytes.extend_from_slice(&start_time_ticks.to_le_bytes());
    bytes.extend_from_slice(&raw_status.to_le_bytes());
    bytes.extend_from_slice(&(stdout.len() as u32).to_le_bytes());
    bytes.extend_from_slice(stdout);
    bytes.extend_from_slice(&(stderr.len() as u32).to_le_bytes());
    bytes.extend_from_slice(stderr);
    Ok(bytes)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedPublicDispatchIntentV1 {
    schema_version: u8,
    source_commit: String,
    target: String,
    archive_sha256: DiagnosticSha256,
    manifest_sha256: DiagnosticSha256,
    qualification_sha256: DiagnosticSha256,
    public_cli_sha256: DiagnosticSha256,
    build_context_sha256: DiagnosticSha256,
    release_catalogue_sha256: DiagnosticSha256,
    public_uid: u32,
    public_gid: u32,
    observer: ProtectedPublicObserverIntentV1,
    historical_e0: HistoricalE0DispatchV1,
    historical_spoof: HistoricalSpoofDispatchV1,
    cases: Vec<PublicDispatchCaseV1>,
    policy: Option<PublicPolicyDispatchV1>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicPolicyDispatchV1 {
    base_challenge: String,
    branches: Vec<PublicDispatchCaseV1>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedPublicObserverIntentV1 {
    boot_id: String,
    kernel_release: String,
    btf_sha256: DiagnosticSha256,
    probe_map_sha256: DiagnosticSha256,
    control_result_key: DiagnosticSha256,
    probe_bundle: crate::private_probe_bundle::ExpectedProbeBundleV1,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicDispatchCaseV1 {
    selector: String,
    challenge: String,
    contract_path: std::path::PathBuf,
    contract_sha256: DiagnosticSha256,
    fixture_path: std::path::PathBuf,
    fixture_sha256: DiagnosticSha256,
    expected_plan_path: Option<std::path::PathBuf>,
    expected_plan_sha256: Option<DiagnosticSha256>,
    report_path: std::path::PathBuf,
    outcome: String,
    policy_branch: Option<memcordon_core::private_release_branch_v1::PolicyOperationBranchV1>,
    tampered_contract_path: Option<std::path::PathBuf>,
    tampered_contract_sha256: Option<DiagnosticSha256>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalE0DispatchV1 {
    selector: String,
    challenge: String,
    contract_path: std::path::PathBuf,
    contract_sha256: DiagnosticSha256,
    fixture_path: std::path::PathBuf,
    fixture_sha256: DiagnosticSha256,
    expected_plan_path: std::path::PathBuf,
    expected_plan_sha256: DiagnosticSha256,
    report_path: std::path::PathBuf,
    outcome: String,
    e0_installation_epoch_sha256: DiagnosticSha256,
    e0_h1_receipt_sha256: DiagnosticSha256,
    upgrade_archive_path: std::path::PathBuf,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalSpoofDispatchV1 {
    selector: String,
    challenge: String,
    contract_path: std::path::PathBuf,
    contract_sha256: DiagnosticSha256,
    fixture_path: std::path::PathBuf,
    fixture_sha256: DiagnosticSha256,
    report_path: std::path::PathBuf,
    outcome: String,
    unauthorized_uid: u32,
    unauthorized_gid: u32,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalPublicEpochReplayV1 {
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

pub struct ExpectedHistoricalPublicEpochReplayV1<'a> {
    pub selector: &'a str,
    pub result_key: &'a DiagnosticSha256,
    pub original_request_bytes: &'a [u8],
    pub e0_installation_epoch_sha256: &'a DiagnosticSha256,
    pub e0_h1_receipt_sha256: &'a DiagnosticSha256,
    pub e1_installation_epoch_sha256: &'a DiagnosticSha256,
    pub e1_h1_receipt_sha256: &'a DiagnosticSha256,
}

/// Pure join of the protected replay record and exact rejection payload. A
/// separate live BPF interval must prove that this rejection allocated none.
pub fn validate_historical_public_epoch_replay_v1(
    record_bytes: &[u8],
    rejection_bytes: &[u8],
    expected: &ExpectedHistoricalPublicEpochReplayV1<'_>,
) -> crate::Result<()> {
    if record_bytes.is_empty() || record_bytes.len() > 16 * 1024 {
        return Err(crate::CiError::Message(
            "historical replay record byte bound differs".into(),
        ));
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(record_bytes)
        .map_err(crate::CiError::Message)?;
    let replay: HistoricalPublicEpochReplayV1 = serde_json::from_slice(record_bytes)?;
    let rejection =
        memcordon_core::provider_rejection_wire::RejectionWireV1::parse(rejection_bytes)
            .map_err(crate::CiError::Message)?;
    if replay.schema_version != 1
        || replay.selector != expected.selector
        || replay.result_key != *expected.result_key
        || replay.original_request_sha256 != hash_bytes(expected.original_request_bytes)
        || replay.e0_installation_epoch_sha256 != *expected.e0_installation_epoch_sha256
        || replay.e0_h1_receipt_sha256 != *expected.e0_h1_receipt_sha256
        || replay.e1_installation_epoch_sha256 != *expected.e1_installation_epoch_sha256
        || replay.e1_h1_receipt_sha256 != *expected.e1_h1_receipt_sha256
        || replay.e0_installation_epoch_sha256 == replay.e1_installation_epoch_sha256
        || replay.e0_h1_receipt_sha256 == replay.e1_h1_receipt_sha256
        || replay.rejection_sha256 != hash_bytes(rejection_bytes)
        || replay.rejection_code != "MCSEALED-PRIVATE-EXPECTED-PLAN"
        || rejection.code != replay.rejection_code
        || rejection.target_created
        || rejection.target_released
        || !replay.durable_attempt_record_absent
    {
        return Err(crate::CiError::Message(
            "historical E1 protected replay facts differ".into(),
        ));
    }
    Ok(())
}

pub fn validate_public_dispatch_intent_bytes(bytes: &[u8], target: &str) -> crate::Result<()> {
    parse_public_dispatch_intent(bytes, target).map(|_| ())
}

fn parse_public_dispatch_intent(
    bytes: &[u8],
    target: &str,
) -> crate::Result<ProtectedPublicDispatchIntentV1> {
    use memcordon_core::private_release_case_v1::REQUIRED_PRIVATE_RELEASE_SELECTORS_V1;
    if bytes.is_empty() || bytes.len() > 128 * 1024 {
        return Err(crate::CiError::Message(
            "public dispatch intent byte bound differs".into(),
        ));
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)
        .map_err(crate::CiError::Message)?;
    let intent: ProtectedPublicDispatchIntentV1 = serde_json::from_slice(bytes)?;
    if intent.schema_version != 1
        || intent.target != target
        || intent.public_uid == 0
        || intent.public_gid == 0
        || intent.cases.len() != REQUIRED_PRIVATE_RELEASE_SELECTORS_V1.len()
        || intent
            .cases
            .iter()
            .zip(REQUIRED_PRIVATE_RELEASE_SELECTORS_V1)
            .any(|(case, selector)| case.selector != selector)
        || intent.source_commit.len() != 40
        || !intent
            .source_commit
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || intent.archive_sha256 == DiagnosticSha256::from_bytes([0; 32])
        || intent.manifest_sha256 == DiagnosticSha256::from_bytes([0; 32])
        || intent.qualification_sha256 == DiagnosticSha256::from_bytes([0; 32])
        || intent.public_cli_sha256 == DiagnosticSha256::from_bytes([0; 32])
        || intent.build_context_sha256 == DiagnosticSha256::from_bytes([0; 32])
        || intent.release_catalogue_sha256 == DiagnosticSha256::from_bytes([0; 32])
        || intent.observer.boot_id.is_empty()
        || intent.observer.boot_id.len() > 128
        || intent.observer.kernel_release.is_empty()
        || intent.observer.kernel_release.len() > 128
        || intent.observer.btf_sha256 == DiagnosticSha256::from_bytes([0; 32])
        || intent.observer.probe_map_sha256 == DiagnosticSha256::from_bytes([0; 32])
        || intent.observer.control_result_key == DiagnosticSha256::from_bytes([0; 32])
        || intent.historical_e0.selector != "private_tcp::caller_identity_and_epoch_bound"
        || intent.historical_e0.challenge.len() != 64
        || !intent
            .historical_e0
            .challenge
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || intent
            .historical_e0
            .challenge
            .bytes()
            .all(|byte| byte == b'0')
        || intent.historical_e0.challenge == intent.cases[4].challenge
        || intent.historical_spoof.selector != "private_tcp::caller_identity_and_epoch_bound"
        || intent.historical_spoof.challenge.len() != 64
        || !intent
            .historical_spoof
            .challenge
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || intent
            .historical_spoof
            .challenge
            .bytes()
            .all(|byte| byte == b'0')
        || intent.historical_spoof.challenge == intent.historical_e0.challenge
        || intent.historical_spoof.challenge == intent.cases[4].challenge
        || intent.historical_spoof.unauthorized_uid == 0
        || intent.historical_spoof.unauthorized_gid == 0
        || intent.historical_spoof.unauthorized_uid == intent.public_uid
        || intent.historical_spoof.outcome != "preallocation-rejected"
        || intent.historical_spoof.contract_sha256 == DiagnosticSha256::from_bytes([0; 32])
        || intent.historical_spoof.fixture_sha256 == DiagnosticSha256::from_bytes([0; 32])
        || [
            &intent.historical_spoof.contract_path,
            &intent.historical_spoof.fixture_path,
            &intent.historical_spoof.report_path,
        ]
        .iter()
        .any(|path| {
            !path.starts_with("/run/memcordon-final-public/historical-spoof/")
                || path.components().any(|part| {
                    matches!(
                        part,
                        std::path::Component::CurDir | std::path::Component::ParentDir
                    )
                })
        })
        || intent.historical_e0.outcome != "exit-zero"
        || intent.historical_e0.e0_installation_epoch_sha256
            == DiagnosticSha256::from_bytes([0; 32])
        || intent.historical_e0.e0_h1_receipt_sha256 == DiagnosticSha256::from_bytes([0; 32])
        || !intent
            .historical_e0
            .upgrade_archive_path
            .starts_with("/run/memcordon-final-public/historical-e0/")
        || intent
            .historical_e0
            .upgrade_archive_path
            .components()
            .any(|part| {
                matches!(
                    part,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            })
        || [
            intent.historical_e0.contract_sha256.clone(),
            intent.historical_e0.fixture_sha256.clone(),
            intent.historical_e0.expected_plan_sha256.clone(),
        ]
        .iter()
        .any(|digest| *digest == DiagnosticSha256::from_bytes([0; 32]))
        || [
            &intent.historical_e0.contract_path,
            &intent.historical_e0.fixture_path,
            &intent.historical_e0.expected_plan_path,
            &intent.historical_e0.report_path,
            &intent.historical_e0.upgrade_archive_path,
        ]
        .iter()
        .any(|path| {
            !path.starts_with("/run/memcordon-final-public/historical-e0/")
                || path.components().any(|part| {
                    matches!(
                        part,
                        std::path::Component::CurDir | std::path::Component::ParentDir
                    )
                })
        })
        || intent.cases.iter().any(|case| {
            case.challenge.len() != [0_u8; 32].len() * 2
                || !case
                    .challenge
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                || case.challenge.bytes().all(|byte| byte == b'0')
                || !matches!(
                    case.outcome.as_str(),
                    "exit-zero"
                        | "preallocation-rejected"
                        | "native-failure"
                        | "interrupted"
                        | "allocated-unverified"
                        | "indeterminate"
                        | "before-submission-failure"
                        | "transport-unverified"
                        | "frontend-lost"
                )
                || case.expected_plan_path.is_none()
                || case.expected_plan_sha256.is_none()
                || case.contract_sha256 == DiagnosticSha256::from_bytes([0; 32])
                || case.fixture_sha256 == DiagnosticSha256::from_bytes([0; 32])
                || case.expected_plan_sha256 == Some(DiagnosticSha256::from_bytes([0; 32]))
                || !case
                    .contract_path
                    .starts_with("/run/memcordon-final-public/")
                || !case
                    .fixture_path
                    .starts_with("/run/memcordon-final-public/")
                || !case.report_path.starts_with("/run/memcordon-final-public/")
                || case
                    .expected_plan_path
                    .as_ref()
                    .is_some_and(|path| !path.starts_with("/run/memcordon-final-public/"))
                || case.expected_plan_path.is_some() != case.expected_plan_sha256.is_some()
                || case.contract_path == case.fixture_path
                || case.contract_path == case.report_path
                || case.fixture_path == case.report_path
        })
    {
        return Err(crate::CiError::Message(
            "public dispatch intent identity differs".into(),
        ));
    }
    let mut paths = std::collections::BTreeSet::new();
    for case in &intent.cases {
        for path in [&case.contract_path, &case.fixture_path, &case.report_path]
            .into_iter()
            .chain(case.expected_plan_path.iter())
        {
            if path.components().any(|part| {
                matches!(
                    part,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            }) || !paths.insert(path)
            {
                return Err(crate::CiError::Message(
                    "public dispatch path alias or traversal".into(),
                ));
            }
        }
    }
    for path in [
        &intent.historical_e0.contract_path,
        &intent.historical_e0.fixture_path,
        &intent.historical_e0.expected_plan_path,
        &intent.historical_e0.report_path,
        &intent.historical_e0.upgrade_archive_path,
    ] {
        if !paths.insert(path) {
            return Err(crate::CiError::Message(
                "historical E0 public path aliases final case".into(),
            ));
        }
    }
    for path in [
        &intent.historical_spoof.contract_path,
        &intent.historical_spoof.fixture_path,
        &intent.historical_spoof.report_path,
    ] {
        if !paths.insert(path) {
            return Err(crate::CiError::Message(
                "historical spoof path aliases another public case".into(),
            ));
        }
    }
    let policy = intent
        .policy
        .as_ref()
        .ok_or_else(|| crate::CiError::Message("public five-branch policy intent absent".into()))?;
    let base = &intent
        .cases
        .iter()
        .find(|case| case.selector == "private_tcp::wrong_grant_profile_and_port_rejected")
        .ok_or_else(|| crate::CiError::Message("public base policy case absent".into()))?;
    let base_bytes: [u8; 32] = hex::decode(&policy.base_challenge)
        .map_err(|_| crate::CiError::Message("public policy base challenge differs".into()))?
        .try_into()
        .map_err(|_| {
            crate::CiError::Message("public policy base challenge length differs".into())
        })?;
    if base_bytes == [0; 32]
        || base.challenge != policy.base_challenge
        || base.policy_branch.is_some()
        || base.tampered_contract_path.is_some()
        || base.tampered_contract_sha256.is_some()
        || policy.branches.len() != 5
    {
        return Err(crate::CiError::Message(
            "public policy composite base differs".into(),
        ));
    }
    let mut policy_keys = std::collections::BTreeSet::new();
    for (branch, case) in memcordon_core::private_release_branch_v1::PolicyOperationBranchV1::ALL
        .into_iter()
        .zip(&policy.branches)
    {
        let derived = memcordon_core::private_release_branch_v1::policy_branch_challenge_v1(
            &base_bytes,
            branch,
        )
        .map_err(|error| crate::CiError::Message(error.into()))?;
        let key = memcordon_core::private_release_case_v1::private_release_case_key_v1(
            memcordon_core::private_release_case_v1::PrivateReleaseStageV1::FinalPublic,
            &case.selector,
            &derived,
        )
        .map_err(crate::CiError::Message)?;
        let needs_plan = matches!(branch,
            memcordon_core::private_release_branch_v1::PolicyOperationBranchV1::AcceptedControl
            | memcordon_core::private_release_branch_v1::PolicyOperationBranchV1::CommittedPortTamper);
        let tampered = branch == memcordon_core::private_release_branch_v1::PolicyOperationBranchV1::CommittedPortTamper;
        if case.selector != base.selector
            || case.policy_branch != Some(branch)
            || case.challenge != hex::encode(derived)
            || !policy_keys.insert(String::from(key))
            || case.contract_sha256 == DiagnosticSha256::from_bytes([0; 32])
            || case.fixture_sha256 == DiagnosticSha256::from_bytes([0; 32])
            || case.expected_plan_path.is_some() != needs_plan
            || case.expected_plan_sha256.is_some() != needs_plan
            || case.tampered_contract_path.is_some() != tampered
            || case.tampered_contract_sha256.is_some() != tampered
            || case.tampered_contract_sha256 == Some(DiagnosticSha256::from_bytes([0; 32]))
            || case.outcome != if branch == memcordon_core::private_release_branch_v1::PolicyOperationBranchV1::AcceptedControl {
                "exit-zero"
            } else { "preallocation-rejected" }
            || !case.contract_path.starts_with("/run/memcordon-final-public/")
            || !case.fixture_path.starts_with("/run/memcordon-final-public/")
            || !case.report_path.starts_with("/run/memcordon-final-public/")
            || case.expected_plan_path.as_ref().is_some_and(|path| !path.starts_with("/run/memcordon-final-public/"))
            || case.tampered_contract_path.as_ref().is_some_and(|path| !path.starts_with("/run/memcordon-final-public/"))
        {
            return Err(crate::CiError::Message("public policy derived branch differs".into()));
        }
        for path in [&case.contract_path, &case.fixture_path, &case.report_path]
            .into_iter()
            .chain(case.expected_plan_path.iter())
            .chain(case.tampered_contract_path.iter())
        {
            if path.components().any(|part| {
                matches!(
                    part,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            }) || !paths.insert(path)
            {
                return Err(crate::CiError::Message(
                    "public policy branch path aliases another fixture".into(),
                ));
            }
        }
    }
    if policy.branches[0].contract_sha256 != base.contract_sha256
        || policy.branches[4].contract_sha256 != base.contract_sha256
    {
        return Err(crate::CiError::Message(
            "public policy base/accepted contract differs".into(),
        ));
    }
    Ok(intent)
}

#[cfg(target_os = "linux")]
fn read_public_fixture(path: &Path, expected: &DiagnosticSha256) -> Result<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    if !path.starts_with("/run/memcordon-final-public/") {
        return Err(CiError::Message("public fixture path differs".into()));
    }
    let mut ancestor = std::path::PathBuf::from("/run/memcordon-final-public");
    let root_metadata = std::fs::symlink_metadata(&ancestor)?;
    if !root_metadata.is_dir() || root_metadata.uid() != 0 || root_metadata.mode() & 0o022 != 0 {
        return Err(CiError::Message("public fixture root is mutable".into()));
    }
    let relative = path
        .strip_prefix(&ancestor)
        .map_err(|_| CiError::Message("public fixture root differs".into()))?;
    for part in relative.parent().into_iter().flat_map(Path::components) {
        if let std::path::Component::Normal(name) = part {
            ancestor.push(name);
            let metadata = std::fs::symlink_metadata(&ancestor)?;
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(CiError::Message(
                    "public fixture ancestor is mutable".into(),
                ));
            }
        } else {
            return Err(CiError::Message(
                "public fixture ancestor path differs".into(),
            ));
        }
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || before.mode() & 0o022 != 0
        || before.len() == 0
        || before.len() > 1024 * 1024
    {
        return Err(CiError::Message("public fixture protection differs".into()));
    }
    let mut bytes = Vec::new();
    (&mut file).take(before.len() + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 != before.len()
        || hash_bytes(&bytes) != *expected
        || (before.dev(), before.ino(), before.len()) != (after.dev(), after.ino(), after.len())
    {
        return Err(CiError::Message("public fixture bytes changed".into()));
    }
    Ok(bytes)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderFrameRecordV2 {
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
    manifest_sha256: DiagnosticSha256,
    qualification_sha256: DiagnosticSha256,
    active_h1_receipt_sha256: DiagnosticSha256,
    policy_branch: Option<memcordon_core::private_release_branch_v1::PolicyOperationBranchV1>,
    policy_base_challenge_sha256: Option<DiagnosticSha256>,
    tampered_contract_digest: Option<DiagnosticSha256>,
    plan_request_sha256: Option<DiagnosticSha256>,
    plan_response_sha256: Option<DiagnosticSha256>,
    grant_decision_sha256: Option<DiagnosticSha256>,
    plan_response_kind: Option<u16>,
    expected_launch_exchanges: u8,
    attempts: Vec<ProviderAttemptRecordV2>,
    inflight: Option<serde_json::Value>,
    terminal_sha256: Option<DiagnosticSha256>,
    phase: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderAttemptRecordV2 {
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

#[derive(serde::Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum ProviderGrantOutcomeV1 {
    Granted {
        grant: memcordon_core::workload_registry_v2::PolicyGrantV2,
    },
    Rejected {
        rejection: memcordon_core::workload_registry_v2::AdmissionRejectionV2,
    },
}

#[derive(serde::Deserialize)]
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

#[derive(Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderProcessIdentityV1 {
    pub(crate) pid: u32,
    pub(crate) start_time: u64,
}

#[derive(Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderTargetIdentityV1 {
    schema_version: u8,
    evidence_scope: String,
    attempt_id: String,
    request_sha256: DiagnosticSha256,
    durable_attempt_record_sha256: DiagnosticSha256,
    pub(crate) target: ProviderProcessIdentityV1,
    namespace_init: ProviderProcessIdentityV1,
    network_namespace_inode: u64,
    entrypoint_sha256: DiagnosticSha256,
    entrypoint_device: u64,
    entrypoint_inode: u64,
    entrypoint_path: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderCleanupReadbackV1 {
    schema_version: u8,
    evidence_scope: String,
    attempt_id: String,
    terminal_sha256: DiagnosticSha256,
    provider_response_kind: u16,
    durable_attempt_record_absent: bool,
    boot_id: String,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderRecoveredCleanupReadbackV1 {
    schema_version: u8,
    result_key: DiagnosticSha256,
    first_attempt_id: String,
    namespace_inode: u64,
    holder_closed_boot_nanos: u64,
    recovery_boot_nanos: u64,
    durable_attempt_record_absent: bool,
}

#[cfg(target_os = "linux")]
pub(crate) struct StructuralProviderFrameReadbackV2 {
    pub(crate) result_key: DiagnosticSha256,
    pub(crate) record_bytes: Vec<u8>,
    pub(crate) policy_branch:
        Option<memcordon_core::private_release_branch_v1::PolicyOperationBranchV1>,
    pub(crate) phase: String,
    pub(crate) request_bytes: Vec<u8>,
    pub(crate) plan_response_bytes: Vec<u8>,
    pub(crate) grant_decision_bytes: Vec<u8>,
    pub(crate) registry_digest: Option<DiagnosticSha256>,
    pub(crate) registry_bytes: Option<Vec<u8>>,
    pub(crate) terminal_bytes: Option<Vec<u8>>,
    pub(crate) attempts: Vec<StructuralProviderAttemptV2>,
}

#[cfg(target_os = "linux")]
pub(crate) struct StructuralProviderAttemptV2 {
    pub(crate) attempt_id: String,
    pub(crate) request_bytes: Vec<u8>,
    pub(crate) response_bytes: Vec<u8>,
    pub(crate) terminal_bytes: Option<Vec<u8>>,
    pub(crate) cleanup_bytes: Option<Vec<u8>>,
    pub(crate) target_identity_bytes: Option<Vec<u8>>,
    pub(crate) target_identity: Option<ProviderTargetIdentityV1>,
}

#[cfg(target_os = "linux")]
pub(crate) struct OwnedPublicRawAttachmentV2 {
    pub(crate) role: memcordon_core::private_release_case_v1::PrivateReleaseAttachmentRoleV1,
    pub(crate) bytes: Vec<u8>,
}

#[cfg(target_os = "linux")]
fn collect_public_raw_attachments(
    selector: &str,
    observed: &ObservedInstalledPublicCaseV3,
    provider: &StructuralProviderFrameReadbackV2,
    interval: &crate::private_kernel_observer::VerifiedKernelIntervalV1,
) -> Result<Vec<OwnedPublicRawAttachmentV2>> {
    use crate::private_kernel_observer::{AllocationBoundaryKindV1, KernelEventV1};
    use memcordon_core::private_release_case_v1::PrivateReleaseAttachmentRoleV1 as Role;

    if interval.result_key() != &provider.result_key || interval.capture_bytes()?.is_empty() {
        return Err(CiError::Message(
            "public raw observer case key/capture differs".into(),
        ));
    }
    let allocated = interval.events().iter().any(|event| matches!(event,
        KernelEventV1::AllocationBoundary { request_key, kind: AllocationBoundaryKindV1::Allocate, .. }
            if *request_key == provider.result_key));
    let frozen_rejection = provider.policy_branch
        == Some(
            memcordon_core::private_release_branch_v1::PolicyOperationBranchV1::CommittedPortTamper,
        );
    if !interval.has_allocation_boundary()
        || provider.phase == "plan-rejected" && (!interval.no_allocation() || allocated)
        || frozen_rejection && (!interval.no_allocation() || allocated)
        || provider.phase != "plan-rejected" && !frozen_rejection && !allocated
    {
        return Err(CiError::Message(
            "public raw allocation interval differs".into(),
        ));
    }
    if provider.phase == "plan-rejected" {
        if selector != "private_tcp::wrong_grant_profile_and_port_rejected"
            || provider.terminal_bytes.is_none()
            || !provider.attempts.is_empty()
        {
            return Err(CiError::Message(
                "public raw preallocation branch differs".into(),
            ));
        }
    } else if provider.attempts.is_empty() || provider.terminal_bytes.is_some() {
        return Err(CiError::Message("public raw launch branch differs".into()));
    }
    let cleanup = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "evidence_scope": "provider-plus-observer-raw-only",
        "result_key": provider.result_key,
        "probe_capture_sha256": interval.trace_sha256(),
        "plan_response_sha256": hash_bytes(&provider.plan_response_bytes),
        "grant_decision_sha256": hash_bytes(&provider.grant_decision_bytes),
        "grant_decision_bytes": provider.grant_decision_bytes,
        "registry_digest": provider.registry_digest,
        "registry_snapshot_bytes": provider.registry_bytes,
        "plan_rejected_terminal_bytes": provider.terminal_bytes,
        "attempts": provider.attempts.iter().map(|attempt| serde_json::json!({
            "attempt_id": attempt.attempt_id,
            "request_bytes": attempt.request_bytes,
            "response_bytes": attempt.response_bytes,
            "terminal_bytes": attempt.terminal_bytes,
            "provider_cleanup_bytes": attempt.cleanup_bytes,
            "target_identity_bytes": attempt.target_identity_bytes,
        })).collect::<Vec<_>>(),
    }))?;
    let mut attachments = Vec::with_capacity(5);
    attachments.push(OwnedPublicRawAttachmentV2 {
        role: Role::Request,
        bytes: provider.request_bytes.clone(),
    });
    if let Some(report) = &observed.report_bytes {
        attachments.push(OwnedPublicRawAttachmentV2 {
            role: Role::Report,
            bytes: report.clone(),
        });
    }
    attachments.push(OwnedPublicRawAttachmentV2 {
        role: Role::Stdio,
        bytes: observed.stdio_bytes.clone(),
    });
    attachments.push(OwnedPublicRawAttachmentV2 {
        role: Role::Observer,
        bytes: interval.capture_bytes()?.to_vec(),
    });
    attachments.push(OwnedPublicRawAttachmentV2 {
        role: Role::Cleanup,
        bytes: cleanup,
    });
    if attachments.iter().any(|item| {
        item.bytes.is_empty()
            || item.bytes.len() as u64
                > memcordon_core::private_release_case_v1::MAX_PRIVATE_RELEASE_ATTACHMENT_BYTES_V1
    }) {
        return Err(CiError::Message(
            "public raw attachment byte bound differs".into(),
        ));
    }
    Ok(attachments)
}

/// Pure parser for provider-origin frames. This proves only the protected
/// provider transcript's structural joins, never CLI stdio, allocation,
/// terminal state or P authority.
pub fn validate_provider_frame_record_v2(
    record_bytes: &[u8],
    leaves: &[(&str, &[u8])],
    expected_selector: &str,
    expected_challenge: &str,
    expected_key: &DiagnosticSha256,
    expected_contract_digest: &DiagnosticSha256,
    expected_peer: (u32, u64, u32, u32),
    expected_release: (
        &DiagnosticSha256,
        &DiagnosticSha256,
        &DiagnosticSha256,
        &DiagnosticSha256,
    ),
) -> crate::Result<()> {
    use memcordon_core::workload_codec::hash_bytes;
    use memcordon_core::workload_contract::reject_duplicate_json_keys;

    if record_bytes.is_empty() || record_bytes.len() > 128 * 1024 {
        return Err(crate::CiError::Message(
            "provider frame record byte bound differs".into(),
        ));
    }
    reject_duplicate_json_keys(record_bytes).map_err(crate::CiError::Message)?;
    let record: ProviderFrameRecordV2 = serde_json::from_slice(record_bytes)?;
    let zero = DiagnosticSha256::from_bytes([0; 32]);
    if record.schema_version != 2
        || record.evidence_scope != "provider-frames-only"
        || record.selector != expected_selector
        || record.challenge != expected_challenge
        || &record.result_key != expected_key
        || &record.contract_digest != expected_contract_digest
        || (
            record.peer_pid,
            record.peer_start_time_ticks,
            record.peer_uid,
            record.peer_gid,
        ) != expected_peer
        || (
            &record.installation_epoch,
            &record.manifest_sha256,
            &record.qualification_sha256,
            &record.active_h1_receipt_sha256,
        ) != expected_release
        || record.result_key == zero
        || record.contract_digest == zero
        || record.peer_pid == 0
        || record.peer_start_time_ticks == 0
        || record.peer_uid == 0
        || record.peer_gid == 0
        || record.inflight.is_some()
        || !matches!(
            record.phase.as_str(),
            "plan-rejected" | "launch-exchanges-complete"
        )
    {
        return Err(crate::CiError::Message(
            "provider frame identity differs".into(),
        ));
    }
    use memcordon_core::private_release_branch_v1::PolicyOperationBranchV1 as PolicyBranch;
    let cap = match record.policy_branch {
        Some(PolicyBranch::AcceptedControl | PolicyBranch::CommittedPortTamper) => 1,
        Some(
            PolicyBranch::WrongGrant
            | PolicyBranch::WrongProfile
            | PolicyBranch::UnapprovedChangedPortPlan,
        ) => 0,
        None => match expected_selector {
            "private_tcp::wrong_grant_profile_and_port_rejected" => 0,
            "private_tcp::dual_attempt_namespace_isolation"
            | "private_tcp::retirement_failure_blocks_reuse" => 2,
            _ => 1,
        },
    };
    if record.policy_branch.is_some() != record.policy_base_challenge_sha256.is_some()
        || record.tampered_contract_digest.is_some()
            != (record.policy_branch == Some(PolicyBranch::CommittedPortTamper))
        || record.policy_base_challenge_sha256 == Some(zero.clone())
        || record.tampered_contract_digest == Some(zero.clone())
        || record.policy_branch.is_some()
            && expected_selector != "private_tcp::wrong_grant_profile_and_port_rejected"
    {
        return Err(crate::CiError::Message(
            "provider policy branch identity differs".into(),
        ));
    }
    let rejected = cap == 0;
    let reuse = expected_selector == "private_tcp::retirement_failure_blocks_reuse";
    if record.expected_launch_exchanges != cap
        || record.plan_response_kind != Some(if rejected { 106 } else { 111 })
        || record.plan_request_sha256.is_none()
        || record.plan_response_sha256.is_none()
        || record.grant_decision_sha256.is_none()
        || record.phase
            != if rejected {
                "plan-rejected"
            } else {
                "launch-exchanges-complete"
            }
        || record.terminal_sha256.is_some() != rejected
        || record.attempts.len() != usize::from(cap)
    {
        return Err(crate::CiError::Message(
            "provider frame phase differs".into(),
        ));
    }
    let mut expected = vec![
        (
            "plan-request.bin".to_owned(),
            record.plan_request_sha256.as_ref(),
        ),
        (
            "request.bin".to_owned(),
            record.plan_request_sha256.as_ref(),
        ),
        (
            "plan-response.bin".to_owned(),
            record.plan_response_sha256.as_ref(),
        ),
        (
            "grant-decision.json".to_owned(),
            record.grant_decision_sha256.as_ref(),
        ),
    ];
    if rejected {
        expected.push(("terminal.bin".to_owned(), record.terminal_sha256.as_ref()));
    }
    let mut seen = std::collections::BTreeSet::new();
    for (ordinal, attempt) in record.attempts.iter().enumerate() {
        if usize::from(attempt.ordinal) != ordinal
            || attempt.attempt_id.len() != 32
            || attempt.attempt_id.bytes().all(|byte| byte == b'0')
            || !attempt
                .attempt_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !seen.insert(&attempt.attempt_id)
            || !matches!(attempt.launch_response_kind, 105 | 106 | 110)
            || if reuse {
                match ordinal {
                    0 => {
                        attempt.phase != "recovered-after-incomplete"
                            || attempt.launch_response_kind != 106
                            || attempt.terminal_sha256.is_some()
                            || attempt.cleanup_sha256.is_none()
                            || attempt.target_identity_sha256.is_none()
                    }
                    1 => {
                        attempt.phase != "reuse-blocked-observed"
                            || attempt.launch_response_kind != 106
                            || attempt.terminal_sha256.is_some()
                            || attempt.cleanup_sha256.is_some()
                            || attempt.target_identity_sha256.is_some()
                    }
                    _ => true,
                }
            } else {
                attempt.phase
                    != if attempt.launch_response_kind == 105 {
                        "terminal-observed"
                    } else {
                        "nonterminal-observed"
                    }
                    || attempt.terminal_sha256.is_some() != (attempt.launch_response_kind == 105)
                    || attempt.cleanup_sha256.is_some() != (attempt.launch_response_kind == 105)
                    || attempt.launch_response_kind == 105
                        && attempt.target_identity_sha256.is_none()
                    || attempt.launch_response_kind == 106
                        && attempt.target_identity_sha256.is_some()
            }
        {
            return Err(crate::CiError::Message(
                "provider attempt identity differs".into(),
            ));
        }
        let prefix = format!("{}-{}/", attempt.ordinal, attempt.attempt_id);
        expected.push((
            format!("{prefix}request.bin"),
            Some(&attempt.launch_request_sha256),
        ));
        expected.push((
            format!("{prefix}response.bin"),
            Some(&attempt.launch_response_sha256),
        ));
        if attempt.launch_response_kind == 105 {
            expected.push((
                format!("{prefix}terminal.bin"),
                attempt.terminal_sha256.as_ref(),
            ));
            expected.push((
                format!("{prefix}cleanup.bin"),
                attempt.cleanup_sha256.as_ref(),
            ));
        }
        if reuse && ordinal == 0 {
            expected.push((
                format!("{prefix}cleanup.bin"),
                attempt.cleanup_sha256.as_ref(),
            ));
        }
        if attempt.target_identity_sha256.is_some() {
            expected.push((
                format!("{prefix}target-identity.json"),
                attempt.target_identity_sha256.as_ref(),
            ));
        }
    }
    if leaves.len() != expected.len() {
        return Err(crate::CiError::Message(
            "provider frame leaf inventory differs".into(),
        ));
    }
    for ((name, bytes), (expected_name, digest)) in leaves.iter().zip(expected) {
        if *name != expected_name
            || bytes.is_empty()
            || bytes.len() > 1024 * 1024
            || digest.is_none_or(|digest| *digest == zero || hash_bytes(bytes) != *digest)
        {
            return Err(crate::CiError::Message(
                "provider frame leaf bytes differ".into(),
            ));
        }
    }
    if leaves[0].1 != leaves[1].1 || rejected && leaves[2].1 != leaves[4].1 {
        return Err(crate::CiError::Message(
            "provider duplicate frame custody differs".into(),
        ));
    }
    let decision_bytes = leaves[3].1;
    reject_duplicate_json_keys(decision_bytes).map_err(crate::CiError::Message)?;
    let decision: ProviderGrantDecisionV1 = serde_json::from_slice(decision_bytes)?;
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
        || decision.registry_digest == zero
        || decision.plan_request_sha256 != record.plan_request_sha256.clone().expect("plan present")
        || decision.plan_response_sha256
            != record
                .plan_response_sha256
                .clone()
                .expect("response present")
        || decision.plan_response_kind != record.plan_response_kind.expect("kind present")
        || rejected != matches!(decision.outcome, ProviderGrantOutcomeV1::Rejected { .. })
    {
        return Err(crate::CiError::Message(
            "provider lease-bound grant decision differs".into(),
        ));
    }
    let expected_denial = match record.policy_branch {
        Some(PolicyBranch::WrongGrant) => {
            Some(memcordon_core::workload_registry_v2::AdmissionCodeV2::ProfileNotAuthorized)
        }
        Some(PolicyBranch::WrongProfile) => {
            Some(memcordon_core::workload_registry_v2::AdmissionCodeV2::ProfileDigestMismatch)
        }
        Some(PolicyBranch::UnapprovedChangedPortPlan) => {
            Some(memcordon_core::workload_registry_v2::AdmissionCodeV2::PlanNotApproved)
        }
        _ => None,
    };
    if let Some(expected) = expected_denial {
        if !matches!(&decision.outcome, ProviderGrantOutcomeV1::Rejected { rejection } if rejection.code == expected)
        {
            return Err(crate::CiError::Message(
                "provider policy branch denial code differs".into(),
            ));
        }
    }
    for attempt in &record.attempts {
        if attempt.target_identity_sha256.is_none() {
            continue;
        }
        let name = format!(
            "{}-{}/target-identity.json",
            attempt.ordinal, attempt.attempt_id
        );
        let bytes = leaves
            .iter()
            .find_map(|(leaf, bytes)| (*leaf == name).then_some(*bytes))
            .ok_or_else(|| {
                crate::CiError::Message("provider target identity leaf absent".into())
            })?;
        memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)
            .map_err(crate::CiError::Message)?;
        let identity: ProviderTargetIdentityV1 = serde_json::from_slice(bytes)?;
        if identity.schema_version != 1
            || identity.evidence_scope != "durable-live-target-gated"
            || identity.attempt_id != attempt.attempt_id
            || identity.request_sha256 != attempt.launch_request_sha256
            || identity.durable_attempt_record_sha256 == zero
            || identity.target.pid == 0
            || identity.target.start_time == 0
            || identity.namespace_init.pid == 0
            || identity.namespace_init.start_time == 0
            || identity.target.pid == identity.namespace_init.pid
            || identity.network_namespace_inode == 0
            || identity.entrypoint_sha256 == zero
            || identity.entrypoint_device == 0
            || identity.entrypoint_inode == 0
            || !identity.entrypoint_path.starts_with('/')
            || identity.entrypoint_path.len() > 4096
            || identity
                .entrypoint_path
                .split('/')
                .any(|part| part == "." || part == "..")
        {
            return Err(crate::CiError::Message(
                "provider target identity facts differ".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_structural_provider_case(
    selector: &str,
    challenge_hex: &str,
    intent: &ProtectedPublicDispatchIntentV1,
    host: &crate::private_final_install::FinalHostReadbackV1,
    observed: &ObservedInstalledPublicCaseV3,
) -> Result<StructuralProviderFrameReadbackV2> {
    use memcordon_core::private_release_case_v1::{
        PrivateReleaseStageV1, private_release_case_key_v1,
    };
    use memcordon_core::workload_codec::contract_digest_v2;
    use memcordon_core::workload_contract::ExecutionIdentityRequestV2;
    use memcordon_core::workload_contract::WorkloadContract;
    use memcordon_core::workload_registry_v2::PolicyRegistryV2;

    let challenge: [u8; 32] = hex::decode(challenge_hex)
        .map_err(|_| CiError::Message("public challenge hex differs".into()))?
        .try_into()
        .map_err(|_| CiError::Message("public challenge length differs".into()))?;
    let key = private_release_case_key_v1(PrivateReleaseStageV1::FinalPublic, selector, &challenge)
        .map_err(CiError::Message)?;
    let directory =
        Path::new("/var/lib/memcordon/sealed/private-public-cases").join(String::from(key.clone()));
    let record_bytes = crate::private_protected_readback::read_protected_raw_case_file(
        &directory.join("provider.json"),
    )?;
    let detached = crate::command::CommandSpec::new(
        "/usr/libexec/memcordon-sealed-agent",
        Path::new("/"),
        Duration::from_secs(30),
    )
    .remove_github_token()
    .args([
        "package",
        "verify-public-release-provider",
        "--selector",
        selector,
        "--challenge",
        challenge_hex,
        "--json",
    ])
    .run()?;
    if detached.strip_suffix(b"\n") != Some(record_bytes.as_slice()) {
        return Err(CiError::Message(
            "public provider detached readback differs".into(),
        ));
    }
    let child = observed
        .process
        .linux_child
        .ok_or_else(|| CiError::Message("public supervised child absent".into()))?;
    let (contract_path, contract_sha256) = if let Some(pinned) = intent
        .cases
        .iter()
        .chain(intent.policy.iter().flat_map(|policy| &policy.branches))
        .find(|case| case.selector == selector && case.challenge == challenge_hex)
    {
        (&pinned.contract_path, &pinned.contract_sha256)
    } else if intent.historical_e0.selector == selector
        && intent.historical_e0.challenge == challenge_hex
    {
        (
            &intent.historical_e0.contract_path,
            &intent.historical_e0.contract_sha256,
        )
    } else {
        return Err(CiError::Message(
            "public provider selector intent absent".into(),
        ));
    };
    let contract_bytes = read_public_fixture(contract_path, contract_sha256)?;
    let WorkloadContract::V2(contract) =
        WorkloadContract::parse(&contract_bytes).map_err(CiError::Message)?
    else {
        return Err(CiError::Message(
            "public provider contract is not V2".into(),
        ));
    };
    let contract_digest = contract_digest_v2(&contract).map_err(CiError::Message)?;
    let record: ProviderFrameRecordV2 = serde_json::from_slice(&record_bytes)?;
    let policy_branch = intent.policy.as_ref().and_then(|policy| {
        policy
            .branches
            .iter()
            .find(|case| case.selector == selector && case.challenge == challenge_hex)
            .map(|case| (policy, case))
    });
    if let Some((policy, case)) = policy_branch {
        let base = hex::decode(&policy.base_challenge)
            .map_err(|_| CiError::Message("public policy base challenge differs".into()))?;
        if record.policy_branch != case.policy_branch
            || record.policy_base_challenge_sha256 != Some(hash_bytes(&base))
            || record.plan_request_sha256 != Some(case.contract_sha256.clone())
        {
            return Err(CiError::Message(
                "public provider policy branch differs from protected intent".into(),
            ));
        }
        if let (Some(path), Some(digest)) =
            (&case.tampered_contract_path, &case.tampered_contract_sha256)
        {
            let bytes = read_public_fixture(path, digest)?;
            let WorkloadContract::V2(tampered) =
                WorkloadContract::parse(&bytes).map_err(CiError::Message)?
            else {
                return Err(CiError::Message(
                    "public frozen tamper contract is not V2".into(),
                ));
            };
            if record.tampered_contract_digest
                != Some(contract_digest_v2(&tampered).map_err(CiError::Message)?)
            {
                return Err(CiError::Message(
                    "public frozen tamper contract digest differs".into(),
                ));
            }
        } else if record.tampered_contract_digest.is_some() {
            return Err(CiError::Message(
                "public non-tamper branch carries tamper contract".into(),
            ));
        }
    } else if record.policy_branch.is_some() {
        return Err(CiError::Message(
            "public provider unpinned policy branch differs".into(),
        ));
    }
    let mut names = vec![
        "plan-request.bin".to_owned(),
        "request.bin".to_owned(),
        "plan-response.bin".to_owned(),
        "grant-decision.json".to_owned(),
    ];
    if record.phase == "plan-rejected" {
        names.push("terminal.bin".into());
    }
    for attempt in &record.attempts {
        let prefix = format!("{}-{}/", attempt.ordinal, attempt.attempt_id);
        names.push(format!("{prefix}request.bin"));
        names.push(format!("{prefix}response.bin"));
        if attempt.phase == "terminal-observed" {
            names.push(format!("{prefix}terminal.bin"));
            names.push(format!("{prefix}cleanup.bin"));
        } else if attempt.phase == "recovered-after-incomplete" {
            names.push(format!("{prefix}cleanup.bin"));
        }
        if attempt.target_identity_sha256.is_some() {
            names.push(format!("{prefix}target-identity.json"));
        }
    }
    let mut raw = Vec::with_capacity(names.len());
    for name in &names {
        raw.push(
            crate::private_protected_readback::read_protected_raw_case_file(&directory.join(name))?,
        );
    }
    let leaves: Vec<(&str, &[u8])> = names
        .iter()
        .zip(&raw)
        .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
        .collect();
    validate_provider_frame_record_v2(
        &record_bytes,
        &leaves,
        selector,
        challenge_hex,
        &key,
        &contract_digest,
        (
            child.pid,
            child.start_time_ticks,
            intent.public_uid,
            intent.public_gid,
        ),
        (
            host.installation_epoch(),
            &intent.manifest_sha256,
            &intent.qualification_sha256,
            host.active_h1_receipt_sha256(),
        ),
    )?;
    let decision: ProviderGrantDecisionV1 = serde_json::from_slice(&raw[3])?;
    if decision.policy_epoch != contract.expected_epoch {
        return Err(CiError::Message(
            "public provider grant decision epoch differs".into(),
        ));
    }
    let WorkloadContract::V2(plan_contract) =
        WorkloadContract::parse(&raw[0]).map_err(CiError::Message)?
    else {
        return Err(CiError::Message(
            "public provider plan request is not V2".into(),
        ));
    };
    if contract_digest_v2(&plan_contract).map_err(CiError::Message)? != contract_digest {
        return Err(CiError::Message(
            "public provider plan request contract differs".into(),
        ));
    }
    let registry_digest = if record.phase != "plan-rejected" {
        let receipt = memcordon_core::workload_plan_v2::PrivatePlanReceiptV2::parse_for_contract(
            &raw[2],
            &plan_contract,
        )
        .map_err(CiError::Message)?;
        let expected_abi = match host.target() {
            "x86_64-unknown-linux-gnu" => {
                memcordon_core::workload_evidence_v2::QualifiedNativeAbiV2::X86_64LinuxGnu
            }
            "aarch64-unknown-linux-gnu" => {
                memcordon_core::workload_evidence_v2::QualifiedNativeAbiV2::Aarch64LinuxGnu
            }
            _ => {
                return Err(CiError::Message(
                    "public provider native ABI differs".into(),
                ));
            }
        };
        if receipt.installed_qualification_sha256 != intent.qualification_sha256
            || receipt.runtime_manifest_sha256 != intent.manifest_sha256
            || receipt.generation_digest != *host.installation_epoch()
            || receipt.source_commit != intent.source_commit
            || receipt.native_abi != expected_abi
            || receipt.caller_uid != intent.public_uid
            || receipt.policy_epoch != decision.policy_epoch
        {
            return Err(CiError::Message(
                "public provider plan receipt differs from H1".into(),
            ));
        }
        if receipt.registry_digest != decision.registry_digest {
            return Err(CiError::Message(
                "public provider receipt/grant registry differs".into(),
            ));
        }
        Some(receipt.registry_digest)
    } else {
        let rejection = memcordon_core::provider_rejection_wire::RejectionWireV1::parse(&raw[2])
            .map_err(CiError::Message)?;
        if rejection.code != "MCSEALED-PRIVATE-PUBLIC-GRANT-REJECTED"
            || rejection.target_created
            || rejection.target_released
            || rejection.cleanup.attempted
        {
            return Err(CiError::Message(
                "public wrong-grant provider rejection differs".into(),
            ));
        }
        Some(decision.registry_digest.clone())
    };
    let raw_map: std::collections::BTreeMap<String, Vec<u8>> = names.into_iter().zip(raw).collect();
    let (registry, registry_bytes) = if let Some(digest) = &registry_digest {
        let path = Path::new("/var/lib/memcordon/policy")
            .join(format!("{}.snapshot", String::from(digest.clone())));
        let bytes = crate::private_protected_readback::read_protected_raw_case_file(&path)?;
        let registry = PolicyRegistryV2::parse(&bytes).map_err(CiError::Message)?;
        if registry.canonical_digest().map_err(CiError::Message)? != *digest {
            return Err(CiError::Message(
                "public protected V2 registry digest differs".into(),
            ));
        }
        (Some(registry), Some(bytes))
    } else {
        (None, None)
    };
    let registry_for_decision = registry.as_ref().ok_or_else(|| {
        CiError::Message("public grant decision has no protected registry".into())
    })?;
    let resolved = memcordon_core::workload_registry_v2::resolve_v2(
        registry_for_decision,
        &decision.policy_epoch,
        &plan_contract,
        &memcordon_core::workload_registry::CallerSelector::Linux {
            uid: record.peer_uid,
        },
        memcordon_core::workload_registry_v2::ProfileKindV2::LinuxTcp4PrivateV1,
        &record.qualification_sha256,
    );
    match (&decision.outcome, resolved) {
        (ProviderGrantOutcomeV1::Granted { grant }, Ok(selected)) if grant == selected => {}
        (ProviderGrantOutcomeV1::Rejected { rejection }, Err(denied)) if rejection == &denied => {}
        _ => {
            return Err(CiError::Message(
                "public protected grant decision differs from V2 registry resolution".into(),
            ));
        }
    }
    let mut attempts = Vec::with_capacity(record.attempts.len());
    for attempt in &record.attempts {
        let prefix = format!("{}-{}/", attempt.ordinal, attempt.attempt_id);
        let read = |leaf: &str| -> Result<Vec<u8>> {
            raw_map
                .get(&format!("{prefix}{leaf}"))
                .cloned()
                .ok_or_else(|| CiError::Message("public provider attempt leaf absent".into()))
        };
        let request_bytes = read("request.bin")?;
        let response_bytes = read("response.bin")?;
        if record.policy_branch == Some(memcordon_core::private_release_branch_v1::PolicyOperationBranchV1::CommittedPortTamper) {
            let rejection = memcordon_core::provider_rejection_wire::RejectionWireV1::parse(&response_bytes)
                .map_err(CiError::Message)?;
            if attempt.launch_response_kind != 106
                || rejection.code != "MCSEALED-PRIVATE-EXPECTED-PLAN"
                || rejection.target_created
                || rejection.target_released
                || rejection.cleanup.attempted
                || attempt.target_identity_sha256.is_some()
                || attempt.terminal_sha256.is_some()
                || attempt.cleanup_sha256.is_some()
            {
                return Err(CiError::Message("public frozen-port preallocation rejection differs".into()));
            }
        }
        let (terminal_bytes, cleanup_bytes) = if attempt.phase == "terminal-observed" {
            let terminal = read("terminal.bin")?;
            let cleanup_bytes = read("cleanup.bin")?;
            memcordon_core::workload_contract::reject_duplicate_json_keys(&cleanup_bytes)
                .map_err(CiError::Message)?;
            let cleanup: ProviderCleanupReadbackV1 = serde_json::from_slice(&cleanup_bytes)?;
            if terminal != response_bytes
                || cleanup.schema_version != 1
                || cleanup.evidence_scope != "post-terminal-state-readback"
                || cleanup.attempt_id != attempt.attempt_id
                || cleanup.terminal_sha256 != hash_bytes(&terminal)
                || cleanup.provider_response_kind != 105
                || !cleanup.durable_attempt_record_absent
                || cleanup.boot_id != host.boot_id()
            {
                return Err(CiError::Message(
                    "public provider cleanup facts differ".into(),
                ));
            }
            (Some(terminal), Some(cleanup_bytes))
        } else if attempt.phase == "recovered-after-incomplete" {
            let cleanup_bytes = read("cleanup.bin")?;
            memcordon_core::workload_contract::reject_duplicate_json_keys(&cleanup_bytes)
                .map_err(CiError::Message)?;
            let cleanup: ProviderRecoveredCleanupReadbackV1 =
                serde_json::from_slice(&cleanup_bytes)?;
            if serde_json::to_vec(&cleanup)? != cleanup_bytes
                || cleanup.schema_version != 1
                || cleanup.result_key != key
                || cleanup.first_attempt_id != attempt.attempt_id
                || cleanup.namespace_inode == 0
                || cleanup.holder_closed_boot_nanos == 0
                || cleanup.recovery_boot_nanos < cleanup.holder_closed_boot_nanos
                || !cleanup.durable_attempt_record_absent
            {
                return Err(CiError::Message(
                    "public recovered reuse cleanup differs".into(),
                ));
            }
            (None, Some(cleanup_bytes))
        } else {
            (None, None)
        };
        let (target_identity_bytes, target_identity) = if attempt.target_identity_sha256.is_some() {
            let bytes = read("target-identity.json")?;
            let identity: ProviderTargetIdentityV1 = serde_json::from_slice(&bytes)?;
            let Some(registry) = &registry else {
                return Err(CiError::Message(
                    "public target lacks active registry".into(),
                ));
            };
            let ExecutionIdentityRequestV2::AdministratorProfile { reference } =
                &plan_contract.execution_identity
            else {
                return Err(CiError::Message(
                    "public target lacks granted execution identity".into(),
                ));
            };
            let approved_count = registry
                .execution_identities
                .as_slice()
                .iter()
                .filter(|record| record.enabled && record.reference == *reference)
                .flat_map(|record| record.entrypoints.as_slice())
                .filter(|entrypoint| {
                    entrypoint.absolute_path.as_str() == identity.entrypoint_path
                        && entrypoint.sha256 == identity.entrypoint_sha256
                })
                .take(2)
                .count();
            if approved_count != 1 {
                return Err(CiError::Message(
                    "public target pinned ELF differs from active registry".into(),
                ));
            }
            (Some(bytes), Some(identity))
        } else {
            (None, None)
        };
        attempts.push(StructuralProviderAttemptV2 {
            attempt_id: attempt.attempt_id.clone(),
            request_bytes,
            response_bytes,
            terminal_bytes,
            cleanup_bytes,
            target_identity_bytes,
            target_identity,
        });
    }
    if let Some(report) = &observed.report {
        if report.report_sha256 == DiagnosticSha256::from_bytes([0; 32]) {
            return Err(CiError::Message("public CLI report digest is zero".into()));
        }
    } else if selector != "private_tcp::frontend_loss_retired"
        || !attempts
            .iter()
            .any(|attempt| attempt.terminal_bytes.is_some())
    {
        return Err(CiError::Message(
            "public report absence lacks protected terminal".into(),
        ));
    }
    Ok(StructuralProviderFrameReadbackV2 {
        result_key: key,
        record_bytes,
        policy_branch: record.policy_branch,
        phase: record.phase,
        request_bytes: raw_map
            .get("request.bin")
            .expect("fixed provider request")
            .clone(),
        plan_response_bytes: raw_map
            .get("plan-response.bin")
            .expect("fixed plan response")
            .clone(),
        grant_decision_bytes: raw_map
            .get("grant-decision.json")
            .expect("fixed grant decision")
            .clone(),
        registry_digest,
        registry_bytes,
        terminal_bytes: raw_map.get("terminal.bin").cloned(),
        attempts,
    })
}

#[cfg(target_os = "linux")]
fn join_public_provider_kernel(
    provider: &StructuralProviderFrameReadbackV2,
    interval: &crate::private_kernel_observer::VerifiedKernelIntervalV1,
    clock: &crate::private_process_clock::VerifiedProcClockCalibrationV1,
) -> Result<crate::private_public_kernel_join::VerifiedPublicCaseKernelJoinV1> {
    use crate::private_public_kernel_join::{
        ProtectedPublicTargetExpectationV1, join_public_case_kernel_targets,
    };
    let targets: Vec<_> = provider
        .attempts
        .iter()
        .filter_map(|attempt| {
            attempt
                .target_identity
                .as_ref()
                .map(|identity| ProtectedPublicTargetExpectationV1 {
                    attempt_id: attempt.attempt_id.clone(),
                    pid: identity.target.pid,
                    start_ticks: identity.target.start_time,
                    network_namespace_inode: identity.network_namespace_inode,
                    entrypoint_sha256: identity.entrypoint_sha256.clone(),
                    entrypoint_device: identity.entrypoint_device,
                    entrypoint_inode: identity.entrypoint_inode,
                    entrypoint_path: identity.entrypoint_path.clone(),
                })
        })
        .collect();
    let joined = join_public_case_kernel_targets(interval, clock, &provider.result_key, &targets)?;
    if joined.capture_sha256() != interval.trace_sha256() || joined.target_count() != targets.len()
    {
        return Err(CiError::Message(
            "public protected target inventory differs from kernel".into(),
        ));
    }
    Ok(joined)
}

#[cfg(target_os = "linux")]
fn compose_public_case_observation(
    selector: &str,
    provider: &StructuralProviderFrameReadbackV2,
    observed: &ObservedInstalledPublicCaseV3,
    interval: &crate::private_kernel_observer::VerifiedKernelIntervalV1,
    joined: &crate::private_public_kernel_join::VerifiedPublicCaseKernelJoinV1,
    positive_control_terminal_sha256: Option<&DiagnosticSha256>,
) -> Result<(
    memcordon_core::private_release_case_v1::PrivateReleaseObservationV1,
    memcordon_core::private_public_report_v2::PublicCliReportEvidenceV2,
    Option<DiagnosticSha256>,
)> {
    use memcordon_core::private_public_report_v2::PublicCliReportEvidenceV2;
    use memcordon_core::private_release_case_v1::{
        PrivateReleaseAllocatedOutcomeV1 as Outcome, PrivateReleaseDualRetiredBranchV1,
        PrivateReleaseExecV1 as Exec, PrivateReleaseKnowledgeV1 as Knowledge,
        PrivateReleaseObservationV1 as Observation, PrivateReleaseStageV1,
        validate_release_observation_v1,
    };
    if joined.capture_sha256() != interval.trace_sha256() {
        return Err(CiError::Message(
            "public observation kernel capture differs".into(),
        ));
    }
    let observer_sha256 = interval.trace_sha256().clone();
    let observation = if selector == "private_tcp::wrong_grant_profile_and_port_rejected" {
        let rejection = provider.terminal_bytes.as_ref().ok_or_else(|| {
            CiError::Message("public wrong-grant protected rejection absent".into())
        })?;
        if provider.phase != "plan-rejected"
            || !provider.attempts.is_empty()
            || joined.target_count() != 0
            || !interval.no_allocation()
            || memcordon_core::provider_rejection_wire::RejectionWireV1::parse(rejection)
                .map_err(CiError::Message)?
                .code
                != "MCSEALED-PRIVATE-PUBLIC-GRANT-REJECTED"
            || positive_control_terminal_sha256.is_none()
        {
            return Err(CiError::Message(
                "public wrong-grant branch lacks independent positive control".into(),
            ));
        }
        Observation::PreallocationRejected {
            rejection_code: "MCSEALED-PRIVATE-PUBLIC-GRANT-REJECTED".into(),
            observer_sha256,
        }
    } else {
        if provider.phase != "launch-exchanges-complete"
            || provider.attempts.len() != joined.target_count()
            || provider.attempts.is_empty()
        {
            return Err(CiError::Message(
                "public allocated attempt inventory differs".into(),
            ));
        }
        let parts = provider
            .attempts
            .iter()
            .map(|attempt| {
                let checkpoint = attempt.target_identity_bytes.as_ref().ok_or_else(|| {
                    CiError::Message("public gated target checkpoint absent".into())
                })?;
                let terminal = attempt
                    .terminal_bytes
                    .as_ref()
                    .ok_or_else(|| CiError::Message("public provider terminal absent".into()))?;
                let cleanup = attempt.cleanup_bytes.as_ref().ok_or_else(|| {
                    CiError::Message("public provider cleanup readback absent".into())
                })?;
                Ok((
                    attempt.attempt_id.clone(),
                    hash_bytes(checkpoint),
                    hash_bytes(terminal),
                    hash_bytes(cleanup),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        match selector {
            "private_tcp::abi_alternate_entry_denied" => {
                return Err(CiError::Message(
                    "public alternate-ABI composite lacks branch exec/decision transcript".into(),
                ));
            }
            "private_tcp::retirement_failure_blocks_reuse" => {
                return Err(CiError::Message("public reuse case lacks protected cleanup-failure and blocked-reuse branch join".into()));
            }
            "private_tcp::dual_attempt_namespace_isolation" => {
                if parts.len() != 2
                    || parts[0].1 == parts[1].1
                    || parts[0].2 == parts[1].2
                    || parts[0].3 == parts[1].3
                {
                    return Err(CiError::Message(
                        "public dual-attempt branches alias or are incomplete".into(),
                    ));
                }
                let branch =
                    |(attempt_id, checkpoint_sha256, terminal_sha256, retirement_sha256): &(
                        String,
                        DiagnosticSha256,
                        DiagnosticSha256,
                        DiagnosticSha256,
                    )| {
                        PrivateReleaseDualRetiredBranchV1 {
                            attempt_id: attempt_id.clone(),
                            checkpoint_sha256: checkpoint_sha256.clone(),
                            terminal_sha256: terminal_sha256.clone(),
                            retirement_sha256: retirement_sha256.clone(),
                            release_knowledge: Knowledge::ExecObserved,
                            exec: Exec::Succeeded,
                        }
                    };
                Observation::DualAttemptsRetired {
                    first: branch(&parts[0]),
                    second: branch(&parts[1]),
                    native_observer_sha256: observer_sha256,
                }
            }
            _ => {
                if parts.len() != 1 {
                    return Err(CiError::Message(
                        "public selector has unexpected attempt count".into(),
                    ));
                }
                let outcome = match selector {
                    "private_tcp::authorization_uncertainty_retired" => {
                        Outcome::AuthorizationUncertain
                    }
                    "private_tcp::frontend_loss_retired" => Outcome::FrontendLost,
                    "private_tcp::guardian_loss_retired" => Outcome::GuardianLost,
                    _ => Outcome::TargetCompleted,
                };
                Observation::AllocatedRetired {
                    outcome,
                    attempt_id: parts[0].0.clone(),
                    checkpoint_sha256: parts[0].1.clone(),
                    terminal_sha256: parts[0].2.clone(),
                    retirement_sha256: parts[0].3.clone(),
                    release_knowledge: Knowledge::ExecObserved,
                    exec: Exec::Succeeded,
                    native_observer_sha256: observer_sha256,
                }
            }
        }
    };
    validate_release_observation_v1(selector, PrivateReleaseStageV1::FinalPublic, &observation)
        .map_err(CiError::Message)?;
    let report = if let Some(bytes) = &observed.report_bytes {
        PublicCliReportEvidenceV2::Present {
            size: bytes.len() as u64,
            sha256: hash_bytes(bytes),
        }
    } else if selector == "private_tcp::frontend_loss_retired" {
        let terminal = provider
            .attempts
            .first()
            .and_then(|attempt| attempt.terminal_bytes.as_ref())
            .ok_or_else(|| CiError::Message("frontend loss lacks protected terminal".into()))?;
        PublicCliReportEvidenceV2::AbsentFrontendLoss {
            authenticated_terminal_sha256: hash_bytes(terminal),
            supervised_transport_sha256: hash_bytes(&observed.stdio_bytes),
            independent_recovery_sha256: interval.trace_sha256().clone(),
        }
    } else {
        return Err(CiError::Message(
            "public CLI report absent outside frontend loss".into(),
        ));
    };
    report.validate_structure().map_err(CiError::Message)?;
    Ok((
        observation,
        report,
        (selector == "private_tcp::wrong_grant_profile_and_port_rejected")
            .then(|| positive_control_terminal_sha256.cloned())
            .flatten(),
    ))
}

#[cfg(target_os = "linux")]
fn compose_final_public_case_v2(
    selector: &str,
    challenge: [u8; 32],
    intent: &ProtectedPublicDispatchIntentV1,
    host: &crate::private_final_install::FinalHostReadbackV1,
    observed: &ObservedInstalledPublicCaseV3,
    provider: &StructuralProviderFrameReadbackV2,
    composed: &(
        memcordon_core::private_release_case_v1::PrivateReleaseObservationV1,
        memcordon_core::private_public_report_v2::PublicCliReportEvidenceV2,
        Option<DiagnosticSha256>,
    ),
    attachments: &[OwnedPublicRawAttachmentV2],
) -> Result<memcordon_core::private_public_case_v2::FinalPublicCaseEvidenceV2> {
    use memcordon_core::private_public_case_v2::{
        FinalPublicCaseEvidenceV2, FinalPublicChildIdentityV2, FinalPublicInstalledBindingV2,
    };
    use memcordon_core::private_release_case_v1::PrivateReleaseAttachmentV1;
    let child = observed
        .process
        .linux_child
        .ok_or_else(|| CiError::Message("final public child process identity absent".into()))?;
    if provider.result_key
        != memcordon_core::private_release_case_v1::private_release_case_key_v1(
            memcordon_core::private_release_case_v1::PrivateReleaseStageV1::FinalPublic,
            selector,
            &challenge,
        )
        .map_err(CiError::Message)?
    {
        return Err(CiError::Message("final public case key differs".into()));
    }
    let result = FinalPublicCaseEvidenceV2 {
        schema_version: 2,
        selector: selector.into(),
        challenge,
        source_commit: intent.source_commit.clone(),
        release_version: memcordon_core::BoundedText::<128>::new(host.version())
            .map_err(|error| CiError::Message(error.into()))?,
        target: host.target().into(),
        native_machine: host.native_machine().into(),
        build_context_sha256: intent.build_context_sha256.clone(),
        release_catalogue_sha256: intent.release_catalogue_sha256.clone(),
        installed: FinalPublicInstalledBindingV2 {
            installation_epoch: host.installation_epoch().clone(),
            archive_sha256: intent.archive_sha256.clone(),
            qualified_manifest_sha256: host.manifest_sha256().clone(),
            release_qualification_sha256: host.qualification_sha256().clone(),
            active_host_receipt_sha256: host.active_h1_receipt_sha256().clone(),
            component_sha256: host.component_sha256().clone(),
            unit_sha256: host.unit_sha256().clone(),
            filter_sha256: host.filter_sha256().clone(),
            public_plan_sha256: hash_bytes(&provider.plan_response_bytes),
            public_grant_sha256: hash_bytes(&provider.grant_decision_bytes),
        },
        child: FinalPublicChildIdentityV2 {
            pid: child.pid,
            start_time_ticks: child.start_time_ticks,
            boot_identity: memcordon_core::BoundedText::<128>::new(host.boot_id())
                .map_err(|error| CiError::Message(error.into()))?,
            uid: intent.public_uid,
            gid: intent.public_gid,
            supplementary_groups_empty: true,
            executable_sha256: observed.cli_sha256.clone(),
            argv_sha256: observed.argv_sha256.clone(),
            working_directory_sha256: observed.working_directory_sha256.clone(),
        },
        observation: composed.0.clone(),
        positive_control_terminal_sha256: composed.2.clone(),
        report: composed.1.clone(),
        attachments: attachments
            .iter()
            .map(|raw| PrivateReleaseAttachmentV1 {
                role: raw.role,
                size: raw.bytes.len() as u64,
                sha256: hash_bytes(&raw.bytes),
            })
            .collect(),
    };
    result.validate().map_err(CiError::Message)?;
    Ok(result)
}

/// Executes the exact public selector inventory only after installed H1
/// readback and root-pinned fixture inputs. It deliberately returns failure
/// until the independent provider/terminal/kernel P join is available.
#[cfg(target_os = "linux")]
pub fn run_final_public_suite(root: &Path, target: &str) -> Result<()> {
    use crate::private_kernel_observer::{
        ExpectedKernelAdapterV1, InstalledObserverRoleV1, observe_installed_observer_subject,
        observe_live_kernel_subject, run_probe_case_interval,
    };
    use crate::private_probe_bundle::verify_probe_bundle;
    use crate::private_probe_controls::run_fixed_known_action_controls;
    use memcordon_core::private_release_case_v1::{
        PrivateReleaseStageV1, private_release_case_key_v1,
    };
    use memcordon_core::workload_evidence_v2::QualifiedNativeAbiV2;
    use std::os::unix::fs::MetadataExt;

    const INTENT: &str = "/etc/memcordon/release-trust/final-public-dispatch.v1.json";
    const AGENT: &str = "/usr/libexec/memcordon-sealed-agent";
    const CLI: &str = "/usr/bin/memcordon";
    let bytes = crate::private_protected_readback::read_protected_raw_case_file(Path::new(INTENT))?;
    let intent = parse_public_dispatch_intent(&bytes, target)?;
    let readback = crate::command::CommandSpec::new(AGENT, root, Duration::from_secs(30))
        .remove_github_token()
        .args(["package", "verify-private-host", "--json"])
        .run()?;
    let host = crate::private_final_install::FinalHostReadbackV1::parse_bounded(&readback)?;
    if host.source_commit() != intent.source_commit
        || host.target() != intent.target
        || host.manifest_sha256() != &intent.manifest_sha256
        || host.qualification_sha256() != &intent.qualification_sha256
        || host.public_cli_sha256() != &intent.public_cli_sha256
        || host.active_h1_receipt_sha256() == &DiagnosticSha256::from_bytes([0; 32])
        || host.boot_id() != std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim()
        || host.boot_id() != intent.observer.boot_id
        || intent.observer.kernel_release
            != std::fs::read_to_string("/proc/sys/kernel/osrelease")?.trim()
        || intent.observer.probe_bundle.agent_sha256 != *host.agent_sha256()
    {
        return Err(CiError::Message(
            "public dispatch installed H1 differs".into(),
        ));
    }
    let native_abi = match target {
        "x86_64-unknown-linux-gnu" => QualifiedNativeAbiV2::X86_64LinuxGnu,
        "aarch64-unknown-linux-gnu" => QualifiedNativeAbiV2::Aarch64LinuxGnu,
        _ => {
            return Err(CiError::Message(
                "public dispatch native ABI differs".into(),
            ));
        }
    };
    let probe = verify_probe_bundle(intent.observer.probe_bundle.clone())?;
    let reader = observe_live_kernel_subject(std::process::id())?;
    let service = observe_installed_observer_subject(InstalledObserverRoleV1::SealedService)?;
    let broker =
        crate::private_kernel_observer::activate_installed_network_broker_for_observation()?;
    let e0_clock =
        crate::private_process_clock::VerifiedProcClockCalibrationV1::observe_live_reader(
            reader.pid,
            reader.start_ticks,
        )?;
    let expected_interval = |result_key: DiagnosticSha256| ExpectedKernelAdapterV1 {
        boot_id: intent.observer.boot_id.clone(),
        kernel_release: intent.observer.kernel_release.clone(),
        btf_sha256: intent.observer.btf_sha256.clone(),
        probe_map_sha256: intent.observer.probe_map_sha256.clone(),
        result_key,
        coordinator_pid: service.pid,
        coordinator_start_time: 0,
        coordinator_start_ticks: service.start_ticks,
        cgroup_inode: service.cgroup_inode,
        broker_pid: broker.pid,
        broker_start_ticks: broker.start_ticks,
        broker_cgroup_inode: broker.cgroup_inode,
    };
    let expected_control_interval = |result_key: DiagnosticSha256| ExpectedKernelAdapterV1 {
        boot_id: intent.observer.boot_id.clone(),
        kernel_release: intent.observer.kernel_release.clone(),
        btf_sha256: intent.observer.btf_sha256.clone(),
        probe_map_sha256: intent.observer.probe_map_sha256.clone(),
        result_key,
        coordinator_pid: reader.pid,
        coordinator_start_time: 0,
        coordinator_start_ticks: reader.start_ticks,
        cgroup_inode: reader.cgroup_inode,
        broker_pid: service.pid,
        broker_start_ticks: service.start_ticks,
        broker_cgroup_inode: service.cgroup_inode,
    };
    let e0_controls = run_fixed_known_action_controls(
        &probe,
        expected_control_interval(intent.observer.control_result_key.clone()),
    )?;
    if host.installation_epoch() != &intent.historical_e0.e0_installation_epoch_sha256
        || host.active_h1_receipt_sha256() != &intent.historical_e0.e0_h1_receipt_sha256
    {
        return Err(CiError::Message(
            "historical E0 H1 differs from protected dispatch intent".into(),
        ));
    }
    let e0 = &intent.historical_e0;
    read_public_fixture(&e0.contract_path, &e0.contract_sha256)?;
    read_public_fixture(&e0.fixture_path, &e0.fixture_sha256)?;
    read_public_fixture(&e0.expected_plan_path, &e0.expected_plan_sha256)?;
    let e0_report_parent = e0
        .report_path
        .parent()
        .ok_or_else(|| CiError::Message("historical E0 report parent absent".into()))?;
    let e0_parent = std::fs::symlink_metadata(e0_report_parent)?;
    if !e0_parent.is_dir()
        || e0_parent.uid() != intent.public_uid
        || e0_parent.mode() & 0o7777 != 0o700
        || !matches!(std::fs::symlink_metadata(&e0.report_path), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
    {
        return Err(CiError::Message(
            "historical E0 public report custody differs".into(),
        ));
    }
    let e0_challenge: [u8; 32] = hex::decode(&e0.challenge)
        .map_err(|_| CiError::Message("historical E0 challenge differs".into()))?
        .try_into()
        .map_err(|_| CiError::Message("historical E0 challenge length differs".into()))?;
    let e0_key = private_release_case_key_v1(
        PrivateReleaseStageV1::FinalPublic,
        &e0.selector,
        &e0_challenge,
    )
    .map_err(CiError::Message)?;
    if e0_key == intent.observer.control_result_key {
        return Err(CiError::Message(
            "historical E0 and observer control keys alias".into(),
        ));
    }
    let e0_expected = ExpectedPublicV2Readback {
        source_commit: &intent.source_commit,
        native_abi,
        archive_sha256: &intent.archive_sha256,
        runtime_manifest_sha256: &intent.manifest_sha256,
        qualification_sha256: &intent.qualification_sha256,
        host_receipt_sha256: host.active_h1_receipt_sha256(),
        report_owner_uid: intent.public_uid,
        outcome: crate::private_public_v2::ExpectedPublicV2Outcome::Exited(0),
    };
    let mut e0_observed = None;
    let e0_interval = run_probe_case_interval(
        &probe,
        expected_interval(e0_key.clone()),
        e0_controls.controls(),
        || {
            e0_observed = Some(run_installed_public_case(
                root,
                &e0.selector,
                &e0.challenge,
                Path::new(CLI),
                &intent.public_cli_sha256,
                &e0.contract_path,
                &e0.report_path,
                &e0.fixture_path,
                Some(&e0.expected_plan_path),
                None,
                e0_report_parent,
                intent.public_uid,
                intent.public_gid,
                Duration::from_secs(120),
                &e0_expected,
            )?);
            Ok(())
        },
    )?;
    let e0_observed =
        e0_observed.ok_or_else(|| CiError::Message("historical E0 public child absent".into()))?;
    let e0_provider =
        read_structural_provider_case(&e0.selector, &e0.challenge, &intent, &host, &e0_observed)?;
    let e0_kernel_join = join_public_provider_kernel(&e0_provider, &e0_interval, &e0_clock)?;
    let e0_raw =
        collect_public_raw_attachments(&e0.selector, &e0_observed, &e0_provider, &e0_interval)?;
    if e0_provider.attempts.len() != 1
        || e0_kernel_join.target_count() != 1
        || e0_provider.attempts[0].terminal_bytes.is_none()
        || e0_provider.attempts[0].cleanup_bytes.is_none()
    {
        return Err(CiError::Message(
            "historical E0 positive provider terminal absent".into(),
        ));
    }
    let e0_host = host;
    let host = crate::private_final_install::upgrade_final_same_host(
        root,
        Path::new("/etc/memcordon/release-trust/final-install-intent.v1.json"),
        &e0.upgrade_archive_path,
        e0_host.installation_epoch(),
    )?;
    if host.source_commit() != intent.source_commit
        || host.target() != intent.target
        || host.manifest_sha256() != &intent.manifest_sha256
        || host.qualification_sha256() != &intent.qualification_sha256
        || host.public_cli_sha256() != &intent.public_cli_sha256
        || host.active_h1_receipt_sha256() == &e0.e0_h1_receipt_sha256
        || host.boot_id() != intent.observer.boot_id
    {
        return Err(CiError::Message(
            "historical E1 H1 differs after same-A upgrade".into(),
        ));
    }
    let probe = verify_probe_bundle(intent.observer.probe_bundle.clone())?;
    let e1_clock =
        crate::private_process_clock::VerifiedProcClockCalibrationV1::observe_live_reader(
            reader.pid,
            reader.start_ticks,
        )?;
    let e1_service = observe_installed_observer_subject(InstalledObserverRoleV1::SealedService)?;
    let e1_broker =
        crate::private_kernel_observer::activate_installed_network_broker_for_observation()?;
    if e1_service.pid == service.pid && e1_service.start_ticks == service.start_ticks {
        return Err(CiError::Message(
            "historical upgrade did not restart sealed service".into(),
        ));
    }
    let expected_interval = |result_key: DiagnosticSha256| ExpectedKernelAdapterV1 {
        boot_id: intent.observer.boot_id.clone(),
        kernel_release: intent.observer.kernel_release.clone(),
        btf_sha256: intent.observer.btf_sha256.clone(),
        probe_map_sha256: intent.observer.probe_map_sha256.clone(),
        result_key,
        coordinator_pid: e1_service.pid,
        coordinator_start_time: 0,
        coordinator_start_ticks: e1_service.start_ticks,
        cgroup_inode: e1_service.cgroup_inode,
        broker_pid: e1_broker.pid,
        broker_start_ticks: e1_broker.start_ticks,
        broker_cgroup_inode: e1_broker.cgroup_inode,
    };
    let expected_control_interval = |result_key: DiagnosticSha256| ExpectedKernelAdapterV1 {
        boot_id: intent.observer.boot_id.clone(),
        kernel_release: intent.observer.kernel_release.clone(),
        btf_sha256: intent.observer.btf_sha256.clone(),
        probe_map_sha256: intent.observer.probe_map_sha256.clone(),
        result_key,
        coordinator_pid: reader.pid,
        coordinator_start_time: 0,
        coordinator_start_ticks: reader.start_ticks,
        cgroup_inode: reader.cgroup_inode,
        broker_pid: e1_service.pid,
        broker_start_ticks: e1_service.start_ticks,
        broker_cgroup_inode: e1_service.cgroup_inode,
    };
    let controls = run_fixed_known_action_controls(
        &probe,
        expected_control_interval(intent.observer.control_result_key.clone()),
    )?;
    let mut replay_output = None;
    let replay_interval = run_probe_case_interval(
        &probe,
        expected_interval(e0_key.clone()),
        controls.controls(),
        || {
            replay_output = Some(
                crate::command::CommandSpec::new(AGENT, root, Duration::from_secs(30))
                    .remove_github_token()
                    .args([
                        "package",
                        "replay-public-release-epoch",
                        "--selector",
                        e0.selector.as_str(),
                        "--challenge",
                        e0.challenge.as_str(),
                        "--json",
                    ])
                    .run()?,
            );
            Ok(())
        },
    )?;
    if replay_interval.result_key() != &e0_key
        || !replay_interval.no_allocation()
        || !replay_interval.has_allocation_boundary()
        || replay_interval.capture_bytes()?.is_empty()
    {
        return Err(CiError::Message(
            "historical E1 replay allocated or lacks complete kernel interval".into(),
        ));
    }
    let replay_directory = Path::new("/var/lib/memcordon/sealed/private-public-cases")
        .join(String::from(e0_key.clone()));
    if !matches!(std::fs::symlink_metadata(replay_directory.join("epoch-replay.pending")), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
    {
        return Err(CiError::Message(
            "historical E1 replay left pending marker".into(),
        ));
    }
    let replay_bytes = crate::private_protected_readback::read_protected_raw_case_file(
        &replay_directory.join("epoch-replay.json"),
    )?;
    let rejection_bytes = crate::private_protected_readback::read_protected_raw_case_file(
        &replay_directory.join("epoch-replay-rejection.bin"),
    )?;
    let output = replay_output
        .ok_or_else(|| CiError::Message("historical E1 replay command output absent".into()))?;
    if output.strip_suffix(b"\n") != Some(replay_bytes.as_slice()) {
        return Err(CiError::Message(
            "historical E1 detached replay bytes differ".into(),
        ));
    }
    validate_historical_public_epoch_replay_v1(
        &replay_bytes,
        &rejection_bytes,
        &ExpectedHistoricalPublicEpochReplayV1 {
            selector: &e0.selector,
            result_key: &e0_key,
            original_request_bytes: &e0_provider.attempts[0].request_bytes,
            e0_installation_epoch_sha256: &e0.e0_installation_epoch_sha256,
            e0_h1_receipt_sha256: &e0.e0_h1_receipt_sha256,
            e1_installation_epoch_sha256: host.installation_epoch(),
            e1_h1_receipt_sha256: host.active_h1_receipt_sha256(),
        },
    )?;
    let _e0_raw = e0_raw;
    let spoof = &intent.historical_spoof;
    read_public_fixture(&spoof.contract_path, &spoof.contract_sha256)?;
    read_public_fixture(&spoof.fixture_path, &spoof.fixture_sha256)?;
    let spoof_parent = spoof
        .report_path
        .parent()
        .ok_or_else(|| CiError::Message("public spoof report parent absent".into()))?;
    let spoof_parent_meta = std::fs::symlink_metadata(spoof_parent)?;
    if !spoof_parent_meta.is_dir()
        || spoof_parent_meta.uid() != spoof.unauthorized_uid
        || spoof_parent_meta.mode() & 0o7777 != 0o700
        || !matches!(std::fs::symlink_metadata(&spoof.report_path), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
    {
        return Err(CiError::Message(
            "public spoof report custody differs".into(),
        ));
    }
    let spoof_challenge: [u8; 32] = hex::decode(&spoof.challenge)
        .map_err(|_| CiError::Message("public spoof challenge differs".into()))?
        .try_into()
        .map_err(|_| CiError::Message("public spoof challenge length differs".into()))?;
    let spoof_key = private_release_case_key_v1(
        PrivateReleaseStageV1::FinalPublic,
        &spoof.selector,
        &spoof_challenge,
    )
    .map_err(CiError::Message)?;
    if spoof_key == e0_key || spoof_key == intent.observer.control_result_key {
        return Err(CiError::Message(
            "public spoof key aliases control/history".into(),
        ));
    }
    let spoof_expected = ExpectedPublicV2Readback {
        source_commit: &intent.source_commit,
        native_abi,
        archive_sha256: &intent.archive_sha256,
        runtime_manifest_sha256: &intent.manifest_sha256,
        qualification_sha256: &intent.qualification_sha256,
        host_receipt_sha256: host.active_h1_receipt_sha256(),
        report_owner_uid: spoof.unauthorized_uid,
        outcome: crate::private_public_v2::ExpectedPublicV2Outcome::PreallocationRejected,
    };
    let mut spoof_child = None;
    let spoof_interval = run_probe_case_interval(
        &probe,
        expected_interval(spoof_key.clone()),
        controls.controls(),
        || {
            spoof_child = Some(run_installed_public_case(
                root,
                &spoof.selector,
                &spoof.challenge,
                Path::new(CLI),
                &intent.public_cli_sha256,
                &spoof.contract_path,
                &spoof.report_path,
                &spoof.fixture_path,
                None,
                None,
                spoof_parent,
                spoof.unauthorized_uid,
                spoof.unauthorized_gid,
                Duration::from_secs(120),
                &spoof_expected,
            )?);
            Ok(())
        },
    )?;
    if spoof_interval.result_key() != &spoof_key
        || spoof_interval.capture_bytes()?.is_empty()
        || !spoof_interval.has_allocation_boundary()
        || !spoof_interval.no_allocation()
    {
        return Err(CiError::Message(
            "public spoof lacks complete no-allocation interval".into(),
        ));
    }
    let spoof_child = spoof_child
        .ok_or_else(|| CiError::Message("public spoof child supervision absent".into()))?;
    let spoof_actor = spoof_child
        .process
        .linux_child
        .ok_or_else(|| CiError::Message("public spoof child PID/start absent".into()))?;
    let spoof_dir = Path::new("/var/lib/memcordon/sealed/private-public-cases")
        .join(String::from(spoof_key.clone()));
    let spoof_record = crate::private_protected_readback::read_protected_raw_case_file(
        &spoof_dir.join("spoof.json"),
    )?;
    let spoof_request = crate::private_protected_readback::read_protected_raw_case_file(
        &spoof_dir.join("spoof-request.bin"),
    )?;
    if spoof_request != read_public_fixture(&spoof.contract_path, &spoof.contract_sha256)? {
        return Err(CiError::Message(
            "public spoof authenticated plan bytes differ from pinned contract".into(),
        ));
    }
    let spoof_rejection = crate::private_protected_readback::read_protected_raw_case_file(
        &spoof_dir.join("spoof-rejection.bin"),
    )?;
    let spoof_grant_decision = crate::private_protected_readback::read_protected_raw_case_file(
        &spoof_dir.join("grant-decision.json"),
    )?;
    let spoof_stdout = crate::command::CommandSpec::new(AGENT, root, Duration::from_secs(30))
        .remove_github_token()
        .args([
            "package",
            "verify-public-spoof",
            "--selector",
            spoof.selector.as_str(),
            "--challenge",
            spoof.challenge.as_str(),
            "--json",
        ])
        .run()?;
    if spoof_stdout.strip_suffix(b"\n") != Some(spoof_record.as_slice()) {
        return Err(CiError::Message(
            "public spoof detached readback differs".into(),
        ));
    }
    crate::private_public_epoch_join::validate_protected_public_spoof_v1(
        &spoof_record,
        &spoof_rejection,
        &crate::private_public_epoch_join::ExpectedPublicSpoofV1 {
            selector: &spoof.selector,
            challenge: &spoof.challenge,
            result_key: &spoof_key,
            authorized_uid: intent.public_uid,
            unauthorized_uid: spoof.unauthorized_uid,
            unauthorized_gid: spoof.unauthorized_gid,
            registered_peer_pid: spoof_actor.pid,
            registered_peer_start_ticks: spoof_actor.start_time_ticks,
            installation_epoch: host.installation_epoch(),
            active_h1_receipt_sha256: host.active_h1_receipt_sha256(),
            request_bytes: &spoof_request,
            grant_decision_bytes: &spoof_grant_decision,
            rejection_code: "MCSEALED-PRIVATE-PUBLIC-GRANT-REJECTED",
        },
    )?;
    read_public_fixture(&spoof.contract_path, &spoof.contract_sha256)?;
    read_public_fixture(&spoof.fixture_path, &spoof.fixture_sha256)?;
    let _spoof_child = spoof_child;
    let policy_intent = intent.policy.as_ref().ok_or_else(|| {
        CiError::Message("public five-branch policy intent absent after E1 H1".into())
    })?;
    let mut policy_branch_inventory = Vec::with_capacity(5);
    let mut policy_case_branches = Vec::with_capacity(5);
    let mut policy_live = Vec::with_capacity(5);
    for (branch, case) in memcordon_core::private_release_branch_v1::PolicyOperationBranchV1::ALL
        .into_iter()
        .zip(&policy_intent.branches)
    {
        let contract_bytes = read_public_fixture(&case.contract_path, &case.contract_sha256)?;
        let memcordon_core::workload_contract::WorkloadContract::V2(contract) =
            memcordon_core::workload_contract::WorkloadContract::parse(&contract_bytes)
                .map_err(CiError::Message)?
        else {
            return Err(CiError::Message(
                "public policy branch contract is not V2".into(),
            ));
        };
        if serde_json::to_vec(&contract)? != contract_bytes {
            return Err(CiError::Message(
                "public policy branch contract fixture is not canonical".into(),
            ));
        }
        read_public_fixture(&case.fixture_path, &case.fixture_sha256)?;
        if let (Some(path), Some(digest)) = (&case.expected_plan_path, &case.expected_plan_sha256) {
            read_public_fixture(path, digest)?;
        }
        if let (Some(path), Some(digest)) =
            (&case.tampered_contract_path, &case.tampered_contract_sha256)
        {
            read_public_fixture(path, digest)?;
        }
        let report_parent = case
            .report_path
            .parent()
            .ok_or_else(|| CiError::Message("public policy report parent absent".into()))?;
        let parent = std::fs::symlink_metadata(report_parent)?;
        if !parent.is_dir()
            || parent.uid() != intent.public_uid
            || parent.mode() & 0o7777 != 0o700
            || !matches!(std::fs::symlink_metadata(&case.report_path), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
        {
            return Err(CiError::Message(
                "public policy report custody differs".into(),
            ));
        }
        let challenge: [u8; 32] = hex::decode(&case.challenge)
            .map_err(|_| CiError::Message("public policy branch challenge differs".into()))?
            .try_into()
            .map_err(|_| {
                CiError::Message("public policy branch challenge length differs".into())
            })?;
        let key = private_release_case_key_v1(
            PrivateReleaseStageV1::FinalPublic,
            &case.selector,
            &challenge,
        )
        .map_err(CiError::Message)?;
        if key == intent.observer.control_result_key || key == e0_key {
            return Err(CiError::Message(
                "public policy branch key aliases control/history".into(),
            ));
        }
        let outcome = if branch
            == memcordon_core::private_release_branch_v1::PolicyOperationBranchV1::AcceptedControl
        {
            crate::private_public_v2::ExpectedPublicV2Outcome::Exited(0)
        } else {
            crate::private_public_v2::ExpectedPublicV2Outcome::PreallocationRejected
        };
        let expected_report = ExpectedPublicV2Readback {
            source_commit: &intent.source_commit,
            native_abi,
            archive_sha256: &intent.archive_sha256,
            runtime_manifest_sha256: &intent.manifest_sha256,
            qualification_sha256: &intent.qualification_sha256,
            host_receipt_sha256: host.active_h1_receipt_sha256(),
            report_owner_uid: intent.public_uid,
            outcome,
        };
        let mut child = None;
        let interval = run_probe_case_interval(
            &probe,
            expected_interval(key.clone()),
            controls.controls(),
            || {
                child = Some(run_installed_public_case(
                    root,
                    &case.selector,
                    &case.challenge,
                    Path::new(CLI),
                    &intent.public_cli_sha256,
                    &case.contract_path,
                    &case.report_path,
                    &case.fixture_path,
                    case.expected_plan_path.as_deref(),
                    case.tampered_contract_path.as_deref(),
                    report_parent,
                    intent.public_uid,
                    intent.public_gid,
                    Duration::from_secs(120),
                    &expected_report,
                )?);
                Ok(())
            },
        )?;
        let child =
            child.ok_or_else(|| CiError::Message("public policy branch child absent".into()))?;
        let provider =
            read_structural_provider_case(&case.selector, &case.challenge, &intent, &host, &child)?;
        let joined = join_public_provider_kernel(&provider, &interval, &e1_clock)?;
        let accepted = branch
            == memcordon_core::private_release_branch_v1::PolicyOperationBranchV1::AcceptedControl;
        if accepted {
            if joined.target_count() != 1
                || provider.attempts.len() != 1
                || provider.attempts[0].terminal_bytes.is_none()
                || provider.attempts[0].cleanup_bytes.is_none()
            {
                return Err(CiError::Message("public policy accepted control lacks target/terminal/cleanup".into()));
            }
        } else if joined.target_count() != 0
            || !interval.no_allocation()
            || branch == memcordon_core::private_release_branch_v1::PolicyOperationBranchV1::CommittedPortTamper
                && (provider.attempts.len() != 1 || provider.phase != "launch-exchanges-complete")
            || branch != memcordon_core::private_release_branch_v1::PolicyOperationBranchV1::CommittedPortTamper
                && (!provider.attempts.is_empty() || provider.phase != "plan-rejected")
        {
            return Err(CiError::Message("public policy negative branch allocated or changed phase".into()));
        }
        let attachments =
            collect_public_raw_attachments(&case.selector, &child, &provider, &interval)?;
        let supervised = child
            .process
            .linux_child
            .ok_or_else(|| CiError::Message("public policy child identity absent".into()))?;
        let report_bytes = child
            .report_bytes
            .as_ref()
            .ok_or_else(|| CiError::Message("public policy CLI report absent".into()))?;
        use memcordon_core::private_public_policy_composite_v1::{
            PublicPolicyBranchEvidenceV1, PublicPolicyBranchOutcomeV1,
        };
        use memcordon_core::private_release_branch_v1::PolicyOperationBranchV1 as PolicyBranch;
        let branch_outcome = match branch {
            PolicyBranch::AcceptedControl => {
                let attempt = &provider.attempts[0];
                PublicPolicyBranchOutcomeV1::AcceptedControl {
                    attempt_id: attempt.attempt_id.clone(),
                    target_identity_sha256: hash_bytes(
                        attempt
                            .target_identity_bytes
                            .as_ref()
                            .expect("accepted target was checked"),
                    ),
                    terminal_sha256: hash_bytes(
                        attempt
                            .terminal_bytes
                            .as_ref()
                            .expect("accepted terminal was checked"),
                    ),
                    cleanup_sha256: hash_bytes(
                        attempt
                            .cleanup_bytes
                            .as_ref()
                            .expect("accepted cleanup was checked"),
                    ),
                }
            }
            PolicyBranch::CommittedPortTamper => PublicPolicyBranchOutcomeV1::FrozenPlanDenied {
                rejection_sha256: hash_bytes(&provider.attempts[0].response_bytes),
            },
            negative => {
                let code = match negative {
                    PolicyBranch::WrongGrant => {
                        memcordon_core::workload_registry_v2::AdmissionCodeV2::ProfileNotAuthorized
                    }
                    PolicyBranch::WrongProfile => {
                        memcordon_core::workload_registry_v2::AdmissionCodeV2::ProfileDigestMismatch
                    }
                    PolicyBranch::UnapprovedChangedPortPlan => {
                        memcordon_core::workload_registry_v2::AdmissionCodeV2::PlanNotApproved
                    }
                    _ => unreachable!("only three policy plan denials"),
                };
                PublicPolicyBranchOutcomeV1::PlanDenied {
                    admission_code: code,
                    rejection_sha256: hash_bytes(
                        provider
                            .terminal_bytes
                            .as_ref()
                            .expect("plan denial terminal was checked"),
                    ),
                }
            }
        };
        let raw_inventory = serde_json::to_vec(
            &attachments
                .iter()
                .map(|item| (item.role, item.bytes.len() as u64, hash_bytes(&item.bytes)))
                .collect::<Vec<_>>(),
        )?;
        policy_case_branches.push(PublicPolicyBranchEvidenceV1 {
            branch,
            challenge,
            result_key: key.clone(),
            child: FinalPublicChildIdentityV2 {
                pid: supervised.pid,
                start_time_ticks: supervised.start_time_ticks,
                boot_identity: memcordon_core::BoundedText::<128>::new(host.boot_id())
                    .map_err(|error| CiError::Message(error.into()))?,
                uid: intent.public_uid,
                gid: intent.public_gid,
                supplementary_groups_empty: true,
                executable_sha256: child.cli_sha256.clone(),
                argv_sha256: child.argv_sha256.clone(),
                working_directory_sha256: child.working_directory_sha256.clone(),
            },
            provider_record_sha256: hash_bytes(&provider.record_bytes),
            plan_response_sha256: hash_bytes(&provider.plan_response_bytes),
            grant_decision_sha256: hash_bytes(&provider.grant_decision_bytes),
            kernel_capture_sha256: interval.trace_sha256().clone(),
            report_sha256: hash_bytes(report_bytes),
            stdio_sha256: hash_bytes(&child.stdio_bytes),
            raw_inventory_sha256: hash_bytes(&raw_inventory),
            outcome: branch_outcome,
        });
        policy_branch_inventory.push(serde_json::json!({
            "branch": branch.as_str(),
            "result_key": key,
            "provider_request_sha256": hash_bytes(&provider.request_bytes),
            "plan_response_sha256": hash_bytes(&provider.plan_response_bytes),
            "grant_decision_sha256": hash_bytes(&provider.grant_decision_bytes),
            "kernel_capture_sha256": interval.trace_sha256(),
            "report_sha256": child.report_bytes.as_ref().map(|bytes| hash_bytes(bytes)),
            "attachment_sha256": attachments.iter().map(|item| hash_bytes(&item.bytes)).collect::<Vec<_>>(),
            "target_count": joined.target_count(),
        }));
        policy_live.push(crate::private_public_verify::PublicPolicyBranchLiveV1 {
            observed: child,
            provider,
            interval,
            joined,
            attachments,
        });
    }
    let policy_composite_bytes = serde_json::to_vec(&policy_branch_inventory)?;
    let policy_composite_sha256 = hash_bytes(&policy_composite_bytes);
    let policy_case =
        memcordon_core::private_public_policy_composite_v1::PublicPolicyCompositeCaseV1 {
            schema_version: 1,
            selector: memcordon_core::private_public_policy_composite_v1::PUBLIC_POLICY_SELECTOR_V1
                .into(),
            base_challenge: hex::decode(&policy_intent.base_challenge)
                .map_err(|_| CiError::Message("public policy base challenge differs".into()))?
                .try_into()
                .map_err(|_| {
                    CiError::Message("public policy base challenge length differs".into())
                })?,
            source_commit: intent.source_commit.clone(),
            release_version: memcordon_core::BoundedText::<128>::new(host.version())
                .map_err(|error| CiError::Message(error.into()))?,
            target: host.target().into(),
            native_machine: host.native_machine().into(),
            archive_sha256: intent.archive_sha256.clone(),
            manifest_sha256: host.manifest_sha256().clone(),
            qualification_sha256: host.qualification_sha256().clone(),
            active_h1_receipt_sha256: host.active_h1_receipt_sha256().clone(),
            installation_epoch: host.installation_epoch().clone(),
            build_context_sha256: intent.build_context_sha256.clone(),
            release_catalogue_sha256: intent.release_catalogue_sha256.clone(),
            provider_inventory_sha256: hash_bytes(&serde_json::to_vec(
                &policy_case_branches
                    .iter()
                    .map(|branch| &branch.provider_record_sha256)
                    .collect::<Vec<_>>(),
            )?),
            interval_inventory_sha256: hash_bytes(&serde_json::to_vec(
                &policy_case_branches
                    .iter()
                    .map(|branch| &branch.kernel_capture_sha256)
                    .collect::<Vec<_>>(),
            )?),
            branches: policy_case_branches.try_into().map_err(|_| {
                CiError::Message("public policy five-branch case inventory differs".into())
            })?,
        };
    let policy_case_bytes = serde_json::to_vec(&policy_case)?;
    memcordon_core::private_public_policy_composite_v1::PublicPolicyCompositeCaseV1::parse(
        &policy_case_bytes,
    )
    .map_err(CiError::Message)?;
    let policy_live: [crate::private_public_verify::PublicPolicyBranchLiveV1; 5] = policy_live
        .try_into()
        .map_err(|_| CiError::Message("public policy live branch count differs".into()))?;
    let verified_policy = crate::private_public_verify::verify_public_policy_composite(
        &policy_case_bytes,
        &policy_live,
    )?;
    let mut observed = Vec::with_capacity(intent.cases.len());
    let mut abi_composite_sha256 = None;
    let mut reuse_composite_sha256 = None;
    let mut e1_positive_control_terminal = None;
    let mut historical_epoch = None;
    for case in &intent.cases {
        if case.selector == "private_tcp::wrong_grant_profile_and_port_rejected" {
            continue;
        }
        read_public_fixture(&case.contract_path, &case.contract_sha256)?;
        read_public_fixture(&case.fixture_path, &case.fixture_sha256)?;
        match (&case.expected_plan_path, &case.expected_plan_sha256) {
            (Some(path), Some(digest)) => read_public_fixture(path, digest)?,
            (None, None) => {}
            _ => {
                return Err(CiError::Message(
                    "public expected-plan inventory differs".into(),
                ));
            }
        }
        if !case.report_path.starts_with("/run/memcordon-final-public/")
            || std::fs::symlink_metadata(&case.report_path).is_ok()
        {
            return Err(CiError::Message("public report path is not fresh".into()));
        }
        let report_parent = case
            .report_path
            .parent()
            .ok_or_else(|| CiError::Message("public report parent absent".into()))?;
        let parent = std::fs::symlink_metadata(report_parent)?;
        if !parent.is_dir() || parent.uid() != intent.public_uid || parent.mode() & 0o7777 != 0o700
        {
            return Err(CiError::Message(
                "public report directory custody differs".into(),
            ));
        }
        let outcome = match case.outcome.as_str() {
            "exit-zero" => crate::private_public_v2::ExpectedPublicV2Outcome::Exited(0),
            "preallocation-rejected" => {
                crate::private_public_v2::ExpectedPublicV2Outcome::PreallocationRejected
            }
            "native-failure" => crate::private_public_v2::ExpectedPublicV2Outcome::NativeFailure,
            "interrupted" => crate::private_public_v2::ExpectedPublicV2Outcome::Interrupted,
            "allocated-unverified" => {
                crate::private_public_v2::ExpectedPublicV2Outcome::AllocatedUnverified
            }
            "indeterminate" => crate::private_public_v2::ExpectedPublicV2Outcome::Indeterminate,
            "before-submission-failure" => {
                crate::private_public_v2::ExpectedPublicV2Outcome::BeforeSubmissionFailure
            }
            "transport-unverified" => {
                crate::private_public_v2::ExpectedPublicV2Outcome::TransportUnverified
            }
            "frontend-lost" => crate::private_public_v2::ExpectedPublicV2Outcome::FrontendLost,
            _ => {
                return Err(CiError::Message(
                    "public case expected outcome differs".into(),
                ));
            }
        };
        let expected = ExpectedPublicV2Readback {
            source_commit: &intent.source_commit,
            native_abi,
            archive_sha256: &intent.archive_sha256,
            runtime_manifest_sha256: &intent.manifest_sha256,
            qualification_sha256: &intent.qualification_sha256,
            host_receipt_sha256: host.active_h1_receipt_sha256(),
            report_owner_uid: intent.public_uid,
            outcome,
        };
        let challenge: [u8; 32] = hex::decode(&case.challenge)
            .map_err(|_| CiError::Message("public case challenge differs".into()))?
            .try_into()
            .map_err(|_| CiError::Message("public case challenge length differs".into()))?;
        let result_key = private_release_case_key_v1(
            PrivateReleaseStageV1::FinalPublic,
            &case.selector,
            &challenge,
        )
        .map_err(CiError::Message)?;
        if result_key == intent.observer.control_result_key {
            return Err(CiError::Message(
                "public control and case result keys alias".into(),
            ));
        }
        if case.selector
            == memcordon_core::private_public_reuse_composite_v1::PUBLIC_REUSE_SELECTOR_V1
        {
            use std::io::{Read, Write};
            use std::os::unix::net::UnixStream;
            use std::sync::{Arc, Mutex};
            let (mut supervisor_barrier, child_barrier) = UnixStream::pair()?;
            supervisor_barrier.set_read_timeout(Some(Duration::from_secs(120)))?;
            supervisor_barrier.set_write_timeout(Some(Duration::from_secs(120)))?;
            let holder_slot = Arc::new(Mutex::new(None::<std::process::Child>));
            let dispatch_key_hex = String::from(result_key.clone());
            let holder_slot_for_child = Arc::clone(&holder_slot);
            let holder_challenge = case.challenge.clone();
            let holder_dispatch_key = dispatch_key_hex.clone();
            let holder_root = root.to_path_buf();
            let mut case_observed = None;
            let (first_interval, blocked_interval) = std::thread::scope(|scope| -> Result<_> {
                let mut public_child = None;
                let first = run_probe_case_interval(
                    &probe,
                    expected_interval(result_key.clone()),
                    controls.controls(),
                    || {
                        public_child = Some(scope.spawn(move || {
                            run_installed_public_reuse_case(
                                root,
                                &case.selector,
                                &case.challenge,
                                Path::new(CLI),
                                &intent.public_cli_sha256,
                                &case.contract_path,
                                &case.report_path,
                                &case.fixture_path,
                                case.expected_plan_path.as_deref(),
                                report_parent,
                                intent.public_uid,
                                intent.public_gid,
                                Duration::from_secs(180),
                                &expected,
                                child_barrier,
                                Box::new(move || {
                                    let holder = std::process::Command::new(AGENT)
                                        .args([
                                            "package",
                                            "public-reuse-hold",
                                            "--selector",
                                            "private_tcp::retirement_failure_blocks_reuse",
                                            "--challenge",
                                            holder_challenge.as_str(),
                                            "--dispatch-key",
                                            holder_dispatch_key.as_str(),
                                        ])
                                        .env_clear()
                                        .current_dir(&holder_root)
                                        .stdin(std::process::Stdio::null())
                                        .stdout(std::process::Stdio::null())
                                        .stderr(std::process::Stdio::null())
                                        .spawn()?;
                                    *holder_slot_for_child.lock().map_err(|_| {
                                        std::io::Error::other("public reuse holder lock failed")
                                    })? = Some(holder);
                                    Ok(())
                                }),
                            )
                        }));
                        let mut ready = [0_u8; 1];
                        supervisor_barrier.read_exact(&mut ready)?;
                        if ready != [b'R'] {
                            return Err(CiError::Message(
                                "public reuse first-attempt barrier differs".into(),
                            ));
                        }
                        Ok(())
                    },
                )?;
                let blocked = run_probe_case_interval(
                    &probe,
                    expected_interval(result_key.clone()),
                    controls.controls(),
                    || {
                        supervisor_barrier.write_all(b"G")?;
                        case_observed = Some(
                            public_child
                                .take()
                                .expect("reuse child started under first interval")
                                .join()
                                .map_err(|_| {
                                    CiError::Message(
                                        "public reuse child supervisor panicked".into(),
                                    )
                                })??,
                        );
                        Ok(())
                    },
                )?;
                Ok((first, blocked))
            })?;
            let case_observed = case_observed.ok_or_else(|| {
                CiError::Message("public reuse same-actor CLI result absent".into())
            })?;
            let mut holder = holder_slot
                .lock()
                .map_err(|_| CiError::Message("public reuse holder lock failed".into()))?
                .take()
                .ok_or_else(|| CiError::Message("public reuse holder was not started".into()))?;
            let holder_subject = observe_live_kernel_subject(holder.id())?;
            let holder_clock =
                crate::private_process_clock::VerifiedProcClockCalibrationV1::observe_live_reader(
                    holder_subject.pid,
                    holder_subject.start_ticks,
                )?;
            let mut recovery = std::process::Command::new(AGENT)
                .args([
                    "package",
                    "public-reuse-release-and-recover",
                    "--selector",
                    case.selector.as_str(),
                    "--challenge",
                    case.challenge.as_str(),
                    "--dispatch-key",
                    dispatch_key_hex.as_str(),
                ])
                .env_clear()
                .current_dir(root)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()?;
            let recovery_subject = observe_live_kernel_subject(recovery.id())?;
            let recovery_expected = ExpectedKernelAdapterV1 {
                boot_id: intent.observer.boot_id.clone(),
                kernel_release: intent.observer.kernel_release.clone(),
                btf_sha256: intent.observer.btf_sha256.clone(),
                probe_map_sha256: intent.observer.probe_map_sha256.clone(),
                result_key: result_key.clone(),
                coordinator_pid: recovery_subject.pid,
                coordinator_start_time: 0,
                coordinator_start_ticks: recovery_subject.start_ticks,
                cgroup_inode: recovery_subject.cgroup_inode,
                broker_pid: e1_service.pid,
                broker_start_ticks: e1_service.start_ticks,
                broker_cgroup_inode: e1_service.cgroup_inode,
            };
            let recovery_interval =
                run_probe_case_interval(&probe, recovery_expected, controls.controls(), || {
                    recovery
                        .stdin
                        .take()
                        .ok_or_else(|| {
                            CiError::Message("public reuse recovery gate absent".into())
                        })?
                        .write_all(b"G")?;
                    std::thread::scope(|scope| -> Result<()> {
                        let holder_wait = scope.spawn(|| wait_public_child_bounded(&mut holder));
                        let recovery_status = wait_public_child_bounded(&mut recovery)?;
                        let holder_status = holder_wait.join().map_err(|_| {
                            CiError::Message("public reuse holder waiter panicked".into())
                        })??;
                        if !recovery_status.success() || !holder_status.success() {
                            return Err(CiError::Message(
                                "public reuse recovery or holder exited unsuccessfully".into(),
                            ));
                        }
                        Ok(())
                    })
                })?;
            let provider = read_structural_provider_case(
                &case.selector,
                &case.challenge,
                &intent,
                &host,
                &case_observed,
            )?;
            let journal =
                Path::new("/var/lib/memcordon/sealed/private-public-reuse").join(&dispatch_key_hex);
            let read = |name: &str| {
                crate::private_protected_readback::read_protected_raw_case_file(&journal.join(name))
            };
            let reuse_bytes = read("reuse.json")?;
            let incomplete = read("incomplete-v4.bin")?;
            let first_failure = read("first-failure.bin")?;
            let blocked_request = read("blocked-request.bin")?;
            let blocked_rejection = read("blocked-rejection.bin")?;
            let recovered_cleanup = read("recovered-cleanup.bin")?;
            let detached = crate::command::CommandSpec::new(AGENT, root, Duration::from_secs(30))
                .remove_github_token()
                .args([
                    "package",
                    "public-reuse-verify",
                    "--selector",
                    case.selector.as_str(),
                    "--challenge",
                    case.challenge.as_str(),
                    "--dispatch-key",
                    dispatch_key_hex.as_str(),
                ])
                .run()?;
            let [first_attempt, blocked_attempt] = provider.attempts.as_slice() else {
                return Err(CiError::Message(
                    "public reuse attempt count differs".into(),
                ));
            };
            let raw: serde_json::Value = serde_json::from_slice(&reuse_bytes)?;
            if raw.get("durable_incomplete_state_sha256")
                != Some(&serde_json::to_value(hash_bytes(&incomplete))?)
            {
                return Err(CiError::Message(
                    "public reuse durable incomplete snapshot differs".into(),
                ));
            }
            let verified = crate::private_public_reuse_join::join_public_reuse_v1(
                &crate::private_public_reuse_join::ExpectedPublicReuseLiveV1 {
                    protected_record_bytes: &reuse_bytes,
                    detached_stdout: &detached,
                    detached: crate::private_public_reuse_join::ExpectedPublicReuseV1 {
                        result_key: &result_key,
                        boot_id: host.boot_id(),
                        installation_epoch: host.installation_epoch(),
                        active_h1_receipt_sha256: host.active_h1_receipt_sha256(),
                        first_attempt_id: &first_attempt.attempt_id,
                        second_attempt_id: &blocked_attempt.attempt_id,
                        cleanup_failure_bytes: &first_failure,
                        blocked_request_bytes: &blocked_request,
                        blocked_rejection_bytes: &blocked_rejection,
                        recovered_cleanup_bytes: &recovered_cleanup,
                        expected_failure_code: "MCSEALED-PRIVATE-REUSE-CLEANUP-INCOMPLETE",
                        expected_blocked_code: "MCSEALED-PRIVATE-REUSE-BLOCKED",
                    },
                    provider: &provider,
                    first_clock: &e1_clock,
                    holder_clock: &holder_clock,
                    first_interval: &first_interval,
                    blocked_interval: &blocked_interval,
                    recovery_interval: &recovery_interval,
                },
            )?;
            let child = case_observed
                .process
                .linux_child
                .ok_or_else(|| CiError::Message("public reuse child identity absent".into()))?;
            let report = case_observed
                .report_bytes
                .as_ref()
                .ok_or_else(|| CiError::Message("public reuse final CLI report absent".into()))?;
            let composite =
                memcordon_core::private_public_reuse_composite_v1::PublicReuseCompositeCaseV1 {
                    schema_version: 1,
                    selector: case.selector.clone(),
                    challenge,
                    source_commit: intent.source_commit.clone(),
                    release_version: memcordon_core::BoundedText::new(host.version())
                        .map_err(|error| CiError::Message(error.into()))?,
                    target: host.target().into(),
                    native_machine: host.native_machine().into(),
                    archive_sha256: intent.archive_sha256.clone(),
                    manifest_sha256: host.manifest_sha256().clone(),
                    qualification_sha256: host.qualification_sha256().clone(),
                    active_h1_receipt_sha256: host.active_h1_receipt_sha256().clone(),
                    installation_epoch: host.installation_epoch().clone(),
                    child: memcordon_core::private_public_case_v2::FinalPublicChildIdentityV2 {
                        pid: child.pid,
                        start_time_ticks: child.start_time_ticks,
                        boot_identity: memcordon_core::BoundedText::new(host.boot_id())
                            .map_err(|error| CiError::Message(error.into()))?,
                        uid: intent.public_uid,
                        gid: intent.public_gid,
                        supplementary_groups_empty: true,
                        executable_sha256: case_observed.cli_sha256.clone(),
                        argv_sha256: case_observed.argv_sha256.clone(),
                        working_directory_sha256: case_observed.working_directory_sha256.clone(),
                    },
                    provider_sha256: hash_bytes(&provider.record_bytes),
                    report_sha256: hash_bytes(report),
                    stdio_sha256: hash_bytes(&case_observed.stdio_bytes),
                    first_failure_sha256: verified.cleanup_failure_sha256().clone(),
                    blocked_rejection_sha256: verified.blocked_rejection_sha256().clone(),
                    recovered_cleanup_sha256: verified.recovered_cleanup_sha256().clone(),
                    durable_incomplete_snapshot_sha256: hash_bytes(&incomplete),
                    protected_reuse_transcript_sha256: hash_bytes(&reuse_bytes),
                    semantic_join_sha256: verified.transcript_sha256().clone(),
                    first_kernel_capture_sha256: first_interval.trace_sha256().clone(),
                    blocked_kernel_capture_sha256: blocked_interval.trace_sha256().clone(),
                    recovery_kernel_capture_sha256: recovery_interval.trace_sha256().clone(),
                };
            let bytes = serde_json::to_vec(&composite)?;
            memcordon_core::private_public_reuse_composite_v1::PublicReuseCompositeCaseV1::parse(
                &bytes,
            )
            .map_err(CiError::Message)?;
            let _verified_reuse = crate::private_public_verify::verify_public_reuse_composite(
                &bytes,
                &verified,
                &first_interval,
                &blocked_interval,
                &recovery_interval,
            )?;
            reuse_composite_sha256 = Some(hash_bytes(&bytes));
            continue;
        }
        let abi_outer = if case.selector
            == memcordon_core::private_public_abi_composite_v1::PUBLIC_ABI_SELECTOR_V1
        {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct OuterCommandResultV1 {
                schema: u8,
                auxiliary_key: DiagnosticSha256,
                raw_sha256: DiagnosticSha256,
            }
            let mut key_bytes = b"memcordon-public-abi-outer-v1\0".to_vec();
            for digest in [
                host.active_h1_receipt_sha256(),
                host.installation_epoch(),
                &result_key,
                &DiagnosticSha256::from_bytes(challenge),
            ] {
                key_bytes.extend_from_slice(digest.bytes());
            }
            let auxiliary_key = hash_bytes(&key_bytes);
            let dispatch_key_hex = String::from(result_key.clone());
            let mut output = None;
            let interval = run_probe_case_interval(
                &probe,
                expected_interval(auxiliary_key.clone()),
                controls.controls(),
                || {
                    output = Some(
                        crate::command::CommandSpec::new(AGENT, root, Duration::from_secs(60))
                            .remove_github_token()
                            .args([
                                "package",
                                "public-abi-outer-control",
                                "--selector",
                                case.selector.as_str(),
                                "--challenge",
                                case.challenge.as_str(),
                                "--dispatch-key",
                                dispatch_key_hex.as_str(),
                            ])
                            .run()?,
                    );
                    Ok(())
                },
            )?;
            let output = output
                .ok_or_else(|| CiError::Message("public ABI outer command output absent".into()))?;
            let output = output.strip_suffix(b"\n").ok_or_else(|| {
                CiError::Message("public ABI outer command output framing differs".into())
            })?;
            let response: OuterCommandResultV1 = serde_json::from_slice(output)?;
            let directory = Path::new("/var/lib/memcordon/sealed/private-public-abi-controls")
                .join(String::from(auxiliary_key.clone()));
            let request = crate::private_protected_readback::read_protected_raw_case_file(
                &directory.join("request.json"),
            )?;
            let raw = crate::private_protected_readback::read_protected_raw_case_file(
                &directory.join("outer-control.raw.json"),
            )?;
            let structural = crate::private_public_abi_outer::readback_public_abi_outer_v1(
                &request,
                &raw,
                &crate::private_public_abi_outer::ExpectedPublicAbiOuterV1 {
                    target: host.target(),
                    challenge: &challenge,
                    h1_sha256: host.active_h1_receipt_sha256(),
                    installation_epoch: host.installation_epoch(),
                    service_pid: e1_service.pid,
                    service_start_ticks: e1_service.start_ticks,
                    service_cgroup_inode: e1_service.cgroup_inode,
                },
            )?;
            let capture = crate::private_public_abi_outer::join_public_abi_outer_kernel_v1(
                &structural,
                &interval,
                &e1_clock,
            )?;
            if response.schema != 1
                || response.auxiliary_key != auxiliary_key
                || response.raw_sha256 != structural.raw_sha256
                || structural.dispatch_key != result_key
            {
                return Err(CiError::Message(
                    "public ABI outer detached readback differs".into(),
                ));
            }
            Some((structural, capture))
        } else {
            None
        };
        let mut case_observed = None;
        let interval = run_probe_case_interval(
            &probe,
            expected_interval(result_key.clone()),
            controls.controls(),
            || {
                case_observed = Some(if abi_outer.is_some() {
                    run_installed_public_abi_case(root, case, &intent, &expected, report_parent)?
                } else {
                    run_installed_public_case(
                        root,
                        &case.selector,
                        &case.challenge,
                        Path::new(CLI),
                        &intent.public_cli_sha256,
                        &case.contract_path,
                        &case.report_path,
                        &case.fixture_path,
                        case.expected_plan_path.as_deref(),
                        None,
                        report_parent,
                        intent.public_uid,
                        intent.public_gid,
                        Duration::from_secs(120),
                        &expected,
                    )?
                });
                Ok(())
            },
        )?;
        let case_observed = case_observed.ok_or_else(|| {
            CiError::Message("public case was not supervised within kernel interval".into())
        })?;
        if interval.result_key() != &result_key || interval.capture_bytes()?.is_empty() {
            return Err(CiError::Message(
                "public kernel interval capture differs".into(),
            ));
        }
        read_public_fixture(&case.contract_path, &case.contract_sha256)?;
        read_public_fixture(&case.fixture_path, &case.fixture_sha256)?;
        if let (Some(path), Some(digest)) = (&case.expected_plan_path, &case.expected_plan_sha256) {
            read_public_fixture(path, digest)?;
        }
        let provider = read_structural_provider_case(
            &case.selector,
            &case.challenge,
            &intent,
            &host,
            &case_observed,
        )?;
        let kernel_join = join_public_provider_kernel(&provider, &interval, &e1_clock)?;
        if case.selector == "private_tcp::native_tcp_bind_listen_connect" {
            if kernel_join.target_count() != 1 {
                return Err(CiError::Message(
                    "public E1 positive control target absent".into(),
                ));
            }
            e1_positive_control_terminal = provider
                .attempts
                .first()
                .and_then(|attempt| attempt.terminal_bytes.as_ref())
                .map(|bytes| hash_bytes(bytes));
            let joined = crate::private_public_epoch_join::join_public_epoch_transition_v1(
                &crate::private_public_epoch_join::ExpectedPublicEpochTransitionV1 {
                    e0: crate::private_public_epoch_join::PublicEpochPositiveV1 {
                        selector: &e0.selector,
                        challenge: &e0.challenge,
                        host: &e0_host,
                        provider: &e0_provider,
                        kernel_join: &e0_kernel_join,
                        interval: &e0_interval,
                    },
                    e1: crate::private_public_epoch_join::PublicEpochPositiveV1 {
                        selector: &case.selector,
                        challenge: &case.challenge,
                        host: &host,
                        provider: &provider,
                        kernel_join: &kernel_join,
                        interval: &interval,
                    },
                    protected_archive_sha256: &intent.archive_sha256,
                    upgrade_archive_sha256: &intent.archive_sha256,
                    replay_record_bytes: &replay_bytes,
                    replay_rejection_bytes: &rejection_bytes,
                    replay_stdout: &output,
                    replay_interval: &replay_interval,
                    spoof_record_bytes: &spoof_record,
                    spoof_stdout: &spoof_stdout,
                    spoof_request_bytes: &spoof_request,
                    spoof_rejection_bytes: &spoof_rejection,
                    spoof_expected: crate::private_public_epoch_join::ExpectedPublicSpoofV1 {
                        selector: &spoof.selector,
                        challenge: &spoof.challenge,
                        result_key: &spoof_key,
                        authorized_uid: intent.public_uid,
                        unauthorized_uid: spoof.unauthorized_uid,
                        unauthorized_gid: spoof.unauthorized_gid,
                        registered_peer_pid: spoof_actor.pid,
                        registered_peer_start_ticks: spoof_actor.start_time_ticks,
                        installation_epoch: host.installation_epoch(),
                        active_h1_receipt_sha256: host.active_h1_receipt_sha256(),
                        request_bytes: &spoof_request,
                        grant_decision_bytes: &spoof_grant_decision,
                        rejection_code: "MCSEALED-PRIVATE-PUBLIC-GRANT-REJECTED",
                    },
                    spoof_interval: &spoof_interval,
                },
            )?;
            historical_epoch = Some(
                crate::private_public_verify::VerifiedHistoricalPublicEpochV1::from_live_join(
                    &joined,
                    host.boot_id(),
                )?,
            );
        }
        if let Some((outer, outer_kernel)) = abi_outer {
            use memcordon_core::private_public_abi_composite_v1::PublicAbiCompositeCaseV1;
            use memcordon_core::private_public_case_v2::FinalPublicChildIdentityV2;
            let child = case_observed.process.linux_child.ok_or_else(|| {
                CiError::Message("public ABI filtered child identity absent".into())
            })?;
            let [attempt] = provider.attempts.as_slice() else {
                return Err(CiError::Message(
                    "public ABI filtered attempt inventory differs".into(),
                ));
            };
            if kernel_join.target_count() != 1 || provider.phase != "launch-exchanges-complete" {
                return Err(CiError::Message(
                    "public ABI filtered target kernel join absent".into(),
                ));
            }
            let terminal = attempt
                .terminal_bytes
                .as_ref()
                .ok_or_else(|| CiError::Message("public ABI filtered terminal absent".into()))?;
            let cleanup = attempt
                .cleanup_bytes
                .as_ref()
                .ok_or_else(|| CiError::Message("public ABI filtered cleanup absent".into()))?;
            let target_identity = attempt.target_identity.as_ref().ok_or_else(|| {
                CiError::Message("public ABI filtered protected target identity absent".into())
            })?;
            if case.fixture_sha256 != *host.agent_sha256()
                || target_identity.entrypoint_sha256 != *host.agent_sha256()
                || target_identity.entrypoint_path != case.fixture_path.to_string_lossy().as_ref()
            {
                return Err(CiError::Message(
                    "public ABI approved target is not the B-pinned fixture".into(),
                ));
            }
            let helper_image = match (host.target(), host.arm32_helper_sha256()) {
                ("x86_64-unknown-linux-gnu", None) => None,
                ("aarch64-unknown-linux-gnu", Some(digest)) => Some(pinned_root_executable(
                    Path::new("/usr/libexec/memcordon-arm32-abi-helper"),
                    digest,
                )?),
                _ => {
                    return Err(CiError::Message(
                        "public ABI helper inventory differs from H1".into(),
                    ));
                }
            };
            let filtered_directory =
                Path::new("/var/lib/memcordon/sealed/private-public-abi-filtered")
                    .join(String::from(result_key.clone()));
            let target_report = crate::private_protected_readback::read_protected_raw_case_file(
                &filtered_directory.join("target-report.bin"),
            )?;
            let protected_filtered =
                crate::private_protected_readback::read_protected_raw_case_file(
                    &filtered_directory.join("filtered.json"),
                )?;
            let checkpoint_file = crate::private_protected_readback::read_protected_raw_case_file(
                &filtered_directory.join("checkpoint.json"),
            )?;
            let checkpoint: memcordon_core::workload_evidence_v2::PrivateTcpCheckpointV2 =
                serde_json::from_slice(&checkpoint_file)?;
            let checkpoint_sha256 = checkpoint.canonical_digest().map_err(CiError::Message)?;
            let filtered = crate::private_public_abi_filtered::readback_public_abi_filtered_v1(
                &target_report,
                &protected_filtered,
                &checkpoint_file,
                &crate::private_public_abi_filtered::ExpectedPublicAbiFilteredV1 {
                    target: host.target(),
                    challenge: &challenge,
                    result_key: &result_key,
                    boot_id: host.boot_id(),
                    installation_epoch: host.installation_epoch(),
                    active_h1_receipt_sha256: host.active_h1_receipt_sha256(),
                    attempt_id: &attempt.attempt_id,
                    target_pid: target_identity.target.pid,
                    target_start_ticks: target_identity.target.start_time,
                    target_uid: intent.public_uid,
                    target_gid: intent.public_gid,
                    checkpoint_sha256: &checkpoint_sha256,
                    filter_sha256: host.filter_sha256(),
                    network_namespace_inode: target_identity.network_namespace_inode,
                    helper_device: helper_image.map(|(dev, _)| dev),
                    helper_inode: helper_image.map(|(_, inode)| inode),
                },
            )?;
            let filtered_capture =
                crate::private_public_abi_filtered::join_public_abi_filtered_kernel_v1(
                    &filtered,
                    &interval,
                    &e1_clock,
                    target_identity.entrypoint_device,
                    target_identity.entrypoint_inode,
                )?;
            let report = case_observed
                .report_bytes
                .as_ref()
                .ok_or_else(|| CiError::Message("public ABI filtered CLI report absent".into()))?;
            let composite = PublicAbiCompositeCaseV1 {
                schema_version: 1,
                selector: case.selector.clone(),
                challenge,
                source_commit: intent.source_commit.clone(),
                release_version: memcordon_core::BoundedText::new(host.version())
                    .map_err(|error| CiError::Message(error.into()))?,
                target: host.target().into(),
                native_machine: host.native_machine().into(),
                archive_sha256: intent.archive_sha256.clone(),
                manifest_sha256: host.manifest_sha256().clone(),
                qualification_sha256: host.qualification_sha256().clone(),
                active_h1_receipt_sha256: host.active_h1_receipt_sha256().clone(),
                installation_epoch: host.installation_epoch().clone(),
                filtered_child: FinalPublicChildIdentityV2 {
                    pid: child.pid,
                    start_time_ticks: child.start_time_ticks,
                    boot_identity: memcordon_core::BoundedText::new(host.boot_id())
                        .map_err(|error| CiError::Message(error.into()))?,
                    uid: intent.public_uid,
                    gid: intent.public_gid,
                    supplementary_groups_empty: true,
                    executable_sha256: case_observed.cli_sha256.clone(),
                    argv_sha256: case_observed.argv_sha256.clone(),
                    working_directory_sha256: case_observed.working_directory_sha256.clone(),
                },
                filtered_provider_sha256: hash_bytes(&provider.record_bytes),
                filtered_report_sha256: hash_bytes(report),
                filtered_stdio_sha256: hash_bytes(&case_observed.stdio_bytes),
                filtered_terminal_sha256: hash_bytes(terminal),
                filtered_cleanup_sha256: hash_bytes(cleanup),
                filtered_target_report_sha256: filtered.report_sha256.clone(),
                filtered_service_journal_sha256: filtered.protected_sha256.clone(),
                filtered_checkpoint_file_sha256: filtered.checkpoint_file_sha256.clone(),
                filtered_kernel_capture_sha256: filtered_capture.capture_sha256().clone(),
                outer_auxiliary_key: outer.auxiliary_key,
                outer_request_sha256: outer.request_sha256,
                outer_raw_sha256: outer.raw_sha256,
                outer_kernel_capture_sha256: outer_kernel.capture_sha256().clone(),
            };
            let bytes = serde_json::to_vec(&composite)?;
            PublicAbiCompositeCaseV1::parse(&bytes).map_err(CiError::Message)?;
            let _verified_abi = crate::private_public_verify::verify_public_abi_composite(
                &bytes,
                &case_observed,
                &provider,
                &outer,
                &outer_kernel,
                &filtered,
                &filtered_capture,
                &interval,
                &kernel_join,
            )?;
            abi_composite_sha256 = Some(hash_bytes(&bytes));
            continue;
        }
        let composed = compose_public_case_observation(
            &case.selector,
            &provider,
            &case_observed,
            &interval,
            &kernel_join,
            e1_positive_control_terminal.as_ref(),
        )?;
        let attachments =
            collect_public_raw_attachments(&case.selector, &case_observed, &provider, &interval)?;
        let case_evidence = compose_final_public_case_v2(
            &case.selector,
            challenge,
            &intent,
            &host,
            &case_observed,
            &provider,
            &composed,
            &attachments,
        )?;
        observed.push((
            case_observed,
            provider,
            interval,
            kernel_join,
            case_evidence,
            attachments,
        ));
    }
    Err(CiError::Message(format!(
        "{} ordinary public V2 cases, five policy branches (composite {}), ABI live composite {:?}, reuse live composite {:?}, and historical E0/E1 live join {:?} ran, but the all-25 public P semantic index and authenticated observer-origin evidence are incomplete; P was not produced",
        observed.len(),
        policy_composite_sha256,
        abi_composite_sha256,
        reuse_composite_sha256,
        historical_epoch.map(|token| token.transcript_sha256().clone()),
    )))
}

#[cfg(not(target_os = "linux"))]
pub fn run_final_public_suite(_root: &std::path::Path, _target: &str) -> crate::Result<()> {
    Err(crate::CiError::Message(
        "public dispatch requires native Linux".into(),
    ))
}

#[cfg(target_os = "linux")]
fn pinned_root_executable(path: &Path, expected: &DiagnosticSha256) -> Result<(u64, u64)> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    if !path.is_absolute() {
        return Err(CiError::Message(
            "installed public executable path differs".into(),
        ));
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || before.mode() & 0o022 != 0
        || before.mode() & 0o111 == 0
        || before.len() == 0
        || before.len() > 64 * 1024 * 1024
    {
        return Err(CiError::Message(
            "installed public executable custody differs".into(),
        ));
    }
    let mut bytes = Vec::new();
    (&mut file).take(before.len() + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let leaf = std::fs::symlink_metadata(path)?;
    if bytes.len() as u64 != before.len()
        || hash_bytes(&bytes) != *expected
        || (before.dev(), before.ino(), before.len()) != (after.dev(), after.ino(), after.len())
        || (before.dev(), before.ino()) != (leaf.dev(), leaf.ino())
    {
        return Err(CiError::Message(
            "installed public executable bytes changed".into(),
        ));
    }
    Ok((before.dev(), before.ino()))
}

#[cfg(target_os = "linux")]
fn observe_public_child(
    pid: u32,
    executable: (u64, u64),
    uid: u32,
    gid: u32,
) -> std::io::Result<LinuxChildIdentityV1> {
    use std::os::unix::fs::MetadataExt;

    let root = Path::new("/proc").join(pid.to_string());
    let stat = std::fs::read_to_string(root.join("stat"))?;
    let identity = parse_linux_child_stat(&stat, pid)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let image = std::fs::metadata(root.join("exe"))?;
    if (image.dev(), image.ino()) != executable {
        return Err(std::io::Error::other("public child gate image differs"));
    }
    let status = std::fs::read_to_string(root.join("status"))?;
    for (key, expected) in [("Uid:", uid), ("Gid:", gid)] {
        let values = status
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .ok_or_else(|| std::io::Error::other("public child credentials absent"))?;
        if values.split_whitespace().count() != 4
            || values
                .split_whitespace()
                .any(|value| value.parse::<u32>() != Ok(expected))
        {
            return Err(std::io::Error::other(
                "public child retained a privileged id",
            ));
        }
    }
    let groups = status
        .lines()
        .find_map(|line| line.strip_prefix("Groups:"))
        .ok_or_else(|| std::io::Error::other("public child groups absent"))?;
    if !groups.trim().is_empty() {
        return Err(std::io::Error::other(
            "public child retained supplementary groups",
        ));
    }
    for key in ["CapEff:", "CapPrm:", "CapInh:", "CapAmb:"] {
        let value = status
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .ok_or_else(|| std::io::Error::other("public child capability field absent"))?;
        if u64::from_str_radix(value.trim(), 16) != Ok(0) {
            return Err(std::io::Error::other("public child retained a capability"));
        }
    }
    Ok(identity)
}

/// Executes one already-approved case through the installed public CLI. The
/// fixed fixture, contract and grant must have been independently prepared by
/// the same-host final session before this call.
#[cfg(target_os = "linux")]
pub fn run_installed_public_case(
    registration_root: &Path,
    selector: &str,
    challenge: &str,
    cli: &Path,
    cli_sha256: &DiagnosticSha256,
    contract_path: &Path,
    report_path: &Path,
    fixture_path: &Path,
    expected_plan_path: Option<&Path>,
    frozen_contract_path: Option<&Path>,
    working_directory: &Path,
    uid: u32,
    gid: u32,
    deadline: Duration,
    expected_report: &ExpectedPublicV2Readback<'_>,
) -> Result<ObservedInstalledPublicCaseV3> {
    run_installed_public_case_inner(
        registration_root,
        selector,
        challenge,
        cli,
        cli_sha256,
        contract_path,
        report_path,
        fixture_path,
        expected_plan_path,
        frozen_contract_path,
        working_directory,
        uid,
        gid,
        deadline,
        expected_report,
        None,
        None,
        None,
    )
}

/// The only final-public case allowed to pass arguments to its approved
/// entrypoint. The arguments select the reviewed, B-pinned filtered ABI mode
/// and bind its target report to the protected dispatch challenge.
#[cfg(target_os = "linux")]
fn run_installed_public_abi_case(
    registration_root: &Path,
    case: &PublicDispatchCaseV1,
    intent: &ProtectedPublicDispatchIntentV1,
    expected_report: &ExpectedPublicV2Readback<'_>,
    report_parent: &Path,
) -> Result<ObservedInstalledPublicCaseV3> {
    if case.selector != memcordon_core::private_public_abi_composite_v1::PUBLIC_ABI_SELECTOR_V1
        || case.fixture_sha256 != intent.observer.probe_bundle.agent_sha256
    {
        return Err(CiError::Message(
            "public ABI entrypoint is not the B-pinned installed agent".into(),
        ));
    }
    let target_arguments = [
        std::ffi::OsString::from("public-abi-filtered-target"),
        std::ffi::OsString::from("--challenge"),
        std::ffi::OsString::from(&case.challenge),
    ];
    run_installed_public_case_inner(
        registration_root,
        &case.selector,
        &case.challenge,
        Path::new("/usr/bin/memcordon"),
        &intent.public_cli_sha256,
        &case.contract_path,
        &case.report_path,
        &case.fixture_path,
        case.expected_plan_path.as_deref(),
        None,
        report_parent,
        intent.public_uid,
        intent.public_gid,
        Duration::from_secs(120),
        expected_report,
        None,
        None,
        Some(&target_arguments),
    )
}

#[cfg(target_os = "linux")]
pub(crate) fn run_installed_public_reuse_case(
    registration_root: &Path,
    selector: &str,
    challenge: &str,
    cli: &Path,
    cli_sha256: &DiagnosticSha256,
    contract_path: &Path,
    report_path: &Path,
    fixture_path: &Path,
    expected_plan_path: Option<&Path>,
    working_directory: &Path,
    uid: u32,
    gid: u32,
    deadline: Duration,
    expected_report: &ExpectedPublicV2Readback<'_>,
    barrier: std::os::unix::net::UnixStream,
    after_registration: Box<dyn FnOnce() -> std::io::Result<()> + Send>,
) -> Result<ObservedInstalledPublicCaseV3> {
    if selector != "private_tcp::retirement_failure_blocks_reuse" {
        return Err(CiError::Message("public reuse selector differs".into()));
    }
    run_installed_public_case_inner(
        registration_root,
        selector,
        challenge,
        cli,
        cli_sha256,
        contract_path,
        report_path,
        fixture_path,
        expected_plan_path,
        None,
        working_directory,
        uid,
        gid,
        deadline,
        expected_report,
        Some(barrier),
        Some(after_registration),
        None,
    )
}

#[cfg(target_os = "linux")]
fn wait_public_child_bounded(child: &mut std::process::Child) -> Result<std::process::ExitStatus> {
    let started = std::time::Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if started.elapsed() >= Duration::from_secs(100) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(CiError::Message(
                "public reuse root child exceeded deadline".into(),
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(target_os = "linux")]
fn run_installed_public_case_inner(
    registration_root: &Path,
    selector: &str,
    challenge: &str,
    cli: &Path,
    cli_sha256: &DiagnosticSha256,
    contract_path: &Path,
    report_path: &Path,
    fixture_path: &Path,
    expected_plan_path: Option<&Path>,
    frozen_contract_path: Option<&Path>,
    working_directory: &Path,
    uid: u32,
    gid: u32,
    deadline: Duration,
    expected_report: &ExpectedPublicV2Readback<'_>,
    reuse_barrier: Option<std::os::unix::net::UnixStream>,
    after_registration: Option<Box<dyn FnOnce() -> std::io::Result<()> + Send>>,
    target_arguments: Option<&[std::ffi::OsString]>,
) -> Result<ObservedInstalledPublicCaseV3> {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::sync::{Arc, Mutex};

    if uid == 0 || gid == 0 || expected_report.report_owner_uid != uid || deadline.is_zero() {
        return Err(CiError::Message(
            "public case caller is not a fixed nonroot principal".into(),
        ));
    }
    pinned_root_executable(cli, cli_sha256)?;
    let gate_exe = std::env::current_exe()?;
    let gate_metadata = std::fs::metadata(&gate_exe)?;
    if !gate_metadata.is_file() || gate_metadata.nlink() != 1 || gate_metadata.mode() & 0o022 != 0 {
        return Err(CiError::Message(
            "public child gate executable is mutable".into(),
        ));
    }
    let gate_identity = (gate_metadata.dev(), gate_metadata.ino());
    let mut argv = public_v2_argv_with_expected_plan(
        contract_path,
        report_path,
        fixture_path,
        expected_plan_path,
    )?;
    if let Some(arguments) = target_arguments {
        if selector != memcordon_core::private_public_abi_composite_v1::PUBLIC_ABI_SELECTOR_V1
            || arguments.len() != 3
            || arguments[0].as_os_str() != std::ffi::OsStr::new("public-abi-filtered-target")
            || arguments[1].as_os_str() != std::ffi::OsStr::new("--challenge")
            || arguments[2].as_os_str() != std::ffi::OsStr::new(challenge)
        {
            return Err(CiError::Message(
                "public ABI target arguments differ".into(),
            ));
        }
        argv.extend_from_slice(arguments);
    }
    if reuse_barrier.is_some() {
        let command_boundary = argv
            .iter()
            .position(|argument| argument == "--")
            .ok_or_else(|| CiError::Message("public reuse argv boundary absent".into()))?;
        argv.insert(
            command_boundary,
            std::ffi::OsString::from("--reuse-private-two-attempts"),
        );
    }
    if let Some(path) = frozen_contract_path {
        if !path.starts_with("/run/memcordon-final-public/")
            || path == contract_path
            || path == report_path
            || path == fixture_path
            || expected_plan_path.is_none()
        {
            return Err(CiError::Message(
                "frozen public contract path differs".into(),
            ));
        }
        argv.splice(
            5..5,
            [
                std::ffi::OsString::from("--frozen-private-contract"),
                path.as_os_str().to_owned(),
            ],
        );
    }
    let mut argv_binding = b"memcordon/public-child-argv/v1\0".to_vec();
    argv_binding.extend_from_slice(&(argv.len() as u32).to_le_bytes());
    for argument in &argv {
        let bytes = argument.as_os_str().as_bytes();
        argv_binding.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        argv_binding.extend_from_slice(bytes);
    }
    let argv_sha256 = hash_bytes(&argv_binding);
    let working_directory_sha256 = hash_bytes(working_directory.as_os_str().as_bytes());
    let observed = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&observed);
    let (gate_reader, mut gate_writer) = UnixStream::pair()?;
    let reader_fd = gate_reader.as_raw_fd();
    let writer_fd = gate_writer.as_raw_fd();
    let reuse_fd = reuse_barrier.as_ref().map(|barrier| barrier.as_raw_fd());
    let mut command = std::process::Command::new(&gate_exe);
    command
        .args(["public-child-gate", "--fd", "3", "--working-directory"])
        .arg(working_directory)
        .arg("--cli")
        .arg(cli)
        .arg("--")
        .args(&argv)
        .current_dir(registration_root)
        .env_clear()
        .stdin(std::process::Stdio::null());
    unsafe {
        command.pre_exec(move || {
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setresgid(gid, gid, gid) != 0
                || libc::setresuid(uid, uid, uid) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if libc::dup2(reader_fd, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if writer_fd != 3 {
                libc::close(writer_fd);
            }
            if reader_fd != 3 {
                libc::close(reader_fd);
            }
            if let Some(fd) = reuse_fd {
                if fd == 3 || libc::dup2(fd, 4) < 0 || libc::fcntl(4, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if fd != 4 {
                    libc::close(fd);
                }
            }
            Ok(())
        });
    }
    let registration_root = registration_root.to_path_buf();
    let selector = selector.to_owned();
    let challenge = challenge.to_owned();
    let close_child_barrier_after_spawn = reuse_barrier;
    let output = memcordon_testkit::run_with_deadline_after_output_limit(
        &mut command,
        deadline,
        1024 * 1024,
        move |pid| {
            // The root parent must not retain the child's FD4 endpoint:
            // otherwise a crashed child could mask EOF on the control socket.
            drop(close_child_barrier_after_spawn);
            // spawn() can return while the child is still completing its
            // credential transition and pre-exec hook. The pipe keeps it
            // unable to run the CLI, so wait briefly for the exact gate
            // image and nonroot credentials before registration.
            let started = std::time::Instant::now();
            let identity = loop {
                match observe_public_child(pid, gate_identity, uid, gid) {
                    Ok(identity) => break identity,
                    Err(error) if started.elapsed() < Duration::from_secs(2) => {
                        std::thread::sleep(Duration::from_millis(10));
                        let _ = error;
                    }
                    Err(error) => return Err(error),
                }
            };
            let pid_text = pid.to_string();
            let start_text = identity.start_time_ticks.to_string();
            let response = crate::command::CommandSpec::new(
                "/usr/libexec/memcordon-sealed-agent",
                &registration_root,
                Duration::from_secs(30),
            )
            .remove_github_token()
            .args([
                "package",
                "register-public-release-case",
                "--selector",
                selector.as_str(),
                "--challenge",
                challenge.as_str(),
                "--pid",
                pid_text.as_str(),
                "--start-time-ticks",
                start_text.as_str(),
            ])
            .run()
            .map_err(|error| std::io::Error::other(error.to_string()))?;
            if response.len() > 16 * 1024 {
                return Err(std::io::Error::other(
                    "public provider registration response exceeds bound",
                ));
            }
            if let Some(start) = after_registration {
                start()?;
            }
            gate_writer.write_all(&[0xa5])?;
            *slot
                .lock()
                .map_err(|_| std::io::Error::other("public child observation lock failed"))? =
                Some(identity);
            Ok(())
        },
    )?;
    if output.stdout.len() > 1024 * 1024 || output.stderr.len() > 1024 * 1024 {
        return Err(CiError::Message("public CLI output exceeds bound".into()));
    }
    let child = observed
        .lock()
        .map_err(|_| CiError::Message("public child observation lock failed".into()))?
        .ok_or_else(|| CiError::Message("public child identity was not observed".into()))?;
    let process = SupervisedProcessV2 {
        status: output.status,
        stdout: output.stdout,
        stderr: output.stderr,
        linux_child: Some(child),
    };
    let (report, report_bytes) = if matches!(
        expected_report.outcome,
        crate::private_public_v2::ExpectedPublicV2Outcome::FrontendLost
    ) {
        let absent = matches!(std::fs::symlink_metadata(report_path), Err(error) if error.kind() == std::io::ErrorKind::NotFound);
        if process.status.success() || !absent {
            return Err(CiError::Message(
                "frontend-loss report was present or child succeeded".into(),
            ));
        }
        (None, None)
    } else {
        let report = read_structural_public_v2_report(report_path, &process, expected_report)?;
        let report_bytes = crate::private_public_v2::read_public_v2_report_bytes(report_path, uid)?;
        if hash_bytes(&report_bytes) != report.report_sha256 {
            return Err(CiError::Message(
                "public report changed after supervised readback".into(),
            ));
        }
        (Some(report), Some(report_bytes))
    };
    let stdio_bytes = canonical_public_stdio_v1(
        child.pid,
        child.start_time_ticks,
        process.status.into_raw(),
        &process.stdout,
        &process.stderr,
    )?;
    Ok(ObservedInstalledPublicCaseV3 {
        process,
        report,
        report_bytes,
        stdio_bytes,
        cli_sha256: cli_sha256.clone(),
        argv_sha256,
        working_directory_sha256,
    })
}
