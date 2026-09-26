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
    if rustix::process::geteuid().is_root()
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
    if memcordon_platform::test_support::private_public_gate_byte(fd)? != 0xa5 {
        return Err(CiError::Message(
            "public child gate was not registered".into(),
        ));
    }
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
    pub dual_report: Option<crate::private_public_v2::StructuralPublicDualV12Readback>,
    pub report_bytes: Option<Vec<u8>>,
    pub stdio_bytes: Vec<u8>,
    pub cli_sha256: DiagnosticSha256,
    pub argv_sha256: DiagnosticSha256,
    pub working_directory_sha256: DiagnosticSha256,
    pub live_samples: std::collections::BTreeMap<String, Vec<u8>>,
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
pub(crate) fn read_public_fixture(path: &Path, expected: &DiagnosticSha256) -> Result<Vec<u8>> {
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
    fault_trigger_sha256: Option<DiagnosticSha256>,
    fault_failure_sha256: Option<DiagnosticSha256>,
    fault_retirement_sha256: Option<DiagnosticSha256>,
    fault_recovery_sha256: Option<DiagnosticSha256>,
    checkpoint_committed_sha256: Option<DiagnosticSha256>,
    release_intent_sha256: Option<DiagnosticSha256>,
    execution_observed_sha256: Option<DiagnosticSha256>,
    cgroup_retirement_sha256: Option<DiagnosticSha256>,
    phase: String,
}

impl ProviderAttemptRecordV2 {
    fn retained_phase_leaves(&self) -> [(&str, Option<&DiagnosticSha256>); 8] {
        [
            ("fault-trigger-v1.json", self.fault_trigger_sha256.as_ref()),
            ("fault-failure-v1.json", self.fault_failure_sha256.as_ref()),
            (
                "fault-retirement-v1.json",
                self.fault_retirement_sha256.as_ref(),
            ),
            (
                "fault-recovery-v1.json",
                self.fault_recovery_sha256.as_ref(),
            ),
            (
                "checkpoint-committed-v4.bin",
                self.checkpoint_committed_sha256.as_ref(),
            ),
            ("release-intent-v4.bin", self.release_intent_sha256.as_ref()),
            (
                "execution-observed-v4.bin",
                self.execution_observed_sha256.as_ref(),
            ),
            (
                "cgroup-retirement-v1.json",
                self.cgroup_retirement_sha256.as_ref(),
            ),
        ]
    }
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
    pub(crate) namespace_init: ProviderProcessIdentityV1,
    pub(crate) network_namespace_inode: u64,
    pub(crate) entrypoint_sha256: DiagnosticSha256,
    pub(crate) entrypoint_device: u64,
    pub(crate) entrypoint_inode: u64,
    pub(crate) entrypoint_path: String,
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

pub(crate) struct StructuralProviderAttemptV2 {
    pub(crate) phase: String,
    pub(crate) response_kind: u16,
    pub(crate) attempt_id: String,
    pub(crate) request_bytes: Vec<u8>,
    pub(crate) response_bytes: Vec<u8>,
    pub(crate) terminal_bytes: Option<Vec<u8>>,
    pub(crate) cleanup_bytes: Option<Vec<u8>>,
    pub(crate) target_identity_bytes: Option<Vec<u8>>,
    pub(crate) checkpoint_bytes: Option<Vec<u8>>,
    pub(crate) gated_attempt_bytes: Option<Vec<u8>>,
    pub(crate) phase_leaves: std::collections::BTreeMap<String, Vec<u8>>,
    pub(crate) target_identity: Option<ProviderTargetIdentityV1>,
    pub(crate) fault: Option<crate::private_public_fault::ValidatedPublicFaultV2>,
}

#[cfg(unix)]
pub(crate) struct OwnedPublicRawAttachmentV2 {
    pub(crate) role: memcordon_core::private_release_case_v1::PrivateReleaseAttachmentRoleV1,
    pub(crate) bytes: Vec<u8>,
}

#[cfg(unix)]
pub(crate) fn collect_public_raw_attachments(
    selector: &str,
    observed: &ObservedInstalledPublicCaseV3,
    provider: &StructuralProviderFrameReadbackV2,
    interval: &crate::private_kernel_observer::VerifiedKernelIntervalV1,
) -> Result<Vec<OwnedPublicRawAttachmentV2>> {
    collect_public_raw_attachments_with_observer_bound(
        selector,
        observed,
        provider,
        interval,
        memcordon_core::private_release_case_v1::MAX_PRIVATE_RELEASE_ATTACHMENT_BYTES_V1,
    )
}

/// Explicit V3 budget. Only the original public physical observer capture
/// gains the reviewed 100,000-event bound; legacy V2 and all other roles keep
/// their existing small limits.
#[cfg(unix)]
pub(crate) fn collect_public_raw_attachments_v3(
    selector: &str,
    observed: &ObservedInstalledPublicCaseV3,
    provider: &StructuralProviderFrameReadbackV2,
    interval: &crate::private_kernel_observer::VerifiedKernelIntervalV1,
) -> Result<Vec<OwnedPublicRawAttachmentV2>> {
    collect_public_raw_attachments_with_observer_bound(
        selector,
        observed,
        provider,
        interval,
        memcordon_core::private_public_case_v2::MAX_FINAL_PUBLIC_OBSERVER_BYTES_V3,
    )
}

#[cfg(unix)]
fn collect_public_raw_attachments_with_observer_bound(
    selector: &str,
    observed: &ObservedInstalledPublicCaseV3,
    provider: &StructuralProviderFrameReadbackV2,
    interval: &crate::private_kernel_observer::VerifiedKernelIntervalV1,
    observer_bound: u64,
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
            "phase":attempt.phase,
            "response_kind":attempt.response_kind,
            "request_bytes": attempt.request_bytes,
            "response_bytes": attempt.response_bytes,
            "terminal_bytes": attempt.terminal_bytes,
            "provider_cleanup_bytes": attempt.cleanup_bytes,
            "target_identity_bytes": attempt.target_identity_bytes,
            "checkpoint_bytes": attempt.checkpoint_bytes,
            "gated_attempt_bytes": attempt.gated_attempt_bytes,
            "phase_leaves": attempt.phase_leaves,
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
                > if item.role == Role::Observer {
                    observer_bound
                } else {
                    memcordon_core::private_release_case_v1::MAX_PRIVATE_RELEASE_ATTACHMENT_BYTES_V1
                }
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
    if !matches!(record.schema_version, 2 | 3)
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
        || if record.schema_version == 3 {
            !record
                .inflight
                .as_ref()
                .is_some_and(|value| value.as_array().is_some_and(Vec::is_empty))
        } else {
            record.inflight.is_some()
        }
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
    let fault_selector = matches!(
        expected_selector,
        "private_tcp::authorization_uncertainty_retired"
            | "private_tcp::frontend_loss_retired"
            | "private_tcp::guardian_loss_retired"
    );
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
            } else if fault_selector {
                record.schema_version != 3
                    || !matches!(
                        attempt.phase.as_str(),
                        "fault-retired-observed" | "fault-recovered-after-incomplete"
                    )
                    || attempt.fault_trigger_sha256.is_none()
                    || attempt.cleanup_sha256.is_none()
                    || attempt.target_identity_sha256.is_none()
                    || attempt.checkpoint_committed_sha256.is_none()
                    || attempt.release_intent_sha256.is_none()
                    || attempt.terminal_sha256.is_some() != (attempt.launch_response_kind == 105)
                    || attempt.phase == "fault-retired-observed"
                        && attempt.fault_retirement_sha256.is_none()
                    || attempt.phase == "fault-recovered-after-incomplete"
                        && (attempt.fault_failure_sha256.is_none()
                            || attempt.fault_recovery_sha256.is_none()
                            || attempt.launch_response_kind != 106)
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
        if fault_selector && attempt.launch_response_kind != 105 {
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
            let checkpoint_name = format!(
                "{prefix}{}",
                if record.schema_version == 3 {
                    "gated-attempt-v4.bin"
                } else {
                    "checkpoint-v4.bin"
                }
            );
            if let Some((_, checkpoint)) = leaves.iter().find(|(name, _)| *name == checkpoint_name)
            {
                let identity_name = format!("{prefix}target-identity.json");
                let identity_bytes = leaves
                    .iter()
                    .find_map(|(name, bytes)| (*name == identity_name).then_some(*bytes))
                    .ok_or_else(|| {
                        crate::CiError::Message("checkpoint lacks target identity".into())
                    })?;
                reject_duplicate_json_keys(identity_bytes).map_err(crate::CiError::Message)?;
                let identity: ProviderTargetIdentityV1 = serde_json::from_slice(identity_bytes)?;
                if hash_bytes(checkpoint) != identity.durable_attempt_record_sha256 {
                    return Err(crate::CiError::Message(
                        "provider checkpoint exact bytes differ".into(),
                    ));
                }
                // Legacy V2 diagnostics without a checkpoint remain structural;
                // production readback independently requires this actual leaf.
                expected.push((checkpoint_name, None));
            }
        }
        for (leaf, digest) in attempt.retained_phase_leaves() {
            if let Some(digest) = digest {
                expected.push((format!("{prefix}{leaf}"), Some(digest)));
            }
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
            || match digest {
                Some(digest) => *digest == zero || hash_bytes(bytes) != *digest,
                None => {
                    !expected_name.ends_with("/checkpoint-v4.bin")
                        && !expected_name.ends_with("/gated-attempt-v4.bin")
                }
            }
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

/// Portable structural decoding only. The self-described frame expectations
/// do not grant authority: specialist callers must independently join the
/// resulting diagnostics to protected recipes and authenticated origin.
pub(crate) fn parse_structural_provider_case_from_leaves(
    record_bytes: &[u8],
    leaves: &std::collections::BTreeMap<String, Vec<u8>>,
) -> Result<StructuralProviderFrameReadbackV2> {
    let record: ProviderFrameRecordV2 =
        crate::private_observer_session::strict_json(record_bytes, 128 * 1024)?;
    // The wire validator has a fixed role order; lexical map order is not
    // that protocol order. A separately archived registry is independently
    // bound to the decision below, not an extra provider-frame role.
    let names = provider_frame_leaf_names(&record);
    if leaves.len() != names.len() + usize::from(leaves.contains_key("registry.json")) {
        return Err(CiError::Message(
            "portable provider raw inventory has extra/missing roles".into(),
        ));
    }
    let views = names
        .iter()
        .map(|name| {
            leaves
                .get(name)
                .map(|bytes| (name.as_str(), bytes.as_slice()))
                .ok_or_else(|| CiError::Message(format!("provider original frame absent: {name}")))
        })
        .collect::<Result<Vec<_>>>()?;
    validate_provider_frame_record_v2(
        record_bytes,
        &views,
        &record.selector,
        &record.challenge,
        &record.result_key,
        &record.contract_digest,
        (
            record.peer_pid,
            record.peer_start_time_ticks,
            record.peer_uid,
            record.peer_gid,
        ),
        (
            &record.installation_epoch,
            &record.manifest_sha256,
            &record.qualification_sha256,
            &record.active_h1_receipt_sha256,
        ),
    )?;
    let get = |name: &str| -> Result<Vec<u8>> {
        leaves
            .get(name)
            .cloned()
            .ok_or_else(|| CiError::Message(format!("provider exact raw role absent: {name}")))
    };
    let mut attempts = Vec::new();
    for attempt in &record.attempts {
        let prefix = std::path::Path::new(&format!("{}-{}", attempt.ordinal, attempt.attempt_id))
            .to_path_buf();
        let read = |name: &str| get(&prefix.join(name).to_string_lossy());
        let request_bytes = read("request.bin")?;
        let response_bytes = read("response.bin")?;
        let target_identity_bytes = attempt
            .target_identity_sha256
            .as_ref()
            .map(|_| read("target-identity.json"))
            .transpose()?;
        let target_identity: Option<ProviderTargetIdentityV1> = target_identity_bytes
            .as_ref()
            .map(|bytes| crate::private_observer_session::strict_json(bytes, 128 * 1024))
            .transpose()?;
        let gated_attempt_bytes = target_identity
            .as_ref()
            .map(|identity| -> Result<Vec<u8>> {
                let raw = read(if record.schema_version == 3 {
                    "gated-attempt-v4.bin"
                } else {
                    "checkpoint-v4.bin"
                })?;
                if hash_bytes(&raw) != identity.durable_attempt_record_sha256 {
                    return Err(CiError::Message(
                        "provider gated durable bytes differ".into(),
                    ));
                }
                Ok(raw)
            })
            .transpose()?;
        let phase_leaves = attempt
            .retained_phase_leaves()
            .into_iter()
            .filter_map(|(name, hash)| hash.map(|_| name))
            .map(|name| Ok((name.into(), read(name)?)))
            .collect::<Result<std::collections::BTreeMap<String, Vec<u8>>>>()?;
        let checkpoint_bytes = phase_leaves.get("checkpoint-committed-v4.bin").cloned();
        if let Some(bytes) = &checkpoint_bytes {
            let snapshot: serde_json::Value =
                crate::private_observer_session::strict_json(bytes, 1024 * 1024)?;
            if snapshot.get("phase").and_then(serde_json::Value::as_str)
                != Some("checkpoint-committed")
                || snapshot
                    .get("attempt_id")
                    .and_then(serde_json::Value::as_str)
                    != Some(attempt.attempt_id.as_str())
                || snapshot
                    .get("checkpoint")
                    .is_none_or(serde_json::Value::is_null)
                || snapshot
                    .get("checkpoint_digest")
                    .is_none_or(serde_json::Value::is_null)
            {
                return Err(CiError::Message(
                    "provider actual committed snapshot differs".into(),
                ));
            }
        }
        let cleanup_bytes = attempt
            .cleanup_sha256
            .as_ref()
            .map(|_| read("cleanup.bin"))
            .transpose()?;
        let terminal_bytes = attempt
            .terminal_sha256
            .as_ref()
            .map(|_| read("terminal.bin"))
            .transpose()?;
        let fault = if attempt.fault_trigger_sha256.is_some() {
            let identity = target_identity
                .as_ref()
                .ok_or_else(|| CiError::Message("provider fault target identity absent".into()))?;
            let durable: serde_json::Value = crate::private_observer_session::strict_json(
                checkpoint_bytes.as_ref().ok_or_else(|| {
                    CiError::Message("provider fault actual committed snapshot absent".into())
                })?,
                1024 * 1024,
            )?;
            Some(crate::private_public_fault::validate_public_fault_attempt(
                &record.selector,
                &record.result_key,
                &attempt.attempt_id,
                &attempt.phase,
                &request_bytes,
                &response_bytes,
                attempt.launch_response_kind,
                checkpoint_bytes
                    .as_ref()
                    .expect("required committed fault snapshot"),
                cleanup_bytes.as_ref().ok_or_else(|| {
                    CiError::Message("provider actual fault cleanup absent".into())
                })?,
                &phase_leaves,
                &crate::private_public_fault::FaultProcessV1 {
                    pid: identity.target.pid,
                    start_time: identity.target.start_time,
                },
                durable
                    .get("boot_identity")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| CiError::Message("provider actual fault boot absent".into()))?,
            )?)
        } else {
            None
        };
        attempts.push(StructuralProviderAttemptV2 {
            phase: attempt.phase.clone(),
            response_kind: attempt.launch_response_kind,
            attempt_id: attempt.attempt_id.clone(),
            request_bytes,
            response_bytes,
            terminal_bytes,
            cleanup_bytes,
            target_identity_bytes,
            checkpoint_bytes,
            gated_attempt_bytes,
            phase_leaves,
            target_identity,
            fault,
        });
    }
    let registry_bytes = leaves.get("registry.json").cloned();
    let registry_digest = registry_bytes
        .as_ref()
        .map(|bytes| -> Result<DiagnosticSha256> {
            let registry: memcordon_core::workload_registry_v2::PolicyRegistryV2 =
                crate::private_observer_session::strict_json(bytes, 1024 * 1024)?;
            registry.canonical_digest().map_err(CiError::Message)
        })
        .transpose()?;
    if let Some(digest) = &registry_digest {
        let decision: ProviderGrantDecisionV1 =
            crate::private_observer_session::strict_json(&get("grant-decision.json")?, 128 * 1024)?;
        if digest != &decision.registry_digest {
            return Err(CiError::Message(
                "portable original registry differs from grant decision".into(),
            ));
        }
    }
    Ok(StructuralProviderFrameReadbackV2 {
        result_key: record.result_key,
        record_bytes: record_bytes.to_vec(),
        policy_branch: record.policy_branch,
        phase: record.phase,
        request_bytes: get("request.bin")?,
        plan_response_bytes: get("plan-response.bin")?,
        grant_decision_bytes: get("grant-decision.json")?,
        registry_digest,
        registry_bytes,
        terminal_bytes: leaves.get("terminal.bin").cloned(),
        attempts,
    })
}

/// Portable byte validation only. It grants no process, origin, release or P
/// authority, and is useful for auditing an archived original source map.
pub fn validate_detached_public_provider_sources(
    record: &[u8],
    leaves: &std::collections::BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    parse_structural_provider_case_from_leaves(record, leaves).map(|_| ())
}

pub(crate) fn public_provider_source_leaf_names(bytes: &[u8]) -> Result<Vec<String>> {
    let record: ProviderFrameRecordV2 =
        crate::private_observer_session::strict_json(bytes, 1024 * 1024)?;
    Ok(provider_frame_leaf_names(&record))
}

fn provider_frame_leaf_names(record: &ProviderFrameRecordV2) -> Vec<String> {
    let mut names = vec![
        "plan-request.bin".into(),
        "request.bin".into(),
        "plan-response.bin".into(),
        "grant-decision.json".into(),
    ];
    if record.phase == "plan-rejected" {
        names.push("terminal.bin".into());
    }
    for attempt in &record.attempts {
        let prefix = std::path::Path::new(&format!("{}-{}", attempt.ordinal, attempt.attempt_id))
            .to_path_buf();
        let mut push = |leaf: &str| names.push(prefix.join(leaf).to_string_lossy().into_owned());
        push("request.bin");
        push("response.bin");
        if attempt.launch_response_kind == 105 {
            push("terminal.bin");
            push("cleanup.bin");
        } else if attempt.cleanup_sha256.is_some() {
            push("cleanup.bin");
        }
        if attempt.target_identity_sha256.is_some() {
            push("target-identity.json");
            push(if record.schema_version == 3 {
                "gated-attempt-v4.bin"
            } else {
                "checkpoint-v4.bin"
            });
        }
        for (leaf, digest) in attempt.retained_phase_leaves() {
            if digest.is_some() {
                push(leaf);
            }
        }
    }
    names
}

/// Native readback of original immutable provider sources. This is not a
/// verified public case: independent replay still binds the caller, grant,
/// host, target facts and kernel interval to its separately approved recipe.
#[cfg(target_os = "linux")]
pub(crate) fn read_original_public_provider_sources(
    selector: &str,
    challenge: &str,
    key: &DiagnosticSha256,
) -> Result<(Vec<u8>, std::collections::BTreeMap<String, Vec<u8>>)> {
    let directory =
        Path::new("/var/lib/memcordon/sealed/private-public-cases").join(String::from(key.clone()));
    let bytes = crate::private_protected_readback::read_protected_raw_case_file(
        &directory.join("provider.json"),
    )?;
    let record: ProviderFrameRecordV2 =
        crate::private_observer_session::strict_json(&bytes, 128 * 1024)?;
    if record.selector != selector || record.challenge != challenge || &record.result_key != key {
        return Err(CiError::Message(
            "public native provider source belongs to another case".into(),
        ));
    }
    let verified = crate::command::CommandSpec::new(
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
        challenge,
        "--json",
    ])
    .run()?;
    if verified.strip_suffix(b"\n") != Some(bytes.as_slice()) {
        return Err(CiError::Message(
            "public provider immutable command readback differs".into(),
        ));
    }
    let mut leaves = std::collections::BTreeMap::new();
    for name in provider_frame_leaf_names(&record) {
        leaves.insert(
            name.clone(),
            crate::private_protected_readback::read_protected_raw_case_file(&directory.join(name))?,
        );
    }
    let decision: ProviderGrantDecisionV1 = crate::private_observer_session::strict_json(
        leaves
            .get("grant-decision.json")
            .expect("fixed source role"),
        128 * 1024,
    )?;
    let registry = Path::new("/var/lib/memcordon/policy")
        .join(String::from(decision.registry_digest))
        .with_extension("snapshot");
    leaves.insert(
        "registry.json".into(),
        crate::private_protected_readback::read_protected_raw_case_file(&registry)?,
    );
    parse_structural_provider_case_from_leaves(&bytes, &leaves)?;
    Ok((bytes, leaves))
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
        if attempt.launch_response_kind == 105 {
            names.push(format!("{prefix}terminal.bin"));
            names.push(format!("{prefix}cleanup.bin"));
        } else if attempt.cleanup_sha256.is_some() {
            names.push(format!("{prefix}cleanup.bin"));
        }
        if attempt.target_identity_sha256.is_some() {
            names.push(format!("{prefix}target-identity.json"));
            names.push(format!(
                "{prefix}{}",
                if record.schema_version == 3 {
                    "gated-attempt-v4.bin"
                } else {
                    "checkpoint-v4.bin"
                }
            ));
        }
        for (leaf, digest) in attempt.retained_phase_leaves() {
            if digest.is_some() {
                names.push(format!("{prefix}{leaf}"));
            }
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
        let (terminal_bytes, cleanup_bytes) = if attempt.launch_response_kind == 105 {
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
        let (terminal_bytes, cleanup_bytes) =
            if attempt.fault_trigger_sha256.is_some() && attempt.launch_response_kind != 105 {
                (None, Some(read("cleanup.bin")?))
            } else {
                (terminal_bytes, cleanup_bytes)
            };
        let mut checkpoint_bytes = None;
        let mut gated_attempt_bytes = None;
        let (target_identity_bytes, target_identity) = if attempt.target_identity_sha256.is_some() {
            let bytes = read("target-identity.json")?;
            let identity: ProviderTargetIdentityV1 = serde_json::from_slice(&bytes)?;
            let checkpoint = read(if record.schema_version == 3 {
                "gated-attempt-v4.bin"
            } else {
                "checkpoint-v4.bin"
            })?;
            memcordon_core::workload_contract::reject_duplicate_json_keys(&checkpoint)
                .map_err(CiError::Message)?;
            let record: serde_json::Value = serde_json::from_slice(&checkpoint)?;
            if hash_bytes(&checkpoint) != identity.durable_attempt_record_sha256
                || record.get("attempt_id").and_then(serde_json::Value::as_str)
                    != Some(attempt.attempt_id.as_str())
                || record.get("target").is_none_or(serde_json::Value::is_null)
            {
                return Err(CiError::Message(
                    "actual public durable checkpoint differs".into(),
                ));
            }
            gated_attempt_bytes = Some(checkpoint);
            let committed = read("checkpoint-committed-v4.bin")?;
            let committed_record: serde_json::Value =
                crate::private_observer_session::strict_json(&committed, 1024 * 1024)?;
            if attempt.checkpoint_committed_sha256.as_ref() != Some(&hash_bytes(&committed))
                || committed_record
                    .get("phase")
                    .and_then(serde_json::Value::as_str)
                    != Some("checkpoint-committed")
                || committed_record
                    .get("attempt_id")
                    .and_then(serde_json::Value::as_str)
                    != Some(attempt.attempt_id.as_str())
                || committed_record
                    .get("checkpoint")
                    .is_none_or(serde_json::Value::is_null)
                || committed_record
                    .get("checkpoint_digest")
                    .is_none_or(serde_json::Value::is_null)
            {
                return Err(CiError::Message(
                    "actual public committed checkpoint file differs".into(),
                ));
            }
            checkpoint_bytes = Some(committed);
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
        let phase_leaves = attempt
            .retained_phase_leaves()
            .into_iter()
            .filter_map(|(name, digest)| digest.map(|_| name))
            .map(|name| Ok((name.to_owned(), read(name)?)))
            .collect::<Result<std::collections::BTreeMap<_, _>>>()?;
        let fault = if attempt.fault_trigger_sha256.is_some() {
            let identity = target_identity
                .as_ref()
                .ok_or_else(|| CiError::Message("public fault target identity absent".into()))?;
            Some(crate::private_public_fault::validate_public_fault_attempt(
                selector,
                &key,
                &attempt.attempt_id,
                &attempt.phase,
                &request_bytes,
                &response_bytes,
                attempt.launch_response_kind,
                checkpoint_bytes
                    .as_deref()
                    .ok_or_else(|| CiError::Message("public fault checkpoint absent".into()))?,
                cleanup_bytes
                    .as_deref()
                    .ok_or_else(|| CiError::Message("public fault cleanup absent".into()))?,
                &phase_leaves,
                &crate::private_public_fault::FaultProcessV1 {
                    pid: identity.target.pid,
                    start_time: identity.target.start_time,
                },
                host.boot_id(),
            )?)
        } else {
            None
        };
        attempts.push(StructuralProviderAttemptV2 {
            phase: attempt.phase.clone(),
            response_kind: attempt.launch_response_kind,
            attempt_id: attempt.attempt_id.clone(),
            request_bytes,
            response_bytes,
            terminal_bytes,
            cleanup_bytes,
            target_identity_bytes,
            checkpoint_bytes,
            gated_attempt_bytes,
            phase_leaves,
            target_identity,
            fault,
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
pub(crate) fn join_public_provider_kernel(
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
    let preexec=provider.attempts.iter().filter(|attempt|attempt.fault.as_ref().is_some_and(|fault|
        fault.knowledge==memcordon_core::private_release_case_v1::PrivateReleaseKnowledgeV1::PossiblyReleased
        && fault.exec==memcordon_core::private_release_case_v1::PrivateReleaseExecV1::NotObserved))
        .map(|attempt|attempt.attempt_id.clone()).collect();
    let joined = crate::private_public_kernel_join::join_public_case_kernel_targets_v2(
        interval,
        clock,
        &provider.result_key,
        &targets,
        &preexec,
    )?;
    if joined.capture_sha256() != interval.trace_sha256() || joined.target_count() != targets.len()
    {
        return Err(CiError::Message(
            "public protected target inventory differs from kernel".into(),
        ));
    }
    Ok(joined)
}

#[cfg(unix)]
pub(crate) fn compose_public_case_observation(
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
                let checkpoint = attempt.checkpoint_bytes.as_ref().ok_or_else(|| {
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
                if provider.attempts.len() != 2 {
                    return Err(CiError::Message(
                        "dual provider exact attempt count differs".into(),
                    ));
                }
                let reports = observed.dual_report.as_ref().ok_or_else(|| {
                    CiError::Message(
                        "dual case has no actual schema12 two-terminal readback".into(),
                    )
                })?;
                if observed.report.is_some()
                    || observed
                        .report_bytes
                        .as_ref()
                        .is_none_or(|bytes| hash_bytes(bytes) != reports.report_sha256)
                {
                    return Err(CiError::Message(
                        "dual case replaced actual two-terminal report with scalar projection"
                            .into(),
                    ));
                }
                for (ordinal, attempt) in provider.attempts.iter().enumerate() {
                    let public = &reports.attempts[ordinal];
                    if public.ordinal as usize != ordinal
                        || public.raw_response != attempt.response_bytes
                        || public.terminal.attempt.attempt_id.as_str() != attempt.attempt_id
                        || attempt.terminal_bytes.as_ref() != Some(&public.raw_response)
                    {
                        return Err(CiError::Message("dual original public terminal/response differs from exact protected attempt".into()));
                    }
                }
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
                if matches!(
                    selector,
                    "private_tcp::authorization_uncertainty_retired"
                        | "private_tcp::frontend_loss_retired"
                        | "private_tcp::guardian_loss_retired"
                ) {
                    return Err(CiError::Message("public fault requires actual authenticated phase/fault/recovery evidence; a normal Terminal cannot establish it".into()));
                }
                let outcome = Outcome::TargetCompleted;
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

/// The V3 path preserves real rejected fault responses and later recovery.
/// Legacy V2 serialization deliberately does not accept this new variant.
#[cfg(unix)]
pub(crate) fn compose_public_fault_observation_v2(
    selector: &str,
    provider: &StructuralProviderFrameReadbackV2,
    observed: &ObservedInstalledPublicCaseV3,
    interval: &crate::private_kernel_observer::VerifiedKernelIntervalV1,
    joined: &crate::private_public_kernel_join::VerifiedPublicCaseKernelJoinV1,
    clock: &crate::private_process_clock::VerifiedProcClockCalibrationV1,
) -> Result<memcordon_core::private_release_case_v1::PrivateReleaseObservationV1> {
    use crate::private_kernel_observer::KernelEventV1;
    use memcordon_core::private_release_case_v1::{
        PrivateReleaseAllocatedOutcomeV1 as Outcome, PrivateReleaseObservationV1 as O,
        PrivateReleaseStageV1, validate_release_observation_v1,
    };
    if provider.phase != "launch-exchanges-complete"
        || provider.attempts.len() != 1
        || joined.target_count() != 1
        || joined.capture_sha256() != interval.trace_sha256()
    {
        return Err(CiError::Message(
            "public actual fault lacks exact settled kernel attempt".into(),
        ));
    }
    let attempt = &provider.attempts[0];
    let fault = attempt.fault.as_ref().ok_or_else(|| {
        CiError::Message("public fault has no actual protected trigger/settlement".into())
    })?;
    if fault.outcome == Outcome::FrontendLost {
        use std::os::unix::process::ExitStatusExt;
        let caller = observed.process.linux_child.ok_or_else(|| {
            CiError::Message("frontend fault lacks original supervisor child identity".into())
        })?;
        if caller.pid != fault.victim.pid
            || caller.start_time_ticks != fault.victim.start_time
            || observed.process.status.signal() != Some(libc::SIGKILL)
            || observed.report_bytes.is_some()
            || observed.live_samples.is_empty()
        {
            return Err(CiError::Message(
                "frontend fault did not kill the exact supervised CLI after live sampling".into(),
            ));
        }
    } else if fault.outcome == Outcome::GuardianLost {
        if !interval.events().iter().any(|event|matches!(event,KernelEventV1::Exit {task,signal}
            if task.pid==fault.victim.pid && clock.matches(*task,fault.victim.start_time) && *signal==libc::SIGKILL)) {
            return Err(CiError::Message("guardian fault exact live victim exit is absent from kernel interval".into()));
        }
    }
    let checkpoint = attempt
        .checkpoint_bytes
        .as_deref()
        .ok_or_else(|| CiError::Message("fault actual committed checkpoint file absent".into()))?;
    let observation = if fault.response_kind == 106 {
        O::PublicFaultRejectedRetiredV2 {
            outcome: fault.outcome,
            attempt_id: attempt.attempt_id.clone(),
            checkpoint_file_sha256: hash_bytes(checkpoint),
            original_rejection_sha256: hash_bytes(&attempt.response_bytes),
            fault_trigger_sha256: fault.trigger_sha256.clone(),
            fault_failure_sha256: fault.failure_sha256.clone(),
            retirement_sha256: fault.retirement_sha256.clone(),
            recovery_sha256: fault.recovery_sha256.clone(),
            release_knowledge: fault.knowledge,
            exec: fault.exec,
            native_observer_sha256: interval.trace_sha256().clone(),
        }
    } else {
        let terminal = attempt
            .terminal_bytes
            .as_ref()
            .ok_or_else(|| CiError::Message("fault original terminal receipt absent".into()))?;
        O::AllocatedRetired {
            outcome: fault.outcome,
            attempt_id: attempt.attempt_id.clone(),
            checkpoint_sha256: hash_bytes(checkpoint),
            terminal_sha256: hash_bytes(terminal),
            retirement_sha256: fault.retirement_sha256.clone(),
            release_knowledge: fault.knowledge,
            exec: fault.exec,
            native_observer_sha256: interval.trace_sha256().clone(),
        }
    };
    validate_release_observation_v1(selector, PrivateReleaseStageV1::FinalPublic, &observation)
        .map_err(CiError::Message)?;
    Ok(observation)
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

/// Structural V3 source record from the authentic live interval and original
/// provider transcript. This is not a selector-family proof or P authority.
#[cfg(target_os = "linux")]
pub(crate) fn compose_static_final_public_case_v3(
    selector: &str,
    challenge: [u8; 32],
    intent: &crate::private_public_plan::StaticPublicSuiteIntentV1,
    host: &crate::private_final_install::FinalHostReadbackV1,
    observed: &ObservedInstalledPublicCaseV3,
    provider: &StructuralProviderFrameReadbackV2,
    interval: &crate::private_kernel_observer::VerifiedKernelIntervalV1,
) -> Result<Vec<u8>> {
    use memcordon_core::private_public_case_v2::{
        FinalPublicCaseEvidenceV2, FinalPublicCaseEvidenceV3, FinalPublicChildIdentityV2,
        FinalPublicInstalledBindingV2,
    };
    let clock = interval.original_clock().ok_or_else(|| {
        CiError::Message("public V3 source original calibrated clock absent".into())
    })?;
    let composed = if matches!(
        selector,
        "private_tcp::authorization_uncertainty_retired"
            | "private_tcp::dual_attempt_namespace_isolation"
            | "private_tcp::frontend_loss_retired"
            | "private_tcp::guardian_loss_retired"
    ) {
        let scenario = intent
            .scenarios
            .iter()
            .position(|scenario| scenario.selector == selector)
            .ok_or_else(|| CiError::Message("public causal source recipe absent".into()))?;
        let samples = std::path::Path::new("cases")
            .join(scenario.to_string())
            .join("samples");
        let observation =
            crate::private_public_fault_dual_replay::compose_public_fault_dual_sources(
                selector,
                provider,
                observed,
                interval,
                clock,
                &challenge,
                intent.scenarios[scenario].recipe.port,
                host.target(),
                |origin_path| {
                    let relative = std::path::Path::new(origin_path)
                        .strip_prefix(&samples)
                        .map_err(|_| {
                            CiError::Message("public causal held image outside source case".into())
                        })?;
                    observed
                        .live_samples
                        .get(relative.to_string_lossy().as_ref())
                        .cloned()
                        .ok_or_else(|| {
                            CiError::Message("public causal original held image absent".into())
                        })
                },
            )?;
        use memcordon_core::private_public_report_v2::PublicCliReportEvidenceV2 as Report;
        let report = if let Some(bytes) = &observed.report_bytes {
            Report::Present {
                size: bytes.len() as u64,
                sha256: hash_bytes(bytes),
            }
        } else if selector == "private_tcp::frontend_loss_retired" {
            let attempt = provider.attempts.first().ok_or_else(|| {
                CiError::Message("public frontend original attempt absent".into())
            })?;
            if let Some(terminal) = &attempt.terminal_bytes {
                Report::AbsentFrontendLoss {
                    authenticated_terminal_sha256: hash_bytes(terminal),
                    supervised_transport_sha256: hash_bytes(&observed.stdio_bytes),
                    independent_recovery_sha256: interval.trace_sha256().clone(),
                }
            } else {
                let wait = observed
                    .live_samples
                    .get("supervisor/wait-v1.json")
                    .ok_or_else(|| {
                        CiError::Message(
                            "public rejected frontend actual supervisor wait absent".into(),
                        )
                    })?;
                Report::AbsentFrontendRejectedV3 {
                    original_rejection_sha256: hash_bytes(&attempt.response_bytes),
                    supervised_transport_sha256: hash_bytes(&observed.stdio_bytes),
                    supervisor_wait_sha256: hash_bytes(wait),
                    independent_recovery_sha256: interval.trace_sha256().clone(),
                }
            }
        } else {
            return Err(CiError::Message(
                "public causal original CLI report absent".into(),
            ));
        };
        report.validate_structure().map_err(CiError::Message)?;
        (observation, report, None)
    } else {
        let joined = join_public_provider_kernel(provider, interval, clock)?;
        compose_public_case_observation(selector, provider, observed, interval, &joined, None)?
    };
    let attachments = collect_public_raw_attachments_v3(selector, observed, provider, interval)?;
    let child = observed
        .process
        .linux_child
        .ok_or_else(|| CiError::Message("public V3 source supervisor child absent".into()))?;
    let result = FinalPublicCaseEvidenceV3(FinalPublicCaseEvidenceV2 {
        schema_version: 3,
        selector: selector.into(),
        challenge,
        source_commit: intent.observer_subject.source_commit.clone(),
        release_version: memcordon_core::BoundedText::new(host.version())
            .map_err(|error| CiError::Message(error.into()))?,
        target: host.target().into(),
        native_machine: host.native_machine().into(),
        build_context_sha256: intent.observer_subject.build_sha256.clone(),
        release_catalogue_sha256: intent.observer_subject.catalogue_sha256.clone(),
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
            boot_identity: memcordon_core::BoundedText::new(host.boot_id())
                .map_err(|error| CiError::Message(error.into()))?,
            uid: intent.public_uid,
            gid: intent.public_gid,
            supplementary_groups_empty: true,
            executable_sha256: observed.cli_sha256.clone(),
            argv_sha256: observed.argv_sha256.clone(),
            working_directory_sha256: observed.working_directory_sha256.clone(),
        },
        observation: composed.0,
        positive_control_terminal_sha256: composed.2,
        report: composed.1,
        attachments: attachments
            .into_iter()
            .map(
                |item| memcordon_core::private_release_case_v1::PrivateReleaseAttachmentV1 {
                    role: item.role,
                    size: item.bytes.len() as u64,
                    sha256: hash_bytes(&item.bytes),
                },
            )
            .collect(),
    });
    result.validate().map_err(CiError::Message)?;
    crate::private_observer_session::canonical_bytes(&result)
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
            child: memcordon_core::private_public_case_v2::FinalPublicChildIdentityV2 {
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
            (Some(path), Some(digest)) => {
                read_public_fixture(path, digest)?;
            }
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
            let public_cli_sha256 = &intent.public_cli_sha256;
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
                                public_cli_sha256,
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
                outer_auxiliary_key: outer.auxiliary_key.clone(),
                outer_request_sha256: outer.request_sha256.clone(),
                outer_raw_sha256: outer.raw_sha256.clone(),
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
        hex::encode(policy_composite_sha256.bytes()),
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
        None,
        None,
    )
}

/// Raw-source variant uses bounded binary held records and exact image-leaf
/// references. The path only names original source bytes, never authority.
#[cfg(target_os = "linux")]
pub(crate) fn run_installed_public_source_case(
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
    case_origin_prefix: &Path,
) -> Result<ObservedInstalledPublicCaseV3> {
    crate::private_public_raw::validate_relative_evidence_path(
        &case_origin_prefix.to_string_lossy(),
    )?;
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
        Some(case_origin_prefix.join("samples")),
        None,
    )
}

/// Source-only reuse orchestration retains the actual target holds while the
/// CLI waits at FD4 between its first cleanup failure and second request.
#[cfg(target_os = "linux")]
pub(crate) fn run_installed_public_reuse_source_case(
    registration_root: &Path,
    challenge: &str,
    cli_sha256: &DiagnosticSha256,
    contract_path: &Path,
    report_path: &Path,
    fixture_path: &Path,
    working_directory: &Path,
    uid: u32,
    gid: u32,
    expected_report: &ExpectedPublicV2Readback<'_>,
    barrier: std::os::unix::net::UnixStream,
    after_registration: Box<dyn FnOnce() -> std::io::Result<()> + Send>,
    case_origin_prefix: &Path,
    first_phase: std::sync::Arc<std::sync::Mutex<std::collections::BTreeMap<String, Vec<u8>>>>,
) -> Result<ObservedInstalledPublicCaseV3> {
    crate::private_public_raw::validate_relative_evidence_path(
        &case_origin_prefix.to_string_lossy(),
    )?;
    run_installed_public_case_inner(
        registration_root,
        "private_tcp::retirement_failure_blocks_reuse",
        challenge,
        Path::new("/usr/bin/memcordon"),
        cli_sha256,
        contract_path,
        report_path,
        fixture_path,
        None,
        None,
        working_directory,
        uid,
        gid,
        Duration::from_secs(180),
        expected_report,
        Some(barrier),
        Some(after_registration),
        None,
        Some(case_origin_prefix.join("samples")),
        Some(first_phase),
    )
}

/// The only final-public case allowed to pass arguments to its approved
/// entrypoint. The arguments select the reviewed, B-pinned filtered ABI mode
/// and bind its target report to the protected dispatch challenge.
#[cfg(target_os = "linux")]
pub(crate) fn run_installed_public_abi_source_case(
    registration_root: &Path,
    selector: &str,
    challenge: &str,
    cli: &Path,
    cli_sha256: &DiagnosticSha256,
    contract_path: &Path,
    report_path: &Path,
    fixture_path: &Path,
    working_directory: &Path,
    uid: u32,
    gid: u32,
    expected_report: &ExpectedPublicV2Readback<'_>,
    case_origin_prefix: &Path,
) -> Result<ObservedInstalledPublicCaseV3> {
    if selector != memcordon_core::private_public_abi_composite_v1::PUBLIC_ABI_SELECTOR_V1 {
        return Err(CiError::Message(
            "ABI source argv used for ordinary public selector".into(),
        ));
    }
    crate::private_public_raw::validate_relative_evidence_path(
        &case_origin_prefix.to_string_lossy(),
    )?;
    let target_arguments = [
        std::ffi::OsString::from("public-abi-filtered-target"),
        std::ffi::OsString::from("--challenge"),
        std::ffi::OsString::from(challenge),
    ];
    run_installed_public_case_inner(
        registration_root,
        selector,
        challenge,
        cli,
        cli_sha256,
        contract_path,
        report_path,
        fixture_path,
        None,
        None,
        working_directory,
        uid,
        gid,
        Duration::from_secs(120),
        expected_report,
        None,
        None,
        Some(&target_arguments),
        Some(case_origin_prefix.join("samples")),
        None,
    )
}

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
        None,
        None,
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
        None,
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
    sample_origin_prefix: Option<std::path::PathBuf>,
    first_phase: Option<
        std::sync::Arc<std::sync::Mutex<std::collections::BTreeMap<String, Vec<u8>>>>,
    >,
) -> Result<ObservedInstalledPublicCaseV3> {
    use std::io::{Read, Write};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::ExitStatusExt;
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
    let dual_case = selector == "private_tcp::dual_attempt_namespace_isolation";
    let (mut dual_control, reuse_barrier) = if dual_case {
        if reuse_barrier.is_some() {
            return Err(CiError::Message("dual aliases reuse barrier".into()));
        }
        let (root, child) = UnixStream::pair()?;
        root.set_read_timeout(Some(Duration::from_secs(30)))?;
        root.set_write_timeout(Some(Duration::from_secs(30)))?;
        (Some(root), Some(child))
    } else {
        (None, reuse_barrier)
    };
    let mut argv = public_v2_argv_with_expected_plan(
        contract_path,
        report_path,
        fixture_path,
        expected_plan_path,
    )?;
    if dual_case {
        argv.insert(5, "--concurrent-private-two-attempts".into());
    }
    let contract_bytes = {
        let mut bytes = Vec::new();
        std::fs::File::open(contract_path)?
            .take(128 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        bytes
    };
    let contract = match memcordon_core::workload_contract::WorkloadContract::parse(&contract_bytes)
        .map_err(CiError::Message)?
    {
        memcordon_core::workload_contract::WorkloadContract::V2(contract) => contract,
        _ => {
            return Err(CiError::Message(
                "public fixture contract must be V2".into(),
            ));
        }
    };
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
    } else {
        argv.extend([
            std::ffi::OsString::from("public-release-fixture"),
            std::ffi::OsString::from(selector),
            std::ffi::OsString::from("--challenge"),
            std::ffi::OsString::from(challenge),
        ]);
        let mut ports = contract
            .requirements
            .as_slice()
            .iter()
            .filter_map(|requirement| match requirement {
                memcordon_core::workload_contract::RequirementV1::Tcp {
                    local_ports:
                        memcordon_core::workload_contract::LocalPortRequirement::Exact { port },
                    ..
                } => Some(port.get()),
                _ => None,
            })
            .collect::<Vec<_>>();
        ports.sort_unstable();
        ports.dedup();
        if matches!(
            selector,
            "private_tcp::native_tcp_bind_listen_connect"
                | "private_tcp::port_collision_same_namespace"
                | "private_tcp::frontend_loss_retired"
                | "private_tcp::guardian_loss_retired"
                | "private_tcp::dual_attempt_namespace_isolation"
                | "private_tcp::scm_rights_and_precreated_socket_denied"
                | "private_tcp::namespace_reentry_denied"
                | "private_tcp::private_namespace_topology_exact"
        ) {
            if ports.len() != 1 {
                return Err(CiError::Message(
                    "public held TCP recipe requires one exact request port".into(),
                ));
            }
            argv.extend([
                std::ffi::OsString::from("--port"),
                std::ffi::OsString::from(ports[0].to_string()),
            ]);
        }
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
    let live_samples = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
    let namespace_holds = Arc::new(Mutex::new(Vec::new()));
    let namespace_slot = Arc::clone(&namespace_holds);
    let live_slot = Arc::clone(&live_samples);
    let slot = Arc::clone(&observed);
    let (gate_reader, mut gate_writer) = UnixStream::pair()?;
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
        .stdin(std::process::Stdio::piped());
    let child_writer = gate_writer.try_clone()?;
    let registration_root = registration_root.to_path_buf();
    let selector = selector.to_owned();
    let frontend_fault = selector == "private_tcp::frontend_loss_retired";
    let original_fault_report = matches!(
        selector.as_str(),
        "private_tcp::authorization_uncertainty_retired" | "private_tcp::guardian_loss_retired"
    );
    let prepared_phase_image = if !matches!(std::fs::symlink_metadata("/etc/memcordon/release-trust/final-public-preparation.v2.json"),Err(error) if error.kind()==std::io::ErrorKind::NotFound)
    {
        let raw = crate::command::CommandSpec::new(
            "/usr/libexec/memcordon-sealed-agent",
            &registration_root,
            Duration::from_secs(30),
        )
        .remove_github_token()
        .args(["package", "verify-private-host", "--json"])
        .run()?;
        let actual = crate::private_final_install::FinalHostReadbackV1::parse_bounded(&raw)?;
        if actual.active_h1_receipt_sha256() != expected_report.host_receipt_sha256
            || actual.public_cli_sha256() != cli_sha256
        {
            return Err(CiError::Message(
                "public pre-phase source image lacks exact installed H1/CLI".into(),
            ));
        }
        Some(actual.agent_sha256().clone())
    } else {
        None
    };
    let challenge = challenge.to_owned();
    let target_argv = std::iter::once(fixture_path.to_string_lossy().into_owned())
        .chain(
            argv.iter()
                .skip(
                    argv.iter()
                        .position(|arg| arg == "--")
                        .ok_or_else(|| CiError::Message("public command boundary absent".into()))?
                        + 2,
                )
                .map(|arg| arg.to_string_lossy().into_owned()),
        )
        .collect::<Vec<_>>();
    let caller_spoof = selector == "private_tcp::caller_identity_and_epoch_bound"
        && expected_report.outcome
            == crate::private_public_v2::ExpectedPublicV2Outcome::PreallocationRejected;
    let caller_argv = std::iter::once(cli.to_string_lossy().into_owned())
        .chain(argv.iter().map(|arg| arg.to_string_lossy().into_owned()))
        .collect::<Vec<_>>();
    let caller_image = cli_sha256.clone();
    let held_case = expected_report.outcome
        != crate::private_public_v2::ExpectedPublicV2Outcome::PreallocationRejected
        && target_arguments.is_none()
        && (!matches!(
            selector.as_str(),
            "private_tcp::authorization_uncertainty_retired"
                | "private_tcp::retirement_failure_blocks_reuse"
                | "private_tcp::dual_attempt_namespace_isolation"
        ) || selector == "private_tcp::retirement_failure_blocks_reuse"
            && sample_origin_prefix.is_some());
    let output = memcordon_testkit::run_with_deadline_owned_spawn_with_io_output_limit(
        command,
        deadline,
        1024 * 1024,
        move |command| {
            memcordon_platform::test_support::spawn_private_public_child(
                command,
                uid,
                gid,
                gate_reader.into(),
                child_writer.into(),
                reuse_barrier.map(Into::into),
            )
        },
        move |pid, mut stdin, output_snapshot| {
            // The root parent must not retain the child's FD4 endpoint:
            // otherwise a crashed child could mask EOF on the control socket.
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
            if let Some(image) = &prepared_phase_image {
                let facility = sample_prepared_public_facility_sources(
                    &registration_root,
                    &selector,
                    &challenge,
                    image,
                    sample_origin_prefix.as_deref(),
                )
                .map_err(|error| std::io::Error::other(error.to_string()))?;
                live_slot
                    .lock()
                    .map_err(|_| std::io::Error::other("Facility source lock poisoned"))?
                    .extend(facility);
            }
            if let Some(start) = after_registration {
                start()?;
            }
            gate_writer.write_all(&[0xa5])?;
            let caller_start = identity.start_time_ticks;
            *slot
                .lock()
                .map_err(|_| std::io::Error::other("public child observation lock failed"))? =
                Some(identity);
            if caller_spoof && sample_origin_prefix.is_some() {
                let challenge_bytes: [u8; 32] = hex::decode(&challenge)
                    .map_err(std::io::Error::other)?
                    .try_into()
                    .map_err(|_| {
                        std::io::Error::other("public spoof fresh challenge width differs")
                    })?;
                let key = memcordon_core::private_release_case_v1::private_release_case_key_v1(
                    memcordon_core::private_release_case_v1::PrivateReleaseStageV1::FinalPublic,
                    &selector,
                    &challenge_bytes,
                )
                .map_err(std::io::Error::other)?;
                let leaves = sample_public_caller_spoof_gate(
                    &key,
                    pid,
                    caller_start,
                    uid,
                    gid,
                    &caller_image,
                    &caller_argv,
                    sample_origin_prefix.as_deref(),
                )
                .map_err(|error| std::io::Error::other(error.to_string()))?;
                live_slot
                    .lock()
                    .map_err(|_| std::io::Error::other("public spoof source lock poisoned"))?
                    .extend(leaves);
                return Ok(());
            }
            if selector == "private_tcp::authorization_uncertainty_retired" {
                if let Some(image) = &prepared_phase_image {
                    let challenge_digest: DiagnosticSha256 =
                        memcordon_core::BoundedText::<64>::new(&challenge)
                            .map_err(std::io::Error::other)?
                            .try_into()
                            .map_err(std::io::Error::other)?;
                    let key = memcordon_core::private_release_case_v1::private_release_case_key_v1(
                        memcordon_core::private_release_case_v1::PrivateReleaseStageV1::FinalPublic,
                        &selector,
                        challenge_digest.bytes(),
                    )
                    .map_err(std::io::Error::other)?;
                    let directory = Path::new("/var/lib/memcordon/sealed/private-public-cases")
                        .join(String::from(key.clone()));
                    let leaves = sample_public_prepared_phase_gates(
                        &directory,
                        &selector,
                        &key,
                        0,
                        image,
                        sample_origin_prefix.as_deref(),
                    )?;
                    live_slot
                        .lock()
                        .map_err(|_| {
                            std::io::Error::other("public pre-phase source lock poisoned")
                        })?
                        .extend(leaves);
                }
                return Ok(());
            }
            if dual_case {
                let mut byte = [0];
                dual_control
                    .as_mut()
                    .ok_or_else(|| std::io::Error::other("dual control absent"))?
                    .read_exact(&mut byte)?;
                if byte != *b"D" {
                    return Err(std::io::Error::other("dual launch ready byte differs"));
                }
            }
            if held_case || dual_case {
                let challenge_digest: DiagnosticSha256 =
                    memcordon_core::BoundedText::<64>::new(&challenge)
                        .map_err(std::io::Error::other)?
                        .try_into()
                        .map_err(std::io::Error::other)?;
                let key = memcordon_core::private_release_case_v1::private_release_case_key_v1(
                    memcordon_core::private_release_case_v1::PrivateReleaseStageV1::FinalPublic,
                    &selector,
                    challenge_digest.bytes(),
                )
                .map_err(std::io::Error::other)?;
                let directory = Path::new("/var/lib/memcordon/sealed/private-public-cases")
                    .join(String::from(key));
                let steps = if dual_case {
                    vec![(0_u8, 0_usize), (0, 1), (1, 0), (1, 1), (0, 2), (1, 2)]
                } else {
                    vec![(0, 0), (0, 1)]
                };
                for (branch_ordinal, held_stage) in steps {
                    if held_stage == 0
                        && let Some(image) = &prepared_phase_image
                    {
                        let key=memcordon_core::private_release_case_v1::private_release_case_key_v1(memcordon_core::private_release_case_v1::PrivateReleaseStageV1::FinalPublic,&selector,challenge_digest.bytes()).map_err(std::io::Error::other)?;
                        let leaves = sample_public_prepared_phase_gates(
                            &directory,
                            &selector,
                            &key,
                            branch_ordinal,
                            image,
                            sample_origin_prefix.as_deref(),
                        )?;
                        live_slot
                            .lock()
                            .map_err(|_| {
                                std::io::Error::other("public pre-phase source lock poisoned")
                            })?
                            .extend(leaves);
                    }
                    let branch_challenge = if dual_case {
                        memcordon_core::private_release_case_v1::public_dual_challenge_v1(
                            challenge_digest.bytes(),
                            branch_ordinal,
                        )
                        .map_err(std::io::Error::other)?
                    } else {
                        *challenge_digest.bytes()
                    };
                    let mut branch_argv = target_argv.clone();
                    if dual_case {
                        let position = branch_argv
                            .iter()
                            .position(|arg| arg == "--challenge")
                            .ok_or_else(|| std::io::Error::other("dual target challenge absent"))?;
                        branch_argv[position + 1] =
                            String::from(DiagnosticSha256::from_bytes(branch_challenge));
                    }
                    let started = std::time::Instant::now();
                    let (target_pid, target_start, raw_identity, raw_response) = loop {
                        let raw_response = if dual_case {
                            let bytes = output_snapshot.stdout()?;
                            let (streams, terminals) = read_dual_stream_snapshot(&bytes)?;
                            if branch_ordinal == 1 && held_stage == 2 && terminals[0].is_none() {
                                if started.elapsed() > Duration::from_secs(20) {
                                    return Err(std::io::Error::other(
                                        "dual first terminal absent before second post-retirement response",
                                    ));
                                }
                                std::thread::sleep(Duration::from_millis(10));
                                continue;
                            }
                            streams[usize::from(branch_ordinal)].clone()
                        } else {
                            output_snapshot.stdout()?
                        };
                        let baseline = fixture_baseline_frame(&raw_response, &branch_challenge)?;
                        let raw_response = if held_stage == 0 {
                            baseline.map_or_else(Vec::new, |bytes| bytes.to_vec())
                        } else {
                            baseline.map_or_else(Vec::new, |_| raw_response[48..].to_vec())
                        };
                        let fixture_response = if held_stage != 0
                            && crate::private_public_source_facts::uses_public_exec_response_frame(
                                &selector,
                            ) {
                            match crate::private_public_source_facts::decode_public_exec_response_frame(
                                &selector, &branch_challenge, &raw_response,
                            ).map_err(|error| std::io::Error::other(error.to_string()))? {
                                Some((_, operations)) => operations,
                                None => {
                                    if started.elapsed() > Duration::from_secs(20) {
                                        return Err(std::io::Error::other("public emitted exec response absent"));
                                    }
                                    std::thread::sleep(Duration::from_millis(10));
                                    continue;
                                }
                            }
                        } else {
                            raw_response.as_slice()
                        };
                        let mut found = None;
                        for entry in std::fs::read_dir(&directory)? {
                            let entry = entry?;
                            let name = entry.file_name();
                            let Some(name) = name.to_str() else { continue };
                            let expected_prefix = if branch_ordinal == 0 { "0-" } else { "1-" };
                            if !name.starts_with(expected_prefix) {
                                continue;
                            }
                            let path = entry.path().join("target-identity.json");
                            if !path.exists() {
                                continue;
                            }
                            let bytes =
                                crate::private_protected_readback::read_protected_raw_case_file(
                                    &path,
                                )
                                .map_err(|error| std::io::Error::other(error.to_string()))?;
                            memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)
                                .map_err(std::io::Error::other)?;
                            let value: serde_json::Value = serde_json::from_slice(&bytes)?;
                            let gated = value.get("gated").unwrap_or(&value);
                            let target = gated
                                .get("target")
                                .ok_or_else(|| std::io::Error::other("live target gate absent"))?;
                            let target_pid = target
                                .get("pid")
                                .and_then(serde_json::Value::as_u64)
                                .and_then(|value| u32::try_from(value).ok())
                                .ok_or_else(|| std::io::Error::other("live target PID differs"))?;
                            let target_start = target
                                .get("start_time")
                                .and_then(serde_json::Value::as_u64)
                                .ok_or_else(|| {
                                    std::io::Error::other("live target start differs")
                                })?;
                            let complete = if held_stage == 0 {
                                raw_response.len() == 48
                            } else if matches!(
                                selector.as_str(),
                                "private_tcp::child_runtime_and_threads_retired"
                                    | "private_tcp::release_checkpoint_terminal_joined"
                            ) {
                                let (magic, pid_count) = if selector
                                    == "private_tcp::child_runtime_and_threads_retired"
                                {
                                    (b"MCRCHLD1".as_slice(), 3)
                                } else {
                                    (b"MCRJOIN1".as_slice(), 1)
                                };
                                let width = std::mem::size_of::<u32>();
                                let length =
                                    magic.len() + pid_count * width + branch_challenge.len();
                                fixture_response.len() == length
                                    && fixture_response.starts_with(magic)
                                    && fixture_response[length - branch_challenge.len()..]
                                        == *hash_bytes(&branch_challenge).bytes()
                            } else {
                                if fixture_response.len() >= 12 {
                                    if !fixture_response.starts_with(b"MCPH\x01\0\0\0") {
                                        return Err(std::io::Error::other(
                                            "public held response magic differs",
                                        ));
                                    }
                                    let size = u32::from_le_bytes(
                                        fixture_response[8..12].try_into().expect("four bytes"),
                                    ) as usize;
                                    if size > 64 * 1024 {
                                        return Err(std::io::Error::other(
                                            "public held response exceeds closed fixture bound",
                                        ));
                                    }
                                    if dual_case {
                                        complete_held_frames(fixture_response)? >= held_stage
                                    } else {
                                        fixture_response.len() == 12 + size
                                    }
                                } else {
                                    false
                                }
                            };
                            if complete {
                                found =
                                    Some((target_pid, target_start, bytes, raw_response.clone()));
                                break;
                            }
                        }
                        if let Some(found) = found {
                            break found;
                        }
                        if started.elapsed() > Duration::from_secs(20) {
                            return Err(std::io::Error::other(
                                "public held target barrier deadline",
                            ));
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    };
                    let decision_bytes =
                        crate::private_protected_readback::read_protected_raw_case_file(
                            &directory.join("grant-decision.json"),
                        )
                        .map_err(|error| std::io::Error::other(error.to_string()))?;
                    let decision: serde_json::Value = serde_json::from_slice(&decision_bytes)?;
                    let registry_digest = decision
                        .get("registry_digest")
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| {
                            std::io::Error::other("held target registry digest absent")
                        })?;
                    let registry_path = Path::new("/var/lib/memcordon/policy")
                        .join(registry_digest)
                        .with_extension("snapshot");
                    let registry_bytes =
                        crate::private_protected_readback::read_protected_raw_case_file(
                            &registry_path,
                        )
                        .map_err(|error| std::io::Error::other(error.to_string()))?;
                    let registry = memcordon_core::workload_registry_v2::PolicyRegistryV2::parse(
                        &registry_bytes,
                    )
                    .map_err(std::io::Error::other)?;
                    if String::from(registry.canonical_digest().map_err(std::io::Error::other)?)
                        != registry_digest
                    {
                        return Err(std::io::Error::other("held registry bytes differ"));
                    }
                    let memcordon_core::workload_contract::ExecutionIdentityRequestV2::AdministratorProfile {reference}= &contract.execution_identity else {return Err(std::io::Error::other("held target lacks administrator identity"));};
                    let identities = registry
                        .execution_identities
                        .as_slice()
                        .iter()
                        .filter(|entry| entry.enabled && entry.reference == *reference)
                        .collect::<Vec<_>>();
                    if identities.len() != 1
                        || !identities[0].supplementary_groups.as_slice().is_empty()
                    {
                        return Err(std::io::Error::other(
                            "held target identity ambiguous or groups not in fixed recipe",
                        ));
                    }
                    let entrypoints = identities[0]
                        .entrypoints
                        .as_slice()
                        .iter()
                        .filter(|entry| entry.absolute_path.as_str() == target_argv[0])
                        .collect::<Vec<_>>();
                    if entrypoints.len() != 1 {
                        return Err(std::io::Error::other("held fixture entrypoint differs"));
                    }
                    let mut sample = crate::private_public_live::sample_held_public_target(
                        target_pid,
                        target_start,
                        identities[0].uid.get(),
                        identities[0].gid.get(),
                        &entrypoints[0].sha256,
                        &branch_argv,
                    )
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                    if held_stage != 0 {
                        crate::private_public_live::sample_held_network_source(&mut sample)
                            .map_err(|error| std::io::Error::other(error.to_string()))?;
                        if selector == "private_tcp::af_unix_abstract_and_pathname_denied" {
                            crate::private_candidate_unix_facts::sample_held_unix_source(
                                &mut sample,
                                branch_challenge,
                            )
                            .map_err(|error| std::io::Error::other(error.to_string()))?;
                        }
                    }
                    if selector == "private_tcp::child_runtime_and_threads_retired"
                        && held_stage != 0
                    {
                        let child = sample_public_held_child(
                            &sample,
                            &raw_response,
                            &branch_challenge,
                            &entrypoints[0].sha256,
                        )
                        .map_err(|error| std::io::Error::other(error.to_string()))?;
                        namespace_slot
                            .lock()
                            .map_err(|_| {
                                std::io::Error::other("child namespace custody lock poisoned")
                            })?
                            .push(
                                crate::private_public_live::hold_sampled_public_namespaces(&child)
                                    .map_err(|error| std::io::Error::other(error.to_string()))?,
                            );
                        let base = Path::new("children/child");
                        let mut leaves = live_slot
                            .lock()
                            .map_err(|_| std::io::Error::other("child source lock poisoned"))?;
                        leaves.insert(
                            base.join("sample-v1.json").to_string_lossy().into_owned(),
                            encode_public_held_source(
                                &child,
                                sample_origin_prefix.as_deref(),
                                base,
                            )
                            .map_err(|error| std::io::Error::other(error.to_string()))?,
                        );
                        for (name, bytes) in child.leaves {
                            leaves.insert(base.join(name).to_string_lossy().into_owned(), bytes);
                        }
                    }
                    if selector == "private_tcp::release_checkpoint_terminal_joined"
                        && held_stage != 0
                    {
                        let identity: serde_json::Value =
                            crate::private_observer_session::strict_json(&raw_identity, 64 * 1024)
                                .map_err(|error| std::io::Error::other(error.to_string()))?;
                        let identity = identity.get("gated").unwrap_or(&identity);
                        let attempt_id = identity
                            .get("attempt_id")
                            .and_then(serde_json::Value::as_str)
                            .ok_or_else(|| {
                                std::io::Error::other("public terminal original attempt absent")
                            })?;
                        let (original, metadata) =
                            sample_public_terminal_midpoint(attempt_id, target_pid, target_start)
                                .map_err(|error| std::io::Error::other(error.to_string()))?;
                        let mut leaves = live_slot
                            .lock()
                            .map_err(|_| std::io::Error::other("terminal source lock poisoned"))?;
                        leaves.insert(
                            "terminal-midpoint/execution-observed-v4.bin".into(),
                            original,
                        );
                        leaves.insert(
                            "terminal-midpoint/execution-observed-v4.bin.metadata.json".into(),
                            metadata,
                        );
                    }
                    namespace_slot
                        .lock()
                        .map_err(|_| std::io::Error::other("namespace custody lock failed"))?
                        .push(
                            crate::private_public_live::hold_sampled_public_namespaces(&sample)
                                .map_err(|error| std::io::Error::other(error.to_string()))?,
                        );
                    let mut leaves = live_slot
                        .lock()
                        .map_err(|_| std::io::Error::other("held sample lock poisoned"))?;
                    let suffix = if dual_case {
                        match (branch_ordinal, held_stage) {
                            (0, 0) => "dual-first-baseline",
                            (1, 0) => "dual-second-baseline",
                            (0, 1) => "dual-first-overlap",
                            (1, 1) => "dual-second-overlap",
                            (0, 2) => "dual-first-pre-retirement",
                            (1, 2) => "dual-second-after-first-retirement",
                            _ => unreachable!(),
                        }
                    } else {
                        if held_stage == 0 { "baseline" } else { "" }
                    };
                    let leaf =
                        |name: &str| Path::new(suffix).join(name).to_string_lossy().into_owned();
                    leaves.insert(leaf("target-identity-at-held-gate.json"), raw_identity);
                    leaves.insert(leaf("target-response-at-held-gate.bin"), raw_response);
                    leaves.insert(leaf("grant-decision-at-held-gate.json"), decision_bytes);
                    leaves.insert(leaf("registry-at-held-gate.json"), registry_bytes);
                    leaves.insert(
                        leaf("target-live-sample-v1.json"),
                        encode_public_held_source(
                            &sample,
                            sample_origin_prefix.as_deref(),
                            &Path::new(suffix).join("target-live"),
                        )
                        .map_err(|error| std::io::Error::other(error.to_string()))?,
                    );
                    for (name, bytes) in sample.leaves {
                        leaves.insert(
                            Path::new(suffix)
                                .join("target-live")
                                .join(name)
                                .to_string_lossy()
                                .into_owned(),
                            bytes,
                        );
                    }
                    drop(leaves);
                    if dual_case {
                        let stream = dual_control
                            .as_mut()
                            .ok_or_else(|| std::io::Error::other("dual control absent"))?;
                        let mut ackbytes = b"memcordon-private-unix-observer-ack-v1\0".to_vec();
                        ackbytes.extend_from_slice(&branch_challenge);
                        let ack = hash_bytes(&ackbytes);
                        let packet = |ordinal: u8, hash: &DiagnosticSha256| {
                            let mut bytes = vec![ordinal];
                            bytes.extend_from_slice(hash.bytes());
                            bytes
                        };
                        match (branch_ordinal, held_stage) {
                            (0, 0) | (1, 0) => {
                                let mut input =
                                    b"memcordon/private-fixture-baseline-ack/v1\0".to_vec();
                                input.extend_from_slice(&fixture_baseline_bytes(&branch_challenge));
                                stream.write_all(&packet(branch_ordinal, &hash_bytes(&input)))?;
                            }
                            (0, 1) => stream.write_all(b"G")?,
                            (1, 1) => {
                                let first=memcordon_core::private_release_case_v1::public_dual_challenge_v1(challenge_digest.bytes(),0).map_err(std::io::Error::other)?;
                                let mut bytes =
                                    b"memcordon-private-unix-observer-ack-v1\0".to_vec();
                                bytes.extend_from_slice(&first);
                                stream.write_all(&packet(0, &hash_bytes(&bytes)))?;
                            }
                            (0, 2) => {
                                stream.write_all(&packet(0, &ack))?;
                                let wait = std::time::Instant::now();
                                loop {
                                    let (_, terminals) =
                                        read_dual_stream_snapshot(&output_snapshot.stdout()?)?;
                                    if let Some(raw) = terminals[0].as_ref() {
                                        live_slot
                                            .lock()
                                            .map_err(|_| {
                                                std::io::Error::other("dual terminal sample lock")
                                            })?
                                            .insert(
                                                "dual-first-authenticated-terminal.bin".into(),
                                                raw.clone(),
                                            );
                                        break;
                                    }
                                    if wait.elapsed() > Duration::from_secs(20) {
                                        return Err(std::io::Error::other(
                                            "dual first settlement barrier timed out",
                                        ));
                                    }
                                    std::thread::sleep(Duration::from_millis(10));
                                }
                                let second=memcordon_core::private_release_case_v1::public_dual_challenge_v1(challenge_digest.bytes(),1).map_err(std::io::Error::other)?;
                                let mut bytes =
                                    b"memcordon-private-unix-observer-ack-v1\0".to_vec();
                                bytes.extend_from_slice(&second);
                                stream.write_all(&packet(1, &hash_bytes(&bytes)))?;
                            }
                            (1, 2) => stream.write_all(&packet(1, &ack))?,
                            _ => unreachable!(),
                        }
                        continue;
                    }
                    if held_stage == 0 {
                        let mut input = b"memcordon/private-fixture-baseline-ack/v1\0".to_vec();
                        input.extend_from_slice(&fixture_baseline_bytes(&branch_challenge));
                        stdin
                            .as_mut()
                            .ok_or_else(|| std::io::Error::other("baseline stdin absent"))?
                            .write_all(hash_bytes(&input).bytes())?;
                        continue;
                    }
                    if matches!(
                        selector.as_str(),
                        "private_tcp::frontend_loss_retired" | "private_tcp::guardian_loss_retired"
                    ) {
                        use std::os::unix::fs::OpenOptionsExt;
                        let started = std::time::Instant::now();
                        loop {
                            let mut gate = None;
                            for entry in std::fs::read_dir(&directory)? {
                                let entry = entry?;
                                let path = entry.path().join("fault-live-gate-v1.json");
                                if path.exists() {
                                    let bytes=crate::private_protected_readback::read_protected_raw_case_file(&path).map_err(|error|std::io::Error::other(error.to_string()))?;
                                    gate = Some((entry.path(), bytes));
                                    break;
                                }
                            }
                            if let Some((attempt_directory, bytes)) = gate {
                                let digest = hash_bytes(&bytes);
                                live_slot
                                    .lock()
                                    .map_err(|_| std::io::Error::other("fault gate lock poisoned"))?
                                    .insert("fault-live-gate-v1.json".into(), bytes);
                                let mut ack = std::fs::OpenOptions::new()
                                    .write(true)
                                    .create_new(true)
                                    .mode(0o600)
                                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                                    .open(attempt_directory.join("fault-live-gate-v1.ack"))?;
                                ack.write_all(digest.bytes())?;
                                ack.sync_all()?;
                                std::fs::File::open(&attempt_directory)?.sync_all()?;
                                break;
                            }
                            if started.elapsed() > Duration::from_secs(5) {
                                return Err(std::io::Error::other("fault live gate absent"));
                            }
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        return Ok(());
                    }
                    let ack = if matches!(
                        selector.as_str(),
                        "private_tcp::child_runtime_and_threads_retired"
                            | "private_tcp::release_checkpoint_terminal_joined"
                    ) {
                        vec![1]
                    } else {
                        let mut bytes = b"memcordon-private-unix-observer-ack-v1\0".to_vec();
                        bytes.extend_from_slice(challenge_digest.bytes());
                        hash_bytes(&bytes).bytes().to_vec()
                    };
                    // Publish the first physical interval's original samples
                    // before this ACK can let the target retire and emit R.
                    if let Some(first_phase) = &first_phase {
                        *first_phase.lock().map_err(|_| {
                            std::io::Error::other("reuse first phase lock poisoned")
                        })? = live_slot
                            .lock()
                            .map_err(|_| std::io::Error::other("reuse live source lock poisoned"))?
                            .clone();
                    }
                    stdin
                        .as_mut()
                        .ok_or_else(|| std::io::Error::other("public held stdin absent"))?
                        .write_all(&ack)?;
                }
            }
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
    if frontend_fault {
        let signal = output
            .status
            .signal()
            .ok_or_else(|| CiError::Message("frontend fault child did not signal".into()))?;
        if signal != 9 {
            return Err(CiError::Message(
                "frontend fault actual wait signal differs".into(),
            ));
        }
        let wait_ns = memcordon_platform::test_support::private_observer_monotonic_ns()
            .map_err(|error| CiError::Message(error.to_string()))?;
        let wait = serde_json::json!({"schema_version":1,"pid":child.pid,"start_time_ticks":child.start_time_ticks,
            "raw_wait_status":output.status.into_raw(),"signal":signal,"stdout_sha256":hash_bytes(&output.stdout),
            "stderr_sha256":hash_bytes(&output.stderr),"wait_observed_monotonic_ns":wait_ns});
        let mut leaves = live_samples
            .lock()
            .map_err(|_| CiError::Message("supervisor wait sample lock failed".into()))?;
        leaves.insert("supervisor/wait-v1.json".into(), serde_json::to_vec(&wait)?);
        leaves.insert("supervisor/stdout.raw".into(), output.stdout.clone());
        leaves.insert("supervisor/stderr.raw".into(), output.stderr.clone());
    }
    let mut closes = Vec::new();
    for custody in std::mem::take(
        &mut *namespace_holds
            .lock()
            .map_err(|_| CiError::Message("namespace close custody lock failed".into()))?,
    ) {
        closes.extend(
            custody
                .close()
                .map_err(|error| CiError::Message(error.to_string()))?,
        );
    }
    if !closes.is_empty() {
        live_samples
            .lock()
            .map_err(|_| CiError::Message("namespace close sample lock failed".into()))?
            .insert(
                "supervisor/namespace-close-v1.json".into(),
                serde_json::to_vec(&closes)?,
            );
    }
    let process = SupervisedProcessV2 {
        status: output.status,
        stdout: output.stdout,
        stderr: output.stderr,
        linux_child: Some(child),
    };
    let dual_report = if dual_case {
        Some(
            crate::private_public_v2::read_structural_public_dual_v12_report(
                report_path,
                &process,
                expected_report,
            )?,
        )
    } else {
        None
    };
    let (report, report_bytes) = if dual_case {
        (
            None,
            Some(crate::private_public_v2::read_public_v2_report_bytes(
                report_path,
                uid,
            )?),
        )
    } else if matches!(
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
        let report = if original_fault_report {
            crate::private_public_v2::read_original_public_fault_report(
                report_path,
                &process,
                expected_report,
            )?
        } else {
            read_structural_public_v2_report(report_path, &process, expected_report)?
        };
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
        dual_report,
        report_bytes,
        stdio_bytes,
        cli_sha256: cli_sha256.clone(),
        argv_sha256,
        working_directory_sha256,
        live_samples: std::mem::take(
            &mut *live_samples
                .lock()
                .map_err(|_| CiError::Message("held sample lock poisoned".into()))?,
        ),
    })
}

#[cfg(target_os = "linux")]
fn encode_public_held_source(
    sample: &crate::private_public_live::HeldPublicTargetSamplesV1,
    prefix: Option<&Path>,
    relative: &Path,
) -> Result<Vec<u8>> {
    if let Some(prefix) = prefix {
        crate::private_source_carrier::encode_held_source(
            sample,
            prefix
                .join(relative)
                .join("image.raw")
                .to_string_lossy()
                .into_owned(),
        )
    } else {
        serde_json::to_vec(sample).map_err(CiError::from)
    }
}

#[cfg(target_os = "linux")]
fn sample_public_prepared_phase_gates(
    directory: &Path,
    selector: &str,
    key: &DiagnosticSha256,
    ordinal: u8,
    image: &DiagnosticSha256,
    sample_origin_prefix: Option<&Path>,
) -> std::io::Result<std::collections::BTreeMap<String, Vec<u8>>> {
    use std::io::{Read, Seek, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let sample = || -> Result<std::collections::BTreeMap<String, Vec<u8>>> {
        let mut leaves = std::collections::BTreeMap::new();
        let mut observed_target = None;
        for phase in ["pre-exec", "release-intent"] {
            let (gate_name, source_name, ack_name) = if phase == "pre-exec" {
                (
                    "public-pre-exec-gate-v3.json",
                    "public-pre-exec-source-v3.bin",
                    "public-pre-exec-gate-v3.ack",
                )
            } else {
                (
                    "public-release-intent-gate-v3.json",
                    "public-release-intent-source-v3.bin",
                    "public-release-intent-gate-v3.ack",
                )
            };
            let started = std::time::Instant::now();
            let (attempt_directory, gate_bytes) = loop {
                let mut ready = Vec::new();
                for entry in std::fs::read_dir(directory)? {
                    let entry = entry?;
                    let name = entry.file_name();
                    let Some(name) = name.to_str() else { continue };
                    let Some((prefix, _)) = name.split_once('-') else {
                        continue;
                    };
                    if prefix.parse::<u8>().ok() != Some(ordinal) {
                        continue;
                    }
                    let gate = entry.path().join(gate_name);
                    match std::fs::symlink_metadata(&gate) {
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(error) => return Err(error.into()),
                        Ok(_) => ready.push((
                            entry.path(),
                            crate::private_protected_readback::read_protected_raw_case_file(&gate)?,
                        )),
                    }
                }
                match ready.len() {
                    1 => break ready.remove(0),
                    0 => {}
                    _ => {
                        return Err(CiError::Message(
                            "public native phase gates alias attempt ordinal".into(),
                        ));
                    }
                }
                if started.elapsed() > Duration::from_secs(20) {
                    return Err(CiError::Message(
                        "public native phase source gate absent".into(),
                    ));
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            let gate: serde_json::Value =
                crate::private_observer_session::strict_json(&gate_bytes, 16 * 1024)?;
            let source = crate::private_protected_readback::read_protected_raw_case_file(
                &attempt_directory.join(source_name),
            )?;
            let record: serde_json::Value =
                crate::private_observer_session::strict_json(&source, 1024 * 1024)?;
            let target: crate::private_public_fault::FaultProcessV1 =
                serde_json::from_value(gate.get("target").cloned().ok_or_else(|| {
                    CiError::Message("public actual phase target absent".into())
                })?)?;
            let source_sha = serde_json::to_value(hash_bytes(&source))?;
            if gate
                .get("schema_version")
                .and_then(serde_json::Value::as_u64)
                != Some(3)
                || gate.get("selector").and_then(serde_json::Value::as_str) != Some(selector)
                || gate.get("result_key") != Some(&serde_json::to_value(key)?)
                || gate.get("ordinal").and_then(serde_json::Value::as_u64)
                    != Some(u64::from(ordinal))
                || gate.get("phase").and_then(serde_json::Value::as_str) != Some(phase)
                || gate.get("durable_source_sha256") != Some(&source_sha)
                || gate.get("target") != record.get("target")
                || gate.get("attempt_id") != record.get("attempt_id")
                || gate.get("boot_identity") != record.get("boot_identity")
                || record.get("phase").and_then(serde_json::Value::as_str)
                    != Some(if phase == "pre-exec" {
                        "target-gated"
                    } else {
                        "release-intent"
                    })
                || observed_target
                    .as_ref()
                    .is_some_and(|prior| prior != &target)
            {
                return Err(CiError::Message(
                    "public original phase/source identity or digest differs".into(),
                ));
            }
            observed_target = Some(target.clone());
            let root = if ordinal == 0 {
                std::path::PathBuf::from(phase)
            } else {
                Path::new("dual-second").join(phase)
            };
            if phase == "release-intent" {
                let attempt_id = record
                    .get("attempt_id")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| {
                        CiError::Message("public original durable identity absent".into())
                    })?;
                let nonce = hex::decode(attempt_id)
                    .map_err(|_| CiError::Message("public durable attempt nonce differs".into()))?;
                if nonce.len() != std::mem::size_of::<u128>() || hex::encode(nonce) != attempt_id {
                    return Err(CiError::Message(
                        "public original durable identity is not a single reviewed filename".into(),
                    ));
                }
                let state_root = Path::new("/var/lib/memcordon/sealed");
                let durable_path = state_root.join(attempt_id);
                // This reads the actual fsynced record, not the immutable
                // public copy (which has a different inode). The gate keeps
                // the owner blocked before GO throughout the held reread.
                if crate::private_protected_readback::read_protected_raw_case_file(&durable_path)?
                    != source
                {
                    return Err(CiError::Message(
                        "public native durable record differs from gated source".into(),
                    ));
                }
                let directory = std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(state_root)?;
                let directory_before = directory.metadata()?;
                let mut original = std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&durable_path)?;
                let before = original.metadata()?;
                if !directory_before.is_dir()
                    || directory_before.uid() != 0
                    || directory_before.mode() & 0o7777 != 0o700
                    || !before.is_file()
                    || before.uid() != 0
                    || before.nlink() != 1
                    || before.mode() & 0o7777 != 0o600
                    || before.len() != source.len() as u64
                    || before.len() > 1024 * 1024
                {
                    return Err(CiError::Message(
                        "public original durable held object custody differs".into(),
                    ));
                }
                let mut first = Vec::new();
                std::io::Read::by_ref(&mut original)
                    .take(1024 * 1024 + 1)
                    .read_to_end(&mut first)?;
                original.seek(std::io::SeekFrom::Start(0))?;
                let mut second = Vec::new();
                std::io::Read::by_ref(&mut original)
                    .take(1024 * 1024 + 1)
                    .read_to_end(&mut second)?;
                let after = original.metadata()?;
                let directory_after = directory.metadata()?;
                let named_after = std::fs::symlink_metadata(&durable_path)?;
                if first != source
                    || second != first
                    || before.dev() != after.dev()
                    || before.ino() != after.ino()
                    || before.len() != after.len()
                    || before.modified()? != after.modified()?
                    || before.mode() != after.mode()
                    || after.uid() != 0
                    || after.nlink() != 1
                    || directory_before.dev() != directory_after.dev()
                    || directory_before.ino() != directory_after.ino()
                    || directory_before.mode() != directory_after.mode()
                    || directory_after.uid() != 0
                    || !named_after.is_file()
                    || named_after.dev() != after.dev()
                    || named_after.ino() != after.ino()
                    || named_after.uid() != 0
                    || named_after.nlink() != 1
                {
                    return Err(CiError::Message(
                        "public original durable held object changed before GO".into(),
                    ));
                }
                let observed_monotonic_ns =
                    memcordon_platform::test_support::private_observer_monotonic_ns()?;
                let metadata = crate::private_observer_session::canonical_bytes(
                    &serde_json::json!({
                        "schema_version":1,"file_dev":after.dev(),"file_inode":after.ino(),
                        "directory_dev":directory_after.dev(),"directory_inode":directory_after.ino(),
                        "bytes_sha256":hash_bytes(&first),"observed_monotonic_ns":observed_monotonic_ns,
                    }),
                )?;
                leaves.insert(
                    root.join("release-intent-v4.bin")
                        .to_string_lossy()
                        .into_owned(),
                    first,
                );
                leaves.insert(
                    root.join("release-intent-v4.bin.metadata.json")
                        .to_string_lossy()
                        .into_owned(),
                    metadata,
                );
            }
            leaves.insert(
                root.join(gate_name).to_string_lossy().into_owned(),
                gate_bytes.clone(),
            );
            leaves.insert(
                root.join(source_name).to_string_lossy().into_owned(),
                source,
            );
            let held = crate::private_public_live::sample_held_target_raw(
                target.pid,
                target.start_time,
                image,
            )?;
            leaves.insert(
                root.join("target-live-sample-v1.json")
                    .to_string_lossy()
                    .into_owned(),
                encode_public_held_source(&held, sample_origin_prefix, &root.join("target-live"))?,
            );
            for (name, bytes) in held.leaves {
                leaves.insert(
                    root.join("target-live")
                        .join(name)
                        .to_string_lossy()
                        .into_owned(),
                    bytes,
                );
            }
            if phase == "pre-exec" {
                for role in ["guardian", "namespace_init"] {
                    if let Some(identity) = record.get(role).filter(|identity| !identity.is_null())
                    {
                        let identity: crate::private_public_fault::FaultProcessV1 =
                            serde_json::from_value(identity.clone())?;
                        let held = crate::private_public_live::sample_held_target_raw(
                            identity.pid,
                            identity.start_time,
                            image,
                        )?;
                        leaves.insert(
                            root.join(role)
                                .join("sample-v1.json")
                                .to_string_lossy()
                                .into_owned(),
                            encode_public_held_source(
                                &held,
                                sample_origin_prefix,
                                &root.join(role),
                            )?,
                        );
                        for (name, bytes) in held.leaves {
                            leaves.insert(
                                root.join(role).join(name).to_string_lossy().into_owned(),
                                bytes,
                            );
                        }
                    }
                }
            }
            let mut ack = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(attempt_directory.join(ack_name))?;
            ack.write_all(hash_bytes(&gate_bytes).bytes())?;
            ack.sync_all()?;
            std::fs::File::open(&attempt_directory)?.sync_all()?;
        }
        Ok(leaves)
    };
    sample().map_err(|error| std::io::Error::other(error.to_string()))
}

#[cfg(target_os = "linux")]
fn read_dual_stream_snapshot(
    bytes: &[u8],
) -> std::io::Result<([Vec<u8>; 2], [Option<Vec<u8>>; 2])> {
    let mut streams = [Vec::new(), Vec::new()];
    let mut terminals = [None, None];
    let mut offset = 0;
    while bytes.len().saturating_sub(offset) >= 14 {
        if &bytes[offset..offset + 8] != b"MCDS\x01\0\0\0" {
            return Err(std::io::Error::other("dual frame magic differs"));
        }
        let ordinal = usize::from(bytes[offset + 8]);
        let kind = bytes[offset + 9];
        let length = u32::from_le_bytes(
            bytes[offset + 10..offset + 14]
                .try_into()
                .expect("fourbytes"),
        ) as usize;
        if ordinal > 1 || kind > 2 || length > 1024 * 1024 {
            return Err(std::io::Error::other("dual frame budget or branch differs"));
        }
        let end = offset
            .checked_add(14)
            .and_then(|value| value.checked_add(length))
            .ok_or_else(|| std::io::Error::other("dual frame overflow"))?;
        if end > bytes.len() {
            break;
        }
        let payload = &bytes[offset + 14..end];
        match kind {
            0 => streams[ordinal].extend_from_slice(payload),
            1 if !payload.is_empty() => {
                return Err(std::io::Error::other("dual fixture stderr nonempty"));
            }
            2 => {
                if terminals[ordinal].replace(payload.to_vec()).is_some() {
                    return Err(std::io::Error::other("dual terminal duplicated"));
                }
            }
            _ => {}
        }
        offset = end;
    }
    Ok((streams, terminals))
}

#[cfg(target_os = "linux")]
fn fixture_baseline_bytes(challenge: &[u8; 32]) -> Vec<u8> {
    let mut bytes = b"MCBL\x01\0\0\0".to_vec();
    bytes.extend_from_slice(challenge);
    bytes.extend_from_slice(&3_i32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes
}

#[cfg(target_os = "linux")]
fn fixture_baseline_frame<'a>(
    bytes: &'a [u8],
    challenge: &[u8; 32],
) -> std::io::Result<Option<&'a [u8]>> {
    if bytes.len() < 48 {
        return Ok(None);
    }
    let frame = &bytes[..48];
    if frame != fixture_baseline_bytes(challenge) {
        return Err(std::io::Error::other(
            "actual fixture baseline frame differs",
        ));
    }
    Ok(Some(frame))
}

#[cfg(target_os = "linux")]
fn sample_public_caller_spoof_gate(
    key: &DiagnosticSha256,
    pid: u32,
    start: u64,
    uid: u32,
    gid: u32,
    image: &DiagnosticSha256,
    argv: &[String],
    origin_prefix: Option<&Path>,
) -> Result<std::collections::BTreeMap<String, Vec<u8>>> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let directory =
        Path::new("/var/lib/memcordon/sealed/private-public-cases").join(String::from(key.clone()));
    let path = directory.join("caller-spoof-ready-v1.json");
    let started = std::time::Instant::now();
    let bytes = loop {
        match std::fs::symlink_metadata(&path) {
            Ok(_) => break crate::private_protected_readback::read_protected_raw_case_file(&path)?,
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && started.elapsed() < Duration::from_secs(20) =>
            {
                std::thread::sleep(Duration::from_millis(10))
            }
            Err(error) => return Err(error.into()),
        }
    };
    let gate: serde_json::Value = crate::private_observer_session::strict_json(&bytes, 16 * 1024)?;
    let admission = crate::private_protected_readback::read_protected_raw_case_file(
        &Path::new("/run/memcordon-final-public/prepared-v2")
            .join(String::from(key.clone()))
            .join("admission.json"),
    )?;
    if gate
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        != Some(1)
        || gate.get("selector").and_then(serde_json::Value::as_str)
            != Some("private_tcp::caller_identity_and_epoch_bound")
        || gate.get("result_key") != Some(&serde_json::to_value(key)?)
        || gate.get("prepared_admission_sha256")
            != Some(&serde_json::to_value(hash_bytes(&admission))?)
        || gate.get("caller")
            != Some(&serde_json::json!({"pid":pid,"start_time_ticks":start,"uid":uid,"gid":gid}))
    {
        return Err(CiError::Message(
            "public spoof actual gate/admission/held caller differs".into(),
        ));
    }
    let held =
        crate::private_public_live::sample_held_public_target(pid, start, uid, gid, image, argv)?;
    if gate
        .get("observed_monotonic_ns")
        .and_then(serde_json::Value::as_u64)
        .is_none_or(|time| time == 0 || time > held.begin_monotonic_ns)
    {
        return Err(CiError::Message(
            "public spoof gate/held original time differs".into(),
        ));
    }
    let base = Path::new("caller-spoof");
    let mut leaves = std::collections::BTreeMap::new();
    leaves.insert(
        base.join("gate.json").to_string_lossy().into_owned(),
        bytes.clone(),
    );
    leaves.insert(
        base.join("sample-v1.json").to_string_lossy().into_owned(),
        encode_public_held_source(&held, origin_prefix, base)?,
    );
    for (name, raw) in held.leaves {
        leaves.insert(base.join(name).to_string_lossy().into_owned(), raw);
    }
    let ack_bytes = hash_bytes(&bytes).bytes().to_vec();
    let mut ack = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join("caller-spoof-ready-v1.ack"))?;
    ack.write_all(&ack_bytes)?;
    ack.sync_all()?;
    std::fs::File::open(&directory)?.sync_all()?;
    leaves.insert(
        base.join("ack.bin").to_string_lossy().into_owned(),
        ack_bytes,
    );
    Ok(leaves)
}

#[cfg(target_os = "linux")]
fn sample_public_terminal_midpoint(
    attempt_id: &str,
    pid: u32,
    start: u64,
) -> Result<(Vec<u8>, Vec<u8>)> {
    use std::io::{Read, Seek};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let nonce = hex::decode(attempt_id)
        .map_err(|_| CiError::Message("public midpoint attempt nonce differs".into()))?;
    if nonce.len() != std::mem::size_of::<u128>() || hex::encode(nonce) != attempt_id {
        return Err(CiError::Message(
            "public midpoint attempt filename differs".into(),
        ));
    }
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/var/lib/memcordon/sealed")?;
    let path = Path::new("/var/lib/memcordon/sealed").join(attempt_id);
    let started = std::time::Instant::now();
    let observed = loop {
        let observed = crate::private_protected_readback::read_protected_raw_case_file(&path)?;
        let raw: serde_json::Value =
            crate::private_observer_session::strict_json(&observed, 1024 * 1024)?;
        if raw.get("attempt_id").and_then(serde_json::Value::as_str) != Some(attempt_id)
            || raw.get("target") != Some(&serde_json::json!({"pid":pid,"start_time":start}))
        {
            return Err(CiError::Message(
                "public terminal actual durable target changed".into(),
            ));
        }
        match raw.get("phase").and_then(serde_json::Value::as_str) {
            Some("execution-observed") => break observed,
            Some("release-intent") if started.elapsed() < Duration::from_secs(20) => {
                std::thread::sleep(Duration::from_millis(10))
            }
            _ => {
                return Err(CiError::Message(
                    "public terminal actual held durable execution phase absent".into(),
                ));
            }
        }
    };
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    let before = file.metadata()?;
    let directory_before = directory.metadata()?;
    if !before.is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || before.mode() & 0o7777 != 0o600
        || before.len() > 1024 * 1024
        || !directory_before.is_dir()
        || directory_before.uid() != 0
        || directory_before.mode() & 0o7777 != 0o700
    {
        return Err(CiError::Message(
            "public midpoint held custody differs".into(),
        ));
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    file.seek(std::io::SeekFrom::Start(0))?;
    let mut second = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(1024 * 1024 + 1)
        .read_to_end(&mut second)?;
    let after = file.metadata()?;
    let dir_after = directory.metadata()?;
    let named = std::fs::symlink_metadata(&path)?;
    if bytes != observed
        || bytes != second
        || bytes.len() as u64 != before.len()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.modified()? != after.modified()?
        || before.mode() != after.mode()
        || after.uid() != 0
        || after.nlink() != 1
        || directory_before.dev() != dir_after.dev()
        || directory_before.ino() != dir_after.ino()
        || directory_before.mode() != dir_after.mode()
        || dir_after.uid() != 0
        || !named.is_file()
        || named.dev() != after.dev()
        || named.ino() != after.ino()
        || named.nlink() != 1
        || named.uid() != 0
    {
        return Err(CiError::Message(
            "public original midpoint durable object changed".into(),
        ));
    }
    let raw: serde_json::Value = crate::private_observer_session::strict_json(&bytes, 1024 * 1024)?;
    if raw.get("attempt_id").and_then(serde_json::Value::as_str) != Some(attempt_id)
        || raw.get("phase").and_then(serde_json::Value::as_str) != Some("execution-observed")
        || raw.get("target") != Some(&serde_json::json!({"pid":pid,"start_time":start}))
    {
        return Err(CiError::Message(
            "public midpoint actual phase or target differs".into(),
        ));
    }
    let metadata = crate::private_observer_session::canonical_bytes(
        &serde_json::json!({"schema_version":1,
        "file_dev":after.dev(),"file_inode":after.ino(),"directory_dev":dir_after.dev(),"directory_inode":dir_after.ino(),
        "bytes_sha256":hash_bytes(&bytes),"observed_monotonic_ns":memcordon_platform::test_support::private_observer_monotonic_ns()?}),
    )?;
    Ok((bytes, metadata))
}

#[cfg(target_os = "linux")]
fn sample_public_held_child(
    parent: &crate::private_public_live::HeldPublicTargetSamplesV1,
    frame: &[u8],
    challenge: &[u8; 32],
    image: &DiagnosticSha256,
) -> Result<crate::private_public_live::HeldPublicTargetSamplesV1> {
    use std::io::Read;
    let (_, operations) = crate::private_public_source_facts::decode_public_exec_response_frame(
        "private_tcp::child_runtime_and_threads_retired",
        challenge,
        frame,
    )?
    .ok_or_else(|| CiError::Message("public live child MCEX frame incomplete".into()))?;
    if operations.len() != 8 + 3 * std::mem::size_of::<u32>() + challenge.len()
        || !operations.starts_with(b"MCRCHLD1")
        || operations[operations.len() - challenge.len()..] != *hash_bytes(challenge).bytes()
    {
        return Err(CiError::Message(
            "public live child actual operation frame differs".into(),
        ));
    }
    let child_ns_pid =
        u32::from_le_bytes(operations[12..16].try_into().expect("fixed child frame"));
    let path = Path::new("/proc")
        .join(parent.pid.to_string())
        .join("task")
        .join(parent.pid.to_string())
        .join("children");
    let mut list = Vec::new();
    std::fs::File::open(path)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut list)?;
    if list.len() > 1024 * 1024 {
        return Err(CiError::Message(
            "public actual child list exceeds bound".into(),
        ));
    }
    let text = std::str::from_utf8(&list)
        .map_err(|_| CiError::Message("public actual child list is not UTF-8".into()))?;
    let mut matches = Vec::new();
    for value in text.split_whitespace() {
        let pid = value
            .parse::<u32>()
            .map_err(|_| CiError::Message("public actual child PID differs".into()))?;
        if pid == 0 || pid == parent.pid {
            return Err(CiError::Message(
                "public actual child list aliases parent".into(),
            ));
        }
        let start = crate::private_process_clock::read_live_start_ticks(pid)?;
        let child = crate::private_public_live::sample_held_target_raw(pid, start, image)?;
        let status = child
            .leaves
            .get("status.raw")
            .ok_or_else(|| CiError::Message("public actual child status absent".into()))?;
        let text = std::str::from_utf8(status)
            .map_err(|_| CiError::Message("public actual child status invalid".into()))?;
        let scalars = |label: &str| -> Result<Vec<u32>> {
            let rows = text
                .lines()
                .filter_map(|line| line.strip_prefix(label))
                .collect::<Vec<_>>();
            let [row] = rows.as_slice() else {
                return Err(CiError::Message(
                    "public child status field ambiguous".into(),
                ));
            };
            row.split_whitespace()
                .map(|value| {
                    value
                        .parse()
                        .map_err(|_| CiError::Message("public child status integer differs".into()))
                })
                .collect()
        };
        if scalars("PPid:")? == [parent.pid]
            && scalars("Tgid:")? == [pid]
            && scalars("NSpid:")?.last() == Some(&child_ns_pid)
        {
            matches.push(child);
        }
    }
    crate::private_process_clock::require_live_start_ticks(parent.pid, parent.start_time_ticks)?;
    let [mut child] = matches.try_into().map_err(
        |_: Vec<crate::private_public_live::HeldPublicTargetSamplesV1>| {
            CiError::Message("public actual held child namespace PID is absent or ambiguous".into())
        },
    )?;
    child.leaves.insert("parent-children.raw".into(), list);
    Ok(child)
}

#[cfg(target_os = "linux")]
fn sample_prepared_public_facility_sources(
    root: &Path,
    selector: &str,
    challenge: &str,
    image: &DiagnosticSha256,
    origin_prefix: Option<&Path>,
) -> Result<std::collections::BTreeMap<String, Vec<u8>>> {
    use memcordon_core::private_public_preparation_v2::{
        ApprovedPublicPreparationPolicyV2, PreparedPublicDispatchRecordV2,
    };
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let policy_bytes = crate::private_protected_readback::read_protected_raw_case_file(Path::new(
        "/etc/memcordon/release-trust/final-public-preparation.v2.json",
    ))?;
    let policy: ApprovedPublicPreparationPolicyV2 =
        crate::private_observer_session::strict_json(&policy_bytes, 128 * 1024)?;
    policy.validate().map_err(CiError::Message)?;
    let approved = policy
        .cases
        .iter()
        .find(|case| case.selector == selector)
        .ok_or_else(|| CiError::Message("public Facility approved selector absent".into()))?;
    let Some(revision) = approved.facility_source_sha256.clone() else {
        return Ok(std::collections::BTreeMap::new());
    };
    let challenge_bytes: DiagnosticSha256 = memcordon_core::BoundedText::<64>::new(challenge)
        .map_err(|error| CiError::Message(error.into()))?
        .try_into()
        .map_err(|error: &str| CiError::Message(error.into()))?;
    let key = memcordon_core::private_release_case_v1::private_release_case_key_v1(
        memcordon_core::private_release_case_v1::PrivateReleaseStageV1::FinalPublic,
        selector,
        challenge_bytes.bytes(),
    )
    .map_err(CiError::Message)?;
    let directory =
        Path::new("/var/lib/memcordon/sealed/private-public-cases").join(String::from(key.clone()));
    let admission_bytes = crate::private_protected_readback::read_protected_raw_case_file(
        &Path::new("/run/memcordon-final-public/prepared-v2")
            .join(String::from(key.clone()))
            .join("admission.json"),
    )?;
    let admission: PreparedPublicDispatchRecordV2 =
        crate::private_observer_session::strict_json(&admission_bytes, 1024 * 1024)?;
    let collected = std::sync::Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
    let slot = std::sync::Arc::clone(&collected);
    let selector = selector.to_owned();
    let challenge = challenge.to_owned();
    let image = image.clone();
    let origin_prefix = origin_prefix.map(Path::to_path_buf);
    let source_revision = String::from(revision.clone());
    let mut command = std::process::Command::new("/usr/libexec/memcordon-sealed-agent");
    command
        .args([
            "release-facility-controls",
            "final-public",
            selector.as_str(),
            challenge.as_str(),
            "--source-revision",
            source_revision.as_str(),
        ])
        .current_dir(root)
        .env_clear()
        .stdin(std::process::Stdio::null());
    let callback_directory = directory.clone();
    let output = memcordon_testkit::run_with_deadline_after_output_limit(
        &mut command,
        Duration::from_secs(90),
        128 * 1024,
        move |_| {
            for (phase, gate_name, ack_name) in [
                (
                    memcordon_core::private_facility_source_v1::FacilityPhaseV1::Outer,
                    "facility-helper-outer-v1.json",
                    "facility-helper-outer-v1.ack",
                ),
                (
                    memcordon_core::private_facility_source_v1::FacilityPhaseV1::Private,
                    "facility-helper-private-v1.json",
                    "facility-helper-private-v1.ack",
                ),
            ] {
                let start = std::time::Instant::now();
                let gate = loop {
                    match std::fs::symlink_metadata(callback_directory.join(gate_name)) {
                        Ok(_) => {
                            break crate::private_protected_readback::read_protected_raw_case_file(
                                &callback_directory.join(gate_name),
                            )
                            .map_err(|error| std::io::Error::other(error.to_string()))?;
                        }
                        Err(error)
                            if error.kind() == std::io::ErrorKind::NotFound
                                && start.elapsed() < Duration::from_secs(30) =>
                        {
                            std::thread::sleep(Duration::from_millis(5))
                        }
                        Err(error) => return Err(error),
                    }
                };
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Gate {
                    schema_version: u8,
                    selector: String,
                    parent_result_key: DiagnosticSha256,
                    prepared_admission_sha256: DiagnosticSha256,
                    installation_epoch: DiagnosticSha256,
                    active_h1_receipt_sha256: DiagnosticSha256,
                    manifest_sha256: DiagnosticSha256,
                    qualification_sha256: DiagnosticSha256,
                    source_revision_sha256: DiagnosticSha256,
                    phase: memcordon_core::private_facility_source_v1::FacilityPhaseV1,
                    helper: memcordon_core::private_facility_source_v1::FacilityProcessV1,
                    objects: Vec<memcordon_core::private_facility_source_v1::FacilityObjectV1>,
                    status: Vec<u8>,
                    observed_monotonic_ns: u64,
                }
                let parsed: Gate = crate::private_observer_session::strict_json(&gate, 128 * 1024)
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                if parsed.schema_version != 1
                    || parsed.selector != selector
                    || parsed.parent_result_key != key
                    || parsed.prepared_admission_sha256 != hash_bytes(&admission_bytes)
                    || parsed.installation_epoch != admission.installation_epoch
                    || parsed.active_h1_receipt_sha256 != admission.active_h1_receipt_sha256
                    || parsed.manifest_sha256 != policy.manifest_sha256
                    || parsed.qualification_sha256 != policy.qualification_sha256
                    || parsed.source_revision_sha256 != revision
                    || parsed.phase != phase
                    || parsed.objects.is_empty()
                    || parsed.observed_monotonic_ns == 0
                {
                    return Err(std::io::Error::other(
                        "public Facility held gate subject differs",
                    ));
                }
                let sample = crate::private_public_live::sample_held_target_raw(
                    parsed.helper.pid,
                    parsed.helper.start_time_ticks,
                    &image,
                )
                .map_err(|error| std::io::Error::other(error.to_string()))?;
                crate::private_public_source_facts::validate_public_facility_status_join(
                    &parsed.status,
                    sample.leaves.get("status.raw").ok_or_else(|| {
                        std::io::Error::other("public Facility original held status absent")
                    })?,
                )
                .map_err(|error| std::io::Error::other(error.to_string()))?;
                let phase_name = match phase {
                    memcordon_core::private_facility_source_v1::FacilityPhaseV1::Outer => "outer",
                    memcordon_core::private_facility_source_v1::FacilityPhaseV1::Private => {
                        "private"
                    }
                };
                let base = Path::new("facility").join(phase_name);
                let source_sample = if selector == "private_tcp::io_uring_and_pidfd_import_denied" {
                    let descriptors = parsed
                        .objects
                        .iter()
                        .filter(|object| object.role == "pidfd")
                        .collect::<Vec<_>>();
                    let [pidfd] = descriptors.as_slice() else {
                        return Err(std::io::Error::other(
                            "Facility source pidfd object is absent or ambiguous",
                        ));
                    };
                    let fdinfo = sample
                        .leaves
                        .get(
                            Path::new("tasks")
                                .join(sample.pid.to_string())
                                .join("fds")
                                .join(pidfd.fd.to_string())
                                .join("fdinfo.raw")
                                .to_string_lossy()
                                .as_ref(),
                        )
                        .ok_or_else(|| {
                            std::io::Error::other(
                                "Facility independently sampled pidfd fdinfo absent",
                            )
                        })?;
                    let text = std::str::from_utf8(fdinfo).map_err(std::io::Error::other)?;
                    let pids = text
                        .lines()
                        .filter_map(|line| line.strip_prefix("Pid:"))
                        .collect::<Vec<_>>();
                    let [value] = pids.as_slice() else {
                        return Err(std::io::Error::other(
                            "Facility sampled pidfd process is ambiguous",
                        ));
                    };
                    let pid = value.trim().parse::<u32>().map_err(std::io::Error::other)?;
                    if pid == 0 || pid == sample.pid {
                        return Err(std::io::Error::other(
                            "Facility pidfd source process differs",
                        ));
                    }
                    let start = crate::private_process_clock::read_live_start_ticks(pid)
                        .map_err(|error| std::io::Error::other(error.to_string()))?;
                    Some(
                        crate::private_public_live::sample_held_target_raw(pid, start, &image)
                            .map_err(|error| std::io::Error::other(error.to_string()))?,
                    )
                } else {
                    None
                };
                let encoded = encode_public_held_source(&sample, origin_prefix.as_deref(), &base)
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                let mut leaves = slot
                    .lock()
                    .map_err(|_| std::io::Error::other("public Facility sample lock poisoned"))?;
                leaves.insert(
                    base.join("gate.json").to_string_lossy().into_owned(),
                    gate.clone(),
                );
                leaves.insert(
                    base.join("ack.bin").to_string_lossy().into_owned(),
                    hash_bytes(&gate).bytes().to_vec(),
                );
                leaves.insert(
                    base.join("sample-v1.json").to_string_lossy().into_owned(),
                    encoded,
                );
                for (name, bytes) in sample.leaves {
                    leaves.insert(base.join(name).to_string_lossy().into_owned(), bytes);
                }
                if let Some(source) = source_sample {
                    let source_base = base.join("source");
                    leaves.insert(
                        source_base
                            .join("sample-v1.json")
                            .to_string_lossy()
                            .into_owned(),
                        encode_public_held_source(&source, origin_prefix.as_deref(), &source_base)
                            .map_err(|error| std::io::Error::other(error.to_string()))?,
                    );
                    for (name, bytes) in source.leaves {
                        leaves.insert(source_base.join(name).to_string_lossy().into_owned(), bytes);
                    }
                }
                drop(leaves);
                let mut ack = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(callback_directory.join(ack_name))?;
                ack.write_all(hash_bytes(&gate).bytes())?;
                ack.sync_all()?;
                std::fs::File::open(&callback_directory)?.sync_all()?;
            }
            Ok(())
        },
    )
    .map_err(|error| CiError::Message(error.to_string()))?;
    if !output.status.success() {
        return Err(CiError::Message(
            "public valid-context Facility helper failed; source proof unavailable".into(),
        ));
    }
    let mut leaves = collected
        .lock()
        .map_err(|_| CiError::Message("public Facility source lock poisoned".into()))?
        .clone();
    leaves.insert(
        "facility/facility-source-v1.json".into(),
        crate::private_protected_readback::read_protected_raw_case_file(
            &directory.join("facility-source-v1.json"),
        )?,
    );
    leaves.insert("facility/stdout.raw".into(), output.stdout);
    leaves.insert("facility/stderr.raw".into(), output.stderr);
    Ok(leaves)
}

fn complete_held_frames(bytes: &[u8]) -> std::io::Result<usize> {
    let mut offset = 0;
    let mut count = 0;
    while bytes.len().saturating_sub(offset) >= 12 {
        if &bytes[offset..offset + 8] != b"MCPH\x01\0\0\0" {
            return Err(std::io::Error::other("dual held frame magic differs"));
        }
        let length = u32::from_le_bytes(
            bytes[offset + 8..offset + 12]
                .try_into()
                .expect("fourbytes"),
        ) as usize;
        if length > 64 * 1024 {
            return Err(std::io::Error::other("dual held frame budget"));
        }
        let end = offset + 12 + length;
        if end > bytes.len() {
            break;
        }
        count += 1;
        offset = end;
    }
    if count > 2 {
        return Err(std::io::Error::other("dual held frame count differs"));
    }
    Ok(count)
}
