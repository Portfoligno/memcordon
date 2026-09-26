//! Structural contract for the installed public V2 CLI stage.
//!
//! These checks distinguish public `memcordon` execution from root-only
//! release-case fixtures. They do not authenticate Q, H1, a public grant, or
//! an OS terminal; consequently they cannot construct P or a trusted run.

use std::ffi::OsString;
#[cfg(unix)]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::io::Read;
use std::path::Path;

use memcordon_core::DiagnosticSha256;
use memcordon_core::private_public_report_v2::PublicCliReportEvidenceV2;
use memcordon_core::private_release_case_v1::PrivateReleaseAllocatedOutcomeV1;
use memcordon_core::report_v11::{
    PrivatePublicOutcomeV11, PrivatePublicResultV11, PrivateTerminalOutcomeV11,
};
use memcordon_core::workload_codec::hash_bytes;
use memcordon_core::workload_evidence_v2::QualifiedNativeAbiV2;
use memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES;

use crate::private_supervisor::SupervisedProcessV2;
use crate::{CiError, Result};

/// Arguments for the actual installed public CLI parser, never the privileged
/// `package release-case` endpoint. The caller must separately authenticate
/// the contract, fixture and installed executable before spawning anything.
pub fn public_v2_argv(
    contract_path: &Path,
    report_path: &Path,
    fixture_path: &Path,
) -> Result<Vec<OsString>> {
    public_v2_argv_with_expected_plan(contract_path, report_path, fixture_path, None)
}

pub fn public_v2_argv_with_expected_plan(
    contract_path: &Path,
    report_path: &Path,
    fixture_path: &Path,
    expected_plan_path: Option<&Path>,
) -> Result<Vec<OsString>> {
    if [contract_path, report_path, fixture_path]
        .into_iter()
        .any(|path| !path.is_absolute() || path.as_os_str().is_empty())
        || contract_path == report_path
        || contract_path == fixture_path
        || report_path == fixture_path
    {
        return Err(CiError::Message(
            "public V2 contract, report and fixture paths must be distinct absolute paths".into(),
        ));
    }
    if expected_plan_path.is_some_and(|path| {
        !path.is_absolute() || [contract_path, report_path, fixture_path].contains(&path)
    }) {
        return Err(CiError::Message(
            "public V2 expected plan path must be a distinct absolute path".into(),
        ));
    }
    let mut argv = vec![
        OsString::from("--sealed"),
        OsString::from("--workload-contract"),
        contract_path.as_os_str().to_owned(),
        OsString::from("--report"),
        report_path.as_os_str().to_owned(),
    ];
    if let Some(path) = expected_plan_path {
        argv.push(OsString::from("--expected-private-plan"));
        argv.push(path.as_os_str().to_owned());
    }
    argv.push(OsString::from("--"));
    argv.push(fixture_path.as_os_str().to_owned());
    Ok(argv)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpectedPublicV2Outcome {
    Exited(i32),
    NativeFailure,
    Interrupted,
    PreallocationRejected,
    AllocatedUnverified,
    Indeterminate,
    BeforeSubmissionFailure,
    TransportUnverified,
    FrontendLost,
}

/// Every hash must come from an independently reopened final installation or
/// release archive, never from the submitted public report. This is still a
/// structural expectation, not a trust token.
pub struct ExpectedPublicV2Readback<'a> {
    pub source_commit: &'a str,
    pub native_abi: QualifiedNativeAbiV2,
    pub archive_sha256: &'a DiagnosticSha256,
    pub runtime_manifest_sha256: &'a DiagnosticSha256,
    pub qualification_sha256: &'a DiagnosticSha256,
    pub host_receipt_sha256: &'a DiagnosticSha256,
    /// Independently observed effective UID of the public CLI child.
    pub report_owner_uid: u32,
    pub outcome: ExpectedPublicV2Outcome,
}

/// Non-authoritative parse/child join; deliberately not convertible to P.
pub struct StructuralPublicV2Readback {
    pub report_sha256: DiagnosticSha256,
    pub child_pid: u32,
    pub child_start_time_ticks: u64,
}

/// Replacement facts obtained from protected terminal, transport and recovery
/// readers outside the CLI process. Copying them from `report_evidence` would
/// make an absent report self-authenticating.
pub struct ExpectedFrontendLossEvidenceV2<'a> {
    pub authenticated_terminal_sha256: &'a DiagnosticSha256,
    pub supervised_transport_sha256: &'a DiagnosticSha256,
    pub independent_recovery_sha256: &'a DiagnosticSha256,
}

pub enum StructuralPublicV2ReportPresence {
    Present(StructuralPublicV2Readback),
    AbsentFrontendLoss {
        child_pid: u32,
        child_start_time_ticks: u64,
    },
}

/// Joins the versioned report-presence record with independently obtained
/// replacement facts. This remains structural and cannot construct P.
pub fn validate_public_v2_report_presence(
    observed: &SupervisedProcessV2,
    report_bytes: Option<&[u8]>,
    report_evidence: &PublicCliReportEvidenceV2,
    release_outcome: PrivateReleaseAllocatedOutcomeV1,
    expected: &ExpectedPublicV2Readback<'_>,
    replacement: Option<&ExpectedFrontendLossEvidenceV2<'_>>,
) -> Result<StructuralPublicV2ReportPresence> {
    report_evidence
        .validate_for_outcome(release_outcome, report_bytes)
        .map_err(CiError::Message)?;
    match (report_evidence, report_bytes, replacement) {
        (PublicCliReportEvidenceV2::Present { .. }, Some(bytes), None) => {
            Ok(StructuralPublicV2ReportPresence::Present(
                validate_structural_public_v2_readback(observed, bytes, expected)?,
            ))
        }
        (
            PublicCliReportEvidenceV2::AbsentFrontendLoss {
                authenticated_terminal_sha256,
                supervised_transport_sha256,
                independent_recovery_sha256,
            },
            None,
            Some(independent),
        ) if expected.outcome == ExpectedPublicV2Outcome::FrontendLost
            && !observed.status.success()
            && authenticated_terminal_sha256 == independent.authenticated_terminal_sha256
            && supervised_transport_sha256 == independent.supervised_transport_sha256
            && independent_recovery_sha256 == independent.independent_recovery_sha256 =>
        {
            validate_public_expected_identity(expected)?;
            let child = observed
                .linux_child
                .filter(|identity| identity.pid != 0 && identity.start_time_ticks != 0)
                .ok_or_else(|| {
                    CiError::Message("public V2 child kernel identity is absent".into())
                })?;
            Ok(StructuralPublicV2ReportPresence::AbsentFrontendLoss {
                child_pid: child.pid,
                child_start_time_ticks: child.start_time_ticks,
            })
        }
        _ => Err(CiError::Message(
            "public V2 report evidence or independent replacement differs".into(),
        )),
    }
}

fn validate_public_expected_identity(expected: &ExpectedPublicV2Readback<'_>) -> Result<()> {
    let zero = DiagnosticSha256::from_bytes([0; 32]);
    if expected.source_commit.len() != 40
        || !expected
            .source_commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || [
            expected.archive_sha256,
            expected.runtime_manifest_sha256,
            expected.qualification_sha256,
            expected.host_receipt_sha256,
        ]
        .into_iter()
        .any(|digest| *digest == zero)
    {
        return Err(CiError::Message(
            "public V2 independent final identity is incomplete".into(),
        ));
    }
    Ok(())
}

pub fn validate_structural_public_v2_readback(
    observed: &SupervisedProcessV2,
    report_bytes: &[u8],
    expected: &ExpectedPublicV2Readback<'_>,
) -> Result<StructuralPublicV2Readback> {
    validate_public_expected_identity(expected)?;
    let child = observed
        .linux_child
        .filter(|identity| identity.pid != 0 && identity.start_time_ticks != 0)
        .ok_or_else(|| CiError::Message("public V2 child kernel identity is absent".into()))?;
    if report_bytes.is_empty() || report_bytes.len() > PUBLIC_OBJECT_BYTES {
        return Err(CiError::Message("public V2 report size differs".into()));
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(report_bytes)
        .map_err(CiError::Message)?;
    let report: PrivatePublicResultV11 = serde_json::from_slice(report_bytes)?;
    report.validate_structure().map_err(CiError::Message)?;
    let actual = match &report.result {
        PrivatePublicOutcomeV11::Complete { terminal, .. } => {
            if terminal.source_commit != expected.source_commit
                || terminal.native_abi != expected.native_abi
                || terminal.runtime_manifest_sha256 != *expected.runtime_manifest_sha256
                || terminal.installed_qualification_sha256 != *expected.qualification_sha256
            {
                return Err(CiError::Message(
                    "public V2 terminal differs from final M1/Q".into(),
                ));
            }
            match terminal.outcome {
                PrivateTerminalOutcomeV11::Exited { code } => ExpectedPublicV2Outcome::Exited(code),
                PrivateTerminalOutcomeV11::NativeFailure { .. } => {
                    ExpectedPublicV2Outcome::NativeFailure
                }
                PrivateTerminalOutcomeV11::Interrupted { .. } => {
                    ExpectedPublicV2Outcome::Interrupted
                }
            }
        }
        PrivatePublicOutcomeV11::PreallocationRejected { .. } => {
            ExpectedPublicV2Outcome::PreallocationRejected
        }
        PrivatePublicOutcomeV11::AllocatedUnverified { .. } => {
            ExpectedPublicV2Outcome::AllocatedUnverified
        }
        PrivatePublicOutcomeV11::Indeterminate { .. } => ExpectedPublicV2Outcome::Indeterminate,
        PrivatePublicOutcomeV11::BeforeSubmissionFailure { .. } => {
            ExpectedPublicV2Outcome::BeforeSubmissionFailure
        }
        PrivatePublicOutcomeV11::TransportUnverified { .. } => {
            ExpectedPublicV2Outcome::TransportUnverified
        }
    };
    let expected_status = match actual {
        ExpectedPublicV2Outcome::Exited(code) if (0..=255).contains(&code) => code,
        _ => 125,
    };
    if actual != expected.outcome || observed.status.code() != Some(expected_status) {
        return Err(CiError::Message(
            "public V2 report outcome differs from observed CLI exit".into(),
        ));
    }
    Ok(StructuralPublicV2Readback {
        report_sha256: hash_bytes(report_bytes),
        child_pid: child.pid,
        child_start_time_ticks: child.start_time_ticks,
    })
}

/// Reads the CLI's report from a pinned no-follow leaf and checks that the
/// same file remained at the expected path throughout readback. A same-UID
/// process could still author these bytes, so this remains structural only.
#[cfg(unix)]
pub fn read_structural_public_v2_report(
    path: &Path,
    observed: &SupervisedProcessV2,
    expected: &ExpectedPublicV2Readback<'_>,
) -> Result<StructuralPublicV2Readback> {
    let bytes = read_public_v2_report_bytes(path, expected.report_owner_uid)?;
    validate_structural_public_v2_readback(observed, &bytes, expected)
}

/// Reads a present report or verifies exact absence for a frontend-loss case.
/// Protected replacement observations must be independently supplied.
#[cfg(unix)]
pub fn read_structural_public_v2_report_presence(
    path: &Path,
    observed: &SupervisedProcessV2,
    report_evidence: &PublicCliReportEvidenceV2,
    release_outcome: PrivateReleaseAllocatedOutcomeV1,
    expected: &ExpectedPublicV2Readback<'_>,
    replacement: Option<&ExpectedFrontendLossEvidenceV2<'_>>,
) -> Result<StructuralPublicV2ReportPresence> {
    if !path.is_absolute() {
        return Err(CiError::Message(
            "public V2 report path is not absolute".into(),
        ));
    }
    let bytes = match report_evidence {
        PublicCliReportEvidenceV2::Present { .. } => Some(read_public_v2_report_bytes(
            path,
            expected.report_owner_uid,
        )?),
        PublicCliReportEvidenceV2::AbsentFrontendLoss { .. } => {
            match std::fs::symlink_metadata(path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(error.into()),
                Ok(_) => {
                    return Err(CiError::Message(
                        "frontend-loss CLI report unexpectedly exists".into(),
                    ));
                }
            }
        }
    };
    validate_public_v2_report_presence(
        observed,
        bytes.as_deref(),
        report_evidence,
        release_outcome,
        expected,
        replacement,
    )
}

#[cfg(unix)]
pub(crate) fn read_public_v2_report_bytes(path: &Path, report_owner_uid: u32) -> Result<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    if !path.is_absolute() {
        return Err(CiError::Message(
            "public V2 report path is not absolute".into(),
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.nlink() != 1
        || before.uid() != report_owner_uid
        || before.mode() & 0o7777 != 0o600
        || before.len() == 0
        || before.len() > PUBLIC_OBJECT_BYTES as u64
    {
        return Err(CiError::Message(
            "public V2 report file protection differs".into(),
        ));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take((PUBLIC_OBJECT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let leaf_after = std::fs::symlink_metadata(path)?;
    if bytes.len() as u64 != before.len()
        || (
            before.dev(),
            before.ino(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        )
        || (after.dev(), after.ino()) != (leaf_after.dev(), leaf_after.ino())
        || !leaf_after.is_file()
    {
        return Err(CiError::Message(
            "public V2 report changed during readback".into(),
        ));
    }
    Ok(bytes)
}
