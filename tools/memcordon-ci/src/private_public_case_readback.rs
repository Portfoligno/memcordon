//! Detached structural join for one versioned final-public case.
//!
//! Every expected value must come from installation, supervisor, protected
//! terminal, or raw-file readback outside the submitted case record. Matching
//! bytes do not authenticate those sources and cannot construct P.

use memcordon_core::DiagnosticSha256;
use memcordon_core::private_public_case_v2::{
    FinalPublicCaseEvidenceV2, FinalPublicChildIdentityV2, FinalPublicInstalledBindingV2,
};
use memcordon_core::private_public_report_v2::PublicCliReportEvidenceV2;
use memcordon_core::private_release_case_v1::{
    PrivateReleaseAttachmentRoleV1, PrivateReleaseAttachmentV1, PrivateReleaseObservationV1,
};
use memcordon_core::workload_codec::hash_bytes;

use crate::private_public_v2::ExpectedFrontendLossEvidenceV2;
use crate::private_supervisor::SupervisedProcessV2;
use crate::{CiError, Result};

pub struct RawPublicAttachmentV2<'a> {
    pub role: PrivateReleaseAttachmentRoleV1,
    pub bytes: &'a [u8],
}

pub struct ExpectedFinalPublicCaseV2<'a> {
    pub selector: &'a str,
    pub challenge: [u8; 32],
    pub source_commit: &'a str,
    pub release_version: &'a str,
    pub target: &'a str,
    pub native_machine: &'a str,
    pub build_context_sha256: &'a DiagnosticSha256,
    pub release_catalogue_sha256: &'a DiagnosticSha256,
    pub installed: &'a FinalPublicInstalledBindingV2,
    pub child: &'a FinalPublicChildIdentityV2,
    pub terminal_observation: &'a PrivateReleaseObservationV1,
    pub positive_control_terminal_sha256: Option<&'a DiagnosticSha256>,
    pub frontend_loss_replacement: Option<&'a ExpectedFrontendLossEvidenceV2<'a>>,
    pub supervised_child: &'a SupervisedProcessV2,
    pub raw_attachments: &'a [RawPublicAttachmentV2<'a>],
}

pub struct StructuralFinalPublicCaseReadbackV2 {
    pub case_sha256: DiagnosticSha256,
    pub result_key: DiagnosticSha256,
    pub child_pid: u32,
    pub child_start_time_ticks: u64,
}

/// Assemble a structural V2 case from separately acquired inputs. The caller
/// must obtain `terminal_observation` from authenticated provider and kernel
/// observations; this function itself cannot confer P authority.
pub fn assemble_structural_final_public_case(
    expected: &ExpectedFinalPublicCaseV2<'_>,
) -> Result<(Vec<u8>, StructuralFinalPublicCaseReadbackV2)> {
    let absent = expected.frontend_loss_replacement.is_some();
    let roles: &[PrivateReleaseAttachmentRoleV1] = if absent {
        &[
            PrivateReleaseAttachmentRoleV1::Request,
            PrivateReleaseAttachmentRoleV1::Stdio,
            PrivateReleaseAttachmentRoleV1::Observer,
            PrivateReleaseAttachmentRoleV1::Cleanup,
        ]
    } else {
        &PrivateReleaseAttachmentRoleV1::ALL
    };
    if expected.raw_attachments.len() != roles.len()
        || expected
            .raw_attachments
            .iter()
            .zip(roles)
            .any(|(raw, role)| raw.role != *role)
    {
        return Err(CiError::Message(
            "final-public assembly raw inventory differs".into(),
        ));
    }
    let report = if absent {
        None
    } else {
        Some(expected.raw_attachments[1].bytes)
    };
    if report.is_some_and(|report| report.is_empty()) {
        return Err(CiError::Message(
            "final-public assembly report is absent".into(),
        ));
    }
    let report_evidence = match (report, expected.frontend_loss_replacement) {
        (Some(report), None) => PublicCliReportEvidenceV2::Present {
            size: report.len() as u64,
            sha256: hash_bytes(report),
        },
        (None, Some(replacement)) => PublicCliReportEvidenceV2::AbsentFrontendLoss {
            authenticated_terminal_sha256: replacement.authenticated_terminal_sha256.clone(),
            supervised_transport_sha256: replacement.supervised_transport_sha256.clone(),
            independent_recovery_sha256: replacement.independent_recovery_sha256.clone(),
        },
        _ => {
            return Err(CiError::Message(
                "final-public report presence differs".into(),
            ));
        }
    };
    let case = FinalPublicCaseEvidenceV2 {
        schema_version: 2,
        selector: expected.selector.into(),
        challenge: expected.challenge,
        source_commit: expected.source_commit.into(),
        release_version: memcordon_core::BoundedText::<128>::new(expected.release_version)
            .map_err(|error| CiError::Message(error.into()))?,
        target: expected.target.into(),
        native_machine: expected.native_machine.into(),
        build_context_sha256: expected.build_context_sha256.clone(),
        release_catalogue_sha256: expected.release_catalogue_sha256.clone(),
        installed: expected.installed.clone(),
        child: expected.child.clone(),
        observation: expected.terminal_observation.clone(),
        positive_control_terminal_sha256: expected.positive_control_terminal_sha256.cloned(),
        report: report_evidence,
        attachments: expected
            .raw_attachments
            .iter()
            .map(|raw| PrivateReleaseAttachmentV1 {
                role: raw.role,
                size: raw.bytes.len() as u64,
                sha256: hash_bytes(raw.bytes),
            })
            .collect(),
    };
    case.validate_report_bytes(report)
        .map_err(CiError::Message)?;
    let bytes = serde_json::to_vec(&case)?;
    let readback = validate_structural_final_public_case(&bytes, expected)?;
    Ok((bytes, readback))
}

pub fn validate_structural_final_public_case(
    case_bytes: &[u8],
    expected: &ExpectedFinalPublicCaseV2<'_>,
) -> Result<StructuralFinalPublicCaseReadbackV2> {
    let case = FinalPublicCaseEvidenceV2::parse(case_bytes).map_err(CiError::Message)?;
    let child = expected
        .supervised_child
        .linux_child
        .filter(|child| child.pid != 0 && child.start_time_ticks != 0)
        .ok_or_else(|| {
            CiError::Message("final-public child was not independently observed".into())
        })?;
    if case.selector != expected.selector
        || case.challenge != expected.challenge
        || case.source_commit != expected.source_commit
        || case.release_version.as_str() != expected.release_version
        || case.target != expected.target
        || case.native_machine != expected.native_machine
        || case.build_context_sha256 != *expected.build_context_sha256
        || case.release_catalogue_sha256 != *expected.release_catalogue_sha256
        || &case.installed != expected.installed
        || &case.child != expected.child
        || child.pid != case.child.pid
        || child.start_time_ticks != case.child.start_time_ticks
        || &case.observation != expected.terminal_observation
        || case.positive_control_terminal_sha256.as_ref()
            != expected.positive_control_terminal_sha256
        || case.attachments.len() != expected.raw_attachments.len()
    {
        return Err(CiError::Message(
            "final-public case differs from independent identity or terminal readback".into(),
        ));
    }
    for (attachment, raw) in case.attachments.iter().zip(expected.raw_attachments) {
        if attachment.role != raw.role
            || attachment.size != raw.bytes.len() as u64
            || attachment.sha256 != hash_bytes(raw.bytes)
        {
            return Err(CiError::Message(
                "final-public raw attachment differs from detached readback".into(),
            ));
        }
    }
    match (&case.report, expected.frontend_loss_replacement) {
        (PublicCliReportEvidenceV2::Present { .. }, None) => {}
        (
            PublicCliReportEvidenceV2::AbsentFrontendLoss {
                authenticated_terminal_sha256,
                supervised_transport_sha256,
                independent_recovery_sha256,
            },
            Some(replacement),
        ) if !expected.supervised_child.status.success()
            && authenticated_terminal_sha256 == replacement.authenticated_terminal_sha256
            && supervised_transport_sha256 == replacement.supervised_transport_sha256
            && independent_recovery_sha256 == replacement.independent_recovery_sha256 => {}
        _ => {
            return Err(CiError::Message(
                "final-public report absence lacks independent replacement".into(),
            ));
        }
    }
    let report_bytes = expected
        .raw_attachments
        .iter()
        .find(|attachment| attachment.role == PrivateReleaseAttachmentRoleV1::Report)
        .map(|attachment| attachment.bytes);
    case.validate_report_bytes(report_bytes)
        .map_err(CiError::Message)?;
    Ok(StructuralFinalPublicCaseReadbackV2 {
        case_sha256: hash_bytes(case_bytes),
        result_key: case.result_key().map_err(CiError::Message)?,
        child_pid: child.pid,
        child_start_time_ticks: child.start_time_ticks,
    })
}
