//! Lossless candidate C transport. The V2 completion summary cannot encode a
//! dual-attempt V1 result, so V3 carries exact protected result and raw bytes.
//! Parsing C is structural; only the independent semantic capability may
//! authorize production, and the downstream collector must reverify it.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read, Write};
use std::path::Path;

use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::{
    PrivateReleaseAbiRawInventoryV1, PrivateReleaseAttachmentRoleV1, PrivateReleaseCaseResultV1,
    PrivateReleaseObservationV1, PrivateReleaseStageV1, REQUIRED_PRIVATE_RELEASE_SELECTORS_V1,
    private_release_case_key_v1,
};
use memcordon_core::workload_codec::hash_bytes;
use serde::{Deserialize, Serialize};

use crate::private_native_verify::VerifiedCandidateSemanticsV2;
use crate::{CiError, Result};

const MAX_ZIP_BYTES: usize = 64 * 1024 * 1024;
const MAX_MEMBER_BYTES: u64 = 8 * 1024 * 1024;
const MAX_INDEX_BYTES: usize = 128 * 1024;
const INDEX: &str = "candidate-c-v3/index.json";
pub(crate) const REPLAY_BUNDLE_LEAF: &str = "replay-bundle.v1.bin";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateRawMemberV3 {
    pub path: String,
    pub size: u64,
    pub sha256: DiagnosticSha256,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateCaseV3 {
    pub selector: String,
    pub result_key: DiagnosticSha256,
    pub result: CandidateRawMemberV3,
    pub attachments: Vec<CandidateRawMemberV3>,
    pub kernel_capture: CandidateRawMemberV3,
    pub family_raw: Vec<CandidateRawMemberV3>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateEvidenceIndexV3 {
    pub schema_version: u8,
    pub target: String,
    pub source_commit: String,
    pub release_version: String,
    pub collector_intent_sha256: DiagnosticSha256,
    pub cases: Vec<CandidateCaseV3>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observer_raw: Vec<CandidateRawMemberV3>,
}

/// Exact bytes retained from the protected native producer and independent
/// BPF capture. The family leaves are additional versioned native transcripts.
pub(crate) struct CandidateCaseBytesV3 {
    pub(crate) result: Vec<u8>,
    pub(crate) attachments: [Vec<u8>; 5],
    pub(crate) kernel_capture: Vec<u8>,
    pub(crate) family_raw: BTreeMap<String, Vec<u8>>,
}

/// Exact bounded members retained for downstream independent replay. This
/// structural readback does not authenticate who observed a kernel interval.
pub(crate) struct ParsedCandidateC3V1 {
    pub(crate) index: CandidateEvidenceIndexV3,
    pub(crate) index_sha256: DiagnosticSha256,
    members: BTreeMap<String, Vec<u8>>,
}

impl ParsedCandidateC3V1 {
    pub(crate) fn member(&self, path: &str) -> Option<&[u8]> {
        self.members.get(path).map(Vec::as_slice)
    }
    pub(crate) fn payload_members(&self) -> BTreeMap<String, Vec<u8>> {
        self.members
            .iter()
            .filter(|(path, _)| path.as_str() != INDEX && !origin_leaf(path))
            .map(|(path, bytes)| (path.clone(), bytes.clone()))
            .collect()
    }
    pub(crate) fn origin_member(&self, leaf: &str) -> Result<&[u8]> {
        let members: Vec<_> = self
            .members
            .iter()
            .filter(|(path, _)| path.rsplit('/').next() == Some(leaf))
            .collect();
        let [(_, bytes)] = members.as_slice() else {
            return Err(CiError::Message(
                "candidate origin carrier absent/ambiguous".into(),
            ));
        };
        Ok(bytes)
    }
}
fn origin_leaf(path: &str) -> bool {
    matches!(
        path.rsplit('/').next(),
        Some(
            crate::private_observer_session::PAYLOAD_INDEX_LEAF
                | crate::private_observer_session::ORIGIN_COMMITMENT_LEAF
                | crate::private_observer_session::ORIGIN_RECEIPT_LEAF
        )
    )
}

fn member(path: String, bytes: &[u8]) -> Result<CandidateRawMemberV3> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_MEMBER_BYTES || !valid_member_path(&path) {
        return Err(CiError::Message(
            "candidate C raw member bound or path differs".into(),
        ));
    }
    Ok(CandidateRawMemberV3 {
        path,
        size: bytes.len() as u64,
        sha256: hash_bytes(bytes),
    })
}

fn valid_member_path(path: &str) -> bool {
    (path.starts_with("candidate-c-v3/cases/") || valid_observer_path(path))
        && path.len() <= 256
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
}

fn valid_observer_path(path: &str) -> bool {
    let Some(relative) = path.strip_prefix("candidate-c-v3/observer/") else {
        return false;
    };
    let parts = relative.split('/').collect::<Vec<_>>();
    match parts.as_slice() {
        ["intervals", id, leaf] => {
            id.len() == 64
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                && matches!(
                    *leaf,
                    "capture.bin"
                        | "clock.json"
                        | "control-output.raw"
                        | "request.json"
                        | "attempt.json"
                        | "result.json"
                        | "replay-rejection.json"
                        | "pre-samples.json"
                        | "second-pre-samples.json"
                        | "baseline-samples.json"
                        | "second-baseline-samples.json"
                        | "second-after-retirement-samples.json"
                        | "post-samples.json"
                        | "namespace-closes.json"
                        | "stdout.raw"
                        | "stderr.raw"
                        | "pre-gate.json"
                        | "first-pre-gate.json"
                        | "second-pre-gate.json"
                        | "post-gate.json"
                        | "baseline-gate.json"
                        | "first-baseline-gate.json"
                        | "second-baseline-gate.json"
                        | "second-after-retirement-gate.json"
                        | "request.bin"
                        | "report.bin"
                        | "stdio.bin"
                        | "observer.bin"
                        | "cleanup.bin"
                )
        }
        ["generations", generation, leaf] => {
            matches!(*generation, "0" | "1")
                && matches!(
                    *leaf,
                    "installation-epoch.json"
                        | "installed-receipt.json"
                        | "manifest.json"
                        | "service.json"
                        | "broker.json"
                        | "transaction.json"
                        | "observer-map.json"
                )
        }
        _ => false,
    }
}

fn case_prefix(key: &DiagnosticSha256) -> String {
    format!("candidate-c-v3/cases/{}", String::from(key.clone()))
}

fn required_family_leaf(selector: &str, target: &str) -> Option<&'static str> {
    match selector {
        "private_tcp::abi_alternate_entry_denied" if target == "x86_64-unknown-linux-gnu" => {
            Some("x32-alternate.raw.json")
        }
        "private_tcp::abi_alternate_entry_denied" => Some("arm32-alternate.raw.json"),
        "private_tcp::caller_identity_and_epoch_bound" => Some("historical-epoch.raw.json"),
        _ => None,
    }
}

const POLICY_FAMILY_LEAVES_V3: [&str; 17] = [
    "policy-intent.v1.json",
    "policy-branches.raw.json",
    "accepted-control.request.json",
    "accepted-control.raw.json",
    "accepted-control.kernel.capture.bin",
    "wrong-grant.request.json",
    "wrong-grant.raw.json",
    "wrong-grant.kernel.capture.bin",
    "wrong-profile.request.json",
    "wrong-profile.raw.json",
    "wrong-profile.kernel.capture.bin",
    "unapproved-changed-port-plan.request.json",
    "unapproved-changed-port-plan.raw.json",
    "unapproved-changed-port-plan.kernel.capture.bin",
    "committed-port-tamper.request.json",
    "committed-port-tamper.raw.json",
    "committed-port-tamper.kernel.capture.bin",
];

const X86_ABI_FAMILY_LEAVES_V3: [&str; 4] = [
    "request.json",
    "attempt.json",
    "x32-alternate.raw.json",
    "i386-entry.raw.json",
];
const ARM_ABI_FAMILY_LEAVES_V3: [&str; 3] =
    ["request.json", "attempt.json", "arm32-alternate.raw.json"];

fn validate_index(
    index: &CandidateEvidenceIndexV3,
    members: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    if members.len() > 256 {
        return Err(CiError::Message(
            "candidate C exceeds reviewed 256-member budget".into(),
        ));
    }
    if !matches!(index.schema_version, 3 | 4 | 5 | 6)
        || index.cases.len() != REQUIRED_PRIVATE_RELEASE_SELECTORS_V1.len()
        || index.collector_intent_sha256 == hash_bytes(&[])
        || index.source_commit.len() != 40
        || !index
            .source_commit
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || index.release_version.is_empty()
        || !matches!(
            index.target.as_str(),
            "x86_64-unknown-linux-gnu" | "aarch64-unknown-linux-gnu"
        )
    {
        return Err(CiError::Message("candidate C index subject differs".into()));
    }
    let mut required = BTreeSet::from([INDEX.to_owned()]);
    if index.schema_version < 5 && !index.observer_raw.is_empty() {
        return Err(CiError::Message(
            "legacy candidate C cannot carry observer metadata".into(),
        ));
    }
    if index.observer_raw.len() > 256 {
        return Err(CiError::Message(
            "candidate observer metadata inventory exceeds closed interval budget".into(),
        ));
    }
    for raw in &index.observer_raw {
        let bytes = members
            .get(&raw.path)
            .ok_or_else(|| CiError::Message("candidate observer raw member absent".into()))?;
        if !valid_observer_path(&raw.path)
            || bytes.is_empty()
            || bytes.len() as u64 > MAX_MEMBER_BYTES
            || raw.size != bytes.len() as u64
            || raw.sha256 != hash_bytes(bytes)
            || !required.insert(raw.path.clone())
        {
            return Err(CiError::Message(
                "candidate observer raw inventory path/size/digest differs".into(),
            ));
        }
    }
    let mut keys = BTreeSet::new();
    for (case, selector) in index
        .cases
        .iter()
        .zip(REQUIRED_PRIVATE_RELEASE_SELECTORS_V1)
    {
        let prefix = case_prefix(&case.result_key);
        let result_bytes = members
            .get(&case.result.path)
            .ok_or_else(|| CiError::Message("candidate C protected result absent".into()))?;
        let result = PrivateReleaseCaseResultV1::parse(result_bytes).map_err(CiError::Message)?;
        let challenge = result.challenge_bytes().map_err(CiError::Message)?;
        if case.selector != selector
            || result.selector != selector
            || result.target != index.target
            || private_release_case_key_v1(
                PrivateReleaseStageV1::CandidateCapability,
                selector,
                &challenge,
            )
            .map_err(CiError::Message)?
                != case.result_key
            || !keys.insert(String::from(case.result_key.clone()))
            || case.result.path != format!("{prefix}/result.json")
            || case.kernel_capture.path
                != format!(
                    "{prefix}/kernel-{}.capture.bin",
                    String::from(index.collector_intent_sha256.clone())
                )
            || case.attachments.len() != PrivateReleaseAttachmentRoleV1::ALL.len()
        {
            return Err(CiError::Message("candidate C case identity differs".into()));
        }
        let expected = std::iter::once(&case.result)
            .chain(case.attachments.iter())
            .chain(std::iter::once(&case.kernel_capture))
            .chain(case.family_raw.iter());
        for raw in expected {
            let bytes = members
                .get(&raw.path)
                .ok_or_else(|| CiError::Message("candidate C raw leaf absent".into()))?;
            if !raw.path.starts_with(&format!("{prefix}/"))
                || !valid_member_path(&raw.path)
                || raw.size != bytes.len() as u64
                || raw.sha256 != hash_bytes(bytes)
                || !required.insert(raw.path.clone())
            {
                return Err(CiError::Message("candidate C raw leaf differs".into()));
            }
        }
        for (position, (role, raw)) in PrivateReleaseAttachmentRoleV1::ALL
            .iter()
            .zip(&case.attachments)
            .enumerate()
        {
            if raw.path != format!("{prefix}/{}", role.leaf()) {
                return Err(CiError::Message(
                    "candidate C attachment role differs".into(),
                ));
            }
            let described = &result.attachments[position];
            if described.role != *role
                || described.size != raw.size
                || described.sha256 != raw.sha256
            {
                return Err(CiError::Message(
                    "candidate C protected attachment differs".into(),
                ));
            }
        }
        if case
            .family_raw
            .iter()
            .any(|raw| !raw.path.starts_with(&format!("{prefix}/family/")))
        {
            return Err(CiError::Message(
                "candidate C family leaf path differs".into(),
            ));
        }
        if index.schema_version >= 4 {
            let mut expected = required_case_family_leaves_v4(selector, &index.target)
                .into_iter()
                .map(|leaf| format!("{prefix}/family/{leaf}"))
                .collect::<BTreeSet<_>>();
            if index.schema_version == 6 {
                expected.insert(format!("{prefix}/family/source-carrier.v1.bin"));
                crate::private_source_carrier::parse_source_carrier(
                    members
                        .get(&format!("{prefix}/family/source-carrier.v1.bin"))
                        .ok_or_else(|| {
                            CiError::Message("candidate exact source carrier absent".into())
                        })?,
                )?;
            }
            if case
                .family_raw
                .iter()
                .map(|raw| raw.path.clone())
                .collect::<BTreeSet<_>>()
                != expected
            {
                return Err(CiError::Message(
                    "candidate C4 exact replay/origin/family inventory differs".into(),
                ));
            }
            let bundle = members
                .get(&format!("{prefix}/family/{REPLAY_BUNDLE_LEAF}"))
                .ok_or_else(|| CiError::Message("candidate replay bundle absent".into()))?;
            let leaves = crate::private_candidate_replay::parse_replay_bundle(bundle)?;
            for role in [
                crate::private_candidate_replay::ReplayLeafRoleV1::Facts,
                crate::private_candidate_replay::ReplayLeafRoleV1::Request,
                crate::private_candidate_replay::ReplayLeafRoleV1::Clock,
                crate::private_candidate_replay::ReplayLeafRoleV1::Controls,
            ] {
                if !leaves
                    .iter()
                    .any(|leaf| leaf.role == role && leaf.ordinal == 0)
                {
                    return Err(CiError::Message(
                        "candidate required raw replay role absent".into(),
                    ));
                }
            }
        }
        if let Some(leaf) = required_family_leaf(selector, &index.target) {
            if !case
                .family_raw
                .iter()
                .any(|raw| raw.path == format!("{prefix}/family/{leaf}"))
            {
                return Err(CiError::Message(
                    "candidate C required family transcript absent".into(),
                ));
            }
        }
        if index.schema_version == 3
            && selector == "private_tcp::wrong_grant_profile_and_port_rejected"
        {
            let expected = POLICY_FAMILY_LEAVES_V3
                .iter()
                .map(|leaf| format!("{prefix}/family/{leaf}"))
                .collect::<BTreeSet<_>>();
            if case
                .family_raw
                .iter()
                .map(|raw| raw.path.clone())
                .collect::<BTreeSet<_>>()
                != expected
            {
                return Err(CiError::Message(
                    "candidate C policy five-branch raw/capture inventory differs".into(),
                ));
            }
        }
        if selector == "private_tcp::abi_alternate_entry_denied" {
            let leaves: &[&str] = if index.target == "x86_64-unknown-linux-gnu" {
                &X86_ABI_FAMILY_LEAVES_V3
            } else {
                &ARM_ABI_FAMILY_LEAVES_V3
            };
            let expected = leaves
                .iter()
                .map(|leaf| format!("{prefix}/family/{leaf}"))
                .collect::<BTreeSet<_>>();
            if index.schema_version == 3
                && case
                    .family_raw
                    .iter()
                    .map(|raw| raw.path.clone())
                    .collect::<BTreeSet<_>>()
                    != expected
            {
                return Err(CiError::Message(
                    "candidate C ABI protected request/subwitness inventory differs".into(),
                ));
            }
            let PrivateReleaseObservationV1::AbiComposite {
                abi_raw,
                independent_interval_sha256,
                terminal_sha256,
                retirement_sha256,
                ..
            } = &result.observation
            else {
                return Err(CiError::Message(
                    "candidate C ABI composite result absent".into(),
                ));
            };
            let leaf = |name: &str| members.get(&format!("{prefix}/family/{name}"));
            let request = leaf("request.json")
                .ok_or_else(|| CiError::Message("candidate ABI request leaf absent".into()))?;
            let capture = members
                .get(&case.kernel_capture.path)
                .ok_or_else(|| CiError::Message("candidate ABI capture absent".into()))?;
            if request
                != members.get(&case.attachments[0].path).ok_or_else(|| {
                    CiError::Message("candidate ABI request attachment absent".into())
                })?
                || independent_interval_sha256 != &hash_bytes(capture)
                || terminal_sha256
                    != &hash_bytes(leaf("attempt.json").ok_or_else(|| {
                        CiError::Message("candidate ABI attempt leaf absent".into())
                    })?)
                || retirement_sha256 != &case.attachments[4].sha256
            {
                return Err(CiError::Message(
                    "candidate C ABI positive/raw/capture hashes differ".into(),
                ));
            }
            match abi_raw {
                PrivateReleaseAbiRawInventoryV1::X86_64 {
                    x32_sha256,
                    i386_sha256,
                } => {
                    if leaf("x32-alternate.raw.json").map(|bytes| hash_bytes(bytes))
                        != Some(x32_sha256.clone())
                        || leaf("i386-entry.raw.json").map(|bytes| hash_bytes(bytes))
                            != Some(i386_sha256.clone())
                    {
                        return Err(CiError::Message(
                            "candidate C x86 ABI subwitness hash differs".into(),
                        ));
                    }
                }
                PrivateReleaseAbiRawInventoryV1::Aarch64 { arm32_sha256 } => {
                    if leaf("arm32-alternate.raw.json").map(|bytes| hash_bytes(bytes))
                        != Some(arm32_sha256.clone())
                    {
                        return Err(CiError::Message(
                            "candidate C ARM32 subwitness hash differs".into(),
                        ));
                    }
                }
            }
        }
    }
    if members.keys().cloned().collect::<BTreeSet<_>>() != required {
        return Err(CiError::Message("candidate C member set differs".into()));
    }
    if index.schema_version >= 4 {
        let expected_entries = if index.target == "x86_64-unknown-linux-gnu" {
            226
        } else {
            225
        };
        let source_carriers = if index.schema_version == 6 { 25 } else { 0 };
        if index.schema_version == 6 && !index.observer_raw.is_empty() {
            return Err(CiError::Message(
                "packed candidate still declares standalone source aliases".into(),
            ));
        }
        if members.len() != expected_entries + index.observer_raw.len() + source_carriers {
            return Err(CiError::Message(
                "candidate C4 reviewed entry arithmetic differs".into(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn required_case_family_leaves_v4(selector: &str, target: &str) -> Vec<&'static str> {
    let mut leaves = vec![REPLAY_BUNDLE_LEAF];
    match selector {
        "private_tcp::wrong_grant_profile_and_port_rejected" => {
            leaves.extend(POLICY_FAMILY_LEAVES_V3)
        }
        "private_tcp::abi_alternate_entry_denied" => {
            if target == "x86_64-unknown-linux-gnu" {
                leaves.extend(X86_ABI_FAMILY_LEAVES_V3);
            } else {
                leaves.extend(ARM_ABI_FAMILY_LEAVES_V3);
            }
            leaves.extend([
                crate::private_observer_session::PAYLOAD_INDEX_LEAF,
                crate::private_observer_session::ORIGIN_COMMITMENT_LEAF,
                crate::private_observer_session::ORIGIN_RECEIPT_LEAF,
            ]);
        }
        "private_tcp::caller_identity_and_epoch_bound" => leaves.push("historical-epoch.raw.json"),
        _ => (),
    }
    leaves.sort();
    leaves
}

/// Parses exact C bytes, including the dual-branch result without flattening
/// it into a one-attempt summary. This returns no qualification capability.
pub fn parse_candidate_c_v3(bytes: &[u8]) -> Result<CandidateEvidenceIndexV3> {
    Ok(parse_candidate_c_v3_full(bytes)?.index)
}

pub(crate) fn parse_candidate_c_v3_full(bytes: &[u8]) -> Result<ParsedCandidateC3V1> {
    if bytes.is_empty() || bytes.len() > MAX_ZIP_BYTES {
        return Err(CiError::Message("candidate C ZIP bound differs".into()));
    }
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
    if archive.len() == 0 || archive.len() > 256 {
        return Err(CiError::Message("candidate C member count differs".into()));
    }
    let mut members = BTreeMap::new();
    let mut expanded = 0_u64;
    for index in 0..archive.len() {
        let mut file = archive.by_index(index)?;
        let path = file.name().to_owned();
        if file.is_dir()
            || file
                .unix_mode()
                .is_some_and(|mode| mode & 0o170000 != 0 && mode & 0o170000 != 0o100000)
            || !matches!(
                file.compression(),
                zip::CompressionMethod::Stored | zip::CompressionMethod::Deflated
            )
            || path != INDEX && !valid_member_path(&path)
            || file.size() == 0
            || file.size() > MAX_MEMBER_BYTES
        {
            return Err(CiError::Message(
                "candidate C member type or bound differs".into(),
            ));
        }
        expanded = expanded
            .checked_add(file.size())
            .ok_or_else(|| CiError::Message("candidate C expansion overflow".into()))?;
        if expanded > MAX_ZIP_BYTES as u64 {
            return Err(CiError::Message(
                "candidate C expansion exceeds bound".into(),
            ));
        }
        let mut value = Vec::new();
        (&mut file)
            .take(MAX_MEMBER_BYTES + 1)
            .read_to_end(&mut value)?;
        if value.len() as u64 != file.size() || members.insert(path, value).is_some() {
            return Err(CiError::Message(
                "candidate C member duplicate or truncated".into(),
            ));
        }
    }
    let index_bytes = members
        .get(INDEX)
        .ok_or_else(|| CiError::Message("candidate C index absent".into()))?;
    if index_bytes.len() > MAX_INDEX_BYTES {
        return Err(CiError::Message("candidate C index bound differs".into()));
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(index_bytes)
        .map_err(CiError::Message)?;
    let index: CandidateEvidenceIndexV3 = serde_json::from_slice(index_bytes)?;
    if serde_json::to_vec(&index)?.as_slice() != index_bytes.as_slice() {
        return Err(CiError::Message(
            "candidate C index is not canonical".into(),
        ));
    }
    let index_sha256 = hash_bytes(index_bytes);
    validate_index(&index, &members)?;
    Ok(ParsedCandidateC3V1 {
        index,
        index_sha256,
        members,
    })
}

/// Only the non-deserializable in-process 25-case semantic token can produce
/// C. The caller must have captured all raw bytes before releasing the host.
pub(crate) fn produce_candidate_c_v3(
    semantics: &VerifiedCandidateSemanticsV2,
    target: &str,
    source_commit: &str,
    release_version: &str,
    collector_intent_sha256: DiagnosticSha256,
    cases: &[CandidateCaseBytesV3],
    observer_raw: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<u8>> {
    if cases.len() != REQUIRED_PRIVATE_RELEASE_SELECTORS_V1.len()
        || semantics.result_digests.len() != cases.len()
        || semantics.inventory_digests.len() != cases.len()
        || semantics.subject.target != target
        || semantics.subject.source_commit != source_commit
        || semantics.subject.release_version != release_version
    {
        return Err(CiError::Message(
            "candidate C semantic case set differs".into(),
        ));
    }
    let mut members = BTreeMap::new();
    let mut records = Vec::with_capacity(cases.len());
    for (index, (bytes, selector)) in cases
        .iter()
        .zip(REQUIRED_PRIVATE_RELEASE_SELECTORS_V1)
        .enumerate()
    {
        let result = PrivateReleaseCaseResultV1::parse(&bytes.result).map_err(CiError::Message)?;
        let challenge = result.challenge_bytes().map_err(CiError::Message)?;
        let key = private_release_case_key_v1(
            PrivateReleaseStageV1::CandidateCapability,
            selector,
            &challenge,
        )
        .map_err(CiError::Message)?;
        if result.selector != selector
            || result.target != target
            || hash_bytes(&bytes.result) != semantics.result_digests[index]
        {
            return Err(CiError::Message(
                "candidate C semantic result differs".into(),
            ));
        }
        let prefix = case_prefix(&key);
        let result_raw = member(format!("{prefix}/result.json"), &bytes.result)?;
        members.insert(result_raw.path.clone(), bytes.result.clone());
        let mut attachments = Vec::with_capacity(5);
        for (role, raw) in PrivateReleaseAttachmentRoleV1::ALL
            .iter()
            .zip(&bytes.attachments)
        {
            let item = member(format!("{prefix}/{}", role.leaf()), raw)?;
            members.insert(item.path.clone(), raw.clone());
            attachments.push(item);
        }
        let kernel_capture = member(
            format!(
                "{prefix}/kernel-{}.capture.bin",
                String::from(collector_intent_sha256.clone())
            ),
            &bytes.kernel_capture,
        )?;
        members.insert(kernel_capture.path.clone(), bytes.kernel_capture.clone());
        let mut family_raw = Vec::new();
        for (name, raw) in &bytes.family_raw {
            let item = member(format!("{prefix}/family/{name}"), raw)?;
            members.insert(item.path.clone(), raw.clone());
            family_raw.push(item);
        }
        records.push(CandidateCaseV3 {
            selector: selector.into(),
            result_key: key,
            result: result_raw,
            attachments,
            kernel_capture,
            family_raw,
        });
    }
    let mut observer_records = Vec::new();
    for (path, bytes) in observer_raw {
        if !valid_observer_path(path) {
            return Err(CiError::Message(
                "candidate observer producer path differs".into(),
            ));
        }
        observer_records.push(member(path.clone(), bytes)?);
        if members.insert(path.clone(), bytes.clone()).is_some() {
            return Err(CiError::Message(
                "candidate observer producer duplicates member".into(),
            ));
        }
    }
    let index = CandidateEvidenceIndexV3 {
        schema_version: if observer_records.is_empty()
            && cases
                .iter()
                .all(|case| case.family_raw.contains_key("source-carrier.v1.bin"))
        {
            6
        } else if observer_records.is_empty() {
            4
        } else {
            5
        },
        target: target.into(),
        source_commit: source_commit.into(),
        release_version: release_version.into(),
        collector_intent_sha256,
        cases: records,
        observer_raw: observer_records,
    };
    let index_bytes = serde_json::to_vec(&index)?;
    if index_bytes.len() > MAX_INDEX_BYTES {
        return Err(CiError::Message("candidate C index bound differs".into()));
    }
    members.insert(INDEX.into(), index_bytes);
    validate_index(&index, &members)?;
    let payload: BTreeMap<_, _> = members
        .iter()
        .filter(|(path, _)| path.as_str() != INDEX && !origin_leaf(path))
        .map(|(path, bytes)| (path.clone(), bytes.clone()))
        .collect();
    let payload_index = crate::private_observer_session::canonical_bytes(
        &crate::private_observer_session::canonical_payload_index(&semantics.subject, &payload)?,
    )?;
    if hash_bytes(&payload_index) != semantics.payload_index_sha256 {
        return Err(CiError::Message(
            "candidate complete raw payload substituted after semantic verification".into(),
        ));
    }
    let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .unix_permissions(0o600);
    for (name, raw) in members {
        archive.start_file(name, options)?;
        archive.write_all(&raw)?;
    }
    let bytes = archive.finish()?.into_inner();
    if bytes.len() > MAX_ZIP_BYTES {
        return Err(CiError::Message("candidate C ZIP bound differs".into()));
    }
    Ok(bytes)
}

/// Materializes uploadable C members only after the semantic capability has
/// authorized the exact archive. Actions zips this directory as its artifact;
/// the completed-job collector parses those same direct V3 members.
pub(crate) fn export_candidate_c_v3(
    semantics: &VerifiedCandidateSemanticsV2,
    target: &str,
    source_commit: &str,
    release_version: &str,
    collector_intent_sha256: DiagnosticSha256,
    cases: &[CandidateCaseBytesV3],
    observer_raw: &BTreeMap<String, Vec<u8>>,
    output_dir: &Path,
) -> Result<()> {
    let bytes = produce_candidate_c_v3(
        semantics,
        target,
        source_commit,
        release_version,
        collector_intent_sha256,
        cases,
        observer_raw,
    )?;
    parse_candidate_c_v3(&bytes)?;
    if output_dir.exists() || !output_dir.is_absolute() {
        return Err(CiError::Message(
            "candidate C export destination is not fresh absolute".into(),
        ));
    }
    let parsed = parse_candidate_c_v3_full(&bytes)?;
    let parent = output_dir
        .parent()
        .ok_or_else(|| CiError::Message("candidate C export parent absent".into()))?;
    if !parent.is_dir() {
        return Err(CiError::Message(
            "candidate C export parent is absent".into(),
        ));
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| CiError::Message("candidate C export clock differs".into()))?
        .as_nanos();
    let name = output_dir
        .file_name()
        .ok_or_else(|| CiError::Message("candidate C export name absent".into()))?;
    let mut staging_name = name.to_os_string();
    staging_name.push(format!(".pending-{}-{nonce}", std::process::id()));
    let staging = parent.join(staging_name);
    std::fs::create_dir(&staging)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700))?;
    }
    let mut directories = BTreeSet::from([staging.clone()]);
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
    for index in 0..archive.len() {
        let mut file = archive.by_index(index)?;
        let name = file.name().to_owned();
        if name != INDEX && !valid_member_path(&name) {
            return Err(CiError::Message(
                "candidate C export member path differs".into(),
            ));
        }
        let path = staging.join(&name);
        std::fs::create_dir_all(
            path.parent()
                .ok_or_else(|| CiError::Message("candidate C export parent absent".into()))?,
        )?;
        let mut directory = path
            .parent()
            .ok_or_else(|| CiError::Message("candidate C export leaf parent absent".into()))?;
        while directory.starts_with(&staging) {
            directories.insert(directory.to_path_buf());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
            }
            let Some(ancestor) = directory.parent() else {
                break;
            };
            directory = ancestor;
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut output = options.open(&path)?;
        std::io::copy(&mut file, &mut output)?;
        output.sync_all()?;
        let exact = crate::private_observer_session::read_bounded_file(&path, MAX_MEMBER_BYTES)?;
        if parsed.member(&name) != Some(exact.as_slice()) {
            return Err(CiError::Message(
                "candidate C export exact leaf readback differs".into(),
            ));
        }
    }
    for directory in directories.iter().rev() {
        std::fs::File::open(directory)?.sync_all()?;
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        &staging,
        rustix::fs::CWD,
        output_dir,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(std::io::Error::from)?;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        return Err(CiError::Message(
            "candidate C export requires atomic no-replace directory rename".into(),
        ));
    }
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}
