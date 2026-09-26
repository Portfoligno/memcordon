//! Exact public-stage transport. Parsing yields bytes, never release authority.
//! Payload I excludes commitment K, receipt R, transport W and derived P/CP.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, Write};

use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::REQUIRED_PRIVATE_RELEASE_SELECTORS_V1;
use memcordon_core::workload_codec::hash_bytes;
use memcordon_core::workload_contract::reject_duplicate_json_keys;
use serde::{Deserialize, Serialize};

use crate::private_observer_session::{
    ObserverPayloadIndexV1, ObserverPayloadLeafV1, ObserverSubjectV1,
};
use crate::{CiError, Result};

pub const PAYLOAD_INDEX: &str = "raw-public-index-v1.json";
pub const TRANSPORT_INDEX: &str = "transport-public-index-v1.json";
pub const ORIGIN_COMMITMENT: &str = "origin/commitment-v1.json";
pub const ORIGIN_RECEIPT: &str = "origin/receipt-v1.json";

/// Reviewed stage-static ceilings. Input cannot raise a ceiling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicRawBudgetV1 {
    pub semantic_index_bytes: u64,
    pub inventory_bytes: u64,
    pub cli_stream_bytes: u64,
    pub capture_events: u64,
    pub capture_bytes: u64,
    pub archive_bytes: u64,
    pub members: usize,
}

impl PublicRawBudgetV1 {
    pub const REVIEWED: Self = Self {
        semantic_index_bytes: 64 * 1024,
        inventory_bytes: 16 * 1024 * 1024,
        cli_stream_bytes: 1024 * 1024,
        capture_events: 100_000,
        capture_bytes: 64 * 1024 * 1024,
        archive_bytes: 4 * 1024 * 1024 * 1024,
        members: 16_384,
    };

    pub fn capture_limit(self, header: u64, event_size: u64) -> Result<u64> {
        if self != Self::REVIEWED || event_size == 0 {
            return Err(fail("public capture budget/version differs"));
        }
        header
            .checked_add(
                self.capture_events
                    .checked_mul(event_size)
                    .ok_or_else(|| fail("capture size overflow"))?,
            )
            .filter(|size| *size <= self.capture_bytes)
            .ok_or_else(|| fail("public capture bound exceeds reviewed ceiling"))
    }

    fn validate(self) -> Result<()> {
        if self != Self::REVIEWED {
            return Err(fail(
                "public budget is not the reviewed stage-static contract",
            ));
        }
        Ok(())
    }
}

fn fail(message: &str) -> CiError {
    CiError::Message(message.into())
}

pub fn validate_relative_evidence_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > 1024
        || path.contains('\\')
        || path.contains('\0')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == ".." || part.contains(':'))
    {
        return Err(fail(
            "public evidence path is not a normal relative UTF-8 path",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PublicLeafKindV1 {
    Session,
    Installed,
    Timeline,
    Case,
    Provider,
    Request,
    Response,
    Checkpoint,
    Terminal,
    Cleanup,
    Report,
    Stdio,
    LiveSample,
    Interval,
    Capture,
    Control,
    Historical,
    PayloadIndex,
    OriginCommitment,
    OriginReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalPublicLeafV1 {
    pub path: String,
    pub kind: PublicLeafKindV1,
    pub size: u64,
    pub sha256: DiagnosticSha256,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawPublicEvidenceIndexV1 {
    pub schema_version: u8,
    pub leaves: Vec<CanonicalPublicLeafV1>,
}

impl RawPublicEvidenceIndexV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        validate_index(self, false, PublicRawBudgetV1::REVIEWED)?;
        canonical_json(self)
    }
}

pub fn canonical_json(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn validate_index(
    index: &RawPublicEvidenceIndexV1,
    transport: bool,
    budget: PublicRawBudgetV1,
) -> Result<()> {
    budget.validate()?;
    if index.schema_version != 1 || index.leaves.is_empty() || index.leaves.len() >= budget.members
    {
        return Err(fail("public inventory schema/count differs"));
    }
    let mut previous: Option<&str> = None;
    let mut total = 0_u64;
    for leaf in &index.leaves {
        validate_relative_evidence_path(&leaf.path)?;
        if previous.is_some_and(|last| last.as_bytes() >= leaf.path.as_bytes())
            || leaf.path == TRANSPORT_INDEX
            || leaf.size > budget.capture_bytes
            || leaf.size == 0
                && !(leaf.kind == PublicLeafKindV1::Stdio
                    && matches!(
                        leaf.path.rsplit('/').next(),
                        Some("stdout.raw" | "stderr.raw")
                    ))
            || leaf.sha256 == DiagnosticSha256::from_bytes([0; 32])
            || (!transport
                && [PAYLOAD_INDEX, ORIGIN_COMMITMENT, ORIGIN_RECEIPT].contains(&leaf.path.as_str()))
            || (!transport
                && matches!(
                    leaf.kind,
                    PublicLeafKindV1::PayloadIndex
                        | PublicLeafKindV1::OriginCommitment
                        | PublicLeafKindV1::OriginReceipt
                ))
        {
            return Err(fail(
                "public inventory ordering, cycle or member bound differs",
            ));
        }
        total = total
            .checked_add(leaf.size)
            .filter(|total| *total <= budget.archive_bytes)
            .ok_or_else(|| fail("public expanded archive size overflow"))?;
        previous = Some(&leaf.path);
    }
    if transport {
        for (path, kind) in [
            (PAYLOAD_INDEX, PublicLeafKindV1::PayloadIndex),
            (ORIGIN_COMMITMENT, PublicLeafKindV1::OriginCommitment),
            (ORIGIN_RECEIPT, PublicLeafKindV1::OriginReceipt),
        ] {
            if index
                .leaves
                .iter()
                .filter(|leaf| leaf.path == path && leaf.kind == kind)
                .count()
                != 1
            {
                return Err(fail("transport lacks exact I/K/R carriers"));
            }
        }
    }
    Ok(())
}

pub fn make_payload_index(
    subject: &ObserverSubjectV1,
    leaves: &BTreeMap<String, (PublicLeafKindV1, Vec<u8>)>,
) -> Result<ObserverPayloadIndexV1> {
    if subject.stage != crate::private_observer_session::ObserverStageV1::Public {
        return Err(fail("public payload has a candidate subject"));
    }
    let structural = RawPublicEvidenceIndexV1 {
        schema_version: 1,
        leaves: leaves
            .iter()
            .map(|(path, (kind, bytes))| CanonicalPublicLeafV1 {
                path: path.clone(),
                kind: *kind,
                size: bytes.len() as u64,
                sha256: hash_bytes(bytes),
            })
            .collect(),
    };
    validate_index(&structural, false, PublicRawBudgetV1::REVIEWED)?;
    let payload = leaves
        .iter()
        .map(|(path, (_, bytes))| (path.clone(), bytes.clone()))
        .collect();
    let index = crate::private_observer_session::canonical_payload_index(subject, &payload)?;
    if canonical_json(&index)?.len() as u64 > PublicRawBudgetV1::REVIEWED.inventory_bytes {
        return Err(fail("public payload index exceeds bound"));
    }
    Ok(index)
}

/// Carriers are structural. Their authority is obtained by independent custody
/// readback after the producer completes, never by this export operation.
pub fn make_transport_index(
    payload: &ObserverPayloadIndexV1,
    leaves: &BTreeMap<String, (PublicLeafKindV1, Vec<u8>)>,
    payload_bytes: &[u8],
    commitment: &[u8],
    receipt: &[u8],
) -> Result<RawPublicEvidenceIndexV1> {
    if make_payload_index(&payload.subject, leaves)? != *payload
        || canonical_json(payload)? != payload_bytes
        || commitment.is_empty()
        || receipt.is_empty()
        || commitment.len() > 64 * 1024
        || receipt.len() > 64 * 1024
    {
        return Err(fail("public I/K/R carrier bytes differ"));
    }
    reject_duplicate_json_keys(commitment).map_err(CiError::Message)?;
    reject_duplicate_json_keys(receipt).map_err(CiError::Message)?;
    let _: serde_json::Value = serde_json::from_slice(commitment)?;
    let _: serde_json::Value = serde_json::from_slice(receipt)?;
    let mut leaves: Vec<_> = leaves
        .iter()
        .map(|(path, (kind, bytes))| CanonicalPublicLeafV1 {
            path: path.clone(),
            kind: *kind,
            size: bytes.len() as u64,
            sha256: hash_bytes(bytes),
        })
        .collect();
    for (path, kind, bytes) in [
        (PAYLOAD_INDEX, PublicLeafKindV1::PayloadIndex, payload_bytes),
        (
            ORIGIN_COMMITMENT,
            PublicLeafKindV1::OriginCommitment,
            commitment,
        ),
        (ORIGIN_RECEIPT, PublicLeafKindV1::OriginReceipt, receipt),
    ] {
        leaves.push(CanonicalPublicLeafV1 {
            path: path.into(),
            kind,
            size: bytes.len() as u64,
            sha256: hash_bytes(bytes),
        });
    }
    leaves.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    let index = RawPublicEvidenceIndexV1 {
        schema_version: 1,
        leaves,
    };
    validate_index(&index, true, PublicRawBudgetV1::REVIEWED)?;
    Ok(index)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PublicRawOutcomeV1 {
    Terminal,
    PreallocationRejected,
    AllocatedRejectedThenRecovered,
    TransportLostThenRecovered,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicRawBranchV1 {
    Ordinary,
    PolicyAccepted,
    PolicyWrongGrant,
    PolicyWrongProfile,
    PolicyUnapprovedPort,
    PolicyFrozenTamper,
    AbiOuter,
    AbiFiltered,
    Reuse,
    HistoricalE0,
    HistoricalReplay,
    HistoricalSpoof,
}

fn insert(
    leaves: &mut BTreeMap<String, PublicLeafKindV1>,
    prefix: &str,
    name: &str,
    kind: PublicLeafKindV1,
) {
    let path = std::path::Path::new(prefix)
        .join(name)
        .to_string_lossy()
        .into_owned();
    assert!(
        leaves.insert(path, kind).is_none(),
        "schema generated duplicate leaf"
    );
}

/// Exact branch inventory. The caller cannot omit a report/rejection by passing
/// an unrelated outcome. Variant-specific failure leaves remain immutable.
pub fn required_public_leaves(
    selector: &str,
    branch: PublicRawBranchV1,
    outcome: PublicRawOutcomeV1,
    target: &str,
) -> Result<BTreeMap<String, PublicLeafKindV1>> {
    use PublicLeafKindV1 as K;
    use PublicRawBranchV1 as B;
    use PublicRawOutcomeV1 as O;
    let ordinal = REQUIRED_PRIVATE_RELEASE_SELECTORS_V1
        .iter()
        .position(|value| *value == selector)
        .ok_or_else(|| fail("unknown public selector"))?;
    if !matches!(
        target,
        "x86_64-unknown-linux-gnu" | "aarch64-unknown-linux-gnu"
    ) {
        return Err(fail("unknown native public target"));
    }
    let root = std::path::Path::new("cases")
        .join(ordinal.to_string())
        .to_string_lossy()
        .into_owned();
    let prefix = match branch {
        B::Ordinary if ![0, 20, 24].contains(&ordinal) => root,
        B::PolicyAccepted
        | B::PolicyWrongGrant
        | B::PolicyWrongProfile
        | B::PolicyUnapprovedPort
        | B::PolicyFrozenTamper
            if ordinal == 24 =>
        {
            let name = match branch {
                B::PolicyAccepted => "accepted",
                B::PolicyWrongGrant => "wrong-grant",
                B::PolicyWrongProfile => "wrong-profile",
                B::PolicyUnapprovedPort => "unapproved-port",
                B::PolicyFrozenTamper => "frozen-tamper",
                _ => unreachable!(),
            };
            std::path::Path::new("composites/policy")
                .join(name)
                .to_string_lossy()
                .into_owned()
        }
        B::AbiOuter | B::AbiFiltered if ordinal == 0 => std::path::Path::new("composites/abi")
            .join(if branch == B::AbiOuter {
                "outer"
            } else {
                "filtered"
            })
            .to_string_lossy()
            .into_owned(),
        B::Reuse if ordinal == 20 => "composites/reuse".into(),
        B::HistoricalE0 | B::HistoricalReplay | B::HistoricalSpoof if ordinal == 4 => {
            std::path::Path::new("historical")
                .join(match branch {
                    B::HistoricalE0 => "e0",
                    B::HistoricalReplay => "replay",
                    B::HistoricalSpoof => "spoof",
                    _ => unreachable!(),
                })
                .to_string_lossy()
                .into_owned()
        }
        _ => return Err(fail("public selector/branch topology differs")),
    };
    let expected_outcome = match branch {
        B::PolicyWrongGrant
        | B::PolicyWrongProfile
        | B::PolicyUnapprovedPort
        | B::PolicyFrozenTamper
        | B::HistoricalReplay
        | B::HistoricalSpoof => O::PreallocationRejected,
        B::Reuse => O::AllocatedRejectedThenRecovered,
        B::Ordinary if ordinal == 3 || ordinal == 11 => O::AllocatedRejectedThenRecovered,
        B::Ordinary if ordinal == 10 => O::TransportLostThenRecovered,
        _ => O::Terminal,
    };
    if outcome != expected_outcome {
        return Err(fail("public outcome is not the closed branch outcome"));
    }
    let mut leaves = BTreeMap::new();
    if branch == B::Reuse {
        for (name, kind) in [
            ("reuse.json", K::Case),
            ("incomplete-v4.bin", K::Checkpoint),
            ("first-failure.bin", K::Response),
            ("blocked-request.bin", K::Request),
            ("blocked-rejection.bin", K::Response),
            ("recovered-cleanup.bin", K::Cleanup),
            ("detached-readback.bin", K::Provider),
            ("holder-identity.json", K::LiveSample),
            ("holder-namespace-fd.bin", K::LiveSample),
            ("first-interval.json", K::Interval),
            ("blocked-interval.json", K::Interval),
            ("recovery-interval.json", K::Interval),
            ("cli/report.json", K::Report),
            ("cli/stdio.bin", K::Stdio),
        ] {
            insert(&mut leaves, &prefix, name, kind);
        }
        return Ok(leaves);
    }
    if branch == B::HistoricalReplay {
        for (name, kind) in [
            ("record.json", K::Historical),
            ("request.bin", K::Request),
            ("rejection.bin", K::Response),
            ("stdout.bin", K::Stdio),
            ("interval.json", K::Interval),
        ] {
            insert(&mut leaves, &prefix, name, kind);
        }
        return Ok(leaves);
    }
    for (name, kind) in [
        ("case.json", K::Case),
        ("provider/record.json", K::Provider),
        ("provider/plan-request.bin", K::Request),
        ("provider/plan-response.bin", K::Response),
        ("provider/registry.json", K::Provider),
        ("provider/grant-decision.json", K::Provider),
        ("cli/stdio.bin", K::Stdio),
        ("interval.json", K::Interval),
    ] {
        insert(&mut leaves, &prefix, name, kind);
    }
    if outcome != O::TransportLostThenRecovered {
        insert(&mut leaves, &prefix, "cli/report.json", K::Report);
    }
    if outcome == O::PreallocationRejected {
        insert(&mut leaves, &prefix, "provider/rejection.bin", K::Response);
        if branch == B::PolicyFrozenTamper {
            insert(
                &mut leaves,
                &prefix,
                "provider/launch-request.bin",
                K::Request,
            );
            insert(
                &mut leaves,
                &prefix,
                "provider/frozen-plan.bin",
                K::Provider,
            );
        }
        return Ok(leaves);
    }
    let attempts = if ordinal == 8 { 2 } else { 1 };
    for attempt in 0..attempts {
        let attempt_root = std::path::Path::new(&prefix)
            .join("attempts")
            .join(attempt.to_string())
            .to_string_lossy()
            .into_owned();
        for (name, kind) in [
            ("request.bin", K::Request),
            ("checkpoint-v4.bin", K::Checkpoint),
            ("target-identity.json", K::Provider),
            ("cleanup.bin", K::Cleanup),
            ("tasks.bin", K::LiveSample),
            ("retirement.bin", K::LiveSample),
        ] {
            insert(&mut leaves, &attempt_root, name, kind);
        }
        match outcome {
            O::Terminal => {
                insert(&mut leaves, &attempt_root, "response.bin", K::Response);
                insert(&mut leaves, &attempt_root, "terminal.bin", K::Terminal);
            }
            O::AllocatedRejectedThenRecovered => {
                insert(
                    &mut leaves,
                    &attempt_root,
                    "original-rejection.bin",
                    K::Response,
                );
                insert(
                    &mut leaves,
                    &attempt_root,
                    "failure-checkpoint-v4.bin",
                    K::Checkpoint,
                );
                insert(&mut leaves, &attempt_root, "fault.json", K::LiveSample);
                insert(
                    &mut leaves,
                    &attempt_root,
                    "recovery-terminal.bin",
                    K::Terminal,
                );
            }
            O::TransportLostThenRecovered => {
                insert(
                    &mut leaves,
                    &attempt_root,
                    "transport-loss.json",
                    K::Provider,
                );
                insert(&mut leaves, &attempt_root, "fault.json", K::LiveSample);
                insert(
                    &mut leaves,
                    &attempt_root,
                    "recovery-terminal.bin",
                    K::Terminal,
                );
            }
            O::PreallocationRejected => unreachable!(),
        }
    }
    let samples: &[&str] = match ordinal {
        0 => &["abi-wrapper", "abi-native-positive"],
        1 => &[
            "unix-intents",
            "unix-table",
            "pathname-absence",
            "entry-fds",
            "unix-positive-control",
        ],
        2 => &["socketpair-operands", "socketpair-positive-control", "tcp"],
        3 => &["durable-release-intent", "permit-epipe", "gate-failure"],
        4 => &["caller-peer", "e1-positive"],
        5 => &[
            "checkpoint-file-sync",
            "checkpoint-directory-sync",
            "release-barrier",
            "tcp",
        ],
        6 => &["simultaneous-child-thread", "parent-retirement"],
        7 => &["gated-fd-table", "executed-fd-table", "stdio-challenge"],
        8 => &[
            "dual-overlap",
            "dual-sockets",
            "dual-challenges",
            "first-retired-second-live",
            "collision-control",
        ],
        9 => &["held-elf", "protected-ancestors", "elf-machine"],
        10 => &["frontend-target-live", "frontend-exit-before-retirement"],
        11 => &["guardian-target-live", "guardian-exit", "recovery-takeover"],
        12 => &[
            "host-before",
            "host-during",
            "host-after",
            "host-mutation-observation",
            "private-sysctls",
        ],
        13 => &[
            "uring-params",
            "clean-entry",
            "pidfd-import-auxiliary",
            "pidfd-positive-control",
        ],
        14 => &[
            "held-netns-fd",
            "namespace-before-after",
            "namespace-auxiliary",
            "namespace-positive-control",
        ],
        15 => &[
            "private-filter-bytes",
            "filter-install",
            "filter-count",
            "native-allow-deny",
        ],
        16 => &["tcp-sockets", "tcp-challenge"],
        17 => &[
            "collision-listener",
            "collision-competitor",
            "collision-return",
            "listener-challenge",
        ],
        18 => &[
            "pid-topology",
            "net-topology",
            "mount-topology",
            "proc-topology",
            "private-sysctls",
        ],
        19 => &["checkpoint-release-terminal", "terminal-midpoint"],
        21 => &[
            "clean-entry",
            "scm-auxiliary",
            "scm-positive-control",
            "auxiliary-fd-close",
            "tcp",
        ],
        22 => &[
            "gated-credentials",
            "executed-credentials",
            "capabilities",
            "securebits",
            "user-namespace",
        ],
        23 => &[
            "exec-image",
            "startup-challenge",
            "gated-fd-table",
            "executed-fd-table",
        ],
        24 => &["policy-accepted"],
        _ => return Err(fail("selector lacks exact public sample contract")),
    };
    for sample in samples {
        insert(
            &mut leaves,
            &std::path::Path::new(&prefix)
                .join("samples")
                .to_string_lossy(),
            sample,
            K::LiveSample,
        );
    }
    if matches!(branch, B::AbiOuter | B::AbiFiltered) {
        for child in if target == "x86_64-unknown-linux-gnu" {
            &['x', 'i'][..]
        } else {
            &['a'][..]
        } {
            let child_root = std::path::Path::new(&prefix)
                .join("children")
                .join(match child {
                    'x' => "x32",
                    'i' => "i386",
                    'a' => "arm32",
                    _ => unreachable!(),
                })
                .to_string_lossy()
                .into_owned();
            for name in ["ready", "exec", "entry", "exit", "reap"] {
                insert(&mut leaves, &child_root, name, K::LiveSample);
            }
            if *child == 'a' {
                insert(&mut leaves, &child_root, "helper-identity", K::LiveSample);
            }
        }
    }
    Ok(leaves)
}

/// Streaming ZIP validation with exact regular-file inventory. Each member is
/// bounded before allocation and released after the callback. No extraction.
pub fn visit_public_archive<R: Read + Seek>(
    reader: R,
    budget: PublicRawBudgetV1,
    mut visit: impl FnMut(&CanonicalPublicLeafV1, &[u8]) -> Result<()>,
) -> Result<(RawPublicEvidenceIndexV1, DiagnosticSha256)> {
    budget.validate()?;
    let mut archive = zip::ZipArchive::new(reader).map_err(|error| fail(&error.to_string()))?;
    if archive.is_empty() || archive.len() > budget.members {
        return Err(fail("public ZIP member count differs"));
    }
    let mut names = BTreeSet::new();
    let mut total = 0_u64;
    for ordinal in 0..archive.len() {
        let member = archive
            .by_index(ordinal)
            .map_err(|error| fail(&error.to_string()))?;
        validate_relative_evidence_path(member.name())?;
        if !names.insert(member.name().to_owned())
            || member.is_dir()
            || member
                .unix_mode()
                .is_some_and(|mode| mode & 0o170000 != 0 && mode & 0o170000 != 0o100000)
            || !matches!(
                member.compression(),
                zip::CompressionMethod::Stored | zip::CompressionMethod::Deflated
            )
            || member.size() > budget.capture_bytes
        {
            return Err(fail("public ZIP repeated/nonregular/unbounded member"));
        }
        total = total
            .checked_add(member.size())
            .filter(|size| *size <= budget.archive_bytes)
            .ok_or_else(|| fail("public ZIP expanded bound exceeded"))?;
    }
    let index_bytes = {
        let member = archive
            .by_name(TRANSPORT_INDEX)
            .map_err(|_| fail("public transport index absent"))?;
        if member.size() > budget.inventory_bytes {
            return Err(fail("public transport index too large"));
        }
        read_exact_member(member, budget.inventory_bytes)?
    };
    reject_duplicate_json_keys(&index_bytes).map_err(CiError::Message)?;
    let transport: RawPublicEvidenceIndexV1 = serde_json::from_slice(&index_bytes)?;
    validate_index(&transport, true, budget)?;
    if canonical_json(&transport)? != index_bytes {
        return Err(fail("public transport index is not canonical"));
    }
    let declared: BTreeSet<_> = transport
        .leaves
        .iter()
        .map(|leaf| leaf.path.as_str())
        .chain([TRANSPORT_INDEX])
        .collect();
    if names.iter().map(String::as_str).collect::<BTreeSet<_>>() != declared {
        return Err(fail("public ZIP exact inventory differs"));
    }
    let payload_bytes = read_exact_member(
        archive
            .by_name(PAYLOAD_INDEX)
            .map_err(|_| fail("public payload index absent"))?,
        budget.inventory_bytes,
    )?;
    reject_duplicate_json_keys(&payload_bytes).map_err(CiError::Message)?;
    let payload: ObserverPayloadIndexV1 = serde_json::from_slice(&payload_bytes)?;
    payload.subject.validate()?;
    if payload.schema_version != 1
        || payload.subject.stage != crate::private_observer_session::ObserverStageV1::Public
        || canonical_json(&payload)? != payload_bytes
    {
        return Err(fail("public payload index is not canonical"));
    }
    let expected_payload = transport
        .leaves
        .iter()
        .filter(|leaf| {
            ![PAYLOAD_INDEX, ORIGIN_COMMITMENT, ORIGIN_RECEIPT].contains(&leaf.path.as_str())
        })
        .map(|leaf| ObserverPayloadLeafV1 {
            path: leaf.path.clone(),
            size: leaf.size,
            sha256: leaf.sha256.clone(),
        })
        .collect::<Vec<_>>();
    if payload.leaves != expected_payload {
        return Err(fail("public payload and transport inventories differ"));
    }
    for leaf in &transport.leaves {
        let member = archive
            .by_name(&leaf.path)
            .map_err(|_| fail("public declared leaf absent"))?;
        if member.size() != leaf.size {
            return Err(fail("public member declared length differs"));
        }
        let bytes = read_exact_member(member, leaf.size)?;
        if hash_bytes(&bytes) != leaf.sha256 {
            return Err(fail("public member exact digest differs"));
        }
        if leaf.path.ends_with(".json") {
            reject_duplicate_json_keys(&bytes).map_err(CiError::Message)?;
            let _: serde_json::Value = serde_json::from_slice(&bytes)?;
        }
        visit(leaf, &bytes)?;
    }
    Ok((transport, hash_bytes(&index_bytes)))
}

fn read_exact_member(mut member: impl Read, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    member
        .by_ref()
        .take(
            limit
                .checked_add(1)
                .ok_or_else(|| fail("member size overflow"))?,
        )
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(fail("public decompressed member exceeded bound"));
    }
    Ok(bytes)
}

pub fn write_public_archive<W: Write + Seek>(
    writer: W,
    transport: &RawPublicEvidenceIndexV1,
    leaves: &BTreeMap<String, Vec<u8>>,
) -> Result<W> {
    validate_index(transport, true, PublicRawBudgetV1::REVIEWED)?;
    if leaves.keys().map(String::as_str).collect::<BTreeSet<_>>()
        != transport
            .leaves
            .iter()
            .map(|leaf| leaf.path.as_str())
            .collect()
    {
        return Err(fail("public export exact inventory differs"));
    }
    let mut archive = zip::ZipWriter::new(writer);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .unix_permissions(0o400);
    for leaf in &transport.leaves {
        let bytes = &leaves[&leaf.path];
        if bytes.len() as u64 != leaf.size || hash_bytes(bytes) != leaf.sha256 {
            return Err(fail("public export leaf changed"));
        }
        archive
            .start_file(&leaf.path, options)
            .map_err(|error| fail(&error.to_string()))?;
        archive.write_all(bytes)?;
    }
    archive
        .start_file(TRANSPORT_INDEX, options)
        .map_err(|error| fail(&error.to_string()))?;
    archive.write_all(&canonical_json(transport)?)?;
    archive.finish().map_err(|error| fail(&error.to_string()))
}
