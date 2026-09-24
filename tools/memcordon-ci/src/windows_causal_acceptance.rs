//! Strict, separate evidence for an installed Windows public-path causal failure.
//! Source-native diagnostic tests are deliberately not accepted here.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use memcordon_core::{
    BoundaryClass, FailureCategoryV1, FailureCodeV1, FailureOperationV1, MemcordonReport,
    OriginalFailureV1, SafeDiagnosticDetailV1, WINDOWS_MAX_JOB_PROCESS_IDENTITIES,
    WindowsQualificationReceiptV1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{CiError, Result};

pub const MAX_REPORT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_STREAM_BYTES: usize = 256 * 1024;
pub const MAX_SUMMARY_BYTES: usize = 64 * 1024;
pub const MAX_MANIFEST_BYTES: usize = 128 * 1024;
pub const RAW_SUFFIXES: [&str; 9] = [
    "report.json",
    "stdout.bin",
    "stderr.bin",
    "package.json",
    "qualification.json",
    "fixture.json",
    "cleanup.json",
    "invocation.json",
    "runtime-manifest.json",
];
pub const ASSERTIONS: [&str; 12] = [
    "installed-identity",
    "package-verified",
    "native-qualified",
    "expected-execution-schema-failure",
    "capacity-original",
    "ordered-secondary-binding-refusal",
    "provider-attempt-request-bound",
    "no-terminal-authority",
    "native-value-absent",
    "raw-report-retained",
    "fixture-family-gone",
    "package-recovered",
];
const ASSERTION_SOURCES: [&str; 12] = [
    "package.json",
    "package.json",
    "qualification.json",
    "report.json",
    "report.json",
    "report.json",
    "report.json",
    "report.json",
    "report.json",
    "report.json",
    "fixture.json",
    "cleanup.json",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum InstalledChannel {
    NativeBundle,
    CargoPackage,
}
impl InstalledChannel {
    pub const fn name(self) -> &'static str {
        match self {
            Self::NativeBundle => "native-bundle",
            Self::CargoPackage => "cargo-package",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledCausalAcceptanceV1 {
    pub schema_version: u32,
    pub source_commit: String,
    pub target: String,
    pub channel: InstalledChannel,
    pub package_version: String,
    pub execution_report_schema: u32,
    pub provider_identity_sha256: String,
    pub component_inventory_sha256: String,
    pub fixture_sha256: String,
    pub runtime_manifest_sha256: String,
    pub expected_case: String,
    #[serde(deserialize_with = "deserialize_raw_map")]
    pub raw_evidence: BTreeMap<String, String>,
    #[serde(deserialize_with = "deserialize_assertion_map")]
    pub assertion_results: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationEvidenceV1 {
    pub schema_version: u32,
    pub exit_code: Option<i32>,
    pub runner_timed_out: bool,
    pub cli_sha256: String,
    pub fixture_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureExitEvidenceV1 {
    pub schema_version: u32,
    pub image_sha256: String,
    pub root_ready: bool,
    #[serde(deserialize_with = "deserialize_family")]
    pub observed_family: Vec<FixtureProcessIdentityV1>,
    pub root_exited: bool,
    pub all_matching_processes_gone: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureProcessIdentityV1 {
    pub ordinal: Option<usize>,
    pub pid: u32,
    pub birth: u128,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryReadiness {
    kind: String,
    ordinal: Option<usize>,
    pid: u32,
    birth: u128,
}

pub fn parse_fixture_readiness(stdout: &[u8]) -> Result<Vec<FixtureProcessIdentityV1>> {
    const MARKER: &[u8] = b"MEMCORDON-INVENTORY-READY:";
    if stdout.len() > MAX_STREAM_BYTES {
        return Err(failure(
            "inventory fixture readiness stream exceeds byte bound",
        ));
    }
    let mut identities = Vec::new();
    let mut ordinals = BTreeSet::new();
    let mut process_identities = BTreeSet::new();
    let mut root_count = 0;
    for line in stdout.split(|byte| *byte == b'\n') {
        let Some(value) = line.strip_prefix(MARKER) else {
            continue;
        };
        let value: InventoryReadiness = serde_json::from_slice(value)?;
        let valid = match (value.kind.as_str(), value.ordinal) {
            ("inventory-root-ready", None) => {
                root_count += 1;
                true
            }
            ("inventory-leaf-ready", Some(ordinal))
                if ordinal < WINDOWS_MAX_JOB_PROCESS_IDENTITIES =>
            {
                ordinals.insert(ordinal)
            }
            _ => false,
        };
        if !valid
            || root_count > 1
            || value.pid == 0
            || value.birth == 0
            || !process_identities.insert((value.pid, value.birth))
        {
            return Err(failure(
                "inventory fixture readiness is malformed or duplicated",
            ));
        }
        identities.push(FixtureProcessIdentityV1 {
            ordinal: value.ordinal,
            pid: value.pid,
            birth: value.birth,
        });
        if identities.len() > WINDOWS_MAX_JOB_PROCESS_IDENTITIES + 1 {
            return Err(failure(
                "inventory fixture readiness exceeds the family bound",
            ));
        }
    }
    if root_count != 1 {
        return Err(failure("inventory fixture root readiness was not observed"));
    }
    Ok(identities)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupEvidenceV1 {
    pub schema_version: u32,
    pub attempts_empty: bool,
    pub package_recovered: bool,
}

fn deserialize_unique_map<'de, D, const LIMIT: usize>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct UniqueMap<const LIMIT: usize>;
    impl<'de, const LIMIT: usize> serde::de::Visitor<'de> for UniqueMap<LIMIT> {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a bounded object with unique string keys")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut map: M,
        ) -> std::result::Result<Self::Value, M::Error> {
            let mut values = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, String>()? {
                if values.len() == LIMIT || values.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom(
                        "duplicate or oversized installed causal evidence map",
                    ));
                }
            }
            Ok(values)
        }
    }
    deserializer.deserialize_map(UniqueMap::<LIMIT>)
}

fn deserialize_raw_map<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, String>, D::Error> {
    deserialize_unique_map::<D, { RAW_SUFFIXES.len() }>(deserializer)
}

fn deserialize_assertion_map<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, String>, D::Error> {
    deserialize_unique_map::<D, { ASSERTIONS.len() }>(deserializer)
}

fn deserialize_family<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<FixtureProcessIdentityV1>, D::Error> {
    struct Family;
    impl<'de> serde::de::Visitor<'de> for Family {
        type Value = Vec<FixtureProcessIdentityV1>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a bounded inventory fixture family")
        }
        fn visit_seq<S: serde::de::SeqAccess<'de>>(
            self,
            mut seq: S,
        ) -> std::result::Result<Self::Value, S::Error> {
            let maximum = WINDOWS_MAX_JOB_PROCESS_IDENTITIES
                .checked_add(1)
                .ok_or_else(|| serde::de::Error::custom("inventory family bound overflow"))?;
            let mut family = Vec::new();
            while let Some(identity) = seq.next_element()? {
                if family.len() == maximum {
                    return Err(serde::de::Error::custom(
                        "inventory fixture family exceeds compiled bound",
                    ));
                }
                family.push(identity);
            }
            Ok(family)
        }
    }
    deserializer.deserialize_seq(Family)
}

fn failure(message: impl Into<String>) -> CiError {
    CiError::Message(message.into())
}

pub fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == Sha256::output_size() * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn raw_name(prefix: &str, suffix: &str) -> String {
    format!("{prefix}-{suffix}")
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(failure(format!(
            "installed causal evidence is not a regular file: {}",
            path.display()
        )));
    }
    let length = fs::metadata(path)?.len();
    if length > limit as u64 {
        return Err(failure(format!(
            "installed causal evidence exceeds its byte bound: {}",
            path.display()
        )));
    }
    Ok(fs::read(path)?)
}

pub fn read_raw(directory: &Path, prefix: &str, suffix: &str) -> Result<Vec<u8>> {
    let limit = match suffix {
        "report.json" => MAX_REPORT_BYTES,
        "stdout.bin" | "stderr.bin" => MAX_STREAM_BYTES,
        "runtime-manifest.json" => MAX_MANIFEST_BYTES,
        other if RAW_SUFFIXES.contains(&other) => MAX_SUMMARY_BYTES,
        _ => return Err(failure("unknown installed causal raw evidence suffix")),
    };
    read_bounded(&directory.join(raw_name(prefix, suffix)), limit)
}

pub fn validate_report(
    bytes: &[u8],
    expected_schema: u32,
    expected_commit: &str,
    qualification: &WindowsQualificationReceiptV1,
    manifest_bytes: &[u8],
) -> Result<()> {
    if bytes.len() > MAX_REPORT_BYTES
        || expected_schema != memcordon_core::EXECUTION_REPORT_SCHEMA_VERSION
    {
        return Err(failure(
            "installed causal report schema or byte bound differs",
        ));
    }
    let report: MemcordonReport = serde_json::from_slice(bytes)?;
    if manifest_bytes.len() > MAX_MANIFEST_BYTES {
        return Err(failure("installed runtime manifest is oversized"));
    }
    let manifest = memcordon_core::runtime_manifest::RuntimeManifestV2::parse(manifest_bytes)
        .map_err(failure)?;
    let provider_binding = manifest.public_binding(manifest_bytes).map_err(failure)?;
    if report.schema_version != expected_schema
        || report.supervision.is_some()
        || !report.attempts.is_empty()
    {
        return Err(failure(
            "installed causal report is not the exact failed execution envelope",
        ));
    }
    if report
        .invocation
        .argv
        .last()
        .is_none_or(|arg| arg.display != "windows-inventory-capacity" || arg.raw.is_some())
    {
        return Err(failure(
            "installed causal report does not bind the inventory fixture command",
        ));
    }
    if !qualification.qualified || !qualification.package_verified || !qualification.is_consistent()
    {
        return Err(failure(
            "installed causal native qualification is incomplete",
        ));
    }
    let backend = report
        .backend
        .as_ref()
        .ok_or_else(|| failure("installed causal report has no backend capability"))?;
    let binding = backend
        .boundary_qualification
        .as_ref()
        .ok_or_else(|| failure("installed causal report has no qualified backend binding"))?;
    if backend.name != "windows-job-object"
        || backend.boundary.class != BoundaryClass::Sealed
        || backend.boundary.mechanism != "windows-job-object-v2"
        || binding.mechanism != "windows-job-object-v2"
        || binding.provider_identity != qualification.provider_identity
        || binding.receipt_digest != sha256(&serde_json::to_vec(qualification)?)
    {
        return Err(failure(
            "installed causal provider identity differs from qualification",
        ));
    }
    let error = report
        .error
        .as_ref()
        .ok_or_else(|| failure("installed causal report has no error"))?;
    let rejection = error
        .provider_rejection
        .as_ref()
        .ok_or_else(|| failure("installed causal report has no provider rejection"))?;
    if !error.target_released
        || error.workload_may_be_alive
        || !rejection.target_released
        || !rejection.cleanup_attempted
        || rejection.terminal_receipt.is_some()
        || rejection.terminal_ack_required
    {
        return Err(failure(
            "installed causal error or rejection invents terminal authority or lacks cleanup",
        ));
    }
    let projection = error
        .provider_failure
        .as_ref()
        .or_else(|| {
            error
                .provider_rejection
                .as_ref()
                .and_then(|rejection| rejection.provider_failure.as_ref())
        })
        .ok_or_else(|| failure("installed causal report has no public provider failure"))?;
    if let (Some(top), Some(nested)) = (
        error.provider_failure.as_ref(),
        error
            .provider_rejection
            .as_ref()
            .and_then(|rejection| rejection.provider_failure.as_ref()),
    ) {
        if top != nested {
            return Err(failure("contradictory public provider failure projections"));
        }
    }
    if projection.provider_binding != provider_binding
        || projection.provider_binding.source_commit.as_str() != expected_commit
        || !projection.is_consistent()
        || projection.canonical_digest() != projection.projection_sha256
    {
        return Err(failure("installed causal projection binding differs"));
    }
    let OriginalFailureV1::Observed { event } = &projection.original else {
        return Err(failure(
            "installed causal original observation is unavailable",
        ));
    };
    if event.category != FailureCategoryV1::Monitor
        || event.operation != FailureOperationV1::AccumulateProcessInventory
        || event.code != FailureCodeV1::ProcessInventoryCapacity
        || event.native_code.is_some()
        || !matches!(event.safe_detail, SafeDiagnosticDetailV1::CountAndLimit { observed, limit }
            if usize::try_from(limit).ok() == Some(WINDOWS_MAX_JOB_PROCESS_IDENTITIES)
                && usize::try_from(observed).ok() == WINDOWS_MAX_JOB_PROCESS_IDENTITIES.checked_add(1))
    {
        return Err(failure(
            "installed causal original is not the typed inventory capacity failure",
        ));
    }
    if !projection.secondary.as_slice().iter().any(|secondary| {
        secondary.sequence > event.sequence
            && secondary.operation == FailureOperationV1::ValidateTerminalResponse
            && secondary.code == FailureCodeV1::TerminalBinding
    }) {
        return Err(failure(
            "installed causal report lacks ordered receiptless binding refusal",
        ));
    }
    Ok(())
}

pub fn validate_artifact(
    bytes: &[u8],
    directory: &Path,
    prefix: &str,
    expected_commit: &str,
    expected_target: &str,
    expected_channel: InstalledChannel,
) -> Result<InstalledCausalAcceptanceV1> {
    validate_artifact_with_raw(
        bytes,
        expected_commit,
        expected_target,
        expected_channel,
        |suffix| read_raw(directory, prefix, suffix),
    )
}

pub fn validate_artifact_with_raw(
    bytes: &[u8],
    expected_commit: &str,
    expected_target: &str,
    expected_channel: InstalledChannel,
    mut raw_reader: impl FnMut(&str) -> Result<Vec<u8>>,
) -> Result<InstalledCausalAcceptanceV1> {
    if bytes.len() > MAX_SUMMARY_BYTES {
        return Err(failure("installed causal acceptance summary is oversized"));
    }
    let artifact: InstalledCausalAcceptanceV1 = serde_json::from_slice(bytes)?;
    let expected_raw: BTreeSet<_> = RAW_SUFFIXES.into_iter().map(str::to_owned).collect();
    let expected_assertions: BTreeSet<_> = ASSERTIONS.into_iter().map(str::to_owned).collect();
    let required_assertions: BTreeMap<String, String> = ASSERTIONS
        .into_iter()
        .zip(ASSERTION_SOURCES)
        .map(|(name, source)| (name.to_owned(), source.to_owned()))
        .collect();
    if artifact.schema_version != 1
        || artifact.source_commit != expected_commit
        || artifact.target != expected_target
        || artifact.channel != expected_channel
        || artifact.package_version.is_empty()
        || artifact.execution_report_schema != memcordon_core::EXECUTION_REPORT_SCHEMA_VERSION
        || artifact.expected_case != "inventory-capacity-receiptless"
        || !valid_sha256(&artifact.provider_identity_sha256)
        || !valid_sha256(&artifact.component_inventory_sha256)
        || !valid_sha256(&artifact.fixture_sha256)
        || !valid_sha256(&artifact.runtime_manifest_sha256)
        || artifact
            .raw_evidence
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
            != expected_raw
        || artifact
            .assertion_results
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
            != expected_assertions
        || artifact.assertion_results != required_assertions
    {
        return Err(failure(
            "installed causal acceptance identity or required inventory differs",
        ));
    }
    let mut raw = BTreeMap::new();
    for suffix in RAW_SUFFIXES {
        let limit = match suffix {
            "report.json" => MAX_REPORT_BYTES,
            "stdout.bin" | "stderr.bin" => MAX_STREAM_BYTES,
            "runtime-manifest.json" => MAX_MANIFEST_BYTES,
            _ => MAX_SUMMARY_BYTES,
        };
        let bytes = raw_reader(suffix)?;
        if bytes.len() > limit {
            return Err(failure(format!(
                "installed causal raw evidence exceeds byte bound: {suffix}"
            )));
        }
        if artifact.raw_evidence.get(suffix) != Some(&sha256(&bytes)) {
            return Err(failure(format!(
                "installed causal raw evidence digest differs: {suffix}"
            )));
        }
        raw.insert(suffix, bytes);
    }
    let qualification: WindowsQualificationReceiptV1 =
        serde_json::from_slice(&raw["qualification.json"])?;
    let invocation: InvocationEvidenceV1 = serde_json::from_slice(&raw["invocation.json"])?;
    let fixture: FixtureExitEvidenceV1 = serde_json::from_slice(&raw["fixture.json"])?;
    let cleanup: CleanupEvidenceV1 = serde_json::from_slice(&raw["cleanup.json"])?;
    let package: serde_json::Value = serde_json::from_slice(&raw["package.json"])?;
    let manifest =
        memcordon_core::runtime_manifest::RuntimeManifestV2::parse(&raw["runtime-manifest.json"])
            .map_err(failure)?;
    let unique_ordinals: BTreeSet<_> = fixture
        .observed_family
        .iter()
        .filter_map(|identity| identity.ordinal)
        .collect();
    let unique_identities: BTreeSet<_> = fixture
        .observed_family
        .iter()
        .map(|identity| (identity.pid, identity.birth))
        .collect();
    if invocation.schema_version != 1
        || invocation.runner_timed_out
        || invocation.exit_code.is_none_or(|code| code == 0)
        || !valid_sha256(&invocation.cli_sha256)
        || invocation.fixture_sha256 != artifact.fixture_sha256
        || fixture.schema_version != 1
        || fixture.image_sha256 != artifact.fixture_sha256
        || !fixture.root_ready
        || !fixture.root_exited
        || !fixture.all_matching_processes_gone
        || fixture.observed_family.len() > WINDOWS_MAX_JOB_PROCESS_IDENTITIES + 1
        || fixture
            .observed_family
            .iter()
            .filter(|identity| identity.ordinal.is_none())
            .count()
            != 1
        || unique_ordinals.len() + 1 != fixture.observed_family.len()
        || unique_identities.len() != fixture.observed_family.len()
        || fixture.observed_family.iter().any(|identity| {
            identity.pid == 0
                || identity.birth == 0
                || identity
                    .ordinal
                    .is_some_and(|ordinal| ordinal >= WINDOWS_MAX_JOB_PROCESS_IDENTITIES)
        })
        || cleanup.schema_version != 1
        || !cleanup.attempts_empty
        || !cleanup.package_recovered
        || sha256(qualification.provider_identity.as_bytes()) != artifact.provider_identity_sha256
        || sha256(&raw["package.json"]) != artifact.component_inventory_sha256
        || sha256(&raw["runtime-manifest.json"]) != artifact.runtime_manifest_sha256
        || manifest.source_commit != artifact.source_commit
        || manifest.version != artifact.package_version
        || manifest.target != artifact.target
        || package
            .get("source_commit")
            .and_then(serde_json::Value::as_str)
            != Some(artifact.source_commit.as_str())
        || package.get("version").and_then(serde_json::Value::as_str)
            != Some(artifact.package_version.as_str())
        || package
            .get("execution_report_schema")
            .and_then(serde_json::Value::as_u64)
            != Some(u64::from(artifact.execution_report_schema))
        || package
            .get("compiled_metadata_valid")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
    {
        return Err(failure(
            "installed causal raw observations do not establish accepted lifecycle",
        ));
    }
    validate_report(
        &raw["report.json"],
        artifact.execution_report_schema,
        expected_commit,
        &qualification,
        &raw["runtime-manifest.json"],
    )?;
    Ok(artifact)
}

pub fn write_raw(directory: &Path, prefix: &str, suffix: &str, bytes: &[u8]) -> Result<()> {
    let limit = match suffix {
        "report.json" => MAX_REPORT_BYTES,
        "stdout.bin" | "stderr.bin" => MAX_STREAM_BYTES,
        "runtime-manifest.json" => MAX_MANIFEST_BYTES,
        _ => MAX_SUMMARY_BYTES,
    };
    if !RAW_SUFFIXES.contains(&suffix) || bytes.len() > limit {
        return Err(failure(format!(
            "installed causal raw artifact is unknown or oversized: {suffix}"
        )));
    }
    fs::write(directory.join(raw_name(prefix, suffix)), bytes)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn write_acceptance(
    directory: &Path,
    prefix: &str,
    artifact_name: &str,
    source_commit: &str,
    target: &str,
    channel: InstalledChannel,
    package_version: &str,
    execution_report_schema: u32,
    fixture_sha256: &str,
) -> Result<()> {
    let mut raw_evidence = BTreeMap::new();
    for suffix in RAW_SUFFIXES {
        let bytes = read_bounded(
            &directory.join(raw_name(prefix, suffix)),
            match suffix {
                "report.json" => MAX_REPORT_BYTES,
                "stdout.bin" | "stderr.bin" => MAX_STREAM_BYTES,
                "runtime-manifest.json" => MAX_MANIFEST_BYTES,
                _ => MAX_SUMMARY_BYTES,
            },
        )?;
        raw_evidence.insert(suffix.to_owned(), sha256(&bytes));
    }
    let qualification: WindowsQualificationReceiptV1 = serde_json::from_slice(&read_bounded(
        &directory.join(raw_name(prefix, "qualification.json")),
        MAX_SUMMARY_BYTES,
    )?)?;
    let package = read_bounded(
        &directory.join(raw_name(prefix, "package.json")),
        MAX_SUMMARY_BYTES,
    )?;
    let runtime_manifest = read_bounded(
        &directory.join(raw_name(prefix, "runtime-manifest.json")),
        MAX_MANIFEST_BYTES,
    )?;
    let assertion_results = ASSERTIONS
        .into_iter()
        .zip(ASSERTION_SOURCES)
        .map(|(name, source)| (name.to_owned(), source.to_owned()))
        .collect();
    let artifact = InstalledCausalAcceptanceV1 {
        schema_version: 1,
        source_commit: source_commit.to_owned(),
        target: target.to_owned(),
        channel,
        package_version: package_version.to_owned(),
        execution_report_schema,
        provider_identity_sha256: sha256(qualification.provider_identity.as_bytes()),
        component_inventory_sha256: sha256(&package),
        fixture_sha256: fixture_sha256.to_owned(),
        runtime_manifest_sha256: sha256(&runtime_manifest),
        expected_case: "inventory-capacity-receiptless".to_owned(),
        raw_evidence,
        assertion_results,
    };
    let bytes = serde_json::to_vec_pretty(&artifact)?;
    if bytes.len() >= MAX_SUMMARY_BYTES {
        return Err(failure(
            "installed causal acceptance summary exceeds its byte bound",
        ));
    }
    validate_artifact(&bytes, directory, prefix, source_commit, target, channel)?;
    let mut terminated = bytes;
    terminated.push(b'\n');
    fs::write(directory.join(artifact_name), terminated)?;
    Ok(())
}
