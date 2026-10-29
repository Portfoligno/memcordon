//! Current Linux native component receipts, separate from installed workloads.
use super::CaseEvidenceV2;
pub use super::linux_component_lifecycle::validate_snapshot_budget;
use crate::{ComponentBuild, VerificationResult};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const VERSION_TEST: &str = "current_version_vectors::emit_current_request_result_vectors";
pub const WIRE_TEST: &str = "protocol_tests::unsupported_current_wire_versions_emit_actual_receipt";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireVersionObservation {
    version: u16,
    frame_bytes: Vec<u8>,
    error: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireVersionReceipt {
    format: String,
    revision: u32,
    run_id: String,
    recipe_id: String,
    test_name: String,
    native_target: String,
    artifact_prefix: String,
    challenge_sha256: String,
    executable_sha256: String,
    rejected_versions: Vec<u16>,
    observations: Vec<WireVersionObservation>,
}

/// Pure observation comparison. Decoded JSON never creates a process handle or
/// authorizes native recovery; callers still authenticate the actual endpoint.
pub fn validate_recovered_native_observation(
    recovery: &Value,
    prepared: &Value,
) -> VerificationResult<()> {
    super::linux_component_lifecycle::recovery_native(recovery, prepared)
}
pub const VERSION_SCENARIOS: &[&str] = &[
    "request-v1-vectors",
    "result-v3-vectors",
    "projection-mutation",
];

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionVector {
    pub scenario: String,
    pub baseline: String,
    pub changed: Vec<String>,
    pub actual_refusals: Vec<String>,
    pub canonical: Option<String>,
    pub digest: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionReceipt {
    pub format: String,
    pub revision: u32,
    pub run_id: String,
    pub recipe_id: String,
    pub native_target: String,
    pub test_name: String,
    pub executable_sha256: String,
    pub challenge_sha256: String,
    pub observations: Vec<VersionVector>,
}

pub fn request_fixture() -> Value {
    json!({"format":"memcordon.workload-request","revision":1,
        "runtime":{"kind":"linux-private","profile":"linux-private-workload-v1",
            "inputs":{"runtime_digest":"11".repeat(32),"input_digest":"22".repeat(32),"entrypoint":"tool"},
            "layout":{"writable_roots":[],"output_files":[]}},"requirements":[]})
}

pub fn validate_version_vectors(
    receipt: &VersionReceipt,
    version: &str,
    target: &str,
    resolve: &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
) -> VerificationResult<()> {
    let expected: std::collections::BTreeSet<_> = VERSION_SCENARIOS.iter().copied().collect();
    let actual: std::collections::BTreeSet<_> = receipt
        .observations
        .iter()
        .map(|row| row.scenario.as_str())
        .collect();
    if receipt.format != "memcordon.linux-current-version-component"
        || receipt.revision != 1
        || receipt.native_target != target
        || receipt.test_name != VERSION_TEST
        || actual != expected
        || receipt.observations.len() != expected.len()
    {
        return Err("current version component inventory/header differs".into());
    }
    for row in &receipt.observations {
        let baseline = resolve(&row.baseline)?;
        let base = crate::validate_json_document(&baseline)?;
        let changed = row
            .changed
            .iter()
            .map(|path| resolve(path))
            .collect::<VerificationResult<Vec<_>>>()?;
        if row.scenario != "projection-mutation"
            && (row.actual_refusals.len() != changed.len()
                || row
                    .actual_refusals
                    .iter()
                    .any(|error| error.is_empty() || error.len() > 4096))
        {
            return Err("current version parser actual refusal inventory differs".into());
        }
        match row.scenario.as_str() {
            "request-v1-vectors" => {
                if base != request_fixture() || changed.len() != 3 {
                    return Err("current request vector baseline differs".into());
                }
                let mut expected = Vec::new();
                for field in ["revision", "authorization", "runtime"] {
                    let mut mutant = base.clone();
                    match field {
                        "revision" => mutant["revision"] = json!(99),
                        "authorization" => mutant["authorization"] = json!({}),
                        _ => mutant["runtime"]["profile"] = json!("administrator-approved"),
                    }
                    expected.push(mutant);
                }
                for (bytes, wanted) in changed.iter().zip(expected) {
                    if crate::validate_json_document(bytes)? != wanted
                        || super::linux::request_digest(bytes).is_ok()
                    {
                        return Err("current request refusal vector substituted".into());
                    }
                }
            }
            "result-v3-vectors" => {
                super::parsers::preparation(&baseline, version, target)?;
                if changed.len() != 3 {
                    return Err("current result vector count differs".into());
                }
                for (bytes, field) in changed.iter().zip(["revision", "runtime", "release"]) {
                    let mut wanted = base.clone();
                    match field {
                        "revision" => wanted["revision"] = json!(99),
                        "runtime" => wanted["runtime"]["kind"] = json!("qualified"),
                        _ => wanted["release"] = json!("released"),
                    }
                    if crate::validate_json_document(bytes)? != wanted
                        || super::parsers::preparation(bytes, version, target).is_ok()
                    {
                        return Err("current result refusal vector substituted".into());
                    }
                }
            }
            "projection-mutation" => {
                if base != request_fixture()
                    || changed.len() != 1
                    || !row.actual_refusals.is_empty()
                {
                    return Err("current projection mutation inventory differs".into());
                }
                let digest = super::linux::request_digest(&baseline)?;
                let canonical = resolve(
                    row.canonical
                        .as_deref()
                        .ok_or("actual request canonical bytes missing")?,
                )?;
                let mut wanted = base.clone();
                wanted["runtime"]["inputs"]["input_digest"] = json!("33".repeat(32));
                if row.digest.as_deref() != Some(&digest)
                    || crate::sha256(&canonical) != digest
                    || crate::validate_json_document(&canonical)? != base
                    || crate::validate_json_document(&changed[0])? != wanted
                    || super::linux::request_digest(&changed[0])? == digest
                {
                    return Err("current request canonical/source projection mutation was not independently bound".into());
                }
            }
            _ => return Err("undeclared current version scenario".into()),
        }
    }
    Ok(())
}
pub fn verify_case(
    evidence: &CaseEvidenceV2,
    input: &serde_json::Value,
    build: &ComponentBuild,
    version: &str,
    resolve: &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
) -> VerificationResult<()> {
    if (evidence.key.family == "L-VER-01"
        && ["release-barrier", "journal-barrier"].contains(&evidence.key.scenario.as_str()))
        || (evidence.key.family == "L-LIFE-04"
            && ["crash-before-root-retirement", "lost-terminal-response"]
                .contains(&evidence.key.scenario.as_str()))
    {
        return super::linux_component_lifecycle::verify(evidence, input, build, version, resolve);
    }
    if evidence.key.family == "C-PARSER" {
        return super::parsers::verify_case(evidence, input, build, version, resolve);
    }
    if evidence.key.family == "L-VER-01" && evidence.key.scenario == "unsupported-wire-version" {
        let (semantic, challenge) =
            super::parsers::native_harness(evidence, input, build, resolve)?;
        let test = semantic
            .component_test
            .as_ref()
            .ok_or("current wire test absent")?;
        let receipt: WireVersionReceipt = crate::wire::decode(&resolve(&test.native_receipt)?)?;
        let (prefix, leaf) = test
            .native_receipt
            .rsplit_once('/')
            .ok_or("current wire receipt prefix absent")?;
        if leaf != "current-wire-version.receipt.json"
            || receipt.format != "memcordon.linux-current-wire-version"
            || receipt.revision != 1
            || receipt.run_id != evidence.run_id
            || receipt.recipe_id != build.recipe_id
            || receipt.test_name != WIRE_TEST
            || test.test_name != WIRE_TEST
            || receipt.native_target != evidence.key.target
            || receipt.artifact_prefix != prefix
            || receipt.challenge_sha256 != challenge
            || receipt.executable_sha256 != crate::sha256(&resolve(&build.executable)?)
            || receipt.rejected_versions != [0, 1, 255]
            || receipt.observations.len() != 3
        {
            return Err(
                "current wire parser source, actual test or version inventory differs".into(),
            );
        }
        let original: Value =
            crate::wire::decode(&resolve(&format!("{prefix}/native-input.json"))?)?;
        let fields = [
            "run_id",
            "recipe_id",
            "native_target",
            "artifact_root",
            "artifact_prefix",
            "challenge",
            "work_deadline_unix_millis",
            "cleanup_deadline_unix_millis",
        ];
        if original.as_object().is_none_or(|object| {
            object.len() != fields.len()
                || object.keys().any(|field| !fields.contains(&field.as_str()))
        }) || original["run_id"] != evidence.run_id
            || original["recipe_id"] != build.recipe_id
            || original["native_target"] != evidence.key.target
            || original["artifact_prefix"] != prefix
            || original["work_deadline_unix_millis"]
                .as_u64()
                .is_none_or(|work| {
                    work == 0
                        || original["cleanup_deadline_unix_millis"]
                            .as_u64()
                            .is_none_or(|cleanup| cleanup <= work)
                })
        {
            return Err("current wire test original input/cutoff differs".into());
        }
        let challenge_bytes: Vec<u8> = serde_json::from_value(original["challenge"].clone())
            .map_err(|error| error.to_string())?;
        if challenge_bytes.len() != 32 || crate::sha256(&challenge_bytes) != challenge {
            return Err("current wire test original challenge substituted".into());
        }
        for (observation, expected_version) in receipt.observations.iter().zip([0_u16, 1, 255]) {
            let mut frame = Vec::new();
            frame.extend(expected_version.to_be_bytes());
            frame.extend(30_u16.to_be_bytes());
            frame.extend(72_u32.to_be_bytes());
            frame.extend([7; 16]);
            frame.extend([9; 16]);
            frame.extend(hex::decode(crate::sha256(&[])).map_err(|error| error.to_string())?);
            if observation.version != expected_version
                || observation.frame_bytes != frame
                || observation.error != format!("unsupported protocol version {expected_version}")
            {
                return Err(
                    "current wire malformed header or actual parser refusal substituted".into(),
                );
            }
        }
        return Ok(());
    }
    if evidence.key.family == "L-VER-01"
        && VERSION_SCENARIOS.contains(&evidence.key.scenario.as_str())
    {
        let (semantic, challenge) =
            super::parsers::native_harness(evidence, input, build, resolve)?;
        let test = semantic
            .component_test
            .as_ref()
            .ok_or("actual current version test absent")?;
        let receipt: VersionReceipt = crate::wire::decode(&resolve(&test.native_receipt)?)?;
        let image = build
            .parser_executable
            .as_deref()
            .ok_or("current version parser executable absent")?;
        if receipt.run_id != evidence.run_id
            || receipt.recipe_id != build.recipe_id
            || receipt.challenge_sha256 != challenge
            || receipt.executable_sha256 != crate::sha256(&resolve(image)?)
            || test.test_name != VERSION_TEST
        {
            return Err("current version native image/challenge/source differs".into());
        }
        return validate_version_vectors(&receipt, version, &evidence.key.target, resolve);
    }
    if evidence.key.family == "L-VER-01"
        && ["filter-x64", "filter-arm64"].contains(&evidence.key.scenario.as_str())
    {
        let (semantic, challenge) =
            super::parsers::native_harness(evidence, input, build, resolve)?;
        let test = semantic
            .component_test
            .as_ref()
            .ok_or("current native filter operation absent")?;
        let receipt: crate::LinuxFilterReceipt =
            crate::wire::decode(&resolve(&test.native_receipt)?)?;
        if receipt.run_id != evidence.run_id
            || receipt.recipe_id != build.recipe_id
            || receipt.challenge_sha256 != challenge
            || receipt.executable_sha256 != crate::sha256(&resolve(&build.executable)?)
            || test.test_name != receipt.test_name
        {
            return Err("current native filter source/challenge/image association differs".into());
        }
        return crate::linux_component::validate_linux_filter_receipt(&receipt, &evidence.key);
    }
    Err("current native component operation has no matching authenticated current receipt".into())
}
