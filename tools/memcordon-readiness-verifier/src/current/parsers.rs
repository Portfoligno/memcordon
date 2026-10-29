//! Independent current parser mutation receipts. Fixtures are data only;
//! successful decoding never proves a native release or creates a live owner.
use super::{CaseEvidenceV2, EvidenceIndexV2};
use crate::{
    ComponentBuild, FixtureInput, NativeInvocation, NativeObservation, OutcomeOrigin,
    RetirementObservation, SemanticObservation, VerificationResult,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub const SCENARIOS: &[&str] = &[
    "duplicate-key",
    "wrong-format",
    "wrong-revision",
    "unknown-variant",
    "oversized-record",
    "stale-attempt",
    "wrong-product",
    "omitted-case",
    "duplicate-case",
    "forged-cleanup",
    "unsupported-result-format",
];
pub const TEST_NAME: &str = "emit_current_parser_mutations";
pub fn canonical_fixture_bytes(value: &Value) -> Vec<u8> {
    fn encode(value: &Value, out: &mut Vec<u8>) {
        match value {
            Value::Object(map) => {
                out.push(b'{');
                for (index, key) in map.keys().collect::<BTreeSet<_>>().into_iter().enumerate() {
                    if index != 0 {
                        out.push(b',');
                    }
                    out.extend(serde_json::to_vec(key).expect("JSON string encoding"));
                    out.push(b':');
                    encode(&map[key], out);
                }
                out.push(b'}');
            }
            Value::Array(values) => {
                out.push(b'[');
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        out.push(b',');
                    }
                    encode(value, out);
                }
                out.push(b']');
            }
            _ => out.extend(serde_json::to_vec(value).expect("JSON scalar encoding")),
        }
    }
    let mut out = Vec::new();
    encode(value, &mut out);
    out
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ParserMutationV2 {
    pub scenario: String,
    pub operation: String,
    pub base_input: String,
    pub mutated_input: String,
    pub actual_refusal: String,
    pub baseline_accepted: bool,
    pub data_only: bool,
    pub baseline_profile_ready: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ParserReceiptV2 {
    pub format: String,
    pub revision: u32,
    pub run_id: String,
    pub recipe_id: String,
    pub test_name: String,
    pub native_target: String,
    pub executable_sha256: String,
    pub challenge_sha256: String,
    pub manifest: String,
    pub observations: Vec<ParserMutationV2>,
}

pub fn validate_index_inventory(
    manifest: &[u8],
    index: &EvidenceIndexV2,
) -> VerificationResult<()> {
    let expected = super::validate_manifest(manifest)?;
    if index.format != "memcordon.consumer-readiness.evidence"
        || index.revision != 2
        || index.profile != super::PROFILE
        || index.manifest_sha256 != crate::sha256(manifest)
    {
        return Err("current index format/profile/manifest binding differs".into());
    }
    let actual = index
        .records
        .iter()
        .map(|r| r.key.clone())
        .collect::<BTreeSet<_>>();
    let fixture = index.fixture_cases.iter().cloned().collect::<BTreeSet<_>>();
    if actual != expected
        || index.records.len() != actual.len()
        || fixture != expected
        || index.fixture_cases.len() != fixture.len()
    {
        return Err("current index missing/duplicate/unexpected/reclassified evidence rows".into());
    }
    Ok(())
}

fn fields(value: &Value, expected: &[&str]) -> VerificationResult<()> {
    let object = value
        .as_object()
        .ok_or("current parser fixture is not an object")?;
    if object.len() != expected.len() || object.keys().any(|key| !expected.contains(&key.as_str()))
    {
        return Err("current parser fixture fields differ".into());
    }
    Ok(())
}
pub(super) fn preparation(bytes: &[u8], version: &str, target: &str) -> VerificationResult<Value> {
    let value = crate::validate_json_document(bytes)?;
    fields(
        &value,
        &[
            "format",
            "revision",
            "tool",
            "invocation",
            "request",
            "provider",
            "workload_attempt",
            "release",
            "outcome",
            "cleanup",
            "delivery",
            "output_delivery",
            "diagnostics",
            "provider_failure",
            "request_rejection",
            "windows_rejection",
            "windows_attempt",
            "runtime",
        ],
    )?;
    let os = if target.ends_with("linux-gnu") {
        "linux"
    } else {
        "windows"
    };
    let architecture = if target.starts_with("aarch64-") {
        "aarch64"
    } else {
        "x86_64"
    };
    if value["format"] != "memcordon.result"
        || value["revision"] != 3
        || value["tool"]
            != json!({"name":"memcordon","version":version,"os":os,"architecture":architecture,"runtime_features":[]})
        || value["release"] != "not-released"
        || value["outcome"]
            != json!({"kind":"provider-failure","native_termination":null,"wrapper_status":125})
        || value["cleanup"] != json!({"state":"unknown","obligations":[]})
        || value["delivery"] != "unknown"
        || value["diagnostics"] != json!([])
        || value["invocation"]
            != json!({"syntax":"plus-budgets-v1","budget_tokens":[],"memory_token":null,"deadline_token":null,"argv":[]})
        || value["runtime"]
            != json!({"kind":"preparation-failed","profile":if os=="linux"{"linux-private-workload-v1"}else{"windows-sealed-current-token-v1"}})
        || [
            "request",
            "provider",
            "workload_attempt",
            "output_delivery",
            "provider_failure",
            "request_rejection",
            "windows_rejection",
            "windows_attempt",
        ]
        .iter()
        .any(|key| !value[*key].is_null())
    {
        return Err("current parser baseline invents release/native authority or differs from current preparation data".into());
    }
    Ok(value)
}

pub(super) fn native_harness(
    evidence: &CaseEvidenceV2,
    input: &Value,
    build: &ComponentBuild,
    resolve: &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
) -> VerificationResult<(SemanticObservation, String)> {
    let input: FixtureInput = serde_json::from_value(input.clone()).map_err(|e| e.to_string())?;
    let semantic: SemanticObservation =
        crate::wire::decode(&resolve(&evidence.semantic_observation)?)?;
    let native: NativeObservation = crate::wire::decode(&resolve(&evidence.native_observation)?)?;
    let retired: RetirementObservation = crate::wire::decode(&resolve(&evidence.retirement)?)?;
    let invocation: NativeInvocation = crate::wire::decode(&resolve(&evidence.invocation)?)?;
    let test = semantic
        .component_test
        .as_ref()
        .ok_or("current native component operation receipt absent")?;
    let image = if evidence.key.family == "C-PARSER"
        || test.test_name == super::linux_components::VERSION_TEST
    {
        build
            .parser_executable
            .as_deref()
            .ok_or("current parser executable role absent")?
    } else {
        build.executable.as_str()
    };
    let image_sha = crate::sha256(&resolve(image)?);
    if input.format != "memcordon.consumer-readiness.input"
        || input.revision != 1
        || input.run_id != evidence.run_id
        || input.key != evidence.key
        || semantic.format != "memcordon.consumer-readiness.semantic"
        || semantic.revision != 1
        || semantic.run_id != evidence.run_id
        || semantic.key != evidence.key
        || test.recipe_id != build.recipe_id
        || test.native_exit != 0
        || test.tests_executed != 1
        || test.tests_failed != 0
        || test.tests_ignored != 0
        || invocation.format != "memcordon.consumer-readiness.invocation"
        || invocation.revision != 1
        || invocation.executable_sha256 != image_sha
        || invocation.association_sha256 != crate::reconstruct_invocation_sha256(&invocation)?
        || invocation.environment_sha256 != crate::sha256(&resolve(&invocation.environment)?)
        || native.format != "memcordon.consumer-readiness.native"
        || native.revision != 1
        || native.run_id != evidence.run_id
        || native.target != evidence.key.target
        || native.executable_sha256 != image_sha
        || native.invocation_sha256 != invocation.association_sha256
        || native.origin != OutcomeOrigin::ComponentRegression
        || native.frontend_status != 0
        || native.target_status.is_some()
        || native.root_pid.is_none_or(|pid| pid == 0)
        || native.root_birth.is_none_or(|birth| birth == 0)
        || !native.relay_complete
        || native.held_processes.len() > 1
        || native.held_processes.iter().any(|held| {
            held.pid != native.root_pid.unwrap_or(0)
                || held.birth != native.root_birth.unwrap_or(0)
                || !held.retirement_observed
        })
        || native.authenticated_provider_exchange
        || native.provider_sha256.is_some()
        || native.provider_generation.is_some()
        || native.runtime_manifest_sha256.is_some()
        || native.attempt_id.is_some()
        || native.request_sha256.is_some()
        || retired.format != "memcordon.consumer-readiness.retirement"
        || retired.revision != 1
        || retired.run_id != evidence.run_id
        || retired.root_pid != native.root_pid
        || retired.root_birth != native.root_birth
        || !retired.target_reaped_or_absent
        || !retired.relays_retired
        || !retired.independently_observed
        || !retired.outstanding.is_empty()
        || !retired.failed_operations.is_empty()
        || retired.namespace_init_reaped.is_some()
        || retired.private_root_closed.is_some()
    {
        return Err("current parser/native harness source, invocation, held-process or actual wait/retirement association differs".into());
    }
    let raw = String::from_utf8(resolve(&test.raw_test_output)?).map_err(|e| e.to_string())?;
    let mut lines = raw.lines().filter(|line| !line.is_empty());
    let expected_test = format!("test {} ... ok", test.test_name);
    if lines.next() != Some("running 1 test") || lines.next() != Some(expected_test.as_str()) {
        return Err("current native component did not execute its exact real test".into());
    }
    let summary = lines.next().ok_or("current native test summary absent")?;
    let counts = summary
        .strip_prefix("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; ")
        .ok_or("current native test exact execution counts differ")?;
    let (filtered, elapsed) = counts
        .split_once(" filtered out; finished in ")
        .ok_or("current native test summary framing differs")?;
    let _: u64 = filtered
        .parse()
        .map_err(|_| "current native test filtered count invalid")?;
    let seconds: f64 = elapsed
        .strip_suffix('s')
        .ok_or("current native test elapsed suffix absent")?
        .parse()
        .map_err(|_| "current native test elapsed time invalid")?;
    if !seconds.is_finite() || seconds < 0.0 || lines.next().is_some() {
        return Err(
            "current native test transcript contains extra execution or invalid timing".into(),
        );
    }
    let root: Value = crate::wire::decode(&resolve(
        test.native_retirement
            .as_deref()
            .ok_or("current native test retirement receipt absent")?,
    )?)?;
    let birth = if evidence.key.target.ends_with("windows-msvc") {
        "creation_time_100ns"
    } else {
        "birth"
    };
    let format = if evidence.key.target.ends_with("windows-msvc") {
        "memcordon.windows-native-test-retirement"
    } else {
        "memcordon.linux-native-test-retirement"
    };
    if root["format"] != format
        || root["revision"] != 1
        || root["process_id"].as_u64() != native.root_pid.map(u64::from)
        || root[birth].as_u64() != native.root_birth
        || root["image_sha256"] != image_sha
        || root["held_before_input_delivery"] != true
        || root["retirement_observed"] != true
        || root["same_image_helpers_absent"] != true
    {
        return Err("current native test original held owner was not independently retired".into());
    }
    if crate::sha256(&resolve(&semantic.challenge)?) != input.challenge_sha256 {
        return Err("current native test challenge was substituted".into());
    }
    Ok((semantic, input.challenge_sha256))
}

pub fn verify_case(
    evidence: &CaseEvidenceV2,
    input: &Value,
    build: &ComponentBuild,
    version: &str,
    resolve: &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
) -> VerificationResult<()> {
    if evidence.key.family != "C-PARSER"
        || evidence.key.channel.is_some()
        || !SCENARIOS.contains(&evidence.key.scenario.as_str())
    {
        return Err("not a current native parser component operation".into());
    }
    let (semantic, challenge) = native_harness(evidence, input, build, resolve)?;
    let test = semantic
        .component_test
        .as_ref()
        .ok_or("current parser native test absent")?;
    let receipt: ParserReceiptV2 = crate::wire::decode(&resolve(&test.native_receipt)?)?;
    let image = build
        .parser_executable
        .as_deref()
        .ok_or("current parser image absent")?;
    if receipt.format != "memcordon.native-parser-mutation-receipt"
        || receipt.revision != 2
        || receipt.run_id != evidence.run_id
        || receipt.recipe_id != build.recipe_id
        || receipt.native_target != evidence.key.target
        || receipt.test_name != TEST_NAME
        || test.test_name != TEST_NAME
        || receipt.executable_sha256 != crate::sha256(&resolve(image)?)
        || receipt.challenge_sha256 != challenge
        || receipt.observations.len() != SCENARIOS.len()
    {
        return Err(
            "current parser actual source/target/recipe/challenge inventory differs".into(),
        );
    }
    validate_mutations(&receipt, version, &evidence.key.target, resolve)
}

/// Independently checks only data-vector semantics. Native source/execution
/// qualification is performed separately by verify_case before this function.
pub fn validate_mutations(
    receipt: &ParserReceiptV2,
    version: &str,
    target: &str,
    resolve: &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
) -> VerificationResult<()> {
    if receipt.format != "memcordon.native-parser-mutation-receipt"
        || receipt.revision != 2
        || receipt.observations.len() != SCENARIOS.len()
    {
        return Err("current parser data receipt identity/inventory differs".into());
    }
    let manifest = resolve(&receipt.manifest)?;
    super::validate_manifest(&manifest)?;
    let mut seen = BTreeSet::new();
    for row in &receipt.observations {
        if !seen.insert(row.scenario.as_str())
            || !SCENARIOS.contains(&row.scenario.as_str())
            || !row.baseline_accepted
            || !row.data_only
            || row.baseline_profile_ready
            || row.actual_refusal.is_empty()
            || row.actual_refusal.len() > 4096
        {
            return Err(
                "current parser mutation missing/duplicate/fabricated acceptance/refusal".into(),
            );
        }
        let base = resolve(&row.base_input)?;
        let changed = resolve(&row.mutated_input)?;
        if ["omitted-case", "duplicate-case", "wrong-product"].contains(&row.scenario.as_str()) {
            if row.operation != "current-index-v2-inventory" {
                return Err("current index operation identity differs".into());
            }
            let index: EvidenceIndexV2 = crate::wire::decode(&base)?;
            validate_index_inventory(&manifest, &index)?;
            let mut expected = index.clone();
            match row.scenario.as_str() {
                "omitted-case" => {
                    expected.records.pop();
                }
                "duplicate-case" => expected.records.push(expected.records[0].clone()),
                _ => {
                    expected
                        .records
                        .iter_mut()
                        .find(|record| record.key.channel.is_some())
                        .ok_or("current index installed row absent")?
                        .key
                        .channel = Some("unselected-product".into());
                }
            }
            let mutated: EvidenceIndexV2 = crate::wire::decode(&changed)?;
            if serde_json::to_value(&mutated).map_err(|e| e.to_string())?
                != serde_json::to_value(expected).map_err(|e| e.to_string())?
                || validate_index_inventory(&manifest, &mutated).is_ok()
            {
                return Err("current index exact mutation was substituted or accepted".into());
            }
            continue;
        }
        if ["stale-attempt", "forged-cleanup"].contains(&row.scenario.as_str()) {
            if row.operation != "core-windows-terminal-v3-association" {
                return Err("current terminal operation identity differs".into());
            }
            let mut expected: Value = crate::wire::decode(&base)?;
            if expected["schema_version"] != 3
                || expected["retirement_proof"]["schema_version"] != 3
                || expected["attempt_id"] != expected["retirement_proof"]["attempt_id"]
                || expected["retirement_proof"]["native_job_empty_observed"] != true
            {
                return Err("current data-only terminal parser baseline differs".into());
            }
            if row.scenario == "stale-attempt" {
                expected["retirement_proof"]["attempt_id"] = json!("stale-attempt");
            } else {
                expected["retirement_proof"]["native_job_empty_observed"] = json!(false);
            }
            if crate::validate_json_document(&changed)? != expected {
                return Err("current terminal exact mutation substituted".into());
            }
            continue;
        }
        if row.operation != "core-result-v3-parse" {
            return Err("current result operation identity differs".into());
        }
        let mut expected = preparation(&base, version, target)?;
        if row.scenario == "oversized-record" {
            expected["diagnostics"] = json!(["x".repeat(16 * 1024 * 1024 + 1)]);
            if changed != canonical_fixture_bytes(&expected) || changed.len() <= 16 * 1024 * 1024 {
                return Err("current oversized raw parser vector was substituted".into());
            }
            continue;
        }
        if row.scenario == "duplicate-key" {
            let text = std::str::from_utf8(&base).map_err(|e| e.to_string())?;
            let exact = format!(
                "{{\"format\":\"memcordon.result\",{}",
                text.strip_prefix('{')
                    .ok_or("current result object absent")?
            );
            if changed != exact.as_bytes() || crate::validate_json_document(&changed).is_ok() {
                return Err("current duplicate raw key was substituted or accepted".into());
            }
            continue;
        }
        match row.scenario.as_str() {
            "wrong-format" => expected["format"] = json!("memcordon.forged"),
            "wrong-revision" => expected["revision"] = json!(99),
            "unknown-variant" => expected["runtime"]["kind"] = json!("qualified-by-readiness"),
            "unsupported-result-format" => {
                expected = json!({"format":"unsupported-result","revision":99});
            }
            _ => return Err("unknown current parser mutation".into()),
        }
        if crate::validate_json_document(&changed)? != expected {
            return Err("current exact result mutation substituted".into());
        }
    }
    Ok(())
}
