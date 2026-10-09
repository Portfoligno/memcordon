#[path = "../../../../crates/memcordon-core/tests/support/windows_postauthorization.rs"]
mod committed_protocol_fixture;

use serde_json::{Value, json};

#[expect(
    clippy::type_complexity,
    reason = "parser vectors independently retain family, scenario, original bytes, hostile bytes and exact diagnostic"
)]
fn vectors() -> Vec<(&'static str, &'static str, Vec<u8>, Vec<u8>, String)> {
    let base = json!({"format":"memcordon.result","revision":2,
        "tool":{"name":"memcordon","version":env!("CARGO_PKG_VERSION"),"os":"linux","architecture":"x86_64","runtime_features":[]},
        "runtime":{"kind":"linux-mixed-private","carrier_revision":2,"provider_contract":4,"launch_wire":4,
            "outcome":{"kind":"rejected-ingress","request_bytes_sha256":"11".repeat(32),"reason":"malformed-ingress","detail":"component vector",
                "allocation":{"authorization":"never-authorized","obligations":[]}}},
        "delivery":"not-submitted","frontend":{"relay_drained":true,"interruption":null,"relay_error":null},"wrapper_status":125,
        "invocation":{"syntax":"plus-budgets-v1","budget_tokens":[],"memory_token":null,"deadline_token":null,"argv":[]}});
    let baseline = serde_json::to_vec(&base).unwrap();
    memcordon_core::result_v2::ResultV2::parse(&baseline).unwrap();
    let mut output = Vec::new();
    for scenario in [
        "duplicate-key",
        "wrong-format",
        "wrong-revision",
        "unknown-authority-variant",
        "oversized-record",
    ] {
        let mut changed = base.clone();
        match scenario {
            "wrong-format" => changed["format"] = json!("memcordon.forged"),
            "wrong-revision" => changed["revision"] = json!(99),
            "unknown-authority-variant" => {
                changed["runtime"]["outcome"]["allocation"]["authorization"] =
                    json!("qualified-by-readiness")
            }
            "oversized-record" => {
                changed["runtime"]["outcome"]["detail"] =
                    json!("x".repeat(memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES + 1))
            }
            _ => {}
        }
        let changed = if scenario == "duplicate-key" {
            let original = String::from_utf8(baseline.clone()).unwrap();
            format!("{{\"format\":\"memcordon.result\",{}", &original[1..]).into_bytes()
        } else {
            serde_json::to_vec(&changed).unwrap()
        };
        let refusal = memcordon_core::result_v2::ResultV2::parse(&changed).unwrap_err();
        output.push((
            scenario,
            "core-result-v2-parse",
            baseline.clone(),
            changed,
            refusal,
        ));
    }
    let receipt = match committed_protocol_fixture::rejection().disposition {
        memcordon_core::WindowsProviderRejectionDispositionV2::PostauthorizationFailure {
            receipt,
        } => receipt,
        _ => panic!("committed fixture must be postauthorization"),
    };
    receipt.validate_for_attempt().unwrap();
    let base = serde_json::to_value(&receipt).unwrap();
    for scenario in ["stale-attempt", "forged-cleanup"] {
        let mut changed = base.clone();
        if scenario == "stale-attempt" {
            changed["retirement_proof"]["attempt_id"] = json!("stale-attempt");
        } else {
            changed["retirement_proof"]["native_job_empty_observed"] = json!(false);
        }
        let decoded: memcordon_core::WindowsTerminalReceiptV2 =
            serde_json::from_value(changed.clone()).unwrap();
        let refusal = decoded.validate_for_attempt().unwrap_err().to_string();
        output.push((
            scenario,
            "core-windows-terminal-v2-association",
            serde_json::to_vec(&base).unwrap(),
            serde_json::to_vec(&changed).unwrap(),
            refusal,
        ));
    }
    output
}

#[test]
fn actual_operational_parsers_reject_all_seven_protocol_mutations() {
    let observations = vectors();
    assert_eq!(observations.len(), 7);
    assert!(
        observations
            .iter()
            .all(|(_, _, _, _, refusal)| !refusal.is_empty())
    );
}

#[test]
fn independently_decoded_operational_receipt_rejects_rehashed_substitutions() {
    use memcordon_readiness_verifier::*;
    use sha2::{Digest, Sha256};
    let root = tempfile::tempdir().unwrap();
    let mut artifacts = Vec::new();
    let mut save = |name: String, bytes: Vec<u8>| {
        std::fs::write(root.path().join(&name), &bytes).unwrap();
        artifacts.push(Artifact {
            path: name.clone(),
            length: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(bytes)),
        });
        name
    };
    let observations = vectors()
        .into_iter()
        .map(
            |(scenario, operation, base, changed, refusal)| OperationalParserMutation {
                scenario: scenario.into(),
                operation: operation.into(),
                base_input: save(format!("{scenario}-base.json"), base),
                mutated_input: save(format!("{scenario}-mutated.json"), changed),
                actual_refusal: refusal,
                baseline_accepted: true,
                fixture_resource_claims: true,
            },
        )
        .collect();
    let receipt = OperationalParserReceipt {
        format: "memcordon.native-operational-parser-receipt".into(),
        revision: 1,
        run_id: "test-run".into(),
        recipe_id: "test-recipe".into(),
        test_name:
            "operational_parser_receipts::native_operational_parser_mutations_emit_actual_receipts"
                .into(),
        native_target: "x86_64-unknown-linux-gnu".into(),
        executable_sha256: "11".repeat(32),
        challenge_sha256: "22".repeat(32),
        observations,
    };
    let key = CaseKey {
        target: receipt.native_target.clone(),
        channel: None,
        evidence_class: EvidenceClass::NativeComponentRegression,
        family: "C-PARSER".into(),
        scenario: "forged-cleanup".into(),
    };
    validate_operational_parser_receipt(&receipt, &key, &artifacts, root.path()).unwrap();
    let mut missing = receipt.clone();
    missing.observations.pop();
    assert!(validate_operational_parser_receipt(&missing, &key, &artifacts, root.path()).is_err());
    let mut fabricated = receipt.clone();
    fabricated.observations[0].fixture_resource_claims = false;
    assert!(
        validate_operational_parser_receipt(&fabricated, &key, &artifacts, root.path()).is_err()
    );
    let row = receipt
        .observations
        .iter()
        .find(|row| row.scenario == "wrong-revision")
        .unwrap();
    let mut changed: Value =
        serde_json::from_slice(&std::fs::read(root.path().join(&row.mutated_input)).unwrap())
            .unwrap();
    changed["wrapper_status"] = json!(0);
    let bytes = serde_json::to_vec(&changed).unwrap();
    std::fs::write(root.path().join(&row.mutated_input), &bytes).unwrap();
    let artifact = artifacts
        .iter_mut()
        .find(|artifact| artifact.path == row.mutated_input)
        .unwrap();
    artifact.length = bytes.len() as u64;
    artifact.sha256 = hex::encode(Sha256::digest(bytes));
    assert!(validate_operational_parser_receipt(&receipt, &key, &artifacts, root.path()).is_err());
}

#[test]
#[ignore = "requires an explicitly owned native component receipt directory"]
fn native_operational_parser_mutations_emit_actual_receipts() {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Write};
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        run_id: String,
        recipe_id: String,
        native_target: String,
        artifact_root: std::path::PathBuf,
        artifact_prefix: String,
        challenge: Vec<u8>,
    }
    let mut input_bytes = Vec::new();
    std::io::stdin()
        .take(65537)
        .read_to_end(&mut input_bytes)
        .unwrap();
    assert!(input_bytes.len() <= 65536);
    let input: Input =
        serde_json::from_value(super::validate_json_document(&input_bytes).unwrap()).unwrap();
    assert!(!input.run_id.is_empty() && !input.recipe_id.is_empty() && input.challenge.len() == 32);
    assert!(input.artifact_root.is_absolute() && input.artifact_root.is_dir());
    assert!(
        !input.artifact_prefix.is_empty()
            && input
                .artifact_prefix
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..")
            && !input.artifact_prefix.contains(['\\', ':'])
    );
    let target = match (std::env::consts::ARCH, std::env::consts::OS) {
        ("x86_64", "linux") => "x86_64-unknown-linux-gnu",
        ("aarch64", "linux") => "aarch64-unknown-linux-gnu",
        ("x86_64", "windows") => "x86_64-pc-windows-msvc",
        ("aarch64", "windows") => "aarch64-pc-windows-msvc",
        _ => panic!("unsupported native target"),
    };
    assert_eq!(input.native_target, target);
    let mut executable = Vec::new();
    std::fs::File::open(std::env::current_exe().unwrap())
        .unwrap()
        .take(512 * 1024 * 1024 + 1)
        .read_to_end(&mut executable)
        .unwrap();
    assert!(executable.len() <= 512 * 1024 * 1024);
    let write = |name: &str, bytes: &[u8]| {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(input.artifact_root.join(name))
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        format!("{}/{}", input.artifact_prefix, name)
    };
    let observations: Vec<Value> = vectors().into_iter().map(|(scenario, operation, base, changed, refusal)| json!({
        "scenario":scenario,"operation":operation,"base_input":write(&format!("{scenario}-base.json"),&base),
        "mutated_input":write(&format!("{scenario}-mutated.json"),&changed),"actual_refusal":refusal,
        "baseline_accepted":true,"fixture_resource_claims":true})).collect();
    let receipt = json!({"format":"memcordon.native-operational-parser-receipt","revision":1,"run_id":input.run_id,"recipe_id":input.recipe_id,
        "test_name":"operational_parser_receipts::native_operational_parser_mutations_emit_actual_receipts","native_target":target,
        "executable_sha256":hex::encode(Sha256::digest(executable)),"challenge_sha256":hex::encode(Sha256::digest(input.challenge)),"observations":observations});
    write(
        "native-receipt.json",
        &serde_json::to_vec(&receipt).unwrap(),
    );
}
