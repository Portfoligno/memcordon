//! Current parser operations emit data-only mutation receipts. The outer native
//! controller independently owns and observes this real test process.
use memcordon_readiness_verifier::{
    CaseRecord, CaseState, ProductKey,
    current::{
        self, EvidenceIndexV2,
        parsers::{ParserMutationV2, ParserReceiptV2},
    },
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::{Read, Write},
    path::PathBuf,
};
#[path = "../../../crates/memcordon-core/tests/support/windows_current_postauthorization.rs"]
mod current_terminal;
#[path = "support/current_version_vectors.rs"]
mod current_version_vectors;

const MANIFEST: &[u8] = include_bytes!("../../../ci/consumer-readiness-v2.toml");
fn preparation() -> Vec<u8> {
    let value = json!({"format":"memcordon.result","revision":3,
        "tool":{"name":"memcordon","version":env!("CARGO_PKG_VERSION"),"os":if cfg!(windows){"windows"}else{"linux"},"architecture":std::env::consts::ARCH,"runtime_features":[]},
        "invocation":{"syntax":"plus-budgets-v1","budget_tokens":[],"memory_token":null,"deadline_token":null,"argv":[]},
        "request":null,"provider":null,"workload_attempt":null,"release":"not-released",
        "outcome":{"kind":"provider-failure","native_termination":null,"wrapper_status":125},"cleanup":{"state":"unknown","obligations":[]},
        "delivery":"unknown","output_delivery":null,"diagnostics":[],"provider_failure":null,"request_rejection":null,"windows_rejection":null,"windows_attempt":null,
        "runtime":{"kind":"preparation-failed","profile":if cfg!(windows){"windows-sealed-current-token-v1"}else{"linux-private-workload-v1"}}});
    let bytes = current::parsers::canonical_fixture_bytes(&value);
    memcordon_core::result_v3::ResultV3::parse(&bytes).unwrap();
    bytes
}
fn index() -> EvidenceIndexV2 {
    let keys = current::validate_manifest(MANIFEST).unwrap();
    EvidenceIndexV2 {
        format: "memcordon.consumer-readiness.evidence".into(),
        revision: 2,
        profile: current::PROFILE.into(),
        run_id: "data-only-parser-model".into(),
        source_commit: "1".repeat(40),
        source_tree_sha256: "2".repeat(64),
        version: env!("CARGO_PKG_VERSION").into(),
        manifest_sha256: hex::encode(Sha256::digest(MANIFEST)),
        repository: None,
        products: Vec::new(),
        component_builds: Vec::new(),
        workflow_cells: keys
            .iter()
            .filter_map(|key| {
                key.channel.as_ref().map(|channel| ProductKey {
                    target: key.target.clone(),
                    channel: channel.clone(),
                })
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        fixture_cases: keys.iter().cloned().collect(),
        artifacts: Vec::new(),
        records: keys
            .into_iter()
            .map(|key| CaseRecord {
                key,
                run_id: "data-only-parser-model".into(),
                state: CaseState::NotRun,
                reason: Some("parser-structure-only".into()),
                evidence: None,
            })
            .collect(),
        producer_origins: Vec::new(),
        job_outcomes: Vec::new(),
        assessment_failures: Vec::new(),
    }
}
type ParserVector = (&'static str, &'static str, Vec<u8>, Vec<u8>, String);

fn vectors() -> Vec<ParserVector> {
    let baseline = preparation();
    let base: Value = serde_json::from_slice(&baseline).unwrap();
    let mut rows = Vec::new();
    for scenario in [
        "duplicate-key",
        "wrong-format",
        "wrong-revision",
        "unknown-variant",
        "oversized-record",
        "unsupported-result-format",
    ] {
        let mut changed = base.clone();
        match scenario {
            "wrong-format" => changed["format"] = json!("memcordon.forged"),
            "wrong-revision" => changed["revision"] = json!(99),
            "unknown-variant" => changed["runtime"]["kind"] = json!("qualified-by-readiness"),
            "oversized-record" => {
                changed["diagnostics"] =
                    json!(["x".repeat(current::parsers::OVERSIZED_DIAGNOSTIC_BYTES)])
            }
            "unsupported-result-format" => {
                changed = json!({"format":"unsupported-result","revision":99});
            }
            _ => {}
        }
        let changed = if scenario == "duplicate-key" {
            let text = std::str::from_utf8(&baseline).unwrap();
            format!("{{\"format\":\"memcordon.result\",{}", &text[1..]).into_bytes()
        } else {
            current::parsers::canonical_fixture_bytes(&changed)
        };
        let refusal = memcordon_core::result_v3::ResultV3::parse(&changed).unwrap_err();
        rows.push((
            scenario,
            "core-result-v3-parse",
            baseline.clone(),
            changed,
            refusal,
        ));
    }
    let rejection = current_terminal::rejection();
    let receipt = match rejection.disposition {
        memcordon_core::WindowsProviderRejectionDispositionV3::PostauthorizationFailure {
            receipt,
        } => receipt,
        _ => panic!("committed current terminal vector must be post-release data"),
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
        let decoded: memcordon_core::WindowsTerminalReceiptV3 =
            serde_json::from_value(changed.clone()).unwrap();
        let refusal = decoded.validate_for_attempt().unwrap_err().to_string();
        rows.push((
            scenario,
            "core-windows-terminal-v3-association",
            serde_json::to_vec(&base).unwrap(),
            serde_json::to_vec(&changed).unwrap(),
            refusal,
        ));
    }
    let baseline = index();
    current::parsers::validate_index_inventory(MANIFEST, &baseline).unwrap();
    for scenario in ["omitted-case", "duplicate-case", "wrong-product"] {
        let mut changed = baseline.clone();
        match scenario {
            "omitted-case" => {
                changed.records.pop();
            }
            "duplicate-case" => changed.records.push(changed.records[0].clone()),
            _ => {
                changed
                    .records
                    .iter_mut()
                    .find(|row| row.key.channel.is_some())
                    .unwrap()
                    .key
                    .channel = Some("unselected-product".into())
            }
        }
        let refusal = current::parsers::validate_index_inventory(MANIFEST, &changed).unwrap_err();
        rows.push((
            scenario,
            "current-index-v2-inventory",
            serde_json::to_vec(&baseline).unwrap(),
            serde_json::to_vec(&changed).unwrap(),
            refusal,
        ));
    }
    rows
}

#[test]
fn all_eleven_current_parser_operations_reject_the_exact_mutations() {
    let rows = vectors();
    assert_eq!(rows.len(), 11);
    assert_eq!(
        rows.iter().map(|row| row.0).collect::<BTreeSet<_>>().len(),
        11
    );
    assert!(rows.iter().all(|row| !row.4.is_empty()));
}

#[test]
fn independent_current_oracle_rejects_rehashed_vector_substitution() {
    let mut files =
        std::collections::BTreeMap::from([("manifest.toml".to_owned(), MANIFEST.to_vec())]);
    let observations = vectors()
        .into_iter()
        .map(|(scenario, operation, base, changed, refusal)| {
            let base_path = format!("{scenario}-base.json");
            let changed_path = format!("{scenario}-changed.json");
            files.insert(base_path.clone(), base);
            files.insert(changed_path.clone(), changed);
            ParserMutationV2 {
                scenario: scenario.into(),
                operation: operation.into(),
                base_input: base_path,
                mutated_input: changed_path,
                actual_refusal: refusal,
                baseline_accepted: true,
                data_only: true,
                baseline_profile_ready: false,
            }
        })
        .collect();
    let target = match (std::env::consts::ARCH, cfg!(windows)) {
        ("aarch64", true) => "aarch64-pc-windows-msvc",
        ("x86_64", true) => "x86_64-pc-windows-msvc",
        ("aarch64", false) => "aarch64-unknown-linux-gnu",
        _ => "x86_64-unknown-linux-gnu",
    };
    let receipt = ParserReceiptV2 {
        format: "memcordon.native-parser-mutation-receipt".into(),
        revision: 2,
        run_id: "data-only".into(),
        recipe_id: "data-only".into(),
        test_name: current::parsers::TEST_NAME.into(),
        native_target: target.into(),
        executable_sha256: "1".repeat(64),
        challenge_sha256: "2".repeat(64),
        manifest: "manifest.toml".into(),
        observations,
    };
    let check = |files: &std::collections::BTreeMap<String, Vec<u8>>, receipt: &ParserReceiptV2| {
        current::parsers::validate_mutations(receipt, env!("CARGO_PKG_VERSION"), target, &|path| {
            files
                .get(path)
                .cloned()
                .ok_or_else(|| "test vector absent".into())
        })
    };
    check(&files, &receipt).unwrap();
    let row = receipt
        .observations
        .iter()
        .find(|row| row.scenario == "wrong-revision")
        .unwrap();
    files.insert(row.mutated_input.clone(), files[&row.base_input].clone());
    assert!(check(&files, &receipt).is_err());
    let mut historical = receipt.clone();
    historical.revision = 1;
    assert!(check(&files, &historical).is_err());
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    run_id: String,
    recipe_id: String,
    native_target: String,
    artifact_root: PathBuf,
    artifact_prefix: String,
    challenge: Vec<u8>,
}

#[test]
fn current_capture_retains_exact_large_rejection_inputs_under_closed_purpose_bounds() {
    use current::parsers::{
        CAPTURE_FILE_COUNT, RESULT_INPUT_BYTES, TERMINAL_INPUT_BYTES, capture_inputs,
        validate_capture_inventory,
    };
    use std::collections::BTreeMap;
    assert_eq!(
        RESULT_INPUT_BYTES,
        memcordon_core::execution_facts::RESULT_MAX_BYTES
    );
    assert_eq!(
        TERMINAL_INPUT_BYTES,
        memcordon_core::WINDOWS_MAX_FRAME_BYTES
    );
    let prefix = "owned/current-parser/authority";
    let manifest = format!("{prefix}/current-manifest.toml");
    let mut files = BTreeMap::from([(manifest.clone(), MANIFEST.to_vec())]);
    let observations = vectors()
        .into_iter()
        .map(|(scenario, operation, base, changed, refusal)| {
            let base_input = format!("{prefix}/{scenario}-base.json");
            let mutated_input = format!("{prefix}/{scenario}-mutated.json");
            files.insert(base_input.clone(), base);
            files.insert(mutated_input.clone(), changed);
            ParserMutationV2 {
                scenario: scenario.into(),
                operation: operation.into(),
                base_input,
                mutated_input,
                actual_refusal: refusal,
                baseline_accepted: true,
                data_only: true,
                baseline_profile_ready: false,
            }
        })
        .collect();
    let target = match (std::env::consts::ARCH, cfg!(windows)) {
        ("aarch64", true) => "aarch64-pc-windows-msvc",
        ("x86_64", true) => "x86_64-pc-windows-msvc",
        ("aarch64", false) => "aarch64-unknown-linux-gnu",
        _ => "x86_64-unknown-linux-gnu",
    };
    let receipt = ParserReceiptV2 {
        format: "memcordon.native-parser-mutation-receipt".into(),
        revision: 2,
        run_id: "data-only".into(),
        recipe_id: "data-only".into(),
        test_name: current::parsers::TEST_NAME.into(),
        native_target: target.into(),
        executable_sha256: "1".repeat(64),
        challenge_sha256: "2".repeat(64),
        manifest,
        observations,
    };
    let reads = std::cell::RefCell::new(Vec::new());
    let read = |path: &str, bound: usize| {
        reads.borrow_mut().push((path.to_string(), bound));
        let bytes = files.get(path).ok_or("input absent")?;
        if bytes.len() > bound {
            return Err("purpose bound exceeded".into());
        }
        Ok(bytes.clone())
    };
    let captured =
        capture_inputs(&receipt, prefix, env!("CARGO_PKG_VERSION"), target, &read).unwrap();
    assert_eq!(captured.len() + 1, CAPTURE_FILE_COUNT);
    let index = format!("{prefix}/duplicate-case-base.json");
    assert!(captured[&index].len() > 256 * 1024);
    let oversized = format!("{prefix}/oversized-record-mutated.json");
    assert!(captured[&oversized].len() > RESULT_INPUT_BYTES);
    assert!(memcordon_core::result_v3::ResultV3::parse(&captured[&oversized]).is_err());
    let reads = reads.borrow();
    assert_eq!(
        reads.iter().find(|(path, _)| path == &index).unwrap().1,
        memcordon_readiness_verifier::MAX_INDEX_BYTES
    );
    assert_eq!(
        reads.iter().find(|(path, _)| path == &oversized).unwrap().1,
        captured[&oversized].len()
    );
    let mut names = captured
        .keys()
        .map(|path| {
            path.strip_prefix(&format!("{prefix}/"))
                .unwrap()
                .to_string()
        })
        .collect::<Vec<_>>();
    names.push("native-receipt.json".into());
    validate_capture_inventory(prefix, &captured, &names).unwrap();
    let mut wrong = names.clone();
    wrong.pop();
    assert!(validate_capture_inventory(prefix, &captured, &wrong).is_err());
    wrong = names.clone();
    wrong.push("unlisted-large.bin".into());
    assert!(validate_capture_inventory(prefix, &captured, &wrong).is_err());
    wrong = names.clone();
    wrong[0] = wrong[1].clone();
    assert!(validate_capture_inventory(prefix, &captured, &wrong).is_err());
    drop(reads);
    drop(captured);
    for (kind, replacement) in [
        ("alias", format!("{prefix}/duplicate-key-base.json")),
        ("escape", "../outside.json".into()),
        ("unexpected", format!("{prefix}/unlisted-large.bin")),
    ] {
        let mut changed = receipt.clone();
        changed.observations[1].base_input = replacement;
        assert!(
            capture_inputs(&changed, prefix, env!("CARGO_PKG_VERSION"), target, &read).is_err(),
            "{kind}"
        );
    }
    let mut incomplete = receipt.clone();
    incomplete.observations.pop();
    assert!(
        capture_inputs(
            &incomplete,
            prefix,
            env!("CARGO_PKG_VERSION"),
            target,
            &read
        )
        .is_err()
    );
    let oversized_limit = files[&oversized].len();
    assert!(
        capture_inputs(
            &receipt,
            prefix,
            env!("CARGO_PKG_VERSION"),
            target,
            &|path, bound| {
                if path == oversized {
                    Ok(vec![b'x'; oversized_limit + 1])
                } else {
                    read(path, bound)
                }
            }
        )
        .is_err()
    );
    assert!(
        capture_inputs(
            &receipt,
            prefix,
            env!("CARGO_PKG_VERSION"),
            target,
            &|path, bound| {
                if path == oversized {
                    Ok(vec![b'x'; oversized_limit])
                } else {
                    read(path, bound)
                }
            }
        )
        .is_err()
    );
}

#[test]
#[ignore = "requires the original native controller's owned receipt directory and challenge"]
fn emit_current_parser_mutations() {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(65537)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 65536);
    let input: Input = serde_json::from_value(
        memcordon_readiness_verifier::validate_json_document(&bytes).unwrap(),
    )
    .unwrap();
    assert!(
        !input.run_id.is_empty()
            && !input.recipe_id.is_empty()
            && input.challenge.len() == 32
            && input.artifact_root.is_absolute()
            && input.artifact_root.is_dir()
    );
    assert!(
        std::path::Path::new(&input.artifact_prefix)
            .components()
            .all(|part| matches!(part, std::path::Component::Normal(_)))
    );
    let native = match (std::env::consts::ARCH, std::env::consts::OS) {
        ("x86_64", "linux") => "x86_64-unknown-linux-gnu",
        ("aarch64", "linux") => "aarch64-unknown-linux-gnu",
        ("x86_64", "windows") => "x86_64-pc-windows-msvc",
        ("aarch64", "windows") => "aarch64-pc-windows-msvc",
        _ => panic!("unsupported native parser target"),
    };
    assert_eq!(input.native_target, native);
    let write = |name: &str, bytes: &[u8]| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(input.artifact_root.join(name))
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        format!("{}/{name}", input.artifact_prefix)
    };
    let manifest = write("current-manifest.toml", MANIFEST);
    let observations = vectors()
        .into_iter()
        .map(
            |(scenario, operation, base, changed, refusal)| ParserMutationV2 {
                scenario: scenario.into(),
                operation: operation.into(),
                base_input: write(&format!("{scenario}-base.json"), &base),
                mutated_input: write(&format!("{scenario}-mutated.json"), &changed),
                actual_refusal: refusal,
                baseline_accepted: true,
                data_only: true,
                baseline_profile_ready: false,
            },
        )
        .collect();
    let mut image = Vec::new();
    std::fs::File::open(std::env::current_exe().unwrap())
        .unwrap()
        .take(512 * 1024 * 1024 + 1)
        .read_to_end(&mut image)
        .unwrap();
    assert!(image.len() <= 512 * 1024 * 1024);
    let receipt = ParserReceiptV2 {
        format: "memcordon.native-parser-mutation-receipt".into(),
        revision: 2,
        run_id: input.run_id,
        recipe_id: input.recipe_id,
        test_name: current::parsers::TEST_NAME.into(),
        native_target: native.into(),
        executable_sha256: hex::encode(Sha256::digest(&image)),
        challenge_sha256: hex::encode(Sha256::digest(&input.challenge)),
        manifest,
        observations,
    };
    write(
        "native-receipt.json",
        &serde_json::to_vec(&receipt).unwrap(),
    );
}
