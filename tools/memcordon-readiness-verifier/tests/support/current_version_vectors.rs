use memcordon_core::workload_request::WorkloadRequestV1;
use memcordon_readiness_verifier::current::linux_components::{
    self, VersionReceipt, VersionVector,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::PathBuf,
};

fn operations(prefix: &str) -> (Vec<VersionVector>, BTreeMap<String, Vec<u8>>) {
    let request = serde_json::to_vec(&linux_components::request_fixture()).unwrap();
    let mut result: Value = serde_json::from_slice(&super::preparation()).unwrap();
    result["tool"]["os"] = json!("linux");
    result["runtime"]["profile"] = json!("linux-private-workload-v1");
    let result = serde_json::to_vec(&result).unwrap();
    let mut files = BTreeMap::new();
    let mut rows = Vec::new();
    let mut retain = |name: String, bytes: Vec<u8>| {
        let path = format!("{prefix}/{name}");
        assert!(files.insert(path.clone(), bytes).is_none());
        path
    };
    for scenario in linux_components::VERSION_SCENARIOS {
        let base = if *scenario == "result-v3-vectors" {
            result.clone()
        } else {
            request.clone()
        };
        let baseline = retain(format!("{scenario}-baseline.json"), base.clone());
        let value: Value = serde_json::from_slice(&base).unwrap();
        let mut changed = Vec::new();
        let mut actual_refusals = Vec::new();
        let mut canonical = None;
        let mut digest = None;
        if *scenario == "projection-mutation" {
            let parsed = WorkloadRequestV1::parse(&base).unwrap();
            let bytes = parsed.canonical_bytes().unwrap();
            let actual: Value = serde_json::to_value(parsed.digest().unwrap()).unwrap();
            digest = Some(actual.as_str().unwrap().to_owned());
            canonical = Some(retain(format!("{scenario}-canonical.json"), bytes));
            let mut mutant = value.clone();
            mutant["runtime"]["inputs"]["input_digest"] = json!("33".repeat(32));
            let bytes = serde_json::to_vec(&mutant).unwrap();
            let changed_digest: Value =
                serde_json::to_value(WorkloadRequestV1::parse(&bytes).unwrap().digest().unwrap())
                    .unwrap();
            assert_ne!(changed_digest.as_str(), digest.as_deref());
            changed.push(retain(format!("{scenario}-mutant.json"), bytes));
        } else {
            for index in 0..3 {
                let mut mutant = value.clone();
                if *scenario == "request-v1-vectors" {
                    match index {
                        0 => mutant["revision"] = json!(99),
                        1 => mutant["authorization"] = json!({}),
                        _ => mutant["runtime"]["profile"] = json!("administrator-approved"),
                    }
                } else {
                    match index {
                        0 => mutant["revision"] = json!(99),
                        1 => mutant["runtime"]["kind"] = json!("qualified"),
                        _ => mutant["release"] = json!("released"),
                    }
                }
                let bytes = serde_json::to_vec(&mutant).unwrap();
                let error = if *scenario == "result-v3-vectors" {
                    memcordon_core::result_v3::ResultV3::parse(&bytes).unwrap_err()
                } else {
                    let error = WorkloadRequestV1::parse(&bytes).unwrap_err();
                    error.to_string()
                };
                changed.push(retain(format!("{scenario}-{index}.json"), bytes));
                actual_refusals.push(error);
            }
        }
        rows.push(VersionVector {
            scenario: (*scenario).into(),
            baseline,
            changed,
            actual_refusals,
            canonical,
            digest,
        });
    }
    (rows, files)
}

#[test]
fn current_request_result_operations_have_independent_mutation_oracles() {
    let (observations, files) = operations("vectors");
    let target = if cfg!(target_arch = "aarch64") {
        "aarch64-unknown-linux-gnu"
    } else {
        "x86_64-unknown-linux-gnu"
    };
    let receipt = VersionReceipt {
        format: "memcordon.linux-current-version-component".into(),
        revision: 1,
        run_id: "data-only".into(),
        recipe_id: "data-only".into(),
        native_target: target.into(),
        test_name: linux_components::VERSION_TEST.into(),
        executable_sha256: "11".repeat(32),
        challenge_sha256: "22".repeat(32),
        observations,
    };
    let resolve = |path: &str| {
        files
            .get(path)
            .cloned()
            .ok_or_else(|| format!("missing {path}"))
    };
    linux_components::validate_version_vectors(
        &receipt,
        env!("CARGO_PKG_VERSION"),
        target,
        &resolve,
    )
    .unwrap();
    let mut forged = files.clone();
    let row = receipt
        .observations
        .iter()
        .find(|row| row.scenario == "projection-mutation")
        .unwrap();
    forged.insert(row.changed[0].clone(), files[&row.baseline].clone());
    assert!(
        linux_components::validate_version_vectors(
            &receipt,
            env!("CARGO_PKG_VERSION"),
            target,
            &|path| forged.get(path).cloned().ok_or_else(|| "missing".into())
        )
        .is_err()
    );
}

#[test]
#[ignore = "requires the original native controller input, held process and exclusive capture directory"]
fn emit_current_request_result_vectors() {
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
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(65537)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 65536);
    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes).unwrap();
    let input: Input = serde_json::from_slice(&bytes).unwrap();
    let target = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
        ("linux", "aarch64") => "aarch64-unknown-linux-gnu",
        _ => panic!("actual native Linux host required"),
    };
    assert_eq!(input.native_target, target);
    assert!(input.artifact_root.is_absolute() && input.artifact_root.is_dir());
    assert!(
        !input.run_id.is_empty()
            && !input.recipe_id.is_empty()
            && input.challenge.len() == 32
            && input.challenge.iter().any(|byte| *byte != 0)
    );
    assert!(
        input
            .artifact_prefix
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
            && !input.artifact_prefix.contains(['\\', ':'])
    );
    let (observations, files) = operations(&input.artifact_prefix);
    let receipt = VersionReceipt {
        format: "memcordon.linux-current-version-component".into(),
        revision: 1,
        run_id: input.run_id,
        recipe_id: input.recipe_id,
        native_target: target.into(),
        test_name: linux_components::VERSION_TEST.into(),
        executable_sha256: hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
            std::fs::read(std::env::current_exe().unwrap()).unwrap(),
        )),
        challenge_sha256: hex::encode(<sha2::Sha256 as sha2::Digest>::digest(input.challenge)),
        observations,
    };
    let write = |name: &str, bytes: &[u8]| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(input.artifact_root.join(name))
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    };
    for (path, bytes) in files {
        write(path.rsplit('/').next().unwrap(), &bytes);
    }
    write(
        "native-receipt.json",
        &serde_json::to_vec(&receipt).unwrap(),
    );
}
