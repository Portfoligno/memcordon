//! Capture current native component operations without a historical launch fixture.
use super::artifacts;
use crate::{CiError, Result, readiness_identity::SourceIdentity};
use memcordon_readiness_verifier::{
    current::{CaseEvidenceV2, parsers},
    *,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, io::Write, path::Path};

pub fn collect_lifecycle(
    identity: &SourceIdentity,
    build: &ComponentBuild,
    source: &Artifact,
    experiment: &super::linux_current_component_lifetime::Experiment,
    prefix: &str,
    destination: &Path,
    version: &str,
) -> Result<(Vec<CaseRecord>, Vec<Artifact>)> {
    let relative = format!("{prefix}/current-lifecycle/{}", experiment.scenario);
    let key = CaseKey {
        target: build.target.clone(),
        channel: None,
        evidence_class: EvidenceClass::NativeComponentRegression,
        family: if ["release-barrier", "journal-barrier"].contains(&experiment.scenario.as_str()) {
            "L-VER-01"
        } else {
            "L-LIFE-04"
        }
        .into(),
        scenario: experiment.scenario.clone(),
    };
    let actor = build.actor_executable.as_ref().ok_or_else(|| {
        CiError::Message("actual current lifecycle controller role absent".into())
    })?;
    let mut files = BTreeMap::new();
    let mut refs = BTreeMap::new();
    for (name, bytes) in &experiment.files {
        if Path::new(name).components().count() != 1 || name.starts_with('.') {
            return Err(CiError::Message(
                "native lifecycle capture leaf escapes allocation".into(),
            ));
        }
        let path = format!("{relative}/{name}");
        refs.insert(name.clone(), path.clone());
        files.insert(path, bytes.clone());
    }
    let input_path = format!("{relative}/input.json");
    let input = json!({"format":"memcordon.current-native-component-input","revision":1,"key":key,"run_id":identity.run_id,"scenario":experiment.scenario});
    let input_bytes = serde_json::to_vec(&input)?;
    let input_sha = artifacts::checksum(&input_bytes);
    files.insert(input_path.clone(), input_bytes);
    let proof = Path::new(actor)
        .parent()
        .ok_or_else(|| CiError::Message("lifecycle actor proof parent absent".into()))?
        .join("preparation.json")
        .to_string_lossy()
        .into_owned();
    let receipt = json!({"format":"memcordon.current-native-lifecycle-component","revision":1,"key":key,"run_id":identity.run_id,"recipe_id":build.recipe_id,
        "source_commit":identity.source_commit,"source_tree_sha256":identity.source_tree_sha256,"actor":actor,"preparation":proof,"captures":refs});
    let receipt_path = format!("{relative}/component.json");
    files.insert(receipt_path.clone(), serde_json::to_vec(&receipt)?);
    let evidence = CaseEvidenceV2 {
        format: "memcordon.consumer-readiness.case".into(),
        revision: 2,
        key: key.clone(),
        run_id: identity.run_id.clone(),
        source_commit: identity.source_commit.clone(),
        source_tree_sha256: identity.source_tree_sha256.clone(),
        lease_id: None,
        fixture: actor.clone(),
        fixture_source: source.path.clone(),
        fixture_sha256: artifacts::checksum(&artifacts::read_file(&destination.join(actor))?),
        fixture_source_sha256: source.sha256.clone(),
        input: input_path,
        input_sha256: input_sha,
        invocation: refs["start.json"].clone(),
        request: Some(refs["request.json"].clone()),
        raw_result: refs.get("result.json").cloned(),
        attempt_observation: Some(refs["attempt.json"].clone()),
        authenticated_terminal: Some(refs["journal-after.json"].clone()),
        recovery: refs.get("recovery.json").cloned(),
        stdout: refs["stdout.bin"].clone(),
        stderr: refs["stderr.bin"].clone(),
        outputs: Vec::new(),
        native_observation: refs["held-before.json"].clone(),
        retirement: refs["action.json"].clone(),
        semantic_observation: receipt_path,
        component_recipe_id: Some(build.recipe_id.clone()),
    };
    let evidence_path = format!("{relative}/case.json");
    files.insert(evidence_path.clone(), serde_json::to_vec(&evidence)?);
    let resolve = |path: &str| -> std::result::Result<Vec<u8>, String> {
        if let Some(bytes) = files.get(path) {
            return Ok(bytes.clone());
        }
        if path == actor || path == proof || path == source.path {
            return artifacts::read_file(&destination.join(path))
                .map_err(|error| error.to_string());
        }
        Err("native lifecycle oracle requested uncaptured artifact".into())
    };
    let verified = memcordon_readiness_verifier::current::linux_components::verify_case(
        &evidence, &input, build, version, &resolve,
    );
    let (state, reason) = match verified {
        Ok(()) => (CaseState::Passed, None),
        Err(error) => (CaseState::Failed, Some(error)),
    };
    let mut captured = Vec::new();
    fs::create_dir_all(destination.join(&relative))?;
    for (path, bytes) in files {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination.join(&path))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        captured.push(Artifact {
            path,
            length: bytes.len() as u64,
            sha256: artifacts::checksum(&bytes),
        });
    }
    Ok((
        vec![CaseRecord {
            key,
            run_id: identity.run_id.clone(),
            state,
            reason,
            evidence: Some(evidence_path),
        }],
        captured,
    ))
}

pub fn collect_parser(
    identity: &SourceIdentity,
    build: &ComponentBuild,
    source: &Artifact,
    output: &Path,
    prefix: &str,
    destination: &Path,
    version: &str,
) -> Result<(Vec<CaseRecord>, Vec<Artifact>)> {
    collect_operation(
        identity,
        build,
        source,
        output,
        prefix,
        destination,
        version,
        "parser",
    )
}

pub fn collect_filter(
    identity: &SourceIdentity,
    build: &ComponentBuild,
    source: &Artifact,
    output: &Path,
    prefix: &str,
    destination: &Path,
    version: &str,
) -> Result<(Vec<CaseRecord>, Vec<Artifact>)> {
    collect_operation(
        identity,
        build,
        source,
        output,
        prefix,
        destination,
        version,
        "filter",
    )
}

pub fn collect_versions(
    identity: &SourceIdentity,
    build: &ComponentBuild,
    source: &Artifact,
    output: &Path,
    prefix: &str,
    destination: &Path,
    version: &str,
) -> Result<(Vec<CaseRecord>, Vec<Artifact>)> {
    collect_operation(
        identity,
        build,
        source,
        output,
        prefix,
        destination,
        version,
        "versions",
    )
}

pub fn collect_wire_version(
    identity: &SourceIdentity,
    build: &ComponentBuild,
    source: &Artifact,
    output: &Path,
    prefix: &str,
    destination: &Path,
    version: &str,
) -> Result<(Vec<CaseRecord>, Vec<Artifact>)> {
    collect_operation(
        identity,
        build,
        source,
        output,
        prefix,
        destination,
        version,
        "wire",
    )
}

fn collect_operation(
    identity: &SourceIdentity,
    build: &ComponentBuild,
    source: &Artifact,
    output: &Path,
    prefix: &str,
    destination: &Path,
    version: &str,
    operation: &str,
) -> Result<(Vec<CaseRecord>, Vec<Artifact>)> {
    let wire = operation == "wire";
    let parser = operation != "filter" && !wire;
    let versions = operation == "versions";
    let test = if wire {
        memcordon_readiness_verifier::current::linux_components::WIRE_TEST
    } else if versions {
        memcordon_readiness_verifier::current::linux_components::VERSION_TEST
    } else if parser {
        parsers::TEST_NAME
    } else {
        "native_current_filter::current_filter_vectors_emit_actual_component_receipts"
    };
    let receipt = if wire {
        "current-wire-version.receipt.json"
    } else if parser {
        "native-receipt.json"
    } else {
        "filter-native-receipt.json"
    };
    let scenarios = if wire {
        &["unsupported-wire-version"][..]
    } else if versions {
        memcordon_readiness_verifier::current::linux_components::VERSION_SCENARIOS
    } else if parser {
        parsers::SCENARIOS
    } else {
        &["filter-x64", "filter-arm64"]
    };
    let mut values = BTreeMap::new();
    let entries = fs::read_dir(output)?.collect::<std::io::Result<Vec<_>>>()?;
    if entries.len() > 128
        || prefix
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == "..")
        || prefix.contains(['\\', ':'])
    {
        return Err(CiError::Message(
            "current native parser capture inventory differs".into(),
        ));
    }
    for entry in entries {
        if !entry.file_type()?.is_file() {
            return Err(CiError::Message(
                "current parser capture has unresolved member".into(),
            ));
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| CiError::Message("current parser member encoding differs".into()))?;
        if name.starts_with('.') {
            return Err(CiError::Message(
                "current parser hidden capture rejected".into(),
            ));
        }
        let bytes = crate::linux_consumer_readiness::measured(&entry.path(), 32 * 1024 * 1024)
            .map_err(CiError::Message)?;
        values.insert(format!("{prefix}/{name}"), bytes);
    }
    let raw = |name: &str| -> Result<Value> {
        let bytes = values
            .get(&format!("{prefix}/{name}"))
            .ok_or_else(|| CiError::Message(format!("current parser capture missing: {name}")))?;
        memcordon_core::canonical_json::reject_duplicate_json_keys(bytes)
            .map_err(CiError::Message)?;
        Ok(serde_json::from_slice(bytes)?)
    };
    let before = raw("native-pre-input.json")?;
    let retired = raw("native-retirement.json")?;
    let exit = raw("native-exit.json")?;
    let spawn = raw("native-spawn-intent.json")?;
    let input = raw("native-input.json")?;
    if exit["native_status"] != 0
        || exit["input_delivered"] != true
        || exit["capture_complete"] != true
        || before["process_id"] != retired["process_id"]
        || before["birth"] != retired["birth"]
        || before["held_before_input_delivery"] != true
        || spawn["environment_cleared"] != true
        || spawn["test_name"] != test
        || input["run_id"] != identity.run_id
        || input["recipe_id"] != build.recipe_id
        || input["native_target"] != build.target
        || input["artifact_prefix"] != prefix
    {
        return Err(CiError::Message(
            "current parser original child/input/wait binding differs".into(),
        ));
    }
    let executable = if parser {
        build
            .parser_executable
            .as_ref()
            .ok_or_else(|| CiError::Message("current parser measured role missing".into()))?
    } else {
        &build.executable
    };
    let image = artifacts::read_file(&destination.join(executable))?;
    let image_sha = artifacts::checksum(&image);
    if before["image_sha256"] != image_sha || spawn["image_sha256"] != image_sha {
        return Err(CiError::Message("current parser held image differs".into()));
    }
    let argv: Vec<Vec<u8>> = serde_json::from_value(spawn["argv_bytes"].clone())?;
    if argv
        != [
            b"--exact".to_vec(),
            test.as_bytes().to_vec(),
            b"--ignored".to_vec(),
            b"--test-threads=1".to_vec(),
        ]
    {
        return Err(CiError::Message(
            "current parser actual argv differs".into(),
        ));
    }
    let challenge: Vec<u8> = serde_json::from_value(input["challenge"].clone())?;
    if challenge.len() != 32 || challenge.iter().all(|byte| *byte == 0) {
        return Err(CiError::Message("current parser challenge invalid".into()));
    }
    let challenge_sha = artifacts::checksum(&challenge);
    let pid = before["process_id"]
        .as_u64()
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid > 0)
        .ok_or_else(|| CiError::Message("current parser held PID absent".into()))?;
    let birth = before["birth"]
        .as_u64()
        .filter(|birth| *birth > 0)
        .ok_or_else(|| CiError::Message("current parser held birth absent".into()))?;
    let mut persist = |name: &str, bytes: Vec<u8>| -> String {
        let path = format!("{prefix}/{name}");
        assert!(
            values.insert(path.clone(), bytes).is_none(),
            "exclusive current parser capture name"
        );
        path
    };
    let challenge_path = persist("controller-challenge.bin", challenge);
    let environment = serde_json::to_vec(&NativeEnvironment::UnixBytes(Vec::new()))?;
    let environment_sha = artifacts::checksum(&environment);
    let environment_path = persist("controller-environment.json", environment);
    use std::os::unix::ffi::OsStrExt;
    let report = memcordon_core::InvocationReport {
        syntax: "plus-budgets-v1".into(),
        budget_tokens: Vec::new(),
        memory_token: None,
        deadline_token: None,
        argv: argv
            .iter()
            .map(|arg| memcordon_core::NativeArgument::from_os(std::ffi::OsStr::from_bytes(arg)))
            .collect(),
    };
    let association = artifacts::checksum(&serde_json::to_vec(&report)?);
    let invocation = NativeInvocation {
        format: "memcordon.consumer-readiness.invocation".into(),
        revision: 1,
        arguments: NativeArguments::UnixBytes(argv.clone()),
        executable_sha256: image_sha.clone(),
        environment: environment_path,
        environment_sha256: environment_sha,
        association_sha256: association.clone(),
        budget_tokens: Vec::new(),
        memory_token: None,
        deadline_token: None,
    };
    let invocation_path = persist(
        "controller-invocation.json",
        serde_json::to_vec(&invocation)?,
    );
    let native = json!({"format":"memcordon.consumer-readiness.native","revision":1,"run_id":identity.run_id,"lease_id":null,"target":build.target,
        "executable_sha256":image_sha,"invocation_sha256":association,"execution_invocation_sha256":null,"request_sha256":null,"provider_sha256":null,
        "provider_generation":null,"runtime_manifest_sha256":null,"attempt_id":null,"root_pid":pid,"root_birth":birth,"attempt_nonce":null,"held_processes":[],
        "frontend_status":0,"origin":"component_regression","target_status":null,"authenticated_provider_exchange":false,"relay_complete":true,
        "result_named_identity_verified":true,"result_readback_verified":true,"application_stage":null});
    let native_path = persist("controller-native.json", serde_json::to_vec(&native)?);
    let retirement = json!({"format":"memcordon.consumer-readiness.retirement","revision":1,"run_id":identity.run_id,"attempt_id":null,"root_pid":pid,"root_birth":birth,
        "target_reaped_or_absent":retired["retirement_observed"],"aggregate_empty":retired["same_image_helpers_absent"],"relays_retired":exit["capture_complete"],
        "guardian_retired":false,"native_handles_closed":false,"independently_observed":before["held_before_input_delivery"],"namespace_init_reaped":null,"private_root_closed":null,
        "exports_finalized":null,"final_job_handles_closed":null,"active_processes_zero":null,"outstanding":[],"failed_operations":[]});
    let retirement_path = persist(
        "controller-retirement.json",
        serde_json::to_vec(&retirement)?,
    );
    let mut candidates = Vec::new();
    for scenario in scenarios {
        let key = CaseKey {
            target: build.target.clone(),
            channel: None,
            evidence_class: EvidenceClass::NativeComponentRegression,
            family: if parser && !versions {
                "C-PARSER"
            } else {
                "L-VER-01"
            }
            .into(),
            scenario: (*scenario).into(),
        };
        let input = FixtureInput {
            format: "memcordon.consumer-readiness.input".into(),
            revision: 1,
            run_id: identity.run_id.clone(),
            key: key.clone(),
            challenge_sha256: challenge_sha.clone(),
            binary: Vec::new(),
            target_argv: NativeArguments::UnixBytes(argv.clone()),
            deadline_millis: None,
            memory_bytes: None,
            toolchain_identity: None,
        };
        let input_bytes = serde_json::to_vec(&input)?;
        let input_sha = artifacts::checksum(&input_bytes);
        let input_path = persist(&format!("{scenario}-input.json"), input_bytes);
        let semantic = json!({"format":"memcordon.consumer-readiness.semantic","revision":1,"run_id":identity.run_id,"key":key,"challenge":challenge_path,
            "operations":[],"comparisons":[],"counters":{},"negative_probe":null,"component_test":{"recipe_id":build.recipe_id,"test_name":test,
            "native_exit":0,"tests_executed":1,"tests_failed":0,"tests_ignored":0,"raw_test_output":format!("{prefix}/stdout.bin"),"native_receipt":format!("{prefix}/{receipt}"),
            "native_retirement":format!("{prefix}/native-retirement.json")},"component_actors":null,"windows_capacity":null,"fixture_behavior":null});
        let semantic_path = persist(
            &format!("{scenario}-semantic.json"),
            serde_json::to_vec(&semantic)?,
        );
        let evidence = CaseEvidenceV2 {
            format: "memcordon.consumer-readiness.case".into(),
            revision: 2,
            key: key.clone(),
            run_id: identity.run_id.clone(),
            source_commit: identity.source_commit.clone(),
            source_tree_sha256: identity.source_tree_sha256.clone(),
            lease_id: None,
            fixture: executable.clone(),
            fixture_source: source.path.clone(),
            fixture_sha256: image_sha.clone(),
            fixture_source_sha256: source.sha256.clone(),
            input: input_path,
            input_sha256: input_sha,
            invocation: invocation_path.clone(),
            request: None,
            raw_result: None,
            attempt_observation: None,
            authenticated_terminal: None,
            recovery: None,
            stdout: format!("{prefix}/stdout.bin"),
            stderr: format!("{prefix}/stderr.bin"),
            outputs: Vec::new(),
            native_observation: native_path.clone(),
            retirement: retirement_path.clone(),
            semantic_observation: semantic_path,
            component_recipe_id: Some(build.recipe_id.clone()),
        };
        let evidence_path = persist(
            &format!("{scenario}-case.json"),
            serde_json::to_vec(&evidence)?,
        );
        candidates.push((key, evidence, evidence_path, serde_json::to_value(input)?));
    }
    drop(persist);
    let resolve = |path: &str| -> std::result::Result<Vec<u8>, String> {
        if let Some(bytes) = values.get(path) {
            return Ok(bytes.clone());
        }
        if path == executable {
            return Ok(image.clone());
        }
        Err("current component oracle requested undeclared artifact".into())
    };
    let mut records = Vec::new();
    for (key, evidence, path, input) in candidates {
        let verified = memcordon_readiness_verifier::current::linux_components::verify_case(
            &evidence, &input, build, version, &resolve,
        );
        let (state, reason) = match verified {
            Ok(()) => (CaseState::Passed, None),
            Err(error) => (
                CaseState::Failed,
                Some(format!("independent current component oracle: {error}")),
            ),
        };
        records.push(CaseRecord {
            key,
            run_id: identity.run_id.clone(),
            state,
            reason,
            evidence: Some(path),
        });
    }
    let mut captured = Vec::new();
    fs::create_dir_all(destination.join(prefix))?;
    for (path, bytes) in values {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination.join(&path))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        captured.push(Artifact {
            path,
            length: bytes.len() as u64,
            sha256: artifacts::checksum(&bytes),
        });
    }
    Ok((records, captured))
}
