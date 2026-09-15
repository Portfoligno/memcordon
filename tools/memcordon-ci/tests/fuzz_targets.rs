use std::collections::BTreeSet;

use memcordon_ci::fuzz_targets::{FuzzShard, targets};

#[test]
fn realistic_seed_records_fit_their_declared_input_classes() {
    use memcordon_ci::fuzz_targets::{CharterRegistry, prepare_corpus};
    use memcordon_core::sealed_provider::{envelope, terminal};
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let registry = CharterRegistry::load(root).unwrap();
    for charter in &registry.targets {
        for entry in std::fs::read_dir(root.join(&charter.seed_directory)).unwrap() {
            let bytes = std::fs::read(entry.unwrap().path()).unwrap();
            assert!(
                bytes.len() <= charter.max_input_bytes,
                "{} seed exceeds input class",
                charter.id
            );
        }
    }
    let seed = |bin: &str| {
        std::fs::read(root.join("fuzz/seeds").join(bin).join("reviewed-input")).unwrap()
    };
    envelope::parse_proc_status(std::str::from_utf8(&seed("caller-envelope-status")).unwrap())
        .unwrap();
    let mask = seed("capability-mask");
    envelope::parse_capability_mask(
        std::str::from_utf8(&mask)
            .unwrap()
            .strip_suffix('\n')
            .unwrap(),
    )
    .unwrap();
    let identity = seed("namespace-identity");
    envelope::parse_namespace_identity(
        std::str::from_utf8(&identity)
            .unwrap()
            .strip_suffix('\n')
            .unwrap(),
        "pid",
    )
    .unwrap();
    terminal::parse_terminal(&seed("terminal-receipt-v2")).unwrap();
    let streams: Vec<memcordon_core::WindowsRemoteStreamV1> =
        serde_json::from_slice(&seed("windows-handle-manifest")).unwrap();
    memcordon_core::validate_windows_stream_manifest(&streams).unwrap();
    let policy = memcordon_ci::config::parse_policy(&seed("policy_parser")).unwrap();
    memcordon_ci::policy::validate_workflow_bytes(
        root,
        std::path::Path::new(".github/workflows/ci.yml"),
        &seed("workflow_parser"),
        &policy,
    )
    .unwrap();
    for bin in ["policy_parser", "workflow_parser"] {
        let charter = registry
            .targets
            .iter()
            .find(|entry| entry.bin == bin)
            .unwrap();
        assert_eq!(charter.max_length_argument().unwrap(), "-max_len=65536");
        assert!(seed(bin).len() > 4096);
    }
    let temp = tempfile::tempdir().unwrap();
    let destination = temp.path().canonicalize().unwrap();
    let charter = &registry.targets[0];
    std::fs::create_dir_all(destination.join(&charter.seed_directory)).unwrap();
    assert!(
        prepare_corpus(&destination, charter).is_err(),
        "empty seed tree must fail"
    );
}

#[test]
fn restored_corpus_inputs_are_included_in_target_evidence() {
    use memcordon_ci::fuzz_targets::{CharterRegistry, prepare_corpus};
    let registry = CharterRegistry::parse(
        include_str!("../../../fuzz/Cargo.toml"),
        include_str!("../../../fuzz/targets.toml"),
    )
    .unwrap();
    let charter = &registry.targets[0];
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let seeds = root.join(&charter.seed_directory);
    std::fs::create_dir_all(&seeds).unwrap();
    std::fs::write(seeds.join("seed"), b"seed\n").unwrap();
    let restored = charter.corpus_directory(&root);
    std::fs::create_dir_all(&restored).unwrap();
    std::fs::write(restored.join("historical-fuzzer-name"), b"restored\n").unwrap();
    let corpus = prepare_corpus(&root, charter).unwrap();
    assert_eq!(corpus.len(), 2);
    assert!(
        corpus
            .iter()
            .any(|entry| entry.bytes == b"restored\n".len())
    );
    assert!(restored.join("historical-fuzzer-name").is_file());
}

#[test]
fn source_inclusion_cannot_claim_direct_production_import() {
    use memcordon_ci::fuzz_targets::{CharterRegistry, validate};
    let baseline = CharterRegistry::parse(
        include_str!("../../../fuzz/Cargo.toml"),
        include_str!("../../../fuzz/targets.toml"),
    )
    .unwrap();
    let mut registry = CharterRegistry {
        schema: 1,
        targets: vec![baseline.targets[0].clone()],
    };
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::create_dir_all(root.join("fuzz/fuzz_targets")).unwrap();
    std::fs::create_dir_all(root.join(&registry.targets[0].seed_directory)).unwrap();
    std::fs::write(
        root.join(&registry.targets[0].seed_directory).join("seed"),
        b"{}\n",
    )
    .unwrap();
    let manifest = format!(
        "[[bin]]\nname = {:?}\npath = \"fuzz_targets/synthetic.rs\"\n",
        registry.targets[0].bin
    );
    std::fs::write(root.join("fuzz/Cargo.toml"), manifest).unwrap();
    std::fs::write(
        root.join("fuzz/targets.toml"),
        toml::to_string(&registry).unwrap(),
    )
    .unwrap();
    std::fs::write(
        root.join("fuzz/fuzz_targets/synthetic.rs"),
        "fn main() {}\n",
    )
    .unwrap();
    validate(&root).unwrap();
    for source in [
        "#[path = \"../private_binary.rs\"] mod borrowed;\n",
        "#[cfg_attr(unix, path = \"../private_binary.rs\")] mod borrowed;\n",
        "#[cfg_attr(unix, cfg_attr(feature = \"alternate\", path = \"../private_binary.rs\"))] mod borrowed;\n",
        "include!(\"../private_binary.rs\");\n",
    ] {
        std::fs::write(root.join("fuzz/fuzz_targets/synthetic.rs"), source).unwrap();
        assert!(
            validate(&root).is_err(),
            "unreported shared source: {source}"
        );
    }
    registry.targets[0].import_mode = "shared-source".into();
    registry.targets[0].parity_required = true;
    std::fs::write(
        root.join("fuzz/targets.toml"),
        toml::to_string(&registry).unwrap(),
    )
    .unwrap();
    validate(&root).unwrap(); // Declaration parity only; source-registry authorization is separate.
}

#[test]
fn charters_cover_bins_and_keep_shards_stable_across_renames_and_additions() {
    use memcordon_ci::fuzz_targets::CharterRegistry;
    let manifest = include_str!("../../../fuzz/Cargo.toml");
    let source = include_str!("../../../fuzz/targets.toml");
    let baseline = CharterRegistry::parse(manifest, source).unwrap();
    let first = baseline
        .selected(Some(FuzzShard::First), "linux-x64")
        .unwrap();
    let second = baseline
        .selected(Some(FuzzShard::Second), "linux-x64")
        .unwrap();
    assert_eq!(first.len() + second.len(), baseline.targets.len());
    assert!(
        first
            .iter()
            .all(|entry| !second.iter().any(|other| entry.id == other.id))
    );
    let mut changed = baseline.clone();
    let old = changed.targets[0].bin.clone();
    changed.targets[0].bin = "future_renamed_target".into();
    changed.targets[0].aliases.push(old.clone());
    let manifest = manifest.replace(&format!("name = {old:?}"), "name = 'future_renamed_target'");
    let reloaded = CharterRegistry::parse(&manifest, &toml::to_string(&changed).unwrap()).unwrap();
    assert_eq!(baseline.targets[0].shard, reloaded.targets[0].shard);
    assert_eq!(baseline.targets[0].id, reloaded.targets[0].id);
    let mut new = changed.targets[0].clone();
    new.id = "fuzz-1001".into();
    new.bin = "additional_future_target".into();
    new.shard = FuzzShard::First;
    new.aliases.clear();
    changed.targets.push(new);
    let manifest = format!(
        "{manifest}\n[[bin]]\nname='additional_future_target'\npath='fuzz_targets/additional_future_target.rs'\n"
    );
    let reloaded = CharterRegistry::parse(&manifest, &toml::to_string(&changed).unwrap()).unwrap();
    for original in baseline.targets {
        let updated = reloaded
            .targets
            .iter()
            .find(|entry| entry.id == original.id)
            .unwrap();
        assert_eq!(updated.shard, original.shard);
    }
}

#[test]
fn charters_reject_unowned_ambiguous_or_weakened_coverage() {
    use memcordon_ci::fuzz_targets::CharterRegistry;
    let manifest = include_str!("../../../fuzz/Cargo.toml");
    let source = include_str!("../../../fuzz/targets.toml");
    let baseline = CharterRegistry::parse(manifest, source).unwrap();
    for mutation in 0..12 {
        let mut changed = baseline.clone();
        match mutation {
            0 => {
                changed.targets.pop();
            }
            1 => changed.targets.push(changed.targets[0].clone()),
            2 => changed.targets[0].id = "fuzz-01".into(),
            3 => changed.targets[0].shard = FuzzShard::Second,
            4 => changed.targets[0].invariants = vec!["no-panic".into()],
            5 => changed.targets[0].corpus_owner.clear(),
            6 => {
                let active = changed.targets[1].bin.clone();
                changed.targets[0].aliases.push(active);
            }
            7 => changed.targets[0].seed_directory = "fuzz/seeds/../../outside".into(),
            8 => changed.targets[0].max_input_bytes = usize::MAX,
            9 => changed.targets[0].artifact_retention_days = 1,
            10 => changed.targets[0].hosts.clear(),
            11 => changed.targets[0].production_unit.clear(),
            _ => unreachable!(),
        }
        assert!(
            CharterRegistry::parse(manifest, &toml::to_string(&changed).unwrap()).is_err(),
            "mutation {mutation}"
        );
    }
    assert!(CharterRegistry::parse(manifest, &format!("unknown=true\n{source}")).is_err());
    assert!(baseline.selected(None, "windows-x64").is_err());
    memcordon_ci::fuzz_targets::validate(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap(),
    )
    .unwrap();
}

#[test]
fn alias_corpus_merge_preserves_sources_and_deduplicates_exact_bytes() {
    use memcordon_ci::fuzz_targets::merge_corpora;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let first = root.join("canonical");
    let second = root.join("historical-alias");
    let output = root.join("stable-id");
    std::fs::create_dir(&first).unwrap();
    std::fs::create_dir(&second).unwrap();
    std::fs::write(first.join("seed"), b"same\n").unwrap();
    std::fs::write(second.join("old-crash"), b"same\n").unwrap();
    std::fs::write(second.join("minimized"), b"different\n").unwrap();
    let entries = merge_corpora(&[first.clone(), second.clone()], &output, 4096).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(std::fs::read(second.join("old-crash")).unwrap(), b"same\n");
    assert_eq!(std::fs::read_dir(&output).unwrap().count(), 2);
    for entry in &entries {
        assert_eq!(
            std::fs::metadata(output.join(&entry.sha256)).unwrap().len(),
            entry.bytes as u64
        );
    }
    std::fs::write(output.join(&entries[0].sha256), b"poisoned").unwrap();
    assert!(merge_corpora(&[first, second], &output, 4096).is_err());
}

#[cfg(unix)]
#[test]
fn corpus_merge_rejects_symlink_escape_and_oversized_inputs() {
    use memcordon_ci::fuzz_targets::merge_corpora;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let source = root.join("source");
    std::fs::create_dir(&source).unwrap();
    let external = root.join("external");
    std::fs::write(&external, b"secret").unwrap();
    std::os::unix::fs::symlink(&external, source.join("escape")).unwrap();
    assert!(merge_corpora(&[source], &root.join("destination"), 4096).is_err());
    assert!(merge_corpora(std::slice::from_ref(&external), &root.join("bounded"), 1).is_err());
    std::os::unix::fs::symlink(root.join("bounded"), root.join("redirect")).unwrap();
    assert!(merge_corpora(&[external], &root.join("redirect/child"), 4096).is_err());
}

#[test]
fn target_reports_and_artifacts_use_stable_identity_and_preserve_failed_evidence() {
    use memcordon_ci::fuzz_targets::{
        CharterRegistry, TargetEvidence, preserve_artifacts, write_evidence,
    };
    let registry = CharterRegistry::parse(
        include_str!("../../../fuzz/Cargo.toml"),
        include_str!("../../../fuzz/targets.toml"),
    )
    .unwrap();
    let charter = &registry.targets[0];
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let legacy = root.join("fuzz/artifacts").join(&charter.bin);
    std::fs::create_dir_all(&legacy).unwrap();
    std::fs::write(legacy.join("crash-historical-name"), b"crash\n").unwrap();
    let artifacts = preserve_artifacts(&root, charter).unwrap();
    assert_eq!(artifacts.len(), 1);
    assert_eq!(
        std::fs::read(charter.artifact_directory(&root).join(&artifacts[0].sha256)).unwrap(),
        b"crash\n"
    );
    assert!(legacy.join("crash-historical-name").is_file());
    write_evidence(
        &root,
        &TargetEvidence {
            schema: 1,
            charter,
            phase: "failed",
            corpus: &[],
            artifacts: &artifacts,
            failure: Some("fixture failure".into()),
        },
    )
    .unwrap();
    let report: serde_json::Value = serde_json::from_slice(
        &std::fs::read(charter.artifact_directory(&root).join("evidence.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(report["charter"]["id"], charter.id);
    assert_eq!(report["phase"], "failed");
    assert_eq!(report["artifacts"][0]["sha256"], artifacts[0].sha256);
    assert_eq!(report["failure"], "fixture failure");
    let oversized = legacy.join("oversized-original-crash");
    std::fs::write(&oversized, vec![b'x'; charter.max_input_bytes + 1]).unwrap();
    assert!(
        memcordon_ci::fuzz_targets::finish_target(
            &root,
            charter,
            &[],
            Err(memcordon_ci::CiError::Message(
                "original command failed".into()
            ))
        )
        .is_err()
    );
    assert!(
        oversized.is_file(),
        "preservation failure must retain original crash"
    );
    let report: serde_json::Value = serde_json::from_slice(
        &std::fs::read(charter.artifact_directory(&root).join("evidence.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(report["phase"], "artifact-preservation-failed");
    let failure = report["failure"].as_str().unwrap();
    assert!(failure.contains("original command failed"));
    assert!(failure.contains("artifact preservation"));
}

#[test]
fn shards_cover_current_and_future_manifest_targets_exactly_once() {
    let manifest = include_str!("../../../fuzz/Cargo.toml");
    for manifest in [
        manifest.to_owned(),
        format!(
            "{manifest}\n[[bin]]\nname = 'future_target'\npath = 'fuzz_targets/future_target.rs'\n"
        ),
    ] {
        let all = targets(&manifest, None).unwrap();
        let first = targets(&manifest, Some(FuzzShard::First)).unwrap();
        let second = targets(&manifest, Some(FuzzShard::Second)).unwrap();
        let first: BTreeSet<_> = first.into_iter().collect();
        let second: BTreeSet<_> = second.into_iter().collect();
        assert!(first.is_disjoint(&second));
        assert_eq!(first.union(&second).cloned().collect::<Vec<_>>(), all);
        assert!(first.len().abs_diff(second.len()) <= 1);
        assert_ne!(first.contains("report_json"), first.contains("schema_four"));
    }
    assert_eq!(targets(manifest, None).unwrap().len(), 52);
}

#[test]
fn malformed_or_empty_inventory_cannot_silently_lose_coverage() {
    for manifest in [
        "",
        "bin = []",
        "[[bin]]\npath='x'",
        "[[bin]]\nname=''",
        "[[bin]]\nname='a b'",
        "[[bin]]\nname='same'\n[[bin]]\nname='same'",
        "bin = [7]",
    ] {
        assert!(targets(manifest, None).is_err(), "{manifest}");
    }
    assert!(targets("[[bin]]\nname='only'", Some(FuzzShard::Second)).is_err());
}

#[test]
fn workflow_requires_complete_static_shards_and_cache_inputs() {
    let workflow = include_str!("../../../.github/workflows/deep-ci.yml");
    let validate = |source: &str| {
        let mut yaml: serde_yaml::Value = serde_yaml::from_str(source).unwrap();
        memcordon_ci::managed_workflow::validate_and_project(&mut yaml)?;
        memcordon_ci::policy::check_fuzz_shards(yaml["jobs"]["fuzz"].as_mapping().unwrap())
    };
    validate(workflow).unwrap();
    for (from, to) in [
        ("shard: [first, second]", "shard: [first]"),
        ("shard: [first, second]", "shard: [first, first]"),
        ("matrix.shard == 'second'", "matrix.shard == 'first'"),
        ("suite fuzz-second", "suite fuzz-first"),
        ("fail-fast: false", "fail-fast: true"),
        ("${{ matrix.shard }}-nightly", "nightly"),
        ("'Cargo.toml', 'Cargo.lock', '.cargo/**'", "'Cargo.lock'"),
        (
            "always() && steps.fuzz-target",
            "success() && steps.fuzz-target",
        ),
    ] {
        assert!(workflow.contains(from));
        assert!(
            validate(&workflow.replace(from, to)).is_err(),
            "accepted {to}"
        );
    }
    let mut yaml: serde_yaml::Value = serde_yaml::from_str(workflow).unwrap();
    memcordon_ci::managed_workflow::validate_and_project(&mut yaml).unwrap();
    let baseline = yaml["jobs"]["fuzz"].as_mapping().unwrap();
    for (name, value) in [
        ("timeout-minutes", serde_yaml::Value::Number(90.into())),
        ("if", serde_yaml::Value::Bool(false)),
        ("continue-on-error", serde_yaml::Value::Bool(true)),
    ] {
        let mut job = baseline.clone();
        job.insert(name.into(), value);
        assert!(memcordon_ci::policy::check_fuzz_shards(&job).is_err());
    }
    let steps_key = serde_yaml::Value::String("steps".into());
    let count = baseline[&steps_key].as_sequence().unwrap().len();
    for index in 0..count {
        let mut job = baseline.clone();
        job[&steps_key].as_sequence_mut().unwrap().remove(index);
        assert!(memcordon_ci::policy::check_fuzz_shards(&job).is_err());
        let mut job = baseline.clone();
        job[&steps_key].as_sequence_mut().unwrap()[index]
            .as_mapping_mut()
            .unwrap()
            .insert("continue-on-error".into(), true.into());
        assert!(memcordon_ci::policy::check_fuzz_shards(&job).is_err());
    }
    let mut job = baseline.clone();
    job[&steps_key].as_sequence_mut().unwrap().swap(5, 7);
    assert!(memcordon_ci::policy::check_fuzz_shards(&job).is_err());
}
