use std::collections::BTreeSet;

use memcordon_ci::fuzz_targets::{FuzzShard, targets};

#[test]
fn retained_probe_and_distribution_seeds_reach_valid_models_and_reject_substitution() {
    let probe_bytes = include_bytes!("../../../fuzz/corpus/windows-provider-probe/observed.json");
    memcordon_core::canonical_json::reject_duplicate_json_keys(probe_bytes).unwrap();
    let probe: memcordon_core::WindowsProviderProbeV1 =
        serde_json::from_slice(probe_bytes).unwrap();
    probe.validate().unwrap();
    let mut foreign = probe.clone();
    foreign.format = "memcordon.retired-qualification".into();
    assert!(foreign.validate().is_err());
    let mut unauthenticated = probe;
    unauthenticated.launcher_authenticated = false;
    assert!(unauthenticated.validate().is_err());

    let distribution_bytes =
        include_bytes!("../../../fuzz/corpus/target-distribution/cli-only.json");
    memcordon_core::canonical_json::reject_duplicate_json_keys(distribution_bytes).unwrap();
    let mut distribution: memcordon_ci::release::distribution::TargetDistribution =
        serde_json::from_slice(distribution_bytes).unwrap();
    distribution.validate().unwrap();
    distribution.units.push("unexpected.service".into());
    assert!(distribution.validate().is_err());
    assert!(
        memcordon_core::canonical_json::reject_duplicate_json_keys(
            br#"{"revision":1,"revision":1}"#,
        )
        .is_err()
    );
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
fn typed_fuzz_cache_write_permission_requires_trusted_branch_events() {
    use memcordon_ci::segment_cache::write_event_for;
    for event in ["push", "workflow_dispatch"] {
        assert!(write_event_for(Some(event), Some("refs/heads/main")));
        for reference in [
            None,
            Some(""),
            Some("refs/tags/release"),
            Some("refs/pull/1/merge"),
        ] {
            assert!(!write_event_for(Some(event), reference));
        }
    }
    for event in [
        None,
        Some(""),
        Some("pull_request"),
        Some("merge_group"),
        Some("schedule"),
    ] {
        assert!(!write_event_for(event, Some("refs/heads/main")));
    }
}

#[test]
fn workflow_requires_complete_static_shards_and_cache_inputs() {
    let workflow = include_str!("../../../.github/workflows/deep-ci.yml");
    let yaml: serde_yaml::Value = serde_yaml::from_str(workflow).unwrap();
    let baseline = yaml["jobs"]["fuzz"].as_mapping().unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let configuration = memcordon_ci::config::policy(&root).unwrap();
    let fixture = tempfile::tempdir().unwrap();
    let canonical_fixture_root = fixture.path().canonicalize().unwrap();
    let fixture_root = canonical_fixture_root.as_path();
    let fixture_home = fixture_root.join("cargo-home");
    std::fs::create_dir(&fixture_home).unwrap();
    for (name, bytes) in [
        ("Cargo.toml", "[workspace]\nmembers = [\"fuzz\"]\n"),
        ("Cargo.lock", "version = 4\n"),
        (
            "fuzz/Cargo.toml",
            "[package]\nname = \"fuzz-inputs\"\nversion = \"0.1.0\"\n",
        ),
        ("fuzz/Cargo.lock", "version = 4\n"),
        ("ci/toolchains.toml", "miri = \"nightly-2026-07-31\"\n"),
        (".cargo/config.toml", "profile.release.opt-level=1\n"),
    ] {
        let path = fixture_root.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }
    let git = memcordon_ci::release::git::Git::new(fixture_root).unwrap();
    git.text(["init", "--quiet"]).unwrap();
    git.text([
        "update-index",
        "--add",
        "--",
        "Cargo.toml",
        "Cargo.lock",
        "fuzz/Cargo.toml",
        "fuzz/Cargo.lock",
        "ci/toolchains.toml",
        ".cargo/config.toml",
    ])
    .unwrap();
    let inputs = memcordon_ci::cache_inputs::local_files(fixture_root, "fuzz").unwrap();
    for input in [
        "Cargo.lock",
        "Cargo.toml",
        "fuzz/Cargo.lock",
        "fuzz/Cargo.toml",
        "ci/toolchains.toml",
        ".cargo/config.toml",
    ] {
        assert!(inputs.contains_key(input), "fuzz cache omitted {input}");
    }
    let key_inputs = memcordon_ci::cache_inputs::KeyInputs {
        family: "compiled-transfer".into(),
        layout_revision: 1,
        compatibility: memcordon_ci::cache_inputs::cargo_configs_with_home(
            fixture_root,
            &fixture_home,
            None,
        )
        .unwrap(),
        content: inputs,
    };
    let initial = memcordon_ci::cache_inputs::keys(&key_inputs).unwrap();
    for input in [
        "Cargo.lock",
        "fuzz/Cargo.lock",
        "Cargo.toml",
        "fuzz/Cargo.toml",
        "ci/toolchains.toml",
        ".cargo/config.toml",
    ] {
        let mut changed = key_inputs.clone();
        changed
            .content
            .insert(input.into(), "changed input digest".into());
        assert_ne!(
            memcordon_ci::cache_inputs::keys(&changed).unwrap(),
            initial,
            "fuzz cache ignored {input}"
        );
    }
    let mut changed = key_inputs.clone();
    changed
        .compatibility
        .insert("profile.release.opt-level".into(), "3".into());
    assert_ne!(memcordon_ci::cache_inputs::keys(&changed).unwrap(), initial);
    let validate = |job: &serde_yaml::Mapping| {
        let mut document = yaml.clone();
        document["jobs"]["fuzz"] = serde_yaml::Value::Mapping(job.clone());
        memcordon_ci::policy::validate_workflow_bytes(
            &root,
            std::path::Path::new(".github/workflows/deep-ci.yml"),
            serde_yaml::to_string(&document).unwrap().as_bytes(),
            &configuration,
        )
    };
    validate(baseline).unwrap();
    let reject = |job: serde_yaml::Mapping| {
        assert_ne!(
            &job, baseline,
            "mutation did not change the validated fuzz job"
        );
        assert!(
            validate(&job).is_err(),
            "accepted changed fuzz job: {job:?}"
        );
    };
    let strategy_key = serde_yaml::Value::String("strategy".into());
    assert_eq!(baseline[&strategy_key]["fail-fast"].as_bool(), Some(false));
    for value in [
        true.into(),
        "${{ github.event_name != 'workflow_dispatch' || inputs.failure-mode != 'collect-all' }}"
            .into(),
        "${{ github.event_name == 'workflow_dispatch' }}".into(),
    ] {
        let mut job = baseline.clone();
        job.get_mut(&strategy_key).unwrap()["fail-fast"] = value;
        reject(job);
    }
    let mut job = baseline.clone();
    job.get_mut(&strategy_key)
        .unwrap()
        .as_mapping_mut()
        .unwrap()
        .remove(serde_yaml::Value::String("fail-fast".into()));
    reject(job);
    for shards in [
        vec!["quarter-one"],
        vec![
            "quarter-one",
            "quarter-one",
            "quarter-three",
            "quarter-four",
        ],
        vec!["quarter-one", "quarter-two", "quarter-three", "other"],
        vec![
            "quarter-one",
            "quarter-two",
            "quarter-three",
            "quarter-four",
            "extra",
        ],
    ] {
        let mut job = baseline.clone();
        job.get_mut(&strategy_key).unwrap()["matrix"]["shard"] =
            serde_yaml::to_value(shards).unwrap();
        reject(job);
    }
    for (name, value) in [
        ("timeout-minutes", serde_yaml::Value::Number(90.into())),
        ("if", serde_yaml::Value::Bool(false)),
        ("continue-on-error", serde_yaml::Value::Bool(true)),
    ] {
        let mut job = baseline.clone();
        job.insert(name.into(), value);
        reject(job);
    }
    let steps_key = serde_yaml::Value::String("steps".into());
    let steps = baseline[&steps_key].as_sequence().unwrap();
    let step_id = |id: &str| {
        steps
            .iter()
            .position(|step| step["id"].as_str() == Some(id))
            .unwrap()
    };
    let source_restore = step_id("shard-fuzz-fetch-request-source-restore");
    let source_save = steps
        .iter()
        .position(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|value| value.starts_with("actions/cache/save@"))
                && step["with"]["key"].as_str()
                    == Some("${{ steps.shard-fuzz-fetch.outputs.source-complete-key }}")
        })
        .unwrap();
    for (index, field, from, to) in [
        (
            step_id("fuzz-two"),
            "if",
            "matrix.shard == 'quarter-two'",
            "matrix.shard == 'quarter-one'",
        ),
        (
            step_id("fuzz-two"),
            "run",
            "ci segment fuzz-execute-quarter-two",
            "ci segment fuzz-execute-quarter-one",
        ),
        (
            source_restore,
            "if",
            "steps.shard-fuzz-fetch-request.outputs.source-restore == 'true'",
            "true",
        ),
        (source_save, "if", "always()", "success()"),
    ] {
        let original = steps[index][field].as_str().unwrap();
        assert!(original.contains(from));
        let mut job = baseline.clone();
        job.get_mut(&steps_key).unwrap().as_sequence_mut().unwrap()[index][field] =
            original.replace(from, to).into();
        reject(job);
    }
    for (field, from, to) in [
        (
            "key",
            "steps.shard-fuzz-fetch-request.outputs.source-key",
            "steps.unowned.outputs.source-key",
        ),
        (
            "path",
            "${{ steps.shard-fuzz-fetch-request.outputs.source-path }}",
            "target/ci",
        ),
    ] {
        let original = steps[source_restore]["with"][field].as_str().unwrap();
        assert!(original.contains(from));
        let mut job = baseline.clone();
        job.get_mut(&steps_key).unwrap().as_sequence_mut().unwrap()[source_restore]["with"]
            [field] = original.replace(from, to).into();
        reject(job);
    }
    for (index, step) in steps.iter().enumerate() {
        let mut job = baseline.clone();
        job.get_mut(&steps_key)
            .unwrap()
            .as_sequence_mut()
            .unwrap()
            .remove(index);
        // The complete authored adapter inventory is now checked before the
        // legacy projection; optional cache failure does not permit drift.
        reject(job);
        if step["run"].as_str().is_none() {
            // Cache transfers and retained diagnostics intentionally remain optional.
            continue;
        }
        let mut job = baseline.clone();
        job.get_mut(&steps_key).unwrap().as_sequence_mut().unwrap()[index]
            .as_mapping_mut()
            .unwrap()
            .insert("continue-on-error".into(), true.into());
        if step["continue-on-error"].as_bool() != Some(true) {
            reject(job);
        }
    }
    let mut job = baseline.clone();
    let driver = steps
        .iter()
        .position(|step| step["id"].as_str() == Some("fuzz-current-probe"))
        .unwrap();
    for index in [driver, step_id("fuzz-setup-extract")] {
        let mut job = baseline.clone();
        job.get_mut(&steps_key)
            .unwrap()
            .as_sequence_mut()
            .unwrap()
            .swap(step_id("shard-workspace-fetch"), index);
        reject(job);
    }
    let mut conditional_fetch = baseline.clone();
    conditional_fetch
        .get_mut(&steps_key)
        .unwrap()
        .as_sequence_mut()
        .unwrap()[step_id("shard-workspace-fetch")]["if"] = "success()".into();
    reject(conditional_fetch);
    job.get_mut(&steps_key)
        .unwrap()
        .as_sequence_mut()
        .unwrap()
        .swap(driver, step_id("fuzz-one"));
    reject(job);
}
