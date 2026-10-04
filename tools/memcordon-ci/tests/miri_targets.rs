use memcordon_ci::miri_targets::{MiriTarget, plan};
use serde_json::{Value, json};

#[test]
fn report_case_batches_are_deterministic_exhaustive_and_preserve_ignored_cases() {
    use memcordon_ci::miri_targets::report_batches;
    let names: Vec<_> = (0..19).map(|index| format!("case_{index:02}")).collect();
    let listing = |names: &[String]| {
        names
            .iter()
            .map(|name| format!("{name}: test\n"))
            .collect::<String>()
    };
    let all = listing(&names);
    let ignored_names = vec![names[2].clone(), names[17].clone()];
    let ignored = listing(&ignored_names);
    let batches = report_batches(all.as_bytes(), ignored.as_bytes()).unwrap();
    assert_eq!(batches.len(), 3);
    assert_eq!(
        batches
            .iter()
            .map(|batch| batch.selected.len())
            .collect::<Vec<_>>(),
        [8, 8, 3]
    );
    assert_eq!(
        batches
            .iter()
            .flat_map(|batch| batch.selected.clone())
            .collect::<Vec<_>>(),
        names
    );
    assert_eq!(
        batches
            .iter()
            .flat_map(|batch| batch.ignored.clone())
            .collect::<Vec<_>>(),
        ignored_names
    );
    for batch in &batches {
        let arguments = batch.arguments();
        assert_eq!(arguments.first().unwrap(), "--exact");
        assert!(
            !arguments
                .iter()
                .any(|argument| matches!(argument.as_str(), "--include-ignored" | "--ignored"))
        );
        for name in &names {
            assert_ne!(batch.selected.contains(name), batch.excluded.contains(name));
        }
        assert_eq!(
            arguments[1..]
                .chunks_exact(2)
                .map(|pair| {
                    assert_eq!(pair[0], "--skip");
                    pair[1].clone()
                })
                .collect::<Vec<_>>(),
            batch.excluded
        );
    }
    let mut reversed = names;
    reversed.reverse();
    assert_eq!(
        report_batches(listing(&reversed).as_bytes(), ignored.as_bytes()).unwrap(),
        batches
    );
}

#[test]
fn malformed_case_inventory_cannot_silently_drop_miri_coverage() {
    use memcordon_ci::miri_targets::report_batches;
    for all in [
        "",
        "a: test\na: test\n",
        "a: bench\n",
        "bad name: test\n",
        "a: test\nunknown row\n",
    ] {
        assert!(report_batches(all.as_bytes(), b"").is_err());
    }
    assert!(report_batches(b"a: test\n", b"foreign: test\n").is_err());
    assert!(report_batches(b"a: test\n", b"a: test\n").is_err());
    assert!(report_batches(&[b'x'; 64 * 1024 + 1], b"").is_err());
    assert!(report_batches(b"\xff: test\n", b"").is_err());
}

#[test]
fn complete_harness_shards_are_disjoint_and_preserve_authoritative_plan() {
    use memcordon_ci::miri_targets::{MiriShard, plan_shard};
    let data = metadata(
        json!({}),
        vec![
            target("core", "lib", true, true, &[]),
            target("integration", "test", true, false, &[]),
            target("example", "example", true, false, &[]),
            target("bench", "bench", true, false, &[]),
            target("binary", "bin", true, false, &[]),
        ],
    );
    let first = plan_shard(&data, "core", MiriShard::First).unwrap();
    let second = plan_shard(&data, "core", MiriShard::Second).unwrap();
    assert!(first.iter().all(|target| !second.contains(target)));
    let mut joined = first;
    joined.extend(second);
    joined.sort();
    assert_eq!(joined, plan(&data, "core").unwrap());
    let single = metadata(json!({}), vec![target("core", "lib", true, false, &[])]);
    assert!(plan_shard(&single, "core", MiriShard::Second).is_err());
}

fn target(name: &str, kind: &str, test: bool, doctest: bool, required: &[&str]) -> Value {
    json!({"name":name,"kind":[kind],"test":test,"doctest":doctest,"required-features":required})
}

fn metadata(features: Value, targets: Vec<Value>) -> Vec<u8> {
    serde_json::to_vec(&json!({"packages":[{"name":"core","features":features,"targets":targets}]}))
        .unwrap()
}

#[test]
fn preserves_library_integration_docs_and_default_feature_selection() {
    let data = metadata(
        json!({"test-support":[]}),
        vec![
            target("core", "lib", true, true, &[]),
            target("diagnostics", "test", true, false, &[]),
            target("restart", "test", true, false, &["test-support"]),
        ],
    );
    assert_eq!(
        plan(&data, "core").unwrap(),
        vec![
            MiriTarget::Library,
            MiriTarget::Integration("diagnostics".into()),
            MiriTarget::Documentation,
        ]
    );
    assert_eq!(MiriTarget::Library.arguments(), ["--lib"]);
    assert_eq!(
        MiriTarget::Integration("diagnostics".into()).arguments(),
        ["--test", "diagnostics"]
    );
    assert_eq!(MiriTarget::Documentation.arguments(), ["--doc"]);
}

#[test]
fn discovers_new_targets_and_expands_only_local_default_features() {
    let data = metadata(
        json!({
        "default":["suite","dep:optional"],
            "suite":["enabled"],"enabled":["suite"],"extra":[],"optional":[],
        }),
        vec![
            target("new_safety_regression", "test", true, false, &[]),
            target("default_enabled", "test", true, false, &["enabled"]),
            target(
                "dependency_feature_is_not_local",
                "test",
                true,
                false,
                &["extra"],
            ),
            target(
                "explicit_dependency_is_not_local",
                "test",
                true,
                false,
                &["optional"],
            ),
        ],
    );
    assert_eq!(
        plan(&data, "core").unwrap(),
        vec![
            MiriTarget::Integration("default_enabled".into()),
            MiriTarget::Integration("new_safety_regression".into()),
        ]
    );
    for forwarding in ["optional/extra", "optional?/extra"] {
        let unsupported = metadata(
            json!({"default":[forwarding], "optional":["dep:optional"]}),
            vec![target("gated", "test", true, false, &["optional"])],
        );
        assert!(plan(&unsupported, "core").is_err());
    }
}

#[test]
fn supports_explicit_testable_kinds_and_rejects_unrepresented_coverage() {
    let data = metadata(
        json!({}),
        vec![
            target("tool", "bin", true, false, &[]),
            target("sample", "example", true, false, &[]),
            target("measurement", "bench", true, false, &[]),
        ],
    );
    assert_eq!(
        plan(&data, "core").unwrap(),
        vec![
            MiriTarget::Binary("tool".into()),
            MiriTarget::Example("sample".into()),
            MiriTarget::Bench("measurement".into()),
        ]
    );
    for unsupported in [
        target("compile_only_example", "example", false, false, &[]),
        target("unknown", "future-kind", true, false, &[]),
        target("non_library_docs", "test", true, true, &[]),
    ] {
        assert!(plan(&metadata(json!({}), vec![unsupported]), "core").is_err());
    }
    assert!(plan(&metadata(json!({}), vec![]), "core").is_err());
    assert!(plan(&data, "missing").is_err());
    assert!(
        plan(
            &metadata(
                json!({}),
                vec![
                    target("same", "test", true, false, &[]),
                    target("same", "test", true, false, &[])
                ]
            ),
            "core"
        )
        .is_err()
    );
}
