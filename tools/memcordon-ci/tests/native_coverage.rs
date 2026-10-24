use memcordon_ci::{native_coverage::*, release::source::BuildSourceIdentity};
use serde_json::json;
use std::collections::BTreeMap;

fn profile(test: bool) -> serde_json::Value {
    json!({"debug_assertions":false,"debuginfo":0,"opt_level":"3","overflow_checks":false,"test":test})
}
fn target(package: &str, name: &str, kind: TargetKind, source: &str) -> TargetSpec {
    TargetSpec {
        package: package.into(),
        name: name.into(),
        kind,
        source: source.into(),
        required_features: vec!["enabled".into()],
        harness: true,
        test: true,
        expected_profile: profile(true),
    }
}
fn spec() -> WorkspaceSpec {
    let mut targets = Vec::new();
    // These are canonical plan members, independent of native filesystem separators.
    for (package, manifest, library, binary_source, duplicate_source) in [
        (
            "one",
            "one/Cargo.toml",
            "one/src/lib.rs",
            "one/src/main.rs",
            "one/tests/duplicate.rs",
        ),
        (
            "two",
            "two/Cargo.toml",
            "two/src/lib.rs",
            "two/src/main.rs",
            "two/tests/duplicate.rs",
        ),
    ] {
        targets.push(target(manifest, package, TargetKind::Lib, library));
        let mut binary = target(manifest, package, TargetKind::Bin, binary_source);
        binary.test = false;
        targets.push(binary);
        targets.push(target(
            manifest,
            "duplicate",
            TargetKind::Test,
            duplicate_source,
        ));
    }
    let mut custom = target(
        "one/Cargo.toml",
        "custom",
        TargetKind::Test,
        "one/tests/custom.rs",
    );
    custom.harness = false;
    targets.push(custom);
    let mut example = target(
        "one/Cargo.toml",
        "sample",
        TargetKind::Example,
        "one/examples/sample.rs",
    );
    example.test = false;
    targets.push(example);
    WorkspaceSpec {
        identity: CoverageIdentity {
            source: BuildSourceIdentity::Working {
                version: "0.5.8-dev".parse().unwrap(),
                commit: "a".repeat(40),
            },
            source_tree_sha256: "b".repeat(64),
            lock_sha256: "c".repeat(64),
            configuration_sha256: "d".repeat(64),
            toolchain: "1.97.1".into(),
            cargo_version: "cargo 1.97.1".into(),
            rustc_verbose_sha256: "e".repeat(64),
            host: "x86_64-apple-darwin".into(),
            target: "x86_64-apple-darwin".into(),
            profile: "release".into(),
            all_features: true,
        },
        packages: vec!["one/Cargo.toml".into(), "two/Cargo.toml".into()],
        package_features: BTreeMap::from([
            ("one/Cargo.toml".into(), vec!["enabled".into()]),
            ("two/Cargo.toml".into(), vec!["enabled".into()]),
        ]),
        targets,
    }
}
fn raw_kind(kind: TargetKind) -> &'static str {
    match kind {
        TargetKind::Lib => "lib",
        TargetKind::ProcMacro => "proc-macro",
        TargetKind::Bin => "bin",
        TargetKind::Test => "test",
        TargetKind::Bench => "bench",
        TargetKind::Example => "example",
        TargetKind::CustomBuild => "custom-build",
    }
}
fn observation(plan: &Plan, requirement: &Requirement) -> UnitObservation {
    let mut selected = requirement.target.expected_profile.clone();
    selected["test"] = json!(requirement.variant == Variant::Test);
    UnitObservation {
        package: requirement.target.package.clone(),
        target_name: requirement.target.name.clone(),
        target_kind: requirement.target.kind,
        source: requirement.target.source.clone(),
        raw_target: json!({"name":requirement.target.name,"src_path":requirement.target.source,"kind":[raw_kind(requirement.target.kind)]}),
        profile: selected,
        features: plan.spec.package_features[&requirement.target.package].clone(),
        executable: Some(ExecutableRecord {
            length: 10,
            sha256: "f".repeat(64),
        }),
    }
}
fn receipts(plan: &Plan) -> Vec<ShardReceipt> {
    plan.shards
        .iter()
        .map(|shard| {
            let units: Vec<_> = shard
                .groups
                .iter()
                .flat_map(|group| plan.groups[*group].requirements.iter())
                .map(|id| {
                    observation(
                        plan,
                        plan.requirements
                            .iter()
                            .find(|requirement| &requirement.id == id)
                            .unwrap(),
                    )
                })
                .collect();
            let phase = PhaseReceipt {
                selection_sha256: plan.selection_sha256(shard.id).unwrap(),
                success: true,
                writers_settled: true,
                completed_before_deadline: true,
            };
            ShardReceipt {
                schema_version: 1,
                identity: plan.spec.identity.clone(),
                plan_sha256: plan.sha256.clone(),
                shard_id: shard.id,
                compile: phase.clone(),
                execute: phase,
                compiled_units: units.clone(),
                executed_units: units,
            }
        })
        .collect()
}

#[test]
fn canonical_groups_preserve_global_names_custom_harness_and_ordinary_support() {
    let plan = Plan::build(spec(), 4).unwrap();
    plan.validate().unwrap();
    let duplicate = plan
        .groups
        .iter()
        .find(|group| group.selector == Selector::Test("duplicate".into()))
        .unwrap();
    assert_eq!(
        duplicate
            .requirements
            .iter()
            .filter(|id| plan
                .requirements
                .iter()
                .any(|item| &item.id == *id && item.variant == Variant::Test))
            .count(),
        2
    );
    assert_eq!(
        plan.groups
            .iter()
            .filter(|group| group.selector == Selector::Lib)
            .count(),
        1
    );
    assert_eq!(
        plan.requirements
            .iter()
            .filter(|requirement| requirement.variant == Variant::OrdinaryBinarySupport)
            .count(),
        2
    );
    for group in &plan.groups {
        for id in &group.requirements {
            if plan.requirements.iter().any(|requirement| {
                &requirement.id == id && requirement.variant == Variant::OrdinaryBinarySupport
            }) {
                assert!(matches!(group.selector, Selector::Bin(_)));
            }
        }
    }
    assert!(
        plan.requirements
            .iter()
            .any(|requirement| !requirement.target.harness && requirement.execution_required)
    );
    assert!(
        plan.requirements
            .iter()
            .any(|requirement| requirement.target.kind == TargetKind::Example
                && !requirement.execution_required)
    );
    for shard in &plan.shards {
        let arguments = plan.selectors(shard.id).unwrap();
        for flag in ["--workspace", "--all-features", "--locked", "--release"] {
            assert!(arguments.iter().any(|arg| arg == flag));
        }
        assert!(
            !arguments
                .iter()
                .any(|arg| arg == "--all-targets" || arg == "-p")
        );
    }
    let mut reordered = spec();
    reordered.targets.reverse();
    reordered.packages.reverse();
    assert_eq!(plan, Plan::build(reordered, 4).unwrap());
    let actual = receipts(&plan);
    for receipt in &actual {
        plan.validate_receipt(receipt).unwrap();
    }
    let aggregate = plan.aggregate(&actual).unwrap();
    assert_eq!(
        aggregate.covered_requirements.len(),
        plan.requirements.len()
    );
}

#[test]
fn missing_stale_failed_unsettled_or_divergent_receipts_never_certify_union() {
    let plan = Plan::build(spec(), 3).unwrap();
    let original = receipts(&plan);
    assert!(plan.aggregate(&original[..original.len() - 1]).is_err());
    for mutation in [
        "duplicate-owner",
        "source",
        "plan",
        "selection",
        "compile",
        "execute",
        "writer",
        "deadline",
        "unit",
        "executable",
        "profile",
        "features",
        "raw-kind",
        "execution-inventory",
    ] {
        let mut changed = original.clone();
        match mutation {
            "duplicate-owner" => changed[1] = changed[0].clone(),
            "source" => changed[0].identity.source_tree_sha256 = "0".repeat(64),
            "plan" => changed[0].plan_sha256 = "0".repeat(64),
            "selection" => changed[0].execute.selection_sha256 = "0".repeat(64),
            "compile" => changed[0].compile.success = false,
            "execute" => changed[0].execute.success = false,
            "writer" => changed[0].execute.writers_settled = false,
            "deadline" => changed[0].compile.completed_before_deadline = false,
            "unit" => {
                changed[0].compiled_units.remove(0);
                changed[0].executed_units = changed[0].compiled_units.clone();
            }
            "executable" => {
                changed[0].compiled_units[0].executable = None;
                changed[0].executed_units = changed[0].compiled_units.clone();
            }
            "profile" => {
                changed[0].compiled_units[0].profile["opt_level"] = json!("0");
                changed[0].executed_units = changed[0].compiled_units.clone();
            }
            "features" => {
                changed[0].compiled_units[0].features.clear();
                changed[0].executed_units = changed[0].compiled_units.clone();
            }
            "raw-kind" => {
                changed[0].compiled_units[0].raw_target["kind"] = json!(["custom-build"]);
                changed[0].executed_units = changed[0].compiled_units.clone();
            }
            "execution-inventory" => {
                changed[0].executed_units[0]
                    .executable
                    .as_mut()
                    .unwrap()
                    .sha256 = "0".repeat(64)
            }
            _ => unreachable!(),
        }
        assert!(plan.aggregate(&changed).is_err(), "{mutation}");
    }
    let mut extra = original.clone();
    let foreign = extra[1]
        .compiled_units
        .iter()
        .find(|unit| unit.profile["test"] == true)
        .unwrap()
        .clone();
    extra[0].compiled_units.push(foreign.clone());
    extra[0].executed_units.push(foreign);
    assert!(
        plan.aggregate(&extra)
            .unwrap_err()
            .contains("another shard")
    );
}

#[test]
fn dependencies_keep_distinct_feature_variants_but_source_plan_mutations_fail() {
    let plan = Plan::build(spec(), 1).unwrap();
    let mut actual = receipts(&plan);
    for feature in ["build", "dev"] {
        let unit = UnitObservation {
            package: "registry+shared@1.0".into(),
            target_name: "shared".into(),
            target_kind: TargetKind::Lib,
            source: "src/lib.rs".into(),
            raw_target: json!({"name":"shared","kind":["lib"],"src_path":"src/lib.rs"}),
            profile: profile(false),
            features: vec![feature.into()],
            executable: None,
        };
        actual[0].compiled_units.push(unit.clone());
        actual[0].executed_units.push(unit);
    }
    plan.aggregate(&actual).unwrap();
    for mutation in [
        "target-source",
        "missing-package",
        "required-feature",
        "unsupported-bench",
        "unsupported-proc-macro",
        "duplicate-target",
        "duplicate-bin-output",
        "case-alias-bin-output",
        "unicode-bin-output",
        "disabled-library-test",
        "profile",
        "cargo-version",
    ] {
        let mut changed = spec();
        match mutation {
            "target-source" => changed.targets[0].source = "../outside.rs".into(),
            "missing-package" => {
                changed.package_features.remove("one/Cargo.toml");
            }
            "required-feature" => changed.targets[0].required_features.push("absent".into()),
            "unsupported-bench" => changed.targets[0].kind = TargetKind::Bench,
            "unsupported-proc-macro" => changed.targets[0].kind = TargetKind::ProcMacro,
            "duplicate-target" => changed.targets.push(changed.targets[0].clone()),
            "unicode-bin-output" => {
                changed
                    .targets
                    .iter_mut()
                    .find(|target| target.kind == TargetKind::Bin)
                    .unwrap()
                    .name = "caf\u{e9}".into();
            }
            "disabled-library-test" => {
                changed
                    .targets
                    .iter_mut()
                    .find(|target| target.kind == TargetKind::Lib)
                    .unwrap()
                    .test = false;
            }
            "duplicate-bin-output" | "case-alias-bin-output" => {
                let first = changed
                    .targets
                    .iter()
                    .position(|target| target.kind == TargetKind::Bin)
                    .unwrap();
                let last = changed
                    .targets
                    .iter()
                    .rposition(|target| target.kind == TargetKind::Bin)
                    .unwrap();
                assert_ne!(first, last);
                let name = changed.targets[first].name.clone();
                changed.targets[last].name = if mutation == "case-alias-bin-output" {
                    name.to_ascii_uppercase()
                } else {
                    name
                };
            }
            "profile" => changed.identity.profile = "dev".into(),
            "cargo-version" => changed.identity.cargo_version = "cargo 1.98.0".into(),
            _ => unreachable!(),
        }
        assert!(Plan::build(changed, 2).is_err(), "{mutation}");
    }
    let mut forged = plan.clone();
    forged.shards[0].groups.clear();
    assert!(forged.validate().is_err());
    assert!(target_kind(&["bin".into(), "lib".into()]).is_err());
    let mut without_integration = spec();
    without_integration
        .targets
        .retain(|target| target.kind != TargetKind::Test);
    let standalone = Plan::build(without_integration, 2).unwrap();
    assert_eq!(
        standalone
            .requirements
            .iter()
            .filter(|requirement| requirement.variant == Variant::OrdinaryBinarySupport)
            .count(),
        2
    );
    for shard in &standalone.shards {
        let support = standalone.support_selectors(shard.id).unwrap();
        for name in support
            .windows(2)
            .filter(|pair| pair[0] == "--bin")
            .map(|pair| &pair[1])
        {
            assert!(
                standalone
                    .selectors(shard.id)
                    .unwrap()
                    .windows(2)
                    .any(|pair| pair == ["--bin", name])
            );
        }
    }
}

#[test]
fn real_phase_unit_merge_deduplicates_identical_support_and_rejects_conflicts() {
    let plan = Plan::build(spec(), 4).unwrap();
    let unit = observation(&plan, &plan.requirements[0]);
    assert_eq!(
        merge_units(vec![unit.clone()], vec![unit.clone()]).unwrap(),
        vec![unit.clone()]
    );
    let mut changed = unit.clone();
    changed.executable.as_mut().unwrap().length += 1;
    assert!(merge_units(vec![unit], vec![changed]).is_err());
}
