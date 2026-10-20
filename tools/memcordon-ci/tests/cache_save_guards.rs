#[path = "../src/cache_guard.rs"]
mod cache_guard;

use cache_guard::parse;
use memcordon_ci::{config, policy, workflow_definitions};
use serde_yaml::Value;
use std::path::Path;

#[test]
fn every_fetch_family_retains_partial_sources_after_settled_failed_fetch() {
    let mut families = std::collections::BTreeSet::new();
    let mut checked = 0;
    for file in workflow_definitions::FILES {
        let before = checked;
        let document: Value = serde_yaml::from_slice(
            &std::fs::read(root().join(".github/workflows").join(file)).unwrap(),
        )
        .unwrap();
        for (job, value) in document["jobs"].as_mapping().unwrap() {
            let Some(steps) = value["steps"].as_sequence() else {
                continue;
            };
            for producer in steps.iter().filter(|step| {
                step["run"].as_str().is_some_and(|run| {
                    run.ends_with(" ci segment workspace-fetch")
                        || run.ends_with(" ci segment fuzz-fetch")
                })
            }) {
                let owner = producer["id"].as_str().unwrap();
                families.insert(
                    producer["run"]
                        .as_str()
                        .unwrap()
                        .split_whitespace()
                        .last()
                        .unwrap()
                        .to_owned(),
                );
                for kind in ["archives", "index"] {
                    let id = format!("{owner}-{kind}-partial-save");
                    let snapshot = steps
                        .iter()
                        .find(|s| s["id"].as_str() == Some(id.as_str()))
                        .unwrap();
                    let guard = parse(snapshot["if"].as_str().unwrap()).unwrap();
                    let ready = format!("steps.{owner}.outputs.{kind}-partial-save");
                    let fields = |field: &str| {
                        if field == "github.event_name" {
                            "push"
                        } else if field == "matrix.producer-job" {
                            ""
                        } else if field == format!("steps.{owner}.outcome") {
                            "failure"
                        } else if field == ready {
                            "true"
                        } else if field == "steps.driver-build.outcome"
                            || field == "steps.driver-build-producer.outcome"
                        {
                            "success"
                        } else if field.ends_with(".outcome") {
                            "skipped"
                        } else if field.ends_with("-populated") {
                            "false"
                        } else {
                            ""
                        }
                        .to_owned()
                    };
                    assert!(
                        guard.evaluate(&fields, &|status| status == "always"),
                        "{file} {job:?} {kind}: failed settled fetch must retain partial sources"
                    );
                    assert!(
                        !guard.evaluate(
                            &|field| if field == ready {
                                "false".into()
                            } else {
                                fields(field)
                            },
                            &|status| status == "always"
                        ),
                        "{file} {job:?} {kind}: unresolved fetch must block source reads"
                    );
                    checked += 1;
                }
            }
        }
        assert!(
            checked > before,
            "{file} must exercise actual source retention saves"
        );
    }
    assert!(
        checked > 20,
        "source retention inventory unexpectedly shrank: {checked}"
    );
    assert!(families.contains("workspace-fetch") && families.contains("fuzz-fetch"));
}

#[test]
fn guard_parser_preserves_precedence_exact_strings_and_truthy_false_outputs() {
    let condition = parse("always() && (steps.normal.outcome == 'skipped' || steps.normal.outputs.cache-quiescent == 'true') && (steps.diagnostic.outcome == 'skipped' || steps.diagnostic.outputs.cache-quiescent == 'true')").unwrap();
    for (normal, diagnostic, permitted) in [
        ("true", "", true),
        ("false", "true", false),
        ("true", "false", false),
        ("", "", false),
    ] {
        let fields = |field: &str| {
            match field {
                "steps.normal.outputs.cache-quiescent" => normal,
                "steps.diagnostic.outputs.cache-quiescent" => diagnostic,
                "steps.diagnostic.outcome" if diagnostic.is_empty() => "skipped",
                _ => "failure",
            }
            .to_owned()
        };
        assert_eq!(
            condition.evaluate(&fields, &|status| status == "always"),
            permitted
        );
    }
    let unsafe_choice = parse("(steps.normal.outputs.cache-quiescent || steps.diagnostic.outputs.cache-quiescent) == 'true'").unwrap();
    assert!(!unsafe_choice.evaluate(
        &|field| {
            if field.contains("normal") {
                "false".into()
            } else {
                "true".into()
            }
        },
        &|_| false
    ));
    let mandatory = parse("steps.owner.outputs.cache-quiescent == 'true'").unwrap();
    assert!(
        mandatory
            .references()
            .contains("steps.owner.outputs.cache-quiescent")
    );
    assert!(
        !parse("steps.owner.outputs.cache-quiescent == 'true' || true")
            .unwrap()
            .requires(&mandatory)
    );
    assert!(
        parse("always() && steps.owner.outputs.cache-quiescent == 'true'")
            .unwrap()
            .requires(&mandatory)
    );
    assert!(
        !parse("!success()")
            .unwrap()
            .requires(&parse("success()").unwrap())
    );
    for unsupported in [
        "contains(a, b)",
        "steps.x[0]",
        "always(1)",
        "a & b",
        "'unterminated",
    ] {
        assert!(parse(unsupported).is_err(), "accepted {unsupported}");
    }
    assert!(
        parse(&vec!["true"; 1024].join(" || "))
            .unwrap_err()
            .contains("bounded expression depth")
    );
}

fn root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn actual_save_blocks_reject_aggregate_status_and_missing_owner_facts() {
    let root = root();
    let configuration = config::policy(&root).unwrap();
    let mut checked = 0;
    for file in [
        "ci.yml",
        "deep-ci.yml",
        "backend-certification.yml",
        "release.yml",
    ] {
        let relative = Path::new(".github/workflows").join(file);
        let bytes = std::fs::read(root.join(&relative)).unwrap();
        let document: Value = serde_yaml::from_slice(&bytes).unwrap();
        policy::validate_workflow_bytes(&root, &relative, &bytes, &configuration)
            .unwrap_or_else(|error| panic!("{file}: {error}"));
        for (job_name, job) in document["jobs"].as_mapping().unwrap() {
            let Some(steps) = job["steps"].as_sequence() else {
                continue;
            };
            for (ordinal, step) in steps.iter().enumerate() {
                if !step["uses"]
                    .as_str()
                    .is_some_and(|uses| uses.starts_with("actions/cache/save@"))
                {
                    continue;
                }
                let original = step["if"].as_str().unwrap();
                assert!(!parse(original).unwrap().contains_status("success"));
                let mut changed = document.clone();
                changed["jobs"][job_name]["steps"][ordinal]["if"] =
                    format!("({original}) && success()").into();
                let source = serde_yaml::to_string(&changed).unwrap();
                let error = policy::validate_workflow_bytes(
                    &root,
                    &relative,
                    source.as_bytes(),
                    &configuration,
                )
                .unwrap_err();
                assert!(
                    error
                        .to_string()
                        .contains("invalid Rust-owned cache save adapter"),
                    "{file}/{job_name:?}/{ordinal}: {error}"
                );
                let mut changed = document.clone();
                changed["jobs"][job_name]["steps"][ordinal]["if"] = "always()".into();
                let source = serde_yaml::to_string(&changed).unwrap();
                let error = policy::validate_workflow_bytes(
                    &root,
                    &relative,
                    source.as_bytes(),
                    &configuration,
                )
                .unwrap_err();
                assert!(
                    error
                        .to_string()
                        .contains("invalid Rust-owned cache save adapter"),
                    "missing owner fact {file}/{job_name:?}/{ordinal}: {error}"
                );
                checked += 1;
            }
        }
    }
    assert!(
        checked > 100,
        "whole-workflow save inventory unexpectedly shrank: {checked}"
    );
}

#[test]
fn settled_compilation_survives_later_failed_assertion_and_skipped_execution() {
    let root = root();
    let document: Value =
        serde_yaml::from_slice(&std::fs::read(root.join(".github/workflows/ci.yml")).unwrap())
            .unwrap();
    let steps = document["jobs"]["native"]["steps"].as_sequence().unwrap();
    let save = steps
        .iter()
        .find(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|uses| uses.starts_with("actions/cache/save@"))
                && step["with"]["key"].as_str()
                    == Some("${{ steps.native-compile.outputs.native-tests-complete-key }}")
        })
        .unwrap();
    let guard = parse(save["if"].as_str().unwrap()).unwrap();
    let fields = |field: &str| {
        if field.ends_with(".outcome") {
            if field.contains("native-run") || field.contains("native-diagnostic") {
                "skipped"
            } else if field.contains("native-compile") {
                "failure"
            } else {
                "success"
            }
        } else if field == "github.event_name" {
            "push"
        } else if field.ends_with(".cache-hit") {
            ""
        } else if field.ends_with("-key") {
            "same-key"
        } else if field.ends_with("-paths") {
            "target/owned"
        } else {
            "true"
        }
        .to_owned()
    };
    assert!(
        guard.evaluate(&fields, &|name| name == "always"),
        "settled compilation must be retained while the work step remains failed"
    );
    assert!(
        !guard.evaluate(
            &|field| {
                if field == "steps.native-compile.outputs.native-tests-complete-save" {
                    "false".into()
                } else {
                    fields(field)
                }
            },
            &|name| name == "always"
        ),
        "unstaged compilation must never be saved"
    );
    use memcordon_ci::{
        segment_cache::{RetentionDecision, compilation_retention},
        work_outcome::WriterSettlement,
    };
    assert_eq!(
        compilation_retention(true, true, true, WriterSettlement::Settled, true),
        RetentionDecision::Complete
    );
    assert_eq!(
        compilation_retention(true, true, true, WriterSettlement::Unknown, true),
        RetentionDecision::None
    );
    for (eligible, unchanged, payload) in [
        (false, true, true),
        (true, false, true),
        (true, true, false),
    ] {
        assert_eq!(
            compilation_retention(
                eligible,
                unchanged,
                payload,
                WriterSettlement::Settled,
                true
            ),
            RetentionDecision::None
        );
    }
    let compile = steps
        .iter()
        .position(|step| step["id"].as_str() == Some("native-compile"))
        .unwrap();
    let save = steps
        .iter()
        .position(|step| step["id"].as_str() == Some("native-compile-native-tests-complete-save"))
        .unwrap();
    let execute = steps
        .iter()
        .position(|step| {
            step["run"]
                .as_str()
                .is_some_and(|run| run.ends_with(" ci segment native-execute"))
        })
        .unwrap();
    assert!(
        compile < save && save < execute,
        "immutable compiler checkpoint must precede execution writers"
    );
}

#[test]
fn actual_workflows_reject_missing_recipe_writer_context_and_order_requirements() {
    let root = root();
    let configuration = config::policy(&root).unwrap();
    let relative = Path::new(".github/workflows/ci.yml");
    let document: Value =
        serde_yaml::from_slice(&std::fs::read(root.join(relative)).unwrap()).unwrap();
    let steps = document["jobs"]["quality"]["steps"].as_sequence().unwrap();
    let save = steps
        .iter()
        .position(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|uses| uses.starts_with("actions/cache/save@"))
                && step["with"]["key"].as_str()
                    == Some("${{ steps.quality-run.outputs.compiled-complete-key }}")
        })
        .unwrap();
    for (from, to, expected) in [
        (
            "steps.quality-run.outputs.compiled-complete-save == 'true'",
            "true",
            "invalid Rust-owned cache save adapter",
        ),
        (
            "always()",
            "success()",
            "invalid Rust-owned cache save adapter",
        ),
        (
            "steps.quality-run.outputs.compiled-complete-save",
            "steps.unknown-owner.outputs.compiled-complete-save",
            "invalid Rust-owned cache save adapter",
        ),
        (
            "steps.quality-run-compiled-complete-probe.outputs.cache-hit != 'true'",
            "true",
            "invalid Rust-owned cache save adapter",
        ),
    ] {
        let mut changed = document.clone();
        let guard = changed["jobs"]["quality"]["steps"][save]["if"]
            .as_str()
            .unwrap();
        assert!(guard.contains(from));
        changed["jobs"]["quality"]["steps"][save]["if"] = guard.replace(from, to).into();
        let source = serde_yaml::to_string(&changed).unwrap();
        let error =
            policy::validate_workflow_bytes(&root, relative, source.as_bytes(), &configuration)
                .unwrap_err();
        assert!(error.to_string().contains(expected), "{from}: {error}");
    }
    let mut changed = document.clone();
    changed["jobs"]["quality"]["steps"][save]["with"]["path"] = "unassociated-payload".into();
    let source = serde_yaml::to_string(&changed).unwrap();
    let error = policy::validate_workflow_bytes(&root, relative, source.as_bytes(), &configuration)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("invalid Rust-owned cache save adapter"),
        "payload association: {error}"
    );
    let source_save = steps
        .iter()
        .position(|step| step["id"].as_str() == Some("workspace-fetch-source-complete-save"))
        .unwrap();
    let mut changed = document.clone();
    let steps = changed["jobs"]["quality"]["steps"]
        .as_sequence_mut()
        .unwrap();
    let moved = steps.remove(source_save);
    steps.insert(0, moved);
    let source = serde_yaml::to_string(&changed).unwrap();
    let error = policy::validate_workflow_bytes(&root, relative, source.as_bytes(), &configuration)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("cache save owner must precede transfer"),
        "moved source retention: {error}"
    );

    let mut changed = document.clone();
    let seed = changed["jobs"]["quality"]["steps"]
        .as_sequence()
        .unwrap()
        .iter()
        .position(|step| step["id"].as_str() == Some("quality-run-request"))
        .unwrap();
    let steps = changed["jobs"]["quality"]["steps"]
        .as_sequence_mut()
        .unwrap();
    let moved = steps.remove(seed);
    steps.insert(0, moved);
    let source = serde_yaml::to_string(&changed).unwrap();
    let error = policy::validate_workflow_bytes(&root, relative, source.as_bytes(), &configuration)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("split leaf differs from reviewed source"),
        "seed before driver: {error}"
    );
}

#[test]
fn settled_miri_setup_failure_retains_download_seed_without_ready_sysroot() {
    let root = root();
    let document: Value =
        serde_yaml::from_slice(&std::fs::read(root.join(".github/workflows/deep-ci.yml")).unwrap())
            .unwrap();
    let steps = document["jobs"]["miri"]["steps"].as_sequence().unwrap();
    let snapshot = steps
        .iter()
        .find(|step| step["id"].as_str() == Some("miri-sysroot-setup-archives-partial-save"))
        .unwrap();
    let sysroot = steps
        .iter()
        .find(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|uses| uses.starts_with("actions/cache/save@"))
                && step["with"]["key"].as_str()
                    == Some("${{ steps.miri-sysroot-setup.outputs.sysroot-key }}")
        })
        .unwrap();
    let fields = |field: &str| {
        if field == "github.event_name" {
            "push"
        } else if field == "steps.miri-sysroot-setup.outcome" {
            "failure"
        } else if field == "steps.miri-sysroot-setup.outputs.sysroot-save" {
            "false"
        } else if field.ends_with(".outcome") && field.contains("miri-quarter-") {
            "skipped"
        } else if field.ends_with(".outcome") {
            "success"
        } else if field.ends_with(".cache-hit") {
            ""
        } else if field.ends_with("-key") {
            "same-key"
        } else {
            "true"
        }
        .to_owned()
    };
    assert!(
        parse(snapshot["if"].as_str().unwrap())
            .unwrap()
            .evaluate(&fields, &|status| status == "always")
    );
    assert!(
        !parse(sysroot["if"].as_str().unwrap())
            .unwrap()
            .evaluate(&fields, &|status| status == "always")
    );
    assert!(!parse(snapshot["if"].as_str().unwrap()).unwrap().evaluate(
        &|field| {
            if field == "steps.miri-sysroot-setup.outputs.archives-partial-save" {
                "false".into()
            } else {
                fields(field)
            }
        },
        &|status| status == "always"
    ));
}
