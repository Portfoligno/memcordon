#[path = "../src/cache_guard.rs"]
mod cache_guard;

use cache_guard::parse;
use memcordon_ci::{config, policy};
use serde_yaml::Value;
use std::path::Path;

#[test]
fn every_fetch_family_retains_partial_sources_after_settled_failed_fetch() {
    for file in [
        "ci.yml",
        "deep-ci.yml",
        "backend-certification.yml",
        "release.yml",
    ] {
        let document: Value = serde_yaml::from_slice(
            &std::fs::read(root().join(".github/workflows").join(file)).unwrap(),
        )
        .unwrap();
        for (job, value) in document["jobs"].as_mapping().unwrap() {
            let Some(steps) = value["steps"].as_sequence() else {
                continue;
            };
            if !steps
                .iter()
                .any(|s| s["id"].as_str() == Some("workspace-fetch"))
            {
                continue;
            }
            for kind in ["registry-archives", "registry-index"] {
                let suffix = format!(" ci cache-snapshot --kind {kind}");
                let snapshot = steps
                    .iter()
                    .find(|s| s["run"].as_str().is_some_and(|run| run.ends_with(&suffix)))
                    .unwrap();
                let guard = parse(snapshot["if"].as_str().unwrap()).unwrap();
                let fields = |field: &str| {
                    if field == "github.event_name" {
                        "push"
                    } else if field == "matrix.producer-job" {
                        ""
                    } else if field == "steps.workspace-fetch.outcome" {
                        "failure"
                    } else if field == "steps.workspace-fetch.outputs.cache-quiescent" {
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
                        &|field| if field == "steps.workspace-fetch.outputs.cache-quiescent" {
                            "false".into()
                        } else {
                            fields(field)
                        },
                        &|status| status == "always"
                    ),
                    "{file} {job:?} {kind}: unresolved fetch must block source reads"
                );
            }
        }
    }
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
                    error.to_string().contains("aggregate success"),
                    "{file}/{job_name:?}/{ordinal}: {error}"
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
                    == Some("${{ steps.compiled-context.outputs.product-key }}")
        })
        .unwrap();
    let guard = parse(save["if"].as_str().unwrap()).unwrap();
    let fields = |field: &str| {
        if field.ends_with(".outcome") {
            if field.contains("native-run") || field.contains("native-diagnostic") {
                "skipped"
            } else if field.contains("compiled.") {
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
                if field == "steps.native-run.outcome" {
                    "failure".into()
                } else if field == "steps.native-run.outputs.cache-quiescent" {
                    "false".into()
                } else {
                    fields(field)
                }
            },
            &|name| name == "always"
        ),
        "unresolved execution must block live-target reads"
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
                    == Some("${{ steps.quality-context.outputs.product-key }}")
        })
        .unwrap();
    for (from, to, expected) in [
        (
            "steps.quality-run.outputs.compiled-recipe-complete == 'true'",
            "true",
            "compiled-recipe-complete",
        ),
        (
            "steps.quality-run.outcome == 'skipped'",
            "steps.quality-run.outcome != 'failure'",
            "skipped/settled writer",
        ),
        (
            "steps.quality-run.outputs.cache-quiescent == 'true'",
            "steps.unknown-owner.outputs.cache-quiescent == 'true'",
            "unknown step",
        ),
        (
            "steps.quality-compiled-save-context.outputs.payload-ready == 'true'",
            "true",
            "payload-ready",
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
    let source_save = steps
        .iter()
        .position(|step| step["name"].as_str() == Some("Save complete workspace downloads"))
        .unwrap();
    let mut changed = document.clone();
    let steps = changed["jobs"]["quality"]["steps"]
        .as_sequence_mut()
        .unwrap();
    let moved = steps.remove(source_save);
    steps.push(moved);
    let source = serde_yaml::to_string(&changed).unwrap();
    let error = policy::validate_workflow_bytes(&root, relative, source.as_bytes(), &configuration)
        .unwrap_err();
    assert!(
        error.to_string().contains("skipped/settled writer"),
        "moved source retention: {error}"
    );

    let mut changed = document.clone();
    let seed = changed["jobs"]["quality"]["steps"]
        .as_sequence()
        .unwrap()
        .iter()
        .position(|step| step["id"].as_str() == Some("quality-compiled-partial-context"))
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
        error.to_string().contains("must precede work"),
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
        .find(|step| step["id"].as_str() == Some("archive-seed-snapshot"))
        .unwrap();
    let sysroot = steps
        .iter()
        .find(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|uses| uses.starts_with("actions/cache/save@"))
                && step["with"]["key"].as_str()
                    == Some("${{ steps.miri-sysroot-context.outputs.sysroot-key }}")
        })
        .unwrap();
    let fields = |field: &str| {
        if field == "github.event_name" {
            "push"
        } else if field == "steps.miri-sysroot-setup.outcome" {
            "failure"
        } else if field == "steps.miri-sysroot-setup.outputs.miri-sysroot-ready" {
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
            if field == "steps.miri-components.outputs.cache-quiescent" {
                "false".into()
            } else if field == "steps.miri-components.outcome" {
                "failure".into()
            } else {
                fields(field)
            }
        },
        &|status| status == "always"
    ));
}
