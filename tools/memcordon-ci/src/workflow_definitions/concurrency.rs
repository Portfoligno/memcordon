//! Finite topology changes; ordinary and Release leaves retain their event scope.
use super::{Result, text};
use serde_yaml::Value;
use std::collections::BTreeSet;

fn no_soft_failure(value: &Value) -> bool {
    value.get("continue-on-error").is_none() || value["continue-on-error"].as_bool() == Some(false)
}

fn distributed_native(workflow: &Value, name: &str, driver: &str, args: &str) -> Result<bool> {
    if !args
        .split_whitespace()
        .any(|word| word == "--native-coverage")
    {
        return Ok(false);
    }
    let fail = || crate::CiError::Message("distributed native producer contract differs".into());
    if workflow["name"].as_str() != Some("Release")
        || name != "native-macos-x64"
        || driver != "./target/ci-runtime/current/memcordon-ci"
        || args
            != "--build-source .release/build-source.json --consumer-readiness --native-coverage .release/native-coverage --product-inputs .release/native-product"
    {
        return Err(fail());
    }
    let jobs = &workflow["jobs"];
    let definitions = [
        (
            "native-macos-x64-plan",
            vec!["select", "readiness-tools-macos-x64"],
            "./target/ci-runtime/current/memcordon-ci release native-coverage-plan --build-source .release/build-source.json",
        ),
        (
            "native-macos-x64-product",
            vec![
                "select",
                "readiness-tools-macos-x64",
                "native-macos-x64-plan",
            ],
            "./target/ci-runtime/current/memcordon-ci release compile-target --build-source .release/build-source.json --consumer-readiness --product-only --destination .release/native-product",
        ),
        (
            "native-macos-x64-shard-0",
            vec![
                "select",
                "readiness-tools-macos-x64",
                "native-macos-x64-plan",
            ],
            "./target/ci-runtime/current/memcordon-ci release native-coverage-shard --build-source .release/build-source.json --shard 0 --destination .release/native-coverage/0",
        ),
        (
            "native-macos-x64-shard-1",
            vec![
                "select",
                "readiness-tools-macos-x64",
                "native-macos-x64-plan",
            ],
            "./target/ci-runtime/current/memcordon-ci release native-coverage-shard --build-source .release/build-source.json --shard 1 --destination .release/native-coverage/1",
        ),
        (
            "native-macos-x64-shard-2",
            vec![
                "select",
                "readiness-tools-macos-x64",
                "native-macos-x64-plan",
            ],
            "./target/ci-runtime/current/memcordon-ci release native-coverage-shard --build-source .release/build-source.json --shard 2 --destination .release/native-coverage/2",
        ),
        (
            "native-macos-x64-shard-3",
            vec![
                "select",
                "readiness-tools-macos-x64",
                "native-macos-x64-plan",
            ],
            "./target/ci-runtime/current/memcordon-ci release native-coverage-shard --build-source .release/build-source.json --shard 3 --destination .release/native-coverage/3",
        ),
        (
            "native-macos-x64",
            vec![
                "select",
                "readiness-tools-macos-x64",
                "native-macos-x64-plan",
                "native-macos-x64-product",
                "native-macos-x64-shard-0",
                "native-macos-x64-shard-1",
                "native-macos-x64-shard-2",
                "native-macos-x64-shard-3",
            ],
            "./target/ci-runtime/current/memcordon-ci release validate-package --build-source .release/build-source.json --consumer-readiness --native-coverage .release/native-coverage --product-inputs .release/native-product",
        ),
    ];
    for (id, expected_needs, command) in definitions {
        let shard = match id {
            "native-macos-x64-shard-0" => Some(0),
            "native-macos-x64-shard-1" => Some(1),
            "native-macos-x64-shard-2" => Some(2),
            "native-macos-x64-shard-3" => Some(3),
            _ => None,
        };
        let job = &jobs[id];
        let needs = job["needs"].as_sequence().ok_or_else(fail)?;
        let selected: BTreeSet<_> = needs.iter().filter_map(Value::as_str).collect();
        if selected != expected_needs.into_iter().collect()
            || selected.len() != needs.len()
            || job["if"].as_str() != Some("needs.select.outputs.recovery-mode == 'reprepare'")
            || !no_soft_failure(job)
            || job["runs-on"].as_str() != Some("${{ matrix.runner }}")
            || (shard.is_some() && job.get("outputs").is_some())
            || (shard.is_none()
                && job["outputs"]["artifact-id"].as_str()
                    != Some("${{ steps.payload.outputs.artifact-id }}"))
        {
            return Err(fail());
        }
        let matrix = job["strategy"]["matrix"].as_mapping().ok_or_else(fail)?;
        if matrix.len() != 1 {
            return Err(fail());
        }
        let entries = job["strategy"]["matrix"]["include"]
            .as_sequence()
            .ok_or_else(fail)?;
        for entry in entries {
            if entry["target"].as_str() != Some("x86_64-apple-darwin")
                || entry["runner"].as_str() != Some("macos-15-intel")
                || entry.as_mapping().is_none_or(|map| map.len() != 2)
            {
                return Err(fail());
            }
        }
        if entries.len() != 1 {
            return Err(fail());
        }
        let steps = job["steps"].as_sequence().ok_or_else(fail)?;
        let matches: Vec<_> = steps
            .iter()
            .enumerate()
            .filter(|(_, step)| step["run"].as_str() == Some(command))
            .collect();
        if matches.len() != 1 {
            return Err(fail());
        }
        let (index, work) = matches[0];
        let expected_guard = (id != "native-macos-x64-plan").then_some("runner.os != 'Windows'");
        if !no_soft_failure(work) || work["if"].as_str() != expected_guard || work["if"].is_bool() {
            return Err(fail());
        }
        let previous = &steps[..index];
        if !previous.iter().any(|step| step["uses"].as_str().is_some_and(|action| action.starts_with("actions/checkout@"))
            && step["with"]["ref"].as_str()==Some("${{ needs.select.outputs.selected-commit }}")
            && step["with"]["persist-credentials"].as_bool()==Some(false)
            && no_soft_failure(step) && step.get("if").is_none())
            || !download(previous,"artifact-ids","${{ needs.select.outputs.selection-artifact-id }}",".release")
            || !previous.iter().any(|step| step["run"].as_str()==Some("./target/ci-runtime/current/memcordon-ci ci preparation-tools check --kind readiness")
                && no_soft_failure(step) && step.get("if").is_none())
        { return Err(fail()); }
        if id != "native-macos-x64-plan"
            && !download(
                previous,
                "artifact-ids",
                "${{ needs.native-macos-x64-plan.outputs.artifact-id }}",
                ".release",
            )
        {
            return Err(fail());
        }
        match id {
            "native-macos-x64-plan" => {
                if !upload(
                    &steps[index + 1..],
                    "native-coverage-plan-${{ github.run_id }}-${{ github.run_attempt }}",
                    ".release/native-coverage-plan.json\n.release/native-coverage-deadline.json\n",
                ) {
                    return Err(fail());
                }
            }
            "native-macos-x64-product" => {
                if !upload(
                    &steps[index + 1..],
                    "native-product-${{ matrix.target }}-${{ github.run_id }}-${{ github.run_attempt }}",
                    ".release/native-product",
                ) {
                    return Err(fail());
                }
            }
            "native-macos-x64" => {
                if !upload(
                    &steps[index + 1..],
                    "native-${{ matrix.target }}-${{ github.run_id }}-${{ github.run_attempt }}",
                    ".release/target",
                ) {
                    return Err(fail());
                }
                if !download(
                    previous,
                    "artifact-ids",
                    "${{ needs.native-macos-x64-product.outputs.artifact-id }}",
                    ".release/native-product",
                ) {
                    return Err(fail());
                }
                for (artifact, path) in [
                    (
                        "native-coverage-${{ matrix.target }}-0-${{ github.run_id }}-${{ github.run_attempt }}",
                        ".release/native-coverage/0",
                    ),
                    (
                        "native-coverage-${{ matrix.target }}-1-${{ github.run_id }}-${{ github.run_attempt }}",
                        ".release/native-coverage/1",
                    ),
                    (
                        "native-coverage-${{ matrix.target }}-2-${{ github.run_id }}-${{ github.run_attempt }}",
                        ".release/native-coverage/2",
                    ),
                    (
                        "native-coverage-${{ matrix.target }}-3-${{ github.run_id }}-${{ github.run_attempt }}",
                        ".release/native-coverage/3",
                    ),
                ] {
                    if !download(previous, "name", artifact, path) {
                        return Err(fail());
                    }
                }
            }
            _ => {
                let shard = shard.expect("fixed distributed shard job");
                let artifact = format!(
                    "native-coverage-${{{{ matrix.target }}}}-{shard}-${{{{ github.run_id }}}}-${{{{ github.run_attempt }}}}"
                );
                let path = format!(".release/native-coverage/{shard}");
                if !upload(&steps[index + 1..], &artifact, &path) {
                    return Err(fail());
                }
            }
        }
    }
    Ok(true)
}

fn download(steps: &[Value], key: &str, selected: &str, destination: &str) -> bool {
    steps.iter().any(|step| {
        step["uses"]
            .as_str()
            .is_some_and(|action| action.starts_with("actions/download-artifact@"))
            && step["with"][key].as_str() == Some(selected)
            && step["with"]["path"].as_str() == Some(destination)
            && step["with"]["digest-mismatch"].as_str() == Some("error")
            && (key != "artifact-ids"
                || (step["with"]["merge-multiple"].as_bool() == Some(true)
                    && step["with"]["name"].is_null()))
            && (key != "name" || step["with"]["artifact-ids"].is_null())
            && no_soft_failure(step)
            && step.get("if").is_none()
    })
}
fn upload(steps: &[Value], name: &str, path: &str) -> bool {
    steps.iter().any(|step| {
        step["uses"]
            .as_str()
            .is_some_and(|action| action.starts_with("actions/upload-artifact@"))
            && step["with"]["name"].as_str() == Some(name)
            && step["with"]["path"].as_str() == Some(path)
            && step["id"].as_str() == Some("payload")
            && step["with"]["if-no-files-found"].as_str() == Some("error")
            && step["with"]["overwrite"].as_bool() == Some(false)
            && step["with"]["include-hidden-files"].as_bool() == Some(true)
            && no_soft_failure(step)
            && step.get("if").is_none()
    })
}

pub(super) fn apply(workflow: &mut Value, file: &str) -> Result<()> {
    let jobs = workflow["jobs"].as_mapping_mut().expect("source jobs");
    if matches!(file, "ci.yml" | "release.yml") {
        let compiler = if file == "ci.yml" {
            "quality"
        } else {
            "source-checks"
        };
        let docs = if file == "ci.yml" {
            "quality-docs"
        } else {
            "source-docs"
        };
        let mut documentation = jobs.get(text(compiler)).expect("quality job").clone();
        documentation["name"] = text(if file == "ci.yml" {
            "quality / documentation"
        } else {
            "Source documentation"
        });
        jobs.insert(text(docs), documentation);
        jobs.get_mut(text(compiler)).expect("compiler job")["name"] = text(if file == "ci.yml" {
            "quality / check and Clippy"
        } else {
            "Source check and Clippy"
        });
        let supply = jobs.remove(text("supply-chain")).expect("supply job");
        for (id, label) in [
            ("supply-chain-audit", "Supply chain / audit"),
            ("supply-chain-deny", "Supply chain / deny"),
        ] {
            let mut leaf = supply.clone();
            leaf["name"] = text(label);
            jobs.insert(text(id), leaf);
        }
        if file == "release.yml" {
            let needs = jobs.get_mut(text("assemble")).expect("assembly")["needs"]
                .as_sequence_mut()
                .expect("required jobs");
            let position = needs
                .iter()
                .position(|n| n.as_str() == Some("supply-chain"))
                .expect("supply predecessor");
            needs.splice(
                position..=position,
                [text("supply-chain-audit"), text("supply-chain-deny")],
            );
            needs.push(text("source-docs"));
        }
    }
    for (_, job) in jobs {
        if job["strategy"]["matrix"].is_mapping() {
            job["strategy"]["fail-fast"] = Value::Bool(false);
        }
    }
    Ok(())
}

pub(super) fn recipe<'a>(job: &str, old: &'a str) -> &'a str {
    match (job, old) {
        ("quality", "quality") => "quality-compiler",
        ("source-checks", "quality-compile") => "release-quality-compiler",
        ("quality-docs" | "source-docs", "quality" | "quality-compile") => "quality-documentation",
        ("supply-chain-audit", "supply-chain") => "supply-audit-prepare",
        ("supply-chain-deny", "supply-chain") => "supply-deny-prepare",
        _ => old,
    }
}

pub(super) fn validate(workflow: &Value) -> Result<()> {
    let fail = |message: &str| crate::CiError::Message(message.into());
    let jobs = workflow["jobs"]
        .as_mapping()
        .ok_or_else(|| fail("missing jobs"))?;
    let release = workflow["name"].as_str() == Some("Release");
    let ordinary = workflow["name"].as_str() == Some("CI");
    if release || ordinary {
        if jobs.contains_key(text("supply-chain")) {
            return Err(fail("combined security duplicates leaves"));
        }
        let compiler = if release { "source-checks" } else { "quality" };
        let docs = if release {
            "source-docs"
        } else {
            "quality-docs"
        };
        for (name, recipes) in [
            (
                compiler,
                vec![if release {
                    "release-quality-compiler"
                } else {
                    "quality-compiler"
                }],
            ),
            (docs, vec!["quality-documentation"]),
            ("supply-chain-audit", vec!["supply-audit"]),
            ("supply-chain-deny", vec!["supply-deny"]),
        ] {
            let job = jobs
                .get(text(name))
                .ok_or_else(|| fail("required independent leaf missing"))?;
            if (release
                && (job["needs"].as_str() != Some("select")
                    || job["if"].as_str()
                        != Some("needs.select.outputs.recovery-mode == 'reprepare'")))
                || (ordinary
                    && (!job["needs"].is_null()
                        || job["if"].as_str() != Some("github.event_name != 'push'")))
            {
                return Err(fail("independent leaf dependency/event scope differs"));
            }
            if job["permissions"]
                .as_mapping()
                .is_some_and(|p| p.values().any(|v| v.as_str() == Some("write")))
            {
                return Err(fail("read-only leaf received credentials"));
            }
            let steps = job["steps"]
                .as_sequence()
                .ok_or_else(|| fail("leaf steps missing"))?;
            let actual = steps
                .iter()
                .filter_map(|step| step["run"].as_str())
                .filter_map(|run| run.split_once(" ci segment ").map(|(_, recipe)| recipe))
                .filter(|recipe| {
                    recipe.starts_with("quality-")
                        || recipe.starts_with("release-quality-")
                        || recipe.starts_with("supply-")
                })
                .collect::<Vec<_>>();
            if actual != recipes {
                return Err(fail("leaf check inventory differs"));
            }
        }
        if release {
            let needs = workflow["jobs"]["assemble"]["needs"]
                .as_sequence()
                .ok_or_else(|| fail("assembly needs missing"))?;
            for leaf in [
                "source-checks",
                "source-docs",
                "supply-chain-audit",
                "supply-chain-deny",
            ] {
                if !needs.iter().any(|n| n.as_str() == Some(leaf)) {
                    return Err(fail("assembly omits required leaf"));
                }
            }
        }
    }
    for (name, job) in jobs {
        if job["strategy"]["matrix"].is_mapping()
            && job["strategy"]["fail-fast"].as_bool() != Some(false)
        {
            return Err(fail("matrix may cancel independent cache owners"));
        }
        let Some(steps) = job["steps"].as_sequence() else {
            continue;
        };
        for (index, step) in steps.iter().enumerate() {
            let Some(run) = step["run"].as_str() else {
                continue;
            };
            if run.contains(" release compile-target ")
                && (step["continue-on-error"].as_bool() == Some(true)
                    || step["if"].as_str().is_some_and(|guard| {
                        ["always(", "failure(", "cancelled("]
                            .iter()
                            .any(|word| guard.contains(word))
                    }))
            {
                return Err(fail("native compiler must be required success-only work"));
            }
            if let Some((driver, args)) = run.split_once(" release validate-package ") {
                if step["continue-on-error"].as_bool() == Some(true)
                    || step["if"].as_str().is_some_and(|guard| {
                        ["always(", "failure(", "cancelled("]
                            .iter()
                            .any(|word| guard.contains(word))
                    })
                {
                    return Err(fail("native validation must require compiler success"));
                }
                if distributed_native(workflow, name.as_str().unwrap_or(""), driver, args)? {
                    continue;
                }
                steps[..index]
                    .iter()
                    .position(|candidate| {
                        candidate["run"]
                            .as_str()
                            .and_then(|r| r.split_once(" release compile-target "))
                            == Some((driver, args))
                    })
                    .ok_or_else(|| fail("native validation has no matching actual compile"))?;
            }
        }
    }
    Ok(())
}

/// Legacy validators still inspect the pre-adapter command/cache vocabulary.
/// Only exact reviewed topology edits are projected; changed real dependencies,
/// guards, permissions, runner layouts or leaf steps fail before that projection.
pub(super) fn project_native_coverage(
    actual: &mut serde_yaml::Mapping,
    expected: &Value,
) -> Result<()> {
    let jobs = actual
        .get_mut(text("jobs"))
        .and_then(Value::as_mapping_mut)
        .expect("jobs");
    let owners = [
        "native-macos-x64-plan",
        "native-macos-x64-product",
        "native-macos-x64-shard-0",
        "native-macos-x64-shard-1",
        "native-macos-x64-shard-2",
        "native-macos-x64-shard-3",
        "native-macos-x64",
    ];
    for name in owners {
        if jobs.get(text(name)) != expected["jobs"].get(name) {
            return Err(crate::CiError::Message(format!(
                "distributed native owner differs from reviewed source: {name}"
            )));
        }
    }
    for name in &owners[..6] {
        jobs.remove(text(name));
    }
    // The aggregate remains exact for the existing preparation projection.
    Ok(())
}

pub(super) fn project(
    actual: &mut serde_yaml::Mapping,
    expected: &Value,
    original: &Value,
    file: &str,
) -> Result<()> {
    let jobs = actual
        .get_mut(text("jobs"))
        .and_then(Value::as_mapping_mut)
        .expect("jobs");
    if matches!(file, "ci.yml" | "release.yml") {
        let compiler = if file == "ci.yml" {
            "quality"
        } else {
            "source-checks"
        };
        let docs = if file == "ci.yml" {
            "quality-docs"
        } else {
            "source-docs"
        };
        for name in [compiler, docs, "supply-chain-audit", "supply-chain-deny"] {
            if jobs.get(text(name)) != expected["jobs"].get(name) {
                return Err(crate::CiError::Message(format!(
                    "split leaf differs from reviewed source: {name}"
                )));
            }
        }
        if jobs.contains_key(text("supply-chain")) {
            return Err(crate::CiError::Message(
                "duplicate combined security job".into(),
            ));
        }
        jobs.remove(text(docs));
        jobs.remove(text("supply-chain-audit"));
        jobs.remove(text("supply-chain-deny"));
        jobs.insert(text(compiler), original["jobs"][compiler].clone());
        jobs.insert(
            text("supply-chain"),
            original["jobs"]["supply-chain"].clone(),
        );
        if file == "release.yml" {
            let assembly = jobs
                .get_mut(text("assemble"))
                .ok_or_else(|| crate::CiError::Message("assembly missing".into()))?;
            if assembly["needs"] != expected["jobs"]["assemble"]["needs"] {
                return Err(crate::CiError::Message(
                    "assembly must require every split leaf".into(),
                ));
            }
            assembly["needs"] = original["jobs"]["assemble"]["needs"].clone();
        }
    }
    for (name, job) in jobs {
        if job["strategy"]["matrix"].is_mapping() {
            if job["strategy"]["fail-fast"].as_bool() != Some(false) {
                return Err(crate::CiError::Message(
                    "cache-producing matrices must preserve peer runners".into(),
                ));
            }
            job["strategy"]["fail-fast"] = original["jobs"][name]["strategy"]["fail-fast"].clone();
        }
    }
    Ok(())
}
