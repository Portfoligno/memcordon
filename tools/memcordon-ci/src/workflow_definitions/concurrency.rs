//! Finite topology changes; ordinary and Release leaves retain their event scope.
use super::{Result, text};
use serde_yaml::Value;

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
            (
                "supply-chain-audit",
                vec!["supply-audit-prepare", "supply-audit-check"],
            ),
            (
                "supply-chain-deny",
                vec!["supply-deny-prepare", "supply-deny-check"],
            ),
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
    for (_, job) in jobs {
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
                let compile = steps[..index]
                    .iter()
                    .position(|candidate| {
                        candidate["run"]
                            .as_str()
                            .and_then(|r| r.split_once(" release compile-target "))
                            == Some((driver, args))
                    })
                    .ok_or_else(|| fail("native validation has no matching actual compile"))?;
                if !steps[compile + 1..index].iter().any(|s| {
                    s["uses"]
                        .as_str()
                        .is_some_and(|u| u.starts_with("actions/cache/save@"))
                }) {
                    return Err(fail("native compiler retention boundary missing"));
                }
            }
        }
    }
    Ok(())
}

/// Legacy validators still inspect the pre-adapter command/cache vocabulary.
/// Only exact reviewed topology edits are projected; changed real dependencies,
/// guards, permissions, runner layouts or leaf steps fail before that projection.
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
