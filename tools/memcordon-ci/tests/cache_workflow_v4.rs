use serde_yaml::Value;
use std::collections::BTreeMap;

const WORKFLOWS: [(&str, &str); 4] = [
    ("ci", include_str!("../../../.github/workflows/ci.yml")),
    (
        "deep",
        include_str!("../../../.github/workflows/deep-ci.yml"),
    ),
    (
        "backend",
        include_str!("../../../.github/workflows/backend-certification.yml"),
    ),
    (
        "release",
        include_str!("../../../.github/workflows/release.yml"),
    ),
];

fn paths(step: &Value) -> Result<Vec<&str>, String> {
    Ok(step["with"]["path"]
        .as_str()
        .ok_or("missing cache paths")?
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect())
}

fn output_reference(value: &str, output: &str) -> Option<String> {
    let inner = value.strip_prefix("${{ steps.")?.strip_suffix(" }}")?;
    let (step, selected) = inner.split_once(".outputs.")?;
    (selected == output && !step.is_empty()).then(|| step.to_owned())
}

fn validate(value: &Value) -> Result<usize, String> {
    let mut expanded = value.clone();
    expanded.apply_merge().map_err(|error| error.to_string())?;
    let jobs = expanded["jobs"].as_mapping().ok_or("missing jobs")?;
    if jobs.len() > 256 {
        return Err("too many jobs".into());
    }
    let mut total = 0;
    for (job_name, job) in jobs {
        let Some(steps) = job["steps"].as_sequence() else {
            continue;
        };
        if steps.len() > 512 {
            return Err("too many steps".into());
        }
        let mut restores = BTreeMap::new();
        let mut saves = BTreeMap::new();
        for (ordinal, step) in steps.iter().enumerate() {
            let Some(action) = step["uses"].as_str() else {
                continue;
            };
            if !action.starts_with("actions/cache") {
                continue;
            }
            let pin = "55cc8345863c7cc4c66a329aec7e433d2d1c52a9";
            if action != format!("actions/cache/restore@{pin}")
                && action != format!("actions/cache/save@{pin}")
            {
                return Err("unpaired/unknown cache action".into());
            }
            let selected_paths = paths(step)?;
            if selected_paths.is_empty() {
                return Err("empty cache path list".into());
            }
            for path in &selected_paths {
                if matches!(
                    *path,
                    "target"
                        | "target/ci-build"
                        | "target/ci-consumers"
                        | "target/ci-tools/bin"
                        | "target/ci-tools-build"
                ) || path.contains('*')
                    || path.contains(".release")
                    || path.contains("reports")
                    || path.contains("credentials")
                {
                    return Err(format!("unsafe cache payload {path}"));
                }
            }
            let key = step["with"]["key"].as_str().ok_or("missing key")?;
            if action.contains("/restore@") {
                total += 1;
                let id = step["id"].as_str().ok_or("restore missing id")?;
                if restores.insert(id, (ordinal, step)).is_some() {
                    return Err("duplicate cache restore id".into());
                }
                let source = selected_paths
                    .iter()
                    .any(|path| path.starts_with("~/.cargo/"));
                if source && selected_paths != ["~/.cargo/registry/index"] {
                    if selected_paths != ["~/.cargo/registry/cache", "~/.cargo/git/db"] {
                        return Err("raw source path list differs".into());
                    }
                    if !key.starts_with("mc-download-v4-${{ runner.os }}-")
                        || key.contains("runner.arch")
                        || key.contains("ci/")
                    {
                        return Err("raw source namespace/scope differs".into());
                    }
                    let condition = step["if"].as_str().unwrap_or_default();
                    if !condition.contains("hashFiles('Cargo.lock') != ''") {
                        return Err("raw source restore lacks lockfile guard".into());
                    }
                    if !step["with"]["restore-keys"].as_str().is_some_and(|prefix| {
                        prefix.starts_with("mc-download-v4-${{ runner.os }}-")
                    }) {
                        return Err("raw source fallback missing".into());
                    }
                } else if let Some(context) = output_reference(key, "product-key") {
                    let prefix =
                        format!("${{{{ steps.{context}.outputs.product-restore-prefix }}}}");
                    if step["with"]["restore-keys"].as_str() != Some(&prefix) {
                        return Err("compiled fallback is not full compatibility boundary".into());
                    }
                    for mode in ["discard", "exact", "compatible"] {
                        let required = format!("--mode {mode}");
                        if !steps.iter().skip(ordinal + 1).any(|candidate| {
                            candidate["run"].as_str().is_some_and(|run| {
                                run.contains(" ci prepare-restored-cache ")
                                    && run.ends_with(&required)
                            }) && candidate["if"].as_str().is_some_and(|condition| {
                                condition.contains(&format!("steps.{id}."))
                            })
                        }) {
                            return Err(format!("compiled restore {id} lacks {mode} sanitation"));
                        }
                    }
                } else if !["tool-key", "tool-build-key", "index-key"]
                    .iter()
                    .any(|output| output_reference(key, output).is_some())
                {
                    return Err(format!("legacy/unprojected cache key {key}"));
                }
            } else {
                let id = output_reference(key, "cache-primary-key")
                    .ok_or("save must use originally requested primary key")?;
                saves
                    .entry(id)
                    .or_insert_with(Vec::new)
                    .push((ordinal, step));
                let condition = step["if"].as_str().unwrap_or_default();
                if !condition.contains("always()")
                    || !condition.contains("github.event_name == 'push'")
                    || !condition.contains("workflow_dispatch")
                    || !condition.contains("cache-primary-key != ''")
                {
                    return Err("save lacks trusted event/always/nonempty key guard".into());
                }
                if !condition.contains("cache-quiescent == 'true'")
                    && !condition.contains("outcome == 'success'")
                    && !(selected_paths == ["~/.cargo/registry/cache", "~/.cargo/git/db"]
                        && condition.contains("success()"))
                {
                    return Err("save lacks settled owner".into());
                }
            }
        }
        for (id, (ordinal, restore)) in restores {
            let paired = saves.remove(id).ok_or_else(|| {
                format!(
                    "unpaired restore {}:{id}",
                    job_name.as_str().unwrap_or_default()
                )
            })?;
            for (save_ordinal, save) in paired {
                if save_ordinal <= ordinal || paths(restore)? != paths(save)? {
                    return Err("restore/save path/order differs".into());
                }
                if output_reference(
                    restore["with"]["key"].as_str().unwrap_or_default(),
                    "product-key",
                )
                .is_some()
                    && !save["if"]
                        .as_str()
                        .unwrap_or_default()
                        .contains("outputs.product-key == steps.")
                {
                    return Err("compiled save lacks unchanged-input context comparison".into());
                }
            }
        }
        if !saves.is_empty() {
            return Err("cache save references missing restore".into());
        }
    }
    Ok(total)
}

#[test]
fn every_workflow_cache_alias_has_a_safe_v4_restore_save_lifecycle() {
    for (name, text) in WORKFLOWS {
        assert!(text.len() <= 512 * 1024);
        let value = serde_yaml::from_str(text).unwrap();
        assert!(validate(&value).unwrap_or_else(|error| panic!("{name}: {error}")) > 0);
    }
}

#[test]
fn sentinel_broad_paths_and_wrong_save_keys_are_rejected() {
    let (_, text) = WORKFLOWS[0];
    let mut original: Value = serde_yaml::from_str(text).unwrap();
    original.apply_merge().unwrap();
    for replacement in [
        "target",
        "target/ci-build",
        "target/ci-consumers",
        "target/ci-tools/bin",
        "target/ci/miri-*",
        ".release/rehearsal-results",
    ] {
        let mut changed = original.clone();
        let job = changed["jobs"]
            .as_mapping_mut()
            .unwrap()
            .values_mut()
            .find(|job| {
                job["steps"].as_sequence().is_some_and(|steps| {
                    steps.iter().any(|step| {
                        step["uses"]
                            .as_str()
                            .is_some_and(|action| action.starts_with("actions/cache/restore@"))
                    })
                })
            })
            .unwrap();
        let step = job["steps"]
            .as_sequence_mut()
            .unwrap()
            .iter_mut()
            .find(|step| {
                step["uses"]
                    .as_str()
                    .is_some_and(|action| action.starts_with("actions/cache/restore@"))
            })
            .unwrap();
        step["with"]["path"] = replacement.into();
        assert!(validate(&changed).is_err(), "{replacement}");
    }
}
