use memcordon_ci::{config, policy};
use serde_yaml::Value;
use std::path::Path;

fn check(file: &str, value: &Value) -> memcordon_ci::Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    policy::validate_workflow_bytes(
        &root,
        Path::new(file),
        serde_yaml::to_string(value).unwrap().as_bytes(),
        &config::policy(&root).unwrap(),
    )
}

#[test]
fn exact_non_release_workflows_and_shard_mutations() {
    for (file, source) in [
        (
            ".github/workflows/ci.yml",
            include_str!("../../../.github/workflows/ci.yml"),
        ),
        (
            ".github/workflows/deep-ci.yml",
            include_str!("../../../.github/workflows/deep-ci.yml"),
        ),
        (
            ".github/workflows/backend-certification.yml",
            include_str!("../../../.github/workflows/backend-certification.yml"),
        ),
    ] {
        let exact: Value = serde_yaml::from_str(source).unwrap();
        check(file, &exact).unwrap_or_else(|error| panic!("{file}: {error}"));
    }
    let exact: Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/deep-ci.yml")).unwrap();
    for family in ["miri", "fuzz"] {
        let mut missing = exact.clone();
        missing["jobs"][family]["strategy"]["matrix"]["shard"]
            .as_sequence_mut()
            .unwrap()
            .pop();
        assert!(check(".github/workflows/deep-ci.yml", &missing).is_err());
        let mut duplicate = exact.clone();
        let shards = duplicate["jobs"][family]["strategy"]["matrix"]["shard"]
            .as_sequence_mut()
            .unwrap();
        shards[1] = shards[0].clone();
        assert!(check(".github/workflows/deep-ci.yml", &duplicate).is_err());
        let mut wrong = exact.clone();
        let steps = wrong["jobs"][family]["steps"].as_sequence_mut().unwrap();
        let prepare = steps
            .iter_mut()
            .find(|step| step["name"].as_str() == Some("Build ordinary CI driver"))
            .unwrap();
        prepare["run"] = Value::String(
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-core"
                .into(),
        );
        assert!(check(".github/workflows/deep-ci.yml", &wrong).is_err());
        let mut substitution = exact.clone();
        let steps = substitution["jobs"][family]["steps"]
            .as_sequence_mut()
            .unwrap();
        let suite = steps
            .iter_mut()
            .find(|step| {
                step["if"]
                    .as_str()
                    .is_some_and(|condition| condition.starts_with("matrix.shard =="))
            })
            .unwrap();
        suite["run"] = Value::String("./target/ci/release/memcordon-ci suite native".into());
        assert!(check(".github/workflows/deep-ci.yml", &substitution).is_err());
    }
}

#[test]
fn windows_native_architecture_runner_and_environment_boundaries_are_exact() {
    let exact: Value = serde_yaml::from_str(include_str!(
        "../../../.github/workflows/backend-certification.yml"
    ))
    .unwrap();
    for (job, wrong_runner) in [
        ("standard-windows", "windows-11-arm"),
        ("standard-windows-arm64", "windows-2025"),
    ] {
        let mut wrong = exact.clone();
        wrong["jobs"][job]["runs-on"] = Value::String(wrong_runner.into());
        assert!(check(".github/workflows/backend-certification.yml", &wrong).is_err());
        let mut changed = exact.clone();
        let steps = changed["jobs"][job]["steps"].as_sequence_mut().unwrap();
        let suite = steps
            .iter_mut()
            .find(|step| {
                step["run"]
                    .as_str()
                    .is_some_and(|run| run.split_whitespace().any(|part| part == "suite"))
            })
            .unwrap();
        suite["env"] = serde_yaml::from_str("CARGO_TARGET_DIR: target/ci/incorrect").unwrap();
        assert!(check(".github/workflows/backend-certification.yml", &changed).is_err());
    }
}

#[test]
fn source_cache_and_duplicate_ordinary_build_controls_cannot_be_weakened() {
    let exact: Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/deep-ci.yml")).unwrap();
    let mut duplicate = exact.clone();
    let steps = duplicate["jobs"]["fuzz"]["steps"]
        .as_sequence_mut()
        .unwrap();
    let ordinal = steps
        .iter()
        .position(|step| step["name"] == "Build ordinary CI driver")
        .unwrap();
    steps.insert(ordinal + 1, steps[ordinal].clone());
    assert!(check(".github/workflows/deep-ci.yml", &duplicate).is_err());
    for mutation in ["staging", "credentials", "success-only"] {
        let mut changed = exact.clone();
        let steps = changed["jobs"]["fuzz"]["steps"].as_sequence_mut().unwrap();
        let cache = steps
            .iter_mut()
            .find(|step| {
                step["uses"]
                    .as_str()
                    .is_some_and(|uses| uses.starts_with("actions/cache/save@"))
            })
            .unwrap();
        match mutation {
            "staging" => cache["with"]["path"] = Value::String("target/ci-tools/staging".into()),
            "credentials" => {
                cache["with"]["path"] = Value::String("~/.cargo/credentials.toml".into())
            }
            "success-only" => cache["if"] = Value::String("success()".into()),
            _ => unreachable!(),
        }
        assert!(
            check(".github/workflows/deep-ci.yml", &changed).is_err(),
            "{mutation}"
        );
    }
}
#[test]
fn stress_phase_evidence_cannot_disappear_or_claim_success_only() {
    let exact: Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/deep-ci.yml")).unwrap();
    for mutation in [
        "missing",
        "duplicate",
        "success-only",
        "missing-seed",
        "missing-active",
        "missing-child",
        "missing-phase",
    ] {
        let mut changed = exact.clone();
        let steps = changed["jobs"]["stress"]["steps"]
            .as_sequence_mut()
            .unwrap();
        let ordinal = steps
            .iter()
            .position(|step| step["with"]["name"] == "stress-combined-${{ matrix.id }}")
            .unwrap();
        match mutation {
            "missing" => {
                steps.remove(ordinal);
            }
            "duplicate" => {
                steps.insert(ordinal + 1, steps[ordinal].clone());
            }
            "success-only" => {
                steps[ordinal]["if"] = Value::String("success()".into());
            }
            other => {
                let omitted = match other {
                    "missing-seed" => "target/ci/reports/stress-seed.txt",
                    "missing-active" => "target/ci/reports/stress-active-target.txt",
                    "missing-child" => "target/ci/reports/stress-deep_short_child_iterations.json",
                    "missing-phase" => "target/ci/reports/stress",
                    _ => unreachable!(),
                };
                steps[ordinal]["with"]["path"] = Value::String(
                    steps[ordinal]["with"]["path"]
                        .as_str()
                        .unwrap()
                        .lines()
                        .filter(|path| *path != omitted)
                        .collect::<Vec<_>>()
                        .join("\n")
                        + "\n",
                );
            }
        }
        assert!(
            check(".github/workflows/deep-ci.yml", &changed).is_err(),
            "{mutation}"
        );
    }
}

#[test]
fn selected_stress_phases_cannot_serialize_share_roots_or_omit_aggregation() {
    let file = ".github/workflows/deep-ci.yml";
    let exact: Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/deep-ci.yml")).unwrap();
    for family in ["stress", "stress-packages", "stress-lifecycle"] {
        for mutation in [
            "serial-edge",
            "static-matrix",
            "conditional-run",
            "shared-root",
        ] {
            let mut changed = exact.clone();
            let job = &mut changed["jobs"][family];
            match mutation {
                "serial-edge" => {
                    job["needs"] = Value::Sequence(vec![
                        Value::String("performance-plan".into()),
                        Value::String("stress-packages".into()),
                    ]);
                }
                "static-matrix" => {
                    job["strategy"]["matrix"]["include"] = Value::Sequence(vec![]);
                }
                other => {
                    let steps = job["steps"].as_sequence_mut().unwrap();
                    let id = if other == "conditional-run" {
                        "stress-run"
                    } else {
                        "compiled"
                    };
                    let step = steps.iter_mut().find(|step| step["id"] == id).unwrap();
                    if other == "conditional-run" {
                        step["if"] = Value::String("success()".into());
                    } else {
                        step["with"]["path"] = Value::String("target/ci/shared-stress".into());
                    }
                }
            }
            assert!(check(file, &changed).is_err(), "{family}: {mutation}");
        }
    }
    for mutation in ["missing-aggregate", "success-only", "missing-phase"] {
        let mut changed = exact.clone();
        match mutation {
            "missing-aggregate" => {
                changed["jobs"]
                    .as_mapping_mut()
                    .unwrap()
                    .remove(Value::String("stress-assessment".into()));
            }
            "success-only" => {
                changed["jobs"]["stress-assessment"]["if"] = Value::String("success()".into())
            }
            "missing-phase" => {
                changed["jobs"]["stress-assessment"]["needs"]
                    .as_sequence_mut()
                    .unwrap()
                    .retain(|need| need.as_str() != Some("stress-lifecycle"));
            }
            _ => unreachable!(),
        }
        assert!(check(file, &changed).is_err(), "{mutation}");
    }
}

#[test]
fn source_cache_paths_select_real_cargo_inputs_without_report_or_credential_custody() {
    let deep: Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/deep-ci.yml")).unwrap();
    for family in [
        "miri",
        "fuzz",
        "stress",
        "stress-packages",
        "stress-lifecycle",
    ] {
        finite_cache_paths(&deep["jobs"][family], family).unwrap();
    }

    let baseline = &deep["jobs"]["miri"];
    for (field, replacement) in [
        ("path", "~/.cargo"),
        ("path", "~/.cargo/credentials.toml"),
        ("path", "target/ci/reports"),
        (
            "key",
            "${{ steps.fuzz-download-context.outputs.source-key }}",
        ),
        (
            "restore-keys",
            "${{ steps.workspace-download-context.outputs.product-restore-prefix }}",
        ),
    ] {
        let mut job = baseline.clone();
        job["steps"]
            .as_sequence_mut()
            .unwrap()
            .iter_mut()
            .find(|step| step["id"] == "workspace-downloads")
            .unwrap()["with"][field] = replacement.into();
        assert_ne!(&job, baseline);
        assert!(finite_cache_paths(&job, "miri").is_err());
    }
    let mut missing_source_context = baseline.clone();
    missing_source_context["steps"]
        .as_sequence_mut()
        .unwrap()
        .retain(|step| step["id"] != "workspace-download-context");
    assert_ne!(&missing_source_context, baseline);
    assert!(finite_cache_paths(&missing_source_context, "miri").is_err());
    for replacement in [
        "~/.cargo",
        "~/.cargo/credentials.toml",
        "~/.cargo/registry/index\n~/.cargo/registry/cache\n~/.cargo/git/db",
    ] {
        let mut job = baseline.clone();
        job["steps"]
            .as_sequence_mut()
            .unwrap()
            .iter_mut()
            .find(|step| step["id"] == "miri-deps")
            .unwrap()["with"]["path"] = replacement.into();
        assert_ne!(&job, baseline);
        assert!(finite_cache_paths(&job, "miri").is_err());
    }
    for replacement in [
        "target/ci/reports",
        "target/ci-build",
        "target/ci/miri-*",
        "${{ steps.compiled-context-second.outputs.product-paths }}",
    ] {
        let mut job = baseline.clone();
        job["steps"]
            .as_sequence_mut()
            .unwrap()
            .iter_mut()
            .find(|step| step["id"] == "compiled-first")
            .unwrap()["with"]["path"] = replacement.into();
        assert_ne!(&job, baseline);
        assert!(finite_cache_paths(&job, "miri").is_err());
    }
    for id in ["compiled-first", "compiled-context-second"] {
        let mut job = baseline.clone();
        job["steps"]
            .as_sequence_mut()
            .unwrap()
            .retain(|step| step["id"] != id);
        assert_ne!(&job, baseline);
        assert!(finite_cache_paths(&job, "miri").is_err());
    }
    let mut job = baseline.clone();
    job["steps"]
        .as_sequence_mut()
        .unwrap()
        .iter_mut()
        .find(|step| step["with"]["key"] == "${{ steps.compiled-first.outputs.cache-primary-key }}")
        .unwrap()["with"]["path"] = "target/ci/reports".into();
    assert_ne!(&job, baseline);
    assert!(finite_cache_paths(&job, "miri").is_err());
    let baseline = &deep["jobs"]["fuzz"];
    for (id, path) in [
        ("cache-cargo-fuzz-binary", "target/ci-tools/bin"),
        ("cache-cargo-fuzz-build", "target/ci-tools-build"),
    ] {
        let mut job = baseline.clone();
        job["steps"]
            .as_sequence_mut()
            .unwrap()
            .iter_mut()
            .find(|step| step["id"] == id)
            .unwrap()["with"]["path"] = path.into();
        assert_ne!(&job, baseline);
        assert!(finite_cache_paths(&job, "fuzz").is_err());
    }
}

fn finite_cache_paths(job: &Value, family: &str) -> Result<(), String> {
    let require = |valid: bool| {
        valid
            .then_some(())
            .ok_or_else(|| "cache role or custody differs".to_owned())
    };
    let steps = job["steps"].as_sequence().ok_or("steps absent")?;
    let shards: &[&str] = match family {
        "miri" => &["first", "second"],
        "fuzz" => &[
            "quarter-one",
            "quarter-two",
            "quarter-three",
            "quarter-four",
        ],
        "stress" | "stress-packages" | "stress-lifecycle" => &["complete"],
        _ => return Err("unknown family".into()),
    };
    let reference =
        |context: &str, output: &str| format!("${{{{ steps.{context}.outputs.{output} }}}}");
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut source_roles = std::collections::BTreeMap::from([(
        "workspace-downloads",
        (
            "workspace-download-context",
            memcordon_ci::download_cache::DownloadFamily::Workspace,
        ),
    )]);
    if family == "fuzz" {
        source_roles.insert(
            "fuzz-downloads",
            (
                "fuzz-download-context",
                memcordon_ci::download_cache::DownloadFamily::Fuzz,
            ),
        );
        source_roles.insert(
            "cache-cargo-fuzz-downloads",
            (
                "cache-cargo-fuzz",
                memcordon_ci::download_cache::DownloadFamily::ToolCargoFuzz,
            ),
        );
    }
    let mut roles = std::collections::BTreeMap::new();
    for shard in shards {
        let (id, context) = if *shard == "complete" {
            ("compiled".to_owned(), "compiled-context".to_owned())
        } else {
            (
                format!("compiled-{shard}"),
                format!("compiled-context-{shard}"),
            )
        };
        let declarations: Vec<_> = steps
            .iter()
            .filter(|step| step["id"].as_str() == Some(&context))
            .collect();
        require(declarations.len() == 1)?;
        require(
            declarations[0]["run"].as_str()
                == Some(&format!(
                    "./target/ci/release/memcordon-ci ci cache-context --purpose {family} --shard {shard}"
                )),
        )?;
        if *shard != "complete" {
            require(declarations[0]["if"].as_str() == Some(&format!("matrix.shard == '{shard}'")))?;
        }
        let roots =
            memcordon_ci::cache_restore::roots(family, shard).map_err(|error| error.to_string())?;
        roles.insert(
            id,
            (
                reference(&context, "product-key"),
                reference(&context, "product-paths"),
                Some(reference(&context, "product-restore-prefix")),
                roots,
            ),
        );
    }
    if family == "fuzz" {
        require(steps.iter().filter(|step| step["id"] == "cache-cargo-fuzz" && step["run"] == "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-fuzz --shard complete").count() == 1)?;
        for (id, key, path, roots) in [
            (
                "cache-cargo-fuzz-binary",
                "tool-key",
                "tool-path",
                vec![
                    memcordon_ci::preparation::auxiliary_tool(Path::new(""), "cargo-fuzz")
                        .map_err(|error| error.to_string())?,
                ],
            ),
            (
                "cache-cargo-fuzz-build",
                "tool-build-key",
                "tool-build-path",
                vec!["target/ci-tools-build/cargo-fuzz".into()],
            ),
        ] {
            roles.insert(
                id.into(),
                (
                    reference("cache-cargo-fuzz", key),
                    reference("cache-cargo-fuzz", path),
                    None,
                    roots,
                ),
            );
        }
    }
    let mut downloads = 0;
    let mut saves = 0;
    let mut paired_saves = 0;
    let mut seen = std::collections::BTreeSet::new();
    for (ordinal, step) in steps.iter().enumerate() {
        let Some(uses) = step["uses"].as_str() else {
            continue;
        };
        if uses.starts_with("actions/cache/save@") {
            saves += 1;
            continue;
        }
        if !uses.starts_with("actions/cache/restore@") {
            continue;
        }
        let id = step["id"].as_str().ok_or("restore id absent")?;
        require(seen.insert(id))?;
        let key = step["with"]["key"].as_str().ok_or("restore key absent")?;
        let path = step["with"]["path"].as_str().ok_or("restore path absent")?;
        let source_role = source_roles.remove(id);
        if key.starts_with("mc-download-bootstrap-v5-${{ runner.os }}-") {
            downloads += 1;
            require(
                path.lines().collect::<Vec<_>>() == ["~/.cargo/registry/cache", "~/.cargo/git/db"],
            )?;
            require(
                key == "mc-download-bootstrap-v5-${{ runner.os }}-${{ hashFiles('Cargo.lock', 'Cargo.toml', '.cargo/**', 'ci/toolchains.toml') }}"
                    && step["if"].as_str().is_some_and(|condition| {
                        condition.contains("hashFiles('Cargo.lock') != ''")
                    }),
            )?;
            if family == "fuzz" {
                require(step["if"].as_str().is_some_and(|condition| {
                    condition.contains("hashFiles('fuzz/Cargo.lock') != ''")
                }))?;
            }
        } else if let Some((context, source_family)) = source_role {
            require(key == reference(context, "source-key"))?;
            require(path == reference(context, "source-paths"))?;
            require(
                step["with"]["restore-keys"].as_str()
                    == Some(&reference(context, "source-restore-prefix")),
            )?;
            let command = if source_family
                == memcordon_ci::download_cache::DownloadFamily::ToolCargoFuzz
            {
                "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-fuzz --shard complete".to_owned()
            } else {
                format!(
                    "./target/ci/release/memcordon-ci ci download-cache-context --family {}",
                    source_family.name()
                )
            };
            require(
                steps[..ordinal]
                    .iter()
                    .filter(|candidate| {
                        candidate["id"] == context && candidate["run"].as_str() == Some(&command)
                    })
                    .count()
                    == 1,
            )?;
            let cwd = if source_family == memcordon_ci::download_cache::DownloadFamily::Fuzz {
                repository.join("fuzz")
            } else {
                repository.clone()
            };
            let home = memcordon_ci::download_cache::cargo_home(&cwd)
                .map_err(|error| error.to_string())?;
            for root in [home.join("registry/cache"), home.join("git/db")] {
                require(root.is_absolute())?;
                require(!root.to_string_lossy().contains('*'))?;
                require(!home.join("credentials.toml").starts_with(&root))?;
                require(!home.join("config.toml").starts_with(&root))?;
                require(!repository.join("target/ci/reports").starts_with(&root))?;
            }
        } else {
            let (expected_key, expected_path, prefix, roots) =
                roles.remove(id).ok_or("unknown restore role")?;
            require(key == expected_key && path == expected_path)?;
            if let Some(prefix) = prefix {
                require(step["with"]["restore-keys"].as_str() == Some(&prefix))?;
                if let Some(shard) = id.strip_prefix("compiled-") {
                    require(step["if"].as_str().is_some_and(|condition| {
                        condition.contains(&format!("matrix.shard == '{shard}'"))
                    }))?;
                }
            }
            for root in roots {
                require(!root.to_string_lossy().contains('*'))?;
                for excluded in [
                    ".release/prepared",
                    "target/ci/reports",
                    "target/ci/deadline-evidence",
                    "target/ci-consumers/capture",
                    "target/ci-build/package-staging",
                    "~/.cargo/credentials.toml",
                    "~/.cargo/config.toml",
                ] {
                    require(!Path::new(excluded).starts_with(&root))?;
                }
                if family == "miri" {
                    let other = if id == "compiled-first" {
                        "target/ci/miri-second"
                    } else {
                        "target/ci/miri-first"
                    };
                    require(!Path::new(other).starts_with(root))?;
                }
            }
        }
        let paired: Vec<_> = steps
            .iter()
            .enumerate()
            .filter(|(_, save)| {
                save["uses"]
                    .as_str()
                    .is_some_and(|uses| uses.starts_with("actions/cache/save@"))
                    && save["with"]["key"].as_str() == Some(&reference(id, "cache-primary-key"))
            })
            .collect();
        require(if source_role.is_some() {
            paired.len() <= 1
        } else {
            paired.len() == 1
        })?;
        for (save_ordinal, save) in &paired {
            require(*save_ordinal > ordinal && save["with"]["path"].as_str() == Some(path))?;
        }
        paired_saves += paired.len();
    }
    require(
        downloads == 1 && roles.is_empty() && source_roles.is_empty() && saves == paired_saves,
    )?;
    // The finite catalog checks custody; production policy checks every declared
    // save's current population, owner settlement and recomputed recipe identity.
    let mut workflow: Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/deep-ci.yml")).unwrap();
    workflow["jobs"][family] = job.clone();
    check(".github/workflows/deep-ci.yml", &workflow).map_err(|error| error.to_string())
}
