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
        let driver_owner = if family == "fuzz" {
            "fuzz-setup"
        } else {
            family
        };
        let steps = wrong["jobs"][driver_owner]["steps"]
            .as_sequence_mut()
            .unwrap();
        let prepare = steps
            .iter_mut()
            .find(|step| step["id"] == "driver-cold-build")
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
                step["id"]
                    == if family == "miri" {
                        "miri-quarter-one"
                    } else {
                        "fuzz-one"
                    }
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
            .find(|step| step["id"] == "backend-run")
            .unwrap();
        suite["env"] = serde_yaml::from_str("CARGO_TARGET_DIR: target/ci/incorrect").unwrap();
        assert!(check(".github/workflows/backend-certification.yml", &changed).is_err());
    }
}

#[test]
fn source_cache_and_duplicate_ordinary_build_controls_cannot_be_weakened() {
    let exact: Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/deep-ci.yml")).unwrap();
    for (job, id) in [
        ("fuzz", "fuzz-current-probe"),
        ("fuzz-setup", "driver-cold-build"),
    ] {
        let mut duplicate = exact.clone();
        let steps = duplicate["jobs"][job]["steps"].as_sequence_mut().unwrap();
        let ordinal = steps.iter().position(|step| step["id"] == id).unwrap();
        steps.insert(ordinal + 1, steps[ordinal].clone());
        assert!(
            check(".github/workflows/deep-ci.yml", &duplicate).is_err(),
            "duplicate {job}/{id}"
        );
    }
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
                        "stress-run-request-compiled-complete-restore"
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
        "fuzz-setup",
        "stress",
        "stress-packages",
        "stress-lifecycle",
    ] {
        finite_cache_paths(&deep["jobs"][family], family)
            .unwrap_or_else(|error| panic!("{family}: {error}"));
    }

    let baseline = &deep["jobs"]["miri"];
    for (field, replacement) in [
        ("path", "~/.cargo"),
        ("path", "~/.cargo/credentials.toml"),
        ("path", "target/ci/reports"),
        (
            "key",
            "${{ steps.shard-fuzz-fetch-request.outputs.source-key }}",
        ),
        (
            "restore-keys",
            "${{ steps.workspace-fetch-request.outputs.product-restore-prefix }}",
        ),
    ] {
        let mut job = baseline.clone();
        job["steps"]
            .as_sequence_mut()
            .unwrap()
            .iter_mut()
            .find(|step| step["id"] == "workspace-fetch-request-source-restore")
            .unwrap()["with"][field] = replacement.into();
        assert_ne!(&job, baseline);
        assert!(finite_cache_paths(&job, "miri").is_err());
    }
    let mut missing_source_context = baseline.clone();
    missing_source_context["steps"]
        .as_sequence_mut()
        .unwrap()
        .retain(|step| step["id"] != "workspace-fetch-request");
    assert_ne!(&missing_source_context, baseline);
    assert!(finite_cache_paths(&missing_source_context, "miri").is_err());
    let mut unknown = baseline.clone();
    let mut extra = unknown["steps"]
        .as_sequence()
        .unwrap()
        .iter()
        .find(|step| step["id"] == "workspace-fetch-request-source-restore")
        .unwrap()
        .clone();
    extra["id"] = "unowned-source-restore".into();
    unknown["steps"].as_sequence_mut().unwrap().push(extra);
    assert!(finite_cache_paths(&unknown, "miri").is_err());
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
        "${{ steps.miri-quarter-two-request.outputs.compiled-complete-inbox }}",
    ] {
        let mut job = baseline.clone();
        job["steps"]
            .as_sequence_mut()
            .unwrap()
            .iter_mut()
            .find(|step| step["id"] == "miri-quarter-one-request-compiled-complete-restore")
            .unwrap()["with"]["path"] = replacement.into();
        assert_ne!(&job, baseline);
        assert!(finite_cache_paths(&job, "miri").is_err());
    }
    for id in [
        "miri-quarter-one-request-compiled-complete-restore",
        "miri-quarter-two-request",
    ] {
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
        .find(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|uses| uses.starts_with("actions/cache/save@"))
                && step["with"]["key"]
                    == "${{ steps.miri-quarter-one.outputs.compiled-complete-key }}"
        })
        .unwrap()["with"]["path"] = "target/ci/reports".into();
    assert_ne!(&job, baseline);
    assert!(finite_cache_paths(&job, "miri").is_err());
    let baseline = &deep["jobs"]["fuzz-setup"];
    for (id, path) in [
        (
            "prepare-fuzz-request-cargo-fuzz-image-restore",
            "target/ci-tools/bin",
        ),
        (
            "prepare-fuzz-request-cargo-fuzz-complete-restore",
            "target/ci-tools-build",
        ),
    ] {
        let mut job = baseline.clone();
        job["steps"]
            .as_sequence_mut()
            .unwrap()
            .iter_mut()
            .find(|step| step["id"] == id)
            .unwrap()["with"]["path"] = path.into();
        assert_ne!(&job, baseline);
        assert!(finite_cache_paths(&job, "fuzz-setup").is_err());
    }
}

fn finite_cache_paths(job: &Value, family: &str) -> Result<(), String> {
    use std::collections::{BTreeMap, BTreeSet};
    #[track_caller]
    fn require(valid: bool) -> Result<(), String> {
        let caller = std::panic::Location::caller();
        valid
            .then_some(())
            .ok_or_else(|| format!("cache role or custody differs at {caller}"))
    }
    fn reference(owner: &str, field: &str) -> String {
        format!("${{{{ steps.{owner}.outputs.{field} }}}}")
    }
    fn equal<T: std::fmt::Debug + PartialEq>(
        family: &str,
        role: &str,
        field: &str,
        actual: T,
        expected: T,
    ) -> Result<(), String> {
        if actual == expected {
            Ok(())
        } else {
            Err(format!(
                "{family}/{role} {field}: expected {expected:?}, actual {actual:?}"
            ))
        }
    }
    fn protected(roots: &[std::path::PathBuf]) -> Result<(), String> {
        for root in roots {
            require(!root.as_os_str().is_empty() && !root.to_string_lossy().contains('*'))?;
            for excluded in [
                ".release/prepared",
                "target/ci/reports",
                "target/ci/deadline-evidence",
                "target/ci-consumers/capture",
                "target/ci-build/package-staging",
                "~/.cargo/credentials.toml",
                "~/.cargo/config.toml",
            ] {
                require(!Path::new(excluded).starts_with(root))?;
            }
        }
        Ok(())
    }
    // Independent catalog: request/save roles are derived from native operation
    // names, never accepted from the YAML's key/path strings or renderer output.
    fn slots(recipe: &str, request: bool) -> Result<Vec<String>, String> {
        let source = if request { "source" } else { "source-complete" };
        let mut result: Vec<String> = match recipe {
            "workspace-fetch" | "fuzz-fetch" | "miri-setup" | "prepare-fuzz" => {
                [source, "archives-partial", "index-partial"]
                    .map(str::to_owned)
                    .into()
            }
            "driver-context" if request => ["image", "compiled-complete", "compiled-partial"]
                .map(str::to_owned)
                .into(),
            "driver-build" if !request => [
                "bootstrap",
                "image",
                "compiled-complete",
                "compiled-partial",
                "source-complete",
                "archives-partial",
                "index-partial",
            ]
            .map(str::to_owned)
            .into(),
            "driver-adopt-cold" if !request => [
                "bootstrap",
                "source-complete",
                "archives-partial",
                "index-partial",
            ]
            .map(str::to_owned)
            .into(),
            "prepare-miri-components" => Vec::new(),
            value
                if value.starts_with("miri-quarter-")
                    || value.starts_with("fuzz-compile-quarter-")
                    || value.starts_with("fuzz-execute-quarter-")
                    || matches!(value, "stress" | "stress-packages" | "stress-lifecycle") =>
            {
                ["compiled-complete", "compiled-partial"]
                    .map(str::to_owned)
                    .into()
            }
            _ => return Err(format!("unknown finite recipe {recipe}")),
        };
        if recipe == "miri-setup" {
            result.push("sysroot".into());
        }
        if recipe == "prepare-fuzz" {
            result.extend(
                if request {
                    [
                        "cargo-fuzz-image",
                        "cargo-fuzz-source",
                        "cargo-fuzz-complete",
                        "cargo-fuzz-partial",
                    ]
                } else {
                    [
                        "cargo-fuzz-image",
                        "cargo-fuzz-source-complete",
                        "cargo-fuzz-complete",
                        "cargo-fuzz-partial",
                    ]
                }
                .map(str::to_owned),
            );
        }
        // Execution consumes the compiler's owned targets, never a second inbox.
        if request && recipe.starts_with("fuzz-execute-") {
            return Err("execution cache reimport".into());
        }
        Ok(result)
    }
    let steps = job["steps"].as_sequence().ok_or("steps absent")?;
    // id -> (save, key, path, prefix, guard, lookup-only, producer ordinal).
    let mut expected =
        BTreeMap::<String, (bool, String, String, Option<String>, String, bool, usize)>::new();
    let mut recipes = BTreeSet::new();
    for (ordinal, step) in steps.iter().enumerate() {
        let Some(run) = step["run"].as_str() else {
            continue;
        };
        let operation = run
            .split_once(" ci cache-requests ")
            .map(|(_, recipe)| (recipe, true))
            .or_else(|| {
                run.split_once(" ci segment ")
                    .map(|(_, recipe)| (recipe, false))
            })
            .or_else(|| {
                ["driver-context", "driver-build", "driver-adopt-cold"]
                    .into_iter()
                    .find(|recipe| run.ends_with(&format!(" ci {recipe}")))
                    .map(|recipe| (recipe, recipe == "driver-context"))
            });
        let Some((recipe, request)) = operation else {
            continue;
        };
        let role_slots = slots(recipe, request)?;
        if role_slots.is_empty() {
            continue;
        }
        let owner = step["id"].as_str().ok_or("finite owner id absent")?;
        require(!owner.is_empty())?;
        recipes.insert(recipe.to_owned());
        if let Some(quarter) = recipe.strip_prefix("miri-quarter-") {
            let shard = format!("quarter-{quarter}");
            let roots =
                memcordon_ci::cache_restore::roots("miri", &shard).map_err(|e| e.to_string())?;
            require(roots == vec![Path::new("target/ci").join(format!("miri-{shard}"))])?;
            protected(&roots)?;
            for other in ["one", "two", "three", "four"]
                .into_iter()
                .filter(|other| *other != quarter)
            {
                require(
                    !Path::new("target/ci")
                        .join(format!("miri-quarter-{other}"))
                        .starts_with(&roots[0]),
                )?;
            }
        } else if let Some(quarter) = recipe
            .strip_prefix("fuzz-compile-quarter-")
            .or_else(|| recipe.strip_prefix("fuzz-execute-quarter-"))
        {
            let roots = memcordon_ci::cache_restore::roots("fuzz", &format!("quarter-{quarter}"))
                .map_err(|e| e.to_string())?;
            require(roots == vec![std::path::PathBuf::from("fuzz/target")])?;
            protected(&roots)?;
        } else if matches!(recipe, "stress" | "stress-packages" | "stress-lifecycle") {
            let roots = memcordon_ci::cache_restore::roots(recipe, "complete")
                .map_err(|e| e.to_string())?;
            require(roots == vec![Path::new("target/ci").join(recipe)])?;
            protected(&roots)?;
        }
        if recipe == "prepare-fuzz" {
            let layout = memcordon_ci::cache_restore::tool_build_layout("cargo-fuzz", "complete")
                .map_err(|e| e.to_string())?;
            require(
                layout.directories
                    == vec![std::path::PathBuf::from("target/ci-tools-build/cargo-fuzz")],
            )?;
            protected(&layout.directories)?;
            let image = memcordon_ci::preparation::auxiliary_tool(Path::new(""), "cargo-fuzz")
                .map_err(|e| e.to_string())?;
            require(image.parent() == Some(Path::new("target/ci-tools/bin")))?;
            protected(&[image])?;
        }
        for slot in role_slots {
            let key = reference(owner, &format!("{slot}-key"));
            let ready = format!(
                "steps.{owner}.outputs.{slot}-{}",
                if request { "restore" } else { "save" }
            );
            if request {
                let direct = matches!(
                    slot.as_str(),
                    "source" | "sysroot" | "cargo-fuzz-image" | "cargo-fuzz-source"
                );
                let path = reference(
                    owner,
                    &format!("{slot}-{}", if direct { "path" } else { "inbox" }),
                );
                let mut guard = format!("{ready} == 'true'");
                if recipe == "driver-context" && slot.starts_with("compiled-") {
                    let selection = match owner {
                        "driver-context" => "driver-selection",
                        "driver-context-windows" => "driver-selection-windows",
                        _ => return Err("driver context name".into()),
                    };
                    guard =
                        format!("steps.{selection}.outputs.build-required == 'true' && {guard}");
                }
                require(
                    expected
                        .insert(
                            format!("{owner}-{slot}-restore"),
                            (
                                false,
                                key,
                                path,
                                Some(reference(owner, &format!("{slot}-prefix"))),
                                guard,
                                false,
                                ordinal,
                            ),
                        )
                        .is_none(),
                )?;
            } else {
                let path = reference(owner, &format!("{slot}-path"));
                let guard = format!("always() && {ready} == 'true'");
                let partial = slot.ends_with("partial");
                if !partial {
                    require(
                        expected
                            .insert(
                                format!("{owner}-{slot}-probe"),
                                (
                                    false,
                                    key.clone(),
                                    path.clone(),
                                    None,
                                    guard.clone(),
                                    true,
                                    ordinal,
                                ),
                            )
                            .is_none(),
                    )?;
                }
                let save_guard = if partial {
                    guard
                } else {
                    format!("{guard} && steps.{owner}-{slot}-probe.outputs.cache-hit != 'true'")
                };
                require(
                    expected
                        .insert(
                            format!("{owner}-{slot}-save"),
                            (true, key, path, None, save_guard, false, ordinal),
                        )
                        .is_none(),
                )?;
            }
        }
    }
    for recipe in match family {
        "miri" => vec![
            "workspace-fetch",
            "miri-setup",
            "miri-quarter-one",
            "miri-quarter-two",
            "miri-quarter-three",
            "miri-quarter-four",
        ],
        "fuzz" => vec![
            "workspace-fetch",
            "fuzz-fetch",
            "fuzz-compile-quarter-one",
            "fuzz-compile-quarter-two",
            "fuzz-compile-quarter-three",
            "fuzz-compile-quarter-four",
            "fuzz-execute-quarter-one",
            "fuzz-execute-quarter-two",
            "fuzz-execute-quarter-three",
            "fuzz-execute-quarter-four",
        ],
        "fuzz-setup" => vec!["workspace-fetch", "prepare-fuzz"],
        "stress" | "stress-packages" | "stress-lifecycle" => vec!["workspace-fetch", family],
        _ => return Err("unknown family".into()),
    } {
        if !recipes.contains(recipe) {
            return Err(format!(
                "{family}: required recipe {recipe} absent from {recipes:?}"
            ));
        }
    }
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let home = memcordon_ci::download_cache::cargo_home(&repository).map_err(|e| e.to_string())?;
    for root in [home.join("registry/cache"), home.join("git/db")] {
        require(root.is_absolute() && !root.to_string_lossy().contains('*'))?;
        require(
            !home.join("credentials.toml").starts_with(&root)
                && !home.join("config.toml").starts_with(&root),
        )?;
        require(!repository.join("target/ci/reports").starts_with(&root))?;
    }
    let mut downloads = 0;
    let mut bootstraps = 0;
    let mut seen = BTreeSet::new();
    for (ordinal, step) in steps.iter().enumerate() {
        let Some(uses) = step["uses"].as_str() else {
            continue;
        };
        let save = uses.starts_with("actions/cache/save@");
        if !save && !uses.starts_with("actions/cache/restore@") {
            continue;
        }
        let id = step["id"].as_str().ok_or("cache id absent")?;
        require(seen.insert(id))?;
        let key = step["with"]["key"].as_str().ok_or("cache key absent")?;
        let path = step["with"]["path"].as_str().ok_or("cache path absent")?;
        if key.starts_with("mc-download-bootstrap-v5-") {
            downloads += 1;
            require(
                !save
                    && path.lines().collect::<Vec<_>>()
                        == ["~/.cargo/registry/cache", "~/.cargo/git/db"],
            )?;
            require(
                key == "mc-download-bootstrap-v5-${{ runner.os }}-${{ hashFiles('Cargo.lock', 'Cargo.toml', '.cargo/**', 'ci/toolchains.toml') }}",
            )?;
            let guard = step["if"].as_str().ok_or("download guard absent")?;
            require(guard.contains("hashFiles('Cargo.lock') != ''"))?;
            if family.starts_with("fuzz") {
                require(guard.contains("hashFiles('fuzz/Cargo.lock') != ''"))?;
            }
            continue;
        }
        if key.starts_with("mc-ci-bootstrap-v1-") {
            bootstraps += 1;
            require(
                id == "driver-bootstrap-cache"
                    || (family.starts_with("stress") && id == "driver-bootstrap-cache-windows"),
            )?;
            require(!save && path == "target/ci-bootstrap-in")?;
            require(
                key == "mc-ci-bootstrap-v1-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/driver-bootstrap.toml', 'ci/toolchains.toml') }}-lookup",
            )?;
            require(
                step["with"]["restore-keys"]
                    == "mc-ci-bootstrap-v1-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/driver-bootstrap.toml', 'ci/toolchains.toml') }}-",
            )?;
            continue;
        }
        let (expected_save, expected_key, expected_path, prefix, guard, probe, owner) = expected
            .remove(id)
            .ok_or_else(|| format!("unknown cache role {id}"))?;
        equal(family, id, "owner precedes cache", owner < ordinal, true)?;
        equal(family, id, "save action", save, expected_save)?;
        equal(family, id, "key", key, expected_key.as_str())?;
        equal(family, id, "path", path, expected_path.as_str())?;
        equal(family, id, "if", step["if"].as_str(), Some(guard.as_str()))?;
        equal(
            family,
            id,
            "lookup-only",
            step["with"]["lookup-only"].as_bool().unwrap_or(false),
            probe,
        )?;
        equal(
            family,
            id,
            "restore-keys",
            step["with"]["restore-keys"].as_str(),
            prefix.as_deref(),
        )?;
        equal(
            family,
            id,
            "continue-on-error",
            step["continue-on-error"].as_bool(),
            Some(true),
        )?;
    }
    require(downloads == usize::from(family != "fuzz"))?;
    require(
        bootstraps
            == if family == "fuzz" {
                0
            } else if family.starts_with("stress") {
                2
            } else {
                1
            },
    )?;
    require(expected.is_empty())?;
    // Additional integration validation, after independent role and root checks.
    let mut workflow: Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/deep-ci.yml")).unwrap();
    workflow["jobs"][family] = job.clone();
    check(".github/workflows/deep-ci.yml", &workflow).map_err(|error| error.to_string())
}
