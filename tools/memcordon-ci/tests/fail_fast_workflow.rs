use serde_yaml::Value;
use std::collections::{BTreeMap, BTreeSet};

fn workflow() -> Value {
    let mut value: Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/release.yml")).unwrap();
    value.apply_merge().unwrap();
    value
}

fn needs(job: &Value) -> Result<BTreeSet<String>, String> {
    match &job["needs"] {
        Value::Null => Ok(BTreeSet::new()),
        Value::String(value) => Ok(BTreeSet::from([value.clone()])),
        Value::Sequence(values) if values.len() <= 128 => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| "non-string dependency".into())
            })
            .collect(),
        _ => Err("invalid dependency list".into()),
    }
}

fn ancestors(
    name: &str,
    graph: &BTreeMap<String, BTreeSet<String>>,
    visiting: &mut BTreeSet<String>,
) -> Result<BTreeSet<String>, String> {
    if !visiting.insert(name.into()) {
        return Err("workflow cycle".into());
    }
    let mut result = BTreeSet::new();
    for parent in graph
        .get(name)
        .ok_or_else(|| format!("dangling dependency {name}"))?
    {
        result.insert(parent.clone());
        result.extend(ancestors(parent, graph, visiting)?);
    }
    visiting.remove(name);
    Ok(result)
}

fn validate(value: &Value) -> Result<(), String> {
    let jobs = value["jobs"].as_mapping().ok_or("missing jobs")?;
    if jobs.len() > 256 {
        return Err("job bound exceeded".into());
    }
    let graph = jobs
        .iter()
        .map(|(key, job)| {
            Ok((
                key.as_str().ok_or("non-string job")?.to_owned(),
                needs(job)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    for name in graph.keys() {
        ancestors(name, &graph, &mut BTreeSet::new())?;
    }
    let select_only = BTreeSet::from(["select".to_owned()]);
    for name in [
        "source-checks",
        "source-docs",
        "msrv",
        "supply-chain-audit",
        "supply-chain-deny",
        "rehearsal-tool",
        "fuzz-setup",
    ] {
        if graph.get(name) != Some(&select_only) {
            return Err(format!("{name} must be independent after select"));
        }
    }
    if graph.contains_key("supply-chain") {
        return Err("combined security must not duplicate required leaves".into());
    }
    for host in [
        "linux-x64",
        "linux-arm64",
        "macos-x64",
        "macos-arm64",
        "windows-x64",
        "windows-arm64",
    ] {
        let preparation = format!("test-tools-{host}");
        let native = format!("native-{host}");
        let expected_native = BTreeSet::from(["select".to_owned(), preparation.clone()]);
        if graph.get(&preparation) != Some(&select_only)
            || graph.get(&native) != Some(&expected_native)
        {
            return Err(format!(
                "{native} must require its selected-source helper preparation"
            ));
        }
        for (name, parents) in &graph {
            if (name.starts_with(&format!("candidate-{host}-"))
                || name.starts_with(&format!("installed-{host}-")))
                && (!parents.contains(&native) || !parents.contains(&preparation))
            {
                return Err(format!(
                    "{name} must require native success and the same-host preparation"
                ));
            }
        }
    }
    if graph.get("fuzz")
        != Some(&BTreeSet::from([
            "select".to_owned(),
            "fuzz-setup".to_owned(),
        ]))
    {
        return Err("fuzz must require actual selected-source setup".into());
    }
    let early = [
        "select",
        "packages",
        "native-linux-x64",
        "native-linux-arm64",
        "native-macos-x64",
        "native-macos-arm64",
        "native-windows-x64",
        "native-windows-arm64",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if graph.get("assemble-payload") != Some(&early) {
        return Err("early assembly inputs differ".into());
    }
    let rehearsal = ["select", "assemble-payload", "rehearsal-tool"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    if graph.get("rehearse") != Some(&rehearsal) {
        return Err("rehearsal must consume early assembly and independent helper".into());
    }
    let final_ancestors = ancestors("assemble", &graph, &mut BTreeSet::new())?;
    for required in [
        "format",
        "source-policy",
        "source-checks",
        "source-docs",
        "msrv",
        "supply-chain-audit",
        "supply-chain-deny",
        "miri",
        "fuzz",
        "fuzz-setup",
        "test-tools-linux-x64",
        "test-tools-linux-arm64",
        "test-tools-macos-x64",
        "test-tools-macos-arm64",
        "test-tools-windows-x64",
        "test-tools-windows-arm64",
        "native-macos-x64-shard-0",
        "native-macos-x64-shard-1",
        "native-macos-x64-shard-2",
        "native-macos-x64-shard-3",
        "rehearse",
        "assemble-payload",
        "candidate-linux-x64-native",
        "candidate-linux-x64-cargo",
        "candidate-linux-arm64-native",
        "candidate-linux-arm64-cargo",
        "candidate-windows-x64-native",
        "candidate-windows-x64-cargo",
        "candidate-windows-arm64-native",
        "candidate-windows-arm64-cargo",
        "installed-macos-x64-native",
        "installed-macos-x64-cargo",
        "installed-macos-arm64-native",
        "installed-macos-arm64-cargo",
    ] {
        if !final_ancestors.contains(required) {
            return Err(format!("final assembly missing {required}"));
        }
    }
    for job in ["assemble", "publish", "recovery-publish"] {
        let condition = jobs[job]["if"].as_str().unwrap_or_default();
        if ["always()", "failure()", "cancelled()", "!= 'failure'"]
            .iter()
            .any(|token| condition.contains(token))
        {
            return Err(format!("{job} bypasses prerequisite success"));
        }
    }
    for name in graph.keys().filter(|name| {
        name.starts_with("test-tools-")
            || name.starts_with("native-")
            || name.starts_with("candidate-")
            || name.starts_with("installed-")
            || matches!(
                name.as_str(),
                "source-checks"
                    | "source-docs"
                    | "supply-chain-audit"
                    | "supply-chain-deny"
                    | "fuzz-setup"
            )
    }) {
        let condition = jobs[name.as_str()]["if"].as_str().unwrap_or_default();
        if ["always()", "failure()", "cancelled()", "!= 'failure'"]
            .iter()
            .any(|token| condition.contains(token))
        {
            return Err(format!("{name} bypasses required preparation success"));
        }
    }
    for (writer, rehearsal) in [
        ("publish", "rehearse"),
        ("recovery-publish", "recovery-rehearse"),
    ] {
        let closure = ancestors(writer, &graph, &mut BTreeSet::new())?;
        if !closure.contains(rehearsal) {
            return Err(format!("{writer} omits real rehearsal"));
        }
        if writer == "publish" && !closure.contains("assemble") {
            return Err("publisher bypasses final assembly".into());
        }
        if writer == "recovery-publish"
            && [
                "format",
                "source-policy",
                "source-checks",
                "source-docs",
                "msrv",
                "supply-chain-audit",
                "supply-chain-deny",
                "fuzz-setup",
                "native-macos-x64-shard-0",
                "native-macos-x64-shard-1",
                "native-macos-x64-shard-2",
                "native-macos-x64-shard-3",
                "assemble-payload",
                "assemble",
            ]
            .iter()
            .any(|job| closure.contains(*job))
        {
            return Err("recovery unexpectedly rebuilds current preparation".into());
        }
        if jobs[writer]["concurrency"]["group"].as_str() != Some("memcordon-publication")
            || jobs[writer]["concurrency"]["cancel-in-progress"].as_bool() != Some(false)
        {
            return Err("publication serialization changed".into());
        }
    }
    for platform in ["linux-x64", "linux-arm64", "windows-x64", "windows-arm64"] {
        for channel in ["native", "cargo"] {
            let name = format!("public-{platform}-{channel}");
            if !jobs.contains_key(Value::String(name.clone())) {
                return Err(format!("missing {name}"));
            }
        }
    }
    for name in ["public-windows-x64-native", "public-windows-x64-cargo"] {
        let job = &jobs[name];
        let rows = job["strategy"]["matrix"]["include"]
            .as_sequence()
            .ok_or("public Windows matrix absent")?;
        if job["runs-on"].as_str() != Some("${{ matrix.runner }}")
            || rows.len() != 1
            || rows[0]["runner"].as_str() != Some("windows-2022")
        {
            return Err("public Windows image changed".into());
        }
    }
    Ok(())
}

#[test]
fn actual_graph_preserves_complete_finalization_closure_and_original_recovery() {
    validate(&workflow()).unwrap();
}

#[test]
fn every_required_final_dependency_is_individually_enforced() {
    let value = workflow();
    validate(&value).expect("current workflow graph must be valid before mutation");
    for parent in [
        "format",
        "source-policy",
        "source-checks",
        "source-docs",
        "msrv",
        "supply-chain-audit",
        "supply-chain-deny",
        "miri",
        "fuzz",
        "fuzz-setup",
        "test-tools-linux-x64",
        "test-tools-linux-arm64",
        "test-tools-macos-x64",
        "test-tools-macos-arm64",
        "test-tools-windows-x64",
        "test-tools-windows-arm64",
        "rehearse",
        "assemble-payload",
        "native-linux-x64",
        "native-linux-arm64",
        "native-macos-x64",
        "native-macos-x64-shard-0",
        "native-macos-x64-shard-1",
        "native-macos-x64-shard-2",
        "native-macos-x64-shard-3",
        "native-macos-arm64",
        "native-windows-x64",
        "native-windows-arm64",
        "candidate-linux-x64-native",
        "candidate-linux-x64-cargo",
        "candidate-linux-arm64-native",
        "candidate-linux-arm64-cargo",
        "candidate-windows-x64-native",
        "candidate-windows-x64-cargo",
        "candidate-windows-arm64-native",
        "candidate-windows-arm64-cargo",
        "installed-macos-x64-native",
        "installed-macos-x64-cargo",
        "installed-macos-arm64-native",
        "installed-macos-arm64-cargo",
    ] {
        let mut changed = value.clone();
        for job in changed["jobs"].as_mapping_mut().unwrap().values_mut() {
            if let Some(needs) = job["needs"].as_sequence_mut() {
                needs.retain(|value| value.as_str() != Some(parent));
            }
        }
        assert_ne!(changed, value, "dependency removal must change {parent}");
        assert!(validate(&changed).is_err(), "removed {parent}");
    }
}

#[test]
fn cycle_and_success_bypass_mutations_are_rejected() {
    let value = workflow();
    validate(&value).expect("current workflow graph must be valid before mutation");
    let mut cycle = value.clone();
    cycle["jobs"]["rehearse"]["needs"] =
        serde_yaml::to_value(["select", "assemble", "rehearsal-tool"]).unwrap();
    assert!(validate(&cycle).is_err());
    for name in ["public-windows-x64-native", "public-windows-x64-cargo"] {
        let mut changed = value.clone();
        changed["jobs"][name]["strategy"]["matrix"]["include"][0]["runner"] = "windows-2025".into();
        assert!(
            validate(&changed).is_err(),
            "{name} must preserve its public image"
        );
    }
    for job in ["assemble", "publish", "recovery-publish"] {
        for condition in ["always()", "failure()", "cancelled()"] {
            let mut changed = value.clone();
            changed["jobs"][job]["if"] = condition.into();
            assert!(validate(&changed).is_err(), "{job}: {condition}");
        }
    }
}
