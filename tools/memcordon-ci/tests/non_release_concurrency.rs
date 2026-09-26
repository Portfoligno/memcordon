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
            .find(|step| step["id"].as_str() == Some("build-context-prepare"))
            .unwrap();
        prepare["run"] = Value::String(
            "./ci-native-fingerprint.exe --profile stable --output target/ci/native-inputs.bin"
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
        suite["run"] = Value::String("./target/ci/control-bootstrap/ci-bootstrap/memcordon-ci --build-context target/ci/native-inputs.bin suite native".into());
        assert!(check(".github/workflows/deep-ci.yml", &substitution).is_err());
    }
}

#[test]
fn windows_architecture_edges_evidence_and_cache_boundaries_are_exact() {
    let exact: Value = serde_yaml::from_str(include_str!(
        "../../../.github/workflows/backend-certification.yml"
    ))
    .unwrap();
    for architecture in ["x64", "arm64"] {
        let other = if architecture == "x64" {
            "arm64"
        } else {
            "x64"
        };
        let provider = format!("windows-provider-lifecycle-{architecture}");
        let mut wrong = exact.clone();
        wrong["jobs"][&provider]["needs"] =
            Value::String(format!("windows-loader-production-{other}"));
        assert!(check(".github/workflows/backend-certification.yml", &wrong).is_err());
        let package = format!("windows-package-channel-{architecture}");
        let mut broad = exact.clone();
        let steps = broad["jobs"][&package]["steps"].as_sequence_mut().unwrap();
        let target = steps
            .iter_mut()
            .find(|step| step["id"].as_str() == Some("package-target"))
            .unwrap();
        target["with"]["path"] = Value::String("target/ci/windows-sealed-cargo\n".into());
        assert!(check(".github/workflows/backend-certification.yml", &broad).is_err());
        let mut archives = exact.clone();
        let steps = archives["jobs"][&package]["steps"]
            .as_sequence_mut()
            .unwrap();
        let target = steps
            .iter_mut()
            .find(|step| step["id"].as_str() == Some("package-target"))
            .unwrap();
        let paths = target["with"]["path"]
            .as_str()
            .unwrap()
            .lines()
            .filter(|path| *path != "!target/ci/windows-sealed-cargo/build/package")
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        target["with"]["path"] = Value::String(paths);
        assert!(check(".github/workflows/backend-certification.yml", &archives).is_err());
        let mut env = exact.clone();
        let steps = env["jobs"][&package]["steps"].as_sequence_mut().unwrap();
        let suite = steps
            .iter_mut()
            .find(|step| step["name"].as_str() == Some("Certify packaged Cargo channel"))
            .unwrap();
        suite["env"] =
            serde_yaml::from_str("CARGO_TARGET_DIR: target/ci/windows-sealed-cargo/build").unwrap();
        assert!(check(".github/workflows/backend-certification.yml", &env).is_err());
        let mut lab = exact.clone();
        lab["jobs"][format!("windows-loader-lab-{architecture}")]["if"] =
            Value::String("github.event_name == 'workflow_dispatch'".into());
        assert!(check(".github/workflows/backend-certification.yml", &lab).is_err());
    }
}

#[test]
fn staged_tool_cache_and_duplicate_managed_controls_cannot_be_projected_away() {
    let exact: Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/deep-ci.yml")).unwrap();
    for path in [
        "target/ci-tools",
        "target/ci-tools/staging",
        "target/ci-tools/bin\ntarget/ci-tools/staging\n",
    ] {
        let mut broad = exact.clone();
        let steps = broad["jobs"]["fuzz"]["steps"].as_sequence_mut().unwrap();
        let tools = steps
            .iter_mut()
            .find(|step| step["id"] == "fuzz-tools")
            .unwrap();
        tools["with"]["path"] = Value::String(path.into());
        assert!(
            check(".github/workflows/deep-ci.yml", &broad).is_err(),
            "staging cache {path}"
        );
    }
    for control in ["seed", "prepare", "audit"] {
        let mut duplicate = exact.clone();
        let steps = duplicate["jobs"]["fuzz"]["steps"]
            .as_sequence_mut()
            .unwrap();
        let ordinal = steps
            .iter()
            .position(|step| match control {
                "seed" => step["run"]
                    .as_str()
                    .is_some_and(|run| run.starts_with("rustup run 1.97.1 rustc")),
                "prepare" => step["id"] == "build-context-prepare",
                "audit" => step["id"] == "build-context-audit",
                _ => unreachable!(),
            })
            .unwrap();
        steps.insert(ordinal + 1, steps[ordinal].clone());
        assert!(
            check(".github/workflows/deep-ci.yml", &duplicate).is_err(),
            "duplicate {control}"
        );
    }
    for excluded in [
        "!target/ci/source-home",
        "!target/ci/native-inputs.bin",
        "!target/ci/reports",
        "!target/ci/*evidence*",
        "!target/ci/*diagnostic*",
        "!target/ci/release-bundle",
        "!target/ci/release-inputs",
    ] {
        let mut broad = exact.clone();
        let steps = broad["jobs"]["fuzz"]["steps"].as_sequence_mut().unwrap();
        let target = steps
            .iter_mut()
            .find(|step| step["id"] == "fuzz-target")
            .unwrap();
        target["with"]["path"] = Value::String(
            target["with"]["path"]
                .as_str()
                .unwrap()
                .lines()
                .filter(|path| *path != excluded)
                .collect::<Vec<_>>()
                .join("\n")
                + "\n",
        );
        assert!(
            check(".github/workflows/deep-ci.yml", &broad).is_err(),
            "removed {excluded}"
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
            .position(|step| step["with"]["name"] == "stress-phases-${{ matrix.id }}")
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
fn tool_and_package_cache_paths_select_build_sentinels_without_staging_or_evidence() {
    let deep: Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/deep-ci.yml")).unwrap();
    let windows: Value = serde_yaml::from_str(include_str!(
        "../../../.github/workflows/backend-certification.yml"
    ))
    .unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let tool_sentinels = [
        ("target/ci-tools/bin/cargo-fuzz", true),
        ("target/ci-tools/build/cargo-fuzz/compiler-output", true),
        ("target/ci-tools/staging/cargo-fuzz/bin/cargo-fuzz", false),
        ("target/ci-tools/staging/cargo-fuzz/.crates2.json", false),
    ];
    let package_sentinels = [
        ("target/ci/windows-sealed-cargo/build/compiler-output", true),
        (
            "target/ci/windows-sealed-cargo/build/package/provider.crate",
            false,
        ),
        (
            "target/ci/windows-sealed-cargo/installed/bin/provider.exe",
            false,
        ),
        ("target/ci/windows-sealed-cargo/report.json", false),
    ];
    for (relative, _) in tool_sentinels.iter().chain(&package_sentinels) {
        let path = temporary.path().join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"sentinel\n").unwrap();
    }
    for (job, restore_id, sentinels) in [
        (
            &deep["jobs"]["fuzz"],
            "fuzz-tools",
            tool_sentinels.as_slice(),
        ),
        (
            &windows["jobs"]["windows-package-channel-x64"],
            "package-target",
            package_sentinels.as_slice(),
        ),
    ] {
        let steps = job["steps"].as_sequence().unwrap();
        let restore = steps.iter().find(|step| step["id"] == restore_id).unwrap();
        let save_key = format!("${{{{ steps.{restore_id}.outputs.cache-primary-key }}}}");
        let save = steps
            .iter()
            .find(|step| step["with"]["key"].as_str() == Some(&save_key))
            .unwrap();
        for step in [restore, save] {
            let paths = step["with"]["path"].as_str().unwrap();
            for (sentinel, expected) in sentinels {
                let relative = Path::new(sentinel);
                let selected = paths
                    .lines()
                    .filter(|path| !path.starts_with('!'))
                    .any(|path| relative.starts_with(path))
                    && !paths
                        .lines()
                        .filter_map(|path| path.strip_prefix('!'))
                        .any(|path| relative.starts_with(path));
                assert_eq!(
                    selected, *expected,
                    "cache paths selected {sentinel}: {paths}"
                );
                assert!(temporary.path().join(relative).is_file());
            }
        }
    }
}
