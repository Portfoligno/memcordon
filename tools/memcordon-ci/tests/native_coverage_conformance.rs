use memcordon_ci::command::{CommandSpec, bounded_excerpt};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    path::Path,
    time::{Duration, Instant},
};

fn cargo(root: &Path) -> CommandSpec {
    CommandSpec::cargo("rustup", root, "1.97.1", Duration::from_secs(60))
}

fn write(root: &Path, path: &str, text: &str) {
    let path = root.join(path);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn units(root: &Path, directory: &str, selectors: &[&str], execute: bool) -> BTreeSet<String> {
    let selection: Vec<_> = [
        "--workspace",
        "--all-features",
        "--release",
        "--locked",
        "--offline",
    ]
    .into_iter()
    .chain(selectors.iter().copied())
    .map(str::to_owned)
    .collect();
    let command = memcordon_ci::release::native_coverage_owner::selection_command(
        root,
        "1.97.1",
        Path::new(directory),
        &selection,
        !execute,
        memcordon_ci::failure_mode::FailureMode::StopAfterFailure,
        Instant::now() + Duration::from_secs(60),
    );
    let output = command.output_owned().into_result().unwrap();
    assert!(
        output.status.success(),
        "Cargo failed: status={}; stdout ({} bytes):\n{}\nstderr ({} bytes):\n{}",
        output.status,
        output.stdout.len(),
        bounded_excerpt(&output.stdout),
        output.stderr.len(),
        bounded_excerpt(&output.stderr)
    );
    let units: BTreeSet<_> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|record| record["reason"] == "compiler-artifact")
        .map(|record| {
            serde_json::to_string(&serde_json::json!({
                "package": record["package_id"], "target": record["target"],
                "profile": record["profile"], "features": record["features"]
            }))
            .unwrap()
        })
        .collect();
    assert!(!units.is_empty(), "Cargo emitted no compiler artifacts");
    units
}

#[test]
fn binary_harness_owner_builds_ordinary_sibling_before_both_phases() {
    let root = if cfg!(unix) {
        tempfile::tempdir_in("/tmp").unwrap()
    } else {
        tempfile::tempdir().unwrap()
    };
    write(
        root.path(),
        "Cargo.toml",
        "[package]\nname='owned-sibling'\nversion='0.0.0'\nedition='2021'\n",
    );
    write(
        root.path(),
        "src/main.rs",
        r#"fn main() {}
#[test] fn launches_ordinary_sibling() {
    let current = std::env::current_exe().unwrap();
    let ordinary = current.parent().unwrap().parent().unwrap()
        .join("owned-sibling").with_extension(std::env::consts::EXE_EXTENSION);
    assert!(std::process::Command::new(ordinary).status().unwrap().success());
}
"#,
    );
    cargo(root.path())
        .args(["generate-lockfile", "--offline"])
        .run()
        .unwrap();
    let selectors: Vec<String> = [
        "--workspace",
        "--all-features",
        "--locked",
        "--offline",
        "--release",
        "--bin",
        "owned-sibling",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let cutoff = Instant::now() + Duration::from_secs(60);
    for compile in [true, false] {
        let output = memcordon_ci::release::native_coverage_owner::support_command(
            root.path(),
            "1.97.1",
            Path::new("owned"),
            &selectors,
            compile,
            memcordon_ci::failure_mode::FailureMode::StopAfterFailure,
            cutoff,
        )
        .output_owned()
        .into_result()
        .unwrap();
        assert!(
            output.status.success(),
            "{}",
            bounded_excerpt(&output.stderr)
        );
        let output = memcordon_ci::release::native_coverage_owner::selection_command(
            root.path(),
            "1.97.1",
            Path::new("owned"),
            &selectors,
            compile,
            memcordon_ci::failure_mode::FailureMode::StopAfterFailure,
            cutoff,
        )
        .output_owned()
        .into_result()
        .unwrap();
        assert!(
            output.status.success(),
            "{}",
            bounded_excerpt(&output.stderr)
        );
    }
}

#[test]
fn pinned_workspace_selectors_preserve_full_units_and_execute_the_same_selection() {
    let root = if cfg!(unix) {
        tempfile::tempdir_in("/tmp").unwrap()
    } else {
        tempfile::tempdir().unwrap()
    };
    write(
        root.path(),
        "Cargo.toml",
        "[workspace]\nresolver='2'\nmembers=['one','two','shared']\n",
    );
    write(
        root.path(),
        "shared/Cargo.toml",
        "[package]\nname='shared'\nversion='0.0.0'\nedition='2021'\n[features]\ndev=[]\nbuild=[]\n",
    );
    write(root.path(), "shared/src/lib.rs", "pub fn value()->u8 {1}\n");
    for name in ["one", "two"] {
        let package = root.path().join(name);
        let mut manifest = toml::toml! {
            [package]
            name = name
            version = "0.0.0"
            edition = "2021"
            [features]
            enabled = []
            [dependencies.shared]
            path = "../shared"
            [dev-dependencies.shared]
            path = "../shared"
            features = ["dev"]
            [build-dependencies.shared]
            path = "../shared"
            features = ["build"]
        };
        manifest.insert(
            "bin".into(),
            toml::Value::Array(vec![
                toml::toml! {name=name path="src/main.rs" test=false}.into(),
            ]),
        );
        manifest.insert("test".into(), toml::Value::Array(vec![
            toml::toml! {name="duplicate" path="tests/duplicate.rs" required-features=["enabled"]}.into(),
            toml::toml! {name="custom" path="tests/custom.rs" harness=false}.into(),
        ]));
        manifest.insert(
            "example".into(),
            toml::Value::Array(vec![
                toml::toml! {name="sample" path="examples/sample.rs" test=false}.into(),
            ]),
        );
        write(&package, "Cargo.toml", &toml::to_string(&manifest).unwrap());
        write(
            &package,
            "src/lib.rs",
            "pub fn value()->u8 {shared::value()}\n#[test] fn executes(){std::fs::write(std::path::Path::new(env!(\"CARGO_MANIFEST_DIR\")).join(\"lib.executed\"),b\"executed\").unwrap();}\n",
        );
        write(
            &package,
            "src/main.rs",
            "fn main() {std::fs::write(std::path::Path::new(env!(\"CARGO_MANIFEST_DIR\")).join(\"bin.executed\"),b\"executed\").unwrap();}\n",
        );
        write(
            &package,
            "build.rs",
            "fn main() {assert_eq!(shared::value(),1);}\n",
        );
        write(
            &package,
            "tests/duplicate.rs",
            "#[test] fn valid(){assert_eq!(shared::value(),1);let binary=option_env!(\"CARGO_BIN_EXE_one\").or(option_env!(\"CARGO_BIN_EXE_two\")).unwrap();assert!(std::process::Command::new(binary).status().unwrap().success());std::fs::write(std::path::Path::new(env!(\"CARGO_MANIFEST_DIR\")).join(\"test.executed\"),b\"executed\").unwrap();}\n",
        );
        write(
            &package,
            "tests/custom.rs",
            "fn main(){assert_eq!(shared::value(),1);std::fs::write(std::path::Path::new(env!(\"CARGO_MANIFEST_DIR\")).join(\"custom.executed\"),b\"executed\").unwrap();}\n",
        );
        write(
            &package,
            "examples/sample.rs",
            "fn main() {std::fs::write(std::path::Path::new(env!(\"CARGO_MANIFEST_DIR\")).join(\"example.executed\"),b\"executed\").unwrap();}\n",
        );
    }
    cargo(root.path())
        .args(["generate-lockfile", "--offline"])
        .run()
        .unwrap();
    let full = units(root.path(), "full", &["--all-targets"], false);
    assert_eq!(full, units(root.path(), "full", &["--all-targets"], true));
    let root_path = root.path();
    let marker_paths: Vec<_> = ["one", "two"]
        .into_iter()
        .flat_map(|package| {
            [
                "lib.executed",
                "bin.executed",
                "test.executed",
                "custom.executed",
                "example.executed",
            ]
            .into_iter()
            .map(move |marker| root_path.join(package).join(marker))
        })
        .collect();
    let original_execution: Vec<_> = marker_paths.iter().map(|path| path.is_file()).collect();
    for path in marker_paths.iter().filter(|path| path.is_file()) {
        std::fs::remove_file(path).unwrap();
    }
    let custom: Vec<Value> = full
        .iter()
        .map(|unit| serde_json::from_str(unit).unwrap())
        .filter(|unit: &Value| unit["target"]["name"] == "custom")
        .collect();
    assert_eq!(custom.len(), 2);
    assert!(
        custom.iter().all(|unit| unit["profile"]["test"] == true),
        "custom harness compile mode differs: {custom:?}"
    );
    let mut union = BTreeSet::new();
    for (index, selectors) in [
        vec!["--lib"],
        vec!["--bin", "one"],
        vec!["--bin", "two"],
        vec!["--test", "duplicate"],
        vec!["--test", "custom"],
        vec!["--example", "sample"],
    ]
    .iter()
    .enumerate()
    {
        let directory = root.path().join(index.to_string());
        let directory = directory.to_str().unwrap();
        let compiled = units(root.path(), directory, selectors, false);
        let executed = units(root.path(), directory, selectors, true);
        assert_eq!(compiled, executed, "execution changed selected compilation");
        union.extend(compiled);
    }
    assert_eq!(
        full, union,
        "named selections changed the original Cargo unit graph"
    );
    let selected_execution: Vec<_> = marker_paths.iter().map(|path| path.is_file()).collect();
    assert_eq!(
        original_execution, selected_execution,
        "named selections changed execution obligations"
    );
}

#[test]
fn pinned_cargo_duplicate_ordinary_outputs_cannot_prove_independent_package_images() {
    let root = if cfg!(unix) {
        tempfile::tempdir_in("/tmp").unwrap()
    } else {
        tempfile::tempdir().unwrap()
    };
    write(
        root.path(),
        "Cargo.toml",
        "[workspace]\nresolver='2'\nmembers=['first','second']\n",
    );
    for name in ["first", "second"] {
        let package = root.path().join(name);
        let mut manifest = toml::toml! { [package] name=name version="0.0.0" edition="2021" };
        manifest.insert(
            "bin".into(),
            toml::Value::Array(vec![
                toml::toml! {name="collision" path="src/main.rs"}.into(),
            ]),
        );
        write(&package, "Cargo.toml", &toml::to_string(&manifest).unwrap());
        write(
            &package,
            "src/main.rs",
            if name == "first" {
                "fn main() {std::process::exit(1);}\n"
            } else {
                "fn main() {std::process::exit(2);}\n"
            },
        );
        write(
            &package,
            "tests/uses_binary.rs",
            "#[test] fn exists(){assert!(std::path::Path::new(env!(\"CARGO_BIN_EXE_collision\")).is_file());}\n",
        );
    }
    cargo(root.path())
        .args(["generate-lockfile", "--offline"])
        .run()
        .unwrap();
    // Shared ordinary output paths need serial construction to inspect identity
    // without racing concurrent linker writes to the same destination.
    let output = cargo(root.path())
        .args([
            "test",
            "--workspace",
            "--all-targets",
            "--release",
            "--no-run",
            "--jobs",
            "1",
            "--offline",
            "--locked",
            "--message-format=json",
        ])
        .output_owned()
        .into_result()
        .unwrap();
    assert!(
        output.status.success(),
        "Cargo failed: status={}; stdout ({} bytes):\n{}\nstderr ({} bytes):\n{}",
        output.status,
        output.stdout.len(),
        bounded_excerpt(&output.stdout),
        output.stderr.len(),
        bounded_excerpt(&output.stderr)
    );
    let records: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|record| {
            record["reason"] == "compiler-artifact"
                && record["target"]["name"] == "collision"
                && record["profile"]["test"] == false
        })
        .collect();
    assert_eq!(records.len(), 2);
    assert_ne!(records[0]["package_id"], records[1]["package_id"]);
    assert_eq!(
        records[0]["executable"], records[1]["executable"],
        "Cargo collision contract changed; review planner admission"
    );
}
